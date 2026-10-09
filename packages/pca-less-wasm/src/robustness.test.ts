/**
 * Negative / robustness suite for the EXPERIMENTAL LESS wasm backend.
 *
 * Verifies the PUBLIC-KEY side behaves like a verifier must: false (never an exception, never a
 * trap) on any malformed or adversarial input, deterministic, and non-malleable on everything we
 * probe. Includes a regression for the upstream missing-length-check defect (see README "Findings").
 */
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { keygen, LessError, MAX_PUBLISHED_SEEDS, open, seedWith, sign, signDetached, sizes, verify } from './index.js';

const WASM = join(__dirname, '..', 'wasm', 'less_cat1.wasm');
const d = existsSync(WASM) ? describe : describe.skip;
const enc = new TextEncoder();

function fixture() {
  seedWith(new Uint8Array(48).fill(3));
  const a = keygen();
  const msg = enc.encode('robustness fixture');
  const sig = signDetached(a.secretKey, msg);
  seedWith(new Uint8Array(48).fill(4));
  const other = keygen();
  return { ...a, msg, sig, other };
}
const flip = (b: Uint8Array, i: number, bit: number): Uint8Array => {
  const c = b.slice();
  c[i] = c[i]! ^ (1 << bit);
  return c;
};

d('LESS wasm: negative / robustness', () => {
  const f = fixture();

  it('baseline: the fixture signature verifies; leaf count within MAX_PUBLISHED_SEEDS', () => {
    expect(verify(f.publicKey, f.msg, f.sig)).toBe(true);
    expect(f.sig[f.sig.length - 1]!).toBeLessThanOrEqual(MAX_PUBLISHED_SEEDS);
    expect(f.sig.length).toBeLessThanOrEqual(sizes().signatureMax);
  });

  it('MAX_PUBLISHED_SEEDS constant is consistent with 40 real signatures (no valid one is rejected by the length guard)', () => {
    seedWith(new Uint8Array(48).fill(7));
    const k = keygen();
    let maxLeaves = 0;
    for (let i = 0; i < 40; i++) {
      const m = randomBytes(i);
      const sm = sign(k.secretKey, m);
      maxLeaves = Math.max(maxLeaves, sm[sm.length - 1]!);
      expect(sm[sm.length - 1]!).toBeLessThanOrEqual(MAX_PUBLISHED_SEEDS);
      expect(open(k.publicKey, sm).ok).toBe(true);
    }
    expect(maxLeaves).toBeGreaterThan(0);
  }, 120_000);

  it('verification is deterministic (repeat x5, inputs not mutated)', () => {
    const pk0 = f.publicKey.slice();
    const sig0 = f.sig.slice();
    for (let i = 0; i < 5; i++) expect(verify(f.publicKey, f.msg, f.sig)).toBe(true);
    const bad = flip(f.sig, 100, 3);
    for (let i = 0; i < 5; i++) expect(verify(f.publicKey, f.msg, bad)).toBe(false);
    expect(Buffer.from(f.publicKey).equals(Buffer.from(pk0))).toBe(true);
    expect(Buffer.from(f.sig).equals(Buffer.from(sig0))).toBe(true);
  }, 60_000);

  it('rejects a wrong message (one-byte change, truncation, extension, empty)', () => {
    expect(verify(f.publicKey, flip(f.msg, 0, 0), f.sig)).toBe(false);
    expect(verify(f.publicKey, f.msg.slice(0, f.msg.length - 1), f.sig)).toBe(false);
    expect(verify(f.publicKey, new Uint8Array([...f.msg, 0]), f.sig)).toBe(false);
    expect(verify(f.publicKey, new Uint8Array(0), f.sig)).toBe(false);
  }, 60_000);

  it('rejects a wrong key; wrong-sized / all-zero / all-0xff keys never throw from verify()', () => {
    expect(verify(f.other.publicKey, f.msg, f.sig)).toBe(false);
    expect(verify(f.publicKey.slice(1), f.msg, f.sig)).toBe(false);
    expect(verify(new Uint8Array(0), f.msg, f.sig)).toBe(false);
    expect(verify(new Uint8Array(f.publicKey.length + 1), f.msg, f.sig)).toBe(false);
    expect(verify(new Uint8Array(f.publicKey.length), f.msg, f.sig)).toBe(false);
    expect(verify(new Uint8Array(f.publicKey.length).fill(0xff), f.msg, f.sig)).toBe(false);
    // open()/sign() keep a documented fail-loud contract for wrong-sized KEYS (a programming error):
    expect(() => open(f.publicKey.slice(1), new Uint8Array(1))).toThrow(LessError);
    expect(() => sign(f.secretKey.slice(1), f.msg)).toThrow(LessError);
  }, 120_000);

  it('rejects single-bit tampering at sampled positions across every region (first/last 8 bytes + stride)', () => {
    const idx = new Set<number>();
    for (let i = 0; i < 8; i++) {
      idx.add(i);
      idx.add(f.sig.length - 1 - i);
    }
    for (let i = 0; i < f.sig.length; i += 41) idx.add(i);
    let n = 0;
    for (const i of idx) {
      expect(verify(f.publicKey, f.msg, flip(f.sig, i, i % 8)), `bit flip @${i}`).toBe(false);
      n++;
    }
    expect(n).toBeGreaterThan(40);
  }, 600_000);

  it('trailing leaf-count byte: every single-bit flip is rejected without throwing/trapping (upstream-defect regression)', () => {
    // Flipping bits of the last byte can make it claim MORE leaves than the buffer holds; the raw
    // reference then underflows its length and traps/crashes. The wrapper must answer false.
    for (let bit = 0; bit < 8; bit++) {
      expect(verify(f.publicKey, f.msg, flip(f.sig, f.sig.length - 1, bit)), `leaf byte bit ${bit}`).toBe(false);
    }
  }, 60_000);

  it('padding-bit rows (weight-K but bits 252..255 set -- would make the reference write out of bounds) are rejected', () => {
    // cf_monom_actions rows start at sig offset 64, 32 bytes each; N=252 so the high nibble of a
    // row's last byte is padding. Move one set bit of row r into the padding: popcount stays K, so the
    // reference's CheckCanonicalAction would accept the row, yet UnpackCosetRep would index past N.
    for (const r of [0, 1, 17, 33]) {
      const sig = f.sig.slice();
      const row = 64 + r * 32;
      let moved = false;
      for (let i = 0; i < 31 && !moved; i++) {
        for (let b = 0; b < 8 && !moved; b++) {
          if (sig[row + i]! & (1 << b)) {
            sig[row + i] = sig[row + i]! & ~(1 << b);
            sig[row + 31] = sig[row + 31]! | 0x10;
            moved = true;
          }
        }
      }
      expect(moved).toBe(true);
      expect(verify(f.publicKey, f.msg, sig), `row ${r}`).toBe(false);
    }
  }, 60_000);

  it('valid signatures never carry padding bits (guard cannot reject honest output)', () => {
    seedWith(new Uint8Array(48).fill(11));
    const k = keygen();
    for (let i = 0; i < 25; i++) {
      const sig = signDetached(k.secretKey, randomBytes(i * 3));
      for (let r = 0; r < 34; r++) expect(sig[64 + r * 32 + 31]! & 0xf0).toBe(0);
    }
  }, 120_000);

  it('truncated / oversized / empty / garbage inputs: always false, never throws, instance stays healthy', () => {
    const cuts = [0, 1, 2, 3, 15, 16, 17, 32, 63, 64, 65, 500, f.sig.length - 17, f.sig.length - 16, f.sig.length - 2, f.sig.length - 1];
    for (const keep of cuts) {
      expect(verify(f.publicKey, f.msg, f.sig.slice(0, keep)), `prefix ${keep}`).toBe(false);
      expect(verify(f.publicKey, f.msg, f.sig.slice(f.sig.length - keep)), `suffix ${keep}`).toBe(false);
    }
    for (const extra of [1, 16, 17, 1000, 100_000]) {
      expect(verify(f.publicKey, f.msg, new Uint8Array([...f.sig, ...randomBytes(extra)])), `+${extra}`).toBe(false);
      expect(verify(f.publicKey, f.msg, new Uint8Array([...randomBytes(extra), ...f.sig])), `prepend ${extra}`).toBe(false);
    }
    expect(open(f.publicKey, new Uint8Array(0))).toEqual({ ok: false, message: new Uint8Array(0) });
    // raw random garbage of assorted lengths, with an in-range trailing byte on half of them
    for (let i = 0; i < 400; i++) {
      const len = Math.floor((randomBytes(2).readUInt16BE(0) / 65536) * 3000);
      const g = randomBytes(len);
      if (len > 0 && i % 2 === 0) g[len - 1] = i % (MAX_PUBLISHED_SEEDS + 1);
      expect(() => open(f.publicKey, g)).not.toThrow();
      expect(open(f.publicKey, g).ok).toBe(false);
    }
    expect(verify(f.publicKey, f.msg, f.sig)).toBe(true); // instance not wedged by any of the above
  }, 600_000);

  it('length-consistent random signature bodies (all four structure classes) are rejected', () => {
    const base = 64 + 32 * 34; // digest+salt+cf_monom_actions for cat252/target45 (sigMax 1329 - 11*16 - 1)
    for (let i = 0; i < 6; i++) {
      const body = randomBytes(f.sig.length);
      body[body.length - 1] = f.sig[f.sig.length - 1]!;
      expect(verify(f.publicKey, f.msg, body)).toBe(false);
      const cf = f.sig.slice();
      cf.set(randomBytes(32 * 34), 64);
      expect(verify(f.publicKey, f.msg, cf)).toBe(false);
      const sd = f.sig.slice();
      sd.set(randomBytes(sd.length - 1 - base), base);
      expect(verify(f.publicKey, f.msg, sd)).toBe(false);
      const h = f.sig.slice();
      h.set(randomBytes(64), 0);
      expect(verify(f.publicKey, f.msg, h)).toBe(false);
    }
  }, 300_000);

  it('malleability: no tested alternative encoding of a signature verifies', () => {
    // Probes: (1) every single-bit flip is covered above (sampled) and exhaustively by the native
    // sweep recorded in the README (10,370/10,370 rejected); (2) here: byte-complement of whole
    // regions, cyclic rotations of the seed tree, and swapping the signature between two messages.
    const regions: Array<[number, number]> = [[0, 32], [32, 64], [64, 1152], [1152, f.sig.length - 1]];
    for (const [a, b] of regions) {
      const c = f.sig.slice();
      for (let i = a; i < b; i++) c[i] = c[i]! ^ 0xff;
      expect(verify(f.publicKey, f.msg, c), `complement ${a}..${b}`).toBe(false);
    }
    const rot = f.sig.slice();
    rot.set(f.sig.slice(1152, f.sig.length - 1).reverse(), 1152);
    expect(verify(f.publicKey, f.msg, rot)).toBe(false);
    const m2 = enc.encode('a different message');
    expect(verify(f.publicKey, m2, f.sig)).toBe(false);
    // Same (key, message) signed twice: signatures differ (randomized salt) and BOTH verify. That is
    // inherent scheme randomization, not malleability of one signature.
    const again = signDetached(f.secretKey, f.msg);
    expect(Buffer.from(again).equals(Buffer.from(f.sig))).toBe(false);
    expect(verify(f.publicKey, f.msg, again)).toBe(true);
  }, 300_000);
});
