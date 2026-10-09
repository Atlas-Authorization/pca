/**
 * Parity / KAT tests for the Kyber-768 lattice core, exercised through the WebAssembly binding.
 * These mirror the native Rust KATs in `crate/src/lib.rs` but additionally prove the TypeScript <->
 * wasm linear-memory marshalling is correct. Determinism lets every vector be reproduced exactly.
 */

import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  CT_BYTES,
  PK_BYTES,
  SK_BYTES,
  SYM_BYTES,
  TVEC_BYTES,
  hashToRing,
  kpkeDec,
  kpkeEnc,
  kpkeKeygen,
  ringAdd,
  ringSub,
} from './index';

/** Deterministic byte generator: SHA-256 counter-mode expansion of a label (test-only). */
function gen(label: string, n: number): Uint8Array {
  const out = new Uint8Array(n);
  let produced = 0;
  let ctr = 0;
  while (produced < n) {
    const block = createHash('sha256').update(`${label}:${ctr}`).digest();
    for (let i = 0; i < block.length && produced < n; i++) out[produced++] = block[i]!;
    ctr++;
  }
  return out;
}

/** Decode the two 12-bit coefficients packed in `buf[3*i .. 3*i+3]` (Kyber poly_frombytes layout). */
function decPair(buf: Uint8Array, i: number): [number, number] {
  const b0 = buf[3 * i]!;
  const b1 = buf[3 * i + 1]!;
  const b2 = buf[3 * i + 2]!;
  const c0 = (b0 | (b1 << 8)) & 0xfff;
  const c1 = ((b1 >> 4) | (b2 << 4)) & 0xfff;
  return [c0, c1];
}

const Q = 3329;

describe('Kyber-768 K-PKE lattice core (wasm)', () => {
  it('exposes the FIPS-203 / Kyber-768 byte sizes', () => {
    expect(PK_BYTES).toBe(1184);
    expect(SK_BYTES).toBe(1152);
    expect(CT_BYTES).toBe(1088);
    expect(TVEC_BYTES).toBe(1152);
    expect(SYM_BYTES).toBe(32);
  });

  // KAT: K-PKE decryption correctness over many independent (seed, coins, msg) triples.
  it('keygen/encrypt/decrypt round-trips the message (correctness KAT)', () => {
    for (let t = 0; t < 24; t++) {
      const { publicKey, secretKey } = kpkeKeygen(gen(`seed${t}`, SYM_BYTES));
      const msg = gen(`msg${t}`, SYM_BYTES);
      const ct = kpkeEnc(publicKey, msg, gen(`coins${t}`, SYM_BYTES));
      const rec = kpkeDec(secretKey, ct);
      expect(Buffer.from(rec).equals(Buffer.from(msg))).toBe(true);
    }
  });

  // Determinism: identical inputs -> identical public key and ciphertext bytes.
  it('keygen and encryption are deterministic in their seeds', () => {
    const seed = gen('det-seed', SYM_BYTES);
    const a = kpkeKeygen(seed);
    const b = kpkeKeygen(seed);
    expect(Buffer.from(a.publicKey).equals(Buffer.from(b.publicKey))).toBe(true);
    const msg = gen('det-msg', SYM_BYTES);
    const coins = gen('det-coins', SYM_BYTES);
    const c1 = kpkeEnc(a.publicKey, msg, coins);
    const c2 = kpkeEnc(a.publicKey, msg, coins);
    expect(Buffer.from(c1).equals(Buffer.from(c2))).toBe(true);
  });

  // The ring homomorphism the endemic construction relies on: subtracting then re-adding the SAME
  // random-oracle value recovers the public-key ring vector EXACTLY, and a ciphertext under the
  // reconstructed key still decrypts under the real secret key.
  it('ringSub then ringAdd of the same RO value is the identity (exact)', () => {
    const { publicKey, secretKey } = kpkeKeygen(gen('ring-seed', SYM_BYTES));
    const tReal = publicKey.slice(0, TVEC_BYTES);
    const rho = publicKey.slice(TVEC_BYTES);
    const h = hashToRing(new TextEncoder().encode('endemic-ro-label'));

    const c = ringSub(tReal, h);
    const back = ringAdd(c, h);
    expect(Buffer.from(back).equals(Buffer.from(tReal))).toBe(true);

    const pkRebuilt = new Uint8Array(PK_BYTES);
    pkRebuilt.set(back, 0);
    pkRebuilt.set(rho, TVEC_BYTES);
    const msg = gen('ring-msg', SYM_BYTES);
    const ct = kpkeEnc(pkRebuilt, msg, gen('ring-coins', SYM_BYTES));
    expect(Buffer.from(kpkeDec(secretKey, ct)).equals(Buffer.from(msg))).toBe(true);
  });

  // hash_to_ring yields a well-formed UNIFORM ring vector: every coefficient reduced into [0, q),
  // deterministic in the input, and sensitive to the input (random-oracle behaviour).
  it('hashToRing produces an in-range, deterministic, input-sensitive ring vector', () => {
    const a = hashToRing(new TextEncoder().encode('uniform-a'));
    expect(a.length).toBe(TVEC_BYTES);
    for (let i = 0; i < TVEC_BYTES / 3; i++) {
      const [c0, c1] = decPair(a, i);
      expect(c0).toBeLessThan(Q);
      expect(c1).toBeLessThan(Q);
    }
    const a2 = hashToRing(new TextEncoder().encode('uniform-a'));
    expect(Buffer.from(a).equals(Buffer.from(a2))).toBe(true);
    const b = hashToRing(new TextEncoder().encode('uniform-b'));
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  // Lattice-level endemic property: a UNIFORM (RO-derived) public key admits no secret the receiver
  // holds, so decrypting its ciphertext with the real secret key does NOT recover the payload.
  it('a uniform (RO-derived) public key is not decryptable with the real secret key', () => {
    const { publicKey, secretKey } = kpkeKeygen(gen('endemic-seed', SYM_BYTES));
    const rho = publicKey.slice(TVEC_BYTES);
    const tUniform = hashToRing(new TextEncoder().encode('non-chosen-branch'));
    const pkUniform = new Uint8Array(PK_BYTES);
    pkUniform.set(tUniform, 0);
    pkUniform.set(rho, TVEC_BYTES);

    const payload = gen('endemic-payload', SYM_BYTES);
    const ct = kpkeEnc(pkUniform, payload, gen('endemic-coins', SYM_BYTES));
    const rec = kpkeDec(secretKey, ct);
    expect(Buffer.from(rec).equals(Buffer.from(payload))).toBe(false);
  });
});
