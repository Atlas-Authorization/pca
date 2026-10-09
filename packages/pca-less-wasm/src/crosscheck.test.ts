/**
 * Differential cross-check: wasm build vs natively compiled UNMODIFIED upstream reference.
 *
 * OPT-IN (needs a host C toolchain and ~minutes of CPU): build the native variants with
 *   scripts/build-native.sh <dir>
 * then run
 *   LESS_NATIVE_DIR=<dir>/bin LESS_DIFF_N=300 npx vitest run src/crosscheck.test.ts
 * Skipped (not failed) when LESS_NATIVE_DIR is unset.
 *
 * Variants (see build-native.sh): less_O2 (apple clang -O2), less_O3llvm (Homebrew LLVM clang -O3 +
 * UBSan), less_O0asan (apple clang -O0 + ASan + UBSan, traps on first finding).
 *
 * Honest scope: wasm and native compile the SAME upstream C. Byte equality shows the wasm build
 * (wasi-sdk clang, wasm32, its libc) computes what x86/arm64 native builds compute from the same
 * source -- it rules out toolchain/ABI/endianness/UB-driven divergence on the tested inputs. It is NOT
 * an independent implementation of the LESS specification.
 */
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { keygen, open, seedWith, sign } from './index.js';

const dir = process.env.LESS_NATIVE_DIR;
const N = Number(process.env.LESS_DIFF_N ?? '300');
const N_ASAN = Number(process.env.LESS_DIFF_N_ASAN ?? '10');
const d = dir ? describe : describe.skip;
const bin = (v: string): string => join(dir ?? '', `less_${v}`);
const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');

function run(variant: string, mode: string, input: string, env: Record<string, string> = {}): { out: string; status: number | null; err: string } {
  const r = spawnSync(bin(variant), [mode], { input, maxBuffer: 1 << 30, encoding: 'utf8', env: { ...process.env, ...env } });
  return { out: r.stdout, status: r.status, err: r.stderr };
}

interface Pair {
  seed: Uint8Array;
  msg: Uint8Array;
}
function pairs(n: number): Pair[] {
  const out: Pair[] = [];
  for (let i = 0; i < n; i++) {
    const len = i === 0 ? 0 : Math.floor((randomBytes(2).readUInt16BE(0) / 65536) * 400);
    out.push({ seed: randomBytes(i % 2 === 0 ? 48 : 32), msg: randomBytes(len) });
  }
  return out;
}
const lines = (ps: Pair[]): string => ps.map((p) => `${hex(p.seed)} ${p.msg.length ? hex(p.msg) : '-'}\n`).join('');

function wasmGen(p: Pair): { pk: Uint8Array; sk: Uint8Array; sm: Uint8Array } {
  seedWith(p.seed);
  const { publicKey, secretKey } = keygen();
  return { pk: publicKey, sk: secretKey, sm: sign(secretKey, p.msg) };
}

d('wasm vs native upstream reference', () => {
  for (const [variant, n] of [['O2', N], ['O3llvm', N], ['O0asan', N_ASAN]] as const) {
    it(`${variant}: keygen+sign byte-identical to wasm on ${n} random (seed,msg); wasm opens native sigs; native opens wasm sigs`, () => {
      expect(existsSync(bin(variant))).toBe(true);
      const ps = pairs(n);
      const r = run(variant, 'gen', lines(ps));
      expect(r.err).toBe('');
      expect(r.status).toBe(0);
      const rows = r.out.trim().split('\n');
      expect(rows).toHaveLength(n);
      const crossIn: string[] = [];
      let identical = 0;
      ps.forEach((p, i) => {
        const [pk, sk, sm, rc] = rows[i]!.split(' ') as [string, string, string, string];
        expect(rc).toBe('0'); // native self-open
        const w = wasmGen(p);
        expect(hex(w.pk)).toBe(pk);
        expect(hex(w.sk)).toBe(sk);
        expect(hex(w.sm)).toBe(sm);
        // wasm verifies the NATIVE signed message
        const o = open(w.pk, Buffer.from(sm, 'hex'));
        expect(o.ok).toBe(true);
        expect(Buffer.from(o.message).equals(Buffer.from(p.msg))).toBe(true);
        crossIn.push(`${pk} ${hex(w.sm)}\n`);
        identical++;
      });
      // native verifies the WASM signed message
      const c = run(variant, 'open', crossIn.join(''));
      expect(c.err).toBe('');
      const rcs = c.out.trim().split('\n').map((l) => l.split(' ')[0]);
      expect(rcs.every((x) => x === '0')).toBe(true);
      expect(identical).toBe(n);
      console.log(`[crosscheck] ${variant}: ${identical}/${n} byte-identical pk/sk/sm; ${rcs.length} cross-verified both ways`);
    }, 3_600_000);
  }

  it('O2 accepts/rejects exactly like wasm on tampered signatures (one bit flipped per sampled byte)', () => {
    const p: Pair = { seed: new Uint8Array(48).fill(3), msg: new TextEncoder().encode('explore') };
    const w = wasmGen(p);
    const sig = w.sm.slice(p.msg.length);
    const inLines: string[] = [];
    const wasmRc: boolean[] = [];
    for (let i = 0; i < sig.length; i += 13) {
      const bad = w.sm.slice();
      bad[p.msg.length + i] = bad[p.msg.length + i]! ^ (1 << (i % 8));
      inLines.push(`${hex(w.pk)} ${hex(bad)}\n`);
      wasmRc.push(open(w.pk, bad).ok);
    }
    const r = run('O2', 'open', inLines.join(''));
    const nat = r.out.trim().split('\n').map((l) => l.split(' ')[0] === '0');
    expect(nat).toEqual(wasmRc);
  }, 3_600_000);

  it('ASan/UBSan reproduce the three documented upstream defects on the RAW reference verifier (regression evidence)', () => {
    const p: Pair = { seed: new Uint8Array(48).fill(3), msg: new TextEncoder().encode('explore') };
    const w = wasmGen(p);
    // (1) too-short signed message whose last byte claims 11 leaves -> mlen underflow -> memcpy(-N)
    const shortSm = Buffer.concat([Buffer.alloc(9), Buffer.from([11])]);
    const r1 = run('O0asan', 'open', `${hex(w.pk)} ${hex(shortSm)}\n`);
    expect(r1.status).not.toBe(0);
    expect(r1.err).toMatch(/AddressSanitizer: negative-size-param/);
    // (2) weight-K row with a bit moved into padding (252..255) -> OOB write in UnpackCosetRep
    const sm = Buffer.from(w.sm);
    const row = p.msg.length + 64; // first cf_monom_actions row
    for (let i = 0; i < 31; i++) {
      if (sm[row + i]! !== 0) {
        const b = sm[row + i]! & -sm[row + i]!; // lowest set bit
        sm[row + i] = sm[row + i]! & ~b;
        sm[row + 31] = sm[row + 31]! | 0x10;
        break;
      }
    }
    const r2 = run('O0asan', 'open', `${hex(w.pk)} ${hex(sm)}\n`);
    expect(r2.status).not.toBe(0);
    expect(r2.err).toMatch(/AddressSanitizer: stack-buffer-overflow[\s\S]*UnpackCosetRep/);
    // (3) forged digest -> challenge needs more seeds than the signature stores -> RebuildGGM over-read
    const forged: string[] = [];
    for (let i = 0; i < 40; i++) {
      const f = Buffer.from(w.sm);
      randomBytes(32).copy(f, p.msg.length); // random digest; everything else (incl. padding bits) valid
      forged.push(`${hex(w.pk)} ${hex(f)}\n`);
    }
    const r3 = run('O0asan', 'open', forged.join(''));
    expect(r3.status).not.toBe(0);
    expect(r3.err).toMatch(/AddressSanitizer: heap-buffer-overflow[\s\S]*RebuildGGM/);
    // the zero-filled-slack mitigation (LESS_PAD=1 == what the wasm wrapper does) makes the same inputs clean
    const r3p = run('O0asan', 'open', forged.join(''), { LESS_PAD: '1' });
    expect(r3p.err).toBe('');
    expect(r3p.status).toBe(0);
    // ...and the wasm binding's wrapper answers false for both, without throwing.
    expect(open(w.pk, shortSm).ok).toBe(false);
    expect(open(w.pk, sm).ok).toBe(false);
    for (const line of forged.slice(0, 10)) expect(open(w.pk, Buffer.from(line.split(' ')[1]!.trim(), 'hex')).ok).toBe(false);
  }, 600_000);
});
