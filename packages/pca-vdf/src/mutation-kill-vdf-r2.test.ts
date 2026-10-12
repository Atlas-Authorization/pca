/**
 * Round-2 adversarial kills. hashToPrime is used symmetrically by prover and verifier, so a mutation of how the
 * candidate is derived (block counter, byte count) is invisible to a prove/verify round trip; only an independent
 * re-derivation of the spec'd transcript distinguishes it.
 */
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { DEFAULT_MODULUS, bigIntToBytes, bytesToBigInt, checkProductionModulus, hashToPrime, insecureDevSetup, isProbablePrime } from './vdf';

const sha = (...p: Uint8Array[]): Uint8Array => new Uint8Array(createHash('sha256').update(Buffer.concat(p)).digest());
const be = (n: bigint, len: number): Uint8Array => {
  const b = new Uint8Array(len);
  for (let i = len - 1, v = n; i >= 0; i--, v >>= 8n) b[i] = Number(v & 0xffn);
  return b;
};
const lp = (b: Uint8Array): Uint8Array => Buffer.concat([be(BigInt(b.length), 4), b]);

/** Straight-line re-implementation of the documented hash-to-prime (domain, length-prefixed transcript, counter x block expansion). */
function reference(x: bigint, y: bigint, T: number, N: bigint, bits: number): bigint {
  const seed = sha(
    new TextEncoder().encode('atlas-pca/vdf/wesolowski/hash-to-prime/v1\0'),
    lp(bigIntToBytes(((x % N) + N) % N)),
    lp(bigIntToBytes(((y % N) + N) % N)),
    lp(bigIntToBytes(BigInt(T))),
    lp(bigIntToBytes(N)),
    lp(be(BigInt(bits), 4)),
  );
  const need = Math.ceil(bits / 8);
  const mask = (1n << BigInt(bits)) - 1n;
  for (let counter = 0n; ; counter++) {
    let raw = new Uint8Array(0);
    for (let blk = 0; raw.length < need; blk++) raw = Buffer.concat([raw, sha(seed, be(counter, 8), be(BigInt(blk), 4))]);
    const cand = (bytesToBigInt(raw.subarray(0, need)) & mask) | (1n << BigInt(bits - 1)) | 1n;
    if (isProbablePrime(cand)) return cand;
  }
}

describe('r2: hashToPrime matches an independent derivation of the documented transcript', () => {
  it('default 256-bit challenge, short and long (multi-block) widths', () => {
    for (const bits of [8, 16, 64, 200, 256, 257, 512, 777]) {
      const got = hashToPrime(3n, 5n, 10, DEFAULT_MODULUS, bits);
      expect(got).toBe(reference(3n, 5n, 10, DEFAULT_MODULUS, bits));
      expect(got.toString(2).length).toBe(bits);
    }
    expect(hashToPrime(7n, 11n, 3, DEFAULT_MODULUS)).toBe(reference(7n, 11n, 3, DEFAULT_MODULUS, 256));
  });
});

describe('r2: insecureDevSetup randomness discipline', () => {
  const bytes = (n: bigint, len: number): Uint8Array => be(n, len);
  it('asks the source for exactly ceil(bits/8) bytes per draw', () => {
    const asked: number[] = [];
    let m = (1n << 31n) + 1n;
    while (!isProbablePrime(m)) m += 2n;
    let m2 = m + 2n;
    while (!isProbablePrime(m2)) m2 += 2n;
    const queue = [m, m2];
    insecureDevSetup({ bits: 64, randomBytes: (n) => { asked.push(n); return bytes(queue.shift() ?? m2, n); } });
    expect(asked).toEqual([4, 4]);
    const odd: number[] = [];
    // 33-bit halves need 5 bytes; any reasonable source works, we only record the request sizes
    insecureDevSetup({ bits: 66, randomBytes: (n) => { odd.push(n); return new Uint8Array(globalThis.crypto.getRandomValues(new Uint8Array(n))); } });
    expect(new Set(odd)).toEqual(new Set([5]));
  });
  it('a stuck source that never yields a prime is abandoned after exactly 50 000 draws', () => {
    let calls = 0;
    const composite = bytes((1n << 31n) + 1n, 4); // 2^31 + 1 = 3 * 715827883
    expect(isProbablePrime((1n << 31n) + 1n)).toBe(false);
    expect(() => insecureDevSetup({ bits: 64, randomBytes: () => { calls++; return composite; } })).toThrow(/failed to yield a prime/);
    expect(calls).toBe(50_000);
  });
  it('a constant source that returns the same prime for p and q is retried exactly 8 times then refused', () => {
    let calls = 0;
    let m = (1n << 31n) + 1n;
    while (!isProbablePrime(m)) m += 2n;
    const fixed = bytes(m, 4);
    expect(() => insecureDevSetup({ bits: 64, randomBytes: () => { calls++; return fixed; } })).toThrow(/same prime repeatedly/);
    expect(calls).toBe(10); // p, q, then 8 redraws of q
  });
});

describe('r2: the dev-modulus registry beats the production-screen cache', () => {
  it('a modulus that passed the screen and is LATER produced by insecureDevSetup is refused', () => {
    const bits = 1050;
    const p = hashToPrime(11n, 13n, 1, DEFAULT_MODULUS, bits);
    const q = hashToPrime(17n, 19n, 2, DEFAULT_MODULUS, bits);
    const N = p * q;
    expect(N.toString(2).length).toBeGreaterThanOrEqual(2048);
    expect(checkProductionModulus(N)).toEqual({ ok: true }); // screened and cached
    const replay = [p, q];
    const setup = insecureDevSetup({ bits: 2 * bits, randomBytes: (n) => be(replay.shift()!, n) });
    expect(setup.N).toBe(N);
    const verdict = checkProductionModulus(N);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toMatch(/insecureDevSetup/);
  });
});
