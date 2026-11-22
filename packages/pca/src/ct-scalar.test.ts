import { describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519';
import { ctAdd, ctFromBigint, ctIsZero, ctMul, ctReduce, ctSub, ctToBigint } from './ct-scalar';

const L = ed25519.CURVE.n;
const big = (b: Uint8Array) => ctToBigint(b);
const edge: bigint[] = [0n, 1n, 2n, L - 1n, L, L + 1n, 2n * L - 1n, 2n ** 252n, 2n ** 253n, 2n ** 255n, 2n ** 256n - 1n];
const rnd = (n = 32) => new Uint8Array(randomBytes(n));

describe('ct-scalar matches BigInt arithmetic mod L', () => {
  it('reduces 1..64 byte inputs, including L multiples and the 512-bit maximum', () => {
    for (const v of [...edge, 2n ** 512n - 1n, L * (2n ** 250n), L * L]) {
      const bytes = new Uint8Array(64);
      let x = v;
      for (let i = 0; i < 64; i++) { bytes[i] = Number(x & 0xffn); x >>= 8n; }
      expect(big(ctReduce(bytes))).toBe(v % L);
    }
    for (let i = 0; i < 100; i++) {
      const n = 1 + (i % 64);
      const b = rnd(n);
      expect(big(ctReduce(b))).toBe(big(b) % L);
    }
  });
  it('add, sub, mul agree on edge values and 300 random pairs', () => {
    const pairs: Array<[Uint8Array, Uint8Array]> = [];
    for (const a of edge) for (const b of edge) pairs.push([ctFromBigint(a), ctFromBigint(b)]);
    for (let i = 0; i < 300; i++) pairs.push([rnd(), rnd()]);
    for (const [a, b] of pairs) {
      const x = big(a), y = big(b);
      expect(big(ctAdd(a, b))).toBe((x + y) % L);
      expect(big(ctSub(a, b))).toBe((((x - y) % L) + L) % L);
      expect(big(ctMul(a, b))).toBe((x * y) % L);
    }
  });
  it('ctIsZero is true exactly for multiples of L', () => {
    expect(ctIsZero(ctFromBigint(0n))).toBe(true);
    expect(ctIsZero(ctFromBigint(L))).toBe(true);
    expect(ctIsZero(ctFromBigint(L - 1n))).toBe(false);
    expect(ctIsZero(ctFromBigint(1n))).toBe(false);
  });
  it('fails closed on malformed input', () => {
    expect(() => ctReduce(new Uint8Array(0))).toThrow();
    expect(() => ctReduce(new Uint8Array(65))).toThrow();
    expect(() => ctAdd(new Uint8Array(31), new Uint8Array(32))).toThrow();
    expect(() => ctMul(new Uint8Array(32), 'x' as unknown as Uint8Array)).toThrow();
  });
});
