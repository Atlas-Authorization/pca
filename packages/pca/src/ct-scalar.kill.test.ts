import { ed25519 } from '@noble/curves/ed25519';
import { describe, expect, it, vi } from 'vitest';

const L = ed25519.CURVE.n;
const le = (v: bigint): Uint8Array => {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = Number((v >> BigInt(8 * i)) & 0xffn);
  return out;
};
const big = (b: Uint8Array): bigint => b.reduceRight((x, byte) => (x << 8n) | BigInt(byte), 0n);

describe('ct-scalar (fresh module: the group-order limbs are built at load)', () => {
  it('reduces L, L+1 and 2^256-1 with the real group order', async () => {
    vi.resetModules();
    const m = await import('./ct-scalar');
    expect(big(m.ctReduce(le(L)))).toBe(0n);
    expect(big(m.ctReduce(le(L + 1n)))).toBe(1n);
    expect(big(m.ctReduce(le((1n << 256n) - 1n)))).toBe(((1n << 256n) - 1n) % L);
    expect(big(m.ctAdd(le(L - 1n), le(2n)))).toBe(1n);
    expect(big(m.ctSub(le(1n), le(2n)))).toBe(L - 1n);
    expect(big(m.ctMul(le(L - 1n), le(L - 1n)))).toBe(1n);
    expect(m.ctIsZero(le(L))).toBe(true);
  });
});

describe('ct-scalar refusals name the bad argument', () => {
  it('exact messages', async () => {
    const { ctAdd, ctSub, ctMul, ctIsZero, ctReduce } = await import('./ct-scalar');
    const ok = new Uint8Array(32);
    const bad = new Uint8Array(31);
    expect(() => ctReduce(new Uint8Array(0))).toThrow(new Error('ct-scalar: reduce takes 1..64 bytes'));
    expect(() => ctAdd(bad, ok)).toThrow(new Error('ct-scalar: a must be 32 bytes'));
    expect(() => ctAdd(ok, bad)).toThrow(new Error('ct-scalar: b must be 32 bytes'));
    expect(() => ctSub(bad, ok)).toThrow(new Error('ct-scalar: a must be 32 bytes'));
    expect(() => ctSub(ok, bad)).toThrow(new Error('ct-scalar: b must be 32 bytes'));
    expect(() => ctMul(bad, ok)).toThrow(new Error('ct-scalar: a must be 32 bytes'));
    expect(() => ctMul(ok, bad)).toThrow(new Error('ct-scalar: b must be 32 bytes'));
    expect(() => ctIsZero(bad)).toThrow(new Error('ct-scalar: a must be 32 bytes'));
  });
});
