import { describe, expect, it, vi } from 'vitest';

const q = vi.hoisted(() => ({ items: [] as Buffer[] }));
vi.mock('node:crypto', async (orig) => {
  const real = await orig<typeof import('node:crypto')>();
  return { ...real, randomBytes: (n: number) => (q.items.length > 0 ? q.items.shift()! : real.randomBytes(n)) };
});

import { SecureFieldRng, fieldRandom, secureOtRandom } from './csprng';
import { FieldRng } from './field';
import { PRIME } from './field';
import { L } from './ec';
import { gf128Add, gf128Mul, gf128MulByXi, gf128MulX } from './gf128';

const be = (v: bigint, n: number): Buffer => {
  const b = Buffer.alloc(n);
  for (let i = n - 1; i >= 0; i--) {
    b[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return b;
};

describe('SecureFieldRng rejection sampling', () => {
  const limit = (2n ** 64n / PRIME) * PRIME;
  it('limit is 2^64 - 8 and the value at the limit is rejected (not reduced to 0)', () => {
    expect(limit).toBe(2n ** 64n - 8n);
    q.items = [be(limit, 8), be(5n, 8)];
    expect(new SecureFieldRng().next()).toBe(5n);
    expect(q.items.length).toBe(0);
  });
  it('values above the limit are rejected, values just below are accepted and reduced', () => {
    q.items = [be(2n ** 64n - 1n, 8), be(limit - 1n, 8)];
    expect(new SecureFieldRng().next()).toBe((limit - 1n) % PRIME);
    q.items = [be(PRIME + 3n, 8)];
    expect(new SecureFieldRng().next()).toBe(3n);
  });
  it('reads the 8 bytes big-endian', () => {
    q.items = [Buffer.from([0, 0, 0, 0, 0, 0, 1, 2])];
    expect(new SecureFieldRng().next()).toBe(258n);
  });
});

describe('secureOtRandom.scalar rejection sampling', () => {
  const bound = (2n ** 256n / L) * L;
  it('rejects 256-bit values at or above the bias bound, accepts just below', () => {
    q.items = [be(bound + 1n, 32), be(2n ** 256n - 1n, 32), be(7n, 32)];
    expect(secureOtRandom().scalar()).toBe(7n);
    expect(q.items.length).toBe(0);
    q.items = [be(bound - 1n, 32)];
    expect(secureOtRandom().scalar()).toBe((bound - 1n) % L);
  });
  it('a zero scalar is rejected', () => {
    q.items = [be(0n, 32), be(L, 32), be(9n, 32)];
    expect(secureOtRandom().scalar()).toBe(9n);
  });
});

describe('gf128Mul', () => {
  it('ignores bits of b at or above 128', () => {
    expect(gf128Mul(1n, 1n << 128n)).toBe(0n);
    expect(gf128Mul(5n, (1n << 128n) | 1n)).toBe(5n);
  });
});

describe('gf128 primitives', () => {
  it('add is a masked xor', () => {
    expect(gf128Add(5n, 3n)).toBe(6n);
    expect(gf128Add((1n << 128n) | 1n, 0n)).toBe(1n);
    expect(gf128Add(1n << 127n, 1n << 127n)).toBe(0n);
  });
  it('mulX shifts and reduces by 0x87 only on overflow', () => {
    expect(gf128MulX(1n)).toBe(2n);
    expect(gf128MulX(1n << 126n)).toBe(1n << 127n);
    expect(gf128MulX(1n << 127n)).toBe(0x87n);
    expect(gf128MulX((1n << 127n) | 1n)).toBe(0x85n);
  });
  it('mulByXi is i repeated mulX on the masked input', () => {
    expect(gf128MulByXi(5n, 0)).toBe(5n);
    expect(gf128MulByXi((1n << 128n) | 5n, 0)).toBe(5n);
    expect(gf128MulByXi(1n, 3)).toBe(8n);
    expect(gf128MulByXi(1n, 127)).toBe(1n << 127n);
    expect(gf128MulByXi(1n, 128)).toBe(0x87n);
    expect(gf128MulByXi(1n, 129)).toBe(0x87n << 1n);
    expect(gf128MulByXi(0x1234n, 1)).toBe(0x2468n);
  });
  it('mul: identity, x and reduction', () => {
    expect(gf128Mul(0x1234n, 1n)).toBe(0x1234n);
    expect(gf128Mul(1n << 127n, 2n)).toBe(0x87n);
    expect(gf128Mul(0xabcdn, 0n)).toBe(0n);
    expect(gf128Mul((1n << 128n) | 3n, 1n)).toBe(3n);
  });
});

describe('csprng misc', () => {
  it('bytes(n) returns the n random bytes as a Uint8Array', () => {
    q.items = [Buffer.from([1, 2, 3])];
    const b = secureOtRandom().bytes(3);
    expect(b).toBeInstanceOf(Uint8Array);
    expect(Array.from(b)).toEqual([1, 2, 3]);
    expect(secureOtRandom().bytes(0)).toHaveLength(0);
  });
  it('fieldRandom is secure by default and seeded only by an explicit testSeed', () => {
    expect(fieldRandom()).toBeInstanceOf(SecureFieldRng);
    expect(fieldRandom({})).toBeInstanceOf(SecureFieldRng);
    expect(fieldRandom({ testSeed: undefined })).toBeInstanceOf(SecureFieldRng);
    const s = fieldRandom({ testSeed: 0n });
    expect(s).not.toBeInstanceOf(SecureFieldRng);
    const ref = new FieldRng(0n);
    expect([s.next(), s.next()]).toEqual([ref.next(), ref.next()]);
    const s2 = fieldRandom({ testSeed: 5n });
    expect(s2.next()).toBe(new FieldRng(5n).next());
  });
});
