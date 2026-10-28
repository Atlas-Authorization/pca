import { afterEach, describe, expect, it, vi } from 'vitest';
import { BASE, IDENTITY, PointValidationError, add, assertInSubgroup, decodePoint, encodePoint, equal, isIdentity, isInSubgroup, isOnCurve, mul, mulBase, neg, sub } from './index';

// Audit-readiness: the fail-closed table of the README, one exact outcome per row.
const msgOf = (f: () => unknown): string | undefined => {
  try {
    f();
  } catch (e) {
    expect(e).toBeInstanceOf(PointValidationError);
    return (e as Error).message;
  }
  return undefined;
};
const offCurve = (): Uint8Array => {
  // y values with no x on the curve exist; scan for one so the test does not hard-code a constant
  for (let y = 2; y < 400; y++) {
    const p = new Uint8Array(32);
    p[0] = y & 0xff;
    p[1] = y >> 8;
    if (!isOnCurve(p)) return p;
  }
  throw new Error('no off-curve y found');
};
const smallOrder = (): Uint8Array => {
  const p = new Uint8Array(32);
  p[31] = 0x80; // y = 0, x sign 1: a point of order 4 (on curve, outside the prime-order subgroup)
  return p;
};

describe('curve-core fail-closed table: exact error messages', () => {
  it('wrong length -> "expected a 32-byte compressed point, got N" naming the operand; not bytes -> "expected a Uint8Array"', () => {
    expect(msgOf(() => add(new Uint8Array(31), BASE))).toBe('add: a: expected a 32-byte compressed point, got 31');
    expect(msgOf(() => add(BASE, new Uint8Array(33)))).toBe('add: b: expected a 32-byte compressed point, got 33');
    expect(msgOf(() => sub(new Uint8Array(0), BASE))).toBe('sub: a: expected a 32-byte compressed point, got 0');
    expect(msgOf(() => mul(2n, new Uint8Array(1)))).toBe('mul: point: expected a 32-byte compressed point, got 1');
    expect(msgOf(() => neg(new Uint8Array(64)))).toBe('neg: point: expected a 32-byte compressed point, got 64');
    expect(msgOf(() => mul(2n, 'x'.repeat(32) as never))).toBe('mul: point: expected a Uint8Array');
  });

  it('off-curve operand -> the operation names itself in the refusal and returns no point', () => {
    const bad = offCurve();
    expect(msgOf(() => mul(3n, bad))).toBe('mul: point not on curve');
    expect(msgOf(() => add(bad, BASE))).toBe('add: operand not on curve');
    expect(msgOf(() => sub(BASE, bad))).toBe('sub: operand not on curve');
    expect(msgOf(() => neg(bad))).toBe('neg: point not on curve');
    expect(msgOf(() => encodePoint(bad))).toBe('encodePoint: point not on curve');
    expect(msgOf(() => decodePoint(bad))).toBe('decodePoint: point not on curve');
  });

  it('assertInSubgroup: off-curve, identity and small-order each have their own message, and the label is used', () => {
    expect(msgOf(() => assertInSubgroup(offCurve(), 'R'))).toBe('R: not on curve');
    expect(msgOf(() => assertInSubgroup(IDENTITY, 'S'))).toBe('S: identity element (forbidden here)');
    expect(msgOf(() => assertInSubgroup(smallOrder(), 'T'))).toBe('T: not in the prime-order subgroup (small-order/cofactor)');
    expect(msgOf(() => assertInSubgroup(BASE))).toBeUndefined();
    expect(msgOf(() => assertInSubgroup(new Uint8Array(3)))).toBe('point: not on curve');
  });

  it('predicates never throw: wrong length, wrong type and off-curve are all false', () => {
    for (const p of [new Uint8Array(31), null, 'x', {}, offCurve()] as unknown[]) {
      expect(isOnCurve(p as Uint8Array)).toBe(false);
      expect(isIdentity(p as Uint8Array)).toBe(false);
      expect(isInSubgroup(p as Uint8Array)).toBe(false);
      expect(equal(p as Uint8Array, BASE)).toBe(false);
      expect(equal(BASE, p as Uint8Array)).toBe(false);
    }
    expect(isOnCurve(smallOrder())).toBe(true);
    expect(isInSubgroup(smallOrder())).toBe(false);
  });

  it('a refused call leaves no residue: the next valid call returns the exact expected point', () => {
    const before = mulBase(7n);
    expect(msgOf(() => mul(5n, offCurve()))).toBe('mul: point not on curve');
    expect(Buffer.from(mulBase(7n)).toString('hex')).toBe(Buffer.from(before).toString('hex'));
    expect(equal(add(before, neg(before)), IDENTITY)).toBe(true);
  });
});

describe('curve-core fail-closed table: the wasm module is missing or corrupt', () => {
  afterEach(() => {
    vi.doUnmock('node:fs');
    vi.resetModules();
  });

  it('wasm file missing -> importing the binding rejects with the read error (the pure-JS fallback is the caller\'s explicit choice)', async () => {
    vi.resetModules();
    vi.doMock('node:fs', async (orig) => ({
      ...(await orig<typeof import('node:fs')>()),
      readFileSync: () => {
        throw Object.assign(new Error('ENOENT: no such file or directory'), { code: 'ENOENT' });
      },
    }));
    await expect(import('./index')).rejects.toThrow(/ENOENT/);
  });

  it('wasm file corrupt -> importing the binding rejects with a compile error', async () => {
    vi.resetModules();
    vi.doMock('node:fs', async (orig) => ({
      ...(await orig<typeof import('node:fs')>()),
      readFileSync: () => new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
    }));
    await expect(import('./index')).rejects.toThrow(/WebAssembly|CompileError|magic/i);
  });
});
