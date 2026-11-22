import { describe, expect, it } from 'vitest';
import { detExp, detLn, detLog2, detPowInt } from './detmath';

describe('detLn: an integer-arithmetic natural logarithm', () => {
  it('exact and special values', () => {
    expect(detLn(1)).toBe(0);
    expect(detLn(0)).toBe(Number.NEGATIVE_INFINITY);
    expect(detLn(-0)).toBe(Number.NEGATIVE_INFINITY);
    expect(Number.isNaN(detLn(-1))).toBe(true);
    expect(Number.isNaN(detLn(Number.NaN))).toBe(true);
    expect(detLn(Infinity)).toBe(Infinity);
  });
  it('agrees with the platform logarithm to a few ulps over the whole range, and is antisymmetric under inversion up to rounding', () => {
    for (const x of [2, 0.5, 100, 1e-5, 0.9, 1.1, 3, 1e10, 1e-300, 1e300, 5e-324, Number.MAX_VALUE]) {
      const want = Math.log(x);
      expect(Math.abs(detLn(x) - want), String(x)).toBeLessThanOrEqual(4 * Number.EPSILON * Math.abs(want));
    }
    expect(detLn(2)).toBeCloseTo(Math.LN2, 15);
  });
  it('is deterministic: pinned values', () => {
    expect(detLn(100)).toBe(4.605170185988092);
    expect(detLn(0.5)).toBe(-0.6931471805599453);
  });
});

describe('detLog2, detExp and detPowInt', () => {
  it('log2 of a power of two is its exponent exactly', () => {
    for (const e of [-1074, -1022, -10, -1, 0, 1, 3, 52, 1023]) expect(detLog2(2 ** e), String(e)).toBe(e);
    expect(Number.isNaN(detLog2(-1))).toBe(true);
    expect(detLog2(0)).toBe(Number.NEGATIVE_INFINITY);
    expect(detLog2(Infinity)).toBe(Infinity);
  });
  it('log2 and exp agree with the platform functions to a few ulps', () => {
    for (const x of [0.3, 0.5, 0.9, 1.5, 3, 100, 1e-9]) expect(Math.abs(detLog2(x) - Math.log2(x))).toBeLessThanOrEqual(4 * Number.EPSILON * Math.max(1, Math.abs(Math.log2(x))));
    for (const x of [0, 1, -1, 0.5, -0.5, 10, -10, 100, -100, 700, -700, 1e-10, -1e-10]) {
      const want = Math.exp(x);
      expect(Math.abs(detExp(x) - want), String(x)).toBeLessThanOrEqual(4 * Number.EPSILON * want);
    }
  });
  it('exp edges', () => {
    expect(detExp(0)).toBe(1);
    expect(detExp(710)).toBe(Infinity);
    expect(detExp(-746)).toBe(0);
    expect(detExp(Number.NEGATIVE_INFINITY)).toBe(0);
    expect(Number.isNaN(detExp(Number.NaN))).toBe(true);
    expect(detExp(1)).toBe(2.718281828459045);
  });
  it('detPowInt multiplies in sequence', () => {
    expect(detPowInt(2, 10)).toBe(1024);
    expect(detPowInt(0.5, 3)).toBe(0.125);
    expect(detPowInt(7, 0)).toBe(1);
  });
});
