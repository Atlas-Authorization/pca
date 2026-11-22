import { describe, expect, it } from 'vitest';
import { binomialCdf, cdfExceeds, cdfRecNumerator, certifyBracket, clopperPearsonCertified, doubleToDyadic } from './clopper';

const A = 1n << 52n;

describe('binomialCdf: the boundary branches', () => {
  it('k >= n is exactly 1 (the summed form falls just short of 1)', () => {
    expect(binomialCdf(4, 4, 0.5)).toBe(1);
    expect(binomialCdf(20, 20, 0.3)).toBe(1);
    expect(binomialCdf(25, 20, 0.3)).toBe(1);
  });
  it('k < 0 is exactly 0, even for p <= 0', () => {
    expect(binomialCdf(-1, 10, 0)).toBe(0);
    expect(binomialCdf(-1, 10, 0.5)).toBe(0);
  });
  it('p <= 0 is exactly 1 and p >= 1 is exactly 0, also outside [0, 1]', () => {
    expect(binomialCdf(2, 10, 0)).toBe(1);
    expect(binomialCdf(2, 10, -0.5)).toBe(1);
    expect(binomialCdf(2, 10, 1)).toBe(0);
    expect(binomialCdf(2, 10, 1.5)).toBe(0);
  });
});

describe('doubleToDyadic', () => {
  it('refuses everything outside (0, 1) with the exact message', () => {
    for (const x of [0, 1, -0.5, 2, Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      expect(() => doubleToDyadic(x)).toThrow(new Error('doubleToDyadic: need 0 < x < 1'));
    }
  });
  it('is the exact binary fraction, down to the smallest subnormal', () => {
    expect(doubleToDyadic(0.5)).toEqual({ num: 1n, exp: 1 });
    expect(doubleToDyadic(0.375)).toEqual({ num: 3n, exp: 3 });
    expect(doubleToDyadic(Number.MIN_VALUE)).toEqual({ num: 1n, exp: 1074 });
  });
});

describe('cdfRecNumerator and cdfExceeds', () => {
  it('refuses a outside [0, 2^52] with the exact message and accepts both ends', () => {
    const msg = 'cdfRecNumerator: a must be in [0, 2^52]';
    expect(() => cdfRecNumerator(3, 1, -1n)).toThrow(new Error(msg));
    expect(() => cdfRecNumerator(3, 1, A + 1n)).toThrow(new Error(msg));
    expect(cdfRecNumerator(3, 1, 0n)).toBe(A ** 3n);
    expect(cdfRecNumerator(3, 1, A)).toBe(0n);
  });
  it('the comparison alpha < cdfRec is strict: equality is not "exceeds"', () => {
    // n = 1, k = 0: cdfRec(a / 2^52) = 1 - a / 2^52, which is exactly 1/2 at a = 2^51
    const half = doubleToDyadic(0.5);
    expect(cdfExceeds(1, 0, A / 2n, half)).toBe(false);
    expect(cdfExceeds(1, 0, A / 2n - 1n, half)).toBe(true);
    expect(cdfExceeds(1, 0, A / 2n + 1n, half)).toBe(false);
  });
});

describe('clopperPearsonCertified: the certified bracket is pinned on small cases', () => {
  // The floating-point starting guess decides which of the (valid, within-tolerance) brackets is returned; these exact
  // values pin it, so any change of the guess is visible.
  it.each([
    [0, 1, 0.05, 4278419646002176n, 4278419646001920n],
    [1, 3, 0.05, 3894035786730155n, 3894035786729899n],
    [1, 3, 0.5, 2251799813685248n, 2251799813684992n],
  ] as const)('k=%s n=%s alpha=%s', (k, n, alpha, upperUnits, lowerUnits) => {
    const c = clopperPearsonCertified(k, n, alpha);
    expect(c.upperUnits).toBe(upperUnits);
    expect(c.lowerUnits).toBe(lowerUnits);
    expect(c.upper).toBe(Number(upperUnits) / 2 ** 52);
  });
  it('an alpha one ulp below 1 gives a bracket that reaches 0 and is still certified', () => {
    const c = clopperPearsonCertified(0, 1, 1 - 2 ** -53);
    expect(c).toEqual({ upper: 256 / 2 ** 52, upperUnits: 256n, lowerUnits: 0n });
  });
});

describe('certifyBracket: the walks a good starting guess never needs', () => {
  it('a start far below the flip point walks up with doubling steps, then down, then bisects', () => {
    const flip = 100000n;
    const r = certifyBracket(10n, (a) => a <= flip);
    expect(r).toEqual({ hi: 100106n, lo: 99850n });
    expect(r.hi - r.lo <= 256n).toBe(true);
  });
  it('a start above the flip point is kept when it already certifies', () => {
    expect(certifyBracket(5n, (a) => a <= 0n)).toEqual({ hi: 5n, lo: 0n });
  });
  it('an exceeds that is false even at 0 is refused (cdfRec(0) = 1 can never fail)', () => {
    expect(() => certifyBracket(5n, () => false)).toThrow(new Error('clopperPearsonUpper: unreachable (cdfRec(0) = 1)'));
  });
});
