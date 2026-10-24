import { describe, expect, it } from 'vitest';
import {
  binomialCdf,
  cdfExceeds,
  cdfRecNumerator,
  clopperPearsonCertified,
  clopperPearsonUpper,
  CP_GRID_BITS,
  CP_TOLERANCE,
  doubleToDyadic,
} from './clopper';

const A = 2 ** CP_GRID_BITS;

describe('exact Clopper–Pearson (code = the Lean definition, formal/intent/lean/PcaIntent/Stats.lean)', () => {
  it('reference values with closed forms: k = 0 gives 1 − α^(1/n), k = n − 1 gives (1 − α)^(1/n)', () => {
    for (const [n, alpha] of [[1, 0.05], [10, 0.05], [30, 0.01], [100, 0.001], [7, 0.3]] as const) {
      const u0 = clopperPearsonUpper(0, n, alpha);
      const ref0 = 1 - alpha ** (1 / n);
      expect(u0).toBeGreaterThanOrEqual(ref0 - 1e-15); // rounded outward
      expect(u0 - ref0).toBeLessThanOrEqual(CP_TOLERANCE + 1e-15);
      if (n >= 2) {
        const u1 = clopperPearsonUpper(n - 1, n, alpha);
        const ref1 = (1 - alpha) ** (1 / n);
        expect(u1).toBeGreaterThanOrEqual(ref1 - 1e-15);
        expect(u1 - ref1).toBeLessThanOrEqual(CP_TOLERANCE + 1e-15);
      }
    }
    // a textbook value: 0 events in 10 trials, 95% one-sided upper bound 0.25886555089…
    expect(clopperPearsonUpper(0, 10, 0.05)).toBeCloseTo(0.25886555089, 10);
  });

  it('the certificate is exact: cdfRec(upper) ≤ α and cdfRec(lower) > α in integer arithmetic, gap ≤ 2^−44', () => {
    for (const [k, n, alpha] of [[0, 10, 0.05], [3, 33, 0.01], [9, 10, 0.05], [50, 200, 0.05], [17, 40, 0.0123]] as const) {
      const c = clopperPearsonCertified(k, n, alpha);
      const al = doubleToDyadic(alpha);
      expect(cdfExceeds(n, k, c.upperUnits, al)).toBe(false);
      expect(cdfExceeds(n, k, c.lowerUnits, al)).toBe(true);
      expect(c.upperUnits - c.lowerUnits).toBeLessThanOrEqual(1n << BigInt(CP_GRID_BITS - 44));
      expect(c.upper).toBe(Number(c.upperUnits) / A); // the double is the dyadic exactly
      expect(c.upper).toBeGreaterThanOrEqual(k / n);
    }
  });

  it('cdfRec (the Lean recursion) agrees with the binomial sum', () => {
    for (const [n, k, p] of [[1, 0, 0.3], [5, 2, 0.5], [12, 4, 0.125], [40, 10, 0.2], [3, 3, 0.9]] as const) {
      const a = BigInt(Math.round(p * A));
      const N = cdfRecNumerator(n, k, a);
      const exact = Number((N << 60n) / (1n << BigInt(CP_GRID_BITS * n))) / 2 ** 60; // exact ratio, then rounded
      expect(exact).toBeCloseTo(binomialCdf(k, n, Number(a) / A), 12);
    }
    expect(cdfRecNumerator(4, 1, 0n)).toBe(1n << BigInt(4 * CP_GRID_BITS)); // q = 0: cdfRec = 1 (= A^4 / A^4)
    expect(cdfRecNumerator(4, 1, 2n ** 52n)).toBe(0n); // q = 1: count = 4 > 1
  });

  it('edge cases: k = n and n = 0 give 1; argument checks', () => {
    expect(clopperPearsonUpper(10, 10, 0.05)).toBe(1);
    expect(clopperPearsonUpper(0, 0, 0.05)).toBe(1);
    expect(() => clopperPearsonUpper(3, 2, 0.05)).toThrow();
    expect(() => clopperPearsonUpper(1, 2, 0)).toThrow();
    expect(() => doubleToDyadic(1)).toThrow();
    const d = doubleToDyadic(0.1);
    expect(Number(d.num) / 2 ** d.exp).toBe(0.1);
  });

  it('monotone: grows with k, shrinks with n, grows as α shrinks', () => {
    expect(clopperPearsonUpper(2, 20, 0.05)).toBeGreaterThan(clopperPearsonUpper(1, 20, 0.05));
    expect(clopperPearsonUpper(1, 40, 0.05)).toBeLessThan(clopperPearsonUpper(1, 20, 0.05));
    expect(clopperPearsonUpper(1, 20, 0.01)).toBeGreaterThan(clopperPearsonUpper(1, 20, 0.05));
  });
});
