import { describe, expect, it } from 'vitest';
import { betacf } from './stats';

// Inputs where a Lentz denominator comes out exactly zero; without the 1e-300 replacement the result is NaN.
describe('betacf zero-denominator guards', () => {
  it('replaces a zero d (1, 4, 0.5: d = 1 - 0.25 * 4 = 0 at the first step) and still converges', () => {
    // I_0.5(1, 4) = 1 - 0.5^4 and the prefactor is 0.125, so the fraction is 7.5.
    expect(betacf(1, 4, 0.5)).toBeCloseTo(7.5, 12);
  });
  it('replaces a zero c (3, 20, x: c is exactly zero at the fourth step) and returns a finite value', () => {
    const v = betacf(3, 20, 0.9963745089231938);
    expect(Number.isFinite(v)).toBe(true);
    expect(v).toBeCloseTo(879722502270062.8, 0);
  });
});
