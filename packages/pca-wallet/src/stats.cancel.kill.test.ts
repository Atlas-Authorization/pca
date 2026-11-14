import { describe, expect, it } from 'vitest';
import { betaInc } from './index';

describe('betaInc when the continued-fraction terms cancel exactly in double precision', () => {
  // With a + b beyond 2^53 the first Lentz terms 1 - (a+b)x/(a+1), 1 + aa*d and 1 + aa/c round to exactly zero. The
  // continued fraction must clamp them to a tiny value (not divide by zero), so the result stays a finite number.
  it.each([
    [3e-17, 0.5, 5e16],
    [1.5e-17, 0.5, 1e17],
    [1.5e-18, 0.5, 1e18],
  ])('betaInc(%s, %s, %s) is finite and close to one', (x, a, b) => {
    const v = betaInc(x, a, b);
    expect(Number.isNaN(v)).toBe(false);
    expect(Number.isFinite(v)).toBe(true);
    expect(v).toBeGreaterThan(0.99);
    expect(v).toBeLessThan(1.01);
  });
});
