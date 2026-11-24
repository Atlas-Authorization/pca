import { describe, expect, it } from 'vitest';
import { validateWindow } from './optimistic';

describe('a non-finite clock or bound never admits a challenge window (optimistic)', () => {
  // old `windowMs < min` / `> max` / `|d| > skew` were false for a NaN policy bound, so any window passed
  it.each(['minWindowMs', 'maxWindowMs', 'maxSkewMs'] as const)('a NaN policy %s refuses the window', (k) => {
    const pol = { minWindowMs: 1000, maxWindowMs: 100_000, defaultWindowMs: 5000, maxSkewMs: 500, [k]: Number.NaN };
    expect(validateWindow(10_000, 5000, 10_000, pol)).not.toBeNull();
  });
  it.each([Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])('a server clock of %s is refused', (now) => {
    expect(validateWindow(10_000, 5000, now)).toBe('server time is not finite');
  });
});
