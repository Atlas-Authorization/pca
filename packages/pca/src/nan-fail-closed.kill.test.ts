import { describe, expect, it } from 'vitest';
import { debitConsolidated, debitConsolidatedPath, leak, subBudget } from './risk';

const BAD = [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY];

// NaN compares false in every direction, so a "refuse when over" check written as `a > b` admits it: each refusal here must read as the
// negation of its positive condition.
describe('a non-finite number never admits (budget code)', () => {
  it.each(BAD)('leak: a clock or stamp of %s depletes the budget', (bad) => {
    expect(leak({ B: 1, tau: 0 }, bad, 1).B).toBe(0);
    expect(leak({ B: 1, tau: bad }, 1000, 1).B).toBe(0);
    expect(leak({ B: 1, tau: 0, asOf: bad }, 1000, 1).B).toBe(0);
  });
  it('subBudget refuses a NaN parent budget; debitConsolidated refuses a NaN sub or parent budget', () => {
    expect(subBudget({ B: Number.NaN, tau: 0 }, 1).ok).toBe(false);
    expect(debitConsolidated({ B: 5, tau: 0 }, { B: Number.NaN, tau: 0 }, 1).ok).toBe(false);
    expect(debitConsolidated({ B: Number.NaN, tau: 0 }, { B: 5, tau: 0 }, 1).ok).toBe(false);
    expect(debitConsolidatedPath([{ B: 5, tau: 0 }, { B: Number.NaN, tau: 0 }], 1).ok).toBe(false);
  });
});
