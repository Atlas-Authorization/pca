import fc from 'fast-check';
import { describe, it } from 'vitest';
import {
  DEFAULT_SEED,
  admissionSoundnessProperty,
  cumulativeBudgetBoundProperty,
  riskMonotoneProperty,
} from './properties';

const R = (n: number): number => (process.env.PCA_INVARIANTS_RUNS ? Math.min(n, Number(process.env.PCA_INVARIANTS_RUNS)) : n); // fewer cases under mutation testing

const SEED = DEFAULT_SEED;

describe('PCA invariant 2: budget soundness', () => {
  it('risk functional is clamped to [0,S] and monotone in its inputs (2000 runs)', () => {
    fc.assert(riskMonotoneProperty(), { numRuns: R(2000), seed: SEED });
  });

  it('auto-admitted / metered cost κ·r is always covered by the budget (2000 runs)', () => {
    fc.assert(admissionSoundnessProperty(), { numRuns: R(2000), seed: SEED });
  });

  it('cumulative machine-only risk obeys Σr ≤ bMax/κ for any action sequence (1000 runs)', () => {
    fc.assert(cumulativeBudgetBoundProperty(), { numRuns: R(1000), seed: SEED });
  });
});
