import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { DEFAULT_SEED, checkInvariants, determinismProperty } from './properties';

const SEED = DEFAULT_SEED;

describe('PCA invariant 4: determinism', () => {
  it('verify / decide / score the same input twice yields identical results (1000 runs)', () => {
    fc.assert(determinismProperty(), { numRuns: 1000, seed: SEED });
  });
});

describe('checkInvariants() runner (public API)', () => {
  it('every PCA safety invariant holds under the reusable runner', () => {
    const results = checkInvariants({ numRuns: 1000, seed: SEED });
    const failures = results.filter((r) => !r.ok);
    expect(failures, failures.map((f) => `${f.name}: ${f.error ?? ''}`).join('\n')).toEqual([]);
    expect(results.length).toBeGreaterThanOrEqual(11);
  });
});
