import fc from 'fast-check';
import { describe, it } from 'vitest';
import { DEFAULT_SEED, attenuationMonotonicityProperty } from './properties';

const SEED = DEFAULT_SEED;

describe('PCA invariant 1: attenuation monotonicity', () => {
  it('a delegate step can only shrink or preserve authority, never widen it (1000 runs)', () => {
    // Verifies: chain verifies; caveats are an append-only prefix extension at every hop;
    // budget_alloc limits are monotone non-increasing; and for every probe point the per-hop
    // "allowed" verdict never goes false -> true down the chain (leaf authority ⊆ ancestors').
    fc.assert(attenuationMonotonicityProperty(), { numRuns: 1000, seed: SEED });
  });
});
