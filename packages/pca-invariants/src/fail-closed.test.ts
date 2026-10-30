import fc from 'fast-check';
import { describe, it } from 'vitest';
import {
  DEFAULT_SEED,
  forgedChainRejectedProperty,
  garbageChainRejectedProperty,
  memberOfCycleSafeProperty,
  undecidableGroupsFailClosedProperty,
  undecidableLeafFailsClosedProperty,
  unknownCaveatTypeDeniesProperty,
} from './properties';

const R = (n: number): number => (process.env.PCA_INVARIANTS_RUNS ? Math.min(n, Number(process.env.PCA_INVARIANTS_RUNS)) : n); // fewer cases under mutation testing

const SEED = DEFAULT_SEED;

describe('PCA invariant 3: fail-closed', () => {
  it('undecidable leaf conditions never grant (2000 runs)', () => {
    fc.assert(undecidableLeafFailsClosedProperty(), { numRuns: R(2000), seed: SEED });
  });

  it('undecidable / empty boolean groups fail closed (1000 runs)', () => {
    fc.assert(undecidableGroupsFailClosedProperty(), { numRuns: R(1000), seed: SEED });
  });

  it('member_of over a cyclic adjacency terminates with a correct, fail-closed verdict (1000 runs)', () => {
    fc.assert(memberOfCycleSafeProperty(), { numRuns: R(1000), seed: SEED });
  });

  it('an unknown caveat type is never satisfied (2000 runs)', () => {
    fc.assert(unknownCaveatTypeDeniesProperty(), { numRuns: R(2000), seed: SEED });
  });

  it('forged / mutated chains never verify (nine distinct attacks, 1000 runs)', () => {
    fc.assert(forgedChainRejectedProperty(), { numRuns: R(1000), seed: SEED });
  });

  it('never-signed / empty chains never verify (2000 runs)', () => {
    fc.assert(garbageChainRejectedProperty(), { numRuns: R(2000), seed: SEED });
  });
});
