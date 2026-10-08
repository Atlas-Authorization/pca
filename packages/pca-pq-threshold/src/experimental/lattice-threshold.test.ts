import { describe, expect, it } from 'vitest';
import {
  EXPERIMENTAL_BANNER,
  type ExperimentalOptIn,
  RACCOON_DESIGN,
  TOY_DEFAULT_PARAMS,
  additiveShareLatticeKey,
  reconstructLatticeKey,
} from './lattice-threshold';

const OPT_IN: ExperimentalOptIn = { iUnderstandThisIsNotProduction: true };

// A deterministic toy coefficient sampler so the reconstruction test is reproducible.
function seededSampler(): (q: bigint) => bigint {
  let state = 0x12345678n;
  return (q: bigint) => {
    state = (state * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n);
    const r = state % q;
    return r < 0n ? r + q : r;
  };
}

describe('experimental lattice-threshold prototype (NOT PRODUCTION)', () => {
  it('carries a loud NOT-PRODUCTION banner and a frozen research design', () => {
    expect(EXPERIMENTAL_BANNER).toMatch(/NOT PRODUCTION/);
    expect(RACCOON_DESIGN.productionReady).toBe(false);
    expect(RACCOON_DESIGN.status).toBe('research-prototype');
    expect(RACCOON_DESIGN.banner).toMatch(/NOT PRODUCTION/);
    expect(RACCOON_DESIGN.construction.length).toBeGreaterThan(0);
    expect(RACCOON_DESIGN.shippableAlternative).toMatch(/HYBRID/);
    expect(Object.isFrozen(RACCOON_DESIGN)).toBe(true);
  });

  it('is gated behind the explicit opt-in flag: a non-true flag throws the banner', () => {
    const key = [1n, 2n, 3n, 4n];
    const notOptedIn: ExperimentalOptIn = { iUnderstandThisIsNotProduction: false };
    expect(() => additiveShareLatticeKey(key, 3, notOptedIn)).toThrow(/NOT PRODUCTION/);
    const shares = additiveShareLatticeKey(key, 3, OPT_IN, TOY_DEFAULT_PARAMS, seededSampler());
    expect(() => reconstructLatticeKey(shares, notOptedIn)).toThrow(/NOT PRODUCTION/);
  });

  it('reconstruct works in-toy: summing all additive shares recovers the key (mod q)', () => {
    const key = [123n, 8380416n, 0n, 42n];
    const n = 4;
    const shares = additiveShareLatticeKey(key, n, OPT_IN, TOY_DEFAULT_PARAMS, seededSampler());
    expect(shares).toHaveLength(n);
    for (const s of shares) expect(s.coeffs).toHaveLength(TOY_DEFAULT_PARAMS.dim);

    const recovered = reconstructLatticeKey(shares, OPT_IN);
    expect(recovered).toEqual(key.map((c) => ((c % TOY_DEFAULT_PARAMS.q) + TOY_DEFAULT_PARAMS.q) % TOY_DEFAULT_PARAMS.q));
  });

  it('is additive n-of-n: a MISSING share does not reconstruct the key (not a true t-of-n)', () => {
    const key = [7n, 7n, 7n, 7n];
    const shares = additiveShareLatticeKey(key, 3, OPT_IN, TOY_DEFAULT_PARAMS, seededSampler());
    const recovered = reconstructLatticeKey(shares.slice(0, 2), OPT_IN); // drop one share
    expect(recovered).not.toEqual(key);
  });
});
