/** 0.4.2 mutation kills for the toy lattice sharing: bounds, indices, the default sampler's arithmetic, negative coefficients, exact reasons. */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { type ExperimentalOptIn, TOY_DEFAULT_PARAMS, additiveShareLatticeKey, reconstructLatticeKey } from './lattice-threshold';

const OPT_IN: ExperimentalOptIn = { iUnderstandThisIsNotProduction: true };
const Q = TOY_DEFAULT_PARAMS.q;
const zero = () => 0n;

afterEach(() => vi.restoreAllMocks());

describe('additiveShareLatticeKey', () => {
  it('n is an integer in [1, 1024]: both ends are accepted, both neighbours refused with the exact reason', () => {
    const key = [1n, 2n, 3n, 4n];
    expect(additiveShareLatticeKey(key, 1, OPT_IN, TOY_DEFAULT_PARAMS, zero)).toHaveLength(1);
    expect(additiveShareLatticeKey(key, 1024, OPT_IN, TOY_DEFAULT_PARAMS, zero)).toHaveLength(1024);
    for (const n of [0, 1025, -1, 1.5, Number.NaN]) {
      expect(() => additiveShareLatticeKey(key, n, OPT_IN, TOY_DEFAULT_PARAMS, zero)).toThrow('additiveShareLatticeKey: n must be an integer in [1, 1024]');
    }
  });
  it('the key must have exactly params.dim coefficients (exact reason names the dimension)', () => {
    expect(() => additiveShareLatticeKey([1n], 2, OPT_IN)).toThrow('additiveShareLatticeKey: key must have 4 coefficients');
    expect(() => additiveShareLatticeKey([1n, 2n], 2, OPT_IN, { q: 97n, dim: 3 })).toThrow('additiveShareLatticeKey: key must have 3 coefficients');
  });
  it('indices are 1-based and consecutive', () => {
    expect(additiveShareLatticeKey([0n, 0n, 0n, 0n], 3, OPT_IN, TOY_DEFAULT_PARAMS, zero).map((s) => s.index)).toEqual([1, 2, 3]);
  });
  it('a negative key coefficient is reduced into [0, q) (n = 1 keeps the reduction visible)', () => {
    const [s] = additiveShareLatticeKey([-1n, -Q, -Q - 1n, 0n], 1, OPT_IN, TOY_DEFAULT_PARAMS, zero);
    expect(s!.coeffs).toEqual([Q - 1n, 0n, Q - 1n, 0n]);
    expect(reconstructLatticeKey([s!], OPT_IN)).toEqual([Q - 1n, 0n, Q - 1n, 0n]);
  });
  it('shares sum to the key mod q for a sampler that returns out-of-range and negative values', () => {
    const wild = (() => { let i = 0n; return () => (i++ % 2n === 0n ? -5n : 3n * Q + 7n); })();
    const key = [10n, 20n, 30n, 40n];
    const shares = additiveShareLatticeKey(key, 4, OPT_IN, TOY_DEFAULT_PARAMS, wild);
    expect(reconstructLatticeKey(shares, OPT_IN)).toEqual(key);
    for (const s of shares) for (const c of s.coeffs) expect(c >= 0n && c < Q).toBe(true);
  });
  it('the default sampler draws two 32-bit halves from Math.random: hi << 32 | lo, mod q', () => {
    const draws = [0.5, 0.25];
    let i = 0;
    vi.spyOn(Math, 'random').mockImplementation(() => draws[i++ % 2]!);
    const [a] = additiveShareLatticeKey([0n, 0n, 0n, 0n], 2, OPT_IN);
    const hi = 0x8000_0000n; // floor(0.5 * 2^32)
    const lo = 0x4000_0000n; // floor(0.25 * 2^32)
    expect(a!.coeffs[0]).toBe(((hi << 32n) | lo) % Q);
    expect(a!.coeffs[1]).toBe(((hi << 32n) | lo) % Q);
  });
});

describe('reconstructLatticeKey', () => {
  it('refuses no shares, a duplicate index, and a share of the wrong dimension, each with its exact reason', () => {
    expect(() => reconstructLatticeKey([], OPT_IN)).toThrow('reconstructLatticeKey: need at least one share');
    const s = { index: 1, coeffs: [1n, 2n, 3n, 4n] };
    expect(() => reconstructLatticeKey([s, s], OPT_IN)).toThrow('reconstructLatticeKey: duplicate share index');
    expect(() => reconstructLatticeKey([{ index: 1, coeffs: [1n, 2n] }], OPT_IN)).toThrow('reconstructLatticeKey: a share has the wrong dimension');
    expect(() => reconstructLatticeKey([{ index: 1, coeffs: [1n, 2n, 3n, 4n, 5n] }], OPT_IN)).toThrow('reconstructLatticeKey: a share has the wrong dimension');
  });
  it('sums every coefficient mod q', () => {
    const a = { index: 1, coeffs: [Q - 1n, 1n, 0n, 5n] };
    const b = { index: 2, coeffs: [2n, Q - 1n, 0n, 6n] };
    expect(reconstructLatticeKey([a, b], OPT_IN)).toEqual([1n, 0n, 0n, 11n]);
  });
});
