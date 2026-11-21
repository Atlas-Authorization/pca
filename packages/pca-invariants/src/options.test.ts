import { describe, expect, it } from 'vitest';
import { DEFAULT_NUM_RUNS, DEFAULT_SEED, INVARIANTS, checkInvariants } from './properties';

describe('checkInvariants options', () => {
  it.each([[0], [-1], [1.5], [Number.NaN], [Infinity], ['10' as never]])('numRuns %j is refused (a run of nothing would pass)', (numRuns) => {
    expect(() => checkInvariants({ numRuns })).toThrow('checkInvariants: numRuns must be a positive integer');
  });
  it.each([[1.5], [Number.NaN], [Infinity]])('seed %j is refused', (seed) => {
    expect(() => checkInvariants({ seed })).toThrow('checkInvariants: seed must be an integer');
  });
  it('defaults, names and result shape', () => {
    expect(DEFAULT_NUM_RUNS).toBe(1000);
    expect(DEFAULT_SEED).toBe(20260108);
    expect(new Set(INVARIANTS.map((i) => i.name)).size).toBe(INVARIANTS.length);
    const r = checkInvariants({ numRuns: 5, seed: 3 });
    expect(r.map((x) => x.name)).toEqual(INVARIANTS.map((i) => i.name));
    for (const x of r) expect(x).toEqual({ name: x.name, ok: true, numRuns: 5, seed: 3 });
  });
  it('the same seed gives the same outcome', () => {
    expect(checkInvariants({ numRuns: 20, seed: 11 })).toEqual(checkInvariants({ numRuns: 20, seed: 11 }));
  });
});
