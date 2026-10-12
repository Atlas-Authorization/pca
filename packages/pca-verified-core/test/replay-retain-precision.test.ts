import { describe, expect, it } from 'vitest';
import { replayRetainUntil, replayRetainUntilExact, type ReplayFacts } from '../src';

const facts = (exp: number, skew: number): ReplayFacts => ({
  nowOk: true, verifierAudOk: true, isObject: true, audMatches: true, iatOk: true, expOk: true,
  iat: 9007199254729192, exp, now: 9007199254740000, skew, leafOk: true, componentsOk: true, counterOk: true,
  hasNonce: false, nonceOk: false, requireNonce: true, hasCounters: false,
});

describe('retention horizon is exact (no silent rounding above 2^53)', () => {
  it('repro from the trusted-base cross-check: exact bigint, number API refuses', () => {
    const f = facts(9007199254730192, 60001);
    expect(replayRetainUntilExact(f)).toBe(9007199254730192n + 60001n); // ...790193
    expect(() => replayRetainUntil(f)).toThrow(RangeError);
  });
  it('safe results are unchanged', () => {
    expect(replayRetainUntil(facts(1000, 60000))).toBe(61000);
    const edge = facts(Number.MAX_SAFE_INTEGER - 60000, 60000);
    expect(replayRetainUntil(edge)).toBe(Number.MAX_SAFE_INTEGER);
    expect(() => replayRetainUntil(facts(Number.MAX_SAFE_INTEGER - 59999, 60000))).toThrow(RangeError);
  });
});
