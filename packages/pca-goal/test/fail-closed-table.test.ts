// The README "Fail-closed behaviour" table as exact-outcome tests: each row is a missing or invalid X and the whole result.
import { describe, expect, it } from 'vitest';
import { REVIEW_LIMITS, alphaOf, assertMonotone, calibrate, effectiveLimits, goalDomain, signGoalArtifact, signPayload, signerId, verifyGoalArtifact, verifyPayload } from '../src';

const secret = new Uint8Array(32).fill(7);
const other = new Uint8Array(32).fill(9);

describe('signed artifacts verify only against a pinned signer', () => {
  const art = signGoalArtifact('thing', { signer: signerId(secret), n: 1 }, secret);
  it('the pinned signer verifies; no pin, a wrong pin, another kind, a tampered body and a non-object do not', () => {
    expect(verifyGoalArtifact('thing', art, 'signer', [signerId(secret)])).toBe(true);
    expect(verifyGoalArtifact('thing', art, 'signer', [])).toBe(false);
    expect(verifyGoalArtifact('thing', art, 'signer', [signerId(other)])).toBe(false);
    expect(verifyGoalArtifact('other-kind', art, 'signer', [signerId(secret)])).toBe(false);
    expect(verifyGoalArtifact('thing', { ...art, n: 2 }, 'signer', [signerId(secret)])).toBe(false);
    expect(verifyGoalArtifact('thing', { ...art, signer: undefined }, 'signer', [signerId(secret)])).toBe(false);
    expect(verifyGoalArtifact('thing', null, 'signer', [signerId(secret)])).toBe(false);
    expect(verifyGoalArtifact('thing', [art], 'signer', [signerId(secret)])).toBe(false);
    expect(verifyGoalArtifact('thing', 'x', 'signer', [signerId(secret)])).toBe(false);
  });
  it('the domain is per kind and an out-of-profile number is refused at signing', () => {
    expect(goalDomain('thing')).toBe('atlas-pca/goal/thing/v1\0');
    // the strict profile admits short plain decimals (1.5) but not these: unsafe integer, sub-1e-6 magnitude, non-finite
    for (const n of [2 ** 60, 1e-7, Number.NaN]) expect(() => signGoalArtifact('thing', { signer: signerId(secret), n }, secret)).toThrow();
    expect(signGoalArtifact('thing', { signer: signerId(secret), n: 1.5 }, secret).sig).toEqual(expect.any(String));
  });
  it('a payload envelope verifies only for its own kind and version', () => {
    const s = signPayload('k', { a: 1 }, secret);
    expect(verifyPayload(s, 'k', [signerId(secret)])).toBe(true);
    expect(verifyPayload(s, 'j', [signerId(secret)])).toBe(false);
    expect(verifyPayload({ ...s, v: 2 as never }, 'k', [signerId(secret)])).toBe(false);
    expect(verifyPayload(null as never, 'k', [signerId(secret)])).toBe(false);
    expect(verifyPayload({ ...s, payload: { a: 2 } }, 'k', [signerId(secret)])).toBe(false);
  });
});

describe('reviewer limits only tighten', () => {
  it('a larger, negative, fractional or non-numeric override is ignored; a smaller one applies; the defaults are pinned', () => {
    expect(REVIEW_LIMITS).toEqual({ max_grants: 32, max_prohibits: 64, max_bounds: 32, max_escalate_on: 32, max_examples: 40, max_card_lines: 200, max_card_bytes: 24_576, max_diff_changes: 60, max_diff_widenings: 12, max_witnesses: 20 });
    expect(effectiveLimits({ max_grants: 33 })).toEqual(REVIEW_LIMITS);
    expect(effectiveLimits({ max_grants: 1.5 })).toEqual(REVIEW_LIMITS);
    expect(effectiveLimits({ max_grants: '3' as never })).toEqual(REVIEW_LIMITS);
    expect(effectiveLimits({ max_grants: 0 }).max_grants).toBe(0);
    expect(effectiveLimits({ max_examples: 5 })).toEqual({ ...REVIEW_LIMITS, max_examples: 5 });
  });
});

describe('calibration refuses malformed losses and is conservative when infeasible', () => {
  it('non-binary or non-monotone losses throw with the case and level', () => {
    expect(() => assertMonotone([[0, 2]])).toThrow('loss must be 0 or 1 (case 0)');
    expect(() => assertMonotone([[1, 0], [0, 1]])).toThrow('loss is not nonincreasing in the threshold (case 1, level 1)');
    expect(() => calibrate([], alphaOf(0.1))).toThrow('calibrate: no levels');
  });
  it('with too few cases the top (escalate-all) level is chosen and reported infeasible', () => {
    expect(calibrate([[1, 1, 0]], alphaOf(0.1))).toEqual({ level: 2, n: 1, feasible: false, correctedRisk: 1 / 2, minN: 9 });
  });
  it('a gate can only make the choice more conservative', () => {
    const losses = Array.from({ length: 20 }, () => [0, 0]);
    expect(calibrate(losses, alphaOf(0.2)).level).toBe(0);
    expect(calibrate(losses, alphaOf(0.2), (_k, _n) => false)).toMatchObject({ level: 1, feasible: false });
  });
});
