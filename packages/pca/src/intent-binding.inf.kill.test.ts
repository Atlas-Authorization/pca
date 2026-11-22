import { describe, expect, it } from 'vitest';
import { b64u } from './hash';
import { decideIntentBinding, intentGoalCommit, type EnvelopeIntent } from './intent-binding';

const D1 = b64u(new Uint8Array(32).fill(1));
const D2 = b64u(new Uint8Array(32).fill(2));
const I: EnvelopeIntent = { ref: D1, map_digest: D2, goal_salt: 's', fidelity_ppm: 500_000, residual_risk_ppm: 10 };
const G = { caveats: [{ type: 'envelope', goal_commit: intentGoalCommit(I) }] };
const BAD = [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY];

describe('a non-finite claimed fidelity or risk never passes a threshold (intent-binding)', () => {
  it('the example passes both thresholds', () => {
    expect(decideIntentBinding(I, G, { min_fidelity_ppm: 100, max_residual_risk_ppm: 100 }).status).toBe('pass');
  });
  // old `x >= min` was true for +Infinity fidelity
  it.each(BAD)('a fidelity of %s fails the minimum', (fidelity_ppm) => {
    expect(decideIntentBinding({ ...I, fidelity_ppm }, G, { min_fidelity_ppm: 100 }).status).toBe('fail');
  });
  // old `x <= max` was true for -Infinity residual risk
  it.each(BAD)('a residual risk of %s fails the maximum', (residual_risk_ppm) => {
    expect(decideIntentBinding({ ...I, residual_risk_ppm }, G, { max_residual_risk_ppm: 100 }).status).toBe('fail');
  });
});
