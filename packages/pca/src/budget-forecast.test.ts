import { describe, expect, it } from 'vitest';
import { autonomyBoundOf, forecast, recommendPolicy } from './budget-forecast';
import { compilePolicy } from './facade';

describe('forecast', () => {
  it('drains the dollar budget and flags the first forced co-sign', () => {
    // $100/day refund budget: κ=100, bMax=100. Each $40 refund costs 40.
    const policy = compilePolicy({ permissions: { stripe: ['refund'] }, limits: { refund: '$100/day' }, now: 0 });
    const f = forecast(policy, [
      { verb: 'stripe.refund', resource: 'c:1', params: { amount: 40, currency: 'usd' }, at: 1 },
      { verb: 'stripe.refund', resource: 'c:2', params: { amount: 40, currency: 'usd' }, at: 2 },
      { verb: 'stripe.refund', resource: 'c:3', params: { amount: 40, currency: 'usd' }, at: 3 }, // budget can't cover
    ]);
    expect(f.steps[0]!.outcome).toBe('auto');
    expect(f.steps[2]!.outcome).toBe('step_up');
    expect(f.firstStepUpAt).toBe(2);
    expect(f.forcesCosign).toBe(true);
    expect(f.cosignsNeeded).toBe(1);
    expect(f.endBudget).toBeCloseTo(20, 5);
  });

  it('a plan within budget needs no co-sign', () => {
    const policy = compilePolicy({ permissions: { stripe: ['refund'] }, limits: { refund: '$100/day' }, now: 0 });
    const f = forecast(policy, [{ verb: 'stripe.refund', resource: 'c:1', params: { amount: 10, currency: 'usd' }, at: 1 }]);
    expect(f.forcesCosign).toBe(false);
    expect(f.firstStepUpAt).toBeUndefined();
  });
});

describe('recommendPolicy', () => {
  it('sizes bMax so N autonomous actions fit under the safety bound', () => {
    const rec = recommendPolicy(10, 0.2); // 10 actions of risk 0.2, κ=1
    expect(rec.kappa).toBe(1);
    expect(rec.bMax).toBeCloseTo(2, 6); // 10 × 0.2
    expect(rec.autonomousBound).toBeCloseTo(2, 6);
    // the recommended policy actually admits the target load
    const policy = compilePolicy({ permissions: { github: ['create_pr'] }, riskPolicy: { kappa: rec.kappa, bMax: rec.bMax, weights: { alpha: 0, beta: 0, gamma: 1, delta: 0, epsilon: 0, zeta: 0 }, theta1: 1, theta2: 1, lambda: 0 } });
    expect(autonomyBoundOf(policy.riskPolicy)).toBeCloseTo(2, 6);
  });

  it('scales with κ', () => {
    const rec = recommendPolicy(5, 0.5, { kappa: 100 });
    expect(rec.bMax).toBeCloseTo(250, 6); // 5 × 0.5 × 100
    expect(rec.autonomousBound).toBeCloseTo(2.5, 6);
  });
});
