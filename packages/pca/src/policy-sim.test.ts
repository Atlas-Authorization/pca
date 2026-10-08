import { describe, expect, it } from 'vitest';
import { compilePolicy } from './facade';
import { lintPolicy, simulate } from './policy-sim';

describe('simulate', () => {
  it('classifies auto / step_up / deny and threads the dollar budget', () => {
    // $100/day refund budget: κ=100, bMax=100. Each $40 refund costs 40 budget.
    const policy = compilePolicy({ permissions: { stripe: ['refund'] }, limits: { refund: '$100/day' }, now: 0 });
    const rep = simulate(policy, [
      { verb: 'stripe.refund', resource: 'charge:1', params: { amount: 40, currency: 'usd' }, at: 1 }, // auto, B 100→60
      { verb: 'stripe.refund', resource: 'charge:2', params: { amount: 40, currency: 'usd' }, at: 2 }, // auto, B 60→20
      { verb: 'stripe.refund', resource: 'charge:3', params: { amount: 40, currency: 'usd' }, at: 3 }, // budget can't cover → step_up
      { verb: 'stripe.refund', resource: 'charge:4', params: { amount: 500, currency: 'usd' }, at: 4 }, // over cap → deny
      { verb: 'stripe.payout', resource: 'acct:1', params: { amount: 1 }, at: 5 }, // ungranted → deny
    ]);
    expect(rep.results[0]!.outcome).toBe('auto');
    expect(rep.results[1]!.outcome).toBe('auto');
    expect(rep.results[2]!.outcome).toBe('step_up');
    expect(rep.results[3]!.outcome).toBe('deny');
    expect(rep.results[4]!.outcome).toBe('deny');
    expect(rep.auto).toBe(2);
    expect(rep.endBudget).toBeCloseTo(20, 5);
    // safety theorem: machine-only risk ≤ bMax/κ = 1
    expect(rep.autonomousRisk).toBeLessThanOrEqual(policy.riskPolicy.bMax / policy.riskPolicy.kappa + 1e-9);
  });

  it('replays in time order regardless of input order', () => {
    const policy = compilePolicy({ permissions: { gmail: ['send'] }, now: 0 });
    const rep = simulate(policy, [
      { verb: 'gmail.send', resource: 'm:2', at: 20 },
      { verb: 'gmail.send', resource: 'm:1', at: 10 },
    ]);
    expect(rep.results.map((r) => r.action.resource)).toEqual(['m:1', 'm:2']);
  });
});

describe('lintPolicy', () => {
  it('flags an unmatched limit as an error', () => {
    const policy = compilePolicy({ permissions: { stripe: ['refund'] }, limits: { charge: '$10' } });
    expect(lintPolicy(policy).some((l) => l.code === 'limit-unmatched' && l.level === 'error')).toBe(true);
  });

  it('warns on an unbounded money action and a broad irreversible resource', () => {
    const policy = compilePolicy({ permissions: { stripe: ['payout'], files: ['delete'] } });
    const codes = lintPolicy(policy).map((l) => l.code);
    expect(codes).toContain('money-unbounded'); // payout has no limit
    expect(codes).toContain('broad-resource'); // files.delete irreversible, resource '*'
  });

  it('warns that irreversible actions auto-admit when theta2 ≥ 1 (dollars model)', () => {
    const policy = compilePolicy({ permissions: { stripe: ['payout'] }, limits: { payout: '$50' } });
    const l = lintPolicy(policy).find((x) => x.code === 'no-step-up-band');
    expect(l?.level).toBe('warn'); // payout is irreversible
  });

  it('is quiet on a tight, well-bounded policy', () => {
    const policy = compilePolicy({ permissions: { gmail: ['draft'] } }); // reversible, risk model (theta2<1)
    expect(lintPolicy(policy).filter((l) => l.level === 'error')).toHaveLength(0);
  });
});
