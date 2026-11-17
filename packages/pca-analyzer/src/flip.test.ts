import { describe, expect, it } from 'vitest';
import { decideAction, minimalFlip, toModel, vetoesFromConstitution, type PolicyInput } from './index';
import { refund, refundShape } from './k2-fixtures';

const policy: PolicyInput = { predicates: [refund(500)], caveats: [] };
const big = { verb: 'stripe.refund', resource: '/acct/1', params: { amount: 900 } };
const who = { holderAuthenticated: true, schema: [refundShape] };

describe('minimalFlip', () => {
  it('lowers the amount to the largest admissible value and verifies it with the real decision', () => {
    const r = minimalFlip(policy, big, who);
    expect(r.current).toBe('deny');
    expect(r.repairs[0]).toMatchObject({ repair: { kind: 'set_param', param: 'amount', from: 900, to: 500 }, decision: 'allow' });
    expect(decideAction(toModel(policy), r.repairs[0]!.action)).toBe('allow');
    expect(r.repairExists).toBe(true);
  });

  it('offers another allowed resource, and a different enum value, when that is the fix', () => {
    const p: PolicyInput = { predicates: [{ verb: 'stripe.refund', resource: '/acct/1', where: [{ field: 'action.params.reason', op: 'in', value: ['fraud'] }] }] };
    const r = minimalFlip(p, { verb: 'stripe.refund', resource: '/acct/2', params: { reason: 'requested' } }, who);
    // neither edit alone is enough: the resource AND the reason are wrong
    expect(r.repairs[0]).toMatchObject({ repair: { kind: 'combine', steps: [{ kind: 'set_param', param: 'reason', to: 'fraud' }, { kind: 'set_resource', to: '/acct/1' }] }, cost: 5, decision: 'allow' });
    expect(decideAction(toModel(p), r.repairs[0]!.action)).toBe('allow');
    // with only one thing wrong, the single edit is returned
    const one = minimalFlip(p, { verb: 'stripe.refund', resource: '/acct/1', params: { reason: 'requested' } }, who);
    expect(one.repairs.map((x) => x.repair.kind)).toEqual(['set_param']);
  });

  it('nothing to do when already allowed', () => {
    expect(minimalFlip(policy, { ...big, params: { amount: 5 } }, who)).toMatchObject({ current: 'allow', repairs: [], repairExists: false });
  });

  it('refuses anyone but the authenticated holder, and rate-limits probing', () => {
    expect(minimalFlip(policy, big, { holderAuthenticated: false }).refused).toBe('counterfactuals are shown only to the authenticated holder');
    const probe = { limit: 2, windowSecs: 60, history: [1000, 2000], now: 3000 };
    expect(minimalFlip(policy, big, { ...who, probe }).refused).toBe('probe budget exhausted');
    const ok = minimalFlip(policy, big, { ...who, probe: { ...probe, now: 100_000 } });
    expect(ok.refused).toBeUndefined();
    expect(ok.probe?.history).toEqual([100_000]);
  });

  it('redacts the value of a critical parameter to "a repair exists"', () => {
    const schema = [{ ...refundShape, params: { ...refundShape.params, amount: { ...refundShape.params.amount!, sensitivity: 'critical' as const } } }];
    const r = minimalFlip(policy, big, { holderAuthenticated: true, schema });
    expect(r.redacted).toBe(true);
    expect(r.repairs[0]!.repair).toEqual({ kind: 'set_param', param: 'amount', redacted: true });
    expect(minimalFlip(policy, big, { holderAuthenticated: true, schema, redact: 'all' })).toMatchObject({ repairs: [], redacted: true, repairExists: true });
  });

  it('for an escalation: the cheapest human-free repair and the human ask', () => {
    const esc: PolicyInput = { ...policy, ...vetoesFromConstitution({ version: 1, principal: 'p', invariants: [{ kind: 'require_approval_over', id: 'big', when: { verb: 'stripe.refund' }, amount: 'action.params.amount', threshold: 200, approved: [] }] }) };
    const r = minimalFlip(esc, { ...big, params: { amount: 400 } }, who);
    expect(r.current).toBe('escalate');
    expect(r.humanFree).toMatchObject({ repair: { kind: 'set_param', to: 200 }, decision: 'allow' });
    expect(r.humanAsk).toMatchObject({ kind: 'approval', verb: 'stripe.refund', params: { amount: 400 } });
    // wanting only an escalation from a denial: lower to the nearest amount that escalates
    const e2 = minimalFlip(esc, big, { ...who, desired: 'escalate' });
    expect(e2.repairs[0]).toMatchObject({ repair: { to: 500 }, decision: 'escalate' });
  });

  it('a hard deny with no repair becomes an access request, not an invented fix', () => {
    const r = minimalFlip(policy, { verb: 'stripe.payout', resource: '/acct/1', params: { amount: 1 } }, who);
    expect(r.repairs).toEqual([]);
    expect(r.humanAsk).toMatchObject({ kind: 'access-request', verb: 'stripe.payout' });
  });

  it('waits for a time caveat to open, verified by the caveat evaluator', () => {
    const timed: PolicyInput = { predicates: [refund(500)], caveats: [{ type: 'not_before', at: 5000 }] };
    const r = minimalFlip(timed, { ...big, params: { amount: 5 } }, { ...who, caveatContext: { now: 1000, blastRadius: 0, reversibilityClass: 'reversible', recentActionTimes: [] } as never });
    expect(r.current).toBe('deny');
    expect(r.repairs).toEqual([{ repair: { kind: 'wait_until', at: 5000, reason: 'a time or rate caveat opens then' }, cost: 1, decision: 'allow', action: { verb: 'stripe.refund', resource: '/acct/1', params: { amount: 5 } } }]);
  });

  it('a rate window resets after its oldest action ages out', () => {
    const rate: PolicyInput = { predicates: [refund(500)], caveats: [{ type: 'rate', max: 2, per_secs: 60 }] };
    const r = minimalFlip(rate, { ...big, params: { amount: 5 } }, { ...who, caveatContext: { now: 100_000, blastRadius: 0, reversibilityClass: 'reversible', recentActionTimes: [70_000, 90_000] } as never });
    expect(r.repairs[0]!.repair).toMatchObject({ kind: 'wait_until', at: 130_000 });
  });

  it('splitting is opt-in and only when nothing meters the total', () => {
    const none = minimalFlip(policy, big, who).repairs.map((x) => x.repair.kind);
    expect(none).not.toContain('split');
    const s = minimalFlip(policy, big, { ...who, allowSplit: true }).repairs.find((x) => x.repair.kind === 'split');
    expect(s?.repair).toMatchObject({ kind: 'split', param: 'amount', parts: [{ amount: 500 }, { amount: 400 }] });
    const metered: PolicyInput = { predicates: [refund(500)], caveats: [{ type: 'rate', max: 2, per_secs: 60 }] };
    expect(minimalFlip(metered, big, { ...who, allowSplit: true }).repairs.map((x) => x.repair.kind)).not.toContain('split');
  });

  it('obtains a missing fact the policy reads', () => {
    const p: PolicyInput = { predicates: [{ verb: 'v', where: [{ field: 'subject.kyc', op: 'eq', value: 'done' }] }] };
    const r = minimalFlip(p, { verb: 'v', resource: '/r' }, { holderAuthenticated: true });
    expect(r.repairs[0]).toMatchObject({ repair: { kind: 'obtain_fact', path: 'subject.kyc', value: 'done' }, decision: 'allow' });
  });
});
