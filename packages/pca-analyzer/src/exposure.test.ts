import { describe, expect, it } from 'vitest';
import { compilePolicy, type prohibitions } from '@atlasauth/pca';
import { decideAction, delegationEnvelope, diffGate, diffPolicies, escalationSurface, findWithBackend, maxExposure, toModel, vetoesFromConstitution, type PolicyInput, type WitnessBackend } from './index';
import { refund } from './k2-fixtures';

const base: PolicyInput = { predicates: [refund(500)], caveats: [] };
const approvalOver200: prohibitions.Constitution = {
  version: 1,
  principal: 'p',
  invariants: [{ kind: 'require_approval_over', id: 'big', when: { verb: 'stripe.refund' }, amount: 'action.params.amount', threshold: 200, approved: [{ field: 'env.approved', op: 'eq', value: true }] }],
};

describe('maxExposure', () => {
  it('finds the attained ceiling with a verified witness', () => {
    const e = maxExposure(base, { verb: 'stripe.refund', integer: true });
    expect(e.perAction).toMatchObject({ admitted: true, max: 500, attained: true });
    expect(e.perAction.witness?.params?.amount).toBe(500);
    expect(decideAction(toModel(base), e.perAction.witness!)).toBe('allow');
    expect(e.window.bound).toBe(Infinity); // no rate limit, no window: only the per-action ceiling
  });

  it('is unbounded without a ceiling, and the schema ceiling then binds', () => {
    const open: PolicyInput = { predicates: [{ verb: 'stripe.refund' }], caveats: [] };
    expect(maxExposure(open, { verb: 'stripe.refund' }).perAction.max).toBe(Infinity);
    expect(maxExposure(open, { verb: 'stripe.refund', max: 1000 }).perAction).toMatchObject({ max: 1000, attained: true });
  });

  it('an exclusive bound is a supremum for a real, and the largest integer below it for an integer', () => {
    const lt: PolicyInput = { predicates: [{ verb: 'v', where: [{ field: 'action.params.amount', op: 'lt', value: 100 }] }] };
    expect(maxExposure(lt, { verb: 'v' }).perAction).toMatchObject({ max: 100, attained: false });
    expect(maxExposure(lt, { verb: 'v', integer: true }).perAction).toMatchObject({ max: 99, attained: true });
  });

  it('reports nothing admitted for a verb the policy never grants', () => {
    const e = maxExposure(base, { verb: 'stripe.payout' });
    expect(e.perAction.admitted).toBe(false);
    expect(e.window.bound).toBe(0);
  });

  it('composes the per-action ceiling with a rate limit over a window', () => {
    const p: PolicyInput = { predicates: [refund(500)], caveats: [{ type: 'rate', max: 3, per_secs: 86400 }] };
    const e = maxExposure(p, { verb: 'stripe.refund', integer: true, windowSecs: 86400 });
    expect(e.window).toMatchObject({ maxActions: 3, bound: 1500 });
    expect(e.window.basis).toContain('rate caveat 3/86400s');
    expect(e.window.sequence?.repeat).toBe(3);
    // over a week that is seven started periods
    expect(maxExposure(p, { verb: 'stripe.refund', integer: true, windowSecs: 7 * 86400 }).window.bound).toBe(10500);
  });

  it('budget_alloc bounds the amount in every budget model', () => {
    const p: PolicyInput = { predicates: [refund(500)], caveats: [{ type: 'budget_alloc', limit: 1200 }] };
    // dollars: an action costs its amount, so the allocation caps the total
    expect(maxExposure(p, { verb: 'stripe.refund', integer: true, budgetModel: 'dollars' }).window).toMatchObject({ bound: 1200, basis: ['per-action ceiling', 'budget_alloc limit 1200'], notApplied: [] });
    // risk: an action costs kappa * r (blast radius 0.5 for a refund in the catalog): 1200 / 50 = 24 actions of at most 500
    const risk = maxExposure(p, { verb: 'stripe.refund', integer: true, budgetModel: 'risk', kappa: 100, blastRadius: 0.5 }).window;
    expect(risk).toMatchObject({ maxActions: 24, bound: 12000, notApplied: [] });
    expect(risk.basis).toContain('budget_alloc 1200 / cost 50 = 24 actions');
    // a heavier verb exhausts the allocation sooner; zero blast radius never does
    expect(maxExposure(p, { verb: 'stripe.refund', integer: true, budgetModel: 'risk', kappa: 100, blastRadius: 1 }).window).toMatchObject({ maxActions: 12, bound: 6000 });
    expect(maxExposure(p, { verb: 'stripe.refund', integer: true, budgetModel: 'risk', kappa: 100, blastRadius: 0 }).window.bound).toBe(Infinity);
    expect(maxExposure(p, { verb: 'stripe.refund', integer: true, budgetModel: 'risk', kappa: 5000, blastRadius: 1 }).window).toMatchObject({ maxActions: 0, bound: 0 });
    // the risk model combines with a rate limit by taking the smaller count
    const rated: PolicyInput = { predicates: [refund(500)], caveats: [{ type: 'budget_alloc', limit: 1200 }, { type: 'rate', max: 2, per_secs: 3600 }] };
    expect(maxExposure(rated, { verb: 'stripe.refund', integer: true, budgetModel: 'risk', kappa: 100, blastRadius: 0.5, windowSecs: 3600 }).window).toMatchObject({ maxActions: 2, bound: 1000 });
    // no model and no kappa: it cannot be related to the amount, and is listed
    expect(maxExposure(p, { verb: 'stripe.refund', integer: true }).window).toMatchObject({ bound: Infinity, notApplied: ['budget_alloc 1200 (trust-budget units; pass budgetModel and kappa)'] });
    expect(maxExposure(p, { verb: 'stripe.refund', integer: true, budgetModel: 'risk' }).window.notApplied).toHaveLength(1);
  });

  it('reads the budget model and kappa from a compiled policy', () => {
    const c = compilePolicy({ permissions: { stripe: ['refund'] }, limits: { refund: '$500' } });
    const withAlloc = { ...c, caveats: [...c.caveats, { type: 'budget_alloc', limit: 1000 }] };
    const e = maxExposure(withAlloc, { verb: 'stripe.refund', integer: true });
    expect(e.window.notApplied).toEqual([]);
    expect(e.window.bound).toBeLessThanOrEqual(1000);
  });

  it('applies a universal cap invariant, and leaves out one that does not provably apply', () => {
    const c: prohibitions.Constitution = {
      version: 1,
      principal: 'p',
      invariants: [
        { kind: 'cap', id: 'daily', when: { verb: 'stripe.refund' }, amount: 'action.params.amount', max: 900, window_secs: 86400 },
        { kind: 'cap', id: 'acct9', when: { verb: 'stripe.refund', resource: '/acct/9' }, amount: 'action.params.amount', max: 10 },
      ],
    };
    const p: PolicyInput = { predicates: [refund(500)], caveats: [{ type: 'rate', max: 5, per_secs: 3600 }] };
    const e = maxExposure(p, { verb: 'stripe.refund', integer: true, windowSecs: 86400, constitution: c });
    expect(e.window.bound).toBe(900); // 5/h * 24h * 500 = 60000, cut to the daily cap
    expect(e.window.basis).toContain('cap invariant daily');
    expect(e.window.notApplied).toEqual(['acct9']);
  });

  it('separates the autonomous ceiling from the one with a human', () => {
    const e = maxExposure({ ...base, ...vetoesFromConstitution(approvalOver200) }, { verb: 'stripe.refund', integer: true });
    expect(e.perAction.max).toBe(500);
    expect(e.autonomousPerAction).toMatchObject({ max: 200, attained: true });
  });

  it('a hard veto removes the amounts it forbids', () => {
    const p: PolicyInput = { ...base, vetoes: [{ id: 'cap300', kind: 'deny', when: { verb: 'stripe.refund', where: [{ field: 'action.params.amount', op: 'gt', value: 300 }] } }] };
    expect(maxExposure(p, { verb: 'stripe.refund', integer: true }).perAction).toMatchObject({ max: 300, attained: true });
  });
});

describe('escalationSurface', () => {
  it('lists verified actions that need a human, none when nothing escalates', () => {
    const p: PolicyInput = { ...base, ...vetoesFromConstitution(approvalOver200) };
    const s = escalationSurface(p, { verb: 'stripe.refund' });
    expect(s.escalates).toBe(true);
    for (const w of s.witnesses) {
      expect(decideAction(toModel(p), w)).toBe('escalate');
      expect(w.params?.amount as number).toBeGreaterThan(200);
    }
    expect(escalationSurface(base).escalates).toBe(false);
  });

  it('a model tighten rule escalates and a deny rule does not count as escalation', () => {
    const p: PolicyInput = { ...base, tighten: [{ id: 'risky', when: { field: 'env.class.risk', op: 'eq', value: 'high' }, signal: 'escalate' }] };
    expect(escalationSurface(p).escalates).toBe(true);
    const d: PolicyInput = { ...base, tighten: [{ id: 'bad', when: { field: 'env.class.risk', op: 'eq', value: 'high' }, signal: 'deny' }] };
    expect(escalationSurface(d).escalates).toBe(false);
  });
});

describe('delegationEnvelope', () => {
  const root: PolicyInput = { predicates: [refund(500), { verb: 'stripe.list' }], caveats: [{ type: 'delegation_depth', max: 3 }] };
  const child: PolicyInput = { predicates: [refund(100)], caveats: [] };

  it('is the meet of the chain, with the remaining depth', () => {
    const env = delegationEnvelope([root, child]);
    expect(env.violations).toEqual([]);
    expect(env.verbs.map((v) => v.verb)).toEqual(['stripe.refund']);
    expect(env.depth).toEqual({ used: 1, allowed: 3, remaining: 2 });
    expect(env.anyVerb).toBe(false);
  });

  it('flags a child that is wider than its parent', () => {
    const wide: PolicyInput = { predicates: [refund(900), { verb: 'stripe.payout' }], caveats: [] };
    const env = delegationEnvelope([root, wide]);
    expect(env.violations).toEqual([1]);
    // yet the envelope is still capped by the parent: the payout verb is not reachable
    expect(env.verbs.map((v) => v.verb)).toEqual(['stripe.refund']);
  });
});

describe('diffPolicies', () => {
  it('widens: names the actions that moved from deny to allow', () => {
    const d = diffPolicies(base, { predicates: [refund(1000)] });
    expect(d.widens).toBe(true);
    expect(d.narrows).toBe(false);
    expect(d.equivalent).toBe(false);
    const moved = d.shifts['deny->allow']!;
    expect(moved.length).toBeGreaterThan(0);
    for (const a of moved) {
      expect(decideAction(toModel(base), a)).toBe('deny');
      expect(decideAction(toModel({ predicates: [refund(1000)] }), a)).toBe('allow');
    }
  });

  it('narrows, and an identical policy is equivalent', () => {
    const d = diffPolicies(base, { predicates: [refund(100)] });
    expect(d.widens).toBe(false);
    expect(d.narrows).toBe(true);
    expect(Object.keys(d.shifts)).toEqual(['allow->deny']);
    expect(diffPolicies(base, { predicates: [refund(500)] }).equivalent).toBe(true);
  });

  it('is ternary: a drop from allow to escalate is a tightening, escalate to allow a widening', () => {
    const esc: PolicyInput = { ...base, ...vetoesFromConstitution(approvalOver200) };
    const down = diffPolicies(base, esc);
    expect(Object.keys(down.shifts)).toEqual(['allow->escalate']);
    expect(down.widens).toBe(false);
    const up = diffPolicies(esc, base);
    expect(Object.keys(up.shifts)).toEqual(['escalate->allow']);
    expect(up.widens).toBe(true);
  });

  it('reports the exposure delta and gates on it', () => {
    const d = diffPolicies(base, { predicates: [refund(800)] }, { exposure: { verb: 'stripe.refund', integer: true } });
    expect(d.exposure).toMatchObject({ perActionDelta: 300, delta: 0 });
    expect(d.summary).toContain('max exposure of stripe.refund rises by 300');
    expect(diffGate(d).ok).toBe(false);
    expect(diffGate(d, { widen: true, maxExposureIncrease: 300 }).ok).toBe(true);
    expect(diffGate(diffPolicies(base, { predicates: [refund(100)] })).ok).toBe(true);
  });

  it('is inconclusive, never equivalent, when the grid overflows', () => {
    const d = diffPolicies(base, { predicates: [refund(500)] }, { maxCombinations: 1 });
    expect(d.approximate).toBe(true);
    expect(d.equivalent).toBe(false);
    expect(diffGate(d).ok).toBe(false);
  });
});

describe('solver backend (optional, never trusted)', () => {
  const q = { kind: 'reachable' as const, a: base, verb: 'stripe.refund' };
  it('accepts a witness the evaluator confirms', async () => {
    const b: WitnessBackend = { name: 'stub', find: async () => ({ witness: { verb: 'stripe.refund', resource: '/acct/1', params: { amount: 10 } } }) };
    expect((await findWithBackend(b, q)).witness?.params?.amount).toBe(10);
  });
  it('rejects a witness the evaluator refuses', async () => {
    const b: WitnessBackend = { name: 'liar', find: async () => ({ witness: { verb: 'stripe.refund', resource: '/acct/1', params: { amount: 99999 } } }) };
    expect(await findWithBackend(b, q)).toEqual({ rejected: true });
  });
  it('labels an unsat claim as unchecked', async () => {
    const b: WitnessBackend = { name: 'z3', find: async () => ({ unsat: true }) };
    expect(await findWithBackend(b, q)).toEqual({ claimedUnsat: { by: 'z3', proof: 'solver-claimed, not machine-checked' } });
  });
  it('differs: checks the witness against both policies', async () => {
    const b: WitnessBackend = { name: 'stub', find: async () => ({ witness: { verb: 'stripe.refund', resource: '/acct/1', params: { amount: 700 } } }) };
    const r = await findWithBackend(b, { kind: 'differs', a: base, b: { predicates: [refund(1000)] } });
    expect(r.witness?.params?.amount).toBe(700);
    expect(await findWithBackend(b, { kind: 'differs', a: base, b: base })).toEqual({ rejected: true });
  });
});
