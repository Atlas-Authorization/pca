import { describe, expect, it } from 'vitest';
import type { ActionContext } from '@atlasauth/pca';
import { decideAction, evalFilter, evalUcast, evaluateResidual, residual, residualPolicy, toFilter, toModel, whatMayIDo, type PolicyInput, type Veto } from './index';
import { refund, refundShape, rng } from './k2-fixtures';

const base: PolicyInput = { predicates: [refund(500)], caveats: [] };
const approval: Veto = { id: 'big', kind: 'approval', when: { verb: 'stripe.refund' }, over: { path: 'action.params.amount', threshold: 200 }, unless: [{ field: 'env.approved', op: 'eq', value: true }] };

describe('residual', () => {
  it('specialises to the verb and leaves the unknown parameter symbolic', () => {
    const r = residual(base, { verb: 'stripe.refund', resource: '/acct/7' });
    expect(r.decision).toBe('conditional');
    expect(r.policy.predicates).toEqual([{ verb: '*', where: [{ field: 'action.params.amount', op: 'lte', value: 500 }] }]);
  });

  it('is never when the known facts rule every clause out', () => {
    expect(residual(base, { verb: 'stripe.payout' }).decision).toBe('never');
    expect(residual(base, { verb: 'stripe.refund', resource: '/other/1' }).decision).toBe('never');
    expect(residual({ predicates: [refund()], caveats: [{ type: 'not_before', at: 10 }, { type: 'expires', at: 5 }] }, { verb: 'stripe.refund' }).reason).toMatch(/caveats unsatisfiable/);
  });

  it('folds known parameters: closed world, then always / never', () => {
    expect(residual(base, { verb: 'stripe.refund', params: { amount: 400 } }, { unknown: [] }).decision).toBe('always');
    expect(residual(base, { verb: 'stripe.refund', params: { amount: 600 } }, { unknown: [] }).decision).toBe('never');
    // an unset parameter is absent in a closed world, and absent fails closed
    expect(residual(base, { verb: 'stripe.refund' }, { unknown: [] }).decision).toBe('never');
  });

  it('an unknown that reaches a veto keeps the veto (never prunes it)', () => {
    const p: PolicyInput = { ...base, vetoes: [{ id: 'cap300', kind: 'deny', when: { verb: 'stripe.refund', where: [{ field: 'action.params.amount', op: 'gt', value: 300 }] } }] };
    const r = residual(p, { verb: 'stripe.refund' });
    expect(r.decision).toBe('conditional');
    expect(r.policy.vetoes).toHaveLength(1);
    expect(r.policy.vetoes[0]!.when.where).toEqual([{ field: 'action.params.amount', op: 'gt', value: 300 }]);
    // a veto that is certain for the known facts makes the whole thing never
    const certain: PolicyInput = { ...base, vetoes: [{ id: 'frozen', kind: 'deny', when: { verb: 'stripe.refund', resource: '/acct/frozen*' } }] };
    expect(residual(certain, { verb: 'stripe.refund', resource: '/acct/frozen1' }).reason).toBe('veto frozen applies to every completion');
    expect(residual(certain, { verb: 'stripe.refund', resource: '/acct/ok' }).policy.vetoes).toEqual([]);
  });

  it('carries the digest of the original policy', () => {
    const a = residual(base, { verb: 'stripe.refund' }).policyDigest;
    expect(a).toBe(residual(base, { verb: 'stripe.payout' }).policyDigest);
    expect(a).not.toBe(residual({ predicates: [refund(501)] }, { verb: 'stripe.refund' }).policyDigest);
  });

  it('a delegation chain keeps every ancestor', () => {
    const chain: PolicyInput = { predicates: [refund(100)], meet: [{ predicates: [refund(500)] }] };
    const r = residual(chain, { verb: 'stripe.refund' });
    expect(r.policy.meet).toHaveLength(1);
    expect(evaluateResidual(r, { action: { verb: 'stripe.refund', resource: '/acct/1', params: { amount: 100 } } })).toBe('allow');
    expect(evaluateResidual(r, { action: { verb: 'stripe.refund', resource: '/acct/1', params: { amount: 101 } } })).toBe('deny');
  });
});

describe('residual is exact (property test against the real evaluator)', () => {
  const policies: PolicyInput[] = [
    base,
    {
      predicates: [
        { verb: ['stripe.refund', 'stripe.charge'], resource: '/acct/*', where: [{ field: 'action.params.amount', op: 'lte', value: 500 }, { any_of: [{ field: 'action.params.reason', op: 'in', value: ['fraud', 'duplicate'] }, { not: { field: 'action.params.reason', op: 'exists' } }] }] },
        { verb: 'stripe.refund', where: [{ field: 'subject.tier', op: 'eq', value: 'gold' }, { field: 'action.params.amount', op: 'lt', value: 5000 }] },
      ],
      caveats: [],
      vetoes: [
        { id: 'frozen', kind: 'deny', when: { verb: 'stripe.refund', resource: '/acct/frozen*' } },
        { id: 'huge', kind: 'deny', when: { verb: '*', where: [{ field: 'action.params.amount', op: 'gt', value: 4000 }] } },
        approval,
      ],
      tighten: [{ id: 'risky', when: { field: 'env.class.risk', op: 'eq', value: 'high' }, signal: 'escalate' }],
    },
  ];
  const known = [
    { verb: 'stripe.refund', resource: '/acct/1' },
    { verb: 'stripe.refund', resource: '/acct/frozen9' },
    { verb: 'stripe.charge', resource: '/acct/2' },
    { verb: 'stripe.refund', resource: '/acct/3', subject: { tier: 'gold' } },
    { verb: 'stripe.refund', resource: '/acct/3', subject: { tier: 'gold' }, env: { class: { risk: 'high' } } },
  ];
  it('the residual decides exactly what the original decides, for every completion of the unknown parameters', () => {
    const rand = rng(7);
    const amounts = [undefined, -1, 0, 1, 199, 200, 201, 499, 500, 501, 3999, 4000, 4001, 'x'];
    const reasons = [undefined, 'fraud', 'duplicate', 'other'];
    let checked = 0;
    for (const policy of policies) {
      for (const k of known) {
        const res = residual(policy, k);
        const full = toModel(policy);
        for (let i = 0; i < 60; i++) {
          const params: Record<string, unknown> = {};
          const a = amounts[Math.floor(rand() * amounts.length)];
          const r = reasons[Math.floor(rand() * reasons.length)];
          if (a !== undefined) params.amount = a;
          if (r !== undefined) params.reason = r;
          const ctx: ActionContext = { action: { verb: k.verb, resource: k.resource, params }, subject: (k as { subject?: object }).subject as Record<string, unknown>, env: (k as { env?: object }).env as Record<string, unknown> };
          const want = decideAction(full, { verb: k.verb, resource: k.resource, params, subject: ctx.subject, env: ctx.env });
          expect(evaluateResidual(res, ctx)).toBe(want);
          // residual(G) is a subset of admits(G): whatever the residual allows, the original allows
          if (evaluateResidual(res, ctx) !== 'deny') expect(want).not.toBe('deny');
          checked++;
        }
      }
    }
    expect(checked).toBe(600);
  });

  it('the residual policy is itself a policy the analyzer can analyse', () => {
    const rp = residualPolicy(residual(policies[1]!, { verb: 'stripe.refund', resource: '/acct/1' }));
    expect(toModel(rp).predicates.length).toBeGreaterThan(0);
  });
});

describe('whatMayIDo (capability discovery)', () => {
  it('returns the allowed parameter domains and the policy digest', () => {
    const [e] = whatMayIDo(base, [refundShape], {});
    expect(e).toMatchObject({ verb: 'stripe.refund', status: 'autonomous', advisory: true });
    expect(e!.params.amount).toEqual({ kind: 'numeric', autonomous: [{ lo: 0, loInclusive: true, hi: 500, hiInclusive: true }], withApproval: [] });
    expect(e!.policyDigest).toBe(residual(base, { verb: 'stripe.refund' }).policyDigest);
  });

  it('shows the approval threshold and the enum values', () => {
    const p: PolicyInput = { predicates: [{ verb: 'stripe.refund', where: [{ field: 'action.params.amount', op: 'lte', value: 500 }, { field: 'action.params.reason', op: 'in', value: ['fraud', 'duplicate'] }] }], vetoes: [approval] };
    const [e] = whatMayIDo(p, [refundShape], {});
    expect(e!.status).toBe('autonomous');
    const amount = e!.params.amount;
    expect(amount).toMatchObject({ kind: 'numeric', autonomous: [{ lo: 0, loInclusive: true, hi: 200, hiInclusive: true }], withApproval: [{ lo: 200, hi: 500, hiInclusive: true }] });
    expect(e!.params.reason).toEqual({ kind: 'enum', autonomous: ['duplicate', 'fraud'], withApproval: [], otherAutonomous: false, otherWithApproval: false });
  });

  it('denied for a verb the policy does not grant, with the reason; passes through budget and discharges', () => {
    const [pay] = whatMayIDo(base, [{ verb: 'stripe.payout', params: {} }], {}, { remaining: { usd: 40 }, missingDischarges: ['compliance'] });
    expect(pay).toMatchObject({ status: 'denied', remaining: { usd: 40 }, missingDischarges: ['compliance'] });
    expect(pay!.reason).toBe('no permit survives the known facts');
  });

  it('a regex resource makes the answer approximate rather than wrong', () => {
    const [e] = whatMayIDo({ predicates: [{ verb: 'stripe.refund', resource: 're:/acct/[0-9]+' }] }, [{ verb: 'stripe.refund', params: {} }], {});
    expect(e!.approximate).toBe(true);
  });
});

describe('toFilter (residual to SQL)', () => {
  const cols = { 'action.resource': 'id', 'action.params.amount': 'amount' };
  it('compiles to a parameterized WHERE fragment', () => {
    const f = toFilter(residual(base, { verb: 'stripe.refund' }, { unknown: ['action.params'], resourceUnknown: true }), { columns: cols });
    expect(f).toMatchObject({ ok: true, sql: "(id LIKE $1 ESCAPE '!' AND amount <= $2)", params: ['/acct/%', 500] });
  });

  it('escapes LIKE metacharacters and supports ? placeholders', () => {
    const p: PolicyInput = { predicates: [{ verb: 'v', resource: '/a_b%/*' }] };
    const f = toFilter(residual(p, { verb: 'v' }, { resourceUnknown: true }), { columns: cols, dialect: 'sqlite' });
    expect(f).toMatchObject({ ok: true, sql: "id LIKE ? ESCAPE '!'", params: ['/a!_b!%/%'] });
  });

  it('refuses what it cannot express exactly, instead of widening', () => {
    expect(toFilter(residual({ predicates: [{ verb: 'v', resource: 're:/a.*' }] }, { verb: 'v' }, { resourceUnknown: true }), { columns: cols })).toEqual({ ok: false, reason: 'regex resource matcher' });
    expect(toFilter(residual({ predicates: [{ verb: 'v', where: [{ field: 'action.params.x', op: 'eq', value: 1 }] }] }, { verb: 'v' }), { columns: cols })).toEqual({ ok: false, reason: "field 'action.params.x' has no usable column" });
    expect(toFilter(residual({ predicates: [{ verb: 'v', where: [{ field: 'action.params.amount', op: 'like', value: 'a*' }] }] }, { verb: 'v' }), { columns: cols })).toMatchObject({ ok: false });
    expect(toFilter(residual({ predicates: [{ verb: 'v', where: [{ field: 'action.params.amount', op: 'gt', value: 'a' }] }] }, { verb: 'v' }), { columns: cols })).toMatchObject({ ok: false });
    expect(toFilter(residual(base, { verb: 'stripe.refund' }, { resourceUnknown: true }), { columns: { 'action.resource': 'id; DROP TABLE x', 'action.params.amount': 'amount' } })).toMatchObject({ ok: false });
  });

  it('UCAST is the expanded syntax: compound and field nodes, with not-null guards so NULL never satisfies a permit', () => {
    const f = toFilter(residual(base, { verb: 'stripe.refund' }, { resourceUnknown: true }), { columns: cols });
    expect(f.ok && f.ucast).toEqual({ type: 'compound', operator: 'and', value: [{ type: 'field', field: 'id', operator: 'startswith', value: '/acct/' }, { type: 'field', field: 'amount', operator: 'lte', value: 500 }] });
    const ne = toFilter(residual({ predicates: [{ verb: 'v', where: [{ field: 'action.params.amount', op: 'ne', value: 5 }] }] }, { verb: 'v' }), { columns: cols });
    expect(ne.ok && ne.ucast).toEqual({ type: 'compound', operator: 'and', value: [{ type: 'field', field: 'amount', operator: 'ne', value: null }, { type: 'field', field: 'amount', operator: 'ne', value: 5 }] });
    expect(ne.ok && evalUcast(ne.ucast, { amount: null })).toBe(false);
  });

  it('a never residual is FALSE', () => {
    expect(toFilter(residual(base, { verb: 'stripe.payout' }), { columns: cols })).toMatchObject({ ok: true, sql: 'FALSE', params: [] });
  });

  it('the filter selects exactly the rows the evaluator allows (Kleene logic, nulls, vetoes, nested not)', () => {
    const p: PolicyInput = {
      predicates: [
        { verb: 'stripe.refund', resource: '/acct/*', where: [{ not: { field: 'action.params.amount', op: 'gt', value: 400 } }, { field: 'action.params.amount', op: 'gte', value: 1 }] },
        { verb: 'stripe.refund', resource: '/vip/*' },
      ],
      vetoes: [
        { id: 'frozen', kind: 'deny', when: { verb: 'stripe.refund', resource: '/acct/frozen*' } },
        { id: 'mid', kind: 'deny', when: { verb: 'stripe.refund', where: [{ field: 'action.params.amount', op: 'in', value: [250, 260] }] } },
        { id: 'big', kind: 'approval', when: { verb: 'stripe.refund' }, over: { path: 'action.params.amount', threshold: 300 }, unless: [] },
      ],
    };
    const f = toFilter(residual(p, { verb: 'stripe.refund' }, { resourceUnknown: true }), { columns: cols });
    expect(f.ok).toBe(true);
    if (!f.ok) return;
    const model = toModel(p);
    const ids = ['/acct/1', '/acct/frozen2', '/vip/9', '/other/3'];
    const amounts = [null, -5, 0, 1, 250, 260, 299, 300, 301, 399, 400, 401];
    for (const id of ids) {
      for (const amount of amounts) {
        const row = { id, amount };
        const params = amount === null ? {} : { amount };
        const want = decideAction(model, { verb: 'stripe.refund', resource: id, params }) === 'allow';
        expect(evalFilter(f.expr, row) === true, `${id} ${amount}`).toBe(want);
        expect(evalUcast(f.ucast, row), `ucast ${id} ${amount}`).toBe(want);
      }
    }
  });
});
