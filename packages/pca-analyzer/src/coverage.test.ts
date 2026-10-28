import { describe, expect, it } from 'vitest';
import { coverage, coverageGate, toModel, witnessOf, type PolicyInput, type AnalyzerAction } from './index';
import { refund } from './k2-fixtures';

const policy: PolicyInput = {
  predicates: [refund(500), { verb: 'stripe.list' }],
  vetoes: [
    { id: 'frozen', kind: 'deny', when: { verb: 'stripe.refund', resource: '/acct/frozen*' } },
    { id: 'big', kind: 'approval', when: { verb: 'stripe.refund' }, over: { path: 'action.params.amount', threshold: 300 } },
  ],
};
const act = (amount: number, resource = '/acct/1', verb = 'stripe.refund'): AnalyzerAction => ({ verb, resource, params: { amount } });

describe('witnessOf', () => {
  const m = toModel(policy);
  it('names the clause that decided', () => {
    expect(witnessOf(m, act(100))).toEqual({ decision: 'allow', winner: { kind: 'permit', id: 'permit[0]' }, also: [] });
    expect(witnessOf(m, act(400))).toMatchObject({ decision: 'escalate', winner: { kind: 'veto', id: 'big' }, also: ['permit[0]'] });
    expect(witnessOf(m, act(100, '/acct/frozen1'))).toMatchObject({ decision: 'deny', winner: { kind: 'veto', id: 'frozen' } });
    expect(witnessOf(m, act(900))).toEqual({ decision: 'deny', winner: { kind: 'none', id: null }, also: ['big'] });
    expect(witnessOf(m, { verb: 'stripe.list', resource: '/x' })).toMatchObject({ decision: 'allow', winner: { id: 'permit[1]' } });
  });
  it('a forbid beats a permit and an approval rule', () => {
    expect(witnessOf(m, act(400, '/acct/frozen1'))).toMatchObject({ decision: 'deny', winner: { id: 'frozen' }, also: ['permit[0]', 'big'] });
  });
});

describe('coverage', () => {
  it('reports clauses, boundaries and surviving mutants, with the action that kills each', () => {
    const r = coverage(policy, [act(100)]);
    expect(r.traffic).toBe(1);
    expect(r.clauses.map((c) => [c.id, c.matched, c.decisive])).toEqual([['permit[0]', 1, 1], ['permit[1]', 0, 0], ['frozen', 0, 0], ['big', 0, 0]]);
    expect(r.neverMatched).toEqual(['permit[1]', 'frozen', 'big']);
    expect(r.untested).toEqual(['permit[1]', 'frozen', 'big']);
    expect(r.unreachable).toEqual([]);
    expect(r.boundaries.map((b) => [b.threshold, b.below, b.at, b.above])).toEqual([[300, false, false, false], [500, false, false, false]]);
    expect(r.mutants.survivors.length).toBeGreaterThan(0);
    for (const s of r.mutants.survivors) expect(s.killer).toBeDefined();
    expect(r.score.clauses).toBeCloseTo(0.25);
  });

  it('boundary traffic and a trigger for each prohibition kill the mutants', () => {
    const traffic = [act(100), act(300), act(301), act(299), act(499), act(500), act(501), act(100, '/acct/frozen1'), act(100, '/acct/ok'), { verb: 'stripe.list', resource: '/x' }, { verb: 'stripe.payout', resource: '/x', params: { amount: 1 } }];
    const r = coverage(policy, traffic);
    expect(r.boundaries.every((b) => b.below && b.at && b.above)).toBe(true);
    expect(r.score.boundaries).toBe(1);
    expect(r.score.clauses).toBe(1);
    expect(r.neverDecisive).toEqual([]);
    expect(r.mutants.survivors.map((s) => s.id)).toEqual([]);
    expect(r.score.mutation).toBe(1);
    expect(coverageGate(r, { clauses: 1, boundaries: 1, mutation: 1, maxSurvivors: 0 })).toEqual({ ok: true, reasons: [] });
  });

  it('a gate fails on missing coverage, and on an unreachable clause', () => {
    const g = coverageGate(coverage(policy, [act(100)]), { clauses: 0.9, maxSurvivors: 0 });
    expect(g.ok).toBe(false);
    expect(g.reasons[0]).toMatch(/clause coverage 0.25 < 0.9/);
    const dead: PolicyInput = { predicates: [{ verb: 'v', where: [{ field: 'action.params.x', op: 'gte', value: 10 }, { field: 'action.params.x', op: 'lte', value: 1 }] }] };
    const r = coverage(dead, []);
    expect(r.unreachable).toEqual(['permit[0]']);
    expect(coverageGate(r).reasons).toContain('unreachable clauses: permit[0]');
  });

  it('a mutant the analyzer proves equivalent is not counted against the score', () => {
    const p: PolicyInput = { predicates: [{ verb: 'v', where: [{ field: 'action.params.n', op: 'lte', value: 5 }, { field: 'action.params.n', op: 'lte', value: 9 }] }] };
    const r = coverage(p, [{ verb: 'v', resource: '/r', params: { n: 5 } }, { verb: 'v', resource: '/r', params: { n: 6 } }, { verb: 'v', resource: '/r', params: { n: 4 } }, { verb: 'v', resource: '/r', params: { n: 9 } }, { verb: 'v', resource: '/r', params: { n: 10 } }, { verb: 'v', resource: '/r', params: { n: 8 } }]);
    expect(r.mutants.equivalent).toBeGreaterThan(0);
    expect(r.mutants.survivors).toEqual([]);
  });
});
