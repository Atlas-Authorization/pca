import { describe, expect, it } from 'vitest';
import {
  aggregateIntentMaps,
  commonRefinement,
  createLearner,
  crossOrgAggregate,
  emitIntentMap,
  jointAcceptance,
  liftIntentMap,
  normalizeRule,
  OTHER,
  ruleAdmits,
  ruleOf,
  verifyAggregate,
  verifyCrossOrgAggregate,
  type AggregationRecord,
  type CatDim,
  type Dim,
  type IntentMap,
  type IntentMapMetrics,
  type NumDim,
  type Omega,
  type VerbSpace,
} from './index';

const P = 'action.params.';
const A = P + 'a';
const K = P + 'k';
const numN = (path: string, n: number): NumDim => ({ kind: 'num', path, lo: 0, hi: n - 1, cuts: Array.from({ length: n - 1 }, (_, i) => i + 1), dist: 'uniform' });
const cat = (path: string, exacts: string[] = []): CatDim => ({
  kind: 'cat',
  path,
  values: [...exacts.map((value) => ({ kind: 'exact' as const, value })), { kind: 'other' as const, value: OTHER }],
});
const sp = (verb: string, reversibility: VerbSpace['reversibility'], dims: Dim[]): VerbSpace => ({ verb, reversibility, weight: 1 / 3, dims });
const omegaOf = (...verbs: VerbSpace[]): Omega => ({ v: 1, verbs, approximate: [] });
const cp = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;

// cells in order: v.i (irreversible), v.l (rate limited), v.r a = 0, 1, 2 (reversible)
const om = omegaOf(sp('v.i', 'irreversible', []), sp('v.l', 'rate_limited', []), sp('v.r', 'reversible', [numN(A, 3)]));
const mk = (ref: string, obs: [string, number | undefined, 0 | 1][]): IntentMap => {
  const l = createLearner(om, { nullMass: 0.05 });
  for (const [verb, v, y] of obs) l.observe({ verb, values: v === undefined ? {} : { [A]: v } }, y);
  return emitIntentMap(l, ref);
};
const MA = mk('A', [['v.r', 0, 1], ['v.r', 1, 1], ['v.l', undefined, 1]]);
const MB = mk('B', [['v.r', 0, 1], ['v.r', 2, 0], ['v.i', undefined, 0]]);

// aggregation does not replay its inputs, so the per-cell posteriors and metrics can be set directly
const fake = (base: IntentMap, ref: string, cs: [number, boolean][], metrics: Partial<IntentMapMetrics>): IntentMap => {
  const x = cp(base);
  x.intent_ref = ref;
  x.principals = [ref];
  x.cells = x.cells.map((c, i) => ({ ...c, p_ppm: cs[i]![0], in_grant: cs[i]![1] }));
  x.metrics = { ...x.metrics, ...metrics };
  return x;
};
const X = fake(MA, 'X', [[300000, true], [600000, false], [900000, true], [1000000, true], [200000, false]], { uncertainty_ppm: 10, disagreement_ppm: 50, entropy_mbits: 100, log2_vs_mbits: 200, questions: 1, conflicts: 2 });
const Y = fake(MB, 'Y', [[400000, false], [700000, true], [800000, true], [500000, true], [100000, true]], { uncertainty_ppm: 30, disagreement_ppm: 20, entropy_mbits: 7, log2_vs_mbits: 5, questions: 4, conflicts: 3 });
const Z = fake(MA, 'Z', [[1000000, true], [1000000, true], [1000000, true], [1000000, true], [1000000, false]], { uncertainty_ppm: 0, disagreement_ppm: 0, entropy_mbits: 0, log2_vs_mbits: null, questions: 0, conflicts: 0 });
const N = fake(MA, 'N', [[1, false], [2, false], [3, false], [4, false], [5, false]], {});
const cells = (m: IntentMap) => m.cells.map((c) => [c.p_ppm, c.in_grant]);
const rv = (lo: number, hi: number) => [{ field: A, op: 'gte', value: lo }, { field: A, op: 'lte', value: hi }];

describe('normalizeRule refusals', () => {
  const refs = ['X', 'Y', 'Z'];
  const w = (weights: Record<string, number>, threshold: number) => () => normalizeRule({ kind: 'weighted', weights, threshold }, refs);
  it('a vetoer that is not one of the maps', () => {
    expect(() => normalizeRule({ kind: 'unanimity', vetoers: ['Q'] }, refs)).toThrow('aggregateIntentMaps: vetoer Q is not one of the maps');
  });

  it('a quorum below 1 or not an integer', () => {
    expect(() => normalizeRule({ kind: 'quorum', k: 0 }, refs)).toThrow('aggregateIntentMaps: quorum k must be an integer in [1, 3]');
    expect(() => normalizeRule({ kind: 'quorum', k: 1.5 }, refs)).toThrow('aggregateIntentMaps: quorum k must be an integer in [1, 3]');
  });

  it('a negative or fractional weight', () => {
    expect(w({ X: 1, Y: -1, Z: 1 }, 1)).toThrow('aggregateIntentMaps: every principal needs a non-negative integer weight');
    expect(w({ X: 1, Y: 1.5, Z: 1 }, 1)).toThrow('aggregateIntentMaps: every principal needs a non-negative integer weight');
  });

  it('a threshold below 1, above the total weight or fractional; the total itself is accepted', () => {
    for (const t of [0, 5, 1.5]) expect(w({ X: 1, Y: 2, Z: 1 }, t)).toThrow('aggregateIntentMaps: threshold must be an integer in [1, 4]');
    expect(w({ X: 1, Y: 2, Z: 1 }, 4)()).toEqual({ weights: [1, 2, 1], threshold: 4, veto: [false, false, false] });
  });
});

describe('rule evaluation edges', () => {
  it('a vetoer missing from a short admission list counts as not admitting', () => {
    expect(ruleAdmits({ weights: [1, 1], threshold: 1, veto: [false, true] }, [true])).toBe(true);
  });

  it('a weight sum with no probability mass contributes nothing, even next to an undefined acceptance', () => {
    expect(jointAcceptance({ weights: [1, 1], threshold: 2, veto: [false, false] }, [0, NaN])).toBe(0);
  });
});

describe('aggregateIntentMaps input checks', () => {
  const U = { kind: 'unanimity' } as const;
  it('exact refusals, each triggered by one bad input among good ones', () => {
    expect(() => aggregateIntentMaps([], U)).toThrow('aggregateIntentMaps: no maps');
    expect(() => aggregateIntentMaps([X, { ...Y, omega: { ...Y.omega, approximate: ['x'] } }], U)).toThrow('aggregateIntentMaps: maps must share Ω (lift them with crossOrgAggregate)');
    const single = 'aggregateIntentMaps: every input must be a single-principal map with an intent_ref';
    const agg = { rule: 'unanimity', vetoers: [], per_principal: [] } as AggregationRecord;
    expect(() => aggregateIntentMaps([X, { ...Y, aggregation: agg }], U)).toThrow(single);
    expect(() => aggregateIntentMaps([X, { ...Y, principals: ['Y', 'W'] }], U)).toThrow(single);
    expect(() => aggregateIntentMaps([X, { ...Y, intent_ref: null }], U)).toThrow(single);
    expect(() => aggregateIntentMaps([X, { ...Y, intent_ref: 'X' }], U)).toThrow('aggregateIntentMaps: duplicate principal');
  });
});

describe('aggregateIntentMaps output', () => {
  it('unanimity: joint acceptance, grant, caveat of the worst admitted verb, worst-case metrics, per-principal estimates', () => {
    const g = aggregateIntentMaps([X, Y], { kind: 'unanimity' }, { orgs: { X: 'org-x' } });
    expect(g.kind).toBe('pca-intent-map');
    expect(cells(g)).toEqual([[120000, false], [420000, false], [720000, true], [500000, true], [20000, false]]);
    expect(g.grant).toEqual({ predicates: [{ verb: 'v.r', resource: '*', where: rv(0, 1) }], caveats: [{ type: 'reversibility_max', class: 'reversible' }] });
    expect(g.metrics).toEqual({ residual_risk_ppm: 77778, burden_ppm: 377778, uncertainty_ppm: 30, disagreement_ppm: 50, mean_harm_ppm: 4666667, fidelity_est_ppm: 968610, entropy_mbits: 107, log2_vs_mbits: 205, questions: 5, conflicts: 5 });
    expect(g.aggregation).toStrictEqual({
      rule: 'unanimity',
      vetoers: [],
      per_principal: [
        { intent_ref: 'X', org: 'org-x', residual_risk_ppm: 11111, burden_ppm: 322222 },
        { intent_ref: 'Y', residual_risk_ppm: 77778, burden_ppm: 377778 },
      ],
    });
    expect(g.observations).toEqual([...X.observations, ...Y.observations]);
  });

  it('quorum 1 is the union, capped at irreversible; the quorum and the vetoers are recorded', () => {
    const g = aggregateIntentMaps([X, Y], { kind: 'quorum', k: 1 });
    expect(cells(g)).toEqual([[580000, true], [880000, true], [980000, true], [1000000, true], [280000, true]]);
    expect(g.grant).toEqual({
      predicates: [{ verb: 'v.i', resource: '*' }, { verb: 'v.l', resource: '*' }, { verb: 'v.r', resource: '*', where: rv(0, 2) }],
      caveats: [{ type: 'reversibility_max', class: 'irreversible' }],
    });
    expect(g.metrics.fidelity_est_ppm).toBe(0);
    expect(g.aggregation).toStrictEqual({
      rule: 'quorum',
      k: 1,
      vetoers: [],
      per_principal: [
        { intent_ref: 'X', residual_risk_ppm: 2833333, burden_ppm: 0 },
        { intent_ref: 'Y', residual_risk_ppm: 2477778, burden_ppm: 0 },
      ],
    });
    expect(aggregateIntentMaps([X, Y], { kind: 'quorum', k: 1, vetoers: ['Y'] }).aggregation?.vetoers).toEqual(['Y']);
  });

  it('weighted: the weights and threshold are recorded and a rate-limited verb sets the caveat', () => {
    const g = aggregateIntentMaps([X, Y], { kind: 'weighted', weights: { X: 1, Y: 2 }, threshold: 2 });
    expect(cells(g)).toEqual([[400000, false], [700000, true], [800000, true], [500000, true], [100000, true]]);
    expect(g.grant).toEqual({ predicates: [{ verb: 'v.l', resource: '*' }, { verb: 'v.r', resource: '*', where: rv(0, 2) }], caveats: [{ type: 'reversibility_max', class: 'rate_limited' }] });
    expect(g.metrics).toEqual({ residual_risk_ppm: 500000, burden_ppm: 133333, uncertainty_ppm: 30, disagreement_ppm: 50, mean_harm_ppm: 4666667, fidelity_est_ppm: 807175, entropy_mbits: 107, log2_vs_mbits: 205, questions: 5, conflicts: 5 });
    expect(g.aggregation).toStrictEqual({
      rule: 'weighted',
      weights: { X: 1, Y: 2 },
      threshold: 2,
      vetoers: [],
      per_principal: [
        { intent_ref: 'X', residual_risk_ppm: 500000, burden_ppm: 100000 },
        { intent_ref: 'Y', residual_risk_ppm: 477778, burden_ppm: 133333 },
      ],
    });
  });

  it('a principal with nothing unacceptable has fidelity 1, and one null log2 size makes the total null', () => {
    const g = aggregateIntentMaps([X, Z], { kind: 'unanimity' });
    expect(g.metrics).toEqual({ residual_risk_ppm: 2344444, burden_ppm: 444444, uncertainty_ppm: 10, disagreement_ppm: 50, mean_harm_ppm: 4666667, fidelity_est_ppm: 172549, entropy_mbits: 100, log2_vs_mbits: null, questions: 1, conflicts: 2 });
    expect(g.grant.caveats).toEqual([{ type: 'reversibility_max', class: 'irreversible' }]);
  });

  it('an empty joint grant has no predicates and no caveat', () => {
    const g = aggregateIntentMaps([X, N], { kind: 'unanimity' });
    expect(g.grant).toEqual({ predicates: [], caveats: [] });
    expect(g.aggregation?.per_principal).toEqual([
      { intent_ref: 'X', residual_risk_ppm: 0, burden_ppm: 533333 },
      { intent_ref: 'N', residual_risk_ppm: 0, burden_ppm: 2 },
    ]);
  });
});

describe('ruleOf', () => {
  const g = (r: Parameters<typeof aggregateIntentMaps>[1]) => ruleOf(aggregateIntentMaps([X, Y], r));
  it('refuses a single map and returns each recorded rule', () => {
    expect(() => ruleOf(X)).toThrow('ruleOf: not an aggregated map');
    expect(g({ kind: 'unanimity', vetoers: ['X'] })).toStrictEqual({ kind: 'unanimity', vetoers: ['X'] });
    expect(g({ kind: 'quorum', k: 2 })).toStrictEqual({ kind: 'quorum', k: 2, vetoers: [] });
    expect(g({ kind: 'weighted', weights: { X: 1, Y: 2 }, threshold: 2 })).toStrictEqual({ kind: 'weighted', weights: { X: 1, Y: 2 }, threshold: 2, vetoers: [] });
  });
});

describe('verifyAggregate and verifyCrossOrgAggregate', () => {
  const badB = cp(MB);
  badB.metrics.residual_risk_ppm += 10;
  badB.metrics.burden_ppm += 10;
  const badBProblems = 'metric residual_risk_ppm differs (10 claimed, 0 replayed); metric burden_ppm differs (372232 claimed, 372222 replayed)';

  it('exact problems: a bad input stops before the recomputation; a mismatch; a recomputation that throws', () => {
    const agg = aggregateIntentMaps([MA, MB], { kind: 'unanimity' });
    expect(verifyAggregate(agg, [MA, MB])).toEqual({ ok: true, problems: [] });
    expect(verifyAggregate(agg, [MA, badB])).toEqual({ ok: false, problems: [`input 1: ${badBProblems}`] });
    const tampered = cp(agg);
    tampered.cells[0]!.in_grant = true;
    expect(verifyAggregate(tampered, [MA, MB])).toEqual({ ok: false, problems: ['aggregate does not match its recomputation'] });
    expect(verifyAggregate(MA, [MA])).toEqual({ ok: false, problems: ['recompute failed: ruleOf: not an aggregated map'] });
  });

  it('a bad input that would also change the aggregate is reported once, without the recomputation', () => {
    const agg = aggregateIntentMaps([MA, MB], { kind: 'unanimity' });
    const i = agg.cells.findIndex((c) => c.in_grant);
    expect(i).toBeGreaterThanOrEqual(0);
    const badC = cp(MB);
    badC.cells[i]!.in_grant = false;
    badC.cells[i]!.p_ppm = 0;
    const r = verifyAggregate(agg, [MA, badC]);
    expect(r.ok).toBe(false);
    expect(r.problems).toHaveLength(1);
    expect(r.problems[0]!.startsWith('input 1: ')).toBe(true);
  });

  it('cross-org: an input that does not verify is refused with all its problems; mismatches are reported', () => {
    expect(() => crossOrgAggregate([MA, badB], { kind: 'unanimity' })).toThrow(`crossOrgAggregate: map 1 does not verify: ${badBProblems}`);
    const { aggregate } = crossOrgAggregate([MA, MB], { kind: 'unanimity' });
    expect(verifyCrossOrgAggregate(aggregate, [MA, MB])).toEqual({ ok: true, problems: [] });
    const tampered = cp(aggregate);
    tampered.cells[0]!.in_grant = true;
    expect(verifyCrossOrgAggregate(tampered, [MA, MB])).toEqual({ ok: false, problems: ['aggregate does not match its recomputation'] });
    expect(verifyCrossOrgAggregate(aggregate, [MA, badB])).toEqual({ ok: false, problems: [`crossOrgAggregate: map 1 does not verify: ${badBProblems}`] });
  });
});

describe('commonRefinement', () => {
  const kv = (exact: string, prefix: string): CatDim => ({ kind: 'cat', path: K, values: [{ kind: 'exact', value: exact }, { kind: 'prefix', value: prefix }, { kind: 'other', value: OTHER }] });
  const num = (path: string, hi: number, cuts: number[]): NumDim => ({ kind: 'num', path, lo: 0, hi, cuts, dist: 'uniform' });

  it('unions and sorts verbs, dimensions, cuts, values and approximations; keeps the most severe reversibility', () => {
    const o1: Omega = { v: 1, approximate: ['z'], verbs: [sp('v.y', 'irreversible', []), sp('v.x', 'reversible', [num(P + 'm', 5, [1, 3]), kv('b', 'p2')])] };
    const o2: Omega = {
      v: 1,
      approximate: ['a', 'z'],
      verbs: [sp('v.y', 'reversible', []), sp('v.c', 'reversible', []), sp('v.x', 'irreversible', [num(P + 'z', 1, []), kv('a', 'p1'), num(P + 'm', 5, [2]), num(A, 1, [])]), sp('v.a', 'rate_limited', [])],
    };
    expect(commonRefinement([o1, o2])).toEqual({
      v: 1,
      verbs: [
        { verb: 'v.a', reversibility: 'rate_limited', weight: 0.25, dims: [] },
        { verb: 'v.c', reversibility: 'reversible', weight: 0.25, dims: [] },
        {
          verb: 'v.x',
          reversibility: 'irreversible',
          weight: 0.25,
          dims: [
            num(A, 1, []),
            {
              kind: 'cat',
              path: K,
              values: [
                { kind: 'exact', value: 'a' },
                { kind: 'exact', value: 'b' },
                { kind: 'prefix', value: 'p1' },
                { kind: 'prefix', value: 'p2' },
                { kind: 'other', value: '⊥' },
              ],
            },
            num(P + 'm', 5, [1, 2, 3]),
            num(P + 'z', 1, []),
          ],
        },
        { verb: 'v.y', reversibility: 'irreversible', weight: 0.25, dims: [] },
      ],
      approximate: ['a', 'z'],
    });
  });

  it('merges two categorical dimensions of one path into one categorical dimension', () => {
    const o = (x: string): Omega => omegaOf(sp('v.x', 'reversible', [cat(K, [x])]));
    expect(commonRefinement([o('b'), o('a')]).verbs[0]!.dims).toEqual([cat(K, ['a', 'b'])]);
  });

  it('dimensions with the same path keep their input order', () => {
    const o: Omega = omegaOf(sp('w', 'reversible', [num('p', 1, []), num('p', 2, [])]));
    expect(commonRefinement([o]).verbs[0]!.dims.map((d) => (d as NumDim).hi)).toEqual([1, 2]);
  });

  it('exact refusals for a kind clash and for different domains', () => {
    const d = (dim: Dim): Omega => omegaOf(sp('v.x', 'reversible', [dim]));
    expect(() => commonRefinement([d(num(P + 'm', 5, [])), d(cat(P + 'm'))])).toThrow('commonRefinement: action.params.m is numeric in one Ω and categorical in another');
    expect(() => commonRefinement([d(num(P + 'm', 5, [])), d({ ...num(P + 'm', 5, []), lo: 1 })])).toThrow('commonRefinement: action.params.m has different domains ([0, 5] vs [1, 5])');
    expect(() => commonRefinement([d(num(P + 'm', 5, [])), d(num(P + 'm', 6, []))])).toThrow('commonRefinement: action.params.m has different domains ([0, 5] vs [0, 6])');
  });
});

describe('liftIntentMap', () => {
  // the target adds a categorical dimension to v.r and a verb v.n the map never covered
  const tgt = commonRefinement([om, omegaOf(sp('v.r', 'reversible', [cat(K, ['a'])]), sp('v.n', 'reversible', []))]);

  it('keeps the recorded null masses, denies a new verb, fills new dimensions and re-applies each observation as its own region', () => {
    const L = liftIntentMap(MA, tgt);
    expect(L.learner.null_mass_ppm).toEqual({ 'v.i': 50000, 'v.l': 50000, 'v.n': 1000000, 'v.r': 50000 });
    expect(L.observations).toEqual([
      { verb: 'v.r', values: { [A]: 0, [K]: 'a' }, y: 1, source: 'elicitation', region: { verb: 'v.r', dims: { [A]: { kind: 'num', lo: 0, hi: 0 } } } },
      { verb: 'v.r', values: { [A]: 1, [K]: 'a' }, y: 1, source: 'elicitation', region: { verb: 'v.r', dims: { [A]: { kind: 'num', lo: 1, hi: 1 } } } },
      { verb: 'v.l', values: {}, y: 1, source: 'elicitation', region: { verb: 'v.l', dims: {} } },
    ]);
    expect(L.cells.map((c) => [c.verb, c.cell, c.p_ppm, c.in_grant])).toEqual([
      ['v.i', [], 950000, false],
      ['v.l', [], 1000000, true],
      ['v.n', [], 0, false],
      ['v.r', [0, 0], 1000000, true],
      ['v.r', [0, 1], 1000000, true],
      ['v.r', [1, 0], 1000000, true],
      ['v.r', [1, 1], 1000000, true],
      ['v.r', [2, 0], 500000, false],
      ['v.r', [2, 1], 500000, false],
    ]);
  });

  it('a verb whose recorded null mass is missing gets 0.2, even when it is spelled like an Object.prototype member', () => {
    const omT = omegaOf(sp('toString', 'reversible', []));
    const MT = cp(emitIntentMap(createLearner(omT, { nullMass: 0.05 }), 'T'));
    delete (MT.learner.null_mass_ppm as Record<string, number>)['toString'];
    expect(liftIntentMap(MT, omT).learner.null_mass_ppm).toEqual({ toString: 200000 });
  });

  it('exact refusals', () => {
    const agg = aggregateIntentMaps([MA, MB], { kind: 'unanimity' });
    expect(() => liftIntentMap(agg, tgt)).toThrow('liftIntentMap: lift single-principal maps, then aggregate');
    expect(() => liftIntentMap({ ...MA, principals: ['A', 'B'] }, tgt)).toThrow('liftIntentMap: lift single-principal maps, then aggregate');
    expect(() => liftIntentMap(MA, omegaOf(sp('v.r', 'reversible', [numN(A, 3)])))).toThrow('liftIntentMap: verb v.l missing from Ω');
    expect(() => liftIntentMap({ ...MA, observations: [{ verb: 'v.r', values: { [A]: 7 }, y: 1, source: 'elicitation' }] }, tgt)).toThrow("liftIntentMap: an observation of v.r lies outside the map's own Ω");
  });
});
