import { describe, expect, it } from 'vitest';
import {
  answerPartial,
  cellRep,
  createLearner,
  elicitAdaptive,
  IntentLearner,
  OTHER,
  refineOmega,
  regionOfObservation,
  verbCellCount,
  type AdaptiveAnswer,
  type CatDim,
  type Dim,
  type LearnerOptions,
  type NumDim,
  type Omega,
  type Outcome,
  type Question,
  type VerbSpace,
} from './index';

const P = 'action.params.';
const K = P + 'k';

const num = (path: string, lo: number, hi: number, cuts: number[]): NumDim => ({ kind: 'num', path, lo, hi, cuts, dist: 'uniform' });
const numN = (path: string, n: number): NumDim => num(path, 0, n - 1, Array.from({ length: n - 1 }, (_, i) => i + 1));
const cat = (path: string, exacts: string[] = [], prefixes: string[] = []): CatDim => ({
  kind: 'cat',
  path,
  values: [
    ...exacts.map((value) => ({ kind: 'exact' as const, value })),
    ...prefixes.map((value) => ({ kind: 'prefix' as const, value })),
    { kind: 'other' as const, value: OTHER },
  ],
});
const vspace = (verb: string, dims: Dim[]): VerbSpace => ({ verb, reversibility: 'reversible', weight: 1, dims });
const omegaOf = (...verbs: VerbSpace[]): Omega => ({ v: 1, verbs, approximate: [] });
const rep = (vs: VerbSpace, ...idx: number[]): Outcome => cellRep(vs, idx);
const ex = (value: string) => ({ kind: 'exact' as const, value });
const pre = (value: string) => ({ kind: 'prefix' as const, value });
const other = { kind: 'other' as const, value: OTHER };

describe('refineOmega: categorical values', () => {
  const base = omegaOf(vspace('v.r', [num(P + 'b', 5, 20, [10]), cat(P + 'd', ['m'])]));
  const dimD = (o: Omega) => o.verbs[0]!.dims[1]!;

  it('names exact values and prefixes, sorted and de-duplicated, exact first, then prefixes, then the other cell', () => {
    const r = refineOmega(base, { verb: 'v.r', path: P + 'd', values: ['z', 'b', 'b'], prefixes: ['q', 'c', 'c'] });
    expect(dimD(r)).toEqual({ kind: 'cat', path: P + 'd', values: [ex('b'), ex('m'), ex('z'), pre('c'), pre('q'), other] });
    expect(dimD(base)).toEqual(cat(P + 'd', ['m']));
  });

  it('prefixes alone add only prefixes, values alone add only values', () => {
    expect((dimD(refineOmega(base, { verb: 'v.r', path: P + 'd', prefixes: ['p'] })) as CatDim).values).toEqual([ex('m'), pre('p'), other]);
    expect((dimD(refineOmega(base, { verb: 'v.r', path: P + 'd', values: ['a'] })) as CatDim).values).toEqual([ex('a'), ex('m'), other]);
  });

  it('refuses more than 20 values, allows exactly 20', () => {
    const wide = omegaOf(vspace('v.r', [cat(P + 'd', Array.from({ length: 18 }, (_, i) => 'e' + String(i).padStart(2, '0')))]));
    expect((refineOmega(wide, { verb: 'v.r', path: P + 'd', values: ['x1'] }).verbs[0]!.dims[0] as CatDim).values).toHaveLength(20);
    expect(() => refineOmega(wide, { verb: 'v.r', path: P + 'd', values: ['x1', 'x2'] })).toThrow(new Error(`refineOmega: ${P}d would have more than 20 values`));
  });

  it('refuses cuts on a categorical dimension', () => {
    expect(() => refineOmega(base, { verb: 'v.r', path: P + 'd', cuts: [3] })).toThrow(new Error(`refineOmega: ${P}d is categorical`));
  });
});

describe('refineOmega: numeric cuts', () => {
  const base = omegaOf(vspace('v.r', [num(P + 'b', 5, 20, [10]), cat(P + 'd', ['m'])]));

  it('adds integer cuts inside [lo, hi] (both ends inclusive), sorted numerically and de-duplicated', () => {
    const r = refineOmega(base, { verb: 'v.r', path: P + 'b', cuts: [20, 21, 4, 5, 12, 12.5, 8, 10, 8] });
    expect((r.verbs[0]!.dims[0] as NumDim).cuts).toEqual([5, 8, 10, 12, 20]);
    expect((base.verbs[0]!.dims[0] as NumDim).cuts).toEqual([10]);
  });

  it('no cuts leaves the dimension as it was', () => {
    expect((refineOmega(base, { verb: 'v.r', path: P + 'b' }).verbs[0]!.dims[0] as NumDim).cuts).toEqual([10]);
    expect((refineOmega(base, { verb: 'v.r', path: P + 'b', values: [], prefixes: [] }).verbs[0]!.dims[0] as NumDim).cuts).toEqual([10]);
  });

  it('refuses values or prefixes on a numeric dimension, each on its own', () => {
    const msg = new Error(`refineOmega: ${P}b is numeric`);
    expect(() => refineOmega(base, { verb: 'v.r', path: P + 'b', values: ['a'] })).toThrow(msg);
    expect(() => refineOmega(base, { verb: 'v.r', path: P + 'b', prefixes: ['a'] })).toThrow(msg);
  });
});

describe('refineOmega: adding a dimension', () => {
  const three = omegaOf(vspace('v.r', [num(P + 'b', 0, 9, []), cat(P + 'd', ['m']), num(P + 'f', 0, 9, [])]));
  const pathsAfter = (path: string): string[] =>
    refineOmega(three, { verb: 'v.r', path, newDim: num(path, 0, 9, []) }).verbs[0]!.dims.map((d) => d.path);

  it('keeps the dimensions ordered by path wherever the new one lands', () => {
    expect(pathsAfter(P + 'c')).toEqual([P + 'b', P + 'c', P + 'd', P + 'f']);
    expect(pathsAfter(P + 'a')).toEqual([P + 'a', P + 'b', P + 'd', P + 'f']);
    expect(pathsAfter(P + 'g')).toEqual([P + 'b', P + 'd', P + 'f', P + 'g']);
    expect(pathsAfter(P + 'e')).toEqual([P + 'b', P + 'd', P + 'e', P + 'f']);
  });

  it('dimensions that already share a path keep their given order', () => {
    const dup = omegaOf(vspace('v.r', [num(P + 'x', 0, 1, []), num(P + 'x', 0, 2, [])]));
    const r = refineOmega(dup, { verb: 'v.r', path: P + 'y', newDim: num(P + 'y', 0, 1, []) });
    expect(r.verbs[0]!.dims.map((d) => (d as NumDim).hi)).toEqual([1, 2, 1]);
  });

  it('normalises a numeric new dimension: cuts inside [lo, hi] inclusive, sorted, de-duplicated', () => {
    const r = refineOmega(three, { verb: 'v.r', path: P + 'c', newDim: num(P + 'c', 0, 20, [15, 5, 20, 21, 10, 10, -1, 0]) });
    expect(r.verbs[0]!.dims[1]).toEqual({ kind: 'num', path: P + 'c', lo: 0, hi: 20, cuts: [0, 5, 10, 15, 20], dist: 'uniform' });
  });

  it('normalises a categorical new dimension through the value sorter', () => {
    const nd: CatDim = { kind: 'cat', path: P + 'c', values: [pre('q'), ex('z'), other, ex('b'), pre('c')] };
    const r = refineOmega(three, { verb: 'v.r', path: P + 'c', newDim: nd });
    expect(r.verbs[0]!.dims[1]).toEqual({ kind: 'cat', path: P + 'c', values: [ex('b'), ex('z'), pre('c'), pre('q'), other] });
  });

  it('refuses an existing path (the first dimension too) and a mismatched newDim.path', () => {
    expect(() => refineOmega(three, { verb: 'v.r', path: P + 'b', newDim: num(P + 'b', 0, 1, []) })).toThrow(new Error(`refineOmega: ${P}b is already a dimension of v.r`));
    expect(() => refineOmega(three, { verb: 'v.r', path: P + 'd', newDim: cat(P + 'd') })).toThrow(new Error(`refineOmega: ${P}d is already a dimension of v.r`));
    expect(() => refineOmega(three, { verb: 'v.r', path: P + 'c', newDim: num(P + 'zz', 0, 1, []) })).toThrow(new Error('refineOmega: newDim.path must equal path'));
  });

  it('refuses an unknown verb', () => {
    expect(() => refineOmega(three, { verb: 'nope', path: P + 'b', cuts: [1] })).toThrow(new Error('refineOmega: no verb nope in Ω'));
  });
});

describe('regionOfObservation', () => {
  it('refuses an observation of a verb the Ω does not have', () => {
    const om = omegaOf(vspace('v.a', [numN(P + 'a', 3)]));
    expect(() => regionOfObservation(om, { verb: 'nope', values: {}, cell: [0], y: 1, source: 'elicitation' })).toThrow(new Error('regionOfObservation: no verb nope'));
  });
});

describe('answerPartial', () => {
  it('refuses a question about a verb the learner does not have', () => {
    const l = createLearner(omegaOf(vspace('v.a', [numN(P + 'a', 3)])));
    const q: Question = { verb: 'nope', cell: [0], outcome: { verb: 'nope', values: {} }, p: 0.5, score: 1 };
    expect(() => answerPartial(l, q, { kind: 'partial', path: P + 'a', cuts: [1], parts: [] })).toThrow(new Error('answerPartial: no verb nope'));
  });

  it('a categorical partial names its values and labels only the sub-cells inside the questioned cell', () => {
    const vs = vspace('v.c', [cat(K, ['a'])]);
    const l = createLearner(omegaOf(vs), { nullMass: 0.05 });
    const q: Question = { verb: 'v.c', cell: [1], outcome: rep(vs, 1), p: 0.5, score: 1 };
    const { learner, added } = answerPartial(l, q, { kind: 'partial', path: K, values: ['b', 'a'], parts: [{ values: ['a', 'b'], y: 0 }, { other: true, y: 1 }] });
    expect(added.map((o) => o.y)).toEqual([0, 1]);
    expect(added.map((o) => o.values[K])).toEqual(['b', 'other']);
    expect(added.map((o) => o.cell)).toEqual([[1], [2]]);
    const values = [ex('a'), ex('b'), other];
    expect(added[0]!.region!.dims[K]).toEqual({ kind: 'cat', values, cells: [1] });
    expect(added[1]!.region!.dims[K]).toEqual({ kind: 'cat', values, cells: [2] });
    expect(learner.observations).toHaveLength(2);
    expect(l.observations).toHaveLength(0);
  });

  it('a new categorical dimension re-scopes earlier yes answers of that verb only', () => {
    const A = vspace('v.a', [numN(P + 'a', 3)]);
    const B = vspace('v.b', [numN(P + 'a', 3)]);
    const l = createLearner(omegaOf(A, B), { nullMass: 0.05 });
    l.observe(rep(A, 0), 1);
    l.observe(rep(A, 2), 0);
    l.observe(rep(B, 0), 1);
    const q: Question = { verb: 'v.a', cell: [1], outcome: rep(A, 1), p: 0.5, score: 1 };
    const { learner } = answerPartial(l, q, { kind: 'partial', path: K, newDim: cat(K, ['x']), parts: [{ values: ['x'], y: 0 }, { other: true, y: 1 }] });
    const obs = learner.observations;
    expect(obs[0]!.verb).toBe('v.a');
    expect(obs[0]!.y).toBe(1);
    expect(obs[0]!.region!.dims[K]).toEqual({ kind: 'cat', values: [ex('x'), other], cells: [1] });
    expect(obs[1]!.y).toBe(0);
    expect(obs[1]!.region!.dims[K]).toBeUndefined();
    expect(obs[2]!.verb).toBe('v.b');
    expect(Object.keys(obs[2]!.region!.dims)).toEqual([P + 'a']);
  });

  it('a new numeric dimension re-scopes earlier yes answers to the contiguous accepted span', () => {
    const A = vspace('v.a', [numN(P + 'a', 3)]);
    const l = createLearner(omegaOf(A), { nullMass: 0.05 });
    l.observe(rep(A, 0), 1);
    const q: Question = { verb: 'v.a', cell: [1], outcome: rep(A, 1), p: 0.5, score: 1 };
    const H = 'env.hour';
    const { learner } = answerPartial(l, q, { kind: 'partial', path: H, newDim: num(H, 0, 23, [12]), parts: [{ lo: 0, hi: 12, y: 1 }, { lo: 13, hi: 23, y: 0 }] });
    expect(learner.observations[0]!.y).toBe(1);
    expect(learner.observations[0]!.region!.dims[H]).toEqual({ kind: 'num', lo: 0, hi: 12 });
  });

  it('when no part of a new numeric dimension is accepted, earlier yes answers on that verb are dropped, not widened', () => {
    const A = vspace('v.a', [numN(P + 'a', 3)]);
    const B = vspace('v.b', [numN(P + 'a', 3)]);
    const l = createLearner(omegaOf(A, B), { nullMass: 0.05 });
    l.observe(rep(A, 0), 1);
    l.observe(rep(B, 0), 1);
    const q: Question = { verb: 'v.a', cell: [1], outcome: rep(A, 1), p: 0.5, score: 1 };
    const H = 'env.hour';
    // cells of the new dimension: [0, 21], {22}, {23}; a region starting past hi + 1 holds none of them
    const { learner } = answerPartial(l, q, { kind: 'partial', path: H, newDim: num(H, 0, 23, [22]), parts: [{ lo: 0, hi: 23, y: 0 }] });
    expect(learner.observations.filter((o) => o.verb === 'v.a' && o.y === 1)).toHaveLength(0);
    expect(learner.observations.filter((o) => o.verb === 'v.b' && o.y === 1)).toHaveLength(1);
  });
});

describe('elicitAdaptive: stop rule, seeds and audit', () => {
  const V3 = vspace('v.a', [numN(P + 'a', 3)]);
  const V1 = vspace('v.1', [num(P + 'a', 0, 5, [])]);
  const truth01 = (q: Question): 0 | 1 => (q.cell[0]! <= 1 ? 1 : 0);
  const fresh = (...vs: VerbSpace[]): IntentLearner => createLearner(omegaOf(...vs));
  const none = { epsRisk: -1, epsBurden: -1 };

  it('stops "converged" once risk and burden are within tolerance', () => {
    const l = fresh(V3);
    const r = elicitAdaptive(l, truth01, { epsRisk: 0, epsBurden: 0, maxQuestions: 50 });
    expect(r.stop).toBe('converged');
    expect(r.questions).toBeGreaterThan(0);
    expect(r.questions).toBe(r.asked.length);
    expect(r.refinements).toBe(0);
    expect(r.learner).toBe(l);
    expect(l.observations).toHaveLength(r.questions);
    expect(l.observations.every((o) => o.source === 'elicitation')).toBe(true);
  });

  it('stops "budget" exactly at maxQuestions', () => {
    for (const max of [0, 1, 2]) {
      const l = fresh(V3);
      const r = elicitAdaptive(l, truth01, { epsRisk: 0, epsBurden: 0, maxQuestions: max });
      expect(r.stop).toBe('budget');
      expect(r.questions).toBe(max);
      expect(l.observations).toHaveLength(max);
    }
  });

  it('stops "no-disagreement" when nothing is left to ask', () => {
    const l = fresh(V3);
    const r = elicitAdaptive(l, truth01, { ...none, maxQuestions: 50 });
    expect(r.stop).toBe('no-disagreement');
    expect(l.nextQuestion()).toBeNull();
  });

  it('asks the seed questions first and in order, at most maxQuestions of them, with the exact question record', () => {
    const seeds = [{ verb: 'v.a', cell: [0] }, { verb: 'v.a', cell: [2] }];
    const one = fresh(V3);
    const r1 = elicitAdaptive(one, truth01, { ...none, maxQuestions: 1, seed: seeds });
    expect(r1.seedQuestions).toBe(1);
    expect(r1.questions).toBe(1);
    expect(r1.stop).toBe('budget');
    expect(r1.asked[0]).toEqual({ verb: 'v.a', cell: [0], outcome: rep(V3, 0), p: fresh(V3).acceptance(rep(V3, 0)), score: 0 });
    expect(r1.asked[0]!.cell).not.toBe(seeds[0]!.cell);
    expect(one.observations[0]!.source).toBe('elicitation');

    const two = fresh(V3);
    const r2 = elicitAdaptive(two, truth01, { ...none, maxQuestions: 10, seed: seeds });
    expect(r2.seedQuestions).toBe(2);
    expect(r2.asked.slice(0, 2).map((q) => q.cell)).toEqual([[0], [2]]);
  });

  it('skips seeds that name no verb, the wrong number of dimensions, or a settled cell', () => {
    const r = elicitAdaptive(fresh(V3), truth01, {
      ...none,
      maxQuestions: 1,
      seed: [{ verb: 'no.such', cell: [0] }, { verb: 'v.a', cell: [0, 0] }, { verb: 'v.a', cell: [1] }],
    });
    expect(r.seedQuestions).toBe(1);
    expect(r.asked.map((q) => q.cell)).toEqual([[1]]);
    expect(r.asked[0]!.verb).toBe('v.a');
  });

  it('finds the verb of a seed among several', () => {
    const vB = vspace('v.b', [numN(P + 'a', 3), cat(P + 'k')]);
    const r = elicitAdaptive(fresh(V3, vB), () => 1, { ...none, maxQuestions: 1, seed: [{ verb: 'v.b', cell: [1, 0] }] });
    expect(r.seedQuestions).toBe(1);
    expect(r.asked[0]!.verb).toBe('v.b');
    expect(r.asked[0]!.outcome).toEqual(rep(vB, 1, 0));
  });

  it('never asks a seed whose cell is already answered yes or no', () => {
    const yes = fresh(V3);
    yes.observe(rep(V3, 0), 1);
    expect(elicitAdaptive(yes, () => 1, { ...none, maxQuestions: 1, seed: [{ verb: 'v.a', cell: [0] }] }).seedQuestions).toBe(0);
    const no = fresh(V3);
    no.observe(rep(V3, 0), 0);
    expect(elicitAdaptive(no, () => 1, { ...none, maxQuestions: 1, seed: [{ verb: 'v.a', cell: [0] }] }).seedQuestions).toBe(0);
  });

  it('never asks about a cell whose probability is within 1e-9 of 0 or 1', () => {
    const seed = [{ verb: 'v.1', cell: [0] }];
    const stuck: LearnerOptions[] = [
      { nullMass: 1, priorMix: { beta: 1e-9, weight: (_vs, contains) => (contains(0) ? 1 : 0) } },
      { nullMass: 1e-9 },
    ];
    for (const opts of stuck) {
      const r = elicitAdaptive(new IntentLearner(omegaOf(V1), opts), () => 1, { ...none, maxQuestions: 5, seed });
      expect(r.seedQuestions).toBe(0);
      expect(r.questions).toBe(0);
      expect(r.stop).toBe('no-disagreement');
    }
    const live = elicitAdaptive(new IntentLearner(omegaOf(V1), { nullMass: 0.5 }), () => 1, { ...none, maxQuestions: 5, seed });
    expect(live.seedQuestions).toBe(1);
  });

  it('skips a vetoed seed cell', () => {
    const noisy = createLearner(omegaOf(V1), { eta: 0.2 });
    noisy.observe(rep(V1, 0), 0, 'runtime');
    const r = elicitAdaptive(noisy, () => 1, { ...none, maxQuestions: 5, seed: [{ verb: 'v.1', cell: [0] }] });
    expect(r.seedQuestions).toBe(0);
  });

  it('a partial answer past maxRefinements counts as a "no" recorded as an elicitation', () => {
    const l = fresh(V3);
    const partial: AdaptiveAnswer = { kind: 'partial', path: P + 'a', cuts: [1], parts: [] };
    const r = elicitAdaptive(l, () => partial, { epsRisk: 0, epsBurden: 0, maxQuestions: 1, maxRefinements: 0 });
    expect(r.refinements).toBe(0);
    expect(r.learner).toBe(l);
    expect(r.asked).toHaveLength(1);
    expect(l.observations).toHaveLength(1);
    expect(l.observations[0]).toMatchObject({ y: 0, source: 'elicitation', verb: 'v.a' });
  });

  describe('the audit round', () => {
    const primed = (...extra: VerbSpace[]): IntentLearner => {
      const l = fresh(V3, ...extra);
      l.observe(rep(V3, 0), 1);
      l.observe(rep(V3, 2), 1);
      return l;
    };

    it('stops at once when the unconfirmed weight is within epsRisk, equality included', () => {
      const w = primed().unconfirmedGrantCells()[0]!.weight;
      expect(elicitAdaptive(primed(), () => 1, { epsRisk: w, epsBurden: 1e9, maxQuestions: 10, audit: true }).auditQuestions).toBe(0);
      expect(elicitAdaptive(primed(), () => 1, { epsRisk: 1e9, epsBurden: 1e9, maxQuestions: 10, audit: true }).auditQuestions).toBe(0);
    });

    it('asks the most consequential unconfirmed cell as an elicitation', () => {
      const l = primed();
      const w = l.unconfirmedGrantCells()[0]!.weight;
      const r = elicitAdaptive(l, () => 1, { epsRisk: 0, epsBurden: 1e9, maxQuestions: 5, audit: true });
      expect(r.stop).toBe('converged');
      expect(r.auditQuestions).toBe(1);
      expect(r.questions).toBe(1);
      expect(r.asked).toHaveLength(1);
      expect(r.asked[0]).toMatchObject({ verb: 'v.a', cell: [1], outcome: rep(V3, 1), p: 1 });
      expect(r.asked[0]!.score).toBeCloseTo(w, 12);
      expect(l.observations).toHaveLength(3);
      expect(l.observations[2]!.source).toBe('elicitation');
      expect(l.unconfirmedGrantCells()).toEqual([]);
    });

    it('reports an exhausted budget as "budget" and asks nothing', () => {
      const l = primed();
      const r = elicitAdaptive(l, () => 1, { epsRisk: 0, epsBurden: 1e9, maxQuestions: 0, audit: true });
      expect(r.stop).toBe('budget');
      expect(r.questions).toBe(0);
      expect(r.auditQuestions).toBe(0);
      expect(l.observations).toHaveLength(2);
    });

    it('finds the verb of the cell it asks about', () => {
      const vB = vspace('v.b', [numN(P + 'a', 3), cat(P + 'k')]);
      const l = fresh(V3, vB);
      l.observe(rep(vB, 0, 0), 1);
      l.observe(rep(vB, 2, 0), 1);
      const r = elicitAdaptive(l, () => 1, { epsRisk: 0, epsBurden: 1e9, maxQuestions: 5, audit: true });
      expect(r.asked).toHaveLength(1);
      expect(r.asked[0]!.verb).toBe('v.b');
      expect(r.asked[0]!.outcome).toEqual(rep(vB, 1, 0));
      expect(verbCellCount(vB)).toBe(3);
    });
  });
});
