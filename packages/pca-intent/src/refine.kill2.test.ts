import { describe, expect, it } from 'vitest';
import {
  answerPartial,
  cellRep,
  createLearner,
  elicitAdaptive,
  OTHER,
  refineLearner,
  regionOfObservation,
  type CatDim,
  type Dim,
  type IntentLearner,
  type NumDim,
  type Omega,
  type Outcome,
  type Question,
  type Region,
  type VerbSpace,
} from './index';

const P = 'action.params.';
const A = P + 'a';
const K = P + 'k';
const H = 'env.hour';

const num = (path: string, lo: number, hi: number, cuts: number[]): NumDim => ({ kind: 'num', path, lo, hi, cuts, dist: 'uniform' });
const numN = (path: string, n: number): NumDim => num(path, 0, n - 1, Array.from({ length: n - 1 }, (_, i) => i + 1));
const cat = (path: string, exacts: string[] = []): CatDim => ({
  kind: 'cat',
  path,
  values: [...exacts.map((value) => ({ kind: 'exact' as const, value })), { kind: 'other' as const, value: OTHER }],
});
const vspace = (verb: string, dims: Dim[]): VerbSpace => ({ verb, reversibility: 'reversible', weight: 1, dims });
const omegaOf = (...verbs: VerbSpace[]): Omega => ({ v: 1, verbs, approximate: [] });
const rep = (vs: VerbSpace, ...idx: number[]): Outcome => cellRep(vs, idx);
const question = (vs: VerbSpace, cell: number[], outcome: Outcome = rep(vs, ...cell)): Question => ({ verb: vs.verb, cell, outcome, p: 0.5, score: 1 });

describe('regionOfObservation', () => {
  it('returns the recorded region as is, and the cell region only when none was recorded', () => {
    const om = omegaOf(vspace('v.a', [numN(A, 3)]));
    const region: Region = { verb: 'v.a', dims: { [A]: { kind: 'num', lo: 1, hi: 2 } } };
    expect(regionOfObservation(om, { verb: 'v.a', values: { [A]: 0 }, cell: [0], y: 1, source: 'elicitation', region })).toBe(region);
    expect(regionOfObservation(om, { verb: 'v.a', values: { [A]: 0 }, cell: [0], y: 1, source: 'elicitation' })).toEqual({ verb: 'v.a', dims: { [A]: { kind: 'num', lo: 0, hi: 0 } } });
  });
});

describe('refineLearner', () => {
  it('replays each observation with its own values; only a dimension it lacks gets the first cell representative', () => {
    const va = vspace('v.a', [numN(A, 3)]);
    const vb = vspace('v.b', [numN(P + 'b', 3)]);
    const l = createLearner(omegaOf(va, vb), { nullMass: 0.05 });
    l.observe(rep(va, 2), 1);
    l.observe(rep(vb, 1), 0);
    const next = refineLearner(l, { verb: 'v.a', path: H, newDim: num(H, 0, 23, [12]) });
    expect(next.observations.map((o) => [o.verb, o.values])).toEqual([
      ['v.a', { [A]: 2, [H]: 11 }],
      ['v.b', { [P + 'b']: 1 }],
    ]);
  });
});

describe('answerPartial: part labels', () => {
  it('categorical: range parts are skipped, value parts match exact cells only, the other part labels non-exact cells only', () => {
    const vs = vspace('v.c', [cat(K, ['a'])]);
    const l = createLearner(omegaOf(vs), { nullMass: 0.05 });
    // refined cells: a, b, other; the questioned other cell covers b and other
    const { added } = answerPartial(l, question(vs, [1]), {
      kind: 'partial',
      path: K,
      values: ['b'],
      parts: [{ lo: 0, hi: 9, y: 0 }, { values: ['other'], y: 0 }, { other: true, y: 1 }],
    });
    expect(added.map((o) => [o.cell, o.y, o.source])).toEqual([[[2], 1, 'elicitation']]);
  });

  it('numeric: value and other parts are skipped; a range part labels only sub-cells wholly inside it', () => {
    // cells after the cut at 15: [0,9] [10] [11,14] [15] [16,19] [20] [21,30]; the question is about [11,19]
    const vs = vspace('v.n', [num(A, 0, 30, [10, 20])]);
    const l = createLearner(omegaOf(vs), { nullMass: 0.05 });
    const { added } = answerPartial(l, question(vs, [2]), {
      kind: 'partial',
      path: A,
      cuts: [15],
      parts: [{ values: ['11'], y: 0 }, { other: true, y: 0 }, { lo: 15, hi: 30, y: 0 }, { lo: 0, hi: 14, y: 1 }],
    });
    expect(added.map((o) => [o.cell, o.y])).toEqual([
      [[2], 1],
      [[3], 0],
      [[4], 0],
    ]);
  });
});

describe('answerPartial: sub-cells and recorded observations', () => {
  it('a new dimension: every one of its cells is a sub-cell of the question', () => {
    const va = vspace('v.a', [numN(A, 3)]);
    const l = createLearner(omegaOf(va), { nullMass: 0.05 });
    const { added } = answerPartial(l, question(va, [1]), {
      kind: 'partial',
      path: H,
      newDim: num(H, 0, 23, [12]),
      parts: [{ lo: 0, hi: 12, y: 1 }, { lo: 13, hi: 23, y: 0 }],
    });
    expect(added.map((o) => [o.cell, o.y])).toEqual([
      [[1, 0], 1],
      [[1, 1], 1],
      [[1, 2], 0],
    ]);
  });

  it('refines the dimension of the questioned verb, not of the first verb', () => {
    const va = vspace('v.a', [numN(A, 3)]);
    const vb = vspace('v.b', [cat(K, ['a'])]);
    const l = createLearner(omegaOf(va, vb), { nullMass: 0.05 });
    const { added } = answerPartial(l, question(vb, [1]), { kind: 'partial', path: K, values: ['b'], parts: [{ other: true, y: 1 }] });
    expect(added.map((o) => [o.verb, o.cell, o.y])).toEqual([['v.b', [2], 1]]);
  });

  it('fills dimensions the question outcome leaves out with the first cell representative', () => {
    const vs = vspace('v.m', [numN(A, 3), cat(K, ['a'])]);
    const l = createLearner(omegaOf(vs), { nullMass: 0.05 });
    const { added } = answerPartial(l, question(vs, [1, 1], { verb: 'v.m', values: {} }), { kind: 'partial', path: K, values: ['b'], parts: [{ other: true, y: 1 }] });
    expect(added.map((o) => o.values)).toEqual([{ [K]: 'other', [A]: 0 }]);
  });

  it('an observation the learner refuses (a value outside Ω) is not reported as added', () => {
    const vs = vspace('v.m', [numN(A, 3), cat(K, ['a'])]);
    const l = createLearner(omegaOf(vs), { nullMass: 0.05 });
    const { added } = answerPartial(l, question(vs, [1, 1], { verb: 'v.m', values: { [A]: 99 } }), { kind: 'partial', path: K, values: ['b'], parts: [{ other: true, y: 1 }] });
    expect(added).toEqual([]);
  });

  it('a categorical dimension whose region entry is numeric (a repeated path) has no sub-cells', () => {
    // the region keeps the last dimension of a path, the refinement edits the first
    const vs = vspace('v.d', [cat(A, ['a']), num(A, 0, 2, [])]);
    const l = createLearner(omegaOf(vs), { nullMass: 0.05 });
    expect(answerPartial(l, question(vs, [0, 0]), { kind: 'partial', path: A, values: ['b'], parts: [{ other: true, y: 1 }] }).added).toEqual([]);
  });
});

describe('elicitAdaptive: control flow on a stub learner', () => {
  const stub = (over: Record<string, unknown>) => over as unknown as IntentLearner;

  it('without seeds the seed loop never looks at Ω', () => {
    let finds = 0;
    const l = stub({ omega: { verbs: { find: () => (finds++, undefined) } }, metrics: () => ({ residualRisk: 0, burden: 0 }) });
    const r = elicitAdaptive(l, () => 1, { epsRisk: 0, epsBurden: 0, maxQuestions: 3 });
    expect(finds).toBe(0);
    expect(r).toEqual({ stop: 'converged', questions: 0, auditQuestions: 0, seedQuestions: 0, asked: [], learner: l, refinements: 0 });
  });

  it('a small burden alone does not converge while the risk is above epsRisk', () => {
    const l = stub({ metrics: () => ({ residualRisk: 1, burden: 0 }) });
    expect(elicitAdaptive(l, () => 1, { epsRisk: 0, epsBurden: 1, maxQuestions: 0 }).stop).toBe('budget');
  });

  it('no audit round unless audit is set', () => {
    let calls = 0;
    const l = stub({ metrics: () => ({ residualRisk: 0, burden: 0 }), unconfirmedGrantCells: () => (calls++, []) });
    expect(elicitAdaptive(l, () => 1, { epsRisk: 0, epsBurden: 0, maxQuestions: 5 }).stop).toBe('converged');
    expect(calls).toBe(0);
  });

  it('the audit round ends at once when nothing is pending, even with a negative epsRisk', () => {
    const l = stub({ metrics: () => ({ residualRisk: -2, burden: 0 }), unconfirmedGrantCells: () => [] });
    const r = elicitAdaptive(l, () => 1, { epsRisk: -1, epsBurden: 0, maxQuestions: 5, audit: true });
    expect([r.stop, r.questions, r.auditQuestions]).toEqual(['converged', 0, 0]);
  });
});
