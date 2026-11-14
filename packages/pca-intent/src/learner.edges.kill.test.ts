import { describe, expect, it } from 'vitest';
import { boxesToPredicates, elicit, hypothesisCellSets, IntentLearner, OTHER, type CatDim, type Dim, type NumDim, type Omega, type VerbSpace } from './index';

const P = 'action.params.';
const numN = (path: string, n: number): NumDim => ({ kind: 'num', path, lo: 0, hi: n - 1, cuts: Array.from({ length: n - 1 }, (_, i) => i + 1), dist: 'uniform' });
const cat = (path: string, exacts: string[] = []): CatDim => ({
  kind: 'cat',
  path,
  values: [...exacts.map((value) => ({ kind: 'exact' as const, value })), { kind: 'other' as const, value: OTHER }],
});
const vspace = (verb: string, dims: Dim[]): VerbSpace => ({ verb, reversibility: 'reversible', weight: 1, dims });
const omegaOf = (...verbs: VerbSpace[]): Omega => ({ v: 1, verbs, approximate: [] });
const sets = (s: Uint8Array[]) => s.map((x) => [...x]);

const V3 = vspace('v.a', [numN(P + 'a', 3)]);
const VC3 = vspace('v.c3', [cat(P + 'k', ['a', 'b'])]);
// a numeric dimension and a categorical one with only the OTHER value
const VK1 = vspace('v.k1', [numN(P + 'a', 3), cat(P + 'k')]);

describe('box hypotheses of a categorical dimension come in subset-mask order', () => {
  it('three values: masks 1..7', () => {
    expect(sets(hypothesisCellSets(VC3).sets)).toEqual([
      [1, 0, 0],
      [0, 1, 0],
      [1, 1, 0],
      [0, 0, 1],
      [1, 0, 1],
      [0, 1, 1],
      [1, 1, 1],
    ]);
  });
});

describe('atomic decision-list tests', () => {
  it('a categorical dimension gets one test per value (not numeric thresholds), in the exact order', () => {
    const r = hypothesisCellSets(VC3, { kind: 'decision-list', maxRules: 1, conditions: 'atomic' });
    expect(sets(r.sets)).toEqual([
      [1, 1, 1],
      [0, 1, 1],
      [1, 0, 0],
      [1, 0, 1],
      [0, 1, 0],
      [1, 1, 0],
      [0, 0, 1],
    ]);
    expect(r.complexity).toEqual([1, 1, 1, 1, 1, 1, 1]);
  });

  it('a test that holds on every cell (a one-value dimension) is not a rule: the class fits the cap exactly', () => {
    const dl = { kind: 'decision-list', maxRules: 1, conditions: 'atomic' } as const;
    expect(hypothesisCellSets(VK1, dl, { maxEnumeration: 10 }).sets.length).toBeGreaterThan(0);
    expect(() => hypothesisCellSets(VK1, dl, { maxEnumeration: 9 })).toThrow('pca-intent: the decision-list class (≤ 1 rules) for v.k1 exceeds the enumeration cap');
  });
});

describe('boxesToPredicates on a dimension with two OTHER values', () => {
  it('selecting one of them adds no condition at all', () => {
    const vs = vspace('v.o', [{ kind: 'cat', path: P + 'k', values: [{ kind: 'other', value: OTHER }, { kind: 'other', value: OTHER }] }]);
    expect(boxesToPredicates(vs, Uint8Array.from([1, 0]))).toEqual([{ verb: 'v.o', resource: '*' }]);
  });
});

describe('anchored prior with three anchors', () => {
  it('pins the exact posterior acceptance of every cell', () => {
    const pol = (verb: string) => ({ predicates: [{ verb, resource: '*' }] });
    const l = new IntentLearner(omegaOf(V3), {
      anchors: [
        { policy: pol('v.a'), lambda: 1 },
        { policy: { predicates: [] }, lambda: 2 },
        { policy: pol('v.a'), lambda: 3 },
      ],
    });
    expect(l.cells().map((c) => c.p)).toEqual([0.44478675239053467, 0.5738523886228761, 0.4447867523905347]);
  });
});

describe('agnostic selection: the conflict thresholds are inclusive', () => {
  it('a "no" when the live hypotheses hold exactly 1 - 1e-12 of the weight is a conflict', () => {
    const V1 = vspace('v.1', [{ kind: 'num', path: P + 'a', lo: 0, hi: 5, cuts: [], dist: 'uniform' }]);
    const l = new IntentLearner(omegaOf(V1), { agnosticSlack: 0, nullMass: 1e-12 });
    expect(l.observe({ verb: 'v.1', values: { [P + 'a']: 2 } }, 0)).toEqual({ verb: 'v.1', values: { [P + 'a']: 2 }, cell: [0], y: 0, source: 'elicitation', conflict: true });
  });

  it('a "yes" when the hypotheses containing the cell hold exactly 1e-12 of the weight is a conflict', () => {
    const V = vspace('v', [{ kind: 'num', path: P + 'a', lo: 0, hi: 1, cuts: [1], dist: 'uniform' }]);
    const l = new IntentLearner(omegaOf(V), { agnosticSlack: 0, nullMass: 0.0025, monotone: { paths: [P + 'a'], offMass: 7.518796992488722e-15 } });
    l.observe({ verb: 'v', values: { [P + 'a']: 0 } }, 0);
    expect(l.cells()[1]!.p).toBe(1e-12);
    expect(l.observe({ verb: 'v', values: { [P + 'a']: 1 } }, 1)?.conflict).toBe(true);
  });
});

describe('nextQuestion with equal noise rates', () => {
  it('scores with the single entropy term (exact score after one answer)', () => {
    const l = new IntentLearner(omegaOf(VC3), { eta: 0.04 });
    const q1 = l.nextQuestion()!;
    l.observe(q1.outcome, 0, 'elicitation');
    expect(l.nextQuestion()).toEqual({ verb: 'v.c3', cell: [1], outcome: { verb: 'v.c3', values: { [P + 'k']: 'b' } }, p: 0.4237288135593221, score: 0.7434538440114661 });
  });
});

describe('elicit stopping rule', () => {
  it('risk and burden exactly at the targets stop before any seed question', () => {
    const ref = new IntentLearner(omegaOf(V3)).metrics();
    const r = elicit(new IntentLearner(omegaOf(V3)), () => 1, { epsRisk: ref.residualRisk, epsBurden: ref.burden, maxQuestions: 5, seed: [{ verb: 'v.a', cell: [1] }] });
    expect([r.stop, r.questions, r.seedQuestions]).toEqual(['converged', 0, 0]);
  });

  it('a small burden alone does not converge while residual risk is above the target', () => {
    const l = new IntentLearner(omegaOf(V3), { tau: 0.3 });
    expect(l.metrics().residualRisk).toBeGreaterThan(0);
    const r = elicit(l, () => 1, { epsRisk: 0, epsBurden: 1e9, maxQuestions: 5 });
    expect(r.questions).toBeGreaterThan(0);
  });
});
