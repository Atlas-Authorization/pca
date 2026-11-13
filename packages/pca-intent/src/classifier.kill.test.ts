import { describe, expect, it } from 'vitest';
import { hashCanonical } from '@atlasauth/pca';
import {
  calibrateConfusion,
  classifierAwareResidualRisk,
  classifierCardNote,
  classifierDim,
  classifierJitCells,
  classifierRisk,
  confusionDigest,
  createLearner,
  labelSound,
  labelSoundBound,
  publishedErrorRate,
  type ClassifierRiskArrays,
  type ConfusionCalibration,
  type IntentLearner,
  type Omega,
} from './index';

const L = ['apologetic', 'hostile', 'neutral'];

describe('calibrateConfusion: refusals and the recorded level', () => {
  it('an empty label set is refused', () => {
    expect(() => calibrateConfusion([], [])).toThrow(new Error('calibrateConfusion: empty label set'));
  });
  it.each([0, 1, -0.1, 1.5, Number.NaN])('a level of %s is refused', (delta) => {
    expect(() => calibrateConfusion([], L, delta)).toThrow(new Error('calibrateConfusion: delta must be in (0, 1)'));
  });
  it('a label outside L is refused whichever side it is on, with both labels in the message', () => {
    expect(() => calibrateConfusion([{ truth: 'neutral', predicted: 'sarcastic' }], L)).toThrow(new Error('calibrateConfusion: label outside L (neutral / sarcastic)'));
    expect(() => calibrateConfusion([{ truth: 'sarcastic', predicted: 'neutral' }], L)).toThrow(new Error('calibrateConfusion: label outside L (sarcastic / neutral)'));
  });
  it('the level is recorded in ppm and the digest covers the domain, labels, counts and level', () => {
    const samples = [
      ...Array(40).fill({ truth: 'neutral', predicted: 'neutral' }),
      ...Array(2).fill({ truth: 'neutral', predicted: 'apologetic' }),
      ...Array(30).fill({ truth: 'hostile', predicted: 'hostile' }),
      ...Array(3).fill({ truth: 'hostile', predicted: 'neutral' }),
    ];
    const c = calibrateConfusion(samples, L, 0.09);
    expect(c.delta_ppm).toBe(90_000);
    expect(calibrateConfusion([], L, 0.5).delta_ppm).toBe(500_000);
    expect(confusionDigest(c)).toBe(hashCanonical({ d: 'atlas-pca/intent-classifier-calibration/v1', labels: L, counts: [[0, 0, 0], [0, 30, 3], [2, 0, 40]], delta_ppm: 90_000 }));
  });
});

describe('published error rate and card note', () => {
  const noisy: ConfusionCalibration = { labels: L, counts: [], gamma: [], gammaBar: [[0.9, 0.05, 0.3], [0.05, 0.9, 0.05], [0.05, 0.05, 0.9]], delta_ppm: 50_000 };
  it('is the largest off-diagonal row sum (the diagonal is the correct label)', () => {
    expect(publishedErrorRate(noisy)).toBeCloseTo(0.35, 12); // row 0: 0.05 + 0.3; rows 1, 2: 0.1
  });
  it('is shown as a percentage with one decimal', () => {
    expect(classifierCardNote('tone', noisy)).toBe('"tone" is decided by an attested classifier, not by a person. Published error rate: up to 35.0%.');
  });
});

describe('R_κ on explicit arrays (hand-computed)', () => {
  // Two x-values, three labels. Column t of g is the confusion of true label t (each column sums to 1).
  const m: ClassifierRiskArrays = {
    mu: [[0.1, 0.2, 0.3], [0.05, 0.15, 0.2]],
    a: [[1, 0, 0], [0, 1, 0]],
    h: [[2, 4, 8], [3, 5, 10]],
    inG: [[true, false, true], [false, true, false]],
    g: [[0.5, 0.2, 0.1], [0.3, 0.6, 0.1], [0.2, 0.2, 0.8]],
  };
  it('classifierRisk = Σ μ (1 − a) h Γ(A_G(x) | ℓ)', () => {
    // x=0: A={0,2}: t=1: 0.2·4·(0.2+0.2) = 0.32, t=2: 0.3·8·(0.1+0.8) = 2.16; x=1: A={1}: t=0: 0.05·3·0.3 = 0.045, t=2: 0.2·10·0.1 = 0.2
    expect(classifierRisk(m)).toBeCloseTo(2.725, 12);
  });
  it('labelSoundBound = H_max · Σ_{a=0} μ Γ(A_G(x) | ℓ)', () => {
    // x=0: 0.2·0.4 + 0.3·0.9 = 0.35; x=1: 0.05·0.3 + 0.2·0.1 = 0.035
    expect(labelSoundBound(m, 10)).toBeCloseTo(3.85, 12);
  });
  it('labelSound needs a = 1 on every cell of the grant, in every row', () => {
    expect(labelSound({ a: [[1, 0], [0, 1]], inG: [[true, false], [false, true]] })).toBe(true);
    expect(labelSound({ a: [[1, 1], [1, 0]], inG: [[true, true], [false, false]] })).toBe(true);
    expect(labelSound({ a: [[1, 0]], inG: [[true, true]] })).toBe(false); // one bad cell in a row
    expect(labelSound({ a: [[1, 0], [0, 1]], inG: [[true, false], [true, false]] })).toBe(false); // one bad row
  });
});

describe('R̂_κ and the γ_max gate over a learner', () => {
  const T = 'env.class.tone';
  const R = 'subject.tier';
  // pay has the classifier dimension FIRST, so flat cell order differs from the order the groups are visited in
  const omega: Omega = {
    v: 1,
    approximate: [],
    verbs: [
      { verb: 'ping', reversibility: 'reversible', weight: 0.5, dims: [{ kind: 'num', path: 'action.params.count', lo: 0, hi: 10, cuts: [5], dist: 'uniform' }] },
      { verb: 'pay', reversibility: 'irreversible', weight: 0.5, dims: [classifierDim('tone', L), { kind: 'num', path: R, lo: 0, hi: 3, cuts: [2], dist: 'uniform' }] },
      { verb: 'zap', reversibility: 'reversible', weight: 0.5, dims: [{ kind: 'num', path: 'action.params.n', lo: 0, hi: 4, cuts: [2], dist: 'uniform' }] },
    ],
  };
  const trained = (): IntentLearner => {
    const l = createLearner(omega, { nullMass: 0.05, tau: 0.5, eta: 0.1 });
    l.observe({ verb: 'pay', values: { [T]: 'neutral', [R]: 0 } }, 1);
    l.observe({ verb: 'pay', values: { [T]: 'apologetic', [R]: 0 } }, 1);
    l.observe({ verb: 'pay', values: { [T]: 'hostile', [R]: 0 } }, 0);
    l.observe({ verb: 'pay', values: { [T]: 'neutral', [R]: 3 } }, 1);
    l.observe({ verb: 'pay', values: { [T]: 'sarcastic', [R]: 0 } }, 1); // a label outside L: the ⊥ cell
    l.observe({ verb: 'ping', values: { 'action.params.count': 3 } }, 1);
    l.observe({ verb: 'ping', values: { 'action.params.count': 5 } }, 1);
    l.observe({ verb: 'zap', values: { 'action.params.n': 1 } }, 1);
    return l;
  };
  // A calibration that does not know "apologetic" and does list ⊥ among its labels: a predicted ⊥ is never output (column 0),
  // a true label unknown to the calibration (apologetic, ⊥) is a row of ones, and the other entries are read from the table.
  const cal: ConfusionCalibration = { labels: ['hostile', 'neutral', '⊥'], counts: [], gamma: [], gammaBar: [[0.1, 0.2, 0.3], [0.05, 0.15, 0.25], [0.01, 0.02, 0.03]], delta_ppm: 50_000 };
  const spec = { verb: 'pay', path: T, cal };

  it('the classifier verb contributes R̂_κ, every other verb its ordinary risk, and the sum is taken in a fixed order', () => {
    const r = classifierAwareResidualRisk(trained(), [spec]);
    expect(r.perVerb.ping).toBeCloseTo(0.025530470635559098, 10);
    expect(r.perVerb.zap).toBeCloseTo(0.05590277777777772, 10);
    expect(r.perVerb.pay).toBeCloseTo(0.6862211491554366, 10);
    expect(r.total).toBeCloseTo(0.7676543975687735, 10);
    expect(Object.keys(r.perVerb)).toEqual(['ping', 'zap', 'pay']);
  });

  it('without a classifier spec every verb is ordinary', () => {
    const r = classifierAwareResidualRisk(trained(), []);
    expect(Object.keys(r.perVerb)).toEqual(['ping', 'pay', 'zap']);
    expect(r.perVerb.pay).toBeCloseTo(0.5707093420330512, 10);
    expect(r.total).toBeCloseTo(0.6521425904463881, 10);
  });

  it('cells whose other coordinates print alike once joined without a separator stay in separate groups', () => {
    // a has 12 cells, b has 13: (a, b) = (1, 12) and (11, 2) would both read "112" without a comma
    const cuts = (n: number) => Array.from({ length: n }, (_, i) => i + 1);
    const big: Omega = {
      v: 1,
      approximate: [],
      verbs: [
        {
          verb: 'col',
          reversibility: 'irreversible',
          weight: 1,
          dims: [classifierDim('tone', L), { kind: 'num', path: 'subject.a', lo: 0, hi: 11, cuts: cuts(11), dist: 'uniform' }, { kind: 'num', path: 'subject.b', lo: 0, hi: 12, cuts: cuts(12), dist: 'uniform' }],
        },
      ],
    };
    const l = createLearner(big, { nullMass: 0.05, tau: 0.5, eta: 0.1 });
    for (const [tone, a, b, yes] of [['neutral', 1, 12, 1], ['neutral', 1, 12, 1], ['apologetic', 1, 12, 1], ['neutral', 11, 2, 0], ['neutral', 11, 2, 0]] as const) {
      l.observe({ verb: 'col', values: { [T]: tone, 'subject.a': a, 'subject.b': b } }, yes);
    }
    const colSpec = { verb: 'col', path: T, cal };
    expect(classifierAwareResidualRisk(l, [colSpec]).perVerb.col).toBeCloseTo(0.4243590227470493, 10);
    expect(classifierJitCells(l, colSpec, 0.01)).toHaveLength(38);
  });

  it('the γ_max gate returns the admitted cells of a group whose worst bad label gets through too often, in flat cell order', () => {
    const flat = (cells: { flat: number }[]) => cells.map((c) => c.flat);
    // bad true label: hostile (not admitted); admitted labels: apologetic (unknown to the calibration: 0), neutral (0.2), ⊥ (never output: 0)
    const out = classifierJitCells(trained(), spec, 0.1);
    expect(flat(out)).toEqual([0, 1, 2, 6, 7, 8, 9, 10, 11]);
    expect(out.map((c) => [c.verb, c.cell])).toEqual([
      ['pay', [0, 0]], ['pay', [0, 1]], ['pay', [0, 2]],
      ['pay', [2, 0]], ['pay', [2, 1]], ['pay', [2, 2]],
      ['pay', [3, 0]], ['pay', [3, 1]], ['pay', [3, 2]],
    ]);
    expect(classifierJitCells(trained(), spec, 0.25)).toEqual([]);
  });

  it('a verb that is not in Ω, and a path that is missing or not categorical, are refused with their names', () => {
    const l = trained();
    expect(() => classifierAwareResidualRisk(l, [{ ...spec, verb: 'nope' }])).toThrow(new Error('classifier: no verb nope in Ω'));
    expect(() => classifierAwareResidualRisk(l, [{ ...spec, path: 'env.class.none' }])).toThrow(new Error('classifier: pay has no categorical dimension env.class.none'));
    expect(() => classifierJitCells(l, { ...spec, path: 'env.class.none' }, 0.1)).toThrow(new Error('classifier: pay has no categorical dimension env.class.none'));
    expect(() => classifierJitCells(l, { ...spec, path: R }, 0.1)).toThrow(new Error('classifier: pay has no categorical dimension subject.tier'));
  });
});
