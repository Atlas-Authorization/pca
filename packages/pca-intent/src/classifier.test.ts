import { describe, expect, it } from 'vitest';
import {
  binomialCdf,
  calibrateConfusion,
  classifierAwareResidualRisk,
  classifierCardNote,
  classifierDim,
  classifierJitCells,
  classifierRisk,
  clopperPearsonUpper,
  confusionDigest,
  createLearner,
  deriveOmega,
  labelSound,
  labelSoundBound,
  publishedErrorRate,
  rng,
  withDims,
  type ClassifierRiskArrays,
  type ConfusionCalibration,
} from './index';

// Intent Layer v2 milestone V8: calibrated confusion matrices, R_κ (T20 decomposition and label-sound bound),
// R̂_κ folded into the map's residual risk, and the γ_max gate to JIT consent.

const L = ['apologetic', 'hostile', 'neutral'];

describe('Clopper-Pearson and calibration', () => {
  it('the upper bound is >= the MLE, decreasing in alpha, 1 at k = n and for an empty row', () => {
    for (const [k, n] of [[0, 10], [3, 10], [9, 10], [50, 200]] as const) {
      const u05 = clopperPearsonUpper(k, n, 0.05);
      const u01 = clopperPearsonUpper(k, n, 0.01);
      expect(u05).toBeGreaterThanOrEqual(k / n);
      expect(u01).toBeGreaterThanOrEqual(u05);
      expect(Math.abs(binomialCdf(k, n, u05) - 0.05)).toBeLessThan(1e-6);
    }
    expect(clopperPearsonUpper(10, 10, 0.05)).toBe(1);
    expect(clopperPearsonUpper(0, 0, 0.05)).toBe(1);
    // known value: k = 0, n = 10, alpha = 0.05 => 1 - 0.05^(1/10)
    expect(clopperPearsonUpper(0, 10, 0.05)).toBeCloseTo(1 - Math.pow(0.05, 0.1), 9);
  });

  it('calibrates counts, Γ and Γ̄ (union-bound level δ/|L|²), refuses labels outside L, digests only recomputable inputs', () => {
    const samples = [
      ...Array(40).fill({ truth: 'neutral', predicted: 'neutral' }),
      ...Array(2).fill({ truth: 'neutral', predicted: 'apologetic' }),
      ...Array(30).fill({ truth: 'hostile', predicted: 'hostile' }),
      ...Array(3).fill({ truth: 'hostile', predicted: 'neutral' }),
    ];
    const c = calibrateConfusion(samples, L, 0.09);
    expect(c.labels).toEqual(L);
    expect(c.counts).toEqual([[0, 0, 0], [0, 30, 3], [2, 0, 40]]);
    expect(c.gamma[2]![0]).toBeCloseTo(2 / 42, 12);
    expect(c.gammaBar[0]).toEqual([1, 1, 1]); // no apologetic example: unknown row
    expect(c.gammaBar[1]![2]).toBeCloseTo(clopperPearsonUpper(3, 33, 0.01), 12);
    for (let t = 0; t < 3; t++) for (let p = 0; p < 3; p++) expect(c.gammaBar[t]![p]).toBeGreaterThanOrEqual(c.gamma[t]![p]!);
    expect(() => calibrateConfusion([{ truth: 'sarcastic', predicted: 'neutral' }], L)).toThrow(/outside L/);
    expect(confusionDigest(c)).toBe(confusionDigest(calibrateConfusion([...samples].reverse(), [...L].reverse(), 0.09)));
    expect(publishedErrorRate(c)).toBe(1);
    expect(classifierCardNote('tone', c)).toMatch(/attested classifier, not by a person/);
  });
});

function randomArrays(seed: number, X: number, nL: number, exact: boolean): ClassifierRiskArrays {
  const r = rng(seed);
  const mu = Array.from({ length: X }, () => Array.from({ length: nL }, () => r()));
  const a = Array.from({ length: X }, () => Array.from({ length: nL }, () => (r() < 0.5 ? 1 : 0)));
  const h = Array.from({ length: X }, () => Array.from({ length: nL }, () => 1 + r() * 9));
  const inG = Array.from({ length: X }, (_, x) => Array.from({ length: nL }, (_, p) => a[x]![p] === 1 && r() < 0.7));
  // g[p][t]: columns sum to 1 when exact (a stochastic matrix per true label t)
  const g = Array.from({ length: nL }, () => Array.from({ length: nL }, () => r()));
  if (exact) for (let t = 0; t < nL; t++) {
    const s = g.reduce((acc, row) => acc + row[t]!, 0);
    for (let p = 0; p < nL; p++) g[p]![t] = g[p]![t]! / s;
  }
  return { mu, a, h, inG, g };
}

describe('T20: R_κ decomposition and the label-sound bound', () => {
  it('with a perfect classifier (Γ = I) R_κ is the ordinary risk Σ_{(x,ℓ)∈G} μ(1 − a)h', () => {
    for (let seed = 1; seed <= 50; seed++) {
      const m = randomArrays(seed, 4, 3, true);
      const I = m.g.map((row, p) => row.map((_, t) => (p === t ? 1 : 0)));
      let ordinary = 0;
      m.mu.forEach((row, x) => row.forEach((mu, t) => (ordinary += m.inG[x]![t] ? mu * (1 - m.a[x]![t]!) * m.h[x]![t]! : 0)));
      expect(classifierRisk({ ...m, g: I })).toBeCloseTo(ordinary, 12);
    }
  });

  it('for label-sound grants, R_κ(G) <= H_max · Σ_{a=0} μ Γ(A_G(x) | ℓ)', () => {
    for (let seed = 1; seed <= 100; seed++) {
      const m = randomArrays(seed, 5, 3, true);
      expect(labelSound(m)).toBe(true);
      const hMax = Math.max(...m.h.flat());
      expect(classifierRisk(m)).toBeLessThanOrEqual(labelSoundBound(m, hMax) + 1e-12);
    }
  });

  it('R_κ is monotone in Γ: an entrywise upper bound Γ̄ >= Γ gives R̂_κ >= R_κ', () => {
    for (let seed = 1; seed <= 100; seed++) {
      const m = randomArrays(seed, 4, 3, true);
      const r = rng(seed + 1000);
      const gBar = m.g.map((row) => row.map((v) => Math.min(1, v + r() * 0.2)));
      expect(classifierRisk({ ...m, g: gBar })).toBeGreaterThanOrEqual(classifierRisk(m) - 1e-12);
    }
  });
});

describe('R̂_κ from a learner and the γ_max gate', () => {
  const AMT = 'action.params.count';
  const omega = withDims(deriveOmega({ policies: [], slots: { verbs: ['slack.post_message'], constraints: [{ path: AMT, max: 10 }] } }), 'slack.post_message', [classifierDim('tone', L)]);
  const exactCal = (): ConfusionCalibration => ({ labels: L, counts: [], gamma: [], gammaBar: L.map((_, t) => L.map((__, p) => (p === t ? 1 : 0))), delta_ppm: 50_000 });
  const noisyCal = (): ConfusionCalibration => ({ labels: L, counts: [], gamma: [], gammaBar: [[0.9, 0.05, 0.3], [0.05, 0.9, 0.05], [0.05, 0.05, 0.9]], delta_ppm: 50_000 });
  const spec = (cal: ConfusionCalibration) => ({ verb: 'slack.post_message', path: 'env.class.tone', cal });

  function trained() {
    const l = createLearner(omega, { nullMass: 0.05 });
    // the principal: neutral or apologetic messages, any count up to 10; never hostile
    for (const tone of ['neutral', 'apologetic']) l.observe({ verb: 'slack.post_message', values: { [AMT]: 3, 'env.class.tone': tone } }, 1);
    l.observe({ verb: 'slack.post_message', values: { [AMT]: 3, 'env.class.tone': 'hostile' } }, 0);
    return l;
  }

  it('with an exact classifier and no mass on ⊥ true labels, R̂_κ equals the ordinary R̂ restricted to labelled cells', () => {
    const l = trained();
    const r = classifierAwareResidualRisk(l, [spec(exactCal())]);
    let ordinary = 0;
    let otherRows = 0;
    const k = omega.verbs[0]!.dims.findIndex((d) => d.path === 'env.class.tone');
    for (const c of l.cells()) {
      const isOther = omega.verbs[0]!.dims[k]!.kind === 'cat' && c.cell[k] === L.length;
      if (c.inGrant && !isOther) ordinary += c.mass * (1 - c.p) * c.harm;
      if (isOther) otherRows += c.mass * (1 - c.p) * c.harm; // ⊥ true-label rows are all ones: bounded by their full weight
    }
    expect(r.total).toBeGreaterThanOrEqual(ordinary - 1e-12);
    expect(r.total).toBeLessThanOrEqual(ordinary + otherRows + 1e-12);
  });

  it('a noisy Γ̄ raises R̂_κ above the exact one, and the γ_max gate routes the admitted labels to JIT', () => {
    const l = trained();
    const exact = classifierAwareResidualRisk(l, [spec(exactCal())]).total;
    const noisy = classifierAwareResidualRisk(l, [spec(noisyCal())]).total;
    expect(noisy).toBeGreaterThanOrEqual(exact);
    // rows are true labels: a hostile message (not admitted) is labelled apologetic or neutral with Γ̄ 0.05 + 0.05 = 0.1
    expect(classifierJitCells(l, spec(noisyCal()), 0.2)).toEqual([]);
    const jit = classifierJitCells(l, spec(noisyCal()), 0.05);
    expect(jit.length).toBeGreaterThan(0);
    const k = omega.verbs[0]!.dims.findIndex((d) => d.path === 'env.class.tone');
    for (const c of jit) expect(c.cell[k]).not.toBe(L.indexOf('hostile'));
    expect(classifierJitCells(l, spec(exactCal()), 0)).toEqual([]);
  });

  it('an unknown verb or a non-categorical path is refused', () => {
    const l = trained();
    expect(() => classifierAwareResidualRisk(l, [{ ...spec(exactCal()), verb: 'nope' }])).toThrow(/no verb/);
    expect(() => classifierJitCells(l, { ...spec(exactCal()), path: AMT }, 0.1)).toThrow(/categorical/);
  });
});
