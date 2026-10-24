import { describe, expect, it } from 'vitest';
import { hashCanonical } from '@atlasauth/pca';
import { cellRep, decodeCell, IntentLearner, rng, verbCellCount, type Omega } from '@atlasauth/pca-intent';
import {
  BETA_MAX,
  cryptoRand,
  debiasRandomizedResponse,
  gaussian,
  gaussianSigma,
  PopulationAggregator,
  populationCellKey,
  populationPrior,
  priorAdmittedPpm,
  randomizedResponse,
  rrKeepProbability,
  type PopulationRelease,
} from './index';

const SCHEMA = hashCanonical({ t: 'schema' });
const PAY: Omega = {
  v: 1,
  approximate: [],
  verbs: [
    {
      verb: 'pay',
      reversibility: 'irreversible',
      weight: 1,
      dims: [
        { kind: 'num', path: 'action.params.amount', lo: 0, hi: 1000, cuts: [100, 500], dist: 'uniform' },
        { kind: 'cat', path: 'action.params.to', values: [{ kind: 'exact', value: 'alice' }, { kind: 'exact', value: 'bob' }, { kind: 'other', value: '⊥' }] },
      ],
    },
  ],
};
const VS = PAY.verbs[0]!;
const N = verbCellCount(VS);

function randomRelease(r: () => number): PopulationRelease {
  const cells: PopulationRelease['cells'] = {};
  for (let c = 0; c < N; c++) if (r() < 0.8) cells[populationCellKey(SCHEMA, VS, decodeCell(VS, c))] = { q: 0.02 + 0.96 * r(), n: 100 };
  return { v: 1, kind: 'pca-intent-population-prior', schema: SCHEMA, period: 1, epsilon: 0.5, delta: 1e-6, sigma: 1, sensitivity: 1, cells };
}

const grantOf = (l: IntentLearner) => l.cells().map((c) => c.inGrant);

describe('T23: population priors are neutral at τ = 1 under noise-free answers', () => {
  it('G̃_1 is identical with and without the population prior, for any release, β and realizable answers (property)', () => {
    const r = rng(2026);
    let pDiffered = 0;
    for (let trial = 0; trial < 60; trial++) {
      // A realizable truth: an amount interval × a recipient set (a box of the hypothesis class).
      const a = Math.floor(r() * 5);
      const b = a + Math.floor(r() * (5 - a));
      const to = [0, 1, 2].filter(() => r() < 0.6);
      const truth = (idx: number[]) => idx[0]! >= a && idx[0]! <= b && to.includes(idx[1]!);
      const release = randomRelease(r);
      const beta = r() * BETA_MAX;
      const base = new IntentLearner(PAY, {});
      const pop = new IntentLearner(PAY, { priorMix: populationPrior(release, beta) });
      const k = Math.floor(r() * 10);
      for (let i = 0; i < k; i++) {
        const idx = decodeCell(VS, Math.floor(r() * N));
        const y = truth(idx) ? 1 : 0;
        base.observe(cellRep(VS, idx), y);
        pop.observe(cellRep(VS, idx), y);
      }
      expect(grantOf(pop)).toEqual(grantOf(base));
      expect(base.synthesize()).toEqual(pop.synthesize());
      // The prior does move p (it is not vacuous): it changes which questions get asked, not what is admitted.
      if (base.cells().some((c, i) => Math.abs(c.p - pop.cells()[i]!.p) > 1e-6)) pDiffered++;
    }
    expect(pDiffered).toBeGreaterThan(20);
  });
  it('priorAdmittedPpm is 0 at τ = 1, and measures the cells only the prior admits at τ < 1', () => {
    const release: PopulationRelease = { ...randomRelease(() => 0.5), cells: {} };
    for (let c = 0; c < N; c++) release.cells[populationCellKey(SCHEMA, VS, decodeCell(VS, c))] = { q: 0.98, n: 1000 };
    const mix = populationPrior(release, 0.9);
    expect(priorAdmittedPpm(PAY, {}, [], mix)).toBe(0);
    const obs = new IntentLearner(PAY, {});
    obs.observe(cellRep(VS, [0, 0]), 1);
    expect(priorAdmittedPpm(PAY, {}, obs.observations, mix)).toBe(0);
    expect(priorAdmittedPpm(PAY, { eta: 0.1, tau: 0.6 }, [], mix)).toBeGreaterThan(0);
  });
  it('β must keep full support', () => {
    expect(() => populationPrior(randomRelease(() => 0.3), 0.95)).toThrow(/beta/);
    expect(() => new IntentLearner(PAY, { priorMix: { beta: 1, weight: () => 1 } })).toThrow(/beta/);
    expect(() => new IntentLearner(PAY, { priorMix: { beta: 0.5, weight: () => Number.NaN } })).toThrow(/finite/);
  });
});

describe('DP aggregation (§3.12)', () => {
  it('one vote per principal per cell per period, a per-principal cell cap, and no foreign schema or period', () => {
    const agg = new PopulationAggregator(SCHEMA, 7, { maxCellsPerPrincipal: 2 });
    const v = (principal: string, cellKey: string, y: 0 | 1 = 1) => ({ principal, schemaDigest: SCHEMA, cellKey, y, period: 7 });
    expect(agg.contribute(v('p1', 'c1')).ok).toBe(true);
    expect(agg.contribute(v('p1', 'c1', 0)).ok).toBe(false);
    expect(agg.contribute(v('p1', 'c2')).ok).toBe(true);
    expect(agg.contribute(v('p1', 'c3')).ok).toBe(false);
    expect(agg.contribute({ ...v('p2', 'c1'), period: 8 }).ok).toBe(false);
    expect(agg.contribute({ ...v('p2', 'c1'), schemaDigest: hashCanonical({ t: 'other' }) }).ok).toBe(false);
    expect(agg.contribute(v('', 'c1')).ok).toBe(false);
  });
  it('calibrates σ to the whole-release L2 sensitivity and recovers a large cell, suppressing small ones', () => {
    const r = rng(1);
    const agg = new PopulationAggregator(SCHEMA, 1, { maxCellsPerPrincipal: 8, rand: r });
    for (let i = 0; i < 4000; i++) agg.contribute({ principal: `p${i}`, schemaDigest: SCHEMA, cellKey: 'big', y: r() < 0.7 ? 1 : 0, period: 1 });
    agg.contribute({ principal: 'lonely', schemaDigest: SCHEMA, cellKey: 'small', y: 1, period: 1 });
    const rel = agg.release({ epsilon: 0.5, delta: 1e-6 });
    expect(rel.sensitivity).toBeCloseTo(4, 12);
    expect(rel.sigma).toBeCloseTo((4 * Math.sqrt(2 * Math.log(1.25 / 1e-6))) / 0.5, 9);
    expect(Math.abs(rel.cells.big!.q - 0.7)).toBeLessThan(0.05);
    expect(rel.cells.small).toBeUndefined();
    expect(() => agg.release({ epsilon: 1.5, delta: 1e-6 })).toThrow(/epsilon/);
    expect(() => gaussianSigma(0.5, 0, 1)).toThrow(/delta/);
  });
  it('local randomized response is unbiased after debiasing', () => {
    const r = rng(9);
    const eps = 1;
    let yes = 0;
    const n = 40000;
    for (let i = 0; i < n; i++) yes += randomizedResponse(r() < 0.3 ? 1 : 0, eps, r);
    expect(Math.abs(debiasRandomizedResponse(yes, n, eps) - 0.3)).toBeLessThan(0.02);
    expect(rrKeepProbability(eps)).toBeCloseTo(Math.E / (1 + Math.E), 12);
  });
  it('the noise sources are sane', () => {
    const r = rng(4);
    let s = 0;
    let s2 = 0;
    const n = 20000;
    for (let i = 0; i < n; i++) {
      const x = gaussian(r);
      s += x;
      s2 += x * x;
    }
    expect(Math.abs(s / n)).toBeLessThan(0.03);
    expect(Math.abs(s2 / n - 1)).toBeLessThan(0.05);
    for (let i = 0; i < 100; i++) {
      const u = cryptoRand();
      expect(u > 0 && u < 1).toBe(true);
    }
  });
  it('a cell key is semantic (schema, verb, coordinates), never text', () => {
    expect(populationCellKey(SCHEMA, VS, [1, 0])).toBe(populationCellKey(SCHEMA, VS, [1, 0]));
    expect(populationCellKey(SCHEMA, VS, [1, 0])).not.toBe(populationCellKey(SCHEMA, VS, [1, 1]));
    expect(populationCellKey(SCHEMA, VS, [1, 0])).not.toBe(populationCellKey(hashCanonical({ t: 'x' }), VS, [1, 0]));
  });
});
