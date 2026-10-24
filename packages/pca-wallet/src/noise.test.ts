import { describe, expect, it } from 'vitest';
import { rng, type Omega } from '@atlasauth/pca-intent';
import {
  admissionPolicy,
  betaInc,
  betaQuantile,
  boundaryNeighbours,
  clopperPearsonUpper,
  doubleConfirmed,
  EMPTY_NOISE,
  estimateNoise,
  etaUnderLoad,
  noiseState,
  pickCanary,
  recordCanary,
  SlidingWindowCounter,
  DEFAULT_FATIGUE,
} from './index';

describe('numerics', () => {
  it('Beta(1, b) has the closed-form CDF 1 − (1 − x)^b and quantile 1 − (1 − q)^(1/b)', () => {
    for (const b of [1, 2, 9, 30]) {
      for (const x of [0.01, 0.1, 0.37, 0.9]) expect(betaInc(x, 1, b)).toBeCloseTo(1 - (1 - x) ** b, 12);
      expect(betaQuantile(0.95, 1, b)).toBeCloseTo(1 - 0.05 ** (1 / b), 12);
    }
  });
  it('symmetry I_x(a, b) = 1 − I_{1−x}(b, a) (property)', () => {
    const r = rng(11);
    for (let i = 0; i < 200; i++) {
      const a = 0.5 + r() * 20;
      const b = 0.5 + r() * 20;
      const x = r();
      expect(betaInc(x, a, b)).toBeCloseTo(1 - betaInc(1 - x, b, a), 10);
    }
  });
  it('Clopper–Pearson (exact binomial-tail inversion) agrees with the independent Beta-quantile formula', () => {
    for (const [k, n, d] of [[0, 10, 0.05], [1, 20, 0.05], [3, 33, 0.01], [7, 50, 0.1], [19, 20, 0.05], [12, 100, 0.001]] as const) {
      const exact = clopperPearsonUpper(k, n, d);
      const viaBeta = betaQuantile(1 - d, k + 1, n - k);
      expect(Math.abs(exact - viaBeta)).toBeLessThan(1e-9);
    }
  });
  it('Clopper–Pearson: k = 0 gives 1 − δ^(1/n); bounds grow with k and shrink with n', () => {
    expect(clopperPearsonUpper(0, 10, 0.05)).toBeCloseTo(1 - 0.05 ** (1 / 10), 12);
    expect(clopperPearsonUpper(10, 10, 0.05)).toBe(1);
    expect(clopperPearsonUpper(2, 20, 0.05)).toBeGreaterThan(clopperPearsonUpper(1, 20, 0.05));
    expect(clopperPearsonUpper(1, 40, 0.05)).toBeLessThan(clopperPearsonUpper(1, 20, 0.05));
  });
});

describe('canary noise estimates (§3.4 item 5)', () => {
  it('Beta(1 + false_yes, 9 + correct_no): prior mean 0.1; a false yes raises it, correct noes lower it', () => {
    expect(estimateNoise(EMPTY_NOISE).etaPos).toBeCloseTo(0.1, 12);
    const fy = recordCanary(EMPTY_NOISE, 0, 1);
    expect(fy).toEqual({ falseYes: 1, correctNo: 0, falseNo: 0, correctYes: 0 });
    expect(estimateNoise(fy).etaPos).toBeCloseTo(2 / 11, 12);
    let n = EMPTY_NOISE;
    for (let i = 0; i < 20; i++) n = recordCanary(n, 0, 0);
    expect(estimateNoise(n).etaPos).toBeCloseTo(1 / 30, 12);
    expect(estimateNoise(n).etaPosUpper).toBeCloseTo(1 - 0.05 ** (1 / 29), 10);
    expect(recordCanary(EMPTY_NOISE, 1, 0).falseNo).toBe(1);
    expect(recordCanary(EMPTY_NOISE, 1, 1).correctYes).toBe(1);
  });
});

const OM: Omega = {
  v: 1,
  approximate: [],
  verbs: [{ verb: 'pay', reversibility: 'irreversible', weight: 1, dims: [{ kind: 'num', path: 'action.params.amount', lo: 0, hi: 1000, cuts: [100, 500], dist: 'uniform' }, { kind: 'cat', path: 'action.params.to', values: [{ kind: 'exact', value: 'alice' }, { kind: 'exact', value: 'bob' }, { kind: 'other', value: '⊥' }] }] }],
};

describe('canary selection near the boundary', () => {
  it('neighbours differ from a confirmed cell in exactly one dimension and are outside the confirmed region', () => {
    const conf = [{ verb: 'pay', idx: [0, 0] }, { verb: 'pay', idx: [1, 0] }];
    const ns = boundaryNeighbours(OM, conf);
    for (const n of ns) {
      const diffs = conf.map((c) => c.idx.filter((x, k) => x !== n.idx[k]).length);
      expect(Math.min(...diffs)).toBe(1);
      expect(conf.some((c) => c.idx.join() === n.idx.join())).toBe(false);
    }
    expect(ns.map((n) => n.idx.join())).toEqual(['0,1', '0,2', '1,1', '1,2', '2,0']);
  });
  it('picks only known labels, at rate ρ, at most once in a low-harm session (property)', () => {
    const r = rng(5);
    let inserted = 0;
    for (let i = 0; i < 2000; i++) {
      const c = pickCanary({
        omega: OM,
        confirmed: [{ verb: 'pay', idx: [0, 0] }],
        knownNo: (_v, idx) => (idx[1] === 2 ? 'ceiling' : idx[0] === 1 ? 'veto' : null),
        knownYes: [{ verb: 'pay', idx: [0, 0] }],
        exclude: new Set(),
        rand: r,
        rho: 0.1,
        lowHarmSession: false,
        canariesSoFar: 0,
      });
      if (!c) continue;
      inserted++;
      if (c.expected === 0) expect(c.idx[1] === 2 || c.idx[0] === 1).toBe(true);
      else expect(c.idx).toEqual([0, 0]);
    }
    expect(inserted).toBeGreaterThan(130);
    expect(inserted).toBeLessThan(270);
    expect(pickCanary({ omega: OM, confirmed: [{ verb: 'pay', idx: [0, 0] }], knownNo: () => 'veto', knownYes: [], exclude: new Set(), rand: () => 0, rho: 1, lowHarmSession: true, canariesSoFar: 1 })).toBeNull();
  });
});

describe('fatigue, freezing, admission (§3.4 items 6-7)', () => {
  it('η⁺ grows with load and is capped at 1/2', () => {
    expect(etaUnderLoad(0.1, 0.005, 10)).toBeCloseTo(0.15, 12);
    expect(etaUnderLoad(0.4, 0.05, 100)).toBe(0.5);
  });
  it('a fresh principal is not frozen; one false yes freezes (mean > η_stop); the literal reading freezes at once', () => {
    expect(noiseState(EMPTY_NOISE, 0).frozen).toBe(false);
    expect(noiseState(recordCanary(EMPTY_NOISE, 0, 1), 0).frozen).toBe(true);
    expect(noiseState(EMPTY_NOISE, 0, { ...DEFAULT_FATIGUE, freezeOn: 'upper' }).frozen).toBe(true);
    // Load alone can freeze: 0.1 + 0.005 * 11 > 0.15.
    expect(noiseState(EMPTY_NOISE, 11).frozen).toBe(true);
  });
  it('estimated noise forbids τ = 1 and requires double confirmation; NF keeps τ = 1', () => {
    const p = admissionPolicy(noiseState(EMPTY_NOISE, 0));
    expect(p.tau).toBeCloseTo(0.95, 12);
    expect(p.doubleConfirmIrreversible).toBe(true);
    expect(p.falseAdmitBound).toBeCloseTo(p.etaPos * p.etaPos, 12);
    expect(p.etaPos).toBeLessThan(0.5);
    expect(admissionPolicy(noiseState(EMPTY_NOISE, 0), { ...DEFAULT_FATIGUE, assumeNoiseFree: true })).toEqual({ tau: 1, etaPos: 0, etaNeg: 0, doubleConfirmIrreversible: false, falseAdmitBound: 0 });
  });
  it('the hourly counter is a sliding window shared across sessions', () => {
    const c = new SlidingWindowCounter(1000);
    expect(c.tryAdd(0, 2)).toBe(true);
    expect(c.tryAdd(10, 2)).toBe(true);
    expect(c.tryAdd(20, 2)).toBe(false);
    expect(c.count(999)).toBe(2);
    expect(c.count(1000)).toBe(1);
    expect(c.tryAdd(1011, 2)).toBe(true);
    expect(() => c.tryAdd(5, 10)).toThrow(/backwards/);
  });
  it('double confirmation needs two strong answers with another screen in between', () => {
    expect(doubleConfirmed([{ screen: 1, tier: 'typed' }, { screen: 2, tier: 'typed' }])).toBe(false);
    expect(doubleConfirmed([{ screen: 1, tier: 'typed' }, { screen: 3, tier: 'device' }])).toBe(true);
    expect(doubleConfirmed([{ screen: 1, tier: 'tap' }, { screen: 3, tier: 'typed' }])).toBe(false);
  });
});
