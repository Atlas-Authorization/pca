import { afterEach, describe, expect, it, vi } from 'vitest';
import { hashCanonical } from '@atlasauth/pca';
import { decodeCell, verbCellCount, type Omega } from '@atlasauth/pca-intent';
import {
  cryptoRand,
  debiasRandomizedResponse,
  gaussian,
  gaussianSigma,
  PopulationAggregator,
  populationCellKey,
  populationPrior,
  randomizedResponse,
  rrKeepProbability,
  type PopulationRelease,
  type PopulationVote,
} from './index';

const SCHEMA = hashCanonical({ t: 'schema-kill' });
const OMEGA: Omega = {
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
const VS = OMEGA.verbs[0]!;

const vote = (over: Partial<PopulationVote> = {}): PopulationVote => ({ principal: 'p1', schemaDigest: SCHEMA, cellKey: 'k1', y: 1, period: 7, ...over });

afterEach(() => vi.unstubAllGlobals());

describe('cryptoRand', () => {
  it('fails with a message when Web Crypto is missing', () => {
    vi.stubGlobal('crypto', undefined);
    expect(() => cryptoRand()).toThrow('cryptoRand: no Web Crypto available; pass a rand source');
  });
  it('builds a uniform from 27 + 26 random bits plus a half-step', () => {
    vi.stubGlobal('crypto', { getRandomValues: (a: Uint32Array) => (a.set([0, 0]), a) });
    expect(cryptoRand()).toBe(0.5 / 9007199254740992);
    vi.stubGlobal('crypto', { getRandomValues: (a: Uint32Array) => (a.set([32, 64]), a) });
    expect(cryptoRand()).toBe((67108864 + 1 + 0.5) / 9007199254740992);
  });
});

describe('gaussian', () => {
  it('redraws a zero uniform', () => {
    const seq = [0, 0.5, 0];
    expect(gaussian(() => seq.shift()!)).toBeCloseTo(Math.sqrt(2 * Math.LN2), 12);
  });
});

describe('gaussianSigma argument checks', () => {
  it('rejects each bad argument with its message', () => {
    for (const e of [0, 1, -0.5, 2]) expect(() => gaussianSigma(e, 1e-5, 1)).toThrow('gaussianSigma: the classic Gaussian mechanism needs epsilon in (0, 1)');
    for (const d of [0, 1, -0.5, 2]) expect(() => gaussianSigma(0.5, d, 1)).toThrow('gaussianSigma: delta must be in (0, 1)');
    for (const s of [0, -1]) expect(() => gaussianSigma(0.5, 1e-5, s)).toThrow('gaussianSigma: sensitivity must be > 0');
  });
});

describe('PopulationAggregator', () => {
  it('rejects a non-canonical digest and a bad cell cap with messages', () => {
    expect(() => new PopulationAggregator('nope', 1)).toThrow('PopulationAggregator: schemaDigest must be a canonical b64u digest');
    for (const m of [0, -1, 1.5, Number.NaN]) {
      expect(() => new PopulationAggregator(SCHEMA, 1, { maxCellsPerPrincipal: m })).toThrow('PopulationAggregator: maxCellsPerPrincipal must be a positive integer');
    }
    expect(() => new PopulationAggregator(SCHEMA, 1, { maxCellsPerPrincipal: 1 })).not.toThrow();
  });

  it('refuses each bad vote with its exact reason', () => {
    const a = new PopulationAggregator(SCHEMA, 7, { maxCellsPerPrincipal: 1 });
    expect(a.contribute(vote({ schemaDigest: hashCanonical({ t: 'other' }) }))).toEqual({ ok: false, reason: 'vote for another schema' });
    expect(a.contribute(vote({ period: 8 }))).toEqual({ ok: false, reason: 'vote for another period' });
    expect(a.contribute(vote({ y: 2 as 1 }))).toEqual({ ok: false, reason: 'y must be 0 or 1' });
    expect(a.contribute(vote({ principal: '' }))).toEqual({ ok: false, reason: 'an accountable principal is required' });
    expect(a.contribute(vote({ principal: undefined as unknown as string }))).toEqual({ ok: false, reason: 'an accountable principal is required' });
    expect(a.contribute(vote())).toEqual({ ok: true });
    expect(a.contribute(vote())).toEqual({ ok: false, reason: 'one vote per principal per cell per period (sensitivity 1)' });
    expect(a.contribute(vote({ cellKey: 'k2' }))).toEqual({ ok: false, reason: 'at most 1 cells per principal per period' });
    expect(a.contribute(vote({ principal: 'p2', y: 0 }))).toEqual({ ok: true });
  });

  it('release: rejects qMin outside (0, 0.5)', () => {
    const a = new PopulationAggregator(SCHEMA, 7, { rand: () => 1 });
    for (const qMin of [0, 0.5, -0.1, 0.7]) expect(() => a.release({ epsilon: 0.5, delta: 1e-5, qMin })).toThrow('release: qMin must be in (0, 0.5)');
  });

  it('release: exact noisy counts in sorted cell order, using the supplied source', () => {
    const draws = [0.3, 0.6, 0.2, 0.9, 0.7, 0.1, 0.45, 0.8];
    const q0 = [...draws];
    const a = new PopulationAggregator(SCHEMA, 7, { maxCellsPerPrincipal: 1, rand: () => q0.shift()! });
    // contribute in reverse key order, so the release must sort
    for (const [k, total, yes] of [['b', 150, 60], ['a', 200, 120]] as const) {
      for (let i = 0; i < total; i++) a.contribute(vote({ principal: `${k}${i}`, cellKey: k, y: i < yes ? 1 : 0 }));
    }
    const rel = a.release({ epsilon: 0.9, delta: 1e-5, qMin: 0.1, minCount: -1e9 });
    const sensitivity = Math.sqrt(2);
    const sigma = gaussianSigma(0.9, 1e-5, sensitivity);
    const q = [...draws];
    const g = () => gaussian(() => q.shift()!);
    const exp: PopulationRelease['cells'] = {};
    for (const [k, yes, total] of [['a', 120, 200], ['b', 60, 150]] as const) {
      const y = yes + sigma * g();
      const t = total + sigma * g();
      exp[k] = { q: Math.min(0.9, Math.max(0.1, y / t)), n: Math.round(t) };
    }
    expect(exp.a!.q).toBeGreaterThan(0.1);
    expect(exp.a!.q).toBeLessThan(0.9);
    expect(exp.b!.q).toBeGreaterThan(0.1);
    expect(exp.b!.q).toBeLessThan(0.9);
    expect(rel).toEqual({ v: 1, kind: 'pca-intent-population-prior', schema: SCHEMA, period: 7, epsilon: 0.9, delta: 1e-5, sigma, sensitivity, cells: exp });
  });

  it('release: clamps to [qMin, 1 - qMin] and keeps a cell whose count equals minCount', () => {
    // rand = 1 makes every Gaussian draw exactly 0, so the counts are exact
    const a = new PopulationAggregator(SCHEMA, 7, { rand: () => 1 });
    for (let i = 0; i < 4; i++) a.contribute(vote({ principal: `u${i}`, cellKey: 'all-yes', y: 1 }));
    for (let i = 0; i < 4; i++) a.contribute(vote({ principal: `u${i}`, cellKey: 'all-no', y: 0 }));
    const rel = a.release({ epsilon: 0.5, delta: 1e-5, qMin: 0.1, minCount: 4 });
    expect(rel.cells).toEqual({ 'all-yes': { q: 0.9, n: 4 }, 'all-no': { q: 0.1, n: 4 } });
    expect(a.release({ epsilon: 0.5, delta: 1e-5, qMin: 0.1, minCount: 4.5 }).cells).toEqual({});
  });
});

describe('randomized response', () => {
  it('rejects epsilon that is not positive and finite', () => {
    for (const e of [0, -1, Number.POSITIVE_INFINITY, Number.NaN]) expect(() => rrKeepProbability(e)).toThrow('randomized response: epsilon must be > 0');
  });
  it('flips when the draw equals the keep probability', () => {
    const p = rrKeepProbability(1);
    expect(randomizedResponse(1, 1, () => p)).toBe(0);
    expect(randomizedResponse(0, 1, () => p)).toBe(1);
    expect(randomizedResponse(1, 1, () => p - 1e-12)).toBe(1);
  });
  it('debias rejects each bad count and accepts the edges', () => {
    const msg = 'debias: bad counts';
    expect(() => debiasRandomizedResponse(1.5, 4, 1)).toThrow(msg);
    expect(() => debiasRandomizedResponse(1, 4.5, 1)).toThrow(msg);
    expect(() => debiasRandomizedResponse(1, 0, 1)).toThrow(msg);
    expect(() => debiasRandomizedResponse(0, 0, 1)).toThrow(msg);
    expect(() => debiasRandomizedResponse(-1, 4, 1)).toThrow(msg);
    expect(() => debiasRandomizedResponse(5, 4, 1)).toThrow(msg);
    expect(Number.isFinite(debiasRandomizedResponse(0, 4, 1))).toBe(true);
    expect(Number.isFinite(debiasRandomizedResponse(4, 4, 1))).toBe(true);
    expect(Number.isFinite(debiasRandomizedResponse(1, 1, 1))).toBe(true);
  });
});

describe('populationPrior', () => {
  const release = (cells: PopulationRelease['cells']): PopulationRelease => ({
    v: 1, kind: 'pca-intent-population-prior', schema: SCHEMA, period: 1, epsilon: 0.5, delta: 1e-6, sigma: 1, sensitivity: 1, cells,
  });
  it('accepts beta in [0, 0.9] only, with the message', () => {
    const r = release({});
    expect(() => populationPrior(r, -0.1)).toThrow('populationPrior: beta must be in [0, 0.9] (full support needs beta < 1)');
    expect(() => populationPrior(r, 0.95)).toThrow('populationPrior: beta must be in [0, 0.9]');
    expect(populationPrior(r, 0).beta).toBe(0);
    expect(populationPrior(r, 0.9).beta).toBe(0.9);
  });
  it('weights only the released cells inside the verb, never an out-of-range wrap-around cell', () => {
    const n = verbCellCount(VS);
    const key = populationCellKey(SCHEMA, VS, decodeCell(VS, 0));
    const mix = populationPrior(release({ [key]: { q: 0.3, n: 10 } }), 0.5);
    expect(mix.weight(VS, (c) => c === 0)).toBeCloseTo(0.3, 12);
    expect(mix.weight(VS, () => false)).toBeCloseTo(0.7, 12);
    expect(n).toBeGreaterThan(1);
  });
});
