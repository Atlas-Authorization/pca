import { hashCanonical } from '@atlasauth/pca';
import { decodeCell, IntentLearner, verbCellCount, type LearnerOptions, type Observation, type Omega, type VerbSpace } from '@atlasauth/pca-intent';
import { coordsOfCell } from './box';
import { isB64u32 } from './wire';

/**
 * OPT-IN, PRIVACY-PRESERVING POPULATION PRIORS (§3.12, V16, T23).
 *
 * Contribution. A principal who opts in contributes cell-level answers keyed by (schema_digest, verb, semantic cell),
 * where the cell is its coordinates in schema units and semantic types (never free text). Each principal contributes
 * at most ONE vote per cell per period, and to at most `maxCellsPerPrincipal` cells per period.
 *
 * Central DP release (the aggregator, normally the Atlas instance). Per released cell the aggregator publishes noisy
 * counts (yes, total). One principal changes at most `maxCellsPerPrincipal` cells by one vote each, and a vote moves
 * both counts by one, so the L2 sensitivity of the whole release is Δ₂ = √(2 · maxCellsPerPrincipal). Gaussian noise
 * σ = Δ₂ · √(2 ln(1.25/δ)) / ε gives (ε, δ)-DP per release for ε ∈ (0, 1) (Dwork–Roth Thm 3.22). Composition across
 * releases is the operator's accounting (standard; not tracked here beyond the `release` counter).
 *
 * Local DP (for principals who do not trust the aggregator): randomized response with keep probability
 * e^ε/(1 + e^ε) per vote, debiased by the aggregator.
 *
 * Prior. π_0 = (1 − β)·π_base + β·π_pop with π_pop(θ) ∝ Π_c q_c^{1[c∈θ]} (1 − q_c)^{1[c∉θ]} over Θ̃ and β ≤ β_max < 1, so
 * the prior keeps full support. Hence T23: under noise-free answers and τ = 1, G̃_1 = ∩ VS_n does not depend on π_0. The
 * population prior changes which questions are asked and how many, never what is admitted at τ = 1. At τ < 1 it can
 * admit unasked cells; `priorAdmittedPpm` measures exactly that mass, so a site policy can require
 * `max_prior_admitted_ppm: 0`.
 */

export const POPULATION_VOTE_DOMAIN = 'atlas-pca/intent-population-cell/v1';
export const BETA_MAX = 0.9;

/** The semantic key of a cell: its coordinates in schema terms, bound to the schema digest and the verb. */
export function populationCellKey(schemaDigest: string, vs: VerbSpace, idx: readonly number[]): string {
  return hashCanonical({ d: POPULATION_VOTE_DOMAIN, s: schemaDigest, v: vs.verb, c: coordsOfCell(vs, idx) });
}

export interface PopulationVote {
  /** An accountable principal id (Sybil resistance is the identity provider's job, §3.15). */
  principal: string;
  schemaDigest: string;
  cellKey: string;
  y: 0 | 1;
  /** The period index (e.g. the ISO week number); one vote per principal, cell and period. */
  period: number;
}

export interface AggregatorOptions {
  maxCellsPerPrincipal?: number;
  /** Randomness source for the Gaussian noise. Default: Web Crypto. Tests pass a seeded generator. */
  rand?: () => number;
}

export interface ReleasedCell {
  /** Noisy acceptance rate, clamped to [qMin, 1 − qMin]. */
  q: number;
  /** Noisy vote count (for weighting by the consumer). */
  n: number;
}

export interface PopulationRelease {
  v: 1;
  kind: 'pca-intent-population-prior';
  schema: string;
  period: number;
  epsilon: number;
  delta: number;
  sigma: number;
  sensitivity: number;
  cells: Record<string, ReleasedCell>;
}

/** Uniform (0, 1) from 53 random bits of the Web Crypto CSPRNG (Node ≥ 20 and browsers alike). */
export function cryptoRand(): number {
  const c = (globalThis as { crypto?: { getRandomValues<T extends ArrayBufferView>(a: T): T } }).crypto;
  if (!c) throw new Error('cryptoRand: no Web Crypto available; pass a rand source');
  const w = c.getRandomValues(new Uint32Array(2));
  const hi = w[0]! >>> 5;
  const lo = w[1]! >>> 6;
  return (hi * 67108864 + lo + 0.5) / 9007199254740992;
}

/** A standard normal draw (Box–Muller) from a uniform source. */
export function gaussian(rand: () => number): number {
  let u = rand();
  while (u <= 0) u = rand();
  const v = rand();
  return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
}

/** σ of the Gaussian mechanism for L2 sensitivity Δ₂ (requires ε ∈ (0, 1), δ ∈ (0, 1)). */
export function gaussianSigma(epsilon: number, delta: number, l2Sensitivity: number): number {
  if (!(epsilon > 0 && epsilon < 1)) throw new Error('gaussianSigma: the classic Gaussian mechanism needs epsilon in (0, 1)');
  if (!(delta > 0 && delta < 1)) throw new Error('gaussianSigma: delta must be in (0, 1)');
  if (!(l2Sensitivity > 0)) throw new Error('gaussianSigma: sensitivity must be > 0');
  return (l2Sensitivity * Math.sqrt(2 * Math.log(1.25 / delta))) / epsilon;
}

export class PopulationAggregator {
  private readonly votes = new Map<string, { yes: number; total: number }>();
  private readonly perPrincipal = new Map<string, Set<string>>();
  private readonly maxCells: number;
  private readonly rand: () => number;
  constructor(readonly schemaDigest: string, readonly period: number, opts: AggregatorOptions = {}) {
    if (!isB64u32(schemaDigest)) throw new Error('PopulationAggregator: schemaDigest must be a canonical b64u digest');
    this.maxCells = opts.maxCellsPerPrincipal ?? 32;
    if (!(Number.isInteger(this.maxCells) && this.maxCells > 0)) throw new Error('PopulationAggregator: maxCellsPerPrincipal must be a positive integer');
    this.rand = opts.rand ?? cryptoRand;
  }

  /** Accept a vote; refuses a second vote on a cell, a vote past the per-principal cell cap, or a foreign schema/period. */
  contribute(v: PopulationVote): { ok: true } | { ok: false; reason: string } {
    if (v.schemaDigest !== this.schemaDigest) return { ok: false, reason: 'vote for another schema' };
    if (v.period !== this.period) return { ok: false, reason: 'vote for another period' };
    if (v.y !== 0 && v.y !== 1) return { ok: false, reason: 'y must be 0 or 1' };
    if (typeof v.principal !== 'string' || v.principal.length === 0) return { ok: false, reason: 'an accountable principal is required' };
    const mine = this.perPrincipal.get(v.principal) ?? new Set<string>();
    if (mine.has(v.cellKey)) return { ok: false, reason: 'one vote per principal per cell per period (sensitivity 1)' };
    if (mine.size >= this.maxCells) return { ok: false, reason: `at most ${this.maxCells} cells per principal per period` };
    mine.add(v.cellKey);
    this.perPrincipal.set(v.principal, mine);
    const c = this.votes.get(v.cellKey) ?? { yes: 0, total: 0 };
    this.votes.set(v.cellKey, { yes: c.yes + v.y, total: c.total + 1 });
    return { ok: true };
  }

  /** The (ε, δ)-DP release. Cells whose noisy count is below `minCount` are suppressed (q would be pure noise). */
  release(opts: { epsilon: number; delta: number; qMin?: number; minCount?: number }): PopulationRelease {
    const sensitivity = Math.sqrt(2 * this.maxCells);
    const sigma = gaussianSigma(opts.epsilon, opts.delta, sensitivity);
    const qMin = opts.qMin ?? 0.02;
    if (!(qMin > 0 && qMin < 0.5)) throw new Error('release: qMin must be in (0, 0.5)');
    const minCount = opts.minCount ?? 3 * sigma;
    const cells: Record<string, ReleasedCell> = {};
    for (const key of [...this.votes.keys()].sort()) {
      const c = this.votes.get(key)!;
      const yes = c.yes + sigma * gaussian(this.rand);
      const total = c.total + sigma * gaussian(this.rand);
      if (!(total >= minCount)) continue;
      cells[key] = { q: Math.min(1 - qMin, Math.max(qMin, yes / total)), n: Math.round(total) };
    }
    return { v: 1, kind: 'pca-intent-population-prior', schema: this.schemaDigest, period: this.period, epsilon: opts.epsilon, delta: opts.delta, sigma, sensitivity, cells };
  }
}

// ---- local DP ---------------------------------------------------------------------------------------------------------

export function rrKeepProbability(epsilon: number): number {
  if (!(epsilon > 0 && Number.isFinite(epsilon))) throw new Error('randomized response: epsilon must be > 0');
  return Math.exp(epsilon) / (1 + Math.exp(epsilon));
}

/** ε-LDP randomized response: report y with probability e^ε/(1+e^ε), else 1 − y. */
export function randomizedResponse(y: 0 | 1, epsilon: number, rand: () => number = cryptoRand): 0 | 1 {
  return rand() < rrKeepProbability(epsilon) ? y : ((1 - y) as 0 | 1);
}

/** Unbiased estimate of the true yes-rate from randomized reports: (ȳ − (1 − p)) / (2p − 1). */
export function debiasRandomizedResponse(yesReports: number, total: number, epsilon: number): number {
  if (!(Number.isInteger(yesReports) && Number.isInteger(total) && total > 0 && yesReports >= 0 && yesReports <= total)) throw new Error('debias: bad counts');
  const p = rrKeepProbability(epsilon);
  return (yesReports / total - (1 - p)) / (2 * p - 1);
}

// ---- the mixture prior ----------------------------------------------------------------------------------------------

/**
 * The learner's `priorMix` for a population release: weight(θ) = Π_c q_c^{1[c∈θ]}(1 − q_c)^{1[c∉θ]} over the released
 * cells of the verb (unreleased cells contribute the constant 1/2 and drop out), mixed with weight β ≤ β_max < 1.
 */
export function populationPrior(release: PopulationRelease, beta: number): NonNullable<LearnerOptions['priorMix']> {
  if (!(beta >= 0 && beta <= BETA_MAX)) throw new Error(`populationPrior: beta must be in [0, ${BETA_MAX}] (full support needs beta < 1)`);
  const perVerb = new WeakMap<VerbSpace, { cells: number[]; lq: number[]; lnq: number[] }>();
  const tables = (vs: VerbSpace) => {
    const hit = perVerb.get(vs);
    if (hit) return hit;
    const t = { cells: [] as number[], lq: [] as number[], lnq: [] as number[] };
    const n = verbCellCount(vs);
    for (let c = 0; c < n; c++) {
      const r = release.cells[populationCellKey(release.schema, vs, decodeCell(vs, c))];
      if (!r) continue;
      t.cells.push(c);
      t.lq.push(Math.log(r.q));
      t.lnq.push(Math.log(1 - r.q));
    }
    perVerb.set(vs, t);
    return t;
  };
  return {
    beta,
    weight: (vs, contains) => {
      const t = tables(vs);
      let lw = 0;
      for (let i = 0; i < t.cells.length; i++) lw += contains(t.cells[i]!) ? t.lq[i]! : t.lnq[i]!;
      return Math.exp(lw);
    },
  };
}

/**
 * μ-mass (ppm) of cells admitted only because of the population prior: in G_τ with the prior, not in G_τ without it,
 * after the same observations. Zero at τ = 1 under noise-free answers (T23); the map reports it as
 * `metrics.prior_admitted_ppm`.
 */
export function priorAdmittedPpm(omega: Omega, base: LearnerOptions, observations: readonly Observation[], mix: NonNullable<LearnerOptions['priorMix']>): number {
  const { priorMix: _drop, ...rest } = base;
  void _drop;
  const without = IntentLearner.replay(omega, rest, observations);
  const withPop = IntentLearner.replay(omega, { ...rest, priorMix: mix }, observations);
  const a = without.cells();
  const b = withPop.cells();
  let mass = 0;
  b.forEach((c, i) => {
    if (c.inGrant && !a[i]!.inGrant) mass += c.mass;
  });
  return Math.round(mass * 1_000_000);
}
