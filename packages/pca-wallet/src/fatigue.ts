import { estimateNoise, type NoiseCounts } from './canary';

/**
 * APPROVAL FATIGUE AND ITS CONSEQUENCES FOR THE GRANT (§2.5, §3.4 items 6-7).
 *
 * Load model: η⁺_n = η⁺_0 + β_f · n_recent, capped at 1/2, where n_recent is the number of questions the principal saw
 * in the last hour (across sessions) and η⁺_0 is the canary estimate. Prototype default β_f = 0.005.
 *
 * Freezing. The spec freezes lazy widening when "η̄⁺ rises above η_stop (0.15)". With the spec's own Beta(1, 9) prior and
 * a 95% upper bound, η̄⁺ is 0.28 before any canary, so a literal reading would freeze every session at its first
 * question. This implementation therefore freezes on the posterior MEAN under load (0.1 before any canary, above 0.15
 * after the first false yes on a fresh principal), and uses the UPPER bound η̄⁺ where the spec needs a conservative
 * number: the learner's noise and the double-confirmation bound. `freezeOn: 'upper'` gives the literal reading.
 *
 * Admission (§3.4 item 7). Under the noise-free assumption (NF, the v1 default) the grant is G̃_1 (τ = 1, T14). Once
 * noise is estimated, η̄⁺ > 0, T = 1 is unavailable, and the wallet admits a cell only at p ≥ τ = 1 − δ (the T17
 * credence bound applies), and requires two independent confirmations at typed or device tier, separated by at least
 * one other screen, for an irreversible cell. If false yeses are independent ([X], measured by the M4 study), the
 * false-admit probability of such a cell is at most (η̄⁺)².
 */

export interface FatigueModel {
  /** β_f ≥ 0: added false-yes rate per question in the last hour. */
  betaF: number;
  /** η_stop: freeze lazy widening above this. */
  etaStop: number;
  /** δ_c: level of the upper bound η̄. */
  deltaC: number;
  /** Which statistic is compared with η_stop (see the module comment). */
  freezeOn: 'mean' | 'upper';
  /** Assume noise-free answers (NF, τ = 1) instead of the estimate. The v1 default; T14 holds only under it. */
  assumeNoiseFree: boolean;
  /** δ in τ = 1 − δ when noise is estimated. */
  delta: number;
}

export const DEFAULT_FATIGUE: FatigueModel = Object.freeze({ betaF: 0.005, etaStop: 0.15, deltaC: 0.05, freezeOn: 'mean', assumeNoiseFree: false, delta: 0.05 });

/** η⁺ under load: base + β_f · n_recent, capped at 1/2. */
export function etaUnderLoad(base: number, betaF: number, nRecent: number): number {
  if (!(base >= 0 && betaF >= 0 && Number.isInteger(nRecent) && nRecent >= 0)) throw new Error('etaUnderLoad: bad arguments');
  return Math.min(0.5, base + betaF * nRecent);
}

export interface NoiseState {
  /** Posterior mean of η⁺ under load. */
  etaPos: number;
  /** Upper bound η̄⁺ under load (the learner's η⁺). */
  etaPosBar: number;
  /** Upper bound η̄⁻ (the learner's η⁻; load does not raise false noes in this model). */
  etaNegBar: number;
  frozen: boolean;
}

export function noiseState(counts: NoiseCounts, nRecent: number, model: FatigueModel = DEFAULT_FATIGUE): NoiseState {
  const e = estimateNoise(counts, model.deltaC);
  const etaPos = etaUnderLoad(e.etaPos, model.betaF, nRecent);
  const etaPosBar = etaUnderLoad(e.etaPosUpper, model.betaF, nRecent);
  const stat = model.freezeOn === 'mean' ? etaPos : etaPosBar;
  return { etaPos, etaPosBar, etaNegBar: Math.min(0.5, e.etaNegUpper), frozen: stat > model.etaStop };
}

export interface AdmissionPolicy {
  tau: number;
  /** Learner noise (each strictly below 1/2, as the learner requires). */
  etaPos: number;
  etaNeg: number;
  /** Irreversible cells need two independent typed/device confirmations. */
  doubleConfirmIrreversible: boolean;
  /** Bound on the false-admit probability of a double-confirmed cell, under independence ([X]). */
  falseAdmitBound: number;
}

const BELOW_HALF = 0.5 - 1e-9;

export function admissionPolicy(state: NoiseState, model: FatigueModel = DEFAULT_FATIGUE): AdmissionPolicy {
  if (model.assumeNoiseFree) return { tau: 1, etaPos: 0, etaNeg: 0, doubleConfirmIrreversible: false, falseAdmitBound: 0 };
  if (!(model.delta > 0 && model.delta < 1)) throw new Error('admissionPolicy: delta must be in (0, 1)');
  const ep = Math.min(BELOW_HALF, state.etaPosBar);
  const en = Math.min(BELOW_HALF, state.etaNegBar);
  return { tau: 1 - model.delta, etaPos: ep, etaNeg: en, doubleConfirmIrreversible: ep > 0, falseAdmitBound: ep * ep };
}

/**
 * Sliding-window question counter shared across sessions (the per-hour cap is an accumulator, so an agent cannot split
 * around it by opening sessions). Keeps only timestamps inside the window.
 */
export class SlidingWindowCounter {
  private readonly times: number[] = [];
  constructor(readonly windowMs: number = 3_600_000) {
    if (!(Number.isInteger(windowMs) && windowMs > 0)) throw new Error('SlidingWindowCounter: windowMs must be a positive integer');
  }
  private prune(now: number): void {
    while (this.times.length > 0 && this.times[0]! <= now - this.windowMs) this.times.shift();
  }
  count(now: number): number {
    this.prune(now);
    return this.times.length;
  }
  /** Record one event at `now` if the count is below `cap`; false (and nothing recorded) otherwise. */
  tryAdd(now: number, cap: number): boolean {
    this.prune(now);
    if (this.times.length >= cap) return false;
    if (this.times.length > 0 && now < this.times[this.times.length - 1]!) throw new Error('SlidingWindowCounter: time went backwards');
    this.times.push(now);
    return true;
  }
}

/**
 * Double confirmation of an irreversible cell (§3.4 item 7): two "yes" answers at typed or device tier, on different
 * screens, with at least one other screen between them.
 */
export interface ConfirmationRecord {
  screen: number;
  tier: 'tap' | 'hold' | 'typed' | 'device';
}

export function doubleConfirmed(records: readonly ConfirmationRecord[]): boolean {
  const strong = records.filter((r) => r.tier === 'typed' || r.tier === 'device').map((r) => r.screen).sort((a, b) => a - b);
  for (let i = 0; i < strong.length; i++) for (let j = i + 1; j < strong.length; j++) if (strong[j]! - strong[i]! >= 2) return true;
  return false;
}
