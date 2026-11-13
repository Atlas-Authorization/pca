import { verifyIntentObservation, type IntentVerifyOptions, type SignedIntentObservation } from '@atlasauth/pca/ext/intent';
import type { IntentLearner } from './learner';
import type { MapLearnerOptions } from './map';
import type { Omega, Outcome } from './omega';
import type { IntentSlots } from './slots';

/**
 * TRUST RAMP AND DRIFT (spec §4.6, roadmap M5).
 *
 * Start narrow (`narrowStart`): τ = 1, ∅ prior high for every verb, very high for verbs the slots do not name, no
 * anchor. Authority then widens ONLY through confirmed behaviour (a cell enters G only when p_n reaches τ), and every
 * negative runtime signal vetoes its cell for good (the ratchet; `IntentLearner.observe` with source `runtime`).
 *
 * Runtime signals map to labels:
 *   jit-approve, principal-confirm              → y = 1
 *   jit-refuse, challenge-upheld, judge-deny-upheld, postcondition-violation → y = 0 (veto)
 *
 * DRIFT: a one-sided Bernoulli CUSUM (Page 1954) on DIVERGENCES, i.e. negative signals about actions the map's grant
 * admitted at the time (the map was wrong there). Under H0 they occur at rate ρ₀, under H1 at ρ₁ > ρ₀; the statistic
 * S_t = max(0, S_{t−1} + log LR_t) raises an alarm at S_t ≥ h. Signals about actions OUTSIDE the grant carry no
 * evidence about the grant and leave S unchanged. On alarm the ramp FREEZES widening: positive signals are queued
 * (not fed to the learner) until `rebase` with a new, signed intent statement; negative signals are always applied.
 * The statistic is non-negative, an alarm is sticky until rebase, and freezing can only shrink what the grant
 * admits relative to not freezing (pending theorem R2).
 */

export type RuntimeSignal = 'jit-approve' | 'principal-confirm' | 'jit-refuse' | 'challenge-upheld' | 'judge-deny-upheld' | 'postcondition-violation';

export function signalLabel(s: RuntimeSignal): 0 | 1 {
  return s === 'jit-approve' || s === 'principal-confirm' ? 1 : 0;
}

/** The narrow starting configuration for a learner that will be ramped (spec §4.6 "Start narrow"). */
export function narrowStart(omega: Omega, slots: IntentSlots, opts: { slotNullMass?: number; otherNullMass?: number } = {}): MapLearnerOptions {
  const nullMass: Record<string, number> = {};
  for (const vs of omega.verbs) nullMass[vs.verb] = slots.verbs.includes(vs.verb) ? (opts.slotNullMass ?? 0.5) : (opts.otherNullMass ?? 0.95);
  return { eta: 0, tau: 1, nullMass };
}

export interface DriftOptions {
  /** Divergence rate under "the map is right". Default 0.02. */
  rho0?: number;
  /** Divergence rate to detect. Default 0.25. */
  rho1?: number;
  /** Alarm threshold h on the CUSUM statistic (nats). Default ln(100) ≈ 4.6. */
  h?: number;
}

export interface DriftState {
  statistic: number;
  alarm: boolean;
  /** Signals that fed the statistic (actions inside the grant at the time). */
  informative: number;
  divergences: number;
}

export class DriftDetector {
  readonly rho0: number;
  readonly rho1: number;
  readonly h: number;
  private s: DriftState = { statistic: 0, alarm: false, informative: 0, divergences: 0 };

  constructor(o: DriftOptions = {}) {
    this.rho0 = o.rho0 ?? 0.02;
    this.rho1 = o.rho1 ?? 0.25;
    this.h = o.h ?? Math.log(100);
    if (!(this.rho0 > 0 && this.rho0 < this.rho1 && this.rho1 < 1)) throw new Error('DriftDetector: need 0 < rho0 < rho1 < 1');
    if (!(this.h > 0)) throw new Error('DriftDetector: h must be positive');
  }

  /** Feed one signal about an action that was inside the grant: diverged = true for a negative signal. */
  update(diverged: boolean): DriftState {
    const inc = diverged ? Math.log(this.rho1 / this.rho0) : Math.log((1 - this.rho1) / (1 - this.rho0));
    const statistic = Math.max(0, this.s.statistic + inc);
    this.s = { statistic, alarm: this.s.alarm || statistic >= this.h, informative: this.s.informative + 1, divergences: this.s.divergences + (diverged ? 1 : 0) };
    return this.state;
  }

  get state(): DriftState {
    return { ...this.s };
  }

  reset(): void {
    this.s = { statistic: 0, alarm: false, informative: 0, divergences: 0 };
  }
}

export interface RampRecord {
  signal: RuntimeSignal;
  y: 0 | 1;
  /** Was the action inside the grant when the signal arrived? */
  wasInGrant: boolean;
  /** Cells in the grant before / after. */
  before: number;
  after: number;
  /** Applied to the learner (false: a positive signal queued because widening is frozen). */
  applied: boolean;
  drift: DriftState;
}

export class TrustRamp {
  private l: IntentLearner;
  readonly drift: DriftDetector;
  private queued: { o: Outcome; signal: RuntimeSignal }[] = [];
  readonly log: RampRecord[] = [];

  constructor(learner: IntentLearner, drift: DriftOptions = {}) {
    this.l = learner;
    this.drift = new DriftDetector(drift);
  }

  get learner(): IntentLearner {
    return this.l;
  }

  /** Widening is frozen while a drift alarm stands. */
  get frozen(): boolean {
    return this.drift.state.alarm;
  }

  /** Positive signals held back by a freeze (released only by `rebase`). */
  get pending(): readonly { o: Outcome; signal: RuntimeSignal }[] {
    return this.queued;
  }

  private grantSize(): number {
    return this.l.cells().filter((c) => c.inGrant).length;
  }

  record(o: Outcome, signal: RuntimeSignal): RampRecord {
    const y = signalLabel(signal);
    const wasInGrant = this.l.admitsOutcome(o);
    const before = this.grantSize();
    let drift = this.drift.state;
    if (wasInGrant) drift = this.drift.update(y === 0);
    let applied = true;
    if (y === 1 && this.frozen) {
      this.queued.push({ o, signal });
      applied = false;
    } else this.l.observe(o, y, 'runtime');
    const rec: RampRecord = { signal, y, wasInGrant, before, after: this.grantSize(), applied, drift };
    this.log.push(rec);
    return rec;
  }

  /**
   * Record a SIGNED runtime observation (the core `IntentObservation` wire artifact, spec §8): the signature must
   * verify, the signer must be trusted (the principal or a verifier-held oracle, §4.6 "poisoned runtime signal"),
   * and the observation must be about this map. y = 1 counts as `principal-confirm`, y = 0 as
   * `postcondition-violation` (any negative runtime signal vetoes the same way).
   */
  recordObservation(obs: SignedIntentObservation, ctx: { mapDigest: string; trustedSigners: readonly string[]; verify?: IntentVerifyOptions }): { ok: true; record: RampRecord } | { ok: false; reason: string } {
    const v = verifyIntentObservation(obs, ctx.verify ?? {});
    if (!v.ok) return { ok: false, reason: v.reason };
    if (!ctx.trustedSigners.includes(obs.signer)) return { ok: false, reason: 'untrusted observation signer' };
    if (obs.map_digest !== ctx.mapDigest) return { ok: false, reason: 'observation is about a different map' };
    if (obs.source !== 'runtime') return { ok: false, reason: 'only runtime observations feed the ramp' };
    return { ok: true, record: this.record({ verb: obs.verb, values: obs.values }, obs.y === 1 ? 'principal-confirm' : 'postcondition-violation') };
  }

  /**
   * Re-base on a new, signed intent statement (the only way to clear an alarm, spec §4.6): the caller supplies the
   * learner for the new statement (vetoes from the old one are NOT carried over: the new statement is new
   * authority). Queued positive signals are discarded; they were evidence about the old intent.
   */
  rebase(next: IntentLearner): void {
    this.l = next;
    this.queued = [];
    this.drift.reset();
  }
}
