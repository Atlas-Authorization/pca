/**
 * Behavioral immune system (spec Part 2.4 "the intelligence layer").
 *
 * "Authorization that gets more paranoid when something's off." Learn each principal's NORMAL risk
 * distribution from the stream of their agents' actions, detect drift / volatility / violation bursts,
 * and — under suspicion — PROPOSE a tightened risk policy for the next epoch: lower θ (so more actions
 * need a human) and higher κ (so each action costs more budget, draining the autonomous allowance
 * faster). When behavior returns to baseline, the proposal relaxes smoothly back to the base policy.
 *
 * HONEST framing: this PROPOSES a policy; it never secretly mutates a signed grant. A signed grant is
 * immutable — tightening is applied by the control plane at the next epoch (a new grant / an adaptive
 * server-side overlay), exactly like a human co-sign recharge is applied to the budget. The adaptation
 * is a pure, deterministic, REVERSIBLE function of the current threat score, so it can only ever make
 * authorization stricter under threat and return to baseline when calm — never silently widen.
 */

import { type RiskPolicy, validateRiskPolicy } from './risk';

// ---- baseline (Welford running mean/variance) -----------------------------------------------------

export interface Baseline {
  n: number;
  mean: number;
  /** Sum of squared deviations (Welford M2). */
  m2: number;
}

export const EMPTY_BASELINE: Baseline = { n: 0, mean: 0, m2: 0 };

export function updateBaseline(b: Baseline, r: number): Baseline {
  const x = Number.isFinite(r) ? r : 0;
  const n = b.n + 1;
  const delta = x - b.mean;
  const mean = b.mean + delta / n;
  const m2 = b.m2 + delta * (x - mean);
  return { n, mean, m2 };
}

/** Population standard deviation of the baseline (0 until ≥2 samples). */
export function baselineStd(b: Baseline): number {
  return b.n >= 2 ? Math.sqrt(b.m2 / b.n) : 0;
}

// ---- immune state ---------------------------------------------------------------------------------

export interface RiskObservation {
  /** Risk value of the action in [0,1]. */
  r: number;
  at: number;
  /** The action required a human/guardian step-up. */
  stepUp?: boolean;
  /** The action was denied by policy. */
  denied?: boolean;
}

export interface ImmuneConfig {
  /** EWMA smoothing for the "recent" signal (0<α≤1; higher = more reactive). Default 0.3. */
  alpha: number;
  /** Half-life (ms) for decaying the recent step-up / deny counters. Default 1 hour. */
  halfLifeMs: number;
  /** z-score at which drift saturates the drift signal. Default 3. */
  driftZSat: number;
  /** recent step-up RATE (per decayed count) at which the volatility signal saturates. Default 5. */
  stepUpSat: number;
  /** recent deny count at which the violation signal saturates. Default 3. */
  denySat: number;
}

export const DEFAULT_IMMUNE_CONFIG: ImmuneConfig = {
  alpha: 0.3,
  halfLifeMs: 3_600_000,
  driftZSat: 3,
  stepUpSat: 5,
  denySat: 3,
};

export interface ImmuneState {
  baseline: Baseline;
  /** EWMA of recent risk. */
  ewma: number;
  /** Decayed count of recent step-ups. */
  stepUps: number;
  /** Decayed count of recent denies. */
  denies: number;
  lastAt: number;
  seeded: boolean;
}

export const INITIAL_IMMUNE_STATE: ImmuneState = {
  baseline: EMPTY_BASELINE,
  ewma: 0,
  stepUps: 0,
  denies: 0,
  lastAt: 0,
  seeded: false,
};

function decay(count: number, dtMs: number, halfLifeMs: number): number {
  if (dtMs <= 0 || count === 0) return count;
  return count * Math.pow(0.5, dtMs / halfLifeMs);
}

/** Fold one observation into the immune state (updates baseline + recent EWMA + decayed counters). */
export function observe(state: ImmuneState, obs: RiskObservation, cfg: ImmuneConfig = DEFAULT_IMMUNE_CONFIG): ImmuneState {
  const r = Math.max(0, Math.min(1, Number.isFinite(obs.r) ? obs.r : 0));
  // A non-finite timestamp (NaN / Infinity, or a PCActn whose `iat` was absent) must not poison the
  // state: `at - lastAt` would be NaN, decay() would turn the step-up/deny counters into NaN forever,
  // and the threat score would read a permanent (fail-open) `calm`. Pin a bad timestamp to the last
  // good one so this observation advances no clock (dt = 0) and `lastAt` stays finite.
  const at = Number.isFinite(obs.at) ? obs.at : state.lastAt;
  const dt = state.seeded ? Math.max(0, at - state.lastAt) : 0;
  const baseline = updateBaseline(state.baseline, r);
  const ewma = state.seeded ? cfg.alpha * r + (1 - cfg.alpha) * state.ewma : r;
  const stepUps = decay(state.stepUps, dt, cfg.halfLifeMs) + (obs.stepUp ? 1 : 0);
  const denies = decay(state.denies, dt, cfg.halfLifeMs) + (obs.denied ? 1 : 0);
  return { baseline, ewma, stepUps, denies, lastAt: at, seeded: true };
}

// ---- threat assessment ----------------------------------------------------------------------------

export type ThreatLevel = 'calm' | 'elevated' | 'high';

export interface ThreatAssessment {
  level: ThreatLevel;
  /** Combined threat score in [0,1]. */
  score: number;
  signals: string[];
  components: { drift: number; volatility: number; violation: number };
}

const clamp01 = (x: number) => Math.max(0, Math.min(1, x));

/**
 * Assess the current threat from the immune state. Combines three signals, each normalized to [0,1]:
 *  - drift:     how far recent mean risk (EWMA) has moved above baseline, in std units;
 *  - volatility: the decayed recent step-up rate;
 *  - violation:  the decayed recent deny count.
 * The score is the max of the three (any one firing is enough to be suspicious); level thresholds at
 * 0.33 / 0.66.
 */
export function assess(state: ImmuneState, cfg: ImmuneConfig = DEFAULT_IMMUNE_CONFIG): ThreatAssessment {
  const std = baselineStd(state.baseline);
  const signals: string[] = [];

  // Drift: only ABOVE-baseline movement is threatening (riskier than usual). Needs a settled baseline.
  let drift = 0;
  if (state.baseline.n >= 5 && std > 1e-9) {
    const z = (state.ewma - state.baseline.mean) / std;
    drift = clamp01(z / cfg.driftZSat);
    if (drift > 0.33) signals.push(`risk drifted ${z.toFixed(1)}σ above baseline`);
  }

  const volatility = clamp01(state.stepUps / cfg.stepUpSat);
  if (volatility > 0.33) signals.push(`elevated step-up rate (${state.stepUps.toFixed(1)})`);

  const violation = clamp01(state.denies / cfg.denySat);
  if (violation > 0.33) signals.push(`repeated policy violations (${state.denies.toFixed(1)})`);

  const score = Math.max(drift, volatility, violation);
  const level: ThreatLevel = score >= 0.66 ? 'high' : score >= 0.33 ? 'elevated' : 'calm';
  return { level, score, signals, components: { drift, volatility, violation } };
}

// ---- adaptation (anomaly-gated epoch) -------------------------------------------------------------

export interface AdaptConfig {
  /** Max multiple κ can be raised to at score=1. Default 3×. */
  maxKappaMult: number;
  /** Min multiple θ can be lowered to at score=1 (0<..≤1). Default 0.4×. */
  minThetaMult: number;
}

export const DEFAULT_ADAPT_CONFIG: AdaptConfig = { maxKappaMult: 3, minThetaMult: 0.4 };

export interface Adaptation {
  policy: RiskPolicy;
  changed: boolean;
  rationale: string;
}

/**
 * Derive the adapted policy from the BASE policy and the current threat score. Deterministic and
 * reversible: score 0 ⇒ the base policy unchanged (calm); higher scores raise κ toward maxKappaMult×
 * and lower θ toward minThetaMult×. Because it is always computed FROM the base (never compounded),
 * returning to a calm score restores the base exactly. The result is re-validated.
 */
export function adapt(base: RiskPolicy, assessment: ThreatAssessment, cfg: AdaptConfig = DEFAULT_ADAPT_CONFIG): Adaptation {
  const s = clamp01(assessment.score);
  if (s === 0) return { policy: base, changed: false, rationale: 'calm — baseline policy' };

  const kappaMult = 1 + (cfg.maxKappaMult - 1) * s;
  const thetaMult = 1 - (1 - cfg.minThetaMult) * s;
  const policy: RiskPolicy = {
    ...base,
    weights: { ...base.weights },
    kappa: base.kappa * kappaMult,
    theta1: clamp01(base.theta1 * thetaMult),
    theta2: clamp01(base.theta2 * thetaMult),
  };
  const bad = validateRiskPolicy(policy);
  if (bad) return { policy: base, changed: false, rationale: `adaptation rejected (${bad}) — kept baseline` };

  const why = assessment.signals.length ? assessment.signals.join('; ') : `threat score ${s.toFixed(2)}`;
  return {
    policy,
    changed: true,
    rationale: `${assessment.level}: ${why} → κ ×${kappaMult.toFixed(2)}, θ ×${thetaMult.toFixed(2)}`,
  };
}
