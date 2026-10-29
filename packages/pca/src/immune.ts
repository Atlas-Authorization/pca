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
 *
 * WHAT IS GUARANTEED (deterministic, tested, enforced in code): the adapted policy is a pure function of
 * (base policy, immune state); it never widens the base (κ' ≥ κ, θ' ≤ θ, everything else equal, checked by
 * {@link assertNoWiden}); score 0 restores the base exactly; a malformed state or score fails CLOSED to the
 * most restrictive threat level; a {@link TighteningProposal} is guardian-signed, bound to the base policy and
 * state digests, and applies only with a strictly higher epoch. WHAT IS NOT: the anomaly score itself is a
 * heuristic (EWMA / z-score over one principal's history). It can be gamed by a slow attacker who drifts the
 * baseline, and it is no proof that an agent is compromised or benign.
 */

import type { DurableKv } from './durable-state';
import { b64u, canonicalBytesLenient, hashCanonicalLenient, utf8 } from './hash';
import { publicKeyOf, sign, verifyB64u } from './keys';
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

const MAX_COUNT = 1e9;
const inRange = (x: unknown, lo: number, hi: number): boolean => typeof x === 'number' && Number.isFinite(x) && x >= lo && x <= hi;

/** Reason string if the state is malformed (non-finite, negative, out of bound), else null. */
export function validateImmuneState(s: unknown): string | null {
  if (s === null || typeof s !== 'object') return 'state must be an object';
  const x = s as Partial<ImmuneState>;
  const b = x.baseline as Partial<Baseline> | undefined;
  if (!b || typeof b !== 'object') return 'baseline missing';
  if (!inRange(b.n, 0, MAX_COUNT) || !Number.isInteger(b.n)) return 'baseline.n must be an integer in [0, 1e9]';
  if (!inRange(b.mean, 0, 1)) return 'baseline.mean must be in [0, 1]';
  if (!inRange(b.m2, 0, MAX_COUNT)) return 'baseline.m2 must be finite and >= 0';
  if (!inRange(x.ewma, 0, 1)) return 'ewma must be in [0, 1]';
  if (!inRange(x.stepUps, 0, MAX_COUNT)) return 'stepUps must be finite and >= 0';
  if (!inRange(x.denies, 0, MAX_COUNT)) return 'denies must be finite and >= 0';
  if (!inRange(x.lastAt, 0, Number.MAX_SAFE_INTEGER)) return 'lastAt must be a finite non-negative time';
  if (typeof x.seeded !== 'boolean') return 'seeded must be a boolean';
  return null;
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
  const bad = validateImmuneState(state);
  if (bad) return { level: 'high', score: 1, signals: [`invalid immune state: ${bad}`], components: { drift: 1, volatility: 1, violation: 1 } };
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
  // a non-finite score is untrusted input: treat it as the worst case, never as calm
  const s = Number.isFinite(assessment.score) ? clamp01(assessment.score) : 1;
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
  const bad = validateRiskPolicy(policy) ?? noWidenViolation(base, policy);
  if (bad) return { policy: base, changed: false, rationale: `adaptation rejected (${bad}) — kept baseline` };

  const why = assessment.signals.length ? assessment.signals.join('; ') : `threat score ${s.toFixed(2)}`;
  return {
    policy,
    changed: true,
    rationale: `${assessment.level}: ${why} → κ ×${kappaMult.toFixed(2)}, θ ×${thetaMult.toFixed(2)}`,
  };
}

// ---- the no-widen invariant -----------------------------------------------------------------------

/** Why `adapted` is looser than `base`, or null when it only tightens (κ' ≥ κ, θ' ≤ θ, rest identical). */
export function noWidenViolation(base: RiskPolicy, adapted: RiskPolicy): string | null {
  if (!(adapted.kappa >= base.kappa)) return 'kappa decreased';
  if (!(adapted.theta1 <= base.theta1)) return 'theta1 increased';
  if (!(adapted.theta2 <= base.theta2)) return 'theta2 increased';
  for (const k of ['lambda', 'rho', 'bMax'] as const) if (adapted[k] !== base[k]) return `${k} changed`;
  for (const k of Object.keys(base.weights) as Array<keyof RiskPolicy['weights']>) if (adapted.weights[k] !== base.weights[k]) return `weights.${k} changed`;
  return null;
}

/** Throws unless `adapted` only tightens `base`. */
export function assertNoWiden(base: RiskPolicy, adapted: RiskPolicy): void {
  const v = noWidenViolation(base, adapted);
  if (v) throw new Error(`immune: adaptation widens the policy (${v})`);
}

// ---- signed tightening proposals ------------------------------------------------------------------

export const TIGHTENING_DOMAIN = 'atlas-pca/immune-tightening/v1\0';

export interface TighteningClaim {
  v: 1;
  /** Digest of the base policy this tightens (a proposal for another base never applies). */
  base_digest: string;
  /** Digest of the immune state the proposal was derived from (audit trail). */
  state_digest: string;
  /** Strictly increasing per subject; a replayed or lower epoch is refused. */
  epoch: number;
  issued_at: number;
  policy: RiskPolicy;
  rationale: string;
  /** b64u Ed25519 key of the issuing guardian. */
  guardian: string;
}
export interface TighteningProposal extends TighteningClaim {
  sig: string;
}

const tighteningMessage = (c: TighteningClaim): Uint8Array => {
  const pre = utf8(TIGHTENING_DOMAIN);
  const body = canonicalBytesLenient(c);
  const m = new Uint8Array(pre.length + body.length);
  m.set(pre);
  m.set(body, pre.length);
  return m;
};

export const policyDigest = (p: RiskPolicy): string => hashCanonicalLenient(p);
export const immuneStateDigest = (s: ImmuneState): string => hashCanonicalLenient(s);

/** Derive and sign the tightening for `state`. Throws on a malformed base, bad epoch, or malformed state (fail closed, never an unsigned loosening). */
export function issueTighteningProposal(a: {
  base: RiskPolicy;
  state: ImmuneState;
  epoch: number;
  now: number;
  guardianSecret: Uint8Array;
  cfg?: ImmuneConfig;
  adaptCfg?: AdaptConfig;
}): TighteningProposal {
  const bad = validateRiskPolicy(a.base);
  if (bad) throw new Error(`issueTighteningProposal: ${bad}`);
  if (!Number.isSafeInteger(a.epoch) || a.epoch < 1) throw new Error('issueTighteningProposal: epoch must be an integer >= 1');
  if (!Number.isFinite(a.now)) throw new Error('issueTighteningProposal: now must be finite');
  const ad = adapt(a.base, assess(a.state, a.cfg), a.adaptCfg);
  const claim: TighteningClaim = {
    v: 1,
    base_digest: policyDigest(a.base),
    state_digest: hashCanonicalLenient(a.state),
    epoch: a.epoch,
    issued_at: a.now,
    policy: ad.policy,
    rationale: ad.rationale,
    guardian: b64u(publicKeyOf(a.guardianSecret)),
  };
  return { ...claim, sig: b64u(sign(a.guardianSecret, tighteningMessage(claim))) };
}

export type TighteningOutcome =
  | { ok: true; policy: RiskPolicy; epoch: number }
  | { ok: false; reason: 'malformed' | 'guardian' | 'signature' | 'base' | 'stale' | 'replayed-epoch' | 'widens' | 'invalid-policy' | 'state-mismatch' };

export interface ApplyTighteningOptions {
  /** Pinned guardian public key (b64u). Required: an unpinned proposal is refused. */
  guardian: string;
  /** Highest epoch already applied for this subject (0 when none). */
  lastEpoch: number;
  now: number;
  /** Proposals older than this (ms) are refused. */
  maxAgeMs: number;
  /** When given, the proposal must equal the tightening this state derives (a recompute check). */
  state?: ImmuneState;
}

/** Verify a proposal and return the policy to enforce. Never throws; every refusal is a distinct reason. */
export function applyTightening(base: RiskPolicy, p: TighteningProposal, o: ApplyTighteningOptions): TighteningOutcome {
  try {
    if (!p || typeof p !== 'object' || p.v !== 1 || typeof p.sig !== 'string' || typeof p.guardian !== 'string') return { ok: false, reason: 'malformed' };
    if (typeof o.guardian !== 'string' || o.guardian !== p.guardian) return { ok: false, reason: 'guardian' };
    const { sig, ...claim } = p;
    if (!verifyB64u(p.guardian, tighteningMessage(claim), sig)) return { ok: false, reason: 'signature' };
    if (validateRiskPolicy(base) || validateRiskPolicy(p.policy)) return { ok: false, reason: 'invalid-policy' };
    if (p.base_digest !== policyDigest(base)) return { ok: false, reason: 'base' };
    if (!Number.isFinite(o.now) || !Number.isFinite(p.issued_at) || p.issued_at > o.now || o.now - p.issued_at > o.maxAgeMs) return { ok: false, reason: 'stale' };
    if (!Number.isSafeInteger(p.epoch) || !(p.epoch > o.lastEpoch)) return { ok: false, reason: 'replayed-epoch' };
    if (noWidenViolation(base, p.policy)) return { ok: false, reason: 'widens' };
    if (o.state && (p.state_digest !== hashCanonicalLenient(o.state) || policyDigest(adapt(base, assess(o.state)).policy) !== policyDigest(p.policy))) return { ok: false, reason: 'state-mismatch' };
    return { ok: true, policy: p.policy, epoch: p.epoch };
  } catch {
    return { ok: false, reason: 'malformed' };
  }
}

// ---- durable state --------------------------------------------------------------------------------

/** Immune state + applied epoch for one subject, persisted through an atomic `DurableKv.update`, so a restart keeps the history and the replay floor. */
export function createImmuneStore(kv: DurableKv, subject: string) {
  const sKey = `immune/state/${subject}`;
  const eKey = `immune/epoch/${subject}`;
  return {
    async get(): Promise<ImmuneState> {
      const v = await kv.get(sKey);
      return v === undefined ? INITIAL_IMMUNE_STATE : (v as ImmuneState);
    },
    /** Folds one observation atomically. Throws if the stored state is malformed (it is never silently reset to calm). */
    async observe(obs: RiskObservation, cfg: ImmuneConfig = DEFAULT_IMMUNE_CONFIG): Promise<ImmuneState> {
      return (await kv.update(sKey, (prev) => {
        const cur = prev === undefined ? INITIAL_IMMUNE_STATE : (prev as ImmuneState);
        const bad = validateImmuneState(cur);
        if (bad) throw new Error(`immune store: stored state invalid (${bad})`);
        return observe(cur, obs, cfg);
      })) as ImmuneState;
    },
    async lastEpoch(): Promise<number> {
      const v = await kv.get(eKey);
      return typeof v === 'number' ? v : 0;
    },
    /** Verify and apply a proposal; the epoch floor advances atomically, so two racing applies of one epoch cannot both win. */
    async apply(base: RiskPolicy, p: TighteningProposal, o: Omit<ApplyTighteningOptions, 'lastEpoch'>): Promise<TighteningOutcome> {
      let out: TighteningOutcome = { ok: false, reason: 'malformed' };
      await kv.update(eKey, (prev) => {
        out = applyTightening(base, p, { ...o, lastEpoch: typeof prev === 'number' ? prev : 0 });
        return out.ok ? out.epoch : undefined;
      });
      return out;
    },
  };
}
