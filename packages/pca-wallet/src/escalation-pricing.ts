// escalation-pricing.ts - risk-priced escalation (K4, C-284..C-287).
//
// Rule: ask a human iff  pBadUpper * loss > interruptionCost  (integer arithmetic: probabilities in ppm, money in minor units,
// BigInt products; no floats, no randomness, no clock). Every input is explicit: the loss and the interruption cost come from a
// principal-SIGNED configuration, `pBadUpperPpm` is the caller's conformal upper bound for this action. Anything missing, out of range
// or unsigned means ASK (fail strict). This module never lets a number it learned, or a model it cannot reproduce, approve anything.
//
// The only learned component is a per-principal `Calibration.multiplierPpm >= 1_000_000`. It scales P(bad) UP, so it can only add
// asks. Its update function is monotone non-decreasing for every input sequence (C-286); moving the other way needs a principal-signed
// `AutonomyRaise`, which is capped by the configured hard ceiling and is never produced by the learner.

import { decodeKey, encodeKey, hashCanonical, sign, verify } from '@atlasauth/pca';

export const PPM = 1_000_000;
export const MAX_MULTIPLIER_PPM = 100 * PPM;

export interface PricingConfigBody {
  v: 1;
  principal: string; // b64u public key
  currency: string;
  /** Cost of interrupting the principal, minor units. */
  interruptionCost: number;
  /** Upper limit the cost may ever be raised to by an AutonomyRaise. */
  maxInterruptionCost: number;
  /** An action whose loss exceeds this is always asked, whatever its P(bad): the hard ceiling X. */
  hardCeilingLoss: number;
  /** Each recorded miss (human denied what pricing would have auto-approved) adds this many ppm to the multiplier. */
  tightenStepPpm: number;
  epoch: number;
}
export interface SignedPricingConfig extends PricingConfigBody { sig: string }

const isMinor = (n: unknown): n is number => typeof n === 'number' && Number.isSafeInteger(n) && n >= 0;
const msg = (kind: string, body: object): Uint8Array => new TextEncoder().encode(hashCanonical({ kind, body }));

export function signPricingConfig(body: PricingConfigBody, principalSecret: Uint8Array): SignedPricingConfig {
  return { ...body, sig: encodeKey(sign(principalSecret, msg('pca.escalation_pricing', body))) };
}

// A config that verified once keeps verifying (pure function of its content); cache by full content, bounded.
const okCache = new Set<string>();
export function pricingConfigError(c: unknown): string | null {
  try {
    const key = JSON.stringify(c);
    if (okCache.has(key)) return null;
    const r = pricingConfigErrorUncached(c);
    if (r === null) { if (okCache.size >= 64) okCache.clear(); okCache.add(key); }
    return r;
  } catch { return 'config_malformed'; }
}
function pricingConfigErrorUncached(c: unknown): string | null {
  try {
    const x = c as SignedPricingConfig;
    if (x === null || typeof x !== 'object' || x.v !== 1 || typeof x.principal !== 'string' || typeof x.currency !== 'string' || typeof x.sig !== 'string') return 'config_malformed';
    if (!isMinor(x.interruptionCost) || !isMinor(x.maxInterruptionCost) || !isMinor(x.hardCeilingLoss) || !isMinor(x.epoch)) return 'config_amounts_invalid';
    if (x.interruptionCost > x.maxInterruptionCost) return 'config_cost_above_max';
    if (!Number.isSafeInteger(x.tightenStepPpm) || x.tightenStepPpm < 0 || x.tightenStepPpm > MAX_MULTIPLIER_PPM) return 'config_step_invalid';
    const { sig, ...body } = x;
    return verify(decodeKey(x.principal), msg('pca.escalation_pricing', body), decodeKey(sig)) ? null : 'config_signature_invalid';
  } catch {
    return 'config_malformed';
  }
}

export interface Calibration { multiplierPpm: number; seen: readonly string[] }
export const freshCalibration = (): Calibration => ({ multiplierPpm: PPM, seen: [] });

export interface ActionRisk {
  currency: string;
  /** Loss if the action is bad, minor units, from the action schema (amount, reversibility class, ...). */
  loss: number;
  /** Conformal UPPER bound on P(bad), ppm 0..1_000_000. */
  pBadUpperPpm: number;
}

export interface EscalationDecision { ask: boolean; reason: string }

/** Pure and total. */
export function decideEscalation(config: SignedPricingConfig, cal: Calibration, a: ActionRisk): EscalationDecision {
  const e = pricingConfigError(config);
  if (e !== null) return { ask: true, reason: e };
  if (a === null || typeof a !== 'object' || a.currency !== config.currency) return { ask: true, reason: 'currency_mismatch' };
  if (!isMinor(a.loss) || !Number.isSafeInteger(a.pBadUpperPpm) || a.pBadUpperPpm < 0 || a.pBadUpperPpm > PPM) return { ask: true, reason: 'risk_input_invalid' };
  if (!(Number.isSafeInteger(cal?.multiplierPpm) && cal.multiplierPpm >= PPM && cal.multiplierPpm <= MAX_MULTIPLIER_PPM)) return { ask: true, reason: 'calibration_invalid' };
  if (a.loss > config.hardCeilingLoss) return { ask: true, reason: 'above_hard_ceiling' };
  // effective P(bad) = min(1, p * mult), in units of 1e-12: p_ppm * mult_ppm. Compare p*mult*loss > cost * 1e12.
  const pe = BigInt(a.pBadUpperPpm) * BigInt(cal.multiplierPpm);
  const capped = pe > BigInt(PPM) * BigInt(PPM) ? BigInt(PPM) * BigInt(PPM) : pe;
  const lhs = capped * BigInt(a.loss);
  const rhs = BigInt(config.interruptionCost) * BigInt(PPM) * BigInt(PPM);
  return lhs > rhs ? { ask: true, reason: 'expected_loss_exceeds_interruption_cost' } : { ask: false, reason: 'expected_loss_within_interruption_cost' };
}

// ---- per-principal calibration from signed answers ----------------------------------------------------------------------

export interface AnswerBody { v: 1; principal: string; nonce: string; action_digest: string; answer: 'approve' | 'deny' }
export interface SignedAnswer extends AnswerBody { sig: string }

export function signAnswer(body: AnswerBody, principalSecret: Uint8Array): SignedAnswer {
  return { ...body, sig: encodeKey(sign(principalSecret, msg('pca.escalation_answer', body))) };
}
function answerOk(a: SignedAnswer, principal: string): boolean {
  try {
    if (a.v !== 1 || a.principal !== principal || typeof a.nonce !== 'string' || a.nonce.length < 8 || typeof a.action_digest !== 'string' || (a.answer !== 'approve' && a.answer !== 'deny')) return false;
    const { sig, ...body } = a;
    return verify(decodeKey(principal), msg('pca.escalation_answer', body), decodeKey(sig));
  } catch { return false; }
}

/**
 * Fold signed answers into the calibration. A DENY the principal gave to an action that the CURRENT pricing would have auto-approved
 * is a miss and adds `tightenStepPpm` (capped). An approve, a deny of something already asked, an invalid signature, a replayed nonce
 * and an answer for an unknown action change nothing. The result's multiplier is >= the input's for every input (C-286).
 */
export function updateCalibration(config: SignedPricingConfig, cal: Calibration, answers: readonly SignedAnswer[], risks: ReadonlyMap<string, ActionRisk>): Calibration {
  if (pricingConfigError(config) !== null) return cal;
  let mult = cal.multiplierPpm;
  const seen = new Set(cal.seen);
  const order: string[] = [...cal.seen];
  for (const a of answers) {
    if (!answerOk(a, config.principal) || seen.has(a.nonce)) continue;
    seen.add(a.nonce); order.push(a.nonce);
    const risk = risks.get(a.action_digest);
    if (a.answer !== 'deny' || risk === undefined) continue;
    if (!decideEscalation(config, { multiplierPpm: mult, seen: [] }, risk).ask) mult = Math.min(MAX_MULTIPLIER_PPM, mult + config.tightenStepPpm);
  }
  return { multiplierPpm: Math.max(mult, cal.multiplierPpm), seen: order };
}

// ---- the only way to ask less: a principal-signed raise -------------------------------------------------------------------

export interface AutonomyRaiseBody { v: 1; principal: string; epoch: number; newInterruptionCost: number }
export interface SignedAutonomyRaise extends AutonomyRaiseBody { sig: string }
export const signAutonomyRaise = (b: AutonomyRaiseBody, secret: Uint8Array): SignedAutonomyRaise => ({ ...b, sig: encodeKey(sign(secret, msg('pca.autonomy_raise', b))) });

/** A higher interruption cost means fewer asks. Requires the principal's signature, a strictly newer epoch, and `<= maxInterruptionCost`. Throws otherwise. */
export function applyAutonomyRaise(config: SignedPricingConfig, raise: SignedAutonomyRaise, principalSecret: Uint8Array): SignedPricingConfig {
  const { sig, ...b } = raise;
  let ok = false;
  try { ok = raise.v === 1 && raise.principal === config.principal && verify(decodeKey(config.principal), msg('pca.autonomy_raise', b), decodeKey(sig)); } catch { /* ok stays false */ }
  if (!ok) throw new Error('applyAutonomyRaise: signature or principal invalid');
  if (!(raise.epoch > config.epoch)) throw new Error('applyAutonomyRaise: epoch must advance');
  if (!isMinor(raise.newInterruptionCost) || raise.newInterruptionCost > config.maxInterruptionCost) throw new Error('applyAutonomyRaise: above the configured maximum');
  const { sig: _s, ...body } = config;
  return signPricingConfig({ ...body, interruptionCost: raise.newInterruptionCost, epoch: raise.epoch }, principalSecret);
}
