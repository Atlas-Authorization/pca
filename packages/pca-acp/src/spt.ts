/**
 * Stripe Shared Payment Tokens. Source: Stripe API reference, "The Shared Payment Granted Token object"
 * (docs.stripe.com/api/shared-payment/granted-token/object) and the test-mode create parameters
 * (docs.stripe.com/api/shared-payment/granted-token/create): object `shared_payment.granted_token`, id `spt_...`,
 * `usage_limits` { `currency` lowercase ISO 4217, `max_amount` integer minor units, `expires_at` seconds }, `usage_details`
 * { `amount_captured` { `value`, `currency` } }, `deactivated_at` and `deactivated_reason`
 * (`consumed` | `expired` | `resolved` | `revoked`), `payment_method_details`, `agent_details`, `shared_metadata`, `livemode`,
 * `created`. This module reads and checks that object and relates it to a PCA delegated payment token; it does no I/O and
 * never calls Stripe. Whether Stripe accepts a token is Stripe's decision: these checks only refuse what PCA authority forbids.
 */

export const STRIPE_SPT_OBJECT = 'shared_payment.granted_token' as const;
export type StripeSptDeactivatedReason = 'consumed' | 'expired' | 'resolved' | 'revoked';

export interface StripeSptUsageLimits {
  currency: string;
  max_amount: number;
  expires_at?: number | null;
}

export interface StripeSharedPaymentGrantedToken {
  id: string;
  object: typeof STRIPE_SPT_OBJECT;
  created: number;
  livemode: boolean;
  deactivated_at: number | null;
  deactivated_reason: StripeSptDeactivatedReason | null;
  usage_limits: StripeSptUsageLimits | null;
  usage_details: { amount_captured: { value: number; currency: string } } | null;
  payment_method_details: { type: string; [k: string]: unknown } | null;
  agent_details: Record<string, unknown> | null;
  shared_metadata: Record<string, unknown> | null;
  risk_details?: Record<string, unknown> | null;
}

const REASONS: readonly string[] = ['consumed', 'expired', 'resolved', 'revoked'];
const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const isInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v);
const isCurrency = (v: unknown): v is string => typeof v === 'string' && /^[a-z]{3}$/.test(v);

/** Problems with a Shared Payment Granted Token object (empty = well formed). */
export function stripeSptProblems(t: unknown): string[] {
  if (!isObj(t)) return ['the token must be an object'];
  const p: string[] = [];
  if (t.object !== STRIPE_SPT_OBJECT) p.push(`object must be "${STRIPE_SPT_OBJECT}"`);
  if (typeof t.id !== 'string' || !/^spt_[A-Za-z0-9_]+$/.test(t.id)) p.push('id must be an spt_ identifier');
  if (!isInt(t.created)) p.push('created must be an integer timestamp');
  if (typeof t.livemode !== 'boolean') p.push('livemode must be a boolean');
  if (t.deactivated_at !== null && !isInt(t.deactivated_at)) p.push('deactivated_at must be null or an integer timestamp');
  if (t.deactivated_reason !== null && !(typeof t.deactivated_reason === 'string' && REASONS.includes(t.deactivated_reason))) p.push('deactivated_reason must be null or one of consumed, expired, resolved, revoked');
  if (!isObj(t.usage_limits)) p.push('usage_limits is required');
  else {
    const u = t.usage_limits;
    if (!isCurrency(u.currency)) p.push('usage_limits.currency must be a lowercase three-letter code');
    if (!isInt(u.max_amount) || u.max_amount < 0) p.push('usage_limits.max_amount must be a non-negative integer in minor units');
    if (u.expires_at !== undefined && u.expires_at !== null && !isInt(u.expires_at)) p.push('usage_limits.expires_at must be an integer timestamp');
  }
  if (t.usage_details !== null && t.usage_details !== undefined) {
    const c = isObj(t.usage_details) ? t.usage_details.amount_captured : undefined;
    if (!isObj(c) || !isInt(c.value) || c.value < 0 || !isCurrency(c.currency)) p.push('usage_details.amount_captured needs a non-negative integer value and a lowercase currency');
  }
  for (const k of ['payment_method_details', 'agent_details', 'shared_metadata'] as const) {
    if (t[k] !== null && t[k] !== undefined && !isObj(t[k])) p.push(`${k} must be null or an object`);
  }
  if (isObj(t.payment_method_details) && typeof t.payment_method_details.type !== 'string') p.push('payment_method_details.type must be a string');
  return p;
}

/** Parse a Shared Payment Granted Token; throws a `TypeError` listing every problem. */
export function parseStripeSpt(t: unknown): StripeSharedPaymentGrantedToken {
  const problems = stripeSptProblems(t);
  if (problems.length > 0) throw new TypeError(`stripe spt: ${problems.join('; ')}`);
  return t as StripeSharedPaymentGrantedToken;
}

export interface StripeSptUseRequest {
  /** Epoch seconds. */
  now: number;
  /** Integer minor units to capture. */
  amount: number;
  /** Currency of the capture (case-insensitive). */
  currency: string;
  /** Require a live-mode token (default true). */
  livemode?: boolean;
}

/**
 * Can this token still be used for this capture? Refuses a malformed token, a deactivated or expired one, the wrong mode, a
 * different currency, a non-integer amount and one above `max_amount` minus what was already captured.
 */
export function stripeSptUsable(t: unknown, use: StripeSptUseRequest): { ok: true } | { ok: false; reason: string } {
  const problems = stripeSptProblems(t);
  if (problems.length > 0) return { ok: false, reason: `malformed token: ${problems[0]}` };
  const spt = t as StripeSharedPaymentGrantedToken;
  if (!isInt(use.now) || !isInt(use.amount) || use.amount <= 0) return { ok: false, reason: 'now and amount must be integers and the amount positive' };
  if ((use.livemode ?? true) !== spt.livemode) return { ok: false, reason: 'the token is in the wrong mode' };
  if (spt.deactivated_reason !== null) return { ok: false, reason: `the token is deactivated (${spt.deactivated_reason})` };
  if (spt.deactivated_at !== null && spt.deactivated_at <= use.now) return { ok: false, reason: 'the token is deactivated' };
  const lim = spt.usage_limits as StripeSptUsageLimits;
  if (typeof lim.expires_at === 'number' && use.now >= lim.expires_at) return { ok: false, reason: 'the token has expired' };
  if (lim.currency !== use.currency.toLowerCase()) return { ok: false, reason: 'the capture currency differs from the token currency' };
  const captured = spt.usage_details?.amount_captured;
  if (captured !== undefined && captured.currency !== lim.currency) return { ok: false, reason: 'the captured amount is in another currency' };
  const remaining = lim.max_amount - (captured?.value ?? 0);
  if (use.amount > remaining) return { ok: false, reason: `the amount ${use.amount} exceeds the remaining ${remaining}` };
  return { ok: true };
}

/** The `usage_limits` to request for a PCA authority: lowercase currency, integer minor units, expiry in whole seconds (rounded down). */
export function stripeUsageLimitsFor(authority: { maxAmount: number; currency: string; expiresAtMs?: number }): StripeSptUsageLimits {
  if (!isInt(authority.maxAmount) || authority.maxAmount <= 0) throw new TypeError('stripe spt: maxAmount must be a positive integer in minor units');
  if (typeof authority.currency !== 'string' || !/^[A-Za-z]{3}$/.test(authority.currency)) throw new TypeError('stripe spt: currency must be a three-letter code');
  if (authority.expiresAtMs !== undefined && !(Number.isFinite(authority.expiresAtMs) && authority.expiresAtMs > 0)) throw new TypeError('stripe spt: expiresAtMs must be a positive epoch-ms time');
  return {
    currency: authority.currency.toLowerCase(),
    max_amount: authority.maxAmount,
    ...(authority.expiresAtMs !== undefined ? { expires_at: Math.floor(authority.expiresAtMs / 1000) } : {}),
  };
}

/**
 * A Shared Payment Token may be no wider than the delegated payment token (and so the PCA proof) it serves: same currency,
 * `max_amount` not above the delegated amount, and an expiry present and not after the delegated token's. Returns the reason
 * it is wider, or `ok`.
 */
export function stripeSptWithinClaims(
  t: unknown,
  claims: { amount: number; currency: string; exp: number },
): { ok: true } | { ok: false; reason: string } {
  const problems = stripeSptProblems(t);
  if (problems.length > 0) return { ok: false, reason: `malformed token: ${problems[0]}` };
  const lim = (t as StripeSharedPaymentGrantedToken).usage_limits as StripeSptUsageLimits;
  if (lim.currency !== claims.currency.toLowerCase()) return { ok: false, reason: 'the token currency differs from the delegated currency' };
  if (lim.max_amount > claims.amount) return { ok: false, reason: `max_amount ${lim.max_amount} exceeds the delegated amount ${claims.amount}` };
  if (typeof lim.expires_at !== 'number') return { ok: false, reason: 'the token has no expiry' };
  if (lim.expires_at * 1000 > claims.exp) return { ok: false, reason: 'the token outlives the delegated payment token' };
  return { ok: true };
}
