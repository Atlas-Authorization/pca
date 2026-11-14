import type { PaymentMandate } from './mandate';

/**
 * The `usage_limits` of a Stripe Shared Payment Token (docs.stripe.com/api/shared-payment/granted-token/create:
 * `currency` lowercase ISO 4217, `max_amount` integer minor units, `expires_at` seconds) that fits what this mandate lets an
 * agent spend WITHOUT a human co-sign: at most the auto-approve threshold, at most the remaining autonomous budget, in the
 * mandate currency, expiring with the mandate period. Throws when there is no autonomous capacity left (a token for more
 * would need a co-sign) or the mandate has already ended at `now`.
 */
export function sharedPaymentTokenLimits(mandate: PaymentMandate, now: number): { currency: string; max_amount: number; expires_at?: number } {
  if (!Number.isFinite(now)) throw new TypeError('sharedPaymentTokenLimits: now must be an epoch-ms time');
  const t = mandate.terms;
  const budget = Math.floor(mandate.budget.B);
  const max = Math.min(t.autoApproveThreshold, budget);
  if (!Number.isSafeInteger(max) || max <= 0) throw new RangeError('sharedPaymentTokenLimits: no autonomous spend capacity is left; a human co-sign is needed');
  if (t.periodEnd !== undefined && now >= t.periodEnd) throw new RangeError('sharedPaymentTokenLimits: the mandate period has ended');
  return {
    currency: t.currency.toLowerCase(),
    max_amount: max,
    ...(t.periodEnd !== undefined ? { expires_at: Math.floor(t.periodEnd / 1000) } : {}),
  };
}
