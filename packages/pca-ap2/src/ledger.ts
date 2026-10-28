import { verifyPurchase, type PurchaseResult, type VerifyPurchaseOptions } from './chain';
import type { MandateContext } from './constraints';

/**
 * Durable, serialised purchase state for open mandates. `reserve` is ONE atomic step: it refuses a transaction id that
 * was already reserved under this open mandate (`replayed`), otherwise records it with its amount and returns the
 * usage of every EARLIER reservation (so two concurrent purchases see each other and cannot share one budget).
 * Back it with a unique key on (openMandateHash, transactionId) and a serialised sum (a row lock or one conditional
 * write). `release` undoes a reservation whose purchase then failed verification.
 */
export interface PurchaseLedger {
  reserve(openMandateHash: string, transactionId: string, amountMinor: number): Promise<MandateContext | 'replayed'>;
  release(openMandateHash: string, transactionId: string): Promise<void>;
}

export type RedeemResult = PurchaseResult | { ok: false; reason: 'replayed' | 'ledger_unavailable' | 'ledger_required' };

/**
 * `verifyPurchase` plus single use and server-owned cumulative state. The usage context comes from `ledger`, never from
 * the caller, and the purchase's transaction id can be redeemed once. A missing or failing ledger denies.
 */
export async function redeemPurchase(checkoutToken: string, paymentToken: string, o: Omit<VerifyPurchaseOptions, 'context'>, ledger: PurchaseLedger): Promise<RedeemResult> {
  if (!ledger || typeof ledger.reserve !== 'function' || typeof ledger.release !== 'function') return { ok: false, reason: 'ledger_required' };
  // A zero context is the most permissive one for budget and recurrence, so a failure here is final.
  const first = verifyPurchase(checkoutToken, paymentToken, { ...o, context: { totalAmount: 0, totalUses: 0 } });
  if (!first.ok) return first;
  const openHash = first.payment.openHash;
  const txId = first.payment.closed.transaction_id;
  const amount = first.payment.closed.payment_amount.amount;
  let ctx: MandateContext | 'replayed';
  try {
    ctx = await ledger.reserve(openHash, txId, amount);
  } catch {
    return { ok: false, reason: 'ledger_unavailable' };
  }
  if (ctx === 'replayed') return { ok: false, reason: 'replayed' };
  const final = verifyPurchase(checkoutToken, paymentToken, { ...o, context: ctx });
  if (!final.ok) {
    try {
      await ledger.release(openHash, txId);
    } catch {
      /* the reservation stays: a failed release only ever over-counts spend */
    }
  }
  return final;
}
