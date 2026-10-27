import { describe, expect, it } from 'vitest';
import { checkPaymentConstraints, redeemPurchase, type MandateContext, type PaymentConstraint, type PaymentMandateClaims, type PurchaseLedger } from './index';
import { memoryPurchaseLedger } from './testing';
import { MERCHANT, makeScenario, purchaseOptions, verifyScenario } from './testkit';

const opts = (s: ReturnType<typeof makeScenario>) => {
  const { context: _c, ...rest } = purchaseOptions(s);
  return rest;
};

describe('redeemPurchase: single use and server-owned cumulative state', () => {
  it('redeems once; the second redemption of the same purchase is replayed', async () => {
    const s = makeScenario();
    const ledger = memoryPurchaseLedger();
    const first = await redeemPurchase(s.checkoutChain, s.paymentChain, opts(s), ledger);
    expect(first.ok).toBe(true);
    expect(await redeemPurchase(s.checkoutChain, s.paymentChain, opts(s), ledger)).toEqual({ ok: false, reason: 'replayed' });
  });
  it('requires a ledger (fail closed)', async () => {
    const s = makeScenario();
    for (const bad of [undefined, null, {}, { reserve: async () => 'replayed' }]) {
      expect(await redeemPurchase(s.checkoutChain, s.paymentChain, opts(s), bad as never)).toEqual({ ok: false, reason: 'ledger_required' });
    }
  });
  it('a throwing ledger denies', async () => {
    const s = makeScenario();
    const ledger: PurchaseLedger = { reserve: async () => { throw new Error('down'); }, release: async () => {} };
    expect(await redeemPurchase(s.checkoutChain, s.paymentChain, opts(s), ledger)).toEqual({ ok: false, reason: 'ledger_unavailable' });
  });
  it('the budget is enforced from ledger state: earlier spend leaves no room, and the failed attempt is released', async () => {
    const s = makeScenario({ cumulativeCap: 500 }); // budget 500.00 = 50000 minor, purchase 4000
    const probe = verifyScenario(s);
    if (!probe.ok) throw new Error(probe.reason);
    const ledger = memoryPurchaseLedger();
    await ledger.reserve(probe.payment.openHash, 'earlier', 47_000);
    const r = await redeemPurchase(s.checkoutChain, s.paymentChain, opts(s), ledger);
    expect(r.ok).toBe(false);
    expect((r as { reason: string }).reason).toMatch(/cumulative spend 51000 exceeds budget 50000 \(past spend 47000\)/);
    expect(ledger.usage(probe.payment.openHash)).toEqual({ totalAmount: 47_000, totalUses: 1 });
    // room again after the earlier spend shrinks: redeemable
    await ledger.release(probe.payment.openHash, 'earlier');
    expect((await redeemPurchase(s.checkoutChain, s.paymentChain, opts(s), ledger)).ok).toBe(true);
  });
  it('concurrent redemptions of one purchase: exactly one wins', async () => {
    const s = makeScenario();
    const ledger = memoryPurchaseLedger();
    const rs = await Promise.all(Array.from({ length: 5 }, () => redeemPurchase(s.checkoutChain, s.paymentChain, opts(s), ledger)));
    expect(rs.filter((r) => r.ok).length).toBe(1);
    expect(rs.filter((r) => !r.ok && r.reason === 'replayed').length).toBe(4);
  });
  it('a tampered purchase never reaches the ledger', async () => {
    const s = makeScenario();
    let reserved = 0;
    const ledger: PurchaseLedger = { reserve: async () => { reserved++; return { totalAmount: 0, totalUses: 0 }; }, release: async () => {} };
    const r = await redeemPurchase(s.checkoutChain, s.paymentChain.slice(0, -3) + 'AAA', opts(s), ledger);
    expect(r.ok).toBe(false);
    expect(reserved).toBe(0);
  });
});

describe('usage context is validated (a NaN or negative counter must not widen a cap)', () => {
  const closed = { vct: 'mandate.payment.1', transaction_id: 'T', payee: MERCHANT, payment_amount: { amount: 1000, currency: 'USD' }, payment_instrument: { id: 'pi', type: 'card' } } as PaymentMandateClaims;
  const budget: PaymentConstraint = { type: 'payment.budget', currency: 'USD', max: 10 };
  const rec: PaymentConstraint = { type: 'payment.agent_recurrence', frequency: 'ON_DEMAND', max_occurrences: 1 };
  const msg = ['mandate context must carry non-negative integer totalAmount, totalUses and lastUsedDate'];
  const run = (c: PaymentConstraint, context: Partial<MandateContext>) => checkPaymentConstraints({ constraints: [c] } as never, closed, { now: 1_800_000_000, context: { totalAmount: 0, totalUses: 0, ...context } });
  it.each([[NaN], [-5], [0.5], [Infinity]])('budget refuses totalAmount %s', (v) => {
    expect(run(budget, { totalAmount: v })).toEqual(msg);
  });
  it.each([[NaN], [-1], [1.5]])('recurrence refuses totalUses %s', (v) => {
    expect(run(rec, { totalUses: v })).toContain(msg[0]);
  });
  it('a valid context still evaluates', () => {
    expect(run(budget, { totalAmount: 0 })).toEqual([]);
  });
});
