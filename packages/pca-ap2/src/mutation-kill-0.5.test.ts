/** Kills for the AP2 budget arithmetic, the minor-unit term errors, the cumulative-cap readers and the ledger/context guards. */
import { describe, expect, it } from 'vitest';
import { encodeKey } from '@atlasauth/pca';
import { buildPaymentMandate } from '@atlasauth/pca-payments';
import { ap2BudgetMax, ap2BudgetReads, buildPcaPaymentBinding, pcaOpenClaim, redeemPurchase, verifyPcaBinding, checkPaymentConstraints, type MandateContext, type PaymentConstraint, type PaymentMandateClaims, type PurchaseLedger } from './index';
import { memoryPurchaseLedger } from './testing';
import { MERCHANT, NOW_MS, makeScenario, purchaseOptions, verifyScenario } from './testkit';

describe('ap2BudgetMax', () => {
  it('names the cumulative cap in its term error and accepts zero', () => {
    expect(() => ap2BudgetMax(-1, 'USD')).toThrow('PCA term cumulativeCap must be a non-negative integer in minor units, got -1');
    expect(() => ap2BudgetMax(1.5, 'USD')).toThrow('PCA term cumulativeCap must be a non-negative integer in minor units, got 1.5');
    expect(ap2BudgetMax(0, 'USD')).toBe(0);
  });
  it('refuses a cap with no exact representation, with the exact reason, whichever check trips', () => {
    // SDK reading differs (JPY), major-unit reading exceeds (USD), major-unit reading exceeds with exponent 3 (KWD)
    expect(() => ap2BudgetMax(7052058671673818, 'JPY')).toThrow('cumulativeCap 7052058671673818 JPY has no exact AP2 budget.max representation');
    expect(() => ap2BudgetMax(4313814379151066, 'USD')).toThrow('cumulativeCap 4313814379151066 USD has no exact AP2 budget.max representation');
    expect(() => ap2BudgetMax(4500449875289640, 'KWD')).toThrow('cumulativeCap 4500449875289640 KWD has no exact AP2 budget.max representation');
  });
});

describe('ap2BudgetReads', () => {
  it('refuses a non-finite or negative max with the exact reason and accepts zero', () => {
    for (const [bad, shown] of [[NaN, 'NaN'], [Infinity, 'Infinity'], [-1, '-1'], ['5', '5']] as const) {
      expect(() => ap2BudgetReads(bad as never, 'USD')).toThrow(`budget.max must be a finite non-negative number, got ${shown}`);
    }
    expect(ap2BudgetReads(0, 'USD')).toEqual({ sdk: 0, major: 0 });
  });
});

describe('buildPcaPaymentBinding', () => {
  it('names the charge amount in its term error', () => {
    expect(() => buildPcaPaymentBinding({ amount: { amount: -1, currency: 'USD' } } as never)).toThrow('PCA term amount must be a non-negative integer in minor units, got -1');
  });
});

describe('verifyPcaBinding: signed fractional terms and the two budget readers', () => {
  const pub = (k: { publicKey: Uint8Array }) => encodeKey(k.publicKey);
  const mandateFor = (s: ReturnType<typeof makeScenario>, over: Record<string, unknown>) =>
    buildPaymentMandate({
      principalSecret: s.principal.secretKey,
      principalPublic: pub(s.principal),
      agentPublic: pub(s.agentEd),
      merchants: [MERCHANT.id],
      currency: 'USD',
      perTransactionCap: 50_000,
      autoApproveThreshold: 5_000,
      cumulativeCap: 100_000,
      periodMs: 24 * 3_600_000,
      maxTransactionsPerPeriod: 5,
      now: NOW_MS,
      ...over,
    });
  const run = async (s: ReturnType<typeof makeScenario>, over: Record<string, unknown>, tamper?: (c: Record<string, unknown>[]) => void) => {
    // no overrides: the scenario's own mandate, the grant its chains are rooted in (a rebuilt mandate is a different grant)
    const m = Object.keys(over).length === 0 ? s.pca : mandateFor(s, over);
    const r = verifyScenario(s);
    if (!r.ok) throw new Error(r.reason);
    const open = structuredClone(r.payment.open);
    const cons = open.constraints as unknown as Record<string, unknown>[];
    const cur = m.terms.currency;
    for (const c of cons) if (c.type === 'payment.amount_range' || c.type === 'payment.budget') c.currency = cur;
    tamper?.(cons);
    (open as { x_pca?: unknown }).x_pca = pcaOpenClaim(m);
    const res = await verifyPcaBinding({
      open,
      closed: structuredClone(r.payment.closed),
      openHash: r.payment.openHash,
      expectedPrincipal: pub(s.principal),
      audience: s.pcaAudience,
      now: NOW_MS + 60_000,
      mandate: m,
      recentChargeTimes: [],
    } as never);
    return res.ok ? 'ACCEPTED' : res.reason;
  };
  const budget = (cons: Record<string, unknown>[]) => cons.find((c) => c.type === 'payment.budget')!;
  const NOT_INT = 'must be a non-negative integer in minor units';

  it('a fractional per-transaction cap is refused naming that term', async () => {
    expect(await run(makeScenario(), { perTransactionCap: 500.5, autoApproveThreshold: 50, strictMinorUnits: false })).toBe(`PCA term perTransactionCap ${NOT_INT}, got 500.5`);
  });
  it('a fractional cumulative cap is refused naming that term', async () => {
    expect(await run(makeScenario(), { cumulativeCap: 100_000.5, strictMinorUnits: false })).toBe(`PCA term cumulativeCap ${NOT_INT}, got 100000.5`);
  });
  it('a budget only the major-unit reader sees above the cap is refused (USD: 100000.6 minor)', async () => {
    const t = (c: Record<string, unknown>[]) => { budget(c).max = 1000.006; };
    expect(await run(makeScenario(), {}, t)).toBe('budget exceeds the PCA cumulative cap');
  });
  it('a budget only the SDK reader sees above the cap is refused (JPY: 100002 hundredths vs 1000 yen)', async () => {
    const t = (c: Record<string, unknown>[]) => { budget(c).max = 1000.02; };
    expect(await run(makeScenario(), { currency: 'JPY' }, t)).toBe('budget exceeds the PCA cumulative cap');
  });
  it('a budget at the cap passes the budget check (JPY and USD)', async () => {
    expect(await run(makeScenario(), { currency: 'JPY' })).not.toBe('budget exceeds the PCA cumulative cap');
    expect(await run(makeScenario(), {})).toBe('ACCEPTED');
  });
});

describe('redeemPurchase ledger shape', () => {
  it('a ledger without reserve is refused even when it has release', async () => {
    const s = makeScenario();
    const { context: _c, ...rest } = purchaseOptions(s);
    expect(await redeemPurchase(s.checkoutChain, s.paymentChain, rest, { release: async () => {} } as never)).toEqual({ ok: false, reason: 'ledger_required' });
  });
});

describe('memoryPurchaseLedger', () => {
  it('releasing a purchase on an open mandate never seen is a no-op', async () => {
    const l = memoryPurchaseLedger();
    await expect(l.release('never-seen', 'tx')).resolves.toBeUndefined();
    expect(l.usage('never-seen')).toEqual({ totalAmount: 0, totalUses: 0 });
  });
});

describe('usage context lastUsedDate', () => {
  const closed = { vct: 'mandate.payment.1', transaction_id: 'T', payee: MERCHANT, payment_amount: { amount: 1000, currency: 'USD' }, payment_instrument: { id: 'pi', type: 'card' } } as PaymentMandateClaims;
  const budget: PaymentConstraint = { type: 'payment.budget', currency: 'USD', max: 10 };
  const msg = ['mandate context must carry non-negative integer totalAmount, totalUses and lastUsedDate'];
  const run = (context: Partial<MandateContext>) => checkPaymentConstraints({ constraints: [budget] } as never, closed, { now: 1_800_000_000, context: { totalAmount: 0, totalUses: 0, ...context } });
  it.each([[NaN], [-1], [1.5], [-0]])('refuses lastUsedDate %s', (v) => {
    expect(run({ lastUsedDate: v })).toEqual(msg);
  });
  it('accepts an absent or valid lastUsedDate', () => {
    expect(run({})).toEqual([]);
    expect(run({ lastUsedDate: 1_700_000_000 })).toEqual([]);
  });
});
