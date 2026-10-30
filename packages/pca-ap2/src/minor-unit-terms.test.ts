/** PCA terms in the AP2 binding are integer minor units of the mandate currency (ISO 4217 exponent per currency). */
import { describe, expect, it } from 'vitest';
import { encodeKey, generateKeyPair } from '@atlasauth/pca';
import { buildPaymentMandate } from '@atlasauth/pca-payments';
import { Ap2Error, ap2BudgetMax, ap2BudgetReads, buildPcaPaymentBinding, paymentConstraintsFromTerms, verifyPcaBinding } from './index';
import { MERCHANT, NOW_MS, createThresholdVerifier, makeScenario, verifyScenario } from './testkit';

const principal = generateKeyPair();
const agent = generateKeyPair();
const mk = (currency: string, cap: number, perTx = 1000, over: Record<string, unknown> = {}) =>
  buildPaymentMandate({
    principalSecret: principal.secretKey, principalPublic: encodeKey(principal.publicKey), agentPublic: encodeKey(agent.publicKey),
    merchants: ['merchant_1'], currency, perTransactionCap: perTx, autoApproveThreshold: 100, cumulativeCap: cap, now: NOW_MS, ...over,
  });
const budget = (m: ReturnType<typeof mk>) => paymentConstraintsFromTerms(m.terms, [MERCHANT], 'R').find((c) => c.type === 'payment.budget');
const range = (m: ReturnType<typeof mk>) => paymentConstraintsFromTerms(m.terms, [MERCHANT], 'R').find((c) => c.type === 'payment.amount_range');

describe('exponent per currency', () => {
  it('USD (2): minor-unit range, major-unit budget the SDK reads back exactly', () => {
    const m = mk('USD', 123_456);
    expect(range(m)).toMatchObject({ max: 1000 });
    const b = budget(m) as { max: number };
    expect(Math.trunc(b.max * 100)).toBe(123_456); // what the official SDK reads
    expect(Math.round(b.max * 100)).toBe(123_456);
  });
  it('KWD (3): budget is cap / 1000 (exact for a major-unit reader); the SDK x100 read is cap / 10, narrower, never wider', () => {
    const b = budget(mk('KWD', 5_000_000)) as { max: number };
    expect(b.max).toBe(5000);
    expect(ap2BudgetReads(b.max, 'KWD')).toEqual({ sdk: 500_000, major: 5_000_000 });
  });
  it('JPY (0): budget is cap / 100, so the SDK x100 read is exactly the cap (a major-unit reader reads less); amount_range stays in yen', () => {
    const m = mk('JPY', 100_000, 5_000);
    const b = budget(m) as { max: number };
    expect(b.max).toBe(1000);
    expect(ap2BudgetReads(b.max, 'JPY')).toEqual({ sdk: 100_000, major: 1000 });
    expect(range(m)).toMatchObject({ max: 5000, currency: 'JPY' });
  });
  it('USD (2): exact for both readers, including caps whose x100 product is inexact in floating point (29, 57, 58, 115)', () => {
    for (const cap of [29, 57, 58, 115, 123_456]) {
      const r = ap2BudgetReads(ap2BudgetMax(cap, 'USD'), 'USD');
      expect(r).toEqual({ sdk: cap, major: cap });
    }
  });
  it('for every exponent and 1..3000 minor units neither reader ever reads above the cap, and the SDK read is exact up to exponent 2', () => {
    for (const cur of ['USD', 'JPY', 'KWD', 'CLF']) {
      for (let cap = 1; cap <= 3000; cap++) {
        const r = ap2BudgetReads(ap2BudgetMax(cap, cur), cur);
        expect(r.sdk, `${cur} ${cap}`).toBeLessThanOrEqual(cap);
        expect(r.major, `${cur} ${cap}`).toBeLessThanOrEqual(cap);
        if (cur === 'USD' || cur === 'JPY') expect(r.sdk, `${cur} ${cap}`).toBe(cap);
        if (cur === 'KWD') expect(r.sdk, `${cur} ${cap}`).toBe(Math.floor(cap / 10));
      }
    }
  });
  it('a verifier refuses an open mandate whose budget either reader would read above the PCA cap', () => {
    expect(ap2BudgetReads(1000.01, 'USD').sdk).toBe(100_001);
    expect(() => ap2BudgetMax(1.5, 'USD')).toThrow(Ap2Error);
    expect(() => ap2BudgetReads(-1, 'USD')).toThrow(Ap2Error);
  });
});

describe('terms must be integer minor units', () => {
  it('a legacy fractional major-unit mandate is refused with the exact reason', () => {
    const legacy = mk('USD', 1000.5, 500.5, { autoApproveThreshold: 50, strictMinorUnits: false });
    expect(() => paymentConstraintsFromTerms(legacy.terms, [MERCHANT], 'R')).toThrow(Ap2Error);
    expect(() => paymentConstraintsFromTerms(legacy.terms, [MERCHANT], 'R')).toThrow('PCA term perTransactionCap must be a non-negative integer in minor units, got 500.5');
  });
  it('buildPaymentMandate itself refuses fractional terms by default', () => {
    expect(() => mk('USD', 1000.5)).toThrow(/cumulativeCap/);
  });
  it('a charge amount that is not an integer is refused when the binding is built', () => {
    const s = makeScenario();
    expect(() => buildPcaPaymentBinding({ mandate: s.pca, open: s.openPayment, agentJwk: s.agent.publicJwk, agentSecret: s.agentEd.secretKey, audience: s.pcaAudience, counter: 7, transactionId: 'T', payee: MERCHANT, amount: { amount: 12.5, currency: 'USD' }, instrumentId: 'card_4242' })).toThrow(/integer in minor units/);
  });
});

describe('an amount with cents is accepted end to end (it used to be denied as a fractional major-unit value)', () => {
  it('27999 minor (USD 279.99) with a human co-sign verifies', async () => {
    const s = makeScenario({ amountMinor: 27_999, quantity: 1, unitPrice: 27_999, cosign: true });
    const r = verifyScenario(s);
    if (!r.ok) throw new Error(r.reason);
    const v = await verifyPcaBinding({
      open: structuredClone(r.payment.open), closed: structuredClone(r.payment.closed), openHash: r.payment.openHash,
      expectedPrincipal: encodeKey(s.principal.publicKey), audience: s.pcaAudience, now: NOW_MS + 60_000, mandate: s.pca, recentChargeTimes: [],
      hooks: { threshold: createThresholdVerifier({ t: 3, signerSet: s.signerSet }) as never },
    });
    expect(v.ok, v.ok ? '' : v.reason).toBe(true);
  });
});
