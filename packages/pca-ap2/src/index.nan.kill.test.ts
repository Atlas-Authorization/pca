import { describe, expect, it } from 'vitest';
import { encodeKey } from '@atlasauth/pca';
import { checkPaymentConstraints, verifyPcaBinding, type MandateContext, type OpenPaymentMandateClaims, type PaymentConstraint, type PaymentMandateClaims } from './index';
import { NOW_MS, makeScenario, verifyScenario } from './testkit';

const BAD = [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY];

describe('chain clock: a non-finite now or skew never admits a purchase', () => {
  // pre-fix: `now > exp + skew` and `iat > now + skew` were false for a NaN operand
  it.each(BAD)('now of %s', (now) => {
    expect(verifyScenario(makeScenario(), { now }).ok).toBe(false);
  });
  it('clockSkewSeconds of NaN', () => {
    expect(verifyScenario(makeScenario(), { clockSkewSeconds: Number.NaN }).ok).toBe(false);
  });
  // an infinite skew widens both windows without bound (`iat <= now + Infinity`), so it never admits either
  it('clockSkewSeconds of +Infinity', () => {
    expect(verifyScenario(makeScenario(), { clockSkewSeconds: Number.POSITIVE_INFINITY }).ok).toBe(false);
  });
});

describe('payment.budget with a non-finite amount or max never admits', () => {
  const closed = (amount: number): PaymentMandateClaims =>
    ({
      vct: 'mandate.payment.1',
      transaction_id: 'T',
      payee: { id: 'm1', name: 'One', website: 'https://one.example' },
      payment_amount: { amount, currency: 'USD' },
      payment_instrument: { id: 'pi', type: 'card' },
    }) as PaymentMandateClaims;
  const run = (max: number, amount: number): string[] => {
    const budget: PaymentConstraint = { type: 'payment.budget', currency: 'USD', max };
    const context: MandateContext = { totalAmount: 0, totalUses: 0 };
    return checkPaymentConstraints({ vct: 'mandate.payment.open.1', constraints: [budget], cnf: { jwk: {} } } as never, closed(amount), { now: 1, context });
  };
  // pre-fix: `spend > maxMinor` was false for NaN spend; `abs(scaled - maxMinor) > 1e-6` was false for NaN
  it.each(BAD)('closed amount of %s', (amount) => {
    expect(run(100, amount)).not.toEqual([]);
  });
  it.each(BAD)('budget max of %s', (max) => {
    expect(run(max, 1000)).not.toEqual([]);
  });
});

describe('x_pca amount_range.max of NaN is refused against the per-transaction cap', () => {
  // pre-fix: `max > perTx` was false for NaN, so the comparison with the cap was skipped
  it('NaN max', async () => {
    const s = makeScenario();
    const r = verifyScenario(s);
    if (!r.ok) throw new Error(r.reason);
    const open = structuredClone(r.payment.open) as OpenPaymentMandateClaims;
    (open.constraints.find((c) => c.type === 'payment.amount_range') as unknown as { max: number }).max = Number.NaN;
    const res = await verifyPcaBinding({
      open,
      closed: structuredClone(r.payment.closed),
      openHash: r.payment.openHash,
      expectedPrincipal: encodeKey(s.principal.publicKey),
      audience: s.pcaAudience,
      now: NOW_MS + 60_000,
      mandate: s.pca,
      recentChargeTimes: [],
    } as never);
    expect(res).toEqual({ ok: false, reason: expect.stringMatching(/exceeds the PCA per-transaction cap/) });
  });
});
