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

describe('payment constraints never admit on a non-finite amount, count or clock', () => {
  const closed = (amount: number, extra: object = {}): PaymentMandateClaims =>
    ({
      vct: 'mandate.payment.1',
      transaction_id: 'T',
      payee: { id: 'm1', name: 'One', website: 'https://one.example' },
      payment_amount: { amount, currency: 'USD' },
      payment_instrument: { id: 'pi', type: 'card' },
      ...extra,
    }) as PaymentMandateClaims;
  const check = (c: PaymentConstraint, cl: PaymentMandateClaims, now = 1, context: MandateContext = { totalAmount: 0, totalUses: 0 }): string[] =>
    checkPaymentConstraints({ vct: 'mandate.payment.open.1', constraints: [c], cnf: { jwk: {} } } as never, cl, { now, context });

  // pre-fix: `amount > max` was false for NaN, so the amount sailed through the range
  it.each(BAD)('amount_range with an amount of %s', (amount) => {
    expect(check({ type: 'payment.amount_range', currency: 'USD', max: 1000 }, closed(amount))).not.toEqual([]);
  });
  // pre-fix: `amount < min` and `amount > max` were both false for a NaN bound
  it('amount_range with a NaN min or max', () => {
    expect(check({ type: 'payment.amount_range', currency: 'USD', max: 1000, min: Number.NaN }, closed(10))).not.toEqual([]);
    expect(check({ type: 'payment.amount_range', currency: 'USD', max: Number.NaN }, closed(10))).not.toEqual([]);
  });
  // pre-fix: `totalUses >= max_occurrences` was false for a NaN limit
  it('max_occurrences of NaN', () => {
    expect(check({ type: 'payment.agent_recurrence', frequency: 'ON_DEMAND', max_occurrences: Number.NaN } as PaymentConstraint, closed(10))).not.toEqual([]);
  });
  // pre-fix: `lastUsed >= periodStart(NaN)` was false, so a used period read as unused
  it.each(BAD)('daily recurrence with a clock of %s', (now) => {
    expect(check({ type: 'payment.agent_recurrence', frequency: 'DAILY' } as PaymentConstraint, closed(10), now, { totalAmount: 0, totalUses: 1, lastUsedDate: 1 })).not.toEqual([]);
  });
  // pre-fix: `at < not_before` was false for a NaN instant derived from a non-finite clock
  it.each(BAD)('execution_date window with a clock of %s', (now) => {
    expect(check({ type: 'payment.execution_date', not_before: '2000-01-01T00:00:00Z' } as PaymentConstraint, closed(10), now)).not.toEqual([]);
  });
  // pre-fix: periodStart returned undefined and the violation only fired when a last-used date existed
  it.each(['HOURLY', '', 'daily'])('unknown recurrence frequency %j is always a violation', (frequency) => {
    const c = { type: 'payment.agent_recurrence', frequency } as unknown as PaymentConstraint;
    expect(check(c, closed(10))).toContain('unknown recurrence frequency');
    expect(check(c, closed(10), 1, { totalAmount: 0, totalUses: 0 })).toContain('unknown recurrence frequency');
  });
});

describe('chain clock: an infinite clockSkewSeconds never admits', () => {
  // pre-fix: `now > exp + Infinity` was false, so any expired chain verified
  it.each([Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])('clockSkewSeconds of %s', (clockSkewSeconds) => {
    expect(verifyScenario(makeScenario(), { clockSkewSeconds }).ok).toBe(false);
  });
});
