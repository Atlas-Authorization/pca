import { encodeKey, generateKeyPair } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import { type MandateTerms, type PaymentMandateParams, buildPaymentMandate, mandateCaveats } from './mandate';

const principal = generateKeyPair();
const agent = generateKeyPair();
const base = (over: Partial<PaymentMandateParams> = {}): PaymentMandateParams => ({
  principalSecret: principal.secretKey,
  principalPublic: encodeKey(principal.publicKey),
  agentPublic: encodeKey(agent.publicKey),
  merchants: ['m1', 'm2'],
  currency: 'USD',
  perTransactionCap: 100,
  autoApproveThreshold: 50,
  cumulativeCap: 500,
  now: 1_700_000_000_000,
  goalSalt: Buffer.alloc(16, 7).toString('base64url'),
  ...over,
});
const msg = (over: Partial<PaymentMandateParams>): string => {
  try {
    buildPaymentMandate(base(over));
  } catch (e) {
    return (e as Error).message;
  }
  return 'no error';
};
const LOOSE = { strictMinorUnits: false } as const;

describe('validation: exact refusals and boundaries', () => {
  it('merchant ids must be non-empty strings', () => {
    const m = 'buildPaymentMandate: merchant ids must be non-empty strings';
    expect(msg({ merchants: [''] })).toBe(m);
    expect(msg({ merchants: ['ok', ''] })).toBe(m);
    expect(msg({ merchants: [5 as never] })).toBe(m);
    expect(msg({ merchants: ['ok'] })).toBe('no error');
  });
  it('currency is required', () => {
    expect(msg({ currency: '' })).toBe('buildPaymentMandate: currency is required');
    expect(msg({ currency: 5 as never })).toBe('buildPaymentMandate: currency is required');
  });
  it('the auto-approve threshold Y: 0 <= Y <= X and finite', () => {
    const m = 'buildPaymentMandate: autoApproveThreshold (Y) must satisfy 0 ≤ Y ≤ X';
    expect(msg({ autoApproveThreshold: 0 })).toBe('no error');
    expect(msg({ autoApproveThreshold: 100 })).toBe('no error');
    expect(msg({ autoApproveThreshold: -1 })).toBe(m);
    expect(msg({ autoApproveThreshold: 101 })).toBe(m);
    expect(msg({ ...LOOSE, autoApproveThreshold: Number.NaN })).toBe(m);
    expect(msg({ ...LOOSE, autoApproveThreshold: -0.5 })).toBe(m);
  });
  it('periodMs must be a finite number > 0 when given', () => {
    const m = 'buildPaymentMandate: periodMs must be a finite number > 0 when given';
    expect(msg({ periodMs: 1 })).toBe('no error');
    for (const v of [0, -1, Number.NaN, Infinity, '5' as never]) expect(msg({ periodMs: v })).toBe(m);
  });
  it('maxTransactionsPerPeriod must be a positive integer when given', () => {
    const m = 'buildPaymentMandate: maxTransactionsPerPeriod must be a positive integer when given';
    expect(msg({ maxTransactionsPerPeriod: 1 })).toBe('no error');
    for (const v of [0, -1, 1.5, Number.NaN, '3' as never]) expect(msg({ maxTransactionsPerPeriod: v })).toBe(m);
  });
  it('replenishPerCosign must be a finite number >= 0 when given', () => {
    const m = 'buildPaymentMandate: replenishPerCosign must be a finite number ≥ 0 when given';
    expect(msg({ replenishPerCosign: 0 })).toBe('no error');
    expect(msg({ replenishPerCosign: 10 })).toBe('no error');
    expect(msg({ replenishPerCosign: -1 })).toBe(m);
    expect(msg({ ...LOOSE, replenishPerCosign: Number.NaN })).toBe(m);
    expect(msg({ ...LOOSE, replenishPerCosign: -0.5 })).toBe(m);
    expect(msg({ ...LOOSE, replenishPerCosign: Infinity })).toBe(m);
  });
});

describe('terms and caveats', () => {
  const terms = (over: Partial<MandateTerms> = {}): MandateTerms => ({ merchants: ['m1'], categories: [], currency: 'USD', perTransactionCap: 100, autoApproveThreshold: 50, cumulativeCap: 500, periodStart: 0, ...over });
  it('a non-finite now falls back to the real clock', () => {
    const before = Date.now();
    const m = buildPaymentMandate(base({ now: Number.NaN }));
    expect(Number.isFinite(m.budget.tau)).toBe(true);
    expect(m.budget.tau).toBeGreaterThanOrEqual(before);
    expect(m.terms.periodStart).toBe(m.budget.tau);
    expect(buildPaymentMandate(base({ now: 'x' as never })).budget.asOf).toBeGreaterThanOrEqual(before);
  });
  it('a period start of 0 adds no not_before caveat, a positive one does', () => {
    expect(mandateCaveats(terms({ periodStart: 0 }))).toEqual([{ type: 'reversibility_max', class: 'reversible' }]);
    expect(mandateCaveats(terms({ periodStart: 5 }))).toEqual([{ type: 'not_before', at: 5 }, { type: 'reversibility_max', class: 'reversible' }]);
    expect(buildPaymentMandate(base({ periodStart: 0 })).terms.periodStart).toBe(0);
  });
  it('the rate caveat needs both a cap and an end, and spans the window in seconds (at least 1)', () => {
    expect(mandateCaveats(terms({ maxTransactionsPerPeriod: 3 }))).toEqual([{ type: 'reversibility_max', class: 'reversible' }]);
    expect(mandateCaveats(terms({ periodEnd: 90_000 }))).toEqual([{ type: 'expires', at: 90_000 }, { type: 'reversibility_max', class: 'reversible' }]);
    expect(mandateCaveats(terms({ periodStart: 10_000, periodEnd: 100_000, maxTransactionsPerPeriod: 3 }))).toEqual([
      { type: 'not_before', at: 10_000 },
      { type: 'expires', at: 100_000 },
      { type: 'rate', max: 3, per_secs: 90 },
      { type: 'reversibility_max', class: 'reversible' },
    ]);
    const tiny = mandateCaveats(terms({ periodStart: 0, periodEnd: 400, maxTransactionsPerPeriod: 2 }));
    expect(tiny).toContainEqual({ type: 'rate', max: 2, per_secs: 1 });
    expect(mandateCaveats(terms({ periodStart: 1, periodEnd: 1501, maxTransactionsPerPeriod: 2 }))).toContainEqual({ type: 'rate', max: 2, per_secs: 2 });
  });
  it('the built terms carry the velocity cap only when given', () => {
    expect(buildPaymentMandate(base({ periodMs: 1000, maxTransactionsPerPeriod: 4 })).terms).toEqual({
      merchants: ['m1', 'm2'], categories: [], currency: 'USD', perTransactionCap: 100, autoApproveThreshold: 50, cumulativeCap: 500, periodStart: 1_700_000_000_000, periodEnd: 1_700_000_001_000, maxTransactionsPerPeriod: 4,
    });
    expect(buildPaymentMandate(base()).terms).not.toHaveProperty('maxTransactionsPerPeriod');
  });
  it('the default goal states the terms; a supplied goal and salt are honoured', () => {
    const def = buildPaymentMandate(base());
    const explicit = buildPaymentMandate(base({ goal: 'spend ≤ 50 USD autonomously / ≤ 100 with co-sign, ≤ 500 cumulative, at [m1, m2]' }));
    expect(def.goalCommit).toBe(explicit.goalCommit);
    expect(buildPaymentMandate(base({ goal: 'something else' })).goalCommit).not.toBe(def.goalCommit);
    expect(def.goalSalt).toBe(Buffer.alloc(16, 7).toString('base64url'));
    const noSalt = buildPaymentMandate(base({ goalSalt: undefined }));
    expect(noSalt.goalSalt).not.toBe(def.goalSalt);
    expect(noSalt.goalSalt.length).toBeGreaterThan(0);
  });
});
