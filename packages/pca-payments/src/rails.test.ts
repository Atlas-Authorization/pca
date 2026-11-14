import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { encodeKey, generateKeyPair } from '@atlasauth/pca';
import { buildPaymentMandate, type PaymentMandateParams } from './mandate';
import {
  categoriesFromTraits, createRailAuthorizer, railLimits, reconcileSettlement, type InstrumentBinding, type RailAuthorization,
} from './rails';
import {
  createStripeIssuingWebhook, signStripePayload, stripeAuthorizationFromEvent, stripeCardParams, stripeSettlementFromTransaction, verifyStripeSignature,
} from './rails-stripe';
import { memoryChargeBudgetStore } from './testing';

const NOW = 1_800_000_000_000;
const fx = (n: string): unknown => JSON.parse(readFileSync(join(__dirname, '../test-fixtures/stripe-issuing', n), 'utf8'));
const raw = (n: string): string => readFileSync(join(__dirname, '../test-fixtures/stripe-issuing', n), 'utf8');
const principal = generateKeyPair();
const agent = generateKeyPair();
const params: PaymentMandateParams = {
  principalSecret: principal.secretKey, principalPublic: encodeKey(principal.publicKey), agentPublic: encodeKey(agent.publicKey),
  merchants: ['1234567890'], categories: ['5734', '5817'], currency: 'USD', perTransactionCap: 800, autoApproveThreshold: 500, cumulativeCap: 1000, periodMs: 86_400_000, now: NOW,
};
const mandate = buildPaymentMandate(params);
const binding = (): InstrumentBinding => ({ mandate, grant: mandate.grant });
const mkAuthorizer = (over: { latencyBudgetMs?: number; instruments?: (id: string) => InstrumentBinding | undefined | Promise<InstrumentBinding | undefined> } = {}) =>
  createRailAuthorizer({ instruments: (id) => (id === 'ic_card_1' ? binding() : undefined), store: memoryChargeBudgetStore(), now: () => NOW, ...over });

describe('rail limits mirror the grant', () => {
  it('per-authorization = min(threshold, budget), total = budget, categories and expiry from the mandate', () => {
    const l = railLimits(mandate, NOW);
    expect(l).toEqual({ currency: 'USD', perAuthorizationMax: 500, totalMax: 1000, categories: ['5734', '5817'], merchants: ['1234567890'], expiresAt: NOW + 86_400_000 });
  });
  it('action traits only narrow the categories; an empty intersection or no control at all is refused', () => {
    expect(categoriesFromTraits(['pca.money_moving', 'mcc.c5734', 'mcc.cxx', 'acme.mcc.c1111'])).toEqual(['5734']);
    expect(railLimits(mandate, NOW, { actionTraits: ['mcc.c5734', 'mcc.c0001'] }).categories).toEqual(['5734']);
    expect(() => railLimits(mandate, NOW, { actionTraits: ['mcc.c0001'] })).toThrow(/do not intersect/);
    const open = buildPaymentMandate({ ...params, categories: undefined });
    expect(() => railLimits(open, NOW)).toThrow(/no category control/);
    expect(railLimits(open, NOW, { allowAnyCategory: true }).categories).toEqual([]);
    expect(railLimits(open, NOW, { actionTraits: ['mcc.c5734'] }).categories).toEqual(['5734']);
  });
  it('no autonomous capacity left means no instrument', () => {
    expect(() => railLimits({ ...mandate, budget: { ...mandate.budget, B: 0 } }, NOW)).toThrow(/no autonomous spend capacity/);
  });
  it('Stripe card params carry the same limits and a Stripe category name for every MCC', () => {
    const p = stripeCardParams(railLimits(mandate, NOW), { cardholder: 'ich_1', categoryNames: { '5734': 'computer_software_stores', '5817': 'digital_goods_applications' }, metadata: { grant: 'g1' } });
    expect(p).toMatchObject({
      type: 'virtual', status: 'active', currency: 'usd',
      'spending_controls[spending_limits][0][amount]': '500', 'spending_controls[spending_limits][0][interval]': 'per_authorization',
      'spending_controls[spending_limits][1][amount]': '1000', 'spending_controls[spending_limits][1][interval]': 'all_time',
      'spending_controls[allowed_categories][0]': 'computer_software_stores', 'spending_controls[allowed_categories][1]': 'digital_goods_applications', 'metadata[grant]': 'g1',
    });
    expect(() => stripeCardParams(railLimits(mandate, NOW), { cardholder: 'ich_1', categoryNames: { '5734': 'x' } })).toThrow(/5817/);
  });
});

describe('real-time authorization answers from authorizeCharge', () => {
  const a = (over: Partial<RailAuthorization> = {}): RailAuthorization => ({ id: 'iauth_1', instrumentId: 'ic_card_1', amount: 400, currency: 'usd', merchantId: '1234567890', mcc: '5734', ...over });
  it('approves only an `auto` decision and debits the budget', async () => {
    const authorize = mkAuthorizer();
    const v = await authorize(a());
    expect(v).toMatchObject({ approved: true, reasons: [] });
    expect(v.decision?.budgetAfter.B).toBeLessThan(v.decision!.budgetBefore.B);
  });
  it('declines: over the human line (step-up), over the ceiling, wrong merchant, category, currency, unknown card, bad amount', async () => {
    const authorize = mkAuthorizer();
    const stepUps: string[] = [];
    const withHook = createRailAuthorizer({ instruments: () => binding(), store: memoryChargeBudgetStore(), now: () => NOW, onStepUp: (x) => { stepUps.push(x.id); } });
    expect(await withHook(a({ amount: 600 }))).toMatchObject({ approved: false, reasons: expect.arrayContaining(['step_up_required']) });
    expect(stepUps).toEqual(['iauth_1']);
    for (const bad of [a({ amount: 900 }), a({ merchantId: '9999999999' }), a({ mcc: '7995' }), a({ mcc: undefined }), a({ currency: 'eur' }), a({ instrumentId: 'ic_other' }), a({ amount: 0 }), a({ amount: 1.5 }), a({ amount: -5 }), a({ merchantId: undefined }), a({ id: '' })]) {
      expect((await authorize(bad)).approved, JSON.stringify(bad)).toBe(false);
    }
    expect((await authorize(null as unknown as RailAuthorization)).reasons).toEqual(['malformed_authorization']);
  });
  it('the cumulative budget is spent atomically: the third 400 does not fit in 1000', async () => {
    const authorize = mkAuthorizer();
    const r = [await authorize(a({ id: '1' })), await authorize(a({ id: '2' })), await authorize(a({ id: '3' }))];
    expect(r.map((x) => x.approved)).toEqual([true, true, false]);
  });
  it('declines at the latency budget, and on any thrown error', async () => {
    const slow = mkAuthorizer({ latencyBudgetMs: 20, instruments: () => new Promise((res) => setTimeout(() => res(binding()), 200)) });
    const t0 = Date.now();
    expect(await slow(a())).toEqual({ approved: false, reasons: ['latency_budget_exceeded'] });
    expect(Date.now() - t0).toBeLessThan(150);
    const boom = mkAuthorizer({ instruments: () => { throw new Error('db down'); } });
    expect(await boom(a())).toEqual({ approved: false, reasons: ['authorizer_error'] });
    expect(() => createRailAuthorizer({ instruments: () => undefined, store: memoryChargeBudgetStore(), latencyBudgetMs: 0 })).toThrow(RangeError);
  });
});

describe('Stripe Issuing webhook (documented-shape fixtures)', () => {
  const secret = 'whsec_test_secret';
  const T = Math.floor(NOW / 1000);
  const hook = () => createStripeIssuingWebhook({ secret, authorize: mkAuthorizer(), nowSec: () => T });
  const post = (name: string, over: { sig?: string | undefined; body?: string } = {}) => {
    const body = over.body ?? raw(name);
    return hook()({ rawBody: body, signature: 'sig' in over ? over.sig : signStripePayload(body, secret, T) });
  };
  it('approves an in-policy request with the required Stripe-Version header and no amount', async () => {
    const r = await post('request-ok.json');
    expect(r.status).toBe(200);
    expect(r.headers['Stripe-Version']).toBe('2025-03-31.basil');
    expect(r.headers['Content-Type']).toBe('application/json');
    expect(JSON.parse(r.body)).toEqual({ approved: true });
  });
  it.each(['request-over-threshold.json', 'request-wrong-category.json', 'request-unknown-merchant.json', 'request-unknown-card.json', 'request-wrong-currency.json', 'request-no-pending.json'])('declines %s', async (n) => {
    const r = await post(n);
    expect(r.status).toBe(200);
    expect(JSON.parse(r.body)).toEqual({ approved: false });
  });
  it('a bad, missing, stale or tampered signature decides nothing (400)', async () => {
    const body = raw('request-ok.json');
    for (const sig of [undefined, '', 'garbage', signStripePayload(body, 'whsec_other', T), signStripePayload(body, secret, T - 600), signStripePayload(body + ' ', secret, T), `t=${T},v1=${'0'.repeat(64)}`]) {
      expect((await post('request-ok.json', { sig })).status, String(sig)).toBe(400);
    }
    expect((await post('request-ok.json', { body: 'not json', sig: signStripePayload('not json', secret, T) })).status).toBe(400);
  });
  it('other event types get an empty 200', async () => {
    expect(JSON.parse((await post('other-event.json')).body)).toEqual({});
  });
  it('signature scheme: v1 over "t.payload", constant-time compare, multiple v1 accepted, tolerance respected', () => {
    const body = '{"a":1}';
    const h = signStripePayload(body, secret, T);
    expect(verifyStripeSignature(body, h, secret, T)).toBe(true);
    expect(verifyStripeSignature(body, `${h},v1=${'1'.repeat(64)}`, secret, T)).toBe(true);
    expect(verifyStripeSignature(body, h, secret, T + 301)).toBe(false);
    expect(verifyStripeSignature(body, h, secret, T + 299)).toBe(true);
    expect(verifyStripeSignature(body, h, '', T)).toBe(false);
    expect(verifyStripeSignature(body, h, secret, T, 0)).toBe(false);
  });
  it('event normalisation reads structured fields only', () => {
    expect(stripeAuthorizationFromEvent(fx('request-ok.json'))).toEqual({ id: 'iauth_1', instrumentId: 'ic_card_1', amount: 400, currency: 'usd', merchantId: '1234567890', mcc: '5734' });
    expect(stripeAuthorizationFromEvent(fx('other-event.json'))).toBeUndefined();
    expect(stripeAuthorizationFromEvent(null)).toBeUndefined();
  });
});

describe('settlement reconciliation', () => {
  const approved = { id: 'iauth_1', amount: 400, currency: 'usd', merchantId: '1234567890' };
  const settle = (n: string) => stripeSettlementFromTransaction(fx(n))!;
  it('an exact capture reconciles', () => {
    expect(reconcileSettlement(approved, settle('transaction-capture.json'))).toEqual({ ok: true });
    expect(reconcileSettlement(approved, { ...settle('transaction-capture.json'), amount: 300 })).toEqual({ ok: true });
  });
  it('more charged, another merchant, a second capture, another authorization: freeze the grant', () => {
    expect(reconcileSettlement(approved, settle('transaction-capture-more.json'))).toEqual({ ok: false, reasons: ['settled_more_than_approved'], action: 'freeze_grant' });
    expect(reconcileSettlement(approved, settle('transaction-capture-other-merchant.json'))).toMatchObject({ ok: false, reasons: ['merchant_mismatch'] });
    expect(reconcileSettlement(approved, { ...settle('transaction-capture.json'), captures: 2 })).toMatchObject({ ok: false, reasons: ['second_capture'] });
    expect(reconcileSettlement(approved, { ...settle('transaction-capture.json'), authorizationId: 'iauth_9' })).toMatchObject({ ok: false, reasons: ['authorization_id_mismatch'] });
  });
  it('only captures settle; a refund is not a settlement', () => {
    expect(stripeSettlementFromTransaction(fx('transaction-refund.json'))).toBeUndefined();
  });
});
