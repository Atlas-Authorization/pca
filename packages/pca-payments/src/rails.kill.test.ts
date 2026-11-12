import { createHmac } from 'node:crypto';
import { encodeKey, generateKeyPair } from '@atlasauth/pca';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { type RailAuthorization, categoriesFromTraits, createRailAuthorizer, railLimits, reconcileSettlement } from './rails';
import { createStripeIssuingWebhook, signStripePayload, stripeAuthorizationFromEvent, stripeSettlementFromTransaction, verifyStripeSignature } from './rails-stripe';
import { type PaymentMandate, buildPaymentMandate } from './mandate';
import { memoryChargeBudgetStore } from './testing';

const principal = generateKeyPair();
const agent = generateKeyPair();
const NOW = 1_700_000_000_000;
const mk = (over: Record<string, unknown> = {}): PaymentMandate =>
  buildPaymentMandate({
    principalSecret: principal.secretKey,
    principalPublic: encodeKey(principal.publicKey),
    agentPublic: encodeKey(agent.publicKey),
    merchants: ['m1', 'm2'],
    currency: 'USD',
    perTransactionCap: 100,
    autoApproveThreshold: 50,
    cumulativeCap: 500,
    now: NOW,
    ...over,
  });

describe('rail limits', () => {
  it('categories come from the mandate and the mcc traits, sorted, and only the intersection when both exist', () => {
    expect(categoriesFromTraits(['mcc.c5734', 'x', 'mcc.c1111', 'mcc.c5734', 'mcc.c12'])).toEqual(['1111', '5734']);
    const m = mk({ categories: ['5734', '1111', '9999'] });
    expect(railLimits(m, NOW, { actionTraits: ['mcc.c5734', 'mcc.c1111'] }).categories).toEqual(['1111', '5734']);
    expect(railLimits(m, NOW).categories).toEqual(['1111', '5734', '9999'].sort());
    expect(railLimits(mk({ categories: ['5734', '1111'] }), NOW).categories).toEqual(['1111', '5734']);
    expect(railLimits(mk(), NOW, { actionTraits: ['mcc.c5734', 'mcc.c1111'] }).categories).toEqual(['1111', '5734']);
    expect(() => railLimits(mk({ categories: ['1111'] }), NOW, { actionTraits: ['mcc.c5734'] })).toThrow('do not intersect');
    expect(() => railLimits(mk(), NOW)).toThrow('no category control');
    expect(railLimits(mk(), NOW, { allowAnyCategory: true }).categories).toEqual([]);
  });
  it('the expiry is carried only for a mandate with a period', () => {
    expect(railLimits(mk(), NOW, { allowAnyCategory: true })).toStrictEqual({ currency: 'USD', perAuthorizationMax: 50, totalMax: 500, categories: [], merchants: ['m1', 'm2'] });
    expect(railLimits(mk({ periodMs: 10_000 }), NOW, { allowAnyCategory: true })).toMatchObject({ expiresAt: Math.floor((NOW + 10_000) / 1000) * 1000 });
  });
});

describe('createRailAuthorizer', () => {
  afterEach(() => vi.useRealTimers());
  const good: RailAuthorization = { id: 'a1', instrumentId: 'i1', amount: 40, currency: 'usd', merchantId: 'm1' };
  const build = (over: Partial<Parameters<typeof createRailAuthorizer>[0]> = {}, m = mk()) =>
    createRailAuthorizer({ instruments: () => ({ mandate: m, grant: m.grant }), store: memoryChargeBudgetStore(), now: () => NOW, ...over });

  it('a non-positive latency budget is refused', () => {
    for (const latencyBudgetMs of [0, -1, Number.NaN, Infinity]) expect(() => build({ latencyBudgetMs })).toThrow(new RangeError('createRailAuthorizer: latencyBudgetMs must be positive'));
  });
  it('an in-policy authorization is approved without an explicit clock', async () => {
    expect(await build({ now: undefined })(good)).toMatchObject({ approved: true, reasons: [] });
  });
  it('each malformed field has its own decline reason', async () => {
    const run = build();
    const reasons = async (a: unknown) => (await run(a as RailAuthorization)).reasons;
    for (const bad of [null, { ...good, id: 5 }, { ...good, id: '' }, { ...good, instrumentId: 5 }]) expect(await reasons(bad)).toEqual(['malformed_authorization']);
    for (const amount of [0, -1, 1.5, Number.NaN, '5']) expect(await reasons({ ...good, amount })).toEqual(['amount_not_positive_minor_units']);
    for (const currency of ['', 5, undefined]) expect(await reasons({ ...good, currency })).toEqual(['currency_missing']);
    for (const merchantId of ['', 5, undefined]) expect(await reasons({ ...good, merchantId })).toEqual(['merchant_unknown']);
    expect(await build({ instruments: () => undefined })(good)).toEqual({ approved: false, reasons: ['instrument_unknown'] });
  });
  it('a throwing lookup is an authorizer_error decline', async () => {
    expect(await build({ instruments: () => { throw new Error('x'); } })(good)).toEqual({ approved: false, reasons: ['authorizer_error'] });
  });
  it('a step-up is declined and notifies; a deny is declined with its own reasons and does not', async () => {
    const calls: unknown[] = [];
    const run = build({ onStepUp: (a, d) => { calls.push([a, d.outcome]); } });
    const up = await run({ ...good, amount: 80 });
    expect(up.approved).toBe(false);
    expect(up.reasons[0]).toBe('step_up_required');
    expect(up.decision?.outcome).toBe('step_up');
    expect(calls).toEqual([[{ ...good, amount: 80 }, 'step_up']]);
    const no = await run({ ...good, merchantId: 'elsewhere' });
    expect(no.approved).toBe(false);
    expect(no.decision?.outcome).toBe('deny');
    expect(no.reasons).toEqual(no.decision!.reasons);
    expect(no.reasons).not.toContain('step_up_required');
    expect(no.reasons).not.toEqual(['denied']);
    expect(calls).toHaveLength(1);
    const throwing = build({ onStepUp: () => { throw new Error('notifier down'); } });
    expect((await throwing({ ...good, amount: 80 })).reasons[0]).toBe('step_up_required');
  });
  it('the category and currency reach the charge decision', async () => {
    const m = mk({ categories: ['5734'] });
    const run = build({}, m);
    expect((await run({ ...good, mcc: '5734' })).approved).toBe(true);
    expect((await run({ ...good, id: 'a2', mcc: '9999' })).approved).toBe(false);
    expect((await run({ ...good, id: 'a3', currency: 'eur', mcc: '5734' })).approved).toBe(false);
  });
  it('the timer is cleared whether the answer is fast or not, and a late decision declines', async () => {
    vi.useFakeTimers();
    await build()(good);
    expect(vi.getTimerCount()).toBe(0);
    await build({ instruments: () => undefined })(good);
    expect(vi.getTimerCount()).toBe(0);
    const slow = build({ latencyBudgetMs: 100, instruments: () => new Promise(() => {}) })(good);
    await vi.advanceTimersByTimeAsync(100);
    expect(await slow).toEqual({ approved: false, reasons: ['latency_budget_exceeded'] });
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe('reconcileSettlement', () => {
  const approved = { id: 'a1', amount: 40, currency: 'USD', merchantId: 'm1' };
  it('an exact fit commits; each deviation has its own reason', () => {
    const s = { authorizationId: 'a1', amount: 40, currency: 'usd', merchantId: 'm1', captures: 1 };
    expect(reconcileSettlement(approved, s)).toEqual({ ok: true });
    expect(reconcileSettlement(approved, { ...s, authorizationId: 'x' })).toEqual({ ok: false, reasons: ['authorization_id_mismatch'], action: 'freeze_grant' });
    expect(reconcileSettlement(approved, { ...s, amount: 41 })).toMatchObject({ reasons: ['settled_more_than_approved'] });
    expect(reconcileSettlement(approved, { ...s, currency: 'eur' })).toMatchObject({ reasons: ['currency_mismatch'] });
    expect(reconcileSettlement(approved, { ...s, merchantId: 'm2' })).toMatchObject({ reasons: ['merchant_mismatch'] });
    expect(reconcileSettlement(approved, { ...s, captures: 2 })).toMatchObject({ reasons: ['second_capture'] });
  });
});

describe('Stripe webhook signature', () => {
  const secret = 'whsec_test';
  const body = '{"a":1}';
  const T = 1_700_000_000;
  const hmac = (t: string, b = body, s = secret) => createHmac('sha256', s).update(`${t}.${b}`, 'utf8').digest('hex');
  const ok = (header: string | undefined, now = T, tol?: number) => verifyStripeSignature(body, header, secret, now, tol);
  it('a correct header verifies; surrounding spaces and extra members are tolerated', () => {
    expect(ok(`t=${T},v1=${hmac(String(T))}`)).toBe(true);
    expect(ok(`t=${T}, v1=${hmac(String(T))}`)).toBe(true);
    expect(ok(` t = ${T} , v1 = ${hmac(String(T))} `)).toBe(true);
    expect(ok(`t=${T},v0=00,v1=${'0'.repeat(64)},v1=${hmac(String(T))}`)).toBe(true);
    expect(ok(`junk,t=${T},v1=${hmac(String(T))}`)).toBe(true);
  });
  it('the inputs must be well-formed', () => {
    const h = `t=${T},v1=${hmac(String(T))}`;
    expect(verifyStripeSignature(body, undefined, secret, T)).toBe(false);
    expect(verifyStripeSignature(body, 5 as never, secret, T)).toBe(false);
    expect(verifyStripeSignature(body, h, 5 as never, T)).toBe(false);
    expect(verifyStripeSignature(body, h, '', T)).toBe(false);
    expect(verifyStripeSignature(body, h, secret, T, 0)).toBe(false);
    expect(verifyStripeSignature(body, h, secret, T, Number.NaN)).toBe(false);
    expect(verifyStripeSignature(body, h, 'other', T)).toBe(false);
    expect(verifyStripeSignature('{"a":2}', h, secret, T)).toBe(false);
  });
  it('a member named anything but v1 does not count, and a trailing malformed member cannot replace the timestamp', () => {
    expect(ok(`t=${T},x=${hmac(String(T))}`)).toBe(false);
    expect(ok(`t=${T},v1=${hmac(String(T))},tx`)).toBe(true);
    expect(ok(`t=${T},v1=${hmac(String(T))},t`)).toBe(true);
  });
  it('the timestamp must be 1..12 digits and present', () => {
    expect(ok(`v1=${hmac('undefined')}`)).toBe(false);
    expect(ok(`t=abc,v1=${hmac('abc')}`)).toBe(false);
    expect(ok(`t=x123,v1=${hmac('x123')}`, 123)).toBe(false);
    expect(ok(`t=123x,v1=${hmac('123x')}`, 123)).toBe(false);
    expect(ok(`t=,v1=${hmac('')}`, 0)).toBe(false);
    const big = '1234567890123';
    expect(ok(`t=${big},v1=${hmac(big)}`, Number(big))).toBe(false);
    expect(ok(`t=${T}`)).toBe(false);
  });
  it('tolerance is inclusive', () => {
    const h = `t=${T},v1=${hmac(String(T))}`;
    expect(ok(h, T + 300)).toBe(true);
    expect(ok(h, T + 301)).toBe(false);
    expect(ok(h, T - 300)).toBe(true);
    expect(ok(h, T - 301)).toBe(false);
    expect(ok(h, T + 10, 10)).toBe(true);
    expect(ok(h, T + 11, 10)).toBe(false);
  });
  it('a signature must be exactly 64 lower-case hex characters', () => {
    const good = hmac(String(T));
    expect(ok(`t=${T},v1=${good}zz`)).toBe(false);
    expect(ok(`t=${T},v1=${good.toUpperCase()}`)).toBe(false);
    expect(ok(`t=${T},v1=${good.slice(1)}`)).toBe(false);
  });
  it('signStripePayload produces the header Stripe would send', () => {
    expect(signStripePayload(body, secret, T)).toBe(`t=${T},v1=${hmac(String(T))}`);
    expect(signStripePayload('café', secret, T)).toBe(`t=${T},v1=${hmac(String(T), 'café')}`);
  });
});

describe('Stripe event normalisation', () => {
  const ev = (over: Record<string, unknown> = {}) => ({
    type: 'issuing_authorization.request',
    data: { object: { id: 'iauth_1', card: { id: 'ic_1' }, pending_request: { amount: 500, currency: 'usd' }, merchant_data: { network_id: 'm1', category_code: '5734' }, ...over } },
  });
  it('a complete request becomes an authorization with merchant and category', () => {
    expect(stripeAuthorizationFromEvent(ev())).toStrictEqual({ id: 'iauth_1', instrumentId: 'ic_1', amount: 500, currency: 'usd', merchantId: 'm1', mcc: '5734' });
  });
  it('merchant and category are optional and only taken when well-typed', () => {
    const bare = { id: 'iauth_1', instrumentId: 'ic_1', amount: 500, currency: 'usd' };
    expect(stripeAuthorizationFromEvent(ev({ merchant_data: undefined }))).toStrictEqual(bare);
    expect(stripeAuthorizationFromEvent(ev({ merchant_data: {} }))).toStrictEqual(bare);
    expect(stripeAuthorizationFromEvent(ev({ merchant_data: { network_id: '', category_code: 5 } }))).toStrictEqual(bare);
    expect(stripeAuthorizationFromEvent(ev({ merchant_data: { network_id: 'm1' } }))).toStrictEqual({ ...bare, merchantId: 'm1' });
    expect(stripeAuthorizationFromEvent(ev({ merchant_data: { category_code: '5734' } }))).toStrictEqual({ ...bare, mcc: '5734' });
  });
  it('anything else is undefined and never throws', () => {
    for (const e of [undefined, null, 'x', 5, [], {}, { type: 'other' }, { type: 'issuing_authorization.request' }, { type: 'issuing_authorization.request', data: {} }, { type: 'issuing_authorization.request', data: { object: 'x' } }]) {
      expect(stripeAuthorizationFromEvent(e)).toBeUndefined();
    }
    for (const over of [{ id: 5 }, { id: undefined }, { card: undefined }, { card: {} }, { card: { id: 5 } }, { pending_request: undefined }, { pending_request: { amount: '5', currency: 'usd' } }, { pending_request: { amount: 5 } }, { pending_request: { amount: 5, currency: 5 } }]) {
      expect(stripeAuthorizationFromEvent(ev(over))).toBeUndefined();
    }
  });
  it('a capture becomes a settlement with the amount negated', () => {
    const t = { type: 'capture', authorization: 'iauth_1', amount: -500, currency: 'usd', merchant_data: { network_id: 'm1' } };
    expect(stripeSettlementFromTransaction(t)).toStrictEqual({ authorizationId: 'iauth_1', amount: 500, currency: 'usd', merchantId: 'm1', captures: 1 });
    expect(stripeSettlementFromTransaction({ ...t, merchant_data: undefined })).toStrictEqual({ authorizationId: 'iauth_1', amount: 500, currency: 'usd', captures: 1 });
    expect(stripeSettlementFromTransaction({ ...t, merchant_data: {} })).toStrictEqual({ authorizationId: 'iauth_1', amount: 500, currency: 'usd', captures: 1 });
    for (const bad of [undefined, null, 'x', {}, { ...t, type: 'refund' }, { ...t, authorization: 5 }, { ...t, amount: '5' }, { ...t, currency: 5 }]) expect(stripeSettlementFromTransaction(bad)).toBeUndefined();
  });
});

describe('Stripe issuing webhook handler', () => {
  const secret = 'whsec_test';
  const version = '2025-03-31.basil';
  const headers = { 'Stripe-Version': version, 'Content-Type': 'application/json' };
  const event = JSON.stringify({ type: 'issuing_authorization.request', data: { object: { id: 'iauth_1', card: { id: 'ic_1' }, pending_request: { amount: 500, currency: 'usd' } } } });
  const sign = (b: string, t: number) => signStripePayload(b, secret, t);
  const T = Math.floor(Date.now() / 1000);

  it('a bad signature is a 400 and nothing is decided', async () => {
    let called = 0;
    const h = createStripeIssuingWebhook({ secret, authorize: async () => (called++, { approved: true, reasons: [] }), nowSec: () => T });
    expect(await h({ rawBody: event, signature: 'nope' })).toEqual({ status: 400, headers, body: '{"error":"bad_signature"}' });
    expect(called).toBe(0);
  });
  it('a signed body that is not JSON is a 400 bad_json', async () => {
    const h = createStripeIssuingWebhook({ secret, authorize: async () => ({ approved: true, reasons: [] }), nowSec: () => T });
    expect(await h({ rawBody: 'not json', signature: sign('not json', T) })).toEqual({ status: 400, headers, body: '{"error":"bad_json"}' });
  });
  it('other event types, and a JSON null, get an empty 200', async () => {
    const h = createStripeIssuingWebhook({ secret, authorize: async () => ({ approved: true, reasons: [] }), nowSec: () => T });
    for (const b of ['{"type":"other"}', 'null', '5', '[]']) expect(await h({ rawBody: b, signature: sign(b, T) })).toEqual({ status: 200, headers, body: '{}' });
  });
  it('a malformed request is declined without asking the authorizer; a well-formed one is decided', async () => {
    const seen: RailAuthorization[] = [];
    const h = createStripeIssuingWebhook({ secret, authorize: async (a) => (seen.push(a), { approved: seen.length === 1, reasons: [] }), nowSec: () => T });
    const bad = '{"type":"issuing_authorization.request"}';
    expect(await h({ rawBody: bad, signature: sign(bad, T) })).toEqual({ status: 200, headers, body: '{"approved":false}' });
    expect(seen).toHaveLength(0);
    expect(await h({ rawBody: event, signature: sign(event, T) })).toEqual({ status: 200, headers, body: '{"approved":true}' });
    expect(seen[0]).toEqual({ id: 'iauth_1', instrumentId: 'ic_1', amount: 500, currency: 'usd' });
    expect(await h({ rawBody: event, signature: sign(event, T) })).toEqual({ status: 200, headers, body: '{"approved":false}' });
  });
  it('the default clock rejects a stale signature and accepts a fresh one; a version override is echoed', async () => {
    const h = createStripeIssuingWebhook({ secret, authorize: async () => ({ approved: true, reasons: [] }) });
    expect((await h({ rawBody: event, signature: sign(event, Math.floor(Date.now() / 1000) - 1000) })).status).toBe(400);
    expect((await h({ rawBody: event, signature: sign(event, Math.floor(Date.now() / 1000)) })).status).toBe(200);
    const v = createStripeIssuingWebhook({ secret, stripeVersion: 'v-x', authorize: async () => ({ approved: true, reasons: [] }), nowSec: () => T });
    expect((await v({ rawBody: event, signature: sign(event, T) })).headers['Stripe-Version']).toBe('v-x');
  });
});
