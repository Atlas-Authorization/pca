import { describe, expect, it } from 'vitest';
import { STRIPE_SPT_OBJECT, parseStripeSpt, stripeSptProblems, stripeSptUsable, stripeSptWithinClaims, stripeUsageLimitsFor } from './index';

const TOK = {
  id: 'spt_abc_1',
  object: STRIPE_SPT_OBJECT,
  created: 1_700_000_000,
  livemode: true,
  deactivated_at: null,
  deactivated_reason: null,
  usage_limits: { currency: 'usd', max_amount: 1000, expires_at: 2_000_000_000 },
  payment_method_details: { type: 'card' },
};
const t = (over: Record<string, unknown>) => ({ ...TOK, ...over });
const lim = (over: Record<string, unknown>) => t({ usage_limits: { ...TOK.usage_limits, ...over } });
const NOW = 1_800_000_000;
const use = { now: NOW, amount: 100, currency: 'USD' };

describe('stripeSptProblems exact messages', () => {
  it('a token without the optional members is well formed', () => {
    expect(stripeSptProblems(TOK)).toEqual([]);
    expect(stripeSptProblems(t({ usage_details: null, agent_details: null, shared_metadata: null, payment_method_details: null }))).toEqual([]);
    expect(stripeSptProblems(t({ usage_details: undefined, agent_details: undefined, shared_metadata: undefined }))).toEqual([]);
    expect(stripeSptProblems(t({ usage_details: { amount_captured: { value: 0, currency: 'usd' } }, agent_details: {}, shared_metadata: {} }))).toEqual([]);
    expect(stripeSptProblems(null)).toEqual(['the token must be an object']);
  });
  it('id', () => {
    const m = 'id must be an spt_ identifier';
    for (const bad of [undefined, 5, ['spt_abc'], 'xspt_a', 'spt_a!', 'spt_', 'spt_a b', '']) expect(stripeSptProblems(t({ id: bad })), String(bad)).toEqual([m]);
    expect(stripeSptProblems(t({ id: 'spt_A9_z' }))).toEqual([]);
  });
  it('created, livemode, deactivated_at, deactivated_reason', () => {
    expect(stripeSptProblems(t({ created: 1.5 }))).toEqual(['created must be an integer timestamp']);
    expect(stripeSptProblems(t({ created: '1' }))).toEqual(['created must be an integer timestamp']);
    expect(stripeSptProblems(t({ created: -0 }))).toEqual(['created must be an integer timestamp']);
    for (const bad of [1, 'true', undefined, null]) expect(stripeSptProblems(t({ livemode: bad })), String(bad)).toEqual(['livemode must be a boolean']);
    expect(stripeSptProblems(t({ livemode: false }))).toEqual([]);
    for (const bad of ['x', 1.5, undefined, {}]) expect(stripeSptProblems(t({ deactivated_at: bad })), String(bad)).toEqual(['deactivated_at must be null or an integer timestamp']);
    expect(stripeSptProblems(t({ deactivated_at: 5 }))).toEqual([]);
    const r = 'deactivated_reason must be null or one of consumed, expired, resolved, revoked';
    for (const bad of ['other', 5, ['consumed'], undefined]) expect(stripeSptProblems(t({ deactivated_reason: bad })), String(bad)).toEqual([r]);
    for (const ok of ['consumed', 'expired', 'resolved', 'revoked']) expect(stripeSptProblems(t({ deactivated_reason: ok }))).toEqual([]);
  });
  it('usage_limits', () => {
    expect(stripeSptProblems(t({ usage_limits: null }))).toEqual(['usage_limits is required']);
    expect(stripeSptProblems(t({ usage_limits: undefined }))).toEqual(['usage_limits is required']);
    const cur = 'usage_limits.currency must be a lowercase three-letter code';
    for (const bad of ['USD', 'us', 'usdx', 'xusd', 'usd!', '!usd', 5, ['usd'], undefined]) expect(stripeSptProblems(lim({ currency: bad })), String(bad)).toEqual([cur]);
    const max = 'usage_limits.max_amount must be a non-negative integer in minor units';
    for (const bad of [-1, 1.5, '5', undefined, -0]) expect(stripeSptProblems(lim({ max_amount: bad })), String(bad)).toEqual([max]);
    expect(stripeSptProblems(lim({ max_amount: 0 }))).toEqual([]);
    const exp = 'usage_limits.expires_at must be an integer timestamp';
    for (const bad of ['x', 1.5, {}]) expect(stripeSptProblems(lim({ expires_at: bad })), String(bad)).toEqual([exp]);
    expect(stripeSptProblems(lim({ expires_at: null }))).toEqual([]);
    expect(stripeSptProblems(lim({ expires_at: undefined }))).toEqual([]);
    expect(stripeSptProblems(lim({ expires_at: 0 }))).toEqual([]);
  });
  it('usage_details', () => {
    const m = 'usage_details.amount_captured needs a non-negative integer value and a lowercase currency';
    const ud = (c: unknown) => stripeSptProblems(t({ usage_details: c }));
    for (const bad of ['x', 5, {}, { amount_captured: null }, { amount_captured: 'x' }, { amount_captured: { value: 'x', currency: 'usd' } }, { amount_captured: { value: -1, currency: 'usd' } },
      { amount_captured: { value: 1, currency: 'USD' } }, { amount_captured: { value: 1.5, currency: 'usd' } }, { amount_captured: { currency: 'usd' } }, { amount_captured: { value: 1 } }]) {
      expect(ud(bad), JSON.stringify(bad)).toEqual([m]);
    }
    expect(ud({ amount_captured: { value: 0, currency: 'usd' } })).toEqual([]);
  });
  it('object members and the payment method type', () => {
    for (const k of ['payment_method_details', 'agent_details', 'shared_metadata']) {
      for (const bad of [5, 'x', []]) expect(stripeSptProblems(t({ [k]: bad })), `${k} ${String(bad)}`).toContain(`${k} must be null or an object`);
    }
    expect(stripeSptProblems(t({ payment_method_details: { type: 5 } }))).toEqual(['payment_method_details.type must be a string']);
    expect(stripeSptProblems(t({ payment_method_details: {} }))).toEqual(['payment_method_details.type must be a string']);
    expect(stripeSptProblems(t({ object: 'x' }))).toEqual([`object must be "shared_payment.granted_token"`]);
  });
  it('parseStripeSpt returns the token or throws with every problem joined', () => {
    expect(parseStripeSpt(TOK)).toBe(TOK);
    expect(() => parseStripeSpt(t({ livemode: 1, created: 'x' }))).toThrow(new TypeError('stripe spt: created must be an integer timestamp; livemode must be a boolean'));
  });
});

describe('stripeSptUsable', () => {
  const u = (tok: unknown, over: Record<string, unknown> = {}) => stripeSptUsable(tok, { ...use, ...over });
  it('a live token with room is usable; livemode defaults to true', () => {
    expect(u(TOK)).toEqual({ ok: true });
    expect(u(TOK, { livemode: true })).toEqual({ ok: true });
    expect(u(t({ livemode: false }), { livemode: false })).toEqual({ ok: true });
    expect(u(t({ livemode: false }))).toEqual({ ok: false, reason: 'the token is in the wrong mode' });
    expect(u(TOK, { livemode: false })).toEqual({ ok: false, reason: 'the token is in the wrong mode' });
  });
  it('a malformed token is refused with its first problem', () => {
    expect(u({})).toEqual({ ok: false, reason: 'malformed token: object must be "shared_payment.granted_token"' });
    expect(u(null)).toEqual({ ok: false, reason: 'malformed token: the token must be an object' });
    expect(u(t({ livemode: 1, id: 'x' }))).toEqual({ ok: false, reason: 'malformed token: id must be an spt_ identifier' });
  });
  it('now and amount must be positive integers', () => {
    const m = { ok: false, reason: 'now and amount must be integers and the amount positive' };
    expect(u(TOK, { now: 1.5 })).toEqual(m);
    expect(u(TOK, { amount: 1.5 })).toEqual(m);
    expect(u(TOK, { amount: 0 })).toEqual(m);
    expect(u(TOK, { amount: -5 })).toEqual(m);
    expect(u(TOK, { amount: 1 })).toEqual({ ok: true });
  });
  it('deactivation: reason, and the deactivated_at instant is inclusive', () => {
    expect(u(t({ deactivated_reason: 'revoked' }))).toEqual({ ok: false, reason: 'the token is deactivated (revoked)' });
    expect(u(t({ deactivated_at: NOW + 1 }))).toEqual({ ok: true });
    expect(u(t({ deactivated_at: NOW }))).toEqual({ ok: false, reason: 'the token is deactivated' });
    expect(u(t({ deactivated_at: NOW - 1 }))).toEqual({ ok: false, reason: 'the token is deactivated' });
  });
  it('expiry applies only when a number', () => {
    expect(u(lim({ expires_at: null }))).toEqual({ ok: true });
    expect(u(lim({ expires_at: undefined }))).toEqual({ ok: true });
    expect(u(lim({ expires_at: NOW }))).toEqual({ ok: false, reason: 'the token has expired' });
    expect(u(lim({ expires_at: NOW + 1 }))).toEqual({ ok: true });
  });
  it('captured usage: absent, present, other currency, remaining', () => {
    expect(u(t({ usage_details: null }))).toEqual({ ok: true });
    expect(u(t({ usage_details: undefined }))).toEqual({ ok: true });
    expect(u(t({ usage_details: { amount_captured: { value: 900, currency: 'usd' } } }))).toEqual({ ok: true });
    expect(u(t({ usage_details: { amount_captured: { value: 901, currency: 'usd' } } }))).toEqual({ ok: false, reason: 'the amount 100 exceeds the remaining 99' });
    expect(u(t({ usage_details: { amount_captured: { value: 0, currency: 'eur' } } }))).toEqual({ ok: false, reason: 'the captured amount is in another currency' });
    expect(u(TOK, { currency: 'eur' })).toEqual({ ok: false, reason: 'the capture currency differs from the token currency' });
    expect(u(TOK, { amount: 1000 })).toEqual({ ok: true });
    expect(u(TOK, { amount: 1001 })).toEqual({ ok: false, reason: 'the amount 1001 exceeds the remaining 1000' });
  });
});

describe('stripeUsageLimitsFor', () => {
  it('lowercases the currency and floors the expiry to whole seconds', () => {
    expect(stripeUsageLimitsFor({ maxAmount: 5, currency: 'USD' })).toStrictEqual({ currency: 'usd', max_amount: 5 });
    expect(stripeUsageLimitsFor({ maxAmount: 5, currency: 'eUr', expiresAtMs: 1999 })).toStrictEqual({ currency: 'eur', max_amount: 5, expires_at: 1 });
    expect(stripeUsageLimitsFor({ maxAmount: 5, currency: 'usd', expiresAtMs: 1 })).toStrictEqual({ currency: 'usd', max_amount: 5, expires_at: 0 });
  });
  it('refusals carry their exact message', () => {
    const amt = new TypeError('stripe spt: maxAmount must be a positive integer in minor units');
    for (const maxAmount of [0, -1, 1.5, NaN]) expect(() => stripeUsageLimitsFor({ maxAmount, currency: 'usd' }), String(maxAmount)).toThrow(amt);
    const cur = new TypeError('stripe spt: currency must be a three-letter code');
    for (const currency of ['us', 'usdx', 'xusd', 'us1', '', 5, ['usd'], undefined]) expect(() => stripeUsageLimitsFor({ maxAmount: 1, currency: currency as never }), String(currency)).toThrow(cur);
    const exp = new TypeError('stripe spt: expiresAtMs must be a positive epoch-ms time');
    for (const expiresAtMs of [0, -1, NaN, Infinity]) expect(() => stripeUsageLimitsFor({ maxAmount: 1, currency: 'usd', expiresAtMs }), String(expiresAtMs)).toThrow(exp);
  });
});

describe('stripeSptWithinClaims', () => {
  const claims = { amount: 1000, currency: 'USD', exp: 2_000_000_000_000 };
  it('malformed token reason', () => {
    expect(stripeSptWithinClaims({}, claims)).toEqual({ ok: false, reason: 'malformed token: object must be "shared_payment.granted_token"' });
  });
  it('relations', () => {
    expect(stripeSptWithinClaims(TOK, claims)).toEqual({ ok: true });
    expect(stripeSptWithinClaims(TOK, { ...claims, currency: 'eur' })).toEqual({ ok: false, reason: 'the token currency differs from the delegated currency' });
    expect(stripeSptWithinClaims(TOK, { ...claims, amount: 999 })).toEqual({ ok: false, reason: 'max_amount 1000 exceeds the delegated amount 999' });
    expect(stripeSptWithinClaims(lim({ expires_at: null }), claims)).toEqual({ ok: false, reason: 'the token has no expiry' });
    expect(stripeSptWithinClaims(TOK, { ...claims, exp: 1_999_999_999_999 })).toEqual({ ok: false, reason: 'the token outlives the delegated payment token' });
  });
});
