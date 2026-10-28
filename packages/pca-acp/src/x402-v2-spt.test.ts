/**
 * Vectors are the published examples: the x402 v2 specification (PaymentRequired and PaymentPayload examples) and the
 * Stripe API reference (the Shared Payment Granted Token object).
 */
import { describe, expect, it } from 'vitest';
import { buildPCActn, encodeKey, generateKeyPair, mintRoot } from '@atlasauth/pca';
import {
  STRIPE_SPT_OBJECT,
  acpX402Verifier,
  decodePaymentRequiredHeader,
  encodePaymentRequiredHeader,
  mintDelegatedPaymentToken,
  normalizeX402Payload,
  parseStripeSpt,
  paymentRequiredV2Problems,
  spendCapCaveat,
  stripeSptProblems,
  stripeSptUsable,
  stripeSptWithinClaims,
  stripeUsageLimitsFor,
  x402AcceptedMatches,
  x402ChallengeV2,
  x402Negotiate,
  x402Settle,
  type SingleUseStore,
  type X402PaymentRequiredV2,
  type X402PaymentPayload,
} from './index';

// x402 specification v2, "PaymentRequired" example (verbatim)
const SPEC_PAYMENT_REQUIRED: X402PaymentRequiredV2 = {
  x402Version: 2,
  error: 'PAYMENT-SIGNATURE header is required',
  resource: { url: 'https://api.example.com/premium-data', description: 'Access to premium market data', mimeType: 'application/json', serviceName: 'Example Market Data', tags: ['market-data', 'finance'], iconUrl: 'https://api.example.com/icon.png' },
  accepts: [{ scheme: 'exact', network: 'eip155:84532', amount: '10000', asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e', payTo: '0x209693Bc6afc0C5328bA36FaF03C514EF312287C', maxTimeoutSeconds: 60, extra: { name: 'USDC', version: '2' } }],
  extensions: {},
};

// Stripe API reference, "The Shared Payment Granted Token object" example (verbatim)
const STRIPE_SPT_EXAMPLE = {
  id: 'spt_1RgaZcFPC5QUO6ZCDVZuVA8q',
  object: 'shared_payment.granted_token',
  agent_details: { network_business_profile: 'profile_test_61U92KWAstyE3VYhXA6U91t01FSQ3ByrZzKJOCR0y5ey' },
  created: 1751500820,
  deactivated_at: null,
  deactivated_reason: null,
  livemode: false,
  payment_method_details: {
    type: 'card',
    billing_details: { address: { city: null, country: null, line1: null, line2: null, postal_code: null, state: null }, email: null, name: 'John Doe', phone: null },
    card: { brand: 'visa', country: 'US', display_brand: 'visa', exp_month: 9, exp_year: 2029, fingerprint: 'dyRcYjZNxnHpC51l', funding: 'credit', last4: '4242', networks: { available: ['visa'], preferred: null }, wallet: null },
  },
  shared_metadata: {},
  usage_details: { amount_captured: { value: 0, currency: 'usd' } },
  usage_limits: { currency: 'usd', expires_at: 1751587220, max_amount: 1000 },
};

describe('x402 v2 (specification vectors)', () => {
  it('the specification PaymentRequired example is valid, and its header round-trips', () => {
    expect(paymentRequiredV2Problems(SPEC_PAYMENT_REQUIRED)).toEqual([]);
    const header = encodePaymentRequiredHeader(SPEC_PAYMENT_REQUIRED);
    expect(decodePaymentRequiredHeader(header)).toEqual(SPEC_PAYMENT_REQUIRED);
  });
  it('x402ChallengeV2 reproduces the specification example from its inputs', () => {
    const c = x402ChallengeV2(SPEC_PAYMENT_REQUIRED.resource, { amount: 10000, network: 'eip155:84532', asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e', payTo: '0x209693Bc6afc0C5328bA36FaF03C514EF312287C', extra: { name: 'USDC', version: '2' }, extensions: {} });
    expect(c.status).toBe(402);
    expect(c.body).toEqual(SPEC_PAYMENT_REQUIRED);
    expect(decodePaymentRequiredHeader(c.headers['PAYMENT-REQUIRED']!)).toEqual(SPEC_PAYMENT_REQUIRED);
  });
  it.each([
    ['a non-CAIP-2 network', { network: 'base-sepolia' }],
    ['a zero amount', { amount: 0 }],
    ['a fractional amount', { amount: 1.5 }],
    ['no payee', { payTo: '' }],
    ['no asset', { asset: '' }],
    ['a zero timeout', { maxTimeoutSeconds: 0 }],
  ])('refuses %s', (_n, over) => {
    expect(() => x402ChallengeV2('https://api.example.com/x', { amount: 5, network: 'eip155:1', asset: 'USD', payTo: 'merchant', ...over })).toThrow(TypeError);
  });
  it('validates ResourceInfo limits: relative url, long serviceName, six tags, non-ASCII tag, bad icon', () => {
    const base = { amount: 5, network: 'eip155:1', asset: 'USD', payTo: 'merchant' };
    expect(() => x402ChallengeV2('/relative', base)).toThrow(/resource.url/);
    expect(() => x402ChallengeV2({ url: 'https://a.example', serviceName: 'x'.repeat(33) }, base)).toThrow(/serviceName/);
    expect(() => x402ChallengeV2({ url: 'https://a.example', tags: ['1', '2', '3', '4', '5', '6'] }, base)).toThrow(/tags/);
    expect(() => x402ChallengeV2({ url: 'https://a.example', tags: ['café'] }, base)).toThrow(/tags/);
    expect(() => x402ChallengeV2({ url: 'https://a.example', iconUrl: 'ftp://a.example/i.png' }, base)).toThrow(/iconUrl/);
  });
  it('a header that is not base64, not JSON or not a valid PaymentRequired is refused', () => {
    expect(() => decodePaymentRequiredHeader('not base64!')).toThrow('not base64');
    expect(() => decodePaymentRequiredHeader(Buffer.from('{').toString('base64'))).toThrow('not JSON');
    expect(() => decodePaymentRequiredHeader(Buffer.from('{"x402Version":1}').toString('base64'))).toThrow('x402Version must be 2');
    expect(paymentRequiredV2Problems({ ...SPEC_PAYMENT_REQUIRED, accepts: [] })).toContain('accepts must be a non-empty array');
    expect(paymentRequiredV2Problems({ ...SPEC_PAYMENT_REQUIRED, extensions: { a: { info: {} } } })).toEqual(['extensions.a needs info and schema objects']);
  });
});

describe('version negotiation', () => {
  it('picks the highest common version; a client that says nothing gets v1; no overlap is undefined', () => {
    expect(x402Negotiate([1, 2])).toBe(2);
    expect(x402Negotiate([2])).toBe(2);
    expect(x402Negotiate([1])).toBe(1);
    expect(x402Negotiate(undefined)).toBe(1);
    expect(x402Negotiate([])).toBe(1);
    expect(x402Negotiate([3])).toBeUndefined();
    expect(x402Negotiate([2], [1])).toBeUndefined();
    expect(x402Negotiate([1, 2], [1])).toBe(1);
  });
});

describe('payload normalisation and v2 settlement', () => {
  const NOW = 1_800_000_000_000;
  const SECRET = new Uint8Array(32).fill(7);
  const accepted = SPEC_PAYMENT_REQUIRED.accepts[0]!;
  const mem = (): SingleUseStore => { const seen = new Set<string>(); return { claim: async (j) => (seen.has(j) ? false : (seen.add(j), true)) }; };
  async function token() {
    const principal = generateKeyPair();
    const agent = generateKeyPair();
    const grant = mintRoot({ principalSecret: principal.secretKey, principalPublic: encodeKey(principal.publicKey), holder: encodeKey(agent.publicKey), caveats: [spendCapCaveat(50_000, 'USD')] });
    const pcActn = buildPCActn({ grant, chain: [grant], plan: [{ id: 'p', verb: 'pay', resource: 'checkout/s', reversibility_class: 'R2' }], nodeId: 'p', counter: 1, signerSecret: agent.secretKey, aud: 'rs', now: NOW });
    return mintDelegatedPaymentToken(pcActn, { amount: 10_000, currency: 'USD', merchant: 'acme', session: 's1', expiresAt: NOW + 60_000, paymentMethod: { type: 'x402' }, signingKey: SECRET, alg: 'HS256', now: NOW });
  }

  it('reads v1 (top level) and v2 (payload.token + accepted) and refuses everything else', () => {
    expect(normalizeX402Payload({ token: 't', merchant: 'm', amount: 5 })).toEqual({ ok: true, version: 1, token: 't', merchant: 'm', amount: 5 });
    expect(normalizeX402Payload({ x402Version: 1, token: 't' })).toEqual({ ok: true, version: 1, token: 't' });
    expect(normalizeX402Payload({ x402Version: 2, accepted, payload: { token: 't' } })).toEqual({ ok: true, version: 2, token: 't', accepted, amount: 10000 });
    expect(normalizeX402Payload({ x402Version: 2, accepted, payload: {} })).toEqual({ ok: false, reason: 'x402 v2 payload is missing payload.token' });
    expect(normalizeX402Payload({ x402Version: 2, accepted: { ...accepted, network: 'x' }, payload: { token: 't' } })).toMatchObject({ ok: false });
    expect(normalizeX402Payload({ x402Version: 3, token: 't' })).toEqual({ ok: false, reason: 'unsupported x402Version 3' });
    expect(normalizeX402Payload({ x402Version: 1 })).toEqual({ ok: false, reason: 'x402 payment payload is missing a token' });
    for (const bad of [null, [], 'x', 7]) expect(normalizeX402Payload(bad)).toEqual({ ok: false, reason: 'x402 payment payload is not an object' });
  });
  it('a v2 payload settles under a strict verifier; the client merchant is never read', async () => {
    const t = await token();
    const payload: X402PaymentPayload = { x402Version: 2, accepted, payload: { token: t }, merchant: 'evil' } as never;
    const verify = acpX402Verifier({ verifyKey: SECRET, alg: 'HS256', now: NOW + 1, expectedMerchant: 'acme', amount: 10_000, expectedCurrency: 'USD', singleUse: mem(), offered: [accepted] });
    const r = await x402Settle(payload, { verify, settle: () => ({ ok: 1 }) });
    expect(r).toMatchObject({ settled: true, status: 200, receipt: { ok: 1 } });
    expect(r.claims?.merchant).toBe('acme');
  });
  it('a v2 payload that accepted something the server did not offer is refused', async () => {
    const t = await token();
    const cheaper = { ...accepted, amount: '1' };
    const verify = acpX402Verifier({ verifyKey: SECRET, alg: 'HS256', now: NOW + 1, expectedMerchant: 'acme', amount: 10_000, expectedCurrency: 'USD', singleUse: mem(), offered: [accepted] });
    expect(await x402Settle({ x402Version: 2, accepted: cheaper, payload: { token: t } } as never, { verify })).toEqual({ settled: false, status: 402, reason: 'x402 v2 payload.accepted is not one of the requirements this server offered' });
    expect(x402AcceptedMatches([accepted], { ...accepted, extra: { version: '2', name: 'USDC' } })).toBe(true); // key order is irrelevant
    expect(x402AcceptedMatches([accepted], cheaper)).toBe(false);
    expect(x402AcceptedMatches([], accepted)).toBe(false);
  });
  it('v1 still settles exactly as before', async () => {
    const t = await token();
    const verify = acpX402Verifier({ verifyKey: SECRET, alg: 'HS256', now: NOW + 1, expectedMerchant: 'acme', amount: 10_000, expectedCurrency: 'USD', singleUse: mem() });
    expect((await x402Settle({ token: t }, { verify })).settled).toBe(true);
  });
  it('an unsupported or malformed payload is a 402 with the reason, not a throw', async () => {
    const verify = acpX402Verifier({ verifyKey: SECRET, now: NOW, expectedMerchant: 'acme', amount: 1, expectedCurrency: 'USD', singleUse: mem() });
    expect(await x402Settle({ x402Version: 9, token: 't' } as never, { verify })).toEqual({ settled: false, status: 402, reason: 'unsupported x402Version 9' });
    expect(await x402Settle(null as never, { verify })).toEqual({ settled: false, status: 402, reason: 'x402 payment payload is not an object' });
  });
});

describe('Stripe Shared Payment Granted Token (API reference vectors)', () => {
  it('the published example object is well formed', () => {
    expect(stripeSptProblems(STRIPE_SPT_EXAMPLE)).toEqual([]);
    expect(parseStripeSpt(STRIPE_SPT_EXAMPLE).object).toBe(STRIPE_SPT_OBJECT);
  });
  it.each([
    ['a wrong object type', { object: 'payment_intent' }, 'object must be "shared_payment.granted_token"'],
    ['a non-spt id', { id: 'pi_123' }, 'id must be an spt_ identifier'],
    ['an uppercase currency', { usage_limits: { currency: 'USD', max_amount: 1000, expires_at: 1 } }, 'usage_limits.currency must be a lowercase three-letter code'],
    ['a fractional max_amount', { usage_limits: { currency: 'usd', max_amount: 10.5, expires_at: 1 } }, 'usage_limits.max_amount must be a non-negative integer in minor units'],
    ['no usage_limits', { usage_limits: null }, 'usage_limits is required'],
    ['an unknown deactivation reason', { deactivated_reason: 'lost' }, 'deactivated_reason must be null or one of consumed, expired, resolved, revoked'],
    ['a bad captured amount', { usage_details: { amount_captured: { value: -1, currency: 'usd' } } }, 'usage_details.amount_captured needs a non-negative integer value and a lowercase currency'],
  ])('refuses %s', (_n, over, problem) => {
    expect(stripeSptProblems({ ...STRIPE_SPT_EXAMPLE, ...over })).toEqual([problem]);
    expect(() => parseStripeSpt({ ...STRIPE_SPT_EXAMPLE, ...over })).toThrow(problem);
  });
  it('a non-object is refused', () => {
    expect(stripeSptProblems(null)).toEqual(['the token must be an object']);
  });

  const use = { now: 1751500900, amount: 1000, currency: 'USD', livemode: false };
  it('usability: exact boundary of the amount, expiry, currency, mode and deactivation', () => {
    expect(stripeSptUsable(STRIPE_SPT_EXAMPLE, use)).toEqual({ ok: true });
    expect(stripeSptUsable(STRIPE_SPT_EXAMPLE, { ...use, amount: 1001 })).toEqual({ ok: false, reason: 'the amount 1001 exceeds the remaining 1000' });
    expect(stripeSptUsable(STRIPE_SPT_EXAMPLE, { ...use, now: 1751587219 })).toEqual({ ok: true });
    expect(stripeSptUsable(STRIPE_SPT_EXAMPLE, { ...use, now: 1751587220 })).toEqual({ ok: false, reason: 'the token has expired' });
    expect(stripeSptUsable(STRIPE_SPT_EXAMPLE, { ...use, currency: 'EUR' })).toEqual({ ok: false, reason: 'the capture currency differs from the token currency' });
    expect(stripeSptUsable(STRIPE_SPT_EXAMPLE, { ...use, livemode: true })).toEqual({ ok: false, reason: 'the token is in the wrong mode' });
    expect(stripeSptUsable(STRIPE_SPT_EXAMPLE, { ...use, amount: 0 })).toMatchObject({ ok: false });
    expect(stripeSptUsable(STRIPE_SPT_EXAMPLE, { ...use, amount: 1.5 })).toMatchObject({ ok: false });
    expect(stripeSptUsable({ ...STRIPE_SPT_EXAMPLE, deactivated_reason: 'revoked', deactivated_at: 5 }, use)).toEqual({ ok: false, reason: 'the token is deactivated (revoked)' });
    expect(stripeSptUsable({ ...STRIPE_SPT_EXAMPLE, deactivated_at: 5 }, use)).toEqual({ ok: false, reason: 'the token is deactivated' });
    expect(stripeSptUsable({ ...STRIPE_SPT_EXAMPLE, usage_details: { amount_captured: { value: 400, currency: 'usd' } } }, { ...use, amount: 601 })).toEqual({ ok: false, reason: 'the amount 601 exceeds the remaining 600' });
    expect(stripeSptUsable({ ...STRIPE_SPT_EXAMPLE, usage_details: { amount_captured: { value: 400, currency: 'usd' } } }, { ...use, amount: 600 })).toEqual({ ok: true });
    expect(stripeSptUsable({ ...STRIPE_SPT_EXAMPLE, usage_details: { amount_captured: { value: 0, currency: 'eur' } } }, use)).toEqual({ ok: false, reason: 'the captured amount is in another currency' });
    expect(stripeSptUsable({ id: 1 }, use)).toMatchObject({ ok: false });
  });
  it('usage limits for a PCA authority: lowercase currency, minor units, expiry in whole seconds rounded down', () => {
    expect(stripeUsageLimitsFor({ maxAmount: 1000, currency: 'USD', expiresAtMs: 1751587220999 })).toEqual({ currency: 'usd', max_amount: 1000, expires_at: 1751587220 });
    expect(stripeUsageLimitsFor({ maxAmount: 1, currency: 'jpy' })).toEqual({ currency: 'jpy', max_amount: 1 });
    for (const bad of [{ maxAmount: 0, currency: 'USD' }, { maxAmount: 1.5, currency: 'USD' }, { maxAmount: 5, currency: 'US' }, { maxAmount: 5, currency: 'USD', expiresAtMs: -1 }]) expect(() => stripeUsageLimitsFor(bad)).toThrow(TypeError);
  });
  it('a token may be no wider than the delegated payment token it serves', () => {
    const claims = { amount: 1000, currency: 'USD', exp: 1751587220 * 1000 };
    expect(stripeSptWithinClaims(STRIPE_SPT_EXAMPLE, claims)).toEqual({ ok: true });
    expect(stripeSptWithinClaims(STRIPE_SPT_EXAMPLE, { ...claims, amount: 999 })).toEqual({ ok: false, reason: 'max_amount 1000 exceeds the delegated amount 999' });
    expect(stripeSptWithinClaims(STRIPE_SPT_EXAMPLE, { ...claims, exp: 1751587220 * 1000 - 1 })).toEqual({ ok: false, reason: 'the token outlives the delegated payment token' });
    expect(stripeSptWithinClaims(STRIPE_SPT_EXAMPLE, { ...claims, currency: 'EUR' })).toEqual({ ok: false, reason: 'the token currency differs from the delegated currency' });
    expect(stripeSptWithinClaims({ ...STRIPE_SPT_EXAMPLE, usage_limits: { currency: 'usd', max_amount: 5 } }, claims)).toEqual({ ok: false, reason: 'the token has no expiry' });
    expect(stripeSptWithinClaims({}, claims)).toMatchObject({ ok: false });
  });
});
