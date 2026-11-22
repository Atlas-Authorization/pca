import { describe, expect, it } from 'vitest';
import { buildPCActn, encodeKey, generateKeyPair, mintRoot } from '@atlasauth/pca';
import { STRIPE_SPT_OBJECT, checkPaymentAuthority, mintDelegatedPaymentToken, spendCapCaveat, stripeSptWithinClaims } from './index';

const NOW = 1_800_000_000_000;

function proof() {
  const principal = generateKeyPair();
  const agent = generateKeyPair();
  const grant = mintRoot({ principalSecret: principal.secretKey, principalPublic: encodeKey(principal.publicKey), holder: encodeKey(agent.publicKey), caveats: [spendCapCaveat(500, 'USD')] });
  return buildPCActn({
    grant,
    chain: [grant],
    plan: [{ id: 'pay', verb: 'pay', resource: 'checkout/sess-1', reversibility_class: 'R2' }],
    nodeId: 'pay',
    counter: 1,
    signerSecret: agent.secretKey,
    aud: 'rs-acme',
    now: NOW,
  });
}
const mintOpts = () => ({
  amount: 100,
  merchant: 'acme',
  currency: 'USD',
  session: 'sess-1',
  signingKey: new Uint8Array(32).fill(7),
  alg: 'HS256',
  paymentMethod: { type: 'shared_payment_token', token: 'spt_abc' },
  now: NOW,
  expiresAt: NOW + 60_000,
});

describe('a non-finite proof expiry or delegated bound never admits (acp)', () => {
  // pre-fix: `expiresAt > exp` was false against a NaN exp, so the token was minted
  it('mint refuses when the proof exp is NaN', async () => {
    await expect(mintDelegatedPaymentToken({ ...proof(), exp: Number.NaN }, mintOpts() as never)).rejects.toThrow(/outlive the proof/);
  });
  it('mint refuses when the proof exp is -Infinity', async () => {
    await expect(mintDelegatedPaymentToken({ ...proof(), exp: Number.NEGATIVE_INFINITY }, mintOpts() as never)).rejects.toThrow(/outlive the proof/);
  });
});

describe('stripeSptWithinClaims with a non-finite bound refuses', () => {
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
  const claims = { amount: 1000, currency: 'USD', exp: 2_000_000_000_000 };
  // pre-fix: `max_amount > NaN` was false
  it('NaN delegated amount', () => {
    expect(stripeSptWithinClaims(TOK, { ...claims, amount: Number.NaN }).ok).toBe(false);
  });
  it('-Infinity delegated amount', () => {
    expect(stripeSptWithinClaims(TOK, { ...claims, amount: Number.NEGATIVE_INFINITY }).ok).toBe(false);
  });
  // pre-fix: `expires_at * 1000 > NaN` was false
  it.each([Number.NaN, Number.NEGATIVE_INFINITY])('delegated exp of %s', (exp) => {
    expect(stripeSptWithinClaims(TOK, { ...claims, exp }).ok).toBe(false);
  });
});

describe('an infinite proof expiry or delegated bound never admits (acp)', () => {
  // pre-fix: `expiresAt > Infinity` was false, so a token could outlive any proof
  it('mint refuses when the proof exp is +Infinity', async () => {
    await expect(mintDelegatedPaymentToken({ ...proof(), exp: Number.POSITIVE_INFINITY }, mintOpts() as never)).rejects.toThrow(/outlive the proof/);
  });
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
  // pre-fix: `max_amount <= Infinity` and `expires_at * 1000 <= Infinity` were true
  it('+Infinity delegated amount or exp', () => {
    expect(stripeSptWithinClaims(TOK, { amount: Number.POSITIVE_INFINITY, currency: 'USD', exp: 2_000_000_000_000 }).ok).toBe(false);
    expect(stripeSptWithinClaims(TOK, { amount: 1000, currency: 'USD', exp: Number.POSITIVE_INFINITY }).ok).toBe(false);
  });
  // pre-fix: `amount > NaN` was false, so a NaN cap admitted the charge
  it('a NaN spend cap refuses', () => {
    const a = { maxAmount: Number.NaN, merchants: null, categories: null, humanPresentRequired: false };
    expect(checkPaymentAuthority(a, { amount: 1, currency: 'USD', merchant: 'm' }).ok).toBe(false);
  });
  // pre-fix: only NaN was refused; an infinite, negative, negative-zero or fractional cap was honoured
  it.each([Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, Number.NaN, -1, -0, 1.5])('a present spend cap of %s refuses with the exact reason', (maxAmount) => {
    const a = { maxAmount, merchants: null, categories: null, humanPresentRequired: false };
    expect(checkPaymentAuthority(a, { amount: 1, currency: 'USD', merchant: 'm' })).toEqual({ ok: false, reason: 'authorized spend cap is not a non-negative integer (fail closed)' });
  });
  it('an absent spend cap is unbounded', () => {
    const a = { merchants: null, categories: null, humanPresentRequired: false };
    expect(checkPaymentAuthority(a, { amount: 1, currency: 'USD', merchant: 'm' }).ok).toBe(true);
  });
});
