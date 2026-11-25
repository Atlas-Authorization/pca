import { describe, expect, it } from 'vitest';
import { buildPCActn, encodeKey, generateKeyPair, mintRoot, type PCActn } from '@atlasauth/pca';
import {
  AcpAuthorityError,
  acpX402Verifier,
  mintDelegatedPaymentToken,
  spendCapCaveat,
  toAcpAllowance,
  verifyDelegatedPaymentToken,
  x402Challenge,
  type DelegatedPaymentClaims,
  type SingleUseStore,
} from './index';

const NOW = 1_800_000_000_000;
const ALG = 'HS256';
const SECRET = new Uint8Array(32).fill(7);

function proof(): { pcActn: PCActn; grant: ReturnType<typeof mintRoot> } {
  const principal = generateKeyPair();
  const agent = generateKeyPair();
  const grant = mintRoot({ principalSecret: principal.secretKey, principalPublic: encodeKey(principal.publicKey), holder: encodeKey(agent.publicKey), caveats: [spendCapCaveat(500, 'USD')] });
  const pcActn = buildPCActn({ grant, chain: [grant], plan: [{ id: 'pay', verb: 'pay', resource: 'checkout/s', reversibility_class: 'R2' }], nodeId: 'pay', counter: 1, signerSecret: agent.secretKey, aud: 'rs', now: NOW });
  return { pcActn, grant };
}
const mem = (): SingleUseStore => {
  const seen = new Set<string>();
  return { claim: async (j) => (seen.has(j) ? false : (seen.add(j), true)) };
};
async function token() {
  const { pcActn, grant } = proof();
  const t = await mintDelegatedPaymentToken(pcActn, { amount: 100, currency: 'USD', merchant: 'acme', session: 'sess-1', expiresAt: NOW + 60_000, paymentMethod: { type: 'shared_payment_token', token: 'spt' }, signingKey: SECRET, alg: ALG, now: NOW });
  return { t, pcActn, grant };
}
const base = { expectedMerchant: 'acme', amount: 100, verifyKey: SECRET, alg: ALG, now: NOW + 1 } as const;

describe('settlement is strict by default', () => {
  it('no single-use store: refused with the exact reason', async () => {
    const { t } = await token();
    expect(await verifyDelegatedPaymentToken(t, { ...base, expectedCurrency: 'USD' })).toEqual({ ok: false, reason: 'strict settlement requires a singleUse store (fail closed)' });
  });
  it('no expected currency: refused with the exact reason', async () => {
    const { t } = await token();
    expect(await verifyDelegatedPaymentToken(t, { ...base, singleUse: mem() })).toEqual({ ok: false, reason: 'strict settlement requires expectedCurrency (fail closed)' });
  });
  it('with both, the token redeems exactly once', async () => {
    const { t } = await token();
    const o = { ...base, expectedCurrency: 'USD', singleUse: mem() };
    expect((await verifyDelegatedPaymentToken(t, o)).ok).toBe(true);
    expect(await verifyDelegatedPaymentToken(t, o)).toMatchObject({ ok: false, reason: 'the delegated payment token was already redeemed' });
  });
  it('the x402 verifier never reads the client merchant and amount unless strict:false', async () => {
    const { t } = await token();
    const v = acpX402Verifier({ verifyKey: SECRET, alg: ALG, now: NOW + 1, expectedCurrency: 'USD', singleUse: mem() });
    expect(await v({ token: t, merchant: 'acme', amount: 100 })).toEqual({ ok: false, reason: 'strict settlement requires the server to supply expectedMerchant and amount (fail closed)' });
  });
  it('strict:false is the explicit opt-out and then the old behaviour holds', async () => {
    const { t } = await token();
    expect((await verifyDelegatedPaymentToken(t, { ...base, strict: false })).ok).toBe(true);
  });
  it('a grant without the pcActn to re-verify is refused, not silently skipped', async () => {
    const { t, grant } = await token();
    expect(await verifyDelegatedPaymentToken(t, { ...base, strict: false, grant })).toMatchObject({ ok: false, reason: 'a grant was supplied without the pcActn to re-verify (fail closed)' });
  });
});

describe('x402Challenge is a complete x402 v1 requirement', () => {
  it('carries maxTimeoutSeconds and a body error, and refuses a missing payee or asset', () => {
    const c = x402Challenge('/r', { amount: 5, payTo: '0xabc', currency: 'USDC' });
    expect(c.body.error).toBe('X-PAYMENT header is required');
    expect(c.body.accepts[0]).toMatchObject({ maxTimeoutSeconds: 60, payTo: '0xabc', asset: 'USDC', scheme: 'exact' });
    expect(x402Challenge('/r', { amount: 5, payTo: '0xabc', currency: 'USDC', maxTimeoutSeconds: 5, error: 'again' }).body).toMatchObject({ error: 'again', accepts: [{ maxTimeoutSeconds: 5 }] });
    expect(() => x402Challenge('/r', { amount: 5, currency: 'USDC' })).toThrow(/payTo/);
    expect(() => x402Challenge('/r', { amount: 5, payTo: '' , currency: 'USDC' })).toThrow(/payTo/);
    expect(() => x402Challenge('/r', { amount: 5, payTo: '0xabc' })).toThrow(/currency/);
    for (const maxTimeoutSeconds of [0, -1, 1.5, NaN]) expect(() => x402Challenge('/r', { amount: 5, payTo: '0xabc', currency: 'USDC', maxTimeoutSeconds })).toThrow(/maxTimeoutSeconds/);
  });
});

describe('toAcpAllowance', () => {
  const claims = (over: Partial<DelegatedPaymentClaims> = {}): DelegatedPaymentClaims =>
    ({ typ: 'acp-delegated-payment', ver: 1, jti: 'j', session: 'sess-1', merchant: 'acme', amount: 2000, currency: 'USD', iat: NOW, exp: Date.UTC(2027, 0, 2, 3, 4, 5), paymentMethod: { type: 'x' }, humanPresent: false, pca: {} as never, ...over }) as DelegatedPaymentClaims;
  it('maps to the ACP delegate_payment allowance exactly', () => {
    expect(toAcpAllowance(claims())).toEqual({ reason: 'one_time', max_amount: 2000, currency: 'usd', checkout_session_id: 'sess-1', merchant_id: 'acme', expires_at: '2027-01-02T03:04:05.000Z' });
  });
  it.each([
    ['fractional amount', { amount: 1.5 }],
    ['zero amount', { amount: 0 }],
    ['two-letter currency', { currency: 'US' }],
    ['non-letter currency', { currency: 'U5D' }],
    ['empty merchant', { merchant: '' }],
    ['merchant over 256', { merchant: 'm'.repeat(257) }],
    ['empty session', { session: '' }],
    ['NaN expiry', { exp: NaN }],
    ['absurd expiry', { exp: 8.64e15 + 1 }],
  ])('refuses %s', (_n, over) => {
    expect(() => toAcpAllowance(claims(over as Partial<DelegatedPaymentClaims>))).toThrow(AcpAuthorityError);
  });
  it('accepts a merchant of exactly 256 characters', () => {
    expect(toAcpAllowance(claims({ merchant: 'm'.repeat(256) })).merchant_id).toHaveLength(256);
  });
});
