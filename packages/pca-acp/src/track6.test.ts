import { describe, expect, it } from 'vitest';
import { compactJwsAliases } from '@atlasauth/pca';
import {
  type Capability,
  type Caveat,
  type PCActn,
  buildPCActn,
  encodeKey,
  generateKeyPair,
  mintRoot,
  pcactnDigest,
} from '@atlasauth/pca';
import {
  AcpAuthorityError,
  ACP_DELEGATED_TOKEN_TYPE,
  acpX402Verifier,
  checkPaymentAuthority,
  extractPaymentAuthority,
  humanPresentCaveat,
  merchantAllowCaveat,
  merchantCategoryCaveat,
  type MintOptions,
  mintDelegatedPaymentToken,
  spendCapCaveat,
  verifyDelegatedPaymentToken,
  x402Challenge,
  x402Settle,
  type X402PaymentPayload,
} from './index';

// ---------------------------------------------------------------------------------------------------
// Fixtures: real PCActns built via the core, carrying real payment caveats on their capability chain.
// The delegated-payment-token JWS is signed with a symmetric HS256 key (a Uint8Array TokenKey) so the
// test suite stays synchronous and deterministic; the authority model under test is alg-agnostic.
// ---------------------------------------------------------------------------------------------------

const NOW = 1_800_000_000_000;
const AUD = 'rs-acme';
const ALG = 'HS256';
const SECRET = new Uint8Array(32).fill(7);
const WRONG_SECRET = new Uint8Array(32).fill(9);

/**
 * Build a real, signed PCActn whose leaf capability carries `caveats`. The principal mints a root
 * capability held by the agent; the agent signs the action. The grant returned is the root — the
 * capability a verifier re-checks the chain against.
 */
function buildProof(caveats: Caveat[]): { pcActn: PCActn; grant: Capability } {
  const principal = generateKeyPair();
  const agent = generateKeyPair();
  const grant = mintRoot({
    principalSecret: principal.secretKey,
    principalPublic: encodeKey(principal.publicKey),
    holder: encodeKey(agent.publicKey),
    caveats,
  });
  const nodes = [{ id: 'pay', verb: 'pay', resource: 'checkout/sess-1', reversibility_class: 'R2' }];
  const pcActn = buildPCActn({
    grant,
    chain: [grant],
    plan: nodes,
    nodeId: 'pay',
    counter: 1,
    signerSecret: agent.secretKey,
    aud: AUD,
    now: NOW,
  });
  return { pcActn, grant };
}

/** A proof that authorizes up to 500 USD at merchants acme/globex — the common happy-path authority. */
function standardProof() {
  return buildProof([spendCapCaveat(500, 'USD'), merchantAllowCaveat(['acme', 'globex'])]);
}

/** Mint options with sensible defaults; callers override amount/merchant/etc. */
function mintOpts(extra: Partial<MintOptions> & { amount: number; merchant: string }): MintOptions {
  return {
    currency: 'USD',
    session: 'sess-1',
    signingKey: SECRET,
    alg: ALG,
    paymentMethod: { type: 'shared_payment_token', token: 'spt_abc' },
    now: NOW,
    expiresAt: NOW + 10 * 60_000,
    ...extra,
  };
}

// ---- Track 6: integer minor units, single use, server-owned settlement ----------------------------------

const mem = () => {
  const seen = new Set<string>();
  return { seen, claim: async (jti: string) => (seen.has(jti) ? false : (seen.add(jti), true)) };
};
const base = { expectedMerchant: 'acme', amount: 100, verifyKey: SECRET, alg: ALG, now: NOW, expectedCurrency: 'USD' };

describe('integer minor units', () => {
  it.each([[12.5], [NaN], [Infinity], [-5], [0], [2 ** 53]])('mint refuses amount %s', async (amount) => {
    const { pcActn } = standardProof();
    await expect(mintDelegatedPaymentToken(pcActn, mintOpts({ amount, merchant: 'acme' }))).rejects.toThrow(/positive integer in minor units/);
  });
  it('a fractional spend cap is a malformed caveat (fail closed)', () => {
    expect(() => extractPaymentAuthority([spendCapCaveat(99.5, 'USD')])).toThrow(/integer/);
  });
  it('settlement amount must be an integer', async () => {
    const { pcActn } = standardProof();
    const token = await mintDelegatedPaymentToken(pcActn, mintOpts({ amount: 100, merchant: 'acme' }));
    expect(await verifyDelegatedPaymentToken(token, { ...base, amount: 99.5 })).toMatchObject({ ok: false, reason: 'settlement amount must be a positive integer in minor units' });
  });
  it('x402Challenge refuses a fractional amount', () => {
    expect(() => x402Challenge('/r', { amount: 0.5 })).toThrow(/positive integer/);
    expect(x402Challenge('/r', { amount: 5 }).body.accepts[0]?.maxAmountRequired).toBe('5');
  });
});

describe('single-use redemption', () => {
  async function tok() {
    const { pcActn } = standardProof();
    return mintDelegatedPaymentToken(pcActn, mintOpts({ amount: 100, merchant: 'acme' }));
  }
  it('second redemption of the same token is refused with the exact reason', async () => {
    const token = await tok();
    const singleUse = mem();
    expect((await verifyDelegatedPaymentToken(token, { ...base, singleUse })).ok).toBe(true);
    const again = await verifyDelegatedPaymentToken(token, { ...base, singleUse });
    expect(again.ok).toBe(false);
    expect(again.reason).toBe('the delegated payment token was already redeemed');
  });
  it('a failed binding check does not burn the token', async () => {
    const token = await tok();
    const singleUse = mem();
    expect((await verifyDelegatedPaymentToken(token, { ...base, expectedMerchant: 'globex', singleUse })).ok).toBe(false);
    expect(singleUse.seen.size).toBe(0);
    expect((await verifyDelegatedPaymentToken(token, { ...base, singleUse })).ok).toBe(true);
  });
  it('a throwing store fails closed', async () => {
    const token = await tok();
    const res = await verifyDelegatedPaymentToken(token, { ...base, singleUse: { claim: async () => { throw new Error('down'); } } });
    expect(res).toMatchObject({ ok: false, reason: 'single-use store unavailable (fail closed)' });
  });
  it('strict mode requires a store and an expected currency', async () => {
    const token = await tok();
    expect(await verifyDelegatedPaymentToken(token, { ...base, strict: true })).toMatchObject({ ok: false, reason: 'strict settlement requires a singleUse store (fail closed)' });
    const { expectedCurrency: _c, ...noCur } = base;
    expect(await verifyDelegatedPaymentToken(token, { ...noCur, strict: true, singleUse: mem() })).toMatchObject({ ok: false, reason: 'strict settlement requires expectedCurrency (fail closed)' });
    expect((await verifyDelegatedPaymentToken(token, { ...base, strict: true, singleUse: mem() })).ok).toBe(true);
  });
  it('the x402 flow cannot redeem twice', async () => {
    const token = await tok();
    const verify = acpX402Verifier({ verifyKey: SECRET, alg: ALG, now: NOW, expectedMerchant: 'acme', amount: 100, expectedCurrency: 'USD', singleUse: mem(), strict: true });
    const p: X402PaymentPayload = { token };
    expect((await x402Settle(p, { verify })).settled).toBe(true);
    expect(await x402Settle(p, { verify })).toEqual({ settled: false, status: 402, reason: 'the delegated payment token was already redeemed', claims: expect.anything() });
  });
});

describe('server-owned settlement (strict x402 verifier)', () => {
  it('does not fall back to the client-supplied merchant or amount', async () => {
    const { pcActn } = standardProof();
    const token = await mintDelegatedPaymentToken(pcActn, mintOpts({ amount: 100, merchant: 'acme' }));
    const lie: X402PaymentPayload = { token, merchant: 'acme', amount: 1 };
    const noMerchant = acpX402Verifier({ verifyKey: SECRET, alg: ALG, now: NOW, amount: 100, expectedCurrency: 'USD', singleUse: mem(), strict: true });
    expect(await noMerchant(lie)).toEqual({ ok: false, reason: 'strict settlement requires the server to supply expectedMerchant and amount (fail closed)' });
    const noAmount = acpX402Verifier({ verifyKey: SECRET, alg: ALG, now: NOW, expectedMerchant: 'acme', expectedCurrency: 'USD', singleUse: mem(), strict: true });
    expect((await noAmount(lie)).ok).toBe(false);
  });
  it('a payload amount that is fractional is refused in the default mode too', async () => {
    const { pcActn } = standardProof();
    const token = await mintDelegatedPaymentToken(pcActn, mintOpts({ amount: 100, merchant: 'acme' }));
    const v = acpX402Verifier({ verifyKey: SECRET, alg: ALG, now: NOW });
    expect(await v({ token, merchant: 'acme', amount: 50.5 })).toEqual({ ok: false, reason: 'x402 payload has no amount to check the token against' });
  });
  it('wrong payee, over-amount and expired are denied with exact reasons', async () => {
    const { pcActn } = standardProof();
    const token = await mintDelegatedPaymentToken(pcActn, mintOpts({ amount: 100, merchant: 'acme' }));
    expect((await verifyDelegatedPaymentToken(token, { ...base, expectedMerchant: 'globex' })).reason).toBe('token merchant "acme" does not match expected "globex"');
    expect((await verifyDelegatedPaymentToken(token, { ...base, amount: 101 })).reason).toBe("settlement amount 101 exceeds the token's authorized amount 100");
    expect((await verifyDelegatedPaymentToken(token, { ...base, now: NOW + 11 * 60_000 })).reason).toBe('the delegated payment token has expired');
    expect((await verifyDelegatedPaymentToken(token, { ...base, expectedCurrency: 'EUR' })).reason).toBe('token currency "USD" does not match expected "EUR"');
  });
});
