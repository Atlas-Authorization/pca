import { describe, expect, it } from 'vitest';
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

// ---------------------------------------------------------------------------------------------------
// extractPaymentAuthority / checkPaymentAuthority
// ---------------------------------------------------------------------------------------------------

describe('extractPaymentAuthority', () => {
  it('collapses caveats conjunctively: tightest cap, intersected allowlists, sticky human-present', () => {
    const a = extractPaymentAuthority([
      spendCapCaveat(500, 'USD'),
      spendCapCaveat(200),
      merchantAllowCaveat(['acme', 'globex']),
      merchantAllowCaveat(['acme', 'initech']),
      humanPresentCaveat(true),
    ]);
    expect(a.maxAmount).toBe(200);
    expect(a.currency).toBe('USD');
    expect(a.merchants).toEqual(['acme']);
    expect(a.humanPresentRequired).toBe(true);
    expect(a.categories).toBeNull();
  });

  it('fails closed on a malformed max_amount caveat', () => {
    expect(() => extractPaymentAuthority([{ type: 'max_amount', max: -1 }])).toThrow(AcpAuthorityError);
    expect(() => extractPaymentAuthority([{ type: 'max_amount', max: 'lots' }])).toThrow(AcpAuthorityError);
  });

  it('fails closed on conflicting spend-cap currencies', () => {
    expect(() => extractPaymentAuthority([spendCapCaveat(100, 'USD'), spendCapCaveat(100, 'EUR')])).toThrow(AcpAuthorityError);
  });

  it('ignores non-payment caveats (ttl, scope, ...)', () => {
    const a = extractPaymentAuthority([{ type: 'ttl', secs: 60 }, spendCapCaveat(10)]);
    expect(a.maxAmount).toBe(10);
    expect(a.merchants).toBeNull();
  });
});

describe('checkPaymentAuthority', () => {
  const authority = extractPaymentAuthority([
    spendCapCaveat(500, 'USD'),
    merchantAllowCaveat(['acme']),
    merchantCategoryCaveat(['saas']),
  ]);

  it('admits an in-authority request', () => {
    expect(checkPaymentAuthority(authority, { amount: 100, currency: 'USD', merchant: 'acme', category: 'saas' }).ok).toBe(true);
  });
  it('rejects over-cap, wrong currency, disallowed merchant, and missing/forbidden category', () => {
    expect(checkPaymentAuthority(authority, { amount: 600, currency: 'USD', merchant: 'acme', category: 'saas' }).ok).toBe(false);
    expect(checkPaymentAuthority(authority, { amount: 100, currency: 'EUR', merchant: 'acme', category: 'saas' }).ok).toBe(false);
    expect(checkPaymentAuthority(authority, { amount: 100, currency: 'USD', merchant: 'evil', category: 'saas' }).ok).toBe(false);
    expect(checkPaymentAuthority(authority, { amount: 100, currency: 'USD', merchant: 'acme' }).ok).toBe(false);
    expect(checkPaymentAuthority(authority, { amount: 100, currency: 'USD', merchant: 'acme', category: 'gambling' }).ok).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------------
// mintDelegatedPaymentToken — caveat gating at issuance
// ---------------------------------------------------------------------------------------------------

describe('mintDelegatedPaymentToken', () => {
  it('mints a one-time token from a proof whose caveats permit the amount + merchant', async () => {
    const { pcActn } = standardProof();
    const token = await mintDelegatedPaymentToken(pcActn, mintOpts({ amount: 100, merchant: 'acme' }));
    expect(typeof token).toBe('string');
    expect(token.split('.')).toHaveLength(3); // compact JWS
  });

  it('refuses at mint when the amount exceeds the spend cap', async () => {
    const { pcActn } = standardProof();
    await expect(mintDelegatedPaymentToken(pcActn, mintOpts({ amount: 600, merchant: 'acme' }))).rejects.toBeInstanceOf(AcpAuthorityError);
  });

  it('refuses at mint for a merchant outside the allowlist', async () => {
    const { pcActn } = standardProof();
    await expect(mintDelegatedPaymentToken(pcActn, mintOpts({ amount: 100, merchant: 'evil' }))).rejects.toBeInstanceOf(AcpAuthorityError);
  });

  it('refuses at mint for a currency the cap forbids', async () => {
    const { pcActn } = standardProof();
    await expect(mintDelegatedPaymentToken(pcActn, mintOpts({ currency: 'EUR', amount: 100, merchant: 'acme' }))).rejects.toBeInstanceOf(
      AcpAuthorityError,
    );
  });

  it('enforces a human_present caveat at mint', async () => {
    const { pcActn } = buildProof([spendCapCaveat(500, 'USD'), merchantAllowCaveat(['acme']), humanPresentCaveat(true)]);
    await expect(mintDelegatedPaymentToken(pcActn, mintOpts({ amount: 100, merchant: 'acme' }))).rejects.toBeInstanceOf(AcpAuthorityError);
    const token = await mintDelegatedPaymentToken(pcActn, mintOpts({ amount: 100, merchant: 'acme', humanPresent: true }));
    expect(typeof token).toBe('string');
  });

  it('enforces a merchant_category caveat at mint', async () => {
    const { pcActn } = buildProof([merchantCategoryCaveat(['saas'])]);
    await expect(mintDelegatedPaymentToken(pcActn, mintOpts({ amount: 10, merchant: 'acme' }))).rejects.toBeInstanceOf(AcpAuthorityError);
    await expect(mintDelegatedPaymentToken(pcActn, mintOpts({ amount: 10, merchant: 'acme', category: 'gambling' }))).rejects.toBeInstanceOf(
      AcpAuthorityError,
    );
    const token = await mintDelegatedPaymentToken(pcActn, mintOpts({ amount: 10, merchant: 'acme', category: 'saas' }));
    expect(typeof token).toBe('string');
  });

  it('refuses a token that would outlive the authorizing proof, or that expires in the past', async () => {
    const { pcActn } = standardProof();
    await expect(mintDelegatedPaymentToken(pcActn, mintOpts({ amount: 100, merchant: 'acme', expiresAt: pcActn.exp + 1 }))).rejects.toBeInstanceOf(
      AcpAuthorityError,
    );
    await expect(mintDelegatedPaymentToken(pcActn, mintOpts({ amount: 100, merchant: 'acme', expiresAt: NOW - 1 }))).rejects.toBeInstanceOf(
      AcpAuthorityError,
    );
  });

  it('stamps the proof authority by reference (digest), never the proof contents', async () => {
    const { pcActn } = standardProof();
    const token = await mintDelegatedPaymentToken(pcActn, mintOpts({ amount: 100, merchant: 'acme', issuer: 'agent-x' }));
    const payloadPart = token.split('.')[1];
    expect(payloadPart).toBeDefined();
    if (payloadPart === undefined) throw new Error('no payload');
    const claims = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf8')) as Record<string, unknown>;
    expect(claims.typ).toBe(ACP_DELEGATED_TOKEN_TYPE);
    const pca = claims.pca;
    expect(pca !== null && typeof pca === 'object').toBe(true);
    if (pca === null || typeof pca !== 'object') throw new Error('no pca');
    expect((pca as Record<string, unknown>).digest).toBe(pcactnDigest(pcActn));
    expect(claims.iss).toBe('agent-x');
    // The proof's caveats are NOT re-exposed in the token.
    expect(JSON.stringify(claims)).not.toContain('max_amount');
  });
});

// ---------------------------------------------------------------------------------------------------
// verifyDelegatedPaymentToken — settlement-time binding
// ---------------------------------------------------------------------------------------------------

describe('verifyDelegatedPaymentToken', () => {
  async function mintStandard() {
    const { pcActn, grant } = standardProof();
    const token = await mintDelegatedPaymentToken(pcActn, mintOpts({ amount: 100, merchant: 'acme' }));
    return { token, pcActn, grant };
  }

  it('verifies a matching token (merchant + amount + expiry + session + currency)', async () => {
    const { token } = await mintStandard();
    const res = await verifyDelegatedPaymentToken(token, {
      expectedMerchant: 'acme',
      amount: 100,
      verifyKey: SECRET,
      alg: ALG,
      now: NOW + 60_000,
      expectedSession: 'sess-1',
      expectedCurrency: 'USD',
    });
    expect(res.ok).toBe(true);
    expect(res.claims?.merchant).toBe('acme');
  });

  it('admits settling LESS than the authorized amount', async () => {
    const { token } = await mintStandard();
    const res = await verifyDelegatedPaymentToken(token, { expectedMerchant: 'acme', amount: 40, verifyKey: SECRET, alg: ALG, now: NOW });
    expect(res.ok).toBe(true);
  });

  it('fails closed on over-amount, wrong-merchant, wrong-session, wrong-currency, and expiry', async () => {
    const { token } = await mintStandard();
    const base = { verifyKey: SECRET, alg: ALG, now: NOW } as const;
    expect((await verifyDelegatedPaymentToken(token, { ...base, expectedMerchant: 'acme', amount: 200 })).ok).toBe(false);
    expect((await verifyDelegatedPaymentToken(token, { ...base, expectedMerchant: 'globex', amount: 100 })).ok).toBe(false);
    expect((await verifyDelegatedPaymentToken(token, { ...base, expectedMerchant: 'acme', amount: 100, expectedSession: 'other' })).ok).toBe(false);
    expect((await verifyDelegatedPaymentToken(token, { ...base, expectedMerchant: 'acme', amount: 100, expectedCurrency: 'EUR' })).ok).toBe(false);
    expect(
      (await verifyDelegatedPaymentToken(token, { expectedMerchant: 'acme', amount: 100, verifyKey: SECRET, alg: ALG, now: NOW + 11 * 60_000 })).ok,
    ).toBe(false);
  });

  it('fails closed on a tampered token and on a wrong verification key', async () => {
    const { token } = await mintStandard();
    const [h, payload, sig] = token.split('.');
    if (h === undefined || payload === undefined || sig === undefined) throw new Error('bad token');
    const flipped = payload[0] === 'A' ? 'B' : 'A';
    const tampered = `${h}.${flipped}${payload.slice(1)}.${sig}`;
    expect((await verifyDelegatedPaymentToken(tampered, { expectedMerchant: 'acme', amount: 100, verifyKey: SECRET, alg: ALG, now: NOW })).ok).toBe(false);
    expect((await verifyDelegatedPaymentToken(token, { expectedMerchant: 'acme', amount: 100, verifyKey: WRONG_SECRET, alg: ALG, now: NOW })).ok).toBe(false);
  });

  it('re-binds to the PCActn: matching digest passes end-to-end, a different proof fails closed', async () => {
    const { token, pcActn, grant } = await mintStandard();
    const matched = await verifyDelegatedPaymentToken(token, {
      expectedMerchant: 'acme',
      amount: 100,
      verifyKey: SECRET,
      alg: ALG,
      now: NOW,
      pcActn,
      grant,
      audience: AUD,
    });
    expect(matched.ok).toBe(true);
    expect(matched.pcaResult?.allow).toBe(true);

    const { pcActn: otherProof } = standardProof();
    const mismatched = await verifyDelegatedPaymentToken(token, {
      expectedMerchant: 'acme',
      amount: 100,
      verifyKey: SECRET,
      alg: ALG,
      now: NOW,
      pcActn: otherProof,
    });
    expect(mismatched.ok).toBe(false);
    expect(mismatched.reason).toContain('digest');
  });
});

// ---------------------------------------------------------------------------------------------------
// x402 facilitator — 402 → pay-with-proof → settle
// ---------------------------------------------------------------------------------------------------

describe('x402Challenge', () => {
  it('builds an HTTP 402 Payment-Required challenge with an accepts requirement', () => {
    const challenge = x402Challenge('/api/report', { amount: 100, currency: 'USD', payTo: '0xabc', network: 'base' });
    expect(challenge.status).toBe(402);
    expect(challenge.body.x402Version).toBe(1);
    const req = challenge.body.accepts[0];
    expect(req).toBeDefined();
    if (req === undefined) throw new Error('no accepts entry');
    expect(req.maxAmountRequired).toBe('100');
    expect(req.payTo).toBe('0xabc');
    expect(req.network).toBe('base');
    expect(req.resource).toBe('/api/report');
  });
});

describe('x402Settle (end-to-end with acpX402Verifier)', () => {
  async function mintStandard() {
    const { pcActn, grant } = standardProof();
    const token = await mintDelegatedPaymentToken(pcActn, mintOpts({ amount: 100, merchant: 'acme' }));
    return { token, pcActn, grant };
  }

  it('402 → proof → settle: admits a valid PCActn-bound payment and runs settlement', async () => {
    const { token } = await mintStandard();
    const payload: X402PaymentPayload = { x402Version: 1, scheme: 'exact', token, merchant: 'acme', amount: 100 };
    const res = await x402Settle(payload, {
      verify: acpX402Verifier({ verifyKey: SECRET, alg: ALG, now: NOW }),
      settle: (_p, claims) => ({ captured: claims.amount, merchant: claims.merchant }),
    });
    expect(res.settled).toBe(true);
    expect(res.status).toBe(200);
    expect(res.receipt).toEqual({ captured: 100, merchant: 'acme' });
    expect(res.claims?.session).toBe('sess-1');
  });

  it('rejects an unauthorized payment with a fresh 402 (over-amount)', async () => {
    const { token } = await mintStandard();
    const payload: X402PaymentPayload = { token, merchant: 'acme', amount: 300 };
    const res = await x402Settle(payload, { verify: acpX402Verifier({ verifyKey: SECRET, alg: ALG, now: NOW }) });
    expect(res.settled).toBe(false);
    expect(res.status).toBe(402);
  });

  it('rejects a payment for the wrong merchant', async () => {
    const { token } = await mintStandard();
    const payload: X402PaymentPayload = { token, merchant: 'globex', amount: 100 };
    const res = await x402Settle(payload, { verify: acpX402Verifier({ verifyKey: SECRET, alg: ALG, now: NOW }) });
    expect(res.settled).toBe(false);
    expect(res.status).toBe(402);
  });

  it('rejects a missing token and re-verifies the bound proof when supplied', async () => {
    const { token, pcActn, grant } = await mintStandard();
    const missing = await x402Settle({ token: '' } as X402PaymentPayload, {
      verify: acpX402Verifier({ verifyKey: SECRET, alg: ALG, now: NOW, expectedMerchant: 'acme', amount: 100 }),
    });
    expect(missing.settled).toBe(false);

    const payload: X402PaymentPayload = { token, merchant: 'acme', amount: 100 };
    const bound = await x402Settle(payload, {
      verify: acpX402Verifier({ verifyKey: SECRET, alg: ALG, now: NOW, pcActn, grant, audience: AUD }),
    });
    expect(bound.settled).toBe(true);
  });
});
