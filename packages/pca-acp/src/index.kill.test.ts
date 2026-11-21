import { generateKeyPairSync } from 'node:crypto';
import { CompactSign, type JWK } from 'jose';
import { describe, expect, it } from 'vitest';
import { type Caveat, type PCActn, buildPCActn, encodeKey, generateKeyPair, mintRoot, pcactnDigest } from '@atlasauth/pca';
import {
  AcpAuthorityError,
  acpX402Verifier,
  checkPaymentAuthority,
  extractPaymentAuthority,
  humanPresentCaveat,
  merchantAllowCaveat,
  merchantCategoryCaveat,
  mintDelegatedPaymentToken,
  spendCapCaveat,
  toAcpAllowance,
  verifyDelegatedPaymentToken,
  x402Challenge,
  x402Settle,
  type DelegatedPaymentClaims,
  type MintOptions,
  type X402PaymentPayload,
  type X402RequirementV2,
} from './index';

const NOW = 1_800_000_000_000;
const AUD = 'rs-acme';
const ALG = 'HS256';
const SECRET = new Uint8Array(32).fill(7);

function buildProof(caveats: Caveat[]) {
  const principal = generateKeyPair();
  const agent = generateKeyPair();
  const grant = mintRoot({ principalSecret: principal.secretKey, principalPublic: encodeKey(principal.publicKey), holder: encodeKey(agent.publicKey), caveats });
  const pcActn = buildPCActn({
    grant,
    chain: [grant],
    plan: [{ id: 'pay', verb: 'pay', resource: 'checkout/sess-1', reversibility_class: 'R2' }],
    nodeId: 'pay',
    counter: 1,
    signerSecret: agent.secretKey,
    aud: AUD,
    now: NOW,
  });
  return { pcActn, grant };
}
const standardProof = () => buildProof([spendCapCaveat(500, 'USD'), merchantAllowCaveat(['acme', 'globex'])]);

function mintOpts(extra: Partial<MintOptions> = {}): MintOptions {
  return {
    amount: 100,
    merchant: 'acme',
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

const b64json = (part: string | undefined): Record<string, unknown> => {
  if (part === undefined) throw new Error('missing part');
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8')) as Record<string, unknown>;
};
const claimsOf = (token: string) => b64json(token.split('.')[1]);
const headerOf = (token: string) => b64json(token.split('.')[0]);

const vfy = (token: string, extra: Partial<Parameters<typeof verifyDelegatedPaymentToken>[1]> = {}) =>
  verifyDelegatedPaymentToken(token, { strict: false, expectedMerchant: 'acme', amount: 100, verifyKey: SECRET, alg: ALG, now: NOW, ...extra });

const signRaw = (text: string) => new CompactSign(new TextEncoder().encode(text)).setProtectedHeader({ alg: ALG }).sign(SECRET);

describe('caveat builders and error identity', () => {
  it('humanPresentCaveat defaults to required and honours an explicit false', () => {
    expect(humanPresentCaveat()).toEqual({ type: 'human_present', required: true });
    expect(humanPresentCaveat(false)).toEqual({ type: 'human_present', required: false });
  });
  it('spendCapCaveat omits the currency key when none is given', () => {
    expect(spendCapCaveat(5)).toStrictEqual({ type: 'max_amount', max: 5 });
    expect(spendCapCaveat(5, 'USD')).toStrictEqual({ type: 'max_amount', max: 5, currency: 'USD' });
  });
  it('AcpAuthorityError carries its name', () => {
    expect(new AcpAuthorityError('x').name).toBe('AcpAuthorityError');
  });
});

describe('extractPaymentAuthority', () => {
  it('an empty caveat list yields an unconstrained authority with no stray keys', () => {
    expect(extractPaymentAuthority([])).toStrictEqual({ merchants: null, categories: null, humanPresentRequired: false });
  });
  it('a cap without a currency leaves currency absent', () => {
    expect(extractPaymentAuthority([spendCapCaveat(7)])).toStrictEqual({ maxAmount: 7, merchants: null, categories: null, humanPresentRequired: false });
  });
  it('the tightest cap wins regardless of order, and a zero cap is valid', () => {
    expect(extractPaymentAuthority([spendCapCaveat(200), spendCapCaveat(500)]).maxAmount).toBe(200);
    expect(extractPaymentAuthority([spendCapCaveat(500), spendCapCaveat(200)]).maxAmount).toBe(200);
    expect(extractPaymentAuthority([spendCapCaveat(0)]).maxAmount).toBe(0);
  });
  it('the same currency twice is not a conflict; different currencies are, with the exact message', () => {
    expect(extractPaymentAuthority([spendCapCaveat(1, 'USD'), spendCapCaveat(2, 'USD')]).currency).toBe('USD');
    expect(() => extractPaymentAuthority([spendCapCaveat(1, 'USD'), spendCapCaveat(2, 'EUR')])).toThrow('conflicting spend-cap currencies "USD" vs "EUR" (fail closed)');
  });
  it('a malformed cap currency fails closed with the exact message', () => {
    for (const currency of ['', 5]) {
      expect(() => extractPaymentAuthority([{ type: 'max_amount', max: 1, currency }])).toThrow(
        'malformed max_amount caveat: currency must be a non-empty string (fail closed)',
      );
    }
  });
  it('a malformed allowlist fails closed with the exact, labelled message', () => {
    for (const bad of ['acme', ['acme', 5], 7, undefined]) {
      expect(() => extractPaymentAuthority([{ type: 'merchant_allow', merchants: bad }])).toThrow(
        new AcpAuthorityError('malformed merchant_allow caveat: expected a string[] (fail closed)'),
      );
      expect(() => extractPaymentAuthority([{ type: 'merchant_category', categories: bad }])).toThrow(
        new AcpAuthorityError('malformed merchant_category caveat: expected a string[] (fail closed)'),
      );
    }
  });
  it('category allowlists intersect and a single list is kept as given', () => {
    expect(extractPaymentAuthority([merchantCategoryCaveat(['a', 'b', 'a'])]).categories).toEqual(['a', 'b']);
    expect(extractPaymentAuthority([merchantCategoryCaveat(['a', 'b']), merchantCategoryCaveat(['b', 'c'])]).categories).toEqual(['b']);
    expect(extractPaymentAuthority([merchantCategoryCaveat(['a']), merchantCategoryCaveat(['c'])]).categories).toEqual([]);
  });
  it('human_present: a false requirement stays false, true is sticky, a non-boolean fails closed', () => {
    expect(extractPaymentAuthority([humanPresentCaveat(false)]).humanPresentRequired).toBe(false);
    expect(extractPaymentAuthority([humanPresentCaveat(true), humanPresentCaveat(false)]).humanPresentRequired).toBe(true);
    expect(extractPaymentAuthority([humanPresentCaveat(false), humanPresentCaveat(true)]).humanPresentRequired).toBe(true);
    expect(() => extractPaymentAuthority([{ type: 'human_present', required: 'yes' }])).toThrow(
      'malformed human_present caveat: required must be a boolean (fail closed)',
    );
  });
});

describe('checkPaymentAuthority', () => {
  const open = extractPaymentAuthority([]);
  it('refuses a non-string or empty currency and merchant with the exact reason', () => {
    for (const currency of ['', 5]) {
      expect(checkPaymentAuthority(open, { amount: 1, currency: currency as string, merchant: 'm' })).toEqual({ ok: false, reason: 'currency must be a non-empty string' });
    }
    for (const merchant of ['', 5]) {
      expect(checkPaymentAuthority(open, { amount: 1, currency: 'USD', merchant: merchant as string })).toEqual({ ok: false, reason: 'merchant must be a non-empty string' });
    }
  });
  it('boundary: an amount equal to the cap passes, one above fails with the exact reason', () => {
    const a = extractPaymentAuthority([spendCapCaveat(500)]);
    expect(checkPaymentAuthority(a, { amount: 500, currency: 'USD', merchant: 'm' })).toEqual({ ok: true });
    expect(checkPaymentAuthority(a, { amount: 501, currency: 'USD', merchant: 'm' })).toEqual({ ok: false, reason: 'amount 501 exceeds the authorized spend cap 500' });
  });
  it('exact reasons for currency, merchant, category and human-present refusals', () => {
    const a = extractPaymentAuthority([spendCapCaveat(500, 'USD'), merchantAllowCaveat(['acme']), merchantCategoryCaveat(['saas']), humanPresentCaveat(true)]);
    const ok = { amount: 1, currency: 'USD', merchant: 'acme', category: 'saas', humanPresent: true };
    expect(checkPaymentAuthority(a, ok)).toEqual({ ok: true });
    expect(checkPaymentAuthority(a, { ...ok, currency: 'EUR' })).toEqual({ ok: false, reason: 'currency "EUR" is not the authorized currency "USD"' });
    expect(checkPaymentAuthority(a, { ...ok, merchant: 'evil' })).toEqual({ ok: false, reason: 'merchant "evil" is not in the authorized allowlist' });
    expect(checkPaymentAuthority(a, { amount: 1, currency: 'USD', merchant: 'acme', humanPresent: true })).toEqual({
      ok: false,
      reason: 'the proof constrains merchant categories but no category was supplied',
    });
    expect(checkPaymentAuthority(a, { ...ok, category: 'gambling' })).toEqual({ ok: false, reason: 'category "gambling" is not in the authorized allowlist' });
    expect(checkPaymentAuthority(a, { ...ok, humanPresent: false })).toEqual({
      ok: false,
      reason: 'the proof requires a human-present charge but humanPresent was not asserted',
    });
  });
});

describe('mintDelegatedPaymentToken', () => {
  it('stamps the exact claims and protected header', async () => {
    const { pcActn } = standardProof();
    const token = await mintDelegatedPaymentToken(pcActn, mintOpts());
    const digest = pcactnDigest(pcActn);
    expect(claimsOf(token)).toEqual({
      typ: 'acp-delegated-payment',
      ver: 1,
      jti: pcactnDigest({ ...pcActn, nonce: `acp:sess-1:acme:100:USD:${NOW + 600_000}:${digest}` }),
      session: 'sess-1',
      merchant: 'acme',
      amount: 100,
      currency: 'USD',
      iat: NOW,
      exp: NOW + 600_000,
      paymentMethod: { type: 'shared_payment_token', token: 'spt_abc' },
      humanPresent: false,
      pca: {
        digest,
        aud: AUD,
        grant_ref: pcActn.grant_ref,
        leaf_holder: pcActn.cap_chain[0]?.holder,
        verb: 'pay',
        resource: 'checkout/sess-1',
        params_digest: pcActn.action.params_digest,
      },
    });
    expect(headerOf(token)).toEqual({ alg: ALG, typ: 'acp-delegated-payment' });
  });

  it('derived one-time id is deterministic and depends on the binding; an explicit jti wins', async () => {
    const { pcActn } = standardProof();
    const a = claimsOf(await mintDelegatedPaymentToken(pcActn, mintOpts()));
    const b = claimsOf(await mintDelegatedPaymentToken(pcActn, mintOpts()));
    const c = claimsOf(await mintDelegatedPaymentToken(pcActn, mintOpts({ session: 'sess-2' })));
    expect(a.jti).toBe(b.jti);
    expect(a.jti).not.toBe(c.jti);
    expect(claimsOf(await mintDelegatedPaymentToken(pcActn, mintOpts({ jti: 'fixed-id' }))).jti).toBe('fixed-id');
  });

  it('carries optional category, issuer, kid and human-present only when supplied', async () => {
    const { pcActn } = standardProof();
    const bare = await mintDelegatedPaymentToken(pcActn, mintOpts());
    expect('category' in claimsOf(bare)).toBe(false);
    expect('iss' in claimsOf(bare)).toBe(false);
    expect('kid' in headerOf(bare)).toBe(false);
    const full = await mintDelegatedPaymentToken(pcActn, mintOpts({ category: 'saas', issuer: 'agent-x', kid: 'k1', humanPresent: true }));
    expect(claimsOf(full)).toMatchObject({ category: 'saas', iss: 'agent-x', humanPresent: true });
    expect(headerOf(full)).toEqual({ alg: ALG, typ: 'acp-delegated-payment', kid: 'k1' });
    const explicitFalse = await mintDelegatedPaymentToken(pcActn, mintOpts({ humanPresent: false }));
    expect(claimsOf(explicitFalse).humanPresent).toBe(false);
  });

  it('refuses with the exact message for over-authority, expiry and session problems', async () => {
    const { pcActn } = standardProof();
    await expect(mintDelegatedPaymentToken(pcActn, mintOpts({ amount: 600 }))).rejects.toThrow('refused: amount 600 exceeds the authorized spend cap 500');
    for (const expiresAt of [Number.NaN, Number.POSITIVE_INFINITY]) {
      await expect(mintDelegatedPaymentToken(pcActn, mintOpts({ expiresAt }))).rejects.toThrow('refused: expiresAt must be a finite epoch-ms timestamp');
    }
    await expect(mintDelegatedPaymentToken(pcActn, mintOpts({ expiresAt: NOW }))).rejects.toThrow('refused: expiresAt is not in the future');
    await expect(mintDelegatedPaymentToken(pcActn, mintOpts({ expiresAt: pcActn.exp + 1 }))).rejects.toThrow(
      `refused: token expiry ${pcActn.exp + 1} would outlive the proof's exp ${pcActn.exp}`,
    );
    await expect(mintDelegatedPaymentToken(pcActn, mintOpts({ session: '' }))).rejects.toThrow('refused: a session id is required');
  });

  it('expiry boundaries: one ms after now and exactly the proof exp are both accepted', async () => {
    const { pcActn } = standardProof();
    expect(claimsOf(await mintDelegatedPaymentToken(pcActn, mintOpts({ expiresAt: NOW + 1 }))).exp).toBe(NOW + 1);
    expect(claimsOf(await mintDelegatedPaymentToken(pcActn, mintOpts({ expiresAt: pcActn.exp }))).exp).toBe(pcActn.exp);
  });

  it('a proof with no usable capability chain is refused with the exact message', async () => {
    const { pcActn } = standardProof();
    await expect(mintDelegatedPaymentToken({ ...pcActn, cap_chain: [] } as PCActn, mintOpts())).rejects.toThrow('PCActn carries no capability chain (fail closed)');
    await expect(mintDelegatedPaymentToken({ ...pcActn, cap_chain: undefined } as unknown as PCActn, mintOpts())).rejects.toThrow(
      new AcpAuthorityError('PCActn carries no capability chain (fail closed)'),
    );
    await expect(mintDelegatedPaymentToken({ ...pcActn, cap_chain: [undefined] } as unknown as PCActn, mintOpts())).rejects.toThrow(
      new AcpAuthorityError('PCActn capability chain has no leaf (fail closed)'),
    );
  });

  it('signs and verifies with JWK keys, defaulting to EdDSA', async () => {
    const { pcActn } = standardProof();
    const kp = generateKeyPairSync('ed25519');
    const priv = kp.privateKey.export({ format: 'jwk' }) as JWK;
    const pub = kp.publicKey.export({ format: 'jwk' }) as JWK;
    const o = mintOpts({ signingKey: priv });
    delete o.alg;
    const token = await mintDelegatedPaymentToken(pcActn, o);
    expect(headerOf(token).alg).toBe('EdDSA');
    const vOpts = { strict: false, expectedMerchant: 'acme', amount: 100, verifyKey: pub, now: NOW } as const;
    expect((await verifyDelegatedPaymentToken(token, vOpts)).ok).toBe(true);
    expect((await verifyDelegatedPaymentToken(token, { ...vOpts, alg: 'EdDSA' })).ok).toBe(true);
  });

  it('verification pins the algorithm and never treats a non-JWK key as a JWK', async () => {
    const { pcActn } = standardProof();
    const token = await mintDelegatedPaymentToken(pcActn, mintOpts());
    expect((await vfy(token, { alg: 'HS512' })).ok).toBe(false);
    for (const key of ['secret', null]) {
      const res = await vfy(token, { verifyKey: key as never });
      expect(res.ok).toBe(false);
      expect(res.reason).toMatch(/^token signature did not verify: /);
      expect(res.reason).not.toContain("'in' operator");
    }
  });
});

describe('verifyDelegatedPaymentToken', () => {
  async function good() {
    const { pcActn, grant } = standardProof();
    const token = await mintDelegatedPaymentToken(pcActn, mintOpts({ category: 'saas', issuer: 'i' }));
    return { token, pcActn, grant, claims: claimsOf(token) };
  }
  const WELL_FORMED = 'token payload is not a well-formed delegated payment token';

  it('rejects any structurally malformed claim set with the well-formed reason and no claims', async () => {
    const { claims } = await good();
    const pca = claims.pca as Record<string, unknown>;
    const overrides: Record<string, unknown>[] = [
      { typ: 'other' },
      { ver: 2 },
      { jti: 5 },
      { session: 5 },
      { merchant: 5 },
      { amount: 1.5 },
      { amount: 0 },
      { currency: 5 },
      { iat: 'x' },
      { exp: 'x' },
      { jti: '' },
      { session: '' },
      { merchant: '' },
      { currency: '' },
      { humanPresent: 'yes' },
      { humanPresent: undefined },
      { paymentMethod: undefined },
      { paymentMethod: null },
      { paymentMethod: 'card' },
      { paymentMethod: {} },
      { paymentMethod: { type: 5 } },
      { pca: undefined },
      { pca: null },
      ...['digest', 'aud', 'grant_ref', 'leaf_holder', 'verb', 'resource', 'params_digest'].map((k) => ({ pca: { ...pca, [k]: 5 } })),
    ];
    for (const o of overrides) {
      const res = await vfy(await signRaw(JSON.stringify({ ...claims, ...o })));
      expect(res, JSON.stringify(o)).toEqual({ ok: false, reason: WELL_FORMED });
    }
    // Non-object / non-JSON payloads never reach claim parsing: the canonical-JWS gate refuses them first.
    const GATE = 'token signature did not verify: non-canonical compact JWS: ';
    for (const text of ['null', '"str"', '[]', '5']) {
      expect(await vfy(await signRaw(text)), text).toEqual({ ok: false, reason: `${GATE}not-an-object` });
    }
    expect((await vfy(await signRaw('not json'))).reason).toMatch(/^token signature did not verify: non-canonical compact JWS: bad-json/);
    const base = JSON.stringify(claims);
    for (const k of ['iat', 'exp']) {
      const res = await vfy(await signRaw(base.replace(new RegExp(`"${k}":\\d+`), `"${k}":1e999`)));
      expect(res.ok).toBe(false);
      expect(res.reason).toMatch(/^token signature did not verify: non-canonical compact JWS: bad-json \(strict JSON: exponent form/);
    }
  });

  it('an unmodified claim set re-signed verifies and has no reason key', async () => {
    const { claims, token } = await good();
    const res = await vfy(await signRaw(JSON.stringify(claims)));
    expect(res.ok).toBe(true);
    expect('reason' in res).toBe(false);
    expect(res.claims?.category).toBe('saas');
    expect((await vfy(token)).ok).toBe(true);
  });

  it('expiry is inclusive of the exact exp and exclusive after it', async () => {
    const { token } = await good();
    expect((await vfy(token, { now: NOW + 600_000 })).ok).toBe(true);
    expect(await vfy(token, { now: NOW + 600_001 })).toMatchObject({ ok: false, reason: 'the delegated payment token has expired' });
  });

  it('exact session and currency mismatch reasons', async () => {
    const { token } = await good();
    expect(await vfy(token, { expectedSession: 'other' })).toMatchObject({ ok: false, reason: 'token session "sess-1" does not match expected "other"' });
    expect((await vfy(token, { expectedSession: 'sess-1', expectedCurrency: 'USD' })).ok).toBe(true);
  });

  it('strict settlement refuses a store without a claim function and an empty expected currency', async () => {
    const { token } = await good();
    expect(await verifyDelegatedPaymentToken(token, { expectedMerchant: 'acme', amount: 100, verifyKey: SECRET, alg: ALG, now: NOW, expectedCurrency: 'USD', singleUse: {} as never })).toEqual({
      ok: false,
      reason: 'strict settlement requires a singleUse store (fail closed)',
    });
    const store = { claim: async () => true };
    expect(await verifyDelegatedPaymentToken(token, { expectedMerchant: 'acme', amount: 100, verifyKey: SECRET, alg: ALG, now: NOW, expectedCurrency: '', singleUse: store })).toEqual({
      ok: false,
      reason: 'strict settlement requires expectedCurrency (fail closed)',
    });
  });

  it('a store that does not answer true is a refusal; one that throws fails closed', async () => {
    const { token } = await good();
    const base = { expectedMerchant: 'acme', amount: 100, verifyKey: SECRET, alg: ALG, now: NOW, expectedCurrency: 'USD' } as const;
    expect(await verifyDelegatedPaymentToken(token, { ...base, singleUse: { claim: async () => 1 as never } })).toMatchObject({ ok: false, reason: 'the delegated payment token was already redeemed' });
    expect(
      await verifyDelegatedPaymentToken(token, {
        ...base,
        singleUse: {
          claim: async () => {
            throw new Error('down');
          },
        },
      }),
    ).toMatchObject({ ok: false, reason: 'single-use store unavailable (fail closed)' });
  });

  it('a pcActn with no grant is a digest check only and never runs the core', async () => {
    const { token, pcActn } = await good();
    const res = await vfy(token, { pcActn });
    expect(res.ok).toBe(true);
    expect('pcaResult' in res).toBe(false);
  });

  it('the bound-proof re-verification honours authorizedPlanRoots and reports the core reason', async () => {
    const { token, pcActn, grant } = await good();
    const denied = await vfy(token, { pcActn, grant, audience: AUD });
    expect(denied.ok).toBe(false);
    expect(denied.pcaResult?.allow).toBe(false);
    expect(denied.reason).toBe(`bound proof failed to verify: ${denied.pcaResult?.reason}`);
    expect(denied.reason).toContain('plan_root_authorized');
    const allowed = await vfy(token, { pcActn, grant, audience: AUD, authorizedPlanRoots: [pcActn.plan.root] });
    expect(allowed.ok).toBe(true);
    expect(allowed.pcaResult?.allow).toBe(true);
    const skipped = await vfy(token, { pcActn, grant, audience: AUD, insecureSkipPlanRootCheck: true });
    expect(skipped.ok).toBe(true);
  });
});

describe('x402Challenge defaults', () => {
  it('fills the documented defaults and keeps provided values', () => {
    const c = x402Challenge('/r', { amount: 5, payTo: '0xabc', currency: 'USDC' });
    expect(c.headers).toEqual({ 'Content-Type': 'application/json' });
    expect(c.body.accepts[0]).toEqual({
      maxTimeoutSeconds: 60,
      scheme: 'exact',
      network: 'base-sepolia',
      maxAmountRequired: '5',
      resource: '/r',
      description: 'Payment required for /r',
      payTo: '0xabc',
      asset: 'USDC',
      mimeType: 'application/json',
    });
    const o = x402Challenge('/r', { amount: 5, payTo: '0xabc', currency: 'USDC', description: 'd', mimeType: 'text/plain', scheme: 's', network: 'n' });
    expect(o.body.accepts[0]).toMatchObject({ description: 'd', mimeType: 'text/plain', scheme: 's', network: 'n' });
  });
  it('refuses an empty currency', () => {
    expect(() => x402Challenge('/r', { amount: 5, payTo: '0xabc', currency: '' })).toThrow('x402Challenge: currency (the x402 asset) is required');
  });
});

describe('x402Settle', () => {
  const claims = { amount: 1 } as unknown as DelegatedPaymentClaims;
  it('refuses an unreadable payload without calling verify', async () => {
    let called = false;
    const res = await x402Settle({ x402Version: 3 } as X402PaymentPayload, {
      verify: () => {
        called = true;
        return { ok: true, claims };
      },
    });
    expect(res).toEqual({ settled: false, status: 402, reason: 'unsupported x402Version 3' });
    expect(called).toBe(false);
  });
  it('a failed verification without a reason gets the default reason', async () => {
    const res = await x402Settle({ token: 't' }, { verify: () => ({ ok: false }) });
    expect(res).toEqual({ settled: false, status: 402, reason: 'payment verification failed' });
  });
  it('an admission without claims is refused', async () => {
    const res = await x402Settle({ token: 't' }, { verify: () => ({ ok: true }) });
    expect(res).toEqual({ settled: false, status: 402, reason: 'verifier admitted the payment but returned no claims (fail closed)' });
  });
  it('settles without a settler and carries no receipt key', async () => {
    const res = await x402Settle({ token: 't' }, { verify: () => ({ ok: true, claims }) });
    expect(res).toEqual({ settled: true, status: 200, claims });
    expect('receipt' in res).toBe(false);
  });
});

describe('acpX402Verifier', () => {
  const ACCEPTED: X402RequirementV2 = { scheme: 'exact', network: 'eip155:84532', amount: '10000', asset: 'USDC', payTo: '0x209693Bc6afc0C5328bA36FaF03C514EF312287C', maxTimeoutSeconds: 60 };
  const v = (o: Partial<Parameters<typeof acpX402Verifier>[0]> = {}) =>
    acpX402Verifier({ strict: false, verifyKey: SECRET, alg: ALG, now: NOW, expectedMerchant: 'acme', amount: 100, ...o });
  async function minted() {
    const { pcActn, grant } = standardProof();
    return { pcActn, grant, token: await mintDelegatedPaymentToken(pcActn, mintOpts()) };
  }

  it('an unreadable payload is refused with exactly the normaliser reason', async () => {
    expect(await v()({ x402Version: 3 } as X402PaymentPayload)).toEqual({ ok: false, reason: 'unsupported x402Version 3' });
  });

  it('v2 payloads pass without an offered list; v1 payloads are not matched against one', async () => {
    const { token } = await minted();
    const v2: X402PaymentPayload = { x402Version: 2, payload: { token }, accepted: ACCEPTED };
    expect((await v()(v2)).ok).toBe(true);
    expect((await v({ offered: [ACCEPTED] })(v2)).ok).toBe(true);
    expect(await v({ offered: [{ ...ACCEPTED, amount: '1' }] })(v2)).toEqual({
      ok: false,
      reason: 'x402 v2 payload.accepted is not one of the requirements this server offered',
    });
    expect((await v({ offered: [ACCEPTED] })({ token })).ok).toBe(true);
  });

  it('refuses a payload with no usable merchant or amount when the server supplied none', async () => {
    const { token } = await minted();
    const bare = { strict: false, verifyKey: SECRET, alg: ALG, now: NOW } as const;
    for (const merchant of [undefined, '']) {
      expect(await acpX402Verifier(bare)({ token, ...(merchant === undefined ? {} : { merchant }), amount: 100 })).toEqual({
        ok: false,
        reason: 'x402 payload has no merchant to check the token against',
      });
    }
    expect(await acpX402Verifier(bare)({ token, merchant: 'acme' })).toEqual({ ok: false, reason: 'x402 payload has no amount to check the token against' });
    expect((await acpX402Verifier(bare)({ token, merchant: 'acme', amount: 100 })).ok).toBe(true);
  });

  it('forwards session, currency, grant and plan roots to the token verification', async () => {
    const { token, pcActn, grant } = await minted();
    const p: X402PaymentPayload = { token };
    expect(await v({ expectedSession: 'other' })(p)).toMatchObject({ ok: false, reason: 'token session "sess-1" does not match expected "other"' });
    expect((await v({ expectedSession: 'sess-1' })(p)).ok).toBe(true);
    expect((await v({ expectedCurrency: 'EUR' })(p)).ok).toBe(false);
    const denied = await v({ pcActn, grant, audience: AUD })(p);
    expect(denied.ok).toBe(false);
    expect(denied.reason).toContain('bound proof failed to verify');
    expect((await v({ pcActn, grant, audience: AUD, authorizedPlanRoots: [pcActn.plan.root] })(p)).ok).toBe(true);
  });

  it('a success carries claims and no reason key', async () => {
    const { token } = await minted();
    const res = await v()({ token });
    expect(res.ok).toBe(true);
    expect('reason' in res).toBe(false);
    expect(res.claims?.merchant).toBe('acme');
  });
});

describe('toAcpAllowance refusals', () => {
  const base = (over: Record<string, unknown> = {}) =>
    ({ typ: 'acp-delegated-payment', ver: 1, jti: 'j', session: 'sess-1', merchant: 'acme', amount: 2000, currency: 'USD', iat: NOW, exp: NOW + 1000, paymentMethod: { type: 'x' }, humanPresent: false, pca: {}, ...over }) as unknown as DelegatedPaymentClaims;
  it('exact messages', () => {
    expect(() => toAcpAllowance(base({ amount: 1.5 }))).toThrow(new AcpAuthorityError('allowance: amount must be a positive integer in minor units'));
    for (const currency of [5, 'US', '1usd', 'usd1', 'usdx', '']) {
      expect(() => toAcpAllowance(base({ currency })), String(currency)).toThrow(new AcpAuthorityError('allowance: currency must be a three-letter ISO-4217 code'));
    }
    for (const merchant of [5, '', 'm'.repeat(257)]) {
      expect(() => toAcpAllowance(base({ merchant }))).toThrow(new AcpAuthorityError('allowance: merchant_id must be 1 to 256 characters'));
    }
    for (const session of [5, '']) {
      expect(() => toAcpAllowance(base({ session }))).toThrow(new AcpAuthorityError('allowance: checkout_session_id is required'));
    }
    for (const exp of [Number.NaN, 8.64e15 + 1]) {
      expect(() => toAcpAllowance(base({ exp }))).toThrow(new AcpAuthorityError('allowance: expiry is not a valid time'));
    }
  });
});
