import { encodeKey, generateKeyPair, hashCanonical, pcactnDigest } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import type { Charge } from './authorize';
import { chargeParams, chargePlanNode, chargeToPCActn } from './charge-action';
import { type PaymentMandate, buildPaymentMandate } from './mandate';
import {
  type NetworkTokenProvider,
  bindNetworkToken,
  chargeWithNetworkToken,
  controlsFromLimits,
  looksLikePan,
  mastercardAgentPayAdapter,
  reconcileNetworkSettlement,
  tokenRefError,
  verifyNetworkTokenBinding,
  visaIntelligentCommerceAdapter,
} from './network-token';
import type { RailLimits } from './rails';
import { sharedPaymentTokenLimits } from './spt-limits';
import { memoryChargeBudgetStore } from './testing';

const principal = generateKeyPair();
const agent = generateKeyPair();
const NOW = 1_700_000_000_000;
const mk = (over: Record<string, unknown> = {}): PaymentMandate =>
  buildPaymentMandate({
    principalSecret: principal.secretKey,
    principalPublic: encodeKey(principal.publicKey),
    agentPublic: encodeKey(agent.publicKey),
    merchants: ['m1'],
    currency: 'USD',
    perTransactionCap: 100,
    autoApproveThreshold: 50,
    cumulativeCap: 500,
    now: NOW,
    ...over,
  });
const charge = (over: Partial<Charge> = {}): Charge => ({ merchant: 'm1', amount: 40, now: NOW, ...over });
const opts = { signerSecret: agent.secretKey, aud: 'rs', counter: 7, now: NOW };

describe('charge-action', () => {
  it('chargeParams carries the category only when given', () => {
    const m = mk();
    expect(chargeParams(m, charge())).toStrictEqual({ amount: 40, currency: 'USD' });
    expect(chargeParams(m, charge({ category: 'saas', currency: 'EUR' }))).toStrictEqual({ amount: 40, currency: 'EUR', category: 'saas' });
    expect(chargePlanNode(m, charge(), 'n1')).toMatchObject({ id: 'n1', verb: 'charge', resource: 'merchant:m1', reversibility_class: 'reversible' });
  });
  it('the default node id names the merchant and counter, and an explicit one wins', () => {
    const m = mk();
    expect(chargeToPCActn(m, charge(), opts).node.id).toBe('charge:m1:7');
    expect(chargeToPCActn(m, charge(), { ...opts, nodeId: 'custom' }).node.id).toBe('custom');
  });
  it('the risk claim is amount / X, clamped to [0, 1], and its inputs carry the params and blastRadius', () => {
    const m = mk();
    const claim = (amount: number, mm = m) => chargeToPCActn(mm, charge({ amount }), opts).pcactn.risk_claim;
    expect(claim(40)).toEqual({ r: 0.4, inputs: { amount: 40, currency: 'USD', blastRadius: 0.4 } });
    expect(claim(0).r).toBe(0);
    expect(claim(100).r).toBe(1);
    expect(claim(150).r).toBe(1);
    expect(chargeToPCActn(m, charge({ amount: 7, category: 'saas' }), opts).pcactn.risk_claim.inputs).toEqual({ amount: 7, currency: 'USD', category: 'saas', blastRadius: 0.07 });
    const zero = { ...m, terms: { ...m.terms, perTransactionCap: 0 } };
    expect(claim(0, zero).r).toBe(1);
    expect(claim(5, zero).r).toBe(1);
  });
  it('a fractional or negative amount is refused', () => {
    const m = mk();
    for (const amount of [1.5, -1, Number.NaN]) expect(() => chargeToPCActn(m, charge({ amount }), opts)).toThrow('chargeToPCActn: amount must be a non-negative integer in minor units');
  });
});

describe('sharedPaymentTokenLimits', () => {
  it('a non-finite now is a TypeError with its message', () => {
    expect(() => sharedPaymentTokenLimits(mk(), Number.NaN)).toThrow(new TypeError('sharedPaymentTokenLimits: now must be an epoch-ms time'));
    expect(() => sharedPaymentTokenLimits(mk(), Infinity)).toThrow(TypeError);
  });
  it('without a period the token has no expiry; with one it expires with the mandate', () => {
    expect(sharedPaymentTokenLimits(mk(), NOW)).toStrictEqual({ currency: 'usd', max_amount: 50 });
    expect(sharedPaymentTokenLimits(mk({ periodMs: 10_000 }), NOW)).toStrictEqual({ currency: 'usd', max_amount: 50, expires_at: Math.floor((NOW + 10_000) / 1000) });
    expect(() => sharedPaymentTokenLimits(mk({ periodMs: 10_000 }), NOW + 10_000)).toThrow('the mandate period has ended');
  });
});

describe('memoryChargeBudgetStore', () => {
  it('versions start at 1 and advance by one on each committed write', async () => {
    const s = memoryChargeBudgetStore();
    const b = { B: 1, tau: 1, asOf: 1 };
    expect(await s.compareAndSet('k', undefined, b)).toBe(true);
    expect((await s.get('k'))!.version).toBe(1);
    expect(await s.compareAndSet('k', undefined, b)).toBe(false);
    expect(await s.compareAndSet('k', 1, { ...b, B: 2 })).toBe(true);
    expect(await s.get('k')).toEqual({ budget: { B: 2, tau: 1, asOf: 1 }, version: 2 });
  });
});

describe('network token binding', () => {
  const m = mk();
  const NONCE = 'nonce-0123456789abcdef';
  const holder = encodeKey(agent.publicKey);
  const bind = (over: Record<string, unknown> = {}) => bindNetworkToken({ provider: 'visa_ic', tokenRef: 'tok_abcdef123456', grant: m.grant, issuerNonce: NONCE, holderSecret: agent.secretKey, holderPublic: agent.publicKey, ...over });
  const exp = { grant: m.grant, holder, issuerNonce: NONCE };

  it('Luhn: doubled digits above 9 are folded back, and only valid runs look like a PAN', () => {
    for (const pan of ['5555555555554444', '4012888888881881', '378282246310005', '6011111111111117']) expect(looksLikePan(pan)).toBe(true);
    for (const no of ['5555555555554445', '4012888888881882', '1234567890123456']) expect(looksLikePan(no)).toBe(false);
    expect(tokenRefError('pan_5555555555554444')).toBe('token_ref_looks_like_pan');
    expect(tokenRefError('pan_5555555555554445')).toBeNull();
    expect(tokenRefError('abcdefgh')).toBeNull();
  });
  it('a binding that is not an object with the right kind is malformed, whatever else it holds', () => {
    for (const bad of [null, undefined, 'x', 5, {}, { kind: 'other' }]) expect(verifyNetworkTokenBinding(bad, exp)).toBe('binding_malformed');
  });
  it('a provider that is not a non-empty string is a provider mismatch, even when the proof is valid', () => {
    expect(verifyNetworkTokenBinding(bind({ provider: 5 }), exp)).toBe('provider_mismatch');
    expect(verifyNetworkTokenBinding(bind({ provider: '' }), exp)).toBe('provider_mismatch');
    expect(verifyNetworkTokenBinding(bind(), exp)).toBeNull();
  });
  it('an undecodable key is malformed, not an invalid proof', () => {
    const b = { ...bind(), holder: '!!!!' };
    expect(verifyNetworkTokenBinding(b, { ...exp, holder: '!!!!' })).toBe('binding_malformed');
  });
  it('controls copy the rail limits (arrays by value) and carry the expiry only when set', () => {
    const limits: RailLimits = { currency: 'USD', perAuthorizationMax: 50, totalMax: 500, categories: ['c1'], merchants: ['m1', 'm2'] };
    const c = controlsFromLimits(limits, m.grant);
    expect(c).toStrictEqual({ currency: 'USD', perAuthorizationMax: 50, totalMax: 500, categories: ['c1'], merchants: ['m1', 'm2'], metadata: { grant_digest: hashCanonical(m.grant) } });
    expect(c.merchants).not.toBe(limits.merchants);
    expect(controlsFromLimits({ ...limits, expiresAt: 99 }, m.grant)).toMatchObject({ expiresAt: 99 });
  });
  it('a charge needs a well-formed token_ref and a binding for the same grant', () => {
    const b = bind();
    expect(() => chargeWithNetworkToken({ ...b, token_ref: 'x' }, m, charge(), opts)).toThrow(new RangeError('chargeWithNetworkToken: bad binding'));
    expect(() => chargeWithNetworkToken({ ...b, grant_digest: 'other' }, m, charge(), opts)).toThrow('chargeWithNetworkToken: binding is for another grant');
    const out = chargeWithNetworkToken(b, m, charge(), opts);
    expect(out.pcactnDigest).toBe(pcactnDigest(out.pcactn));
    expect(out.metadata).toEqual({ pca_grant: b.grant_digest, pca_pcactn: out.pcactnDigest, pca_token_ref: b.token_ref });
  });
  it('settlement reconciliation: a missing record, or an empty digest on either side, never joins', () => {
    const e = { grantDigest: 'g', pcactnDigest: 'p', tokenRef: 't' };
    expect(reconcileNetworkSettlement(e, { metadata: { pca_grant: 'g', pca_pcactn: 'p', pca_token_ref: 't' } })).toEqual({ ok: true });
    expect(reconcileNetworkSettlement(e, undefined as never)).toEqual({ ok: false, reasons: ['pcactn_digest_missing', 'grant_digest_mismatch', 'pcactn_digest_mismatch', 'token_ref_mismatch'] });
    expect(reconcileNetworkSettlement(e, null as never)).toMatchObject({ ok: false });
    expect(reconcileNetworkSettlement(e, {})).toMatchObject({ ok: false });
    expect(reconcileNetworkSettlement(e, { metadata: { pca_grant: 'g', pca_pcactn: '', pca_token_ref: 't' } })).toEqual({ ok: false, reasons: ['pcactn_digest_missing', 'pcactn_digest_mismatch'] });
    expect(reconcileNetworkSettlement({ ...e, pcactnDigest: '' }, { metadata: { pca_grant: 'g', pca_pcactn: 'p', pca_token_ref: 't' } })).toEqual({ ok: false, reasons: ['pcactn_digest_missing', 'pcactn_digest_mismatch'] });
    expect(reconcileNetworkSettlement(e, { metadata: { pca_grant: 'g', pca_pcactn: 5, pca_token_ref: 't' } })).toEqual({ ok: false, reasons: ['pcactn_digest_missing', 'pcactn_digest_mismatch'] });
  });
  it('the partner adapters post the controls to /tokens and suspend by encoded reference', async () => {
    const limits: RailLimits = { currency: 'USD', perAuthorizationMax: 50, totalMax: 500, categories: ['c1'], merchants: ['m1'] };
    for (const [adapter, id, scope] of [[visaIntelligentCommerceAdapter, 'visa_ic', 'instructions'], [mastercardAgentPayAdapter, 'mastercard_agent_pay', 'session_scope']] as const) {
      const posts: Array<{ path: string; body: Record<string, unknown> }> = [];
      const transport = { post: async (path: string, body: Record<string, unknown>) => (posts.push({ path, body }), { token_ref: 'tok_abcdef123456' }) };
      const p: NetworkTokenProvider = adapter(transport);
      expect(p.id).toBe(id);
      const controls = controlsFromLimits(limits, m.grant);
      expect(await p.issue({ controls, agentId: 'ag1' })).toEqual({ token_ref: 'tok_abcdef123456' });
      expect(posts[0]!.path).toBe('/tokens');
      expect(posts[0]!.body).toStrictEqual({
        agent_id: 'ag1',
        [scope]: { currency: 'USD', per_authorization_max: 50, total_max: 500, merchant_categories: ['c1'], merchants: ['m1'] },
        metadata: controls.metadata,
      });
      await p.issue({ controls: { ...controls, expiresAt: 123 }, agentId: 'ag1' });
      expect((posts[1]!.body[scope] as Record<string, unknown>).expires_at).toBe(123);
      await p.suspend('a/b c', 'grant_revoked');
      expect(posts[2]).toEqual({ path: '/tokens/a%2Fb%20c/suspend', body: { reason: 'grant_revoked' } });
      for (const bad of ['x', 5, undefined, '4111111111111111']) {
        const evil = adapter({ post: async () => ({ token_ref: bad }) });
        await expect(evil.issue({ controls, agentId: 'ag1' })).rejects.toThrow(`${id}: provider returned ${bad === '4111111111111111' ? 'token_ref_looks_like_pan' : 'token_ref_malformed'}`);
      }
    }
  });
});
