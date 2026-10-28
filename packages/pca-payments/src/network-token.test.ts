import { describe, expect, it } from 'vitest';
import { generateKeyPair, hashCanonical } from '@atlasauth/pca';
import { buildPaymentMandate } from './mandate';
import { encodeKey } from '@atlasauth/pca';
import { railLimits } from './rails';
import { chargeWithNetworkToken } from './network-token';
import {
  bindNetworkToken, issueBoundNetworkToken, looksLikePan, mastercardAgentPayAdapter, reconcileNetworkSettlement, settlementMetadata,
  suspendOnRevoke, tokenRefError, verifyNetworkTokenBinding, visaIntelligentCommerceAdapter, type PartnerTransport,
} from './network-token';

const NOW = 1_800_000_000_000;
const principal = generateKeyPair();
const agent = generateKeyPair();
const mandate = buildPaymentMandate({
  principalSecret: principal.secretKey, principalPublic: encodeKey(principal.publicKey), agentPublic: encodeKey(agent.publicKey),
  merchants: ['m1'], categories: ['5734'], currency: 'USD', perTransactionCap: 800, autoApproveThreshold: 500, cumulativeCap: 1000, periodMs: 86_400_000, now: NOW,
});
const NONCE = 'nonce-0123456789abcdef';
const holder = encodeKey(agent.publicKey);
const mk = () => bindNetworkToken({ provider: 'visa_ic', tokenRef: 'tok_abcdef123456', grant: mandate.grant, issuerNonce: NONCE, holderSecret: agent.secretKey, holderPublic: agent.publicKey });
const exp = { grant: mandate.grant, holder, issuerNonce: NONCE };

describe('network token binding (C-280)', () => {
  it('a binding signed by the holder over token_ref, grant digest and nonce verifies', () => {
    expect(verifyNetworkTokenBinding(mk(), exp)).toBeNull();
  });
  it('every field is bound: token_ref, grant, holder, nonce, provider', () => {
    const b = mk();
    expect(verifyNetworkTokenBinding({ ...b, token_ref: 'tok_other_123456' }, exp)).toBe('binding_proof_invalid');
    expect(verifyNetworkTokenBinding(b, { ...exp, grant: { other: 1 } })).toBe('grant_digest_mismatch');
    expect(verifyNetworkTokenBinding(b, { ...exp, holder: encodeKey(principal.publicKey) })).toBe('holder_mismatch');
    expect(verifyNetworkTokenBinding(b, { ...exp, issuerNonce: 'nonce-other-0123456' })).toBe('issuer_nonce_mismatch');
    expect(verifyNetworkTokenBinding(b, { ...exp, provider: 'mastercard_agent_pay' })).toBe('provider_mismatch');
    expect(verifyNetworkTokenBinding({ ...b, binding_proof: b.binding_proof.slice(0, 10) + (b.binding_proof[10] === 'A' ? 'B' : 'A') + b.binding_proof.slice(11) }, exp)).toBe('binding_proof_invalid');
    expect(verifyNetworkTokenBinding(null, exp)).toBe('binding_malformed');
  });
  it('a PAN-shaped or malformed token_ref is refused', () => {
    expect(looksLikePan('4111111111111111')).toBe(true);
    expect(looksLikePan('4111-1111-1111-1111')).toBe(true);
    expect(looksLikePan('4111111111111112')).toBe(false);
    expect(tokenRefError('tok_4111111111111111')).toBe('token_ref_looks_like_pan');
    expect(tokenRefError('short')).toBe('token_ref_malformed');
    expect(() => bindNetworkToken({ provider: 'x', tokenRef: '4111111111111111', grant: {}, issuerNonce: NONCE, holderSecret: agent.secretKey, holderPublic: agent.publicKey })).toThrow(/pan/);
  });
});

describe('issuance gate and adapters (C-281, mock transport, partner-gated)', () => {
  const calls: Array<{ path: string; body: Record<string, unknown> }> = [];
  const transport = (ref: unknown): PartnerTransport => ({ post: async (path, body) => { calls.push({ path, body }); return { token_ref: ref }; } });
  it('controls sent to the network equal the rail limits and carry the grant digest', async () => {
    calls.length = 0;
    const limits = railLimits(mandate, NOW);
    const p = visaIntelligentCommerceAdapter(transport('tok_abcdef123456'));
    const { binding, controls } = await issueBoundNetworkToken({ provider: p, limits, grant: mandate.grant, agentId: 'agent-1', holderSecret: agent.secretKey, holderPublic: agent.publicKey, issuerNonce: NONCE });
    expect(controls).toMatchObject({ perAuthorizationMax: 500, totalMax: 1000, categories: ['5734'], currency: 'USD', metadata: { grant_digest: hashCanonical(mandate.grant) } });
    expect(calls[0]!.body.instructions).toMatchObject({ per_authorization_max: 500, total_max: 1000, merchant_categories: ['5734'] });
    expect(verifyNetworkTokenBinding(binding, { ...exp, provider: 'visa_ic' })).toBeNull();
  });
  it('the Mastercard mapping uses its own scope key; a PAN-shaped provider response is refused', async () => {
    calls.length = 0;
    const limits = railLimits(mandate, NOW);
    await issueBoundNetworkToken({ provider: mastercardAgentPayAdapter(transport('tok_abcdef123456')), limits, grant: mandate.grant, agentId: 'a', holderSecret: agent.secretKey, holderPublic: agent.publicKey, issuerNonce: NONCE });
    expect(Object.keys(calls[0]!.body)).toContain('session_scope');
    await expect(issueBoundNetworkToken({ provider: mastercardAgentPayAdapter(transport('4111111111111111')), limits, grant: mandate.grant, agentId: 'a', holderSecret: agent.secretKey, holderPublic: agent.publicKey, issuerNonce: NONCE })).rejects.toThrow(/token_ref/);
  });
  it('revoking the grant suspends the token; a failing suspend propagates', async () => {
    calls.length = 0;
    await suspendOnRevoke(visaIntelligentCommerceAdapter(transport('x')), mk());
    expect(calls[0]).toEqual({ path: '/tokens/tok_abcdef123456/suspend', body: { reason: 'grant_revoked' } });
    await expect(suspendOnRevoke(visaIntelligentCommerceAdapter({ post: async () => { throw new Error('down'); } }), mk())).rejects.toThrow('down');
  });
});

describe('settlement join (C-282)', () => {
  it('joins only on an exact echo of grant digest, PCActn digest and token_ref', () => {
    const b = mk();
    const md = settlementMetadata(b, 'pcactn-digest-1');
    const e = { grantDigest: b.grant_digest, pcactnDigest: 'pcactn-digest-1', tokenRef: b.token_ref };
    expect(reconcileNetworkSettlement(e, { metadata: md })).toEqual({ ok: true });
    expect(reconcileNetworkSettlement(e, { metadata: { ...md, pca_pcactn: 'other' } })).toEqual({ ok: false, reasons: ['pcactn_digest_mismatch'] });
    expect(reconcileNetworkSettlement(e, {})).toEqual({ ok: false, reasons: ['pcactn_digest_missing', 'grant_digest_mismatch', 'pcactn_digest_mismatch', 'token_ref_mismatch'] });
  });
});

describe('the charge hands its PCActn digest to settlement automatically (C-283)', () => {
  it('chargeWithNetworkToken derives the metadata from the PCActn it built, and a settlement with that metadata joins', () => {
    const b = mk();
    const c = chargeWithNetworkToken(b, mandate, { merchant: 'm1', amount: 400, category: '5734', now: NOW }, { signerSecret: agent.secretKey, aud: 'rs', counter: 1, now: NOW });
    expect(c.metadata).toEqual({ pca_grant: b.grant_digest, pca_pcactn: c.pcactnDigest, pca_token_ref: b.token_ref });
    expect(reconcileNetworkSettlement({ grantDigest: b.grant_digest, pcactnDigest: c.pcactnDigest, tokenRef: b.token_ref }, { metadata: c.metadata })).toEqual({ ok: true });
  });
  it('a settlement without the PCActn digest is refused, including when the expectation is empty too', () => {
    const b = mk();
    const md = settlementMetadata(b, 'x-digest-1');
    const { pca_pcactn: _drop, ...without } = md;
    expect(reconcileNetworkSettlement({ grantDigest: b.grant_digest, pcactnDigest: 'x-digest-1', tokenRef: b.token_ref }, { metadata: without })).toEqual({ ok: false, reasons: ['pcactn_digest_missing', 'pcactn_digest_mismatch'] });
    expect(reconcileNetworkSettlement({ grantDigest: b.grant_digest, pcactnDigest: '', tokenRef: b.token_ref }, { metadata: { ...md, pca_pcactn: '' } })).toMatchObject({ ok: false });
  });
  it('a binding for another grant cannot start a charge', () => {
    const other = bindNetworkToken({ provider: 'visa_ic', tokenRef: 'tok_abcdef123456', grant: { not: 'it' }, issuerNonce: NONCE, holderSecret: agent.secretKey, holderPublic: agent.publicKey });
    expect(() => chargeWithNetworkToken(other, mandate, { merchant: 'm1', amount: 400, category: '5734', now: NOW }, { signerSecret: agent.secretKey, aud: 'rs', counter: 1, now: NOW })).toThrow(/another grant/);
  });
});

// ---- exact-outcome boundary tests (mutation kill set, T-700..704) ----
const withCheck = (body: string): string => {
  for (let c = 0; c < 10; c++) {
    const d = body + String(c);
    let sum = 0;
    for (let i = 0; i < d.length; i++) {
      let n = Number(d[d.length - 1 - i]);
      if (i % 2 === 1) { n *= 2; if (n > 9) n -= 9; }
      sum += n;
    }
    if (sum % 10 === 0) return d;
  }
  throw new Error('unreachable');
};

describe('PAN detection boundaries (C-280)', () => {
  it('13 to 19 digit Luhn-valid runs are PANs; 12 and 20 are not; a bad check digit is not', () => {
    expect(looksLikePan(withCheck('1'.repeat(11)))).toBe(false); // 12 digits
    expect(looksLikePan(withCheck('4'.repeat(12)))).toBe(true); // 13
    expect(looksLikePan(withCheck('4'.repeat(18)))).toBe(true); // 19
    expect(looksLikePan(withCheck('4'.repeat(19)))).toBe(false); // 20
    const ok = withCheck('4'.repeat(15));
    const bad = ok.slice(0, -1) + String((Number(ok.at(-1)) + 1) % 10);
    expect(looksLikePan(ok)).toBe(true);
    expect(looksLikePan(bad)).toBe(false);
  });
  it('spaces and hyphens are removed, other separators split a run', () => {
    const p = withCheck('4'.repeat(15));
    expect(looksLikePan(`${p.slice(0, 4)} ${p.slice(4, 8)}-${p.slice(8)}`)).toBe(true);
    expect(looksLikePan(`${p.slice(0, 8)}_${p.slice(8)}`)).toBe(false);
    expect(looksLikePan('')).toBe(false);
  });
});

describe('token_ref shape boundaries (C-280)', () => {
  it('8 to 128 characters of the closed alphabet', () => {
    expect(tokenRefError('a'.repeat(7))).toBe('token_ref_malformed');
    expect(tokenRefError('a'.repeat(8))).toBeNull();
    expect(tokenRefError('a'.repeat(128))).toBeNull();
    expect(tokenRefError('a'.repeat(129))).toBe('token_ref_malformed');
    expect(tokenRefError('aaaa.:-_ZZ09')).toBeNull();
    for (const c of [' ', '/', '@', '+', '=', '\n']) expect(tokenRefError(`aaaa${c}aaaa`)).toBe('token_ref_malformed');
    expect(tokenRefError('aaaaaaaa\n')).toBe('token_ref_malformed');
    expect(tokenRefError(12345678)).toBe('token_ref_malformed');
  });
  it('the issuer nonce needs at least 16 characters', () => {
    const mkn = (n: string) => bindNetworkToken({ provider: 'p', tokenRef: 'tok_abcdef123456', grant: {}, issuerNonce: n, holderSecret: agent.secretKey, holderPublic: agent.publicKey });
    expect(() => mkn('a'.repeat(15))).toThrow(/nonce/);
    expect(mkn('a'.repeat(16)).issuer_nonce).toHaveLength(16);
  });
  it('an empty provider never verifies', () => {
    const b = { ...mk(), provider: '' };
    expect(verifyNetworkTokenBinding(b, exp)).toBe('provider_mismatch');
  });
});

describe('the network settlement metadata is exactly the three digests (C-282)', () => {
  it('has fixed keys and carries the binding values', () => {
    const b = mk();
    expect(settlementMetadata(b, 'pc-1')).toEqual({ pca_grant: b.grant_digest, pca_pcactn: 'pc-1', pca_token_ref: b.token_ref });
  });
  it('each mismatch is reported on its own', () => {
    const b = mk();
    const e = { grantDigest: b.grant_digest, pcactnDigest: 'pc-1', tokenRef: b.token_ref };
    const md = settlementMetadata(b, 'pc-1');
    expect(reconcileNetworkSettlement(e, { metadata: { ...md, pca_grant: 'x' } })).toEqual({ ok: false, reasons: ['grant_digest_mismatch'] });
    expect(reconcileNetworkSettlement(e, { metadata: { ...md, pca_token_ref: 'x' } })).toEqual({ ok: false, reasons: ['token_ref_mismatch'] });
  });
});
