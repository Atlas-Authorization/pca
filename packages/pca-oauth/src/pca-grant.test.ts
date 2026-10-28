import { describe, expect, it } from 'vitest';
import { authorizePcaGrantToken, buildPcaGrantDetail, pcaGrantRequestParam, protectedResourceMetadata } from './index';

const RS = 'https://api.example.com';
const ids = ['capA', 'capB'];

describe('pca_grant for authorization servers and resource servers - T-586', () => {
  const detail = buildPcaGrantDetail({ chainIds: ids.slice(0, 1), chainRef: 'https://as.example.com/pca/grants/g1', bundleRevision: 3, locations: [RS] });
  it('builds a detail the profile accepts and a request parameter that round-trips', () => {
    expect(detail).toMatchObject({ type: 'pca_grant', chain_len: 1, bundle_revision: 3 });
    expect(JSON.parse(decodeURIComponent(pcaGrantRequestParam([detail])))).toEqual([detail]);
  });
  it('refuses to build what the profile refuses', () => {
    expect(() => buildPcaGrantDetail({ chainIds: [] })).toThrow(/bad_chain_len/);
    expect(() => buildPcaGrantDetail({ chainIds: ids, chainRef: 'http://x.example' })).toThrow(/bad_chain_ref/);
  });
  it('allows a token whose details name the chain, with a verified proof', () => {
    const r = authorizePcaGrantToken({ authorizationDetails: [{ type: 'other' }, detail], resource: RS, chainIds: ids, proofVerified: true });
    expect(r).toEqual({ allow: true, detail });
  });
  it('the token alone is never sufficient', () => {
    const r = authorizePcaGrantToken({ authorizationDetails: [detail], resource: RS, chainIds: ids, proofVerified: false });
    expect(r).toEqual({ allow: false, status: 401, error: 'invalid_token', code: 'proof_required' });
  });
  it('a token for another chain is 401, for another location 403, malformed details 401', () => {
    expect(authorizePcaGrantToken({ authorizationDetails: [detail], resource: RS, chainIds: ['zzz'], proofVerified: true })).toMatchObject({ allow: false, status: 401, code: 'chain_mismatch' });
    expect(authorizePcaGrantToken({ authorizationDetails: [detail], resource: 'https://other.example.com', chainIds: ids, proofVerified: true })).toMatchObject({ allow: false, status: 403, error: 'insufficient_scope', code: 'wrong_location' });
    expect(authorizePcaGrantToken({ authorizationDetails: 'nope', resource: RS, chainIds: ids, proofVerified: true })).toMatchObject({ allow: false, status: 401, code: 'not_an_array' });
    expect(authorizePcaGrantToken({ authorizationDetails: [], resource: RS, chainIds: ids, proofVerified: true })).toMatchObject({ allow: false, status: 401, code: 'no_detail' });
  });
  it('the protected resource metadata can advertise the type (RFC 9728)', () => {
    const prm = protectedResourceMetadata({ resource: RS, authorizationDetailsTypesSupported: ['pca_grant'] });
    expect(prm.authorization_details_types_supported).toEqual(['pca_grant']);
    expect(protectedResourceMetadata({ resource: RS }).authorization_details_types_supported).toBeUndefined();
  });
});

describe('end to end: an OAuth server carries the grant, the resource server still verifies the proof - T-586', () => {
  it('introspection-shaped token + real PCActn: allowed; same token + a proof for another grant: denied', async () => {
    const { agent, generateKeyPair, verifyPCActnCore } = await import('@atlasauth/pca');
    const aud = 'https://api.example.com';
    const mk = () => agent({ principal: generateKeyPair(), goal: 'tickets', permissions: { tickets: ['write'] }, aud });
    const a = mk();
    const b = mk();
    const ids = (p: { cap_chain: Array<{ id: string }> }) => p.cap_chain.map((c) => c.id);
    const proofA = a.act('write', 'tickets/1', { aud }).pcactn;
    // what the authorization server stored when it issued the token for agent A's grant
    const introspection = { active: true, authorization_details: [buildPcaGrantDetail({ chainIds: ids(proofA).slice(0, 1), locations: [aud] })] };
    const verified = async (p: typeof proofA, who: typeof a) => (await verifyPCActnCore(p, { insecureSkipPlanRootCheck: true, grant: who.grant, audience: aud })).allow;

    expect(authorizePcaGrantToken({ authorizationDetails: introspection.authorization_details, resource: aud, chainIds: ids(proofA), proofVerified: await verified(proofA, a) })).toMatchObject({ allow: true });
    // the token is good, but B's proof names another chain: the token cannot be lent to a different agent
    const proofB = b.act('write', 'tickets/1', { aud }).pcactn;
    expect(authorizePcaGrantToken({ authorizationDetails: introspection.authorization_details, resource: aud, chainIds: ids(proofB), proofVerified: await verified(proofB, b) })).toMatchObject({ allow: false, code: 'chain_mismatch' });
    // and a tampered proof of A's chain is not a verified proof
    const forged = { ...proofA, counter: proofA.counter + 1 };
    expect(authorizePcaGrantToken({ authorizationDetails: introspection.authorization_details, resource: aud, chainIds: ids(forged), proofVerified: await verified(forged, a) })).toMatchObject({ allow: false, code: 'proof_required' });
  });
});

describe('OAuth scopes derived from the confirmed action - T-592', () => {
  const act = { verb: 'mail.send', def_digest: 'd'.repeat(43), confirmed: true, upstream: { provider: 'google', scopes_min: ['gmail.send', 'gmail.send'] } };
  it('requests exactly the action scopes, deduplicated and sorted, inside the grant', async () => {
    const { oauthScopeForAction } = await import('./index');
    expect(oauthScopeForAction(act, { provider: 'google', granted: ['gmail.send', 'gmail.readonly'], resource: 'https://gmail.example' })).toEqual({ ok: true, scope: 'gmail.send', scopes: ['gmail.send'], resource: 'https://gmail.example' });
  });
  it('nothing is requested for an unconfirmed, unknown, mismatched, empty, malformed or over-grant action', async () => {
    const { oauthScopeForAction } = await import('./index');
    expect(oauthScopeForAction({ ...act, confirmed: false }, { provider: 'google' })).toEqual({ ok: false, code: 'unconfirmed' });
    expect(oauthScopeForAction({ ...act, confirmed: 'true' as never }, { provider: 'google' })).toEqual({ ok: false, code: 'unconfirmed' });
    expect(oauthScopeForAction(undefined, { provider: 'google' })).toEqual({ ok: false, code: 'unknown_action' });
    expect(oauthScopeForAction(act, { provider: 'slack' })).toEqual({ ok: false, code: 'provider_mismatch' });
    expect(oauthScopeForAction({ ...act, upstream: { provider: 'google', scopes_min: [] } }, { provider: 'google' })).toEqual({ ok: false, code: 'no_scopes' });
    expect(oauthScopeForAction({ ...act, upstream: { provider: 'google', scopes_min: ['a b'] } }, { provider: 'google' })).toEqual({ ok: false, code: 'bad_scope' });
    expect(oauthScopeForAction(act, { provider: 'google', granted: ['gmail.readonly'] })).toEqual({ ok: false, code: 'exceeds_grant' });
  });
});
