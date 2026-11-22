import { describe, expect, it } from 'vitest';
import { authorizePcaGrantToken, buildPcaGrantDetail, oauthScopeForAction } from './index';

describe('buildPcaGrantDetail members', () => {
  it('a minimal detail carries only type, digest and length', () => {
    const d = buildPcaGrantDetail({ chainIds: ['a'] });
    expect(Object.keys(d).sort()).toEqual(['chain_digest', 'chain_len', 'type']);
  });
  it('optional members appear exactly when given, and locations are copied', () => {
    const locations = ['https://rs.example.com'];
    const d = buildPcaGrantDetail({ chainIds: ['a', 'b'], chainRef: 'https://as.example.com/g', bundleRevision: 0, locations });
    expect(Object.keys(d).sort()).toEqual(['bundle_revision', 'chain_digest', 'chain_len', 'chain_ref', 'locations', 'type']);
    expect(d).toMatchObject({ chain_len: 2, chain_ref: 'https://as.example.com/g', bundle_revision: 0, locations });
    expect(d.locations).not.toBe(locations);
    expect(Object.keys(buildPcaGrantDetail({ chainIds: ['a'], bundleRevision: 7 })).sort()).toEqual(['bundle_revision', 'chain_digest', 'chain_len', 'type']);
    expect(Object.keys(buildPcaGrantDetail({ chainIds: ['a'], chainRef: 'https://as.example.com/g' })).sort()).toEqual(['chain_digest', 'chain_len', 'chain_ref', 'type']);
    expect(Object.keys(buildPcaGrantDetail({ chainIds: ['a'], locations })).sort()).toEqual(['chain_digest', 'chain_len', 'locations', 'type']);
  });
});

describe('authorizePcaGrantToken', () => {
  it('malformed details are a 401 invalid_token carrying the parse code', () => {
    expect(authorizePcaGrantToken({ authorizationDetails: 'nope', resource: 'https://rs.example.com', chainIds: ['a'], proofVerified: true })).toEqual({
      allow: false,
      status: 401,
      error: 'invalid_token',
      code: 'not_an_array',
    });
  });
});

describe('oauthScopeForAction', () => {
  const action = { confirmed: true, def_digest: 'd', upstream: { provider: 'p', scopes_min: ['b', 'a', 'a'] } };
  it('joins the sorted unique scopes with single spaces and adds no resource key unless given', () => {
    const r = oauthScopeForAction(action as never, { provider: 'p' });
    expect(r).toStrictEqual({ ok: true, scope: 'a b', scopes: ['a', 'b'] });
    expect(oauthScopeForAction(action as never, { provider: 'p', granted: ['a', 'b'] })).toStrictEqual({ ok: true, scope: 'a b', scopes: ['a', 'b'] });
    expect(oauthScopeForAction(action as never, { provider: 'p', resource: 'https://rs.example.com' })).toStrictEqual({ ok: true, scope: 'a b', scopes: ['a', 'b'], resource: 'https://rs.example.com' });
  });
  it('a scope outside the grant is refused', () => {
    expect(oauthScopeForAction(action as never, { provider: 'p', granted: ['a'] })).toEqual({ ok: false, code: 'exceeds_grant' });
  });
});
