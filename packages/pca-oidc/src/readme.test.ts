import { describe, expect, it } from 'vitest';
import { createOidcJwks, oidcPrincipal, verifyIdToken } from './index';
import { baseClaims, makeIssuer, makePrincipalBinding } from './testkit';

describe('README quick start', () => {
  it('verify with the failing-closed resolver, then map to a principal', async () => {
    const idp = await makeIssuer('https://accounts.example.com');
    const bind = makePrincipalBinding();
    const fetchFn = async () => new Response(JSON.stringify({ keys: [idp.publicJwk] }));
    const key = createOidcJwks({ jwksUri: 'https://accounts.example.com/jwks', fetch: fetchFn as never });
    const t = await idp.mint(baseClaims({ issuer: idp.issuer, audience: 'my-client-id', extra: { nonce: 'n1', cnf: bind.cnf } }));
    const claims = await verifyIdToken(t, { issuer: idp.issuer, audience: 'my-client-id', key, nonce: 'n1' });
    const p = oidcPrincipal(claims);
    expect(p.principalId).toBe('https://accounts.example.com#user-123');
    expect(p.principalPublic).toBe(bind.principalPublic);
  });
});
