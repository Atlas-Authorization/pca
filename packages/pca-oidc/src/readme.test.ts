import { afterEach, describe, expect, it, vi } from 'vitest';
import { createOidcJwks, oidcPrincipal, verifyIdToken } from './index';
import { baseClaims, makeIssuer, makePrincipalBinding } from './testkit';

afterEach(() => vi.unstubAllGlobals());

describe('README quick start', () => {
  it('verify with the failing-closed resolver, then map to a principal', async () => {
    const idp = await makeIssuer('https://accounts.example.com');
    const bind = makePrincipalBinding();
    vi.stubGlobal('fetch', async (url: string) => {
      expect(url).toBe('https://accounts.example.com/jwks');
      return new Response(JSON.stringify({ keys: [idp.publicJwk] }));
    });
    const idToken = await idp.mint(baseClaims({ issuer: idp.issuer, audience: 'my-client-id', extra: { nonce: 'n1', cnf: bind.cnf } }));

    // --- the README quick start, verbatim ---
    const key = createOidcJwks({ jwksUri: 'https://accounts.example.com/jwks' });
    const claims = await verifyIdToken(idToken, {
      issuer: 'https://accounts.example.com',
      audience: 'my-client-id',
      key,
      nonce: 'n1',
    });
    const principal = oidcPrincipal(claims);
    // --- end ---

    expect(principal.principalId).toBe('https://accounts.example.com#user-123');
    expect(principal.subjectCaveat).toEqual({ type: 'oidc_subject', iss: 'https://accounts.example.com', sub: 'user-123' });
    expect(principal.principalPublic).toBe(bind.principalPublic);
  });
});
