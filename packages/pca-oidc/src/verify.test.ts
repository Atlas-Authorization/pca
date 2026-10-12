import { describe, expect, it } from 'vitest';
import { exportJWK, generateKeyPair, type JWK } from 'jose';
import { discoverOidc, OidcDiscoveryError } from './discovery';
import { OidcVerificationError, verifyIdToken, type OidcVerificationErrorCode } from './verify';
import { baseClaims, makeIssuer, makePrincipalBinding } from './testkit';

const AUD = 'client-abc';

/** Assert a promise rejects with an OidcVerificationError of the given code. */
async function expectCode(p: Promise<unknown>, code: OidcVerificationErrorCode): Promise<void> {
  await expect(p).rejects.toBeInstanceOf(OidcVerificationError);
  await p.catch((e: unknown) => {
    expect(e).toBeInstanceOf(OidcVerificationError);
    if (e instanceof OidcVerificationError) expect(e.code).toBe(code);
  });
}

describe('verifyIdToken', () => {
  it('verifies a well-formed ID token and returns its claims', async () => {
    const idp = await makeIssuer();
    const token = await idp.mint(
      baseClaims({ issuer: idp.issuer, audience: AUD, extra: { email: 'a@b.com', email_verified: true, name: 'Ada' } }),
    );
    const claims = await verifyIdToken(token, { issuer: idp.issuer, audience: AUD, key: idp.publicKey });
    expect(claims.iss).toBe(idp.issuer);
    expect(claims.sub).toBe('user-123');
    expect(claims.aud).toBe(AUD);
    expect(claims.email).toBe('a@b.com');
    expect(claims.email_verified).toBe(true);
    expect(claims.name).toBe('Ada');
    expect(typeof claims.iat).toBe('number');
    expect(typeof claims.exp).toBe('number');
  });

  it('verifies with an injected JWKS resolver (no network)', async () => {
    const idp = await makeIssuer();
    const token = await idp.mint(baseClaims({ issuer: idp.issuer, audience: AUD }));
    // A JWTVerifyGetKey that returns the single local public JWK.
    const claims = await verifyIdToken(token, {
      issuer: idp.issuer,
      audience: AUD,
      key: async () => idp.publicJwk,
    });
    expect(claims.sub).toBe('user-123');
  });

  it('rejects a bad audience', async () => {
    const idp = await makeIssuer();
    const token = await idp.mint(baseClaims({ issuer: idp.issuer, audience: AUD }));
    await expectCode(verifyIdToken(token, { issuer: idp.issuer, audience: 'someone-else', key: idp.publicKey }), 'audience');
  });

  it('rejects a bad issuer', async () => {
    const idp = await makeIssuer();
    const token = await idp.mint(baseClaims({ issuer: idp.issuer, audience: AUD }));
    await expectCode(
      verifyIdToken(token, { issuer: 'https://evil.example.com', audience: AUD, key: idp.publicKey }),
      'issuer',
    );
  });

  it('rejects an expired token', async () => {
    const idp = await makeIssuer();
    const past = Math.floor(Date.now() / 1000) - 7200;
    const token = await idp.mint(baseClaims({ issuer: idp.issuer, audience: AUD, nowSec: past, ttlSec: 3600 }));
    await expectCode(verifyIdToken(token, { issuer: idp.issuer, audience: AUD, key: idp.publicKey }), 'expired');
  });

  it('rejects a token older than maxTokenAgeSec', async () => {
    const idp = await makeIssuer();
    const old = Math.floor(Date.now() / 1000) - 1000;
    const token = await idp.mint(baseClaims({ issuer: idp.issuer, audience: AUD, nowSec: old, ttlSec: 100000 }));
    await expectCode(
      verifyIdToken(token, { issuer: idp.issuer, audience: AUD, key: idp.publicKey, maxTokenAgeSec: 60 }),
      'issued_at',
    );
  });

  it('enforces the nonce when one is expected', async () => {
    const idp = await makeIssuer();
    const good = await idp.mint(baseClaims({ issuer: idp.issuer, audience: AUD, extra: { nonce: 'n-123' } }));
    const claims = await verifyIdToken(good, { issuer: idp.issuer, audience: AUD, key: idp.publicKey, nonce: 'n-123' });
    expect(claims.nonce).toBe('n-123');

    const wrong = await idp.mint(baseClaims({ issuer: idp.issuer, audience: AUD, extra: { nonce: 'other' } }));
    await expectCode(
      verifyIdToken(wrong, { issuer: idp.issuer, audience: AUD, key: idp.publicKey, nonce: 'n-123' }),
      'nonce',
    );

    const missing = await idp.mint(baseClaims({ issuer: idp.issuer, audience: AUD }));
    await expectCode(
      verifyIdToken(missing, { issuer: idp.issuer, audience: AUD, key: idp.publicKey, nonce: 'n-123' }),
      'nonce',
    );
  });

  it('requires azp when there is more than one audience, and checks it', async () => {
    const idp = await makeIssuer();
    const multiNoAzp = await idp.mint(baseClaims({ issuer: idp.issuer, audience: AUD, extra: { aud: [AUD, 'other'] } }));
    await expectCode(verifyIdToken(multiNoAzp, { issuer: idp.issuer, audience: AUD, key: idp.publicKey }), 'azp');

    const multiBadAzp = await idp.mint(
      baseClaims({ issuer: idp.issuer, audience: AUD, extra: { aud: [AUD, 'other'], azp: 'other' } }),
    );
    await expectCode(verifyIdToken(multiBadAzp, { issuer: idp.issuer, audience: AUD, key: idp.publicKey }), 'azp');

    const multiOk = await idp.mint(
      baseClaims({ issuer: idp.issuer, audience: AUD, extra: { aud: [AUD, 'other'], azp: AUD } }),
    );
    const claims = await verifyIdToken(multiOk, { issuer: idp.issuer, audience: AUD, key: idp.publicKey });
    expect(claims.azp).toBe(AUD);
  });

  it('rejects a tampered signature', async () => {
    const idp = await makeIssuer();
    const token = await idp.mint(baseClaims({ issuer: idp.issuer, audience: AUD }));
    const parts = token.split('.');
    const header = parts[0] ?? '';
    const body = parts[1] ?? '';
    const sig = parts[2] ?? '';
    // Flip the first character of the signature segment (stays valid base64url, changes the bytes).
    const flipped = `${sig.slice(0, 1) === 'A' ? 'B' : 'A'}${sig.slice(1)}`;
    const tampered = `${header}.${body}.${flipped}`;
    await expectCode(verifyIdToken(tampered, { issuer: idp.issuer, audience: AUD, key: idp.publicKey }), 'signature');
  });

  it('rejects a token signed by a different (wrong) key', async () => {
    const idp = await makeIssuer();
    const token = await idp.mint(baseClaims({ issuer: idp.issuer, audience: AUD }));
    const { publicKey: otherPub } = await generateKeyPair('EdDSA', { extractable: true });
    await expectCode(verifyIdToken(token, { issuer: idp.issuer, audience: AUD, key: otherPub }), 'signature');
  });

  it('rejects the "none" alg / disallowed algorithms', async () => {
    const idp = await makeIssuer();
    const token = await idp.mint(baseClaims({ issuer: idp.issuer, audience: AUD }));
    // Only permit ES256; the EdDSA token must be refused as an invalid token (JOSEAlgNotAllowed).
    await expectCode(
      verifyIdToken(token, { issuer: idp.issuer, audience: AUD, key: idp.publicKey, algorithms: ['ES256'] }),
      'invalid_token',
    );
  });

  it('rejects a token with no sub', async () => {
    const idp = await makeIssuer();
    const noSub = await idp.mint({ iss: idp.issuer, aud: AUD, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 3600 });
    await expectCode(verifyIdToken(noSub, { issuer: idp.issuer, audience: AUD, key: idp.publicKey }), 'claims');
  });

  it('carries the cnf confirmation claim through verification', async () => {
    const idp = await makeIssuer();
    const binding = makePrincipalBinding();
    const token = await idp.mint(baseClaims({ issuer: idp.issuer, audience: AUD, extra: { cnf: binding.cnf } }));
    const claims = await verifyIdToken(token, { issuer: idp.issuer, audience: AUD, key: idp.publicKey });
    expect(claims.cnf?.jwk?.x).toBe(binding.principalPublic);
  });

  it('throws a config error when no key source is given', async () => {
    const idp = await makeIssuer();
    const token = await idp.mint(baseClaims({ issuer: idp.issuer, audience: AUD }));
    await expectCode(verifyIdToken(token, { issuer: idp.issuer, audience: AUD }), 'config');
  });
});

describe('discoverOidc', () => {
  it('fetches and validates the discovery document with an injected fetch', async () => {
    const issuer = 'https://idp.example.com';
    const meta = { issuer, jwks_uri: `${issuer}/jwks`, authorization_endpoint: `${issuer}/auth` };
    const fakeFetch: typeof fetch = async (input) => {
      expect(String(input)).toBe(`${issuer}/.well-known/openid-configuration`);
      return new Response(JSON.stringify(meta), { status: 200, headers: { 'content-type': 'application/json' } });
    };
    const got = await discoverOidc(issuer, { fetch: fakeFetch });
    expect(got.issuer).toBe(issuer);
    expect(got.jwks_uri).toBe(`${issuer}/jwks`);
    expect(got.authorization_endpoint).toBe(`${issuer}/auth`);
  });

  it('rejects a document whose issuer does not match', async () => {
    const issuer = 'https://idp.example.com';
    const fakeFetch: typeof fetch = async () =>
      new Response(JSON.stringify({ issuer: 'https://evil.example.com', jwks_uri: 'x' }), { status: 200 });
    await expect(discoverOidc(issuer, { fetch: fakeFetch })).rejects.toBeInstanceOf(OidcDiscoveryError);
  });

  it('rejects a non-2xx response', async () => {
    const fakeFetch: typeof fetch = async () => new Response('nope', { status: 404 });
    await expect(discoverOidc('https://idp.example.com', { fetch: fakeFetch })).rejects.toBeInstanceOf(OidcDiscoveryError);
  });

  it('end-to-end: discover the JWKS endpoint, then verify a token against those keys', async () => {
    const idp = await makeIssuer();
    const jwks = { keys: [idp.publicJwk] };
    const token = await idp.mint(baseClaims({ issuer: idp.issuer, audience: AUD }));
    // Fake fetch serves both the discovery doc and the JWKS; the test wires them to verifyIdToken via
    // a key resolver that picks the matching JWK by kid, so no real network is used.
    const fakeFetch: typeof fetch = async (input) => {
      const url = String(input);
      if (url.endsWith('/.well-known/openid-configuration')) {
        return new Response(JSON.stringify({ issuer: idp.issuer, jwks_uri: `${idp.issuer}/jwks` }), { status: 200 });
      }
      if (url === `${idp.issuer}/jwks`) {
        return new Response(JSON.stringify(jwks), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      throw new Error(`unexpected fetch ${url}`);
    };
    const meta = await discoverOidc(idp.issuer, { fetch: fakeFetch });
    expect(meta.jwks_uri).toBe(`${idp.issuer}/jwks`);
    const res = await fakeFetch(meta.jwks_uri);
    const body: unknown = await res.json();
    const keys = (body as { keys?: JWK[] }).keys ?? [];
    const claims = await verifyIdToken(token, {
      issuer: idp.issuer,
      audience: AUD,
      key: async (header) => {
        const match = keys.find((k) => k.kid === header.kid);
        if (match === undefined) throw new Error('no matching key');
        return match;
      },
    });
    expect(claims.sub).toBe('user-123');
    // sanity: exportJWK is available and the IdP public key is exportable
    await exportJWK(idp.publicKey);
  });
});
