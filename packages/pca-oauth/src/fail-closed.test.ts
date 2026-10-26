import { describe, expect, it } from 'vitest';
import {
  checkResourceIndicator,
  checkTokenAudience,
  oauthDiscoveryHandler,
  parseProtectedResourceMetadata,
  prmPathForResource,
  prmUrlForResource,
  protectedResourceMetadata,
  resourceIdentifierProblem,
  upgradeUnauthorizedChallenge,
  wwwAuthenticate,
} from './index';

/** Settle a sync call into `{ok, value|message}` so each row asserts the whole outcome. */
function settle<T>(f: () => T): { ok: true; value: T } | { ok: false; message: string } {
  try {
    return { ok: true, value: f() };
  } catch (e) {
    return { ok: false, message: (e as Error).message };
  }
}

// RFC 9728 section 3.2 example metadata (the standard members).
const RFC_EXAMPLE = {
  resource: 'https://resource.example.com',
  authorization_servers: ['https://as1.example.com', 'https://as2.example.net'],
  bearer_methods_supported: ['header', 'body'],
  scopes_supported: ['profile', 'email', 'phone'],
  resource_documentation: 'https://resource.example.com/resource_documentation.html',
};

describe('RFC 9728 examples', () => {
  it('section 3.2: our document carries exactly the example standard members', () => {
    const prm = protectedResourceMetadata({
      resource: 'https://resource.example.com',
      authorizationServers: ['https://as1.example.com', 'https://as2.example.net'],
      bearerMethodsSupported: ['header', 'body'],
      scopesSupported: ['profile', 'email', 'phone'],
      resourceDocumentation: 'https://resource.example.com/resource_documentation.html',
      strict: true,
    });
    const standard = Object.fromEntries(Object.entries(prm).filter(([k]) => !k.startsWith('pca')));
    expect(standard).toEqual(RFC_EXAMPLE);
  });
  it('section 3.1: well-known URI insertion', () => {
    expect(prmPathForResource('https://resource.example.com')).toBe('/.well-known/oauth-protected-resource');
    expect(prmPathForResource('https://resource.example.com/')).toBe('/.well-known/oauth-protected-resource');
    expect(prmPathForResource('https://resource.example.com/resource1')).toBe('/.well-known/oauth-protected-resource/resource1');
    expect(prmUrlForResource('https://resource.example.com/resource1')).toBe(
      'https://resource.example.com/.well-known/oauth-protected-resource/resource1',
    );
    expect(prmUrlForResource('https://resource.example.com')).toBe('https://resource.example.com/.well-known/oauth-protected-resource');
    expect(settle(() => prmPathForResource('http://resource.example.com'))).toEqual({
      ok: false,
      message: 'prmPathForResource: resource identifier must use the https scheme',
    });
  });
  it('section 5.1: the challenge, without the PCA addition, is the RFC value', () => {
    expect(wwwAuthenticate('https://resource.example.com/.well-known/oauth-protected-resource', { includePca: false })).toBe(
      'Bearer resource_metadata="https://resource.example.com/.well-known/oauth-protected-resource"',
    );
  });
  it('the handler reports the RFC path next to the historical constant', () => {
    const h = oauthDiscoveryHandler({ resource: 'https://resource.example.com/resource1' });
    expect([h.path, h.rfcPath]).toEqual(['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/resource1']);
    expect(oauthDiscoveryHandler({ resource: 'not a url' }).rfcPath).toBe('/.well-known/oauth-protected-resource');
  });
  it('the PCA parser refuses a document that has only the standard members', () => {
    expect(settle(() => parseProtectedResourceMetadata(RFC_EXAMPLE))).toEqual({
      ok: false,
      message: 'parseProtectedResourceMetadata: missing pca_action_header',
    });
  });
});

describe('resource identifier rows (RFC 9728 1.2)', () => {
  it('table', () => {
    expect(resourceIdentifierProblem('https://api.acme.com')).toBeUndefined();
    expect(resourceIdentifierProblem('https://api.acme.com/mcp?x=1')).toBeUndefined();
    expect(resourceIdentifierProblem('')).toBe('resource identifier must be a non-empty string');
    expect(resourceIdentifierProblem(5)).toBe('resource identifier must be a non-empty string');
    expect(resourceIdentifierProblem('api.acme.com')).toBe('resource identifier is not an absolute URL');
    expect(resourceIdentifierProblem('http://api.acme.com')).toBe('resource identifier must use the https scheme');
    expect(resourceIdentifierProblem('https://api.acme.com/#frag')).toBe('resource identifier must not contain a fragment');
    expect(resourceIdentifierProblem('https://api.acme.com#')).toBe('resource identifier must not contain a fragment');
  });
  it('strict metadata construction refuses them; the default does not', () => {
    expect(settle(() => protectedResourceMetadata({ resource: 'http://x.example', strict: true }))).toEqual({
      ok: false,
      message: 'protectedResourceMetadata: resource identifier must use the https scheme',
    });
    expect(settle(() => protectedResourceMetadata({ resource: 'http://x.example' })).ok).toBe(true);
  });
});

describe('parse: the document must be the one asked for (RFC 9728 3.3)', () => {
  const doc = () => JSON.parse(JSON.stringify(protectedResourceMetadata({ resource: 'https://api.acme.com' })));
  it('rows', () => {
    expect(settle(() => parseProtectedResourceMetadata(doc(), { expectedResource: 'https://api.acme.com' })).ok).toBe(true);
    expect(settle(() => parseProtectedResourceMetadata(doc(), { expectedResource: 'https://evil.example' }))).toEqual({
      ok: false,
      message: 'parseProtectedResourceMetadata: `resource` does not match the expected resource identifier',
    });
    const d = doc();
    d.pca.audience = 'https://other.example';
    expect(settle(() => parseProtectedResourceMetadata(d, { expectedResource: 'https://api.acme.com' }))).toEqual({
      ok: false,
      message: 'parseProtectedResourceMetadata: embedded pca.audience does not match the expected resource identifier',
    });
    // trailing slash is NOT the same identifier
    expect(settle(() => parseProtectedResourceMetadata(doc(), { expectedResource: 'https://api.acme.com/' })).ok).toBe(false);
    const bm = doc();
    bm.bearer_methods_supported = ['cookie'];
    expect(settle(() => parseProtectedResourceMetadata(bm, { strict: true }))).toEqual({
      ok: false,
      message: 'parseProtectedResourceMetadata: bearer_methods_supported has a value outside header/body/query',
    });
    expect(settle(() => parseProtectedResourceMetadata(bm)).ok).toBe(true);
    const http = doc();
    http.resource = 'http://api.acme.com';
    expect(settle(() => parseProtectedResourceMetadata(http, { strict: true }))).toEqual({
      ok: false,
      message: 'parseProtectedResourceMetadata: resource identifier must use the https scheme',
    });
  });
});

describe('token-audience binding', () => {
  const R = 'https://api.acme.com';
  it('rows', () => {
    expect(checkTokenAudience(R, R)).toEqual({ ok: true, matched: R });
    expect(checkTokenAudience(['https://other.example', R], R)).toEqual({ ok: true, matched: R });
    expect(checkTokenAudience(undefined, R)).toEqual({ ok: false, reason: 'token has no audience' });
    expect(checkTokenAudience(null, R)).toEqual({ ok: false, reason: 'token has no audience' });
    expect(checkTokenAudience([], R)).toEqual({ ok: false, reason: 'token has an empty audience' });
    expect(checkTokenAudience('https://other.example', R)).toEqual({
      ok: false,
      reason: 'token audience "https://other.example" does not include resource "https://api.acme.com"',
    });
    // exact match only: trailing slash, case, prefix, non-string
    for (const bad of [R + '/', 'HTTPS://API.ACME.COM', R + '/mcp', 'https://api.acme', 7, { a: R }, [R + '/']]) {
      expect(checkTokenAudience(bad, R).ok).toBe(false);
    }
    expect(settle(() => checkTokenAudience(R, ''))).toEqual({ ok: false, message: 'checkTokenAudience: expectedResource is required' });
  });
  it('resource indicators: same exactness, empty/typed junk skipped', () => {
    expect(checkResourceIndicator([7 as never, '', R], R)).toEqual({ ok: true, matched: R });
    expect(checkResourceIndicator(R + '/', R).ok).toBe(false);
    expect(checkResourceIndicator([], R)).toEqual({ ok: false, reason: 'empty resource indicator' });
    expect(checkResourceIndicator(undefined, R)).toEqual({ ok: false, reason: 'no resource indicator presented' });
  });
});

describe('header injection', () => {
  const P = 'https://api.acme.com/.well-known/oauth-protected-resource';
  const msg = 'pca-oauth: WWW-Authenticate parameter value may not contain a quote or newline';
  it('rows', () => {
    for (const bad of ['a"b', 'a\\', 'a\r\nSet-Cookie: x=1', 'a\nb', 'a\u0000b', 'a\u007fb']) {
      expect(settle(() => wwwAuthenticate(bad))).toEqual({ ok: false, message: msg });
      expect(settle(() => wwwAuthenticate(P, { error: bad }))).toEqual({ ok: false, message: msg });
      expect(settle(() => wwwAuthenticate(P, { errorDescription: bad }))).toEqual({ ok: false, message: msg });
      expect(settle(() => wwwAuthenticate(P, { scope: bad }))).toEqual({ ok: false, message: msg });
      expect(settle(() => wwwAuthenticate(P, { realm: bad }))).toEqual({ ok: false, message: msg });
      expect(settle(() => wwwAuthenticate(P, { hint: bad }))).toEqual({ ok: false, message: msg });
    }
  });
  it('an upstream PCA challenge with a newline cannot be smuggled into the header', () => {
    const cr = 'PCA realm="pca"\r\nSet-Cookie: x=1';
    const m = 'pca-oauth: pcaChallenge may not contain control characters or newlines';
    expect(settle(() => wwwAuthenticate(P, { pcaChallenge: cr }))).toEqual({ ok: false, message: m });
    expect(settle(() => upgradeUnauthorizedChallenge({ wwwAuthenticate: cr }, P))).toEqual({ ok: false, message: m });
    expect(wwwAuthenticate(P, { pcaChallenge: 'PCA realm="pca", hint="a\tb"' })).toBe(`Bearer resource_metadata="${P}", PCA realm="pca", hint="a\tb"`);
  });
});
