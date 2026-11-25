import type { VaultFetch } from '@atlasauth/pca-connect';
import { InMemoryConnectionStore } from '@atlasauth/pca-connect/testing';
import { TokenVault } from '@atlasauth/pca-connect';
import { describe, expect, it } from 'vitest';
import {
  ConnectorError,
  ProviderRegistry,
  applyAccessToken,
  assertManifest,
  buildAuthorizeUrl,
  catalogDigest,
  createDefaultRegistry,
  exchangeCode,
  manifestDigest,
  refresh,
  substituteVars,
  validateManifest,
} from './index';

const REG = createDefaultRegistry();
const ALL = REG.list();
const BASE = { clientId: 'cid', redirectUri: 'https://app.example/cb' };
const good = () => ({ ...REG.require('github') });
const issues = (m: object) => {
  const r = validateManifest(m);
  return r.ok ? [] : r.issues;
};

describe('the built-in catalog is pinned', () => {
  it('every manifest and the whole catalog have a digest that changes with any field', () => {
    expect(catalogDigest(REG)).toBe(PINNED_CATALOG);
    const g = REG.require('google');
    expect(manifestDigest({ ...g, displayName: 'Evil' })).not.toBe(manifestDigest(g));
    expect(manifestDigest({ ...g, tokenUrl: 'https://evil.example/token' })).not.toBe(manifestDigest(g));
    expect(catalogDigest(createDefaultRegistry())).toBe(catalogDigest(REG));
  });
  it('the registry refuses to swap a registered provider silently', () => {
    const r = createDefaultRegistry();
    const evil = { ...r.require('google'), tokenUrl: 'https://evil.example/token' };
    expect(() => r.register(evil)).toThrow("provider 'google' is already registered; pass { replace: true } to replace it deliberately");
    expect(r.require('google').tokenUrl).toBe('https://oauth2.googleapis.com/token');
    expect(r.register(evil, { replace: true }).tokenUrl).toBe('https://evil.example/token');
  });
  it('a pinned digest accepts the reviewed manifest and refuses another', () => {
    const r = new ProviderRegistry();
    const m = good();
    expect(() => r.register({ ...m, displayName: 'Changed' }, { expectedDigest: manifestDigest(m) })).toThrow("manifest 'github' does not match the pinned digest");
    expect(r.register(m, { expectedDigest: manifestDigest(m) }).id).toBe('github');
  });
  it('a registered manifest cannot be edited through the returned object', () => {
    const r = new ProviderRegistry();
    r.register(good());
    expect(() => { (r.require('github') as { tokenUrl: string }).tokenUrl = 'https://evil.example'; }).toThrow();
  });
});

describe('manifest validation', () => {
  it.each([
    ['userinfo in a url', { tokenUrl: 'https://user:pw@host.example/token' }, 'tokenUrl must be an https:// URL'],
    ['a placeholder that is the whole host', { authorizeUrl: 'https://{host}/a', tokenUrl: 'https://{host}/t', requiredVars: ['host'] }, 'authorizeUrl must be an https:// URL'],
    ['a fragment', { authorizeUrl: 'https://a.example/x#frag' }, 'authorizeUrl must be an https:// URL'],
    ['http', { tokenUrl: 'http://a.example/t' }, 'tokenUrl must be an https:// URL'],
    ['a scope with a space', { scopesAvailable: ['a b'], defaultScopes: [] }, 'scopesAvailable entries must be non-empty and contain no whitespace or comma (a separator inside a scope would smuggle in another scope)'],
    ['a scope with a comma', { scopesAvailable: ['a,b'], defaultScopes: [] }, 'scopesAvailable entries must be non-empty and contain no whitespace or comma (a separator inside a scope would smuggle in another scope)'],
    ['an empty scope', { scopesAvailable: [''], defaultScopes: [] }, 'scopesAvailable entries must be non-empty and contain no whitespace or comma (a separator inside a scope would smuggle in another scope)'],
    ['duplicate scopes', { scopesAvailable: ['a', 'a'], defaultScopes: ['a'] }, 'scopesAvailable must not contain duplicates'],
    ['a reserved authParam', { authParams: { state: 'fixed' } }, "authParams may not set 'state': the request builder owns it"],
    ['a reserved refresh param', { refresh: { mode: 'refresh_token', extraParams: { grant_type: 'x' } } }, "refresh.extraParams may not set 'grant_type': the request builder owns it"],
    ['a protocol header name', { tokenPlacement: 'header', headerName: 'Host' }, "headerName 'Host' must be an HTTP token and not a protocol header"],
    ['a header name with a newline', { tokenPlacement: 'header', headerName: 'X-Token\nX-Evil' }, "headerName 'X-Token\nX-Evil' must be an HTTP token and not a protocol header"],
    ['a query param with an ampersand', { tokenPlacement: 'query', queryParam: 'a&b=c' }, "queryParam 'a&b=c' must be a plain parameter name"],
    ['an empty scope separator', { scopeSeparator: '' }, 'scopeSeparator must not be empty'],
  ])('refuses %s', (_n, patch, why) => {
    expect(issues({ ...good(), ...patch })).toContain(why);
  });
  it('every built-in manifest passes', () => {
    for (const m of ALL) expect(issues(m), m.id).toEqual([]);
  });
  it('a non-object, null and arrays are not manifests', () => {
    for (const x of [null, undefined, 5, 'x', [], [good()]]) expect(validateManifest(x).ok).toBe(false);
    expect(() => assertManifest(null)).toThrow('invalid provider manifest: manifest must be an object');
  });
  it('the manifest carries no secrets: no field of a built-in looks like a credential', () => {
    for (const m of ALL) expect(JSON.stringify(m), m.id).not.toMatch(/client_secret|password|api[_-]?key|eyJ[\w-]{10,}\./i);
  });
});

describe('URL variables cannot move a request to another host', () => {
  it.each([['evil.com/x?'], ['a.b'], ['a/b'], ['a#b'], ['a@b'], ['a b'], ['-a'], [''], ['a'.repeat(64)], ['a:443'], ['%2e%2e'], ['a\nb']])('%j is refused', (v) => {
    expect(() => substituteVars('https://{shop}.myshopify.com/x', { shop: v })).toThrow("URL variable '{shop}' must be a single DNS label (letters, digits and hyphens)");
  });
  it('a single DNS label is accepted', () => {
    expect(substituteVars('https://{shop}.myshopify.com/x', { shop: 'acme-1' })).toBe('https://acme-1.myshopify.com/x');
  });
  it('a missing variable, an inherited one and a non-string are refused', () => {
    expect(() => substituteVars('https://{shop}.x.com', {})).toThrow("missing URL variable '{shop}'");
    expect(() => substituteVars('https://{toString}.x.com', {})).toThrow("missing URL variable '{toString}'");
    expect(() => substituteVars('https://{shop}.x.com', { shop: 5 as never })).toThrow('must be a single DNS label');
  });
  it('the authorize URL and the token exchange both apply the rule', async () => {
    expect(() => buildAuthorizeUrl('shopify', { ...BASE, vars: { shop: 'evil.com/x?' } })).toThrow('single DNS label');
    await expect(
      exchangeCode({ providerId: 'shopify', clientId: 'c', code: 'abc', redirectUri: 'https://app.example/cb', vars: { shop: 'evil.com/x?' }, fetch: async () => ({ ok: true, status: 200, json: async () => ({}), text: async () => '' }), bind: { vault: new TokenVault({ strict: false, insecureBearerRelease: true, store: new InMemoryConnectionStore() }), agentId: 'a', authority: { principal: 'p' } } }),
    ).rejects.toThrow('single DNS label');
  });
});

describe('the authorize request', () => {
  const bad = (opts: object) => () => buildAuthorizeUrl('github', { ...BASE, ...opts } as never);
  it('refuses a redirect uri that is not absolute, has a fragment or credentials, or is plain http off localhost', () => {
    for (const redirectUri of ['', 'cb', '/cb', 'javascript:alert(1)', 'https://a.example/cb#x', 'https://u:p@a.example/cb', 'http://a.example/cb']) {
      expect(bad({ redirectUri }), redirectUri).toThrow('buildAuthorizeUrl: redirectUri');
    }
    expect(() => buildAuthorizeUrl('github', { ...BASE, redirectUri: 'http://localhost:3000/cb' })).not.toThrow();
    expect(() => buildAuthorizeUrl('github', { ...BASE, redirectUri: 'http://127.0.0.1/cb' })).not.toThrow();
  });
  it('refuses an empty client id', () => {
    expect(bad({ clientId: '' })).toThrow('buildAuthorizeUrl: clientId must be a non-empty string');
  });
  it('a caller-supplied state must be long enough to be a CSRF token; none gives a random one', () => {
    expect(bad({ state: 'abc' })).toThrow('buildAuthorizeUrl: state must be at least 16 characters (omit it to get a random one)');
    expect(bad({ state: '' })).toThrow('state must be at least 16 characters');
    expect(buildAuthorizeUrl('github', { ...BASE, state: 'a'.repeat(16) }).state).toBe('a'.repeat(16));
    const a = buildAuthorizeUrl('github', BASE).state;
    expect(a.length).toBeGreaterThanOrEqual(43);
    expect(buildAuthorizeUrl('github', BASE).state).not.toBe(a);
  });
  it('extraParams cannot override what the builder owns', () => {
    for (const k of ['client_id', 'redirect_uri', 'scope', 'state', 'response_type', 'code_challenge', 'code_challenge_method']) {
      expect(bad({ extraParams: { [k]: 'x' } }), k).toThrow(`buildAuthorizeUrl: extraParams may not set '${k}'`);
    }
    expect(buildAuthorizeUrl('github', { ...BASE, extraParams: { login: 'octocat' } }).url).toContain('login=octocat');
  });
  it('PKCE: the verifier must be RFC 7636 shaped, and plain is refused unless allowed', () => {
    for (const verifier of ['short', 'x'.repeat(129), `${'a'.repeat(42)} `, `${'a'.repeat(42)}!`]) {
      expect(bad({ pkce: { verifier } }), verifier).toThrow('the PKCE verifier must be 43 to 128 unreserved characters (RFC 7636)');
    }
    const v = 'a'.repeat(43);
    expect(bad({ pkce: { verifier: v, method: 'plain' } })).toThrow("PKCE method must be 'S256' (pass allowPlainPkce to use 'plain')");
    expect(buildAuthorizeUrl('github', { ...BASE, pkce: { verifier: v, method: 'plain' }, allowPlainPkce: true }).pkce?.method).toBe('plain');
  });
});

describe('scopes: least privilege per provider', () => {
  it.each(ALL.map((m) => [m.id]))('%s: the default scopes build, an unlisted scope is refused, a separator cannot smuggle a scope', (id) => {
    const m = REG.require(id);
    const sep = m.scopeSeparator ?? ' ';
    const a = buildAuthorizeUrl(id, { ...BASE, registry: REG, vars: { shop: 'acme', account: 'acme' } });
    const scope = new URL(a.url).searchParams.get('scope');
    if (m.defaultScopes.length > 0) expect(scope).toBe(m.defaultScopes.join(sep));
    if (m.scopesAvailable.length > 0) expect(() => buildAuthorizeUrl(id, { ...BASE, registry: REG, vars: { shop: 'acme', account: 'acme' }, scopes: ['not-a-listed-scope'] })).toThrow("is not offered by provider");
    expect(() => buildAuthorizeUrl(id, { ...BASE, registry: REG, vars: { shop: 'acme', account: 'acme' }, scopes: [`${m.scopesAvailable[0] ?? 'x'}${sep}admin`] })).toThrow('without whitespace, commas or the separator');
    if (m.scopesAvailable.length > 1) expect(() => buildAuthorizeUrl(id, { ...BASE, registry: REG, vars: { shop: 'acme', account: 'acme' }, scopes: [m.scopesAvailable[0]!, m.scopesAvailable[0]!] })).toThrow('is listed twice');
    expect(new URL(buildAuthorizeUrl(id, { ...BASE, registry: REG, vars: { shop: 'acme', account: 'acme' }, scopes: ['custom-scope'], allowUnlistedScopes: true }).url).searchParams.get('scope')).toBe('custom-scope');
  });
  it('a refresh sends a scope parameter exactly when the manifest supports narrowing, joined with its separator', async () => {
    for (const m of ALL.filter((x) => x.refresh.mode === 'refresh_token')) {
      const bodies: string[] = [];
      const fetch: VaultFetch = async (_u, init) => (bodies.push(init.body), { ok: true, status: 200, json: async () => ({ access_token: 'AT', expires_in: 60 }), text: async () => '' });
      const vault = new TokenVault({ strict: false, insecureBearerRelease: true, store: new InMemoryConnectionStore() });
      const scopes = m.scopesAvailable.slice(0, 2);
      await refresh({ providerId: m.id, clientId: 'c', clientSecret: 'cs-0123456789', refreshToken: 'RT', scopes, fetch, vars: { shop: 'acme', account: 'acme' }, registry: REG, bind: { vault, agentId: 'a', authority: { principal: 'p' } } });
      const p = new URLSearchParams(bodies[0]);
      if (m.refresh.supportsScopeNarrowing === true) expect(p.get('scope'), m.id).toBe(scopes.join(m.scopeSeparator ?? ' '));
      else expect(p.has('scope'), m.id).toBe(false);
    }
  });
});

describe('the access token on an outbound request', () => {
  it.each([['abc\r\nX-Evil: 1'], ['a b'], ['a\tb'], [''], ['tok\u0000'], ['tökén']])('%j is refused', (t) => {
    expect(() => applyAccessToken(REG.require('github'), t)).toThrow('applyAccessToken: the access token must be a non-empty string of printable ASCII without spaces');
  });
  it('placements', () => {
    expect(applyAccessToken(REG.require('github'), 'tok')).toEqual({ kind: 'header', name: 'Authorization', value: 'Bearer tok' });
    expect(applyAccessToken(assertManifest({ ...good(), id: 'h', tokenPlacement: 'header', headerName: 'X-Api-Token' }), 'tok')).toEqual({ kind: 'header', name: 'X-Api-Token', value: 'tok' });
    expect(applyAccessToken(assertManifest({ ...good(), id: 'q', tokenPlacement: 'query', queryParam: 'access_token' }), 'tok')).toEqual({ kind: 'query', name: 'access_token', value: 'tok' });
  });
});

describe('the token exchange', () => {
  const vault = () => new TokenVault({ strict: false, insecureBearerRelease: true, store: new InMemoryConnectionStore() });
  const bind = () => ({ vault: vault(), agentId: 'a', authority: { principal: 'p' } });
  const ok = (body: unknown): VaultFetch => async () => ({ ok: true, status: 200, json: async () => body, text: async () => '' });
  it('refuses an empty code or refresh token and reserved extra parameters', async () => {
    await expect(exchangeCode({ providerId: 'github', clientId: 'c', code: '', redirectUri: 'https://a.example/cb', fetch: ok({}), bind: bind() })).rejects.toThrow('[github] an authorization code is required');
    await expect(refresh({ providerId: 'google', clientId: 'c', refreshToken: '', fetch: ok({}), bind: bind() })).rejects.toThrow('[google] a refresh token is required');
    for (const k of ['grant_type', 'client_id', 'redirect_uri', 'code', 'client_secret', 'code_verifier', 'refresh_token']) {
      await expect(exchangeCode({ providerId: 'github', clientId: 'c', code: 'x', redirectUri: 'https://a.example/cb', extraParams: { [k]: 'y' }, fetch: ok({}), bind: bind() }), k).rejects.toThrow(`exchangeCode: extraParams may not set '${k}'`);
    }
  });
  it('a provider error or transport error that echoes the code, the secret or the verifier is redacted', async () => {
    const echo: VaultFetch = async (_u, init) => ({ ok: false, status: 400, json: async () => ({}), text: async () => `bad request: ${init.body}` });
    const err = await exchangeCode({ providerId: 'github', clientId: 'cid', clientSecret: 'S3CR3T-value', code: 'CODE-123456', codeVerifier: 'V'.repeat(43), redirectUri: 'https://a.example/cb', fetch: echo, bind: bind() }).then(() => new Error('did not throw'), (e: Error) => e);
    expect(err).toBeInstanceOf(ConnectorError);
    for (const s of ['S3CR3T-value', 'CODE-123456', 'V'.repeat(43)]) expect(err.message).not.toContain(s);
    expect(err.message).toContain('[redacted]');
    const boom: VaultFetch = async (_u, init) => { throw new Error(`connect failed: ${init.body}`); };
    const err2 = await refresh({ providerId: 'google', clientId: 'cid', clientSecret: 'S3CR3T-value', refreshToken: 'RT-987654', fetch: boom, bind: bind() }).then(() => new Error('did not throw'), (e: Error) => e);
    expect(err2.message).not.toMatch(/S3CR3T-value|RT-987654/);
  });
  it('an unparseable body is reported without quoting it', async () => {
    const f: VaultFetch = async () => ({ ok: true, status: 200, json: async () => JSON.parse('{"access_token":"LEAKED-TOKEN-1234" oops'), text: async () => '' });
    const err = await exchangeCode({ providerId: 'github', clientId: 'c', code: 'x', redirectUri: 'https://a.example/cb', fetch: f, bind: bind() }).then(() => new Error('did not throw'), (e: Error) => e);
    expect(err.message).toBe('[github] unparseable token JSON');
  });
  it('a response with no access token is refused', async () => {
    for (const body of [null, [], {}, { access_token: '' }, { access_token: 5 }]) {
      await expect(exchangeCode({ providerId: 'github', clientId: 'c', code: 'x', redirectUri: 'https://a.example/cb', fetch: ok(body), bind: bind() })).rejects.toBeInstanceOf(ConnectorError);
    }
  });
});

const PINNED_CATALOG = 'vfIUoAS_qLiGRn-fZ4qn3CZTpkk-REkVjXI5BY_dnaU';
