import { describe, expect, it } from 'vitest';
import {
  type ProviderManifest,
  ConnectorError,
  ManifestValidationError,
  ProviderRegistry,
  UnknownProviderError,
  applyAccessToken,
  assertManifest,
  buildAuthorizeUrl,
  buildVaultProviders,
  exchangeCode,
  manifestToProviderConfig,
  pkceChallenge,
  refresh,
  validateManifest,
} from './index';

const base = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  id: 'p',
  displayName: 'P',
  authorizeUrl: 'https://a.example/auth',
  tokenUrl: 'https://a.example/token',
  scopesAvailable: ['a', 'b'],
  defaultScopes: ['a'],
  refresh: { mode: 'refresh_token' },
  tokenPlacement: 'bearer',
  ...over,
});
const regOf = (over: Record<string, unknown> = {}): ProviderRegistry => {
  const r = new ProviderRegistry();
  r.register(base(over));
  return r;
};
const issues = (over: Record<string, unknown>): string[] => {
  const v = validateManifest(base(over));
  return v.ok ? [] : v.issues;
};
const throwsMsg = (fn: () => unknown): string => {
  try {
    fn();
  } catch (e) {
    return (e as Error).message;
  }
  return 'NO THROW';
};
const rejMsg = async (p: Promise<unknown>): Promise<string> => p.then(() => 'NO THROW', (e: Error) => e.message);

describe('errors and registry', () => {
  it('named errors carry their names and messages', () => {
    expect(new ConnectorError('m').name).toBe('ConnectorError');
    const v = new ManifestValidationError(['one', 'two']);
    expect(v.name).toBe('ManifestValidationError');
    expect(v.message).toBe('invalid provider manifest: one; two');
    const u = new UnknownProviderError('zz');
    expect([u.name, u.message, u.providerId]).toEqual(['UnknownProviderError', "no connector registered for provider 'zz'", 'zz']);
  });
  it('require throws for an unknown id, has/get/list/ids behave', () => {
    const r = new ProviderRegistry();
    for (const id of ['c', 'a', 'b']) r.register(base({ id }));
    expect(() => r.require('zz')).toThrow(new UnknownProviderError('zz'));
    expect(r.require('a').id).toBe('a');
    expect(r.has('a')).toBe(true);
    expect(r.has('zz')).toBe(false);
    expect(r.ids()).toEqual(['a', 'b', 'c']);
    expect(r.list().map((m) => m.id)).toEqual(['a', 'b', 'c']);
  });
});

describe('validateManifest messages', () => {
  it('id', () => {
    for (const id of [undefined, '', 5]) expect(issues({ id })).toEqual(['id must be a non-empty string']);
  });
  it('scope lists', () => {
    expect(issues({ scopesAvailable: 'x' })).toContain('scopesAvailable must be an array of strings');
    expect(issues({ scopesAvailable: [1] })).toContain('scopesAvailable must be an array of strings');
    expect(issues({ defaultScopes: 'x' })).toEqual(['defaultScopes must be an array of strings']);
    expect(issues({ defaultScopes: [1] })).toEqual(['defaultScopes must be an array of strings']);
    expect(issues({ defaultScopes: ['q', 'r'] })).toEqual(['defaultScopes must be a subset of scopesAvailable (unknown: q, r)']);
    expect(issues({ scopesAvailable: [], defaultScopes: ['q'] })).toEqual([]);
  });
  it('refresh', () => {
    expect(issues({ refresh: 'x' })).toEqual(['refresh must be an object']);
    expect(issues({ refresh: { mode: 'x' } })).toEqual(['refresh.mode must be one of refresh_token | none']);
    expect(issues({ refresh: { mode: 'none', tokenEndpoint: 'http://x.example/t' } })).toEqual(['refresh.tokenEndpoint, when present, must be an https:// URL']);
    expect(issues({ refresh: { mode: 'none', supportsScopeNarrowing: 'yes' } })).toEqual(['refresh.supportsScopeNarrowing must be a boolean']);
    expect(issues({ refresh: { mode: 'none', extraParams: { a: 1 } } })).toEqual(['refresh.extraParams must be a string→string map']);
    expect(issues({ refresh: { mode: 'none', extraParams: { client_id: 'x' } } })).toEqual(["refresh.extraParams may not set 'client_id': the request builder owns it"]);
    expect(issues({ refresh: { mode: 'none', extraParams: { audience: 'x' } } })).toEqual([]);
  });
  it('placement, optional members and url variables', () => {
    expect(issues({ tokenPlacement: 'x' })).toEqual(['tokenPlacement must be one of bearer | header | query']);
    expect(issues({ tokenPlacement: 'query' })).toEqual(["tokenPlacement 'query' requires a non-empty queryParam"]);
    expect(issues({ pkce: 'y' })).toEqual(['pkce must be a boolean']);
    expect(issues({ scopeSeparator: 5 })).toEqual(['scopeSeparator must be a string']);
    expect(issues({ authParams: { a: 1 } })).toEqual(['authParams must be a string→string map']);
    expect(issues({ clientAuth: 'x' })).toEqual(['clientAuth must be one of post | basic']);
    expect(issues({ clientAuth: 5 })).toEqual(['clientAuth must be one of post | basic']);
    expect(issues({ requiredVars: 'x' })).toEqual(['requiredVars must be an array of strings']);
    expect(issues({ requiredVars: ['zzz'] })).toEqual(["requiredVars declares 'zzz' but no URL uses '{zzz}'"]);
    expect(issues({ docsUrl: 5 })).toEqual(['docsUrl must be a string']);
  });
  it('urls: https only, no credentials, no fragment, no bare placeholder host', () => {
    const msg = 'authorizeUrl must be an https:// URL';
    for (const authorizeUrl of [5, 'http://a.example/x', 'https://exa mple.com/x', 'https://u:p@a.example/x', 'https://u@a.example/x', 'https://:p@a.example/x', 'https://a.example/x#f', 'https://{shop}/x', 'https://{shop}:8443/x']) {
      expect(issues({ authorizeUrl, requiredVars: ['shop'] }), String(authorizeUrl)).toContain(msg);
    }
  });
  it('a placeholder inside a host name, with a multi-letter name, is accepted', () => {
    const m = assertManifest(base({ authorizeUrl: 'https://{shop}.a.example/auth', tokenUrl: 'https://api.{shop}/t', requiredVars: ['shop'] }));
    expect(m.requiredVars).toEqual(['shop']);
  });
  it('one bad url among two does not trigger variable checks', () => {
    expect(issues({ authorizeUrl: 5, tokenUrl: 'https://{v}.a.example/t' })).toEqual(['authorizeUrl must be an https:// URL']);
    expect(issues({ authorizeUrl: 'https://{v}.a.example/t', tokenUrl: 'http://x' })).toEqual(['tokenUrl must be an https:// URL']);
  });
  it('a URL variable that is not declared is reported', () => {
    expect(issues({ authorizeUrl: 'https://{v}.a.example/t' })).toEqual(["url uses '{v}' but requiredVars does not declare it"]);
  });
  it('assertManifest reports every issue joined with a semicolon', () => {
    expect(throwsMsg(() => assertManifest(base({ id: '', docsUrl: 5 })))).toBe('invalid provider manifest: id must be a non-empty string; docsUrl must be a string');
  });
});

describe('validated manifests keep exactly the declared members', () => {
  it('copies refresh details, clientAuth and docs, and omits absent members', () => {
    const full = assertManifest(
      base({ refresh: { mode: 'refresh_token', tokenEndpoint: 'https://a.example/r', supportsScopeNarrowing: false, extraParams: { x: 'y' } }, clientAuth: 'post', docsUrl: 'https://d', pkce: false, scopeSeparator: ',' }),
    );
    expect(full.refresh).toEqual({ mode: 'refresh_token', tokenEndpoint: 'https://a.example/r', supportsScopeNarrowing: false, extraParams: { x: 'y' } });
    expect([full.clientAuth, full.docsUrl, full.pkce, full.scopeSeparator]).toEqual(['post', 'https://d', false, ',']);
    const bare = assertManifest(base());
    for (const k of ['pkce', 'scopeSeparator', 'authParams', 'clientAuth', 'headerName', 'queryParam', 'requiredVars', 'docsUrl']) expect(k in bare).toBe(false);
    expect(Object.keys(bare.refresh)).toEqual(['mode']);
  });
  it('refresh extraParams are copied, not shared', () => {
    const ep = { x: 'y' };
    const m = assertManifest(base({ refresh: { mode: 'none', extraParams: ep } }));
    expect(m.refresh.extraParams).toEqual(ep);
    expect(m.refresh.extraParams).not.toBe(ep);
  });
});

describe('buildAuthorizeUrl', () => {
  const o = { clientId: 'cid', redirectUri: 'https://app.example/cb', state: 's'.repeat(16) };
  const build = (over: Record<string, unknown> = {}, opts: Record<string, unknown> = {}) => buildAuthorizeUrl('p', { ...o, registry: regOf(over), ...opts } as never);

  it('pkceChallenge: S256 is the RFC 7636 vector and plain is the verifier', () => {
    const v = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    expect(pkceChallenge(v)).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
    expect(pkceChallenge(v, 'S256')).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
    expect(pkceChallenge(v, 'plain')).toBe(v);
  });
  it('refuses a bad client id, state or scope list with exact messages', () => {
    for (const clientId of ['', 5]) expect(throwsMsg(() => build({}, { clientId }))).toBe('buildAuthorizeUrl: clientId must be a non-empty string');
    expect(throwsMsg(() => build({}, { state: 5 }))).toMatch(/^buildAuthorizeUrl: state must be at least 16 characters/);
    expect(throwsMsg(() => build({}, { state: 'short' }))).toMatch(/state must be at least 16/);
    expect(throwsMsg(() => build({}, { scopes: 'ab' }))).toBe('buildAuthorizeUrl: scopes must be a list');
  });
  it('every scope is a clean single token, including against a custom separator', () => {
    const msg = 'buildAuthorizeUrl: every scope must be a non-empty string without whitespace, commas or the separator';
    for (const scopes of [[5], [''], ['a b'], ['a,b']]) expect(throwsMsg(() => build({}, { scopes })), JSON.stringify(scopes)).toBe(msg);
    expect(throwsMsg(() => build({ scopeSeparator: ':', scopesAvailable: ['a:b'], defaultScopes: [] }, { scopes: ['a:b'] }))).toBe(msg);
  });
  it('a scope whose text contains "undefined" is fine under the default separator', () => {
    const r = build({ scopesAvailable: ['undefined'], defaultScopes: [] }, { scopes: ['undefined'] });
    expect(r.url).toContain('scope=undefined');
  });
  it('a provider that lists no scopes accepts any scope; one that lists some does not', () => {
    expect(() => build({ scopesAvailable: [], defaultScopes: [] }, { scopes: ['anything'] })).not.toThrow();
    expect(throwsMsg(() => build({}, { scopes: ['zz'] }))).toBe("buildAuthorizeUrl: scope 'zz' is not offered by provider 'p'");
    expect(() => build({}, { scopes: ['zz'], allowUnlistedScopes: true })).not.toThrow();
  });
  it('an empty scope list sends no scope parameter', () => {
    expect(build({ defaultScopes: [] }).url).not.toContain('scope=');
    expect(build().url).toContain('scope=a');
  });
  it('redirect uris: https, or http on loopback only, no credentials', () => {
    const ok = (redirectUri: string) => () => build({}, { redirectUri });
    expect(ok('http://localhost:3000/cb')).not.toThrow();
    expect(ok('http://127.0.0.1/cb')).not.toThrow();
    expect(ok('http://[::1]:3000/cb')).not.toThrow();
    for (const bad of ['http://example.com/cb', 'ftp://localhost/cb', 'https://u:p@app.example/cb', 'https://u@app.example/cb', 'https://:p@app.example/cb', 'https://app.example/cb#f', 'not a url']) {
      expect(ok(bad), bad).toThrow(ConnectorError);
    }
  });
  it('pkce: follows the manifest by default, can be disabled, and can be forced on', () => {
    expect(build().pkce).toBeUndefined();
    expect('pkce' in build()).toBe(false);
    expect(build({ pkce: true }).pkce?.method).toBe('S256');
    expect(build({ pkce: true }, { pkce: false }).pkce).toBeUndefined();
    expect(build({ pkce: false }, { pkce: true }).pkce?.method).toBe('S256');
    const given = 'v'.repeat(43);
    const r = build({}, { pkce: { verifier: given } });
    expect(r.pkce).toEqual({ verifier: given, challenge: pkceChallenge(given), method: 'S256' });
  });
  it('pkce method: plain needs an explicit opt-in and other methods are refused', () => {
    const verifier = 'v'.repeat(43);
    const msg = "buildAuthorizeUrl: PKCE method must be 'S256' (pass allowPlainPkce to use 'plain')";
    expect(throwsMsg(() => build({}, { pkce: { verifier, method: 'plain' } }))).toBe(msg);
    expect(throwsMsg(() => build({}, { pkce: { verifier, method: 'foo' }, allowPlainPkce: true }))).toBe(msg);
    const r = build({}, { pkce: { verifier, method: 'plain' }, allowPlainPkce: true });
    expect(r.pkce).toEqual({ verifier, challenge: verifier, method: 'plain' });
  });
  it('a url that already has a query is extended with an ampersand', () => {
    const r = build({ authorizeUrl: 'https://a.example/auth?x=1' });
    expect(r.url.startsWith('https://a.example/auth?x=1&response_type=code&')).toBe(true);
    expect(build().url.startsWith('https://a.example/auth?response_type=code&')).toBe(true);
  });
});

describe('applyAccessToken', () => {
  it('refuses non-string, empty and non-printable tokens', () => {
    const m = assertManifest(base());
    const msg = 'applyAccessToken: the access token must be a non-empty string of printable ASCII without spaces';
    for (const t of [5, '', 'a b', 'a\nb']) expect(throwsMsg(() => applyAccessToken(m, t as never)), String(t)).toBe(msg);
    expect(applyAccessToken(m, 'tok')).toEqual({ kind: 'header', name: 'Authorization', value: 'Bearer tok' });
  });
  it('a header or query placement without its name is refused', () => {
    const header = { ...assertManifest(base()), tokenPlacement: 'header' as const };
    const query = { ...assertManifest(base()), tokenPlacement: 'query' as const };
    expect(throwsMsg(() => applyAccessToken(header, 'tok'))).toBe("manifest 'p' is header-placed but has no headerName");
    expect(throwsMsg(() => applyAccessToken(query, 'tok'))).toBe("manifest 'p' is query-placed but has no queryParam");
    expect(applyAccessToken({ ...header, headerName: 'X-T' }, 'tok')).toEqual({ kind: 'header', name: 'X-T', value: 'tok' });
    expect(applyAccessToken({ ...query, queryParam: 'k' }, 'tok')).toEqual({ kind: 'query', name: 'k', value: 'tok' });
  });
});

// ---- token endpoint ------------------------------------------------------------------------------------
type Sent = { url: string; init: { method: string; headers: Record<string, string>; body: string } };
function transport(respond: (n: number) => { ok: boolean; status?: number; json?: () => unknown; text?: () => string }) {
  const sent: Sent[] = [];
  const fetch = (async (url: string, init: Sent['init']) => {
    sent.push({ url, init });
    const r = respond(sent.length);
    return { ok: r.ok, status: r.status ?? 200, json: async () => r.json?.(), text: async () => r.text?.() ?? '' };
  }) as never;
  return { sent, fetch };
}
function vault() {
  const puts: Array<Record<string, unknown>> = [];
  return { puts, vault: { putConnection: async (x: Record<string, unknown>) => (puts.push(x), x) } as never };
}
const okJson = (body: unknown) => () => ({ ok: true, json: () => body });
const args = (over: Record<string, unknown> = {}) => {
  const v = vault();
  const t = transport(okJson({ access_token: 'AT' }));
  return { v, t, a: { providerId: 'p', clientId: 'cid', code: 'code1', redirectUri: 'https://app.example/cb', fetch: t.fetch, bind: { vault: v.vault, agentId: 'ag', authority: { principal: 'pr' } }, now: 1000, registry: regOf(), ...over } as never };
};

describe('exchangeCode request and storage', () => {
  it('sends the exact request: method, headers, and an ampersand-joined body', async () => {
    const { t, a } = args({ clientSecret: 'sec', codeVerifier: 'cv', extraParams: { extra: 'x' } });
    await exchangeCode(a);
    const s = t.sent[0]!;
    expect(s.url).toBe('https://a.example/token');
    expect(s.init.method).toBe('POST');
    expect(s.init.headers).toEqual({ 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' });
    expect(s.init.body).toBe('grant_type=authorization_code&code=code1&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&client_id=cid&client_secret=sec&code_verifier=cv&extra=x');
  });
  it('omits the secret and verifier when not given, and refuses reserved extra params', async () => {
    const { t, a } = args();
    await exchangeCode(a);
    expect(t.sent[0]!.init.body).toBe('grant_type=authorization_code&code=code1&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&client_id=cid');
    expect(await rejMsg(exchangeCode(args({ extraParams: { client_id: 'x' } }).a))).toBe("[p] exchangeCode: extraParams may not set 'client_id'");
    expect(await rejMsg(exchangeCode(args({ code: 5 }).a))).toBe('[p] an authorization code is required');
    expect(await rejMsg(exchangeCode(args({ code: '' }).a))).toBe('[p] an authorization code is required');
  });
  it('a PKCE provider requires a verifier', async () => {
    const x = args({ registry: regOf({ pkce: true }) });
    expect(await rejMsg(exchangeCode(x.a))).toBe('[p] provider uses PKCE; a codeVerifier is required to exchange the code');
    expect(await rejMsg(exchangeCode(args({ registry: regOf({ pkce: true }), codeVerifier: 'v' }).a))).toBe('NO THROW');
  });
  it('stores expiry, scopes, refresh token and authority from the response', async () => {
    const x = args({ bind: { vault: vault().vault, agentId: 'ag', authority: { principal: 'pr' } } });
    const v = vault();
    const t = transport(okJson({ access_token: 'AT', expires_in: 60, refresh_token: 'RT', scope: ' a, b  c ' }));
    await exchangeCode(args({ fetch: t.fetch, bind: { vault: v.vault, agentId: 'ag', connectionId: 'c1', authority: { principal: 'pr', scopes: ['x'], audience: 'aud' } } }).a);
    void x;
    expect(v.puts[0]).toEqual({
      agentId: 'ag',
      provider: 'p',
      accessToken: 'AT',
      expiresAt: 1000 + 60_000,
      scopes: ['a', 'b', 'c'],
      authority: { principal: 'pr', scopes: ['x'], audience: 'aud' },
      connectionId: 'c1',
      refreshToken: 'RT',
    });
  });
  it('without optional response and binding members nothing extra is stored', async () => {
    const { v, a } = args();
    await exchangeCode(a);
    const put = v.puts[0]!;
    expect(put.expiresAt).toBe(1000 + 3_600_000);
    expect(put.scopes).toEqual(['a']);
    expect(put.authority).toEqual({ principal: 'pr', scopes: ['a'] });
    expect('audience' in (put.authority as object)).toBe(false);
    expect('connectionId' in put).toBe(false);
    expect('refreshToken' in put).toBe(false);
  });
  it('response fields are only trusted when well typed', async () => {
    const stored = async (body: unknown) => {
      const v = vault();
      await exchangeCode(args({ fetch: transport(okJson(body)).fetch, bind: { vault: v.vault, agentId: 'ag', authority: { principal: 'pr' } } }).a);
      return v.puts[0]!;
    };
    for (const expires_in of [0, -5, '60', null, Infinity, NaN]) expect((await stored({ access_token: 'AT', expires_in })).expiresAt, String(expires_in)).toBe(1000 + 3_600_000);
    for (const refresh_token of ['', 5]) expect('refreshToken' in (await stored({ access_token: 'AT', refresh_token })), String(refresh_token)).toBe(false);
    for (const scope of ['   ', 5, '']) expect((await stored({ access_token: 'AT', scope })).scopes, String(scope)).toEqual(['a']);
    expect((await stored({ access_token: 'AT', scope: 'x,y' })).scopes).toEqual(['x', 'y']);
  });
  it('refuses a malformed token response with exact messages', async () => {
    const run = (body: unknown) => rejMsg(exchangeCode(args({ fetch: transport(okJson(body)).fetch }).a));
    for (const body of [null, 'str', [], 5]) expect(await run(body), JSON.stringify(body)).toBe('[p] token endpoint returned a non-object body');
    for (const body of [{}, { access_token: '' }, { access_token: 5 }]) expect(await run(body)).toBe('[p] token endpoint response has no access_token');
    const t = transport(() => ({ ok: true, json: () => { throw new Error('secret in here'); } }));
    expect(await rejMsg(exchangeCode(args({ fetch: t.fetch }).a))).toBe('[p] unparseable token JSON');
  });
  it('transport failures and error bodies are reported with secrets redacted and bounded', async () => {
    const boom = transport(() => { throw new Error('connect sek failed'); });
    expect(await rejMsg(exchangeCode(args({ clientSecret: 'sek', fetch: boom.fetch }).a))).toBe('[p] token transport error: connect [redacted] failed');
    const str = transport(() => { throw 'plain'; });
    expect(await rejMsg(exchangeCode(args({ fetch: str.fetch }).a))).toBe('[p] token transport error: plain');
    const bad = transport(() => ({ ok: false, status: 400, text: () => `x${'y'.repeat(400)}` }));
    expect(await rejMsg(exchangeCode(args({ fetch: bad.fetch }).a))).toBe(`[p] token endpoint 400: x${'y'.repeat(255)}`);
    const secretBody = transport(() => ({ ok: false, status: 400, text: () => 'bad code code1 and sek' }));
    expect(await rejMsg(exchangeCode(args({ clientSecret: 'sek', fetch: secretBody.fetch }).a))).toBe('[p] token endpoint 400: bad code [redacted] and [redacted]');
    const unreadable = transport(() => ({ ok: false, status: 502, text: () => { throw new Error('x'); } }));
    expect(await rejMsg(exchangeCode(args({ fetch: unreadable.fetch }).a))).toBe('[p] token endpoint 502: <unreadable body>');
  });
  it('an empty client secret does not shred the error text', async () => {
    const bad = transport(() => ({ ok: false, status: 400, text: () => 'abc' }));
    expect(await rejMsg(exchangeCode(args({ clientSecret: '', fetch: bad.fetch }).a))).toBe('[p] token endpoint 400: abc');
  });
});

describe('HTTP basic client authentication', () => {
  const basic = () => regOf({ clientAuth: 'basic' });
  it('moves the credentials into a standard padded base64 Authorization header', async () => {
    for (const [id, sec] of [['a', '>>>>>>'], ['a', '??????'], ['id', 's'], ['abc', 'de']] as const) {
      const { t, a } = args({ registry: basic(), clientId: id, clientSecret: sec });
      await exchangeCode(a);
      const h = t.sent[0]!.init.headers;
      expect(h['authorization']).toBe(`Basic ${Buffer.from(`${id}:${sec}`).toString('base64')}`);
      expect(t.sent[0]!.init.body).not.toContain('client_id');
      expect(t.sent[0]!.init.body).not.toContain('client_secret');
    }
  });
  it('requires a secret and a client id', async () => {
    expect(await rejMsg(exchangeCode(args({ registry: basic() }).a))).toBe("[p] clientAuth 'basic' requires a clientSecret");
    expect(await rejMsg(exchangeCode(args({ registry: basic(), clientSecret: 's', clientId: undefined }).a))).toBe('[p] missing client_id for basic auth');
  });
  it('the Authorization header is redacted from transport errors', async () => {
    const t = transport(() => ({ ok: true }));
    const leaky = (async (_u: string, init: Sent['init']) => {
      throw new Error(`failed with ${init.headers['authorization']}`);
    }) as never;
    void t;
    const msg = await rejMsg(exchangeCode(args({ registry: basic(), clientSecret: 'sek', fetch: leaky }).a));
    expect(msg).toBe('[p] token transport error: failed with [redacted]');
  });
});

describe('refresh', () => {
  const rargs = (over: Record<string, unknown> = {}, manifest: Record<string, unknown> = {}) => {
    const v = vault();
    const t = transport(okJson({ access_token: 'AT2' }));
    return { v, t, a: { providerId: 'p', clientId: 'cid', refreshToken: 'RT1', fetch: t.fetch, bind: { vault: v.vault, agentId: 'ag', authority: { principal: 'pr' } }, now: 5, registry: regOf(manifest), ...over } as never };
  };
  it('refuses providers without refresh, a missing token, and reserved params', async () => {
    expect(await rejMsg(refresh(rargs({}, { refresh: { mode: 'none' } }).a))).toBe('[p] provider does not support token refresh');
    for (const refreshToken of ['', 5]) expect(await rejMsg(refresh(rargs({ refreshToken }).a))).toBe('[p] a refresh token is required');
    expect(await rejMsg(refresh(rargs({ extraParams: { refresh_token: 'x' } }).a))).toBe("[p] refresh: extraParams may not set 'refresh_token'");
  });
  it('sends the refresh body with secret, manifest params and caller params in order, and keeps the prior refresh token', async () => {
    const { t, v, a } = rargs({ clientSecret: 'sec', extraParams: { c: '3' } }, { refresh: { mode: 'refresh_token', extraParams: { m: '2' } } });
    await refresh(a);
    expect(t.sent[0]!.init.body).toBe('grant_type=refresh_token&refresh_token=RT1&client_id=cid&client_secret=sec&m=2&c=3');
    expect(v.puts[0]!.refreshToken).toBe('RT1');
    const bare = rargs();
    await refresh(bare.a);
    expect(bare.t.sent[0]!.init.body).toBe('grant_type=refresh_token&refresh_token=RT1&client_id=cid');
  });
  it('scope narrowing sends the requested scopes joined by the separator, only when asked and non-empty', async () => {
    const narrow = { refresh: { mode: 'refresh_token', supportsScopeNarrowing: true }, scopesAvailable: ['a', 'b'], defaultScopes: ['a', 'b'] };
    const x = rargs({}, narrow);
    await refresh(x.a);
    expect(x.t.sent[0]!.init.body).toBe('grant_type=refresh_token&refresh_token=RT1&client_id=cid&scope=a%20b');
    const comma = rargs({}, { ...narrow, scopeSeparator: ',' });
    await refresh(comma.a);
    expect(comma.t.sent[0]!.init.body).toContain('scope=a%2Cb');
    const none = rargs({ scopes: [] }, narrow);
    await refresh(none.a);
    expect(none.t.sent[0]!.init.body).not.toContain('scope');
    const off = rargs({}, { ...narrow, refresh: { mode: 'refresh_token', supportsScopeNarrowing: false } });
    await refresh(off.a);
    expect(off.t.sent[0]!.init.body).not.toContain('scope');
  });
  it('uses the refresh endpoint when the manifest has one', async () => {
    const x = rargs({}, { refresh: { mode: 'refresh_token', tokenEndpoint: 'https://a.example/refresh' } });
    await refresh(x.a);
    expect(x.t.sent[0]!.url).toBe('https://a.example/refresh');
  });
});

describe('vault provider configuration', () => {
  const m = (over: Record<string, unknown> = {}): ProviderManifest => assertManifest(base(over));
  it('refuses providers that cannot refresh', () => {
    expect(throwsMsg(() => manifestToProviderConfig(m({ refresh: { mode: 'none' } }), { clientId: 'c' }))).toBe('[p] provider does not support token refresh; no ProviderConfig');
  });
  it('derives the config, including false flags, copies of extra params and no stray members', () => {
    const ep = { a: 'b' };
    const cfg = manifestToProviderConfig(m({ refresh: { mode: 'refresh_token', supportsScopeNarrowing: false, extraParams: ep } }), { clientId: 'c', clientSecret: 's' });
    expect(cfg).toStrictEqual({ tokenEndpoint: 'https://a.example/token', clientId: 'c', clientSecret: 's', supportsScopeNarrowing: false, extraParams: { a: 'b' } });
    expect(cfg.extraParams).not.toBe(ep);
    const bare = manifestToProviderConfig(m(), { clientId: 'c' });
    expect(bare).toStrictEqual({ tokenEndpoint: 'https://a.example/token', clientId: 'c' });
  });
  it('buildVaultProviders skips non-refreshing providers', () => {
    const r = new ProviderRegistry();
    r.register(base({ id: 'x' }));
    r.register(base({ id: 'y', refresh: { mode: 'none' } }));
    expect(Object.keys(buildVaultProviders({ x: { clientId: 'c' }, y: { clientId: 'c' } }, r))).toEqual(['x']);
  });
});
