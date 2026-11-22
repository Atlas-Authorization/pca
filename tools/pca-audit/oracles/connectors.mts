// Oracle: @atlasauth/pca-connectors (connector catalog: manifest validation + digests, provider registry, authorize URL / PKCE / URL variables,
// access-token placement, code exchange + refresh into the vault, manifest -> vault provider config). Deterministic: authorize cases always pass an
// explicit state and PKCE verifier (the random branches are covered by native unit tests), clocks are fixed, keys derive from seed(label).
// Writes out/ref-connectors.json.gz.
//
// PORTING (fn(args) -> native entry point, comparison rule). Errors are returned as data ({ok:false, name, message, issues?}) so messages are
// compared exactly; a non-ConnectorError failure is {ok:false, name:'Error'} (a TypeError / URIError in the reference).
//   validateManifest(input)                 -> Manifest.validateManifest                {ok:true, manifest} | {ok:false, issues}
//   assertManifest(input)                   -> Manifest.assertManifest                  {ok, manifest} | error
//   manifestDigest(manifest)                -> Manifest.manifestDigest (of a validated manifest)       string
//   catalog()                               -> Providers.BUILTIN_MANIFESTS (toMap) + ProviderRegistry.listProviders/getProvider + catalogDigest
//   registry(scenario)                      -> ProviderRegistry ops (register/get/require/has/list/ids/catalogDigest) on a fresh registry
//   substituteVars(url, vars)               -> Authorize.substituteVars
//   pkceChallenge(verifier, method)         -> Authorize.pkceChallenge
//   buildAuthorizeUrl(providerId, options, customManifests) -> Authorize.buildAuthorizeUrl; customManifests (list or null) are registered on top of
//                                              the default catalog and passed as the registry
//   applyAccessToken(rawManifest, token)    -> Authorize.applyAccessToken over a manifest object used AS IS (not validated)
//   manifestToProviderConfig(id, creds)     -> Exchange.manifestToProviderConfig over the built-in manifest `id`
//   buildVaultProviders(credsById)          -> Exchange.buildVaultProviders (default registry)
//   exchange(case) / refresh(case)          -> Exchange.exchangeCode / Exchange.refresh with a scripted transport and a non-strict in-memory vault;
//                                              result {result, fetchCalls, stored}
import * as PCA0 from '@atlasauth/pca';
import * as CNS0 from '@atlasauth/pca-connectors';
import * as CON0 from '@atlasauth/pca-connect';
import * as TST0 from '../../../packages/pca-connect/src/testing';
import * as STO0 from '../../../packages/pca-connect/src/store';
import { Oracle, refWrite, jsonOut, reparse, variants } from './lib.mjs';
const pick = (m: any) => m.default ?? m;
const { encodeKey, publicKeyOf } = pick(PCA0);
const C: any = pick(CNS0);
const { TokenVault } = pick(CON0);
const { InMemoryConnectionStore } = pick(TST0);
const { cloneConnection } = pick(STO0);

const o = new Oracle('connectors', 'tools/pca-audit/oracles/connectors.mts', 'TS-reference oracle for the connector catalog.');
const T0 = 1_800_000_000_000;
const BUILTIN: any[] = JSON.parse(JSON.stringify(C.providers.BUILTIN_MANIFESTS));
const byId = (id: string) => BUILTIN.find((m) => m.id === id);

const errOut = (e: any) => {
  const known = ['ConnectorError', 'ManifestValidationError', 'UnknownProviderError'];
  return known.includes(e?.name) ? { ok: false, name: e.name, message: e.message, ...(e.issues ? { issues: [...e.issues] } : {}) } : { ok: false, name: 'Error' };
};
const guard = (f: (...a: any[]) => any) => async (...a: any[]) => { try { return { ok: true, value: jsonOut(await f(...a)) }; } catch (e) { return errOut(e); } };
const withReg = (customs: any[] | null) => {
  const r = C.createDefaultRegistry();
  for (const m of customs ?? []) r.register(m);
  return r;
};

// ---- manifests --------------------------------------------------------------------------------------------------------------------------------
const validate = (i: any) => { const r = C.validateManifest(i); return r.ok ? { ok: true, manifest: r.manifest } : { ok: false, issues: r.issues }; };
const MANIFEST_SEEDS = [byId('google'), byId('shopify'), byId('slack'), byId('notion'), byId('snowflake')];
for (const m of BUILTIN) {
  await o.run('validateManifest', `builtin-${m.id}`, validate, [m]);
  await o.run('assertManifest', `builtin-${m.id}`, guard(C.assertManifest), [m]);
  await o.run('manifestDigest', `builtin-${m.id}`, C.manifestDigest, [m]);
}
const g = byId('google');
const MANUAL: Array<[string, any]> = [
  ['null', null], ['string', 'x'], ['array', []], ['empty', {}], ['number', 5],
  ['min', { id: 'x1', displayName: 'X', authorizeUrl: 'https://x.example/a', tokenUrl: 'https://x.example/t', scopesAvailable: [], defaultScopes: [], refresh: { mode: 'none' }, tokenPlacement: 'bearer' }],
  ['min-extra-keys', { id: 'x1', displayName: 'X', authorizeUrl: 'https://x.example/a', tokenUrl: 'https://x.example/t', scopesAvailable: [], defaultScopes: [], refresh: { mode: 'none', junk: 1 }, tokenPlacement: 'bearer', junk: 2 }],
  ['empty-available-default-nonempty', { ...g, scopesAvailable: [], defaultScopes: ['a'] }],
  ['default-not-subset', { ...g, defaultScopes: ['openid', 'nope', 'nada'] }],
  ['dup-scopes', { ...g, scopesAvailable: ['a', 'a'], defaultScopes: ['a'] }],
  ['scope-comma', { ...g, scopesAvailable: ['a,b'], defaultScopes: [] }], ['scope-space', { ...g, scopesAvailable: ['a b'], defaultScopes: [] }], ['scope-empty', { ...g, scopesAvailable: [''], defaultScopes: [] }],
  ['scope-nbsp', { ...g, scopesAvailable: ['a b'], defaultScopes: [] }], ['scope-tab', { ...g, scopesAvailable: ['a\tb'], defaultScopes: [] }],
  ['id-upper', { ...g, id: 'Google' }], ['id-space', { ...g, id: 'a b' }], ['id-dot', { ...g, id: 'a.b-c_d' }], ['id-leading-dash', { ...g, id: '-a' }], ['id-empty', { ...g, id: '' }], ['id-newline', { ...g, id: 'a\n' }],
  ['http-url', { ...g, authorizeUrl: 'http://accounts.google.com/auth' }], ['url-creds', { ...g, tokenUrl: 'https://u:p@x.example/t' }], ['url-frag', { ...g, tokenUrl: 'https://x.example/t#f' }],
  ['url-empty-frag', { ...g, tokenUrl: 'https://x.example/t#' }], ['url-user-only', { ...g, tokenUrl: 'https://u@x.example/t' }], ['url-colon-only', { ...g, tokenUrl: 'https://:@x.example/t' }],
  ['url-bad-host', { ...g, tokenUrl: 'https://exa mple.com/t' }], ['url-whole-host-var', { ...g, tokenUrl: 'https://{h}/t', requiredVars: ['h'] }], ['url-host-var-port', { ...g, tokenUrl: 'https://{h}:8443/t', requiredVars: ['h'] }],
  ['url-var-ok', { ...g, tokenUrl: 'https://{s}.example.com/t', requiredVars: ['s'] }], ['url-var-undeclared', { ...g, tokenUrl: 'https://{s}.example.com/t' }], ['url-var-unused', { ...g, requiredVars: ['s'] }],
  ['url-var-both', { ...g, authorizeUrl: 'https://{s}.example.com/a', tokenUrl: 'https://{s}.example.com/t', requiredVars: ['s'] }],
  ['url-var-in-path', { ...g, authorizeUrl: 'https://x.example/{p}/a', requiredVars: ['p'] }], ['url-var-two', { ...g, authorizeUrl: 'https://{a}.example/{b}', requiredVars: ['a', 'b'] }],
  ['url-uppercase-scheme', { ...g, authorizeUrl: 'HTTPS://x.example/a' }], ['url-ip', { ...g, authorizeUrl: 'https://127.0.0.1/a' }], ['url-port', { ...g, authorizeUrl: 'https://x.example:99999/a' }],
  ['refresh-missing', { ...g, refresh: undefined }], ['refresh-array', { ...g, refresh: [] }], ['refresh-bad-mode', { ...g, refresh: { mode: 'x' } }],
  ['refresh-endpoint-http', { ...g, refresh: { mode: 'refresh_token', tokenEndpoint: 'http://x.example/t' } }], ['refresh-endpoint-ok', { ...g, refresh: { mode: 'refresh_token', tokenEndpoint: 'https://x.example/t' } }],
  ['refresh-narrow-str', { ...g, refresh: { mode: 'refresh_token', supportsScopeNarrowing: 'yes' } }],
  ['refresh-extra-reserved', { ...g, refresh: { mode: 'refresh_token', extraParams: { client_id: 'x', refresh_token: 'y', ok: 'z' } } }], ['refresh-extra-nonstring', { ...g, refresh: { mode: 'refresh_token', extraParams: { a: 1 } } }],
  ['refresh-extra-ok', { ...g, refresh: { mode: 'refresh_token', extraParams: { audience: 'x' } } }],
  ['placement-bad', { ...g, tokenPlacement: 'cookie' }], ['placement-header-missing', { ...g, tokenPlacement: 'header' }], ['placement-query-missing', { ...g, tokenPlacement: 'query' }],
  ['placement-header-ok', { ...g, tokenPlacement: 'header', headerName: 'X-Api-Key' }], ['placement-query-ok', { ...g, tokenPlacement: 'query', queryParam: 'api_key' }],
  ['header-forbidden', { ...g, tokenPlacement: 'header', headerName: 'Host' }], ['header-forbidden-case', { ...g, tokenPlacement: 'header', headerName: 'Set-Cookie' }], ['header-bad-token', { ...g, tokenPlacement: 'header', headerName: 'X Key' }],
  ['header-stray-on-bearer', { ...g, headerName: 'Content-Type' }], ['query-bad', { ...g, tokenPlacement: 'query', queryParam: '1abc' }], ['query-stray-on-bearer', { ...g, queryParam: 'a b' }],
  ['sep-empty', { ...g, scopeSeparator: '' }], ['sep-num', { ...g, scopeSeparator: 5 }], ['sep-comma', { ...g, scopeSeparator: ',' }], ['pkce-str', { ...g, pkce: 'yes' }], ['pkce-null', { ...g, pkce: null }],
  ['authparams-reserved', { ...g, authParams: { state: 'x', scope: 'y', access_type: 'offline' } }], ['authparams-nonstring', { ...g, authParams: { a: [] } }], ['authparams-array', { ...g, authParams: [] }],
  ['clientauth-bad', { ...g, clientAuth: 'bearer' }], ['clientauth-num', { ...g, clientAuth: 1 }], ['clientauth-basic', { ...g, clientAuth: 'basic' }],
  ['requiredvars-str', { ...g, requiredVars: 'x' }], ['docs-num', { ...g, docsUrl: 1 }], ['docs-ok', { ...g, docsUrl: '' }],
  ['displayname-empty', { ...g, displayName: '' }], ['displayname-num', { ...g, displayName: 5 }], ['everything-wrong', { id: 5, displayName: 5, authorizeUrl: 5, tokenUrl: 5, scopesAvailable: 5, defaultScopes: 5, refresh: 5, tokenPlacement: 5 }],
  ['proto-keys', JSON.parse('{"id":"x","__proto__":{"a":1},"displayName":"X","authorizeUrl":"https://x.example/a","tokenUrl":"https://x.example/t","scopesAvailable":[],"defaultScopes":[],"refresh":{"mode":"none"},"tokenPlacement":"bearer"}')],
];
for (const [n, m] of MANUAL) {
  await o.run('validateManifest', n, validate, [m]);
  await o.run('assertManifest', n, guard(C.assertManifest), [m]);
}
for (const [mi, seedM] of MANIFEST_SEEDS.entries()) {
  let n = 0;
  for (const [label, v] of variants(seedM, { depth: 4, maxPaths: 60 })) {
    if (n++ % 3 !== 0) continue;
    await o.run('validateManifest', `var${mi}-${label}`, validate, [v]);
  }
}
// digests are stable for equal content and differ on any change
await o.run('manifestDigest', 'google-key-order', C.manifestDigest, [{ tokenPlacement: 'bearer', refresh: g.refresh, defaultScopes: g.defaultScopes, scopesAvailable: g.scopesAvailable, tokenUrl: g.tokenUrl, authorizeUrl: g.authorizeUrl, displayName: g.displayName, id: g.id, pkce: g.pkce, authParams: g.authParams, docsUrl: g.docsUrl }]);
await o.run('manifestDigest', 'google-changed', C.manifestDigest, [{ ...g, tokenUrl: 'https://evil.example/token' }]);

// ---- the catalog and registry --------------------------------------------------------------------------------------------------------------------
await o.run('catalog', 'all', () => ({ ids: C.listProviders().map((m: any) => m.id), manifests: C.listProviders(), digest: C.catalogDigest(), google: C.getProvider('google'), nope: C.getProvider('nope') ?? null }), []);
const regRef = async (s: any) => {
  const r = s.empty ? new C.ProviderRegistry() : C.createDefaultRegistry();
  const out: any[] = [];
  for (const op of s.ops) {
    try {
      let v: any;
      if (op.op === 'register') v = r.register(op.manifest, op.opts);
      else if (op.op === 'get') v = r.get(op.id) ?? null;
      else if (op.op === 'require') v = r.require(op.id);
      else if (op.op === 'has') v = r.has(op.id);
      else if (op.op === 'list') v = r.list();
      else if (op.op === 'ids') v = r.ids();
      else v = C.catalogDigest(r);
      out.push({ ok: true, value: jsonOut(v) });
    } catch (e) { out.push(errOut(e)); }
  }
  return out;
};
const custom = { ...g, id: 'acme', displayName: 'Acme' };
const customDigest = C.manifestDigest(custom);
const REG: Array<[string, any]> = [
  ['list-default', { ops: [{ op: 'ids' }, { op: 'catalogDigest' }] }],
  ['register-new', { ops: [{ op: 'register', manifest: custom }, { op: 'get', id: 'acme' }, { op: 'ids' }, { op: 'has', id: 'acme' }, { op: 'catalogDigest' }] }],
  ['register-dup', { ops: [{ op: 'register', manifest: byId('google') }, { op: 'register', manifest: byId('google'), opts: { replace: true } }, { op: 'register', manifest: { ...custom, id: 'google' }, opts: { replace: false } }] }],
  ['register-replace', { ops: [{ op: 'register', manifest: { ...custom, id: 'google', tokenUrl: 'https://evil.example/t' }, opts: { replace: true } }, { op: 'get', id: 'google' }, { op: 'catalogDigest' }] }],
  ['register-pinned-ok', { ops: [{ op: 'register', manifest: custom, opts: { expectedDigest: customDigest } }] }],
  ['register-pinned-bad', { ops: [{ op: 'register', manifest: custom, opts: { expectedDigest: 'AAAA' } }, { op: 'has', id: 'acme' }] }],
  ['register-pinned-empty', { ops: [{ op: 'register', manifest: custom, opts: { expectedDigest: '' } }] }],
  ['register-invalid', { ops: [{ op: 'register', manifest: { id: 'x' } }, { op: 'register', manifest: null }, { op: 'has', id: 'x' }] }],
  ['require-unknown', { ops: [{ op: 'require', id: 'nope' }, { op: 'get', id: 'nope' }, { op: 'has', id: 'nope' }, { op: 'require', id: 'google' }] }],
  ['empty-registry', { empty: true, ops: [{ op: 'ids' }, { op: 'list' }, { op: 'catalogDigest' }, { op: 'register', manifest: custom }, { op: 'register', manifest: { ...custom, id: 'aaa' } }, { op: 'ids' }, { op: 'catalogDigest' }] }],
  ['sort-order', { empty: true, ops: ['b', 'B', 'a1', 'a', 'a-b', 'a.b', 'a_b', '0', 'z9'].map((id) => ({ op: 'register', manifest: { ...custom, id } })).concat([{ op: 'ids' } as any]) }],
];
for (const [n, s] of REG) await o.run('registry', n, regRef, [s]);

// ---- substituteVars / pkceChallenge ----------------------------------------------------------------------------------------------------------------
const SV: Array<[string, string, any]> = [
  ['none', 'https://x.example/a', undefined], ['one', 'https://{shop}.myshopify.com/a', { shop: 'acme' }], ['two', 'https://{a}.{b}.example/{a}', { a: 'x', b: 'y' }], ['missing', 'https://{shop}.example/a', {}],
  ['missing-undefined', 'https://{shop}.example/a', undefined], ['evil-dot', 'https://{shop}.example/a', { shop: 'evil.com/x?' }], ['evil-slash', 'https://{shop}.example/a', { shop: 'a/b' }], ['empty', 'https://{shop}.example/a', { shop: '' }],
  ['hyphen-lead', 'https://{shop}.example/a', { shop: '-a' }], ['hyphen-mid', 'https://{shop}.example/a', { shop: 'a-b' }], ['max-63', 'https://{shop}.example/a', { shop: 'a'.repeat(63) }], ['over-63', 'https://{shop}.example/a', { shop: 'a'.repeat(64) }],
  ['number', 'https://{shop}.example/a', { shop: 5 }], ['null', 'https://{shop}.example/a', { shop: null }], ['array', 'https://{shop}.example/a', { shop: ['a'] }], ['upper', 'https://{shop}.example/a', { shop: 'ACME9' }],
  ['unicode', 'https://{shop}.example/a', { shop: 'é' }], ['space', 'https://{shop}.example/a', { shop: 'a b' }], ['proto', 'https://{toString}.example/a', {}], ['proto-own', 'https://{toString}.example/a', { toString: 'x' }],
  ['not-var', 'https://x.example/{not a var}/{}', {}], ['dollar', 'https://x.example/$&{a}', { a: 'b' }], ['reserved-name', 'https://{__proto__}.example/', {}], ['extra-vars', 'https://{a}.example/', { a: 'x', b: '!!' }],
];
for (const [n, u, v] of SV) await o.run('substituteVars', n, guard(C.substituteVars), [u, v ?? null]);
const VER43 = 'A'.repeat(43);
for (const [i, [v, m]] of ([[VER43, 'S256'], [VER43, 'plain'], ['abc', 'S256'], ['dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk', 'S256'], ['é'.repeat(43), 'S256'], ['', 'S256']] as any[]).entries()) await o.run('pkceChallenge', `p${i}`, guard(C.pkceChallenge), [v, m]);
await o.run('pkceChallenge', 'default-method', guard(C.pkceChallenge), [VER43]);
await o.run('pkceChallenge', 'rfc7636', guard(C.pkceChallenge), ['dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk', 'S256']);

// ---- buildAuthorizeUrl -------------------------------------------------------------------------------------------------------------------------------
const STATE = 'state-0123456789abcdef';
const bau = guard((id: string, opts: any, customs: any) => C.buildAuthorizeUrl(id, { ...opts, registry: withReg(customs) }));
const baseOpts = (m: any, over: any = {}) => ({ clientId: 'cid', redirectUri: 'https://app.example.com/cb', state: STATE, pkce: m.pkce ? { verifier: VER43 } : undefined, vars: Object.fromEntries((m.requiredVars ?? []).map((v: string) => [v, 'acme'])), ...over });
for (const m of BUILTIN) {
  await o.run('buildAuthorizeUrl', `${m.id}-default`, bau, [m.id, baseOpts(m), null]);
  await o.run('buildAuthorizeUrl', `${m.id}-all-scopes`, bau, [m.id, baseOpts(m, { scopes: m.scopesAvailable }), null]);
  await o.run('buildAuthorizeUrl', `${m.id}-pkce-off`, bau, [m.id, baseOpts(m, { pkce: false }), null]);
  await o.run('buildAuthorizeUrl', `${m.id}-pkce-on`, bau, [m.id, baseOpts(m, { pkce: { verifier: VER43 } }), null]);
  await o.run('buildAuthorizeUrl', `${m.id}-no-scopes`, bau, [m.id, baseOpts(m, { scopes: [] }), null]);
  await o.run('buildAuthorizeUrl', `${m.id}-extra`, bau, [m.id, baseOpts(m, { extraParams: { login_hint: 'a@b.c', prompt: 'x y&z=é' } }), null]);
  await o.run('buildAuthorizeUrl', `${m.id}-unlisted`, bau, [m.id, baseOpts(m, { scopes: ['not-a-scope'] }), null]);
  await o.run('buildAuthorizeUrl', `${m.id}-unlisted-allowed`, bau, [m.id, baseOpts(m, { scopes: ['not-a-scope'], allowUnlistedScopes: true }), null]);
  await o.run('buildAuthorizeUrl', `${m.id}-no-vars`, bau, [m.id, baseOpts(m, { vars: undefined }), null]);
}
const gg = byId('google');
const BO: Array<[string, any]> = [
  ['no-client', { clientId: undefined }], ['empty-client', { clientId: '' }], ['num-client', { clientId: 5 }],
  ['short-state', { state: 'short' }], ['state-15', { state: 'a'.repeat(15) }], ['state-16', { state: 'a'.repeat(16) }], ['state-num', { state: 123 }],
  ['dup-scope', { scopes: ['openid', 'openid'] }], ['scope-space', { scopes: ['open id'] }], ['scope-comma', { scopes: ['a,b'] }], ['scope-empty', { scopes: [''] }], ['scope-num', { scopes: [1] }], ['scopes-string', { scopes: 'openid' }],
  ['scopes-null-default', { scopes: null }],
  ['extra-reserved-state', { extraParams: { state: 'x' } }], ['extra-reserved-cc', { extraParams: { code_challenge: 'x' } }], ['extra-overrides-auth', { extraParams: { prompt: 'none', access_type: 'online' } }],
  ['pkce-short', { pkce: { verifier: 'short' } }], ['pkce-long', { pkce: { verifier: 'a'.repeat(129) } }], ['pkce-128', { pkce: { verifier: 'a'.repeat(128) } }], ['pkce-bad-char', { pkce: { verifier: 'a'.repeat(42) + '!' } }],
  ['pkce-tilde', { pkce: { verifier: 'a.~_-'.repeat(9) } }], ['pkce-no-verifier', { pkce: {} }], ['pkce-num-verifier', { pkce: { verifier: 5 } }],
  ['pkce-plain-refused', { pkce: { verifier: VER43, method: 'plain' } }], ['pkce-plain-allowed', { pkce: { verifier: VER43, method: 'plain' }, allowPlainPkce: true }], ['pkce-weird-method', { pkce: { verifier: VER43, method: 'S512' }, allowPlainPkce: true }],
  ['pkce-s256-explicit', { pkce: { verifier: VER43, method: 'S256' } }],
  ['redirect-http', { redirectUri: 'http://app.example.com/cb' }], ['redirect-localhost', { redirectUri: 'http://localhost:3000/cb' }], ['redirect-127', { redirectUri: 'http://127.0.0.1/cb' }], ['redirect-v6', { redirectUri: 'http://[::1]:8080/cb' }],
  ['redirect-localhost-upper', { redirectUri: 'http://LOCALHOST/cb' }], ['redirect-localhost-https', { redirectUri: 'https://localhost/cb' }], ['redirect-fragment', { redirectUri: 'https://app.example.com/cb#x' }], ['redirect-empty-fragment', { redirectUri: 'https://app.example.com/cb#' }],
  ['redirect-creds', { redirectUri: 'https://u:p@app.example.com/cb' }], ['redirect-user', { redirectUri: 'https://u@app.example.com/cb' }], ['redirect-relative', { redirectUri: '/cb' }], ['redirect-custom-scheme', { redirectUri: 'myapp://cb' }],
  ['redirect-js', { redirectUri: 'javascript:alert(1)' }], ['redirect-query', { redirectUri: 'https://app.example.com/cb?a=1&b=é' }], ['redirect-upper-scheme', { redirectUri: 'HTTPS://app.example.com/cb' }], ['redirect-space', { redirectUri: 'https://app.example.com/c b' }],
  ['redirect-empty', { redirectUri: '' }], ['redirect-missing', { redirectUri: undefined }], ['redirect-num', { redirectUri: 5 }], ['redirect-tab', { redirectUri: 'https://app.example.com/\tcb' }], ['redirect-ws-pad', { redirectUri: '  https://app.example.com/cb  ' }],
  ['redirect-unicode-host', { redirectUri: 'https://bücher.example/cb' }], ['redirect-bad-port', { redirectUri: 'https://app.example.com:99999/cb' }], ['redirect-ftp', { redirectUri: 'ftp://app.example.com/cb' }],
  ['vars-null', { vars: null }], ['unicode-client', { clientId: 'cid é&=' }],
];
for (const [n, ov] of BO) await o.run('buildAuthorizeUrl', n, bau, ['google', baseOpts(gg, ov), null]);
const CUST: any[] = [
  { ...g, id: 'q1', authorizeUrl: 'https://x.example/auth?existing=1', scopesAvailable: ['a'], defaultScopes: ['a'], pkce: false, authParams: undefined },
  { ...g, id: 'q2', scopeSeparator: '+', scopesAvailable: ['a', 'b'], defaultScopes: ['a', 'b'], pkce: false, authParams: { audience: 'api://x y' } },
  { ...g, id: 'q3', scopesAvailable: [], defaultScopes: [], pkce: false, authParams: undefined },
  { ...g, id: 'q4', scopeSeparator: ' ', scopesAvailable: ['a'], defaultScopes: ['a'], pkce: true, authParams: undefined },
];
for (const c of CUST) {
  await o.run('buildAuthorizeUrl', `${c.id}-default`, bau, [c.id, baseOpts(c), [c]]);
  await o.run('buildAuthorizeUrl', `${c.id}-any-scope`, bau, [c.id, baseOpts(c, { scopes: ['whatever', 'x:y'] }), [c]]);
}
await o.run('buildAuthorizeUrl', 'unknown-provider', bau, ['nope', baseOpts(gg), null]);
await o.run('buildAuthorizeUrl', 'sep-in-scope', bau, ['q2', baseOpts(CUST[1], { scopes: ['a+b'] }), [CUST[1]]]);
// hostile variants of valid options
{
  let n = 0;
  for (const [label, v] of variants(baseOpts(gg, { scopes: ['openid', 'email'], extraParams: { login_hint: 'x' } }), { depth: 3, maxPaths: 30 })) {
    if (n++ % 3 !== 0 || v === null || typeof v !== 'object') continue;
    // a missing state or PKCE verifier is generated at random: not a deterministic case
    const pk = (v as any).pkce;
    if (typeof (v as any).state !== 'string' || !(pk === false || (pk !== null && typeof pk === 'object' && !Array.isArray(pk)))) continue;
    await o.run('buildAuthorizeUrl', `var-${label}`, bau, ['google', v, null]);
  }
}

// ---- applyAccessToken -----------------------------------------------------------------------------------------------------------------------------------
const AM: Array<[string, any]> = [
  ['bearer', byId('google')], ['header', byId('shopify')], ['query', { ...g, tokenPlacement: 'query', queryParam: 'api_key' }],
  ['header-missing-name', { ...g, tokenPlacement: 'header' }], ['query-missing-name', { ...g, tokenPlacement: 'query' }], ['header-empty-name', { ...g, tokenPlacement: 'header', headerName: '' }],
];
const TOKENS: any[] = ['abc', 'ey.J0.sig-_~+/=', 'a b', 'a\tb', 'a\nb', 'é', '', ' ', '!', '~', '\u007f', ' x', null, 5, undefined, 'x'.repeat(5000)];
for (const [n, m] of AM) for (const [i, t] of TOKENS.entries()) await o.run('applyAccessToken', `${n}-t${i}`, guard(C.applyAccessToken), [m, t ?? null]);

// ---- provider configs for the vault -----------------------------------------------------------------------------------------------------------------
for (const m of BUILTIN) {
  const vars = Object.fromEntries((m.requiredVars ?? []).map((v: string) => [v, 'acme']));
  await o.run('manifestToProviderConfig', `${m.id}-secret`, guard((id: string, creds: any) => C.manifestToProviderConfig(C.getProvider(id), creds)), [m.id, { clientId: 'cid', clientSecret: 'sec', vars }]);
  await o.run('manifestToProviderConfig', `${m.id}-public`, guard((id: string, creds: any) => C.manifestToProviderConfig(C.getProvider(id), creds)), [m.id, { clientId: 'cid', vars }]);
}
await o.run('manifestToProviderConfig', 'snowflake-no-vars', guard((id: string, creds: any) => C.manifestToProviderConfig(C.getProvider(id), creds)), ['snowflake', { clientId: 'cid' }]);
await o.run('manifestToProviderConfig', 'snowflake-bad-var', guard((id: string, creds: any) => C.manifestToProviderConfig(C.getProvider(id), creds)), ['snowflake', { clientId: 'cid', vars: { account: 'a.b' } }]);
const allCreds = Object.fromEntries(BUILTIN.map((m) => [m.id, { clientId: `cid-${m.id}`, clientSecret: 's', vars: Object.fromEntries((m.requiredVars ?? []).map((v: string) => [v, 'acme'])) }]));
await o.run('buildVaultProviders', 'all', guard((c: any) => C.buildVaultProviders(c)), [allCreds]);
await o.run('buildVaultProviders', 'refreshable-subset', guard((c: any) => C.buildVaultProviders(c)), [{ google: allCreds.google, github: allCreds.github, zoom: allCreds.zoom }]);
await o.run('buildVaultProviders', 'unknown', guard((c: any) => C.buildVaultProviders(c)), [{ nope: { clientId: 'x' } }]);
await o.run('buildVaultProviders', 'empty', guard((c: any) => C.buildVaultProviders(c)), [{}]);
await o.run('buildVaultProviders', 'bad-vars', guard((c: any) => C.buildVaultProviders(c)), [{ snowflake: { clientId: 'x', vars: {} } }]);

// ---- exchangeCode / refresh ---------------------------------------------------------------------------------------------------------------------------
const P_SEED = new Uint8Array(32).fill(7), A_SEED = new Uint8Array(32).fill(9);
const PRINC = encodeKey(publicKeyOf(P_SEED)), AGENT = encodeKey(publicKeyOf(A_SEED));
const mkTransport = (script: any[] | undefined, log: any[]) => {
  if (script === undefined) return undefined;
  let i = 0;
  return async (url: string, init: any) => {
    log.push({ url, method: init.method, headers: init.headers, body: init.body });
    const r = script[Math.min(i++, script.length - 1)];
    if (r.throws !== undefined) throw new Error(r.throws);
    return { ok: r.ok, status: r.status, json: async () => { if (r.jsonThrows) throw new Error('bad json'); return r.json; }, text: async () => { if (r.textThrows) throw new Error('bad text'); return r.text ?? ''; } };
  };
};
const tokenRun = (which: 'exchangeCode' | 'refresh') => async (c: any) => {
  const log: any[] = [];
  const store = new InMemoryConnectionStore();
  const vault = new TokenVault({ strict: false, insecureSkipPlanRootCheck: true, store, now: () => c.now });
  const { bind, script, customs, ...rest } = c;
  const args: any = { ...rest, fetch: mkTransport(script, log), registry: withReg(customs ?? null),
    bind: { vault, agentId: bind.agentId, ...(bind.connectionId !== undefined ? { connectionId: bind.connectionId } : {}), authority: { principal: bind.principal, ...(bind.scopes !== undefined ? { scopes: bind.scopes } : {}), ...(bind.audience !== undefined ? { audience: bind.audience } : {}) } } };
  let result: any;
  try { result = { ok: true, value: jsonOut(await C[which](args)) }; } catch (e) { result = errOut(e); }
  const g2 = await store.get({ agentId: bind.agentId, provider: c.providerId, connectionId: bind.connectionId ?? 'default' });
  return { result, fetchCalls: log, stored: g2 === undefined ? null : jsonOut(cloneConnection(g2)) };
};
const exchangeRun = tokenRun('exchangeCode'), refreshRun = tokenRun('refresh');
const tokJson = (over: any = {}) => [{ ok: true, status: 200, json: { access_token: 'AT-new', expires_in: 3600, ...over } }];
const bindOf = (over: any = {}) => ({ agentId: AGENT, principal: PRINC, ...over });
const exCase = (m: any, over: any = {}) => ({
  providerId: m.id, clientId: 'cid', clientSecret: 'csec', code: 'auth-code-123', redirectUri: 'https://app.example.com/cb', ...(m.pkce ? { codeVerifier: VER43 } : {}),
  now: T0, bind: bindOf(), script: tokJson(), vars: Object.fromEntries((m.requiredVars ?? []).map((v: string) => [v, 'acme'])), ...over,
});
for (const m of BUILTIN) {
  await o.run('exchange', `${m.id}-ok`, exchangeRun, [exCase(m)]);
  await o.run('exchange', `${m.id}-public-client`, exchangeRun, [exCase(m, { clientSecret: undefined })]);
  await o.run('exchange', `${m.id}-refresh-token-echo`, exchangeRun, [exCase(m, { script: tokJson({ refresh_token: 'RT-1', scope: 'a b,c' }) })]);
  if (m.refresh.mode !== 'none') {
    await o.run('refresh', `${m.id}-ok`, refreshRun, [{ ...exCase(m), refreshToken: 'RT-old', code: undefined, redirectUri: undefined, codeVerifier: undefined }]);
    await o.run('refresh', `${m.id}-rotate`, refreshRun, [{ ...exCase(m), refreshToken: 'RT-old', script: tokJson({ refresh_token: 'RT-new' }), scopes: m.defaultScopes }]);
  } else {
    await o.run('refresh', `${m.id}-none`, refreshRun, [{ ...exCase(m), refreshToken: 'RT-old' }]);
  }
}
const gx = (over: any = {}) => exCase(byId('google'), over);
const EX: Array<[string, any]> = [
  ['no-code', gx({ code: '' })], ['code-missing', gx({ code: undefined })], ['pkce-no-verifier', gx({ codeVerifier: undefined })], ['pkce-given-for-non-pkce', exCase(byId('github'), { codeVerifier: VER43 })],
  ['extra-reserved', gx({ extraParams: { code: 'x' } })], ['extra-ok', gx({ extraParams: { audience: 'api://x', note: 'é y&z' } })], ['extra-override-nothing', gx({ extraParams: { tenant: 't' } })],
  ['scopes-explicit', gx({ scopes: ['openid'] })], ['scopes-empty', gx({ scopes: [] })], ['scopes-echo-wins', gx({ scopes: ['openid'], script: tokJson({ scope: 'openid email' }) })],
  ['bind-authority-scopes', gx({ scopes: ['openid', 'email'], bind: bindOf({ scopes: ['openid'] }) })], ['bind-audience', gx({ bind: bindOf({ audience: 'rs' }) })], ['bind-connection-id', gx({ bind: bindOf({ connectionId: 'work' }) })],
  ['bind-empty-principal', gx({ bind: bindOf({ principal: '' }) })], ['bind-empty-agent', gx({ bind: bindOf({ agentId: '' }) })],
  ['no-expiry', gx({ script: [{ ok: true, status: 200, json: { access_token: 'AT-new' } }] })], ['frac-expiry', gx({ script: tokJson({ expires_in: 0.5 }) })], ['zero-expiry', gx({ script: tokJson({ expires_in: 0 }) })], ['str-expiry', gx({ script: tokJson({ expires_in: '60' }) })],
  ['scope-comma-space', gx({ script: tokJson({ scope: ' a, b ,c  d ' }) })], ['scope-leading-comma', gx({ script: tokJson({ scope: ',a' }) })], ['scope-trailing-comma', gx({ script: tokJson({ scope: 'a,' }) })], ['scope-blank', gx({ script: tokJson({ scope: '  ' }) })],
  ['scope-only-commas', gx({ script: tokJson({ scope: ',,' }) })],
  ['no-token', gx({ script: [{ ok: true, status: 200, json: { expires_in: 5 } }] })], ['empty-token', gx({ script: tokJson({ access_token: '' }) })], ['array-body', gx({ script: [{ ok: true, status: 200, json: [] }] })], ['null-body', gx({ script: [{ ok: true, status: 200, json: null }] })],
  ['bad-json', gx({ script: [{ ok: true, status: 200, jsonThrows: true }] })], ['http-400', gx({ script: [{ ok: false, status: 400, text: 'invalid_grant' }] })], ['http-long', gx({ script: [{ ok: false, status: 500, text: 'y'.repeat(300) }] })],
  ['http-leak', gx({ script: [{ ok: false, status: 400, text: 'bad auth-code-123 csec ' + VER43 }] })], ['http-unreadable', gx({ script: [{ ok: false, status: 502, textThrows: true }] })],
  ['transport-throw', gx({ script: [{ throws: 'ECONNRESET' }] })], ['transport-leak', gx({ script: [{ throws: 'failed for auth-code-123 / csec' }] })],
  ['basic-ok', exCase(byId('zoom'))], ['basic-no-secret', exCase(byId('zoom'), { clientSecret: undefined })], ['basic-leak', exCase(byId('zoom'), { script: [{ ok: false, status: 401, text: 'got Basic ' + Buffer.from('cid:csec').toString('base64') }] })],
  ['basic-unicode', exCase(byId('zoom'), { clientId: 'cïd', clientSecret: 'sé:cret' })], ['basic-notion', exCase(byId('notion'))],
  ['vars-missing', exCase(byId('shopify'), { vars: undefined })], ['vars-evil', exCase(byId('shopify'), { vars: { shop: 'evil.com/x?' } })], ['vars-ok', exCase(byId('shopify'), { vars: { shop: 'my-shop' } })],
  ['unknown-provider', gx({ providerId: 'nope' })], ['custom-provider', exCase({ ...g, id: 'acme', pkce: false }, { customs: [{ ...g, id: 'acme', pkce: false }] })],
  ['unicode-code', gx({ code: 'cödé/+= &' })],
];
for (const [n, c] of EX) await o.run('exchange', n, exchangeRun, [c]);
const gr = (over: any = {}) => ({ ...gx(), refreshToken: 'RT-old', code: undefined, redirectUri: undefined, codeVerifier: undefined, ...over });
const RF: Array<[string, any]> = [
  ['no-refresh-token', gr({ refreshToken: '' })], ['missing-refresh-token', gr({ refreshToken: undefined })], ['extra-reserved', gr({ extraParams: { refresh_token: 'x' } })], ['extra-ok', gr({ extraParams: { audience: 'x' } })],
  ['narrowing-on', { ...gr({ providerId: 'acme', customs: [{ ...g, id: 'acme', refresh: { mode: 'refresh_token', supportsScopeNarrowing: true, extraParams: { audience: 'api://m' } } }] }) }],
  ['narrowing-on-scoped', { ...gr({ providerId: 'acme', scopes: ['openid', 'email'], customs: [{ ...g, id: 'acme', scopeSeparator: ',', refresh: { mode: 'refresh_token', supportsScopeNarrowing: true } }] }) }],
  ['narrowing-on-empty-scopes', { ...gr({ providerId: 'acme', scopes: [], customs: [{ ...g, id: 'acme', refresh: { mode: 'refresh_token', supportsScopeNarrowing: true } }] }) }],
  ['narrowing-off', gr({ scopes: ['openid'] })],
  ['refresh-endpoint', { ...gr({ providerId: 'acme', customs: [{ ...g, id: 'acme', refresh: { mode: 'refresh_token', tokenEndpoint: 'https://{s}.refresh.example/t' }, tokenUrl: 'https://{s}.token.example/t', requiredVars: ['s'] }], vars: { s: 'acme' } }) }],
  ['manifest-extra-then-caller-override', { ...gr({ providerId: 'acme', extraParams: { audience: 'caller' }, customs: [{ ...g, id: 'acme', refresh: { mode: 'refresh_token', extraParams: { audience: 'manifest', tenant: 't' } } }] }) }],
  ['rotation-keeps-old', gr()], ['rotation-new', gr({ script: tokJson({ refresh_token: 'RT-new' }) })], ['echo-scopes', gr({ script: tokJson({ scope: 'a,b c' }) })],
  ['http-401', gr({ script: [{ ok: false, status: 401, text: 'nope RT-old' }] })], ['transport', gr({ script: [{ throws: 'down RT-old' }] })], ['bad-json', gr({ script: [{ ok: true, status: 200, jsonThrows: true }] })],
  ['basic-refresh', { ...exCase(byId('zoom')), refreshToken: 'RT-old', code: undefined, redirectUri: undefined, codeVerifier: undefined }], ['basic-refresh-no-secret', { ...exCase(byId('zoom'), { clientSecret: undefined }), refreshToken: 'RT-old', code: undefined, redirectUri: undefined, codeVerifier: undefined }],
  ['unknown-provider', gr({ providerId: 'nope' })],
];
for (const [n, c] of RF) await o.run('refresh', n, refreshRun, [c]);

refWrite(o, 'connectors');
