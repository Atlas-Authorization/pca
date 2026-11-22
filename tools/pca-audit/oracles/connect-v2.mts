// Corrected copy of connect.mts: the hostile-variant vault cases record args as [scenario] like every other vault case (the original
// passes the scenario object itself as args). Everything else is unchanged; it writes the connect-v2 corpus.
// Oracle: @atlasauth/pca-connect (outbound connection/token vault: oauth_scope caveats, token refresh, proxy-mode request extractor,
// signed release receipts, envelope-encrypted store, TokenVault release/proxy scenarios). Deterministic: keys come from seed(label),
// clocks are fixed (T0), PCActns carry an explicit nonce, encryption vectors use fixed IVs written here (the TS store's own IVs are random).
// Writes out/ref-connect.json.gz.
//
// PORTING (fn(args) -> native entry point, comparison rule). Args and results are JSON; a result that is {"$throws": ...} means the
// native must throw (a native error carrying a stable `code` must match it).
//   oauthScopeCaveat(provider, scopes)            -> Authority.oauthScopeCaveat            exact JSON
//   isOAuthScopeCaveat(cv)                        -> Authority.isOAuthScopeCaveat          boolean
//   grantedOAuthScopes(chain, provider)           -> Authority.grantedOAuthScopes          null, or the scope set as a sorted array
//   httpExtractor(spec, request)                  -> Proxy.httpExtractor(spec).apply(req)  params object, or throw (code request_mismatch)
//   checkProxyHeaders(headers, allow)             -> Proxy.checkProxyHeaders               headers object or throw
//   outboundRequestDigest(method,url,headers,body)-> Proxy.outboundRequestDigest           string
//   signReleaseReceipt(body, seedB64u)            -> Proxy.signReleaseReceipt (Ed25519 key from the seed)   signed receipt (exact)
//   verifyReleaseReceipt(receipt, pk)             -> Proxy.verifyReleaseReceipt            boolean
//   receiptActionDigest(pcactn)                   -> Proxy.receiptActionDigest             string
//   refreshConnection(case)                       -> Refresh.refreshConnection with a scripted transport; case = {connection, config, refreshToken,
//                                                    requested, now, defaultTokenLifetimeMs, script}; result {ok, value|error, calls}
//   decryptRecord(case)                           -> EncryptedConnectionStore.get over an inner store holding the given sealed record
//   vault(scenario)                               -> TokenVault: put/get/proxy/delete calls in order against the scenario's options; result
//                                                    {results, store, receipts, fetchCalls, proxyCalls}; an error is {name, code, message?}
//                                                    (message omitted for not_authorized, whose text carries verifier reasons)
// A scripted transport element: {ok, status, json?, jsonThrows?, text?, textThrows?} | {throws: message}. A scripted proxy response:
// {status, headers, body} | {throws: true}.
import { createCipheriv } from 'node:crypto';
import * as PCA0 from '@atlasauth/pca';
import * as CON0 from '@atlasauth/pca-connect';
import * as TST0 from '../../../packages/pca-connect/src/testing';
import * as PRX0 from '../../../packages/pca-connect/src/proxy';
import * as REF0 from '../../../packages/pca-connect/src/refresh';
import * as STO0 from '../../../packages/pca-connect/src/store';
const pick = (m: any) => m.default ?? m;
const { InMemoryReplayStore, b64u, buildPCActn, delegate, encodeKey, mintRoot, paramsDigest, publicKeyOf, unb64u } = pick(PCA0);
const {
  EncryptedConnectionStore, LocalKeyWrapper, TokenVault, VaultError, grantedOAuthScopes, httpExtractor, isOAuthScopeCaveat,
  oauthScopeCaveat, outboundRequestDigest, signReleaseReceipt, verifyReleaseReceipt, DEFAULT_PROXY_HEADERS,
} = pick(CON0);
const { InMemoryConnectionStore } = pick(TST0);
const { checkProxyHeaders, receiptActionDigest } = pick(PRX0);
const { refreshConnection } = pick(REF0);
const { cloneConnection } = pick(STO0);
import { Oracle, refWrite, jsonOut, reparse, seed, variants } from './lib.mjs';

const o = new Oracle('connect-v2', 'tools/pca-audit/oracles/connect-v2.mts', 'TS-reference oracle for the outbound connection/token vault.');
const T0 = 1_800_000_000_000;

const key = (l: string) => { const sk = seed('connect/' + l); return { sk, pk: encodeKey(publicKeyOf(sk)), seed: b64u(sk) }; };
const P = key('principal'), A = key('agent'), B = key('other-agent'), S = key('sub'), V = key('vault');

// ---- scope caveats --------------------------------------------------------------------------------------------------
const SC: any[][] = [[], ['read'], ['read', 'read'], ['read', 'write', 'read'], ['a', 'b', 'c'], ['https://www.googleapis.com/auth/calendar', 'openid'], ['', 'x'], ['é', 'é']];
for (const [i, s] of SC.entries()) for (const p of ['google', '', 'slack']) await o.run('oauthScopeCaveat', `s${i}p${p}`, oauthScopeCaveat, [p, s]);
const cavs: any[] = [
  oauthScopeCaveat('google', ['read']), { type: 'oauth_scope', provider: 'google', scopes: [] }, { type: 'oauth_scope', provider: 'google' }, { type: 'oauth_scope', scopes: [] },
  { type: 'oauth_scope', provider: 1, scopes: [] }, { type: 'oauth_scope', provider: 'g', scopes: 'read' }, { type: 'oauth_scope', provider: 'g', scopes: ['a', 1] },
  { type: 'other', provider: 'g', scopes: [] }, { type: 'oauth_scope', provider: 'g', scopes: null }, { type: null, provider: 'g', scopes: [] },
  null, 1, 'x', [], {}, true, { type: 'oauth_scope', provider: 'g', scopes: [], extra: 1 }, { type: 'oauth_scope', provider: '', scopes: ['a', 'a'] },
];
for (const [i, c] of cavs.entries()) await o.run('isOAuthScopeCaveat', `c${i}`, isOAuthScopeCaveat, [c]);
const sorted = (x: any) => (x === null ? null : [...x].sort());
const gos = (chain: any, p: string) => sorted(grantedOAuthScopes(chain, p));
const cap = (cv: any[]) => ({ issuer: 'i', holder: 'h', caveats: cv, parent: null });
const CH: any[] = [
  [cap([oauthScopeCaveat('google', ['read', 'write'])])], [cap([])], [], null, 'x', {}, [null], [{}], [{ caveats: 'x' }], [{ caveats: null }],
  [cap([oauthScopeCaveat('google', ['read', 'write']), oauthScopeCaveat('google', ['read'])])],
  [cap([oauthScopeCaveat('google', ['read']), oauthScopeCaveat('google', ['write'])])],
  [cap([oauthScopeCaveat('google', ['read', 'write'])]), cap([oauthScopeCaveat('google', ['read'])])],
  [cap([oauthScopeCaveat('google', ['a', 'b', 'c']), { type: 'other' }, oauthScopeCaveat('slack', ['z']), oauthScopeCaveat('google', ['b', 'c', 'd'])])],
  [cap([{ type: 'oauth_scope', provider: 'google', scopes: [1] }, oauthScopeCaveat('google', ['x'])])],
  [cap([oauthScopeCaveat('google', [])])], [cap([oauthScopeCaveat('google', ['a', 'a', 'b'])])],
];
for (const [i, ch] of CH.entries()) for (const p of ['google', 'slack', 'nope']) await o.run('grantedOAuthScopes', `ch${i}p${p}`, gos, [ch, p]);

// ---- httpExtractor / checkProxyHeaders -----------------------------------------------------------------------------------
const extract = (spec: any, req: any) => httpExtractor(spec)(req);
const SPECS: any[] = [
  { method: 'GET', url: 'https://api.example.com/v1/items/{id}', query: ['expand', 'fields'] },
  { method: 'POST', url: 'https://api.example.com/v1/send', body: 'json', fixed: { kind: 'mail' } },
  { method: 'POST', url: 'https://api.example.com/v1/forms/{form}/submit?'.slice(0, -1), body: 'form', fixed: { src: 'agent' }, query: ['dry'] },
  { method: 'DELETE', url: 'https://api.example.com/v1/x/{a}/y/{b}' },
  { method: 'PUT', url: 'https://api.example.com/v1/json', body: 'json' },
  { method: 'GET', url: 'https://API.Example.com/v1/case' },
  { method: 'GET', url: 'https://api.example.com:8443/v1/port/{n}' },
  { method: 'GET', url: 'https://api.example.com/v1/a.b/{c}/d+e' },
];
const BADSPECS: any[] = [
  { method: 'GET', url: 'http://api.example.com/x' }, { method: 'GET', url: 'https://api.example.com/x?a=1' }, { method: 'GET', url: 'https://u:p@api.example.com/x' },
  { method: 'GET', url: 'https://api.example.com/x#f' }, { method: 'get', url: 'https://api.example.com/x' }, { method: 'GET', url: 'not a url' },
  { method: 'GET', url: 'https://api.example.com:443/x' }, { method: 'GET', url: 'https://{host}/x' }, { method: 'GET', url: 'ftp://api.example.com/x' },
];
for (const [i, s] of BADSPECS.entries()) await o.run('httpExtractor', `bad${i}`, extract, [s, { method: s.method, url: 'https://api.example.com/x' }]);
const J = { 'content-type': 'application/json' }, F = { 'content-type': 'application/x-www-form-urlencoded' };
const REQS: Array<[number, any]> = [
  [0, { method: 'GET', url: 'https://api.example.com/v1/items/42' }],
  [0, { method: 'GET', url: 'https://api.example.com/v1/items/42?expand=a&fields=b' }],
  [0, { method: 'GET', url: 'https://api.example.com/v1/items/a%20b' }],
  [0, { method: 'GET', url: 'https://api.example.com/v1/items/%E0%A4%A' }],
  [0, { method: 'GET', url: 'https://api.example.com/v1/items/%ff' }],
  [0, { method: 'GET', url: 'https://api.example.com/v1/items/42?expand=a&expand=b' }],
  [0, { method: 'GET', url: 'https://api.example.com/v1/items/42?other=1' }],
  [0, { method: 'GET', url: 'https://api.example.com/v1/items/42?expand=a+b%20c' }],
  [0, { method: 'GET', url: 'https://api.example.com/v1/items/42?expand' }],
  [0, { method: 'GET', url: 'https://api.example.com/v1/items/42#frag' }],
  [0, { method: 'GET', url: 'https://u@api.example.com/v1/items/42' }],
  [0, { method: 'GET', url: 'https://evil.example.com/v1/items/42' }],
  [0, { method: 'GET', url: 'http://api.example.com/v1/items/42' }],
  [0, { method: 'GET', url: 'https://api.example.com/v1/items/42/extra' }],
  [0, { method: 'GET', url: 'https://api.example.com/v1/items/' }],
  [0, { method: 'POST', url: 'https://api.example.com/v1/items/42' }],
  [0, { method: 'GET', url: 'https://api.example.com/v1/items/42', body: 'x' }],
  [0, { method: 'GET', url: 'https://api.example.com/v1/items/42', body: '' }],
  [0, { method: 'GET', url: 'https://API.EXAMPLE.COM/v1/items/42' }], [0, { method: 'GET', url: 'https://api.example.com:443/v1/items/42' }],
  [0, { method: 'GET', url: 'nope' }], [0, { method: 'GET', url: 'https://api.example.com/v1/items/a/../b' }], [0, { method: 'GET', url: 'https://api.example.com/v1/items/%2e' }],
  [1, { method: 'POST', url: 'https://api.example.com/v1/send', headers: J, body: '{"kind":"mail","to":"a@b.c","n":1}' }],
  [1, { method: 'POST', url: 'https://api.example.com/v1/send', headers: { 'Content-Type': 'application/json; charset=utf-8' }, body: '{"kind":"mail","to":"x"}' }],
  [1, { method: 'POST', url: 'https://api.example.com/v1/send', headers: J, body: '{"kind":"other","to":"x"}' }],
  [1, { method: 'POST', url: 'https://api.example.com/v1/send', headers: J, body: '{"to":"x"}' }],
  [1, { method: 'POST', url: 'https://api.example.com/v1/send', headers: J, body: '{"kind":"mail","to":"x","to":"y"}' }],
  [1, { method: 'POST', url: 'https://api.example.com/v1/send', headers: J, body: '[1]' }], [1, { method: 'POST', url: 'https://api.example.com/v1/send', headers: J, body: 'null' }],
  [1, { method: 'POST', url: 'https://api.example.com/v1/send', headers: J, body: '{bad' }], [1, { method: 'POST', url: 'https://api.example.com/v1/send', headers: J, body: '{"kind":"mail","a":{"b":[1,2,{"c":null}]},"f":1.5}' }],
  [1, { method: 'POST', url: 'https://api.example.com/v1/send', headers: J }], [1, { method: 'POST', url: 'https://api.example.com/v1/send', headers: J, body: '' }],
  [1, { method: 'POST', url: 'https://api.example.com/v1/send', body: '{"kind":"mail"}' }], [1, { method: 'POST', url: 'https://api.example.com/v1/send', headers: F, body: '{"kind":"mail"}' }],
  [1, { method: 'POST', url: 'https://api.example.com/v1/send?x=1', headers: J, body: '{"kind":"mail"}' }],
  [1, { method: 'POST', url: 'https://api.example.com/v1/send', headers: J, body: '{"kind":{"a":1}}' }],
  [2, { method: 'POST', url: 'https://api.example.com/v1/forms/f1/submit', headers: F, body: 'src=agent&a=1&b=x+y%21' }],
  [2, { method: 'POST', url: 'https://api.example.com/v1/forms/f1/submit?dry=1', headers: F, body: 'src=agent' }],
  [2, { method: 'POST', url: 'https://api.example.com/v1/forms/f1/submit', headers: F, body: 'src=other' }],
  [2, { method: 'POST', url: 'https://api.example.com/v1/forms/f1/submit', headers: F, body: 'a=1' }],
  [2, { method: 'POST', url: 'https://api.example.com/v1/forms/f1/submit', headers: F, body: 'src=agent&a=1&a=2' }],
  [2, { method: 'POST', url: 'https://api.example.com/v1/forms/f1/submit', headers: F, body: '?src=agent&=empty&&k' }],
  [2, { method: 'POST', url: 'https://api.example.com/v1/forms/f1/submit', headers: F, body: 'src=agent&%zz=1&q=%E2%82%AC' }],
  [2, { method: 'POST', url: 'https://api.example.com/v1/forms/f1/submit', headers: J, body: 'src=agent' }],
  [2, { method: 'POST', url: 'https://api.example.com/v1/forms/f1/submit', headers: F, body: 'src=agent&dry=1' }],
  [3, { method: 'DELETE', url: 'https://api.example.com/v1/x/1/y/2' }], [3, { method: 'DELETE', url: 'https://api.example.com/v1/x/1/y' }], [3, { method: 'DELETE', url: 'https://api.example.com/v1/x/a.b~c%2Fd/y/2' }],
  [4, { method: 'PUT', url: 'https://api.example.com/v1/json', headers: J, body: '{"a":1,"b":[true]}' }], [4, { method: 'PUT', url: 'https://api.example.com/v1/json', headers: J, body: '{}' }],
  [5, { method: 'GET', url: 'https://api.example.com/v1/case' }], [6, { method: 'GET', url: 'https://api.example.com:8443/v1/port/7' }], [6, { method: 'GET', url: 'https://api.example.com/v1/port/7' }],
  [7, { method: 'GET', url: 'https://api.example.com/v1/a.b/zz/d+e' }], [7, { method: 'GET', url: 'https://api.example.com/v1/aXb/zz/d+e' }],
];
let ri = 0;
for (const [si, r] of REQS) {
  await o.run('httpExtractor', `r${ri++}s${si}`, extract, [SPECS[si], r]);
}
// hostile variants of a few valid requests
let vv = 0;
for (const [si, r] of [REQS[1]!, REQS[22]!, REQS[38]!]) {
  let n = 0; vv++;
  for (const [label, v] of variants(r, { maxPaths: 12 })) if (n++ % 3 === 0 && v && typeof v === 'object') await o.run('httpExtractor', `v${vv}s${si}-${label}`, extract, [SPECS[si], v]);
}
const HDR: any[] = [undefined, {}, { 'Content-Type': 'application/json' }, { accept: 'x', 'idempotency-key': 'k' }, { Accept: 'a', accept: 'b' }, { Host: 'evil' }, { cookie: 'a=b' }, { 'x-http-method-override': 'DELETE' },
  { accept: 'a\nb' }, { accept: 'a\rb' }, { accept: 'a\u0000b' }, { accept: '' }, { 'content-type': 'x', 'CONTENT-TYPE': 'y' }, { Authorization: 'Bearer x' }];
for (const [i, h] of HDR.entries()) {
  await o.run('checkProxyHeaders', `h${i}`, checkProxyHeaders, [h ?? null, [...DEFAULT_PROXY_HEADERS]]);
  await o.run('checkProxyHeaders', `h${i}-wide`, checkProxyHeaders, [h ?? null, ['content-type', 'accept', 'idempotency-key', 'x-extra', 'authorization']]);
}
await o.run('DEFAULT_PROXY_HEADERS', 'const', () => [...DEFAULT_PROXY_HEADERS], []);
await o.run('outboundRequestDigest', 'a', outboundRequestDigest, ['GET', 'https://api.example.com/v1/items/42', {}, null]);
await o.run('outboundRequestDigest', 'b', outboundRequestDigest, ['POST', 'https://api.example.com/v1/send', { 'content-type': 'application/json' }, '{"a":1}']);
await o.run('outboundRequestDigest', 'c', outboundRequestDigest, ['POST', 'https://x/é', { accept: 'é' }, '']);

// ---- release receipts -------------------------------------------------------------------------------------------------
const RBODY = { v: 1, kind: 'pca-release-receipt', action_digest: 'AAAA', provider: 'google', connection_id: 'default', mode: 'proxy', scopes_released: ['a', 'b'], request_digest: 'D', http_status: 200, outcome: 'executed', ts: T0 };
const sign = (b: any, seedB64: string) => signReleaseReceipt(b, unb64u(seedB64));
const RB: any[] = [RBODY, { ...RBODY, mode: 'bearer', request_digest: null, http_status: null, outcome: 'released' }, { ...RBODY, outcome: 'failed', http_status: null }, { ...RBODY, scopes_released: [] }];
for (const [i, b] of RB.entries()) for (const [j, sd] of [V.seed, P.seed].entries()) await o.run('signReleaseReceipt', `b${i}k${j}`, sign, [b, sd]);
const rec0 = sign(RBODY, V.seed);
const RECS: any[] = [rec0, { ...rec0, ts: T0 + 1 }, { ...rec0, sig: rec0.sig.slice(0, -2) + 'AA' }, { ...rec0, sig: 5 }, { ...rec0, outcome: 'failed' }, (({ sig, ...r }: any) => r)(rec0), { ...rec0, alg: 'ml-dsa-65' }, { ...rec0, extra: 1 }, { ...rec0, sig: '' }];
for (const [i, r] of RECS.entries()) for (const [j, pk] of [V.pk, P.pk, 'bad', ''].entries()) await o.run('verifyReleaseReceipt', `r${i}k${j}`, verifyReleaseReceipt, [r, pk]);

// ---- capability chains and PCActns ------------------------------------------------------------------------------------------
const grantFor = (scopes: string[] | null, holder = A.pk, provider = 'google') =>
  mintRoot({ principalSecret: P.sk, principalPublic: P.pk, holder, caveats: scopes === null ? [] : [oauthScopeCaveat(provider, scopes)] });
const actn = (opt: { chain: any[]; signer?: Uint8Array; verb?: string; resource?: string; aud?: string; params?: any; now?: number; counter?: number; nonce?: string; ttlMs?: number; planRootOk?: boolean }) =>
  buildPCActn({
    grant: opt.chain[0], chain: opt.chain, plan: [{ id: 'use', verb: opt.verb ?? 'use_connection', resource: opt.resource ?? 'oauth:google', ...(opt.params !== undefined ? { params_digest: paramsDigest(opt.params) } : {}) }], nodeId: 'use',
    counter: opt.counter ?? 1, signerSecret: opt.signer ?? A.sk, aud: opt.aud ?? 'rs', now: opt.now ?? T0, nonce: opt.nonce ?? `n${opt.counter ?? 1}`,
    ...(opt.params !== undefined ? { params: opt.params } : {}), ...(opt.ttlMs !== undefined ? { ttlMs: opt.ttlMs } : {}),
  });
const jp = (x: any) => JSON.parse(JSON.stringify(x));
const g1 = grantFor(['read', 'write']);
const sub = delegate(g1, S.pk, [oauthScopeCaveat('google', ['read'])], A.sk);
const gA = jp(actn({ chain: [g1] }));
await o.run('receiptActionDigest', 'a', receiptActionDigest, [gA]);
await o.run('receiptActionDigest', 'b', receiptActionDigest, [jp(actn({ chain: [g1], counter: 2 }))]);
await o.run('receiptActionDigest', 'c', receiptActionDigest, [{ ...gA, sig: 'x' }]);

// ---- refreshConnection ---------------------------------------------------------------------------------------------------------
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
const errOut = (e: any) => (e instanceof VaultError
  ? { ok: false, name: e.name, code: e.code, ...(e.code !== 'not_authorized' ? { message: e.message } : {}), ...((e as any).status !== undefined ? { status: (e as any).status } : {}), ...((e as any).missing ? { missing: [...(e as any).missing] } : {}) }
  : { ok: false, name: 'Error' });
const conn = (over: any = {}) => ({ agentId: A.pk, provider: 'google', connectionId: 'default', accessToken: 'AT-old', refreshToken: 'RT-old', expiresAt: T0 - 1000, scopes: ['read', 'write'], authority: { provider: 'google', principal: P.pk, scopes: ['read'] }, createdAt: T0 - 5000, useCount: 2, ...over });
const refreshRef = async (c: any) => {
  const log: any[] = [];
  try {
    const v = await refreshConnection({ connection: c.connection, config: c.config ?? undefined, refreshToken: c.refreshToken, requested: c.requested, fetch: mkTransport(c.script, log), now: c.now, defaultTokenLifetimeMs: c.defaultTokenLifetimeMs });
    return { ok: true, value: v, calls: log };
  } catch (e: any) { return { ...errOut(e), calls: log }; }
};
const CFG = { tokenEndpoint: 'https://oauth2.example.com/token', clientId: 'cid', clientSecret: 'csecret' };
const jwt = (payload: any, parts = 3) => [b64u(new TextEncoder().encode('{"alg":"none"}')), b64u(new TextEncoder().encode(typeof payload === 'string' ? payload : JSON.stringify(payload))), 'sig', 'x', 'y'].slice(0, parts).join('.');
const OKR = (json: any) => [{ ok: true, status: 200, json }];
const REF: Array<[string, any]> = [
  ['basic', { script: OKR({ access_token: 'AT-new', expires_in: 3600 }) }],
  ['rotate', { script: OKR({ access_token: 'AT-new', refresh_token: 'RT-new', expires_in: 60 }) }],
  ['noexpiry', { script: OKR({ access_token: 'AT-new' }) }],
  ['zero-expiry', { script: OKR({ access_token: 'AT-new', expires_in: 0 }) }],
  ['neg-expiry', { script: OKR({ access_token: 'AT-new', expires_in: -5 }) }],
  ['frac-expiry', { script: OKR({ access_token: 'AT-new', expires_in: 1.5 }) }],
  ['str-expiry', { script: OKR({ access_token: 'AT-new', expires_in: '60' }) }],
  ['scope-echo', { script: OKR({ access_token: 'AT-new', expires_in: 60, scope: '  read   write\tadmin ' }) }],
  ['scope-blank', { script: OKR({ access_token: 'AT-new', expires_in: 60, scope: '   ' }) }],
  ['scope-comma', { script: OKR({ access_token: 'AT-new', expires_in: 60, scope: 'a,b c' }) }],
  ['narrow', { config: { ...CFG, supportsScopeNarrowing: true }, requested: ['read'], script: OKR({ access_token: 'AT-new', expires_in: 60 }) }],
  ['narrow-empty', { config: { ...CFG, supportsScopeNarrowing: true }, requested: [], script: OKR({ access_token: 'AT-new', expires_in: 60 }) }],
  ['narrow-echo', { config: { ...CFG, supportsScopeNarrowing: true }, requested: ['read'], script: OKR({ access_token: 'AT-new', expires_in: 60, scope: 'read write' }) }],
  ['no-narrow-flag', { config: { ...CFG, supportsScopeNarrowing: false }, requested: ['read'], script: OKR({ access_token: 'AT-new', expires_in: 60 }) }],
  ['public-client', { config: { tokenEndpoint: CFG.tokenEndpoint, clientId: 'cid' }, script: OKR({ access_token: 'AT-new', expires_in: 60 }) }],
  ['extra-params', { config: { ...CFG, extraParams: { audience: 'api://x', tenant: 'a b&c' } }, script: OKR({ access_token: 'AT-new', expires_in: 60 }) }],
  ['extra-override', { config: { ...CFG, extraParams: { client_id: 'evil', grant_type: 'x' } }, script: OKR({ access_token: 'AT-new', expires_in: 60 }) }],
  ['unicode-secret', { config: { ...CFG, clientSecret: 'sé cret/+=' }, refreshToken: 'RT é', script: OKR({ access_token: 'AT-new', expires_in: 60 }) }],
  ['jwt-exp', { script: OKR({ access_token: jwt({ exp: 1900000000 }) }) }],
  ['jwt-exp-frac', { script: OKR({ access_token: jwt({ exp: 1900000000.5 }) }) }],
  ['jwt-exp-str', { script: OKR({ access_token: jwt({ exp: '1900000000' }) }) }],
  ['jwt-no-exp', { script: OKR({ access_token: jwt({ sub: 'x' }) }) }],
  ['jwt-array', { script: OKR({ access_token: jwt('[1]') }) }],
  ['jwt-garbage', { script: OKR({ access_token: jwt('not json') }) }],
  ['jwt-2part', { script: OKR({ access_token: jwt({ exp: 1900000000 }, 2) }) }],
  ['jwt-4part', { script: OKR({ access_token: jwt({ exp: 1900000000 }, 4) }) }],
  ['jwt-5part', { script: OKR({ access_token: jwt({ exp: 1900000000 }, 5) }) }],
  ['jwt-expires_in-wins', { script: OKR({ access_token: jwt({ exp: 1900000000 }), expires_in: 10 }) }],
  ['no-token', { script: OKR({ expires_in: 60 }) }], ['empty-token', { script: OKR({ access_token: '' }) }], ['num-token', { script: OKR({ access_token: 5 }) }],
  ['array-body', { script: OKR([1]) }], ['null-body', { script: OKR(null) }], ['string-body', { script: OKR('x') }],
  ['bad-json', { script: [{ ok: true, status: 200, jsonThrows: true }] }],
  ['http-400', { script: [{ ok: false, status: 400, text: '{"error":"invalid_grant"}' }] }],
  ['http-500-long', { script: [{ ok: false, status: 500, text: 'x'.repeat(400) }] }],
  ['http-leak', { script: [{ ok: false, status: 400, text: 'bad RT-old and csecret and AT-old here' }] }],
  ['http-unreadable', { script: [{ ok: false, status: 502, textThrows: true }] }],
  ['transport-throw', { script: [{ throws: 'connect ECONNREFUSED' }] }],
  ['transport-leak', { script: [{ throws: 'boom csecret RT-old' }] }],
  ['no-config', { config: null, script: OKR({ access_token: 'AT-new' }) }],
  ['no-transport', { script: undefined }],
  ['no-refresh-conn-scopes', { connection: conn({ scopes: [] }), script: OKR({ access_token: 'AT-new', expires_in: 60 }) }],
];
for (const [name, ov] of REF) {
  const c: any = { connection: conn(), config: CFG, refreshToken: 'RT-old', requested: ['read', 'write'], now: T0, defaultTokenLifetimeMs: 300000, script: [], ...ov };
  if (!('script' in ov)) c.script = undefined;
  if (c.config === null) delete c.config;
  await o.run('refreshConnection', name, refreshRef, [c]);
}

// ---- envelope-encrypted store (reference decrypt of independently sealed records) -----------------------------------------------------
const ALG = 'aes-256-gcm';
const sealFixed = (kk: Uint8Array, aad: Uint8Array, plain: Uint8Array, iv: Uint8Array) => { const c = createCipheriv(ALG, kk, iv); c.setAAD(aad); const ct = Buffer.concat([c.update(plain), c.final()]); return new Uint8Array(Buffer.concat([iv, ct, c.getAuthTag()])); };
const aadOf = (k: any, field: string) => new Uint8Array(Buffer.from(['pca-connect/v1', field, k.agentId, k.provider, k.connectionId].map((p) => `${Buffer.byteLength(p)}:${p}`).join('|')));
const ring = { k1: seed('connect/ring1'), k2: seed('connect/ring2') };
const envelope = (k: any, field: string, plain: string, keyId: string, n: number) => {
  const dek = seed(`connect/dek${n}`);
  const aad = aadOf(k, field);
  const wrapped = sealFixed((ring as any)[keyId], aad, dek, seed(`connect/wiv${n}`).slice(0, 12));
  const sealed = sealFixed(dek, aad, new Uint8Array(Buffer.from(plain)), seed(`connect/siv${n}`).slice(0, 12));
  return ['pca1', b64u(new Uint8Array(Buffer.from(keyId))), b64u(wrapped), b64u(sealed)].join('.');
};
const decryptRef = async (c: any) => {
  const inner = new InMemoryConnectionStore();
  await inner.set(c.record);
  const w = new LocalKeyWrapper(Object.fromEntries(Object.entries(c.ring).map(([k, v]) => [k, unb64u(v as string)])), c.active);
  const store = new EncryptedConnectionStore(inner, w);
  try { const r = await store.get(c.key); return { ok: true, value: r === undefined ? null : cloneConnection(r) }; } catch (e: any) { return errOut(e); }
};
const ringJ = Object.fromEntries(Object.entries(ring).map(([k, v]) => [k, b64u(v)]));
const kk = { agentId: A.pk, provider: 'google', connectionId: 'default' };
const c0 = conn();
const sealedRec = (over: any = {}, n = 1) => ({ ...c0, accessToken: envelope(kk, 'access', 'AT-secret', 'k1', n), refreshToken: envelope(kk, 'refresh', 'RT-secret', 'k1', n + 10), ...over });
const flip = (s: string) => s.slice(0, -3) + (s.slice(-3, -2) === 'A' ? 'B' : 'A') + s.slice(-2);
const DEC: Array<[string, any, any?]> = [
  ['ok', sealedRec()], ['ok-no-refresh', (({ refreshToken, ...r }: any) => r)(sealedRec())],
  ['ok-k2', sealedRec({ accessToken: envelope(kk, 'access', 'AT-k2', 'k2', 3), refreshToken: envelope(kk, 'refresh', 'RT-k2', 'k2', 4) })],
  ['plaintext', c0], ['tampered-access', sealedRec({ accessToken: flip(sealedRec().accessToken) })],
  ['swapped-fields', sealedRec({ accessToken: sealedRec().refreshToken, refreshToken: sealedRec().accessToken })],
  ['other-provider-aad', sealedRec({ accessToken: envelope({ ...kk, provider: 'slack' }, 'access', 'AT-x', 'k1', 5) })],
  ['unknown-key', sealedRec({ accessToken: envelope(kk, 'access', 'AT-x', 'k1', 6).replace(/^pca1\.[^.]+/, 'pca1.' + b64u(new Uint8Array(Buffer.from('gone')))) })],
  ['bad-prefix', sealedRec({ accessToken: sealedRec().accessToken.replace('pca1', 'pca2') })],
  ['five-parts', sealedRec({ accessToken: sealedRec().accessToken + '.x' })], ['short', sealedRec({ accessToken: 'pca1.a.b.c' })],
  ['non-b64', sealedRec({ accessToken: 'pca1.!!.!!.!!' })], ['empty', sealedRec({ accessToken: '' })],
  ['key-mismatch', sealedRec({ provider: 'slack' }), { ...kk }], ['absent', null],
  ['unicode-token', sealedRec({ accessToken: envelope(kk, 'access', 'AT-é€😀', 'k1', 7) })],
];
for (const [name, rec, kOver] of DEC) {
  const c: any = { ring: ringJ, active: 'k1', key: kOver ?? kk, record: rec };
  if (rec === null) { c.record = { ...c0, agentId: 'zz' }; c.key = { ...kk }; }
  await o.run('decryptRecord', name, decryptRef, [c]);
}

// ---- TokenVault scenarios --------------------------------------------------------------------------------------------------------
async function vaultRef(s: any) {
  const nowRef = { v: s.nowMs };
  const store = new InMemoryConnectionStore();
  const fetchLog: any[] = [], proxyLog: any[] = [], receipts: any[] = [];
  const op = s.opts ?? {};
  const table: any = s.actionsTable;
  let pi = 0;
  const options: any = {
    strict: false, store, now: () => nowRef.v, fetch: mkTransport(s.fetchScript, fetchLog),
    ...(op.insecureBearerRelease ? { insecureBearerRelease: true } : {}), ...(op.insecureSkipPlanRootCheck ? { insecureSkipPlanRootCheck: true } : {}),
    ...(op.authorizedPlanRoots ? { authorizedPlanRoots: op.authorizedPlanRoots } : {}), ...(op.audience !== undefined ? { audience: op.audience } : {}),
    ...(op.expiryLeewayMs !== undefined ? { expiryLeewayMs: op.expiryLeewayMs } : {}), ...(op.defaultTokenLifetimeMs !== undefined ? { defaultTokenLifetimeMs: op.defaultTokenLifetimeMs } : {}),
    ...(op.requireActionBinding !== undefined ? { requireActionBinding: op.requireActionBinding } : {}), ...('useVerb' in op ? { useVerb: op.useVerb } : {}),
    ...(op.defaultConnectionId !== undefined ? { defaultConnectionId: op.defaultConnectionId } : {}), ...(op.providers ? { providers: op.providers } : {}),
    ...(op.pqPins ? { pqPins: op.pqPins } : {}), ...(op.maxProxyResponseBytes !== undefined ? { maxProxyResponseBytes: op.maxProxyResponseBytes } : {}),
    ...(op.replay ? { replay: new InMemoryReplayStore() } : {}),
    ...(op.revoked ? { isRevoked: () => { if (op.revoked === 'throws') throw new Error('src down'); return op.revoked === 'yes'; } } : {}),
    ...(table ? { actions: (verb: string) => { const t = table[verb]; return t === undefined ? undefined : { verb: t.verb, def_digest: t.def_digest, confirmed: t.confirmed, upstream: t.upstream, ...(t.extract ? { extract: httpExtractor(t.extract) } : {}) }; } } : {}),
    ...(op.proxy ? { proxyFetch: async (req: any) => { proxyLog.push({ method: req.method, url: req.url, headers: req.headers, body: req.body ?? null, redirect: req.redirect }); const r = s.proxyScript[Math.min(pi++, s.proxyScript.length - 1)]; if (r.throws) throw new Error('net'); return { status: r.status, headers: r.headers, body: r.body }; } } : {}),
    ...(op.receiptSeed ? { receipts: { secretKey: unb64u(op.receiptSeed), sink: (r: any) => { receipts.push(r); if (op.failingSink) throw new Error('sink'); } } } : {}),
  };
  const vault = new TokenVault(options);
  const results: any[] = [];
  const rec = async (f: () => Promise<any>) => { try { results.push({ ok: true, value: jsonOut(await f()) }); } catch (e: any) { results.push(errOut(e)); } };
  for (const c of s.calls) {
    if (c.op === 'put') await rec(async () => vault.putConnection(c.args));
    else if (c.op === 'get') await rec(async () => vault.getConnectionToken(c.pcActn, c.args));
    else if (c.op === 'proxy') await rec(async () => { const r = await vault.proxyCall(c.pcActn, c.request, c.args); return { response: r.response, ...(r.receipt ? { receipt: r.receipt } : {}) }; });
    else if (c.op === 'delete') await rec(async () => { await vault.deleteConnection(c.agentId, c.provider, c.connectionId); return null; });
    else if (c.op === 'now') nowRef.v = c.now;
  }
  const out: any[] = [];
  for (const k of s.watch ?? []) { const g = await store.get(k); out.push(g === undefined ? null : cloneConnection(g)); }
  return { results, store: out, receipts, fetchCalls: fetchLog, proxyCalls: proxyLog };
}
const runV = (name: string, s: any) => o.run('vault', name, vaultRef, [s]);
const putArgs = (over: any = {}) => ({ agentId: A.pk, provider: 'google', accessToken: 'AT-1', refreshToken: 'RT-1', expiresAt: T0 + 3_600_000, scopes: ['read', 'write'], authority: { principal: P.pk, scopes: ['read'] }, ...over });
const WATCH = [{ agentId: A.pk, provider: 'google', connectionId: 'default' }, { agentId: A.pk, provider: 'google', connectionId: 'work' }, { agentId: B.pk, provider: 'google', connectionId: 'default' }];
const base = (calls: any[], over: any = {}) => ({ nowMs: T0, opts: { insecureBearerRelease: true, insecureSkipPlanRootCheck: true }, calls, watch: WATCH, ...over });
const put = (a: any = {}) => ({ op: 'put', args: putArgs(a) });
const get = (pcActn: any, args: any = { provider: 'google' }) => ({ op: 'get', pcActn: jp(pcActn), args });
const ok1 = actn({ chain: [g1] });

await runV('release', base([put(), get(ok1)]));
await runV('release-twice', base([put(), get(ok1), get(ok1)]));
await runV('bearer-disabled', base([put(), get(ok1)], { opts: { insecureSkipPlanRootCheck: true } }));
await runV('no-plan-root-policy', base([put(), get(ok1)], { opts: { insecureBearerRelease: true } }));
await runV('plan-root-listed', base([put(), get(ok1)], { opts: { insecureBearerRelease: true, authorizedPlanRoots: [ok1.plan.root] } }));
await runV('plan-root-other', base([put(), get(ok1)], { opts: { insecureBearerRelease: true, authorizedPlanRoots: ['nope'] } }));
await runV('plan-root-empty-list', base([put(), get(ok1)], { opts: { insecureBearerRelease: true, authorizedPlanRoots: [] } }));
await runV('unknown-connection', base([get(ok1)]));
await runV('other-agent', base([put({ agentId: B.pk }), get(ok1)]));
await runV('wrong-principal', base([put({ authority: { principal: S.pk } }), get(ok1)]));
await runV('connection-id', base([put({ connectionId: 'work' }), get(ok1, { provider: 'google', connectionId: 'work' }), get(ok1, { provider: 'google' })]));
await runV('default-connection-id', base([put({ connectionId: 'work' }), get(ok1)], { opts: { insecureBearerRelease: true, insecureSkipPlanRootCheck: true, defaultConnectionId: 'work' } }));
await runV('scope-subset', base([put(), get(ok1, { provider: 'google', scopes: ['read'] })]));
await runV('scope-exceeded', base([put(), get(ok1, { provider: 'google', scopes: ['read', 'admin'] })]));
await runV('scope-default-authority', base([put({ authority: { principal: P.pk, scopes: ['read', 'write'] } }), get(ok1)]));
await runV('scope-authority-exceeds-grant', base([put({ authority: { principal: P.pk, scopes: ['read', 'admin'] } }), get(ok1)]));
await runV('attenuated-chain', base([put({ agentId: S.pk }), get(actn({ chain: [g1, sub], signer: S.sk }), { provider: 'google', scopes: ['read'] }), get(actn({ chain: [g1, sub], signer: S.sk, counter: 2 }), { provider: 'google', scopes: ['read', 'write'] })]));
await runV('no-authority', base([put(), get(actn({ chain: [grantFor(null)] }))]));
await runV('other-provider-grant', base([put(), get(actn({ chain: [grantFor(['read'], A.pk, 'slack')] }))]));
await runV('expired-no-refresh', base([put({ refreshToken: undefined, expiresAt: T0 - 1 }), get(ok1)]));
await runV('within-leeway-no-refresh', base([put({ refreshToken: undefined, expiresAt: T0 + 29_000 }), get(ok1)]));
await runV('leeway-edge', base([put({ refreshToken: undefined, expiresAt: T0 + 30_000 }), get(ok1)]));
await runV('leeway-custom', base([put({ refreshToken: undefined, expiresAt: T0 + 30_001 }), get(ok1)], { opts: { insecureBearerRelease: true, insecureSkipPlanRootCheck: true, expiryLeewayMs: 0 } }));
for (const [name, ov] of REF.slice(0, 20)) {
  const script = (ov as any).script;
  await runV('refresh-' + name, base([put({ expiresAt: T0 - 1, refreshToken: 'RT-old' }), get(ok1, { provider: 'google', scopes: ['read'] }), get(actn({ chain: [g1], counter: 2 }), { provider: 'google', scopes: ['read'] })], {
    opts: { insecureBearerRelease: true, insecureSkipPlanRootCheck: true, providers: { google: (ov as any).config ?? CFG } }, fetchScript: script,
  }));
}
await runV('refresh-no-config', base([put({ expiresAt: T0 - 1 }), get(ok1)], { fetchScript: OKR({ access_token: 'x' }) }));
await runV('refresh-no-fetch', base([put({ expiresAt: T0 - 1 }), get(ok1)], { opts: { insecureBearerRelease: true, insecureSkipPlanRootCheck: true, providers: { google: CFG } } }));
await runV('refresh-fail-keeps-state', base([put({ expiresAt: T0 - 1 }), get(ok1), get(actn({ chain: [g1], counter: 2 }))], { opts: { insecureBearerRelease: true, insecureSkipPlanRootCheck: true, providers: { google: CFG } }, fetchScript: [{ ok: false, status: 500, text: 'down' }, { ok: true, status: 200, json: { access_token: 'AT-2', expires_in: 3600 } }] }));
await runV('audience-pinned', base([put(), get(ok1)], { opts: { insecureBearerRelease: true, insecureSkipPlanRootCheck: true, audience: 'rs' } }));
await runV('audience-wrong', base([put(), get(ok1)], { opts: { insecureBearerRelease: true, insecureSkipPlanRootCheck: true, audience: 'other' } }));
await runV('audience-connection-overrides', base([put({ authority: { principal: P.pk, scopes: ['read'], audience: 'rs' } }), get(ok1)], { opts: { insecureBearerRelease: true, insecureSkipPlanRootCheck: true, audience: 'other' } }));
await runV('audience-connection-wrong', base([put({ authority: { principal: P.pk, scopes: ['read'], audience: 'zzz' } }), get(ok1)]));
await runV('resource-mismatch', base([put(), get(actn({ chain: [g1], resource: 'oauth:slack' }))]));
await runV('verb-mismatch', base([put(), get(actn({ chain: [g1], verb: 'other_verb' }))]));
await runV('verb-skipped', base([put(), get(actn({ chain: [g1], verb: 'other_verb' }))], { opts: { insecureBearerRelease: true, insecureSkipPlanRootCheck: true, useVerb: null } }));
await runV('verb-custom', base([put(), get(actn({ chain: [g1], verb: 'my.verb' }))], { opts: { insecureBearerRelease: true, insecureSkipPlanRootCheck: true, useVerb: 'my.verb' } }));
await runV('binding-off', base([put(), get(actn({ chain: [g1], resource: 'x', verb: 'y' }))], { opts: { insecureBearerRelease: true, insecureSkipPlanRootCheck: true, requireActionBinding: false } }));
await runV('revoked', base([put(), get(ok1)], { opts: { insecureBearerRelease: true, insecureSkipPlanRootCheck: true, revoked: 'yes' } }));
await runV('not-revoked', base([put(), get(ok1)], { opts: { insecureBearerRelease: true, insecureSkipPlanRootCheck: true, revoked: 'no' } }));
await runV('revocation-throws', base([put(), get(ok1)], { opts: { insecureBearerRelease: true, insecureSkipPlanRootCheck: true, revoked: 'throws' } }));
await runV('replay-guard', base([put(), get(ok1), get(ok1), get(actn({ chain: [g1], counter: 2 }))], { opts: { insecureBearerRelease: true, insecureSkipPlanRootCheck: true, replay: true } }));
await runV('replay-refused-does-not-burn', base([put(), get(ok1, { provider: 'google', scopes: ['admin'] }), get(ok1)], { opts: { insecureBearerRelease: true, insecureSkipPlanRootCheck: true, replay: true } }));
await runV('replay-no-nonce', base([put(), get((({ nonce, ...r }: any) => r)(jp(ok1)))], { opts: { insecureBearerRelease: true, insecureSkipPlanRootCheck: true, replay: true } }));
await runV('pcactn-expired', base([put(), { op: 'now', now: T0 + 3_600_001 }, get(ok1)]));
await runV('pcactn-not-yet-valid', base([put(), { op: 'now', now: T0 - 61_000 }, get(ok1)]));
await runV('pcactn-skew-ok', base([put(), { op: 'now', now: T0 - 59_000 }, get(ok1)]));
await runV('signed-by-other', base([put(), get(actn({ chain: [g1], signer: B.sk }))]));
await runV('pq-pin-unused', base([put(), get(ok1)], { opts: { insecureBearerRelease: true, insecureSkipPlanRootCheck: true, pqPins: { [P.pk]: 'AAAA' } } }));
await runV('put-invalid', base([put({ agentId: '' }), put({ accessToken: '' }), put({ refreshToken: '' }), put({ authority: { principal: '' } }), put({ provider: '' }), put({ connectionId: '' })]));
await runV('put-replace-delete', base([put(), put({ accessToken: 'AT-2' }), { op: 'delete', agentId: A.pk, provider: 'google' }, get(ok1)]));
await runV('put-authority-defaults', base([put({ authority: { principal: P.pk } })]));
await runV('put-no-refresh', base([put({ refreshToken: undefined })]));
await runV('put-fractional', base([put({ expiresAt: T0 + 0.5 }), get(ok1)]));

// derived (action-bound) mode
const SPEC_SEND = { method: 'POST', url: 'https://api.example.com/v1/messages/{box}/send', body: 'json', fixed: { kind: 'mail' }, query: ['dry'] };
const ACT = (over: any = {}) => ({ verb: 'mail.send', def_digest: 'dd', confirmed: true, upstream: { provider: 'google', scopes_min: ['write'] }, extract: SPEC_SEND, ...over });
const ptable = (over: any = {}) => ({ 'mail.send': ACT(over) });
const gSend = grantFor(['write']);
const mkSend = (o2: any = {}) => actn({ chain: [gSend], verb: 'mail.send', resource: 'mail/inbox', params: { box: 'inbox', to: 'a@b.c', dry: '1' }, ...o2 });
const sendReq = (over: any = {}) => ({ method: 'POST', url: 'https://api.example.com/v1/messages/inbox/send?dry=1', headers: { 'content-type': 'application/json' }, body: '{"kind":"mail","to":"a@b.c"}', ...over });
const dOpts = (extra: any = {}) => ({ insecureSkipPlanRootCheck: true, proxy: true, receiptSeed: V.seed, ...extra });
const dBase = (calls: any[], over: any = {}) => ({ nowMs: T0, opts: dOpts(), actionsTable: ptable(), proxyScript: [{ status: 200, headers: { 'content-type': 'application/json', 'set-cookie': 'a=b', 'x-echo': 'AT-1' }, body: '{"ok":true,"echo":"AT-1"}' }], calls, watch: WATCH, ...over });
const pput = (a: any = {}) => put({ scopes: ['write'], authority: { principal: P.pk, scopes: ['write'] }, ...a });
const pcall = (pcActn: any, request: any = sendReq(), args: any = { provider: 'google' }) => ({ op: 'proxy', pcActn: jp(pcActn), request, args });
await runV('proxy-ok', dBase([pput(), pcall(mkSend())]));
await runV('proxy-ok-no-receipts', dBase([pput(), pcall(mkSend())], { opts: dOpts({ receiptSeed: undefined }) }));
await runV('proxy-failing-sink', dBase([pput(), pcall(mkSend())], { opts: dOpts({ failingSink: true }) }));
await runV('proxy-refresh', dBase([pput({ expiresAt: T0 - 1 }), pcall(mkSend())], { opts: dOpts({ providers: { google: CFG } }), fetchScript: OKR({ access_token: 'AT-new', expires_in: 3600 }) }));
await runV('proxy-replay', dBase([pput(), pcall(mkSend()), pcall(mkSend())], { opts: dOpts({ replay: true }) }));
await runV('proxy-no-actions', dBase([pput(), pcall(mkSend())], { actionsTable: undefined }));
await runV('proxy-unknown-verb', dBase([pput(), pcall(mkSend({ verb: 'other.verb' }))]));
await runV('proxy-unconfirmed', dBase([pput(), pcall(mkSend())], { actionsTable: ptable({ confirmed: false }) }));
await runV('proxy-wrong-provider', dBase([pput(), pcall(mkSend())], { actionsTable: ptable({ upstream: { provider: 'slack', scopes_min: ['write'] } }) }));
await runV('proxy-no-scopes-min', dBase([pput(), pcall(mkSend())], { actionsTable: ptable({ upstream: { provider: 'google', scopes_min: [] } }) }));
await runV('proxy-verb-mismatch-table', dBase([pput(), pcall(mkSend())], { actionsTable: { 'mail.send': ACT({ verb: 'mail.other' }) } }));
await runV('proxy-no-extractor', dBase([pput(), pcall(mkSend())], { actionsTable: ptable({ extract: undefined }) }));
await runV('proxy-scopes-beyond-min', dBase([pput(), pcall(mkSend(), sendReq(), { provider: 'google', scopes: ['write', 'read'] })]));
await runV('proxy-scopes-narrower', dBase([pput({ scopes: ['read', 'write'], authority: { principal: P.pk, scopes: ['read', 'write'] } }), pcall(mkSend(), sendReq(), { provider: 'google', scopes: ['write'] })], { actionsTable: ptable({ upstream: { provider: 'google', scopes_min: ['read', 'write'] } }) }));
await runV('proxy-conn-lacks-scope', dBase([pput({ scopes: ['read'], authority: { principal: P.pk, scopes: ['read'] } }), pcall(mkSend())]));
await runV('proxy-conn-authority-lacks-scope', dBase([pput({ authority: { principal: P.pk, scopes: ['read'] } }), pcall(mkSend())]));
await runV('proxy-grant-lacks-scope', dBase([pput(), pcall(actn({ chain: [grantFor(['read'])], verb: 'mail.send', resource: 'mail/inbox', params: { box: 'inbox', to: 'a@b.c', dry: '1' } }))]));
await runV('proxy-conn-extra-scope-ok', dBase([pput({ scopes: ['write', 'read'], authority: { principal: P.pk, scopes: ['write', 'read'] } }), pcall(mkSend())]));
await runV('proxy-request-mismatch-query', dBase([pput(), pcall(mkSend(), sendReq({ url: 'https://api.example.com/v1/messages/inbox/send?dry=2' }))]));
await runV('proxy-request-mismatch-body', dBase([pput(), pcall(mkSend(), sendReq({ body: '{"kind":"mail","to":"x@y.z"}' }))]));
await runV('proxy-request-extra-param', dBase([pput(), pcall(mkSend(), sendReq({ body: '{"kind":"mail","to":"a@b.c","bcc":"e"}' }))]));
await runV('proxy-request-other-host', dBase([pput(), pcall(mkSend(), sendReq({ url: 'https://evil.example.com/v1/messages/inbox/send?dry=1' }))]));
await runV('proxy-request-bad-header', dBase([pput(), pcall(mkSend(), sendReq({ headers: { 'content-type': 'application/json', cookie: 'x' } }))]));
await runV('proxy-request-extra-header-ok', dBase([pput(), pcall(mkSend(), sendReq({ headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'Idempotency-Key': 'k1' } }))]));
await runV('proxy-transport-throws', dBase([pput(), pcall(mkSend())], { proxyScript: [{ throws: true }] }));
await runV('proxy-response-too-big', dBase([pput(), pcall(mkSend())], { opts: dOpts({ maxProxyResponseBytes: 10 }) }));
await runV('proxy-response-exact-limit', dBase([pput(), pcall(mkSend())], { opts: dOpts({ maxProxyResponseBytes: 25 }), proxyScript: [{ status: 200, headers: {}, body: '{"ok":true,"echo":"x"}   ' }] }));
await runV('proxy-redirect-3xx', dBase([pput(), pcall(mkSend())], { proxyScript: [{ status: 302, headers: { location: 'https://evil.example.com/AT-1' }, body: '' }] }));
await runV('proxy-multibyte-body', dBase([pput(), pcall(mkSend())], { proxyScript: [{ status: 200, headers: {}, body: 'é€😀 AT-1 é' }] }));
await runV('proxy-5xx', dBase([pput(), pcall(mkSend())], { proxyScript: [{ status: 503, headers: {}, body: 'down' }] }));
await runV('proxy-get-token-derived', dBase([pput({ scopes: ['write'] }), get(mkSend())], { opts: dOpts({ insecureBearerRelease: true }) }));
await runV('proxy-get-token-derived-extra-scopes', dBase([pput({ scopes: ['write', 'read'], authority: { principal: P.pk, scopes: ['write', 'read'] } }), get(mkSend())], { opts: dOpts({ insecureBearerRelease: true }) }));
await runV('proxy-get-token-lifetime-capped', dBase([pput({ expiresAt: T0 + 10_000_000 }), get(mkSend())], { opts: dOpts({ insecureBearerRelease: true }) }));
await runV('proxy-get-token-lifetime-uncapped', dBase([pput({ expiresAt: T0 + 100_000 }), get(mkSend())], { opts: dOpts({ insecureBearerRelease: true }) }));
await runV('proxy-bearer-disabled', dBase([pput(), get(mkSend())]));
await runV('legacy-get-no-proxy-fetch-action-needed', base([put(), { op: 'proxy', pcActn: jp(ok1), request: sendReq(), args: { provider: 'google' } }]));

// hostile variants of a valid PCActn through the legacy release path: only references that yield a typed outcome are recorded
{
  const seedV = jp(ok1);
  let n = 0, kept = 0;
  const scen = (v: any) => base([put(), get(v)], { opts: { insecureBearerRelease: true, insecureSkipPlanRootCheck: true, replay: true } });
  for (const [label, v] of variants(seedV, { depth: 5, maxPaths: 120 })) {
    if (n++ % 4 !== 0) continue;
    const s = reparse(scen(v));
    const r: any = await vaultRef(s);
    if (r.results.some((x: any) => !x.ok && x.name === 'Error')) continue; // a raw TypeError on hostile shape: not a contract
    if (o.add('vault', `variant ${label}`, [s], jsonOut(r))) kept++;
  }
  console.log('hostile vault variants kept:', kept, 'of', n);
}

refWrite(o, 'connect-v2');
