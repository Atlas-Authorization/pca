// Oracle: @atlasauth/pca-oidc (discovery, ID-token verification over a local JWK Set, claims -> PCA principal, the fail-closed
// caching JWKS resolver). Deterministic (Ed25519 and RFC 6979 P-256 signatures from fixed seeds; far-future exp, past iat).
// Writes out/ref-oidc-java.json.gz.
//
// PORTING (fn(args) -> native entry point, comparison rule). A refusal of the reference means the native must throw; a thrown
// OidcVerificationError carries its `code` (config, invalid_token, signature, issuer, audience, expired, issued_at, not_before,
// nonce, azp, at_hash, c_hash, keys, claims) which the native error must expose and the replay compares.
//   discoveryUrl(issuer)                      -> discoveryUrl
//   discoverOidc(issuer, opts, resp)          -> discoverOidc with an injected fetch answering `resp` = {status, text, contentLength?,
//                                                throws?}; opts = {requireHttps?, maxBytes?}. Result: the metadata object.
//   verifyIdToken(token, opts)                -> verifyIdToken; opts.jwks (a JWK Set) = the local JWK Set key resolver, absent = no key
//   oidcPrincipal(claims, opts?)              -> oidcPrincipal (JSON compare)
//   isOidcSubjectCaveat(cv)                   -> isOidcSubjectCaveat
//   jwksScenario(opts, steps)                 -> a resolver (createOidcJwks) driven by steps [{t(ms clock), header, resp}]: `resp` is the
//                                                answer given if the resolver fetches ({status, text} or "throw"); each step yields
//                                                {fetches (total so far), ok:true} or {fetches, ok:false, code}. opts: cacheMaxAgeSec, cooldownSec,
//                                                maxBytes, requireHttps, jwksUri.
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { p256 } from '@noble/curves/p256';
import { createLocalJWKSet } from 'jose';
import * as M0 from '@atlasauth/pca-oidc';
import { Oracle, seed, refWrite } from './lib.mjs';

const M: any = (M0 as any).default ?? M0;
const o = new Oracle('oidc-java', 'tools/pca-audit/oracles/oidc-java.mts', 'TS-reference oracle for OIDC discovery, ID-token verification, principal mapping and the JWKS resolver.');

const b64u = (b: Uint8Array | Buffer | string) => Buffer.from(b as any).toString('base64url');
const PKCS8_ED = Buffer.from('302e020100300506032b657004220420', 'hex');
const edPriv = createPrivateKey({ key: Buffer.concat([PKCS8_ED, Buffer.from(seed('oidc/ed'))]), format: 'der', type: 'pkcs8' });
const edJwk = { ...createPublicKey(edPriv).export({ format: 'jwk' }), kid: 'ed1' } as any;
const edPriv2 = createPrivateKey({ key: Buffer.concat([PKCS8_ED, Buffer.from(seed('oidc/ed2'))]), format: 'der', type: 'pkcs8' });
const edJwk2 = { ...createPublicKey(edPriv2).export({ format: 'jwk' }), kid: 'ed2' } as any;
const esSk = Buffer.from(seed('oidc/es'));
const esPub = p256.getPublicKey(esSk, false);
const esJwk = { kty: 'EC', crv: 'P-256', x: b64u(esPub.slice(1, 33)), y: b64u(esPub.slice(33)), kid: 'es1' } as any;

import { sign as nodeSign } from 'node:crypto';
const signers: Record<string, (data: string) => string> = {
  EdDSA: (d) => b64u(nodeSign(null, Buffer.from(d), edPriv)),
  EdDSA2: (d) => b64u(nodeSign(null, Buffer.from(d), edPriv2)),
  ES256: (d) => b64u(p256.sign(createHash('sha256').update(d).digest(), esSk).toCompactRawBytes()),
};
const mk = (header: any, payload: any, signer = 'EdDSA') => {
  const h = b64u(JSON.stringify(header)), p = b64u(JSON.stringify(payload));
  return `${h}.${p}.${signers[signer](`${h}.${p}`)}`;
};

const ISS = 'https://idp.example.com';
const AUD = 'client-1';
const CLAIMS: any = { iss: ISS, sub: 'user-1', aud: AUD, iat: 1_700_000_000, exp: 4_000_000_000, nonce: 'n1', name: 'Ann', email: 'a@x.example', email_verified: true, preferred_username: 'ann', given_name: 'A', family_name: 'N', picture: 'https://x/p.png', auth_time: 1_699_999_000, cnf: { jwk: { kty: 'OKP', crv: 'Ed25519', x: edJwk.x }, jkt: 'abc' } };
const JWKS = { keys: [edJwk, esJwk] };
const HDR_ED = { alg: 'EdDSA', typ: 'JWT', kid: 'ed1' };
const HDR_ES = { alg: 'ES256', typ: 'JWT', kid: 'es1' };
const OPTS = { issuer: ISS, audience: AUD, jwks: JWKS, nonce: 'n1' };

const verify = async (token: string, opts: any) => {
  if (opts === null) return M.verifyIdToken(token, null);
  const { jwks, ...rest } = opts;
  return M.verifyIdToken(token, { ...rest, ...(jwks !== undefined ? { key: createLocalJWKSet(jwks) } : {}) });
};
let vi = 0;
const V = (label: string, token: any, opts: any = OPTS) => o.run('verifyIdToken', `${label}#${vi++}`, verify, [token, opts]);

const HOST: any[] = [null, true, false, 0, -1, 1.5, 2 ** 53, '', 'x', ' ', 'é', [], ['x'], {}, { x: 1 }];
const tokEd = mk(HDR_ED, CLAIMS);
const tokEs = mk(HDR_ES, CLAIMS, 'ES256');

// ---- baseline and claim variants
await V('ed ok', tokEd);
await V('es ok', tokEs);
await V('ed no nonce opt', tokEd, { ...OPTS, nonce: undefined });
for (const k of Object.keys(CLAIMS)) {
  const del = { ...CLAIMS }; delete del[k];
  await V(`claim ${k} deleted`, mk(HDR_ED, del));
  for (const [i, h] of HOST.entries()) await V(`claim ${k} = host${i}`, mk(HDR_ED, { ...CLAIMS, [k]: h }));
}
for (const [label, c] of Object.entries({
  expired: { exp: 1 }, 'exp now-ish past': { exp: 1_700_000_001 }, 'nbf future': { nbf: 4_000_000_000 }, 'nbf past': { nbf: 1 }, 'iat future': { iat: 4_000_000_000 },
  'multi aud no azp': { aud: [AUD, 'other'] }, 'multi aud azp ok': { aud: [AUD, 'other'], azp: AUD }, 'multi aud azp bad': { aud: [AUD, 'other'], azp: 'zz' },
  'single aud array': { aud: [AUD] }, 'aud other': { aud: 'other' }, 'aud array lacks': { aud: ['a', 'b'], azp: AUD }, 'iss other': { iss: 'https://evil' }, 'azp bad': { azp: 'zz' },
  'exp float': { exp: 4_000_000_000.5 }, 'extra claims': { foo: 1, bar: [1, 2] }, 'cnf array': { cnf: [] }, 'cnf null': { cnf: null },
} as Record<string, any>)) await V(`claims ${label}`, mk(HDR_ED, { ...CLAIMS, ...c }));

// ---- header variants
for (const [label, h, s] of [
  ['alg none', { alg: 'none', typ: 'JWT' }, 'EdDSA'], ['alg HS256', { alg: 'HS256', typ: 'JWT' }, 'EdDSA'], ['alg missing', { typ: 'JWT', kid: 'ed1' }, 'EdDSA'], ['alg empty', { alg: '', kid: 'ed1' }, 'EdDSA'],
  ['alg number', { alg: 5, kid: 'ed1' }, 'EdDSA'], ['alg RS256 vs ed key', { alg: 'RS256', kid: 'ed1' }, 'EdDSA'], ['alg ES256 on ed sig', { alg: 'ES256', kid: 'es1' }, 'EdDSA'],
  ['kid unknown', { alg: 'EdDSA', kid: 'nope' }, 'EdDSA'], ['kid absent', { alg: 'EdDSA' }, 'EdDSA'], ['kid number', { alg: 'EdDSA', kid: 5 }, 'EdDSA'], ['kid es on ed alg', { alg: 'EdDSA', kid: 'es1' }, 'EdDSA'],
  ['signed by other ed key', HDR_ED, 'EdDSA2'], ['no typ', { alg: 'EdDSA', kid: 'ed1' }, 'EdDSA'], ['typ weird', { alg: 'EdDSA', typ: 5, kid: 'ed1' }, 'EdDSA'],
  ['crit b64 true', { ...HDR_ED, crit: ['b64'], b64: true }, 'EdDSA'], ['crit b64 false', { ...HDR_ED, crit: ['b64'], b64: false }, 'EdDSA'], ['crit unknown', { ...HDR_ED, crit: ['x'], x: 1 }, 'EdDSA'],
  ['crit empty', { ...HDR_ED, crit: [] }, 'EdDSA'], ['crit not array', { ...HDR_ED, crit: 'b64' }, 'EdDSA'], ['crit b64 missing', { ...HDR_ED, crit: ['b64'] }, 'EdDSA'],
  ['crit b64 string', { ...HDR_ED, crit: ['b64'], b64: 'x' }, 'EdDSA'], ['jwk header', { ...HDR_ED, jwk: edJwk }, 'EdDSA'], ['extra header', { ...HDR_ED, zz: 1 }, 'EdDSA'],
] as [string, any, string][]) await V(`header ${label}`, mk(h, CLAIMS, s));
await V('es kid wrong', mk({ alg: 'ES256', kid: 'ed1' }, CLAIMS, 'ES256'));
await V('es no kid', mk({ alg: 'ES256' }, CLAIMS, 'ES256'));

// ---- token string variants
const [th, tp, ts] = tokEd.split('.');
const flip = (s: string) => s.slice(0, -2) + (s.at(-2) === 'A' ? 'B' : 'A') + s.at(-1);
for (const [label, t] of Object.entries({
  empty: '', one: 'x', two: `${th}.${tp}`, four: `${tokEd}.x`, 'sig flipped': `${th}.${tp}.${flip(ts)}`, 'sig empty': `${th}.${tp}.`, 'payload swapped': `${th}.${b64u(JSON.stringify({ ...CLAIMS, sub: 'evil' }))}.${ts}`,
  padded: `${th}=.${tp}.${ts}`, 'leading space': ` ${tokEd}`, 'trailing newline': `${tokEd}\n`, 'std alphabet': tokEd.replace(/-/g, '+'), 'upper header': `${th.toUpperCase()}.${tp}.${ts}`,
  'sig short': `${th}.${tp}.${ts.slice(0, 20)}`, 'sig long': `${th}.${tp}.${ts}${ts}`, 'header not json': `${b64u('nope')}.${tp}.${ts}`, 'header array': `${b64u('[1]')}.${tp}.${ts}`,
  'payload not json': `${th}.${b64u('nope')}.${ts}`, 'payload array': `${th}.${b64u('[1]')}.${ts}`, 'dup keys': `${th}.${b64u('{"iss":"a","iss":"b"}')}.${ts}`, 'huge': 'a'.repeat(70_000),
} as Record<string, string>)) await V(`token ${label}`, t);
await o.run('verifyIdToken', 'token not string', verify, [5, OPTS]);
await o.run('verifyIdToken', 'token null', verify, [null, OPTS]);

// ---- option variants
const OV: Record<string, any> = {
  'audience array has': { audience: [AUD, 'z'] }, 'audience array lacks': { audience: ['z'] }, 'audience empty array': { audience: [] }, 'audience empty string': { audience: '' }, 'audience number': { audience: 5 }, 'audience absent': { audience: undefined },
  'issuer other': { issuer: 'https://evil' }, 'issuer empty': { issuer: '' }, 'issuer absent': { issuer: undefined }, 'issuer number': { issuer: 5 },
  'nonce wrong': { nonce: 'zz' }, 'nonce empty': { nonce: '' }, 'azp opt ok': { authorizedParty: AUD }, 'azp opt bad': { authorizedParty: 'zz' },
  'algs ed': { algorithms: ['EdDSA'] }, 'algs es': { algorithms: ['ES256'] }, 'algs empty': { algorithms: [] }, 'algs hs': { algorithms: ['HS256'] }, 'algs rs': { algorithms: ['RS256', 'PS256'] }, 'algs number': { algorithms: [5] }, 'algs string': { algorithms: 'EdDSA' },
  'tol 5': { clockToleranceSec: 5 }, 'tol 0': { clockToleranceSec: 0 }, 'tol neg': { clockToleranceSec: -5 }, 'tol big': { clockToleranceSec: 1e12 },
  'age 0': { maxTokenAgeSec: 0 }, 'age 1': { maxTokenAgeSec: 1 }, 'age huge': { maxTokenAgeSec: 1e12 }, 'age neg': { maxTokenAgeSec: -1 },
  'no key': { jwks: undefined }, 'jwks empty': { jwks: { keys: [] } }, 'jwks malformed': { jwks: { keys: 5 } }, 'jwks keys non-object': { jwks: { keys: [1] } }, 'jwks not object': { jwks: 5 },
  'jwks other key only': { jwks: { keys: [edJwk2] } }, 'jwks two matching': { jwks: { keys: [edJwk, { ...edJwk }] } }, 'jwks only es': { jwks: { keys: [esJwk] } },
  'jwks use enc': { jwks: { keys: [{ ...edJwk, use: 'enc' }] } }, 'jwks use sig': { jwks: { keys: [{ ...edJwk, use: 'sig' }] } }, 'jwks key_ops sign': { jwks: { keys: [{ ...edJwk, key_ops: ['sign'] }] } }, 'jwks key_ops verify': { jwks: { keys: [{ ...edJwk, key_ops: ['verify'] }] } },
  'jwks alg mismatch': { jwks: { keys: [{ ...edJwk, alg: 'ES256' }] } }, 'jwks alg match': { jwks: { keys: [{ ...edJwk, alg: 'EdDSA' }] } }, 'jwks crv wrong': { jwks: { keys: [{ ...edJwk, crv: 'Ed448' }] } },
  'jwks private': { jwks: { keys: [{ ...edJwk, d: b64u(seed('oidc/ed')) }] } }, 'jwks bad x': { jwks: { keys: [{ ...edJwk, x: 'AAAA' }] } }, 'jwks no kid on key': { jwks: { keys: [{ ...edJwk, kid: undefined }] } },
  'jwks es off curve': { jwks: { keys: [{ ...esJwk, y: b64u(Buffer.alloc(32, 1)) }] } }, 'jwks es crv P-384': { jwks: { keys: [{ ...esJwk, crv: 'P-384' }] } },
  'jwks ed2 first': { jwks: { keys: [edJwk2, edJwk, esJwk] } },
};
for (const [label, ov] of Object.entries(OV)) {
  await V(`opts ${label} ed`, tokEd, { ...OPTS, ...ov });
  await V(`opts ${label} es`, tokEs, { ...OPTS, ...ov });
}
await V('opts null', tokEd, null);
await V('opts jwksUri http', tokEd, { issuer: ISS, audience: AUD, jwksUri: 'http://x.example/jwks' });
await V('opts jwksUri empty', tokEd, { issuer: ISS, audience: AUD, jwksUri: '' });

// ---- at_hash / c_hash
const half = (alg: string, v: string) => { const d = createHash(alg === 'EdDSA' ? 'sha512' : 'sha256').update(v, 'ascii').digest(); return b64u(d.subarray(0, d.length / 2)); };
for (const [alg, hdr, signer, jwksOk] of [['EdDSA', HDR_ED, 'EdDSA', true], ['ES256', HDR_ES, 'ES256', true]] as [string, any, string, boolean][]) {
  const at = 'access-token-1', code = 'auth-code-1';
  const good = { at_hash: half(alg, at), c_hash: half(alg, code) };
  await V(`hash ${alg} ok both`, mk(hdr, { ...CLAIMS, ...good }, signer), { ...OPTS, accessToken: at, code });
  await V(`hash ${alg} at wrong`, mk(hdr, { ...CLAIMS, ...good }, signer), { ...OPTS, accessToken: 'other', code });
  await V(`hash ${alg} c wrong`, mk(hdr, { ...CLAIMS, ...good }, signer), { ...OPTS, accessToken: at, code: 'other' });
  await V(`hash ${alg} at missing`, mk(hdr, CLAIMS, signer), { ...OPTS, accessToken: at });
  await V(`hash ${alg} c missing`, mk(hdr, CLAIMS, signer), { ...OPTS, code });
  await V(`hash ${alg} present unchecked`, mk(hdr, { ...CLAIMS, ...good }, signer), OPTS);
  await V(`hash ${alg} empty at`, mk(hdr, { ...CLAIMS, at_hash: half(alg, '') }, signer), { ...OPTS, accessToken: '' });
  await V(`hash ${alg} non-ascii`, mk(hdr, { ...CLAIMS, at_hash: half(alg, 'tokén') }, signer), { ...OPTS, accessToken: 'tokén' });
}

// ---- discovery
for (const [i, u] of ['https://idp.example.com', 'https://idp.example.com/', 'https://idp.example.com//', 'https://idp.example.com/tenant/', '', 'x'].entries()) await o.run('discoveryUrl', `u${i}`, M.discoveryUrl, [u]);
const meta = { issuer: ISS, jwks_uri: 'https://idp.example.com/jwks', authorization_endpoint: 'https://idp.example.com/auth', extra: { a: [1, 2] } };
const J = (x: any) => JSON.stringify(x);
const RESP: Record<string, any> = {
  ok: { status: 200, text: J(meta) }, '404': { status: 404, text: '' }, throws: { throws: true }, 'not json': { status: 200, text: 'nope' }, array: { status: 200, text: '[]' }, null: { status: 200, text: 'null' },
  'no issuer': { status: 200, text: J({ jwks_uri: 'https://x/j' }) }, 'no jwks': { status: 200, text: J({ issuer: ISS }) }, 'issuer mismatch': { status: 200, text: J({ ...meta, issuer: 'https://evil' }) },
  'jwks http': { status: 200, text: J({ ...meta, jwks_uri: 'http://idp.example.com/jwks' }) }, 'issuer number': { status: 200, text: J({ ...meta, issuer: 5 }) }, 'jwks empty': { status: 200, text: J({ ...meta, jwks_uri: '' }) },
  'content-length big': { status: 200, text: J(meta), contentLength: '99999999' }, 'content-length ok': { status: 200, text: J(meta), contentLength: '100' }, 'content-length junk': { status: 200, text: J(meta), contentLength: 'abc' },
  'content-length empty': { status: 200, text: J(meta), contentLength: '' }, 'body big': { status: 200, text: J({ ...meta, pad: 'x'.repeat(200) }) },
};
const dopts: any[] = [{}, { requireHttps: false }, { maxBytes: 100 }, { maxBytes: 0 }, { maxBytes: 100000 }];
const issuers = [ISS, 'http://idp.example.com', '', 'idp', ISS + '/', 'https://evil'];
const disc = async (issuer: any, opts: any, resp: any) => {
  const fetch: any = async () => {
    if (resp.throws) throw new Error('net');
    return { ok: resp.status >= 200 && resp.status < 300, status: resp.status, headers: { get: (k: string) => (k === 'content-length' ? (resp.contentLength ?? null) : null) }, text: async () => resp.text };
  };
  return M.discoverOidc(issuer, { ...opts, fetch });
};
for (const [ri, [rl, r]] of Object.entries(RESP).entries()) for (const [oi, op] of dopts.entries()) for (const [ii, iss] of issuers.entries()) {
  if (ii > 1 && oi > 1) continue;
  await o.run('discoverOidc', `r${ri}-${rl}/o${oi}/i${ii}`, disc, [iss, op, r]);
}
await o.run('discoverOidc', 'issuer number', disc, [5, {}, RESP.ok]);

// ---- principal
const PUB = edJwk.x;
const pclaims: any[] = [CLAIMS, { iss: ISS, sub: 'u' }, { ...CLAIMS, cnf: undefined }, { ...CLAIMS, cnf: { jwk: { kty: 'OKP', crv: 'Ed25519', x: esJwk.x } } }, { ...CLAIMS, cnf: { jwk: { kty: 'OKP', crv: 'Ed25519', x: PUB + '=' } } },
  { ...CLAIMS, cnf: { jwk: { kty: 'OKP', crv: 'Ed448', x: PUB } } }, { ...CLAIMS, cnf: { jwk: { kty: 'EC', crv: 'Ed25519', x: PUB } } }, { ...CLAIMS, cnf: { jwk: null } }, { ...CLAIMS, cnf: 'x' }, { ...CLAIMS, cnf: { jwk: { kty: 'OKP', crv: 'Ed25519', x: 5 } } },
  { ...CLAIMS, iss: '' }, { ...CLAIMS, sub: '' }, { ...CLAIMS, iss: 5 }, { ...CLAIMS, sub: undefined }, { ...CLAIMS, email: null, name: null, email_verified: null, preferred_username: null, auth_time: null }, { ...CLAIMS, email_verified: false }, {}];
const popts: any[] = [undefined, {}, { principalPublic: PUB }, { principalPublic: b64u(Buffer.alloc(32, 7)) }, { principalPublic: b64u(Buffer.alloc(31, 7)) }, { principalPublic: '' }, { principalPublic: PUB + '=' }, { principalPublic: 5 }, { principalPublic: PUB.toUpperCase() }, { principalPublic: null }];
for (const [i, c] of pclaims.entries()) for (const [j, p] of popts.entries()) await o.run('oidcPrincipal', `c${i}p${j}`, M.oidcPrincipal, p === undefined ? [c] : [c, p]);
const cavs: any[] = [{ type: 'oidc_subject', iss: 'a', sub: 'b' }, { type: 'oidc_subject', iss: '', sub: 'b' }, { type: 'oidc_subject', iss: 'a', sub: '' }, { type: 'x', iss: 'a', sub: 'b' }, { type: 'oidc_subject', iss: 'a' }, { type: 'oidc_subject', iss: 1, sub: 'b' }, null, 'x', [], {}, 5, { type: 'oidc_subject', iss: 'a', sub: 'b', extra: 1 }];
for (const [i, c] of cavs.entries()) await o.run('isOidcSubjectCaveat', `c${i}`, M.isOidcSubjectCaveat, [c]);

// ---- JWKS resolver scenarios
const GOOD = { status: 200, text: J(JWKS) };
const scenario = async (opts: any, steps: any[]) => {
  let cur = 0, fetches = 0, queue: any = null;
  const fetch: any = async () => {
    fetches++;
    if (queue === 'throw' || queue === null) throw new Error('net');
    return { ok: queue.status >= 200 && queue.status < 300, status: queue.status, headers: { get: () => null }, text: async () => queue.text };
  };
  const r = M.createOidcJwks({ jwksUri: 'https://idp.example.com/jwks', ...opts, fetch, now: () => cur });
  const out: any[] = [];
  for (const s of steps) {
    cur = s.t; queue = s.resp ?? null;
    try { await r(s.header, { header: s.header }); out.push({ fetches, ok: true }); } catch (e: any) { out.push({ fetches, ok: false, code: e instanceof M.OidcVerificationError ? e.code : 'other' }); }
  }
  return out;
};
const H = (kid?: string, alg = 'EdDSA') => ({ alg, ...(kid ? { kid } : {}) });
const SC: Record<string, [any, any[]]> = {
  'first fetch': [{}, [{ t: 0, header: H('ed1'), resp: GOOD }]],
  cached: [{}, [{ t: 0, header: H('ed1'), resp: GOOD }, { t: 1000, header: H('ed1'), resp: 'throw' }]],
  'stale refetch fails': [{}, [{ t: 0, header: H('ed1'), resp: GOOD }, { t: 600_000, header: H('ed1'), resp: 'throw' }, { t: 600_001, header: H('ed1'), resp: GOOD }]],
  'stale at boundary': [{}, [{ t: 0, header: H('ed1'), resp: GOOD }, { t: 599_999, header: H('ed1'), resp: 'throw' }, { t: 600_000, header: H('ed1'), resp: GOOD }]],
  'unknown kid within cooldown': [{}, [{ t: 0, header: H('ed1'), resp: GOOD }, { t: 10_000, header: H('zz'), resp: GOOD }]],
  'unknown kid after cooldown': [{}, [{ t: 0, header: H('ed1'), resp: GOOD }, { t: 30_000, header: H('zz'), resp: GOOD }, { t: 30_001, header: H('zz'), resp: GOOD }, { t: 60_000, header: H('zz'), resp: GOOD }]],
  'kid refetch fails keeps cache': [{}, [{ t: 0, header: H('ed1'), resp: GOOD }, { t: 40_000, header: H('zz'), resp: 'throw' }, { t: 41_000, header: H('ed1'), resp: 'throw' }]],
  'no kid in header': [{}, [{ t: 0, header: H(), resp: GOOD }, { t: 100_000, header: H(), resp: 'throw' }]],
  '404': [{}, [{ t: 0, header: H('ed1'), resp: { status: 404, text: '' } }]],
  'not jwks': [{}, [{ t: 0, header: H('ed1'), resp: { status: 200, text: '{"keys":5}' } }, { t: 1, header: H('ed1'), resp: { status: 200, text: 'nope' } }, { t: 2, header: H('ed1'), resp: GOOD }]],
  'keys non-object': [{}, [{ t: 0, header: H('ed1'), resp: { status: 200, text: '{"keys":[1]}' } }]],
  'too big': [{ maxBytes: 10 }, [{ t: 0, header: H('ed1'), resp: GOOD }]],
  'maxBytes 0': [{ maxBytes: 0 }, [{ t: 0, header: H('ed1'), resp: GOOD }]],
  'short cache': [{ cacheMaxAgeSec: 1 }, [{ t: 0, header: H('ed1'), resp: GOOD }, { t: 999, header: H('ed1'), resp: 'throw' }, { t: 1000, header: H('ed1'), resp: GOOD }]],
  'zero cache': [{ cacheMaxAgeSec: 0 }, [{ t: 0, header: H('ed1'), resp: GOOD }, { t: 0, header: H('ed1'), resp: GOOD }]],
  'zero cooldown': [{ cooldownSec: 0 }, [{ t: 0, header: H('ed1'), resp: GOOD }, { t: 0, header: H('zz'), resp: GOOD }, { t: 0, header: H('zz'), resp: GOOD }]],
  'no match alg': [{}, [{ t: 0, header: H('ed1', 'RS256'), resp: GOOD }, { t: 1, header: H('ed1', 'HS256'), resp: GOOD }]],
  'es header': [{}, [{ t: 0, header: H('es1', 'ES256'), resp: GOOD }]],
};
for (const [label, [op, steps]] of Object.entries(SC)) await o.run('jwksScenario', label, scenario, [op, steps]);
for (const [label, op] of Object.entries({ http: { jwksUri: 'http://x/j' }, 'http allowed': { jwksUri: 'http://x/j', requireHttps: false }, HTTPS: { jwksUri: 'HTTPS://x/j' }, empty: { jwksUri: '' }, nan: { cacheMaxAgeSec: -1 }, neg: { cooldownSec: -1 }, bigts: { timeoutMs: -5 } } as Record<string, any>)) {
  await o.run('jwksScenario', `cfg ${label}`, scenario, [op, [{ t: 0, header: H('ed1'), resp: GOOD }]]);
}

refWrite(o, 'oidc-java');
