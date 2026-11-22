// 0.6 oracle: @atlasauth/pca-idjag (ID-JAG verify, principal / capability projection, XAA request shapes) for the native ports.
// TS reference: packages/pca-idjag/src/index.ts. Tokens are Ed25519 (deterministic, fixed seeds) signed here; times are far past / far future so
// the vectors do not age. Function-valued options travel as JSON specs the native test turns into the same callable:
//   consumeJti {mode: fresh|seen|throw|truthy}      key {jwks: <JWK Set>} -> a local JWK-Set resolver
//   fetch {responses: [{status, body, headers} | {throws: true}]} -> sequence of replies (the last repeats)
// Run: node node_modules/tsx/dist/cli.mjs --tsconfig tools/pca-audit/oracles/tsconfig.json tools/pca-audit/oracles/idjag.mts
import { createPrivateKey, createPublicKey, sign as nodeSign, type KeyObject } from 'node:crypto';
import { exportJWK, createLocalJWKSet } from 'jose';
import { Oracle, refWrite } from './lib.mjs';

const M: any = await import('../../../packages/pca-idjag/src/index.ts');
const o = new Oracle('idjag', 'tools/pca-audit/oracles/idjag.mts', 'TS-reference oracle for @atlasauth/pca-idjag (ID-JAG verification, principal/capability projection, token-exchange and jwt-bearer request shapes).');

const b64u = (b: Uint8Array | Buffer) => Buffer.from(b).toString('base64url');
const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const keyFromSeed = (n: number): KeyObject => createPrivateKey({ key: Buffer.concat([PKCS8, Buffer.alloc(32, n)]), format: 'der', type: 'pkcs8' });
const jwkOf = async (priv: KeyObject, kid?: string) => ({ ...(await exportJWK(createPublicKey(priv))), ...(kid ? { kid } : {}) });

const K1 = keyFromSeed(1), K2 = keyFromSeed(2), KP = keyFromSeed(7);
const J1: any = await jwkOf(K1, 'k1'), J2: any = await jwkOf(K2, 'k2');
const PUB_P: string = ((await exportJWK(createPublicKey(KP))) as any).x; // principal key (b64u) = the JWK x
const SEED_P = new Uint8Array(32).fill(7);
const HOLDER = b64u(new Uint8Array(32).fill(9));

const mk = (header: any, payload: any, priv: KeyObject | null = K1): string => {
  const h = b64u(Buffer.from(JSON.stringify(header))), p = b64u(Buffer.from(JSON.stringify(payload)));
  const sig = priv ? nodeSign(null, Buffer.from(`${h}.${p}`), priv) : Buffer.alloc(64, 1);
  return `${h}.${p}.${b64u(sig)}`;
};
const HDR = { alg: 'EdDSA', typ: 'oauth-id-jag+jwt', kid: 'k1' };
const ISS = 'https://idp.example.com', AUD = 'https://api.app.example', CLIENT = 'client-1';
const PAY: any = { iss: ISS, sub: 'user-123', aud: AUD, iat: 1700000000, exp: 4102444800, jti: 'jti-1', client_id: CLIENT, act: { sub: 'agent-1' }, scope: 'read write' };
const tok = (over: any = {}, hdr: any = HDR, priv: KeyObject | null = K1) => {
  const p = { ...PAY, ...over };
  for (const k of Object.keys(p)) if (p[k] === undefined) delete p[k];
  return mk(hdr, p, priv);
};
const OPTS: any = { issuer: ISS, audience: AUD, clientId: CLIENT, consumeJti: { mode: 'fresh' }, key: J1 };

// ---- spec -> callable adapters (mirrored by the native test) ------------------------------------------------------------------------------
const dec = (v: any): any => {
  if (Array.isArray(v)) return v.map(dec);
  if (v !== null && typeof v === 'object') {
    if (Object.keys(v).length === 1 && typeof v.$bytes === 'string') return new Uint8Array(Buffer.from(v.$bytes, 'base64url'));
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, dec(x)]));
  }
  return v;
};
const mkFetch = (spec: any) => {
  let i = 0;
  return async () => {
    const r = spec.responses[Math.min(i++, spec.responses.length - 1)];
    if (r.throws) throw new Error('boom');
    const h = Object.fromEntries(Object.entries(r.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
    return { ok: r.status >= 200 && r.status <= 299, status: r.status, headers: { get: (k: string) => (h as any)[k.toLowerCase()] ?? null }, text: async () => r.body };
  };
};
const adapt = (opts: any): any => {
  if (opts === null || typeof opts !== 'object' || Array.isArray(opts)) return opts;
  const a = { ...opts };
  const cj = a.consumeJti;
  if (cj !== null && typeof cj === 'object' && 'mode' in cj) {
    a.consumeJti = (_jti: string, _exp: number) => {
      if (cj.mode === 'throw') throw new Error('store down');
      return cj.mode === 'fresh' ? true : cj.mode === 'truthy' ? 1 : false;
    };
  }
  if (a.key && typeof a.key === 'object' && 'jwks' in a.key) a.key = createLocalJWKSet(a.key.jwks);
  if (a.fetch && typeof a.fetch === 'object') a.fetch = mkFetch(a.fetch);
  return a;
};
const verify = (jwt: any, opts: any) => M.verifyIdJag(jwt, adapt(opts));

// ---- verifyIdJag --------------------------------------------------------------------------------------------------------------------------
const V = (name: string, jwt: any, opts: any = OPTS) => o.run('verifyIdJag', name, verify, [jwt, opts]);
const T = tok();
await V('happy strict', T);
await V('happy loose (strictDraft false, no consume/client)', tok({ client_id: undefined, jti: undefined }, { alg: 'EdDSA', kid: 'k1' }), { issuer: ISS, audience: AUD, strictDraft: false, key: J1 });
await V('loose ignores a wrong typ / client_id', tok({ client_id: 'other' }, { alg: 'EdDSA', typ: 'JWT', kid: 'k1' }), { issuer: ISS, audience: AUD, strictDraft: false, key: J1 });
await V('scope array', tok({ scope: ['a', 'b', '', 3, 'c'] }));
await V('scopes claim', tok({ scope: undefined, scopes: ['x', 'y', 1] }));
await V('scope number falls to scopes', tok({ scope: 5, scopes: ['z'] }));
await V('scope empty string is an empty list', tok({ scope: '' }));
await V('scope unicode whitespace', tok({ scope: 'a b c﻿d\u001ce\u0085f  g' }));
await V('scope missing', tok({ scope: undefined }));
await V('scope object and no scopes', tok({ scope: { a: 1 } }));
await V('required scope present', T, { ...OPTS, requiredScopes: ['read'] });
await V('required scope missing', T, { ...OPTS, requiredScopes: ['admin'] });
await V('required scopes empty list', T, { ...OPTS, requiredScopes: [] });
await V('required scopes not an array is ignored', T, { ...OPTS, requiredScopes: 'admin' });
await V('required scope non-string item', T, { ...OPTS, requiredScopes: [1] });
await V('actor extra members kept', tok({ act: { sub: 'agent-1', iss: 'x', n: 1 } }));
await V('actor missing', tok({ act: undefined }));
await V('actor array', tok({ act: ['agent-1'] }));
await V('actor null', tok({ act: null }));
await V('actor string', tok({ act: 'agent-1' }));
await V('actor empty sub', tok({ act: { sub: '' } }));
await V('actor numeric sub', tok({ act: { sub: 5 } }));
await V('cnf kept', tok({ cnf: { jwk: { kty: 'OKP', crv: 'Ed25519', x: PUB_P }, jkt: 'abc' } }));
await V('cnf array dropped', tok({ cnf: ['x'] }));
await V('nonce match', tok({ nonce: 'n-1' }), { ...OPTS, nonce: 'n-1' });
await V('nonce mismatch', tok({ nonce: 'n-2' }), { ...OPTS, nonce: 'n-1' });
await V('nonce missing', T, { ...OPTS, nonce: 'n-1' });
await V('nonce in token not required', tok({ nonce: 'n-2' }));
await V('aud single array', tok({ aud: [AUD] }));
await V('aud two (azp present)', tok({ aud: [AUD, 'other'], azp: AUD }));
await V('aud two (no azp)', tok({ aud: [AUD, 'other'] }));
await V('aud duplicated', tok({ aud: [AUD, AUD], azp: AUD }));
await V('aud other', tok({ aud: 'https://other' }));
await V('aud missing', tok({ aud: undefined }));
await V('azp mismatch', tok({ azp: 'someone-else' }));
await V('azp match', tok({ azp: AUD }));
await V('iss other', tok({ iss: 'https://evil.example' }));
await V('iss missing', tok({ iss: undefined }));
await V('sub missing', tok({ sub: undefined }));
await V('sub empty', tok({ sub: '' }));
await V('expired', tok({ exp: 1000000000 }));
await V('expired but tolerated', tok({ exp: 1000000000 }), { ...OPTS, clockToleranceSec: 1e10 });
await V('exp missing', tok({ exp: undefined }));
await V('exp string', tok({ exp: '4102444800' }));
await V('nbf in the future', tok({ nbf: 4102444700 }));
await V('nbf string', tok({ nbf: 'x' }));
await V('iat missing', tok({ iat: undefined }));
await V('iat string', tok({ iat: '1700000000' }));
await V('iat missing with maxTokenAge', tok({ iat: undefined }), { ...OPTS, maxTokenAgeSec: 60 });
await V('too old for maxTokenAge', T, { ...OPTS, maxTokenAgeSec: 60 });
await V('maxTokenAge 0 is no limit', T, { ...OPTS, maxTokenAgeSec: 0 });
await V('maxTokenAge huge', T, { ...OPTS, maxTokenAgeSec: 1e10 });
await V('iat in the future with maxTokenAge', tok({ iat: 4102444700 }), { ...OPTS, maxTokenAgeSec: 1e10 });
await V('wrong key', tok({}, HDR, K2));
await V('wrong key, key set picks by kid', tok({}, { ...HDR, kid: 'k2' }, K1), { ...OPTS, key: { jwks: { keys: [J1, J2] } } });
await V('key set, right key', tok({}, { ...HDR, kid: 'k2' }, K2), { ...OPTS, key: { jwks: { keys: [J1, J2] } } });
await V('key set, kid unknown', tok({}, { ...HDR, kid: 'nope' }), { ...OPTS, key: { jwks: { keys: [J1, J2] } } });
await V('key set, no kid in header, two candidates', tok({}, { alg: 'EdDSA', typ: 'oauth-id-jag+jwt' }), { ...OPTS, key: { jwks: { keys: [J1, J2] } } });
await V('key set, no kid in header, one candidate', tok({}, { alg: 'EdDSA', typ: 'oauth-id-jag+jwt' }), { ...OPTS, key: { jwks: { keys: [J1] } } });
await V('key set with a private member', tok(), { ...OPTS, key: { jwks: { keys: [{ ...J1, d: b64u(Buffer.alloc(32, 1)) }] } } });
await V('jwk key with alg mismatch', T, { ...OPTS, key: { ...J1, alg: 'RS256' } });
await V('jwk key with use enc', T, { ...OPTS, key: { ...J1, use: 'enc' } });
await V('jwk key with key_ops without verify', T, { ...OPTS, key: { ...J1, key_ops: ['sign'] } });
await V('jwk key that is private', T, { ...OPTS, key: { ...J1, d: b64u(Buffer.alloc(32, 1)) } });
await V('jwk key wrong length x', T, { ...OPTS, key: { kty: 'OKP', crv: 'Ed25519', x: 'AAAA' } });
await V('payload tampered', (() => { const [h, , s] = T.split('.'); return `${h}.${b64u(Buffer.from(JSON.stringify({ ...PAY, sub: 'attacker' })))}.${s}`; })());
await V('signature bit flipped', (() => { const [h, p, s] = T.split('.'); const b = Buffer.from(s, 'base64url'); b[0] ^= 1; return `${h}.${p}.${b64u(b)}`; })());
await V('signature non-canonical tail', (() => { const [h, p, s] = T.split('.'); return `${h}.${p}.${s.slice(0, -1)}${s.endsWith('A') ? 'B' : 'A'}`; })());
await V('alg none', `${b64u(Buffer.from(JSON.stringify({ alg: 'none', typ: 'oauth-id-jag+jwt' })))}.${T.split('.')[1]}.`);
await V('alg HS256 not allowed', tok({}, { ...HDR, alg: 'HS256' }));
await V('alg missing', tok({}, { typ: 'oauth-id-jag+jwt', kid: 'k1' }));
await V('alg number', tok({}, { ...HDR, alg: 5 }));
await V('algorithms custom ok', T, { ...OPTS, algorithms: ['EdDSA'] });
await V('algorithms excludes EdDSA', T, { ...OPTS, algorithms: ['RS256'] });
await V('algorithms empty', T, { ...OPTS, algorithms: [] });
await V('crit unknown', tok({}, { ...HDR, crit: ['exp'], exp: 1 }));
await V('crit empty', tok({}, { ...HDR, crit: [] }));
await V('crit b64 true', tok({}, { ...HDR, crit: ['b64'], b64: true }));
await V('crit b64 false', tok({}, { ...HDR, crit: ['b64'], b64: false }));
await V('crit b64 missing member', tok({}, { ...HDR, crit: ['b64'] }));
await V('typ wrong', tok({}, { ...HDR, typ: 'JWT' }));
await V('typ missing', tok({}, { alg: 'EdDSA', kid: 'k1' }));
await V('typ case differs', tok({}, { ...HDR, typ: 'OAUTH-ID-JAG+JWT' }));
await V('client_id missing', tok({ client_id: undefined }));
await V('client_id empty', tok({ client_id: '' }));
await V('client_id mismatch', tok({ client_id: 'other' }));
await V('client_id number', tok({ client_id: 1 }));
await V('jti missing', tok({ jti: undefined }));
await V('jti empty', tok({ jti: '' }));
await V('jti number', tok({ jti: 5 }));
await V('jti number loose', tok({ jti: 5 }), { issuer: ISS, audience: AUD, strictDraft: false, key: J1 });
await V('jti replay (seen)', T, { ...OPTS, consumeJti: { mode: 'seen' } });
await V('jti store throws', T, { ...OPTS, consumeJti: { mode: 'throw' } });
await V('jti store truthy but not true', T, { ...OPTS, consumeJti: { mode: 'truthy' } });
await V('config: strict without consumeJti', T, { ...OPTS, consumeJti: undefined });
await V('config: consumeJti not a function', T, { ...OPTS, consumeJti: 'yes' });
await V('config: strict without clientId', T, { ...OPTS, clientId: undefined });
await V('config: strict empty clientId', T, { ...OPTS, clientId: '' });
await V('config: issuer missing', T, { ...OPTS, issuer: undefined });
await V('config: issuer empty', T, { ...OPTS, issuer: '' });
await V('config: audience missing', T, { ...OPTS, audience: undefined });
await V('config: audience array', T, { ...OPTS, audience: [AUD] });
await V('config: opts null', T, null);
await V('config: opts string', T, 'x');
await V('config: no key source', T, { issuer: ISS, audience: AUD, clientId: CLIENT, consumeJti: { mode: 'fresh' } });
await V('config: http jwksUri', T, { ...OPTS, key: undefined, jwksUri: 'http://idp.example.com/jwks' });
await V('config: empty jwksUri', T, { ...OPTS, key: undefined, jwksUri: '' });
await V('discover: server error', T, { ...OPTS, key: undefined, discover: true, fetch: { responses: [{ status: 500, body: '' }] } });
await V('discover: fetch throws', T, { ...OPTS, key: undefined, discover: true, fetch: { responses: [{ throws: true }] } });
await V('discover: issuer mismatch', T, { ...OPTS, key: undefined, discover: true, fetch: { responses: [{ status: 200, body: JSON.stringify({ issuer: 'https://other', jwks_uri: 'https://other/jwks' }) }] } });
await V('discover: not json', T, { ...OPTS, key: undefined, discover: true, fetch: { responses: [{ status: 200, body: 'nope' }] } });
await V('discover: http issuer needs https', T, { ...OPTS, issuer: 'http://idp.example.com', key: undefined, discover: true, fetch: { responses: [{ status: 200, body: '{}' }] } });
await V('discover: no fetch given is not exercised; key wins over discover', T, { ...OPTS, discover: true });
await V('jwt empty', '');
await V('jwt not a string', 5);
await V('jwt null', null);
await V('jwt not compact', 'abc');
await V('jwt two parts', 'a.b');
await V('jwt four parts', `${T}.x`);
await V('jwt at the size limit', 'a'.repeat(16384));
await V('jwt over the size limit', 'a'.repeat(16385));
await V('jwt padded segment', `${T.split('.')[0]}=.${T.split('.')[1]}.${T.split('.')[2]}`);
await V('jwt header not an object', `${b64u(Buffer.from('[1]'))}.${T.split('.')[1]}.${T.split('.')[2]}`);
await V('jwt payload with a duplicate key', (() => { const p = b64u(Buffer.from(JSON.stringify(PAY).replace('"sub":"user-123"', '"sub":"user-123","sub":"x"'))); const h = T.split('.')[0]; return `${h}.${p}.${b64u(nodeSign(null, Buffer.from(`${h}.${p}`), K1))}`; })());
// hostile option values (every JSON type), one option at a time
const HOST: any[] = [true, false, 0, 1, -1, 1.5, '', 'x', [], ['x'], {}, { x: 1 }];
for (const [i, h] of HOST.entries()) {
  for (const k of ['issuer', 'audience', 'nonce', 'requiredScopes', 'clientId', 'strictDraft', 'algorithms', 'maxTokenAgeSec', 'clockToleranceSec']) {
    await V(`hostile ${k} #${i}`, T, { ...OPTS, [k]: h });
  }
}

// ---- idJagToPcaPrincipal -----------------------------------------------------------------------------------------------------------
const baseClaims: any = { iss: ISS, sub: 'user-123', aud: AUD, iat: 1700000000, exp: 4102444800 };
const grantOf = (over: any = {}, claims: any = baseClaims) => ({ iss: ISS, sub: 'user-123', actor: { sub: 'agent-1' }, agent: 'agent-1', audience: AUD, scopes: ['read', 'write'], iat: 1700000000, exp: 4102444800, jti: 'jti-1', oidcClaims: claims, ...over });
const cnfClaims = { ...baseClaims, cnf: { jwk: { kty: 'OKP', crv: 'Ed25519', x: PUB_P } } };
const P = (name: string, g: any, opts?: any) => o.run('idJagToPcaPrincipal', name, M.idJagToPcaPrincipal, opts === undefined ? [g] : [g, opts]);
await P('no key', grantOf());
await P('cnf key', grantOf({}, cnfClaims));
await P('cnf key plus the same principalPublic', grantOf({}, cnfClaims), { principalPublic: PUB_P });
await P('cnf key plus a different principalPublic', grantOf({}, cnfClaims), { principalPublic: b64u(Buffer.alloc(32, 5)) });
await P('principalPublic only', grantOf(), { principalPublic: PUB_P });
await P('principalPublic padded', grantOf(), { principalPublic: PUB_P + '=' });
await P('principalPublic standard alphabet', grantOf(), { principalPublic: b64u(Buffer.alloc(32, 0xfb)).replace(/-/g, '+').replace(/_/g, '/') });
await P('principalPublic too short', grantOf(), { principalPublic: b64u(Buffer.alloc(31, 5)) });
await P('principalPublic too long', grantOf(), { principalPublic: b64u(Buffer.alloc(33, 5)) });
await P('principalPublic empty', grantOf(), { principalPublic: '' });
await P('principalPublic number', grantOf(), { principalPublic: 5 });
await P('principalPublic non-canonical tail', grantOf(), { principalPublic: PUB_P.slice(0, -1) + (PUB_P.endsWith('A') ? 'B' : 'A') });
await P('claims with the profile fields', grantOf({}, { ...baseClaims, email: 'a@b.c', email_verified: false, name: 'N', preferred_username: 'pu', auth_time: 1700000001 }));
await P('claims with null profile fields', grantOf({}, { ...baseClaims, email: null, name: null }));
await P('cnf jwk wrong curve', grantOf({}, { ...baseClaims, cnf: { jwk: { kty: 'OKP', crv: 'Ed448', x: PUB_P } } }));
await P('cnf jwk wrong kty', grantOf({}, { ...baseClaims, cnf: { jwk: { kty: 'EC', crv: 'Ed25519', x: PUB_P } } }));
await P('cnf jwk x not canonical', grantOf({}, { ...baseClaims, cnf: { jwk: { kty: 'OKP', crv: 'Ed25519', x: PUB_P + '=' } } }));
await P('cnf jwk x number', grantOf({}, { ...baseClaims, cnf: { jwk: { kty: 'OKP', crv: 'Ed25519', x: 5 } } }));
await P('cnf jwk null', grantOf({}, { ...baseClaims, cnf: { jwk: null } }));
await P('cnf jkt only', grantOf({}, { ...baseClaims, cnf: { jkt: 'abc' } }));
await P('cnf a string', grantOf({}, { ...baseClaims, cnf: 'x' }));
await P('claims iss missing', grantOf({}, { ...baseClaims, iss: undefined }));
await P('claims sub empty', grantOf({}, { ...baseClaims, sub: '' }));
await P('claims iss number', grantOf({}, { ...baseClaims, iss: 5 }));
await P('grant null', null);
await P('grant string', 'x');
await P('grant without claims', { iss: ISS });
await P('claims null', grantOf({}, null));

// ---- idJagToCapability -------------------------------------------------------------------------------------------------------------
const CAPOPTS = { principalSecret: SEED_P, principalPublic: PUB_P, holder: HOLDER };
const C = (name: string, g: any, opts: any) => o.run('idJagToCapability', name, (gg: any, oo: any) => M.idJagToCapability(dec(gg), dec(oo)), [g, opts]);
await C('basic', grantOf(), CAPOPTS);
await C('with cnf-bound key', grantOf({}, cnfClaims), CAPOPTS);
await C('without jti', grantOf({ jti: undefined }), CAPOPTS);
await C('extra caveats', grantOf(), { ...CAPOPTS, extraCaveats: [{ type: 'max_uses', n: 3 }, { type: 'expires', at: 4102444800 }] });
await C('scopes empty', grantOf({ scopes: [] }), CAPOPTS);
await C('unicode scope', grantOf({ scopes: ['é', '😀'] }), CAPOPTS);
await C('cnf key differs from principalPublic', grantOf({}, cnfClaims), { ...CAPOPTS, principalPublic: b64u(Buffer.alloc(32, 5)) });
await C('principalPublic missing', grantOf(), { ...CAPOPTS, principalPublic: undefined });
await C('principalPublic empty', grantOf(), { ...CAPOPTS, principalPublic: '' });
await C('principalPublic not canonical', grantOf(), { ...CAPOPTS, principalPublic: PUB_P + '=' });
await C('holder missing', grantOf(), { ...CAPOPTS, holder: undefined });
await C('holder empty', grantOf(), { ...CAPOPTS, holder: '' });
await C('secret a string', grantOf(), { ...CAPOPTS, principalSecret: 'x' });
await C('secret missing', grantOf(), { ...CAPOPTS, principalSecret: undefined });
await C('grant null', null, CAPOPTS);
await C('opts null', grantOf(), null);
await C('claims missing iss', grantOf({}, { ...baseClaims, iss: undefined }), CAPOPTS);

// ---- caveat guards / readers -------------------------------------------------------------------------------------------------------
const AUTH = { type: 'idjag_authority', scopes: ['a'], aud: AUD };
const PROV = { type: 'idjag_provenance', iss: ISS, sub: 's', agent: 'a', aud: AUD, iat: 1, exp: 2 };
const authVariants: any[] = [AUTH, { ...AUTH, scopes: [] }, { ...AUTH, scopes: ['a', 1] }, { ...AUTH, scopes: 'a' }, { ...AUTH, aud: '' }, { ...AUTH, aud: 5 }, { ...AUTH, type: 'x' },
  { type: 'idjag_authority' }, { ...AUTH, extra: 1 }, null, undefined, 5, 'x', [], [AUTH], true];
for (const [i, v] of authVariants.entries()) await o.run('isIdJagAuthorityCaveat', `variant #${i}`, M.isIdJagAuthorityCaveat, [v]);
const provVariants: any[] = [PROV, { ...PROV, jti: 'j' }, { ...PROV, iss: 5 }, { ...PROV, sub: null }, { ...PROV, agent: undefined }, { ...PROV, aud: '' }, { ...PROV, iat: '1' }, { ...PROV, exp: true }, { ...PROV, iat: 1.5 },
  { ...PROV, type: 'idjag_authority' }, null, 5, [], undefined];
for (const [i, v] of provVariants.entries()) await o.run('isIdJagProvenanceCaveat', `variant #${i}`, M.isIdJagProvenanceCaveat, [v]);
const capVariants: any[] = [{ caveats: [AUTH, PROV] }, { caveats: [PROV, AUTH] }, { caveats: [{ ...AUTH, scopes: 'bad' }, AUTH] }, { caveats: [{ type: 'other' }] }, { caveats: [] }, { caveats: null }, {},
  { caveats: [null, AUTH, 5] }, { caveats: [{ ...PROV, iat: 'x' }, PROV] }, null, 5, 'x', [], { caveats: 'x' }, { caveats: {} }, { caveats: 5 }];
for (const [i, v] of capVariants.entries()) {
  await o.run('readIdJagAuthority', `variant #${i}`, M.readIdJagAuthority, [v]);
  await o.run('readIdJagProvenance', `variant #${i}`, M.readIdJagProvenance, [v]);
}

// ---- XAA request shapes ------------------------------------------------------------------------------------------------------------
const TX = (name: string, opts: any) => o.run('tokenExchangeRequest', name, M.tokenExchangeRequest, [opts]);
const TE = 'https://idp.example.com/token';
await TX('minimal', { tokenEndpoint: TE, subjectToken: 'st' });
await TX('everything', { tokenEndpoint: TE, subjectToken: 'st', subjectTokenType: 'urn:x:st', actorToken: 'at', actorTokenType: 'urn:x:at', audience: 'app', resource: 'https://api.app', scope: ['a', 'b'], requestedTokenType: 'urn:x:rt', clientId: 'cid', extra: { foo: 'bar' } });
await TX('actor defaults its type', { tokenEndpoint: TE, subjectToken: 'st', actorToken: 'at' });
await TX('actor empty dropped', { tokenEndpoint: TE, subjectToken: 'st', actorToken: '', actorTokenType: 'urn:x:at' });
await TX('scope string with unicode whitespace', { tokenEndpoint: TE, subjectToken: 'st', scope: ' a b c  d ' });
await TX('scope array with junk', { tokenEndpoint: TE, subjectToken: 'st', scope: ['a', '', 5, null, 'b c'] });
await TX('scope empty', { tokenEndpoint: TE, subjectToken: 'st', scope: '' });
await TX('scope empty array', { tokenEndpoint: TE, subjectToken: 'st', scope: [] });
await TX('scope number', { tokenEndpoint: TE, subjectToken: 'st', scope: 5 });
await TX('empty values dropped', { tokenEndpoint: TE, subjectToken: 'st', audience: '', resource: '', clientId: '' });
await TX('extra overrides grant_type in place', { tokenEndpoint: TE, subjectToken: 'st', extra: { grant_type: 'x', zzz: '1', aaa: '2' } });
await TX('extra non-string values dropped', { tokenEndpoint: TE, subjectToken: 'st', extra: { a: 1, b: null, c: true, d: 'ok' } });
await TX('extra numeric-like keys sort first', { tokenEndpoint: TE, subjectToken: 'st', extra: { b: 'x', 10: 'ten', 2: 'two', '01': 'z', a: 'y' } });
await TX('extra an array', { tokenEndpoint: TE, subjectToken: 'st', extra: ['p', 'q'] });
await TX('extra a string', { tokenEndpoint: TE, subjectToken: 'st', extra: 'ab' });
await TX('extra a number', { tokenEndpoint: TE, subjectToken: 'st', extra: 5 });
await TX('encoding of reserved and non-ASCII characters', { tokenEndpoint: TE, subjectToken: 'a b&c=d/e+f?g#h~i*j-k_l.m!n(o)p\'q é 😀 \u0000 %', clientId: 'x y' });
await TX('lone surrogate becomes U+FFFD', { tokenEndpoint: TE, subjectToken: 'a\ud800b' });
await TX('tokenEndpoint missing', { subjectToken: 'st' });
await TX('tokenEndpoint empty', { tokenEndpoint: '', subjectToken: 'st' });
await TX('tokenEndpoint number', { tokenEndpoint: 5, subjectToken: 'st' });
await TX('subjectToken missing', { tokenEndpoint: TE });
await TX('subjectToken empty', { tokenEndpoint: TE, subjectToken: '' });
await TX('opts null', null);
await TX('opts string', 'x');
const JB = (name: string, opts: any) => o.run('jwtBearerAssertion', name, M.jwtBearerAssertion, [opts]);
await JB('minimal', { tokenEndpoint: 'https://app.example/token', assertion: 'jag' });
await JB('everything', { tokenEndpoint: 'https://app.example/token', assertion: 'jag', scope: 'a b', clientId: 'cid', clientAssertion: 'ca', extra: { k: 'v' } });
await JB('scope array', { tokenEndpoint: 'https://app.example/token', assertion: 'jag', scope: ['a', 'b'] });
await JB('scope blank', { tokenEndpoint: 'https://app.example/token', assertion: 'jag', scope: '   ' });
await JB('client assertion empty', { tokenEndpoint: 'https://app.example/token', assertion: 'jag', clientAssertion: '' });
await JB('client assertion number', { tokenEndpoint: 'https://app.example/token', assertion: 'jag', clientAssertion: 5 });
await JB('extra overrides assertion', { tokenEndpoint: 'https://app.example/token', assertion: 'jag', extra: { assertion: 'other', grant_type: 'g' } });
await JB('encoding', { tokenEndpoint: 'https://app.example/token', assertion: 'a.b-c_d~e*f g+h' });
await JB('tokenEndpoint missing', { assertion: 'jag' });
await JB('assertion missing', { tokenEndpoint: 'https://app.example/token' });
await JB('assertion empty', { tokenEndpoint: 'https://app.example/token', assertion: '' });
await JB('opts null', null);

// ---- constants ---------------------------------------------------------------------------------------------------------------------
await o.run('constants', 'all', () => ({
  MAX_ID_JAG_CHARS: M.MAX_ID_JAG_CHARS, IDJAG_AUTHORITY_CAVEAT: M.IDJAG_AUTHORITY_CAVEAT, IDJAG_PROVENANCE_CAVEAT: M.IDJAG_PROVENANCE_CAVEAT,
  GRANT_TYPE_TOKEN_EXCHANGE: M.GRANT_TYPE_TOKEN_EXCHANGE, GRANT_TYPE_JWT_BEARER: M.GRANT_TYPE_JWT_BEARER, TOKEN_TYPE_ID_JAG: M.TOKEN_TYPE_ID_JAG,
  TOKEN_TYPE_ID_TOKEN: M.TOKEN_TYPE_ID_TOKEN, TOKEN_TYPE_ACCESS_TOKEN: M.TOKEN_TYPE_ACCESS_TOKEN, TOKEN_TYPE_JWT: M.TOKEN_TYPE_JWT,
  CLIENT_ASSERTION_TYPE_JWT_BEARER: M.CLIENT_ASSERTION_TYPE_JWT_BEARER,
}), []);

refWrite(o, 'idjag');
