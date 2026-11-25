// Oracle: @atlasauth/pca-dpop (RFC 9449 DPoP proofs, RFC 8705 mTLS confirmation, the PCActn <-> DPoP binding, replay stores, server
// nonces). Deterministic: keys come from seeds; EdDSA, RFC 6979 ECDSA (noble) and RSA PKCS#1 v1.5 signatures are reproducible, so
// the corpus is byte-stable. Randomized signatures (RSA-PSS, jose's ECDSA) never reach the corpus: `createThenVerify` records only
// the verification outcome. Writes out/ref-dpop.json.gz.
// Keys are JWK objects (a private JWK carries `d`); bytes are {"$bytes": b64url}. A throw requires the native to throw (and, for a
// DpopVerificationError, to carry the same `code`).
// PORTING (fn -> Java net.atlasauth.pca.dpop.Dpop; comparison = canonical JSON equality unless noted)
//   constants()                              {allowedAlgs, typ, defaultMaxAgeSec, clockSkewSec, maxProofBytes, inMemoryMaxEntries}
//   jwkThumbprint(jwk, digest?)              Dpop.jwkThumbprint(jwk, digest)                      exact string
//   dpopAlgForJwk(jwk) / dpopAlgMatchesJwk(alg, jwk)    same names                                exact
//   normalizeHtu(url)                        Dpop.normalizeHtu(url)                                exact string (a throw -> must throw)
//   athFor(token)                            Dpop.athFor(token)                                    exact string
//   nonceIssuer(secretB64u|null, ttl|null, ops)   createDpopNonceIssuer(secret, ttl); ops [{op:'issue',now?}|{op:'check',nonce,now?}]
//                                            -> array of results (issue: string, check: boolean); nonce {"$issued": i} = the i-th issued nonce
//   replayStore(maxEntries|null, ops)        createInMemoryDpopReplayStore; ops [{key, exp, now}] -> array of booleans, 'throws' for a store error
//   replayConformance(kind)                  runDpopReplayStoreConformance over kind memory | alwaysTrue | alwaysFalse | noExpiry
//   createDpopProof(input)                   Dpop.createDpopProof: exact token (EdDSA keys only: the signature is deterministic)
//   createThenVerify(input, verifyOpts)      create (any alg) then verify: {claims, jwk, jkt} or a throw
//   verifyDpopProof(proof, opts)             opts = TS names + seenJti:[jti...] | replayStore:{kind:memory|true|false|throws,maxEntries?,preload?:[[key,exp,now]]} |
//                                            nonceIssuer:{secret,ttl?}; result {claims, jwk, jkt, seen?}
//   mtlsCnf / mtlsThumbprint(cert)           cert = {"$bytes"} (DER) or a PEM string
//   assertMtlsBound(cert, cnf)               exact; leafHolderJwk / bindPcaToDpop(p); assertPcaDpop(p, proof, opts)  as verifyDpopProof
import * as M0 from '@atlasauth/pca-dpop';
import { createHash, createPrivateKey, sign as nodeSign, X509Certificate } from 'node:crypto';
import { Oracle, refWrite, seed, variants } from './lib.mjs';
import { T0, aliases, b64, ecKit, ed448Kit, edKit, mkJws, rev, rsaKit, tamperSig, unb, utf8 } from './idkit.mjs';

const M: any = (M0 as any).default ?? M0;
const o = new Oracle('dpop', 'dpop.mts', 'TS-reference oracle for DPoP proofs, mTLS confirmation, the PCActn binding, replay stores and server nonces.');

const K = edKit('dpop/holder');
const K2 = edKit('dpop/other');
const E448 = ed448Kit('dpop/ed448');
const E256 = ecKit('P-256', 'dpop/p256');
const E256H = ecKit('P-256', 'dpop/p256', { lowS: false });
const E384 = ecKit('P-384', 'dpop/p384');
const E521 = ecKit('P-521', 'dpop/p521');
const RSA = rsaKit('dpop/rsa');
const URL1 = 'https://api.example.com/v1/items?q=1#frag';
const NOW = T0 + 10;
const SECRET = b64(seed('dpop/nonce-secret'));

// ---- argument adapters (JSON -> the TS objects) ----
function mkStore(s: any): any {
  if (s.kind === 'memory') {
    const st = M.createInMemoryDpopReplayStore(s.maxEntries === undefined ? {} : { maxEntries: s.maxEntries });
    for (const [k, e, n] of s.preload ?? []) st.addIfAbsent(k, e, n);
    return st;
  }
  if (s.kind === 'true') return { addIfAbsent: () => true };
  if (s.kind === 'false') return { addIfAbsent: () => false };
  return { addIfAbsent: () => { throw new Error('boom'); } };
}
function adapt(opts: any): { out: any; seen?: Set<string> } {
  const out: any = { ...opts };
  let seen: Set<string> | undefined;
  if (opts.seenJti !== undefined) { seen = new Set<string>(opts.seenJti); out.seenJti = seen; }
  if (opts.replayStore !== undefined) out.replayStore = mkStore(opts.replayStore);
  if (opts.nonceIssuer !== undefined) out.nonceIssuer = M.createDpopNonceIssuer({ secret: unb(opts.nonceIssuer.secret), ...(opts.nonceIssuer.ttl !== undefined ? { ttlSec: opts.nonceIssuer.ttl } : {}) });
  return { out, ...(seen ? { seen } : {}) };
}
const withSeen = (r: any, seen?: Set<string>) => ({ claims: r.claims, jwk: r.jwk, jkt: r.jkt, ...(seen ? { seen: [...seen] } : {}) });

const verifyW = async (proof: any, opts: any) => { const a = adapt(opts); return withSeen(await M.verifyDpopProof(proof, a.out), a.seen); };
const assertW = async (p: any, proof: any, opts: any) => { const a = adapt(opts); return withSeen(await M.assertPcaDpop(p, proof, a.out), a.seen); };
const createW = async (input: any) => M.createDpopProof(input);
const createVerifyW = async (input: any, vo: any) => {
  const proof = await M.createDpopProof(input);
  const a = adapt({ method: input.method, url: input.url, maxAgeSec: 300, nowSec: (input.iat ?? T0) + 1, seenJti: [], ...vo });
  return withSeen(await M.verifyDpopProof(proof, a.out), a.seen);
};

// ---- constants ----
await o.run('constants', 'all', () => ({
  allowedAlgs: M.DPOP_ALLOWED_ALGS, typ: M.DPOP_JWT_TYP, defaultMaxAgeSec: M.DPOP_DEFAULT_MAX_AGE_SEC, clockSkewSec: M.DPOP_CLOCK_SKEW_SEC,
  maxProofBytes: M.DPOP_MAX_PROOF_BYTES, inMemoryMaxEntries: M.DPOP_INMEMORY_MAX_ENTRIES,
}), []);

// ---- thumbprints, alg mapping ----
const JWKS: any[] = [
  K.pub, K.priv, E448.pub, E256.pub, E384.pub, E521.pub, RSA.pub, { kty: 'oct', k: 'AAAA' }, { kty: 'oct' }, { kty: 'EC', crv: 'P-256' }, { kty: 'EC', crv: 'secp256k1', x: 'a', y: 'b' },
  { kty: 'OKP', crv: 'X25519', x: 'abc' }, { kty: 'OKP', crv: 'Ed25519' }, { kty: 'OKP', x: 'abc' }, { kty: 'RSA', n: 'abc' }, { kty: 'RSA', e: 'AQAB' }, { kty: 'EC', crv: '', x: 'a', y: 'b' },
  { kty: 'EC', crv: 'P-256', x: 1, y: 'b' }, { kty: 'XYZ' }, { kty: 5 }, {}, { kty: 'OKP', crv: 'Ed25519', x: 'a"b\\cé\u0001' }, { ...K.pub, extra: 1, alg: 'EdDSA', use: 'sig' },
  null, 'str', 5, [], true,
];
for (const [i, j] of JWKS.entries()) {
  await o.run('jwkThumbprint', `j${i}`, async (x: any) => M.jwkThumbprint(x), [j]);
  for (const d of ['sha384', 'sha512']) if (i < 8) await o.run('jwkThumbprint', `j${i}-${d}`, async (x: any, dg: any) => M.jwkThumbprint(x, dg), [j, d]);
  await o.run('dpopAlgForJwk', `j${i}`, M.dpopAlgForJwk, [j]);
  for (const alg of ['EdDSA', 'ES256', 'ES384', 'ES512', 'PS256', 'RS256', 'HS256', 'none', 'ps256', '', 'RS384']) await o.run('dpopAlgMatchesJwk', `j${i}-${alg}`, M.dpopAlgMatchesJwk, [alg, j]);
}
await o.run('jwkThumbprint', 'bad-digest', async (x: any, d: any) => M.jwkThumbprint(x, d), [K.pub, 'md5']);

// ---- normalizeHtu ----
const URLS = [
  'https://api.example.com/v1/items?q=1#frag', 'https://api.example.com', 'https://api.example.com/', 'HTTPS://API.EXAMPLE.COM/Path', 'https://api.example.com:443/x', 'https://api.example.com:8443/x',
  'http://api.example.com:80/x', 'http://api.example.com:8080/x', 'https://api.example.com:0443/x', 'https://api.example.com:/x', 'https://api.example.com:65535/x', 'https://api.example.com:65536/x',
  'https://api.example.com:abc/x', 'https://user:pw@api.example.com/x', 'https://@api.example.com/x', 'https://user@/x', 'https://api.example.com/a/b/../c', 'https://api.example.com/a/./b', 'https://api.example.com/a/b/..',
  'https://api.example.com/a/b/.', 'https://api.example.com/../../a', 'https://api.example.com/a/%2e%2e/b', 'https://api.example.com/a/%2E/b', 'https://api.example.com/a/.%2e/b', 'https://api.example.com//double',
  'https://api.example.com/a b', 'https://api.example.com/a"b', 'https://api.example.com/a<b>c', 'https://api.example.com/a`b', 'https://api.example.com/a{b}c', 'https://api.example.com/%41%7e', 'https://api.example.com/%zz',
  'https://api.example.com/café', 'https://api.example.com/😀', 'https://api.example.com/a?b', 'https://api.example.com/a#b', 'https://api.example.com?x=1', 'https://api.example.com#x', 'https:\\\\api.example.com\\a\\b',
  'https:/api.example.com/x', 'https:api.example.com/x', 'https:///api.example.com/x', '  https://api.example.com/x  ', 'https://api.exa\tmple.com/x\n', 'https://[::1]/x', 'https://[::1]:8443/x', 'https://[2001:db8::ff00:42:8329]/x',
  'https://[2001:0db8:0000:0000:0000:ff00:0042:8329]/x', 'https://[::ffff:192.0.2.1]/x', 'https://[1:2:3:4:5:6:7:8]/x', 'https://[1:0:0:2:0:0:0:3]/x', 'https://[::]/x', 'https://[1::]/x', 'https://[zz]/x', 'https://[::1/x',
  'https://127.0.0.1/x', 'https://127.1/x', 'https://0x7f.1/x', 'https://017700000001/x', 'https://2130706433/x', 'https://256.1.1.1/x', 'https://1.2.3.4.5/x', 'https://1.2.3.4./x', 'https://example.com./x',
  'https://münchen.example/x', 'https://EXAMPLE.com/x', 'https://exa%6dple.com/x', 'https://exa mple.com/x', 'https://a_b.example/x', 'https://example.com%2fevil/x', 'https://a..b/x', 'https://-a.example/x',
  'http://api.example.com/x', 'ws://api.example.com/x', 'wss://api.example.com:443/x', 'ftp://api.example.com:21/x', 'ftp://api.example.com:2121/x',
  'foo://host/path', 'foo://Host:80/path?x', 'foo:///path', 'foo:/path', 'foo:opaque path?x', 'mailto:a@b.c', 'file:///etc/passwd', 'data:text/plain,hi', 'javascript:alert(1)',
  '', ' ', 'example.com/x', '//example.com/x', '/x', 'https://', 'https:', '1http://x', 'http://', 'http://:80/x',
];
for (const [i, u] of URLS.entries()) await o.run('normalizeHtu', `u${i}`, M.normalizeHtu, [u]);
for (const [i, u] of [null, 5, {}, []].entries()) await o.run('normalizeHtu', `bad${i}`, M.normalizeHtu, [u]);

// ---- athFor ----
for (const [i, t] of ['', 'token', 'Bearer abc.def', 'café', '😀', 'lone \ud800 surrogate', 'a'.repeat(5000), '\u0000'].entries()) await o.run('athFor', `t${i}`, M.athFor, [t]);

// ---- nonce issuer ----
const nonceOps = (ops: any[]) => async (secret: any, ttl: any, list: any[]) => {
  const iss = M.createDpopNonceIssuer({ secret: secret === null ? undefined : unb(secret), ...(ttl !== null ? { ttlSec: ttl } : {}) });
  const issued: string[] = [];
  const out: any[] = [];
  for (const op of list) {
    if (op.op === 'issue') { const n = op.now === undefined ? iss.issue() : iss.issue(op.now); issued.push(n); out.push(n); }
    else {
      const nonce = op.nonce && typeof op.nonce === 'object' && '$issued' in op.nonce ? issued[op.nonce.$issued] : op.nonce;
      out.push(op.now === undefined ? iss.check(nonce) : iss.check(nonce, op.now));
    }
  }
  return out;
};
const NW = nonceOps([]);
const SH = b64(seed('dpop/nonce-short').subarray(0, 31));
const ISS = (i: number) => ({ $issued: i });
const nonceScripts: Array<[string, any, any, any[]]> = [
  ['basic', SECRET, null, [{ op: 'issue', now: T0 }, { op: 'check', nonce: ISS(0), now: T0 }, { op: 'check', nonce: ISS(0), now: T0 + 300 }, { op: 'check', nonce: ISS(0), now: T0 + 301 }, { op: 'check', nonce: ISS(0), now: T0 - 5 }, { op: 'check', nonce: ISS(0), now: T0 - 6 }]],
  ['ttl 60', SECRET, 60, [{ op: 'issue', now: T0 }, { op: 'check', nonce: ISS(0), now: T0 + 60 }, { op: 'check', nonce: ISS(0), now: T0 + 61 }]],
  ['ttl frac', SECRET, 0.5, [{ op: 'issue', now: T0 }, { op: 'check', nonce: ISS(0), now: T0 }, { op: 'check', nonce: ISS(0), now: T0 + 1 }]],
  ['distinct nows', SECRET, null, [{ op: 'issue', now: 0 }, { op: 'issue', now: 1 }, { op: 'issue', now: 2 ** 40 }, { op: 'check', nonce: ISS(2), now: 2 ** 40 }, { op: 'check', nonce: ISS(0), now: 0 }]],
  ['forged', SECRET, null, [{ op: 'issue', now: T0 }, { op: 'check', nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', now: T0 }, { op: 'check', nonce: '', now: T0 }, { op: 'check', nonce: 5, now: T0 }, { op: 'check', nonce: null, now: T0 }, { op: 'check', nonce: {}, now: T0 }, { op: 'check', nonce: [], now: T0 }]],
  ['spelling', SECRET, null, [{ op: 'issue', now: T0 }, { op: 'check', nonce: { $issued: 0 }, now: T0 }]],
  ['short secret', SH, null, [{ op: 'issue', now: T0 }]],
  ['no secret', null, null, [{ op: 'issue', now: T0 }]],
  ['zero ttl', SECRET, 0, [{ op: 'issue', now: T0 }]],
  ['negative ttl', SECRET, -1, [{ op: 'issue', now: T0 }]],
  ['fractional now', SECRET, null, [{ op: 'issue', now: 1.5 }]],
  ['other secret', SECRET, null, [{ op: 'issue', now: T0 }]],
];
for (const [n, s, t, ops] of nonceScripts) await o.run('nonceIssuer', n, NW, [s, t, ops]);
{
  // padded / standard-alphabet / trailing-bit aliases of a genuine nonce must be refused
  const iss = M.createDpopNonceIssuer({ secret: unb(SECRET) });
  const n = iss.issue(T0);
  for (const [nm, v] of [['padded', n + '='], ['std', n.replace(/-/g, '+').replace(/_/g, '/')], ['space', n + ' '], ['trunc', n.slice(0, -1)], ['ext', n + 'A'], ['upper', n.toUpperCase()], ['trailing-bits', n.slice(0, -1) + (n.endsWith('A') ? 'B' : 'A')]] as const)
    await o.run('nonceIssuer', `alias ${nm}`, NW, [SECRET, null, [{ op: 'check', nonce: v, now: T0 }]]);
  await o.run('nonceIssuer', 'genuine', NW, [SECRET, null, [{ op: 'check', nonce: n, now: T0 }]]);
}

// ---- in-memory replay store ----
const storeW = async (max: any, ops: any[]) => {
  const st = M.createInMemoryDpopReplayStore(max === null ? {} : { maxEntries: max });
  const out: any[] = [];
  for (const op of ops) { try { out.push(await st.addIfAbsent(op.key, op.exp, op.now)); } catch { out.push('throws'); } }
  return out;
};
const A = (key: string, exp: number, now: number) => ({ key, exp, now });
const storeScripts: Array<[string, any, any[]]> = [
  ['basic', null, [A('a', 200, 100), A('a', 200, 101), A('b', 200, 101), A('a', 200, 199), A('a', 300, 200), A('a', 300, 201)]],
  ['expiry boundary', null, [A('c', 200, 100), A('c', 400, 199), A('c', 400, 200), A('c', 500, 200)]],
  ['max 1', 1, [A('a', 200, 100), A('b', 200, 100), A('a', 200, 101), A('b', 400, 200), A('c', 500, 200)]],
  ['max 2 evicts expired only', 2, [A('a', 150, 100), A('b', 300, 100), A('c', 300, 149), A('c', 300, 150), A('d', 300, 150), A('e', 300, 150)]],
  ['max 3 full', 3, [A('a', 1000, 1), A('b', 1000, 1), A('c', 1000, 1), A('d', 1000, 2), A('a', 1000, 2), A('d', 1000, 1001)]],
  ['max 0', 0, []], ['max -1', -1, []], ['max 1.5', 1.5, []], ['max NaN-ish string', 'x', []],
];
for (const [n, m, ops] of storeScripts) await o.run('replayStore', n, storeW, [m, ops]);

const confW = async (kind: string) => {
  const make = () => {
    if (kind === 'memory') return M.createInMemoryDpopReplayStore();
    if (kind === 'alwaysTrue') return { addIfAbsent: () => true };
    if (kind === 'alwaysFalse') return { addIfAbsent: () => false };
    const seen = new Set<string>();
    return { addIfAbsent: (k: string) => { if (seen.has(k)) return false; seen.add(k); return true; } };
  };
  return M.runDpopReplayStoreConformance(make);
};
for (const k of ['memory', 'alwaysTrue', 'alwaysFalse', 'noExpiry']) await o.run('replayConformance', k, confW, [k]);

// ---- createDpopProof ----
const baseIn = (kit: any, extra: any = {}) => ({ method: 'post', url: URL1, privateKey: kit.priv, publicJwk: kit.pub, iat: T0, jti: 'jti-1', ...extra });
const createCases: Array<[string, any]> = [
  ['base', baseIn(K)], ['get', baseIn(K, { method: 'GET' })], ['nonce+ath', baseIn(K, { nonce: 'n-1', ath: M.athFor('tok') })], ['no iat', null], ['ed448', baseIn(E448)],
  ['pub has private members', baseIn(K, { publicJwk: { ...K.pub, d: b64(new Uint8Array(32).fill(7)) } })], ['pub extra members', baseIn(K, { publicJwk: { ...K.pub, alg: 'EdDSA', use: 'sig', kid: 'k' } })],
  ['method lower unicode', baseIn(K, { method: 'pätch' })], ['url bad', baseIn(K, { url: 'not a url' })], ['url ipv6', baseIn(K, { url: 'https://[::1]:9000/a?b' })],
  ['empty jti', baseIn(K, { jti: '' })], ['iat 0', baseIn(K, { iat: 0 })], ['iat frac', baseIn(K, { iat: 1.5 })], ['iat neg', baseIn(K, { iat: -5 })],
  ['unsupported kty', baseIn(K, { publicJwk: { kty: 'oct', k: 'AAAA' } })], ['unsupported curve', baseIn(K, { publicJwk: { kty: 'OKP', crv: 'X25519', x: K.pub.x } })],
  ['public key as private', baseIn(K, { privateKey: K.pub })], ['other private key', baseIn(K, { privateKey: K2.priv })], ['alg mismatch key', baseIn(K, { publicJwk: E256.pub })],
];
for (const [n, i] of createCases) {
  if (i === null) continue;
  await o.run('createDpopProof', n, createW, [i]);
}
// the signature-randomized and other-alg keys: outcome only
const tv = (kit: any, extra: any = {}) => baseIn(kit, extra);
for (const [n, i, vo] of [
  ['ed25519', tv(K), {}], ['ed448', tv(E448), {}], ['es256', tv(E256), {}], ['es384', tv(E384), {}], ['es512', tv(E521), {}], ['ps256', tv(RSA), {}],
  ['es256 nonce+ath', tv(E256, { nonce: 'n', ath: M.athFor('t') }), { expectedNonce: 'n', accessToken: 't' }], ['ps256 wrong nonce', tv(RSA, { nonce: 'n' }), { expectedNonce: 'x' }],
  ['es256 jkt', tv(E256), { expectedJkt: await M.jwkThumbprint(E256.pub) }], ['es256 bad jkt', tv(E256), { expectedJkt: 'x' }], ['es256 stale', tv(E256), { nowSec: T0 + 1000 }],
  ['es256 other url', tv(E256), { url: 'https://api.example.com/other' }], ['es256 other method', tv(E256), { method: 'GET' }],
  ['mismatched key alg', tv(E256, { publicJwk: K.pub }), {}], ['es256 key with ps pub', tv(RSA, { publicJwk: E256.pub }), {}],
] as Array<[string, any, any]>) await o.run('createThenVerify', n, createVerifyW, [i, vo]);

// ---- verifyDpopProof ----
const PUB = K.pub;
const mkProof = (over: { header?: any; payload?: any; kit?: any; claims?: any; hdrx?: any } = {}) => {
  const kit = over.kit ?? K;
  const header = over.header ?? { typ: 'dpop+jwt', alg: kit.alg === 'RS256' ? 'RS256' : kit.alg, jwk: kit.pub, ...(over.hdrx ?? {}) };
  const payload = over.payload ?? { htm: 'POST', htu: 'https://api.example.com/v1/items', iat: T0, jti: 'jti-1', ...(over.claims ?? {}) };
  return mkJws(header, payload, kit);
};
const BASE = mkProof();
const OPT = { method: 'POST', url: URL1, maxAgeSec: 300, nowSec: NOW, seenJti: [] as string[] };
const ver = (name: string, proof: any, opts: any = {}) => o.run('verifyDpopProof', name, verifyW, [proof, { ...OPT, ...opts }]);
const JKT = await M.jwkThumbprint(PUB);

await ver('valid', BASE);
await ver('valid get lower', BASE, { method: 'post' });
await ver('wrong method', BASE, { method: 'GET' });
await ver('empty method', BASE, { method: '' });
for (const [n, u] of [['query differs', 'https://api.example.com/v1/items?z=9'], ['other path', 'https://api.example.com/v1/other'], ['trailing slash', 'https://api.example.com/v1/items/'], ['port 443', 'https://api.example.com:443/v1/items'], ['port 8443', 'https://api.example.com:8443/v1/items'], ['upper host', 'https://API.example.com/v1/items'], ['http', 'http://api.example.com/v1/items'], ['dots', 'https://api.example.com/v1/x/../items'], ['userinfo', 'https://u:p@api.example.com/v1/items'], ['garbage', 'not a url'], ['empty', ''], ['cred+frag', 'https://api.example.com/v1/items#a?b']] as const) await ver('url ' + n, BASE, { url: u });
for (const [n, now, max] of [['now = iat', T0, 300], ['future -5', T0 - 5, 300], ['future -6', T0 - 6, 300], ['age 300', T0 + 300, 300], ['age 301', T0 + 301, 300], ['max 0 now=iat', T0, 0], ['max 0 +1', T0 + 1, 0], ['max -1', T0, -1], ['max huge', T0 + 1e9, 1e12], ['now frac', T0 + 0.5, 300], ['now 0', 0, 300], ['now neg', -1e9, 300], ['max frac', T0 + 1.4, 1.2]] as const) await ver('time ' + n, BASE, { nowSec: now, maxAgeSec: max });
await ver('jkt ok', BASE, { expectedJkt: JKT });
await ver('jkt bad', BASE, { expectedJkt: JKT.slice(0, -1) + 'A' });
await ver('jkt empty', BASE, { expectedJkt: '' });
// replay
await ver('no store', BASE, { seenJti: undefined });
await ver('no store, opted out', BASE, { seenJti: undefined, requireReplayStore: false });
await ver('no store, opted in', BASE, { seenJti: undefined, requireReplayStore: true });
await ver('seen set empty', BASE, { seenJti: [] });
await ver('seen set hit', BASE, { seenJti: ['jti-1'] });
await ver('seen set other', BASE, { seenJti: ['jti-2', 'x'] });
await ver('store memory', BASE, { seenJti: undefined, replayStore: { kind: 'memory' } });
await ver('store memory seen', BASE, { seenJti: undefined, replayStore: { kind: 'memory', preload: [[`${JKT}.jti-1`, T0 + 305, NOW]] } });
await ver('store memory seen expired', BASE, { seenJti: undefined, replayStore: { kind: 'memory', preload: [[`${JKT}.jti-1`, NOW - 1, NOW - 5]] } });
await ver('store memory other key', BASE, { seenJti: undefined, replayStore: { kind: 'memory', preload: [[`other.jti-1`, T0 + 305, NOW]] } });
await ver('store full', BASE, { seenJti: undefined, replayStore: { kind: 'memory', maxEntries: 1, preload: [['x', T0 + 1000, NOW]] } });
await ver('store true', BASE, { seenJti: undefined, replayStore: { kind: 'true' } });
await ver('store false', BASE, { seenJti: undefined, replayStore: { kind: 'false' } });
await ver('store throws', BASE, { seenJti: undefined, replayStore: { kind: 'throws' } });
await ver('both stores', BASE, { seenJti: ['jti-1'], replayStore: { kind: 'true' } });
await ver('both stores, set fresh', BASE, { seenJti: [], replayStore: { kind: 'false' } });
// nonce / ath
const NONCE = M.createDpopNonceIssuer({ secret: unb(SECRET) });
const nonceFor = (t: number) => NONCE.issue(t);
await ver('expectedNonce absent in proof', BASE, { expectedNonce: 'n1' });
await ver('expectedNonce match', mkProof({ claims: { nonce: 'n1' } }), { expectedNonce: 'n1' });
await ver('expectedNonce mismatch', mkProof({ claims: { nonce: 'n2' } }), { expectedNonce: 'n1' });
await ver('expectedNonce non-string', mkProof({ claims: { nonce: 1 } }), { expectedNonce: '1' });
await ver('expectedNonce empty', mkProof({ claims: { nonce: '' } }), { expectedNonce: '' });
await ver('nonce kept in claims', mkProof({ claims: { nonce: 'n1' } }), {});
await ver('nonce non-string dropped', mkProof({ claims: { nonce: 5 } }), {});
await ver('issuer ok', mkProof({ claims: { nonce: nonceFor(T0 + 5) } }), { nonceIssuer: { secret: SECRET } });
await ver('issuer expired', mkProof({ claims: { nonce: nonceFor(T0 - 400) } }), { nonceIssuer: { secret: SECRET } });
await ver('issuer ttl short', mkProof({ claims: { nonce: nonceFor(T0 - 5) } }), { nonceIssuer: { secret: SECRET, ttl: 10 } });
await ver('issuer ttl edge', mkProof({ claims: { nonce: nonceFor(NOW - 10) } }), { nonceIssuer: { secret: SECRET, ttl: 10 } });
await ver('issuer future', mkProof({ claims: { nonce: nonceFor(NOW + 6) } }), { nonceIssuer: { secret: SECRET } });
await ver('issuer future ok', mkProof({ claims: { nonce: nonceFor(NOW + 5) } }), { nonceIssuer: { secret: SECRET } });
await ver('issuer forged', mkProof({ claims: { nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' } }), { nonceIssuer: { secret: SECRET } });
await ver('issuer missing', BASE, { nonceIssuer: { secret: SECRET } });
await ver('issuer other secret', mkProof({ claims: { nonce: nonceFor(T0) } }), { nonceIssuer: { secret: b64(seed('dpop/other-secret')) } });
await ver('issuer + expectedNonce', mkProof({ claims: { nonce: nonceFor(T0) } }), { nonceIssuer: { secret: SECRET }, expectedNonce: 'x' });
const ATH = M.athFor('access-token-1');
await ver('ath ok', mkProof({ claims: { ath: ATH } }), { accessToken: 'access-token-1' });
await ver('ath wrong token', mkProof({ claims: { ath: ATH } }), { accessToken: 'access-token-2' });
await ver('ath missing', BASE, { accessToken: 'access-token-1' });
await ver('ath non-string', mkProof({ claims: { ath: 5 } }), { accessToken: 'access-token-1' });
await ver('ath empty token', mkProof({ claims: { ath: M.athFor('') } }), { accessToken: '' });
await ver('ath kept', mkProof({ claims: { ath: ATH } }), {});
await ver('ath non-string dropped', mkProof({ claims: { ath: 5 } }), {});
// header shape
const H0 = { typ: 'dpop+jwt', alg: 'EdDSA', jwk: PUB };
const hdr = (h: any, name: string, opts: any = {}) => ver('hdr ' + name, mkProof({ header: h }), opts);
await hdr(H0, 'base');
await hdr({ ...H0, typ: undefined }, 'no typ');
for (const t of ['JWT', 'DPoP+JWT', 'dpop+jwt ', 'application/dpop+jwt', '', 5, null, ['dpop+jwt']]) await hdr({ ...H0, typ: t }, `typ ${JSON.stringify(t)}`);
await hdr({ typ: 'dpop+jwt', alg: 'EdDSA' }, 'no jwk');
for (const j of [null, 'x', 5, true, [], {}, [PUB], { kty: 'OKP' }, { ...PUB, d: 'x' }, { ...PUB, k: 'x' }, { ...K.pub, d: b64(new Uint8Array(32).fill(7)) }, { ...RSA.pub, p: 'x' }, { ...PUB, x: 'AAAA' }, { ...PUB, x: K2.pub.x }, { ...PUB, crv: 'Ed448' }, { kty: 'oct', k: 'AAAA' }, { ...PUB, use: 'enc' }, { ...PUB, key_ops: ['sign'] }, { ...PUB, alg: 'ES256' }, { ...PUB, ext: false }, { ...PUB, extra: [1, 2] }, { kty: 'OKP', crv: 'X25519', x: PUB.x }])
  await hdr({ ...H0, jwk: j }, `jwk ${JSON.stringify(j)}`);
for (const a of ['none', 'HS256', 'HS512', 'ES256', 'ES384', 'ES512', 'PS256', 'RS256', 'RS384', 'PS384', 'eddsa', 'Ed25519', '', null, 5, ['EdDSA'], 'ES256K']) await hdr({ ...H0, alg: a }, `alg ${JSON.stringify(a)}`);
await hdr({ typ: 'dpop+jwt', jwk: PUB }, 'no alg');
await hdr({ ...H0, crit: ['exp'], exp: 1 }, 'crit unknown');
await hdr({ ...H0, crit: ['b64'], b64: true }, 'crit b64 true');
await hdr({ ...H0, crit: ['b64'], b64: false }, 'crit b64 false');
await hdr({ ...H0, crit: [] }, 'crit empty');
await hdr({ ...H0, crit: 'b64' }, 'crit string');
await hdr({ ...H0, crit: [''] }, 'crit empty name');
await hdr({ ...H0, crit: ['b64'] }, 'crit b64 missing');
await hdr({ ...H0, kid: 'k1', cty: 'x', x5c: ['AAAA'], extra: { a: 1 } }, 'extra members');
await ver('hdr duplicate keys', mkProof({ header: '{"typ":"dpop+jwt","alg":"EdDSA","alg":"EdDSA","jwk":' + JSON.stringify(PUB) + '}' }));
await ver('hdr not an object', mkProof({ header: '[1]' }));
await ver('hdr not json', mkProof({ header: 'nope' }));
await ver('hdr BOM', mkProof({ header: '﻿' + JSON.stringify(H0) }));
await ver('hdr whitespace', mkProof({ header: ' ' + JSON.stringify(H0) }));
await ver('hdr float', mkProof({ header: JSON.stringify({ ...H0, n: 1.5 }) }));
await ver('hdr exponent', mkProof({ header: '{"typ":"dpop+jwt","alg":"EdDSA","jwk":' + JSON.stringify(PUB) + ',"n":1e3}' }));
// payload shape
const P0 = { htm: 'POST', htu: 'https://api.example.com/v1/items', iat: T0, jti: 'jti-1' };
const pay = (p: any, name: string, opts: any = {}) => ver('pay ' + name, mkProof({ payload: p }), opts);
await pay(P0, 'base');
for (const [k, vs] of Object.entries({
  htm: [undefined, null, 5, '', 'post', 'GET', ' POST', ['POST']],
  htu: [undefined, null, 5, '', 'https://api.example.com/v1/items/', 'https://api.example.com/v1/items?q=1', 'HTTPS://API.EXAMPLE.COM/v1/items', 'https://api.example.com:443/v1/items'],
  iat: [undefined, null, '1800000000', 0, -1, T0 + 5, T0 + 6, T0 - 300, T0 - 301, 1.5, 2 ** 53 - 1, 1e15, true, [], {}],
  jti: [undefined, null, '', 5, 'x', 'jti-1 ', ['jti-1'], 'a'.repeat(500)],
}) as Array<[string, any[]]>) for (const v of vs) await pay({ ...P0, [k]: v }, `${k}=${JSON.stringify(v)}`);
for (const [n, c] of [['exp future', { exp: 4_000_000_000 }], ['exp past', { exp: 1 }], ['exp string', { exp: '4000000000' }], ['exp null', { exp: null }], ['nbf future', { nbf: 4_000_000_000 }], ['nbf past', { nbf: 1 }], ['nbf string', { nbf: 'x' }],
  ['iss/sub/aud', { iss: 'a', sub: 'b', aud: 'c' }], ['extra obj', { extra: { a: [1, { b: null }] } }], ['proto key', { ['__proto__']: 1 }], ['unicode claim', { u: 'café 😀' }], ['long claim', { long: 'x'.repeat(3000) }]] as Array<[string, any]>)
  await pay({ ...P0, ...c }, n);
await ver('pay dup keys', mkProof({ payload: '{"htm":"POST","htm":"POST","htu":"https://api.example.com/v1/items","iat":1800000000,"jti":"j"}' }));
await ver('pay not object', mkProof({ payload: '[1]' }));
await ver('pay null', mkProof({ payload: 'null' }));
await ver('pay string', mkProof({ payload: '"x"' }));
await ver('pay exponent', mkProof({ payload: '{"htm":"POST","htu":"https://api.example.com/v1/items","iat":1.8e9,"jti":"j"}' }));
await ver('pay float iat', mkProof({ payload: '{"htm":"POST","htu":"https://api.example.com/v1/items","iat":1800000000.5,"jti":"j"}' }));
await ver('pay lone surrogate', mkProof({ payload: '{"htm":"POST","htu":"https://api.example.com/v1/items","iat":1800000000,"jti":"\\ud800"}' }));
// structure variants of the payload (each re-signed)
for (const [n, v] of variants(P0, { hostile: [null, true, 0, 1.5, '', 'x', [], {}, 2 ** 53, '\ud800'] })) await pay(v, 'var ' + n);
// signature / spelling
await ver('sig tampered', tamperSig(BASE));
await ver('sig tampered mid', tamperSig(BASE, 30));
await ver('sig other key', mkProof({ kit: { ...K, sign: K2.sign } }));
await ver('sig empty', BASE.split('.').slice(0, 2).join('.') + '.');
for (const [n, t] of aliases(BASE)) await ver('alias ' + n, t);
{
  const [h, p] = BASE.split('.');
  await ver('payload swapped', `${h}.${b64(utf8(JSON.stringify({ ...P0, jti: 'other' })))}.${(BASE.split('.')[2] as string)}`);
  await ver('header swapped', `${b64(utf8(JSON.stringify({ ...H0, kid: 'x' })))}.${p}.${(BASE.split('.')[2] as string)}`);
}
for (const [n, t] of [['null', null], ['undefined', undefined], ['number', 5], ['object', {}], ['array', [BASE]], ['empty string', ''], ['dots', '..'], ['one segment', 'abc'], ['oversize', 'a'.repeat(8193)], ['at limit', 'a'.repeat(8192)], ['not base64', '!!!.!!!.!!!']] as Array<[string, any]>) await ver('proof ' + n, t);
// the other algorithms: valid, then wrong-key / wrong-alg / wrong-curve
const ALGKITS: Array<[string, any]> = [['ed448', E448], ['es256', E256], ['es256 high-s', E256H], ['es384', E384], ['es512', E521], ['rs256', RSA]];
for (const [n, kit] of ALGKITS) {
  const pr = mkProof({ kit });
  await ver('alg ' + n, pr);
  await ver('alg ' + n + ' tampered', tamperSig(pr));
  await ver('alg ' + n + ' jkt', pr, { expectedJkt: await M.jwkThumbprint(kit.pub) });
  await ver('alg ' + n + ' wrong jkt', pr, { expectedJkt: JKT });
  await ver('alg ' + n + ' with ed jwk', mkProof({ kit, hdrx: { jwk: PUB } }));
  await ver('alg ' + n + ' as EdDSA', mkProof({ kit, hdrx: { alg: 'EdDSA' } }));
  await ver('alg ' + n + ' as ES256', mkProof({ kit, hdrx: { alg: 'ES256' } }));
  await ver('alg ' + n + ' as PS256', mkProof({ kit, hdrx: { alg: 'PS256' } }));
  await ver('alg ' + n + ' as none', mkProof({ kit, hdrx: { alg: 'none' } }));
}
{
  const es = mkProof({ kit: E256 });
  const [h, p, s] = es.split('.') as [string, string, string];
  const sig = Buffer.from(s, 'base64url');
  await ver('es256 sig truncated', `${h}.${p}.${b64(sig.subarray(0, 63))}`);
  await ver('es256 sig long', `${h}.${p}.${b64(Buffer.concat([sig, Buffer.from([0])]))}`);
  await ver('es256 sig zero', `${h}.${p}.${b64(Buffer.alloc(64))}`);
  await ver('es256 sig r=s=n', `${h}.${p}.${b64(Buffer.alloc(64, 0xff))}`);
  await ver('es256 sig swapped halves', `${h}.${p}.${b64(Buffer.concat([sig.subarray(32), sig.subarray(0, 32)]))}`);
  await ver('es256 off-curve jwk', mkProof({ kit: { ...E256, pub: { ...E256.pub, y: b64(Buffer.alloc(32, 1)) } } }));
  await ver('es256 curve P-384 jwk', mkProof({ kit: E256, hdrx: { jwk: E384.pub } }));
  await ver('rsa small key', mkProof({ kit: { ...RSA, pub: { ...RSA.pub, n: b64(Buffer.concat([Buffer.from([1]), Buffer.alloc(100)])) } } }));
  await ver('rsa e=1', mkProof({ kit: RSA, hdrx: { jwk: { ...RSA.pub, e: 'AQ' } } }));
  await ver('rsa oth', mkProof({ kit: RSA, hdrx: { jwk: { ...RSA.pub, oth: [] } } }));
}

// ---- mTLS ----
const derNode = (tag: number, ...parts: Buffer[]): Buffer => {
  const body = Buffer.concat(parts);
  const n = body.length;
  const len = n < 128 ? Buffer.from([n]) : n < 256 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 0xff]);
  return Buffer.concat([Buffer.from([tag]), len, body]);
};
function testCert(cn: string, kit: any) {
  const privKey = createPrivateKey({ key: kit.priv, format: 'jwk' });
  const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(unb(kit.pub.x))]);
  const algId = derNode(0x30, derNode(0x06, Buffer.from([0x2b, 0x65, 0x70])));
  const name = derNode(0x30, derNode(0x31, derNode(0x30, derNode(0x06, Buffer.from([0x55, 0x04, 0x03])), derNode(0x0c, Buffer.from(cn)))));
  const validity = derNode(0x30, derNode(0x17, Buffer.from('250101000000Z')), derNode(0x17, Buffer.from('450101000000Z')));
  const tbs = derNode(0x30, derNode(0xa0, derNode(0x02, Buffer.from([2]))), derNode(0x02, Buffer.from([1])), algId, name, validity, name, spki);
  const cert = derNode(0x30, tbs, algId, derNode(0x03, Buffer.concat([Buffer.from([0]), nodeSign(null, tbs, privKey)])));
  const body = cert.toString('base64').replace(/.{1,64}/g, '$&\n');
  return { der: new Uint8Array(cert), pem: `-----BEGIN CERTIFICATE-----\n${body}-----END CERTIFICATE-----\n`, raw: cert };
}
const C1 = testCert('mtls-test-client', K);
const C2 = testCert('someone-else', K2);
const OSSL = `-----BEGIN CERTIFICATE-----
MIIBhzCCAS2gAwIBAgIUJNnxKGIZtm6X50ZPUimg4pELamAwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNcGNhLWRwb3AtdGVzdDAgFw0yNjEwMjYwNjI4MjBaGA8yMTI2
MTAwMjA2MjgyMFowGDEWMBQGA1UEAwwNcGNhLWRwb3AtdGVzdDBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABEUMOC7lpXyDyP7zRuzlIFZE2N55fI6t9YeL6hSgmOq2
gAa7VsKCebHufEqQIxGgiLR8UH2a/sBD5P79bqzLUMKjUzBRMB0GA1UdDgQWBBTX
JKwVRMF9HCh+g6yCG8Vapw+EwDAfBgNVHSMEGDAWgBTXJKwVRMF9HCh+g6yCG8Va
pw+EwDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQCQ+cwkz3O7
yzv9nWZgdmrTP5wHxp/GZuNWM1CKH52DjwIgC0l6KtM7TWCWzeroer6ShI8cMkuN
FD8Bv16yLKjV0Rg=
-----END CERTIFICATE-----`;
const OSSL_DER = new Uint8Array(new X509Certificate(OSSL).raw);
const bytesArg = (u: Uint8Array | Buffer) => ({ $bytes: b64(new Uint8Array(u)) });
const t5 = (der: Uint8Array) => b64(new Uint8Array(createHash('sha256').update(der).digest()));
const CERTS: Array<[string, any]> = [
  ['ed der', bytesArg(C1.der)], ['ed pem', C1.pem], ['ed pem no trailing nl', C1.pem.trimEnd()], ['ed pem crlf', C1.pem.replace(/\n/g, '\r\n')], ['ed pem junk around', `junk\n${C1.pem}trailer`],
  ['other der', bytesArg(C2.der)], ['ossl pem', OSSL], ['ossl der', bytesArg(OSSL_DER)],
  ['der + trailing', bytesArg(Buffer.concat([C1.raw, Buffer.from([1, 2, 3])]))], ['der truncated', bytesArg(C1.raw.subarray(0, C1.raw.length - 10))], ['der tampered sig', bytesArg(Buffer.concat([C1.raw.subarray(0, C1.raw.length - 1), Buffer.from([(C1.raw[C1.raw.length - 1] as number) ^ 1])]))],
  ['empty', bytesArg(new Uint8Array(0))], ['junk bytes', bytesArg(new Uint8Array([1, 2, 3]))], ['not a cert', 'not a certificate'], ['empty string', ''], ['pem AAAA', '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n'],
  ['pem no end', '-----BEGIN CERTIFICATE-----\nAAAA'], ['pem wrong label', C1.pem.replace(/CERTIFICATE/g, 'PUBLIC KEY')], ['pem lowercase body', C1.pem.replace(/[A-Z]/g, (c) => c.toLowerCase())],
];
for (const [n, c] of CERTS) {
  await o.run('mtlsCnf', n, (x: any) => M.mtlsCnf(rev(x)), [c]);
  await o.run('mtlsThumbprint', n, (x: any) => M.mtlsThumbprint(rev(x)), [c]);
  for (const [cn, cnf] of [['good', { 'x5t#S256': t5(C1.der) }], ['other', { 'x5t#S256': t5(C2.der) }]] as const) await o.run('assertMtlsBound', `${n} ${cn}`, (x: any, y: any) => M.assertMtlsBound(rev(x), y), [c, cnf]);
}
for (const [i, cnf] of [undefined, null, 'str', 5, {}, { 'x5t#S256': '' }, { 'x5t#S256': 5 }, { x5t: 'abc' }, [], { 'x5t#S256': t5(C1.der), other: 1 }, { 'x5t#S256': t5(C1.der) + '=' }, { 'x5t#S256': t5(C1.der).toLowerCase() }, { 'x5t#S256': t5(C1.der).slice(0, -1) }, { 'x5t#S256': t5(C1.der) + 'A' }].entries())
  for (const [n, c] of [['ed der', bytesArg(C1.der)], ['ed pem', C1.pem], ['junk', bytesArg(new Uint8Array([1]))]] as const) await o.run('assertMtlsBound', `cnf${i} ${n}`, (x: any, y: any) => M.assertMtlsBound(rev(x), y), [c, cnf ?? null]);

// ---- PCActn <-> DPoP binding ----
const holder = (kit: any) => kit.pub.x;
const PS: Array<[string, any]> = [
  ['one hop', { cap_chain: [{ holder: holder(K) }] }], ['two hops', { cap_chain: [{ holder: holder(K2) }, { holder: holder(K) }] }], ['extra fields', { ver: 2, aud: 'a', cap_chain: [{ issuer: 'i', holder: holder(K), caveats: [] }], sig: 'x' }],
  ['empty chain', { cap_chain: [] }], ['no chain', {}], ['chain string', { cap_chain: 'x' }], ['chain object', { cap_chain: { length: 1 } }], ['hop null', { cap_chain: [null] }], ['hop number', { cap_chain: [5] }],
  ['no holder', { cap_chain: [{}] }], ['holder number', { cap_chain: [{ holder: 5 }] }], ['holder empty', { cap_chain: [{ holder: '' }] }], ['holder non-canonical', { cap_chain: [{ holder: holder(K) + '=' }] }], ['holder short', { cap_chain: [{ holder: 'AAAA' }] }],
];
for (const [n, p] of PS) {
  await o.run('leafHolderJwk', n, M.leafHolderJwk, [p]);
  await o.run('bindPcaToDpop', n, async (x: any) => M.bindPcaToDpop(x), [p]);
}
const PK = { cap_chain: [{ holder: holder(K2) }, { holder: holder(K) }] };
const PAO = { method: 'POST', url: URL1, nowSec: NOW, seenJti: [] as string[] };
const asr = (n: string, p: any, proof: any, opts: any = {}) => o.run('assertPcaDpop', n, assertW, [p, proof, { ...PAO, ...opts }]);
await asr('valid', PK, BASE);
await asr('wrong holder', { cap_chain: [{ holder: holder(K2) }] }, BASE);
await asr('proof by other key', PK, mkProof({ kit: K2 }));
await asr('default max age', PK, BASE, { nowSec: T0 + 300 });
await asr('default max age exceeded', PK, BASE, { nowSec: T0 + 301 });
await asr('maxAge 10', PK, BASE, { maxAgeSec: 10, nowSec: T0 + 11 });
await asr('replay', PK, BASE, { seenJti: ['jti-1'] });
await asr('no store', PK, BASE, { seenJti: undefined });
await asr('no store opted out', PK, BASE, { seenJti: undefined, requireReplayStore: false });
await asr('store', PK, BASE, { seenJti: undefined, replayStore: { kind: 'memory' } });
await asr('nonce', PK, mkProof({ claims: { nonce: 'n' } }), { expectedNonce: 'n' });
await asr('nonce wrong', PK, mkProof({ claims: { nonce: 'm' } }), { expectedNonce: 'n' });
await asr('ath', PK, mkProof({ claims: { ath: ATH } }), { accessToken: 'access-token-1' });
await asr('issuer', PK, mkProof({ claims: { nonce: nonceFor(T0) } }), { nonceIssuer: { secret: SECRET } });
await asr('empty chain', { cap_chain: [] }, BASE);
await asr('bad holder', { cap_chain: [{ holder: 5 }] }, BASE);
await asr('wrong method', PK, BASE, { method: 'GET' });
await asr('wrong url', PK, BASE, { url: 'https://other.example/x' });
await asr('es256 proof', PK, mkProof({ kit: E256 }));
await asr('malformed', PK, 'x');

// The RSA kit key is a private key: its cases never enter the committed corpus. They go to ref-dpop-rsa.json.gz, which CI regenerates from
// this generator (scripts/pca-ci-workflows/_native/scripts/dpop-rsa-corpus.sh) next to the lane's other test data before the tests run.
const rsaOracle = new Oracle('dpop-rsa', 'dpop.mts', 'TS-reference oracle for the DPoP cases whose arguments carry the RSA test private key (generated in CI, never committed).');
const isRsa = (c: any) => JSON.stringify(c).includes(RSA.priv.d as string);
rsaOracle.cases = o.cases.filter(isRsa);
o.cases = o.cases.filter((c: any) => !isRsa(c));
refWrite(o, 'dpop');
refWrite(rsaOracle, 'dpop-rsa');
