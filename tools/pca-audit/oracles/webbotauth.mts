// Oracle: @atlasauth/pca-webbotauth (RFC 9421 HTTP Message Signatures in the web-bot-auth profile, the signed key directory, Content-Digest, PCA proof
// binding). Deterministic: every call passes `created` / `now`, Ed25519 signatures are deterministic, keys come from seeds or the RFC 9421 test key.
// Writes out/ref-webbotauth.json.gz.
//
// PORTING (fn(args) -> native entry point, comparison rule). Values are JSON; compare by JSON value; a throw only requires the native to refuse.
// Bytes are {"$bytes": b64url}. A signing key is {secretKey: b64url seed, publicKey: b64url}; the native derives the pair from the seed.
//   constants()                                     -> exported constants as {name: value}
//   jwkThumbprint(publicKey)                        -> publicKey is {"$bytes"}
//   signRequest(input)                              -> {signatureInput, signature, signatureAgent?, covered, headers}. The BYTES of signatureInput and signature
//       are compared exactly (the signature base is built byte for byte as the reference does). input.key is a signing key.
//       Documented divergence: only http(s) / ws(s) / ftp URLs (special schemes) are signed; others are refused.
//   verifySignedRequest(req, opts[, times])         -> verify result {valid, reason?, label?, keyid?, covered?, created?, expires?, tag?, nonce?}. opts:
//       resolveKey is {keyid: {"$bytes"} | public JWK | null | {"$throw": true}} (an unlisted keyid resolves to null); jwks is the directory document;
//       maxLifetimeSec "Infinity" = disabled; replayCache is "memory" (a fresh in-process cache, default size), "memory:<n>" (max entries n), "always"
//       (claim true), "never" (claim false) or "throw" (claim throws). times > 1 verifies that many times over the SAME cache and returns the list.
//   buildKeyDirectory(keys)                         -> JWKS; each input key's publicKey is a {"$bytes"}
//   resolveFromDirectory(directory, keyid)          -> JWK | null
//   directoryHandler(keys, pathnames)               -> list of handler(pathname) results (null = fall through)
//   memoryReplayCache(maxEntries|null, ops)         -> ops [[key, expiresAtSec, nowSec]...] -> list of true | false | "throw"
//   proofHeaders(pcactn) / decodeProofHeader(value) -> decode errors compare as throws
//   signRequestWithProof(input)                     -> sign result + proofHeader (input.pcactn is the PCActn)
//   verifySignedRequestWithProof(req, opts)         -> verify result (+ pcactn); a reason "invalid PCActn in PCA-Action: <detail>" is cut after the colon
//   contentDigestBytes(body, alg) / contentDigestHeader(body[, algs]) / parseContentDigest(value) / verifyContentDigest(header|null, body[, opts])
//       body is a string or {"$bytes"}
//   parseKeyDirectory(text) / signDirectoryResponse(input) / verifyDirectoryResponse(input): signing keys are signing-key specs
//   fetchKeyDirectory(url, spec)                    -> spec = {response: {status, headers, body}, options?} (a scripted fetch that records the URL and headers
//       it was called with); result {directory | error: true, called: {url, headers}|null}. Documented divergence: a URL with credentials is refused and a
//       @target-uri covering a URL with credentials or a fragment is refused (those inputs are not in the corpus).
import { createPrivateKey } from 'node:crypto';
import * as M0 from '@atlasauth/pca-webbotauth';
import { Oracle, refWrite, seed, variants } from './lib.mjs';

const M: any = (M0 as any).default ?? M0;
const o = new Oracle('webbotauth', 'tools/pca-audit/oracles/webbotauth.mts', 'TS-reference oracle for Web Bot Auth (RFC 9421 message signatures).');
const HOST: any[] = [null, true, 0, 1.5, '', 'x', [], {}, ['x']];
const vv = (x: any, op: any = {}) => variants(x, { hostile: HOST, ...op });
const T0 = 1_800_000_000;
const b64u = (u: Uint8Array | Buffer) => Buffer.from(u).toString('base64url');
const bytes = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));
const kp = (label: string): any => {
  const s = seed(label);
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(s)]);
  const jwk: any = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' }).export({ format: 'jwk' });
  return { secretKey: b64u(s), publicKey: jwk.x };
};
const KA = kp('wba/a');
const KB = kp('wba/b');
const KRFC = { secretKey: 'n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU', publicKey: 'JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs' };
const keyOf = (k: any) => ({ publicKey: bytes(k.publicKey), secretKey: bytes(k.secretKey) });
const withKey = (x: any) => (x && typeof x === 'object' && x.key && typeof x.key === 'object' ? { ...x, key: keyOf(x.key) } : x);

const signR = (input: any) => M.signRequest(withKey(input));
const signP = (input: any) => M.signRequestWithProof(withKey(input));

const mkResolve = (spec: any) => (kid: string) => {
  const v = spec[kid];
  if (v && v.$throw) throw new Error('resolver down');
  if (v && v.$bytes !== undefined) return bytes(v.$bytes);
  return v ?? null;
};
const mkCache = (spec: any): any => {
  if (spec === 'always') return { claim: () => true };
  if (spec === 'never') return { claim: () => false };
  if (spec === 'throw') return { claim: () => { throw new Error('cache down'); } };
  if (spec === 'memory') return M.memoryReplayCache();
  if (typeof spec === 'string' && spec.startsWith('memory:')) return M.memoryReplayCache(Number(spec.slice(7)));
  return spec;
};
const vopts = (op: any) => {
  const out: any = { ...op };
  if (out.resolveKey && typeof out.resolveKey === 'object') out.resolveKey = mkResolve(out.resolveKey);
  if (out.maxLifetimeSec === 'Infinity') out.maxLifetimeSec = Infinity;
  if ('replayCache' in out) out.replayCache = mkCache(out.replayCache);
  return out;
};
const norm = (r: any) => {
  const out = { ...r };
  if (typeof out.reason === 'string') out.reason = out.reason.replace(/^(invalid PCActn in PCA-Action): .*$/s, '$1');
  return out;
};
const verifyW = async (req: any, op: any, times = 1) => {
  const vo = vopts(op);
  const rs: any[] = [];
  for (let i = 0; i < times; i++) rs.push(norm(await M.verifySignedRequest(req, vo)));
  return times === 1 ? rs[0] : rs;
};
const verifyP = async (req: any, op: any) => {
  const vo = vopts(op);
  return norm(await M.verifySignedRequestWithProof(req, vo));
};

await o.run('constants', 'all', () => ({
  tag: M.WEB_BOT_AUTH_TAG, alg: M.WEB_BOT_AUTH_ALG, path: M.WELL_KNOWN_DIRECTORY_PATH, ct: M.DIRECTORY_CONTENT_TYPE, label: M.DEFAULT_SIGNATURE_LABEL, exp: M.DEFAULT_EXPIRES_SEC,
  agent: M.SIGNATURE_AGENT_HEADER, pca: M.PCA_HEADER, comp: M.PCA_PROOF_COMPONENT, cd: M.CONTENT_DIGEST_HEADER, algs: M.CONTENT_DIGEST_ALGS, dtag: M.DIRECTORY_SIGNATURE_TAG,
}), []);

// ---- jwkThumbprint
for (const [i, k] of [KA, KB, KRFC].entries()) await o.run('jwkThumbprint', `k${i}`, (pk: any) => M.jwkThumbprint(bytes(pk.$bytes)), [{ $bytes: k.publicKey }]);
await o.run('jwkThumbprint', 'empty', (pk: any) => M.jwkThumbprint(bytes(pk.$bytes)), [{ $bytes: '' }]);
await o.run('jwkThumbprint', 'short', (pk: any) => M.jwkThumbprint(bytes(pk.$bytes)), [{ $bytes: 'AQID' }]);

// ---- signRequest
const BASE: any = { method: 'GET', url: 'https://example.com/a/b?x=1', headers: { 'Content-Type': 'application/json', 'X-Custom': ' v ' }, key: KA, keyid: 'kid-a', created: T0, expiresInSec: 120, nonce: 'n-1', label: 'sig1' };
await o.run('signRequest', 'base', signR, [BASE]);
await o.run('signRequest', 'min', signR, [{ method: 'get', url: 'https://example.com', key: KA, keyid: 'k', created: T0 }]);
const URLS = ['https://example.com/', 'https://EXAMPLE.com/A%20b', 'https://example.com:8443/x', 'https://example.com:443/x', 'http://example.com:80/x', 'http://example.com:8080/x?q', 'https://example.com/a/../b/./c',
  'https://example.com/x?', 'https://example.com/x?a=1&b=%20c', 'https://example.com/x#frag', 'https://example.com/x?a#frag', 'https://example.com/é/ü?ü=1', 'https://[::1]:9/x', 'https://[2001:db8::1]/x',
  'https://192.168.0.1/x', 'https://0x7f.1/x', 'https://exa%6dple.com/x', 'https://example.com//double', 'https://example.com/x y', 'https://example.com/a\\b', 'wss://example.com/s', 'ftp://example.com/f',
  'https://example.com/%7Efoo', 'https://example.com/?a=1', 'https://example.com?a=1', 'https://example.com./x', 'https://üñí.example/x', 'https://example.com/x?a b', "https://example.com/x?a'b", 'https://example.com/x`{}'];
for (const [i, u] of URLS.entries()) {
  await o.run('signRequest', `url${i}`, signR, [{ ...BASE, url: u }]);
  await o.run('signRequest', `url${i}-all`, signR, [{ ...BASE, url: u, components: ['@authority', '@method', '@path', '@query', '@scheme', '@request-target'] }]);
}
for (const [i, u] of ['https://example.com/x', 'https://example.com/x?a=1', 'https://example.com/x?', 'https://example.com:8443/x?a=%20b&c'].entries()) {
  await o.run('signRequest', `target${i}`, signR, [{ ...BASE, url: u, components: ['@authority', '@target-uri'] }]);
}
for (const [i, c] of ([['@authority'], ['@authority', '@method'], ['@method'], [], ['@Authority'], ['@AUTHORITY', '@PATH'], ['@authority', 'content-type'], ['@authority', '@query-param'], ['@authority', '@status'], ['@authority', '@authority']] as any[]).entries())
  await o.run('signRequest', `comp${i}`, signR, [{ ...BASE, components: c }]);
await o.run('signRequest', 'comp-lower-auth', signR, [{ ...BASE, components: ['@AUTHORITY'] }]);
for (const [i, c] of ([['content-type'], ['Content-Type'], ['x-custom'], ['content-type', 'CONTENT-TYPE'], ['x-missing'], ['content-type', 'x-custom']] as any[]).entries()) await o.run('signRequest', `cover${i}`, signR, [{ ...BASE, coverHeaders: c }]);
for (const [i, h] of ([{ A: 'x', a: 'y' }, { 'X-Multi': ['a ', ' b'] }, { 'x-multi': ['a'], 'X-Multi': 'b' }, {}, undefined, { 'Content-Type': '' }, { 'X-Q': 'a\tb' }] as any[]).entries()) {
  await o.run('signRequest', `hdrs${i}`, signR, [{ ...BASE, headers: h, coverHeaders: Object.keys(h ?? {}).slice(0, 1).map((k) => k.toLowerCase()) }]);
}
for (const [i, a] of ([{ agentDirectoryUrl: 'https://a.test' }, { agentDirectoryUrl: 'https://a.test', agentDirectoryKey: 'agent1' }, { agentDirectoryKey: 'agent1' }, { agentDirectoryUrl: 'https://a."test"\\' },
  { agentDirectoryUrl: 'https://a.test', agentDirectoryKey: 'a"b' }, { agentDirectoryUrl: '' }, { agentDirectoryUrl: 'https://a.test', headers: { 'Signature-Agent': 'old' } }] as any[]).entries()) await o.run('signRequest', `agent${i}`, signR, [{ ...BASE, ...a }]);
for (const [k, d] of Object.entries({ nonce: { nonce: undefined }, nonceq: { nonce: 'a"b\\c' }, label: { label: 'x' }, label2: { label: 'sig-é' }, exp0: { expiresInSec: 0 }, expneg: { expiresInSec: -5 }, expfrac: { expiresInSec: 1.5 }, expdef: { expiresInSec: undefined },
  big: { created: 9007199254740991 }, frac: { created: 1.5 }, zero: { created: 0 }, neg: { created: -1 }, exp21: { created: 1e21 }, kid: { keyid: 'a"b\\c é' }, kidempty: { keyid: '' }, method: { method: 'pOsT' }, keyB: { key: KB }, rfc: { key: KRFC } } as any))
  await o.run('signRequest', `opt-${k}`, signR, [{ ...BASE, ...d }]);
for (const [l, v] of vv(BASE, { maxPaths: 100 })) {
  if (l.startsWith('/key') || l.includes('surrogate')) continue; // a lone surrogate is encoded differently by each runtime's UTF-8 writer
  // JavaScript coercion of a non-numeric time (string concatenation) is not part of the contract: numeric edits only
  if (/^\/(created|expiresInSec)/.test(l) && (l.includes('hostile') || l.includes('deleted') || l.includes('+ space') || l.includes('upper') || l.includes('surrogate') || l.includes('len '))) continue;
  await o.run('signRequest', `var ${l}`, signR, [v]);
}

// RFC 9421 + web-bot-auth draft vectors
const fx = (n: string): any => JSON.parse(readFileSync(new URL(`../../../packages/pca-webbotauth/fixtures/${n}`, import.meta.url), 'utf8'));
import { readFileSync } from 'node:fs';
const rfc = fx('rfc9421-appendix-b.json');
const draft = fx('webbotauth-draft-05.json');
const RREQ = rfc.test_request;
const paramOf = (input: string, name: string): string => { const m = new RegExp(`;${name}=("[^"]*"|[0-9]+)`).exec(input)!; return m[1].replace(/^"|"$/g, ''); };
const rfcVer = (sec: string, op: any = {}) => {
  const v = rfc.vectors.find((x: any) => x.section === sec);
  return [{ ...RREQ, headers: { ...RREQ.headers, 'Signature-Input': v.signature_input, Signature: v.signature } }, { requiredComponents: ['@authority'], maxLifetimeSec: 'Infinity', resolveKey: { 'test-key-ed25519': { $bytes: KRFC.publicKey }, 'oD0HwocPBSfpNy5W3bpJeyFGe9T4m9RlhYeoMVuYAkk': { $bytes: KRFC.publicKey } }, requiredTag: null, now: 1618884500, ...op }];
};
for (const sec of ['B.2.1', 'B.2.2', 'B.2.3', 'B.2.4', 'B.2.5', 'B.2.6']) {
  await o.run('verifySignedRequest', `rfc-${sec}`, verifyW, rfcVer(sec, { requireExpires: false }));
  await o.run('verifySignedRequest', `rfc-${sec}-default`, verifyW, rfcVer(sec));
}
{
  const [rq, op] = rfcVer('B.2.6', { requireExpires: false });
  for (const [k, d] of Object.entries({ method: { method: 'GET' }, path: { url: 'https://example.com/bar' }, host: { url: 'https://evil.example.com/foo' }, len: { headers: { ...rq.headers, 'Content-Length': '19' } }, date: { headers: { ...rq.headers, Date: 'x' } }, nodate: { headers: { 'Signature-Input': rq.headers['Signature-Input'], Signature: rq.headers.Signature } } } as any))
    await o.run('verifySignedRequest', `rfc-B.2.6-${k}`, verifyW, [{ ...rq, ...d }, op]);
  await o.run('verifySignedRequest', 'rfc-B.2.6-otherkey', verifyW, [rq, { ...op, resolveKey: { 'test-key-ed25519': { $bytes: KA.publicKey } } }]);
  await o.run('verifySignedRequest', 'rfc-B.2.6-alg', verifyW, [{ ...rq, headers: { ...rq.headers, 'Signature-Input': rq.headers['Signature-Input'].replace(';created=', ';alg="hmac-sha256";created=') } }, op]);
}
for (const v of draft.vectors) {
  const input = v.signature_input;
  const label = input.slice(0, input.indexOf('='));
  const isEd = v.section.startsWith('A.2');
  const agent = v.signature_agent !== undefined;
  const key = v.signature_agent && v.signature_agent.startsWith('agent2') ? 'agent2' : undefined;
  const exp = Number(paramOf(input, 'expires')) - Number(paramOf(input, 'created'));
  if (isEd) {
    await o.run('signRequest', `draft-${v.section}`, signR, [{ method: RREQ.method, url: RREQ.url, headers: RREQ.headers, key: KRFC, keyid: paramOf(input, 'keyid'), created: Number(paramOf(input, 'created')), expiresInSec: exp, nonce: paramOf(input, 'nonce'), label, components: ['@authority'], ...(agent ? { agentDirectoryUrl: 'https://signature-agent.test' } : {}), ...(key ? { agentDirectoryKey: key } : {}) }]);
  }
  await o.run('verifySignedRequest', `draft-${v.section}`, verifyW, [{ ...RREQ, headers: { ...RREQ.headers, 'Signature-Input': input, Signature: v.signature, ...(agent ? { 'Signature-Agent': v.signature_agent } : {}) } },
    { requiredComponents: ['@authority'], maxLifetimeSec: 'Infinity', resolveKey: { [paramOf(input, 'keyid')]: { $bytes: KRFC.publicKey } }, now: Number(paramOf(input, 'created')) + 60 }]);
}

// ---- verify: TS-signed requests, then tampering
const KID = 'kid-a';
const RK = { [KID]: { $bytes: KA.publicKey } };
const VBASE: any = { resolveKey: RK, now: T0 + 10 };
const SIGNED: [string, any, any][] = [];
for (const [n, d] of Object.entries({
  basic: {}, query: { url: 'https://example.com/a/b?x=1&y=2' }, post: { method: 'POST' }, cover: { coverHeaders: ['content-type', 'x-custom'] }, agent: { agentDirectoryUrl: 'https://a.test' }, agentkey: { agentDirectoryUrl: 'https://a.test', agentDirectoryKey: 'agent1' },
  nonce: { nonce: 'abc' }, nononce: { nonce: undefined }, port: { url: 'https://example.com:8443/a' }, components: { components: ['@authority', '@method', '@path', '@query', '@scheme'] }, onlyauth: { components: ['@authority'] }, label: { label: 'my-sig' },
  long: { expiresInSec: 3600 }, short: { expiresInSec: 1 }, noexp: { expiresInSec: 300 }, target: { components: ['@authority', '@method', '@path', '@target-uri'] }, reqtarget: { components: ['@authority', '@method', '@path', '@request-target'] }, rfc: { key: KRFC, keyid: 'kid-a' },
} as any)) {
  const input = { ...BASE, ...d, headers: { ...BASE.headers } };
  const out = M.signRequest(withKey(input));
  const rq = { method: input.method, url: input.url, headers: { ...input.headers, ...out.headers } };
  SIGNED.push([n, rq, n === 'rfc' ? { ...VBASE, resolveKey: { [KID]: { $bytes: KRFC.publicKey } } } : VBASE]);
}
for (const [n, rq, op] of SIGNED) {
  await o.run('verifySignedRequest', `ok-${n}`, verifyW, [rq, op]);
  await o.run('verifySignedRequest', `ok-${n}-twice-memory`, verifyW, [rq, { ...op, replayCache: 'memory' }, 2]);
}
const [, RQ, OP] = SIGNED[0];
const hdr = (h: any) => ({ ...RQ, headers: { ...RQ.headers, ...h } });
const SI = RQ.headers['Signature-Input'], SG = RQ.headers.Signature;
const flipSig = (s: string) => s.replace(/^(sig1=:)(.)/, (_m: string, a: string, b: string) => a + (b === 'A' ? 'B' : 'A'));
const tamper: [string, any][] = [
  ['method', { ...RQ, method: 'POST' }], ['method-lower', { ...RQ, method: 'get' }], ['path', { ...RQ, url: 'https://example.com/a/c?x=1' }], ['query', { ...RQ, url: 'https://example.com/a/b?x=2' }], ['noquery', { ...RQ, url: 'https://example.com/a/b' }],
  ['host', { ...RQ, url: 'https://example.org/a/b?x=1' }], ['host-case', { ...RQ, url: 'https://EXAMPLE.com/a/b?x=1' }], ['port', { ...RQ, url: 'https://example.com:444/a/b?x=1' }], ['default-port', { ...RQ, url: 'https://example.com:443/a/b?x=1' }], ['fragment', { ...RQ, url: 'https://example.com/a/b?x=1#f' }],
  ['badurl', { ...RQ, url: 'not a url' }], ['sigflip', hdr({ Signature: flipSig(SG) })], ['siginput-reorder', hdr({ 'Signature-Input': SI.replace(';created=', ';alg="ed25519";created=') })], ['nosig', hdr({ Signature: undefined })],
  ['nosiginput', hdr({ 'Signature-Input': undefined })], ['upper-names', { ...RQ, headers: { 'SIGNATURE-INPUT': SI, SIGNATURE: SG } }], ['label-mismatch', hdr({ Signature: SG.replace(/^sig1=/, 'sig9=') })], ['siglen', hdr({ Signature: 'sig1=:AAAA:' })],
  ['sig-notbytes', hdr({ Signature: 'sig1=abc' })], ['sig-empty', hdr({ Signature: 'sig1=::' })], ['sig-noeq', hdr({ Signature: 'abc' })], ['sig-junkb64', hdr({ Signature: SG.replace(/^(sig1=:)/, '$1!!').replace(/:$/, '$$:') })],
  ['sig-padding-junk', hdr({ Signature: SG.replace(/:$/, '=:') })], ['sig-trailing', hdr({ Signature: SG + ', ' })], ['sig-two', hdr({ Signature: SG + ', sig2=:AAAA:' })], ['sig-ws', hdr({ Signature: ' ' + SG + ' ' })],
  ['two-inputs', hdr({ 'Signature-Input': SI + ', other=("@authority");tag="x"' })], ['two-inputs-first-other', hdr({ 'Signature-Input': 'other=("@authority");tag="x", ' + SI, Signature: 'other=:AAAA:, ' + SG })],
  ['multi-sig', hdr({ 'Signature-Input': 'a=("@authority" "@method" "@path");created=1;expires=2;keyid="kid-a";tag="x", ' + SI, Signature: 'a=:AAAA:, ' + SG })],
  ['array-headers', { ...RQ, headers: { 'Signature-Input': [SI], Signature: [SG], 'Content-Type': ['application/json'], 'X-Custom': [' v '] } }], ['array-split', { ...RQ, headers: { 'Signature-Input': [SI, 'x=()'], Signature: [SG] } }],
  ['extra-header', hdr({ 'X-Other': 'z' })], ['ctype-change', hdr({ 'Content-Type': 'text/plain' })], ['no-headers', { method: 'GET', url: RQ.url }], ['empty-headers', { ...RQ, headers: {} }],
  ['dup-case', { ...RQ, headers: { ...RQ.headers, 'signature-input': SI } }],
];
for (const [n, rq] of tamper) await o.run('verifySignedRequest', `tamper-${n}`, verifyW, [rq, OP]);
// hostile Signature-Input strings (parse paths); the Signature header is a plausible placeholder
const PL = 'sig1=:AAAA:';
const SIS = ['', ' ', ',', 'sig1', 'sig1=', 'sig1=5', 'sig1=()', 'sig1=(', 'sig1=("@authority"', 'sig1=("@authority")', 'sig1=("@authority");', 'sig1=("@authority");;', 'sig1=("@authority");created', 'sig1=("@authority");created=', 'sig1=("@authority") ;created=1',
  'sig1=("@authority");created=1;expires=2;keyid="kid-a"', 'sig1=("@authority");created=1;expires=2;keyid=kid-a', 'sig1=("@authority");created=1;expires=2;keyid="a\\"b"', 'sig1=("@authority");created=1;expires=2;keyid="a\\xb"', 'sig1=("@authority");created=1;expires=2;keyid="unterminated',
  'sig1=("@authority");created=1;expires=2;keyid="kid-a"x', 'sig1=("@authority" );created=1', 'sig1=(  "@authority"   "@method" );created=1', 'sig1=("@authority"x)', 'sig1=(@authority)', 'sig1=("@authority";key="a")', 'sig1=("x-h";key="a")', 'sig1=("x-h";key=a)', 'sig1=("x-h";key="a";z)',
  'sig1=("@AUTHORITY" "@Method" "@PATH");created=1;expires=2;keyid="kid-a"', 'sig1=("@authority" "@method" "@path");created=1.5;expires=2.5;keyid="kid-a"', 'sig1=("@authority" "@method" "@path");created=-5;expires=2;keyid="kid-a"', 'sig1=("@authority" "@method" "@path");created=?1;expires=?0;keyid="kid-a"',
  'sig1=("@authority" "@method" "@path");created=0012;expires=0099;keyid="kid-a"', 'sig1=("@authority" "@method" "@path");created=1e3;expires=2;keyid="kid-a"', 'sig1=("@authority" "@method" "@path");created="1";expires="2";keyid="kid-a"', 'sig1=("@authority" "@method" "@path");created=99999999999999999999999;expires=99999999999999999999999;keyid="kid-a"',
  'sig1=("@authority" "@method" "@path");created=1;;expires=2;keyid="kid-a"', 'sig1=("@authority" "@method" "@path");created=1;expires=2;keyid="kid-a";tag="web-bot-auth";tag="other"', 'sig1=("@authority" "@method" "@path");created=1;expires=2;keyid="kid-a";tag=web-bot-auth', 'sig1=("@authority" "@method" "@path");created=1;expires=2;keyid="kid-a";tag',
  'sig1=("@authority" "@method" "@path");created=1;expires=2;keyid="kid-a";alg="ed25519";tag="web-bot-auth"', 'sig1=("@authority" "@method" "@path");created=1;expires=2;keyid="kid-a";alg=ed25519', 'sig1=("@authority" "@method" "@path");created=1;expires=2;keyid="kid-a";alg=5', 'sig1=("@authority" "@method" "@path");created=1;expires=2;keyid="kid-a";alg',
  'sig1=("@authority" "@method" "@path");created=1;expires=2;keyid=5', 'sig1=("@authority" "@method" "@path");created=1;expires=2', 'sig1=("@authority" "@method" "@path");created=1;expires=2;keyid=""', 'sig1=("@authority" "@method" "@path") ; created=1 ; expires=2 ; keyid="kid-a"', 'sig1=("@authority" "@method" "@path"),sig2=("@authority")',
  'sig1=("a b" "@method")', 'sig1=("@authority" "x-missing")', 'sig1=("@target-uri" "@authority" "@method" "@path")', 'sig1=("@scheme" "@authority" "@method" "@path")', 'sig1=("@status" "@authority" "@method" "@path")', 'sig1=("@query-param";name="x" "@authority")',
  '(a)=b', 'sig1=("@authority"),', ',sig1=("@authority")', 'sig1=("@authority"), , sig2=("@method")', 'SIG1=("@authority")'];
for (const [i, s] of SIS.entries()) {
  await o.run('verifySignedRequest', `si${i}`, verifyW, [{ ...RQ, headers: { ...RQ.headers, 'Signature-Input': s, Signature: PL } }, { ...OP, requireExpires: false }]);
  if (i % 3 === 0) await o.run('verifySignedRequest', `si${i}-requiredTagNull`, verifyW, [{ ...RQ, headers: { ...RQ.headers, 'Signature-Input': s, Signature: PL } }, { ...OP, requiredTag: null, requiredComponents: [], maxLifetimeSec: 'Infinity', requireExpires: false }]);
}
const SIGS = ['', ' ', ',', 'sig1', 'sig1=', 'sig1=:', 'sig1=::', 'sig1=:A:', 'sig1=:AAAA', 'sig1=AAAA:', 'sig1=:AA AA:', 'sig1=:AA\nAA:', 'sig1=:AAAA:, ', ', sig1=:AAAA:', 'sig1=:AAAA:,sig1=:BBBB:', 'sig1 = :AAAA:', 'a=b=:AAAA:', 'sig1=:A=:A:'];
for (const [i, s] of SIGS.entries()) await o.run('verifySignedRequest', `sg${i}`, verifyW, [{ ...RQ, headers: { ...RQ.headers, Signature: s } }, OP]);

// timing / options (token fixed: created T0, expires T0+120)
const T = [T0 - 100, T0 - 1, T0, T0 + 1, T0 + 119, T0 + 120, T0 + 121, T0 + 200, T0 + 100000];
for (const t of T) for (const sk of [0, 5, 60]) await o.run('verifySignedRequest', `time-${t - T0}-skew${sk}`, verifyW, [RQ, { ...OP, now: t, clockSkewSec: sk }]);
for (const m of [0, 1, 10, 60, 1000]) for (const t of [T0, T0 + 30, T0 + 100]) await o.run('verifySignedRequest', `maxage-${m}-${t - T0}`, verifyW, [RQ, { ...OP, now: t, maxAgeSec: m }]);
for (const m of [0, 119, 120, 121, 300, 'Infinity', -1]) await o.run('verifySignedRequest', `maxlife-${m}`, verifyW, [RQ, { ...OP, maxLifetimeSec: m }]);
for (const [n, rq] of SIGNED) if (['long', 'short', 'noexp'].includes(n)) for (const m of [undefined, 300, 3600, 'Infinity']) await o.run('verifySignedRequest', `life-${n}-${m}`, verifyW, [rq, { ...OP, maxLifetimeSec: m }]);
for (const [i, t] of ([undefined, null, 'web-bot-auth', 'other', ''] as any[]).entries()) await o.run('verifySignedRequest', `reqtag${i}`, verifyW, [RQ, t === undefined ? OP : { ...OP, requiredTag: t }]);
for (const [i, l] of (['sig1', 'sig2', '', null] as any[]).entries()) await o.run('verifySignedRequest', `label${i}`, verifyW, [RQ, { ...OP, label: l }]);
for (const [i, c] of ([[], ['@authority'], ['@authority', '@method', '@path'], ['@authority', '@method', '@path', '@query'], ['@query'], ['content-type'], ['@scheme'], null] as any[]).entries()) {
  await o.run('verifySignedRequest', `reqcomp${i}-plain`, verifyW, [RQ, { ...OP, requiredComponents: c }]);
  const [, rq2, op2] = SIGNED[1];
  await o.run('verifySignedRequest', `reqcomp${i}-query`, verifyW, [rq2, { ...op2, requiredComponents: c }]);
}
for (const [n, rq, op] of SIGNED) {
  await o.run('verifySignedRequest', `noexp-${n}`, verifyW, [rq, { ...op, requireExpires: false }]);
  await o.run('verifySignedRequest', `tagnull-${n}`, verifyW, [rq, { ...op, requiredTag: null }]);
}
// key resolution
const KJ = { kty: 'OKP', crv: 'Ed25519', x: KA.publicKey };
const RES: [string, any][] = [
  ['bytes', { resolveKey: { [KID]: { $bytes: KA.publicKey } } }], ['jwk', { resolveKey: { [KID]: KJ } }], ['jwk-extra', { resolveKey: { [KID]: { ...KJ, kid: 'z', use: 'sig' } } }], ['jwk-crv', { resolveKey: { [KID]: { ...KJ, crv: 'Ed448' } } }], ['jwk-kty', { resolveKey: { [KID]: { ...KJ, kty: 'EC' } } }],
  ['jwk-nox', { resolveKey: { [KID]: { kty: 'OKP', crv: 'Ed25519' } } }], ['jwk-xnum', { resolveKey: { [KID]: { ...KJ, x: 5 } } }], ['jwk-xshort', { resolveKey: { [KID]: { ...KJ, x: 'AAAA' } } }], ['jwk-xbad', { resolveKey: { [KID]: { ...KJ, x: '!!!!' } } }],
  ['null', { resolveKey: { [KID]: null } }], ['unlisted', { resolveKey: {} }], ['short', { resolveKey: { [KID]: { $bytes: 'AQID' } } }], ['throw', { resolveKey: { [KID]: { $throw: true } } }], ['wrongkey', { resolveKey: { [KID]: { $bytes: KB.publicKey } } }], ['zero', { resolveKey: { [KID]: { $bytes: b64u(new Uint8Array(32)) } } }],
  ['jwks', { jwks: { keys: [{ ...KJ, kid: KID }] } }], ['jwks-other', { jwks: { keys: [{ ...KJ, kid: 'other' }] } }], ['jwks-empty', { jwks: { keys: [] } }], ['jwks-first', { jwks: { keys: [{ ...KJ, x: KB.publicKey, kid: KID }, { ...KJ, kid: KID }] } }],
  ['jwks-nbf-ok', { jwks: { keys: [{ ...KJ, kid: KID, nbf: T0 }] } }], ['jwks-nbf-future', { jwks: { keys: [{ ...KJ, kid: KID, nbf: T0 + 11 }] } }], ['jwks-exp-past', { jwks: { keys: [{ ...KJ, kid: KID, exp: T0 + 9 }] } }], ['jwks-exp-ok', { jwks: { keys: [{ ...KJ, kid: KID, exp: T0 + 10 }] } }],
  ['jwks-skew', { clockSkewSec: 5, jwks: { keys: [{ ...KJ, kid: KID, nbf: T0 + 14 }] } }], ['jwks-skew-no', { clockSkewSec: 2, jwks: { keys: [{ ...KJ, kid: KID, nbf: T0 + 14 }] } }], ['jwks-nbf-str', { jwks: { keys: [{ ...KJ, kid: KID, nbf: '5' }] } }], ['jwks-exp-null', { jwks: { keys: [{ ...KJ, kid: KID, exp: null }] } }],
  ['jwks-both', { jwks: { keys: [{ ...KJ, kid: KID }] }, resolveKey: { [KID]: null } }], ['none', {}],
];
for (const [n, d] of RES) await o.run('verifySignedRequest', `resolve-${n}`, verifyW, [RQ, { now: T0 + 10, ...d }]);
for (const [i, c] of (['memory', 'always', 'never', 'throw', 'memory:1', 'memory:0'] as string[]).entries()) await o.run('verifySignedRequest', `replay${i}-${c}`, verifyW, [RQ, { ...OP, replayCache: c }, 3]);
for (const [n, rq] of SIGNED) if (['nonce', 'nononce', 'noexp', 'onlyauth'].includes(n)) await o.run('verifySignedRequest', `replay-${n}`, verifyW, [rq, { ...OP, replayCache: 'memory' }, 2]);
await o.run('verifySignedRequest', 'replay-noexp-created', verifyW, [RQ, { ...OP, replayCache: 'memory', requireExpires: false, maxLifetimeSec: 'Infinity' }, 2]);
// @query handling in the default required components
for (const u of ['https://example.com/a/b?x=1', 'https://example.com/a/b?', 'https://example.com/a/b?#f', 'https://example.com/a/b#f?x', 'https://example.com/a/b?x#f', 'https://example.com/a/b?#']) {
  const out = M.signRequest(withKey({ ...BASE, url: u.replace(/\?.*$/, ''), components: ['@authority', '@method', '@path'] }));
  await o.run('verifySignedRequest', `query-${u}`, verifyW, [{ method: 'GET', url: u, headers: { ...BASE.headers, ...out.headers } }, OP]);
}

// ---- directory
const DK: any[] = [{ publicKey: { $bytes: KA.publicKey } }, { publicKey: { $bytes: KB.publicKey }, keyid: 'kb', use: 'sig', nbf: 5, exp: 9 }, { publicKey: { $bytes: KA.publicKey }, keyid: null, nbf: null }, { publicKey: { $bytes: '' } }];
const dk = (ks: any[]) => ks.map((k) => ({ ...k, publicKey: bytes(k.publicKey.$bytes) }));
await o.run('buildKeyDirectory', 'empty', (ks: any[]) => M.buildKeyDirectory(dk(ks)), [[]]);
for (const [i, k] of DK.entries()) await o.run('buildKeyDirectory', `k${i}`, (ks: any[]) => M.buildKeyDirectory(dk(ks)), [[k]]);
await o.run('buildKeyDirectory', 'all', (ks: any[]) => M.buildKeyDirectory(dk(ks)), [DK]);
const DIR = M.buildKeyDirectory(dk(DK.slice(0, 2)));
for (const id of [DIR.keys[0].kid, 'kb', 'nope', '', 'KB']) await o.run('resolveFromDirectory', `id-${id}`, M.resolveFromDirectory, [DIR, id]);
const PATHS = ['/.well-known/http-message-signatures-directory', '/.well-known/http-message-signatures-directory?x=1', '/.well-known/http-message-signatures-directory#f', '/', '', '/.well-known/http-message-signatures-directory/', '/.WELL-KNOWN/http-message-signatures-directory', '/x?/.well-known/http-message-signatures-directory', '?', '/.well-known/http-message-signatures-directory??'];
await o.run('directoryHandler', 'paths', (ks: any[], ps: string[]) => { const h = M.directoryHandler(dk(ks)); return ps.map((p) => h(p)); }, [DK.slice(0, 2), PATHS]);
await o.run('directoryHandler', 'empty', (ks: any[], ps: string[]) => { const h = M.directoryHandler(dk(ks)); return ps.map((p) => h(p)); }, [[], PATHS.slice(0, 2)]);

// ---- memoryReplayCache
const cacheRun = (max: number | null, ops: any[]) => { const c = max === null ? M.memoryReplayCache() : M.memoryReplayCache(max); return ops.map(([k, e, n]) => { try { return c.claim(k, e, n); } catch { return 'throw'; } }); };
for (const [i, [max, ops]] of ([
  [null, [['a', 10, 0], ['a', 10, 0], ['a', 10, 10], ['a', 10, 11], ['b', 5, 0]]], [1, [['a', 10, 0], ['b', 10, 0], ['b', 10, 11], ['a', 10, 11], ['c', 20, 11]]], [2, [['a', 5, 0], ['b', 50, 0], ['c', 50, 6], ['d', 50, 6], ['e', 50, 100]]],
  [0, [['a', 5, 0], ['a', 5, 0]]], [3, [['a', 1, 0], ['b', 1, 0], ['c', 1, 0], ['d', 1, 5], ['a', 9, 5]]], [2, [['a', 5, 5], ['a', 5, 5], ['b', 4, 5], ['c', 4, 6]]], [1, [['a', 10, 0], ['a', 20, 10], ['a', 20, 9]]],
] as any[]).entries()) await o.run('memoryReplayCache', `seq${i}`, cacheRun, [max, ops]);

// ---- proof binding
const PCT: any = { ver: 2, aud: 'rs', iat: T0 * 1000, exp: T0 * 1000 + 60000, nonce: 'n', grant_ref: 'g', action: { verb: 'pay', resource: 'shop', params_digest: 'p' }, cap_chain: [{ id: 'g', holder: 'h', caveats: [] }], plan: { root: 'r', node_id: 'n1' }, sig: 'x' };
await o.run('proofHeaders', 'base', M.proofHeaders, [PCT]);
await o.run('proofHeaders', 'unicode', M.proofHeaders, [{ ...PCT, note: 'é 😀', z: 1, a: [1.5, null] }]);
const PH: string = M.proofHeaders(PCT)['PCA-Action'];
const enc = (s: string) => Buffer.from(s).toString('base64url');
for (const [i, v] of ([PH, PH + '=', PH.slice(0, -1), PH + '\n', ' ' + PH, '', '!', 'AAAA', enc('{}'), enc('[]'), enc('null'), enc('{"a":1,"a":2}'), enc('{"a":01}'), enc(' {}'), enc('{} '), enc('﻿{}'), enc('{"a":1.50}'), enc('{"a":1e5}'), enc('{"a":"\\ud800"}'), enc('{"a":-0}'), enc('{"a":9007199254740993}'), Buffer.from([0xff, 0xfe]).toString('base64url'), enc('{"x":' + '['.repeat(40) + ']'.repeat(40) + '}')] as any[]).entries())
  await o.run('decodeProofHeader', `v${i}`, M.decodeProofHeader, [v]);
await o.run('signRequestWithProof', 'base', signP, [{ ...BASE, pcactn: PCT }]);
await o.run('signRequestWithProof', 'cover', signP, [{ ...BASE, pcactn: PCT, coverHeaders: ['content-type'] }]);
await o.run('signRequestWithProof', 'lower-proof-header', signP, [{ ...BASE, pcactn: PCT, headers: { ...BASE.headers, 'pca-action': 'old' } }]);
await o.run('signRequestWithProof', 'agent', signP, [{ ...BASE, pcactn: PCT, agentDirectoryUrl: 'https://a.test', agentDirectoryKey: 'a1' }]);
await o.run('signRequestWithProof', 'nopcactn', signP, [BASE]);
for (const [l, v] of vv(PCT, { maxPaths: 40 })) if (!l.includes('surrogate')) await o.run('signRequestWithProof', `pc ${l}`, signP, [{ ...BASE, pcactn: v }]);
const SP = M.signRequestWithProof(withKey({ ...BASE, pcactn: PCT }));
const PRQ = { method: BASE.method, url: BASE.url, headers: { ...BASE.headers, ...SP.headers } };
await o.run('verifySignedRequestWithProof', 'ok', verifyP, [PRQ, OP]);
await o.run('verifySignedRequestWithProof', 'expected-same', verifyP, [PRQ, { ...OP, expectedPCActn: PCT }]);
await o.run('verifySignedRequestWithProof', 'expected-other', verifyP, [PRQ, { ...OP, expectedPCActn: { ...PCT, nonce: 'z' } }]);
await o.run('verifySignedRequestWithProof', 'expected-reorder', verifyP, [PRQ, { ...OP, expectedPCActn: JSON.parse(JSON.stringify({ sig: 'x', plan: PCT.plan, cap_chain: PCT.cap_chain, action: PCT.action, grant_ref: 'g', nonce: 'n', exp: PCT.exp, iat: PCT.iat, aud: 'rs', ver: 2 })) }]);
await o.run('verifySignedRequestWithProof', 'not-covered', verifyP, [RQ, OP]);
await o.run('verifySignedRequestWithProof', 'bad-sig', verifyP, [{ ...PRQ, headers: { ...PRQ.headers, Signature: flipSig(PRQ.headers.Signature) } }, OP]);
await o.run('verifySignedRequestWithProof', 'swapped-proof', verifyP, [{ ...PRQ, headers: { ...PRQ.headers, 'PCA-Action': M.proofHeaders({ ...PCT, nonce: 'swap' })['PCA-Action'] } }, OP]);
for (const [i, v] of ([PH + '=', '', 'AAAA', enc('{}'), enc('[1]')] as string[]).entries()) {
  const bad = M.signRequestWithProof(withKey({ ...BASE, pcactn: PCT }));
  void bad;
  // sign over a header carrying the odd proof value: build the request by signing with that header present and covered
  const out = M.signRequest(withKey({ ...BASE, headers: { ...BASE.headers, 'PCA-Action': v }, coverHeaders: ['pca-action'] }));
  await o.run('verifySignedRequestWithProof', `odd-proof${i}`, verifyP, [{ method: BASE.method, url: BASE.url, headers: { ...BASE.headers, 'PCA-Action': v, ...out.headers } }, OP]);
}
{
  const out = M.signRequest(withKey({ ...BASE, headers: { ...BASE.headers, 'PCA-Action': 'x' }, coverHeaders: ['pca-action'] }));
  await o.run('verifySignedRequestWithProof', 'odd-proof-removed', verifyP, [{ method: BASE.method, url: BASE.url, headers: { ...BASE.headers, ...out.headers } }, OP]);
}

// ---- Content-Digest
const BODIES: any[] = ['', 'hello', '{"hello": "world"}\n', 'é😀', { $bytes: '' }, { $bytes: 'AAEC_w' }];
const body = (b: any) => (b && typeof b === 'object' && b.$bytes !== undefined ? bytes(b.$bytes) : b);
for (const [i, b] of BODIES.entries()) {
  for (const a of ['sha-256', 'sha-512', 'md5', 'SHA-256']) await o.run('contentDigestBytes', `b${i}-${a}`, (x: any, al: string) => M.contentDigestBytes(body(x), al), [b, a]);
  for (const [j, algs] of ([undefined, ['sha-256'], ['sha-512'], ['sha-512', 'sha-256'], ['sha-256', 'sha-256'], [], ['md5'], ['sha-256', 'sha']] as any[]).entries())
    await o.run('contentDigestHeader', `b${i}-a${j}`, (x: any, al?: any) => (al === undefined ? M.contentDigestHeader(body(x)) : M.contentDigestHeader(body(x), al)), algs === undefined ? [b] : [b, algs]);
}
const H1 = M.contentDigestHeader('hello', ['sha-256', 'sha-512']);
const H256 = M.contentDigestHeader('hello'), H512 = M.contentDigestHeader('hello', ['sha-512']);
const d256 = H256.slice(10, -1);
const CDV: string[] = [H1, H256, H512, ' ' + H256 + ' ', H256 + ',', ',' + H256, H256 + ', ' + H512, H512 + ',' + H256, H256 + ', ' + H256, 'sha-256=:' + d256.slice(0, -2) + 'B=:', 'sha-256=:' + d256.slice(0, -1) + ':', 'sha-256=:' + d256 + 'A:', 'sha-256=:' + d256.replace(/=+$/, '') + ':', 'SHA-256=:' + d256 + ':',
  'sha-256=' + d256, 'sha-256=:' + d256 + ':;x=1', 'sha-256=:' + d256 + ':, md5=:AAAA:', 'md5=:AAAA:', 'sha=:AAAA:', 'unixsum=:AAAA:', '', ' ', 'x', 'sha-256=::', 'sha-256=:AAAA:', 'sha-256=:A===:', 'sha-256=:AAAAAA==:', 'sha-256=:AAAAAB==:', 'sha-256=:AA==:', 'sha-256=:AB==:', 'a*b=:AAAA:', 'a=:AAAA:, a=:AAAA:', '=:AAAA:', '9a=:AAAA:'];
for (const [i, h] of CDV.entries()) {
  for (const b of ['hello', 'hellO', '']) await o.run('verifyContentDigest', `h${i}-${b}`, (h2: any, bd: any, op?: any) => M.verifyContentDigest(h2 === null ? undefined : h2, body(bd), op), [h, b]);
  if (i < 10) for (const [j, r] of ([['sha-256'], ['sha-512'], ['sha-256', 'sha-512'], [], ['md5']] as any[]).entries()) await o.run('verifyContentDigest', `h${i}-req${j}`, (h2: any, bd: any, op?: any) => M.verifyContentDigest(h2, body(bd), op), [h, 'hello', { require: r }]);
  await o.run('parseContentDigest', `h${i}`, M.parseContentDigest, [h]);
}
await o.run('verifyContentDigest', 'absent', (h2: any, bd: any) => M.verifyContentDigest(h2 === null ? undefined : h2, body(bd)), [null, 'hello']);
await o.run('verifyContentDigest', 'bytes', (h2: any, bd: any) => M.verifyContentDigest(h2, body(bd)), [M.contentDigestHeader(bytes('AAEC_w')), { $bytes: 'AAEC_w' }]);
await o.run('verifyContentDigest', 'rfc-digest', (h2: any, bd: any) => M.verifyContentDigest(h2, body(bd)), [RREQ.headers['Content-Digest'], '{"hello": "world"}']);

// ---- signed directory
const GOOD_DIR = M.buildKeyDirectory([{ publicKey: bytes(KA.publicKey), keyid: 'ka' }, { publicKey: bytes(KB.publicKey), keyid: 'kb' }]);
const GTXT = JSON.stringify(GOOD_DIR);
await o.run('parseKeyDirectory', 'good', M.parseKeyDirectory, [GTXT]);
for (const [i, t] of ([JSON.stringify({ keys: [] }), '{}', 'null', '[]', 'x', '', JSON.stringify({ keys: 'x' }), JSON.stringify({ keys: [null] }), JSON.stringify({ keys: [5] }), JSON.stringify({ keys: [[]] }), JSON.stringify({ keys: [{ ...GOOD_DIR.keys[0], kty: 'EC' }] }), JSON.stringify({ keys: [{ ...GOOD_DIR.keys[0], crv: 'X25519' }] }),
  JSON.stringify({ keys: [{ ...GOOD_DIR.keys[0], kid: '' }] }), JSON.stringify({ keys: [{ ...GOOD_DIR.keys[0], kid: 5 }] }), JSON.stringify({ keys: [{ ...GOOD_DIR.keys[0], x: 'AAAA' }] }), JSON.stringify({ keys: [{ ...GOOD_DIR.keys[0], x: GOOD_DIR.keys[0].x + 'A' }] }), JSON.stringify({ keys: [{ ...GOOD_DIR.keys[0], x: 5 }] }),
  JSON.stringify({ keys: [{ ...GOOD_DIR.keys[0], nbf: 'x' }] }), JSON.stringify({ keys: [{ ...GOOD_DIR.keys[0], exp: null }] }), JSON.stringify({ keys: [{ ...GOOD_DIR.keys[0], nbf: 1, exp: 2 }] }), JSON.stringify({ keys: [GOOD_DIR.keys[0], { kty: 'OKP' }] }), '{"keys":[' + JSON.stringify(GOOD_DIR.keys[0]) + '],"keys":[]}',
  JSON.stringify({ ...GOOD_DIR, extra: 1 }), ' ' + GTXT + ' ', '﻿' + GTXT, JSON.stringify({ keys: [{ ...GOOD_DIR.keys[0], x: GOOD_DIR.keys[0].x.slice(0, 42) + '\n' }] })] as string[]).entries()) await o.run('parseKeyDirectory', `t${i}`, M.parseKeyDirectory, [t]);
const sdIn = (i: any) => ({ ...i, keys: i.keys.map(keyOf) });
const sdSign = (i: any) => M.signDirectoryResponse(sdIn(i));
const SD: any = { keys: [KA], directory: GOOD_DIR, authority: 'example.com', created: T0, expiresInSec: 3600 };
await o.run('signDirectoryResponse', 'one', sdSign, [SD]);
await o.run('signDirectoryResponse', 'two', sdSign, [{ ...SD, keys: [KA, KB] }]);
await o.run('signDirectoryResponse', 'default-life', sdSign, [{ ...SD, expiresInSec: undefined }]);
for (const [k, d] of Object.entries({ nokeys: { keys: [] }, notindir: { keys: [KRFC] }, authport: { authority: 'example.com:8443' }, authuc: { authority: 'Example.com' }, authempty: { authority: '' }, authipv6: { authority: '[::1]:9' }, authspace: { authority: 'a b' }, authuser: { authority: 'u@x' }, created: { created: 0 }, exp0: { expiresInSec: 0 } } as any))
  await o.run('signDirectoryResponse', `opt-${k}`, sdSign, [{ ...SD, ...d }]);
for (const [l, v] of vv(SD, { maxPaths: 40 })) if (l.startsWith('/authority') && !l.includes('hostile') && !l.includes('deleted')) await o.run('signDirectoryResponse', `var ${l}`, sdSign, [v]);
const SIGNED_DIR = M.signDirectoryResponse(sdIn({ ...SD, keys: [KA, KB] }));
const vd = (i: any) => M.verifyDirectoryResponse(i);
const VD: any = { authority: 'example.com', headers: SIGNED_DIR.headers, body: SIGNED_DIR.body, now: T0 + 10 };
await o.run('verifyDirectoryResponse', 'ok', vd, [VD]);
const hh = (h: any) => ({ ...VD, headers: { ...VD.headers, ...h } });
const SI2 = SIGNED_DIR.headers['signature-input'], SG2 = SIGNED_DIR.headers.signature;
const VDS: [string, any][] = [
  ['authority', { ...VD, authority: 'other.com' }], ['body', { ...VD, body: VD.body + ' ' }], ['body-bad', { ...VD, body: '{}' }], ['nosig', hh({ signature: undefined })], ['nosi', hh({ 'signature-input': undefined })], ['upper-hdr', { ...VD, headers: { 'Signature-Input': SI2, Signature: SG2 } }],
  ['only-first', hh({ 'signature-input': SI2.split(', ')[0], signature: SG2.split(', ')[0] })], ['only-second', hh({ 'signature-input': SI2.split(', ')[1], signature: SG2.split(', ')[1] })], ['sig-missing-label', hh({ signature: SG2.split(', ')[0] })], ['sig-bad', hh({ signature: 'x' })],
  ['sig-flip', hh({ signature: SG2.replace(/^(sig1=:)(.)/, (_m: string, a: string, b: string) => a + (b === 'A' ? 'B' : 'A')) })], ['sig-short', hh({ signature: 'sig1=:AAAA:, sig2=:AAAA:' })], ['si-bad', hh({ 'signature-input': 'x' })],
  ['si-comma', hh({ 'signature-input': SI2.replace(', ', ',') })], ['si-dup-param', hh({ 'signature-input': SI2.replace(';alg="ed25519"', ';alg="ed25519";alg="ed25519"') })], ['si-tag', hh({ 'signature-input': SI2.replaceAll(DIRECTORY_TAG(), 'web-bot-auth') })], ['si-noalg', hh({ 'signature-input': SI2.replaceAll(';alg="ed25519"', '') })],
  ['si-alg', hh({ 'signature-input': SI2.replaceAll('alg="ed25519"', 'alg="rsa"') })], ['si-nocreated', hh({ 'signature-input': SI2.replace(/;created=\d+/, '') })], ['si-noexpires', hh({ 'signature-input': SI2.replace(/;expires=\d+/, '') })], ['si-nokeyid', hh({ 'signature-input': SI2.replace(/;keyid="[^"]*"/, '') })],
  ['si-badkeyid', hh({ 'signature-input': SI2.replace(/keyid="[^"]*"/, 'keyid="zzz"') })], ['si-extra-component', hh({ 'signature-input': SI2.replace('("@authority";req)', '("@authority";req "@path")') })], ['si-label-case', hh({ 'signature-input': SI2.replace('sig1=', 'Sig1=') })],
  ['time-future', { ...VD, now: T0 - 1 }], ['time-edge', { ...VD, now: T0 + 3600 }], ['time-expired', { ...VD, now: T0 + 3601 }], ['skew', { ...VD, now: T0 - 5, clockSkewSec: 5 }], ['skew-exp', { ...VD, now: T0 + 3605, clockSkewSec: 5 }], ['life-short', { ...VD, maxLifetimeSec: 3599 }], ['life-ok', { ...VD, maxLifetimeSec: 3600 }], ['life-default', { ...VD, maxLifetimeSec: undefined }],
];
function DIRECTORY_TAG() { return 'http-message-signatures-directory'; }
for (const [n, i] of VDS) await o.run('verifyDirectoryResponse', n, vd, [i]);
for (const [n, d] of Object.entries({ nbf: { keys: [{ ...GOOD_DIR.keys[0], nbf: T0 + 11 }, GOOD_DIR.keys[1]] }, exp: { keys: [{ ...GOOD_DIR.keys[0], exp: T0 + 9 }, GOOD_DIR.keys[1]] }, okwin: { keys: [{ ...GOOD_DIR.keys[0], nbf: T0, exp: T0 + 10 }, GOOD_DIR.keys[1]] } } as any)) {
  // the body is re-signed over the modified directory (same keys, so the thumbprints still match)
  const s = M.signDirectoryResponse(sdIn({ ...SD, keys: [KA, KB], directory: d }));
  await o.run('verifyDirectoryResponse', `window-${n}`, vd, [{ authority: 'example.com', headers: s.headers, body: s.body, now: T0 + 10 }]);
}
{
  const dup = M.signDirectoryResponse(sdIn({ ...SD, keys: [KA, KA] }));
  await o.run('verifyDirectoryResponse', 'same-key-twice', vd, [{ authority: 'example.com', headers: dup.headers, body: dup.body, now: T0 + 10 }]);
  const port = M.signDirectoryResponse(sdIn({ ...SD, authority: 'example.com:8443' }));
  await o.run('verifyDirectoryResponse', 'port', vd, [{ authority: 'example.com:8443', headers: port.headers, body: port.body, now: T0 + 10 }]);
  await o.run('verifyDirectoryResponse', 'port-mismatch', vd, [{ authority: 'example.com', headers: port.headers, body: port.body, now: T0 + 10 }]);
}
for (const [l, v] of vv({ authority: VD.authority, headers: VD.headers, body: VD.body, now: VD.now }, { maxPaths: 40 })) if (l.startsWith('/authority') && !l.includes('hostile') && !l.includes('deleted')) await o.run('verifyDirectoryResponse', `var ${l}`, vd, [v]);

// ---- fetchKeyDirectory (scripted fetch)
const fetchRun = async (url: string, spec: any) => {
  let called: any = null;
  const res = spec.response;
  const fetch = async (u: string, init: any) => {
    called = { url: u, headers: init.headers, redirect: init.redirect };
    if (res === 'throw') throw new Error('network down');
    return { status: res.status, headers: { get: (n: string) => (res.headers ?? {})[n.toLowerCase()] ?? null }, text: async () => res.body };
  };
  try {
    const directory = await M.fetchKeyDirectory(url, { ...(spec.options ?? {}), fetch });
    return { directory, called };
  } catch (e: any) {
    const msg = String(e.message);
    return { error: true, message: /^(directory |Invalid URL)/.test(msg) ? msg.replace(/^(directory signature): .*$/s, '$1') : 'other', called };
  }
};
const CT = 'application/http-message-signatures-directory+json';
const OK = { status: 200, headers: { 'content-type': CT }, body: GTXT };
const FURLS = ['https://example.com/.well-known/http-message-signatures-directory', 'http://example.com/d', 'https://EXAMPLE.com:8443/d?x=1', 'ftp://example.com/d', 'not a url', '', 'https://example.com'];
for (const [i, u] of FURLS.entries()) {
  await o.run('fetchKeyDirectory', `url${i}`, fetchRun, [u, { response: OK }]);
  await o.run('fetchKeyDirectory', `url${i}-http`, fetchRun, [u, { response: OK, options: { allowInsecureHttp: true } }]);
}
for (const [n, r] of Object.entries({ s404: { ...OK, status: 404 }, s204: { ...OK, status: 204 }, ct: { ...OK, headers: { 'content-type': 'application/json' } }, ctcase: { ...OK, headers: { 'content-type': 'Application/HTTP-Message-Signatures-Directory+JSON; charset=utf-8' } }, noct: { ...OK, headers: {} },
  big: { ...OK, body: GTXT + ' '.repeat(70000) }, bad: { ...OK, body: 'nope' }, empty: { ...OK, body: '{"keys":[]}' }, malformed: { ...OK, body: '{"keys":[{"kty":"OKP"}]}' }, throw: 'throw' } as any)) await o.run('fetchKeyDirectory', `resp-${n}`, fetchRun, ['https://example.com/d', { response: r }]);
for (const [n, op] of Object.entries({ max: { maxBytes: 10 }, maxok: { maxBytes: GTXT.length }, maxlt: { maxBytes: GTXT.length - 1 } } as any)) await o.run('fetchKeyDirectory', `opt-${n}`, fetchRun, ['https://example.com/d', { response: OK, options: op }]);
{
  const s = M.signDirectoryResponse(sdIn({ ...SD, keys: [KA], directory: GOOD_DIR }));
  const sresp = { status: 200, headers: { 'content-type': CT, 'signature-input': s.headers['signature-input'], signature: s.headers.signature }, body: s.body };
  await o.run('fetchKeyDirectory', 'sig-ok', fetchRun, ['https://example.com/d', { response: sresp, options: { requireSignature: true, now: T0 + 5 } }]);
  await o.run('fetchKeyDirectory', 'sig-nosig', fetchRun, ['https://example.com/d', { response: OK, options: { requireSignature: true, now: T0 + 5 } }]);
  await o.run('fetchKeyDirectory', 'sig-host', fetchRun, ['https://other.example/d', { response: sresp, options: { requireSignature: true, now: T0 + 5 } }]);
  await o.run('fetchKeyDirectory', 'sig-port', fetchRun, ['https://example.com:8443/d', { response: sresp, options: { requireSignature: true, now: T0 + 5 } }]);
  await o.run('fetchKeyDirectory', 'sig-expired', fetchRun, ['https://example.com/d', { response: sresp, options: { requireSignature: true, now: T0 + 99999 } }]);
  await o.run('fetchKeyDirectory', 'sig-false', fetchRun, ['https://example.com/d', { response: OK, options: { requireSignature: false } }]);
}

{ const by: any = {}; for (const c of o.cases) by[c.fn] = (by[c.fn] ?? 0) + JSON.stringify(c).length; console.log(JSON.stringify(by)); }
refWrite(o, 'webbotauth');
