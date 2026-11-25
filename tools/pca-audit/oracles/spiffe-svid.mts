// Oracle: @atlasauth/pca-spiffe (SPIFFE ID parsing, JWT-SVID / X.509-SVID verification, SVID -> PCA holder binding, trust-bundle and
// revocation caches, admission evidence). Deterministic: keys come from seeds, the extra X.509 certificates are built here from hand-written
// DER and signed with deterministic Ed25519 / RFC 6979 ECDSA, JWT-SVIDs are assembled by hand and signed the same way. Writes out/ref-spiffe-svid.json.gz.
//
// PORTING (fn(args) -> native entry point; a `$throws` with `code` needs the same SpiffeError / JOSE code, without code any refusal):
//   parseSpiffeId(s)                                  -> parse_spiffe_id   {id, trustDomain, path}
//   parseX509Svid(cert)                               -> parse_x509_svid   {spiffeId, publicKeyDer}   (cert: PEM string or {$bytes} DER)
//   verifyX509Svid(chain, vo)                         -> verify_x509_svid  {id, trustDomain, path, publicKeyDer, calls}
//        vo = {trustDomain, roots, nowMs?, maxChainLength?, revocation?}; revocation = null (not a function) | 'false' | 'true' | 'at:N'
//        (true for position N) | 'throw' | 'nonbool'; calls = the subjects the check saw, in order (camelCase here, snake_case native)
//   verifyJwtSvid(token, vo)                          -> verify_jwt_svid   {spiffeId:{id,trustDomain,path}, claims, audience, expiresAt, calls}
//        vo = {audience, key, trustDomain, currentSec?, algorithms?, clockTolerance?, revocation?}; key = {jwk} | {jwks} (candidate resolver)
//   svidToHolderX509(chain, vo, holderKey, bind)      verify then svid_to_holder -> {holder, spiffeId, trustDomain, path}
//   svidToHolderJwt(token, vo, holderKey, bind)       same for a JWT-SVID; holderKey null = omitted; {$bytes} = raw key bytes
//   svidToHolderUnverified(kind, pem)                 svid_to_holder over a string / hand-built object / parse-only SVID: always refuses
//   spiffeIdForHolder(chain, vo, leafHolder, bind)    spiffe_id_for_holder over a verified X.509 SVID
//   workloadDischargePin(label, chain, vo)            workload_discharge_pin over a verified X.509 SVID
//   holderToSpiffeId(holder) / holderBindingMessage(spiffeId, holder)
//   spiffeAdmissionEvidence(e, instanceKey)           spiffe_admission_evidence ({kind, chain|token, verify: vo, bind})
//   trustBundleScenario(opts, steps) / revocationScenario(opts, steps)   scripted clock + fetch; one {ok|code, fetches} per step
//        a step's fetch: the bundle / list, {$throw: text} (plain failure) or {$spiffe: code}; bundle / list keys camelCase here
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { ed25519 } from '@noble/curves/ed25519';
import { p256 } from '@noble/curves/p256';
import { p384 } from '@noble/curves/p384';
import { importJWK, createLocalJWKSet } from 'jose';
import { Oracle, refWrite, seed } from './lib.mjs';

const M: any = await import('../../../packages/pca-spiffe/src/index.ts');
const o = new Oracle('spiffe-svid', 'tools/pca-audit/oracles/spiffe-svid.mts', 'TS-reference oracle for SPIFFE IDs, SVID verification and binding, trust-bundle and revocation caches.');

const FIX = fileURLToPath(new URL('../../../packages/pca-spiffe/fixtures/generated/', import.meta.url));
const pem = (n: string) => fs.readFileSync(FIX + n + '.pem', 'utf8');
const b64u = (b: Uint8Array | Buffer | string) => Buffer.from(b as any).toString('base64url');
const sha256 = (d: Uint8Array) => new Uint8Array(createHash('sha256').update(d).digest());
const sha384 = (d: Uint8Array) => new Uint8Array(createHash('sha384').update(d).digest());
const rev = (v: any): any => (v && typeof v === 'object' && !Array.isArray(v) && typeof v.$bytes === 'string' ? Buffer.from(v.$bytes, 'base64url') : v);
const T = (s: string) => Date.parse(s);
const NOW_MS = T('2027-06-01T00:00:00Z');
const ID = 'spiffe://example.org/workload/db';

// ---- a minimal DER certificate builder (extra leaves: Ed25519 keys, hostile extensions) ---------------------------------------------
const lenB = (n: number) => (n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 255]);
const tlv = (tag: number, ...p: Uint8Array[]) => { const c = Buffer.concat(p); return Buffer.concat([Buffer.from([tag, ...lenB(c.length)]), c]); };
const seq = (...p: Uint8Array[]) => tlv(0x30, ...p);
const oid = (h: string) => tlv(6, Buffer.from(h, 'hex'));
const octet = (...p: Uint8Array[]) => tlv(4, ...p);
const cname = (cn: string) => seq(tlv(0x31, seq(oid('550403'), tlv(0x0c, Buffer.from(cn)))));
const ext = (oidHex: string, critical: boolean, value: Uint8Array) => seq(oid(oidHex), ...(critical ? [tlv(1, Buffer.from([0xff]))] : []), octet(value));
const bcExt = (ca: boolean, pathLen?: number) => ext('551d13', true, seq(...(ca ? [tlv(1, Buffer.from([0xff]))] : []), ...(pathLen !== undefined ? [tlv(2, Buffer.from([pathLen]))] : [])));
const kuExt = (b0: number, unused: number) => ext('551d0f', true, tlv(3, Buffer.from([unused, b0])));
const sanExt = (uris: string[]) => ext('551d11', false, seq(...uris.map((u) => tlv(0x86, Buffer.from(u)))));
const ED_ALG = seq(oid('2b6570'));
const EC_ALG = seq(oid('2a8648ce3d040302'));
const spkiEd = (pub: Uint8Array) => Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), pub]);
const spkiP256 = (pub: Uint8Array) => Buffer.concat([Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'), pub]);
interface Signer { alg: Buffer; sign: (d: Uint8Array) => Uint8Array }
const edSigner = (s: Uint8Array): Signer => ({ alg: ED_ALG, sign: (d) => ed25519.sign(d, s) });
const ecSigner = (s: Uint8Array): Signer => ({ alg: EC_ALG, sign: (d) => p256.sign(sha256(d), s).toDERRawBytes() });
const mkCert = (a: { serial: number; issuer: string; subject: string; spki: Uint8Array; exts: Uint8Array[]; signer: Signer; nb?: string; na?: string; noExtWrap?: boolean }) => {
  const tbs = seq(tlv(0xa0, tlv(2, Buffer.from([2]))), tlv(2, Buffer.from([a.serial])), a.signer.alg, cname(a.issuer),
    seq(tlv(0x17, Buffer.from(a.nb ?? '261001000000Z')), tlv(0x17, Buffer.from(a.na ?? '361001000000Z'))), cname(a.subject), a.spki,
    ...(a.noExtWrap ? [] : [tlv(0xa3, seq(...a.exts))]));
  return seq(tbs, a.signer.alg, tlv(3, Buffer.from([0]), a.signer.sign(tbs)));
};
const toPem = (der: Uint8Array) => `-----BEGIN CERTIFICATE-----\n${Buffer.from(der).toString('base64').match(/.{1,64}/g)!.join('\n')}\n-----END CERTIFICATE-----\n`;

const ROOT_SEED = seed('ref-spiffe/root-ed');
const EC_ROOT_SEED = seed('ref-spiffe/root-ec');
const LEAF_ED_SEED = seed('ref-spiffe/leaf-ed');
const LEAF_EC_SEED = seed('ref-spiffe/leaf-ec');
const rootExts = [bcExt(true), kuExt(0x06, 1)];
const ROOT_DER = mkCert({ serial: 1, issuer: 'ed-root', subject: 'ed-root', spki: spkiEd(ed25519.getPublicKey(ROOT_SEED)), exts: rootExts, signer: edSigner(ROOT_SEED) });
const EC_ROOT_DER = mkCert({ serial: 2, issuer: 'ec-root', subject: 'ec-root', spki: spkiP256(p256.getPublicKey(EC_ROOT_SEED, false)), exts: rootExts, signer: ecSigner(EC_ROOT_SEED) });
const leafExts = (uris: string[]) => [bcExt(false), kuExt(0x80, 7), sanExt(uris)];
const leafEd = (serial: number, exts: Uint8Array[], extra: Record<string, any> = {}) => mkCert({ serial, issuer: 'ed-root', subject: 'leaf', spki: spkiEd(ed25519.getPublicKey(LEAF_ED_SEED)), exts, signer: edSigner(ROOT_SEED), ...extra });
const leafEc = (serial: number, exts: Uint8Array[], extra: Record<string, any> = {}) => mkCert({ serial, issuer: 'ed-root', subject: 'leaf', spki: spkiP256(p256.getPublicKey(LEAF_EC_SEED, false)), exts, signer: edSigner(ROOT_SEED), ...extra });
const ED_ROOT = toPem(ROOT_DER);
const EC_ROOT = toPem(EC_ROOT_DER);
const ID_ED = 'spiffe://example.org/workload/ed';
const ID_EC = 'spiffe://example.org/workload/ec';
const LEAF_ED = toPem(leafEd(10, leafExts([ID_ED])));
const LEAF_EC = toPem(leafEc(11, leafExts([ID_EC])));
const LEAF_EC_BY_EC = toPem(mkCert({ serial: 12, issuer: 'ec-root', subject: 'leaf', spki: spkiP256(p256.getPublicKey(LEAF_EC_SEED, false)), exts: leafExts([ID_EC]), signer: ecSigner(EC_ROOT_SEED) }));

// ---- option builders shared by every wrapper ---------------------------------------------------------------------------------------
const mkRev = (mode: any, calls: any[]) => {
  if (mode === null) return null;
  const at = typeof mode === 'string' && mode.startsWith('at:') ? Number(mode.slice(3)) : -1;
  return (s: any) => {
    calls.push(JSON.parse(JSON.stringify(s)));
    if (mode === 'throw') throw new Error('backend down');
    if (mode === 'nonbool') return 'no';
    if (mode === 'true') return true;
    if (at >= 0) return s.position === at;
    return false;
  };
};
const xo = (v: any, calls: any[]) => {
  const r: any = { trustDomain: v.trustDomain, roots: (v.roots ?? []).map(rev) };
  if (v.nowMs !== undefined) r.now = new Date(v.nowMs);
  if (v.maxChainLength !== undefined) r.maxChainLength = v.maxChainLength;
  if ('revocation' in v) r.revocation = mkRev(v.revocation, calls);
  return r;
};
const jo = async (v: any, calls: any[]) => {
  const r: any = { audience: v.audience, trustDomain: v.trustDomain };
  if (v.key?.jwk) r.key = await importJWK(v.key.jwk, v.key.jwk.crv === 'P-384' ? 'ES384' : 'ES256');
  else if (v.key?.jwks) r.key = createLocalJWKSet(v.key.jwks);
  if (v.currentSec !== undefined) r.currentDate = new Date(v.currentSec * 1000);
  if (v.algorithms !== undefined) r.algorithms = v.algorithms;
  if (v.clockTolerance !== undefined) r.clockTolerance = v.clockTolerance;
  if ('revocation' in v) r.revocation = mkRev(v.revocation, calls);
  return r;
};
const idOut = (i: any) => ({ id: i.id, trustDomain: i.trustDomain, path: i.path });
const x509Out = (s: any, calls: any[]) => ({ ...idOut(s.spiffeId), publicKeyDer: s.publicKeyDer, calls });
const jwtOut = (s: any, calls: any[]) => ({ spiffeId: idOut(s.spiffeId), claims: s.claims, audience: s.audience, expiresAt: s.expiresAt, calls });
const hk = (v: any) => (v === null ? undefined : rev(v));
const bindOf = (b: any) => (b === null ? undefined : b);

const verifyX509 = (chain: any, vo: any) => { const calls: any[] = []; const c = Array.isArray(chain) ? chain.map(rev) : rev(chain); return x509Out(M.verifyX509Svid(c, xo(vo, calls)), calls); };
const verifyJwt = async (token: any, vo: any) => { const calls: any[] = []; return jwtOut(await M.verifyJwtSvid(token, await jo(vo, calls)), calls); };
const holderOut = (h: any) => ({ holder: h.holder, spiffeId: h.spiffeId, trustDomain: h.trustDomain, path: h.path });
const x509Verified = (chain: any, vo: any) => M.verifyX509Svid(Array.isArray(chain) ? chain.map(rev) : rev(chain), xo(vo, []));
const jwtVerified = async (token: any, vo: any) => M.verifyJwtSvid(token, await jo(vo, []));

// ---- parseSpiffeId -----------------------------------------------------------------------------------------------------------------
const ids: any[] = [
  ID, 'spiffe://example.org', 'spiffe://example.org/', 'spiffe://a', 'spiffe://trust-domain_1.example/a-b_c.d/SEG2', 'spiffe://example.org/a/b/c/d/e', '', null, 5, {}, [], true,
  'https://example.org/x', 'SPIFFE://example.org/x', 'Spiffe://example.org/x', 'spiffe:/example.org/x', 'spiffe:example.org/x', 'spiffe:///workload', 'spiffe://Example.org/x', 'spiffe://exa mple.org/x',
  'spiffe://example.org//db', 'spiffe://example.org/./db', 'spiffe://example.org/../db', 'spiffe://example.org/db/.', 'spiffe://example.org/db/..', 'spiffe://example.org/wor kload', 'spiffe://example.org/wörkload',
  'spiffe://example.org/a%20b', 'spiffe://example.org/a?b', 'spiffe://example.org/a#b', 'spiffe://example.org:8080/a', 'spiffe://user@example.org/a', 'spiffe://example.org/a\n', 'spiffe://example.org\n/a', 'spiffe://example.org\n',
  'spiffe://exämple.org/a', 'spiffe://example.org/\ud800', 'spiffe://\ud800/a', ' spiffe://example.org/a', 'spiffe://example.org/a ', 'spiffe://.', 'spiffe://-', 'spiffe://_/_', 'spiffe://0/0',
  'spiffe://example.org/' + 'a'.repeat(2048 - 'spiffe://example.org/'.length), 'spiffe://example.org/' + 'a'.repeat(2049 - 'spiffe://example.org/'.length), 'spiffe://example.org/' + 'a'.repeat(2048),
  'spiffe://' + 'a'.repeat(255) + '/x', 'spiffe://' + 'a'.repeat(256) + '/x', 'spiffe://' + 'a'.repeat(255), 'spiffe://' + 'a'.repeat(256), 'spiffe://' + 'a'.repeat(255) + '/' + 'b'.repeat(2048 - 9 - 255 - 1),
  'spiffe://' + 'é'.repeat(1030) + '/x', 'spiffe://x/' + 'é'.repeat(1030),
];
for (const [i, s] of ids.entries()) await o.run('parseSpiffeId', `id${i}`, (x: any) => idOut(M.parseSpiffeId(x)), [s]);
for (let c = 0; c < 256; c++) {
  const ch = String.fromCharCode(c);
  await o.run('parseSpiffeId', `td-char-${c}`, (x: any) => idOut(M.parseSpiffeId(x)), [`spiffe://exa${ch}mple.org/p`]);
  await o.run('parseSpiffeId', `path-char-${c}`, (x: any) => idOut(M.parseSpiffeId(x)), [`spiffe://example.org/a${ch}b`]);
}

// ---- parseX509Svid -----------------------------------------------------------------------------------------------------------------
const derOf = (p: string) => ({ $bytes: Buffer.from(p.replace(/-----[A-Z ]+-----|\s/g, ''), 'base64').toString('base64url') });
const parseW = (c: any) => { const s = M.parseX509Svid(rev(c)); return { spiffeId: idOut(s.spiffeId), publicKeyDer: s.publicKeyDer }; };
const leafNames = ['leaf', 'leaf-direct', 'leaf-via-chain', 'leaf-noks', 'leaf-notca', 'leaf-expired', 'leaf-two-uri', 'leaf-dns-only', 'leaf-root-path', 'leaf-other-td', 'leaf-unknown-critical', 'leaf-is-ca',
  'leaf-cert-sign', 'leaf-crl-sign', 'leaf-no-digital-signature', 'leaf-no-key-usage', 'root', 'inter0', 'inter', 'inter-noks', 'inter-notca', 'other-root'];
for (const n of leafNames) {
  await o.run('parseX509Svid', n, parseW, [pem(n)]);
  await o.run('parseX509Svid', `${n}/der`, parseW, [derOf(pem(n))]);
}
const GARBAGE = ['', 'not a cert', '-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----', '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----', pem('leaf').slice(0, 200), pem('leaf').replace('MII', 'MIJ'),
  'junk\n' + pem('leaf') + '\njunk', pem('leaf') + pem('inter0'), pem('leaf').toLowerCase(), ['-----BEGIN ', 'PRIVATE KEY-----\nAAAA\n-----END ', 'PRIVATE KEY-----'].join('') /* assembled: a junk PEM body, never a key-shaped literal in source */, null, 5, {}, [],
  { $bytes: '' }, { $bytes: 'MIIB' }, { $bytes: Buffer.from(pem('leaf'), 'latin1').toString('base64url') }, derOf(pem('leaf')).$bytes, { $bytes: b64u(Buffer.concat([Buffer.from(derOf(pem('leaf')).$bytes, 'base64url'), Buffer.from([0])])) }];
for (const [i, g] of GARBAGE.entries()) await o.run('parseX509Svid', `garbage${i}`, parseW, [g]);
// built certificates
const builtCases: Array<[string, Uint8Array]> = [
  ['ed-leaf', leafEd(20, leafExts([ID_ED]))], ['ec-leaf', leafEc(21, leafExts([ID_EC]))],
  ['no-extensions', leafEd(22, [], { noExtWrap: true })], ['empty-extensions', leafEd(23, [])],
  ['dup-san', leafEd(24, [sanExt([ID_ED]), sanExt([ID_ED]), bcExt(false), kuExt(0x80, 7)])],
  ['dup-bc', leafEd(25, [bcExt(false), bcExt(false), kuExt(0x80, 7), sanExt([ID_ED])])],
  ['unknown-critical', leafEd(26, [...leafExts([ID_ED]), ext('2a0304', true, seq())])],
  ['unknown-noncritical', leafEd(27, [...leafExts([ID_ED]), ext('2a0304', false, seq())])],
  ['known-critical-eku', leafEd(28, [...leafExts([ID_ED]), ext('551d25', true, seq(oid('2b06010505070302')))])],
  ['two-uri', leafEd(29, leafExts([ID_ED, ID_EC]))], ['no-uri', leafEd(30, [bcExt(false), kuExt(0x80, 7), ext('551d11', false, seq(tlv(0x82, Buffer.from('example.org'))))])],
  ['uri-bad-id', leafEd(31, leafExts(['spiffe://Example.org/x']))], ['uri-http', leafEd(32, leafExts(['https://example.org/x']))],
  ['uri-root-path', leafEd(33, leafExts(['spiffe://example.org']))], ['uri-latin1', leafEd(34, leafExts(['spiffe://example.org/é']))],
  ['ca-true', leafEd(35, [bcExt(true), kuExt(0x80, 7), sanExt([ID_ED])])], ['ca-pathlen', leafEd(36, [bcExt(false, 2), kuExt(0x80, 7), sanExt([ID_ED])])],
  ['ku-sig-certsign', leafEd(37, [bcExt(false), kuExt(0x84, 2), sanExt([ID_ED])])], ['ku-sig-crlsign', leafEd(38, [bcExt(false), kuExt(0x82, 1), sanExt([ID_ED])])],
  ['ku-none-set', leafEd(39, [bcExt(false), kuExt(0x00, 0), sanExt([ID_ED])])], ['ku-short', leafEd(40, [bcExt(false), ext('551d0f', true, tlv(3, Buffer.from([0]))), sanExt([ID_ED])])],
  ['ku-not-bitstring', leafEd(41, [bcExt(false), ext('551d0f', true, tlv(4, Buffer.from([0, 0x80]))), sanExt([ID_ED])])],
  ['ext-value-not-octet', leafEd(42, [bcExt(false), kuExt(0x80, 7), seq(oid('551d11'), tlv(0x0c, Buffer.from('x')))])],
  ['ext-no-oid', leafEd(43, [bcExt(false), kuExt(0x80, 7), seq(tlv(0x0c, Buffer.from('x')), octet(seq()))])],
  ['ext-oid-only', leafEd(44, [bcExt(false), kuExt(0x80, 7), seq(oid('551d11'))])],
  ['ext-critical-false-explicit', leafEd(45, [bcExt(false), kuExt(0x80, 7), sanExt([ID_ED]), seq(oid('2a0304'), tlv(1, Buffer.from([0x00])), octet(seq()))])],
  ['ext-critical-nonff', leafEd(46, [bcExt(false), kuExt(0x80, 7), sanExt([ID_ED]), seq(oid('2a0304'), tlv(1, Buffer.from([0x01])), octet(seq()))])],
  ['ext-critical-empty-bool', leafEd(47, [bcExt(false), kuExt(0x80, 7), sanExt([ID_ED]), seq(oid('2a0304'), tlv(1), octet(seq()))])],
  ['ext-high-tag', leafEd(48, [bcExt(false), kuExt(0x80, 7), sanExt([ID_ED]), Buffer.from('1f8001 00'.replace(' ', ''), 'hex')])],
  ['san-inner-garbage', leafEd(49, [bcExt(false), kuExt(0x80, 7), ext('551d11', false, Buffer.from([0x30, 0x05, 0x86, 0x09, 0x41]))])],
  ['bc-bool-false-explicit', leafEd(50, [ext('551d13', true, seq(tlv(1, Buffer.from([0x00])))), kuExt(0x80, 7), sanExt([ID_ED])])],
  ['bc-bool-nonff', leafEd(51, [ext('551d13', true, seq(tlv(1, Buffer.from([0x01])))), kuExt(0x80, 7), sanExt([ID_ED])])],
  ['bc-absent', leafEd(52, [kuExt(0x80, 7), sanExt([ID_ED])])],
];
for (const [n, der] of builtCases) {
  await o.run('parseX509Svid', `built-${n}`, parseW, [toPem(der)]);
  await o.run('verifyX509Svid', `built-${n}`, verifyX509, [[toPem(der)], { trustDomain: 'example.org', roots: [ED_ROOT], nowMs: NOW_MS }]);
}
const T0DER = leafEd(60, leafExts([ID_ED]));
for (const [i, d] of [T0DER.subarray(0, T0DER.length - 1), T0DER.subarray(0, 10), Buffer.concat([T0DER, Buffer.from([0])]), Buffer.from([0x30, 0x00]), Buffer.from([0x30, 0x84, 0, 0, 0, 0]), Buffer.from([0x31, 0x00])].entries()) {
  await o.run('parseX509Svid', `der-mut${i}`, parseW, [{ $bytes: b64u(d) }]);
}

// ---- verifyX509Svid ----------------------------------------------------------------------------------------------------------------
const BASE = { trustDomain: 'example.org', roots: [pem('root')], nowMs: NOW_MS };
const G = pem;
const chains: Array<[string, any, any?]> = [
  ['leaf+inter0', [G('leaf'), G('inter0')]], ['leaf only', [G('leaf')]], ['leaf-direct', [G('leaf-direct')]], ['leaf-direct+root', [G('leaf-direct'), G('root')]],
  ['leaf+inter0+root', [G('leaf'), G('inter0'), G('root')]], ['via-chain', [G('leaf-via-chain'), G('inter-under-inter0'), G('inter0')]], ['via-chain+inter0 missing', [G('leaf-via-chain'), G('inter-under-inter0')]],
  ['leaf-noks', [G('leaf-noks'), G('inter-noks')]], ['leaf-notca', [G('leaf-notca'), G('inter-notca')]], ['leaf-expired', [G('leaf-expired'), G('inter0')]],
  ['string pem', G('leaf') + G('inter0')], ['string leaf only', G('leaf')], ['string junk around', 'x\n' + G('leaf') + 'y\n' + G('inter0') + 'z'], ['der items', [derOf(G('leaf')), derOf(G('inter0'))]],
  ['mixed der pem', [G('leaf'), derOf(G('inter0'))]], ['pem inside bytes', [{ $bytes: Buffer.from(G('leaf')).toString('base64url') }, G('inter0')]], ['multi in one item', [G('leaf') + G('inter0')]],
  ['wrong order', [G('inter0'), G('leaf')]], ['duplicate leaf', [G('leaf'), G('leaf')]], ['leaf as own anchor', [G('leaf-direct')], { roots: [G('leaf-direct')] }], ['inter as leaf', [G('inter0')]],
  ['other root', [G('leaf'), G('inter0')], { roots: [G('other-root')] }], ['two roots', [G('leaf'), G('inter0')], { roots: [G('other-root'), G('root')] }], ['bundle string two certs', [G('leaf'), G('inter0')], { roots: [G('other-root') + G('root')] }],
  ['roots der', [G('leaf'), G('inter0')], { roots: [derOf(G('root'))] }], ['roots empty', [G('leaf'), G('inter0')], { roots: [] }], ['roots garbage', [G('leaf'), G('inter0')], { roots: ['nope'] }], ['roots no pem', [G('leaf'), G('inter0')], { roots: [''] }],
  ['wrong trust domain', [G('leaf'), G('inter0')], { trustDomain: 'other.org' }], ['other-td leaf', [G('leaf-other-td'), G('inter0')]], ['no trust domain', [G('leaf'), G('inter0')], { trustDomain: undefined }],
  ['maxChain 1', [G('leaf'), G('inter0')], { maxChainLength: 1 }], ['maxChain 2', [G('leaf'), G('inter0')], { maxChainLength: 2 }], ['maxChain 0', [G('leaf')], { maxChainLength: 0 }],
  ['empty chain', []], ['empty string', ''], ['garbage', ['nope']], ['null item', [null]], ['number item', [5]], ['null chain', null], ['number chain', 5], ['object chain', {}],
  ['two-uri', [G('leaf-two-uri'), G('inter0')]], ['dns-only', [G('leaf-dns-only'), G('inter0')]], ['root-path', [G('leaf-root-path'), G('inter0')]], ['unknown-critical', [G('leaf-unknown-critical'), G('inter0')]],
  ['is-ca', [G('leaf-is-ca'), G('inter0')]], ['cert-sign', [G('leaf-cert-sign'), G('inter0')]], ['crl-sign', [G('leaf-crl-sign'), G('inter0')]], ['no-digital-signature', [G('leaf-no-digital-signature'), G('inter0')]],
  ['no-key-usage', [G('leaf-no-key-usage'), G('inter0')]], ['leaf signed by other', [G('leaf'), G('inter')]], ['inter under wrong', [G('leaf'), G('inter0'), G('inter')]],
  ['ed leaf', [LEAF_ED], { roots: [ED_ROOT] }], ['ed leaf+root', [LEAF_ED, ED_ROOT], { roots: [ED_ROOT] }], ['ed leaf wrong root', [LEAF_ED], { roots: [EC_ROOT] }], ['ed leaf bundle', [LEAF_ED], { roots: [EC_ROOT, ED_ROOT] }],
  ['ec leaf', [LEAF_EC], { roots: [ED_ROOT] }], ['ec leaf by ec root', [LEAF_EC_BY_EC], { roots: [EC_ROOT] }], ['ec leaf by ec root wrong', [LEAF_EC_BY_EC], { roots: [ED_ROOT] }],
];
for (const [n, c, ov] of chains) {
  const vo = { ...BASE, ...(ov ?? {}) };
  await o.run('verifyX509Svid', n, verifyX509, [c, vo]);
}
const GOOD = [G('leaf'), G('inter0')];
for (const [n, t] of [['at NB', T('2026-10-01T00:00:00Z')], ['before NB', T('2026-09-30T23:59:59Z')], ['after NB', T('2026-10-01T00:00:01Z')], ['at NA', T('2036-10-01T00:00:00Z')],
  ['after NA', T('2036-10-01T00:00:01Z')], ['2021', T('2021-01-01T00:00:00Z')], ['epoch', 0]] as Array<[string, number]>) {
  await o.run('verifyX509Svid', `time ${n}`, verifyX509, [GOOD, { ...BASE, nowMs: t }]);
  await o.run('verifyX509Svid', `time expired ${n}`, verifyX509, [[G('leaf-expired'), G('inter0')], { ...BASE, nowMs: t }]);
}
for (const mode of [null, 'false', 'true', 'at:0', 'at:1', 'at:2', 'throw', 'nonbool']) {
  await o.run('verifyX509Svid', `revocation ${mode}`, verifyX509, [GOOD, { ...BASE, revocation: mode }]);
  await o.run('verifyX509Svid', `revocation ${mode} direct`, verifyX509, [[G('leaf-direct')], { ...BASE, revocation: mode }]);
  await o.run('verifyX509Svid', `revocation ${mode} 3`, verifyX509, [[G('leaf'), G('inter0'), G('root')], { ...BASE, revocation: mode }]);
  await o.run('verifyX509Svid', `revocation ${mode} bad chain`, verifyX509, [[G('leaf')], { ...BASE, revocation: mode }]);
}
await o.run('verifyX509Svid', 'revocation ed built', verifyX509, [[LEAF_ED], { trustDomain: 'example.org', roots: [ED_ROOT], nowMs: NOW_MS, revocation: 'false' }]);

// ---- JWT-SVID ----------------------------------------------------------------------------------------------------------------------
const K256 = seed('ref-spiffe/jwt-es256');
const K256B = seed('ref-spiffe/jwt-es256-other');
const K384 = new Uint8Array([...seed('ref-spiffe/jwt-es384'), ...seed('ref-spiffe/jwt-es384b')].slice(0, 48));
const jwkP256 = (s: Uint8Array, kid?: string, extra: any = {}) => { const pub = p256.getPublicKey(s, false); return { kty: 'EC', crv: 'P-256', x: b64u(pub.slice(1, 33)), y: b64u(pub.slice(33)), ...(kid ? { kid } : {}), ...extra }; };
const jwkP384 = (s: Uint8Array, kid?: string, extra: any = {}) => { const pub = p384.getPublicKey(s, false); return { kty: 'EC', crv: 'P-384', x: b64u(pub.slice(1, 49)), y: b64u(pub.slice(49)), ...(kid ? { kid } : {}), ...extra }; };
const J256 = jwkP256(K256, 'k256');
const J256B = jwkP256(K256B, 'k256b');
const J384 = jwkP384(K384, 'k384');
const sig256 = (s: Uint8Array) => (d: Uint8Array) => p256.sign(sha256(d), s).toCompactRawBytes();
const sig384 = (s: Uint8Array) => (d: Uint8Array) => p384.sign(sha384(d), s).toCompactRawBytes();
const jws = (h: any, p: any, sign: (d: Uint8Array) => Uint8Array) => { const a = typeof h === 'string' ? h : b64u(JSON.stringify(h)); const b = typeof p === 'string' ? p : b64u(JSON.stringify(p)); return `${a}.${b}.${b64u(sign(Buffer.from(`${a}.${b}`)))}`; };
const NOW = 1_800_000_000;
const AUD = 'https://rs.example.com';
const PAY: any = { sub: ID, aud: AUD, exp: NOW + 3600, iat: NOW };
const HDR: any = { alg: 'ES256', typ: 'JWT', kid: 'k256' };
const tok = (p: any = PAY, h: any = HDR, s = K256) => jws(h, p, sig256(s));
const JO = { audience: AUD, key: { jwk: J256 }, trustDomain: 'example.org', currentSec: NOW + 60 };
const without = (p: any, k: string) => { const r = { ...p }; delete r[k]; return r; };
const tokCases: Array<[string, any, any?]> = [
  ['valid', tok()], ['valid jwks', tok(), { key: { jwks: { keys: [J256, J256B] } } }], ['valid jwks no kid', tok(PAY, { alg: 'ES256' }), { key: { jwks: { keys: [J256] } } }],
  ['jwks kid mismatch', tok(PAY, { alg: 'ES256', kid: 'nope' }), { key: { jwks: { keys: [J256] } } }], ['jwks wrong key kid', tok(PAY, { alg: 'ES256', kid: 'k256b' }), { key: { jwks: { keys: [J256, J256B] } } }],
  ['jwks two no kid', tok(PAY, { alg: 'ES256' }), { key: { jwks: { keys: [J256B, J256] } } }], ['jwks none verify', tok(PAY, { alg: 'ES256' }), { key: { jwks: { keys: [J256B] } } }],
  ['jwks use enc', tok(), { key: { jwks: { keys: [{ ...J256, use: 'enc' }] } } }], ['jwks use sig', tok(), { key: { jwks: { keys: [{ ...J256, use: 'sig' }] } } }], ['jwks alg ES384', tok(), { key: { jwks: { keys: [{ ...J256, alg: 'ES384' }] } } }],
  ['jwks alg ES256', tok(), { key: { jwks: { keys: [{ ...J256, alg: 'ES256' }] } } }], ['jwks key_ops sign', tok(), { key: { jwks: { keys: [{ ...J256, key_ops: ['sign'] }] } } }], ['jwks key_ops verify', tok(), { key: { jwks: { keys: [{ ...J256, key_ops: ['verify'] }] } } }],
  ['jwks empty', tok(), { key: { jwks: { keys: [] } } }], ['jwks rsa only', tok(), { key: { jwks: { keys: [{ kty: 'RSA', n: 'AQAB', e: 'AQAB', kid: 'k256' }] } } }],
  ['es384', jws({ alg: 'ES384', typ: 'JWT' }, PAY, sig384(K384)), { key: { jwk: J384 } }], ['es384 wrong curve key', jws({ alg: 'ES384', typ: 'JWT' }, PAY, sig384(K384)), { key: { jwk: J256 } }],
  ['es256 with p384 key', tok(), { key: { jwk: J384 } }], ['wrong key', tok(PAY, HDR, K256B)], ['other key', tok(), { key: { jwk: J256B } }],
  ['aud array', tok({ ...PAY, aud: [AUD, 'other'] })], ['aud array miss', tok({ ...PAY, aud: ['a', 'b'] })], ['aud mismatch', tok({ ...PAY, aud: 'other' })], ['aud missing', tok(without(PAY, 'aud'))],
  ['aud number', tok({ ...PAY, aud: 5 })], ['aud empty array', tok({ ...PAY, aud: [] })], ['opt aud array', tok(), { audience: [AUD, 'x'] }], ['opt aud array miss', tok(), { audience: ['x', 'y'] }],
  ['opt aud empty str', tok(), { audience: '' }], ['opt aud empty array', tok(), { audience: [] }], ['opt aud array with empty', tok(), { audience: [AUD, ''] }], ['opt aud null', tok(), { audience: null }],
  ['opt aud number', tok(), { audience: 5 }], ['opt aud missing', tok(), { audience: undefined }],
  ['expired', tok({ ...PAY, exp: NOW + 30 })], ['exp == now', tok({ ...PAY, exp: NOW + 60 })], ['exp now+1', tok({ ...PAY, exp: NOW + 61 })], ['exp missing', tok(without(PAY, 'exp'))], ['exp string', tok({ ...PAY, exp: '9999999999' })],
  ['exp float', tok({ ...PAY, exp: NOW + 3600.5 })], ['exp null', tok({ ...PAY, exp: null })], ['exp bool', tok({ ...PAY, exp: true })],
  ['nbf future', tok({ ...PAY, nbf: NOW + 120 })], ['nbf now', tok({ ...PAY, nbf: NOW + 60 })], ['nbf string', tok({ ...PAY, nbf: 'x' })], ['iat string', tok({ ...PAY, iat: 'x' })],
  ['tolerance 30', tok({ ...PAY, exp: NOW + 30 }), { clockTolerance: 30 }], ['tolerance 31', tok({ ...PAY, exp: NOW + 30 }), { clockTolerance: 31 }], ['tolerance "30s"', tok({ ...PAY, exp: NOW + 30 }), { clockTolerance: '30s' }],
  ['tolerance "31s"', tok({ ...PAY, exp: NOW + 30 }), { clockTolerance: '31s' }], ['tolerance "1 minute"', tok({ ...PAY, exp: NOW + 30 }), { clockTolerance: '1 minute' }], ['tolerance "1h"', tok({ ...PAY, exp: NOW - 3000 }), { clockTolerance: '1h' }],
  ['tolerance nbf', tok({ ...PAY, nbf: NOW + 120 }), { clockTolerance: 60 }], ['tolerance junk', tok(), { clockTolerance: 'abc' }], ['tolerance bool', tok(), { clockTolerance: true }],
  ['sub missing', tok(without(PAY, 'sub'))], ['sub number', tok({ ...PAY, sub: 5 })], ['sub invalid', tok({ ...PAY, sub: 'spiffe://Example.org/x' })], ['sub https', tok({ ...PAY, sub: 'https://example.org/x' })],
  ['sub other td', tok({ ...PAY, sub: 'spiffe://other.org/x' })], ['sub bare td', tok({ ...PAY, sub: 'spiffe://example.org' })], ['sub empty', tok({ ...PAY, sub: '' })],
  ['typ JOSE', tok(PAY, { ...HDR, typ: 'JOSE' })], ['typ none', tok(PAY, { alg: 'ES256', kid: 'k256' })], ['typ at+jwt', tok(PAY, { ...HDR, typ: 'at+jwt' })], ['typ lower jwt', tok(PAY, { ...HDR, typ: 'jwt' })],
  ['typ null', tok(PAY, { ...HDR, typ: null })], ['typ number', tok(PAY, { ...HDR, typ: 5 })], ['typ empty', tok(PAY, { ...HDR, typ: '' })],
  ['alg none', jws({ alg: 'none', typ: 'JWT' }, PAY, () => new Uint8Array(0))], ['alg HS256', jws({ alg: 'HS256', typ: 'JWT' }, PAY, () => new Uint8Array(32))], ['alg missing', jws({ typ: 'JWT' }, PAY, sig256(K256))],
  ['alg number', jws({ alg: 5, typ: 'JWT' }, PAY, sig256(K256))], ['alg ES512', jws({ alg: 'ES512', typ: 'JWT' }, PAY, sig256(K256))], ['alg RS256 on ec key', jws({ alg: 'RS256', typ: 'JWT' }, PAY, sig256(K256))],
  ['alg EdDSA', jws({ alg: 'EdDSA', typ: 'JWT' }, PAY, sig256(K256))], ['alg lower', jws({ alg: 'es256', typ: 'JWT' }, PAY, sig256(K256))],
  ['crit unknown', tok(PAY, { ...HDR, crit: ['x'], x: 1 })], ['crit empty', tok(PAY, { ...HDR, crit: [] })], ['crit b64 false', tok(PAY, { ...HDR, crit: ['b64'], b64: false })], ['crit b64 true', tok(PAY, { ...HDR, crit: ['b64'], b64: true })],
  ['algorithms ES256 only', tok(), { algorithms: ['ES256'] }], ['algorithms ES384 only', tok(), { algorithms: ['ES384'] }], ['algorithms none', tok(), { algorithms: ['none'] }], ['algorithms HS256', tok(), { algorithms: ['ES256', 'HS256'] }],
  ['algorithms hs384 lower', tok(), { algorithms: ['hs384'] }], ['algorithms empty', tok(), { algorithms: [] }], ['algorithms Hxx', tok(), { algorithms: ['ES256', 'HS'] }], ['algorithms RS256', tok(), { algorithms: ['RS256'] }],
  ['algorithms number', tok(), { algorithms: [5] }], ['algorithms string', tok(), { algorithms: 'ES256' }],
  ['trust domain missing', tok(), { trustDomain: undefined }], ['trust domain empty', tok(), { trustDomain: '' }], ['trust domain number', tok(), { trustDomain: 5 }], ['trust domain mismatch', tok(), { trustDomain: 'other.org' }],
  ['no key', tok(), { key: null }],
  ['not canonical padding', tok() + '='], ['two segments', tok().split('.').slice(0, 2).join('.')], ['four segments', tok() + '.x'], ['empty', ''], ['not a string', null], ['number', 5], ['spaces', ' ' + tok()],
  ['sig flipped', (() => { const t = tok(); return t.slice(0, -2) + (t.endsWith('A') ? 'B' : 'A') + t.slice(-1); })()], ['sig short', (() => { const t = tok(); return t.slice(0, -4); })()],
  ['payload tampered', (() => { const [h, , s] = tok().split('.'); return `${h}.${b64u(JSON.stringify({ ...PAY, sub: 'spiffe://example.org/evil' }))}.${s}`; })()],
  ['payload array', jws(HDR, '[]', sig256(K256))], ['payload not json', jws(HDR, b64u('nope'), sig256(K256))], ['header array', jws(b64u('[]'), PAY, sig256(K256))], ['dup keys payload', jws(HDR, b64u('{"sub":"spiffe://example.org/a","sub":"spiffe://example.org/b","aud":"' + AUD + '","exp":' + (NOW + 3600) + '}'), sig256(K256))],
  ['jti', tok({ ...PAY, jti: 'j-1' })], ['jti number', tok({ ...PAY, jti: 5 })],
];
for (const [n, t, ov] of tokCases) await o.run('verifyJwtSvid', n, verifyJwt, [t, { ...JO, ...(ov ?? {}) }]);
for (const mode of [null, 'false', 'true', 'throw', 'nonbool']) {
  await o.run('verifyJwtSvid', `revocation ${mode}`, verifyJwt, [tok({ ...PAY, jti: 'j-9' }), { ...JO, revocation: mode }]);
  await o.run('verifyJwtSvid', `revocation ${mode} no jti`, verifyJwt, [tok(), { ...JO, revocation: mode }]);
  await o.run('verifyJwtSvid', `revocation ${mode} bad token`, verifyJwt, [tok(PAY, HDR, K256B), { ...JO, revocation: mode }]);
}

// ---- svidToHolder and friends -----------------------------------------------------------------------------------------------------
const HOLDER_SEED = seed('ref-spiffe/holder');
const HOLDER = b64u(ed25519.getPublicKey(HOLDER_SEED));
const HOLDER2 = b64u(ed25519.getPublicKey(seed('ref-spiffe/holder2')));
const LEAF_ED_PUB = b64u(ed25519.getPublicKey(LEAF_ED_SEED));
const msgOf = (id: string, h: string) => Buffer.from(M.holderBindingMessage(id, h));
const proofEd = (id: string, h: string) => b64u(ed25519.sign(msgOf(id, h), LEAF_ED_SEED));
const proofEc = (id: string, h: string) => b64u(p256.sign(sha256(msgOf(id, h)), LEAF_EC_SEED).toCompactRawBytes());
const flip = (s: string) => s.slice(0, 4) + (s[4] === 'A' ? 'B' : 'A') + s.slice(5);
const VO_ED = { trustDomain: 'example.org', roots: [ED_ROOT], nowMs: NOW_MS };
const holderKeys: any[] = [null, HOLDER, { $bytes: b64u(ed25519.getPublicKey(HOLDER_SEED)) }, LEAF_ED_PUB, { $bytes: LEAF_ED_PUB }, '', 'short', HOLDER + '=', HOLDER.slice(0, -1), { $bytes: b64u(new Uint8Array(31)) }, { $bytes: b64u(new Uint8Array(33)) }, 5, [], true, flip(HOLDER)];
const x509W = (chain: any, vo: any, h: any, b: any) => holderOut(M.svidToHolder(x509Verified(chain, vo), hk(h), bindOf(b) ?? {}));
const jwtW = async (t: any, vo: any, h: any, b: any) => holderOut(M.svidToHolder(await jwtVerified(t, vo), hk(h), bindOf(b) ?? {}));
for (const [i, h] of holderKeys.entries()) {
  await o.run('svidToHolderX509', `ed leaf key${i}`, x509W, [[LEAF_ED], VO_ED, h, null]);
  await o.run('svidToHolderX509', `ed leaf key${i} proof`, x509W, [[LEAF_ED], VO_ED, h, { proof: proofEd(ID_ED, typeof h === 'string' ? h : HOLDER) }]);
  await o.run('svidToHolderX509', `ec leaf key${i}`, x509W, [[LEAF_EC], VO_ED, h, null]);
}
for (const [n, b] of [['good', { proof: proofEc(ID_EC, HOLDER) }], ['wrong holder', { proof: proofEc(ID_EC, HOLDER2) }], ['wrong id', { proof: proofEc(ID_ED, HOLDER) }], ['flipped', { proof: flip(proofEc(ID_EC, HOLDER)) }],
  ['ed proof', { proof: proofEd(ID_EC, HOLDER) }], ['short', { proof: b64u(new Uint8Array(63)) }], ['long', { proof: b64u(new Uint8Array(65)) }], ['zeros', { proof: b64u(new Uint8Array(64)) }], ['not b64u', { proof: '***' }],
  ['padded', { proof: proofEc(ID_EC, HOLDER) + '=' }], ['empty', { proof: '' }], ['number', { proof: 5 }], ['null', { proof: null }], ['none', {}], ['accept unbound', { acceptUnboundJwtHolder: true }]] as Array<[string, any]>) {
  await o.run('svidToHolderX509', `ec proof ${n}`, x509W, [[LEAF_EC], VO_ED, HOLDER, b]);
  await o.run('svidToHolderX509', `ec by ec root proof ${n}`, x509W, [[LEAF_EC_BY_EC], { trustDomain: 'example.org', roots: [EC_ROOT], nowMs: NOW_MS }, HOLDER, b]);
}
for (const [n, b] of [['good', { proof: proofEd(ID_ED, HOLDER) }], ['wrong holder', { proof: proofEd(ID_ED, HOLDER2) }], ['ec proof', { proof: proofEc(ID_ED, HOLDER) }], ['flipped', { proof: flip(proofEd(ID_ED, HOLDER)) }]] as Array<[string, any]>) {
  await o.run('svidToHolderX509', `ed proof ${n}`, x509W, [[LEAF_ED], VO_ED, HOLDER, b]);
}
// a fixture chain whose key is P-256 and whose private key is gone: the proof can never verify, the refusal path still runs
await o.run('svidToHolderX509', 'fixture leaf no proof', x509W, [GOOD, BASE, HOLDER, null]);
await o.run('svidToHolderX509', 'fixture leaf no key', x509W, [GOOD, BASE, null, null]);
await o.run('svidToHolderX509', 'fixture leaf junk proof', x509W, [GOOD, BASE, HOLDER, { proof: b64u(new Uint8Array(64).fill(1)) }]);
await o.run('svidToHolderX509', 'unverified chain', x509W, [[LEAF_ED], { ...VO_ED, trustDomain: 'other.org' }, HOLDER, null]);
const cnfOf = (x: string) => ({ jwk: { kty: 'OKP', crv: 'Ed25519', x } });
const jwtBinds: Array<[string, any, any, any]> = [
  ['cnf match', { ...PAY, cnf: cnfOf(HOLDER) }, HOLDER, null], ['cnf match bytes', { ...PAY, cnf: cnfOf(HOLDER) }, { $bytes: b64u(ed25519.getPublicKey(HOLDER_SEED)) }, null], ['cnf mismatch', { ...PAY, cnf: cnfOf(HOLDER2) }, HOLDER, null],
  ['no cnf', PAY, HOLDER, null], ['no cnf unbound ok', PAY, HOLDER, { acceptUnboundJwtHolder: true }], ['no cnf unbound false', PAY, HOLDER, { acceptUnboundJwtHolder: false }], ['no cnf unbound truthy', PAY, HOLDER, { acceptUnboundJwtHolder: 1 }],
  ['no holder', PAY, null, null], ['no holder cnf', { ...PAY, cnf: cnfOf(HOLDER) }, null, null], ['bad holder', PAY, 'xx', { acceptUnboundJwtHolder: true }], ['cnf wrong crv', { ...PAY, cnf: { jwk: { kty: 'OKP', crv: 'Ed448', x: HOLDER } } }, HOLDER, null],
  ['cnf wrong kty', { ...PAY, cnf: { jwk: { kty: 'EC', crv: 'Ed25519', x: HOLDER } } }, HOLDER, null], ['cnf x number', { ...PAY, cnf: { jwk: { kty: 'OKP', crv: 'Ed25519', x: 5 } } }, HOLDER, null], ['cnf string', { ...PAY, cnf: 'x' }, HOLDER, null],
  ['cnf null', { ...PAY, cnf: null }, HOLDER, null], ['cnf jwk null', { ...PAY, cnf: { jwk: null } }, HOLDER, null], ['cnf array', { ...PAY, cnf: [] }, HOLDER, null], ['cnf unpadded other spelling', { ...PAY, cnf: cnfOf(HOLDER + '=') }, HOLDER, null],
];
for (const [n, p, h, b] of jwtBinds) await o.run('svidToHolderJwt', n, jwtW, [tok(p), JO, h, b]);
for (const [i, [kind, p]] of ([['string', null], ['object', null], ['null', null], ['number', null], ['parsed', G('leaf-direct')], ['parsed built', LEAF_ED], ['parsed jwt-like', null]] as Array<[string, any]>).entries()) {
  await o.run('svidToHolderUnverified', `u${i}-${kind}`, (k: string, c: any) => {
    const v: any = k === 'string' ? ID : k === 'object' ? { spiffeId: M.parseSpiffeId(ID), certificate: {}, publicKeyDer: 'x' } : k === 'null' ? null : k === 'number' ? 5 : k === 'parsed jwt-like' ? { spiffeId: M.parseSpiffeId(ID), claims: {}, audience: [], expiresAt: 1 } : M.parseX509Svid(c);
    return holderOut(M.svidToHolder(v, HOLDER, {}));
  }, [kind, p]);
}
const idForW = (chain: any, vo: any, h: any, b: any) => M.spiffeIdForHolder(x509Verified(chain, vo), h, bindOf(b) ?? {});
for (const [n, h, b] of [['own key', LEAF_ED_PUB, null], ['other key', HOLDER, null], ['other key proof', HOLDER, { proof: proofEd(ID_ED, HOLDER) }], ['other key bad proof', HOLDER, { proof: proofEd(ID_ED, HOLDER2) }], ['junk', 'xx', null]] as Array<[string, any, any]>) {
  await o.run('spiffeIdForHolder', n, idForW, [[LEAF_ED], VO_ED, h, b]);
}
await o.run('spiffeIdForHolder', 'ec proof', idForW, [[LEAF_EC], VO_ED, HOLDER, { proof: proofEc(ID_EC, HOLDER) }]);
await o.run('spiffeIdForHolder', 'ec no proof', idForW, [[LEAF_EC], VO_ED, HOLDER, null]);
const pinW = (label: any, chain: any, vo: any) => M.workloadDischargePin(label, x509Verified(chain, vo));
await o.run('workloadDischargePin', 'ed', pinW, ['runtime', [LEAF_ED], VO_ED]);
await o.run('workloadDischargePin', 'ed empty label', pinW, ['', [LEAF_ED], VO_ED]);
await o.run('workloadDischargePin', 'ec refused', pinW, ['runtime', [LEAF_EC], VO_ED]);
await o.run('workloadDischargePin', 'fixture refused', pinW, ['runtime', GOOD, BASE]);
await o.run('workloadDischargePin', 'unverified', pinW, ['runtime', [LEAF_ED], { ...VO_ED, trustDomain: 'x.org' }]);
for (const [i, h] of ([{ spiffeId: ID }, { spiffeId: 'spiffe://Example.org/x' }, { spiffeId: 'nope' }, { spiffeId: '' }, {}, { spiffeId: 5 }, { spiffeId: 'spiffe://example.org' }]).entries()) {
  await o.run('holderToSpiffeId', `h${i}`, M.holderToSpiffeId, [h]);
}
for (const [i, [a, b]] of ([[ID, HOLDER], ['', ''], ['spiffe://é/x', 'h'], ['a\nb', 'c\nd'], ['\ud800', 'x'], [ID, '\ud800']] as Array<[string, string]>).entries()) {
  await o.run('holderBindingMessage', `m${i}`, M.holderBindingMessage, [a, b]);
}
const admW = async (e: any, key: any) => {
  const calls: any[] = [];
  const ee: any = e.kind === 'x509' ? { kind: 'x509', chain: Array.isArray(e.chain) ? e.chain.map(rev) : e.chain, verify: xo(e.verify, calls) } : { kind: 'jwt', token: e.token, verify: await jo(e.verify, calls) };
  if (e.bind !== undefined) ee.bind = e.bind;
  return M.spiffeAdmissionEvidence(ee, key);
};
const adm: Array<[string, any, any]> = [
  ['x509 own key', { kind: 'x509', chain: [LEAF_ED], verify: VO_ED }, LEAF_ED_PUB], ['x509 other key', { kind: 'x509', chain: [LEAF_ED], verify: VO_ED }, HOLDER],
  ['x509 other key proof', { kind: 'x509', chain: [LEAF_ED], verify: VO_ED, bind: { proof: proofEd(ID_ED, HOLDER) } }, HOLDER], ['x509 ec proof', { kind: 'x509', chain: [LEAF_EC], verify: VO_ED, bind: { proof: proofEc(ID_EC, HOLDER) } }, HOLDER],
  ['x509 ec no proof', { kind: 'x509', chain: [LEAF_EC], verify: VO_ED }, HOLDER], ['x509 bad chain', { kind: 'x509', chain: ['nope'], verify: VO_ED }, HOLDER], ['x509 untrusted', { kind: 'x509', chain: [LEAF_ED], verify: { ...VO_ED, roots: [EC_ROOT] } }, HOLDER],
  ['x509 revoked', { kind: 'x509', chain: [LEAF_ED], verify: { ...VO_ED, revocation: 'true' } }, LEAF_ED_PUB], ['x509 bad key', { kind: 'x509', chain: [LEAF_ED], verify: VO_ED }, 'xx'],
  ['jwt bound', { kind: 'jwt', token: tok({ ...PAY, cnf: cnfOf(HOLDER) }), verify: JO }, HOLDER], ['jwt unbound', { kind: 'jwt', token: tok(), verify: JO }, HOLDER], ['jwt unbound accepted', { kind: 'jwt', token: tok(), verify: JO, bind: { acceptUnboundJwtHolder: true } }, HOLDER],
  ['jwt expired', { kind: 'jwt', token: tok({ ...PAY, exp: NOW + 30 }), verify: JO, bind: { acceptUnboundJwtHolder: true } }, HOLDER], ['jwt bad sig', { kind: 'jwt', token: tok(PAY, HDR, K256B), verify: JO, bind: { acceptUnboundJwtHolder: true } }, HOLDER],
  ['jwt wrong aud', { kind: 'jwt', token: tok(), verify: { ...JO, audience: 'x' }, bind: { acceptUnboundJwtHolder: true } }, HOLDER], ['jwt malformed', { kind: 'jwt', token: 'x', verify: JO }, HOLDER], ['jwt revoked', { kind: 'jwt', token: tok(), verify: { ...JO, revocation: 'true' }, bind: { acceptUnboundJwtHolder: true } }, HOLDER],
];
for (const [n, e, k] of adm) await o.run('spiffeAdmissionEvidence', n, admW, [e, k]);

// ---- trust-bundle and revocation caches -----------------------------------------------------------------------------------------------
const tbScenario = async (opts: any, steps: any[]) => {
  let t = 0, cur: any, fetches = 0;
  let src: any;
  try {
    src = M.createTrustBundleSource({ fetch: async () => { fetches++; if (cur?.$throw) throw new Error(cur.$throw); if (cur?.$spiffe) throw new M.SpiffeError(cur.$spiffe, 'x'); return cur; }, ...opts, now: () => t });
  } catch (e: any) { return { ctor: e.code ?? null }; }
  const out: any[] = [];
  for (const s of steps) {
    t = s.at; cur = s.fetch; fetches = 0;
    try {
      if (s.op === 'x509Roots') out.push({ ok: await src.x509Roots(), fetches });
      else { await src.jwtKey(s.header ?? { alg: 'ES256' }, 'tok'); out.push({ ok: 'key', fetches }); }
    } catch (e: any) { out.push({ code: e.code ?? null, fetches }); }
  }
  return { steps: out };
};
const BX = { x509Authorities: [pem('root')] };
const BX2 = { x509Authorities: [pem('other-root'), pem('root')] };
const BJ = { jwks: { keys: [J256] } };
const BJX = { jwks: { keys: [J256] }, x509Authorities: [pem('root')] };
const W = { refreshMs: 1000, maxStaleMs: 5000 };
const x = (at: number, fetch: any, op = 'x509Roots', header?: any) => ({ at, fetch, op, ...(header ? { header } : {}) });
const tbScripts: Array<[string, any, any[]]> = [
  ['first fetch ok', W, [x(0, BX)]], ['cached within refresh', W, [x(0, BX), x(999, BX2), x(1000, BX2)]], ['refresh replaces', W, [x(0, BX2), x(1000, BX)]],
  ['refresh fails keeps good', W, [x(0, BX), x(1000, { $throw: 'down' }), x(5000, { $throw: 'down' }), x(5001, { $throw: 'down' })]], ['stale boundary', W, [x(0, BX), x(5000, { $throw: 'd' }), x(5001, { $throw: 'd' })]],
  ['no first success', W, [x(0, { $throw: 'down' }), x(1, BX)]], ['spiffe error', W, [x(0, { $spiffe: 'trust_bundle_invalid' })]], ['empty bundle', W, [x(0, {})]], ['null bundle', W, [x(0, null)]], ['missing bundle', W, [x(0, undefined)]],
  ['bundle array', W, [x(0, [])]], ['bundle string', W, [x(0, 'x')]], ['empty authorities', W, [x(0, { x509Authorities: [] })]], ['empty jwks', W, [x(0, { jwks: { keys: [] } })]], ['jwks no keys', W, [x(0, { jwks: {} })]],
  ['recover', W, [x(0, { $throw: 'd' }), x(0, BX)]], ['invalid then good', W, [x(0, {}), x(1500, BX)]], ['jwt only bundle x509', W, [x(0, BJ)]], ['x509 only bundle jwt', W, [x(0, BX, 'jwtKey')]],
  ['jwt kid hit', W, [x(0, BJX, 'jwtKey', { alg: 'ES256', kid: 'k256' })]], ['jwt kid miss', W, [x(0, BJX, 'jwtKey', { alg: 'ES256', kid: 'zz' })]], ['jwt no kid', W, [x(0, BJX, 'jwtKey', { alg: 'ES256' })]], ['jwt bad alg', W, [x(0, BJX, 'jwtKey', { alg: 'RS256' })]],
  ['jwt then x509', W, [x(0, BJX, 'jwtKey'), x(10, BJX, 'x509Roots'), x(1200, BJX, 'jwtKey')]], ['equal windows', { refreshMs: 10, maxStaleMs: 10 }, [x(0, BX), x(10, { $throw: 'd' }), x(11, { $throw: 'd' })]],
  ['ctor zero refresh', { refreshMs: 0, maxStaleMs: 10 }, []], ['ctor negative', { refreshMs: -1, maxStaleMs: 10 }, []], ['ctor stale < refresh', { refreshMs: 10, maxStaleMs: 9 }, []], ['ctor nan', { refreshMs: null, maxStaleMs: 10 }, []],
  ['ctor string', { refreshMs: '10', maxStaleMs: 10 }, []], ['ctor missing', {}, []], ['ctor float ok', { refreshMs: 0.5, maxStaleMs: 0.5 }, [x(0, BX), x(1, BX)]],
];
for (const [n, opts, steps] of tbScripts) await o.run('trustBundleScenario', n, tbScenario, [opts, steps]);

const rvScenario = async (opts: any, steps: any[]) => {
  let t = 0, cur: any, fetches = 0;
  let src: any;
  try {
    src = M.createRevocationSource({ fetch: async () => { fetches++; if (cur?.$throw) throw new Error(cur.$throw); if (cur?.$spiffe) throw new M.SpiffeError(cur.$spiffe, 'x'); return cur; }, ...opts, now: () => t });
  } catch (e: any) { return { ctor: e.code ?? null }; }
  const out: any[] = [];
  for (const s of steps) {
    t = s.at; cur = s.fetch; fetches = 0;
    try {
      let v: any = null;
      if (s.op === 'ensureFresh') await src.ensureFresh();
      else if (s.op === 'refresh') await src.refresh();
      else if (s.op === 'x509') v = src.x509(s.subject);
      else v = await src.jwt(s.subject);
      out.push({ ok: v, fetches });
    } catch (e: any) { out.push({ code: e.code ?? null, fetches }); }
  }
  return { steps: out };
};
const SUBJ_X = { spiffeId: ID, serialNumber: '0A1B', fingerprint256: 'AA:BB:CC', position: 0, isLeaf: true };
const SUBJ_J = { spiffeId: ID, jti: 'j1', expiresAt: 1, tokenHash: 'th1' };
const r = (at: number, op: string, fetch?: any, subject?: any) => ({ at, op, fetch, ...(subject ? { subject } : {}) });
const rvScripts: Array<[string, any, any[]]> = [
  ['x509 before fetch', W, [r(0, 'x509', undefined, SUBJ_X)]], ['ensure then x509 clean', W, [r(0, 'ensureFresh', {}), r(1, 'x509', undefined, SUBJ_X)]],
  ['fingerprint', W, [r(0, 'ensureFresh', { fingerprints: ['aa:bb:cc'] }), r(1, 'x509', undefined, SUBJ_X)]], ['fingerprint no colons', W, [r(0, 'ensureFresh', { fingerprints: ['aabbcc'] }), r(1, 'x509', undefined, SUBJ_X)]],
  ['fingerprint other', W, [r(0, 'ensureFresh', { fingerprints: ['aa:bb:dd'] }), r(1, 'x509', undefined, SUBJ_X)]],
  ['serial leading zeros', W, [r(0, 'ensureFresh', { serials: ['000a1b'] }), r(1, 'x509', undefined, SUBJ_X)]], ['serial colons case', W, [r(0, 'ensureFresh', { serials: ['0a:1b'] }), r(1, 'x509', undefined, SUBJ_X)]],
  ['serial zero', W, [r(0, 'ensureFresh', { serials: ['00'] }), r(1, 'x509', undefined, { ...SUBJ_X, serialNumber: '0' })]], ['serial 0000', W, [r(0, 'ensureFresh', { serials: ['0000'] }), r(1, 'x509', undefined, { ...SUBJ_X, serialNumber: '00' })]],
  ['serial other', W, [r(0, 'ensureFresh', { serials: ['0a1c'] }), r(1, 'x509', undefined, SUBJ_X)]],
  ['spiffe id', W, [r(0, 'ensureFresh', { spiffeIds: [ID] }), r(1, 'x509', undefined, SUBJ_X), r(2, 'jwt', undefined, SUBJ_J)]], ['spiffe id other', W, [r(0, 'ensureFresh', { spiffeIds: ['spiffe://example.org/other'] }), r(1, 'x509', undefined, SUBJ_X)]],
  ['jti', W, [r(0, 'ensureFresh', { jtis: ['j1'] }), r(1, 'jwt', undefined, SUBJ_J), r(2, 'jwt', undefined, { ...SUBJ_J, jti: 'j2' }), r(3, 'jwt', undefined, { spiffeId: ID, expiresAt: 1, tokenHash: 'x' })]],
  ['token hash', W, [r(0, 'ensureFresh', { tokenHashes: ['th1'] }), r(1, 'jwt', undefined, SUBJ_J), r(2, 'jwt', undefined, { ...SUBJ_J, tokenHash: 'th2' })]], ['jwt refreshes itself', W, [r(0, 'jwt', {}, SUBJ_J), r(500, 'jwt', {}, SUBJ_J), r(1000, 'jwt', { jtis: ['j1'] }, SUBJ_J)]],
  ['jwt fetch fails', W, [r(0, 'jwt', { $throw: 'down' }, SUBJ_J)]], ['jwt stale', W, [r(0, 'jwt', {}, SUBJ_J), r(5000, 'jwt', { $throw: 'd' }, SUBJ_J), r(5001, 'jwt', { $throw: 'd' }, SUBJ_J)]],
  ['x509 uses cache past refresh', W, [r(0, 'ensureFresh', { spiffeIds: [ID] }), r(3000, 'x509', { spiffeIds: [] }, SUBJ_X), r(5000, 'x509', undefined, SUBJ_X), r(5001, 'x509', undefined, SUBJ_X)]],
  ['ensureFresh fails', W, [r(0, 'ensureFresh', { $throw: 'down' }), r(1, 'ensureFresh', {})]], ['ensureFresh keeps good', W, [r(0, 'ensureFresh', {}), r(1000, 'ensureFresh', { $throw: 'd' }), r(5001, 'ensureFresh', { $throw: 'd' })]],
  ['refresh ok', W, [r(0, 'refresh', {}), r(1, 'refresh', { fingerprints: ['aa'] })]], ['refresh fails', W, [r(0, 'refresh', { $throw: 'down' })]], ['refresh fails keeps good', W, [r(0, 'refresh', {}), r(1, 'refresh', { $throw: 'down' }), r(2, 'x509', undefined, SUBJ_X)]],
  ['refresh spiffe error', W, [r(0, 'refresh', { $spiffe: 'revocation_unavailable' })]], ['refresh replaces', W, [r(0, 'refresh', { spiffeIds: [ID] }), r(1, 'refresh', {}), r(2, 'x509', undefined, SUBJ_X)]],
  ['malformed list array', W, [r(0, 'refresh', [])]], ['malformed list null', W, [r(0, 'refresh', null)]], ['malformed list string', W, [r(0, 'refresh', 'x')]], ['malformed field string', W, [r(0, 'refresh', { fingerprints: 'aa' })]],
  ['malformed field numbers', W, [r(0, 'refresh', { serials: [1] })]], ['malformed field null', W, [r(0, 'refresh', { jtis: null })]], ['malformed field object', W, [r(0, 'refresh', { spiffeIds: {} })]],
  ['unknown field ignored', W, [r(0, 'refresh', { other: [1] }), r(1, 'x509', undefined, SUBJ_X)]], ['malformed keeps previous', W, [r(0, 'refresh', { spiffeIds: [ID] }), r(1, 'refresh', { jtis: 5 }), r(2, 'x509', undefined, SUBJ_X)]],
  ['stale boundary', W, [r(0, 'refresh', {}), r(5000, 'x509', undefined, SUBJ_X), r(5001, 'x509', undefined, SUBJ_X)]],
  ['ctor zero refresh', { refreshMs: 0, maxStaleMs: 10 }, []], ['ctor negative', { refreshMs: -1, maxStaleMs: 10 }, []], ['ctor stale < refresh', { refreshMs: 10, maxStaleMs: 9 }, []], ['ctor null', { refreshMs: null, maxStaleMs: 10 }, []],
  ['ctor string', { refreshMs: '10', maxStaleMs: 10 }, []], ['ctor missing', {}, []], ['ctor equal ok', { refreshMs: 10, maxStaleMs: 10 }, [r(0, 'refresh', {})]],
];
for (const [n, opts, steps] of rvScripts) await o.run('revocationScenario', n, rvScenario, [opts, steps]);

// ---- constants -------------------------------------------------------------------------------------------------------------------------
await o.run('constants', 'all', () => ({ jwtSvidAlgorithms: M.JWT_SVID_ALGORITHMS }), []);

refWrite(o, 'spiffe-svid');
