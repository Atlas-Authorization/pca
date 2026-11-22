// Oracle (Java lane): @atlasauth/pca-spiffe (SPIFFE ID parsing, JWT-SVID / X.509-SVID verification, SVID -> PCA holder binding, revocation and
// trust-bundle caches, blueprint-admission evidence). Writes out/ref-spiffe.json.gz.
// The certificates of the committed fixture PKI are used as they are. The holder-binding leaves (Ed25519 / P-256 / P-384 / RSA) and the
// JWT-SVID signing keys, holder-binding leaves and certificates derive from fixed seeds (deterministic ECDSA, seeded PSS salt, fixed
// certificate validity): regenerating reproduces the corpus byte for byte. Only public data, tokens and signatures are written.
//
// PORTING (fn(args) -> native entry point, comparison rule). Values are JSON; a throw requires the native to refuse and, when the
// reference carries a SpiffeError code, the same code (a failure from the JOSE layer has code "jose": any non-SpiffeError failure).
//   constants()                          -> {JWT_SVID_ALGORITHMS}
//   parseSpiffeId(s)                     -> {id, trustDomain, path}
//   holderBindingMessage(spiffeId, holder) -> bytes ({"$bytes": b64url})
//   holderToSpiffeId(holder)             -> holderToSpiffeId over {holder, spiffeId, trustDomain, path}
//   readCertFacts(derB64u)               -> the DER facts reader over the certificate bytes (b64url); malformed DER throws
//   parseX509Svid(cert)                  -> {spiffeId, publicKeyDer}; cert = PEM text or {"$bytes"} DER
//   verifyX509Svid(chain, opts)          -> {spiffeId, publicKeyDer, calls}: chain = PEM text or list of PEM / {"$bytes"}; opts = {trustDomain, roots,
//       nowMs?, maxChainLength?, revocation?: mode}; revocation modes: false | true | true@N (true only at chain position N) | throw | one (returns 1) |
//       undef (returns nothing) | promise (returns a Promise) | notfn (not a function); `calls` = the revocation subjects asked, in order
//   holderSession(spec)                  -> {holder|spiffeId|pin}: spec = {svid: x509|x509-parsed|jwt|string|parsed-id|hand-built|null, chain?, roots?, nowMs?,
//       jwt?: {token, jwk, audience, trustDomain, currentDateMs}, op: holder|forHolder|pin, holderKey?, proof?, acceptUnbound?, label?}; holderKey is text, {"$bytes"} or absent
//   jwtSession(spec)                     -> {spiffeId, claims, audience, expiresAt, calls}: spec = {token, key: {jwk} | {bundle: {jwks}}, audience, trustDomain,
//       currentDateMs?, algorithms?, clockTolerance?, revocation?: false|true|throw|one|undef|async-true|async-false|async-throw|notfn}
//   revocationSession(spec)              -> per-step results: spec = {refreshMs, maxStaleMs, start, fetches: [{list}|{throw}], steps: [{op: x509|jwt|refresh|ensureFresh|adv, ...}]}
//       (the fetch script repeats its last entry; `adv` advances the manual clock by `ms`; a step result is {v} or {code}); plus {fetchCalls}
//   bundleSession(spec)                  -> as revocationSession for a trust-bundle source: ops x509Roots | jwtKey (header) | adv; jwtKey yields {kty, crv?, x?, n?} of the chosen key
//   admission(spec)                      -> spiffeAdmissionEvidence: spec = {kind: x509|jwt, ..., instanceKey}; `reason` is the error code, or "other" for a non-SpiffeError failure
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { X509Certificate, createHash, createPrivateKey, sign as nodeSign } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { importJWK, type JWK } from 'jose';
import { p256 } from '@noble/curves/p256';
import { p384 } from '@noble/curves/p384';
import { p521 } from '@noble/curves/p521';
import * as M0 from '@atlasauth/pca-spiffe';
import * as DER0 from '../../../packages/pca-spiffe/src/der';
import * as SJ0 from '../../../packages/pca/src/strict-jws';
import { Oracle, refWrite, seed } from './lib.mjs';

// ---- deterministic key material: every key derives from seed(label) (hash counter stream); nothing is random.
const stream = (label: string, n: number): Buffer => {
  const out: Buffer[] = [];
  for (let i = 0; out.length * 32 < n; i++) out.push(createHash('sha256').update(seed(label)).update(String(i)).digest());
  return Buffer.concat(out).subarray(0, n);
};
const big = (b: Uint8Array) => BigInt('0x' + Buffer.from(b).toString('hex'));
const bigB = (x: bigint, len?: number) => { let h = x.toString(16); if (h.length % 2) h = '0' + h; const b = Buffer.from(h, 'hex'); return len ? Buffer.concat([Buffer.alloc(Math.max(0, len - b.length)), b]) : b; };
const modPow = (b: bigint, e: bigint, m: bigint) => { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; };
const egcd = (a: bigint, b: bigint): [bigint, bigint, bigint] => (b === 0n ? [a, 1n, 0n] : ((): [bigint, bigint, bigint] => { const [g, x, y] = egcd(b, a % b); return [g, y, x - (a / b) * y]; })());
const modInv = (a: bigint, m: bigint) => { const [, x] = egcd(((a % m) + m) % m, m); return ((x % m) + m) % m; };
const SMALL = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n, 43n, 47n];
const isPrime = (n: bigint, label: string): boolean => {
  for (const q of SMALL) if (n === q) return true; else if (n % q === 0n) return false;
  let d = n - 1n, r = 0; while ((d & 1n) === 0n) { d >>= 1n; r++; }
  for (let i = 0; i < 24; i++) {
    const a = 2n + (big(stream(`${label}/mr${i}`, 8)) % (n - 4n));
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    let ok = false;
    for (let j = 1; j < r; j++) { x = (x * x) % n; if (x === n - 1n) { ok = true; break; } }
    if (!ok) return false;
  }
  return true;
};
const detPrime = (label: string, bits: number): bigint => {
  for (let i = 0; ; i++) {
    const b = Buffer.from(stream(`${label}/${i}`, bits / 8)); b[0]! |= 0xc0; b[b.length - 1]! |= 1;
    const n = big(b); if (isPrime(n, `${label}/${i}`)) return n;
  }
};
type RsaKey = { n: bigint; d: bigint; jwk: JWK; priv: any; bits: number };
const detRsa = (label: string, bits = 2048): RsaKey => {
  const e = 65537n;
  for (let t = 0; ; t++) {
    const p = detPrime(`${label}/p${t}`, bits / 2), q = detPrime(`${label}/q${t}`, bits / 2);
    if (p === q) continue;
    const phi = (p - 1n) * (q - 1n);
    if (egcd(e, phi)[0] !== 1n) continue;
    const n = p * q, d = modInv(e, phi);
    const f = (x: bigint) => bigB(x).toString('base64url');
    const full: any = { kty: 'RSA', n: f(n), e: f(e), d: f(d), p: f(p), q: f(q), dp: f(d % (p - 1n)), dq: f(d % (q - 1n)), qi: f(modInv(q, p)) };
    const { d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, ...pub } = full;
    return { n, d, jwk: pub as JWK, priv: createPrivateKey({ key: full, format: 'jwk' }), bits };
  }
};
// RSASSA-PSS (RFC 8017 9.1.1) with a seeded salt, so the signature is reproducible.
const pssSign = (k: RsaKey, hash: string, msg: Uint8Array, label: string): Buffer => {
  const h = (x: Uint8Array) => createHash(hash).update(x).digest();
  const hLen = h(new Uint8Array()).length, emBits = k.bits - 1, emLen = Math.ceil(emBits / 8);
  const salt = stream(`${label}/salt`, hLen);
  const H = h(Buffer.concat([Buffer.alloc(8), h(msg), salt]));
  const DB = Buffer.concat([Buffer.alloc(emLen - hLen * 2 - 2), Buffer.from([1]), salt]);
  const mask = Buffer.concat(Array.from({ length: Math.ceil(DB.length / hLen) }, (_, c) => h(Buffer.concat([H, Buffer.from([0, 0, 0, c])])))).subarray(0, DB.length);
  const mdb = Buffer.from(DB.map((b, i) => b ^ mask[i]!)); mdb[0]! &= 0xff >> (8 * emLen - emBits);
  const em = Buffer.concat([mdb, H, Buffer.from([0xbc])]);
  return bigB(modPow(big(em), k.d, k.n), k.bits / 8);
};
const NOBLE: Record<string, any> = { P256: p256, P384: p384, P521: p521 };
type EcKey = { jwk: JWK; priv: any; d: Uint8Array; curve: string };
const detEc = (label: string, curve: 'P256' | 'P384' | 'P521'): EcKey => {
  const c = NOBLE[curve], len = curve === 'P521' ? 66 : curve === 'P384' ? 48 : 32;
  const d = bigB(1n + (big(stream(label, len + 8)) % (c.CURVE.n - 1n)), len);
  const pt = c.getPublicKey(d, false), cr = { P256: 'P-256', P384: 'P-384', P521: 'P-521' }[curve];
  const x = Buffer.from(pt.subarray(1, 1 + len)).toString('base64url'), y = Buffer.from(pt.subarray(1 + len)).toString('base64url');
  return { jwk: { kty: 'EC', crv: cr, x, y } as JWK, priv: createPrivateKey({ key: { kty: 'EC', crv: cr, x, y, d: Buffer.from(d).toString('base64url') } as any, format: 'jwk' }), d, curve };
};
const ecSign = (k: EcKey, hash: string, msg: Uint8Array): Buffer => Buffer.from(NOBLE[k.curve].sign(createHash(hash).update(msg).digest(), k.d).toCompactRawBytes());

const M: any = (M0 as any).default ?? M0;
const readCertFacts: any = ((DER0 as any).default ?? DER0).readCertFacts;
const compactJwsAliases: any = ((SJ0 as any).default ?? SJ0).compactJwsAliases;
const o = new Oracle('spiffe', 'tools/pca-audit/oracles/spiffe-java.mts', 'TS-reference oracle for the SPIFFE / SPIRE identity bridge (Java lane).');
const FIX = fileURLToPath(new URL('../../../packages/pca-spiffe/fixtures/', import.meta.url));
const gen = (n: string) => readFileSync(`${FIX}generated/${n}.pem`, 'utf8');
const gs = (n: string) => readFileSync(`${FIX}go-spiffe/${n}.pem`, 'utf8');
const pemsOf = (t: string) => t.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
const derOf = (pem: string) => new X509Certificate(pem).raw;
const bytes = (u: Uint8Array) => ({ $bytes: Buffer.from(u).toString('base64url') });
const b64u = (u: Uint8Array) => Buffer.from(u).toString('base64url');
const SUB = 'spiffe://example.org/workload/db';
const TS_ERR = (e: any): any => e && e.$tsErr ? e : Object.assign(new Error(e instanceof Error ? e.message : String(e)), { $tsErr: true, code: e && e.constructor && e.constructor.name === 'SpiffeError' ? e.code : 'jose' });

// ---- constants / parseSpiffeId / holder helpers
await o.run('constants', 'all', () => ({ JWT_SVID_ALGORITHMS: [...M.JWT_SVID_ALGORITHMS] }), []);
const TDCH = (c: string) => `spiffe://a${c}b/x`;
const PCH = (c: string) => `spiffe://example.org/a${c}b`;
const IDS: any[] = ['spiffe://example.org', 'spiffe://example.org/', 'spiffe://example.org/a/b', 'spiffe://Example.org/a', 'spiffe://example.org/a/../b', 'spiffe://example.org/a//b', 'spiffe://example.org/a b',
  'spiffe://example.org/a?x', 'spiffe://ex_am-ple.d/x.y', 'spiffe://', 'spiffe:///a', 'http://example.org/a', '', 'SPIFFE://example.org/a', 'spiffe:/example.org/a', 'spiffe://example.org/.', 'spiffe://example.org/..',
  'spiffe://example.org/a/.', 'spiffe://example.org/a/..', 'spiffe://example.org/...', 'spiffe://example.org/a.b-c_d', 'spiffe://example.org:8080/a', 'spiffe://user@example.org/a', 'spiffe://example.org/é',
  'spiffe://exámple.org/a', 'spiffe://example.org/a#f', 'spiffe://example.org/a%20b', 'spiffe://example.org/\u0000', 'spiffe://example.org/a\n', ' spiffe://example.org/a',
  `spiffe://example.org/${'a'.repeat(2030)}`, `spiffe://example.org/${'a'.repeat(2040)}`, `spiffe://${'a'.repeat(255)}/x`, `spiffe://${'a'.repeat(256)}/x`, `spiffe://${'a'.repeat(255)}`, `spiffe://${'a'.repeat(256)}`,
  'spiffe://' + 'a'.repeat(2039), 'spiffe://' + 'a'.repeat(2040), `spiffe://example.org/${'a'.repeat(2048 - 'spiffe://example.org/'.length)}`, `spiffe://example.org/${'a'.repeat(2049 - 'spiffe://example.org/'.length)}`,
  null, 5, true, [], {}, ['spiffe://example.org/a']];
for (const [i, s] of IDS.entries()) await o.run('parseSpiffeId', `i${i}`, M.parseSpiffeId, [s]);
for (let c = 0; c < 256; c++) {
  const ch = String.fromCharCode(c);
  await o.run('parseSpiffeId', `td-char-${c}`, M.parseSpiffeId, [TDCH(ch)]);
  await o.run('parseSpiffeId', `path-char-${c}`, M.parseSpiffeId, [PCH(ch)]);
}
for (const ch of ['İ', 'K', 'Ａ', '\ud800', '😀']) {
  await o.run('parseSpiffeId', `td-wide-${ch.charCodeAt(0)}`, M.parseSpiffeId, [TDCH(ch)]);
  await o.run('parseSpiffeId', `path-wide-${ch.charCodeAt(0)}`, M.parseSpiffeId, [PCH(ch)]);
}
await o.run('holderBindingMessage', 'a', M.holderBindingMessage, [SUB, 'h'.repeat(43)]);
await o.run('holderBindingMessage', 'e', M.holderBindingMessage, ['', '']);
await o.run('holderBindingMessage', 'u', M.holderBindingMessage, ['spiffe://é/x', 'ü']);
for (const [i, h] of [{ holder: 'h', spiffeId: SUB, trustDomain: 'example.org', path: '/workload/db' }, { holder: 'h', spiffeId: 'spiffe://x.org', trustDomain: 'x.org', path: '' },
  { holder: 'h', spiffeId: 'bad', trustDomain: 't', path: 'p' }, { holder: 'h', spiffeId: 'spiffe://example.org/a/', trustDomain: 'example.org', path: '/a/' }].entries()) await o.run('holderToSpiffeId', `h${i}`, M.holderToSpiffeId, [h]);

// ---- fixtures
const GEN = ['root', 'other-root', 'inter0', 'inter', 'inter-under-inter0', 'inter-noks', 'inter-notca', 'leaf', 'leaf-direct', 'leaf-via-chain', 'leaf-noks', 'leaf-notca', 'leaf-expired', 'leaf-two-uri',
  'leaf-dns-only', 'leaf-root-path', 'leaf-other-td', 'leaf-unknown-critical', 'leaf-is-ca', 'leaf-cert-sign', 'leaf-crl-sign', 'leaf-no-digital-signature', 'leaf-no-key-usage'];
const GS = ['good-leaf-and-intermediate', 'good-leaf-only', 'wrong-intermediate-no-ca', 'wrong-intermediate-no-key-cert-sign', 'wrong-leaf-ca-true', 'wrong-leaf-cert-sign', 'wrong-leaf-crl-sign', 'wrong-leaf-empty-id', 'wrong-leaf-no-digital-signature'];
const P: Record<string, string> = {};
for (const n of GEN) P[n] = gen(n);
for (const n of GS) P['gs:' + n] = gs(n);

// readCertFacts: every fixture, plus truncations and byte flips of a few
const facts = (b: string) => readCertFacts(new Uint8Array(Buffer.from(b, 'base64url')));
for (const [n, pem] of Object.entries(P)) for (const [k, c] of pemsOf(pem).entries()) await o.run('readCertFacts', `${n}#${k}`, facts, [b64u(derOf(c))]);
for (const n of ['leaf', 'inter0', 'leaf-unknown-critical', 'gs:wrong-leaf-ca-true']) {
  const d = derOf(pemsOf(P[n]!)[0]!);
  for (let len = 0; len < d.length; len += 3) await o.run('readCertFacts', `${n}-trunc${len}`, facts, [b64u(d.subarray(0, len))]);
  for (let pos = 0; pos < d.length; pos += 5) for (const [vi, v] of [0x00, 0xff, d[pos]! ^ 0x01].entries()) {
    const m = new Uint8Array(d);
    m[pos] = v;
    await o.run('readCertFacts', `${n}-flip${pos}-${vi}`, facts, [b64u(m)]);
  }
  await o.run('readCertFacts', `${n}-trailing`, facts, [b64u(Buffer.concat([d, Buffer.from([0])]))]);
}
await o.run('readCertFacts', 'empty', facts, ['']);

// parseX509Svid
const parse = (c: any) => { const s = M.parseX509Svid(c?.$bytes ? new Uint8Array(Buffer.from(c.$bytes, 'base64url')) : c); return { spiffeId: { id: s.spiffeId.id, trustDomain: s.spiffeId.trustDomain, path: s.spiffeId.path }, publicKeyDer: s.publicKeyDer }; };
for (const [n, pem] of Object.entries(P)) {
  await o.run('parseX509Svid', n, parse, [pem]);
  await o.run('parseX509Svid', `${n}-der`, parse, [bytes(derOf(pemsOf(pem)[0]!))]);
}
const LEAF = P['leaf']!;
for (const [i, c] of ['', 'x', LEAF.slice(0, 100), LEAF.replace('MII', 'M!I'), LEAF.replace(/\n/g, ''), '\n' + LEAF + '\n', 'junk\n' + LEAF + 'trail', LEAF.replace('-----END CERTIFICATE-----', ''),
  LEAF + P['root'], 5, null, [], {}, bytes(new Uint8Array(0)), bytes(new Uint8Array([0x30, 0x00])), bytes(derOf(LEAF).subarray(0, 50))].entries()) await o.run('parseX509Svid', `bad${i}`, parse, [c]);

// ---- verifyX509Svid
const NB = Date.UTC(2026, 9, 1), NA = Date.UTC(2036, 9, 1);
const DAY = 86_400_000;
const REV = (mode: string | undefined, calls: any[]) => {
  if (mode === undefined) return undefined;
  if (mode === 'notfn') return null;
  return (s: any) => {
    calls.push({ ...s });
    if (mode === 'false') return false;
    if (mode === 'true') return true;
    if (mode.startsWith('true@')) return s.position === Number(mode.slice(5));
    if (mode === 'throw') throw new Error('boom');
    if (mode === 'one') return 1;
    if (mode === 'promise') return Promise.resolve(true);
    return undefined;
  };
};
const fromSpec = (c: any): any => (c && c.$bytes ? new Uint8Array(Buffer.from(c.$bytes, 'base64url')) : c);
async function x509Verify(chain: any, opts: any) {
  const calls: any[] = [];
  const r = M.verifyX509Svid(Array.isArray(chain) ? chain.map(fromSpec) : chain, {
    trustDomain: opts.trustDomain, roots: opts.roots.map(fromSpec),
    ...(opts.nowMs !== undefined ? { now: new Date(opts.nowMs) } : {}), ...(opts.maxChainLength !== undefined ? { maxChainLength: opts.maxChainLength } : {}),
    ...(opts.revocation !== undefined ? { revocation: REV(opts.revocation, calls) } : {}),
  });
  return { spiffeId: { id: r.spiffeId.id, trustDomain: r.spiffeId.trustDomain, path: r.spiffeId.path }, publicKeyDer: r.publicKeyDer, calls };
}
const wrapV = async (chain: any, opts: any) => { try { return await x509Verify(chain, opts); } catch (e) { throw TS_ERR(e); } };
const NOWOK = NB + DAY;
let vn = 0;
const V = (chain: any, opts: any) => o.run('verifyX509Svid', `v${vn++}`, wrapV, [chain, { trustDomain: 'example.org', ...opts }]);
const R = P['root']!;
const base = { roots: [R], nowMs: NOWOK };
await V([P['leaf'], P['inter0']], base);
await V(P['leaf']! + P['inter0'], base);
await V([P['leaf'], P['inter0'], R], base);
await V([P['leaf'], P['inter0']], { ...base, roots: [P['other-root']] });
await V([P['leaf'], P['inter0']], { ...base, roots: [P['other-root']! + R] });
await V([P['leaf'], P['inter0']], { ...base, roots: [bytes(derOf(R))] });
await V([bytes(derOf(P['leaf']!)), bytes(derOf(P['inter0']!))], base);
await V([P['leaf']], base);
await V([P['leaf']], { ...base, roots: [P['inter0']] });
await V([P['leaf-direct']], base);
await V([P['leaf-direct'], R], base);
await V([P['leaf-direct'], R], { ...base, maxChainLength: 1 });
await V([P['leaf'], P['inter0']], { ...base, maxChainLength: 1 });
await V([P['leaf'], P['inter0']], { ...base, maxChainLength: 2 });
await V([P['leaf-via-chain'], P['inter-under-inter0'], P['inter0']], base);
await V([P['leaf-via-chain'], P['inter-under-inter0']], base);
await V([P['leaf-via-chain'], P['inter-under-inter0'], P['inter0']], { ...base, roots: [R, P['inter0']] });
await V([P['leaf-noks'], P['inter-noks']], base);
await V([P['leaf-notca'], P['inter-notca']], base);
await V([P['leaf'], P['inter']], base);
await V([P['leaf'], P['other-root']], base);
await V([P['inter0'], P['leaf']], base);
await V([], base);
await V('', base);
await V('not pem', base);
await V([P['leaf'], P['inter0']], { ...base, roots: [] });
await V([P['leaf'], P['inter0']], { ...base, roots: ['junk'] });
await V([P['leaf'], P['inter0']], { ...base, trustDomain: 'other.org' });
await V([P['leaf'], P['inter0']], { ...base, trustDomain: '' });
for (const [n, t] of [['before', NB - 1000], ['at-nb', NB], ['just-after', NB + 1000], ['mid', NOWOK], ['at-na', NA], ['past-na', NA + 1000], ['year2020', Date.UTC(2020, 5, 1)], ['zero', 0]] as any[]) {
  await V([P['leaf'], P['inter0']], { ...base, nowMs: t });
  await V([P['leaf-expired'], P['inter0']], { ...base, nowMs: t });
}
for (const n of GEN.filter((x) => x.startsWith('leaf'))) { await V([P[n], P['inter0']], base); await V([P[n], P['inter0']], { ...base, nowMs: Date.UTC(2020, 5, 1) }); }
for (const n of GS) {
  const cs = pemsOf(P['gs:' + n]!);
  const from = Math.max(...cs.map((c) => new X509Certificate(c).validFromDate.getTime())) + 60_000;
  await V(P['gs:' + n], { roots: [cs[cs.length - 1]!], nowMs: from });
  await V(P['gs:' + n], { roots: [cs[cs.length - 1]!], nowMs: NOWOK });
  await V(cs, { roots: [cs[cs.length - 1]!], nowMs: from, trustDomain: 'example.org' });
  await V(P['gs:' + n], { roots: [R], nowMs: from });
}
for (const mode of ['false', 'true', 'true@0', 'true@1', 'throw', 'one', 'undef', 'promise', 'notfn']) {
  await V([P['leaf'], P['inter0']], { ...base, revocation: mode });
  await V([P['leaf'], P['inter0'], R], { ...base, revocation: mode });
  await V([P['leaf-direct']], { ...base, revocation: mode });
  await V([P['leaf'], P['inter0']], { ...base, revocation: mode, nowMs: NA + DAY });
}

// ---- generated holder-binding PKI (seeded; only public data and signatures are emitted)
const dir = mkdtempSync(join(tmpdir(), 'spiffe-oracle-'));
const sh = (...a: string[]) => void execFileSync('openssl', a, { cwd: dir, stdio: 'ignore' });
const NBF = '20260101000000Z'; // fixed validity start: the corpus never depends on the clock
const edPem = (label: string) => createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), stream(label, 32)]), format: 'der', type: 'pkcs8' });
const pemOf = (k: any) => k.export({ type: 'pkcs8', format: 'pem' }) as string;
writeFileSync(join(dir, 'root.key'), pemOf(edPem('spiffe/hroot')));
sh('req', '-new', '-key', 'root.key', '-subj', '/CN=root', '-out', 'root.csr');
writeFileSync(join(dir, 'rootext'), 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n');
sh('x509', '-req', '-in', 'root.csr', '-key', 'root.key', '-out', 'hroot.pem', '-not_before', NBF, '-not_after', '20260131000000Z', '-set_serial', '1', '-extfile', 'rootext');
writeFileSync(join(dir, 'ext'), 'subjectAltName=URI:spiffe://example.org/workload/db\nkeyUsage=critical,digitalSignature\nbasicConstraints=critical,CA:FALSE\n');
const LEAVES: Record<string, { pem: string; key: any }> = {};
const HRSA = detRsa('spiffe/holder-rsa');
const HKEYS: Record<string, { key: any; ec?: EcKey }> = { ed: { key: edPem('spiffe/holder-ed') }, rsa: { key: HRSA.priv } };
HKEYS['ec'] = { key: undefined, ec: detEc('spiffe/holder-p256', 'P256') }; HKEYS['ec']!.key = HKEYS['ec']!.ec!.priv;
HKEYS['ec384'] = { key: undefined, ec: detEc('spiffe/holder-p384', 'P384') }; HKEYS['ec384']!.key = HKEYS['ec384']!.ec!.priv;
let serial = 2;
for (const name of ['ed', 'ec', 'ec384', 'rsa']) {
  writeFileSync(join(dir, `${name}.key`), pemOf(HKEYS[name]!.key));
  sh('req', '-new', '-key', `${name}.key`, '-subj', `/CN=${name}`, '-out', `${name}.csr`);
  sh('x509', '-req', '-in', `${name}.csr`, '-CA', 'hroot.pem', '-CAkey', 'root.key', '-set_serial', String(serial++), '-out', `${name}.pem`, '-not_before', NBF, '-not_after', '20260111000000Z', '-extfile', 'ext');
  LEAVES[name] = { pem: readFileSync(join(dir, `${name}.pem`), 'utf8'), key: HKEYS[name]!.key };
}
const HROOT = readFileSync(join(dir, 'hroot.pem'), 'utf8');
const HNOW = new X509Certificate(LEAVES['ed']!.pem).validFromDate.getTime() + 3_600_000;
const kp = (n: number) => { const k = new Uint8Array(32); k.fill(n); return k; };
const HK = [b64u(kp(1)), b64u(kp(2))];
const psign = (leaf: string, spiffe: string, holder: string) => {
  const k = LEAVES[leaf]!.key;
  const msg = M.holderBindingMessage(spiffe, holder);
  if (leaf === 'ed') return b64u(nodeSign(null, msg, k));
  if (leaf === 'rsa') return b64u(nodeSign('sha256', msg, k));
  return b64u(ecSign(HKEYS[leaf]!.ec!, leaf === 'ec384' ? 'sha384' : 'sha256', msg));
};
// X.509 verification of the generated leaves
for (const n of Object.keys(LEAVES)) {
  await V(LEAVES[n]!.pem, { roots: [HROOT], nowMs: HNOW });
  await V(LEAVES[n]!.pem, { roots: [HROOT], nowMs: HNOW + 20 * DAY });
  await V([LEAVES[n]!.pem], { roots: [R], nowMs: HNOW });
}
await V([LEAVES['ed']!.pem, HROOT], { roots: [HROOT], nowMs: HNOW });

// ---- JWT-SVID
const T = 1_800_000_000;
const NOWMS = (T + 60) * 1000;
type JKey = { sign: (m: Uint8Array) => Buffer; jwk: JWK };
const KEYS: Record<string, JKey> = {};
const HASH: Record<string, string> = { '256': 'sha256', '384': 'sha384', '512': 'sha512' };
for (const alg of ['ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512']) {
  const h = HASH[alg.slice(2)]!;
  if (alg.startsWith('ES')) {
    const k = detEc(`spiffe/jwt-${alg}`, { ES256: 'P256', ES384: 'P384', ES512: 'P521' }[alg] as any);
    KEYS[alg] = { jwk: k.jwk, sign: (m) => ecSign(k, h, m) };
  } else {
    const k = detRsa(`spiffe/jwt-${alg}`);
    KEYS[alg] = { jwk: k.jwk, sign: alg.startsWith('RS') ? (m) => nodeSign(h, m, k.priv) : (m) => pssSign(k, h, m, `spiffe/jwt-${alg}`) };
  }
}
const ES256B = detEc('spiffe/jwt-ES256-b', 'P256');
const ES256B_JWK = ES256B.jwk;
const RS1024 = (() => { const k = detRsa('spiffe/rsa1024', 1024); return { priv: k.priv, jwk: k.jwk }; })();
const claims = (extra: any = {}) => ({ sub: SUB, aud: 'api', exp: T + 3600, iat: T, ...extra });
async function mint(alg: string, payload: any, header: any = {}, key: JKey = KEYS[alg]!): Promise<string> {
  const input = `${b64u(Buffer.from(JSON.stringify({ alg, ...header })))}.${b64u(Buffer.from(JSON.stringify(payload)))}`;
  return `${input}.${b64u(key.sign(Buffer.from(input)))}`;
}
const AUD = 'api';
const spec = (token: string, alg: string, over: any = {}) => ({ token, key: { jwk: KEYS[alg]!.jwk }, audience: AUD, trustDomain: 'example.org', currentDateMs: NOWMS, ...over });

function jwtOpts(s: any, calls: any[]): any {
  const rv: any = s.revocation;
  const revocation = rv === undefined ? undefined : rv === 'notfn' ? null : (subj: any) => {
    calls.push({ ...subj });
    if (rv === 'false') return false;
    if (rv === 'true') return true;
    if (rv === 'throw') throw new Error('boom');
    if (rv === 'one') return 1;
    if (rv === 'async-true') return Promise.resolve(true);
    if (rv === 'async-false') return Promise.resolve(false);
    if (rv === 'async-throw') return Promise.reject(new Error('boom'));
    return undefined;
  };
  return {
    audience: s.audience, trustDomain: s.trustDomain, ...(s.currentDateMs !== undefined ? { currentDate: new Date(s.currentDateMs) } : {}),
    ...(s.algorithms !== undefined ? { algorithms: s.algorithms } : {}), ...(s.clockTolerance !== undefined ? { clockTolerance: s.clockTolerance } : {}),
    ...(revocation !== undefined ? { revocation } : {}),
  };
}
async function jwtKey(s: any): Promise<any> {
  if (s.key.jwk) {
    let alg = 'ES256';
    try { const a = (JSON.parse(Buffer.from(s.token.split('.')[0], 'base64url').toString()) as any).alg; if (typeof a === 'string') alg = a; } catch { /* the token is refused before the key is used */ }
    try { return await importJWK(s.key.jwk, alg); } catch { return new Uint8Array(1); }
  }
  const src = M.createTrustBundleSource({ fetch: async () => ({ jwks: s.key.bundle.jwks }), refreshMs: 1000, maxStaleMs: 5000, now: () => NOWMS });
  return src.jwtKey;
}
async function jwtVerify(s: any) {
  const calls: any[] = [];
  try {
    const r = await M.verifyJwtSvid(s.token, { ...jwtOpts(s, calls), key: await jwtKey(s) });
    return { spiffeId: { id: r.spiffeId.id, trustDomain: r.spiffeId.trustDomain, path: r.spiffeId.path }, claims: r.claims, audience: r.audience, expiresAt: r.expiresAt, calls };
  } catch (e) { throw TS_ERR(e); }
}
let jn = 0;
const J = (s: any) => o.run('jwtSession', `j${jn++}`, jwtVerify, [s]);
const tamper = (tok: string, i: number, f: (s: string) => string) => tok.split('.').map((p, k) => (k === i ? f(p) : p)).join('.');
const flipMid = (s: string) => s.slice(0, 10) + (s[10] === 'A' ? 'B' : 'A') + s.slice(11);

for (const alg of Object.keys(KEYS)) {
  const tok = await mint(alg, claims());
  await J(spec(tok, alg));
  await J(spec(tok, alg, { algorithms: [alg] }));
  await J(spec(tok, alg, { algorithms: ['ES256', 'RS256'].filter((a) => a !== alg) }));
  await J(spec(tamper(tok, 2, flipMid), alg));
  await J(spec(tamper(tok, 1, () => Buffer.from(JSON.stringify({ ...claims(), sub: 'spiffe://example.org/evil' })).toString('base64url')), alg));
  for (const a of compactJwsAliases(tok)) await J(spec(a.token, alg, {}));
  await J(spec(tok, alg, { revocation: 'false' }));
  await J(spec(tok, alg, { revocation: 'true' }));
}
const ES = await mint('ES256', claims({ jti: 'tok-1' }));
await J(spec(ES, 'ES256', { revocation: 'false' }));
await J({ ...spec(ES, 'ES256'), key: { jwk: ES256B_JWK } });
await J({ ...spec(ES, 'ES256'), key: { jwk: KEYS['ES384']!.jwk } });
await J({ ...spec(ES, 'ES256'), key: { jwk: KEYS['RS256']!.jwk } });
{
  const h = Buffer.from('{"alg":"RS256"}').toString('base64url'), pl = Buffer.from(JSON.stringify(claims())).toString('base64url');
  await J({ ...spec(`${h}.${pl}.${b64u(nodeSign('sha256', Buffer.from(`${h}.${pl}`), RS1024.priv))}`, 'ES256'), key: { jwk: RS1024.jwk } });
}
for (const rv of ['true', 'throw', 'one', 'undef', 'async-true', 'async-false', 'async-throw', 'notfn']) await J(spec(ES, 'ES256', { revocation: rv }));
for (const p of Object.values({
  expired: claims({ exp: T + 59 }), 'exp-eq-now': claims({ exp: T + 60 }), 'exp-now+1': claims({ exp: T + 61 }), 'no-exp': { sub: SUB, aud: 'api' }, 'exp-str': claims({ exp: '99' }), 'exp-float': claims({ exp: T + 3600.5 }),
  'nbf-future': claims({ nbf: T + 120 }), 'nbf-eq': claims({ nbf: T + 60 }), 'nbf-past': claims({ nbf: T }), 'nbf-str': claims({ nbf: 'x' }), 'iat-str': claims({ iat: 'x' }), 'iat-future': claims({ iat: T + 9999 }),
  'aud-arr': claims({ aud: ['x', 'api'] }), 'aud-other': claims({ aud: 'other' }), 'aud-none': { sub: SUB, exp: T + 3600 }, 'aud-num': claims({ aud: 5 }), 'aud-arr-miss': claims({ aud: ['x', 'y'] }), 'aud-empty-arr': claims({ aud: [] }),
  'sub-none': { aud: 'api', exp: T + 3600 }, 'sub-bad': claims({ sub: 'nope' }), 'sub-num': claims({ sub: 5 }), 'sub-td': claims({ sub: 'spiffe://other.org/x' }), 'sub-upper': claims({ sub: 'spiffe://Example.org/x' }), 'sub-bare': claims({ sub: 'spiffe://example.org' }),
  'sub-slash': claims({ sub: 'spiffe://example.org/a/' }), cnf: claims({ cnf: { jwk: { kty: 'OKP', crv: 'Ed25519', x: HK[0] } } }), extra: claims({ x: [1, { y: null }], iss: 'me' }), 'jti-num': claims({ jti: 5 }),
}) as any[]) await J(spec(await mint('ES256', p), 'ES256', { revocation: 'false' }));
for (const h of Object.values({ typ: { typ: 'JWT' }, jose: { typ: 'JOSE' }, 'typ-at': { typ: 'at+jwt' }, 'typ-lower': { typ: 'jwt' }, 'typ-num': { typ: 5 }, kid: { kid: 'k1' }, 'crit-b64': { crit: ['b64'], b64: true }, x5t: { x5t: 'abc' } }) as any[]) {
  await J(spec(await mint('ES256', claims(), h), 'ES256'));
}
for (const t of [5, '30s', '1m', '-5s', '5 seconds', '1 hour ago', 'bad', '', 0, -1, 1e9, '1.5m', '2 days', 1.5]) {
  for (const exp of [T + 59, T + 40, T + 61]) await J(spec(await mint('ES256', claims({ exp })), 'ES256', { clockTolerance: t }));
}
for (const alg of [[], ['none'], ['HS256'], ['hs384'], ['ES256', 'none'], ['RS256'], ['ES256'], ['ES256', 'RS256'], ['EdDSA'], ['es256']]) await J(spec(ES, 'ES256', { algorithms: alg }));
for (const [a, td] of [[AUD, ''], [[], 'example.org'], [[''], 'example.org'], [['api', ''], 'example.org'], [['x', 'api'], 'example.org'], ['other', 'example.org'], [AUD, 'other.org']] as any[]) await J(spec(ES, 'ES256', { audience: a, trustDomain: td }));
for (const t of [
  [Buffer.from('{"alg":"none"}').toString('base64url'), Buffer.from(JSON.stringify(claims())).toString('base64url'), ''].join('.'),
  ES.replace(/^[^.]+/, Buffer.from('{"alg":"HS256"}').toString('base64url')),
  'a.b', 'a.b.c.d', '', '..', 'a!.b.c',
  ['W10', Buffer.from(JSON.stringify(claims())).toString('base64url'), 'AAAA'].join('.'), [ES.split('.')[0], 'W10', ES.split('.')[2]].join('.'),
]) await J(spec(t as string, 'ES256'));

// bundle-resolved keys (jwks), kid selection and ambiguity
const jwkOf = (alg: string, extra: any = {}) => ({ ...KEYS[alg]!.jwk, ...extra });
const BUNDLE = (keys: any[]) => ({ key: { bundle: { jwks: { keys } } } });
const JB = (tok: string, keys: any[], over: any = {}) => J({ token: tok, ...BUNDLE(keys), audience: AUD, trustDomain: 'example.org', currentDateMs: NOWMS, ...over });
const esK = await mint('ES256', claims(), { kid: 'a' });
const esNoK = await mint('ES256', claims());
await JB(esK, [jwkOf('ES256', { kid: 'a' })]);
await JB(esK, [jwkOf('ES256', { kid: 'b' })]);
await JB(esK, [jwkOf('ES256', { kid: 'a' }), { ...ES256B_JWK, kid: 'b' }]);
await JB(esNoK, [jwkOf('ES256', { kid: 'a' }), { ...ES256B_JWK, kid: 'b' }]);
await JB(esNoK, [jwkOf('ES256'), jwkOf('ES384')]);
await JB(esNoK, [jwkOf('ES384'), jwkOf('RS256')]);
await JB(esNoK, [jwkOf('ES256', { alg: 'ES256' })]);
await JB(esNoK, [jwkOf('ES256', { alg: 'ES384' })]);
await JB(esNoK, [jwkOf('ES256', { use: 'enc' })]);
await JB(esNoK, [jwkOf('ES256', { use: 'sig' })]);
await JB(esNoK, [jwkOf('ES256', { key_ops: ['sign'] })]);
await JB(esNoK, [jwkOf('ES256', { key_ops: ['verify'] })]);
await JB(esNoK, [jwkOf('ES256', { kty: 'EC', d: 'AAAA' })]);
await JB(esNoK, []);
await JB(await mint('RS256', claims()), [jwkOf('RS256'), jwkOf('ES256')]);
await JB(await mint('PS256', claims()), [jwkOf('PS256', { alg: 'PS256' })]);
await JB(await mint('ES384', claims()), [jwkOf('ES384')]);
await JB(await mint('ES512', claims()), [jwkOf('ES512')]);
// crit must be refused before the resolver is consulted (unknown kid would otherwise fail first)
await JB(await mint('ES256', claims(), { kid: 'zzz', crit: ['x'], x: 1 }), [jwkOf('ES256', { kid: 'a' })]);
await JB(await mint('ES256', claims(), { kid: 'zzz', crit: ['b64'], b64: 'no' }), [jwkOf('ES256', { kid: 'a' })]);
await JB(esNoK, [jwkOf('ES256'), jwkOf('ES256')]);

// ---- holder binding
let hn = 0;
const hk = (k: any) => (k && k.$bytes ? new Uint8Array(Buffer.from(k.$bytes, 'base64url')) : k);
async function holderSession(s: any) {
  try {
    let svid: any;
    if (s.svid === 'x509' || s.svid === 'x509-parsed') {
      svid = s.svid === 'x509' ? M.verifyX509Svid(s.chain, { trustDomain: 'example.org', roots: s.roots, now: new Date(s.nowMs) }) : M.parseX509Svid(s.chain);
    } else if (s.svid === 'jwt') {
      const key = await importJWK(s.jwt.jwk, JSON.parse(Buffer.from(s.jwt.token.split('.')[0], 'base64url').toString()).alg);
      svid = await M.verifyJwtSvid(s.jwt.token, { audience: s.jwt.audience, key, trustDomain: s.jwt.trustDomain, currentDate: new Date(s.jwt.currentDateMs) });
    } else if (s.svid === 'string') svid = SUB;
    else if (s.svid === 'parsed-id') svid = M.parseSpiffeId(SUB);
    else if (s.svid === 'hand-built') svid = { spiffeId: M.parseSpiffeId(SUB), claims: {}, audience: [], expiresAt: 1 };
    else svid = null;
    const opts = { ...(s.proof !== undefined ? { proof: s.proof } : {}), ...(s.acceptUnbound !== undefined ? { acceptUnboundJwtHolder: s.acceptUnbound } : {}) };
    if (s.op === 'holder') return { holder: { ...M.svidToHolder(svid, hk(s.holderKey), opts) } };
    if (s.op === 'forHolder') return { spiffeId: M.spiffeIdForHolder(svid, s.holderKey, opts) };
    return { pin: M.workloadDischargePin(s.label, svid) };
  } catch (e) { throw TS_ERR(e); }
}
const H = (s: any) => o.run('holderSession', `h${hn++}`, holderSession, [s]);
const xs = (leaf: string, over: any = {}) => ({ svid: 'x509', chain: LEAVES[leaf]!.pem, roots: [HROOT], nowMs: HNOW, ...over });
const edHolder = M.svidToHolder(M.verifyX509Svid(LEAVES['ed']!.pem, { trustDomain: 'example.org', roots: [HROOT], now: new Date(HNOW) })).holder;
for (const svid of ['x509-parsed', 'string', 'parsed-id', 'hand-built', 'null']) for (const op of ['holder', 'forHolder', 'pin']) await H(xs('ed', { svid, op, holderKey: HK[0], label: 'l' }));
for (const op of ['holder', 'forHolder', 'pin']) {
  await H(xs('ed', { op, label: 'runtime', holderKey: op === 'holder' ? undefined : edHolder }));
  await H(xs('ed', { op, label: 'runtime', holderKey: edHolder }));
  await H(xs('ed', { op, label: 'runtime', holderKey: HK[0] }));
  await H(xs('ed', { op, label: 'runtime', holderKey: bytes(Buffer.from(edHolder, 'base64url')) }));
  await H(xs('ec', { op, label: 'runtime', holderKey: HK[0] }));
  await H(xs('ec', { op, label: 'runtime' }));
}
await H(xs('ed', { op: 'holder', holderKey: HK[0], proof: psign('ed', SUB, HK[0]!) }));
await H(xs('ed', { op: 'holder', holderKey: HK[0], proof: psign('ed', SUB, HK[1]!) }));
await H(xs('ed', { op: 'holder', holderKey: HK[0], proof: psign('ed', 'spiffe://example.org/other', HK[0]!) }));
await H(xs('ed', { op: 'holder', holderKey: HK[0], proof: 'AAAA' }));
await H(xs('ed', { op: 'holder', holderKey: HK[0], proof: '!!' }));
await H(xs('ed', { op: 'holder', holderKey: HK[0], proof: '' }));
await H(xs('ed', { op: 'forHolder', holderKey: HK[0], proof: psign('ed', SUB, HK[0]!) }));
for (const leaf of ['ec', 'ec384', 'rsa']) {
  const good = psign(leaf, SUB, HK[0]!);
  await H(xs(leaf, { op: 'holder', holderKey: HK[0], proof: good }));
  await H(xs(leaf, { op: 'holder', holderKey: HK[1], proof: good }));
  await H(xs(leaf, { op: 'holder', holderKey: HK[0], proof: psign(leaf, SUB, HK[1]!) }));
  await H(xs(leaf, { op: 'holder', holderKey: HK[0], proof: good.slice(0, -4) }));
  await H(xs(leaf, { op: 'holder', holderKey: HK[0], proof: good.slice(0, 10) + (good[10] === 'A' ? 'B' : 'A') + good.slice(11) }));
  await H(xs(leaf, { op: 'forHolder', holderKey: HK[0], proof: good }));
  await H(xs(leaf, { op: 'pin', label: 'x' }));
}
await H(xs('ec', { op: 'holder', holderKey: HK[0], proof: psign('ec384', SUB, HK[0]!) }));
await H(xs('ec384', { op: 'holder', holderKey: HK[0], proof: psign('ec', SUB, HK[0]!) }));
for (const k of ['', 'short', b64u(new Uint8Array(31)), b64u(new Uint8Array(33)), HK[0] + '=', HK[0]!.slice(0, -1) + (HK[0]!.endsWith('E') ? 'F' : 'E'), bytes(new Uint8Array(31)), bytes(new Uint8Array(33)), bytes(new Uint8Array(32)), 5, null]) {
  await H(xs('ed', { op: 'holder', holderKey: k, proof: 'AAAA' }));
}
// JWT-SVID binding
const bound = await mint('ES256', claims({ cnf: { jwk: { kty: 'OKP', crv: 'Ed25519', x: HK[0] } } }));
const unbound = await mint('ES256', claims());
const cnfs: any[] = [{ kty: 'OKP', crv: 'Ed25519', x: HK[1] }, { kty: 'EC', crv: 'Ed25519', x: HK[0] }, { kty: 'OKP', crv: 'Ed448', x: HK[0] }, { kty: 'OKP', crv: 'Ed25519', x: 5 }, 'x', null];
const jw = (token: string, extra: any = {}) => ({ svid: 'jwt', jwt: { token, jwk: KEYS['ES256']!.jwk, audience: AUD, trustDomain: 'example.org', currentDateMs: NOWMS }, ...extra });
for (const op of ['holder', 'forHolder', 'pin']) {
  await H(jw(bound, { op, holderKey: HK[0], label: 'j' }));
  await H(jw(bound, { op, holderKey: HK[1], label: 'j' }));
  await H(jw(unbound, { op, holderKey: HK[0], label: 'j' }));
  await H(jw(unbound, { op, holderKey: HK[0], acceptUnbound: true, label: 'j' }));
  await H(jw(unbound, { op, label: 'j' }));
  await H(jw(unbound, { op, holderKey: HK[0], acceptUnbound: 'yes', label: 'j' }));
  await H(jw(unbound, { op, holderKey: bytes(new Uint8Array(32)), acceptUnbound: true, label: 'j' }));
}
for (const c of cnfs) await H(jw(await mint('ES256', claims({ cnf: { jwk: c } })), { op: 'holder', holderKey: HK[0] }));
await H(jw(await mint('ES256', claims({ cnf: 5 })), { op: 'holder', holderKey: HK[0] }));
await H(jw(await mint('ES256', claims({ cnf: { jwk: 7 } })), { op: 'holder', holderKey: HK[0], acceptUnbound: true }));

// ---- revocation / bundle caches (manual clock)
async function cacheSession(kind: 'revocation' | 'bundle', s: any) {
  let t = s.start;
  let fetchCalls = 0;
  const fetchFn = async () => {
    const f = s.fetches[Math.min(fetchCalls, s.fetches.length - 1)];
    fetchCalls++;
    if (f.throw) throw new Error('fetch failed');
    return f.list;
  };
  const out: any[] = [];
  let src: any;
  try {
    src = kind === 'revocation' ? M.createRevocationSource({ fetch: fetchFn, refreshMs: s.refreshMs, maxStaleMs: s.maxStaleMs, now: () => t }) : M.createTrustBundleSource({ fetch: fetchFn, refreshMs: s.refreshMs, maxStaleMs: s.maxStaleMs, now: () => t });
  } catch (e) { throw TS_ERR(e); }
  for (const st of s.steps) {
    try {
      if (st.op === 'adv') { t += st.ms; out.push({ v: t }); continue; }
      let v: any;
      if (st.op === 'x509') v = src.x509(st.subject);
      else if (st.op === 'jwt') v = await src.jwt(st.subject);
      else if (st.op === 'refresh') v = (await src.refresh(), null);
      else if (st.op === 'ensureFresh') v = (await src.ensureFresh(), null);
      else if (st.op === 'x509Roots') v = (await src.x509Roots()).map((r: any) => (typeof r === 'string' ? r : bytes(r)));
      else { const k: any = await src.jwtKey(st.header, undefined); const j = k.export({ format: 'jwk' }); v = { kty: j.kty, ...(j.crv ? { crv: j.crv } : {}), ...(j.x ? { x: j.x } : {}), ...(j.n ? { n: j.n } : {}) }; }
      out.push({ v: v ?? null });
    } catch (e: any) { out.push({ code: TS_ERR(e).code }); }
  }
  return { steps: out, fetchCalls };
}
const wrapCache = (kind: 'revocation' | 'bundle') => async (s: any) => { try { return await cacheSession(kind, s); } catch (e) { throw TS_ERR(e); } };
const XSUB = { spiffeId: SUB, serialNumber: '0A0B', fingerprint256: 'AB:CD:EF', position: 0, isLeaf: true };
const JSUB = { spiffeId: SUB, jti: 'j1', expiresAt: 5, tokenHash: 'hash1' };
const L1 = { fingerprints: ['ab:cd:ef'], serials: ['000a0b', '9'], spiffeIds: ['spiffe://example.org/revoked'], jtis: ['j2'], tokenHashes: ['hash2'] };
let rn = 0;
const RS = (s: any) => o.run('revocationSession', `r${rn++}`, wrapCache('revocation'), [{ start: 1_800_000_000_000, refreshMs: 1000, maxStaleMs: 5000, ...s }]);
const x = (subject: any = {}) => ({ op: 'x509', subject: { ...XSUB, ...subject } });
const jt = (subject: any = {}) => ({ op: 'jwt', subject: { ...JSUB, ...subject } });
const adv = (ms: number) => ({ op: 'adv', ms });
await RS({ fetches: [{ list: {} }], steps: [x(), jt()] });
await RS({ fetches: [{ list: L1 }], steps: [{ op: 'ensureFresh' }, x(), x({ fingerprint256: 'AB:CD:EE' }), x({ serialNumber: '0A0B' }), x({ serialNumber: 'A0B', fingerprint256: 'zz' }), x({ serialNumber: '9', fingerprint256: 'zz' }), x({ serialNumber: '09', fingerprint256: 'zz' }),
  x({ spiffeId: 'spiffe://example.org/revoked' }), x({ fingerprint256: 'ab:cd:ef' }), jt(), jt({ jti: 'j2' }), jt({ jti: undefined }), jt({ tokenHash: 'hash2' }), jt({ spiffeId: 'spiffe://example.org/revoked' })] });
await RS({ fetches: [{ list: L1 }], steps: [x()] });
await RS({ fetches: [{ list: L1 }], steps: [{ op: 'refresh' }, x(), adv(999), x(), jt(), adv(2), jt(), x(), adv(4000), x(), adv(1), x(), jt()] });
await RS({ fetches: [{ list: L1 }, { throw: true }], steps: [{ op: 'refresh' }, adv(1500), jt(), adv(1500), jt(), adv(3000), jt(), { op: 'ensureFresh' }, x()] });
await RS({ fetches: [{ throw: true }], steps: [{ op: 'refresh' }, x(), jt(), { op: 'ensureFresh' }] });
await RS({ fetches: [{ list: null }], steps: [{ op: 'refresh' }, x()] });
await RS({ fetches: [{ list: [] }], steps: [{ op: 'refresh' }] });
await RS({ fetches: [{ list: 'x' }], steps: [{ op: 'refresh' }] });
await RS({ fetches: [{ list: { fingerprints: 'x' } }], steps: [{ op: 'refresh' }] });
await RS({ fetches: [{ list: { serials: [1] } }], steps: [{ op: 'refresh' }] });
await RS({ fetches: [{ list: { jtis: null } }], steps: [{ op: 'refresh' }] });
await RS({ fetches: [{ list: { spiffeIds: [], extra: 1 } }], steps: [{ op: 'refresh' }, x(), jt()] });
await RS({ fetches: [{ list: L1 }, { list: {} }], steps: [{ op: 'refresh' }, x(), { op: 'refresh' }, x()] });
await RS({ fetches: [{ list: L1 }, { list: { fingerprints: 5 } }], steps: [{ op: 'refresh' }, { op: 'refresh' }, x(), adv(5001), x()] });
await RS({ refreshMs: 0, fetches: [{ list: {} }], steps: [] });
await RS({ refreshMs: -1, fetches: [{ list: {} }], steps: [] });
await RS({ refreshMs: 10, maxStaleMs: 5, fetches: [{ list: {} }], steps: [] });
await RS({ refreshMs: 10, maxStaleMs: 10, fetches: [{ list: {} }], steps: [{ op: 'refresh' }, x()] });
await RS({ fetches: [{ list: { fingerprints: ['AA:bb'], serials: ['0', '00', 'DE:AD'] } }], steps: [{ op: 'refresh' }, x({ fingerprint256: 'aabb' }), x({ serialNumber: '0', fingerprint256: 'z' }), x({ serialNumber: '000', fingerprint256: 'z' }), x({ serialNumber: 'dead', fingerprint256: 'z' }), x({ serialNumber: '', fingerprint256: 'z' })] });
const BX = ['-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----'];
const JK = { keys: [jwkOf('ES256', { kid: 'a' }), { ...ES256B_JWK, kid: 'b' }, jwkOf('RS256')] };
let bn = 0;
const BS = (s: any) => o.run('bundleSession', `b${bn++}`, wrapCache('bundle'), [{ start: 1_800_000_000_000, refreshMs: 1000, maxStaleMs: 5000, ...s }]);
const kh = (header: any) => ({ op: 'jwtKey', header });
await BS({ fetches: [{ list: { jwks: JK, x509Authorities: BX } }], steps: [{ op: 'x509Roots' }, kh({ alg: 'ES256', kid: 'a' }), kh({ alg: 'ES256', kid: 'b' }), kh({ alg: 'ES256' }), kh({ alg: 'RS256' }), kh({ alg: 'ES384' }), kh({ alg: 'EdDSA' }), kh({ alg: 'HS256' }), kh({ alg: 'ES256', kid: 'zz' }), kh({})] });
await BS({ fetches: [{ list: { x509Authorities: BX } }], steps: [{ op: 'x509Roots' }, kh({ alg: 'ES256' })] });
await BS({ fetches: [{ list: { jwks: JK } }], steps: [{ op: 'x509Roots' }, kh({ alg: 'RS256' })] });
await BS({ fetches: [{ list: { jwks: { keys: [] }, x509Authorities: [] } }], steps: [{ op: 'x509Roots' }] });
await BS({ fetches: [{ list: { jwks: { keys: [] }, x509Authorities: BX } }], steps: [{ op: 'x509Roots' }, kh({ alg: 'ES256' })] });
await BS({ fetches: [{ list: null }], steps: [{ op: 'x509Roots' }] });
await BS({ fetches: [{ list: 5 }], steps: [{ op: 'x509Roots' }] });
await BS({ fetches: [{ list: {} }], steps: [{ op: 'x509Roots' }] });
await BS({ fetches: [{ list: { jwks: { keys: 'x' }, x509Authorities: 'y' } }], steps: [{ op: 'x509Roots' }] });
await BS({ fetches: [{ throw: true }], steps: [{ op: 'x509Roots' }, kh({ alg: 'ES256' })] });
await BS({ fetches: [{ list: { x509Authorities: BX } }, { throw: true }], steps: [{ op: 'x509Roots' }, adv(1500), { op: 'x509Roots' }, adv(3000), { op: 'x509Roots' }, adv(1), { op: 'x509Roots' }] });
await BS({ fetches: [{ list: { x509Authorities: BX } }, { list: {} }], steps: [{ op: 'x509Roots' }, adv(1000), { op: 'x509Roots' }, adv(5001), { op: 'x509Roots' }] });
await BS({ fetches: [{ list: { x509Authorities: BX } }, { list: { x509Authorities: ['other'] } }], steps: [{ op: 'x509Roots' }, adv(1000), { op: 'x509Roots' }, { op: 'x509Roots' }] });
await BS({ refreshMs: 0, fetches: [{ list: {} }], steps: [] });
await BS({ refreshMs: 10, maxStaleMs: 1, fetches: [{ list: {} }], steps: [] });
await BS({ fetches: [{ list: { jwks: { keys: [jwkOf('ES256'), 5] } } }], steps: [kh({ alg: 'ES256' })] });
await BS({ fetches: [{ list: { jwks: { keys: [{ ...jwkOf('ES256'), d: 'AAAA' }] } } }], steps: [kh({ alg: 'ES256' })] });

// ---- admission evidence
const KNOWN = new Set(['malformed_spiffe_id', 'empty_trust_domain', 'trust_domain_too_long', 'invalid_trust_domain', 'invalid_path', 'id_too_long', 'missing_audience', 'missing_exp', 'malformed_token', 'invalid_subject', 'trust_domain_mismatch', 'no_uri_san',
  'multiple_uri_san', 'invalid_holder_key', 'unverified_svid', 'missing_trust_domain', 'holder_binding_failed', 'malformed_certificate', 'leaf_is_ca', 'leaf_no_digital_signature', 'leaf_cert_sign', 'leaf_crl_sign', 'leaf_root_path',
  'unsupported_critical_extension', 'forbidden_algorithm', 'invalid_typ', 'chain_empty', 'chain_trust_domain_mismatch', 'chain_signature', 'chain_not_ca', 'chain_no_key_cert_sign', 'chain_path_len', 'chain_expired', 'chain_untrusted_root',
  'chain_too_long', 'trust_bundle_unavailable', 'trust_bundle_invalid', 'svid_revoked', 'chain_revoked', 'revocation_unavailable', 'SVID is bound to a different key']);
async function admission(s: any) {
  const ev: any = s.kind === 'x509'
    ? { kind: 'x509', chain: s.chain, verify: { trustDomain: 'example.org', roots: s.roots, now: new Date(s.nowMs) }, ...(s.bind ? { bind: s.bind } : {}) }
    : { kind: 'jwt', token: s.token, verify: { audience: AUD, trustDomain: 'example.org', currentDate: new Date(NOWMS), key: await importJWK(s.jwk, 'ES256') }, ...(s.bind ? { bind: s.bind } : {}) };
  const r = await M.spiffeAdmissionEvidence(ev, s.instanceKey);
  return { ...r, ...(r.reason !== undefined ? { reason: KNOWN.has(r.reason) ? r.reason : 'other' } : {}) };
}
let an = 0;
const A = (s: any) => o.run('admission', `a${an++}`, admission, [s]);
const xa = (leaf: string, over: any = {}) => ({ kind: 'x509', chain: LEAVES[leaf]!.pem, roots: [HROOT], nowMs: HNOW, instanceKey: edHolder, ...over });
await A(xa('ed'));
await A(xa('ed', { instanceKey: HK[0] }));
await A(xa('ed', { instanceKey: HK[0], bind: { proof: psign('ed', SUB, HK[0]!) } }));
await A(xa('ec', { instanceKey: HK[0], bind: { proof: psign('ec', SUB, HK[0]!) } }));
await A(xa('ec', { instanceKey: HK[0] }));
await A(xa('ec', { instanceKey: 'short' }));
await A(xa('ed', { nowMs: HNOW + 100 * DAY }));
await A(xa('ed', { roots: [R] }));
await A(xa('ed', { chain: 'junk' }));
await A(xa('rsa', { instanceKey: HK[1], bind: { proof: psign('rsa', SUB, HK[0]!) } }));
const ja = (token: string, over: any = {}) => ({ kind: 'jwt', token, jwk: KEYS['ES256']!.jwk, instanceKey: HK[0], ...over });
await A(ja(bound));
await A(ja(unbound));
await A(ja(unbound, { bind: { acceptUnboundJwtHolder: true } }));
await A(ja(bound, { instanceKey: HK[1] }));
await A(ja(tamper(bound, 2, flipMid)));
await A(ja(await mint('ES256', claims({ exp: T + 1 }))));
await A(ja('junk'));
await A(ja(bound, { jwk: ES256B_JWK }));

refWrite(o, 'spiffe');
