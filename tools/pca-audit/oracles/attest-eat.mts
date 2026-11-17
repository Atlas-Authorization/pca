// Oracle: @atlasauth/pca-attest-eat (EAT build / verify / freshness / channel binding / RATS appraisal / tolerant SEV-SNP parse / AMD delegation, the
// post-quantum co-signature of a verdict, EAT admission evidence, the artifact discharge). Writes out/ref-attest-eat.json.gz.
// Deterministic: Ed25519 and every post-quantum suite sign deterministically (keys from seeds); ES256 is randomized, so ES256 tokens are VERIFY-ONLY inputs;
// the discharge nonce is a counter hash (randomBytes is replaced, the counter restarts at every call): nonce_i = sha256("eat-oracle-nonce/" + i)[:16].
//
// PORTING (fn(args) -> native entry point, comparison rule). JSON values; bytes are {"$bytes": b64url}; a throw only requires the native to refuse.
// Key specs: signing {alg: "EdDSA", seed} ; verifying {alg: "EdDSA", pub} | {alg: "ES256", x, y} (the native builds a JDK / library key from them).
//   constants()                                   -> the exported constants
//   deriveChannelCnf(channelId[, thumb]) / bindChannel(evidence, channelId, nonce)
//   buildEAT(args)                                -> args.key is a signing spec (Ed25519: the token bytes are exact)
//   verifyEAT(eat, pubSpec[, opts])               -> the parsed claims (or a throw)
//   verifyFreshness(claims, opts) / verifyChannelBinding(claims, opts) / appraise(evidence[, referenceValues[, endorsements[, extras]]])
//   parseReportTolerant(bytes)                    -> {ok, version, known, degraded, notes, evidence?, hasReport, measured?}
//   verifyAmdAttestation(bytes, opts)             -> {ok, reason?, hardwareRoot, evidence?, measured?}; opts.vcek/ask/ark are PEM strings or {"$bytes"}
//   verifyFreshAttestedEAT(eat, opts)             -> the verdict; opts.verifyKey is a pubSpec; opts.amd.rawReport / certs as above
//   canonicalVerdictBytes(verdict, cosignedAt) / verdictFromAppraisal(result, claims) / isPqCoSignSuite(x)
//   coSignAttestation(verdict, {suite?, key, now?}) -> key = {ed?: seed, pq?: {prim: "ml-dsa-65"|"ml-dsa-87"|"slh-dsa-sha2-128f"|"slh-dsa-sha2-256s", seed}}; exact
//   verifyCoSignedAttestation(cosigned[, opts])
//   ed25519Jkt(x) / eatAdmissionEvidence(eat, o)  -> o.verifyKey is a pubSpec
//   runtimeDigestFromEat(verdict[, o]) / issueArtifactDischarge(i) -> i.roots is the trusted_root JSON, i.issuerKey a signing spec; the discharge bytes are exact
import crypto from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';
import { readFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey, sign as nodeSign } from 'node:crypto';
import { Oracle, refWrite, splitWrite, tokensIn, rng, seed, variants } from './lib.mjs';

let ctr = 0;
(crypto as any).randomBytes = (n: number) => crypto.createHash('sha256').update('eat-oracle-nonce/' + ctr++).digest().subarray(0, n);
syncBuiltinESMExports();

const M: any = await import('../../../packages/pca-attest-eat/src/index.ts');
const P: any = await import('@atlasauth/pca');
const A: any = await import('@atlasauth/pca/ext/attestation');
const o = new Oracle('attest-eat', 'tools/pca-audit/oracles/attest-eat.mts', 'TS-reference oracle for @atlasauth/pca-attest-eat.');
const b64u = (u: Uint8Array | Buffer) => Buffer.from(u).toString('base64url');
const bytes = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));
const B = (u: Uint8Array) => ({ $bytes: b64u(u) });
const isB = (x: any) => x && typeof x === 'object' && !Array.isArray(x) && typeof x.$bytes === 'string' && Object.keys(x).length === 1;
const rev = (v: any): any => (isB(v) ? bytes(v.$bytes) : Array.isArray(v) ? v.map(rev) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).map((k) => [k, rev(v[k])])) : v);
const PK8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const edKey = (label: string) => {
  const s = seed(label);
  const priv = createPrivateKey({ key: Buffer.concat([PK8, Buffer.from(s)]), format: 'der', type: 'pkcs8' });
  return { priv: { alg: 'EdDSA', seed: b64u(s) }, pub: { alg: 'EdDSA', pub: (priv.export({ format: 'jwk' }) as any).x as string } };
};
const esKey = (label: string) => {
  const d = Buffer.from(seed(label));
  d[0] &= 0x7f;
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.setPrivateKey(d);
  const pt = ecdh.getPublicKey();
  const x = b64u(pt.subarray(1, 33)), y = b64u(pt.subarray(33, 65));
  return { priv: { alg: 'ES256', d: b64u(d), x, y }, pub: { alg: 'ES256', x, y } };
};
const toKey = (s: any, priv: boolean): any => {
  if (s.alg === 'EdDSA') return priv ? createPrivateKey({ key: Buffer.concat([PK8, Buffer.from(s.seed, 'base64url')]), format: 'der', type: 'pkcs8' }) : createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: s.pub }, format: 'jwk' });
  return priv ? createPrivateKey({ key: { kty: 'EC', crv: 'P-256', d: s.d, x: s.x, y: s.y }, format: 'jwk' }) : createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: s.x, y: s.y }, format: 'jwk' });
};
const E1 = edKey('eat/a'), E2 = edKey('eat/b'), S1 = esKey('eat/es-a');
const T0 = 1_800_000_000_000;
const NONCE = 'nonce-123.abc';
const CHAN = 'channel-exporter-1';
const jws = (header: any, payload: any, key: any = E1.priv, rawSig?: Uint8Array) => {
  const si = `${b64u(Buffer.from(typeof header === 'string' ? header : JSON.stringify(header)))}.${b64u(Buffer.from(typeof payload === 'string' ? payload : JSON.stringify(payload)))}`;
  const k = toKey(key, true);
  const sig = rawSig ?? new Uint8Array(key.alg === 'EdDSA' ? nodeSign(null, Buffer.from(si), k) : nodeSign('sha256', Buffer.from(si), { key: k, dsaEncoding: 'ieee-p1363' }));
  return `${si}.${b64u(sig)}`;
};
const HDR = { alg: 'EdDSA', typ: 'eat+jwt' };
const MEASURED = { model_id: 'm1', weights_digest: 'ab'.repeat(32), weights_measured: true, runtime_measurement: 'cd'.repeat(48), operator: 'ef'.repeat(64) };
const SEV = { version: 3, measurement: 'cd'.repeat(48), reported_tcb: '1234567890', guest_svn: 4, chip_id: 'ef'.repeat(64), debug: false };

const fixKeys = (a: any) => {
  const x = { ...a };
  if (x.key && x.key.alg) x.key = toKey(x.key, true);
  return x;
};
const vkOf = (opts: any) => {
  if (!opts || typeof opts !== 'object') return opts;
  const x = { ...opts };
  if (x.verifyKey && x.verifyKey.alg) x.verifyKey = toKey(x.verifyKey, false);
  return x;
};
const pqKeys = (spec: any): any => {
  const k: any = {};
  if (spec.ed) k.edSecret = bytes(spec.ed);
  if (spec.pq) {
    const sd = bytes(spec.pq.seed);
    if (spec.pq.prim === 'ml-dsa-65') k.mlDsa = P.mlDsa65Keygen(sd);
    if (spec.pq.prim === 'ml-dsa-87') k.mlDsa87 = P.mlDsa87Keygen(sd);
    if (spec.pq.prim === 'slh-dsa-sha2-128f') k.slhDsa = P.slhDsa128fKeygen(sd);
    if (spec.pq.prim === 'slh-dsa-sha2-256s') k.slhDsa256s = P.slhDsa256sKeygen(sd);
  }
  return k;
};
const proj = (r: any) => {
  const out: any = { ok: r.ok, hardwareRoot: r.hardwareRoot };
  if (r.reason !== undefined) out.reason = r.reason;
  if (r.evidence) out.evidence = r.evidence;
  if (r.measured) out.measured = r.measured;
  return out;
};
const REF: Record<string, (...a: any[]) => any> = {
  constants: () => ({
    EAT_TYP: M.EAT_TYP, DEFAULT_EAT_ALG: M.DEFAULT_EAT_ALG, DEFAULT_MAX_AGE_MS: M.DEFAULT_MAX_AGE_MS, CHANNEL_BINDING_DOMAIN: M.CHANNEL_BINDING_DOMAIN,
    AMD_SEV_SNP_SIGNED_REGION_END: M.AMD_SEV_SNP_SIGNED_REGION_END, AMD_SEV_SNP_HARDWARE_ROOT_LABEL: M.AMD_SEV_SNP_HARDWARE_ROOT_LABEL,
    KNOWN_REPORT_VERSIONS: M.KNOWN_REPORT_VERSIONS, KNOWN_AMD_ARK_SPKI_SHA384: M.KNOWN_AMD_ARK_SPKI_SHA384, AMD_MILAN_ARK_SPKI_SHA384: M.AMD_MILAN_ARK_SPKI_SHA384,
    PQCOSIGN_DOMAIN: M.PQCOSIGN_DOMAIN, DEFAULT_PQ_COSIGN_SUITE: M.DEFAULT_PQ_COSIGN_SUITE, PQ_COSIGN_SUITES: M.PQ_COSIGN_SUITES,
  }),
  deriveChannelCnf: (...a: any[]) => M.deriveChannelCnf(...a),
  bindChannel: (...a: any[]) => M.bindChannel(...a),
  buildEAT: (args: any) => M.buildEAT(fixKeys(args)),
  verifyEAT: (eat: any, pub: any, opts?: any) => M.verifyEAT(eat, toKey(pub, false), opts ?? {}),
  verifyFreshness: (c: any, opts: any) => M.verifyFreshness(c, opts),
  verifyChannelBinding: (c: any, opts: any) => M.verifyChannelBinding(c, opts),
  appraise: (...a: any[]) => M.appraise(...a),
  parseReportTolerant: (b: any) => {
    const r = M.parseReportTolerant(rev(b));
    const out: any = { ok: r.ok, version: r.version, known: r.known, degraded: r.degraded, notes: r.notes, hasReport: r.report !== undefined };
    if (r.evidence) out.evidence = r.evidence;
    if (r.report) out.measured = M.measuredFromReport(r.report);
    return out;
  },
  verifyAmdAttestation: async (b: any, opts: any) => proj(await M.verifyAmdAttestation(rev(b), rev(opts))),
  verifyFreshAttestedEAT: async (eat: any, opts: any) => {
    return M.verifyFreshAttestedEAT(eat, vkOf(rev(opts)));
  },
  canonicalVerdictBytes: (v: any, t: any) => M.canonicalVerdictBytes(v, t),
  verdictFromAppraisal: (r: any, c: any) => M.verdictFromAppraisal(r, c),
  isPqCoSignSuite: (x: any) => M.isPqCoSignSuite(x),
  coSignAttestation: (v: any, op: any) => M.coSignAttestation(v, { ...(op.suite !== undefined ? { suite: op.suite } : {}), secretKey: pqKeys(op.key), ...(op.now !== undefined ? { now: op.now } : {}) }),
  verifyCoSignedAttestation: (c: any, op?: any) => (op === undefined ? M.verifyCoSignedAttestation(c) : M.verifyCoSignedAttestation(c, op)),
  ed25519Jkt: (x: any) => M.ed25519Jkt(x),
  eatAdmissionEvidence: async (eat: any, op: any) => M.eatAdmissionEvidence(eat, vkOf(rev(op))),
  runtimeDigestFromEat: (v: any, op?: any) => (op === undefined ? M.runtimeDigestFromEat(v) : M.runtimeDigestFromEat(v, op)),
  issueArtifactDischarge: (i: any) => {
    ctr = 0;
    const r = M.issueArtifactDischarge({ ...i, roots: M.parseTrustedRoot(i.roots), issuerSecret: bytes(i.issuerKey.seed) , ...(i.runtime === undefined ? {} : {}) });
    return r;
  },
};
const add = async (fn: string, name: string, args: any[]) => {
  let nm = name;
  for (let k = 1; o.names.has(`${fn}/${nm}`); k++) nm = `${name}~${k}`;
  await o.run(fn, nm, REF[fn]!, args);
};
// ======================================================================================= small pure helpers
await add('constants', 'all', []);
for (const [c, t] of [['chan', undefined], ['chan', 'jkt-1'], ['chan', ''], ['', undefined], [5, undefined], [null, undefined], ['é😀', 'x'], ['a'.repeat(300), undefined]] as any[]) await add('deriveChannelCnf', `${JSON.stringify(c)}-${JSON.stringify(t)}`, t === undefined ? [c] : [c, t]);
for (const [ev, c, n] of [[{ a: 1 }, 'chan', 'n1'], [null, 'chan', 'n1'], [SEV, 'chan', ''], [SEV, 'chan', 5], [SEV, '', 'n'], [SEV, 'ch', 'n']] as any[]) await add('bindChannel', `${JSON.stringify(c)}-${JSON.stringify(n)}`, [ev, c, n]);
// ======================================================================================= buildEAT / verifyEAT
const BASE = { issuer: 'https://attester.example', key: E1.priv, nonce: NONCE, channelId: CHAN, now: T0 };
const FULL = { ...BASE, measured: MEASURED, sevsnp: SEV, measurements: [{ type: 'launch', value: 'cd'.repeat(48) }, { type: 'weights', value: 'ab'.repeat(32) }], ueid: 'ue1', sueid: 'su1', dbgstat: 'disabled', oemid: 'amd' };
const BUILDS: [string, any][] = [
  ['minimal channelId', BASE], ['full', FULL], ['channelBinding tls', { ...BASE, channelId: undefined, channelBinding: { tls_exporter: 'abc' } }],
  ['channelBinding jkt', { ...BASE, channelId: undefined, channelBinding: { jkt: 'tp' } }], ['both id and binding', { ...BASE, channelBinding: { tls_exporter: 'override', jkt: 'tp' } }],
  ['no now fixed alg', { ...BASE, alg: 'EdDSA' }], ['iat fraction', { ...BASE, now: T0 + 999 }], ['iat negative', { ...BASE, now: -5000 }], ['iat zero', { ...BASE, now: 0 }],
  ['unicode issuer', { ...BASE, issuer: 'é-iss ' }], ['measured only', { ...BASE, measured: MEASURED }], ['sevsnp degraded', { ...BASE, sevsnp: { version: 9, measurement: 'aa', degraded: true } }],
  ['tcb object', { ...BASE, sevsnp: { ...SEV, reported_tcb: { bootloader: 1, tee: 2, snp: 3, microcode: 4 } } }], ['tcb number', { ...BASE, sevsnp: { ...SEV, reported_tcb: 77 } }],
  ['null ueid', { ...BASE, ueid: null }], ['empty measurements', { ...BASE, measurements: [] }],
  ['no issuer', { ...BASE, issuer: '' }], ['issuer number', { ...BASE, issuer: 5 }], ['no nonce', { ...BASE, nonce: '' }], ['nonce number', { ...BASE, nonce: 5 }],
  ['no binding', { ...BASE, channelId: undefined }], ['empty binding', { ...BASE, channelId: undefined, channelBinding: {} }], ['binding non-string', { ...BASE, channelId: undefined, channelBinding: { tls_exporter: 5 } }],
  ['empty channelId', { ...BASE, channelId: '' }], ['alg bad', { ...BASE, alg: 'RS256' }], ['alg none', { ...BASE, alg: 'none' }], ['alg ES256 with Ed key', { ...BASE, alg: 'ES256' }],
  ['binding null', { ...BASE, channelId: undefined, channelBinding: null }],
];
for (const [n, a] of BUILDS) await add('buildEAT', n, [a]);
const TOK = (extra: any = {}) => REF.buildEAT!({ ...FULL, ...extra });
const GOOD = TOK();
const GOOD_ES = M.buildEAT({ ...FULL, alg: 'ES256', key: toKey(S1.priv, true) });
const payloadOf = (t: string) => JSON.parse(Buffer.from(t.split('.')[1]!, 'base64url').toString());
const PAY = payloadOf(GOOD);
const VE = async (n: string, tok: any, key: any = E1.pub, opts?: any) => add('verifyEAT', n, opts === undefined ? [tok, key] : [tok, key, opts]);
await VE('good', GOOD); await VE('good es256', GOOD_ES, S1.pub); await VE('es256 token ed key', GOOD_ES, E1.pub);
await VE('wrong key', GOOD, E2.pub); await VE('minimal', TOK({ measured: undefined, sevsnp: undefined, measurements: undefined, ueid: undefined, sueid: undefined, dbgstat: undefined, oemid: undefined }));
await VE('issuer ok', GOOD, E1.pub, { issuer: 'https://attester.example' }); await VE('issuer list ok', GOOD, E1.pub, { issuer: ['x', 'https://attester.example'] });
await VE('issuer wrong', GOOD, E1.pub, { issuer: 'other' }); await VE('issuer empty list', GOOD, E1.pub, { issuer: [] }); await VE('issuer null', GOOD, E1.pub, { issuer: null });
await VE('algorithms EdDSA', GOOD, E1.pub, { algorithms: ['EdDSA'] }); await VE('algorithms ES256 only', GOOD, E1.pub, { algorithms: ['ES256'] }); await VE('algorithms empty', GOOD, E1.pub, { algorithms: [] });
await VE('algorithms null', GOOD, E1.pub, { algorithms: null }); await VE('algorithms string', GOOD, E1.pub, { algorithms: 'EdDSA' });
await VE('typ custom ok', jws({ alg: 'EdDSA', typ: 'JWT' }, PAY), E1.pub, { typ: 'JWT' }); await VE('typ mismatch', jws({ alg: 'EdDSA', typ: 'JWT' }, PAY));
await VE('typ application form', jws({ alg: 'EdDSA', typ: 'application/eat+jwt' }, PAY)); await VE('typ upper', jws({ alg: 'EdDSA', typ: 'APPLICATION/EAT+JWT' }, PAY));
await VE('typ upper short', jws({ alg: 'EdDSA', typ: 'EAT+JWT' }, PAY)); await VE('typ missing', jws({ alg: 'EdDSA' }, PAY)); await VE('typ missing no require', jws({ alg: 'EdDSA' }, PAY), E1.pub, { requireTyp: false });
await VE('typ number', jws({ alg: 'EdDSA', typ: 5 }, PAY)); await VE('typ other slash', jws({ alg: 'EdDSA', typ: 'application/jwt' }, PAY)); await VE('requireTyp null', jws({ alg: 'EdDSA' }, PAY), E1.pub, { requireTyp: null });
await VE('typ opt number', GOOD, E1.pub, { typ: 5 });
for (const [n, h] of [['alg none', { alg: 'none', typ: 'eat+jwt' }], ['alg RS256', { alg: 'RS256', typ: 'eat+jwt' }], ['alg missing', { typ: 'eat+jwt' }], ['alg number', { alg: 5, typ: 'eat+jwt' }], ['alg lower', { alg: 'eddsa', typ: 'eat+jwt' }], ['extra member', { alg: 'EdDSA', typ: 'eat+jwt', kid: 'k' }]] as any[]) await VE(`header ${n}`, jws(h, PAY));
for (const [n, p] of [['no iss', { ...PAY, iss: undefined }], ['iss number', { ...PAY, iss: 5 }], ['no iat', { ...PAY, iat: undefined }], ['iat string', { ...PAY, iat: '5' }], ['iat fraction', { ...PAY, iat: 1.5 }], ['iat negative', { ...PAY, iat: -3 }],
  ['payload array', []], ['payload number', 5], ['payload null', null], ['cnf wrong type', { ...PAY, cnf: 'x' }], ['cnf empty', { ...PAY, cnf: {} }], ['cnf non-strings', { ...PAY, cnf: { tls_exporter: 5, jkt: [] } }],
  ['cnf partial', { ...PAY, cnf: { jkt: 'j', extra: 1 } }], ['nonce number', { ...PAY, eat_nonce: 5 }], ['measurements junk', { ...PAY, measurements: [1, null, { type: 'a' }, { type: 'a', value: 'b', x: 1 }] }], ['measurements all junk', { ...PAY, measurements: [1, 2] }],
  ['measurements not array', { ...PAY, measurements: 'x' }], ['dbgstat unknown', { ...PAY, dbgstat: 'maybe' }], ['dbgstat number', { ...PAY, dbgstat: 3 }], ['dbgstat each', { ...PAY, dbgstat: 'disabled-fully-and-permanently' }],
  ['measured partial', { ...PAY, measured: { model_id: 'm' } }], ['measured extras', { ...PAY, measured: { ...MEASURED, system_prompt_digest: 'sp', tool_manifest_digest: 'tm', weights_measured: 'yes', extra: 1 } }], ['measured null', { ...PAY, measured: null }],
  ['sevsnp no version', { ...PAY, sevsnp: { measurement: 'aa' } }], ['sevsnp version string', { ...PAY, sevsnp: { version: '3', measurement: 'aa' } }], ['sevsnp full junk fields', { ...PAY, sevsnp: { version: 3, measurement: 'aa', reported_tcb: true, guest_svn: 'x', chip_id: 5, debug: 'no', degraded: 1 } }],
  ['sevsnp tcb object partial', { ...PAY, sevsnp: { version: 3, measurement: 'aa', reported_tcb: { bootloader: 1, tee: 'x', other: 1 } } }], ['sevsnp tcb array', { ...PAY, sevsnp: { version: 3, measurement: 'aa', reported_tcb: [1] } }],
  ['ueid number', { ...PAY, ueid: 5, sueid: 6, oemid: 7 }], ['extra claims', { ...PAY, zzz: 1, exp: 5 }]] as any[]) await VE(`payload ${n}`, jws(HDR, p));
const parts = GOOD.split('.');
for (const [n, t] of [['not string', 5], ['null', null], ['empty', ''], ['two parts', `${parts[0]}.${parts[1]}`], ['four parts', `${GOOD}.x`], ['empty sig', `${parts[0]}.${parts[1]}.`], ['empty header', `.${parts[1]}.${parts[2]}`], ['padded sig', `${GOOD}=`],
  ['standard alphabet', GOOD.replace(/-/g, '+')], ['whitespace', ` ${GOOD}`], ['newline', `${GOOD}\n`], ['trailing bits', `${parts[0]}.${parts[1]}.${parts[2]!.slice(0, -1)}${parts[2]!.endsWith('A') ? 'B' : 'A'}`],
  ['header not json', `${b64u(Buffer.from('nope'))}.${parts[1]}.${parts[2]}`], ['header array', jws([], PAY)], ['header duplicate keys', jws('{"alg":"EdDSA","alg":"EdDSA","typ":"eat+jwt"}', PAY)],
  ['payload duplicate keys', jws(HDR, '{"iss":"a","iss":"b","iat":1}')], ['payload exponent number', jws(HDR, '{"iss":"a","iat":1e3}')], ['payload bom', jws(HDR, '﻿{"iss":"a","iat":1}')],
  ['sig tampered', `${parts[0]}.${parts[1]}.${b64u(Buffer.alloc(64, 1))}`], ['sig short', `${parts[0]}.${parts[1]}.${b64u(Buffer.alloc(10, 1))}`], ['payload tampered', `${parts[0]}.${b64u(Buffer.from(JSON.stringify({ ...PAY, iat: 5 })))}.${parts[2]}`],
  ['too long', `${parts[0]}.${b64u(Buffer.alloc((1 << 20) + 10, 65))}.${parts[2]}`]] as any[]) await VE(`token ${n}`, t);
{
  const r = rng(0xea7);
  for (let i = 0; i < 80; i++) {
    const c = GOOD.split('');
    const k = r.int(0, c.length - 1);
    c[k] = c[k] === 'A' ? 'B' : 'A';
    await VE(`flip${i}`, c.join(''));
  }
}
// ======================================================================================= freshness + channel binding
const CL = { iss: 'i', iat: T0 / 1000, eat_nonce: NONCE, cnf: M.deriveChannelCnf(CHAN) };
const VF = (n: string, c: any, op: any) => add('verifyFreshness', n, [c, op]);
const FO = { expectedNonce: NONCE, maxAgeMs: 60_000, now: T0 + 1000 };
await VF('ok', CL, FO); await VF('ok at max', CL, { ...FO, now: T0 + 60_000 }); await VF('stale by 1', CL, { ...FO, now: T0 + 60_001 }); await VF('future by 1', { ...CL, iat: T0 / 1000 + 2 }, { ...FO, now: T0 + 1000 });
await VF('skew allows future', { ...CL, iat: T0 / 1000 + 2 }, { ...FO, clockSkewMs: 1000 }); await VF('skew allows stale', CL, { ...FO, now: T0 + 61_000, clockSkewMs: 1000 }); await VF('skew too small', CL, { ...FO, now: T0 + 62_000, clockSkewMs: 1000 });
await VF('negative skew', { ...CL, iat: T0 / 1000 + 2 }, { ...FO, clockSkewMs: -5000 }); await VF('skew string number', { ...CL, iat: T0 / 1000 + 2 }, { ...FO, clockSkewMs: '5000' }); await VF('skew junk string', { ...CL, iat: T0 / 1000 + 2 }, { ...FO, clockSkewMs: 'abc' });
await VF('skew junk stale', CL, { ...FO, now: T0 + 999_999, clockSkewMs: 'abc' }); await VF('skew null', CL, { ...FO, clockSkewMs: null }); await VF('skew true', { ...CL, iat: T0 / 1000 + 2 }, { ...FO, clockSkewMs: true });
await VF('nonce mismatch', CL, { ...FO, expectedNonce: 'other' }); await VF('nonce empty expected', CL, { ...FO, expectedNonce: '' }); await VF('nonce number expected', CL, { ...FO, expectedNonce: 5 }); await VF('no eat_nonce', { ...CL, eat_nonce: undefined }, FO);
await VF('empty eat_nonce', { ...CL, eat_nonce: '' }, FO); await VF('nonce prefix', { ...CL, eat_nonce: NONCE + 'x' }, FO); await VF('nonce unicode', { ...CL, eat_nonce: 'é' }, { ...FO, expectedNonce: 'é' });
await VF('no iat', { ...CL, iat: undefined }, FO); await VF('iat string', { ...CL, iat: '5' }, FO); await VF('maxAge zero', CL, { ...FO, maxAgeMs: 0 }); await VF('maxAge negative', CL, { ...FO, maxAgeMs: -1 }); await VF('maxAge string', CL, { ...FO, maxAgeMs: '60000' });
await VF('maxAge missing', CL, { expectedNonce: NONCE, now: T0 }); await VF('maxAge huge', CL, { ...FO, maxAgeMs: 1e300 }); await VF('now missing uses clock', CL, { expectedNonce: NONCE, maxAgeMs: 1e15 }); await VF('now string uses clock', CL, { expectedNonce: NONCE, maxAgeMs: 1e15, now: '5' });
await VF('iat fraction', { ...CL, iat: T0 / 1000 + 0.5 }, FO);
const VC = (n: string, c: any, op: any) => add('verifyChannelBinding', n, [c, op]);
await VC('channelId ok', CL, { channelId: CHAN }); await VC('channelId wrong', CL, { channelId: 'other' }); await VC('expectedCnf ok', CL, { expectedCnf: CL.cnf }); await VC('expectedCnf jkt only missing', CL, { expectedCnf: { jkt: 'j' } });
await VC('jkt ok', { ...CL, cnf: { jkt: 'j' } }, { expectedCnf: { jkt: 'j' } }); await VC('jkt wrong', { ...CL, cnf: { jkt: 'j' } }, { expectedCnf: { jkt: 'k' } }); await VC('both ok', { ...CL, cnf: { ...CL.cnf, jkt: 'j' } }, { channelId: CHAN, expectedCnf: { jkt: 'j' } });
await VC('both jkt wrong', { ...CL, cnf: { ...CL.cnf, jkt: 'j' } }, { channelId: CHAN, expectedCnf: { jkt: 'x' } }); await VC('expectedCnf overrides channelId', CL, { channelId: 'other', expectedCnf: CL.cnf }); await VC('no expectation', CL, {});
await VC('empty expectedCnf', CL, { expectedCnf: {} }); await VC('empty channelId', CL, { channelId: '' }); await VC('expectedCnf null', CL, { expectedCnf: null }); await VC('expectedCnf string', CL, { expectedCnf: 'x' }); await VC('no cnf', { ...CL, cnf: undefined }, { channelId: CHAN });
await VC('empty cnf', { ...CL, cnf: {} }, { channelId: CHAN }); await VC('cnf string', { ...CL, cnf: 'x' }, { channelId: CHAN }); await VC('exporter mismatch', { ...CL, cnf: { tls_exporter: 'zzz' } }, { channelId: CHAN }); await VC('jkt only token vs exporter', { ...CL, cnf: { jkt: 'j' } }, { channelId: CHAN });
await VC('exporter only token vs jkt', CL, { expectedCnf: { tls_exporter: CL.cnf.tls_exporter, jkt: 'j' } });
// ======================================================================================= appraise
const CLAIMS = (x: any = {}) => ({ iss: 'https://attester.example', iat: 1, eat_nonce: 'n', measured: MEASURED, sevsnp: SEV, measurements: [{ type: 'launch', value: 'CD'.repeat(48) }, { type: 'weights', value: 'AB'.repeat(32) }], dbgstat: 'disabled', oemid: 'amd', ...x });
const RVS: any[] = [
  { measurements: ['cd'.repeat(48)] }, { measurements: ['CD'.repeat(48)] }, { measurements: ['00'.repeat(48)] }, { models: ['m1'] }, { models: ['m2'] }, { requireMeasuredWeights: true }, { weightsMeasurements: ['ab'.repeat(32)] }, { weightsMeasurements: ['00'] },
  { minTcb: '1234567890' }, { minTcb: '1234567891' }, { minTcb: 5 }, { minTcb: -1 }, { minTcb: 1.5 }, { minTcb: 'abc' }, { minTcb: '' }, { minTcb: ' 12 ' }, { minTcb: { bootloader: 1 } }, { minTcb: { bootloader: 300 } }, { minTcb: { tee: -0 } }, { minTcb: {} },
  { minTcb: { bootloader: 1, tee: 2, snp: 3, microcode: 4 } }, { minTcb: null }, { minTcb: true }, { minTcb: [] }, { minTcb: 1e21 }, { minGuestSvn: 4 }, { minGuestSvn: 5 }, { minGuestSvn: 0 }, { requireDebugDisabled: true }, { requireDebugDisabled: false },
  { measurements: [] }, {}, { measurements: ['cd'.repeat(48), 5] }, { measurements: [5] }, { models: [5] }, { requireMeasuredWeights: 'yes' }, { measurements: 'x' },
  { measurements: ['cd'.repeat(48)], models: ['m1'], requireMeasuredWeights: true, weightsMeasurements: ['ab'.repeat(32)], minTcb: '1', minGuestSvn: 1, requireDebugDisabled: true },
];
const ENS: any[] = [{}, { issuers: ['https://attester.example'] }, { issuers: ['x'] }, { oemids: ['amd'] }, { oemids: ['intel'] }, { operators: ['ef'.repeat(64)] }, { operators: ['nope'] }, { issuers: [] }, { issuers: [5] }, { issuers: ['https://attester.example'], oemids: ['amd'], operators: ['ef'.repeat(64)] }, { issuers: 'x' }];
const EXT: any[] = [undefined, {}, { hardwareVerified: true }, { hardwareVerified: true, hardwareRootLabel: 'custom' }, { hardwareVerified: 'yes' }, { hardwareVerified: true, hardwareRootLabel: null }];
const CLS: any[] = [CLAIMS(), CLAIMS({ sevsnp: { ...SEV, degraded: true } }), CLAIMS({ dbgstat: 'enabled' }), CLAIMS({ dbgstat: undefined, sevsnp: { ...SEV, debug: true } }), CLAIMS({ dbgstat: undefined, sevsnp: { ...SEV, debug: undefined } }),
  CLAIMS({ measured: undefined }), CLAIMS({ sevsnp: undefined }), CLAIMS({ measured: { ...MEASURED, weights_measured: false } }), CLAIMS({ measured: { ...MEASURED, runtime_measurement: '' }, sevsnp: SEV }), CLAIMS({ measured: undefined, sevsnp: undefined }),
  CLAIMS({ measured: undefined, sevsnp: undefined, measurements: undefined }), CLAIMS({ sevsnp: { ...SEV, reported_tcb: { bootloader: 1, tee: 2, snp: 3, microcode: 4 } } }), CLAIMS({ sevsnp: { ...SEV, reported_tcb: 99999999999 } }), CLAIMS({ sevsnp: { ...SEV, reported_tcb: 'x' } }),
  CLAIMS({ sevsnp: { ...SEV, reported_tcb: undefined } }), CLAIMS({ sevsnp: { ...SEV, guest_svn: undefined } }), CLAIMS({ oemid: undefined }), CLAIMS({ measured: { ...MEASURED, operator: '' } }), CLAIMS({ dbgstat: null }), CLAIMS({ measurements: [{ type: 'measurement', value: 'cd'.repeat(48) }], measured: undefined, sevsnp: undefined }),
  CLAIMS({ measured: { ...MEASURED, weights_digest: '' }, measurements: [{ type: 'weights', value: 'ab'.repeat(32) }] }), CLAIMS({ iss: 5 }), CLAIMS({ measurements: 'x' })];
let ai = 0;
for (const cl of CLS) await add('appraise', `bare${ai++}`, [cl]);
{
  const r = rng(0xa99);
  for (let i = 0; i < 700; i++) {
    const cl = r.pick(CLS), rv = r.pick(RVS), en = r.pick(ENS), ex = r.pick(EXT);
    const args = ex === undefined ? [cl, rv, en] : [cl, rv, en, ex];
    await add('appraise', `mix${i}`, args);
  }
  for (const rv of RVS) for (const cl of [CLS[0], CLS[1], CLS[2]]) await add('appraise', `each${ai++}`, [cl, rv, {}, {}]);
  for (const en of ENS) await add('appraise', `en${ai++}`, [CLS[0], {}, en]);
  await add('appraise', 'no policy args', [CLS[0], {}, {}]); await add('appraise', 'null rv', [CLS[0], null, ENS[1]]); await add('appraise', 'null en', [CLS[0], RVS[0], null]);
}
// ======================================================================================= tolerant parse + AMD
const PCA = new URL('../../../packages/pca/', import.meta.url).pathname;
const genoaCerts = JSON.parse(readFileSync(PCA + 'fixtures/real-azure-maa/sevsnp-amd-certs.json', 'utf8'));
const PEM = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
const [gAsk, gArk] = genoaCerts.certificateChain.match(PEM) as [string, string];
const GENOA = new Uint8Array(readFileSync(PCA + 'fixtures/real-azure-maa/sevsnp-hcl-report.bin').subarray(32, 32 + 1184));
const mChain = readFileSync(PCA + 'testdata/sevsnp-real/chain.pem', 'utf8').match(PEM) as [string, string];
const MILAN = new Uint8Array(readFileSync(PCA + 'testdata/sevsnp-real/snp_report.bin'));
const mVcek = new Uint8Array(readFileSync(PCA + 'testdata/sevsnp-real/vcek.der'));
const flipAt = (u: Uint8Array, k: number) => { const c = Uint8Array.from(u); c[k] ^= 1; return c; };
const withVersion = (u: Uint8Array, v: number) => { const c = Uint8Array.from(u); new DataView(c.buffer).setUint32(0, v, true); return c; };
for (const [n, b] of [['genoa', GENOA], ['milan', MILAN], ['genoa v2', withVersion(GENOA, 2)], ['genoa v5', withVersion(GENOA, 5)], ['genoa v7 unknown', withVersion(GENOA, 7)], ['genoa v0', withVersion(GENOA, 0)], ['genoa short 800', GENOA.subarray(0, 800)],
  ['genoa 816 exact', GENOA.subarray(0, 816)], ['genoa 815', GENOA.subarray(0, 815)], ['genoa 0x1e0', GENOA.subarray(0, 0x1e0)], ['genoa 0x1a0', GENOA.subarray(0, 0x1a0)], ['genoa 0xc0', GENOA.subarray(0, 0xc0)], ['genoa 0x90', GENOA.subarray(0, 0x90)], ['genoa 0x80', GENOA.subarray(0, 0x80)],
  ['genoa 5', GENOA.subarray(0, 5)], ['genoa 4', GENOA.subarray(0, 4)], ['genoa 3', GENOA.subarray(0, 3)], ['empty', new Uint8Array(0)], ['zeros 1184', new Uint8Array(1184)], ['zeros 0x330 v3', withVersion(new Uint8Array(0x330), 3)], ['genoa debug', (() => { const c = Uint8Array.from(GENOA); c[0x8 + 2] |= 0x08; return c; })()],
  ['genoa trailing', Uint8Array.from([...GENOA, 1, 2, 3])], ['v9 short', withVersion(GENOA.subarray(0, 0x1a8), 9)]] as any[]) await add('parseReportTolerant', n, [B(b)]);
const AMDO = (x: any = {}) => ({ vcek: genoaCerts.vcekCert, ask: gAsk, ark: gArk, family: 'genoa', nowMs: Date.parse('2026-10-08T12:00:00Z'), ...x });
const MILO = (x: any = {}) => ({ vcek: B(mVcek), ask: mChain[0], ark: mChain[1], family: 'milan', nowMs: Date.parse('2026-10-08T12:00:00Z'), ...x });
const der = (pem: string) => B(new Uint8Array(new crypto.X509Certificate(pem).raw));
const MEAS_G = Buffer.from(GENOA.subarray(0x90, 0x90 + 48)).toString('hex');
const AM: [string, any, any][] = [
  ['genoa ok', GENOA, AMDO()], ['genoa der', GENOA, AMDO({ vcek: der(genoaCerts.vcekCert), ask: der(gAsk), ark: der(gArk) })], ['milan ok', MILAN, MILO()], ['genoa wrong family milan', GENOA, AMDO({ family: 'milan' })], ['genoa wrong family turin', GENOA, AMDO({ family: 'turin' })],
  ['family unknown', GENOA, AMDO({ family: 'rome' })], ['family null', GENOA, AMDO({ family: null })], ['family number', GENOA, AMDO({ family: 5 })], ['both family and pin', GENOA, AMDO({ trustAnchorArkSpkiSha384: 'aa' })], ['neither', GENOA, (() => { const x: any = AMDO(); delete x.family; return x; })()],
  ['explicit pin ok', GENOA, (() => { const x: any = AMDO(); delete x.family; x.trustAnchorArkSpkiSha384 = M.KNOWN_AMD_ARK_SPKI_SHA384.genoa; return x; })()], ['explicit pin upper', GENOA, (() => { const x: any = AMDO(); delete x.family; x.trustAnchorArkSpkiSha384 = M.KNOWN_AMD_ARK_SPKI_SHA384.genoa.toUpperCase(); return x; })()],
  ['explicit pin wrong', GENOA, (() => { const x: any = AMDO(); delete x.family; x.trustAnchorArkSpkiSha384 = '00'.repeat(48); return x; })()],
  ['expected measurement ok', GENOA, AMDO({ expectedMeasurement: MEAS_G })], ['expected measurement upper', GENOA, AMDO({ expectedMeasurement: MEAS_G.toUpperCase() })], ['expected measurement wrong', GENOA, AMDO({ expectedMeasurement: '00'.repeat(48) })],
  ['expected measurement empty', GENOA, AMDO({ expectedMeasurement: '' })], ['expected measurement number', GENOA, AMDO({ expectedMeasurement: 5 })], ['allowDebug', GENOA, AMDO({ allowDebug: true })], ['allowDebug string', GENOA, AMDO({ allowDebug: 'true' })],
  ['not yet valid', GENOA, AMDO({ nowMs: Date.parse('2001-01-01T00:00:00Z') })], ['expired', GENOA, AMDO({ nowMs: Date.parse('2200-01-01T00:00:00Z') })], ['skew rescues nothing', GENOA, AMDO({ nowMs: Date.parse('2200-01-01T00:00:00Z'), clockSkewMs: 1000 })],
  ['skew negative', GENOA, AMDO({ clockSkewMs: -1 })], ['skew string', GENOA, AMDO({ clockSkewMs: '5' })], ['skew huge', GENOA, AMDO({ nowMs: Date.parse('2200-01-01T00:00:00Z'), clockSkewMs: 1e13 })],
  ['tampered report sig', flipAt(GENOA, 0x2a0 + 3), AMDO()], ['tampered measurement', flipAt(GENOA, 0x90), AMDO()], ['tampered chip id', flipAt(GENOA, 0x1a0 + 5), AMDO()], ['tampered tcb', flipAt(GENOA, 0x180), AMDO()], ['reserved byte', flipAt(GENOA, 0x2a0 + 60), AMDO()],
  ['trailing byte', Uint8Array.from([...GENOA, 0]), AMDO()], ['short report', GENOA.subarray(0, 100), AMDO()], ['empty report', new Uint8Array(0), AMDO()],
  ['vcek two pems', GENOA, AMDO({ vcek: genoaCerts.vcekCert + genoaCerts.vcekCert })], ['vcek empty string', GENOA, AMDO({ vcek: '' })], ['ask is ark', GENOA, AMDO({ ask: gArk })],
  ['ask ark swapped', GENOA, AMDO({ ask: gArk, ark: gAsk })], ['nowMs missing', GENOA, (() => { const x: any = AMDO(); delete x.nowMs; return x; })()], ['milan vcek wrong chain', MILAN, MILO({ ask: gAsk, ark: gArk })],
  ['milan under genoa pin', MILAN, MILO({ family: 'genoa' })], ['milan tampered', flipAt(MILAN, 0x2a0 + 3), MILO()], ['milan expected measurement', MILAN, MILO({ expectedMeasurement: Buffer.from(MILAN.subarray(0x90, 0x90 + 48)).toString('hex') })],
];
for (const [n, b, op] of AM) await add('verifyAmdAttestation', n, [B(b), op]);
// ======================================================================================= verifyFreshAttestedEAT
const NOWV = T0 + 1000;
const mkEat = (extra: any = {}, key: any = E1.priv) => REF.buildEAT!({ ...FULL, key, ...extra });
const VO = (x: any = {}) => ({ verifyKey: E1.pub, nonce: NONCE, channelId: CHAN, policy: { referenceValues: { measurements: ['cd'.repeat(48)] } }, now: NOWV, ...x });
const VFA = async (n: string, eat: any, op: any) => add('verifyFreshAttestedEAT', n, [eat, op]);
await VFA('ok affirming', GOOD, VO());
await VFA('ok es256', GOOD_ES, VO({ verifyKey: S1.pub }));
for (const [n, x] of [['wrong key', { verifyKey: E2.pub }], ['nonce wrong', { nonce: 'other' }], ['nonce missing', { nonce: undefined }], ['channel wrong', { channelId: 'other' }], ['no channel expectation', { channelId: undefined }], ['channelBinding jkt', { channelId: undefined, channelBinding: { jkt: 'j' } }],
  ['channelBinding null', { channelId: undefined, channelBinding: null }], ['stale', { now: T0 + 400_000 }], ['maxAge custom', { maxAgeMs: 500 }], ['maxAge null', { maxAgeMs: null }], ['skew', { now: T0 - 500, clockSkewMs: 1000 }], ['issuer ok', { issuer: 'https://attester.example' }],
  ['issuer wrong', { issuer: 'other' }], ['algorithms ES256 only', { algorithms: ['ES256'] }], ['typ wrong', { typ: 'JWT' }], ['requireTyp false', { requireTyp: false }], ['policy empty', { policy: {} }], ['policy missing', { policy: undefined }], ['policy null', { policy: null }],
  ['policy models', { policy: { referenceValues: { models: ['m1'] } } }], ['policy bad models', { policy: { referenceValues: { models: ['zz'] } } }], ['policy endorsements', { policy: { endorsements: { issuers: ['https://attester.example'], oemids: ['amd'] } } }],
  ['policy endorsements bad', { policy: { endorsements: { issuers: ['nope'] } } }], ['policy debug required', { policy: { referenceValues: { requireDebugDisabled: true } } }], ['policy tcb', { policy: { referenceValues: { minTcb: '1234567890' } } }], ['policy tcb high', { policy: { referenceValues: { minTcb: '9999999999' } } }]] as any[]) await VFA(n, GOOD, VO(x));
await VFA('degraded evidence warning', mkEat({ sevsnp: { version: 9, measurement: 'cd'.repeat(48), degraded: true }, measured: undefined }), VO());
await VFA('no cnf token', jws(HDR, { ...PAY, cnf: undefined }), VO()); await VFA('no nonce token', jws(HDR, { ...PAY, eat_nonce: undefined }), VO()); await VFA('garbage token', 'garbage', VO());
{
  // the AMD cases need a token whose clock is near the AMD fixture clock
  const NOWA = Date.parse('2026-10-08T12:00:00Z');
  const tokA = REF.buildEAT!({ ...FULL, now: NOWA - 1000, measured: { ...MEASURED, runtime_measurement: MEAS_G }, sevsnp: { ...SEV, measurement: MEAS_G } });
  const AMDI = { rawReport: B(GENOA), vcek: genoaCerts.vcekCert, ask: gAsk, ark: gArk, family: 'genoa' };
  await VFA('hw-rooted ok', tokA, VO({ now: NOWA, amd: AMDI, policy: { referenceValues: { measurements: [MEAS_G] } } }));
  await VFA('hw-rooted bad family', tokA, VO({ now: NOWA, amd: { ...AMDI, family: 'turin' }, policy: { referenceValues: { measurements: [MEAS_G] } } }));
  await VFA('hw-rooted tampered', tokA, VO({ now: NOWA, amd: { ...AMDI, rawReport: B(flipAt(GENOA, 0x2a0 + 3)) }, policy: { referenceValues: { measurements: [MEAS_G] } } }));
  await VFA('hw-rooted der certs', tokA, VO({ now: NOWA, amd: { ...AMDI, vcek: der(genoaCerts.vcekCert), ask: der(gAsk), ark: der(gArk) }, policy: { referenceValues: { measurements: [MEAS_G] } } }));
  await VFA('hw-rooted policy fail contraindicated', tokA, VO({ now: NOWA, amd: AMDI, policy: { referenceValues: { measurements: ['00'.repeat(48)] } } }));
  await VFA('hw-rooted debug claim', tokA, VO({ now: NOWA, amd: AMDI, policy: { referenceValues: { measurements: [MEAS_G], requireDebugDisabled: true } } }));
  for (const [n, am] of [['no pin', { ...AMDI, family: undefined }], ['null', null], ['empty', {}], ['bad report', { ...AMDI, rawReport: 'x' }], ['expected override', { ...AMDI, expectedMeasurement: MEAS_G }], ['expected wrong', { ...AMDI, expectedMeasurement: '00'.repeat(48) }], ['allowDebug', { ...AMDI, allowDebug: true }], ['skew', { ...AMDI, clockSkewMs: 5 }], ['skew junk', { ...AMDI, clockSkewMs: 'x' }]] as any[])
    await VFA(`amd ${n}`, tokA, VO({ now: NOWA, amd: am, policy: { referenceValues: { measurements: [MEAS_G] } } }));
  await VFA('hw-rooted clock stale', tokA, VO({ now: NOWA + 600_000, amd: AMDI, policy: { referenceValues: { measurements: [MEAS_G] } } }));
}
// ======================================================================================= post-quantum co-signature
const VERDICT = { tier: 'affirming-hw-rooted', trustworthy: true, measured: MEASURED, measurement: 'cd'.repeat(48), nonce: NONCE, iat: 1_800_000_000, issuer: 'https://attester.example' };
const CV = (n: string, v: any, t: any) => add('canonicalVerdictBytes', n, [v, t]);
for (const [n, v] of [['full', VERDICT], ['minimal', { tier: 'affirming', trustworthy: false }], ['no measured', { ...VERDICT, measured: undefined }], ['measured extras', { ...VERDICT, measured: { ...MEASURED, system_prompt_digest: 'sp', tool_manifest_digest: 'tm' } }],
  ['measured partial', { ...VERDICT, measured: { model_id: 'm' } }], ['measured null', { ...VERDICT, measured: null }], ['measured string', { ...VERDICT, measured: 'x' }], ['trustworthy string', { ...VERDICT, trustworthy: 'true' }], ['trustworthy missing', { tier: 'x' }], ['tier missing', { trustworthy: true }],
  ['tier number', { ...VERDICT, tier: 5 }], ['tier null', { ...VERDICT, tier: null }], ['measurement number', { ...VERDICT, measurement: 5 }], ['nonce number', { ...VERDICT, nonce: 5 }], ['iat fraction', { ...VERDICT, iat: 1.5 }], ['iat string', { ...VERDICT, iat: '1' }], ['iat negative', { ...VERDICT, iat: -1 }],
  ['unicode', { ...VERDICT, issuer: 'é 😀"\\' }], ['extra members ignored', { ...VERDICT, extra: 1 }], ['measured weights_measured string', { ...VERDICT, measured: { ...MEASURED, weights_measured: 'x' } }]] as any[]) { await CV(n, v, T0); }
await CV('cosignedAt zero', VERDICT, 0); await CV('cosignedAt fraction', VERDICT, 1.5); await CV('cosignedAt negative', VERDICT, -5); await CV('cosignedAt string', VERDICT, 'x'); await CV('cosignedAt big', VERDICT, 9007199254740991);
for (const x of ['ml-dsa-65', 'ml-dsa-87', 'slh-dsa-sha2-128f', 'slh-dsa-sha2-256s', 'hybrid-ed25519-ml-dsa-65', 'hybrid-nested-ed25519-ml-dsa-65', 'hybrid-ed25519-ml-dsa-87', 'hybrid-ed25519-slh-dsa-sha2-128f', 'hybrid-ed25519-slh-dsa-sha2-256s', 'ed25519', 'fn-dsa-512', 'less-cat1', '', 'ML-DSA-65', 5, null, undefined, {}, ['ml-dsa-65']])
  await add('isPqCoSignSuite', JSON.stringify(x) ?? 'undefined', [x]);
const AP = { tier: 'affirming-hw-rooted', trustworthy: true, reasons: ['x'] };
const VC1 = { iss: 'i', iat: 100, eat_nonce: 'n1', measured: MEASURED, sevsnp: SEV };
for (const [n, r, c] of [['full', AP, VC1], ['no measured', AP, { ...VC1, measured: undefined }], ['empty runtime falls to sevsnp', AP, { ...VC1, measured: { ...MEASURED, runtime_measurement: '' } }], ['no sevsnp no measured', AP, { iss: 'i', iat: 1 }],
  ['iat string', AP, { ...VC1, iat: '5' }], ['nonce number', AP, { ...VC1, eat_nonce: 5 }], ['iss number', AP, { ...VC1, iss: 5 }], ['rejected', { tier: 'rejected', trustworthy: false, reasons: [] }, VC1], ['sevsnp empty measurement', AP, { iss: 'i', iat: 1, sevsnp: { ...SEV, measurement: '' } }]] as any[]) await add('verdictFromAppraisal', n, [r, c]);
const KED = (i: number) => B(seed(`eat/pq-ed/${i}`)).$bytes;
const KEYS: Record<string, any> = {
  'ml-dsa-65': { pq: { prim: 'ml-dsa-65', seed: b64u(seed('eat/pq/ml65')) } }, 'ml-dsa-87': { pq: { prim: 'ml-dsa-87', seed: b64u(seed('eat/pq/ml87')) } },
  'slh-dsa-sha2-128f': { pq: { prim: 'slh-dsa-sha2-128f', seed: b64u(Buffer.concat([seed('eat/pq/slh128/a'), seed('eat/pq/slh128/b')]).subarray(0, 48)) } },
  'slh-dsa-sha2-256s': { pq: { prim: 'slh-dsa-sha2-256s', seed: b64u(Buffer.concat([seed('eat/pq/slh256/a'), seed('eat/pq/slh256/b'), seed('eat/pq/slh256/c')]).subarray(0, 96)) } },
};
const SUITE_KEY = (s: string) => {
  const pqName = s.includes('ml-dsa-87') ? 'ml-dsa-87' : s.includes('ml-dsa-65') ? 'ml-dsa-65' : s.includes('slh-dsa-sha2-128f') ? 'slh-dsa-sha2-128f' : 'slh-dsa-sha2-256s';
  return { ...(s.startsWith('hybrid') ? { ed: KED(1) } : {}), pq: KEYS[pqName].pq };
};
const SUITES: string[] = M.PQ_COSIGN_SUITES;
const signed: Record<string, any> = {};
for (const s of SUITES) {
  const op = { suite: s, key: SUITE_KEY(s), now: T0 };
  await add('coSignAttestation', s, [VERDICT, op]);
  signed[s] = M.coSignAttestation(VERDICT, { suite: s, secretKey: pqKeys(op.key), now: T0 });
}
await add('coSignAttestation', 'default suite', [VERDICT, { key: KEYS['ml-dsa-65'], now: T0 }]);
for (const [n, v, op] of [['minimal verdict', { tier: 'affirming', trustworthy: false }, { key: KEYS['ml-dsa-65'], now: T0 }], ['no pq key', VERDICT, { key: {}, now: T0 }], ['hybrid missing ed', VERDICT, { suite: 'hybrid-ed25519-ml-dsa-65', key: KEYS['ml-dsa-65'], now: T0 }],
  ['ed25519 refused', VERDICT, { suite: 'ed25519', key: { ed: KED(1) }, now: T0 }], ['unknown suite', VERDICT, { suite: 'nope', key: KEYS['ml-dsa-65'], now: T0 }], ['wrong key for suite', VERDICT, { suite: 'ml-dsa-87', key: KEYS['ml-dsa-65'], now: T0 }],
  ['now fraction', VERDICT, { key: KEYS['ml-dsa-65'], now: 1.5 }]] as any[]) await add('coSignAttestation', n, [v, op]);
const VCS = (n: string, c: any, op?: any) => add('verifyCoSignedAttestation', n, op === undefined ? [c] : [c, op]);
const S65 = signed['ml-dsa-65'], SH = signed['hybrid-ed25519-ml-dsa-65'], SN = signed['hybrid-nested-ed25519-ml-dsa-65'], S128 = signed['slh-dsa-sha2-128f'];
for (const s of SUITES) await VCS(`valid ${s}`, signed[s], { now: T0 + 1000 });
await VCS('valid no opts', S65); await VCS('valid expected string', S65, { now: T0, expectedSigner: S65.signer_pub.pq }); await VCS('valid expected pair', SH, { now: T0, expectedSigner: SH.signer_pub });
await VCS('expected pair pq only', SH, { now: T0, expectedSigner: { pq: SH.signer_pub.pq } }); await VCS('expected wrong string', S65, { now: T0, expectedSigner: 'AAAA' }); await VCS('expected wrong ed', SH, { now: T0, expectedSigner: { pq: SH.signer_pub.pq, ed: 'AAAA' } });
await VCS('expected ed missing in artifact', S65, { now: T0, expectedSigner: { pq: S65.signer_pub.pq, ed: 'AAAA' } }); await VCS('expected null', S65, { now: T0, expectedSigner: null }); await VCS('expected number', S65, { now: T0, expectedSigner: 5 }); await VCS('expected empty object', S65, { now: T0, expectedSigner: {} });
await VCS('age ok', S65, { now: T0 + 1000, maxAgeMs: 1000 }); await VCS('age stale by 1', S65, { now: T0 + 1001, maxAgeMs: 1000 }); await VCS('age future', S65, { now: T0 - 1, maxAgeMs: 1000 }); await VCS('maxAge zero', S65, { now: T0, maxAgeMs: 0 });
await VCS('maxAge negative', S65, { now: T0, maxAgeMs: -1 }); await VCS('maxAge string', S65, { now: T0, maxAgeMs: '5' }); await VCS('maxAge null', S65, { now: T0, maxAgeMs: null }); await VCS('no maxAge future ok', S65, { now: T0 - 5000 });
await VCS('now fraction', S65, { now: T0 + 0.5, maxAgeMs: 10 }); await VCS('now string uses clock', S65, { now: 'x' });
for (const [n, mut] of [['tier', (c: any) => (c.verdict.tier = 'affirming')], ['trustworthy', (c: any) => (c.verdict.trustworthy = false)], ['nonce', (c: any) => (c.verdict.nonce = 'z')], ['measurement', (c: any) => (c.verdict.measurement = 'aa')], ['measured', (c: any) => (c.verdict.measured.operator = 'z')],
  ['cosignedAt', (c: any) => (c.cosig.cosignedAt += 1)], ['sig flip', (c: any) => (c.cosig.sig = c.cosig.sig.replace(/^./, (x: string) => (x === 'A' ? 'B' : 'A')))], ['sig short', (c: any) => (c.cosig.sig = c.cosig.sig.slice(0, -4))], ['sig number', (c: any) => (c.cosig.sig = 5)],
  ['pq key swapped', (c: any) => (c.signer_pub.pq = S128.signer_pub.pq)], ['pq key empty', (c: any) => (c.signer_pub.pq = '')], ['pq key number', (c: any) => (c.signer_pub.pq = 5)], ['signer_pub null', (c: any) => (c.signer_pub = null)], ['signer_pub array', (c: any) => (c.signer_pub = [])],
  ['suite ed25519', (c: any) => (c.suite = 'ed25519')], ['suite unknown', (c: any) => (c.suite = 'x')], ['suite number', (c: any) => (c.suite = 5)], ['suite null', (c: any) => (c.suite = null)], ['suite missing', (c: any) => delete c.suite], ['suite swapped', (c: any) => (c.suite = 'ml-dsa-87')],
  ['verdict null', (c: any) => (c.verdict = null)], ['verdict tier number', (c: any) => (c.verdict.tier = 5)], ['verdict trustworthy string', (c: any) => (c.verdict.trustworthy = 'true')], ['cosig null', (c: any) => (c.cosig = null)], ['cosignedAt string', (c: any) => (c.cosig.cosignedAt = '5')],
  ['cosignedAt missing', (c: any) => delete c.cosig.cosignedAt], ['extra pq_sig on pure', (c: any) => (c.cosig.pq_sig = c.cosig.sig)], ['extra member', (c: any) => (c.zzz = 1)]] as any[]) {
  const c = JSON.parse(JSON.stringify(S65));
  mut(c);
  await VCS(`mutated ${n}`, c, { now: T0 + 5 });
}
for (const [n, mut] of [['pq_sig missing', (c: any) => delete c.cosig.pq_sig], ['pq_sig flip', (c: any) => (c.cosig.pq_sig = c.cosig.pq_sig.replace(/^./, (x: string) => (x === 'A' ? 'B' : 'A')))], ['ed missing', (c: any) => delete c.signer_pub.ed], ['ed wrong', (c: any) => (c.signer_pub.ed = S65.cosig.sig.slice(0, 43))],
  ['sig swapped with pq_sig', (c: any) => ([c.cosig.sig, c.cosig.pq_sig] = [c.cosig.pq_sig, c.cosig.sig])], ['tier', (c: any) => (c.verdict.tier = 'warning')], ['ed empty', (c: any) => (c.signer_pub.ed = '')], ['pq_sig number', (c: any) => (c.cosig.pq_sig = 5)]] as any[]) {
  for (const [sn, base] of [['hybrid', SH], ['nested', SN]] as any[]) { const c = JSON.parse(JSON.stringify(base)); mut(c); await VCS(`mutated ${sn} ${n}`, c, { now: T0 + 5 }); }
}
{
  const c = JSON.parse(JSON.stringify(SN));
  c.suite = 'hybrid-ed25519-ml-dsa-65'; await VCS('nested as plain hybrid', c, { now: T0 }); const d = JSON.parse(JSON.stringify(SH)); d.suite = 'hybrid-nested-ed25519-ml-dsa-65'; await VCS('plain hybrid as nested', d, { now: T0 });
  const e = JSON.parse(JSON.stringify(S128)); e.cosig.cosignedAt += 1; await VCS('slh tampered time', e, { now: T0 + 5 });
  for (const x of [null, 5, 'x', [], {}]) await VCS(`artifact ${JSON.stringify(x)}`, x, { now: T0 });
}
// ======================================================================================= admission
for (const x of ['', 'AAAA', E1.pub.pub, 'é', 'a"b', 'x'.repeat(100)]) await add('ed25519Jkt', JSON.stringify(x), [x]);
const INST = E2.pub.pub;
const JKT = M.ed25519Jkt(INST);
const ADM = (x: any = {}) => ({ verifyKey: E1.pub, nonce: NONCE, instanceKey: INST, policy: { referenceValues: { measurements: ['cd'.repeat(48)] } }, now: NOWV, ...x });
const adToken = (extra: any = {}) => REF.buildEAT!({ ...FULL, channelId: undefined, channelBinding: { jkt: JKT }, ...extra });
const AD = (n: string, eat: any, op: any) => add('eatAdmissionEvidence', n, [eat, op]);
await AD('ok', adToken(), ADM()); await AD('ok no measured', adToken({ measured: undefined }), ADM()); await AD('wrong instance key', adToken(), ADM({ instanceKey: E1.pub.pub })); await AD('unbound token', GOOD, ADM()); await AD('bad signature', adToken(), ADM({ verifyKey: E2.pub }));
await AD('stale', adToken(), ADM({ now: T0 + 900_000 })); await AD('nonce wrong', adToken(), ADM({ nonce: 'x' })); await AD('empty policy', adToken(), ADM({ policy: {} })); await AD('policy missing', adToken(), ADM({ policy: undefined }));
await AD('degraded below min', adToken({ sevsnp: { version: 9, measurement: 'cd'.repeat(48), degraded: true }, measured: undefined }), ADM()); await AD('min tier hw-rooted', adToken(), ADM({ minTier: 'affirming-hw-rooted' })); await AD('min tier unknown', adToken(), ADM({ minTier: 'bogus' }));
await AD('min tier null', adToken(), ADM({ minTier: null })); await AD('min tier affirming', adToken(), ADM({ minTier: 'affirming' })); await AD('policy contraindicated', adToken(), ADM({ policy: { referenceValues: { measurements: ['00'.repeat(48)] } } }));
await AD('instance key number', adToken(), ADM({ instanceKey: 5 })); await AD('instance key missing', adToken(), ADM({ instanceKey: undefined })); await AD('garbage token', 'x', ADM()); await AD('token number', 5, ADM());
await AD('issuer wrong', adToken(), ADM({ issuer: 'other' })); await AD('channelId extra ignored by omit', adToken(), ADM({ channelId: 'ignored' })); await AD('es256 token', M.buildEAT({ ...FULL, alg: 'ES256', key: toKey(S1.priv, true), channelId: undefined, channelBinding: { jkt: JKT } }), ADM({ verifyKey: S1.pub }));
// ======================================================================================= provenance
const FIXD = new URL('../../../packages/pca-attest-eat/test-fixtures/sigstore/', import.meta.url).pathname;
const ROOTS = JSON.parse(readFileSync(FIXD + 'trusted_root.json', 'utf8'));
const ATT = JSON.parse(readFileSync(FIXD + 'npm-sigstore-5.0.0.attestations.json', 'utf8')).attestations as { predicateType: string; bundle: unknown }[];
const SLSA = ATT.find((a) => a.predicateType === 'https://slsa.dev/provenance/v1')!.bundle;
const H64 = 'ab'.repeat(32), H128 = 'cd'.repeat(64);
const verdictOf = (ms: any, ok: any = true, hasClaims = true) => ({ ok, reasons: [], ...(hasClaims ? { claims: { iss: 'i', iat: 0, ...(ms ? { measurements: ms } : {}) } } : {}) });
const RD = (n: string, v: any, op?: any) => add('runtimeDigestFromEat', n, op === undefined ? [v] : [v, op]);
await RD('good', verdictOf([{ type: 'image', value: H64 }])); await RD('null', null); await RD('ok false', verdictOf([{ type: 'image', value: H64 }], false)); await RD('ok 1', verdictOf([{ type: 'image', value: H64 }], 1)); await RD('ok string', verdictOf([{ type: 'image', value: H64 }], 'true'));
await RD('no claims', verdictOf([{ type: 'image', value: H64 }], true, false)); await RD('no measurements', verdictOf(undefined)); await RD('empty measurements', verdictOf([])); await RD('sha512', verdictOf([{ type: 'image', value: H128 }]), { alg: 'sha512' });
await RD('sha512 default', verdictOf([{ type: 'image', value: H128 }])); await RD('sha256 with 128', verdictOf([{ type: 'image', value: H64 }]), { alg: 'sha512' }); await RD('other alg uses 128', verdictOf([{ type: 'image', value: H128 }]), { alg: 'weird' });
for (const bad of ['a', H64.slice(1), H64 + 'a', 'x' + H64, H64.toUpperCase(), ' ' + H64, H64 + '\n', '', 5, [H64], null]) await RD(`bad ${JSON.stringify(bad)}`, verdictOf([{ type: 'image', value: bad }]));
await RD('two entries', verdictOf([{ type: 'image', value: H64 }, { type: 'image', value: H64 }])); await RD('other slot', verdictOf([{ type: 'launch', value: H64 }, { type: 'image', value: H64 }])); await RD('slot launch', verdictOf([{ type: 'launch', value: H64 }, { type: 'image', value: H64 }]), { slot: 'launch' });
await RD('slot none', verdictOf([{ type: 'launch', value: H64 }]), { slot: 'none' }); await RD('slot null default', verdictOf([{ type: 'image', value: H64 }]), { slot: null, alg: null }); await RD('measurements string', verdictOf('x')); await RD('verdict array', []);
const REPO = 'https://github.com/sigstore/sigstore-js';
const IDENT = `${REPO}/.github/workflows/release.yml@refs/heads/main`;
const GHA = 'https://token.actions.githubusercontent.com';
const BUILDER = 'https://github.com/actions/runner/github-hosted';
const TARBALL = Buffer.from('hJqJfoG/e4qFQaauQL00c6J6FrHLBGKtkFvW3JbTSIEFOhLrSjdSM/gWd/yUOfYo/gsERehTXGC1VZWX+9X4Dg==', 'base64').toString('hex');
const INTEGRATED_S = 1780347770;
const ISS = edKey('eat/discharge-issuer');
const caveat = P.provenanceCaveat({ issuer: 'prov', min_level: 2, source_repo: REPO, bind: 'chain_hop' });
const request = { v: 1, kind: 'pca-discharge-request', caveat_id: caveat.id, issuer: caveat.issuer, cap_hash: b64u(new Uint8Array(32).fill(9)), bind: 'chain_hop', require: caveat.require, ttl_ms: caveat.ttl_ms };
const policy = (extra: any = {}) => ({ roots: [{ oidc_issuer: GHA, identity: IDENT, builder_id: BUILDER, level: 2 }], min_level: 2, source_repo: REPO, require_runtime: true, ...extra });
const ID = (n: string, x: any) => add('issueArtifactDischarge', n, [{ bundle: SLSA, roots: ROOTS, policy: policy(), runtime: { alg: 'sha512', digest: TARBALL }, request, now: (INTEGRATED_S + 100) * 1000, issuerKey: ISS.priv, ...x }]);
await ID('ok', {}); await ID('ok ttl', { ttl_ms: 1000 }); await ID('ttl too long', { ttl_ms: request.ttl_ms + 1 }); await ID('ttl zero', { ttl_ms: 0 }); await ID('ttl negative', { ttl_ms: -1 });
await ID('action bind', { request: { ...request, bind: 'action', action_digest: b64u(new Uint8Array(32).fill(7)) } }); await ID('action bind missing digest', { request: { ...request, bind: 'action' } });
await ID('no runtime', { runtime: undefined }); await ID('null runtime', { runtime: null }); await ID('wrong runtime', { runtime: { alg: 'sha512', digest: 'aa'.repeat(64) } }); await ID('malformed runtime', { runtime: { alg: 'x' } });
await ID('policy not require runtime', { runtime: undefined, policy: policy({ require_runtime: false }) }); await ID('stale', { policy: policy({ max_age_s: 1 }) }); await ID('fresh max age', { policy: policy({ max_age_s: 100 }) }); await ID('future clock', { now: (INTEGRATED_S - 1) * 1000 });
await ID('clock exact', { now: INTEGRATED_S * 1000 }); await ID('clock sub second', { now: INTEGRATED_S * 1000 + 999 }); await ID('level too high', { policy: policy({ min_level: 3 }) }); await ID('wrong repo', { policy: policy({ source_repo: 'https://github.com/other/repo' }) });
await ID('no roots', { policy: policy({ roots: [] }) }); await ID('bad policy', { policy: {} }); await ID('policy null', { policy: null }); await ID('bad bundle', { bundle: { mediaType: 'x' } }); await ID('bundle null', { bundle: null });
await ID('request ttl small', { request: { ...request, ttl_ms: 10 } }); await ID('request issuer bad', { request: { ...request, issuer: '' } }); await ID('request bind bad', { request: { ...request, bind: 'x' } }); await ID('request cap_hash bad', { request: { ...request, cap_hash: 'AAAA' } });
splitWrite(o, 'attest-eat', (j: string) => tokensIn(j, /"prim":"slh-dsa[^"]*","seed":"([A-Za-z0-9_-]+)"/g));
