// Oracle: @atlasauth/pca-sandbox (policy compile, OS profile generators, runtime-claim signing/verification, receipt hash chains,
// capability handle table, egress admission policy, private-address check). Deterministic: fixed clocks, seed-derived Ed25519 keys.
// Whole-process pieces are not covered (the WebAssembly host, the component host, the HTTP proxy server): they need a runtime a native
// SDK does not carry.
// PORTING (fn(args) -> native entry point, comparison rule; all by JSON value, a throw requires the native to refuse):
//   satisfiesRuntimeClass(a, b)               Receipts.satisfiesRuntimeClass
//   receiptLog(spec)                          spec {sign: bool, appends: [{t, rc, body}]}: new ReceiptLog(now = constant t before each append, sign = d => 'sig:' + d if
//                                             sign); result: the entries, or {$err} for a step that threw (the log keeps the entries before it)
//   verifyReceiptChain(receipts, mode)        Receipts.verifyReceiptChain; mode 'none' = no signature check, 'tag' = verifySig (d, s) => s === 'sig:' + d
//   policyFromNeeds(needs, proxyPort)         Profiles.policyFromNeeds; proxyPort absent = null
//   compilePolicy(spec)                       spec {items: [{allow, bind: {verb, resource, params, id}|null, operation}], needs: {"verb resource": Needs|null}, proxyPort}:
//                                             an item's result is {allow, operation: {verb, resource, params_digest: hashCanonical(bind.params), id}}; needsOf looks the operation up
//   seccompProfile / landlockRuleset / macosProfile / confineArgs (policy)   Profiles.*, Confine.confineArgs
//   isPrivateAddress(ip)                      Egress.isPrivateAddress
//   egress(spec)                              scenario over an EgressPolicy: spec {steps}: {op:'now', t} | {op:'admit', allow, bind, operation, template, opts} | {op:'claim', req}
//                                             req {method, url, body?: {$bytes}}; result per step ({$err} for a throw)
//   handles(spec)                             scenario over a HandleTable: spec {cls, steps}; executors by verb are fixed: bytes -> [1,2,3], echo -> canonical JSON of the
//                                             operation as bytes, throw, notbytes (returns a string); step {op:'now', t} | mint | attenuate | revoke | use | verbOf | size
//   signRuntimeClaim(keyLabel, pubLabel, c)   RuntimeClaims.signRuntimeClaim; the key is the Ed25519 seed sha256('atlas-pca-conformance/' + label) ({short: n} = an n-byte key, which must throw); Ed25519 is deterministic
//   verifiedRuntimeClass(claim, trust)        RuntimeClaims.verifiedRuntimeClass
//   passportDigest(x) / evidenceDigest(doc)   RuntimeClaims.* (hashCanonical)
//   runtimeClaimDomain / reference tool       RuntimeClaims.RUNTIME_CLAIM_DOMAIN; buildTool(spec) / buildProbeTool(cap) / referenceComponentWat(o): ReferenceTool.*, ReferenceComponent.* (bytes / text)
//   moduleConsts                              IMPORT_MODULE, ALLOWED_IMPORTS, USE_ERR, GENESIS, RUNTIME_CLASSES
// Shortcut recorded for natives: the WHATWG URL parser behind the egress target parse is ported for ASCII hosts; a non-ASCII host is refused (fail closed).
import * as S0 from '@atlasauth/pca-sandbox';
import * as C0 from '@atlasauth/pca';
import { createHash } from 'node:crypto';
import { Oracle, refWrite, seed, HOSTILE } from './lib.mjs';

const S: any = (S0 as any).default ?? S0;
const C: any = (C0 as any).default ?? C0;
const o = new Oracle('sandbox', 'tools/pca-audit/oracles/sandbox.mts', 'TS-reference oracle for @atlasauth/pca-sandbox.');
let n = 0;
const nm = (s: string) => `${s}#${n++}`;
const run = (fn: string, name: string, ref: (...a: any[]) => any, args: any[]) => o.run(fn, nm(name), ref, args);
const b64 = (u: Uint8Array) => ({ $bytes: Buffer.from(u).toString('base64url') });
const unb = (x: any): any => (x && typeof x === 'object' && !Array.isArray(x) && Object.keys(x).length === 1 && '$bytes' in x ? new Uint8Array(Buffer.from(x.$bytes, 'base64url')) : x);

// ---- consts ---------------------------------------------------------------------------------------------------------------
await run('moduleConsts', 'all', () => ({ IMPORT_MODULE: S.IMPORT_MODULE, ALLOWED_IMPORTS: S.ALLOWED_IMPORTS, USE_ERR: S.USE_ERR, GENESIS: S.GENESIS, RUNTIME_CLASSES: S.RUNTIME_CLASSES, DOMAIN: S.RUNTIME_CLAIM_DOMAIN }), []);

// ---- satisfiesRuntimeClass ------------------------------------------------------------------------------------------------
const names: any[] = [...S.RUNTIME_CLASSES, '', 'NONE', 'wasi', null, 5, true, 'os_confined ', 'x'];
for (const a of names) for (const b of names) await run('satisfiesRuntimeClass', `${a}/${b}`, S.satisfiesRuntimeClass, [a, b]);

// ---- policyFromNeeds ------------------------------------------------------------------------------------------------------
const needsList: any[][] = [
  [], [{}], [{ fs: [] , net: [] }], [5], [{ fs: [{ path: '/usr/bin/tool', mode: 'x' }] }], [{ fs: [{ path: '/data', mode: 'r' }, { path: '/data', mode: 'rw' }, { path: '/tmp/work', mode: 'rw' }] }],
  [{ fs: [{ path: '/b', mode: 'r' }, { path: '/a', mode: 'r' }, { path: '/a', mode: 'r' }] }, { fs: [{ path: '/c d', mode: 'rw' }] }],
  [{ net: [{ host: 'api.example.com', port: 443 }, { host: 'api.example.com', port: 443 }, { host: 'a.io', port: 80 }] }],
  [{ net: [{ host: 'localhost', port: 1 }, { host: '127.0.0.1', port: 65535 }] }, { fs: [{ path: '/', mode: 'r' }] }],
  [{ fs: [{ path: '/x', mode: 'w' }] }], [{ fs: [{ path: 'rel', mode: 'r' }] }], [{ fs: [{ path: '/a//b', mode: 'r' }] }], [{ fs: [{ path: '/a/', mode: 'r' }] }],
  [{ fs: [{ path: '/a/./b', mode: 'r' }] }], [{ fs: [{ path: '/a/../b', mode: 'r' }] }], [{ fs: [{ path: '/..', mode: 'r' }] }], [{ fs: [{ path: '/a"b', mode: 'r' }] }],
  [{ fs: [{ path: '/a(b)', mode: 'r' }] }], [{ fs: [{ path: '/a\nb', mode: 'r' }] }], [{ fs: [{ path: '/é', mode: 'r' }] }], [{ fs: [{ path: '/a;b', mode: 'r' }] }],
  [{ fs: [{ path: '/a b/c+d@e=f,g:h~i._-', mode: 'x' }] }], [{ fs: [{ path: '', mode: 'r' }] }], [{ fs: [{ path: 5, mode: 'r' }] }], [{ fs: [null] }], [{ fs: [{ path: '/a' }] }],
  [{ net: [{ host: 'A.com', port: 80 }] }], [{ net: [{ host: '-a.com', port: 80 }] }], [{ net: [{ host: 'a.com', port: 0 }] }], [{ net: [{ host: 'a.com', port: 65536 }] }],
  [{ net: [{ host: 'a.com', port: 1.5 }] }], [{ net: [{ host: 'a.com', port: '80' }] }], [{ net: [{ host: 'a.com' }] }], [{ net: [{ host: '', port: 80 }] }], [{ net: [{ host: 'a_b.com', port: 80 }] }],
  [{ net: [{ host: 'a.com.', port: 80 }] }], [{ net: [{ host: 'a b', port: 80 }] }], [{ net: [{ host: 'a.com\n', port: 80 }] }], [{ net: [{ host: 'xn--e1afmkfd.example', port: 80 }] }],
  [{ net: [null] }], [{ fs: 'x' }], [{ fs: {} }], [null], [{ fs: [{ path: '/a', mode: 'x' }, { path: '/a', mode: 'r' }, { path: '/a', mode: 'rw' }] }],
];
const ports: any[] = [undefined, null, 8080, 1, 65535, 0, 65536, -1, 1.5, '80', NaN === 0 ? 0 : 3128];
for (const nd of needsList) for (const p of ports) await run('policyFromNeeds', `${JSON.stringify(nd).slice(0, 40)}/${p}`, S.policyFromNeeds, p === undefined ? [nd] : [nd, p]);
await run('policyFromNeeds', 'notarray', S.policyFromNeeds, [{}]);
await run('policyFromNeeds', 'null', S.policyFromNeeds, [null]);

// ---- policies for the generators ------------------------------------------------------------------------------------------
const policies: any[] = [];
for (const nd of needsList) for (const p of [null, 8080, 1]) { try { policies.push(S.policyFromNeeds(JSON.parse(JSON.stringify(nd)), p)); } catch { /* refused */ } }
policies.push({ v: 1, fs: { read: ['/r'], write: ['/w'], exec: ['/e', '/r'] }, net: { proxy: { host: '::1', port: 9 }, hosts: [] } });
policies.push({ v: 1, fs: { read: [], write: ['/only/w'], exec: [] }, net: { proxy: null, hosts: ['h:1'] } });
for (const [i, p] of policies.entries()) {
  for (const fn of ['seccompProfile', 'landlockRuleset', 'macosProfile', 'confineArgs']) await run(fn, `${i}`, S[fn], [p]);
}

// ---- compilePolicy --------------------------------------------------------------------------------------------------------
const mkRes = (allow: boolean, bind: any) => ({ allow, ...(bind ? { operation: { verb: bind.verb, resource: bind.resource, params_digest: C.hashCanonical(bind.params), id: bind.id ?? 'op' } } : {}) });
const compile = (spec: any) => {
  const items = spec.items.map((it: any) => ({ result: mkRes(it.allow, it.bind), operation: it.operation }));
  return S.compilePolicy(items, (op: any) => spec.needs[`${op.verb} ${op.resource}`] ?? null, spec.proxyPort ?? null);
};
const A = { verb: 'fs.read', resource: 'file:a', params: { p: 1 } };
const B = { verb: 'net.get', resource: 'url:b', params: {} };
const needsMap = { 'fs.read file:a': { fs: [{ path: '/a', mode: 'r' }] }, 'net.get url:b': { net: [{ host: 'b.com', port: 443 }] }, 'x y': null };
const cspecs: any[] = [
  { items: [], needs: needsMap },
  { items: [{ allow: true, bind: { ...A, id: 'i1' }, operation: A }], needs: needsMap },
  { items: [{ allow: true, bind: { ...A, id: 'i1' }, operation: A }, { allow: true, bind: { ...B, id: 'i2' }, operation: B }], needs: needsMap, proxyPort: 9000 },
  { items: [{ allow: true, bind: { ...A, id: 'i1' }, operation: A }, { allow: true, bind: { ...B, id: 'i2' }, operation: B }], needs: needsMap },
  { items: [{ allow: false, bind: { ...A, id: 'i1' }, operation: A }], needs: needsMap },
  { items: [{ allow: true, bind: null, operation: A }], needs: needsMap },
  { items: [{ allow: true, bind: { ...A, params: { p: 2 }, id: 'i1' }, operation: A }], needs: needsMap },
  { items: [{ allow: true, bind: { ...A, verb: 'fs.write', id: 'i1' }, operation: A }], needs: needsMap },
  { items: [{ allow: true, bind: { ...A, id: 'i1' }, operation: { ...A, resource: 'file:z' } }], needs: needsMap },
  { items: [{ allow: true, bind: { ...A, id: 'i1' }, operation: { ...A, params: [] } }], needs: needsMap },
  { items: [{ allow: true, bind: { ...A, id: 'i1' }, operation: { ...A, verb: '' } }], needs: { ...needsMap } },
  { items: [{ allow: true, bind: { verb: 'x', resource: 'y', params: {}, id: 'i' }, operation: { verb: 'x', resource: 'y', params: {} } }], needs: needsMap },
  { items: [{ allow: true, bind: { ...A, id: 'i1' }, operation: A }], needs: { 'fs.read file:a': { fs: [{ path: '/a b"', mode: 'r' }] } } },
  { items: [{ allow: true, bind: { ...A, id: 'i1' }, operation: A }], needs: needsMap, proxyPort: 0 },
];
for (const [i, s] of cspecs.entries()) await run('compilePolicy', `${i}`, compile, [s]);

// ---- isPrivateAddress -----------------------------------------------------------------------------------------------------
const ips = ['0.0.0.0', '0.1.2.3', '10.0.0.1', '10.255.255.255', '127.0.0.1', '127.255.0.9', '169.254.1.1', '169.253.1.1', '172.15.0.1', '172.16.0.1', '172.31.255.255', '172.32.0.1', '192.168.0.1', '192.167.0.1',
  '100.63.0.1', '100.64.0.1', '100.127.255.255', '100.128.0.1', '224.0.0.1', '239.1.1.1', '255.255.255.255', '223.255.255.255', '8.8.8.8', '1.1.1.1', '93.184.216.34', '1.2.3', '1.2.3.4.5', '256.1.1.1', '01.2.3.4', '1.2.3.04', '1.2.3.4 ', ' 1.2.3.4', '',
  '::', '::1', '::2', '0:0:0:0:0:0:0:1', '0:0:0:0:0:0:0:0', 'fc00::1', 'FD00::1', 'fe80::1', 'FE80::1', 'fea0::1', 'febf::1', 'fec0::1', 'ff02::1', 'FF02::1', '2001:db8::1', '2606:4700::1111', '2001:4860:4860::8888',
  '::ffff:127.0.0.1', '::ffff:8.8.8.8', '::FFFF:10.1.2.3', '::ffff:256.0.0.1', '::ffff:1.2.3', '::ffff:7f00:1', '::ffff:0:0', '::1%eth0', 'fe80::1%en0', 'fe80::1%', '[::1]', '1:2:3:4:5:6:7:8', '1:2:3:4:5:6:7:8:9', '1::2::3', ':::', '12345::1',
  '::1.2.3.4', '1:2:3:4:5:6:1.2.3.4', 'localhost', 'example.com', 'abc', '1', '0x7f.1', '2130706433', '127.1', '::ffff:127.1', '::127.0.0.1', 'f::', 'fc::', 'fd', 'fe8', 'f:1', 'ff:1::', '::ffff:1.2.3.4%x'];
for (const ip of ips) await run('isPrivateAddress', ip, S.isPrivateAddress, [ip]);
for (const x of [null, 5, true, ['::1'], {}]) await run('isPrivateAddress', `h-${JSON.stringify(x)}`, S.isPrivateAddress, [x]);

// ---- receipts -------------------------------------------------------------------------------------------------------------
const SUBJ = { op_id: 'o1', verb: 'v', resource: 'r', params_digest: 'p' };
const rlog = (spec: any) => {
  let t = 0;
  const log = new S.ReceiptLog({ now: () => t, ...(spec.sign ? { sign: (d: string) => `sig:${d}` } : {}) });
  const outs: any[] = [];
  for (const a of spec.appends) {
    t = a.t;
    try { outs.push(log.append(a.rc, a.body)); } catch { outs.push({ $err: true }); }
  }
  return outs;
};
const bodies: any[] = [
  { kind: 'handle_use', subject: SUBJ, outcome: 'ok', reason: 'used' }, { kind: 'egress', subject: { ...SUBJ, op_id: '' }, outcome: 'refused', reason: 'no_admission' },
  { kind: 'egress', subject: SUBJ, outcome: 'error', reason: 'upstream:EACCES' }, { kind: 'handle_use', subject: SUBJ, outcome: 'ok', reason: 'ü' },
  { kind: 'handle_use', subject: SUBJ, outcome: 'ok', reason: 'used', extra: { z: 1, a: [1, 2] } }, { kind: 'handle_use', subject: SUBJ, outcome: 'ok', reason: 'x', seq: 99 },
  { kind: 'handle_use', subject: SUBJ, outcome: 'ok', reason: 'x', at: 5 }, { kind: 'handle_use', subject: SUBJ, outcome: 'ok', reason: 'x', prev: 'zz' }, { kind: 'handle_use', subject: { ...SUBJ, params_digest: 1.5 }, outcome: 'ok', reason: 'x' },
];
const classes = ['none', 'os_confined', 'egress_default_deny', 'wasi_no_ambient', 'bogus'];
for (const sign of [false, true]) {
  for (let len = 0; len <= bodies.length; len++) {
    await run('receiptLog', `${sign}/${len}`, rlog, [{ sign, appends: bodies.slice(0, len).map((b, i) => ({ t: 1_800_000_000_000 + i * 1000, rc: classes[i % classes.length], body: b })) }]);
  }
}
await run('receiptLog', 'float-time', rlog, [{ sign: false, appends: [{ t: 1.5, rc: 'none', body: bodies[0] }, { t: 2, rc: 'none', body: bodies[0] }] }]);
await run('receiptLog', 'neg-time', rlog, [{ sign: true, appends: [{ t: -5, rc: 'none', body: bodies[0] }, { t: 0, rc: 'none', body: bodies[1] }] }]);

const chains: { sign: boolean; entries: any[] }[] = [];
for (const sign of [false, true]) chains.push({ sign, entries: rlog({ sign, appends: bodies.slice(0, 5).map((b, i) => ({ t: 1_800_000_000_000 + i, rc: classes[i % 4], body: b })) }) });
const vchain = (r: any, mode: string) => S.verifyReceiptChain(r, mode === 'tag' ? (d: string, s: string) => s === `sig:${d}` : undefined);
let ci = 0;
for (const { sign, entries } of chains) {
  for (const mode of ['none', 'tag']) {
    await run('verifyReceiptChain', `valid/${sign}/${mode}`, vchain, [JSON.parse(JSON.stringify(entries)), mode]);
    await run('verifyReceiptChain', `empty/${sign}/${mode}`, vchain, [[], mode]);
    for (let i = 0; i < entries.length; i++) {
      const mut = (f: (c: any[]) => void) => { const c = JSON.parse(JSON.stringify(entries)); f(c); return c; };
      const tag = `${sign}/${mode}/${i}`;
      await run('verifyReceiptChain', `drop/${tag}`, vchain, [mut((c) => c.splice(i, 1)), mode]);
      await run('verifyReceiptChain', `swap/${tag}`, vchain, [mut((c) => { const j = (i + 1) % c.length; [c[i], c[j]] = [c[j], c[i]]; }), mode]);
      await run('verifyReceiptChain', `dup/${tag}`, vchain, [mut((c) => c.splice(i, 0, c[i])), mode]);
      for (const [k, v] of [['reason', 'tampered'], ['outcome', 'ok'], ['at', 7], ['digest', 'zz'], ['sig', 'sig:zz'], ['sig', 5], ['prev', 'x'], ['seq', i + 1], ['seq', i + 0.0], ['seq', '0'], ['v', 2], ['v', '1'], ['v', 1.0], ['runtime_class', 'none'], ['subject', null], ['extra', 1]] as any[]) {
        await run('verifyReceiptChain', `set-${k}-${JSON.stringify(v)}/${tag}`, vchain, [mut((c) => { c[i][k] = v; }), mode]);
      }
      await run('verifyReceiptChain', `delsig/${tag}`, vchain, [mut((c) => { delete c[i].sig; }), mode]);
      await run('verifyReceiptChain', `deldigest/${tag}`, vchain, [mut((c) => { delete c[i].digest; }), mode]);
    }
    ci++;
  }
}
for (const x of [null, 5, 'x', {}, [null], [5], ['x'], [[]], [{}], [{ v: 1, seq: 0, prev: 'genesis' }], [{ v: 1, seq: -0, prev: 'genesis', digest: 'x' }], [{ v: 1, seq: 0, prev: 'genesis', digest: 'x', at: 1.5 }]]) await run('verifyReceiptChain', `hostile-${JSON.stringify(x)}`, vchain, [x, 'none']);

// ---- runtime claims -------------------------------------------------------------------------------------------------------
const sk = seed('sandbox-attestor');
const pk = C.publicKeyOf(sk);
const sk2 = seed('sandbox-other');
const pk2 = C.publicKeyOf(sk2);
const PD = C.hashCanonical({ passport: 1 });
const ED = C.hashCanonical({ evidence: 1 });
const base = { class: 'wasi_no_ambient', passport_digest: PD, evidence_digest: ED, iat: 1000, exp: 5000 };
const sign = (c: any, k = sk, p = pk) => S.signRuntimeClaim(k, p, c);
// the secret key is derived from a label on both sides (no key material in the corpus); {short: n} is an n-byte key
const keyOf = (k: any) => (typeof k === 'string' ? seed(k) : new Uint8Array(k.short));
const signRC = (k: any, p: any, c: any) => S.signRuntimeClaim(keyOf(k), C.publicKeyOf(typeof p === 'string' ? seed(p) : seed('x')), c);
for (const cls of S.RUNTIME_CLASSES) await run('signRuntimeClaim', `${cls}`, signRC, ['sandbox-attestor', 'sandbox-attestor', { ...base, class: cls }]);
await run('signRuntimeClaim', 'other-key', signRC, ['sandbox-other', 'sandbox-other', base]);
await run('signRuntimeClaim', 'badclass', signRC, ['sandbox-attestor', 'sandbox-attestor', { ...base, class: 'zzz' }]);
await run('signRuntimeClaim', 'float-iat', signRC, ['sandbox-attestor', 'sandbox-attestor', { ...base, iat: 1.5 }]);
await run('signRuntimeClaim', 'extra-member', signRC, ['sandbox-attestor', 'sandbox-attestor', { ...base, extra: 1 }]);
await run('signRuntimeClaim', 'short-key', signRC, [{ short: 5 }, 'sandbox-attestor', base]);
const goodClaim = sign(base);
const trust = { pinnedAttestors: [C.encodeKey(pk)], passportDigest: PD, verifiedEvidenceDigests: [ED], now: 2000 };
const vr = (claim: any, t: any) => S.verifiedRuntimeClass(claim, t);
await run('verifiedRuntimeClass', 'good', vr, [goodClaim, trust]);
for (const cls of S.RUNTIME_CLASSES) await run('verifiedRuntimeClass', `class-${cls}`, vr, [sign({ ...base, class: cls }), trust]);
for (const now of [999, 1000, 1999, 4999, 5000, 5001, -0, 0, 1.5, '2000', null, 2 ** 53]) await run('verifiedRuntimeClass', `now-${JSON.stringify(now)}`, vr, [goodClaim, { ...trust, now }]);
for (const [k, v] of [['pinnedAttestors', []], ['pinnedAttestors', [C.encodeKey(pk2)]], ['pinnedAttestors', [C.encodeKey(pk2), C.encodeKey(pk)]], ['passportDigest', 'other'], ['passportDigest', null], ['verifiedEvidenceDigests', []], ['verifiedEvidenceDigests', ['x', ED]], ['verifiedEvidenceDigests', ['x']]] as any[]) {
  await run('verifiedRuntimeClass', `trust-${k}-${JSON.stringify(v).slice(0, 20)}`, vr, [goodClaim, { ...trust, [k]: v }]);
}
for (const k of Object.keys(trust)) await run('verifiedRuntimeClass', `trust-missing-${k}`, vr, [goodClaim, Object.fromEntries(Object.entries(trust).filter(([x]) => x !== k))]);
await run('verifiedRuntimeClass', 'trust-null', vr, [goodClaim, null]);
await run('verifiedRuntimeClass', 'wrong-attestor-signed', vr, [sign(base, sk2, pk2), trust]);
await run('verifiedRuntimeClass', 'wrong-attestor-signed-pinned', vr, [sign(base, sk2, pk2), { ...trust, pinnedAttestors: [C.encodeKey(pk2)] }]);
for (const [k, vs] of Object.entries({ v: [2, '1', 1.0, null], class: ['none', 'bogus', 5, null], passport_digest: ['x', 5, null, ''], evidence_digest: ['x', 5, null, ''], iat: [1000.5, -0, '1000', 999, null, 1e21, 2 ** 53], exp: [5000.5, -0, 5001, 1999, null], attestor: ['x', 5, null, C.encodeKey(pk2), ''], sig: ['x', 5, null, '', 'A'.repeat(86)] }) as any) {
  for (const v of vs) await run('verifiedRuntimeClass', `mut-${k}-${JSON.stringify(v)}${Object.is(v, -0) ? 'neg0' : ''}`, vr, [{ ...goodClaim, [k]: v }, { ...trust, pinnedAttestors: [C.encodeKey(pk), C.encodeKey(pk2), 'x'] }]);
}
for (const k of Object.keys(goodClaim)) await run('verifiedRuntimeClass', `del-${k}`, vr, [Object.fromEntries(Object.entries(goodClaim).filter(([x]) => x !== k)), trust]);
await run('verifiedRuntimeClass', 'extra', vr, [{ ...goodClaim, extra: 1 }, trust]);
await run('verifiedRuntimeClass', 'swap-key', vr, [{ ...goodClaim, extra: undefined, a: 1 }, trust]);
for (const x of HOSTILE) await run('verifiedRuntimeClass', `hostile-${JSON.stringify(x)}`, vr, [x, trust]);
await run('verifiedRuntimeClass', 'array', vr, [[goodClaim], trust]);
for (const x of [{ a: 1 }, 'x', null, 5, [1, 2], { b: { c: [1, 2] } }, true]) await run('passportDigest', JSON.stringify(x), S.passportDigest, [x]);
for (const x of [{ format: 'x', data: 'y' }, { a: [1] }, {}]) await run('evidenceDigest', JSON.stringify(x), S.evidenceDigest, [x]);

// ---- reference tool / component -------------------------------------------------------------------------------------------
const toolSpecs: any[] = [
  { calls: [] }, { calls: [{ handle: 1, ptr: 0, cap: 16 }] }, { calls: [{ handle: 1, ptr: 0, cap: 16 }], returns: 'byte0' }, { calls: [{ handle: 1, ptr: 0, cap: 16 }, { handle: 2, ptr: 64, cap: 8 }], returns: 'last' },
  { calls: [{ handle: 1, ptr: 0, cap: 16 }], extraImports: [{ module: 'wasi_snapshot_preview1', name: 'fd_write' }] }, { calls: [{ handle: 300, ptr: 70000, cap: 200 }, { handle: -1, ptr: 0, cap: 0 }] },
  { calls: [{ handle: 1, ptr: 0, cap: 16 }], memory: { min: 1, max: null } }, { calls: [{ handle: 1, ptr: 0, cap: 16 }], memory: { min: 2, max: 300 } }, { calls: [{ handle: 1, ptr: 0, cap: 16 }], spin: true },
  { calls: [{ handle: 1, ptr: 0, cap: 16 }], spin: true, returns: 'byte0' }, { calls: [], spin: true }, { calls: [], returns: 'byte0' },
  { calls: [{ handle: 1, ptr: 0, cap: 16 }], extraImports: [{ module: 'a', name: 'b' }, { module: 'cc'.repeat(70), name: 'é' }] },
  { calls: [{ handle: 63, ptr: 64, cap: 8192 }, { handle: 64, ptr: 8192, cap: 16384 }, { handle: 2 ** 20, ptr: 2 ** 21, cap: 2 ** 28 }] },
];
for (const [i, s] of toolSpecs.entries()) await run('buildTool', `${i}`, S.buildTool, [s]);
for (const cap of [undefined, 0, 1, 63, 64, 65, 127, 128, 300, 16384]) await run('buildProbeTool', `${cap}`, S.buildProbeTool, cap === undefined ? [] : [cap]);
const rcOpts: any[] = [{}, { handle: 1 }, { handle: 5 }, { handle: 0 }, { handle: 300 }, { spin: true }, { extraImport: 'wasi:cli/environment@0.2.0' }, { handle: 2, extraImport: 'x:y/z' }, { spin: true, extraImport: 'a' }, { extraImport: '' }];
for (const [i, x] of rcOpts.entries()) await run('referenceComponentWat', `${i}`, S.referenceComponentWat, [x]);
await run('referenceComponentWat', 'noarg', S.referenceComponentWat, []);

// ---- egress ---------------------------------------------------------------------------------------------------------------
const egress = (spec: any) => {
  let t = 0;
  const p = new S.EgressPolicy(() => t);
  const outs: any[] = [];
  for (const st of spec.steps) {
    try {
      if (st.op === 'now') { t = st.t; outs.push(null); }
      else if (st.op === 'admit') {
        const op = st.operation;
        p.admit(mkRes(st.allow, st.bind), op, () => st.template, st.opts ?? {});
        outs.push('ok');
      } else outs.push(p.claim({ method: st.req.method, url: st.req.url, ...(st.req.body !== undefined ? { body: unb(st.req.body) } : {}) }));
    } catch { outs.push({ $err: true }); }
  }
  return outs;
};
const OP = { verb: 'http.get', resource: 'url:x', params: { k: 1 } };
const BIND = { ...OP, id: 'op-1' };
const adm = (template: any, extra: any = {}) => ({ op: 'admit', allow: true, bind: BIND, operation: OP, template, ...extra });
const T = { method: 'GET', scheme: 'https', host: 'api.example.com', path: '/v1/items' };
const body = Buffer.from('hello');
const BH = createHash('sha256').update(body).digest().toString('base64url');
const cl = (method: string, url: string, b?: any) => ({ op: 'claim', req: { method, url, ...(b ? { body: b64(b) } : {}) } });
const urls = [
  'https://api.example.com/v1/items', 'https://API.Example.COM/v1/items', 'https://api.example.com:443/v1/items', 'HTTPS://api.example.com/v1/items', 'https://api.example.com/v1/items?', 'https://api.example.com/v1/items?a=1', 'https://api.example.com/v1/items#frag', 'https://api.example.com/v1/items#',
  'https://api.example.com/v1/items/', 'https://api.example.com/v1/items/sub', 'https://api.example.com/v1/itemsX', 'https://api.example.com/v1', 'https://api.example.com/', 'https://api.example.com', 'https://api.example.com:8443/v1/items', 'http://api.example.com/v1/items', 'http://api.example.com:80/v1/items',
  'https://u@api.example.com/v1/items', 'https://u:p@api.example.com/v1/items', 'https://:@api.example.com/v1/items', 'https://@api.example.com/v1/items', 'https://a@b@api.example.com/v1/items',
  'https://api.example.com/v1/%2e%2e/items', 'https://api.example.com/v1/%2E/items', 'https://api.example.com/v1/%2fitems', 'https://api.example.com/v1%2Fitems', 'https://api.example.com/v1/%5citems', 'https://api.example.com/v1\\items', 'https://api.example.com\\v1\\items',
  'https://api.example.com/v1/./items', 'https://api.example.com/v1/../v1/items', 'https://api.example.com/x/../v1/items', 'https://api.example.com//v1/items', 'https://api.example.com/v1//items', 'https://api.example.com/v1/items/..', 'https://api.example.com/v1/items/.',
  'https://api.example.com/v1/it ems', 'https://api.example.com/v1/it%20ems', 'https://api.example.com/v1/it"ems', 'https://api.example.com/v1/it<ems>', 'https://api.example.com/v1/it`ems', 'https://api.example.com/v1/it{ems}', 'https://api.example.com/v1/it^ems', 'https://api.example.com/v1/it|ems',
  'https://api.example.com/v1/%41items', 'https://api.example.com/v1/%zz', 'https://api.example.com/v1/%', 'https://api.example.com/v1/it\tems', 'https://api.example.com/v1/it\nems', ' https://api.example.com/v1/items', 'https://api.example.com/v1/items ', '\thttps://api.example.com/v1/items',
  'https://api.example.com/v1/items?q=a b', 'https://api.example.com/v1/items?q=a%20b', 'https://api.example.com/v1/items?q="x"', "https://api.example.com/v1/items?q='x'", 'https://api.example.com/v1/items?q=<x>', 'https://api.example.com/v1/items?q=é', 'https://api.example.com/v1/é',
  'https://api.example.com/v1/items?a=1#x?y', 'https://api.example.com/v1/items?a=1?b', 'https://api.example.com?x=1', 'https://api.example.com#x', 'https://api.example.com/v1/items?q=\\',
  'https://api.example.com./v1/items', 'https://api.example.com:/v1/items', 'https://api.example.com:0443/v1/items', 'https://api.example.com:65535/', 'https://api.example.com:65536/', 'https://api.example.com:99999999/', 'https://api.example.com:abc/', 'https://api.example.com:-1/', 'https://api.example.com:+1/',
  'https:/api.example.com/v1/items', 'https:api.example.com/v1/items', 'https:///api.example.com/v1/items', 'https:\\\\api.example.com\\v1\\items', 'https://', 'https:///', 'https://?x', 'https://#x', 'https:',
  'https://127.0.0.1/', 'https://127.0.0.1:8443/v1/items', 'https://0x7f.1/', 'https://2130706433/', 'https://127.1/', 'https://127.0.0.1./', 'https://01.02.03.04/', 'https://1.2.3.4.5/', 'https://256.1.1.1/', 'https://1.2.3/', 'https://0/', 'https://0xffffffff/', 'https://4294967296/', 'https://1.2.3.4/x', 'https://999999999999/',
  'https://[::1]/', 'https://[::1]:8443/', 'https://[0:0:0:0:0:0:0:1]/', 'https://[2001:DB8::1]/', 'https://[2001:db8:0:0:1:0:0:1]/', 'https://[2001:db8::]/', 'https://[::ffff:1.2.3.4]/', 'https://[::ffff:102:304]/', 'https://[1:2:3:4:5:6:7:8]/', 'https://[1::2::3]/', 'https://[::1/', 'https://::1/', 'https://[]/', 'https://[fe80::1%25eth0]/', 'https://[1:2:3:4:5:6:7:8:9]/', 'https://[::1]x/', 'https://[g::1]/',
  'https://exa mple.com/', 'https://exa%6dple.com/', 'https://exa%2fmple.com/', 'https://a_b.example.com/', 'https://-a.example.com/', 'https://a..example.com/', 'https://.example.com/', 'https://ex<ample.com/', 'https://ex^ample.com/', 'https://ex|ample.com/', 'https://ex%ample.com/', 'https://exa\u0000mple.com/', 'https://ex\u007fample.com/',
  'https://xn--e1afmkfd.example/', 'https://EXAMPLE.com/', 'https://example.com%00/', 'https://example.com%2e/', 'https://%65xample.com/',
  'ftp://api.example.com/v1/items', 'ftp://', 'ws://api.example.com/', 'wss://api.example.com/', 'file:///etc/passwd', 'file://host/x', 'javascript:alert(1)', 'data:text/plain,hi', 'mailto:a@b.c', 'foo://bar/baz', 'foo:', 'foo', '/v1/items', '//api.example.com/v1/items', 'api.example.com/v1/items', '', ' ', '1http://x/', 'ht tp://x/', 'h+t.t-p://x/', 'http', 'http:', '://x', 'C:\\x',
];
const tmpls: any[] = [
  T, { ...T, host: 'API.example.com' }, { ...T, path: '/v1/items', path_prefix: true }, { ...T, path: '/v1/items/', path_prefix: true }, { ...T, path: '/v1', path_prefix: true }, { ...T, path: '/', path_prefix: true }, { ...T, path: '/' }, { ...T, query: 'a=1' }, { ...T, query: '' }, { ...T, method: 'POST', body_sha256: BH },
  { ...T, scheme: 'http' }, { ...T, port: 8443 }, { ...T, port: 443 }, { ...T, scheme: 'http', port: 80 }, { ...T, host: '127.0.0.1' }, { ...T, host: '127.0.0.1', port: 8443 }, { ...T, host: '::1' }, { ...T, host: '2001:db8::1' }, { ...T, host: '1.2.3.4' }, { ...T, host: 'a_b.example.com' }, { ...T, host: 'localhost' },
  { method: 'CONNECT', scheme: 'https', host: 'api.example.com', port: 443, path: '/', tunnel: true }, { method: 'GET', scheme: 'https', host: 'api.example.com', path: '/', tunnel: true }, { ...T, host: 'ex.com', path: '/é' }, { ...T, path: '/v1/it%20ems' }, { ...T, path: '/v1/it ems' },
];
let ti = 0;
for (const t of tmpls) {
  const steps = [adm(t, { opts: { uses: 1000 } }), ...urls.map((u) => cl(t.method === 'POST' ? 'POST' : 'GET', u)), cl('get', 'https://api.example.com/v1/items'), cl('POST', 'https://api.example.com/v1/items', body), cl('GET', 'https://api.example.com/v1/items', body)];
  // one scenario per chunk of urls keeps each case small and the verdicts independent
  for (let i = 0; i < steps.length; i += 40) await run('egress', `tmpl${ti}-${i}`, egress, [{ steps: [steps[0], ...steps.slice(Math.max(i, 1), i + 40)] }]);
  ti++;
}
// admission validation
const badTemplates: any[] = [
  { ...T, host: 'Bad.Com' }, { ...T, host: '' }, { ...T, host: 'a b' }, { ...T, host: '-a.com' }, { ...T, host: 'a'.repeat(64) + '.com' }, { ...T, host: 'a'.repeat(63) + '.com' }, { ...T, host: '::FFFF:1.2.3.4' }, { ...T, host: '[::1]' },
  { ...T, scheme: 'ftp' }, { ...T, scheme: 'HTTPS' }, { ...T, scheme: null }, { ...T, port: 0 }, { ...T, port: 65536 }, { ...T, port: 1.5 }, { ...T, port: '80' }, { ...T, port: -0 }, { ...T, port: 1 }, { ...T, port: 65535 },
  { ...T, method: 'get' }, { ...T, method: '' }, { ...T, method: 'GET1' }, { ...T, method: 'GET\n' }, { ...T, method: 'CONNECT' },
  { ...T, path: 'v1' }, { ...T, path: '' }, { ...T, path: '/a?b' }, { ...T, path: '/a#b' }, { ...T, path: '/a\\b' }, { ...T, path: '/a/%2e/b' }, { ...T, path: '/%2F' }, { ...T, path: '/a%5Cb' }, { ...T, path: '/./a' }, { ...T, path: '/a/..' }, { ...T, path: '/a/../b' }, { ...T, path: '/a/.' }, { ...T, path: '/..a' }, { ...T, path: '/a..' }, { ...T, path: '/a.b/c' }, { ...T, path: '/a/..b' }, { ...T, path: '/a\n' }, { ...T, path: '/.\n' },
  null, {}, 'x', { ...T, path: 5 }, { ...T, host: 5 },
];
for (const [i, t] of badTemplates.entries()) await run('egress', `admit-${i}`, egress, [{ steps: [adm(t), cl('GET', 'https://api.example.com/v1/items')] }]);
for (const [i, st] of ([
  [{ op: 'admit', allow: false, bind: BIND, operation: OP, template: T }, cl('GET', 'https://api.example.com/v1/items')],
  [{ op: 'admit', allow: true, bind: null, operation: OP, template: T }],
  [{ op: 'admit', allow: true, bind: { ...BIND, params: { k: 2 } }, operation: OP, template: T }],
  [{ op: 'admit', allow: true, bind: { ...BIND, verb: 'x' }, operation: OP, template: T }],
  [{ op: 'admit', allow: true, bind: BIND, operation: { ...OP, params: [] }, template: T }],
  [adm(T, { opts: { uses: 0 } })], [adm(T, { opts: { uses: -1 } })], [adm(T, { opts: { uses: 1.5 } })], [adm(T, { opts: { uses: 2 } }), cl('GET', 'https://api.example.com/v1/items'), cl('GET', 'https://api.example.com/v1/items'), cl('GET', 'https://api.example.com/v1/items')],
  [adm(T, { opts: { uses: 1 } }), cl('GET', 'https://api.example.com/v1/items'), cl('GET', 'https://api.example.com/v1/items')],
  [{ op: 'now', t: 100 }, adm(T, { opts: { expiresAt: 200 } }), cl('GET', 'https://api.example.com/v1/items'), { op: 'now', t: 200 }, cl('GET', 'https://api.example.com/v1/items'), { op: 'now', t: 150 }, cl('GET', 'https://api.example.com/v1/items')],
  [{ op: 'now', t: 100 }, adm(T, { opts: { expiresAt: 100 } }), cl('GET', 'https://api.example.com/v1/items')],
  [adm(T), adm({ ...T, path: '/v1/other' }, { bind: { ...BIND, id: 'op-2' } }), cl('GET', 'https://api.example.com/v1/other'), cl('GET', 'https://api.example.com/v1/items'), cl('GET', 'https://api.example.com/v1/none')],
  [adm({ ...T, query: 'a=1' }), cl('GET', 'https://api.example.com/v1/items?a=2'), cl('GET', 'https://api.example.com/v1/items?a=1')],
  [adm({ ...T, query: 'a=1' }, { opts: { uses: 5 } }), cl('GET', 'https://api.example.com/v1/items'), cl('GET', 'https://api.example.com/v1/items?a=1'), cl('GET', 'https://api.example.com/v1/items?a=1&')],
  [adm({ ...T, method: 'POST', body_sha256: BH }), cl('POST', 'https://api.example.com/v1/items', body), cl('POST', 'https://api.example.com/v1/items', Buffer.from('other')), cl('POST', 'https://api.example.com/v1/items')],
  [adm({ ...T, method: 'POST', body_sha256: BH }, { opts: { uses: 4 } }), cl('POST', 'https://api.example.com/v1/items'), cl('POST', 'https://api.example.com/v1/items', Buffer.from('other')), cl('POST', 'https://api.example.com/v1/items', body)],
  [adm({ ...T, method: 'POST' }, { opts: { uses: 4 } }), cl('POST', 'https://api.example.com/v1/items', body), cl('POST', 'https://api.example.com/v1/items')],
  [adm({ ...T, method: 'POST', body_sha256: Buffer.from(createHash('sha256').update('').digest()).toString('base64url') }, { opts: { uses: 4 } }), cl('POST', 'https://api.example.com/v1/items'), cl('POST', 'https://api.example.com/v1/items', body)],
  [adm({ method: 'GET', scheme: 'https', host: 'api.example.com', port: 443, path: '/', tunnel: true }, { opts: { uses: 4 } }), cl('CONNECT', 'api.example.com:443'), cl('connect', 'API.EXAMPLE.COM:443'), cl('CONNECT', 'api.example.com:444'), cl('CONNECT', 'api.example.com'), cl('GET', 'https://api.example.com/'), cl('CONNECT', 'a b:1'), cl('CONNECT', '[::1]:443'), cl('CONNECT', 'api.example.com:123456')],
  [adm({ ...T, host: '::1', path: '/', tunnel: true }, { opts: { uses: 4 } }), cl('CONNECT', '[::1]:443'), cl('CONNECT', '[::1]:80'), cl('CONNECT', '[0:0:0:0:0:0:0:1]:443'), cl('CONNECT', '::1:443')],
  [adm(T), cl('GET', 'https://api.example.com/v1/items'), cl('GET', 'https://api.example.com/v1/items')],
  [cl('GET', 'https://api.example.com/v1/items')],
  [adm(T), { op: 'claim', req: { method: 5, url: 'x' } }], [adm(T), { op: 'claim', req: { method: 'GET', url: 5 } }], [adm(T), { op: 'claim', req: { method: 'GET', url: null } }], [adm(T), { op: 'claim', req: { method: 'GET' } }],
] as any[][]).entries()) await run('egress', `flow-${i}`, egress, [{ steps: st }]);

// ---- handle table ---------------------------------------------------------------------------------------------------------
const EXEC: Record<string, any> = {
  'fs.read': () => new Uint8Array([1, 2, 3]),
  'fs.echo': (op: any) => new TextEncoder().encode(JSON.stringify(op)),
  'fs.throw': () => { throw new Error('boom'); },
  'fs.notbytes': () => 'nope',
};
const mintRes = (st: any) => mkRes(st.allow ?? true, st.bind === undefined ? { ...st.operation, id: st.id ?? 'op-h' } : st.bind);
const handles = (spec: any) => {
  let t = 0;
  const log = new S.ReceiptLog({ now: () => t });
  const table = new S.HandleTable(spec.cls, log, EXEC, () => t);
  const outs: any[] = [];
  for (const st of spec.steps) {
    try {
      switch (st.op) {
        case 'now': t = st.t; outs.push(null); break;
        case 'mint': outs.push(table.mint(mintRes(st), st.operation, st.opts ?? {})); break;
        case 'attenuate': outs.push(table.attenuate(st.index, st.narrower ?? {})); break;
        case 'revoke': table.revoke(st.index); outs.push(null); break;
        case 'use': { const r = table.use(st.index); outs.push(r); break; }
        case 'verbOf': outs.push(table.verbOf(st.index)); break;
        case 'size': outs.push(table.size); break;
      }
    } catch { outs.push({ $err: true }); }
  }
  return { outs, log: log.entries };
};
const op = (verb: string, params: any = { a: 1 }) => ({ verb, resource: `r:${verb}`, params });
const mint = (verb: string, extra: any = {}) => ({ op: 'mint', operation: op(verb), ...extra });
const hs: any[] = [
  { cls: 'none', steps: [mint('fs.read'), { op: 'use', index: 1 }, { op: 'use', index: 1 }] },
  { cls: 'none', steps: [mint('fs.read', { opts: { uses: 3 } }), { op: 'use', index: 1 }, { op: 'use', index: 1 }, { op: 'use', index: 1 }, { op: 'use', index: 1 }, { op: 'size' }] },
  { cls: 'wasi_no_ambient', steps: [mint('fs.echo'), mint('fs.throw'), mint('fs.notbytes'), { op: 'use', index: 1 }, { op: 'use', index: 2 }, { op: 'use', index: 3 }, { op: 'use', index: 2 }, { op: 'verbOf', index: 1 }, { op: 'verbOf', index: 3 }, { op: 'verbOf', index: 4 }, { op: 'verbOf', index: 0 }] },
  { cls: 'none', steps: [mint('fs.nothere'), { op: 'use', index: 1 }, { op: 'use', index: 1 }] },
  { cls: 'none', steps: [{ op: 'use', index: 0 }, { op: 'use', index: 1 }, { op: 'use', index: -1 }, { op: 'use', index: 1.5 }, { op: 'verbOf', index: 0 }, { op: 'verbOf', index: -1 }, { op: 'verbOf', index: 1.5 }] },
  { cls: 'none', steps: [mint('fs.read', { allow: false }), mint('fs.read', { bind: null }), mint('fs.read', { bind: { ...op('fs.read'), params: { a: 2 }, id: 'x' } }), mint('fs.read', { bind: { ...op('fs.read'), resource: 'other', id: 'x' } }), { op: 'size' }] },
  { cls: 'none', steps: [{ op: 'mint', operation: { ...op('fs.read'), params: [] }, bind: { ...op('fs.read'), id: 'x' } }, { op: 'mint', operation: { ...op('fs.read'), verb: '' }, bind: { ...op('fs.read'), id: 'x' } }, { op: 'size' }] },
  ...[0, -1, 1.5, 1_000_001, 1_000_000, 2, 1].map((u) => ({ cls: 'none', steps: [mint('fs.read', { opts: { uses: u } }), { op: 'use', index: 1 }, { op: 'size' }] })),
  ...S.RUNTIME_CLASSES.flatMap((cls: string) => S.RUNTIME_CLASSES.map((req: string) => ({ cls, steps: [mint('fs.read', { opts: { requires: req } }), { op: 'size' }] }))),
  { cls: 'none', steps: [mint('fs.read', { opts: { requires: 'bogus' } }), { op: 'size' }] },
  { cls: 'none', steps: [{ op: 'now', t: 100 }, mint('fs.read', { opts: { expiresAt: 200, uses: 5 } }), { op: 'use', index: 1 }, { op: 'now', t: 200 }, { op: 'use', index: 1 }, { op: 'now', t: 50 }, { op: 'use', index: 1 }] },
  { cls: 'none', steps: [mint('fs.read', { opts: { uses: 10, expiresAt: 500 } }), { op: 'attenuate', index: 1, narrower: { uses: 4 } }, { op: 'attenuate', index: 1, narrower: { uses: 7 } }, { op: 'attenuate', index: 1, narrower: { uses: 6 } }, { op: 'attenuate', index: 1, narrower: { uses: 1 } }, { op: 'use', index: 1 }, { op: 'use', index: 2 }, { op: 'use', index: 2 }, { op: 'size' }] },
  { cls: 'none', steps: [mint('fs.read', { opts: { uses: 10, expiresAt: 500 } }), { op: 'attenuate', index: 1, narrower: { expiresAt: 600 } }, { op: 'attenuate', index: 1, narrower: { expiresAt: 500 } }, { op: 'attenuate', index: 1, narrower: { expiresAt: 400, uses: 2 } }, { op: 'attenuate', index: 1, narrower: { uses: 0 } }, { op: 'attenuate', index: 1, narrower: { uses: 1.5 } }, { op: 'attenuate', index: 1, narrower: { uses: -1 } }, { op: 'attenuate', index: 1 }, { op: 'use', index: 1 }, { op: 'size' }] },
  { cls: 'none', steps: [mint('fs.read', { opts: { uses: 1 } }), { op: 'attenuate', index: 1, narrower: { uses: 1 } }, { op: 'use', index: 1 }, { op: 'use', index: 2 }, { op: 'attenuate', index: 2 }] },
  { cls: 'none', steps: [{ op: 'attenuate', index: 1 }, { op: 'attenuate', index: 0 }, mint('fs.read', { opts: { uses: 4 } }), { op: 'revoke', index: 1 }, { op: 'attenuate', index: 1 }, { op: 'use', index: 1 }, { op: 'size' }] },
  { cls: 'none', steps: [mint('fs.read', { opts: { uses: 8 } }), { op: 'attenuate', index: 1, narrower: { uses: 2 } }, { op: 'attenuate', index: 2, narrower: { uses: 1 } }, { op: 'attenuate', index: 1, narrower: { uses: 2 } }, { op: 'revoke', index: 2 }, { op: 'use', index: 2 }, { op: 'use', index: 3 }, { op: 'use', index: 4 }, { op: 'revoke', index: 2 }, { op: 'revoke', index: 99 }, { op: 'revoke', index: 0 }, { op: 'revoke', index: 1 }, { op: 'use', index: 4 }, { op: 'use', index: 1 }] },
  { cls: 'egress_default_deny', steps: [mint('fs.echo', { opts: { uses: 2 } }), { op: 'use', index: 1 }, { op: 'attenuate', index: 1, narrower: { uses: 1 } }, { op: 'use', index: 2 }, { op: 'use', index: 1 }] },
  { cls: 'none', steps: [{ op: 'now', t: 1_800_000_000_000 }, { op: 'mint', operation: { verb: 'fs.echo', resource: 'r', params: { nested: { b: [1, 2.5, 'x', null, true], a: 'é' }, n: 0 } }, id: 'idx' }, { op: 'use', index: 1 }] },
  { cls: 'none', steps: [mint('fs.read', { bind: { ...op('fs.read'), id: undefined } }), { op: 'use', index: 1 }] },
];
for (const [i, s] of hs.entries()) await run('handles', `${i}`, handles, [s]);

refWrite(o, 'sandbox');
