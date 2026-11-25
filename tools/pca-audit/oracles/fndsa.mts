// Oracle: @atlasauth/pca-fndsa (FN-DSA / Falcon suite registry, wire framing, hybrid composition, pluggable backend seam, deterministic mock backend).
// The mock backend's keys (mockKeypair) are SHA-derived from the public strings 'ref' / 'other' (or caller bytes): they have no secrecy and no real key
// is involved, so the corpus carries them as plain values. The primitive itself is NOT covered: the reference ships no Falcon math (a vetted backend is plugged in), so every case runs through the
// deterministic hash-derived mock backend or an explicit stub backend ("kind"). Ed25519 halves are deterministic. Bytes cross as {"$bytes"}.
// PORTING (fn(args) -> native entry point; compared by JSON value; a reference throw requires the native to throw):
//   resolveFnDsaAlg(alg) -> suite {alg, variant, hasEd25519, sigBytes, needsPqPk, pqPkBytes, needsPqSig, pqSigBytes, fnSigBytes} | null     (alg is any JSON value)
//   isKnownFnDsaAlg(x) / isFnDsaVariant(x) -> boolean
//   hashKat(seed, outLen) -> bytes          mockKeypair(variant, seed) -> {pk, sk}  (seed: string or bytes)
//   fndsaLeafMessage(leaf, alg, pqPkB64u) -> bytes
//   fndsaSignWith(kind, variant, sk, msg) / fndsaVerifyWith(kind, variant, pk, msg, sig)
//        kind: "mock" (registerTestBackend()), "none" (default backend: throws once the length guard passes), "verify-only" (mock verify, no sign),
//        "short-sig" (sign returns 10 bytes), "all-true" (verify always true), "throws" (verify throws), "kat" (verify fndsaVerifyKat only)
//   fndsaVerifyKat(variant, pk, msg, sig, vectors) -> boolean       mock backend registered with explicit [{pk, msg, sig}] vectors
//   fndsaSignKat(vectors) -> bytes   (mock backend with vectors; signs mockKeypair("fn-dsa-512" / "fn-dsa-1024" per case name) message "m" - see the case name suffix)
//   signPcaWithFndsa({alg, leaf, fnDsa:{pk, sk}, edSecret?}) -> {sig, alg, pq_pk, pq_sig?}   (mock backend; edSecret is a 32-byte seed)
//   verifyPcaFndsa({alg, leaf, holder?, pq_pk?, sig?, pq_sig?}) -> boolean   (mock backend; kind "none" via verifyPcaFndsaNone: throws after every guard passes)
import * as F0 from '@atlasauth/pca-fndsa';
import * as P0 from '@atlasauth/pca';
import { Oracle, refWrite, rng, seed } from './lib.mjs';

const F: any = (F0 as any).default ?? F0;
const P: any = (P0 as any).mintRoot ? P0 : (P0 as any).default;
const o = new Oracle('fndsa', 'tools/pca-audit/oracles/fndsa.mts', 'TS-reference oracle for the FN-DSA suite registry, framing and hybrid composition (mock backend).');
const r = rng(0xf1d5a);
const B = (u: Uint8Array) => ({ $bytes: Buffer.from(u).toString('base64url') });
const un = (v: any): any => {
  if (Array.isArray(v)) return v.map(un);
  if (v !== null && typeof v === 'object') {
    if (typeof v.$bytes === 'string' && Object.keys(v).length === 1) return new Uint8Array(Buffer.from(v.$bytes, 'base64url'));
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, un(x)]));
  }
  return v;
};
const bytes = (n: number) => Uint8Array.from({ length: n }, () => r.int(0, 255));
const VARS = ['fn-dsa-512', 'fn-dsa-1024'];
const ALGS = ['fn-dsa-512', 'fn-dsa-1024', 'hybrid-ed25519-fn-dsa-512', 'hybrid-ed25519-fn-dsa-1024'];
const SZ: any = { 'fn-dsa-512': [897, 666], 'fn-dsa-1024': [1793, 1280] };
const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64url');

const install = (kind: string) => {
  F.resetFalconBackend();
  const mock = F.registerTestBackend();
  const lenOf = (pk: Uint8Array) => (pk.length === 897 ? 666 : 1280);
  if (kind === 'mock') return;
  if (kind === 'none') { F.resetFalconBackend(); return; }
  if (kind === 'verify-only') { F.setFalconBackend({ verify: mock.verify }); return; }
  if (kind === 'short-sig') { F.setFalconBackend({ verify: mock.verify, sign: () => new Uint8Array(10) }); return; }
  if (kind === 'all-true') { F.setFalconBackend({ verify: () => true, sign: mock.sign }); return; }
  if (kind === 'throws') { F.setFalconBackend({ verify: () => { throw new Error('backend exploded'); }, sign: mock.sign }); return; }
  void lenOf;
  throw new Error('kind ' + kind);
};
const withBackend = (kind: string, f: () => any) => { try { install(kind); return f(); } finally { F.resetFalconBackend(); } };
const run = (fn: string, name: string, f: (...a: any[]) => any, args: any[]) => o.run(fn, name, f, args);

// ---- registry
const suiteJson = (s: any) => (s === null ? null : { ...s });
for (const v of [...ALGS, 'ed25519', 'fn-dsa', 'FN-DSA-512', '', 'constructor', '__proto__', 'toString', 'hasOwnProperty', 'hybrid-ed25519-fn-dsa-512 ', null, 5, true, [], {}, ['fn-dsa-512']]) {
  const t = JSON.stringify(v);
  await run('resolveFnDsaAlg', t, (a: any) => suiteJson(F.resolveFnDsaAlg(a)), [v]);
  await run('isKnownFnDsaAlg', t, (a: any) => F.isKnownFnDsaAlg(a), [v]);
  await run('isFnDsaVariant', t, (a: any) => F.isFnDsaVariant(a), [v]);
}

// ---- mock keys / hashKat
for (const n of [0, 1, 31, 32, 33, 64, 666, 897, 1280, 1793]) for (const s of [new Uint8Array(), new Uint8Array([1, 2, 3]), seed('ref-fndsa/h')]) {
  if (n > 100 && s.length === 3) continue;
  await run('hashKat', `n${n}-s${s.length}`, (a: any, l: number) => F.hashKat(un(a), l), [B(s), n]);
}
await run('hashKat', 'neg', (a: any, l: number) => F.hashKat(un(a), l), [B(new Uint8Array(1)), -1]);
for (const v of VARS) for (const s of ['default', 'a', '', 'é', 'x'.repeat(50)]) await run('mockKeypair', `${v}-${s.slice(0, 3)}${s.length}`, (vv: any, ss: any) => F.mockKeypair(vv, un(ss)), [v, s]);
for (const v of VARS) for (const s of [new Uint8Array(), bytes(32)]) await run('mockKeypair', `${v}-bytes${s.length}`, (vv: any, ss: any) => F.mockKeypair(vv, un(ss)), [v, B(s)]);
for (const v of ['fn-dsa-256', '', null, 'hybrid-ed25519-fn-dsa-512']) await run('mockKeypair', `bad-${v}`, (vv: any) => F.mockKeypair(vv), [v]);

// ---- fixtures
const KP: Record<string, any> = {};
for (const v of VARS) { KP[v] = F.mockKeypair(v, 'ref'); KP[v + '2'] = F.mockKeypair(v, 'other'); }
const MSGS = [new Uint8Array(), new TextEncoder().encode('m'), bytes(100)];
const LEAVES: any[] = [
  { ver: 2, action: { verb: 'revoke', resource: 'sess/1', params_digest: 'p', reversibility_class: 'R1' }, grant_ref: 'g', counter: 7, aud: 'rs', iat: 1800000000000, exp: 1800000060000 },
  { ver: 2, action: { verb: 'x', resource: 'y' }, cap_chain: [{ id: 'a', n: [1, 2, null, true] }], aud: 'é', iat: 1, exp: 2, alg: 'ignored-in-leaf' },
  { ver: 2, sig: 'S', threshold: { t: 1 }, pq_sig: 'Q', action: { v: 'sigs are stripped' } },
  {},
];
const EDS = seed('ref-fndsa/ed');
const holder = b64(P.publicKeyOf(EDS));

// ---- leaf message
for (const [li, leaf] of LEAVES.entries()) for (const a of ALGS) for (const pk of ['', 'AAAA', b64(KP['fn-dsa-512'].pk)]) {
  if (li > 1 && pk === 'AAAA') continue;
  await run('fndsaLeafMessage', `l${li}-${a}-${pk.length}`, (l: any, al: any, p: any) => F.fndsaLeafMessage(l, al, p), [leaf, a, pk]);
}
await run('fndsaLeafMessage', 'unicode-alg', (l: any, al: any, p: any) => F.fndsaLeafMessage(l, al, p), [LEAVES[0], 'é', 'ü']);

// ---- primitive sign / verify through every backend kind
for (const v of VARS) for (const [mi, m] of MSGS.entries()) {
  const kp = KP[v];
  await run('fndsaSignWith', `${v}-mock-m${mi}`, (k: string, vv: any, sk: any, mm: any) => withBackend(k, () => F.fndsaSign(vv, un(sk), un(mm))), ['mock', v, B(kp.sk), B(m)]);
  const sig = withBackend('mock', () => F.fndsaSign(v, kp.sk, m));
  await run('fndsaVerifyWith', `${v}-mock-m${mi}-ok`, (k: string, vv: any, pk: any, mm: any, s: any) => withBackend(k, () => F.fndsaVerify(vv, un(pk), un(mm), un(s))), ['mock', v, B(kp.pk), B(m), B(sig)]);
  const bad = Uint8Array.from(sig); bad[bad.length >> 1] ^= 1;
  await run('fndsaVerifyWith', `${v}-mock-m${mi}-flip`, (k: string, vv: any, pk: any, mm: any, s: any) => withBackend(k, () => F.fndsaVerify(vv, un(pk), un(mm), un(s))), ['mock', v, B(kp.pk), B(m), B(bad)]);
  if (mi === 1) {
    for (const [nm, args] of [
      ['other-pk', ['mock', v, B(KP[v + '2'].pk), B(m), B(sig)]], ['other-msg', ['mock', v, B(kp.pk), B(bytes(3)), B(sig)]],
      ['short-sig', ['mock', v, B(kp.pk), B(m), B(sig.subarray(1))]], ['long-sig', ['mock', v, B(kp.pk), B(m), B(new Uint8Array([...sig, 0]))]],
      ['short-pk', ['mock', v, B(kp.pk.subarray(1)), B(m), B(sig)]], ['long-pk', ['mock', v, B(new Uint8Array([...kp.pk, 0])), B(m), B(sig)]],
      ['other-variant-pk', ['mock', v, B(KP[v === VARS[0] ? VARS[1] : VARS[0]].pk), B(m), B(sig)]],
      ['bad-variant', ['mock', 'fn-dsa-256', B(kp.pk), B(m), B(sig)]], ['hybrid-variant', ['mock', 'hybrid-ed25519-fn-dsa-512', B(kp.pk), B(m), B(sig)]],
      ['msg-null', ['mock', v, B(kp.pk), null, B(sig)]], ['pk-str', ['mock', v, 'x', B(m), B(sig)]], ['sig-null', ['mock', v, B(kp.pk), B(m), null]],
      ['none-ok-lengths', ['none', v, B(kp.pk), B(m), B(sig)]], ['none-short', ['none', v, B(kp.pk), B(m), B(sig.subarray(1))]],
      ['all-true', ['all-true', v, B(kp.pk), B(m), B(bytes(sig.length))]], ['all-true-short', ['all-true', v, B(kp.pk), B(m), B(bytes(sig.length - 1))]], ['all-true-badpk', ['all-true', v, B(bytes(5)), B(m), B(sig)]],
      ['throws', ['throws', v, B(kp.pk), B(m), B(sig)]], ['throws-short', ['throws', v, B(kp.pk), B(m), B(sig.subarray(1))]],
    ] as [string, any[]][]) await run('fndsaVerifyWith', `${v}-${nm}`, (k: string, vv: any, pk: any, mm: any, s: any) => withBackend(k, () => F.fndsaVerify(vv, un(pk), un(mm), un(s))), args);
    for (const [nm, args] of [
      ['none', ['none', v, B(kp.sk), B(m)]], ['verify-only', ['verify-only', v, B(kp.sk), B(m)]], ['short-sig', ['short-sig', v, B(kp.sk), B(m)]],
      ['sk-empty', ['mock', v, B(new Uint8Array()), B(m)]], ['sk-foreign', ['mock', v, B(bytes(40)), B(m)]], ['sk-null', ['mock', v, null, B(m)]], ['msg-null', ['mock', v, B(kp.sk), null]], ['msg-str', ['mock', v, B(kp.sk), 'abc']],
      ['bad-variant', ['mock', 'x', B(kp.sk), B(m)]], ['all-true', ['all-true', v, B(kp.sk), B(m)]],
    ] as [string, any[]][]) await run('fndsaSignWith', `${v}-${nm}`, (k: string, vv: any, sk: any, mm: any) => withBackend(k, () => F.fndsaSign(vv, un(sk), un(mm))), args);
  }
}
// KAT table precedence
for (const v of VARS) {
  const kp = KP[v], m = MSGS[1];
  const kat = bytes(SZ[v][1]);
  const vecs = [{ pk: B(kp.pk), msg: B(m), sig: B(kat) }];
  const f = (vv: any, pk: any, mm: any, s: any, vs: any) => { F.resetFalconBackend(); F.registerTestBackend(un(vs)); try { return F.fndsaVerify(vv, un(pk), un(mm), un(s)); } finally { F.resetFalconBackend(); } };
  await run('fndsaVerifyKat', `${v}-kat`, f, [v, B(kp.pk), B(m), B(kat), vecs]);
  await run('fndsaVerifyKat', `${v}-derived-rejected`, f, [v, B(kp.pk), B(m), B(withBackend('mock', () => F.fndsaSign(v, kp.sk, m))), vecs]);
  await run('fndsaVerifyKat', `${v}-other-msg-derived`, f, [v, B(kp.pk), B(MSGS[2]), B(withBackend('mock', () => F.fndsaSign(v, kp.sk, MSGS[2]))), vecs]);
  await run('fndsaVerifyKat', `${v}-no-vectors`, f, [v, B(kp.pk), B(m), B(kat), []]);
  const sgn = (vs: any) => { F.resetFalconBackend(); F.registerTestBackend(un(vs)); try { return F.fndsaSign(v, kp.sk, m); } finally { F.resetFalconBackend(); } };
  await run('fndsaSignKat', `${v}`, (vs: any) => { F.resetFalconBackend(); F.registerTestBackend(un(vs)); try { return F.fndsaSign(v, kp.sk, m); } finally { F.resetFalconBackend(); } }, [vecs]);
  void sgn;
}

// ---- PCA leaf signing / verification
const sp = (input: any) => withBackend('mock', () => F.signPcaWithFndsa(un(input)));
const vp = (input: any) => withBackend('mock', () => F.verifyPcaFndsa(un(input)));
const vpNone = (input: any) => withBackend('none', () => F.verifyPcaFndsa(un(input)));
const good: Record<string, any> = {};
for (const a of ALGS) {
  const v = a.endsWith('512') ? 'fn-dsa-512' : 'fn-dsa-1024';
  for (const [li, leaf] of LEAVES.entries()) {
    const inp = { alg: a, leaf, fnDsa: { pk: B(KP[v].pk), sk: B(KP[v].sk) }, ...(a.startsWith('hybrid') ? { edSecret: B(EDS) } : {}) };
    await run('signPcaWithFndsa', `${a}-l${li}`, sp, [inp]);
    const f = sp(inp);
    good[`${a}-${li}`] = { f, inp };
    const vin = (over: any = {}) => ({ alg: f.alg, leaf, ...(a.startsWith('hybrid') ? { holder } : {}), pq_pk: f.pq_pk, sig: f.sig, ...(f.pq_sig ? { pq_sig: f.pq_sig } : {}), ...over });
    await run('verifyPcaFndsa', `${a}-l${li}-ok`, vp, [vin()]);
    if (li > 1) continue;
    const L2 = { ...leaf, tampered: 1 };
    const flip = (s: string) => b64(Uint8Array.from(Buffer.from(s, 'base64url').map((x, i) => (i === 3 ? x ^ 1 : x))));
    const cases: [string, any][] = [
      ['tampered-leaf', vin({ leaf: L2 })], ['other-alg', vin({ alg: ALGS[(ALGS.indexOf(a) + 1) % 4] })], ['bad-alg', vin({ alg: 'x' })], ['alg-null', vin({ alg: null })],
      ['pq_pk-other', vin({ pq_pk: b64(KP[v + '2'].pk) })], ['pq_pk-short', vin({ pq_pk: b64(KP[v].pk.subarray(1)) })], ['pq_pk-missing', vin({ pq_pk: undefined })], ['pq_pk-num', vin({ pq_pk: 5 })],
      ['pq_pk-noncanon', vin({ pq_pk: f.pq_pk.slice(0, -1) + (f.pq_pk.endsWith('A') ? 'B' : 'A') })], ['pq_pk-pad', vin({ pq_pk: f.pq_pk + '=' })],
      ['sig-flip', vin({ sig: flip(f.sig) })], ['sig-missing', vin({ sig: undefined })], ['sig-short', vin({ sig: f.sig.slice(0, -4) })], ['sig-num', vin({ sig: 1 })], ['sig-empty', vin({ sig: '' })], ['sig-zero', vin({ sig: b64(new Uint8Array(SZ[v][1])) })],
    ];
    if (a.startsWith('hybrid')) cases.push(
      ['pq_sig-flip', vin({ pq_sig: flip(f.pq_sig) })], ['pq_sig-missing', vin({ pq_sig: undefined })], ['pq_sig-short', vin({ pq_sig: f.pq_sig.slice(0, -4) })], ['pq_sig-zero', vin({ pq_sig: b64(new Uint8Array(SZ[v][1])) })],
      ['holder-other', vin({ holder: b64(P.publicKeyOf(seed('ref-fndsa/ed2'))) })], ['holder-missing', vin({ holder: undefined })], ['holder-num', vin({ holder: 7 })], ['holder-short', vin({ holder: holder.slice(0, -4) })],
      ['sig-swap', vin({ sig: f.pq_sig, pq_sig: f.sig })], ['sig-is-pq', vin({ sig: f.pq_sig })],
    );
    else cases.push(['holder-ignored', vin({ holder: 'junk' })], ['pq_sig-ignored', vin({ pq_sig: 'junk' })]);
    for (const [nm, inp2] of cases) await run('verifyPcaFndsa', `${a}-l${li}-${nm}`, vp, [inp2]);
    await run('verifyPcaFndsaNone', `${a}-l${li}-ok`, vpNone, [vin()]);
    await run('verifyPcaFndsaNone', `${a}-l${li}-bad-alg`, vpNone, [vin({ alg: 'x' })]);
    await run('verifyPcaFndsaNone', `${a}-l${li}-sig-short`, vpNone, [vin({ sig: f.sig.slice(0, -4) })]);
  }
}
// sign errors
for (const a of ['fn-dsa-512', 'hybrid-ed25519-fn-dsa-1024']) {
  const v = a.endsWith('512') ? 'fn-dsa-512' : 'fn-dsa-1024';
  const base = { alg: a, leaf: LEAVES[0], fnDsa: { pk: B(KP[v].pk), sk: B(KP[v].sk) }, edSecret: B(EDS) };
  for (const [nm, inp] of [
    ['wrong-pk-len', { ...base, fnDsa: { pk: B(KP[v].pk.subarray(1)), sk: B(KP[v].sk) } }], ['pk-other-variant', { ...base, fnDsa: { pk: B(KP[v === 'fn-dsa-512' ? 'fn-dsa-1024' : 'fn-dsa-512'].pk), sk: B(KP[v].sk) } }],
    ['sk-empty', { ...base, fnDsa: { pk: B(KP[v].pk), sk: B(new Uint8Array()) } }], ['sk-foreign', { ...base, fnDsa: { pk: B(KP[v].pk), sk: B(bytes(30)) } }], ['no-fnDsa', { alg: a, leaf: LEAVES[0] }], ['fnDsa-null', { ...base, fnDsa: null }],
    ['bad-alg', { ...base, alg: 'x' }], ['no-ed', { alg: a, leaf: LEAVES[0], fnDsa: base.fnDsa }], ['ed-short', { ...base, edSecret: B(bytes(31)) }], ['ed-str', { ...base, edSecret: 'abc' }],
  ] as [string, any][]) await run('signPcaWithFndsa', `${a}-${nm}`, sp, [inp]);
}
refWrite(o, 'fndsa');
