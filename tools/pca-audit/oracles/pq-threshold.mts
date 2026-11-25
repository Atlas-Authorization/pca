// Oracle: @atlasauth/pca-pq-threshold (signed FROST group descriptor, ML-DSA-65 pqT-of-m quorum, hybrid threshold verification).
// Deterministic: Ed25519 and ML-DSA-65 (FIPS 204, deterministic signing) keys derive from fixed seeds. The "FROST aggregate" in hybrid artifacts is an
// ordinary Ed25519 signature by the group key over thresholdMessage(action): that is exactly what the verifier checks (the FROST signing protocol
// itself is not part of this package's verifier surface and is not covered). Bytes cross as {"$bytes"}; the lattice-threshold research prototype
// (experimental) and the hooks that need the core PCActn verifier (createHybridThresholdVerifier / verifyHybridStepUp / foldHybridStepUp) are not covered.
// PORTING (fn(args) -> native entry point; compared by JSON value; a reference throw requires the native to throw):
//   signerSetCommitment(participants) -> string            participants: [{identifier, publicKey: b64u}]
//   issueGroupDescriptor({authoritySeed, groupPublicKey, t, participants}) -> {descriptor, authority, sig}   (authoritySeed: {$bytes} 32-byte Ed25519 seed)
//   verifyGroupDescriptor(s, {trustedAuthorities, groupKey, t, signerSetCommitment?}) -> {ok, descriptor} | {ok:false, reason}
//   normalizePqQuorumPool(pks) -> sorted array of canonical b64u keys
//   pqQuorumRepresentative(msg) -> bytes
//   verifyPqQuorum(block, msg, pool, pqT) -> {ok, count, need, reason?}     (pool: array of b64u keys, normalised by the wrapper)
//   verifyHybridThreshold(action, artifact, opts) -> {ok, frost, pq, reason?}   opts: {groupKey, pqPublicKeys, t, pqT, groupDescriptor, trustedAuthorities, signerSetCommitment?}
//   (a string pqPublicKeys is not generated: JavaScript iterates its characters, the native refuses it)
import * as T0 from '@atlasauth/pca-pq-threshold';
import * as P0 from '@atlasauth/pca';
import * as FR0 from '@atlasauth/pca/ext/frost';
import { Oracle, refWrite, seed } from './lib.mjs';

const T: any = (T0 as any).default ?? T0;
const P: any = (P0 as any).mintRoot ? P0 : (P0 as any).default;
const FR: any = (FR0 as any).default ?? FR0;
const o = new Oracle('pq-threshold', 'tools/pca-audit/oracles/pq-threshold.mts', 'TS-reference oracle for the PQ threshold step-up verifier.');
const B = (u: Uint8Array) => ({ $bytes: Buffer.from(u).toString('base64url') });
const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64url');
const un = (v: any): any => {
  if (Array.isArray(v)) return v.map(un);
  if (v !== null && typeof v === 'object') {
    if (typeof v.$bytes === 'string' && Object.keys(v).length === 1) return new Uint8Array(Buffer.from(v.$bytes, 'base64url'));
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, un(x)]));
  }
  return v;
};
const run = (fn: string, name: string, f: (...a: any[]) => any, args: any[]) => o.run(fn, name, f, args);
const ed = (l: string) => { const s = seed('ref-pqt/' + l); return { s, pk: b64(P.publicKeyOf(s)) }; };
const AUTH = ed('auth'), AUTH2 = ed('auth2'), GRP = ed('group'), GRP2 = ed('group2');
const SH = [1, 2, 3, 4, 5].map((i) => ed('share' + i));
const parts = (n: number, base = 1) => SH.slice(0, n).map((s, i) => ({ identifier: base + i, publicKey: s.pk }));
const PQ = ['pq1', 'pq2', 'pq3', 'pq4'].map((l) => P.mlDsa65Keygen(seed('ref-pqt/' + l)));

// ---- signer set commitment
const ssc = (ps: any) => T.signerSetCommitment(ps);
await run('signerSetCommitment', 'one', ssc, [parts(1)]);
await run('signerSetCommitment', 'three', ssc, [parts(3)]);
await run('signerSetCommitment', 'five', ssc, [parts(5)]);
await run('signerSetCommitment', 'shuffled', ssc, [[parts(3)[2], parts(3)[0], parts(3)[1]]]);
await run('signerSetCommitment', 'big-ids', ssc, [[{ identifier: 9007199254740991, publicKey: SH[0].pk }, { identifier: 7, publicKey: SH[1].pk }]]);
for (const [nm, ps] of [
  ['empty', []], ['not-array', { a: 1 }], ['null', null], ['dup-id', [{ identifier: 1, publicKey: SH[0].pk }, { identifier: 1, publicKey: SH[1].pk }]],
  ['id-0', [{ identifier: 0, publicKey: SH[0].pk }]], ['id-neg', [{ identifier: -1, publicKey: SH[0].pk }]], ['id-1.5', [{ identifier: 1.5, publicKey: SH[0].pk }]], ['id-2^53', [{ identifier: 2 ** 53, publicKey: SH[0].pk }]],
  ['id-str', [{ identifier: '1', publicKey: SH[0].pk }]], ['id-missing', [{ publicKey: SH[0].pk }]], ['pk-short', [{ identifier: 1, publicKey: SH[0].pk.slice(0, -4) }]], ['pk-missing', [{ identifier: 1 }]],
  ['pk-noncanon', [{ identifier: 1, publicKey: SH[0].pk.slice(0, -1) + (SH[0].pk.endsWith('A') ? 'B' : 'A') }]], ['pk-pad', [{ identifier: 1, publicKey: SH[0].pk + '=' }]], ['null-entry', [null]], ['pk-num', [{ identifier: 1, publicKey: 5 }]],
  ['too-many', Array.from({ length: 1025 }, (_, i) => ({ identifier: i + 1, publicKey: SH[0].pk }))],
] as [string, any][]) await run('signerSetCommitment', nm, ssc, [ps]);
await run('signerSetCommitment', 'pk-bytes', (ps: any) => T.signerSetCommitment(un(ps)), [[{ identifier: 1, publicKey: B(P.decodeB64uStrict ? P.decodeB64uStrict(SH[0].pk, 32) : Buffer.from(SH[0].pk, 'base64url')) }]]);

// ---- issue / verify descriptor
const issue = (a: any) => T.issueGroupDescriptor({ authoritySecretKey: un(a.authoritySeed), groupPublicKey: a.groupPublicKey, t: a.t, participants: a.participants });
const iargs = (over: any = {}) => ({ authoritySeed: B(AUTH.s), groupPublicKey: GRP.pk, t: 2, participants: parts(3), ...over });
await run('issueGroupDescriptor', 't2n3', issue, [iargs()]);
await run('issueGroupDescriptor', 't1n1', issue, [iargs({ t: 1, participants: parts(1) })]);
await run('issueGroupDescriptor', 't3n5', issue, [iargs({ t: 3, participants: parts(5) })]);
await run('issueGroupDescriptor', 'auth2', issue, [iargs({ authoritySeed: B(AUTH2.s) })]);
for (const [nm, over] of [
  ['t0', { t: 0 }], ['t>n', { t: 4 }], ['t1.5', { t: 1.5 }], ['t-str', { t: '2' }], ['t-null', { t: null }], ['gpk-short', { groupPublicKey: GRP.pk.slice(0, -4) }], ['gpk-num', { groupPublicKey: 5 }],
  ['auth-short', { authoritySeed: B(new Uint8Array(31)) }], ['auth-null', { authoritySeed: null }], ['dup', { participants: [...parts(2), parts(1)[0]] }], ['empty', { participants: [], t: 1 }],
] as [string, any][]) await run('issueGroupDescriptor', nm, issue, [iargs(over)]);

const D = (t = 2, n = 3, auth = AUTH, gpk = GRP.pk) => issue(iargs({ authoritySeed: B(auth.s), groupPublicKey: gpk, t, participants: parts(n) }));
const D23 = D(), D11 = D(1, 1), D35 = D(3, 5);
const SSC3 = T.signerSetCommitment(parts(3));
const vd = (s: any, e: any) => T.verifyGroupDescriptor(s, e);
const exp = (over: any = {}) => ({ trustedAuthorities: [AUTH.pk], groupKey: GRP.pk, t: 2, ...over });
const flip = (s: string) => b64(Uint8Array.from(Buffer.from(s, 'base64url').map((x, i) => (i === 2 ? x ^ 1 : x))));
const clone = (x: any) => JSON.parse(JSON.stringify(x));
const mod = (path: string[], v: any, base = D23) => { const c = clone(base); let cur = c; for (const k of path.slice(0, -1)) cur = cur[k]; if (v === undefined) delete cur[path[path.length - 1]]; else cur[path[path.length - 1]] = v; return c; };
const VCASES: [string, any, any][] = [
  ['ok', D23, exp()], ['ok-t1', D11, exp({ t: 1 })], ['ok-t3', D35, exp({ t: 3 })], ['ok-pin-ssc', D23, exp({ signerSetCommitment: SSC3 })], ['ok-multi-auth', D23, exp({ trustedAuthorities: [AUTH2.pk, AUTH.pk] })],
  ['wrong-ssc', D23, exp({ signerSetCommitment: T.signerSetCommitment(parts(2)) })], ['t-too-low', D23, exp({ t: 1 })], ['t-too-high', D23, exp({ t: 3 })], ['t-0', D23, exp({ t: 0 })], ['t-1.5', D23, exp({ t: 1.5 })], ['t-str', D23, exp({ t: '2' })], ['t-missing', D23, { trustedAuthorities: [AUTH.pk], groupKey: GRP.pk }],
  ['untrusted', D23, exp({ trustedAuthorities: [AUTH2.pk] })], ['no-trusted', D23, exp({ trustedAuthorities: [] })], ['trusted-not-array', D23, exp({ trustedAuthorities: 'x' })], ['trusted-obj', D23, exp({ trustedAuthorities: {} })], ['trusted-junk', D23, exp({ trustedAuthorities: [5, null, AUTH.pk] })],
  ['other-group', D23, exp({ groupKey: GRP2.pk })], ['group-num', D23, exp({ groupKey: 7 })], ['group-missing', D23, { trustedAuthorities: [AUTH.pk], t: 2 }],
  ['null', null, exp()], ['undefined-ish', {}, exp()], ['string', 'x', exp()], ['num', 5, exp()], ['true', true, exp()], ['array', [], exp()], ['array-with', [D23], exp()],
  ['no-descriptor', mod(['descriptor'], undefined), exp()], ['descriptor-null', mod(['descriptor'], null), exp()], ['descriptor-str', mod(['descriptor'], 'x'), exp()], ['descriptor-array', mod(['descriptor'], []), exp()],
  ['no-authority', mod(['authority'], undefined), exp()], ['authority-num', mod(['authority'], 5), exp()], ['no-sig', mod(['sig'], undefined), exp()], ['sig-num', mod(['sig'], 5), exp()],
  ['v2', mod(['descriptor', 'v'], 2), exp()], ['v-str', mod(['descriptor', 'v'], '1'), exp()], ['v-missing', mod(['descriptor', 'v'], undefined), exp()], ['suite-x', mod(['descriptor', 'suite'], 'x'), exp()],
  ['gpk-num', mod(['descriptor', 'groupPublicKey'], 5), exp()], ['ssc-num', mod(['descriptor', 'signerSetCommitment'], 5), exp()], ['ssc-missing', mod(['descriptor', 'signerSetCommitment'], undefined), exp()],
  ['t-0d', mod(['descriptor', 't'], 0), exp()], ['t-1.5d', mod(['descriptor', 't'], 1.5), exp()], ['t-str-d', mod(['descriptor', 't'], '2'), exp()], ['n<t', mod(['descriptor', 'n'], 1), exp()], ['n-huge', mod(['descriptor', 'n'], 1025), exp()], ['n-1024', mod(['descriptor', 'n'], 1024), exp()],
  ['t-forged-3', mod(['descriptor', 't'], 3), exp({ t: 3 })], ['n-changed', mod(['descriptor', 'n'], 4), exp()], ['gpk-swapped', mod(['descriptor', 'groupPublicKey'], GRP2.pk), exp({ groupKey: GRP2.pk })], ['ssc-swapped', mod(['descriptor', 'signerSetCommitment'], T.signerSetCommitment(parts(2))), exp()],
  ['sig-flip', mod(['sig'], flip(D23.sig)), exp()], ['sig-short', mod(['sig'], D23.sig.slice(0, -4)), exp()], ['sig-empty', mod(['sig'], ''), exp()], ['sig-pad', mod(['sig'], D23.sig + '='), exp()],
  ['authority-swapped', mod(['authority'], AUTH2.pk), exp({ trustedAuthorities: [AUTH2.pk] })], ['authority-short', mod(['authority'], AUTH.pk.slice(0, -4)), exp({ trustedAuthorities: [AUTH.pk.slice(0, -4)] })],
  ['extra-member', mod(['descriptor', 'extra'], 1), exp()], ['extra-top', mod(['extra'], 1), exp()],
];
for (const [nm, s, e] of VCASES) await run('verifyGroupDescriptor', nm, vd, [s, e]);

// ---- pq quorum
const ACTIONS: any[] = [
  { ver: 2, action: { verb: 'transfer', resource: 'acct/1', params_digest: 'p', reversibility_class: 'R3' }, counter: 7, aud: 'rs', iat: 1800000000000, exp: 1800000060000 },
  { ver: 2, action: { verb: 'x', resource: 'y' }, cap_chain: [{ id: 'a', n: [1, 2, null, true] }], aud: 'é', iat: 1, exp: 2 },
  { ver: 2, sig: 'S', threshold: { t: 1 }, pq_sig: 'Q', action: { v: 'stripped' } },
];
const msgOf = (a: any) => P.thresholdMessage(a);
const MSG = msgOf(ACTIONS[0]);
await run('pqQuorumRepresentative', 'm0', (m: any) => T0 && FR.pqQuorumRepresentative(un(m)), [B(MSG)]);
await run('pqQuorumRepresentative', 'empty', (m: any) => FR.pqQuorumRepresentative(un(m)), [B(new Uint8Array())]);
await run('pqQuorumRepresentative', 'm1', (m: any) => FR.pqQuorumRepresentative(un(m)), [B(msgOf(ACTIONS[1]))]);

const norm = (pks: any) => [...FR.normalizePqQuorumPool(un(pks))].sort();
const pkB = (i: number) => b64(PQ[i].publicKey);
await run('normalizePqQuorumPool', 'empty', norm, [[]]);
await run('normalizePqQuorumPool', 'two', norm, [[pkB(0), pkB(1)]]);
await run('normalizePqQuorumPool', 'dup', norm, [[pkB(0), pkB(0), pkB(1)]]);
await run('normalizePqQuorumPool', 'bytes', norm, [[B(PQ[0].publicKey), pkB(1)]]);
await run('normalizePqQuorumPool', 'junk', norm, [[pkB(0), 'abc', '', 5, null, pkB(1).slice(0, -4), pkB(1) + '=', B(new Uint8Array(10))]]);
await run('normalizePqQuorumPool', 'noncanon', norm, [[pkB(2).slice(0, -1) + (pkB(2).endsWith('A') ? 'B' : 'A')]]);

const blk = (msg: Uint8Array, idx: number[], pqT?: number) => FR.signPqQuorum(msg, idx.map((i) => PQ[i]), pqT);
const vq = (block: any, msg: any, pool: any, pqT: any) => FR.verifyPqQuorum(block, un(msg), FR.normalizePqQuorumPool(un(pool)), pqT);
const POOL3 = [pkB(0), pkB(1), pkB(2)];
const B3 = blk(MSG, [0, 1, 2]), B2 = blk(MSG, [0, 1]);
const bm = (b: any, f: (c: any) => void) => { const c = clone(b); f(c); return c; };
const flipB = (s: string) => flip(s);
const QC: [string, any, any, any, any][] = [
  ['ok-3of3', B3, B(MSG), POOL3, 3], ['ok-2of3', B3, B(MSG), POOL3, 2], ['ok-1of3', B3, B(MSG), POOL3, 1], ['short-4of3', B3, B(MSG), POOL3, 4], ['two-sigs-need3', B2, B(MSG), POOL3, 3], ['two-sigs-need2', B2, B(MSG), POOL3, 2],
  ['other-msg', B3, B(msgOf(ACTIONS[1])), POOL3, 1], ['pool-subset', B3, B(MSG), [pkB(0), pkB(1)], 3], ['pool-subset-2', B3, B(MSG), [pkB(0), pkB(1)], 2], ['pool-empty', B3, B(MSG), [], 1], ['pool-junk', B3, B(MSG), [pkB(0), 'x'], 2],
  ['outsider', blk(MSG, [3, 3]), B(MSG), POOL3, 1], ['dup-signer', blk(MSG, [0, 0, 0]), B(MSG), POOL3, 2], ['dup-signer-1', blk(MSG, [0, 0, 0]), B(MSG), POOL3, 1],
  ['pqT-0', B3, B(MSG), POOL3, 0], ['pqT-neg', B3, B(MSG), POOL3, -1], ['pqT-1.5', B3, B(MSG), POOL3, 1.5], ['pqT-str', B3, B(MSG), POOL3, '2'], ['pqT-null', B3, B(MSG), POOL3, null],
  ['null-block', null, B(MSG), POOL3, 1], ['str-block', 'x', B(MSG), POOL3, 1], ['num-block', 5, B(MSG), POOL3, 1], ['array-block', [], B(MSG), POOL3, 1], ['empty-block', {}, B(MSG), POOL3, 1],
  ['v-missing', bm(B3, (c) => delete c.v), B(MSG), POOL3, 1], ['v1', bm(B3, (c) => { c.v = 1; }), B(MSG), POOL3, 1], ['v3', bm(B3, (c) => { c.v = 3; }), B(MSG), POOL3, 1], ['v-str', bm(B3, (c) => { c.v = '2'; }), B(MSG), POOL3, 1], ['v-null', bm(B3, (c) => { c.v = null; }), B(MSG), POOL3, 1],
  ['alg-x', bm(B3, (c) => { c.alg = 'x'; }), B(MSG), POOL3, 1], ['alg-missing', bm(B3, (c) => delete c.alg), B(MSG), POOL3, 1], ['signers-missing', bm(B3, (c) => delete c.signers), B(MSG), POOL3, 1], ['signers-obj', bm(B3, (c) => { c.signers = {}; }), B(MSG), POOL3, 1], ['signers-empty', bm(B3, (c) => { c.signers = []; }), B(MSG), POOL3, 1],
  ['sig-flip', bm(B3, (c) => { c.signers[0].sig = flipB(c.signers[0].sig); }), B(MSG), POOL3, 3], ['sig-flip-2of3', bm(B3, (c) => { c.signers[0].sig = flipB(c.signers[0].sig); }), B(MSG), POOL3, 2],
  ['sig-swapped', bm(B3, (c) => { const t = c.signers[0].sig; c.signers[0].sig = c.signers[1].sig; c.signers[1].sig = t; }), B(MSG), POOL3, 2],
  ['sig-short', bm(B3, (c) => { c.signers[1].sig = c.signers[1].sig.slice(0, -4); }), B(MSG), POOL3, 3], ['sig-num', bm(B3, (c) => { c.signers[1].sig = 5; }), B(MSG), POOL3, 3], ['pk-num', bm(B3, (c) => { c.signers[1].pk = 5; }), B(MSG), POOL3, 3],
  ['pk-missing', bm(B3, (c) => { delete c.signers[2].pk; }), B(MSG), POOL3, 3], ['entry-null', bm(B3, (c) => { c.signers[0] = null; }), B(MSG), POOL3, 3], ['entry-str', bm(B3, (c) => { c.signers.unshift('x'); }), B(MSG), POOL3, 3], ['entry-array', bm(B3, (c) => { c.signers.unshift([]); }), B(MSG), POOL3, 3],
  ['extra-fields', bm(B3, (c) => { c.extra = 1; c.signers[0].more = 2; c.pqT = 99; }), B(MSG), POOL3, 3],
  ['bare-message-sig', { v: 2, alg: 'ml-dsa-65', pqT: 1, signers: [{ pk: pkB(0), sig: b64(P.mlDsa65Sign(PQ[0].secretKey, MSG)) }] }, B(MSG), POOL3, 1],
  ['v1-style-block', { alg: 'ml-dsa-65', pqT: 1, signers: B3.signers }, B(MSG), POOL3, 1],
];
for (const [nm, b, m, pool, t] of QC) await run('verifyPqQuorum', nm, vq, [b, m, pool, t]);

// ---- hybrid
const hv = (action: any, artifact: any, opts: any) => T.verifyHybridThreshold(action, un(artifact), un(opts));
const grpSig = (a: any, g = GRP) => b64(P.sign(g.s, msgOf(a)));
const art = (a: any, idx = [0, 1, 2], over: any = {}) => {
  const msg = msgOf(a);
  return { v: 2, digest: b64(P.sha256(msg)), frost: { alg: 'frost-ed25519', group_pk: GRP.pk, sig: grpSig(a), t: 2, quorum: 3, ...(over.frost ?? {}) }, pq: over.pq ?? blk(msg, idx) };
};
const dsc = (t = 2, n = 3) => D(t, n);
const hopts = (over: any = {}) => ({ groupKey: GRP.pk, pqPublicKeys: POOL3, t: 2, pqT: 2, groupDescriptor: D23, trustedAuthorities: [AUTH.pk], ...over });
const A0 = ACTIONS[0];
const ART0 = art(A0);
const HC: [string, any, any, any][] = [
  ['ok', A0, ART0, hopts()], ['ok-pqT3', A0, ART0, hopts({ pqT: 3 })], ['ok-pqT1-2sigs', A0, art(A0, [0, 1]), hopts({ pqT: 1 })], ['ok-pin-ssc', A0, ART0, hopts({ signerSetCommitment: SSC3 })],
  ['ok-action-1', ACTIONS[1], art(ACTIONS[1]), hopts()], ['ok-action-stripped', ACTIONS[2], art(ACTIONS[2]), hopts()], ['ok-bytes-keys', A0, ART0, hopts({ groupKey: B(Buffer.from(GRP.pk, 'base64url')), trustedAuthorities: [B(Buffer.from(AUTH.pk, 'base64url'))], pqPublicKeys: POOL3.map((k) => B(Buffer.from(k, 'base64url'))) })],
  ['ok-declared-t-higher', A0, art(A0, [0, 1, 2], { frost: { t: 5 } }), hopts()],
  ['pq-short', A0, art(A0, [0]), hopts({ pqT: 2 })], ['pq-outsider', A0, art(A0, [3, 3, 3]), hopts()], ['pq-pool-wrong', A0, ART0, hopts({ pqPublicKeys: [pkB(3)] })], ['pq-block-missing', A0, { ...ART0, pq: undefined }, hopts()], ['pq-block-v1', A0, art(A0, [0, 1, 2], { pq: { ...blk(msgOf(A0), [0, 1, 2]), v: 1 } }), hopts()],
  ['frost-wrong-sig', A0, art(A0, [0, 1, 2], { frost: { sig: grpSig(A0, GRP2) } }), hopts()], ['frost-other-action-sig', A0, art(A0, [0, 1, 2], { frost: { sig: grpSig(ACTIONS[1]) } }), hopts()],
  ['frost-flip', A0, art(A0, [0, 1, 2], { frost: { sig: flip(grpSig(A0)) } }), hopts()], ['frost-sig-num', A0, art(A0, [0, 1, 2], { frost: { sig: 5 } }), hopts()], ['frost-sig-short', A0, art(A0, [0, 1, 2], { frost: { sig: grpSig(A0).slice(0, -4) } }), hopts()],
  ['frost-alg-x', A0, art(A0, [0, 1, 2], { frost: { alg: 'x' } }), hopts()], ['frost-missing', A0, { ...ART0, frost: undefined }, hopts()], ['frost-null', A0, { ...ART0, frost: null }, hopts()], ['frost-str', A0, { ...ART0, frost: 'x' }, hopts()],
  ['declared-t-low', A0, art(A0, [0, 1, 2], { frost: { t: 1 } }), hopts()], ['declared-t-str', A0, art(A0, [0, 1, 2], { frost: { t: '2' } }), hopts()], ['declared-t-1.5', A0, art(A0, [0, 1, 2], { frost: { t: 2.5 } }), hopts()],
  ['declared-group-other', A0, art(A0, [0, 1, 2], { frost: { group_pk: GRP2.pk } }), hopts()],
  ['trusted-group-other', A0, ART0, hopts({ groupKey: GRP2.pk, groupDescriptor: D(2, 3, AUTH, GRP2.pk) })], ['group-key-short', A0, ART0, hopts({ groupKey: GRP.pk.slice(0, -4) })], ['group-key-num', A0, ART0, hopts({ groupKey: 5 })],
  ['desc-t1-for-t2', A0, ART0, hopts({ groupDescriptor: D11 })], ['desc-untrusted', A0, ART0, hopts({ trustedAuthorities: [AUTH2.pk] })], ['desc-missing', A0, ART0, hopts({ groupDescriptor: undefined })], ['desc-null', A0, ART0, hopts({ groupDescriptor: null })],
  ['desc-wrong-ssc-pin', A0, ART0, hopts({ signerSetCommitment: T.signerSetCommitment(parts(2)) })], ['desc-for-other-group', A0, ART0, hopts({ groupDescriptor: D(2, 3, AUTH, GRP2.pk) })], ['desc-auth-not-array', A0, ART0, hopts({ trustedAuthorities: 'x' })],
  ['t-0', A0, ART0, hopts({ t: 0 })], ['t-str', A0, ART0, hopts({ t: '2' })], ['t-3-desc2', A0, ART0, hopts({ t: 3 })], ['t-missing', A0, ART0, hopts({ t: undefined })],
  ['pqT-0', A0, ART0, hopts({ pqT: 0 })], ['pqT-missing', A0, ART0, hopts({ pqT: undefined })], ['pqT-str', A0, ART0, hopts({ pqT: '2' })],
  ['ver-missing', A0, { ...ART0, v: undefined }, hopts()], ['ver-1', A0, { ...ART0, v: 1 }, hopts()], ['ver-3', A0, { ...ART0, v: 3 }, hopts()], ['ver-str', A0, { ...ART0, v: '2' }, hopts()], ['ver-null', A0, { ...ART0, v: null }, hopts()], ['artifact-null', A0, null, hopts()], ['artifact-str', A0, 'x', hopts()], ['artifact-empty', A0, {}, hopts()],
  ['ver-1-pqT-str', A0, { ...ART0, v: 1 }, hopts({ pqT: 'x' })],
  ['action-other', ACTIONS[1], ART0, hopts()], ['action-tampered', { ...A0, counter: 8 }, ART0, hopts()], 
  ['pq-pks-not-iterable', A0, ART0, hopts({ pqPublicKeys: {} })], ['pq-pks-missing', A0, ART0, hopts({ pqPublicKeys: undefined })], ['pq-pks-junk', A0, ART0, hopts({ pqPublicKeys: [...POOL3, 'x', 5, null] })],
  ['both-short', A0, art(A0, [3], { frost: { sig: grpSig(A0, GRP2) } }), hopts()],
];
for (const [nm, a, artf, op] of HC) await run('verifyHybridThreshold', nm, hv, [a, artf, op]);
void dsc;
refWrite(o, 'pq-threshold');
