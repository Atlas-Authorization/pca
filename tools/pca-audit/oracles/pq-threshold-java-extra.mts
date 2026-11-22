// Oracle (extra): the signing / PCActn-verifier side of @atlasauth/pca-pq-threshold that pq-threshold.mts leaves out:
// hybridThresholdSign (real FROST quorum + ML-DSA co-signers), foldHybridStepUp, createHybridThresholdVerifier (the core threshold hook) and
// verifyHybridStepUp (the full core verifier with the hybrid hook). Deterministic inputs (keys, FROST dealer shares, ML-DSA keys from seeds); FROST nonces
// are random in the reference, so hybridThresholdSign cases record everything except the frost signature bytes plus the verdict of the standalone verifier.
// PORTING (fn(args) -> native entry point; compared by JSON value; a reference throw requires the native to throw):
//   hybridSign({t, n, secret, coefficients, quorum:[id], pq:[index into pqSeeds], pqSeeds:[4 ML-DSA-65 keygen seeds], authSeed (the descriptor authority's Ed25519 seed), pqT?, signT?, groupAsString?, action}) ->
//       {artifact: {v, digest, frost: {alg, group_pk, t, quorum}, pq}, verdict}   (HybridThreshold.hybridThresholdSign with the dealer's shares, then
//       PqThreshold.verifyHybridThreshold over the artifact; the frost `sig` is omitted from the output (random nonces), the verdict proves it verifies)
//   fold(action, artifact) -> {pcactn, pq}                                          HybridThreshold.foldHybridStepUp
//   hook(opts, pcactn) -> {enforced, ok, reason?}                                   HybridThreshold.createHybridThresholdVerifier(opts) invoked on a context
//       with that pcactn (opts: groupKey, pqPublicKeys, t, pqT, pqBlock, groupDescriptor, trustedAuthorities, signerSetCommitment?)
//   stepUp(stepUp, opts) -> {allow, pq, reason?, checks}                            HybridThreshold.verifyHybridStepUp; checks = core verifier checks
//       opts: grant, groupKey, pqPublicKeys, t, pqT, groupDescriptor, trustedAuthorities, signerSetCommitment?, audience? (string | null | absent), nowEpoch?
import * as T0 from '@atlasauth/pca-pq-threshold';
import * as P0 from '@atlasauth/pca';
import * as FR0 from '@atlasauth/pca/ext/frost';
import { Oracle, refWrite, seed } from './lib.mjs';

const T: any = (T0 as any).default ?? T0;
const P: any = (P0 as any).mintRoot ? P0 : (P0 as any).default;
const FR: any = (FR0 as any).default ?? FR0;
const o = new Oracle('pq-threshold-java-extra', 'tools/pca-audit/oracles/pq-threshold-java-extra.mts', 'TS-reference oracle for the hybrid PQ threshold signer, step-up folding and PCActn hook.');
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
const clone = (x: any) => JSON.parse(JSON.stringify(x));
const run = (fn: string, name: string, f: (...a: any[]) => any, args: any[]) => o.run(fn, name, f, args);
const T_0 = 1_800_000_000_000;
const sd = (l: string) => seed('ref-pqx/' + l);
const ed = (l: string) => { const s = sd(l); return { s, pk: b64(P.publicKeyOf(s)) }; };
const AUTH = ed('auth'), AUTH2 = ed('auth2'), GRP = ed('group'), GRP2 = ed('group2'), PR = ed('principal'), AG = ed('agent');
const SH = [1, 2, 3, 4, 5].map((i) => ed('share' + i));
const parts = (n: number) => SH.slice(0, n).map((s, i) => ({ identifier: 1 + i, publicKey: s.pk }));
const PQ = ['pq1', 'pq2', 'pq3', 'pq4'].map((l) => P.mlDsa65Keygen(sd(l)));
const pkB = (i: number) => b64(PQ[i].publicKey);
const POOL3 = [pkB(0), pkB(1), pkB(2)];
const issue = (t: number, n: number, auth = AUTH, gpk = GRP.pk) => T.issueGroupDescriptor({ authoritySecretKey: auth.s, groupPublicKey: gpk, t, participants: parts(n) });
const D23 = clone(issue(2, 3)), D11 = clone(issue(1, 1));
const msgOf = (a: any) => P.thresholdMessage(a);
const flip = (s: string) => b64(Uint8Array.from(Buffer.from(s, 'base64url').map((x, i) => (i === 2 ? x ^ 1 : x))));

// ---- a real PCActn
const G = clone(P.mintRoot({ principalSecret: PR.s, principalPublic: P.encodeKey(P.publicKeyOf(PR.s)), holder: P.encodeKey(P.publicKeyOf(AG.s)), caveats: [] }));
const plan = [{ id: 'n1', verb: 'charge', resource: 'merchant:m1', params_digest: P.paramsDigest({ amount: 5 }) }];
const act = (over: any = {}) => clone(P.buildPCActn({ grant: G, chain: [G], plan, nodeId: 'n1', params: { amount: 5 }, counter: 1, signerSecret: AG.s, aud: 'rs', now: T_0, nonce: 'n-1', ...over }));
const A = act();

const grpSig = (a: any, g = GRP) => b64(P.sign(g.s, msgOf(a)));
const blk = (a: any, idx: number[], pqT?: number) => clone(FR.signPqQuorum(msgOf(a), idx.map((i) => PQ[i]), pqT));
const art = (a: any, idx = [0, 1, 2], over: any = {}) => ({ v: 2, digest: b64(P.sha256(msgOf(a))), frost: { alg: 'frost-ed25519', group_pk: GRP.pk, sig: grpSig(a), t: 2, quorum: 3, ...(over.frost ?? {}) }, pq: over.pq ?? blk(a, idx) });
const foldRef = (a: any, f: any) => T.foldHybridStepUp(un(a), un(f));
const fold = (a: any, f: any) => clone(foldRef(a, f));

// ---- fold
const ART = art(A);
await run('fold', 'plain', foldRef, [A, ART]);
await run('fold', 'other-pq', foldRef, [A, art(A, [0, 1])]);
await run('fold', 'with-existing-shares', foldRef, [{ ...A, threshold: { shares: [{ role: 'agent', publicKey: 'x', sig: 'y' }] } }, ART]);
await run('fold', 'existing-empty', foldRef, [{ ...A, threshold: { shares: [] } }, ART]);
await run('fold', 'existing-not-array', foldRef, [{ ...A, threshold: { shares: 'x' } }, ART]);
await run('fold', 'existing-no-shares', foldRef, [{ ...A, threshold: { t: 1 } }, ART]);
await run('fold', 'existing-null', foldRef, [{ ...A, threshold: null }, ART]);
await run('fold', 'existing-str', foldRef, [{ ...A, threshold: 'x' }, ART]);
await run('fold', 'no-frost', foldRef, [A, { ...ART, frost: undefined }]);
await run('fold', 'frost-null', foldRef, [A, { ...ART, frost: null }]);
await run('fold', 'frost-members-missing', foldRef, [A, { ...ART, frost: {} }]);
await run('fold', 'no-pq', foldRef, [A, { ...ART, pq: undefined }]);
await run('fold', 'artifact-null', foldRef, [A, null]);
await run('fold', 'action-null', foldRef, [null, ART]);
await run('fold', 'action-extra', foldRef, [{ ...A, extra: [1, { a: 2 }] }, ART]);

// ---- hook (core threshold hook) and step-up
const hopt = (a: any, over: any = {}) => ({ groupKey: GRP.pk, pqPublicKeys: POOL3, t: 2, pqT: 2, pqBlock: blk(a, [0, 1, 2]), groupDescriptor: D23, trustedAuthorities: [AUTH.pk], ...over });
const hookRef = async (opts: any, pcactn: any) => { const h = T.createHybridThresholdVerifier(un(opts)); const r = await h({ pcactn: un(pcactn), grant: {}, nowEpoch: T_0 }); return r; };
const FA = fold(A, ART).pcactn;
const HOOK: [string, any, any][] = [
  ['ok', hopt(A), FA], ['ok-pqT3', hopt(A, { pqT: 3 }), FA], ['ok-pqT1', hopt(A, { pqT: 1 }), FA], ['ok-pin-ssc', hopt(A, { signerSetCommitment: T.signerSetCommitment(parts(3)) }), FA],
  ['ok-bytes-keys', hopt(A, { groupKey: B(Buffer.from(GRP.pk, 'base64url')), trustedAuthorities: [B(Buffer.from(AUTH.pk, 'base64url'))], pqPublicKeys: POOL3.map((k) => B(Buffer.from(k, 'base64url'))) }), FA],
  ['ok-extra-shares', hopt(A), fold({ ...A, threshold: { shares: [{ role: 'agent', publicKey: 'x', sig: 'y' }, { role: 'principal', sig: 5 }, null] } }, ART).pcactn],
  ['no-threshold', hopt(A), A], ['threshold-null', hopt(A), { ...A, threshold: null }], ['shares-not-array', hopt(A), { ...A, threshold: { shares: 'x' } }], ['shares-empty', hopt(A), { ...A, threshold: { shares: [] } }],
  ['share-other-key', hopt(A), fold(A, art(A, [0, 1, 2], { frost: { group_pk: GRP2.pk } })).pcactn], ['share-sig-num', hopt(A), { ...A, threshold: { shares: [{ role: 'guardian', publicKey: GRP.pk, sig: 5 }] } }],
  ['share-forged', hopt(A), fold(A, art(A, [0, 1, 2], { frost: { sig: grpSig(A, GRP2) } })).pcactn], ['share-flipped', hopt(A), fold(A, art(A, [0, 1, 2], { frost: { sig: flip(grpSig(A)) } })).pcactn],
  ['share-sig-short', hopt(A), fold(A, art(A, [0, 1, 2], { frost: { sig: grpSig(A).slice(0, -4) } })).pcactn],
  ['share-for-other-action', hopt(A), fold(A, art(act({ counter: 2, nonce: 'n-9' }))).pcactn], ['action-tampered', hopt(A), { ...FA, counter: 99 }], ['action-aud-changed', hopt(A), { ...FA, aud: 'other' }],
  ['pq-short', hopt(A, { pqBlock: blk(A, [0]) }), FA], ['pq-outsider', hopt(A, { pqBlock: blk(A, [3, 3, 3]) }), FA], ['pq-pool-wrong', hopt(A, { pqPublicKeys: [pkB(3)] }), FA],
  ['pq-block-v1', hopt(A, { pqBlock: { ...blk(A, [0, 1, 2]), v: 1 } }), FA], ['pq-block-null', hopt(A, { pqBlock: null }), FA], ['pq-block-other-action', hopt(A, { pqBlock: blk(act({ counter: 2, nonce: 'n-9' }), [0, 1, 2]) }), FA],
  ['pq-block-flip', hopt(A, { pqBlock: (() => { const b = blk(A, [0, 1, 2]); b.signers[0].sig = flip(b.signers[0].sig); return b; })() }), FA],
  ['desc-t1-for-t2', hopt(A, { groupDescriptor: D11 }), FA], ['desc-untrusted', hopt(A, { trustedAuthorities: [AUTH2.pk] }), FA], ['desc-missing', hopt(A, { groupDescriptor: undefined }), FA], ['desc-null', hopt(A, { groupDescriptor: null }), FA],
  ['desc-other-group', hopt(A, { groupDescriptor: clone(issue(2, 3, AUTH, GRP2.pk)) }), FA], ['desc-wrong-ssc-pin', hopt(A, { signerSetCommitment: T.signerSetCommitment(parts(2)) }), FA],
  ['group-key-other', hopt(A, { groupKey: GRP2.pk, groupDescriptor: clone(issue(2, 3, AUTH, GRP2.pk)) }), FA], ['group-key-short', hopt(A, { groupKey: GRP.pk.slice(0, -4) }), FA], ['group-key-num', hopt(A, { groupKey: 5 }), FA],
  ['t-3-desc2', hopt(A, { t: 3 }), FA], ['t-str', hopt(A, { t: '2' }), FA], ['pqT-0', hopt(A, { pqT: 0 }), FA], ['pqT-missing', hopt(A, { pqT: undefined }), FA],
  ['pqpks-not-iterable', hopt(A, { pqPublicKeys: {} }), FA], ['pqpks-junk', hopt(A, { pqPublicKeys: [...POOL3, 'x', 5, null] }), FA],
];
for (const [nm, op, pc] of HOOK) await run('hook', nm, hookRef, [op, pc]);

const sopts = (over: any = {}) => ({ grant: G, groupKey: GRP.pk, pqPublicKeys: POOL3, t: 2, pqT: 2, groupDescriptor: D23, trustedAuthorities: [AUTH.pk], audience: 'rs', nowEpoch: T_0 + 1000, ...over });
const stepRef = async (su: any, op: any) => {
  const r = await T.verifyHybridStepUp(un(su), un(op));
  return { allow: r.allow, pq: r.pq, ...(r.reason !== undefined ? { reason: r.reason } : {}), checks: r.core.checks };
};
const SU = (a: any, over: any = {}) => ({ pcactn: fold(a, art(a, [0, 1, 2], over.art ?? {})).pcactn, pq: over.pq ?? blk(a, [0, 1, 2]) });
const A2 = act({ counter: 2, nonce: 'n-9' });
const SC: [string, any, any][] = [
  ['ok', SU(A), sopts()], ['ok-audience-null', SU(A), sopts({ audience: null })], ['ok-audience-absent-fails-aud', SU(A), sopts({ audience: undefined })], ['audience-wrong', SU(A), sopts({ audience: 'other' })],
  ['ok-pqT3', SU(A), sopts({ pqT: 3 })], ['ok-pin-ssc', SU(A), sopts({ signerSetCommitment: T.signerSetCommitment(parts(3)) })], ['now-late', SU(A), sopts({ nowEpoch: T_0 + 7_200_000 })], ['now-early', SU(A), sopts({ nowEpoch: T_0 - 120_000 })],
  ['ok-second-action', SU(A2), sopts()],
  ['no-threshold-share', { pcactn: A, pq: blk(A, [0, 1, 2]) }, sopts()],
  ['pq-short', SU(A, { pq: blk(A, [0]) }), sopts()], ['pq-outsider', SU(A, { pq: blk(A, [3, 3, 3]) }), sopts()], ['pq-pool-wrong', SU(A), sopts({ pqPublicKeys: [pkB(3)] })], ['pq-v1', SU(A, { pq: { ...blk(A, [0, 1, 2]), v: 1 } }), sopts()],
  ['pq-other-action', SU(A, { pq: blk(A2, [0, 1, 2]) }), sopts()], ['pq-block-null', { pcactn: SU(A).pcactn, pq: null }, sopts()],
  ['frost-forged', SU(A, { art: { frost: { sig: grpSig(A, GRP2) } } }), sopts()], ['frost-flipped', SU(A, { art: { frost: { sig: flip(grpSig(A)) } } }), sopts()], ['frost-other-group-key', SU(A, { art: { frost: { group_pk: GRP2.pk } } }), sopts()],
  ['desc-t1', SU(A), sopts({ groupDescriptor: D11 })], ['desc-untrusted', SU(A), sopts({ trustedAuthorities: [AUTH2.pk] })], ['group-key-other', SU(A), sopts({ groupKey: GRP2.pk })], ['group-key-bad', SU(A), sopts({ groupKey: 'x' })],
  ['tampered-counter', { pcactn: { ...SU(A).pcactn, counter: 77 }, pq: blk(A, [0, 1, 2]) }, sopts()], ['tampered-sig', { pcactn: { ...SU(A).pcactn, sig: flip(A.sig) }, pq: blk(A, [0, 1, 2]) }, sopts()],
  ['grant-other', SU(A), sopts({ grant: { ...G, id: 'x' } })], 
  ['both-short', SU(A, { pq: blk(A, [3]), art: { frost: { sig: grpSig(A, GRP2) } } }), sopts()],
  ['existing-shares', { pcactn: fold({ ...A, threshold: { shares: [{ role: 'agent', publicKey: 'x', sig: 'y' }] } }, ART).pcactn, pq: blk(A, [0, 1, 2]) }, sopts()],
];
for (const [nm, su, op] of SC) await run('stepUp', nm, stepRef, [su, op]);

// ---- hybridSign (real FROST quorum)
let signN = 0;
const KEYS = (t: number, n: number, label: string) => ({ secret: B(sd(label + '/s')), coefficients: Array.from({ length: t - 1 }, (_, i) => B(sd(label + '/c' + i))) });
const signRef = (a: any) => {
  const x = un(a);
  void x.pqSeeds;
  const kg = FR.frostTrustedDealerKeygen(x.t, x.n, { secret: x.secret, coefficients: x.coefficients });
  const by = new Map<number, any>(kg.participantShares.map((s: any) => [s.identifier, s]));
  const quorum = x.quorum.map((id: number) => by.get(id));
  const action = x.action;
  const artifact = T.hybridThresholdSign(action, { frost: { groupPublicKey: x.groupAsString ? b64(kg.groupPublicKey) : kg.groupPublicKey, quorum, t: x.signT ?? x.t }, pqSigners: x.pq.map((i: number) => ({ keyPair: PQ[i] })), ...(x.pqT != null ? { pqT: x.pqT } : {}) });
  const parts_ = kg.participantShares.map((s: any) => ({ identifier: s.identifier, publicKey: b64(s.publicKey) }));
  const desc = T.issueGroupDescriptor({ authoritySecretKey: AUTH.s, groupPublicKey: b64(kg.groupPublicKey), t: x.t, participants: parts_ });
  const verdict = T.verifyHybridThreshold(action, artifact, { groupKey: b64(kg.groupPublicKey), pqPublicKeys: POOL3.concat(pkB(3)), t: x.t, pqT: x.pqT ?? x.pq.length, groupDescriptor: desc, trustedAuthorities: [AUTH.pk] });
  const { sig, ...frostRest } = artifact.frost;
  return { artifact: { ...artifact, frost: { ...frostRest, sigLen: sig.length } }, verdict };
};
const sargs = (label: string, t: number, n: number, quorum: number[], pq: number[], over: any = {}) => ({ t, n, ...KEYS(t, n, label), quorum, pq, pqSeeds: ['pq1', 'pq2', 'pq3', 'pq4'].map((l) => B(sd(l))), authSeed: B(AUTH.s), action: A, ...over });
for (const [nm, t, n, q, pq, over] of [
  ['2of3-ok', 2, 3, [1, 3], [0, 1, 2], {}], ['2of3-all', 2, 3, [1, 2, 3], [0, 1, 2], {}], ['3of5', 3, 5, [1, 3, 5], [0, 1], {}], ['1of1', 1, 1, [1], [0], {}], ['pqT-lower', 2, 3, [2, 3], [0, 1, 2], { pqT: 2 }],
  ['pqT-higher-than-signers', 2, 3, [2, 3], [0, 1], { pqT: 3 }], ['group-as-b64u', 2, 3, [1, 2], [0, 1, 2], { groupAsString: true }], ['action-2', 2, 3, [1, 2], [0, 1, 2], { action: A2 }],
  ['pq-outsider-signer', 2, 3, [1, 2], [3], {}],
  ['below-threshold', 3, 5, [1, 2], [0, 1], {}], ['no-quorum', 2, 3, [], [0], {}], ['no-pq-signers', 2, 3, [1, 2], [], {}], ['t-0', 2, 3, [1, 2], [0], { signT: 0 }], ['signT-above-quorum', 2, 3, [1, 2], [0], { signT: 3 }],
  ['dup-quorum-member', 2, 3, [1, 1], [0], {}], ['unknown-member', 2, 3, [1, 9], [0], {}], ['signT-below-real-t', 2, 3, [1], [0], { signT: 1 }],
] as [string, number, number, number[], number[], any][]) {
  signN++;
  await run('hybridSign', nm, signRef, [sargs('sign-' + nm + signN, t, n, q, pq, over)]);
}
refWrite(o, 'pq-threshold-java-extra');
