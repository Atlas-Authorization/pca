// Oracle: networked FROST signing, TS reference = packages/pca/src/frost-net.ts, frost-nonce-store.ts and frost-pq.ts.
// Writes out/ref-frost-net.json.gz (committed: every secret is a seed label or a dealer descriptor; the write refuses if a dealer share
// appears in any case, so this corpus has no CI-generated half).
// Case shape as every sibling: {fn, name, args, out}; `out` is what the reference returned, or {"$throws": message, ...}.
//
// ARGUMENT FORMS (corpus -> value)
//   {"$bytes": "<b64url>"}                a byte string
//   {"$bytes": {"$seed": label}}          the 32 bytes sha256("atlas-pca-conformance/" + label)  (a secret key / nonce randomness / PoP nonce)
//   {"$share": {t, n, secret, coefficients, identifiers, id}}   the FROST(Ed25519) dealer share of participant `id`: run the lane's
//                                         trusted-dealer keygen on those seeds (same descriptor as core-frost-swift) and take that share
//   {"$num": "NaN"|"Infinity"|"-Infinity"}   a non-finite double
//   {"$rng": [value, ...]}                the LAST argument of a case that consumes randomness: the 32-byte values the reference drew, in
//                                         draw order. Feed them, in order, to the lane's random-bytes seam for the call and strip the argument.
//                                         For scenario cases (coordinator) the randomness is per signer (`rng` member of each signer).
//   Unused trailing rng values of a scenario are allowed; a draw beyond the script is a bug.
// OUTPUT CONVENTIONS
//   bytes -> {"$bytes": b64url}.  A refusal is {"$throws": message, ...}: a typed error adds "class" (PoPError, EquivocationError,
//   CoordinatorError, CoordinatorTimeoutError) and its fields (identifier, session_id/round/..., refusals, timeoutMs). Compare "$throws"
//   as "the native refuses", and compare class and fields exactly; the message text is informative except where a function says otherwise.
//   Signer / coordinator refusal objects ({ok:false, reason} / refusals[].reason): "reasonOpen": true marks a reason that wraps an inner
//   primitive error (lane-specific text): a native must refuse there but need not match the text. A reason without that member is exact.
//   verifyAllowToken: the "(fail closed): <detail>" tail of a verification-error reason is open (compare up to and including "(fail closed)").
//
// PORTING (fn(args) -> native entry point)
//   constants []                                      -> {NAME: value} (exported constants of the three modules)
//   frostActionDigest [message]                       -> b64url(sha256(message))
//   issueAllowToken [policySecret, opts]              -> AllowToken {body, authority, sig}; opts {message?, frostActionDigest?, groupPublicKey,
//                                                        nonce?, notBefore?, expiresAt?}; every case that omits `nonce` carries {$rng:[nonce randomness]}
//                                                        (the default nonce is b64url of ONE random 32-byte draw)
//   verifyAllowToken [token, expect]                  -> {ok, reason?}; expect {policyAuthorityPublicKey, groupPublicKey, message, now}
//   createSignerPoP [identifier, share, {groupPublicKey, nonce}] -> SignerPoP {identifier, publicKey, R, s}  (a nonce that reduces to 0 redraws: no case)
//   verifySignerPoP [pop, {groupPublicKey}]           -> bool (never throws)
//   enrollVerificationShares [enrollments, {groupPublicKey}] -> [{identifier, publicKey}] or PoPError {identifier?}
//   equivocationGuard [ops]                           -> one result per op; op observe {session_id, round, identifier, message} -> {ok:true} or
//                                                        EquivocationError / Error; op forget {session_id} -> {ok:true}. ONE guard per case.
//   decodeCommitment [wire] / decodeCommitments [list] / decodeVerificationShares [list] -> decoded (bytes) or a refusal
//   signerService [cfg, steps]                        -> {ctor, steps:[...]}; cfg {identifier, share, groupPublicKey, threshold,
//                                                        policyAuthorityPublicKey, sessionTtlMs?, clock?, store?}; the clock is injected
//                                                        and moves only by `clock` steps. store: "none" | "memory" (the MemoryNonceStore) |
//                                                        "fail-create"|"fail-load"|"fail-spend"|"fail-drop"|"fail-isSpent" (a memory store whose
//                                                        method throws "store down") | "invalid-no-spend" (an object without `spend`: ctor refuses).
//                                                        randomness: ctor draws ONE value (the PoP nonce), then every successful round1 draws TWO
//                                                        (hiding, binding randomness): {$rng} lists them in that order across ctor, round1s and restarts.
//                                                        steps: {op:"round1", req} {op:"round2", req} {op:"clock", ms} {op:"restart"} (a new
//                                                        service over the SAME store and clock; draws one more PoP nonce) {op:"storeLoad", sid}
//                                                        {op:"storeIsSpent", sid}. out.ctor = {verificationShare, pop} or a refusal.
//   coordinator [cfg]                                 -> {ctor?, calls:[{signature, sessionId, signers} | refusal]}; see the cfg described at the cases
//   nonceStore [ops]                                  -> per-op results on one MemoryNonceStore
//   assertNonceStoreContract [{store}]                -> null, or the contract violation as a refusal ("nonce-store contract: ...")
//   resolveFrostGroupAlg [x] -> "ed25519" | "hybrid-ed25519-ml-dsa-65" | null
//   frostSignerSetDigest [ids] -> bytes ; frostCosignRepresentative [groupPkB64u, message, ids, groupAlg] -> bytes
//   signHybridFrostCosign [groupPublicKey, quorum, message, opts] -> {groupAlg?, pq_sig?, pq_pk?, sigVerifies}; the Ed25519 `sig` is fresh-random
//        (the reference ran it on {$rng}); `sigVerifies` = that sig verifies as a strict Ed25519 signature under the group key. opts.guardianMlDsaSeed
//        (a seed) stands for guardianMlDsa = mlDsa65Keygen(seed); opts.guardianMlDsa:{} (no keys) is the malformed form
//   verifyHybridFrostCosign [artifact, message, groupPkB64u, signerSet, opts] -> HybridFrostVerdict
//   pqQuorumRepresentative [message] -> bytes ; signPqQuorum [message, keySeeds, pqT?] -> PqQuorumBlock (keys = mlDsa65Keygen(seed) per seed)
//   normalizePqQuorumPool [list] -> sorted list ; verifyPqQuorum [block, message, pool(list of b64u strings), pqT] -> PqQuorumVerdict
import { Oracle, refWrite, splitWrite, tokensIn, seed, jsonOut, reparse, ser } from './lib.mjs';
import { ed, S, B, b64, fromB64, sdb, un, J, flipB, flipStr, hexB, hex, bindFrost, dealerOf, kgOf, shareOf, as, setQueue, setQueueBytes, clearQueues, errOut, cap, runner, markOpen, PFX, type Dealer } from './frost-net-common.mts';

const F: any = await import('../../../packages/pca/src/frost.ts');
const N: any = await import('../../../packages/pca/src/frost-net.ts');
const NS: any = await import('../../../packages/pca/src/frost-nonce-store.ts');
const PQF: any = await import('../../../packages/pca/src/frost-pq.ts');
const PQ: any = await import('../../../packages/pca/src/pq.ts');
const H: any = await import('../../../packages/pca/src/hash.ts');
bindFrost(F);

const o = new Oracle('frost-net', 'tools/pca-audit/oracles/frost-net.mts', 'TS-reference oracle for networked FROST signing (allow token, signer proof-of-possession, equivocation guard, signer service, coordinator), the durable nonce store contract, and the FROST post-quantum group-algorithm registry and hybrid co-sign.');
const R = runner(o, { open: true });
const RC = runner(o, { open: true, loose: true });
const hb = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));
const utf = (s: string) => new TextEncoder().encode(s);

// ---- fixtures ---------------------------------------------------------------------------------------------------------
const D23 = dealerOf('d23', 2, 3);
const KG23 = kgOf(D23);
const GPK = KG23.groupPublicKey as Uint8Array;
const GPKS = b64(GPK);
const shareBytes = (kg: any, id: number) => kg.participantShares.find((p: any) => p.identifier === id);
const vkey = (kg: any, id: number): Uint8Array => shareBytes(kg, id).publicKey;
const POLICY = 'policy/a';
const polSk = sdb(POLICY);
const polPk = ed.getPublicKey(polSk) as Uint8Array;
const polPk2 = ed.getPublicKey(sdb('policy/b')) as Uint8Array;
const MSG = utf('transfer 10 USD to alice');
const NOW = 1_500_000;
const mkAllow = (msg: Uint8Array, gpk: Uint8Array, over: any = {}) => J(jsonOut(N.issueAllowToken(polSk, { message: msg, groupPublicKey: gpk, nonce: 'allow-nonce-1', notBefore: 1_000_000, expiresAt: 2_000_000, ...over })));
const ALLOW = mkAllow(MSG, GPK);

// ============================ constants ============================
await R('constants', 'all', () => ({
  ALLOW_TOKEN_TYP: N.ALLOW_TOKEN_TYP, SIGNER_POP_DST: N.SIGNER_POP_DST, MAX_FROST_SIGNING_SET: N.MAX_FROST_SIGNING_SET,
  DEFAULT_FROST_GROUP_ALG: PQF.DEFAULT_FROST_GROUP_ALG, PQ_QUORUM_VERSION: PQF.PQ_QUORUM_VERSION, PQ_QUORUM_ALG: PQF.PQ_QUORUM_ALG, MAX_PQ_QUORUM_ENTRIES: PQF.MAX_PQ_QUORUM_ENTRIES,
}), []);

// ============================ frostActionDigest ============================
for (const [n, m] of [['empty', new Uint8Array()], ['abc', utf('abc')], ['msg', MSG], ['seed', sdb('digest/m')], ['long', Uint8Array.from({ length: 5000 }, (_, i) => (i * 7 + 3) & 255)]] as [string, Uint8Array][]) await R('frostActionDigest', n, (m: any) => N.frostActionDigest(m), [B(m)]);
await R('frostActionDigest', 'null', (m: any) => N.frostActionDigest(m), [null]);
await R('frostActionDigest', 'string', (m: any) => N.frostActionDigest(m), ['abc']);

// ============================ issueAllowToken ============================
const iss = (sk: any, opts: any) => N.issueAllowToken(sk, opts);
const I = (name: string, opts: any, sk: any = S(POLICY), rng?: string[]) => R('issueAllowToken', name, iss, [sk, opts], rng);
await I('message', { message: B(MSG), groupPublicKey: B(GPK), nonce: 'n1' });
await I('message-window', { message: B(MSG), groupPublicKey: B(GPK), nonce: 'n1', notBefore: 1_000_000, expiresAt: 2_000_000 });
await I('digest-only', { frostActionDigest: N.frostActionDigest(MSG), groupPublicKey: B(GPK), nonce: 'n2' });
await I('digest-wins-over-message', { message: B(utf('other')), frostActionDigest: N.frostActionDigest(MSG), groupPublicKey: B(GPK), nonce: 'n3' });
await I('empty-message', { message: B(new Uint8Array()), groupPublicKey: B(GPK), nonce: 'n4' });
await I('empty-digest-string', { frostActionDigest: '', message: B(MSG), groupPublicKey: B(GPK), nonce: 'n5' });
await I('neither', { groupPublicKey: B(GPK), nonce: 'n6' });
await I('message-null', { message: null, groupPublicKey: B(GPK), nonce: 'n6b' });
await I('not-before-zero', { message: B(MSG), groupPublicKey: B(GPK), nonce: 'n7', notBefore: 0 });
await I('expires-zero', { message: B(MSG), groupPublicKey: B(GPK), nonce: 'n8', expiresAt: 0 });
await I('expires-negative', { message: B(MSG), groupPublicKey: B(GPK), nonce: 'n9', expiresAt: -5 });
await I('window-fraction', { message: B(MSG), groupPublicKey: B(GPK), nonce: 'n10', notBefore: 1.5, expiresAt: 2.5 });
await I('window-big', { message: B(MSG), groupPublicKey: B(GPK), nonce: 'n11', notBefore: 9007199254740991, expiresAt: 9007199254740991 });
await I('window-nan', { message: B(MSG), groupPublicKey: B(GPK), nonce: 'n12', expiresAt: { $num: 'NaN' } });
await I('window-infinity', { message: B(MSG), groupPublicKey: B(GPK), nonce: 'n13', expiresAt: { $num: 'Infinity' } });
await I('nonce-unicode', { message: B(MSG), groupPublicKey: B(GPK), nonce: 'né\u{1F600}"\\' });
await I('nonce-empty', { message: B(MSG), groupPublicKey: B(GPK), nonce: '' });
await I('group-short', { message: B(MSG), groupPublicKey: B(new Uint8Array(31)), nonce: 'n14' });
await I('group-empty', { message: B(MSG), groupPublicKey: B(new Uint8Array()), nonce: 'n15' });
await I('group-null', { message: B(MSG), groupPublicKey: null, nonce: 'n16' });
await I('other-key', { message: B(MSG), groupPublicKey: B(GPK), nonce: 'n17' }, S('policy/b'));
await I('sk-short', { message: B(MSG), groupPublicKey: B(GPK), nonce: 'n18' }, B(new Uint8Array(31)));
await I('sk-null', { message: B(MSG), groupPublicKey: B(GPK), nonce: 'n19' }, null);
await I('default-nonce', { message: B(MSG), groupPublicKey: B(GPK) }, S(POLICY), ['allow/default-nonce']);
await I('default-nonce-window', { message: B(MSG), groupPublicKey: B(GPK), expiresAt: 5 }, S(POLICY), ['allow/default-nonce-2']);

// ============================ verifyAllowToken ============================
const vfy = (t: any, e: any) => N.verifyAllowToken(t, e);
const EXP = (over: any = {}) => ({ policyAuthorityPublicKey: B(polPk), groupPublicKey: B(GPK), message: B(MSG), now: NOW, ...over });
const V = (name: string, token: any, over: any = {}) => R('verifyAllowToken', name, vfy, [token, EXP(over)]);
const tamper = (f: (t: any) => void) => { const t = J(ALLOW); f(t); return t; };
await V('ok', ALLOW);
await V('ok-no-window', mkAllow(MSG, GPK, { notBefore: undefined, expiresAt: undefined }));
await V('ok-not-before-edge', ALLOW, { now: 1_000_000 });
await V('before-not-before', ALLOW, { now: 999_999 });
await V('ok-before-expiry', ALLOW, { now: 1_999_999 });
await V('expires-edge', ALLOW, { now: 2_000_000 });
await V('after-expiry', ALLOW, { now: 2_000_001 });
await V('now-nan', ALLOW, { now: { $num: 'NaN' } });
await V('now-infinity', ALLOW, { now: { $num: 'Infinity' } });
await V('now-neg-infinity', ALLOW, { now: { $num: '-Infinity' } });
await V('now-string', ALLOW, { now: '1500000' });
await V('now-null', ALLOW, { now: null });
await V('now-fraction-ok', ALLOW, { now: 1_500_000.5 });
await V('zero-window-expired', mkAllow(MSG, GPK, { notBefore: 0, expiresAt: 0 }), { now: 0 });
await V('not-before-zero-ok', mkAllow(MSG, GPK, { notBefore: 0, expiresAt: undefined }), { now: 0 });
for (const [n, t] of [['null', null], ['undefined', undefined], ['string', 'tok'], ['number', 7], ['array', []], ['empty-object', {}], ['body-null', { body: null, sig: 'x' }], ['body-string', { body: 'x', sig: 'x' }], ['body-array', { body: [], sig: ALLOW.sig }]] as [string, any][]) await V('malformed-' + n, t);
await V('wrong-typ', tamper((t) => { t.body.typ = 'pca.frost.allow.v2'; }));
await V('typ-missing', tamper((t) => { delete t.body.typ; }));
await V('sig-missing', tamper((t) => { delete t.sig; }));
await V('sig-number', tamper((t) => { t.sig = 5; }));
await V('sig-empty', tamper((t) => { t.sig = ''; }));
await V('sig-short', tamper((t) => { t.sig = ALLOW.sig.slice(0, 80); }));
await V('sig-padded', tamper((t) => { t.sig = ALLOW.sig + '=='; }));
await V('sig-std-alphabet', tamper((t) => { t.sig = ALLOW.sig.replace(/-/g, '+').replace(/_/g, '/') + 'A'; }));
await V('sig-long', tamper((t) => { t.sig = ALLOW.sig + 'AAAA'; }));
await V('sig-bit-flip', tamper((t) => { t.sig = flipStr(t.sig, 3); }));
await V('sig-s-plus-L', tamper((t) => { const u = fromB64(t.sig); let x = 0n; for (let i = 63; i >= 32; i--) x = (x << 8n) | BigInt(u[i]!); x += F.L; for (let i = 32; i < 64; i++) { u[i] = Number(x & 0xffn); x >>= 8n; } t.sig = b64(u); }));
await V('sig-zero', tamper((t) => { t.sig = b64(new Uint8Array(64)); }));
await V('authority-forged-self', (() => { const sk = sdb('policy/forger'); const t = J(jsonOut(N.issueAllowToken(sk, { message: MSG, groupPublicKey: GPK, nonce: 'f', expiresAt: 2_000_000 }))); return t; })());
await V('authority-field-spoofed', tamper((t) => { t.authority = b64(polPk2); }));
await V('authority-field-missing', tamper((t) => { delete t.authority; }));
await V('expected-key-other', ALLOW, { policyAuthorityPublicKey: B(polPk2) });
await V('expected-key-short', ALLOW, { policyAuthorityPublicKey: B(new Uint8Array(31)) });
await V('expected-key-zero', ALLOW, { policyAuthorityPublicKey: B(new Uint8Array(32)) });
await V('expected-key-null', ALLOW, { policyAuthorityPublicKey: null });
await V('group-mismatch', ALLOW, { groupPublicKey: B(vkey(KG23, 1)) });
await V('group-short', ALLOW, { groupPublicKey: B(new Uint8Array(31)) });
await V('message-mismatch', ALLOW, { message: B(utf('transfer 10 USD to bob')) });
await V('message-empty', ALLOW, { message: B(new Uint8Array()) });
await V('message-null', ALLOW, { message: null });
await V('body-group-edited', tamper((t) => { t.body.group_pk = b64(vkey(KG23, 1)); }));
await V('body-digest-edited', tamper((t) => { t.body.action_digest = N.frostActionDigest(utf('x')); }));
await V('body-nonce-edited', tamper((t) => { t.body.nonce = 'allow-nonce-2'; }));
await V('body-window-extended', tamper((t) => { t.body.expires_at = 9_000_000; }));
await V('body-window-dropped', tamper((t) => { delete t.body.expires_at; }));
await V('body-extra-member', tamper((t) => { t.body.extra = 1; }));
await V('body-key-order', tamper((t) => { const b = t.body; t.body = { expires_at: b.expires_at, not_before: b.not_before, nonce: b.nonce, group_pk: b.group_pk, action_digest: b.action_digest, typ: b.typ }; }));
await V('body-number-nan-failclosed', tamper((t) => { t.body.expires_at = { $num: 'NaN' }; }), {});
await V('token-extra-member', tamper((t) => { t.extra = true; }));
await V('replay-other-message', mkAllow(utf('other'), GPK));
await V('replay-other-group', mkAllow(MSG, vkey(KG23, 2)));

// ============================ signer proof-of-possession ============================
const addToL = (n: bigint) => { let x = F.L + n; const w = new Uint8Array(32); for (let i = 0; i < 32; i++) { w[i] = Number(x & 0xffn); x >>= 8n; } return B(w); };
const mkPop = (id: any, share: any, opts: any) => N.createSignerPoP(id, share, opts);
const P_ = (name: string, id: any, share: any, opts: any) => R('createSignerPoP', name, mkPop, [id, share, opts]);
const GO = { groupPublicKey: B(GPK) };
for (const id of [1, 2, 3]) await P_('dealer-share-' + id, id, shareOf(D23, id), { ...GO, nonce: S('pop/n' + id) });
for (const [i, id] of [200, 9007199254740991, 4].entries()) await P_('id-' + id, id, S('pop/share' + i), { ...GO, nonce: S('pop/m' + i) });
await P_('share-seed-reduced', 5, S('pop/share-wide'), { ...GO, nonce: S('pop/m-wide') });
await P_('share-zero', 5, B(new Uint8Array(32)), { ...GO, nonce: S('pop/m-z') });
await P_('nonce-ge-L', 5, S('pop/share-wide'), { ...GO, nonce: addToL(16n) });
await P_('nonce-short', 5, S('pop/share-wide'), { ...GO, nonce: B(new Uint8Array(5).fill(9)) });
await P_('nonce-long', 5, S('pop/share-wide'), { ...GO, nonce: B(new Uint8Array(40).fill(9)) });
for (const [n, id] of [['id-zero', 0], ['id-negative', -1], ['id-fraction', 1.5], ['id-string', '1'], ['id-big', 9007199254740992], ['id-null', null]] as [string, any][]) await P_(n, id, S('pop/share0'), { ...GO, nonce: S('pop/mx') });
await P_('share-short', 5, B(new Uint8Array(31)), { ...GO, nonce: S('pop/mx') });
await P_('share-long', 5, B(new Uint8Array(33)), { ...GO, nonce: S('pop/mx') });
await P_('share-null', 5, null, { ...GO, nonce: S('pop/mx') });
await P_('group-short', 5, S('pop/share0'), { groupPublicKey: B(new Uint8Array(31)), nonce: S('pop/mx') });
await P_('group-null', 5, S('pop/share0'), { groupPublicKey: null, nonce: S('pop/mx') });
await P_('group-not-a-point-ok', 5, S('pop/share0'), { groupPublicKey: B(new Uint8Array(32).fill(2)), nonce: S('pop/mx') });
// random nonce path is exercised with the scripted draw
await R('createSignerPoP', 'nonce-from-rng', mkPop, [6, S('pop/share1'), GO], ['pop/rng-nonce']);

const popOf = (id: number, share: any, nonceLabel: string) => J(jsonOut(N.createSignerPoP(id, un(share), { groupPublicKey: GPK, nonce: sdb(nonceLabel) })));
const POP1 = popOf(1, shareOf(D23, 1), 'pop/n1'), POP2 = popOf(2, shareOf(D23, 2), 'pop/n2'), POP3 = popOf(3, shareOf(D23, 3), 'pop/n3');
const vp = (pop: any, e: any) => N.verifySignerPoP(pop, e);
const VP = (name: string, pop: any, e: any = GO) => R('verifySignerPoP', name, vp, [pop, e]);
const edit = (p: any, f: (x: any) => void) => { const x = J(p); f(x); return x; };
await VP('ok-1', POP1); await VP('ok-2', POP2); await VP('ok-3', POP3);
await VP('wrong-group', POP1, { groupPublicKey: B(vkey(KG23, 1)) });
await VP('group-short', POP1, { groupPublicKey: B(new Uint8Array(31)) });
await VP('group-null', POP1, { groupPublicKey: null });
await VP('expect-null', POP1, null);
await VP('pop-null', null); await VP('pop-string', 'x'); await VP('pop-array', []); await VP('pop-empty', {});
await VP('id-swapped', edit(POP1, (p) => { p.identifier = 2; }));
for (const [n, v] of [['zero', 0], ['negative', -3], ['fraction', 1.5], ['string', '1'], ['big', 9007199254740992], ['null', null]] as [string, any][]) await VP('id-' + n, edit(POP1, (p) => { p.identifier = v; }));
await VP('pk-other', edit(POP1, (p) => { p.publicKey = POP2.publicKey; }));
await VP('pk-flip', edit(POP1, (p) => { p.publicKey = flipStr(p.publicKey, 1); }));
await VP('pk-short', edit(POP1, (p) => { p.publicKey = p.publicKey.slice(0, 40); }));
await VP('pk-padded', edit(POP1, (p) => { p.publicKey += '='; }));
await VP('pk-small-order', edit(POP1, (p) => { p.publicKey = b64(hb('0100000000000000000000000000000000000000000000000000000000000000')); }));
await VP('pk-missing', edit(POP1, (p) => { delete p.publicKey; }));
await VP('R-flip', edit(POP1, (p) => { p.R = flipStr(p.R, 1); }));
await VP('R-other', edit(POP1, (p) => { p.R = POP2.R; }));
await VP('R-identity', edit(POP1, (p) => { p.R = b64(hb('0100000000000000000000000000000000000000000000000000000000000000')); }));
await VP('R-missing', edit(POP1, (p) => { delete p.R; }));
await VP('R-number', edit(POP1, (p) => { p.R = 1; }));
await VP('s-flip', edit(POP1, (p) => { p.s = flipStr(p.s, 0); }));
await VP('s-zero', edit(POP1, (p) => { p.s = b64(new Uint8Array(32)); }));
await VP('s-other', edit(POP1, (p) => { p.s = POP2.s; }));
await VP('s-short', edit(POP1, (p) => { p.s = p.s.slice(0, 40); }));
await VP('s-plus-L', edit(POP1, (p) => { let x = 0n; const u = fromB64(p.s); for (let i = 31; i >= 0; i--) x = (x << 8n) | BigInt(u[i]!); x += F.L; const w = new Uint8Array(32); for (let i = 0; i < 32; i++) { w[i] = Number(x & 0xffn); x >>= 8n; } p.s = b64(w); }));
await VP('s-missing', edit(POP1, (p) => { delete p.s; }));
await VP('extra-member-ok', edit(POP1, (p) => { p.extra = 1; }));

const enr = (id: number, pk: Uint8Array, pop: any) => ({ identifier: id, publicKey: B(pk), pop });
const EN = [enr(1, vkey(KG23, 1), POP1), enr(2, vkey(KG23, 2), POP2), enr(3, vkey(KG23, 3), POP3)];
const enrol = (l: any, e: any) => N.enrollVerificationShares(l, e);
const EV = (name: string, l: any, e: any = GO) => R('enrollVerificationShares', name, enrol, [l, e]);
await EV('ok-three', EN); await EV('ok-one', [EN[0]]); await EV('ok-reordered', [EN[2], EN[0], EN[1]]);
await EV('empty', []); await EV('null', null); await EV('object', {});
await EV('group-short', EN, { groupPublicKey: B(new Uint8Array(31)) });
await EV('group-null', EN, { groupPublicKey: null });
await EV('wrong-group', EN, { groupPublicKey: B(vkey(KG23, 3)) });
await EV('duplicate', [EN[0], EN[1], EN[0]]);
await EV('entry-null', [EN[0], null]);
for (const [n, v] of [['zero', 0], ['negative', -1], ['fraction', 2.5], ['string', '2']] as [string, any][]) await EV('id-' + n, [EN[0], { ...EN[1], identifier: v }]);
await EV('pk-short', [EN[0], { ...EN[1], publicKey: B(new Uint8Array(31)) }]);
await EV('pk-null', [EN[0], { ...EN[1], publicKey: null }]);
await EV('pop-missing', [EN[0], { identifier: 2, publicKey: EN[1].publicKey }]);
await EV('pop-wrong-id', [EN[0], { ...EN[1], pop: POP3 }]);
await EV('pop-wrong-key', [EN[0], { ...EN[1], publicKey: B(vkey(KG23, 3)) }]);
await EV('pop-invalid-s', [EN[0], { ...EN[1], pop: edit(POP2, (p) => { p.s = flipStr(p.s, 0); }) }]);
await EV('rogue-key', (() => { // a signer that registers a key it has no scalar for: PK = -sum of the honest keys' effect; its PoP is for another scalar
  const x = F.bytesToScalar(sdb('rogue/x')); const pk = ed.ExtendedPoint.BASE.multiply(x).toRawBytes();
  const fake = popOf(2, B(sdb('rogue/other')), 'rogue/n');
  return [EN[0], { identifier: 2, publicKey: B(pk), pop: { ...fake, publicKey: b64(pk) } }];
})());
await EV('pop-for-other-group', [EN[0], { ...EN[1], pop: J(jsonOut(N.createSignerPoP(2, un(shareOf(D23, 2)), { groupPublicKey: vkey(KG23, 1), nonce: sdb('pop/n2') }))) }]);

// ============================ equivocation guard ============================
const guardRun = (ops: any[]) => {
  const g = new N.EquivocationGuard();
  return ops.map((op) => {
    try {
      if (op.op === 'observe') g.observe(op.session_id, op.round, op.identifier, op.message);
      else if (op.op === 'forget') g.forget(op.session_id);
      else throw new Error('bad op');
      return { ok: true };
    } catch (e: any) { return errOut(e); }
  });
};
const G = (name: string, ops: any[]) => R('equivocationGuard', name, guardRun, [ops]);
const ob = (session_id: any, round: any, identifier: any, message: any) => ({ op: 'observe', session_id, round, identifier, message });
await G('first-ok', [ob('s', 1, 1, { a: 1 })]);
await G('identical-repeat', [ob('s', 1, 1, { a: 1, b: [1, 2] }), ob('s', 1, 1, { a: 1, b: [1, 2] })]);
await G('key-order-insensitive', [ob('s', 1, 1, { a: 1, b: 2 }), ob('s', 1, 1, { b: 2, a: 1 })]);
await G('differing-second', [ob('s', 1, 1, { a: 1 }), ob('s', 1, 1, { a: 2 })]);
await G('differing-then-original-still-ok', [ob('s', 1, 1, { a: 1 }), ob('s', 1, 1, { a: 2 }), ob('s', 1, 1, { a: 1 })]);
await G('other-signer-independent', [ob('s', 1, 1, 'x'), ob('s', 1, 2, 'y')]);
await G('other-round-independent', [ob('s', 1, 1, 'x'), ob('s', 2, 1, 'y')]);
await G('other-session-independent', [ob('s', 1, 1, 'x'), ob('t', 1, 1, 'y')]);
await G('array-order-matters', [ob('s', 1, 1, [1, 2]), ob('s', 1, 1, [2, 1])]);
await G('string-vs-number', [ob('s', 1, 1, 1), ob('s', 1, 1, '1')]);
await G('null-message', [ob('s', 1, 1, null), ob('s', 1, 1, null), ob('s', 1, 1, 0)]);
await G('unicode', [ob('sé', 1, 1, { k: 'é\u{1F600}' }), ob('sé', 1, 1, { k: 'é\u{1F600}' }), ob('sé', 1, 1, { k: 'é\u{1F600}' })]);
await G('session-with-nul-collides-not', [ob('a\u0000b', 1, 1, 'x'), ob('a', 1, 1, 'y')]);
await G('empty-session', [ob('', 1, 1, 'x')]);
await G('session-number', [ob(5, 1, 1, 'x')]);
await G('round-zero', [ob('s', 0, 1, 'x')]); await G('round-fraction', [ob('s', 1.5, 1, 'x')]); await G('round-negative', [ob('s', -1, 1, 'x')]);
await G('identifier-zero', [ob('s', 1, 0, 'x')]); await G('identifier-fraction', [ob('s', 1, 1.5, 'x')]); await G('identifier-string', [ob('s', 1, '1', 'x')]);
await G('forget-then-rebind', [ob('s', 1, 1, 'x'), { op: 'forget', session_id: 's' }, ob('s', 1, 1, 'y')]);
await G('forget-other-session-keeps', [ob('s', 1, 1, 'x'), ob('st', 1, 1, 'x'), { op: 'forget', session_id: 's' }, ob('st', 1, 1, 'z')]);
await G('forget-prefix-boundary', [ob('s', 1, 1, 'x'), ob('s\u0000x', 1, 1, 'x'), { op: 'forget', session_id: 's' }, ob('s', 1, 1, 'q'), ob('s\u0000x', 1, 1, 'q')]);
await G('forget-unknown', [{ op: 'forget', session_id: 'nope' }]);
await G('deep-nesting', [ob('s', 1, 1, { a: { b: { c: [1, { d: null }] } } }), ob('s', 1, 1, { a: { b: { c: [1, { d: null }] } } })]);
await G('many-signers', Array.from({ length: 12 }, (_, i) => ob('s', 1, i + 1, { i })).concat(Array.from({ length: 12 }, (_, i) => ob('s', 1, i + 1, { i: i === 7 ? 99 : i }))));

// ============================ wire decoders ============================
const OKPT = b64(vkey(KG23, 1)), OKPT2 = b64(vkey(KG23, 2));
const dc = (w: any) => N.decodeCommitment(w);
const DC = (name: string, w: any) => R('decodeCommitment', name, dc, [w]);
await DC('ok', { identifier: 1, hiding: OKPT, binding: OKPT2 });
await DC('ok-any-32-bytes-not-validated-as-points', { identifier: 7, hiding: b64(new Uint8Array(32)), binding: b64(new Uint8Array(32).fill(255)) });
await DC('big-id', { identifier: 9007199254740991, hiding: OKPT, binding: OKPT2 });
await DC('extra-member', { identifier: 1, hiding: OKPT, binding: OKPT2, x: 1 });
for (const [n, v] of [['null', null], ['number', 3], ['string', 'x'], ['array', []]] as [string, any][]) await DC('wire-' + n, v);
for (const [n, v] of [['zero', 0], ['negative', -1], ['fraction', 1.5], ['string', '1'], ['null', null], ['big', 9007199254740992], ['missing', undefined]] as [string, any][]) await DC('id-' + n, { identifier: v, hiding: OKPT, binding: OKPT2 });
await DC('hiding-short', { identifier: 1, hiding: OKPT.slice(0, 40), binding: OKPT2 });
await DC('hiding-padded', { identifier: 1, hiding: OKPT + '=', binding: OKPT2 });
await DC('hiding-std-alphabet', { identifier: 1, hiding: OKPT.replace(/-/g, '+') + 'A', binding: OKPT2 });
await DC('hiding-noncanonical-tail', { identifier: 1, hiding: OKPT.slice(0, 42) + (OKPT[42] === 'A' ? 'B' : 'A'), binding: OKPT2 });
await DC('hiding-number', { identifier: 1, hiding: 5, binding: OKPT2 });
await DC('binding-missing', { identifier: 1, hiding: OKPT });
await DC('binding-null', { identifier: 1, hiding: OKPT, binding: null });
const dcs = (l: any) => N.decodeCommitments(l);
const DCS = (name: string, l: any) => R('decodeCommitments', name, dcs, [l]);
const wc = (i: number) => ({ identifier: i, hiding: OKPT, binding: OKPT2 });
await DCS('empty', []); await DCS('one', [wc(1)]); await DCS('three', [wc(1), wc(2), wc(3)]);
await DCS('max-256', Array.from({ length: 256 }, (_, i) => wc(i + 1)));
await DCS('over-max-257', Array.from({ length: 257 }, (_, i) => wc(i + 1)));
await DCS('not-list-object', {}); await DCS('not-list-null', null); await DCS('not-list-string', 'abc');
await DCS('one-bad-in-list', [wc(1), { identifier: 0, hiding: OKPT, binding: OKPT2 }]);
await DCS('duplicates-not-checked', [wc(1), wc(1)]);
const dvs = (l: any) => N.decodeVerificationShares(l);
const DVS = (name: string, l: any) => R('decodeVerificationShares', name, dvs, [l]);
const wv = (i: number, pk = OKPT) => ({ identifier: i, publicKey: pk });
await DVS('empty', []); await DVS('two', [wv(1), wv(2, OKPT2)]); await DVS('max-256', Array.from({ length: 256 }, (_, i) => wv(i + 1)));
await DVS('over-max-257', Array.from({ length: 257 }, (_, i) => wv(i + 1)));
await DVS('not-list', {}); await DVS('not-list-null', null);
await DVS('entry-null', [wv(1), null]); await DVS('entry-number', [3]);
await DVS('id-zero', [wv(0)]); await DVS('id-fraction', [wv(1.5)]); await DVS('id-string', [{ identifier: '1', publicKey: OKPT }]);
await DVS('key-short', [wv(1, OKPT.slice(0, 40))]); await DVS('key-null', [{ identifier: 1, publicKey: null }]); await DVS('key-padded', [wv(1, OKPT + '=')]);
await DVS('key-not-validated-as-point', [wv(1, b64(new Uint8Array(32).fill(3)))]);
await DVS('id-check-before-key', [{ identifier: 0, publicKey: 'x' }]);

// ============================ signer service ============================
class FailStore extends NS.MemoryNonceStore {
  constructor(private readonly m: string) { super(); }
  create(a: any, b: any) { if (this.m === 'create') throw new Error('store down'); return super.create(a, b); }
  load(a: any) { if (this.m === 'load') throw new Error('store down'); return super.load(a); }
  spend(a: any) { if (this.m === 'spend') throw new Error('store down'); return super.spend(a); }
  drop(a: any) { if (this.m === 'drop') throw new Error('store down'); return super.drop(a); }
  isSpent(a: any) { if (this.m === 'isSpent') throw new Error('store down'); return super.isSpent(a); }
}
const mkStore = (k: string | undefined): any => {
  if (!k || k === 'none') return undefined;
  if (k === 'memory') return new NS.MemoryNonceStore();
  if (k === 'invalid-no-spend') return { create() {}, load() {}, drop() {}, isSpent() {} };
  if (k.startsWith('fail-')) return new FailStore(k.slice(5));
  throw new Error('store ' + k);
};
const svcOpts = (cfg: any, store: any, clock: () => number) => ({
  identifier: cfg.identifier, share: cfg.share, groupPublicKey: cfg.groupPublicKey, threshold: cfg.threshold, policyAuthorityPublicKey: cfg.policyAuthorityPublicKey,
  sessionTtlMs: cfg.sessionTtlMs ?? undefined, now: clock, nonceStore: store,
});
const signerService = async (cfg: any, steps: any[]) => {
  let clock = cfg.clock ?? 1_000_000;
  const store = mkStore(cfg.store);
  const out: any = { ctor: null, steps: [] };
  let svc: any;
  const mk = () => new N.GuardianSignerService(svcOpts(cfg, store, () => clock));
  try {
    svc = mk();
    out.ctor = jsonOut({ verificationShare: svc.verificationShare, pop: svc.proofOfPossession, enrollment: svc.enrollment() });
  } catch (e: any) { out.ctor = errOut(e); return out; }
  for (const st of steps) {
    try {
      if (st.op === 'round1') out.steps.push(jsonOut(svc.round1(st.req)));
      else if (st.op === 'round2') out.steps.push(jsonOut(svc.round2(st.req)));
      else if (st.op === 'clock') { clock += st.ms; out.steps.push({ clock }); }
      else if (st.op === 'restart') { svc = mk(); out.steps.push({ restarted: true, pop: jsonOut(svc.proofOfPossession) }); }
      else if (st.op === 'storeLoad') { const r = store.load(st.sid); out.steps.push({ live: r !== undefined }); }
      else if (st.op === 'storeIsSpent') out.steps.push({ spent: store.isSpent(st.sid) });
      else throw new Error('bad step');
    } catch (e: any) { out.steps.push(errOut(e)); }
  }
  return out;
};
let FXN = 0;
/** One signer (id 1) under test plus its peer (id 3): a unique randomness label set per fixture, round-1 only on the fixture side. */
function fx(tag: string, over: any = {}) {
  const ids = over.ids ?? [1, 3];
  const sid = over.sid ?? 'sess-' + tag;
  const labels = new Map<number, string[]>();
  const svcs = new Map<number, any>();
  const clock = 1_000_000;
  const policyPk = over.policyPk ?? polPk, kg = over.kg ?? KG23, gpk = over.gpk ?? kg.groupPublicKey, dealer = over.dealer ?? D23, threshold = over.threshold ?? 2;
  for (const id of ids) {
    const L = [`${tag}/${id}/pop`, `${tag}/${id}/hr`, `${tag}/${id}/br`];
    labels.set(id, L);
    setQueue('fx' + id, L);
    svcs.set(id, as('fx' + id, () => new N.GuardianSignerService({ identifier: id, share: shareBytes(kg, id).share, groupPublicKey: gpk, threshold, policyAuthorityPublicKey: policyPk, now: () => clock })));
  }
  const r1 = new Map<number, any>();
  for (const id of ids) r1.set(id, as('fx' + id, () => svcs.get(id).round1({ typ: 'pca.frost.round1.v1', session_id: sid })));
  const commitments = ids.map((id) => J(r1.get(id).commitment));
  const vss = ids.map((id) => ({ identifier: id, publicKey: b64(vkey(kg, id)) }));
  const msg = over.msg ?? MSG;
  const req2 = { typ: 'pca.frost.round2.v1', session_id: sid, message: b64(msg), group_pk: b64(gpk), commitments, verification_shares: vss, allow: over.allow ?? mkAllow(msg, gpk, { nonce: 'fx-' + tag }) };
  const cfg = (id: number, extra: any = {}) => ({ identifier: id, share: shareOf(dealer, id), groupPublicKey: B(gpk), threshold, policyAuthorityPublicKey: B(policyPk), ...extra });
  const rng = (id: number, n = 1) => { const L = labels.get(id)!; return [L[0]!, ...Array.from({ length: n }, () => [L[1]!, L[2]!]).flat()]; };
  return { sid, req1: { typ: 'pca.frost.round1.v1', session_id: sid }, req2, cfg, rng, ids, kg, labels, commitments, vss };
}
const SS = (name: string, f: ReturnType<typeof fx>, cfgExtra: any, steps: any[], rngLabels: string[], id = 1) => RC('signerService', name, signerService, [f.cfg(id, cfgExtra), steps], rngLabels);
const r1s = (f: any) => ({ op: 'round1', req: f.req1 }), r2s = (req: any) => ({ op: 'round2', req });
const mod2 = (f: any, g: (r: any) => void) => { const r = J(f.req2); g(r); return r; };
{
  const f = fx('happy');
  await SS('happy', f, {}, [r1s(f), r2s(f.req2)], f.rng(1));
  const f2 = fx('happy3', { ids: [3, 1] });
  await SS('happy-other-order-set', f2, {}, [r1s(f2), r2s(f2.req2)], f2.rng(1));
  const f3 = fx('happy-store');
  await SS('happy-memory-store', f3, { store: 'memory' }, [r1s(f3), { op: 'storeLoad', sid: f3.sid }, r2s(f3.req2), { op: 'storeLoad', sid: f3.sid }, { op: 'storeIsSpent', sid: f3.sid }], f3.rng(1));
  const f4 = fx('t1', { dealer: dealerOf('d13', 1, 3), kg: kgOf(dealerOf('d13', 1, 3)), threshold: 1, ids: [2] });
  await RC('signerService', 'threshold-1-single', signerService, [f4.cfg(2, { threshold: 1 }), [r1s(f4), r2s(f4.req2)]], f4.rng(2));
}
{ // lifecycle and replay guards
  const f = fx('life');
  await SS('round2-without-round1', f, {}, [r2s(f.req2)], [f.rng(1)[0]!]);
  await SS('round1-twice', f, {}, [r1s(f), r1s(f)], f.rng(1));
  await SS('round1-ids', f, {}, [{ op: 'round1', req: { ...f.req1, session_id: 'other' } }, { op: 'round1', req: { ...f.req1, session_id: '' } }, { op: 'round1', req: { typ: 'x', session_id: 's' } }, { op: 'round1', req: null }, { op: 'round1', req: { typ: 'pca.frost.round1.v1', session_id: 5 } }, { op: 'round1', req: {} }], [f.rng(1)[0]!, 'life/1/hr', 'life/1/br']);
  const g = fx('life2');
  await SS('round2-twice-one-shot', g, {}, [r1s(g), r2s(g.req2), r2s(g.req2)], g.rng(1));
  const g2 = fx('life3');
  await SS('round1-after-signed', g2, {}, [r1s(g2), r2s(g2.req2), r1s(g2)], g2.rng(1));
  const g3 = fx('life4');
  await SS('other-session-round2-no-state', g3, {}, [r1s(g3), r2s({ ...g3.req2, session_id: 'nope' })], g3.rng(1));
  const g4 = fx('life5');
  await SS('two-sessions-independent', g4, {}, [r1s(g4), { op: 'round1', req: { ...g4.req1, session_id: 'second' } }, r2s(g4.req2)], [...g4.rng(1), 'life5/1/hr2', 'life5/1/br2']);
}
{ // stale-session guard
  const f = fx('ttl');
  await SS('ttl-ok-within', f, { sessionTtlMs: 5000 }, [r1s(f), { op: 'clock', ms: 4999 }, r2s(f.req2)], f.rng(1));
  const g = fx('ttl2');
  await SS('ttl-edge-equal-ok', g, { sessionTtlMs: 5000 }, [r1s(g), { op: 'clock', ms: 5000 }, r2s(g.req2)], g.rng(1));
  const h = fx('ttl3');
  await SS('ttl-expired', h, { sessionTtlMs: 5000 }, [r1s(h), { op: 'clock', ms: 5001 }, r2s(h.req2), r2s(h.req2)], h.rng(1));
  const i = fx('ttl4');
  await SS('ttl-expired-store-dropped', i, { sessionTtlMs: 5000, store: 'memory' }, [r1s(i), { op: 'clock', ms: 5001 }, r2s(i.req2), { op: 'storeLoad', sid: i.sid }, { op: 'storeIsSpent', sid: i.sid }, r1s(i)], [...i.rng(1), 'ttl4/1/hr2', 'ttl4/1/br2']);
  const j = fx('ttl5');
  await SS('ttl-clock-backwards-ok', j, { sessionTtlMs: 5000 }, [r1s(j), { op: 'clock', ms: -100 }, r2s(j.req2)], j.rng(1));
}
{ // refusals that keep the nonces: the honest retry then succeeds
  const refusals: [string, (r: any) => void][] = [
    ['wrong-typ', (r) => { r.typ = 'pca.frost.round2.v2'; }],
    ['session-not-string', (r) => { r.session_id = 5; }],
    ['message-not-canonical', (r) => { r.message = r.message + '='; }],
    ['message-missing', (r) => { delete r.message; }],
    ['group-mismatch', (r) => { r.group_pk = b64(vkey(KG23, 2)); }],
    ['group-missing', (r) => { delete r.group_pk; }],
    ['allow-missing', (r) => { delete r.allow; }],
    ['allow-null', (r) => { r.allow = null; }],
    ['allow-other-message', (r) => { r.allow = mkAllow(utf('other'), GPK, { nonce: 'x' }); }],
    ['allow-other-group', (r) => { r.allow = mkAllow(MSG, vkey(KG23, 3), { nonce: 'x' }); }],
    ['allow-expired', (r) => { r.allow = mkAllow(MSG, GPK, { nonce: 'x', expiresAt: 1_000_000 }); }],
    ['allow-not-yet', (r) => { r.allow = mkAllow(MSG, GPK, { nonce: 'x', notBefore: 1_000_001 }); }],
    ['allow-wrong-authority', (r) => { r.allow = J(jsonOut(N.issueAllowToken(sdb('policy/b'), { message: MSG, groupPublicKey: GPK, nonce: 'x' }))); }],
    ['allow-authority-spoofed', (r) => { r.allow = J(jsonOut(N.issueAllowToken(sdb('policy/b'), { message: MSG, groupPublicKey: GPK, nonce: 'x' }))); r.allow.authority = b64(polPk); }],
    ['allow-sig-flipped', (r) => { r.allow.sig = flipStr(r.allow.sig, 0); }],
    ['allow-body-nan-failclosed', (r) => { r.allow = { ...r.allow, body: { ...r.allow.body, expires_at: { $num: 'NaN' } } }; }],
    ['commitments-below-threshold', (r) => { r.commitments = [r.commitments[0]]; }],
    ['commitments-empty', (r) => { r.commitments = []; }],
    ['commitments-missing', (r) => { delete r.commitments; }],
    ['commitments-not-list', (r) => { r.commitments = {}; }],
    ['commitments-257', (r) => { r.commitments = Array.from({ length: 257 }, (_, i) => ({ identifier: i + 1, hiding: OKPT, binding: OKPT2 })); }],
    ['commitment-bad-id', (r) => { r.commitments[1].identifier = 0; }],
    ['commitment-bad-point-b64', (r) => { r.commitments[1].hiding = 'zz'; }],
    ['own-commitment-absent', (r) => { r.commitments[0].identifier = 2; }],
    ['own-commitment-hiding-differs', (r) => { r.commitments[0].hiding = flipStr(r.commitments[0].hiding, 1); }],
    ['own-commitment-binding-differs', (r) => { r.commitments[0].binding = flipStr(r.commitments[0].binding, 1); }],
    ['own-commitment-swapped', (r) => { const c = r.commitments[0]; [c.hiding, c.binding] = [c.binding, c.hiding]; }],
    ['vshares-not-list', (r) => { r.verification_shares = 'x'; }],
    ['vshares-missing', (r) => { delete r.verification_shares; }],
    ['vshares-257', (r) => { r.verification_shares = Array.from({ length: 257 }, (_, i) => ({ identifier: i + 1, publicKey: OKPT })); }],
    ['vshares-bad-entry', (r) => { r.verification_shares[0] = null; }],
  ];
  let k = 0;
  for (const [n, g] of refusals) {
    const f = fx('ret' + k++);
    const bad = mod2(f, g);
    await SS('keeps-' + n, f, {}, [r1s(f), r2s(bad), r2s(f.req2)], f.rng(1));
  }
  // refusals raised INSIDE frostSign (after the decode checks): without a store the nonces are untouched, so the honest retry signs
  const inner: [string, (r: any) => void][] = [
    ['vshares-wrong-key', (r) => { r.verification_shares[0].publicKey = b64(vkey(KG23, 2)); }],
    ['vshares-set-mismatch', (r) => { r.verification_shares = [r.verification_shares[0]]; }],
    ['vshares-peer-key-swapped', (r) => { r.verification_shares[1].publicKey = b64(vkey(KG23, 2)); }],
    ['commitments-duplicate-id', (r) => { r.commitments = [r.commitments[0], r.commitments[0]]; }],
    ['commitment-peer-small-order', (r) => { r.commitments[1].hiding = b64(hb('0100000000000000000000000000000000000000000000000000000000000000')); }],
    ['commitment-peer-off-curve', (r) => { r.commitments[1].binding = b64(new Uint8Array(32).fill(2)); }],
  ];
  for (const [n, g] of inner) {
    const f = fx('inr' + k++);
    const bad = mod2(f, g);
    await SS('inner-' + n + '-no-store', f, {}, [r1s(f), r2s(bad), r2s(f.req2)], f.rng(1));
    const f2 = fx('inr' + k++);
    const bad2 = mod2(f2, g);
    await SS('inner-' + n + '-memory-store-burns', f2, { store: 'memory' }, [r1s(f2), r2s(bad2), r2s(f2.req2), { op: 'storeIsSpent', sid: f2.sid }], f2.rng(1));
  }
}
{ // durable store paths
  const f = fx('st1');
  await SS('store-restart-resumes', f, { store: 'memory' }, [r1s(f), { op: 'restart' }, r2s(f.req2), { op: 'restart' }, r2s(f.req2), r1s(f)], [...f.rng(1), 'st1/1/pop-r1', 'st1/1/pop-r2']);
  const g = fx('st2');
  await SS('store-restart-no-store-loses-session', g, {}, [r1s(g), { op: 'restart' }, r2s(g.req2)], [...g.rng(1), 'st2/1/pop-r']);
  const h = fx('st3');
  await SS('store-fail-create', h, { store: 'fail-create' }, [r1s(h), r2s(h.req2)], [h.rng(1)[0]!, 'st3/1/hr', 'st3/1/br']);
  const i = fx('st4');
  await SS('store-fail-load', i, { store: 'fail-load' }, [r1s(i), r2s(i.req2)], i.rng(1));
  const j = fx('st5');
  await SS('store-fail-spend', j, { store: 'fail-spend' }, [r1s(j), r2s(j.req2), r2s(j.req2)], j.rng(1));
  const k = fx('st6');
  await SS('store-fail-isSpent', k, { store: 'fail-isSpent' }, [r1s(k), r2s(k.req2)], k.rng(1));
  const l = fx('st7');
  await SS('store-fail-drop-on-expiry', l, { store: 'fail-drop', sessionTtlMs: 100 }, [r1s(l), { op: 'clock', ms: 101 }, r2s(l.req2)], l.rng(1));
  const m = fx('st8');
  await SS('store-invalid-ctor', m, { store: 'invalid-no-spend' }, [], []);
}
{ // constructor validation
  const f = fx('ctor');
  const base = f.cfg(1);
  const C = (n: string, over: any, rng: string[] = []) => RC('signerService', 'ctor-' + n, signerService, [{ ...base, ...over }, []], rng);
  await C('ok', {}, [f.rng(1)[0]!]);
  for (const [n, v] of [['zero', 0], ['negative', -1], ['fraction', 1.5], ['string', '1'], ['null', null], ['unsafe', 9007199254740992]] as [string, any][]) await C('identifier-' + n, { identifier: v });
  await C('share-short', { share: B(new Uint8Array(31)) }); await C('share-long', { share: B(new Uint8Array(33)) }); await C('share-null', { share: null });
  await C('group-short', { groupPublicKey: B(new Uint8Array(31)) }); await C('group-null', { groupPublicKey: null });
  for (const [n, v] of [['zero', 0], ['negative', -1], ['fraction', 1.5], ['string', '2'], ['null', null]] as [string, any][]) await C('threshold-' + n, { threshold: v });
  await C('policy-short', { policyAuthorityPublicKey: B(new Uint8Array(31)) }); await C('policy-null', { policyAuthorityPublicKey: null });
  for (const [n, v] of [['zero', 0], ['negative', -5], ['nan', { $num: 'NaN' }], ['infinity', { $num: 'Infinity' }], ['string', '5']] as [string, any][]) await C('ttl-' + n, { sessionTtlMs: v });
  await C('ttl-fraction-ok', { sessionTtlMs: 0.5 }, [f.rng(1)[0]!]);
  await C('share-zero-ok', { share: B(new Uint8Array(32)) }, [f.rng(1)[0]!]);
  await C('share-not-reduced', { share: S('ctor/share-wide') }, [f.rng(1)[0]!]);
  await C('threshold-above-n-ok', { threshold: 99 }, [f.rng(1)[0]!]);
}

// ============================ coordinator ============================
// cfg: {groupPublicKey, threshold, signers:[S], verificationShares:[{identifier, publicKey}] | enroll:[enrollment...], timeoutMs?, sessionIds:[string], calls:[{message, allow, signerIds?, timeoutMs?}]}
// S (a signer): {identifier, share ({$share}), threshold, policyAuthorityPublicKey, sessionTtlMs?, store?, rng:[seed...]} = a GuardianSignerService (rng: PoP nonce, then hr/br per round1), optionally with
//   delay: {r1?: ms, r2?: ms}   the response arrives after that many ms
//   throws: {r1?: true, r2?: true}   the transport throws "unreachable"
//   edits: [{round: 1|2, path: [...keys], op: "set"|"delete"|"flip", value?}]   a hostile transport rewriting that round's response (flip = flip the first bit of the base64url string)
//   canned: {round1: [response|"throw"...], round2: [...]}   no service: the transport replays these responses in call order
const getPath = (x: any, p: string[]) => p.slice(0, -1).reduce((a, k) => a?.[k], x);
const applyEdits = (resp: any, edits: any[], round: number) => {
  let r = J(resp);
  for (const e of edits ?? []) {
    if (e.round !== round) continue;
    const parent = getPath(r, e.path), key = e.path[e.path.length - 1];
    if (!parent) continue;
    if (e.op === 'set') parent[key] = e.value; else if (e.op === 'delete') delete parent[key]; else if (e.op === 'flip') parent[key] = flipStr(parent[key], 0);
  }
  return r;
};
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
const coordinator = async (cfg: any) => {
  const clock = () => 1_000_000;
  const out: any = { calls: [] };
  const transports = cfg.signers.map((s: any) => {
    const id = s.identifier;
    const owner = 'svc' + id;
    let service: any = null;
    const counters = { r1: 0, r2: 0 };
    if (!s.canned) {
      setQueueBytes(owner, s.rng);
      service = as(owner, () => new N.GuardianSignerService({ identifier: id, share: s.share, groupPublicKey: s.groupPublicKey, threshold: s.threshold, policyAuthorityPublicKey: s.policyAuthorityPublicKey, sessionTtlMs: s.sessionTtlMs, now: clock, nonceStore: mkStore(s.store) }));
    }
    const respond = async (round: 1 | 2, req: any) => {
      const key = round === 1 ? 'r1' : 'r2';
      const n = counters[key]++;
      if (s.delay?.[key]) await sleep(s.delay[key]);
      if (s.throws?.[key]) throw new Error('unreachable');
      let resp: any;
      if (s.canned) {
        const c = s.canned[round === 1 ? 'round1' : 'round2'][n];
        if (c === 'throw' || c === undefined) throw new Error('unreachable');
        resp = c;
      } else resp = jsonOut(as(owner, () => (round === 1 ? service.round1(req) : service.round2(req))));
      return applyEdits(resp, s.edits, round);
    };
    return { identifier: id, round1: (req: any) => respond(1, req), round2: (req: any) => respond(2, req) };
  });
  const sids = [...(cfg.sessionIds ?? [])];
  let coord: any;
  try {
    coord = new N.NetworkCoordinator({
      groupPublicKey: cfg.groupPublicKey, threshold: cfg.threshold, signers: transports,
      ...(cfg.verificationShares !== undefined ? { verificationShares: cfg.verificationShares } : {}),
      ...(cfg.enroll !== undefined ? { enroll: cfg.enroll } : {}),
      timeoutMs: cfg.timeoutMs ?? undefined, newSessionId: () => sids.shift() ?? (() => { throw new Error('no more scripted session ids'); })(),
    });
  } catch (e: any) { out.ctor = errOut(e); return out; }
  for (const c of cfg.calls) {
    try {
      const r = await coord.sign(c.message, c.allow, { signerIds: c.signerIds ?? undefined, timeoutMs: c.timeoutMs ?? undefined });
      out.calls.push(jsonOut({ signature: r.signature, sessionId: r.sessionId, signers: r.signers }));
    } catch (e: any) { out.calls.push(errOut(e)); }
  }
  await sleep(0);
  return out;
};
let CN = 0;
function world(tag: string, d: Dealer, ids: number[], over: any = {}) {
  const kg = kgOf(d); const gpk = kg.groupPublicKey as Uint8Array;
  const msg = over.msg ?? MSG;
  const allow = over.allow ?? mkAllow(msg, gpk, { nonce: 'cw-' + tag });
  const rounds = over.rounds ?? 1;
  const signers = ids.map((id) => ({
    identifier: id, share: shareOf(d, id), threshold: d.t, groupPublicKey: B(gpk), policyAuthorityPublicKey: B(over.policyFor?.(id) ?? polPk), ...(over.signerExtra?.(id) ?? {}),
    rng: [`${tag}/${id}/pop`, ...Array.from({ length: rounds }, (_, k) => [`${tag}/${id}/hr${k}`, `${tag}/${id}/br${k}`]).flat()].map(S),
  }));
  const vss = ids.map((id) => ({ identifier: id, publicKey: B(vkey(kg, id)) }));
  const cfg: any = { groupPublicKey: B(gpk), threshold: d.t, signers, verificationShares: vss, sessionIds: over.sessionIds ?? ['cs-' + tag, 'cs-' + tag + '-2'], calls: over.calls ?? [{ message: B(msg), allow }] };
  return { cfg, kg, gpk, allow, msg, ids };
}
const CR = (name: string, cfg: any) => RC('coordinator', name, coordinator, [cfg]);
const D35 = dealerOf('d35', 3, 5);
{
  const w = world('co-happy', D23, [1, 2, 3]); await CR('happy-2of3-default-first-t', w.cfg);
  const w2 = world('co-ids', D23, [1, 2, 3], { calls: [{ message: B(MSG), allow: mkAllow(MSG, GPK, { nonce: 'cw-ids' }), signerIds: [2, 3] }] }); await CR('happy-signerIds-2-3', w2.cfg);
  const w3 = world('co-5', D35, [1, 2, 3, 4, 5]); await CR('happy-3of5', w3.cfg);
  const w4 = world('co-5b', D35, [1, 2, 3, 4, 5], { calls: [{ message: B(MSG), allow: mkAllow(MSG, kgOf(D35).groupPublicKey, { nonce: 'cw-5b' }), signerIds: [5, 3, 1, 4] }] }); await CR('happy-3of5-four-chosen-first-t-committed-used', w4.cfg);
  const w5 = world('co-1of1', dealerOf('d11', 1, 1), [1]); await CR('happy-1of1', w5.cfg);
  const w6 = world('co-emptymsg', D23, [1, 2], { msg: new Uint8Array(), allow: mkAllow(new Uint8Array(), GPK, { nonce: 'cw-e' }) }); await CR('happy-empty-message', w6.cfg);
  const w7 = world('co-long', D23, [1, 2], { msg: Uint8Array.from({ length: 3000 }, (_, i) => (i * 5) & 255) }); await CR('happy-long-message', w7.cfg);
  const w8 = world('co-sparse', dealerOf('dsp', 2, 3, [5, 9, 200]), [5, 9, 200]); await CR('happy-sparse-ids', w8.cfg);
  const w9 = world('co-ttl', D23, [1, 2], { signerExtra: () => ({ sessionTtlMs: 60000, store: 'memory' }) }); await CR('happy-with-memory-store', w9.cfg);
  // two calls on one coordinator: fresh nonces and session ids each time
  const a1 = mkAllow(MSG, GPK, { nonce: 'cw-two-a' }), a2 = mkAllow(utf('second'), GPK, { nonce: 'cw-two-b' });
  const w10 = world('co-two', D23, [1, 2], { rounds: 2, calls: [{ message: B(MSG), allow: a1 }, { message: B(utf('second')), allow: a2 }], sessionIds: ['cs-two-1', 'cs-two-2'] }); await CR('two-sessions-sequential', w10.cfg);
}
{ // enrollment path
  const enrollOf = (tag: string, ids: number[]) => ids.map((id) => {
    const labels = [`${tag}/${id}/pop`];
    setQueue('en' + id, labels);
    const svc = as('en' + id, () => new N.GuardianSignerService({ identifier: id, share: shareBytes(KG23, id).share, groupPublicKey: GPK, threshold: 2, policyAuthorityPublicKey: polPk }));
    return J(jsonOut(svc.enrollment()));
  });
  const w = world('co-enr', D23, [1, 2, 3]); delete w.cfg.verificationShares; w.cfg.enroll = enrollOf('co-enr', [1, 2, 3]); await CR('enroll-happy', w.cfg);
  const w2 = world('co-enr2', D23, [1, 2, 3]); delete w2.cfg.verificationShares; const e2 = enrollOf('co-enr2', [1, 2, 3]); e2[1].pop.s = flipStr(e2[1].pop.s, 0); w2.cfg.enroll = e2; await CR('enroll-rogue-pop-ctor-refuses', w2.cfg);
  const w3 = world('co-enr3', D23, [1, 2, 3]); delete w3.cfg.verificationShares; const e3 = enrollOf('co-enr3', [1, 2, 3]); delete e3[2].pop; w3.cfg.enroll = e3; await CR('enroll-missing-pop-ctor-refuses', w3.cfg);
  const w4 = world('co-enr4', D23, [1, 2]); delete w4.cfg.verificationShares; await CR('ctor-neither-shares-nor-enroll', w4.cfg);
  const w5 = world('co-enr5', D23, [1, 2]); w5.cfg.enroll = enrollOf('co-enr5', [1, 2]); await CR('enroll-wins-over-verificationShares', w5.cfg);
  const w6 = world('co-enr6', D23, [1, 2]); w6.cfg.enroll = []; delete w6.cfg.verificationShares; await CR('enroll-empty-ctor-refuses', w6.cfg);
}
{ // ctor / call validation
  const w = world('co-v', D23, [1, 2]);
  const V2 = (n: string, over: any, calls?: any) => CR('ctor-' + n, { ...J(w.cfg), ...over, ...(calls ? { calls } : {}) });
  await V2('group-short', { groupPublicKey: B(new Uint8Array(31)) }); await V2('group-null', { groupPublicKey: null });
  for (const [n, v] of [['zero', 0], ['negative', -1], ['fraction', 1.5], ['string', '2'], ['null', null]] as [string, any][]) await V2('threshold-' + n, { threshold: v });
  for (const [n, v] of [['zero', 0], ['negative', -1], ['nan', { $num: 'NaN' }], ['infinity', { $num: 'Infinity' }]] as [string, any][]) await V2('timeout-' + n, { timeoutMs: v });
  const w2 = world('co-v2', D23, [1, 2]);
  await CR('sign-message-not-bytes', { ...w2.cfg, calls: [{ message: null, allow: w2.allow }] });
  await CR('sign-too-few-selected', { ...world('co-v3', D23, [1, 2]).cfg, calls: [{ message: B(MSG), allow: w2.allow, signerIds: [1] }] });
  await CR('sign-unknown-signer-ids', { ...world('co-v4', D23, [1, 2]).cfg, calls: [{ message: B(MSG), allow: w2.allow, signerIds: [8, 9] }] });
  const w5 = world('co-v5', D23, [1, 2]); w5.cfg.threshold = 3; await CR('threshold-above-signers', w5.cfg);
}
{ // round-1 refusals and hostile round-1 responses
  const w = world('co-r1a', D23, [1, 2, 3], { signerExtra: (id) => (id === 1 ? { throws: { r1: true } } : {}) });
  await CR('r1-signer-unreachable-default-set-fails', w.cfg);
  const wb = world('co-r1b', D23, [1, 2, 3], { signerExtra: (id) => (id === 1 ? { throws: { r1: true } } : {}) }); wb.cfg.calls[0].signerIds = [1, 2, 3]; await CR('r1-signer-unreachable-all-chosen-succeeds', wb.cfg);
  const edits1 = (id: number, edits: any[]) => (x: number) => (x === id ? { edits } : {});
  for (const [n, e] of [
    ['pop-s-flipped', [{ round: 1, path: ['pop', 's'], op: 'flip' }]],
    ['pop-missing', [{ round: 1, path: ['pop'], op: 'delete' }]],
    ['pop-identifier-other', [{ round: 1, path: ['pop', 'identifier'], op: 'set', value: 3 }]],
    ['pop-publickey-other', [{ round: 1, path: ['pop', 'publicKey'], op: 'set', value: b64(vkey(KG23, 3)) }]],
    ['pop-R-flipped', [{ round: 1, path: ['pop', 'R'], op: 'flip' }]],
    ['identifier-unknown-to-coordinator', [{ round: 1, path: ['identifier'], op: 'set', value: 9 }]],
    ['identifier-claims-other-signer', [{ round: 1, path: ['identifier'], op: 'set', value: 3 }]],
    ['response-ok-false', [{ round: 1, path: ['ok'], op: 'set', value: false }, { round: 1, path: ['reason'], op: 'set', value: 'busy' }]],
    ['commitment-hiding-tampered', [{ round: 1, path: ['commitment', 'hiding'], op: 'flip' }]],
    ['commitment-missing', [{ round: 1, path: ['commitment'], op: 'delete' }]],
    ['commitment-identifier-other', [{ round: 1, path: ['commitment', 'identifier'], op: 'set', value: 2 }]],
  ] as [string, any[]][]) {
    const ww = world('co-r1-' + n, D23, [1, 2, 3], { signerExtra: edits1(1, e) }); ww.cfg.calls[0].signerIds = [1, 2, 3];
    await CR('r1-' + n, ww.cfg);
    const wx = world('co-r1x-' + n, D23, [1, 2], { signerExtra: edits1(1, e) });
    await CR('r1-' + n + '-no-spare-signer', wx.cfg);
  }
}
{ // round-2 refusals and hostile round-2 responses
  const edits2 = (id: number, edits: any[]) => (x: number) => (x === id ? { edits } : {});
  const w = world('co-r2a', D23, [1, 2, 3], { signerExtra: (id) => (id === 2 ? { throws: { r2: true } } : {}) }); w.cfg.calls[0].signerIds = [1, 2, 3];
  await CR('r2-signer-unreachable-below-threshold', w.cfg);
  const wb = world('co-r2b', D23, [1, 2, 3], { policyFor: (id) => (id === 2 ? polPk2 : polPk) }); wb.cfg.calls[0].signerIds = [1, 2, 3];
  await CR('r2-one-signer-trusts-another-policy-key', wb.cfg);
  const wc = world('co-r2c', D23, [1, 2], { policyFor: () => polPk2 });
  await CR('r2-all-refuse-wrong-policy-key', wc.cfg);
  const wd = world('co-r2d', D23, [1, 2], { allow: mkAllow(MSG, GPK, { nonce: 'x', expiresAt: 1_000_000 }) });
  await CR('r2-expired-allow-all-refuse', wd.cfg);
  const we = world('co-r2e', D23, [1, 2], { allow: mkAllow(utf('different action'), GPK, { nonce: 'x' }) });
  await CR('r2-allow-for-different-message', we.cfg);
  const wf = world('co-r2f', D23, [1, 2]); wf.cfg.calls[0].allow = null;
  await CR('r2-allow-null', wf.cfg);
  for (const [n, e] of [
    ['sig-share-flipped-aggregate-refuses', [{ round: 2, path: ['sig_share'], op: 'flip' }]],
    ['sig-share-noncanonical', [{ round: 2, path: ['sig_share'], op: 'set', value: 'AAAA' }]],
    ['sig-share-missing', [{ round: 2, path: ['sig_share'], op: 'delete' }]],
    ['sig-share-number', [{ round: 2, path: ['sig_share'], op: 'set', value: 7 }]],
    ['sig-share-padded', [{ round: 2, path: ['sig_share'], op: 'set', value: 'A'.repeat(43) + '=' }]],
    ['response-ok-false', [{ round: 2, path: ['ok'], op: 'set', value: false }, { round: 2, path: ['reason'], op: 'set', value: 'nope' }]],
    ['identifier-swapped', [{ round: 2, path: ['identifier'], op: 'set', value: 2 }]],
  ] as [string, any[]][]) {
    const ww = world('co-r2-' + n, D23, [1, 2, 3], { signerExtra: edits2(1, e) });
    await CR('r2-' + n, ww.cfg);
    const wy = world('co-r2y-' + n, D23, [1, 2, 3], { signerExtra: edits2(1, e) }); wy.cfg.calls[0].signerIds = [1, 2, 3];
    await CR('r2-' + n + '-spare-signer-unused', wy.cfg);
  }
}
{ // timeouts
  const w = world('co-t1', D23, [1, 2], { signerExtra: (id) => (id === 2 ? { delay: { r2: 400 } } : {}) }); w.cfg.timeoutMs = 60;
  await CR('timeout-ctor-window', w.cfg);
  const w2 = world('co-t2', D23, [1, 2], { signerExtra: (id) => (id === 2 ? { delay: { r1: 400 } } : {}) }); w2.cfg.calls[0].timeoutMs = 60;
  await CR('timeout-call-window-round1', w2.cfg);
  const w3 = world('co-t3', D23, [1, 2], { signerExtra: (id) => (id === 2 ? { delay: { r2: 400 } } : {}) }); w3.cfg.timeoutMs = 60; w3.cfg.calls[0].timeoutMs = 5000;
  await CR('timeout-call-window-overrides-ctor-and-succeeds', w3.cfg);
  const w4 = world('co-t4', D23, [1, 2], { signerExtra: (id) => (id === 2 ? { delay: { r2: 100 } } : {}) }); w4.cfg.timeoutMs = 5000;
  await CR('timeout-generous-window-succeeds', w4.cfg);
  const w5 = world('co-t5', D23, [1, 2], { signerExtra: (id) => (id === 2 ? { delay: { r2: 400 } } : {}) }); w5.cfg.calls[0].timeoutMs = { $num: 'NaN' };
  await CR('timeout-call-nan-means-no-deadline', w5.cfg);
}
{ // session reuse, equivocation across sessions, canned adversaries
  const w = world('co-s1', D23, [1, 2], { rounds: 2, sessionIds: ['reused', 'reused'], calls: [{ message: B(MSG), allow: mkAllow(MSG, GPK, { nonce: 'cw-s1a' }) }, { message: B(MSG), allow: mkAllow(MSG, GPK, { nonce: 'cw-s1b' }) }] });
  await CR('session-id-reused-after-signing', w.cfg);
  // canned honest responses recorded from a real run, then replayed with a differing commitment on the second use of the same session id
  const rec = (tag: string) => {
    const labels = (id: number) => [`${tag}/${id}/pop`, `${tag}/${id}/hr0`, `${tag}/${id}/br0`];
    const sv = [1, 2].map((id) => { setQueue('rc' + id, labels(id)); return as('rc' + id, () => new N.GuardianSignerService({ identifier: id, share: shareBytes(KG23, id).share, groupPublicKey: GPK, threshold: 2, policyAuthorityPublicKey: polPk, now: () => 1_000_000 })); });
    return [1, 2].map((id, i) => J(jsonOut(as('rc' + id, () => sv[i].round1({ typ: 'pca.frost.round1.v1', session_id: 'eq' })))));
  };
  const r1 = rec('co-eq');
  const refuse = { ok: false, identifier: 1, refused: true, reason: 'canned refusal' };
  const mkCanned = (id: number, r1a: any, r1b: any) => ({ identifier: id, canned: { round1: [r1a, r1b], round2: [{ ...refuse, identifier: id }, { ...refuse, identifier: id }] } });
  const cfg = (second: any) => ({
    groupPublicKey: B(GPK), threshold: 2, verificationShares: [1, 2].map((id) => ({ identifier: id, publicKey: B(vkey(KG23, id)) })), sessionIds: ['eq', 'eq'],
    signers: [mkCanned(1, r1[0], second), mkCanned(2, r1[1], r1[1])],
    calls: [{ message: B(MSG), allow: ALLOW }, { message: B(MSG), allow: ALLOW }],
  });
  await CR('equivocation-r1-same-session-different-commitment', cfg({ ...r1[0], commitment: { ...r1[0].commitment, hiding: flipStr(r1[0].commitment.hiding, 1) } }));
  await CR('equivocation-r1-identical-repeat-is-idempotent', cfg(r1[0]));
  await CR('equivocation-r1-binding-differs', cfg({ ...r1[0], commitment: { ...r1[0].commitment, binding: flipStr(r1[0].commitment.binding, 1) } }));
  // round 2 equivocation: the SAME session id, signer answers round 2 twice with different shares
  const mk2 = (a: string, b: string) => ({
    groupPublicKey: B(GPK), threshold: 1, verificationShares: [{ identifier: 1, publicKey: B(vkey(KG23, 1)) }], sessionIds: ['eq2', 'eq2'],
    signers: [{ identifier: 1, canned: { round1: [r1[0], r1[0]], round2: [{ ok: true, identifier: 1, sig_share: a }, { ok: true, identifier: 1, sig_share: b }] } }],
    calls: [{ message: B(MSG), allow: ALLOW }, { message: B(MSG), allow: ALLOW }],
  });
  await CR('equivocation-r2-same-session-different-share', mk2(b64(new Uint8Array(32).fill(1)), b64(new Uint8Array(32).fill(2))));
  await CR('equivocation-r2-identical-share-repeat', mk2(b64(new Uint8Array(32).fill(1)), b64(new Uint8Array(32).fill(1))));
}

// ============================ nonce store ============================
const rec = (n: number) => ({ hiding: B(new Uint8Array(32).fill(n)), binding: B(new Uint8Array(32).fill(n + 1)), hidingCommitment: B(new Uint8Array(32).fill(n + 2)), bindingCommitment: B(new Uint8Array(32).fill(n + 3)), createdAt: n });
const storeRun = (ops: any[]) => {
  const s = new NS.MemoryNonceStore();
  return ops.map((op) => {
    try {
      if (op.op === 'create') { const r = op.rec; s.create(op.sid, r); if (op.mutateInputAfter) { r.hiding.fill(0xee); r.hidingCommitment.fill(0xee); } return { ok: true }; }
      if (op.op === 'load') { const r = s.load(op.sid); const j = r === undefined ? null : jsonOut(r); if (r && op.mutate) { r.hiding.fill(0xee); r.binding.fill(0xee); } return { value: j }; }
      if (op.op === 'spend') { s.spend(op.sid); return { ok: true }; }
      if (op.op === 'drop') { s.drop(op.sid); return { ok: true }; }
      if (op.op === 'isSpent') return { value: s.isSpent(op.sid) };
      throw new Error('bad op');
    } catch (e: any) { return errOut(e); }
  });
};
const NSR = (name: string, ops: any[]) => R('nonceStore', name, storeRun, [ops]);
const c_ = (sid: any, n: number, extra: any = {}) => ({ op: 'create', sid, rec: rec(n), ...extra });
await NSR('create-load', [c_('a', 1), { op: 'load', sid: 'a' }]);
await NSR('load-unknown', [{ op: 'load', sid: 'zz' }, { op: 'isSpent', sid: 'zz' }]);
await NSR('create-twice-refused', [c_('a', 1), c_('a', 9), { op: 'load', sid: 'a' }]);
await NSR('create-copies-input', [c_('a', 1, { mutateInputAfter: true }), { op: 'load', sid: 'a' }]);
await NSR('load-returns-copy', [c_('a', 1), { op: 'load', sid: 'a', mutate: true }, { op: 'load', sid: 'a' }]);
await NSR('spend-removes-secret-keeps-marker', [c_('a', 1), { op: 'spend', sid: 'a' }, { op: 'load', sid: 'a' }, { op: 'isSpent', sid: 'a' }]);
await NSR('spend-twice-refused', [c_('a', 1), { op: 'spend', sid: 'a' }, { op: 'spend', sid: 'a' }]);
await NSR('spend-unknown-refused', [{ op: 'spend', sid: 'nope' }]);
await NSR('create-after-spent-refused', [c_('a', 1), { op: 'spend', sid: 'a' }, c_('a', 2), { op: 'isSpent', sid: 'a' }]);
await NSR('drop-live-not-spent', [c_('a', 1), { op: 'drop', sid: 'a' }, { op: 'load', sid: 'a' }, { op: 'isSpent', sid: 'a' }, c_('a', 3), { op: 'load', sid: 'a' }]);
await NSR('drop-unknown-ok', [{ op: 'drop', sid: 'never' }]);
await NSR('drop-spent-keeps-marker', [c_('a', 1), { op: 'spend', sid: 'a' }, { op: 'drop', sid: 'a' }, { op: 'isSpent', sid: 'a' }]);
await NSR('empty-session-id', [c_('', 1), { op: 'load', sid: '' }]);
await NSR('session-id-number', [c_(5, 1), { op: 'load', sid: 5 }]);
await NSR('independent-sessions', [c_('a', 1), c_('b', 5), { op: 'spend', sid: 'a' }, { op: 'load', sid: 'b' }, { op: 'isSpent', sid: 'b' }]);
await NSR('created-at-preserved', [c_('a', 123456789), { op: 'load', sid: 'a' }]);
// the contract check against the reference store and against stores with exactly one defect
const brokenStore = (kind: string) => {
  const live = new Map<string, any>(); const spent = new Set<string>();
  const cp = (r: any) => ({ hiding: r.hiding.slice(), binding: r.binding.slice(), hidingCommitment: r.hidingCommitment.slice(), bindingCommitment: r.bindingCommitment.slice(), createdAt: r.createdAt });
  const mkStoreObj = (): any => ({
    create(id: string, r: any) { if (kind !== 'create-overwrites' && live.has(id)) throw new Error('exists'); if (kind !== 'create-over-spent' && spent.has(id)) throw new Error('spent'); live.set(id, kind === 'create-aliases-input' ? r : cp(r)); },
    load(id: string) { const r = live.get(id); if (!r) return undefined; return kind === 'load-aliases' ? r : cp(r); },
    spend(id: string) { if (!live.has(id)) { if (kind === 'spend-unknown-ok' || (kind === 'spend-twice-ok' && spent.has(id))) return; throw new Error('not live'); } live.delete(id); spent.add(id); },
    drop(id: string) { live.delete(id); if (kind === 'drop-marks-spent') spent.add(id); },
    isSpent(id: string) { return kind === 'unknown-reports-spent' ? true : spent.has(id); },
  });
  const st = mkStoreObj();
  const reopen = (s: any) => { if (kind === 'spent-forgotten-on-restart') spent.clear(); if (kind === 'live-lost-on-restart') live.clear(); return s; };
  return { make: () => st, reopen };
};
const contract = (a: any) => {
  try {
    if (a.store === 'memory') NS.assertNonceStoreContract(() => new NS.MemoryNonceStore());
    else { const b = brokenStore(a.store.slice('broken:'.length)); NS.assertNonceStoreContract(b.make, b.reopen); }
    return null;
  } catch (e: any) { return errOut(e); }
};
await R('assertNonceStoreContract', 'memory-store-passes', contract, [{ store: 'memory' }]);
for (const k of ['create-overwrites', 'create-over-spent', 'load-aliases', 'spend-unknown-ok', 'spend-twice-ok', 'drop-marks-spent', 'unknown-reports-spent', 'spent-forgotten-on-restart', 'live-lost-on-restart', 'create-aliases-input']) await R('assertNonceStoreContract', (k === 'create-aliases-input' ? 'undetected-' : 'broken-') + k, contract, [{ store: 'broken:' + k }]);

// ============================ frost-pq ============================
const ALGS = [undefined, 'ed25519', 'hybrid-ed25519-ml-dsa-65', 'ml-dsa-65', 'ED25519', ' ed25519', 'hybrid', '', null, 0, 1, true, false, {}, [], ['ed25519']];
for (const [i, a] of ALGS.entries()) await R('resolveFrostGroupAlg', 'v' + i + '-' + (a === undefined ? 'undefined' : JSON.stringify(a)), (...x: any[]) => PQF.resolveFrostGroupAlg(...x), a === undefined ? [] : [a]);
const ssd = (ids: any) => PQF.frostSignerSetDigest(ids);
for (const [n, ids] of [['one', [1]], ['two', [1, 3]], ['reversed', [3, 1]], ['duplicates', [3, 1, 3, 1]], ['sparse', [5, 9, 200]], ['big', [9007199254740991, 1]], ['ten', [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]], ['unsorted-many', [10, 2, 33, 4, 100, 7]],
  ['empty', []], ['null', null], ['string-ids', ['1']], ['zero', [0, 1]], ['negative', [-1]], ['fraction', [1.5]], ['unsafe', [9007199254740992]], ['not-array', 3], ['mixed-bad', [1, null]]] as [string, any][]) await R('frostSignerSetDigest', n, ssd, [ids]);
const GP = b64(GPK);
const cr = (g: any, m: any, ids: any, alg: any) => PQF.frostCosignRepresentative(g, m, ids, alg);
const CRp = (name: string, g: any, m: Uint8Array | null, ids: any, alg: any) => R('frostCosignRepresentative', name, cr, [g, m === null ? null : B(m), ids, alg]);
await CRp('hybrid', GP, MSG, [1, 3], 'hybrid-ed25519-ml-dsa-65');
await CRp('classical', GP, MSG, [1, 3], 'ed25519');
await CRp('set-order-insensitive', GP, MSG, [3, 1, 1], 'hybrid-ed25519-ml-dsa-65');
await CRp('empty-message', GP, new Uint8Array(), [1], 'hybrid-ed25519-ml-dsa-65');
await CRp('other-group', b64(vkey(KG23, 1)), MSG, [1, 3], 'hybrid-ed25519-ml-dsa-65');
await CRp('group-short', b64(new Uint8Array(31)), MSG, [1], 'ed25519');
await CRp('group-padded', GP + '=', MSG, [1], 'ed25519');
await CRp('group-not-string', 5, MSG, [1], 'ed25519');
await CRp('group-not-a-point-ok', b64(new Uint8Array(32).fill(2)), MSG, [1], 'ed25519');
await CRp('empty-set', GP, MSG, [], 'ed25519');
await CRp('unknown-alg-not-validated', GP, MSG, [1], 'whatever');
await CRp('alg-null', GP, MSG, [1], null);
await CRp('message-null', GP, null, [1], 'ed25519');

// artifacts: a deterministic FROST aggregate over MSG for signers {1,3} under D23 (each sign uses randomness no other case uses)
let SIGN_N = 0;
const detSign = (kg: any, ids: number[], msg: Uint8Array, threshold?: number): Uint8Array => {
  const n = ++SIGN_N;
  const quorum = ids.map((id) => shareBytes(kg, id));
  const commits = quorum.map((p: any, i: number) => F.frostCommit(p, { hidingRandomness: sdb(`pq/hr/${n}/${i}`), bindingRandomness: sdb(`pq/br/${n}/${i}`) }));
  const cs = commits.map((c: any) => c.commitment);
  const vss = quorum.map((p: any) => ({ identifier: p.identifier, publicKey: p.publicKey }));
  const shares = quorum.map((p: any, i: number) => F.frostSign(p.identifier, p.share, kg.groupPublicKey, { hiding: commits[i].hidingNonce, binding: commits[i].bindingNonce }, msg, cs, { threshold, verificationShare: p.publicKey, verificationShares: vss }));
  return F.frostAggregate(msg, cs, shares, kg.groupPublicKey, { threshold, verificationShares: vss });
};
const SIG = detSign(KG23, [1, 3], MSG, 2);
const SIG_OTHER_MSG = detSign(KG23, [1, 3], utf('other message'), 2);
const gk = (l: string) => PQ.mlDsa65Keygen(sdb(l));
const GK1 = gk('pq/guardian1'), GK2 = gk('pq/guardian2');
const HYB = 'hybrid-ed25519-ml-dsa-65';
const repOf = (gpk: Uint8Array, msg: Uint8Array, ids: number[], alg = HYB) => PQF.frostCosignRepresentative(b64(gpk), msg, ids, alg);
const hybridArt = (sig: Uint8Array, kp: any, msg: Uint8Array, ids: number[], over: any = {}) => J(jsonOut({ sig: b64(sig), groupAlg: HYB, pq_sig: PQ.signWithSuite('ml-dsa-65', { mlDsa: kp }, repOf(GPK, msg, ids)).sig, pq_pk: b64(kp.publicKey), ...over }));
const HA = hybridArt(SIG, GK1, MSG, [1, 3]);
const CLA = { sig: b64(SIG) };
const vh = (a: any, m: any, g: any, ids: any, o: any) => PQF.verifyHybridFrostCosign(a, m, g, ids, o);
const VH = (name: string, art: any, over: { msg?: Uint8Array; g?: any; ids?: any; opts?: any } = {}) => R('verifyHybridFrostCosign', name, vh, [art, B(over.msg ?? MSG), over.g === undefined ? GP : over.g, over.ids === undefined ? [1, 3] : over.ids, over.opts === undefined ? { guardianPqPublicKey: b64(GK1.publicKey) } : over.opts]);
await VH('classical-ok', CLA, { opts: {} });
await VH('classical-explicit-alg-ok', { ...CLA, groupAlg: 'ed25519' }, { opts: {} });
await VH('classical-extra-pq-fields-ignored', { ...CLA, pq_sig: 'junk', pq_pk: 'junk' }, { opts: {} });
await VH('classical-wrong-message', CLA, { msg: utf('tampered'), opts: {} });
await VH('classical-other-message-sig', { sig: b64(SIG_OTHER_MSG) }, { opts: {} });
await VH('classical-sig-flipped', { sig: flipStr(CLA.sig, 5) }, { opts: {} });
await VH('classical-sig-short', { sig: CLA.sig.slice(0, 80) }, { opts: {} });
await VH('classical-sig-padded', { sig: CLA.sig + '==' }, { opts: {} });
await VH('classical-sig-number', { sig: 5 }, { opts: {} });
await VH('classical-other-group', CLA, { g: b64(vkey(KG23, 1)), opts: {} });
await VH('classical-group-short', CLA, { g: b64(new Uint8Array(31)), opts: {} });
await VH('classical-group-padded', CLA, { g: GP + '=', opts: {} });
await VH('classical-group-not-string', CLA, { g: 5, opts: {} });
await VH('classical-signer-set-irrelevant', CLA, { ids: [], opts: {} });
await VH('classical-expect-hybrid-downgrade-denied', CLA, { opts: { expectGroupAlg: HYB, guardianPqPublicKey: b64(GK1.publicKey) } });
await VH('classical-expect-ed25519-ok', CLA, { opts: { expectGroupAlg: 'ed25519' } });
await VH('classical-expect-unknown', CLA, { opts: { expectGroupAlg: 'rsa' } });
await VH('classical-expect-null', CLA, { opts: { expectGroupAlg: null } });
await VH('hybrid-ok', HA);
await VH('hybrid-ok-set-order-and-dups', HA, { ids: [3, 1, 1] });
await VH('hybrid-ok-expect-hybrid', HA, { opts: { guardianPqPublicKey: b64(GK1.publicKey), expectGroupAlg: HYB } });
await VH('hybrid-expect-ed25519-denied', HA, { opts: { guardianPqPublicKey: b64(GK1.publicKey), expectGroupAlg: 'ed25519' } });
await VH('hybrid-no-pq_pk-self-description-ok', (() => { const a = J(HA); delete a.pq_pk; return a; })());
await VH('hybrid-pq_pk-differs-from-registered', hybridArt(SIG, GK1, MSG, [1, 3], { pq_pk: b64(GK2.publicKey) }));
await VH('hybrid-registered-other-key', HA, { opts: { guardianPqPublicKey: b64(GK2.publicKey) } });
await VH('hybrid-signed-by-other-key-pq_pk-matches-registered', hybridArt(SIG, GK2, MSG, [1, 3]), { opts: { guardianPqPublicKey: b64(GK2.publicKey) } });
await VH('hybrid-attacker-key-self-asserted', hybridArt(SIG, GK2, MSG, [1, 3]), { opts: { guardianPqPublicKey: b64(GK1.publicKey) } });
await VH('hybrid-no-registered-key', HA, { opts: {} });
await VH('hybrid-registered-key-short', HA, { opts: { guardianPqPublicKey: b64(GK1.publicKey).slice(0, 200) } });
await VH('hybrid-registered-key-padded', HA, { opts: { guardianPqPublicKey: b64(GK1.publicKey) + '=' } });
await VH('hybrid-registered-key-number', HA, { opts: { guardianPqPublicKey: 5 } });
await VH('hybrid-pq_sig-missing', (() => { const a = J(HA); delete a.pq_sig; return a; })());
await VH('hybrid-pq_sig-number', hybridArt(SIG, GK1, MSG, [1, 3], { pq_sig: 5 }));
await VH('hybrid-pq_sig-junk', hybridArt(SIG, GK1, MSG, [1, 3], { pq_sig: 'AAAA' }));
await VH('hybrid-pq_sig-flipped', (() => { const a = J(HA); a.pq_sig = flipStr(a.pq_sig, 7); return a; })());
await VH('hybrid-pq_sig-over-plain-message-not-representative', hybridArt(SIG, GK1, MSG, [1, 3], { pq_sig: PQ.signWithSuite('ml-dsa-65', { mlDsa: GK1 }, MSG).sig }));
await VH('hybrid-pq_sig-for-other-signer-set', hybridArt(SIG, GK1, MSG, [1, 3], { pq_sig: PQ.signWithSuite('ml-dsa-65', { mlDsa: GK1 }, repOf(GPK, MSG, [1, 2])).sig }));
await VH('hybrid-pq_sig-for-other-message', hybridArt(SIG, GK1, MSG, [1, 3], { pq_sig: PQ.signWithSuite('ml-dsa-65', { mlDsa: GK1 }, repOf(GPK, utf('other'), [1, 3])).sig }));
await VH('hybrid-pq_sig-for-other-group', hybridArt(SIG, GK1, MSG, [1, 3], { pq_sig: PQ.signWithSuite('ml-dsa-65', { mlDsa: GK1 }, repOf(vkey(KG23, 2), MSG, [1, 3])).sig }));
await VH('hybrid-pq_sig-bound-to-classical-suite-label', hybridArt(SIG, GK1, MSG, [1, 3], { pq_sig: PQ.signWithSuite('ml-dsa-65', { mlDsa: GK1 }, repOf(GPK, MSG, [1, 3], 'ed25519')).sig }));
await VH('hybrid-ed-bad-pq-ok', hybridArt(SIG_OTHER_MSG, GK1, MSG, [1, 3]));
await VH('hybrid-both-bad', hybridArt(SIG_OTHER_MSG, GK1, MSG, [1, 3], { pq_sig: 'AAAA' }));
await VH('hybrid-wrong-message', HA, { msg: utf('tampered') });
await VH('hybrid-wrong-signer-set', HA, { ids: [1, 2] });
await VH('hybrid-empty-signer-set', HA, { ids: [] });
await VH('hybrid-signer-set-bad-id', HA, { ids: [0, 1] });
await VH('hybrid-signer-set-null', HA, { ids: null });
await VH('hybrid-other-group', HA, { g: b64(vkey(KG23, 1)) });
await VH('hybrid-group-malformed', HA, { g: 'x' });
await VH('artifact-null', null); await VH('artifact-string', 'x'); await VH('artifact-empty', {}); await VH('artifact-sig-missing-hybrid', { groupAlg: HYB, pq_sig: HA.pq_sig, pq_pk: HA.pq_pk });
await VH('artifact-array', []);
for (const [n, v] of [['unknown', 'rsa'], ['null', null], ['number', 3], ['empty', ''], ['case', 'ED25519'], ['ml-dsa-only', 'ml-dsa-65']] as [string, any][]) await VH('groupAlg-' + n, { ...CLA, groupAlg: v }, { opts: {} });

// signHybridFrostCosign: Ed25519 half is fresh-random (scripted), so the case reports whether it verifies; the ML-DSA half is deterministic
const shc = (gpk: any, quorum: any, msg: any, opts: any) => {
  const o2 = { ...opts };
  if (o2.guardianMlDsaSeed) { o2.guardianMlDsa = PQ.mlDsa65Keygen(o2.guardianMlDsaSeed); delete o2.guardianMlDsaSeed; }
  const r = PQF.signHybridFrostCosign(gpk, quorum, msg, o2);
  const sigVerifies = ed.verify(fromB64(r.sig), msg, gpk, { zip215: false });
  const { sig, ...rest } = r;
  return { ...rest, sigVerifies, sigLength: fromB64(sig).length };
};
const Qs = (ids: number[]) => ids.map((id) => ({ identifier: id, share: shareOf(D23, id), publicKey: B(vkey(KG23, id)) }));
let HS = 0;
const SH = (name: string, q: any, msg: Uint8Array, opts: any, nDraws: number, gpk: any = B(GPK)) => RC('signHybridFrostCosign', name, shc, [gpk, q, B(msg), opts], Array.from({ length: Math.max(nDraws, 2) * 2 }, (_, i) => `pq/sign/${++HS}/${i}`));
await SH('classical-default', Qs([1, 3]), MSG, {}, 2);
await SH('classical-explicit', Qs([1, 2]), MSG, { groupAlg: 'ed25519', threshold: 2 }, 2);
await SH('classical-three-signers', Qs([1, 2, 3]), MSG, { threshold: 2 }, 3);
await SH('classical-ignores-guardian-key', Qs([2, 3]), MSG, { guardianMlDsaSeed: S('pq/guardian1') }, 2);
await SH('hybrid-ok', Qs([1, 3]), MSG, { groupAlg: HYB, guardianMlDsaSeed: S('pq/guardian1') }, 2);
await SH('hybrid-ok-threshold', Qs([3, 2]), MSG, { groupAlg: HYB, guardianMlDsaSeed: S('pq/guardian2'), threshold: 2 }, 2);
await SH('hybrid-signer-set-is-quorum-order-free', Qs([3, 1]), MSG, { groupAlg: HYB, guardianMlDsaSeed: S('pq/guardian1') }, 2);
await SH('hybrid-empty-message', Qs([1, 3]), new Uint8Array(), { groupAlg: HYB, guardianMlDsaSeed: S('pq/guardian1') }, 2);
await SH('hybrid-without-guardian-key', Qs([1, 3]), MSG, { groupAlg: HYB }, 2);
await SH('hybrid-guardian-key-empty-object', Qs([1, 3]), MSG, { groupAlg: HYB, guardianMlDsa: {} }, 2);
await SH('hybrid-guardian-key-null', Qs([1, 3]), MSG, { groupAlg: HYB, guardianMlDsa: null }, 2);
await SH('unknown-groupAlg', Qs([1, 3]), MSG, { groupAlg: 'rsa' }, 2);
await SH('groupAlg-null', Qs([1, 3]), MSG, { groupAlg: null }, 2);
await SH('below-threshold', Qs([1]), MSG, { threshold: 2 }, 0);
await SH('empty-quorum', [], MSG, {}, 0);
await SH('duplicate-participant', [Qs([1])[0], Qs([1])[0]], MSG, {}, 0);
await SH('wrong-group-key', Qs([1, 3]), MSG, {}, 2, B(vkey(KG23, 1)));
await SH('group-key-short', Qs([1, 3]), MSG, {}, 0, B(new Uint8Array(31)));

// PQ quorum
const qr = (m: any) => PQF.pqQuorumRepresentative(m);
for (const [n, m] of [['empty', new Uint8Array()], ['msg', MSG], ['seed', sdb('pq/q/m')]] as [string, Uint8Array][]) await R('pqQuorumRepresentative', n, qr, [B(m)]);
await R('pqQuorumRepresentative', 'null', qr, [null]);
const spq = (m: any, seeds: any, t: any) => PQF.signPqQuorum(m, seeds.map((s: any) => PQ.mlDsa65Keygen(s)), t);
const QSEEDS = [S('pq/q/k1'), S('pq/q/k2'), S('pq/q/k3')];
const pkOf = (s: any) => b64(PQ.mlDsa65Keygen(un(s)).publicKey);
const QPK = QSEEDS.map(pkOf);
await R('signPqQuorum', 'three', spq, [B(MSG), QSEEDS, null]);
await R('signPqQuorum', 'three-t2', spq, [B(MSG), QSEEDS, 2]);
await R('signPqQuorum', 'one', spq, [B(MSG), [QSEEDS[0]], null]);
await R('signPqQuorum', 'empty-message', spq, [B(new Uint8Array()), QSEEDS.slice(0, 2), null]);
await R('signPqQuorum', 'no-signers', spq, [B(MSG), [], null]);
await R('signPqQuorum', 'pqT-above-signers-informational', spq, [B(MSG), QSEEDS.slice(0, 2), 9]);
await R('signPqQuorum', 'pqT-zero', spq, [B(MSG), QSEEDS.slice(0, 2), 0]);
const BLK = J(jsonOut(spq(MSG, QSEEDS.map(un), 3)));
const npl = (l: any) => [...PQF.normalizePqQuorumPool(l)];
await R('normalizePqQuorumPool', 'valid-strings', npl, [QPK]);
await R('normalizePqQuorumPool', 'bytes-and-strings', (l: any) => [...PQF.normalizePqQuorumPool(l)], [[B(PQ.mlDsa65Keygen(un(QSEEDS[0])).publicKey), QPK[1]]]);
await R('normalizePqQuorumPool', 'dedupes', npl, [[QPK[0], QPK[0], QPK[1]]]);
await R('normalizePqQuorumPool', 'drops-malformed', npl, [[QPK[0], 'short', '', 5, null, QPK[1] + '=', QPK[2].slice(0, 100)]]);
await R('normalizePqQuorumPool', 'empty', npl, [[]]);
await R('normalizePqQuorumPool', 'bytes-wrong-length', npl, [[B(new Uint8Array(32))]]);
const vpq = (blk: any, m: any, pool: any, t: any) => PQF.verifyPqQuorum(blk, m, new Set(pool), t);
const VQ = (name: string, blk: any, over: { msg?: Uint8Array; pool?: any; t?: any } = {}) => R('verifyPqQuorum', name, vpq, [blk, B(over.msg ?? MSG), over.pool ?? QPK, over.t === undefined ? 3 : over.t]);
await VQ('ok-3of3', BLK); await VQ('ok-2of3-need-2', BLK, { t: 2 }); await VQ('ok-1of3', BLK, { t: 1 });
await VQ('short-need-4', BLK, { t: 4 });
await VQ('pool-missing-one', BLK, { pool: QPK.slice(0, 2) }); await VQ('pool-empty', BLK, { pool: [] });
await VQ('pool-has-extra', BLK, { pool: [...QPK, b64(PQ.mlDsa65Keygen(sdb('pq/q/extra')).publicKey)] });
await VQ('wrong-message', BLK, { msg: utf('tampered') });
await VQ('t-zero', BLK, { t: 0 }); await VQ('t-negative', BLK, { t: -1 }); await VQ('t-fraction', BLK, { t: 1.5 }); await VQ('t-string', BLK, { t: '3' });
await VQ('block-null', null); await VQ('block-string', 'x'); await VQ('block-array', []); await VQ('block-empty', {});
await VQ('version-missing', (() => { const b = J(BLK); delete b.v; return b; })());
await VQ('version-1', { ...J(BLK), v: 1 }); await VQ('version-3', { ...J(BLK), v: 3 }); await VQ('version-string', { ...J(BLK), v: '2' });
await VQ('alg-other', { ...J(BLK), alg: 'ml-dsa-87' }); await VQ('alg-missing', (() => { const b = J(BLK); delete b.alg; return b; })());
await VQ('signers-not-list', { ...J(BLK), signers: {} }); await VQ('signers-missing', (() => { const b = J(BLK); delete b.signers; return b; })());
await VQ('duplicate-signer-counted-once', { ...J(BLK), signers: [BLK.signers[0], BLK.signers[0], BLK.signers[1]] }, { t: 3 });
await VQ('duplicate-signer-counted-once-t2', { ...J(BLK), signers: [BLK.signers[0], BLK.signers[0], BLK.signers[1]] }, { t: 2 });
await VQ('entry-null-skipped', { ...J(BLK), signers: [null, ...BLK.signers] });
await VQ('entry-non-string-skipped', { ...J(BLK), signers: [{ pk: 1, sig: 2 }, ...BLK.signers] });
await VQ('sig-flipped-skipped', { ...J(BLK), signers: [{ pk: BLK.signers[0].pk, sig: flipStr(BLK.signers[0].sig, 3) }, BLK.signers[1], BLK.signers[2]] });
await VQ('sig-swapped-between-keys', { ...J(BLK), signers: [{ pk: BLK.signers[0].pk, sig: BLK.signers[1].sig }, BLK.signers[1], BLK.signers[2]] });
await VQ('untrusted-key-skipped', { ...J(BLK), signers: [{ pk: b64(PQ.mlDsa65Keygen(sdb('pq/q/outsider')).publicKey), sig: BLK.signers[0].sig }, BLK.signers[1], BLK.signers[2]] });
await VQ('signature-over-bare-message-not-representative', { ...J(BLK), signers: QSEEDS.map((s) => { const kp = PQ.mlDsa65Keygen(un(s)); return { pk: b64(kp.publicKey), sig: b64(PQ.mlDsa65Sign(kp.secretKey, MSG)) }; }) });
await VQ('t-below-recorded-pqT-informational', { ...J(BLK), pqT: 99 });
await VQ('empty-signers', { ...J(BLK), signers: [] }, { t: 1 });
await VQ('entry-cap-256-exceeded-valid-ones-after-cap-ignored', { ...J(BLK), signers: [...Array.from({ length: 256 }, () => null), ...BLK.signers] }, { t: 1 });
await VQ('entry-cap-256-reached-valid-at-255', { ...J(BLK), signers: [...Array.from({ length: 255 }, () => null), BLK.signers[0]] }, { t: 1 });

// ---- write -------------------------------------------------------------------------------------------------------------
// audit: no dealer share of any dealer used here may appear (as a plain token) in the corpus
const audit = [D23, D35, dealerOf('d11', 1, 1), dealerOf('d13', 1, 3), dealerOf('dsp', 2, 3, [5, 9, 200])].flatMap((d) => kgOf(d).participantShares.map((p: any) => b64(p.share)));
const text = o.cases.map((c: any) => ser(c)).join('\n');
for (const t of audit) if (text.includes(t)) throw new Error('a dealer share leaked into the committed corpus');
refWrite(o, 'frost-net');
