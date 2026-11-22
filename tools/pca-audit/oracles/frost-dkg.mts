// Oracle: FROST distributed key generation, TS reference = packages/pca/src/frost-dkg.ts, frost-dkg-channel.ts and (framing only) frost-dkg-tls.ts.
// Writes out/ref-frost-dkg.json.gz (committed: every secret is a seed label) and out/ref-frost-dkg-gen.json.gz (the cases that carry a derived
// secret: round-2 shares f_i(j), signing shares, revealed shares, and the wire bytes of share messages; regenerated in CI by
// scripts/pca-ci-workflows/_native/scripts/gen-secret-corpus.sh frost-dkg:frost-dkg, never committed).
//
// ARGUMENT FORMS: as frost-net.mts ({"$bytes": b64url}, {"$bytes": {"$seed": label}}, {"$num": ...}, trailing {"$rng": [...]}), plus
//   stateSpec  {id, t, n, sessionId, coefficients:[a_0..a_{t-1}], popNonce}  (every member a seed form): the DkgParticipantState of
//              dkgRound1(id, t, n, sessionId, {coefficients, popNonce}). A native builds the state from the spec with ITS dkgRound1.
//   $rng       the 32-byte values the reference drew, in draw order, for the call: dkgRound1 draws t coefficients (unless given) then one PoP
//              nonce (unless given); frostDkgSimulate draws the session id (unless given) then each participant in order;
//              runDkgOverChannel party cases draw t coefficients then the PoP nonce (the party's round 1 runs before its first await).
//   Unused trailing rng values are allowed.
// OUTPUT: as frost-net.mts. A DkgChannelError adds "class":"DkgChannelError", "code" and "peer" (null when none): compare code and peer exactly;
//   the message text is informative. Verdict / resolution `reason` strings of dkgVerifyComplaint / dkgResolveBlame / dkgCheckEchoes are the
//   reference's fixed strings and are compared exactly. Errors of dkgFinalize / dkgRound1 / dkgRound2 / dkgFileComplaint / dkgRebut /
//   frostDkgSimulate are refusals: compare only that the native refuses.
//
// PORTING (fn(args) -> native entry point)
//   constants []                                              -> DKG_WIRE_VERSION, DKG_MAX_MESSAGE_BYTES, DKG_MAX_PARTICIPANTS, DKG_MESSAGE_KINDS
//   dkgRound1 [id, t, n, sessionId, {coefficients?, popNonce?}]  -> {package}     (the state is rebuilt from the same inputs by later cases)
//   dkgVerifyRound1 [fromIdentifier, package, sessionId]      -> bool (never throws)
//   dkgSignShare [stateSpec, to, shareBytes]                  -> b64url(R_s || s)  (any share bytes, not only a polynomial value)
//   dkgRound2 [stateSpec, packages]                           -> [DkgShareToSend{from,to,sessionId,share,sig}] in package order, own id skipped
//   dkgVerifyShare [{from, share, sig?}, senderPackage, myIdentifier, sessionId] -> bool (never throws)
//   dkgFileComplaint [{accused, accuser, receivedShare, shareSig, senderCommitments, sessionId}] -> DkgComplaint
//   dkgVerifyComplaint [complaint, packages]                  -> {justified, disqualify?, atFault?, reason}
//   dkgRebut [accused, complaint, stateSpec]                  -> DkgRebuttal
//   dkgResolveBlame [complaint, rebuttal|null, packages]      -> {guilty, reason}      (null = undefined rebuttal)
//   dkgQualifiedSet [participants, complaints, packages, rebuttals?] -> ascending ids  (a missing 4th argument is [])
//   dkgTranscriptDigest [{round1Packages, complaints, qualified, sessionId}] -> string ; dkgEcho [{identifier, round1Packages, complaints, qualified, sessionId}] -> DkgEcho
//   dkgCheckEchoes [qualified, echoes, sessionId]             -> {agreed, digest?, reason?}
//   dkgFinalize [myIdentifier, stateSpec, receivedShares, packages, qualified|null, agreement|null] -> DkgKeyPackage (agreement = {echoes, complaints?}); receivedShares[i] = {from, sessionId, share, sig?}
//   frostDkgSimulate [t, n, opts]                             -> the full ceremony result (see the case out)
//   encodeDkgMessage [sessionId, kind, body] -> bytes  (JSON.stringify of {v,sid,kind,body} with that member order, body members in the order given)
//   decodeDkgMessage [bytes, sessionId] -> {kind, body}  ; decodeDkgRound1Package [body, t] ; decodeDkgShareMessage [body] ; decodeDkgComplaints [body] ;
//   decodeDkgRebuttals [body] ; decodeDkgEcho [body]
//   dkgInbox [{sessionId, peers, ops}]  -> one result per op: accept {sender, bytes} fail {peer, code, message} peerGone {peer} close {} collect {kind, from, timeoutMs}
//   memoryNetwork [{ids, sessionId, intercept?, ops}]  -> channels summary, then one result per op (broadcast / send / deliver / collect / close)
//   runDkgOverChannel [party, {$rng}]  (one party replayed over a scripted channel; party = {self, t, participants, sessionId, timeoutMs, peers?, inbound:[{from, kind, bytes}]}).
//        Before every collect(kind) the harness first delivers (inbox.accept(from, bytes), in list order) every inbound entry whose `kind` is that kind or an
//        EARLIER phase (round1, share, complaints, rebuttals, echo); the channel records every broadcast/send as {op, kind, to?, bytes} (bytes =
//        encodeDkgMessage(sessionId, kind, body)); send to a non-peer refuses with DkgChannelError identity. out = {outbound, result} or {outbound, error}.
//   tlsFrameEncode [payload] -> 4-byte big-endian length || payload ; tlsFrameDecode [{chunks}] -> {accepted, error, buffered}: a MODEL of the inline framing
//        loop of startTlsDkgNode (no exported entry point exists): a frame whose length exceeds DKG_MAX_MESSAGE_BYTES is refused before any allocation.
import { Oracle, refWrite, splitWrite, tokensIn, seed, jsonOut, reparse, ser } from './lib.mjs';
import { ed, S, B, b64, fromB64, sdb, un, J, flipB, flipStr, setQueue, as, errOut, runner, bindFrost, PFX } from './frost-net-common.mts';

const F: any = await import('../../../packages/pca/src/frost.ts');
const D: any = await import('../../../packages/pca/src/frost-dkg.ts');
const C: any = await import('../../../packages/pca/src/frost-dkg-channel.ts');
const H: any = await import('../../../packages/pca/src/hash.ts');
bindFrost(F);

const o = new Oracle('frost-dkg', 'tools/pca-audit/oracles/frost-dkg.mts', 'TS-reference oracle for the FROST distributed key generation (rounds, complaints, rebuttals, blame, echo agreement, finalize), its wire codec, inbox and party driver.');
const R = runner(o);
const RL = runner(o, { loose: true });
const utf = (s: string) => new TextEncoder().encode(s);
const hb = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));
const SMALL = '0100000000000000000000000000000000000000000000000000000000000000';

// ---- derived-secret registry (everything f_i(j), s_i, share wire bytes): cases that contain one go to the CI-generated corpus ----
const SECRETS = new Set<string>();
/** a wire message that carries a derived share (a share message, or a non-empty complaint / rebuttal list) is secret as a whole */
const wireSecret = (kind: string, bytes: Uint8Array) => {
  if (kind === 'share') SECRETS.add(b64(bytes));
  else if (kind === 'complaints' || kind === 'rebuttals') { try { const b = JSON.parse(new TextDecoder().decode(bytes)).body; if ((b?.complaints ?? b?.rebuttals ?? []).length > 0) SECRETS.add(b64(bytes)); } catch { SECRETS.add(b64(bytes)); } }
};
const sec = <T extends Uint8Array | string>(x: T): T => { const t = typeof x === 'string' ? x : b64(x); if (!/^(.)\1*$/.test(t)) SECRETS.add(t); return x; }; // a constant string (all-zero scalar) is no secret and would match unrelated cases
const watch = (out: any): any => {
  const walk = (v: any, key?: string) => {
    if (Array.isArray(v)) v.forEach((x) => walk(x, key));
    else if (v && typeof v === 'object') {
      if (typeof v.$bytes === 'string' && key && ['share', 'signingShare'].includes(key)) sec(v.$bytes);
      else for (const [k, x] of Object.entries(v)) walk(x, k);
    } else if (typeof v === 'string' && key && ['revealedShare', 'presentedShare', 'share'].includes(key)) sec(v);
  };
  walk(out);
  return out;
};

// ---- ceremony fixtures -------------------------------------------------------------------------------------------------
const specOf = (label: string, id: number, t: number, n: number) => ({ id, t, n, sessionId: S(label + '/sid'), coefficients: Array.from({ length: t }, (_, j) => S(`${label}/c/${id}/${j}`)), popNonce: S(`${label}/pop/${id}`) });
const rv = (x: any): any => (Array.isArray(x) ? x.map(rv) : x instanceof Uint8Array ? x : un(x));
const stateOf = (spec: any) => D.dkgRound1(spec.id, spec.t, spec.n, rv(spec.sessionId), { coefficients: rv(spec.coefficients), popNonce: rv(spec.popNonce) }).state;
const rngOf = (label: string, id: number, t: number) => [...Array.from({ length: t }, (_, j) => `${label}/c/${id}/${j}`), `${label}/pop/${id}`];
class Cer {
  specs: any[]; states: any[]; pkgs: any[]; sid: Uint8Array; ids: number[]; t: number;
  shares = new Map<string, any>(); // `${from}>${to}` -> {from,to,sessionId,share,sig}
  constructor(public label: string, t: number, ids: number[]) {
    this.t = t; this.ids = ids; const n = ids.length;
    this.specs = ids.map((id) => specOf(label, id, t, n));
    this.states = this.specs.map(stateOf);
    this.pkgs = this.states.map((s: any) => s.package);
    this.sid = un(this.specs[0].sessionId);
    for (const st of this.states) for (const s of D.dkgRound2(st, this.pkgs)) { sec(s.share); this.shares.set(`${s.from}>${s.to}`, s); }
  }
  spec = (id: number) => this.specs[this.ids.indexOf(id)];
  state = (id: number) => this.states[this.ids.indexOf(id)];
  pkg = (id: number) => this.pkgs[this.ids.indexOf(id)];
  share = (from: number, to: number) => this.shares.get(`${from}>${to}`);
  /** the share as a received-share corpus object */
  recv = (from: number, to: number, over: any = {}) => { const s = this.share(from, to); return { from, sessionId: s.sessionId, share: B(s.share), sig: s.sig, ...over }; };
  signed = (from: number, to: number, shareBytes: Uint8Array) => { const sig = D.dkgSignShare(this.state(from), to, shareBytes); sec(shareBytes); return sig as string; };
  /** a bad (VSS-failing) share signed by the cheater, as a corpus received-share */
  badShare = (from: number, to: number) => { const bad = Uint8Array.from(this.share(from, to).share); bad[0] ^= 1; return { from, sessionId: this.share(from, to).sessionId, share: B(sec(bad)), sig: this.signed(from, to, bad) }; };
  complaintFor = (accused: number, accuser: number, recvd = this.badShare(accused, accuser)) => J(jsonOut(D.dkgFileComplaint({ accused, accuser, receivedShare: un(recvd.share), shareSig: recvd.sig, senderCommitments: this.pkg(accused).coefficientCommitments, sessionId: this.sid })));
}
const C23 = new Cer('dkg23', 2, [1, 2, 3]);
const C35 = new Cer('dkg35', 3, [2, 5, 7, 11, 13]);
const C22 = new Cer('dkg22', 2, [1, 2]);
const OTHER = new Cer('dkgx', 2, [1, 2, 3]); // a second ceremony (another session, other polynomials)
const pk = (c: Cer, id: number) => J(c.pkg(id));
const pkgsJ = (c: Cer) => J(c.pkgs);
const SID = (c: Cer) => B(c.sid);
const ed1 = (b: Uint8Array) => b64(b);

// ============================ constants ============================
await R('constants', 'all', () => ({ DKG_WIRE_VERSION: C.DKG_WIRE_VERSION, DKG_MAX_MESSAGE_BYTES: C.DKG_MAX_MESSAGE_BYTES, DKG_MAX_PARTICIPANTS: C.DKG_MAX_PARTICIPANTS, DKG_MESSAGE_KINDS: [...C.DKG_MESSAGE_KINDS] }), []);

// ============================ dkgRound1 ============================
const r1 = (id: any, t: any, n: any, sid: any, opts: any) => { const r = D.dkgRound1(id, t, n, sid, opts); return { package: r.package }; };
const R1 = (name: string, id: any, t: any, n: any, sid: any, opts: any, rng?: string[]) => R('dkgRound1', name, r1, [id, t, n, sid, opts], rng);
const cf = (label: string, t: number, id = 1, over: any = {}) => ({ coefficients: Array.from({ length: t }, (_, j) => S(`${label}/c/${id}/${j}`)), popNonce: S(`${label}/pop/${id}`), ...over });
for (const [t, n] of [[1, 1], [1, 3], [2, 2], [2, 3], [3, 3], [3, 5], [4, 7], [5, 9]] as [number, number][]) for (const id of [...new Set([1, n])]) await R1(`t${t}n${n}-id${id}`, id, t, n, S(`r1/${t}-${n}/sid`), cf(`r1/${t}-${n}`, t, id));
await R1('sparse-id', 200, 2, 3, S('r1/sp/sid'), cf('r1/sp', 2, 200));
await R1('id-max-safe', 9007199254740991, 2, 3, S('r1/big/sid'), cf('r1/big', 2, 9007199254740991));
await R1('session-1-byte', 1, 2, 3, B(new Uint8Array([7])), cf('r1/s1', 2));
await R1('session-64-bytes', 1, 2, 3, B(new Uint8Array(64).fill(9)), cf('r1/s64', 2));
await R1('session-1000-bytes', 1, 2, 3, B(Uint8Array.from({ length: 1000 }, (_, i) => i & 255)), cf('r1/s1000', 2));
await R1('session-empty', 1, 2, 3, B(new Uint8Array()), cf('r1/se', 2));
await R1('session-null', 1, 2, 3, null, cf('r1/sn', 2));
await R1('session-string', 1, 2, 3, 'abc', cf('r1/sn', 2));
for (const [n, v] of [['zero', 0], ['negative', -1], ['fraction', 1.5], ['string', '1'], ['null', null]] as [string, any][]) await R1('id-' + n, v, 2, 3, S('r1/e/sid'), cf('r1/e', 2));
for (const [n, t, nn] of [['t-zero', 0, 3], ['n-below-t', 4, 3], ['t-fraction', 1.5, 3], ['n-fraction', 2, 3.5], ['t-string', '2', 3], ['t-negative', -1, 3]] as [string, any, any][]) await R1(n, 1, t, nn, S('r1/e/sid'), cf('r1/e', 2));
await R1('coefficients-too-few', 1, 3, 3, S('r1/e/sid'), cf('r1/e', 2));
await R1('coefficients-too-many', 1, 2, 3, S('r1/e/sid'), cf('r1/e', 3));
await R1('coefficient-a0-zero-identity-commitment', 1, 2, 3, S('r1/e/sid'), { coefficients: [B(new Uint8Array(32)), S('r1/e/c/1/1')], popNonce: S('r1/e/pop/1') });
await R1('coefficient-a1-zero-identity-commitment', 1, 2, 3, S('r1/e/sid'), { coefficients: [S('r1/e/c/1/0'), B(new Uint8Array(32))], popNonce: S('r1/e/pop/1') });
await R1('coefficient-a0-equals-L-is-zero', 1, 2, 3, S('r1/e/sid'), { coefficients: [(() => { let x = F.L; const w = new Uint8Array(32); for (let i = 0; i < 32; i++) { w[i] = Number(x & 0xffn); x >>= 8n; } return B(w); })(), S('r1/e/c/1/1')], popNonce: S('r1/e/pop/1') });
for (const len of [0, 1, 31, 33, 64]) await R1('coefficient-length-' + len, 1, 2, 3, S('r1/cl/sid'), { coefficients: [B(Uint8Array.from({ length: len }, (_, i) => sdb('r1/cl/a')[i % 32]!)), S('r1/cl/c1')], popNonce: S('r1/cl/pop') });
await R1('coefficient-length-65-refused', 1, 2, 3, S('r1/cl/sid'), { coefficients: [B(new Uint8Array(65).fill(5)), S('r1/cl/c1')], popNonce: S('r1/cl/pop') });
await R1('coefficient-not-bytes', 1, 2, 3, S('r1/cl/sid'), { coefficients: ['x', S('r1/cl/c1')], popNonce: S('r1/cl/pop') });
await R1('popNonce-zero-identity-R', 1, 2, 3, S('r1/pz/sid'), { coefficients: cf('r1/pz', 2).coefficients, popNonce: B(new Uint8Array(32)) });
await R1('popNonce-wide-64', 1, 2, 3, S('r1/pw/sid'), { coefficients: cf('r1/pw', 2).coefficients, popNonce: B(Uint8Array.from({ length: 64 }, (_, i) => (i * 11) & 255)) });
await R1('popNonce-short', 1, 2, 3, S('r1/pw/sid'), { coefficients: cf('r1/pw', 2).coefficients, popNonce: B(new Uint8Array(5).fill(3)) });
await R1('random-popNonce', 1, 2, 3, S('r1/rp/sid'), { coefficients: cf('r1/rp', 2).coefficients }, ['r1/rp/pop-draw']);
await R1('random-everything', 1, 2, 3, S('r1/re/sid'), {}, ['r1/re/c0', 'r1/re/c1', 'r1/re/pop']);
await R1('random-everything-t1', 4, 1, 4, S('r1/re1/sid'), {}, ['r1/re1/c0', 'r1/re1/pop']);
await R1('opts-empty-object', 1, 1, 1, S('r1/eo/sid'), {}, ['r1/eo/c0', 'r1/eo/pop']);
// the same inputs as a ceremony party: pins the ceremony fixtures' packages
for (const id of [1, 2, 3]) await R1('ceremony-dkg23-party' + id, id, 2, 3, S('dkg23/sid'), cf('dkg23', 2, id));

// ============================ dkgVerifyRound1 ============================
const vr1 = (id: any, pkg: any, sid: any) => D.dkgVerifyRound1(id, pkg, sid);
const VR = (name: string, id: any, pkg: any, sid: any) => R('dkgVerifyRound1', name, vr1, [id, pkg, sid]);
const ed_ = (p: any, f: (x: any) => void) => { const x = J(p); f(x); return x; };
const P1 = pk(C23, 1);
for (const id of [1, 2, 3]) await VR('ok-23-' + id, id, pk(C23, id), SID(C23));
for (const id of [2, 5, 7, 11, 13]) await VR('ok-35-' + id, id, pk(C35, id), SID(C35));
await VR('wrong-from', 2, P1, SID(C23));
await VR('from-zero', 0, P1, SID(C23));
await VR('wrong-session-bytes', 1, P1, B(sdb('dkg23/other-sid')));
await VR('session-empty', 1, P1, B(new Uint8Array()));
await VR('session-null', 1, P1, null);
await VR('pkg-session-field-other', 1, ed_(P1, (p) => { p.sessionId = b64(sdb('dkg23/other-sid')); }), SID(C23));
await VR('package-from-other-ceremony', 1, pk(OTHER, 1), SID(C23));
await VR('other-ceremony-ok-under-its-session', 1, pk(OTHER, 1), SID(OTHER));
await VR('mu-flipped', 1, ed_(P1, (p) => { p.proofOfKnowledge.mu = flipStr(p.proofOfKnowledge.mu, 0); }), SID(C23));
await VR('mu-plus-L-malleable', 1, ed_(P1, (p) => { let x = 0n; const u = fromB64(p.proofOfKnowledge.mu); for (let i = 31; i >= 0; i--) x = (x << 8n) | BigInt(u[i]!); x += F.L; const w = new Uint8Array(32); for (let i = 0; i < 32; i++) { w[i] = Number(x & 0xffn); x >>= 8n; } p.proofOfKnowledge.mu = b64(w); }), SID(C23));
await VR('mu-zero', 1, ed_(P1, (p) => { p.proofOfKnowledge.mu = b64(new Uint8Array(32)); }), SID(C23));
await VR('mu-short', 1, ed_(P1, (p) => { p.proofOfKnowledge.mu = p.proofOfKnowledge.mu.slice(0, 40); }), SID(C23));
await VR('mu-padded', 1, ed_(P1, (p) => { p.proofOfKnowledge.mu += '='; }), SID(C23));
await VR('R-flipped', 1, ed_(P1, (p) => { p.proofOfKnowledge.R = flipStr(p.proofOfKnowledge.R, 1); }), SID(C23));
await VR('R-small-order', 1, ed_(P1, (p) => { p.proofOfKnowledge.R = b64(hb(SMALL)); }), SID(C23));
await VR('R-of-other-party', 1, ed_(P1, (p) => { p.proofOfKnowledge.R = pk(C23, 2).proofOfKnowledge.R; }), SID(C23));
await VR('C0-flipped', 1, ed_(P1, (p) => { p.coefficientCommitments[0] = flipStr(p.coefficientCommitments[0], 1); }), SID(C23));
await VR('C0-small-order', 1, ed_(P1, (p) => { p.coefficientCommitments[0] = b64(hb(SMALL)); }), SID(C23));
await VR('C1-swapped-with-other-party', 1, ed_(P1, (p) => { p.coefficientCommitments[1] = pk(C23, 2).coefficientCommitments[1]; }), SID(C23));
await VR('commitment-appended', 1, ed_(P1, (p) => { p.coefficientCommitments.push(p.coefficientCommitments[1]); }), SID(C23));
await VR('commitment-dropped', 1, ed_(P1, (p) => { p.coefficientCommitments.pop(); }), SID(C23));
await VR('commitments-empty', 1, ed_(P1, (p) => { p.coefficientCommitments = []; }), SID(C23));
await VR('commitments-not-list', 1, ed_(P1, (p) => { p.coefficientCommitments = 'x'; }), SID(C23));
await VR('identifier-field-ignored-from-arg-used', 1, ed_(P1, (p) => { p.identifier = 9; }), SID(C23));
await VR('pkg-null', 1, null, SID(C23)); await VR('pkg-empty', 1, {}, SID(C23)); await VR('pkg-string', 1, 'x', SID(C23));
await VR('pop-missing', 1, ed_(P1, (p) => { delete p.proofOfKnowledge; }), SID(C23));

// ============================ dkgSignShare ============================
const ssh = (spec: any, to: any, share: any) => D.dkgSignShare(stateOf(spec), to, share);
const SS_ = (name: string, spec: any, to: any, share: any) => R('dkgSignShare', name, ssh, [spec, to, share]);
const SP1 = C23.spec(1);
for (const to of [2, 3, 200, 9007199254740991]) await SS_('to-' + to, SP1, to, S('sign/sh' + to));
await SS_('to-self', SP1, 1, S('sign/shself'));
await SS_('to-zero', SP1, 0, S('sign/sh0'));
await SS_('to-negative', SP1, -1, S('sign/shneg'));
await SS_('to-fraction', SP1, 1.5, S('sign/shfrac'));
for (const len of [0, 1, 31, 33, 64, 1000]) await SS_('share-length-' + len, SP1, 2, B(Uint8Array.from({ length: len }, (_, i) => sdb('sign/len')[i % 32]!)));
await SS_('share-null', SP1, 2, null);
await SS_('share-ge-L', SP1, 2, B((() => { const w = new Uint8Array(32).fill(255); return w; })()));
for (const id of [2, 3]) await SS_('other-signer-' + id, C23.spec(id), 1, S('sign/sh-o' + id));
await SS_('three-of-five-party-7', C35.spec(7), 2, S('sign/sh35'));
await SS_('same-share-different-recipient-differs', SP1, 3, S('sign/sh2'));
await SS_('same-share-same-recipient-deterministic', SP1, 2, S('sign/sh2'));

// ============================ dkgRound2 (derived shares) ============================
const rd2 = (spec: any, pkgs: any) => D.dkgRound2(stateOf(spec), pkgs).map((s: any) => ({ ...s }));
const RD2 = (name: string, spec: any, pkgs: any) => R('dkgRound2', name, rd2, [spec, pkgs], undefined, watch);
for (const id of [1, 2, 3]) await RD2('ok-23-party' + id, C23.spec(id), pkgsJ(C23));
for (const id of [2, 5, 7, 11, 13]) await RD2('ok-35-party' + id, C35.spec(id), pkgsJ(C35));
await RD2('ok-22', C22.spec(1), pkgsJ(C22));
await RD2('package-order-is-output-order', C23.spec(2), [...pkgsJ(C23)].reverse());
await RD2('duplicate-ids', C23.spec(1), [pk(C23, 1), pk(C23, 2), pk(C23, 2)]);
await RD2('own-package-missing', C23.spec(1), [pk(C23, 2), pk(C23, 3)]);
await RD2('session-mismatch-package', C23.spec(1), [pk(C23, 1), pk(OTHER, 2), pk(C23, 3)]);
await RD2('only-own-package', C23.spec(1), [pk(C23, 1)]);
await RD2('empty-packages', C23.spec(1), []);
await RD2('extra-participant-gets-a-share', C23.spec(1), [...pkgsJ(C23), ed_(pk(C23, 3), (p) => { p.identifier = 9; })]);
await RD2('participant-id-zero', C23.spec(1), [pk(C23, 1), ed_(pk(C23, 2), (p) => { p.identifier = 0; })]);
await RD2('package-not-validated-garbage-commitments-ok', C23.spec(1), [pk(C23, 1), ed_(pk(C23, 2), (p) => { p.coefficientCommitments = ['x']; p.proofOfKnowledge = {}; })]);

// ============================ dkgVerifyShare ============================
const vsh = (recv: any, pkg: any, me: any, sid: any) => D.dkgVerifyShare(recv, pkg, me, sid);
const VS = (name: string, recv: any, pkg: any, me: any, sid: any) => R('dkgVerifyShare', name, vsh, [recv, pkg, me, sid]);
for (const [from, to] of [[1, 2], [1, 3], [2, 1], [2, 3], [3, 1], [3, 2]] as [number, number][]) await VS(`ok-${from}-to-${to}`, C23.recv(from, to), pk(C23, from), to, SID(C23));
for (const [from, to] of [[2, 5], [13, 2], [7, 11]] as [number, number][]) await VS(`ok-35-${from}-to-${to}`, C35.recv(from, to), pk(C35, from), to, SID(C35));
await VS('ok-no-sessionId-member-needed', (({ sessionId, ...r }) => r)(C23.recv(1, 2)), pk(C23, 1), 2, SID(C23));
await VS('wrong-recipient-id', C23.recv(1, 2), pk(C23, 1), 3, SID(C23));
await VS('wrong-sender-id', C23.recv(1, 2, { from: 3 }), pk(C23, 1), 2, SID(C23));
await VS('sender-package-of-someone-else', C23.recv(1, 2), pk(C23, 3), 2, SID(C23));
await VS('wrong-session', C23.recv(1, 2), pk(C23, 1), 2, B(sdb('dkg23/other-sid')));
await VS('sender-package-other-ceremony', C23.recv(1, 2), pk(OTHER, 1), 2, SID(C23));
await VS('share-flipped-sig-stale', C23.recv(1, 2, { share: flipB(B(C23.share(1, 2).share), 0) }), pk(C23, 1), 2, SID(C23));
await VS('share-plus-L-malleable', C23.recv(1, 2, { share: (() => { let x = 0n; const u = C23.share(1, 2).share; for (let i = 31; i >= 0; i--) x = (x << 8n) | BigInt(u[i]!); x += F.L; const w = new Uint8Array(32); for (let i = 0; i < 32; i++) { w[i] = Number(x & 0xffn); x >>= 8n; } return B(sec(w)); })() }), pk(C23, 1), 2, SID(C23));
await VS('share-short', C23.recv(1, 2, { share: B(sec(C23.share(1, 2).share.slice(0, 31))) }), pk(C23, 1), 2, SID(C23));
await VS('share-not-bytes', C23.recv(1, 2, { share: 'x' }), pk(C23, 1), 2, SID(C23));
await VS('sig-missing', (({ sig, ...r }) => r)(C23.recv(1, 2)), pk(C23, 1), 2, SID(C23));
await VS('sig-flipped', C23.recv(1, 2, { sig: flipStr(C23.share(1, 2).sig, 40) }), pk(C23, 1), 2, SID(C23));
await VS('sig-of-other-recipient', C23.recv(1, 2, { sig: C23.share(1, 3).sig }), pk(C23, 1), 2, SID(C23));
await VS('sig-short', C23.recv(1, 2, { sig: C23.share(1, 2).sig.slice(0, 80) }), pk(C23, 1), 2, SID(C23));
await VS('sig-number', C23.recv(1, 2, { sig: 5 }), pk(C23, 1), 2, SID(C23));
{ const bad = C23.badShare(2, 3); await VS('bad-share-signed-by-sender-fails-vss', bad, pk(C23, 2), 3, SID(C23)); }
{ const other = Uint8Array.from(C23.share(1, 2).share); other[5] ^= 8; await VS('forged-share-resigned-by-wrong-party', { from: 1, share: B(sec(other)), sig: C23.signed(3, 2, other) }, pk(C23, 1), 2, SID(C23)); }
await VS('received-null', null, pk(C23, 1), 2, SID(C23));
await VS('sender-package-null', C23.recv(1, 2), null, 2, SID(C23));
await VS('my-id-zero', C23.recv(1, 2), pk(C23, 1), 0, SID(C23));

// ============================ dkgFileComplaint ============================
const fc = (p: any) => D.dkgFileComplaint(p);
const FC = (name: string, p: any) => R('dkgFileComplaint', name, fc, [p], undefined, watch);
const badSig = C23.badShare(2, 3);
const fcp = (over: any = {}) => ({ accused: 2, accuser: 3, receivedShare: badSig.share, shareSig: badSig.sig, senderCommitments: pk(C23, 2).coefficientCommitments, sessionId: SID(C23), ...over });
await FC('ok', fcp());
await FC('ok-arbitrary-share-bytes', fcp({ receivedShare: S('fc/arb'), shareSig: ed1(sdb('fc/sig')) + ed1(sdb('fc/sig2')) }));
await FC('share-reduced-mod-L', fcp({ receivedShare: B(new Uint8Array(32).fill(255)) }));
await FC('share-short', fcp({ receivedShare: B(new Uint8Array(5).fill(1)) }));
await FC('share-empty-is-zero', fcp({ receivedShare: B(new Uint8Array()) }));
await FC('share-65-refused', fcp({ receivedShare: B(new Uint8Array(65).fill(1)) }));
await FC('sender-commitments-unused', fcp({ senderCommitments: null }));
await FC('self-accusation', fcp({ accuser: 2 }));
for (const [n, v] of [['zero', 0], ['negative', -1], ['fraction', 1.5], ['string', '2'], ['null', null]] as [string, any][]) { await FC('accused-' + n, fcp({ accused: v })); await FC('accuser-' + n, fcp({ accuser: v })); }
await FC('shareSig-empty', fcp({ shareSig: '' })); await FC('shareSig-missing', fcp({ shareSig: undefined })); await FC('shareSig-number', fcp({ shareSig: 7 }));
await FC('shareSig-not-validated-at-filing', fcp({ shareSig: 'not a signature' }));
await FC('session-empty', fcp({ sessionId: B(new Uint8Array()) })); await FC('session-null', fcp({ sessionId: null }));

// ============================ dkgVerifyComplaint / dkgResolveBlame / dkgRebut ============================
const cBad = C23.complaintFor(2, 3); // justified: accused-signed share failing VSS
const cFalse = C23.complaintFor(2, 3, C23.recv(2, 3)); // a valid signed share: false accusation
const cUnsigned = (() => { const bad = Uint8Array.from(C23.share(2, 3).share); bad[0] ^= 1; sec(bad); return J(jsonOut(D.dkgFileComplaint({ accused: 2, accuser: 3, receivedShare: bad, shareSig: C23.share(2, 3).sig, senderCommitments: [], sessionId: C23.sid }))); })(); // sig is for the good share: inadmissible
const cFabricated = (() => { const fake = sdb('blame/fabricated'); return J(jsonOut(D.dkgFileComplaint({ accused: 2, accuser: 3, receivedShare: fake, shareSig: C23.share(2, 3).sig, senderCommitments: [], sessionId: C23.sid }))); })();
const cBySomeoneElse = (() => { const bad = Uint8Array.from(C23.share(2, 3).share); bad[1] ^= 1; sec(bad); return J(jsonOut(D.dkgFileComplaint({ accused: 2, accuser: 3, receivedShare: bad, shareSig: D.dkgSignShare(C23.state(1), 3, bad), senderCommitments: [], sessionId: C23.sid }))); })(); // signed by party 1, not the accused
const cWrongRecipient = (() => { const bad = Uint8Array.from(C23.share(2, 1).share); bad[0] ^= 1; sec(bad); return J(jsonOut(D.dkgFileComplaint({ accused: 2, accuser: 3, receivedShare: bad, shareSig: D.dkgSignShare(C23.state(2), 1, bad), senderCommitments: [], sessionId: C23.sid }))); })(); // signed for recipient 1 but filed by 3
const cNonCanonShare = (() => { let x = 0n; const u = C23.share(2, 3).share; for (let i = 31; i >= 0; i--) x = (x << 8n) | BigInt(u[i]!); x += F.L; const w = new Uint8Array(32); for (let i = 0; i < 32; i++) { w[i] = Number(x & 0xffn); x >>= 8n; } sec(w); return { ...cBad, revealedShare: b64(w), shareSig: D.dkgSignShare(C23.state(2), 3, w) }; })();
const PK23 = pkgsJ(C23);
const vc = (c: any, p: any) => D.dkgVerifyComplaint(c, p);
const VC = (name: string, c: any, p: any = PK23) => R('dkgVerifyComplaint', name, vc, [c, p], undefined, watch);
await VC('justified-bad-signed-share', cBad); await VC('false-accusation-valid-signed-share', cFalse); await VC('inadmissible-sig-for-other-share', cUnsigned);
await VC('inadmissible-fabricated-bytes', cFabricated); await VC('inadmissible-signed-by-someone-else', cBySomeoneElse); await VC('inadmissible-signed-for-other-recipient', cWrongRecipient);
await VC('non-canonical-share-plus-L', cNonCanonShare);
await VC('accused-has-no-package', cBad, PK23.filter((p: any) => p.identifier !== 2));
await VC('no-packages', cBad, []);
await VC('session-mismatch-complaint', { ...cBad, sessionId: b64(sdb('dkg23/other-sid')) });
await VC('session-mismatch-package', cBad, [PK23[0], pk(OTHER, 2), PK23[2]]);
await VC('complaint-null', null); await VC('complaint-share-missing', (({ revealedShare, ...c }) => c)(cBad));
await VC('complaint-sig-short', { ...cBad, shareSig: cBad.shareSig.slice(0, 60) });
await VC('packages-not-list', cBad, null);
await VC('accused-package-first-of-duplicates-used', cBad, [PK23[1], ed_(PK23[1], (p) => { p.coefficientCommitments[0] = flipStr(p.coefficientCommitments[0], 1); }), PK23[0]]);
await VC('accuser-3of5-justified', (() => { const bad = Uint8Array.from(C35.share(5, 11).share); bad[2] ^= 1; sec(bad); const s = D.dkgSignShare(C35.state(5), 11, bad); return J(jsonOut(D.dkgFileComplaint({ accused: 5, accuser: 11, receivedShare: bad, shareSig: s, senderCommitments: [], sessionId: C35.sid }))); })(), pkgsJ(C35));
const rb = (acc: any, c: any, spec: any) => D.dkgRebut(acc, c, stateOf(spec));
const RB = (name: string, acc: any, c: any, spec: any) => R('dkgRebut', name, rb, [acc, c, spec], undefined, watch);
await RB('ok-against-justified', 2, cBad, C23.spec(2)); await RB('ok-against-false', 2, cFalse, C23.spec(2)); await RB('ok-against-fabricated', 2, cFabricated, C23.spec(2));
await RB('state-not-the-accused', 2, cBad, C23.spec(1)); await RB('complaint-names-someone-else', 1, cBad, C23.spec(1));
await RB('session-mismatch', 2, { ...cBad, sessionId: b64(sdb('dkg23/other-sid')) }, C23.spec(2));
await RB('complaint-accuser-zero', 2, { ...cBad, accuser: 0 }, C23.spec(2)); await RB('complaint-accuser-fraction', 2, { ...cBad, accuser: 1.5 }, C23.spec(2));
await RB('accused-string', '2', cBad, C23.spec(2));
await RB('rebut-for-accuser-1', 2, { ...cBad, accuser: 1 }, C23.spec(2));
const REB = (c: any, spec: any) => J(jsonOut(D.dkgRebut(c.accused, c, stateOf(spec))));
const rebBad = REB(cBad, C23.spec(2)); watch(rebBad);
const rebBadPresented = (() => { const bad = Uint8Array.from(C23.share(2, 3).share); bad[0] ^= 1; sec(bad); return { ...rebBad, presentedShare: b64(bad), shareSig: D.dkgSignShare(C23.state(2), 3, bad) }; })(); // a cheater re-presents a signed BAD share
const rsb = (c: any, r: any, p: any) => D.dkgResolveBlame(c, r === null ? undefined : r, p);
const RS = (name: string, c: any, r: any, p: any = PK23) => R('dkgResolveBlame', name, rsb, [c, r, p], undefined, watch);
await RS('justified-no-rebuttal', cBad, null); await RS('justified-rebuttal-valid-does-not-save', cBad, rebBad);
await RS('false-accusation', cFalse, null); await RS('false-accusation-with-rebuttal', cFalse, REB(cFalse, C23.spec(2)));
await RS('fabricated-no-rebuttal-accuser-guilty', cFabricated, null);
await RS('fabricated-valid-rebuttal-refutes', cFabricated, REB(cFabricated, C23.spec(2)));
await RS('fabricated-rebuttal-presents-bad-share-accused-guilty', cFabricated, rebBadPresented);
await RS('fabricated-rebuttal-wrong-accuser', cFabricated, { ...REB(cFabricated, C23.spec(2)), accuser: 1 });
await RS('fabricated-rebuttal-wrong-accused', cFabricated, { ...REB(cFabricated, C23.spec(2)), accused: 3 });
await RS('fabricated-rebuttal-wrong-session', cFabricated, { ...REB(cFabricated, C23.spec(2)), sessionId: b64(sdb('dkg23/other-sid')) });
await RS('fabricated-rebuttal-sig-flipped', cFabricated, (() => { const r = REB(cFabricated, C23.spec(2)); r.shareSig = flipStr(r.shareSig, 40); return r; })());
await RS('fabricated-rebuttal-share-flipped', cFabricated, (() => { const r = REB(cFabricated, C23.spec(2)); r.presentedShare = flipStr(r.presentedShare, 0); sec(r.presentedShare); return r; })());
await RS('signed-by-someone-else-no-rebuttal', cBySomeoneElse, null);
await RS('wrong-recipient-no-rebuttal', cWrongRecipient, null);
await RS('accused-no-package-guilty', cBad, null, PK23.filter((p: any) => p.identifier !== 2));
await RS('session-mismatch-accuser-guilty', { ...cBad, sessionId: b64(sdb('dkg23/other-sid')) }, null);
await RS('malformed-complaint-accuser-guilty', { ...cBad, shareSig: 5 }, null);
await RS('packages-null', cBad, null, null);
await RS('non-canonical-share-plus-L', cNonCanonShare, null);

// ============================ dkgQualifiedSet ============================
const qs = (ps: any, cs: any, pk_: any, rb_?: any) => D.dkgQualifiedSet(ps, cs, pk_, rb_ === undefined ? undefined : rb_);
const QS = (name: string, ps: any, cs: any, pk_: any, rb_?: any) => R('dkgQualifiedSet', name, qs, rb_ === undefined ? [ps, cs, pk_] : [ps, cs, pk_, rb_], undefined, watch);
await QS('honest-all', [1, 2, 3], [], PK23);
await QS('honest-all-unsorted-input', [3, 1, 2], [], PK23);
await QS('honest-subset-of-participants', [1, 3], [], PK23);
await QS('unknown-participant-dropped', [1, 2, 3, 4], [], PK23);
await QS('justified-complaint-drops-accused', [1, 2, 3], [cBad], PK23);
await QS('justified-complaint-with-rebuttal-still-drops', [1, 2, 3], [cBad], PK23, [rebBad]);
await QS('false-accusation-drops-nobody', [1, 2, 3], [cFalse], PK23);
await QS('fabricated-no-rebuttal-drops-nobody', [1, 2, 3], [cFabricated], PK23);
await QS('fabricated-bad-rebuttal-drops-accused', [1, 2, 3], [cFabricated], PK23, [rebBadPresented]);
await QS('fabricated-valid-rebuttal-drops-nobody', [1, 2, 3], [cFabricated], PK23, [REB(cFabricated, C23.spec(2))]);
await QS('rebuttal-for-other-pair-ignored', [1, 2, 3], [cFabricated], PK23, [{ ...rebBadPresented, accuser: 1 }]);
await QS('two-complaints-different-accused', [1, 2, 3], [cBad, C23.complaintFor(1, 3)], PK23);
await QS('two-complaints-same-accused-counted-once', [1, 2, 3], [cBad, cBad], PK23);
await QS('bad-pop-package-not-qualified', [1, 2, 3], [], [PK23[0], ed_(PK23[1], (p) => { p.proofOfKnowledge.mu = flipStr(p.proofOfKnowledge.mu, 0); }), PK23[2]]);
await QS('missing-package-not-qualified', [1, 2, 3], [], [PK23[0], PK23[2]]);
await QS('divergent-session-package-not-qualified', [1, 2, 3], [], [PK23[0], pk(OTHER, 2), PK23[2]]);
await QS('session-plurality-two-vs-one', [1, 2, 3], [], [pk(OTHER, 1), pk(OTHER, 2), PK23[2]]);
await QS('session-tie-first-seen-wins', [1, 2], [], [PK23[0], pk(OTHER, 2)]);
await QS('no-packages', [1, 2, 3], [], []);
await QS('no-participants', [], [], PK23);
await QS('rebuttals-empty-list', [1, 2, 3], [cBad], PK23, []);
await QS('complaint-malformed-ignored', [1, 2, 3], [{ nonsense: true }], PK23);
await QS('3of5-cheater-removed', [2, 5, 7, 11, 13], [(() => { const bad = Uint8Array.from(C35.share(5, 11).share); bad[2] ^= 1; sec(bad); return J(jsonOut(D.dkgFileComplaint({ accused: 5, accuser: 11, receivedShare: bad, shareSig: D.dkgSignShare(C35.state(5), 11, bad), senderCommitments: [], sessionId: C35.sid }))); })()], pkgsJ(C35));

// ============================ echo agreement ============================
const QL = [1, 2, 3];
const tdArgs = (c: Cer, complaints: any[] = [], qualified = c.ids, sid = SID(c)) => ({ round1Packages: pkgsJ(c), complaints, qualified, sessionId: sid });
const td = (a: any) => D.dkgTranscriptDigest(a);
const TD = (name: string, a: any) => R('dkgTranscriptDigest', name, td, [a], undefined, watch);
await TD('honest', tdArgs(C23)); await TD('with-complaint', tdArgs(C23, [cBad], [1, 3]));
await TD('package-order-independent', { ...tdArgs(C23), round1Packages: [...pkgsJ(C23)].reverse() });
await TD('qualified-order-independent', tdArgs(C23, [], [3, 1, 2]));
await TD('complaint-order-independent', tdArgs(C23, [cBad, C23.complaintFor(1, 3)], [3]));
await TD('complaint-order-independent-b', tdArgs(C23, [C23.complaintFor(1, 3), cBad], [3]));
await TD('different-qualified', tdArgs(C23, [], [1, 2])); await TD('different-session', tdArgs(C23, [], QL, B(sdb('dkg23/other-sid'))));
await TD('one-package-tampered', { ...tdArgs(C23), round1Packages: [PK23[0], ed_(PK23[1], (p) => { p.proofOfKnowledge.mu = flipStr(p.proofOfKnowledge.mu, 0); }), PK23[2]] });
await TD('duplicate-package-counted-twice', { ...tdArgs(C23), round1Packages: [...PK23, PK23[0]] });
await TD('no-packages-no-complaints', { round1Packages: [], complaints: [], qualified: [], sessionId: SID(C23) });
await TD('3of5', tdArgs(C35)); await TD('invalid-package-member-types-still-hash', { ...tdArgs(C23), round1Packages: [{ identifier: 1, sessionId: 's', coefficientCommitments: [], proofOfKnowledge: { R: 'a', mu: 'b' } }] });
const ec = (a: any) => D.dkgEcho(a);
const EC = (name: string, a: any) => R('dkgEcho', name, ec, [a], undefined, watch);
for (const id of [1, 2, 3]) await EC('party' + id, { identifier: id, ...tdArgs(C23) });
await EC('with-complaint', { identifier: 1, ...tdArgs(C23, [cBad], [1, 3]) }); await EC('identifier-not-validated', { identifier: 'x', ...tdArgs(C23) });
const ECH = (c: Cer, view: number[] = c.ids) => c.ids.map((id) => J(D.dkgEcho({ identifier: id, round1Packages: c.pkgs, complaints: [], qualified: view, sessionId: c.sid })));
const E23 = ECH(C23);
const ce = (q: any, e: any, sid: any) => D.dkgCheckEchoes(q, e, sid);
const CE = (name: string, q: any, e: any, sid: any = SID(C23)) => R('dkgCheckEchoes', name, ce, [q, e, sid]);
await CE('agreed', QL, E23); await CE('agreed-order-independent', QL, [E23[2], E23[0], E23[1]]);
await CE('agreed-non-qualified-echo-ignored', [1, 2], E23); await CE('agreed-non-qualified-echo-wrong-session-ignored', [1, 2], [E23[0], E23[1], { ...E23[2], sessionId: 'zzzz' }]);
await CE('single-qualified', [1], [E23[0]]);
await CE('missing-echo', QL, [E23[0], E23[1]]); await CE('no-echoes', QL, []);
await CE('duplicate-echo', QL, [E23[0], E23[0], E23[1], E23[2]]); await CE('duplicate-identical-echo-still-duplicate', QL, [E23[0], { ...E23[0] }, E23[1], E23[2]]);
await CE('divergent-digest', QL, [E23[0], E23[1], { ...E23[2], transcriptDigest: ECH(C23, [1, 2])[0].transcriptDigest }]);
await CE('divergent-first-party', QL, [{ ...E23[0], transcriptDigest: ECH(C23, [1, 2])[0].transcriptDigest }, E23[1], E23[2]]);
await CE('wrong-session-echo', QL, [E23[0], E23[1], { ...E23[2], sessionId: b64(sdb('dkg23/other-sid')) }]);
await CE('wrong-session-argument', QL, E23, B(sdb('dkg23/other-sid')));
await CE('no-qualified', [], E23); await CE('qualified-duplicates-collapse', [1, 1, 2, 3], E23);
await CE('echoes-null', QL, null); await CE('echo-entry-null', QL, [null, ...E23]); await CE('sessionId-null', QL, E23, null);
await CE('digest-not-validated-equal-garbage-agrees', [1, 2], [{ identifier: 1, sessionId: b64(C23.sid), transcriptDigest: 'junk' }, { identifier: 2, sessionId: b64(C23.sid), transcriptDigest: 'junk' }]);

// ============================ dkgFinalize ============================
const recvAll = (c: Cer, to: number, from: number[] = c.ids.filter((i) => i !== to), over: (r: any) => any = (r) => r) => from.map((f) => over(c.recv(f, to)));
const fin = (me: any, spec: any, recvd: any, pkgs: any, q: any, ag: any) => D.dkgFinalize(me, stateOf(spec), recvd, pkgs, q === null ? undefined : q, ag === null ? undefined : ag);
const FN = (name: string, me: any, spec: any, recvd: any, pkgs: any, q: any = null, ag: any = null) => R('dkgFinalize', name, fin, [me, spec, recvd, pkgs, q, ag], undefined, watch);
for (const id of [1, 2, 3]) await FN('ok-23-party' + id, id, C23.spec(id), recvAll(C23, id), PK23);
for (const id of [2, 5, 7, 11, 13]) await FN('ok-35-party' + id, id, C35.spec(id), recvAll(C35, id), pkgsJ(C35));
await FN('ok-22', 1, C22.spec(1), recvAll(C22, 1), pkgsJ(C22));
await FN('ok-qualified-explicit-all', 1, C23.spec(1), recvAll(C23, 1), PK23, [1, 2, 3]);
await FN('ok-qualified-subset-t', 1, C23.spec(1), recvAll(C23, 1, [3]), PK23, [1, 3]);
await FN('ok-qualified-ignores-unknown-ids', 1, C23.spec(1), recvAll(C23, 1), PK23, [1, 2, 3, 9]);
await FN('ok-extra-share-from-disqualified-ignored', 1, C23.spec(1), recvAll(C23, 1), PK23, [1, 3]);
await FN('ok-own-share-entry-ignored', 1, C23.spec(1), [...recvAll(C23, 1), { from: 1, sessionId: b64(C23.sid), share: B(new Uint8Array(32)), sig: 'x' }], PK23);
await FN('ok-shares-need-no-signature-at-finalize', 1, C23.spec(1), recvAll(C23, 1, undefined, (r) => { delete r.sig; return r; }), PK23);
await FN('ok-3of5-qualified-4', 2, C35.spec(2), recvAll(C35, 2, [5, 7, 11]), pkgsJ(C35), [2, 5, 7, 11]);
await FN('ok-3of5-qualified-exactly-t', 2, C35.spec(2), recvAll(C35, 2, [5, 7]), pkgsJ(C35), [2, 5, 7]);
await FN('qualified-below-t', 1, C23.spec(1), [], PK23, [1]);
await FN('myself-not-qualified', 1, C23.spec(1), recvAll(C23, 1), PK23, [2, 3]);
await FN('identifier-mismatch-with-state', 2, C23.spec(1), recvAll(C23, 1), PK23);
await FN('duplicate-packages', 1, C23.spec(1), recvAll(C23, 1), [...PK23, PK23[2]]);
await FN('own-package-missing', 1, C23.spec(1), recvAll(C23, 1), [PK23[1], PK23[2]]);
await FN('package-other-session', 1, C23.spec(1), recvAll(C23, 1), [PK23[0], pk(OTHER, 2), PK23[2]]);
await FN('package-wrong-commitment-count', 1, C23.spec(1), recvAll(C23, 1), [PK23[0], PK23[1], ed_(PK23[2], (p) => { p.coefficientCommitments.pop(); })]);
await FN('disqualified-package-may-be-malformed', 1, C23.spec(1), recvAll(C23, 1, [3]), [PK23[0], ed_(PK23[1], (p) => { p.coefficientCommitments = []; }), PK23[2]], [1, 3]);
await FN('share-missing-from-qualified', 1, C23.spec(1), recvAll(C23, 1, [2]), PK23);
await FN('share-duplicate-from-same-sender', 1, C23.spec(1), [...recvAll(C23, 1), C23.recv(2, 1)], PK23);
await FN('share-other-session', 1, C23.spec(1), recvAll(C23, 1, [3]).concat([C23.recv(2, 1, { sessionId: b64(sdb('dkg23/other-sid')) })]), PK23);
await FN('share-wrong-value-inconsistent-with-group-commitments', 1, C23.spec(1), recvAll(C23, 1, undefined, (r) => (r.from === 2 ? { ...r, share: flipB(r.share, 0) } : r)), PK23);
await FN('share-not-reduced-accepted-if-congruent', 1, C23.spec(1), recvAll(C23, 1, undefined, (r) => (r.from === 2 ? { ...r, share: (() => { let x = 0n; const u = fromB64(r.share.$bytes); for (let i = 31; i >= 0; i--) x = (x << 8n) | BigInt(u[i]!); x += F.L; const w = new Uint8Array(32); for (let i = 0; i < 32; i++) { w[i] = Number(x & 0xffn); x >>= 8n; } return B(sec(w)); })() } : r)), PK23);
await FN('share-short', 1, C23.spec(1), recvAll(C23, 1, undefined, (r) => (r.from === 2 ? { ...r, share: B(sec(fromB64(r.share.$bytes).slice(0, 31))) } : r)), PK23);
// echo agreement path
const echoesOf = (c: Cer, complaints: any[] = [], view?: number[], q = c.ids) => q.map((id) => J(D.dkgEcho({ identifier: id, round1Packages: c.pkgs, complaints, qualified: view ?? q, sessionId: c.sid })));
await FN('agreement-ok', 1, C23.spec(1), recvAll(C23, 1), PK23, null, { echoes: echoesOf(C23) });
await FN('agreement-ok-with-complaints', 1, C23.spec(1), recvAll(C23, 1, [3]), PK23, [1, 3], { echoes: echoesOf(C23, [cBad], undefined, [1, 3]), complaints: [cBad] });
await FN('agreement-complaints-missing-from-my-view', 1, C23.spec(1), recvAll(C23, 1, [3]), PK23, [1, 3], { echoes: echoesOf(C23, [cBad], undefined, [1, 3]) });
await FN('agreement-divergent-peer', 1, C23.spec(1), recvAll(C23, 1), PK23, null, { echoes: [echoesOf(C23)[0], echoesOf(C23)[1], echoesOf(C23, [], [1, 2])[2]] });
await FN('agreement-all-agree-on-other-view-than-mine', 1, C23.spec(1), recvAll(C23, 1), PK23, null, { echoes: echoesOf(C23, [], [1, 2, 3]).map((e: any) => ({ ...e, transcriptDigest: echoesOf(C23, [], [1, 2])[0].transcriptDigest })) });
await FN('agreement-missing-echo', 1, C23.spec(1), recvAll(C23, 1), PK23, null, { echoes: echoesOf(C23).slice(0, 2) });
await FN('agreement-empty-echoes-means-missing', 1, C23.spec(1), recvAll(C23, 1), PK23, null, { echoes: [] });
await FN('agreement-object-without-echoes-skips-check', 1, C23.spec(1), recvAll(C23, 1), PK23, null, {});

// ============================ frostDkgSimulate ============================
const sim = (t: any, n: any, opts: any) => {
  const r = D.frostDkgSimulate(t, n, opts);
  return {
    groupPublicKey: r.groupPublicKey, participantShares: r.participantShares, groupCommitment: r.groupCommitment, keyPackages: r.keyPackages, round1Packages: r.round1Packages,
    qualified: r.qualified, complaints: r.complaints, rebuttals: r.rebuttals, echoes: r.echoes, sessionId: r.sessionId,
  };
};
const simOpts = (label: string, t: number, ids: number[], over: any = {}) => ({ sessionId: S(label + '/sid'), coefficientsByParticipant: ids.map((id) => Array.from({ length: t }, (_, j) => S(`${label}/c/${id}/${j}`))), ...over });
const SIM = (name: string, t: any, n: any, opts: any, rng?: string[]) => R('frostDkgSimulate', name, sim, [t, n, opts], rng, watch);
const popRng = (label: string, ids: number[]) => ids.map((id) => `${label}/pop/${id}`);
for (const [nm, t, n] of [['1of1', 1, 1], ['1of3', 1, 3], ['2of2', 2, 2], ['2of3', 2, 3], ['3of3', 3, 3], ['3of5', 3, 5], ['4of7', 4, 7]] as [string, number, number][]) { const ids = Array.from({ length: n }, (_, i) => i + 1); await SIM('honest-' + nm, t, n, simOpts('sim/' + nm, t, ids), popRng('sim/' + nm, ids)); }
{ const ids = [5, 9, 200]; await SIM('sparse-identifiers', 2, 3, { ...simOpts('sim/sp', 2, ids), identifiers: ids }, popRng('sim/sp', ids)); }
{ const ids = [3, 1, 2]; await SIM('reordered-identifiers', 2, 3, { ...simOpts('sim/ro', 2, ids), identifiers: ids }, popRng('sim/ro', ids)); }
{ const ids = [1, 2, 3, 4]; await SIM('cheater-2-of-4', 2, 4, simOpts('sim/c1', 2, ids, { cheaters: [2] }), popRng('sim/c1', ids)); }
{ const ids = [1, 2, 3, 4, 5]; await SIM('two-cheaters-3-of-5', 3, 5, simOpts('sim/c2', 3, ids, { cheaters: [1, 4] }), popRng('sim/c2', ids)); }
{ const ids = [1, 2, 3]; await SIM('cheater-of-3-t2', 2, 3, simOpts('sim/c3', 2, ids, { cheaters: [3] }), popRng('sim/c3', ids)); }
{ const ids = [1, 2, 3]; await SIM('too-many-cheaters', 2, 3, simOpts('sim/c4', 2, ids, { cheaters: [1, 2] }), popRng('sim/c4', ids)); }
{ const ids = [1, 2, 3]; await SIM('cheater-not-a-participant-ignored', 2, 3, simOpts('sim/c5', 2, ids, { cheaters: [9] }), popRng('sim/c5', ids)); }
{ const ids = [1, 2, 3]; await SIM('equivocating-echo-aborts', 2, 3, simOpts('sim/eq', 2, ids, { equivocateEchoFor: 2 }), popRng('sim/eq', ids)); }
{ const ids = [1, 2, 3]; await SIM('equivocating-echo-for-unknown-ignored', 2, 3, simOpts('sim/eq2', 2, ids, { equivocateEchoFor: 9 }), popRng('sim/eq2', ids)); }
{ const ids = [1, 2, 3, 4]; await SIM('equivocating-echo-with-cheater', 2, 4, simOpts('sim/eq3', 2, ids, { cheaters: [4], equivocateEchoFor: 1 }), popRng('sim/eq3', ids)); }
{ const ids = [1, 2, 3]; await SIM('random-session-id', 2, 3, { coefficientsByParticipant: simOpts('sim/rs', 2, ids).coefficientsByParticipant }, ['sim/rs/sid', ...popRng('sim/rs', ids)]); }
{ const ids = [1, 2, 3]; await SIM('random-everything', 2, 3, {}, ['sim/re/sid', ...ids.flatMap((id) => [`sim/re/c/${id}/0`, `sim/re/c/${id}/1`, `sim/re/pop/${id}`])]); }
{ const ids = [1, 2, 3]; await SIM('opts-undefined-equivalent-null-not-allowed-use-empty', 2, 3, { sessionId: S('sim/oe/sid'), coefficientsByParticipant: simOpts('sim/oe', 2, ids).coefficientsByParticipant }, popRng('sim/oe', ids)); }
for (const [nm, t, n, over] of [['t-zero', 0, 3], ['n-below-t', 4, 3], ['t-fraction', 1.5, 3], ['n-fraction', 2, 2.5], ['ids-length', 2, 3, { identifiers: [1, 2] }], ['ids-duplicate', 2, 3, { identifiers: [1, 1, 2] }], ['ids-zero', 2, 3, { identifiers: [0, 1, 2] }], ['ids-negative', 2, 3, { identifiers: [-1, 1, 2] }], ['ids-fraction', 2, 3, { identifiers: [1.5, 2, 3] }]] as [string, any, any, any?][]) await SIM('invalid-' + nm, t, n, over ?? {});
await SIM('coefficients-wrong-length-participant', 2, 3, { sessionId: S('sim/cw/sid'), coefficientsByParticipant: [[S('sim/cw/a'), S('sim/cw/b')], [S('sim/cw/c')], [S('sim/cw/d'), S('sim/cw/e')]] }, ['sim/cw/pop/1']);
await SIM('coefficients-fewer-participants-than-n-random-rest', 2, 3, { sessionId: S('sim/cf/sid'), coefficientsByParticipant: simOpts('sim/cf', 2, [1]).coefficientsByParticipant }, ['sim/cf/pop/1', 'sim/cf/c/2/0', 'sim/cf/c/2/1', 'sim/cf/pop/2', 'sim/cf/c/3/0', 'sim/cf/c/3/1', 'sim/cf/pop/3']);

// ============================ wire codec ============================
const SC = (label: string) => sdb(label);
const enc = (sid: any, kind: any, body: any) => C.encodeDkgMessage(sid, kind, body);
const EN = (name: string, sid: any, kind: any, body: any) => R('encodeDkgMessage', name, enc, [sid, kind, body], undefined, watch);
const P1b = pk(C23, 1);
await EN('round1', SID(C23), 'round1', P1b);
await EN('complaints-empty', SID(C23), 'complaints', { complaints: [] }); await EN('rebuttals-empty', SID(C23), 'rebuttals', { rebuttals: [] });
await EN('complaints-one', SID(C23), 'complaints', { complaints: [cBad] }); await EN('rebuttals-one', SID(C23), 'rebuttals', { rebuttals: [rebBad] });
await EN('echo', SID(C23), 'echo', E23[0]);
await EN('share', SID(C23), 'share', { from: 1, to: 2, sessionId: b64(C23.sid), share: b64(C23.share(1, 2).share), sig: C23.share(1, 2).sig });
await EN('share-arbitrary-bytes', SID(C23), 'share', { from: 1, to: 2, sessionId: b64(C23.sid), share: b64(sdb('codec/share')), sig: b64(sdb('codec/sig')) + b64(sdb('codec/sig2')) });
await EN('body-key-order-preserved', SID(C23), 'echo', { transcriptDigest: 'd', identifier: 1, sessionId: 's' });
await EN('body-null', SID(C23), 'echo', null); await EN('body-number', SID(C23), 'echo', 5); await EN('body-string-unicode', SID(C23), 'echo', 'héllo \u{1F600} "q" \\ \n');
await EN('body-nested', SID(C23), 'echo', { a: [1, 2, { b: null, c: true }], d: '' });
await EN('body-integers-big-safe', SID(C23), 'echo', { a: 9007199254740991, b: -9007199254740991, c: 0 });
await EN('kind-unchecked-on-encode', SID(C23), 'anything', {}); await EN('kind-number', SID(C23), 5, {});
await EN('session-short', B(new Uint8Array([1])), 'echo', {}); await EN('session-empty', B(new Uint8Array()), 'echo', {});
await EN('session-long', B(new Uint8Array(200).fill(7)), 'echo', {});
await EN('oversize', SID(C23), 'echo', 'x'.repeat(C.DKG_MAX_MESSAGE_BYTES));
await EN('just-under-cap', SID(C23), 'echo', 'x'.repeat(C.DKG_MAX_MESSAGE_BYTES - 60));
const dec = (bytes: any, sid: any) => C.decodeDkgMessage(bytes, sid);
const DM = (name: string, bytes: any, sid: any = SID(C23)) => R('decodeDkgMessage', name, dec, [bytes, sid], undefined, watch);
const env = (o_: any, text?: string) => B(utf(text ?? JSON.stringify(o_)));
const ENV = (over: any = {}) => ({ v: 1, sid: b64(C23.sid), kind: 'echo', body: { x: 1 }, ...over });
await DM('ok-echo', B(C.encodeDkgMessage(C23.sid, 'echo', E23[0]))); await DM('ok-round1', B(C.encodeDkgMessage(C23.sid, 'round1', P1b)));
await DM('ok-body-null', env(ENV({ body: null }))); await DM('ok-body-scalar', env(ENV({ body: 5 })));
for (const k of ['round1', 'share', 'complaints', 'rebuttals', 'echo']) await DM('ok-kind-' + k, env(ENV({ kind: k })));
await DM('kind-unknown', env(ENV({ kind: 'dkg' }))); await DM('kind-number', env(ENV({ kind: 5 }))); await DM('kind-case', env(ENV({ kind: 'Echo' })));
await DM('version-2', env(ENV({ v: 2 }))); await DM('version-string', env(ENV({ v: '1' }))); await DM('version-float', env(ENV({ v: 1.0 }), '{"v":1.0,"sid":"' + b64(C23.sid) + '","kind":"echo","body":{}}'));
await DM('wrong-session', env(ENV({ sid: b64(sdb('dkg23/other-sid')) }))); await DM('session-non-canonical', env(ENV({ sid: b64(C23.sid) + '=' })));
await DM('missing-member-body', env({ v: 1, sid: b64(C23.sid), kind: 'echo' })); await DM('missing-member-v', env({ sid: b64(C23.sid), kind: 'echo', body: {} }));
await DM('extra-member', env(ENV({ extra: 1 }))); await DM('member-order-any', env({ body: { x: 1 }, kind: 'echo', sid: b64(C23.sid), v: 1 }));
await DM('not-an-object-array', env([1, 2])); await DM('not-an-object-null', env(null)); await DM('not-an-object-string', env('x')); await DM('not-an-object-number', env(5));
for (const [n, t] of [['empty', ''], ['truncated', '{"v":1,"sid":"'], ['garbage', 'xyz'], ['trailing-garbage', JSON.stringify(ENV()) + 'x'], ['trailing-whitespace', JSON.stringify(ENV()) + ' '], ['leading-whitespace', ' ' + JSON.stringify(ENV())],
  ['bom', '﻿' + JSON.stringify(ENV())], ['duplicate-key', '{"v":1,"v":1,"sid":"' + b64(C23.sid) + '","kind":"echo","body":{}}'], ['duplicate-key-in-body', '{"v":1,"sid":"' + b64(C23.sid) + '","kind":"echo","body":{"a":1,"a":2}}'],
  ['nan', '{"v":1,"sid":"' + b64(C23.sid) + '","kind":"echo","body":NaN}'], ['comment', '{"v":1,/*x*/"sid":"' + b64(C23.sid) + '","kind":"echo","body":{}}'], ['single-quotes', "{'v':1}"], ['trailing-comma', '{"v":1,"sid":"' + b64(C23.sid) + '","kind":"echo","body":{},}'],
  ['exponent-number', '{"v":1,"sid":"' + b64(C23.sid) + '","kind":"echo","body":1e2}'], ['leading-zero', '{"v":1,"sid":"' + b64(C23.sid) + '","kind":"echo","body":01}'], ['negative-zero', '{"v":1,"sid":"' + b64(C23.sid) + '","kind":"echo","body":-0}'],
  ['unsafe-integer', '{"v":1,"sid":"' + b64(C23.sid) + '","kind":"echo","body":9007199254740993}'], ['trailing-zero-fraction', '{"v":1,"sid":"' + b64(C23.sid) + '","kind":"echo","body":1.50}'],
  ['lone-surrogate-escape', '{"v":1,"sid":"' + b64(C23.sid) + '","kind":"echo","body":"\\ud800"}'], ['raw-control-char', '{"v":1,"sid":"' + b64(C23.sid) + '","kind":"echo","body":"a\u0001b"}'], ['unknown-escape', '{"v":1,"sid":"' + b64(C23.sid) + '","kind":"echo","body":"\\q"}'],
  ['proto-key-ok', '{"v":1,"sid":"' + b64(C23.sid) + '","kind":"echo","body":{"__proto__":1}}']] as [string, string][]) await DM('strict-' + n, env(null, t));
await DM('deep-nesting-33', env(null, '{"v":1,"sid":"' + b64(C23.sid) + '","kind":"echo","body":' + '['.repeat(33) + ']'.repeat(33) + '}'));
await DM('deep-nesting-ok', env(null, '{"v":1,"sid":"' + b64(C23.sid) + '","kind":"echo","body":' + '['.repeat(25) + ']'.repeat(25) + '}'));
await DM('invalid-utf8', B(Uint8Array.from([0x7b, 0xff, 0xfe, 0x7d]))); await DM('empty-bytes', B(new Uint8Array()));
await DM('bytes-null', null); await DM('bytes-string', '{"v":1}');
await DM('session-null', env(ENV()), null);
{ const pad = (n: number) => { const t = JSON.stringify(ENV({ body: { p: 'x'.repeat(n) } })); return t; };
  const base = pad(0).length; const exact = pad(C.DKG_MAX_MESSAGE_BYTES - base);
  await DM('exactly-cap-ok', env(null, exact)); await DM('one-over-cap-oversize', env(null, pad(C.DKG_MAX_MESSAGE_BYTES - base + 1))); }
await DM('oversize-zeros', B(new Uint8Array(C.DKG_MAX_MESSAGE_BYTES + 1)));
// body decoders
const R1B = P1b;
const d1 = (b: any, t: any) => C.decodeDkgRound1Package(b, t);
const DR1 = (name: string, b: any, t: any = 2) => R('decodeDkgRound1Package', name, d1, [b, t]);
await DR1('ok', R1B); await DR1('ok-t3', pk(C35, 2), 3); await DR1('wrong-t', R1B, 3); await DR1('t-string', R1B, '2'); await DR1('t-zero-no-commitments', ed_(R1B, (p) => { p.coefficientCommitments = []; }), 0);
for (const [n, v] of [['null', null], ['array', []], ['string', 'x'], ['number', 3]] as [string, any][]) await DR1('body-' + n, v);
for (const k of ['identifier', 'sessionId', 'coefficientCommitments', 'proofOfKnowledge']) await DR1('missing-' + k, ed_(R1B, (p) => { delete p[k]; }));
await DR1('extra-member', ed_(R1B, (p) => { p.extra = 1; })); await DR1('pok-extra', ed_(R1B, (p) => { p.proofOfKnowledge.x = 1; })); await DR1('pok-missing-mu', ed_(R1B, (p) => { delete p.proofOfKnowledge.mu; })); await DR1('pok-array', ed_(R1B, (p) => { p.proofOfKnowledge = []; }));
for (const [n, v] of [['zero', 0], ['negative', -1], ['fraction', 1.5], ['string', '1'], ['unsafe', 9007199254740992], ['null', null]] as [string, any][]) await DR1('identifier-' + n, ed_(R1B, (p) => { p.identifier = v; }));
await DR1('sessionId-noncanonical', ed_(R1B, (p) => { p.sessionId += '='; })); await DR1('sessionId-number', ed_(R1B, (p) => { p.sessionId = 5; })); await DR1('sessionId-any-length-ok', ed_(R1B, (p) => { p.sessionId = b64(new Uint8Array(3)); }));
await DR1('commitment-short', ed_(R1B, (p) => { p.coefficientCommitments[0] = p.coefficientCommitments[0].slice(0, 40); })); await DR1('commitment-padded', ed_(R1B, (p) => { p.coefficientCommitments[1] += '='; }));
await DR1('commitment-not-validated-as-point', ed_(R1B, (p) => { p.coefficientCommitments[1] = b64(new Uint8Array(32).fill(2)); })); await DR1('commitments-not-list', ed_(R1B, (p) => { p.coefficientCommitments = 'x'; }));
await DR1('R-short', ed_(R1B, (p) => { p.proofOfKnowledge.R = 'AAAA'; })); await DR1('mu-noncanonical-tail', ed_(R1B, (p) => { const m = p.proofOfKnowledge.mu; p.proofOfKnowledge.mu = m.slice(0, 42) + (m[42] === 'A' ? 'B' : 'A'); }));
const dsm = (b: any) => C.decodeDkgShareMessage(b);
const DS = (name: string, b: any) => R('decodeDkgShareMessage', name, dsm, [b]);
const SHM = { from: 1, to: 2, sessionId: b64(C23.sid), share: b64(sdb('codec/share')), sig: b64(new Uint8Array([...sdb('codec/sig'), ...sdb('codec/sig2')])) };
await DS('ok', SHM);
for (const k of Object.keys(SHM)) await DS('missing-' + k, ed_(SHM, (p) => { delete p[k]; }));
await DS('extra-member', { ...SHM, extra: 1 }); await DS('body-null', null); await DS('body-array', []);
for (const [n, v] of [['zero', 0], ['negative', -1], ['fraction', 1.5], ['string', '1'], ['null', null]] as [string, any][]) { await DS('from-' + n, { ...SHM, from: v }); await DS('to-' + n, { ...SHM, to: v }); }
await DS('share-short', { ...SHM, share: SHM.share.slice(0, 40) }); await DS('share-padded', { ...SHM, share: SHM.share + '=' }); await DS('share-long', { ...SHM, share: SHM.share + 'AAAA' }); await DS('share-number', { ...SHM, share: 5 });
await DS('share-not-reduced-ok', { ...SHM, share: b64(new Uint8Array(32).fill(255)) });
await DS('sig-32-bytes', { ...SHM, sig: SHM.share }); await DS('sig-padded', { ...SHM, sig: SHM.sig + '=' }); await DS('sig-null', { ...SHM, sig: null });
const CMP = { accused: 2, accuser: 3, sessionId: b64(C23.sid), revealedShare: b64(sdb('codec/rs')), shareSig: SHM.sig };
const RBT = { accused: 2, accuser: 3, sessionId: b64(C23.sid), presentedShare: b64(sdb('codec/ps')), shareSig: SHM.sig };
const dcs = (b: any) => C.decodeDkgComplaints(b), drs = (b: any) => C.decodeDkgRebuttals(b);
const DC = (name: string, b: any) => R('decodeDkgComplaints', name, dcs, [b]);
const DRB = (name: string, b: any) => R('decodeDkgRebuttals', name, drs, [b]);
await DC('empty', { complaints: [] }); await DC('one', { complaints: [CMP] }); await DC('three', { complaints: [CMP, { ...CMP, accused: 4 }, { ...CMP, accused: 5 }] });
await DC('max-256', { complaints: Array.from({ length: 256 }, (_, i) => ({ ...CMP, accused: i + 1 })) }); await DC('over-max-257', { complaints: Array.from({ length: 257 }, (_, i) => ({ ...CMP, accused: i + 1 })) });
await DC('duplicates-not-rejected-here', { complaints: [CMP, CMP] });
await DC('body-null', null); await DC('body-array', []); await DC('missing-key', {}); await DC('extra-key', { complaints: [], x: 1 }); await DC('wrong-key', { rebuttals: [] }); await DC('list-not-array', { complaints: {} }); await DC('list-null', { complaints: null });
await DC('entry-null', { complaints: [null] }); await DC('entry-extra', { complaints: [{ ...CMP, x: 1 }] });
for (const k of Object.keys(CMP)) await DC('entry-missing-' + k, { complaints: [ed_(CMP, (p) => { delete p[k]; })] });
await DC('entry-accused-zero', { complaints: [{ ...CMP, accused: 0 }] }); await DC('entry-accuser-fraction', { complaints: [{ ...CMP, accuser: 1.5 }] });
await DC('entry-share-short', { complaints: [{ ...CMP, revealedShare: CMP.revealedShare.slice(0, 40) }] }); await DC('entry-sig-short', { complaints: [{ ...CMP, shareSig: CMP.shareSig.slice(0, 40) }] });
await DC('second-entry-bad', { complaints: [CMP, { ...CMP, accused: 0 }] });
await DRB('empty', { rebuttals: [] }); await DRB('one', { rebuttals: [RBT] }); await DRB('over-max-257', { rebuttals: Array.from({ length: 257 }, (_, i) => ({ ...RBT, accuser: i + 1 })) });
await DRB('wrong-key', { complaints: [] }); await DRB('body-null', null); await DRB('entry-extra', { rebuttals: [{ ...RBT, x: 1 }] }); await DRB('entry-missing-presentedShare', { rebuttals: [ed_(RBT, (p) => { delete p.presentedShare; })] });
await DRB('entry-complaint-shaped', { rebuttals: [CMP] }); await DRB('entry-share-padded', { rebuttals: [{ ...RBT, presentedShare: RBT.presentedShare + '=' }] });
const dec_ = (b: any) => C.decodeDkgEcho(b);
const DE = (name: string, b: any) => R('decodeDkgEcho', name, dec_, [b]);
const ECHOB = { identifier: 1, sessionId: b64(C23.sid), transcriptDigest: E23[0].transcriptDigest };
await DE('ok', ECHOB); await DE('body-null', null); await DE('body-array', []); await DE('extra', { ...ECHOB, x: 1 });
for (const k of Object.keys(ECHOB)) await DE('missing-' + k, ed_(ECHOB, (p) => { delete p[k]; }));
await DE('id-zero', { ...ECHOB, identifier: 0 }); await DE('id-string', { ...ECHOB, identifier: '1' }); await DE('digest-short', { ...ECHOB, transcriptDigest: ECHOB.transcriptDigest.slice(0, 40) }); await DE('digest-padded', { ...ECHOB, transcriptDigest: ECHOB.transcriptDigest + '=' });
await DE('digest-64-bytes', { ...ECHOB, transcriptDigest: b64(new Uint8Array(64)) }); await DE('session-bad', { ...ECHOB, sessionId: 'x!' });

// ============================ DkgInbox ============================
const inboxRun = async (a: any) => {
  const ib = new C.DkgInbox(a.sessionId, a.peers);
  const out: any[] = [];
  for (const op of a.ops) {
    try {
      if (op.op === 'accept') { ib.accept(op.sender, op.bytes); out.push({ ok: true }); }
      else if (op.op === 'fail') { ib.fail(op.peer, new C.DkgChannelError(op.code, undefined, op.message)); out.push({ ok: true }); }
      else if (op.op === 'peerGone') { ib.peerGone(op.peer); out.push({ ok: true }); }
      else if (op.op === 'close') { ib.close(); out.push({ ok: true }); }
      else if (op.op === 'collect') { const m = await ib.collect(op.kind, op.from, op.timeoutMs); out.push({ ok: true, bodies: jsonOut(Object.fromEntries([...m].map(([k, v]) => [String(k), v]))) }); }
      else throw new Error('bad op');
    } catch (e: any) { out.push(errOut(e)); }
  }
  return out;
};
const IB = (name: string, peers: number[], ops: any[], sid: any = SID(C23)) => R('dkgInbox', name, inboxRun, [{ sessionId: sid, peers, ops }]);
const mb = (kind: string, body: any, sid = C23.sid) => B(C.encodeDkgMessage(sid, kind, body));
const acc = (sender: number, bytes: any) => ({ op: 'accept', sender, bytes });
const col = (kind: string, from: number[], timeoutMs = 30) => ({ op: 'collect', kind, from, timeoutMs });
await IB('collect-two-peers', [2, 3], [acc(2, mb('echo', { n: 2 })), acc(3, mb('echo', { n: 3 })), col('echo', [3, 2])]);
await IB('collect-empty-set', [2, 3], [col('echo', [])]);
await IB('collect-timeout-names-lowest-missing', [2, 3], [acc(3, mb('echo', {})), col('echo', [2, 3])]);
await IB('collect-timeout-nothing', [2, 3], [col('round1', [3, 2])]);
await IB('different-kinds-separate', [2], [acc(2, mb('echo', { a: 1 })), acc(2, mb('round1', { b: 2 })), col('round1', [2]), col('echo', [2])]);
await IB('duplicate-identical-sticky', [2, 3], [acc(2, mb('echo', {})), acc(2, mb('echo', {})), col('echo', [2]), col('round1', [2]), col('echo', [3])]);
await IB('equivocation-sticky', [2, 3], [acc(2, mb('echo', { a: 1 })), acc(2, mb('echo', { a: 2 })), col('echo', [2, 3])]);
await IB('equivocation-other-kind-poisons-all-kinds', [2], [acc(2, mb('echo', { a: 1 })), acc(2, mb('share', { a: 1 })), acc(2, mb('share', { a: 2 })), col('echo', [2])]);
await IB('malformed-sticky', [2, 3], [acc(2, B(utf('nope'))), acc(3, mb('echo', {})), col('echo', [2, 3]), col('echo', [3])]);
await IB('wrong-session-message', [2], [acc(2, mb('echo', {}, sdb('dkg23/other-sid'))), col('echo', [2])]);
await IB('oversize-message', [2], [acc(2, B(new Uint8Array(C.DKG_MAX_MESSAGE_BYTES + 1))), col('echo', [2])]);
await IB('non-peer-sender-ignored', [2], [acc(9, B(utf('junk'))), acc(2, mb('echo', {})), col('echo', [2])]);
await IB('error-order-lowest-id-first', [2, 3], [acc(3, B(utf('bad'))), acc(2, mb('echo', {})), acc(2, mb('echo', { x: 1 })), col('echo', [3, 2])]);
await IB('fail-first-wins', [2], [{ op: 'fail', peer: 2, code: 'oversize', message: 'big' }, { op: 'fail', peer: 2, code: 'identity', message: 'other' }, col('echo', [2])]);
await IB('fail-then-collect-other-peer-ok', [2, 3], [{ op: 'fail', peer: 2, code: 'closed', message: 'x' }, acc(3, mb('echo', {})), col('echo', [3])]);
await IB('peerGone-before-message-closed', [2, 3], [{ op: 'peerGone', peer: 2 }, col('echo', [2, 3])]);
await IB('peerGone-after-message-fine', [2], [acc(2, mb('echo', {})), { op: 'peerGone', peer: 2 }, col('echo', [2])]);
await IB('peerGone-for-unrelated-peer', [2, 3], [{ op: 'peerGone', peer: 3 }, acc(2, mb('echo', {})), col('echo', [2])]);
await IB('close-before-all-arrived', [2, 3], [acc(2, mb('echo', {})), { op: 'close' }, col('echo', [2, 3])]);
await IB('close-after-all-arrived-still-returns', [2], [acc(2, mb('echo', {})), { op: 'close' }, col('echo', [2])]);
await IB('collect-from-non-peer-times-out', [2], [col('echo', [9])]);
await IB('collect-zero-timeout', [2], [col('echo', [2], 0)]);
await IB('bodies-keyed-by-authenticated-sender', [2, 3], [acc(2, mb('echo', { identifier: 3 })), acc(3, mb('echo', { identifier: 2 })), col('echo', [2, 3])]);
await IB('session-empty', [2], [acc(2, mb('echo', {}, new Uint8Array()))], B(new Uint8Array()));

// ============================ memory network ============================
const netRun = async (a: any) => {
  const sidb = a.sessionId;
  const log: any[] = [];
  const intercept = a.intercept
    ? (d: any) => {
        const m = a.intercept;
        const hit = (m.kind === undefined || m.kind === d.kind) && (m.from === undefined || m.from === d.from) && (m.to === undefined || m.to === d.to);
        if (!hit) return d.bytes;
        if (m.action === 'drop') return null;
        if (m.action === 'replace') return m.bytes;
        return d.bytes;
      }
    : undefined;
  const net = C.createMemoryDkgNetwork(a.ids, sidb, intercept);
  const out: any[] = [{ channels: jsonOut(Object.fromEntries([...net.channels].map(([id, ch]: any) => [String(id), { self: ch.self, peers: ch.peers }]))) }];
  for (const op of a.ops) {
    try {
      const ch = op.at !== undefined ? net.channels.get(op.at) : undefined;
      if (op.op === 'broadcast') { await net.channels.get(op.from)!.broadcast(op.kind, op.body); out.push({ ok: true }); }
      else if (op.op === 'send') { await net.channels.get(op.from)!.send(op.to, op.kind, op.body); out.push({ ok: true }); }
      else if (op.op === 'deliver') { net.deliver(op.from, op.to, op.bytes); out.push({ ok: true }); }
      else if (op.op === 'collect') { const m = await ch!.collect(op.kind, op.fromIds, op.timeoutMs); out.push({ ok: true, bodies: jsonOut(Object.fromEntries([...m].map(([k, v]) => [String(k), v]))) }); }
      else if (op.op === 'close') { await ch!.close(); out.push({ ok: true }); }
      else throw new Error('bad op');
    } catch (e: any) { out.push(errOut(e)); }
  }
  return out;
};
const NW = (name: string, a: any) => R('memoryNetwork', name, netRun, [a]);
await NW('broadcast-reaches-every-peer', { ids: [3, 1, 2], sessionId: SID(C23), ops: [{ op: 'broadcast', from: 1, kind: 'echo', body: { n: 1 } }, { op: 'collect', at: 2, kind: 'echo', fromIds: [1], timeoutMs: 30 }, { op: 'collect', at: 3, kind: 'echo', fromIds: [1], timeoutMs: 30 }, { op: 'collect', at: 1, kind: 'echo', fromIds: [2], timeoutMs: 20 }] });
await NW('send-reaches-only-recipient', { ids: [1, 2, 3], sessionId: SID(C23), ops: [{ op: 'send', from: 1, to: 2, kind: 'share', body: { n: 1 } }, { op: 'collect', at: 2, kind: 'share', fromIds: [1], timeoutMs: 30 }, { op: 'collect', at: 3, kind: 'share', fromIds: [1], timeoutMs: 20 }] });
await NW('send-to-non-peer-identity-error', { ids: [1, 2], sessionId: SID(C23), ops: [{ op: 'send', from: 1, to: 9, kind: 'share', body: {} }, { op: 'send', from: 1, to: 1, kind: 'share', body: {} }] });
await NW('encode-failure-propagates-oversize', { ids: [1, 2], sessionId: SID(C23), ops: [{ op: 'broadcast', from: 1, kind: 'echo', body: 'x'.repeat(C.DKG_MAX_MESSAGE_BYTES) }] });
await NW('intercept-drop', { ids: [1, 2, 3], sessionId: SID(C23), intercept: { action: 'drop', from: 1, to: 3 }, ops: [{ op: 'broadcast', from: 1, kind: 'echo', body: { n: 1 } }, { op: 'collect', at: 2, kind: 'echo', fromIds: [1], timeoutMs: 30 }, { op: 'collect', at: 3, kind: 'echo', fromIds: [1], timeoutMs: 20 }] });
await NW('intercept-replace-bytes', { ids: [1, 2], sessionId: SID(C23), intercept: { action: 'replace', kind: 'echo', bytes: B(utf('garbage')) }, ops: [{ op: 'broadcast', from: 1, kind: 'echo', body: {} }, { op: 'collect', at: 2, kind: 'echo', fromIds: [1], timeoutMs: 20 }] });
await NW('deliver-adversary-as-sender', { ids: [1, 2], sessionId: SID(C23), ops: [{ op: 'deliver', from: 1, to: 2, bytes: B(C.encodeDkgMessage(C23.sid, 'echo', { forged: true })) }, { op: 'collect', at: 2, kind: 'echo', fromIds: [1], timeoutMs: 30 }] });
await NW('deliver-to-unknown-recipient-silently-lost', { ids: [1, 2], sessionId: SID(C23), ops: [{ op: 'deliver', from: 1, to: 9, bytes: B(utf('x')) }] });
await NW('close-then-collect', { ids: [1, 2], sessionId: SID(C23), ops: [{ op: 'close', at: 2 }, { op: 'collect', at: 2, kind: 'echo', fromIds: [1], timeoutMs: 20 }] });
await NW('single-participant-no-peers', { ids: [7], sessionId: SID(C23), ops: [{ op: 'collect', at: 7, kind: 'echo', fromIds: [], timeoutMs: 10 }] });
await NW('duplicate-ids-collapse-peers', { ids: [2, 2, 1], sessionId: SID(C23), ops: [] });

// ============================ TLS framing (model) ============================
const MAXF = C.DKG_MAX_MESSAGE_BYTES;
const frame = (payload: Uint8Array) => { const f = new Uint8Array(4 + payload.length); new DataView(f.buffer).setUint32(0, payload.length, false); f.set(payload, 4); return f; };
const tlsDecode = (a: any) => {
  let buf: Uint8Array = new Uint8Array();
  const accepted: Uint8Array[] = [];
  let error: string | null = null;
  const cat = (x: Uint8Array, y: Uint8Array) => { const z = new Uint8Array(x.length + y.length); z.set(x); z.set(y, x.length); return z; };
  for (const chunk of a.chunks) {
    if (error) break;
    buf = cat(buf, chunk);
    for (;;) {
      if (buf.length < 4) break;
      const len = new DataView(buf.buffer, buf.byteOffset, 4).getUint32(0, false);
      if (len > MAXF) { error = 'oversize'; break; }
      if (buf.length < 4 + len) break;
      accepted.push(buf.slice(4, 4 + len));
      buf = buf.subarray(4 + len);
    }
  }
  return { accepted, error, buffered: buf.length };
};
await R('tlsFrameEncode', 'empty', (p: any) => frame(p), [B(new Uint8Array())]); await R('tlsFrameEncode', 'abc', (p: any) => frame(p), [B(utf('abc'))]); await R('tlsFrameEncode', 'envelope', (p: any) => frame(p), [B(C.encodeDkgMessage(C23.sid, 'echo', E23[0]))]);
await R('tlsFrameEncode', 'length-256', (p: any) => frame(p), [B(new Uint8Array(256).fill(1))]); await R('tlsFrameEncode', 'length-65536', (p: any) => frame(p), [B(new Uint8Array(65536).fill(2))]);
const f1 = frame(utf('hello')), f2 = frame(utf('world!')), fe = frame(new Uint8Array());
const TF = (name: string, chunks: Uint8Array[]) => R('tlsFrameDecode', name, tlsDecode, [{ chunks: chunks.map(B) }]);
await TF('one-frame', [f1]); await TF('two-frames-one-chunk', [(() => { const z = new Uint8Array(f1.length + f2.length); z.set(f1); z.set(f2, f1.length); return z; })()]);
await TF('header-split', [f1.slice(0, 2), f1.slice(2)]); await TF('payload-split', [f1.slice(0, 6), f1.slice(6)]); await TF('byte-at-a-time', Array.from(f1, (b) => Uint8Array.of(b)));
await TF('partial-frame-left-buffered', [f1.slice(0, 7)]); await TF('three-bytes-only', [f1.slice(0, 3)]); await TF('empty-frame', [fe]); await TF('empty-frame-then-data', [fe, f1]);
await TF('frame-then-partial', [(() => { const z = new Uint8Array(f1.length + 3); z.set(f1); z.set(f2.slice(0, 3), f1.length); return z; })()]);
await TF('length-at-cap-waits-for-payload', [Uint8Array.of(0, 4, 0, 0)]); await TF('length-over-cap', [Uint8Array.of(0, 4, 0, 1)]); await TF('length-ffffffff', [Uint8Array.of(255, 255, 255, 255)]);
await TF('good-frame-then-oversize', [(() => { const z = new Uint8Array(f1.length + 4); z.set(f1); z.set(Uint8Array.of(0, 4, 0, 1), f1.length); return z; })()]);
await TF('oversize-stops-later-chunks', [Uint8Array.of(0, 4, 0, 1), f1]);
await TF('no-chunks', []); await TF('empty-chunks', [new Uint8Array(), new Uint8Array(), f1]);

// ============================ runDkgOverChannel: validation + scripted party replays ============================
const PHASES = ['round1', 'share', 'complaints', 'rebuttals', 'echo'];
async function partyRun(spec: any): Promise<any> {
  const sid = spec.sessionId as Uint8Array;
  const peers = spec.peers ?? spec.participants.filter((p: number) => p !== spec.self).sort((a: number, b: number) => a - b);
  const inbox = new C.DkgInbox(sid, peers);
  const pending = [...(spec.inbound ?? [])];
  const outbound: any[] = [];
  // entries are delivered in list order; an entry of a LATER phase stays queued until that phase is collected
  const flushAll = (kind: string) => { const lim = PHASES.indexOf(kind); const keep: any[] = []; for (const m of pending) { if (PHASES.indexOf(m.kind) <= lim) inbox.accept(m.from, m.bytes); else keep.push(m); } pending.length = 0; pending.push(...keep); };
  for (const g of spec.gone ?? []) inbox.peerGone(g);
  const ch = {
    self: spec.self, peers,
    broadcast: async (kind: string, body: any) => { outbound.push({ op: 'broadcast', kind, bytes: jsonOut(C.encodeDkgMessage(sid, kind, body)) }); },
    send: async (to: number, kind: string, body: any) => { if (!peers.includes(to)) throw new C.DkgChannelError('identity', to, 'not a connected peer'); outbound.push({ op: 'send', kind, to, bytes: jsonOut(C.encodeDkgMessage(sid, kind, body)) }); },
    collect: (kind: string, from: number[], tmo: number) => { flushAll(kind); return inbox.collect(kind, from, tmo); },
    close: async () => { inbox.close(); },
  };
  try {
    const r = await C.runDkgOverChannel(ch, { t: spec.t, participants: spec.participants, sessionId: sid, timeoutMs: spec.timeoutMs });
    return { outbound, result: jsonOut({ qualified: r.qualified, complaints: r.complaints, keyPackage: r.keyPackage }) };
  } catch (e: any) { return { outbound, error: errOut(e) }; }
}
const partyCase = async (name: string, spec: any, rng?: string[]) => {
  const r = await R('runDkgOverChannel', name, partyRun, [spec], rng, (out: any) => {
    // share messages carry a derived secret: register their bytes (outbound) so the case goes to the CI corpus
    for (const m of out.outbound ?? []) wireSecret(m.kind, fromB64(m.bytes.$bytes));
    return watch(out);
  });
  return r;
};
const sidOf = (label: string) => S(label + '/sid');
const pspec = (label: string, self: number, t: number, ids: number[], inbound: any[], over: any = {}) => ({ self, t, participants: ids, sessionId: sidOf(label), timeoutMs: over.timeoutMs ?? 400, inbound, ...over });
// validation (no inbound needed)
{
  const L = 'cv';
  const V = (n: string, spec: any, rng?: string[]) => partyCase('validate-' + n, spec, rng);
  await V('participants-duplicate', pspec(L, 1, 2, [1, 2, 2, 3], [], { peers: [2, 3] }));
  await V('participants-zero', pspec(L, 1, 2, [0, 1, 2], [], { peers: [0, 2] }));
  await V('participants-negative', pspec(L, 1, 2, [-1, 1, 2], [], { peers: [2] }));
  await V('participants-fraction', pspec(L, 1, 2, [1, 1.5, 2], [], { peers: [1.5, 2] }));
  await V('self-not-participant', pspec(L, 9, 2, [1, 2, 3], [], { peers: [1, 2, 3] }));
  await V('t-zero', pspec(L, 1, 0, [1, 2, 3], []));
  await V('t-above-n', pspec(L, 1, 4, [1, 2, 3], []));
  await V('t-fraction', pspec(L, 1, 1.5, [1, 2, 3], []));
  await V('peers-missing-one', pspec(L, 1, 2, [1, 2, 3], [], { peers: [2] }));
  await V('peers-extra', pspec(L, 1, 2, [1, 2, 3], [], { peers: [2, 3, 4] }));
  await V('peers-unsorted', pspec(L, 1, 2, [1, 2, 3], [], { peers: [3, 2] }));
  await V('peers-wrong-ids', pspec(L, 1, 2, [1, 2, 3], [], { peers: [2, 4] }));
  await V('participants-257-over-cap', pspec(L, 1, 2, Array.from({ length: 257 }, (_, i) => i + 1), [], { peers: Array.from({ length: 256 }, (_, i) => i + 2) }));
  await V('participants-256-at-cap-times-out-waiting', pspec(L, 1, 2, Array.from({ length: 256 }, (_, i) => i + 1), [], { peers: Array.from({ length: 255 }, (_, i) => i + 2), timeoutMs: 20 }), rngOf(L, 1, 2));
  await V('single-participant-t1-b', pspec('cv1', 5, 1, [5], []), rngOf('cv1', 5, 1));
  await V('two-parties-no-inbound-timeout', pspec('cv2', 1, 2, [1, 2], [], { timeoutMs: 30 }), rngOf('cv2', 1, 2));
  await V('peer-gone-before-round1', pspec('cv3', 1, 2, [1, 2], [], { gone: [2], timeoutMs: 200 }), rngOf('cv3', 1, 2));
}

// live harness: run every party over the in-memory network (inbound recorded after the adversary), then replay each party alone
type Del = { from: number; to: number; kind: string; bytes: Uint8Array };
async function ceremony(label: string, t: number, ids: number[], opts: { adv?: (d: Del, post: (d: Del) => void, log: Del[]) => Uint8Array | null; timeoutMs?: number; skipParties?: number[] } = {}) {
  const sid = sdb(label + '/sid');
  const log: Del[] = [];
  const tmo = opts.timeoutMs ?? 400;
  const extra: Del[] = [];
  const net = C.createMemoryDkgNetwork(ids, sid, (d: any) => {
    const post = (x: Del) => { wireSecret(x.kind, x.bytes); setImmediate(() => { log.push(x); net.deliver(x.from, x.to, x.bytes); }); };
    const outBytes = opts.adv ? opts.adv(d, post, log) : d.bytes;
    if (outBytes !== null) { wireSecret(d.kind, outBytes); log.push({ from: d.from, to: d.to, kind: d.kind, bytes: outBytes }); }
    return outBytes;
  });
  await Promise.all(ids.map((id) => {
    setQueue('p' + id, rngOf(label, id, t));
    return as('p' + id, () => C.runDkgOverChannel(net.channels.get(id)!, { t, participants: ids, sessionId: sid, timeoutMs: tmo })).then(() => null, () => null);
  }));
  for (let k = 0; k < 3; k++) await new Promise<void>((r) => setImmediate(r)); // late adversary deliveries (post) land in the log before the replay inputs are cut
  for (const id of ids) {
    if (opts.skipParties?.includes(id)) continue;
    const inbound = log.filter((m) => m.to === id).map((m) => ({ from: m.from, kind: m.kind, bytes: B(m.bytes) }));
    await partyCase(`${label}-party${id}`, { self: id, t, participants: ids, sessionId: sidOf(label), timeoutMs: tmo, inbound }, rngOf(label, id, t));
  }
  return log;
}
const dm = (d: Del, sid: Uint8Array) => C.decodeDkgMessage(d.bytes, sid);
const reenc = (sid: Uint8Array, kind: string, body: any) => C.encodeDkgMessage(sid, kind, body);
const SIDB = (label: string) => sdb(label + '/sid');
// honest runs
await ceremony('ch-honest-2of3', 2, [1, 2, 3]);
await ceremony('ch-honest-3of5-sparse', 3, [2, 5, 7, 11, 13]);
await ceremony('ch-honest-2of2', 2, [1, 2]);
await ceremony('ch-honest-3of3', 3, [1, 2, 3]);
await ceremony('ch-honest-1of2', 1, [1, 2]);
await ceremony('ch-honest-2of4', 2, [1, 2, 3, 4]);
// a cheating dealer: signs bad shares for everyone (party 2), blame resolves against it
{
  const L = 'ch-bad-share-all';
  await ceremony(L, 2, [1, 2, 3, 4], { adv: (d) => {
    if (d.kind !== 'share' || d.from !== 2) return d.bytes;
    const sid = SIDB(L); const m = dm(d, sid) as any; const bad = fromB64(m.body.share); bad[0] ^= 1;
    const st = stateOf(specOf(L, 2, 2, 4));
    sec(bad); return reenc(sid, 'share', { ...m.body, share: b64(bad), sig: D.dkgSignShare(st, d.to, bad) });
  } });
}
{
  const L = 'ch-bad-share-one';
  await ceremony(L, 2, [1, 2, 3, 4], { adv: (d) => {
    if (d.kind !== 'share' || d.from !== 2 || d.to !== 3) return d.bytes;
    const sid = SIDB(L); const m = dm(d, sid) as any; const bad = fromB64(m.body.share); bad[3] ^= 4;
    const st = stateOf(specOf(L, 2, 2, 4));
    sec(bad); return reenc(sid, 'share', { ...m.body, share: b64(bad), sig: D.dkgSignShare(st, 3, bad) });
  } });
}
{
  const L = 'ch-bad-share-unsigned';
  await ceremony(L, 2, [1, 2, 3], { timeoutMs: 120, adv: (d) => {
    if (d.kind !== 'share' || d.from !== 2 || d.to !== 3) return d.bytes;
    const sid = SIDB(L); const m = dm(d, sid) as any; const bad = fromB64(m.body.share); bad[0] ^= 1; sec(bad);
    return reenc(sid, 'share', { ...m.body, share: b64(bad) }); // the sig no longer matches
  } });
}
{
  const L = 'ch-share-wrong-recipient-field';
  await ceremony(L, 2, [1, 2, 3], { timeoutMs: 120, adv: (d) => { if (d.kind !== 'share' || d.from !== 2 || d.to !== 3) return d.bytes; const sid = SIDB(L); const m = dm(d, sid) as any; return reenc(sid, 'share', { ...m.body, to: 1 }); } });
}
{
  const L = 'ch-share-wrong-sender-field';
  await ceremony(L, 2, [1, 2, 3], { timeoutMs: 120, adv: (d) => { if (d.kind !== 'share' || d.from !== 2 || d.to !== 3) return d.bytes; const sid = SIDB(L); const m = dm(d, sid) as any; return reenc(sid, 'share', { ...m.body, from: 1 }); } });
}
{
  const L = 'ch-share-other-session-field';
  await ceremony(L, 2, [1, 2, 3], { timeoutMs: 120, adv: (d) => { if (d.kind !== 'share' || d.from !== 2 || d.to !== 3) return d.bytes; const sid = SIDB(L); const m = dm(d, sid) as any; return reenc(sid, 'share', { ...m.body, sessionId: b64(sdb('other-session')) }); } });
}
{
  const L = 'ch-envelope-other-session';
  await ceremony(L, 2, [1, 2, 3], { timeoutMs: 120, adv: (d) => { if (d.kind !== 'round1' || d.from !== 2 || d.to !== 1) return d.bytes; return reenc(sdb('other-session'), 'round1', dm(d, SIDB(L)).body); } });
}
{
  const L = 'ch-round1-identifier-spoofed';
  await ceremony(L, 2, [1, 2, 3], { timeoutMs: 120, adv: (d) => { if (d.kind !== 'round1' || d.from !== 3 || d.to !== 1) return d.bytes; const m = dm(d, SIDB(L)) as any; return reenc(SIDB(L), 'round1', { ...m.body, identifier: 2 }); } });
}
{
  const L = 'ch-round1-bad-pop';
  await ceremony(L, 2, [1, 2, 3, 4], { timeoutMs: 120, adv: (d) => { if (d.kind !== 'round1' || d.from !== 4) return d.bytes; const m = dm(d, SIDB(L)) as any; const mu = fromB64(m.body.proofOfKnowledge.mu); mu[0] ^= 1; return reenc(SIDB(L), 'round1', { ...m.body, proofOfKnowledge: { ...m.body.proofOfKnowledge, mu: b64(mu) } }); } });
}
{
  const L = 'ch-round1-duplicate-identical';
  await ceremony(L, 2, [1, 2, 3], { timeoutMs: 120, adv: (d, post) => { if (d.kind === 'round1' && d.from === 2 && d.to === 1) post({ ...d }); return d.bytes; } });
}
{
  const L = 'ch-round1-equivocation';
  await ceremony(L, 2, [1, 2, 3], { timeoutMs: 120, adv: (d, post) => {
    if (d.kind === 'round1' && d.from === 2 && d.to === 1) { const other = D.dkgRound1(2, 2, 3, SIDB(L), { coefficients: [sdb(L + '/alt0'), sdb(L + '/alt1')], popNonce: sdb(L + '/altpop') }).package; post({ ...d, bytes: reenc(SIDB(L), 'round1', other) }); }
    return d.bytes;
  } });
}
{
  const L = 'ch-round1-malformed-truncated';
  await ceremony(L, 2, [1, 2, 3], { timeoutMs: 120, adv: (d) => (d.kind === 'round1' && d.from === 2 && d.to === 1 ? d.bytes.slice(0, d.bytes.length - 7) : d.bytes) });
}
{
  const L = 'ch-round1-extra-member';
  await ceremony(L, 2, [1, 2, 3], { timeoutMs: 120, adv: (d) => { if (d.kind !== 'round1' || d.from !== 2 || d.to !== 1) return d.bytes; const m = dm(d, SIDB(L)) as any; return reenc(SIDB(L), 'round1', { ...m.body, extra: 1 }); } });
}
{
  const L = 'ch-round1-wrong-commitment-count';
  await ceremony(L, 2, [1, 2, 3], { timeoutMs: 120, adv: (d) => { if (d.kind !== 'round1' || d.from !== 2 || d.to !== 1) return d.bytes; const m = dm(d, SIDB(L)) as any; return reenc(SIDB(L), 'round1', { ...m.body, coefficientCommitments: m.body.coefficientCommitments.slice(1) }); } });
}
{
  const L = 'ch-oversize-message';
  await ceremony(L, 2, [1, 2, 3], { timeoutMs: 120, adv: (d) => (d.kind === 'round1' && d.from === 2 && d.to === 1 ? new Uint8Array(C.DKG_MAX_MESSAGE_BYTES + 1) : d.bytes) });
}
{
  const L = 'ch-drop-round1';
  await ceremony(L, 2, [1, 2, 3], { timeoutMs: 100, adv: (d) => (d.kind === 'round1' && d.from === 2 && d.to === 3 ? null : d.bytes) });
}
{
  const L = 'ch-drop-share';
  await ceremony(L, 2, [1, 2, 3], { timeoutMs: 100, adv: (d) => (d.kind === 'share' && d.from === 1 && d.to === 3 ? null : d.bytes) });
}
{
  const L = 'ch-drop-echo';
  await ceremony(L, 2, [1, 2, 3], { timeoutMs: 100, adv: (d) => (d.kind === 'echo' && d.from === 3 && d.to === 1 ? null : d.bytes) });
}
{
  const L = 'ch-bad-echo-digest';
  await ceremony(L, 2, [1, 2, 3], { timeoutMs: 120, adv: (d) => { if (d.kind !== 'echo' || d.from !== 2 || d.to !== 1) return d.bytes; const m = dm(d, SIDB(L)) as any; return reenc(SIDB(L), 'echo', { ...m.body, transcriptDigest: flipStr(m.body.transcriptDigest, 0) }); } });
}
{
  const L = 'ch-echo-identifier-spoofed';
  await ceremony(L, 2, [1, 2, 3], { timeoutMs: 120, adv: (d) => { if (d.kind !== 'echo' || d.from !== 2 || d.to !== 1) return d.bytes; const m = dm(d, SIDB(L)) as any; return reenc(SIDB(L), 'echo', { ...m.body, identifier: 3 }); } });
}
{
  // a valid complaint filed by party 3 against party 2 is shown only to party 1: party 1's transcript differs, the echo round catches it
  const L = 'ch-complaint-shown-to-one-party';
  const cer = new Cer(L, 2, [1, 2, 3]);
  await ceremony(L, 2, [1, 2, 3], { timeoutMs: 150, adv: (d) => {
    if (d.kind !== 'complaints' || d.from !== 3 || d.to !== 1) return d.bytes;
    const c = cer.complaintFor(2, 3, cer.recv(2, 3));
    return reenc(SIDB(L), 'complaints', { complaints: [c] });
  } });
}
{
  const L = 'ch-complaint-wrong-accuser';
  const cer = new Cer(L, 2, [1, 2, 3]);
  await ceremony(L, 2, [1, 2, 3], { timeoutMs: 120, adv: (d) => (d.kind === 'complaints' && d.from === 3 && d.to === 1 ? reenc(SIDB(L), 'complaints', { complaints: [{ ...cer.complaintFor(2, 3, cer.recv(2, 3)), accuser: 1 }] }) : d.bytes) });
}
{
  const L = 'ch-complaint-two-against-one-accused';
  const cer = new Cer(L, 2, [1, 2, 3]);
  await ceremony(L, 2, [1, 2, 3], { timeoutMs: 120, adv: (d) => { if (!(d.kind === 'complaints' && d.from === 3 && d.to === 1)) return d.bytes; const c = cer.complaintFor(2, 3, cer.recv(2, 3)); return reenc(SIDB(L), 'complaints', { complaints: [c, c] }); } });
}
{
  const L = 'ch-complaint-invalid-accused';
  const cer = new Cer(L, 2, [1, 2, 3]);
  await ceremony(L, 2, [1, 2, 3], { timeoutMs: 120, adv: (d) => { if (!(d.kind === 'complaints' && d.from === 3 && d.to === 1)) return d.bytes; const c = cer.complaintFor(2, 3, cer.recv(2, 3)); return reenc(SIDB(L), 'complaints', { complaints: [{ ...c, accused: 3 }] }); } });
}
{
  const L = 'ch-complaint-other-session';
  const cer = new Cer(L, 2, [1, 2, 3]);
  await ceremony(L, 2, [1, 2, 3], { timeoutMs: 120, adv: (d) => { if (!(d.kind === 'complaints' && d.from === 3 && d.to === 1)) return d.bytes; const c = cer.complaintFor(2, 3, cer.recv(2, 3)); return reenc(SIDB(L), 'complaints', { complaints: [{ ...c, sessionId: b64(sdb('other-session')) }] }); } });
}
{
  const L = 'ch-rebuttal-made-as-someone-else';
  const cer = new Cer(L, 2, [1, 2, 3]);
  await ceremony(L, 2, [1, 2, 3], { timeoutMs: 120, adv: (d) => { if (!(d.kind === 'rebuttals' && d.from === 2 && d.to === 1)) return d.bytes; const c = cer.complaintFor(3, 1, cer.recv(3, 1)); const r = D.dkgRebut(3, c, cer.state(3)); return reenc(SIDB(L), 'rebuttals', { rebuttals: [r] }); } });
}
{
  const L = 'ch-rebuttal-other-session';
  const cer = new Cer(L, 2, [1, 2, 3]);
  await ceremony(L, 2, [1, 2, 3], { timeoutMs: 120, adv: (d) => { if (!(d.kind === 'rebuttals' && d.from === 2 && d.to === 1)) return d.bytes; const c = cer.complaintFor(2, 1, cer.recv(2, 1)); const r = D.dkgRebut(2, c, cer.state(2)); return reenc(SIDB(L), 'rebuttals', { rebuttals: [{ ...r, sessionId: b64(sdb('other-session')) }] }); } });
}
{
  const L = 'ch-wrong-kind-in-envelope';
  await ceremony(L, 2, [1, 2, 3], { timeoutMs: 120, adv: (d) => { if (!(d.kind === 'echo' && d.from === 2 && d.to === 1)) return d.bytes; return C.encodeDkgMessage(SIDB(L), 'complaints', { complaints: [] }); } });
}
{
  const L = 'ch-echo-duplicate-identical';
  await ceremony(L, 2, [1, 2, 3], { timeoutMs: 120, adv: (d, post) => { if (d.kind === 'echo' && d.from === 2 && d.to === 1) post({ ...d }); return d.bytes; } });
}

// ---- write -------------------------------------------------------------------------------------------------------------
splitWrite(o, 'frost-dkg', (j: string) => [...SECRETS].filter((t) => t.length >= 20 && j.includes(t)));
// audit: no committed case may carry a derived secret, in the clear or inside the text of a base64url message
{
  const text = o.cases.map((c: any) => ser(c)).join('\n');
  const plain = [...SECRETS].filter((t) => t.length >= 40 && t.length <= 60); // shares and signing shares (32 bytes), not whole messages
  for (const t of plain) if (text.includes(t)) throw new Error('a derived share leaked into the committed corpus');
  for (const m of text.matchAll(/"\$bytes":"([A-Za-z0-9_-]{20,})"/g)) {
    const dec = Buffer.from(m[1]!, 'base64url').toString('latin1');
    for (const t of plain) if (dec.includes(t)) throw new Error('a derived share leaked into the committed corpus inside a message');
  }
}
