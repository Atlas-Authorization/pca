import { ed25519 } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { b64u, hashCanonical, unb64u, utf8 } from './hash';
import {
  CONTEXT_STRING,
  L,
  bytesToScalar,
  decodeSafePoint,
  scalarToBytes,
  type FrostParticipantShare,
  type ParticipantId,
} from './frost';

/**
 * TRUSTLESS FROST DISTRIBUTED KEY GENERATION (DKG) — PedPoP / FROST paper two-round DKG, now with a
 * JUSTIFIED-COMPLAINT BLAME ROUND and SESSION BINDING.
 *
 * WHAT THIS IS
 * ------------
 * `frost.ts` ships the RFC 9591, vector-exact FROST signing math, but splits the group key with a
 * TRUSTED DEALER (`frostTrustedDealerKeygen`): one party knows the whole group secret for an instant.
 * This module removes that assumption. It implements the standard no-dealer FROST DKG (Pedersen VSS
 * with a proof of possession, a.k.a. "PedPoP", from the Komlo–Goldberg FROST paper, §5.1): every
 * participant contributes a secret polynomial, nobody ever holds the group secret, and the group key
 * is the sum of all QUALIFIED participants' constant-term commitments.
 *
 * The output is a DROP-IN for `frost.ts`: `signingShare` has the same shape/semantics as a
 * trusted-dealer `FrostParticipantShare.share` (a Shamir share f(id) of the group secret on a
 * degree-(t−1) polynomial), and `groupPublicKey` is f(0)·B. So a quorum's `frostCommit` /
 * `frostSign` / `frostAggregate` over a DKG key produces a byte-identical ordinary Ed25519 signature
 * that `verify(groupPublicKey, msg, sig)` accepts — the exact PCA leaf-signature check, unchanged.
 *
 * WHAT THIS REVISION ADDS  (hardening toward production-completeness)
 * ------------------------------------------------------------------
 *   1. SESSION BINDING (anti-replay / anti-equivocation). Every DKG run carries a caller-supplied
 *      `sessionId` (e.g. a random 32-byte ceremony id). It is folded into the Schnorr proof-of-
 *      possession challenge (keeping the `"dkg-pop"` domain separator) AND stamped onto the round-1
 *      packages and the round-2 share packages. `dkgVerifyRound1` / `dkgVerifyShare` require the
 *      matching session, so a round-1 package or a secret share captured from one DKG run cannot be
 *      replayed into another: a package minted for session A fails the PoP under session B, and its
 *      stamped sessionId won't match either. `dkgFinalize` refuses a set of packages/shares that do
 *      not all name one session.
 *   2. NON-REPUDIABLE SHARES + ACCUSED-REBUTTAL BLAME ROUND (attributable blame). Every round-2 secret
 *      share is now SIGNED by the sender: `dkgRound2` attaches a Schnorr signature under the sender's
 *      VSS constant-term key C_0 = g^{a_i0} (the very key the round-1 PoP already proved possession of),
 *      over a domain-separated binding of (sessionId, senderId, recipientId, the share, C_0). A recipient
 *      therefore holds a token the sender CANNOT later deny having produced, and `dkgVerifyShare` now
 *      REQUIRES + verifies that signature in addition to the Pedersen-VSS check.
 *        • A complaint carries the sender-SIGNED share. `dkgVerifyComplaint` is justified iff the share
 *          is validly signed by the ACCUSED *and* fails VSS → the accused is guilty, non-repudiably. A
 *          validly-signed share that PASSES VSS is a FALSE accusation (accuser at fault). A share that
 *          is NOT validly signed by the accused is INADMISSIBLE — a griefer cannot frame an honest party
 *          with fabricated bytes, because only the accused could have signed under C_0.
 *        • `dkgRebut` lets the accused re-present the share it actually signed+sent to that recipient,
 *          and `dkgResolveBlame` adjudicates accused-vs-accuser from the signatures + VSS: a recipient
 *          claiming non-receipt (an inadmissible, unsigned complaint) loses to a signed, VSS-correct
 *          share the accused can produce; an accused who signed a VSS-bad share is convicted regardless
 *          of any rebuttal.
 *      `dkgQualifiedSet` returns the participants that remain after dropping everyone who failed round-1
 *      PoK and every party whose blame resolves with THEM guilty as the accused dealer (a resolved-guilty
 *      accuser is never disqualified, so false accusations and inadmissible griefing cannot remove an
 *      honest party); `dkgFinalize` / `frostDkgSimulate` then build a working (t, |qualified|) key over
 *      that set, so a run in which a cheater is removed still yields a usable key for the honest set when
 *      |qualified| ≥ t.
 *
 * HONEST VALIDATION BASIS  (read this)
 * ------------------------------------
 * RFC 9591 is SIGNING-ONLY: there is NO official FROST DKG test vector, so nothing here is asserted
 * against a published vector (unlike the signing path, which is byte-exact). This DKG is validated two
 * ways instead, both in `frost-dkg.test.ts`:
 *   (a) ROUND-TRIP: DKG → finalize feeds the *already* vector-exact `frostSign`/`frostAggregate`, and
 *       `verify(groupPublicKey, msg, sig)` returns true for every t-of-n quorum (including after a
 *       cheater is disqualified and the honest quorum signs under the smaller qualified set).
 *   (b) INVARIANTS: the DKG's own checks — each peer's Schnorr proof of possession (`dkgVerifyRound1`)
 *       and each received share against the dealer's VSS commitments (`dkgVerifyShare`,
 *       g^{share} == Π_k C_k^{id^k}, and the REQUIRED sender signature on the share) — plus "all
 *       qualified participants compute the same group key", plus the blame round (an accused-signed
 *       VSS-bad share disqualifies the cheater non-repudiably; a false accusation, an inadmissible
 *       unsigned complaint, and a complaint the accused rebuts with a signed VSS-correct share do NOT).
 *
 * REFERENCE-IMPLEMENTATION / SECURITY CAVEATS  (NOT production-ready; needs an audit)
 * ----------------------------------------------------------------------------------
 *   • Assumes an AUTHENTICATED BROADCAST channel for round-1 packages (commitments + PoP) and for
 *     complaints, and PRIVATE, authenticated point-to-point channels for round-2 share delivery. This
 *     module does neither; it only produces/verifies the protocol messages. The session binding raises
 *     the bar on replay but does not create those channels.
 *   • The blame round now gives ATTRIBUTABLE blame: shares are non-repudiable (signed under the sender's
 *     VSS key C_0), so a complaint can only convict the accused when it exhibits the accused's OWN
 *     signature over a VSS-bad share, and `dkgRebut`/`dkgResolveBlame` let the accused clear an
 *     inadmissible/non-receipt accusation by producing the signed, VSS-correct share it actually sent —
 *     a griefer can neither frame an honest party nor disqualify it with a valid share. This STILL
 *     assumes an AUTHENTICATED BROADCAST channel for round-1 packages, rebuttals and complaints, and
 *     PRIVATE, authenticated point-to-point delivery of round-2 shares: the module only produces/verifies
 *     the protocol messages, it does not create those channels. A cheater who delivers garbage WITHOUT a
 *     valid signature is rejected at receipt (`dkgVerifyShare` requires the signature) and shows up as a
 *     MISSING share at finalize rather than as an attributable conviction — non-repudiable blame covers
 *     only signed artifacts. Equivocation across the broadcast is only partly covered (divergent-session
 *     packages are dropped; an authenticated-broadcast transcript is still assumed).
 *   • No defense against rogue-key / biased-key attacks beyond the PoP; the surrounding BigInt scalar
 *     arithmetic is NOT constant-time (a JS-BigInt limitation shared with `frost.ts` — a production
 *     build needs a constant-time field implementation).
 *   • Needs a security audit before any production threshold-custody use. PCA's DEFAULT remains the
 *     multi-signature (`threshold.ts`); FROST(+DKG) is an opt-in aggregation optimization.
 *
 * PCA PLUG-IN
 * -----------
 * The PCA plug-in path can obtain the FROST group key via this DKG instead of the trusted dealer:
 * run the ceremony across agent / guardian / principal, set the capability-leaf `holder` to
 * b64u(groupPublicKey), and let a quorum aggregate signature shares exactly as in the trusted-dealer
 * case (see `frost.ts` header and the `FROST ⨯ PCActn` test). `frostDkgSimulate(t, n)` returns the
 * same `{ groupPublicKey, participantShares, groupCommitment }` shape as `frostTrustedDealerKeygen`,
 * so it is a literal drop-in for that in-process path.
 */

const P = ed25519.ExtendedPoint;

// ---- local scalar / point helpers (frost.ts keeps its own private; mirror them here) -------------

function mod(a: bigint): bigint {
  const r = a % L;
  return r >= 0n ? r : r + L;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let i = 0;
  for (const p of parts) {
    out.set(p, i);
    i += p.length;
  }
  return out;
}

/** HashToScalar for Ed25519: OS2IP_LE(SHA-512(msg)) mod L (same construction as frost.ts §6.1). */
function hashToScalar(msg: Uint8Array): bigint {
  return bytesToScalar(sha512(msg));
}

/** s·B; 0 maps to identity (noble's multiply rejects 0). */
function mulBase(s: bigint): InstanceType<typeof P> {
  const v = mod(s);
  return v === 0n ? P.ZERO : P.BASE.multiply(v);
}

/** s·Q; 0 maps to identity. */
function mulPoint(pt: InstanceType<typeof P>, s: bigint): InstanceType<typeof P> {
  const v = mod(s);
  return v === 0n ? P.ZERO : pt.multiply(v);
}

/** Strict decode (canonical, on-curve, not small-order, torsion-free) — see frost.ts decodeSafePoint. */
const decodePoint = decodeSafePoint;

/**
 * The FULL VSS commitment vector (C_0..C_{t-1}) as bound into every challenge: u32be(count) ‖ each
 * 32-byte point. Binding the whole vector (not just C_0) stops a dealer from showing different
 * higher-degree commitments to different parties under one PoP / share signature.
 */
interface CommitVec {
  c0: InstanceType<typeof P>;
  bytes: Uint8Array;
}
function commitVecOf(commitments: string[]): CommitVec {
  if (!Array.isArray(commitments) || commitments.length === 0) throw new Error('dkg: empty commitment vector');
  const pts = commitments.map((c) => decodePoint(unb64u(c)));
  const hdr = new Uint8Array(4);
  new DataView(hdr.buffer).setUint32(0, pts.length, false);
  return { c0: pts[0]!, bytes: concat(hdr, ...pts.map((p) => p.toRawBytes())) };
}

function randomScalar(): bigint {
  return bytesToScalar(ed25519.utils.randomPrivateKey());
}

/** Evaluate f(x) = Σ_j coeffs[j]·x^j via Horner (scalars). */
function evalPoly(coeffs: bigint[], x: bigint): bigint {
  let acc = 0n;
  for (let j = coeffs.length - 1; j >= 0; j--) acc = mod(acc * x + coeffs[j]!);
  return acc;
}

/**
 * Pedersen-VSS check: g^{share} == Π_k commitments[k]^{atId^k}. Returns true iff the scalar `share`
 * is a valid evaluation at `atId` of the polynomial the `commitments` commit to. Shared by
 * `dkgVerifyShare` and `dkgVerifyComplaint` so detection and blame use the SAME predicate.
 */
function vssCheck(share: bigint, commitments: string[], atId: ParticipantId): boolean {
  if (commitments.length === 0) return false;
  const lhs = mulBase(share);
  let rhs = P.ZERO;
  const x = BigInt(atId);
  let xk = 1n; // x^0
  for (const cB of commitments) {
    rhs = rhs.add(mulPoint(decodePoint(unb64u(cB)), xk));
    xk = mod(xk * x);
  }
  return lhs.equals(rhs);
}

// ---- domain-separated proof-of-possession challenge ---------------------------------------------

/**
 * PoP challenge domain separator for the DKG. DISTINCT from frost.ts's H1..H5 separators
 * ("rho"/"nonce"/"msg"/"com") so a PoP hash can never collide with a signing hash. Reuses the same
 * ciphersuite context string (`FROST-ED25519-SHA512-v1`).
 *
 *   c_i = HashToScalar( CONTEXT_STRING ‖ "dkg-pop" ‖ sessionId ‖ SerializeScalar(identifier)
 *                        ‖ SerializeElement(commitment_0) ‖ SerializeElement(R) )
 *
 * where commitment_0 = g^{a_i0} (the committed constant term) and R = k·B is the PoP's nonce
 * commitment. Binding `identifier` prevents a PoP being replayed under another participant's id;
 * binding `sessionId` prevents it being replayed into another DKG run.
 */
const DKG_POP_DST = utf8('dkg-pop');
const CTX = utf8(CONTEXT_STRING);

function dkgPopChallenge(
  sessionId: Uint8Array,
  identifier: ParticipantId,
  cv: CommitVec,
  R: InstanceType<typeof P>,
): bigint {
  return hashToScalar(
    concat(
      CTX,
      DKG_POP_DST,
      sessionId,
      scalarToBytes(BigInt(identifier)),
      cv.bytes,
      R.toRawBytes(),
    ),
  );
}

// ---- non-repudiable round-2 share signatures ----------------------------------------------------

/**
 * A round-2 share is SIGNED by its sender with a Schnorr signature under the sender's VSS constant-term
 * key C_0 = g^{a_i0} — the SAME key the round-1 proof-of-possession already proved the sender holds, so
 * no separate identity key is introduced and the verifier already has C_0 in the broadcast package. The
 * signature binds (sessionId, senderId, recipientId, the share bytes, C_0); binding senderId+recipientId
 * stops a signed share being re-presented as from/to a different party, and binding sessionId stops it
 * being replayed into another DKG run. Because only the holder of a_i0 can produce a valid signature
 * under C_0, the share is NON-REPUDIABLE: the sender cannot later deny having sent exactly these bytes.
 *
 * DISTINCT domain separators from the PoP ("dkg-pop") and the signing hashes (H1..H5) so a share-sig
 * hash can never collide with any other hash in the suite. The signature is serialized as
 * b64u( R_s(32) ‖ SerializeScalar(s)(32) ) = 64 bytes.
 */
const DKG_SHARE_DST = utf8('dkg-share');
const DKG_SHARE_NONCE_DST = utf8('dkg-share-nonce');

function dkgShareChallenge(
  sessionId: Uint8Array,
  from: ParticipantId,
  to: ParticipantId,
  shareBytes: Uint8Array,
  cv: CommitVec,
  Rs: InstanceType<typeof P>,
): bigint {
  return hashToScalar(
    concat(
      CTX,
      DKG_SHARE_DST,
      sessionId,
      scalarToBytes(BigInt(from)),
      scalarToBytes(BigInt(to)),
      shareBytes,
      cv.bytes,
      Rs.toRawBytes(),
    ),
  );
}

/**
 * Deterministic per-share nonce derived from the secret a_0 and the full share binding. Deterministic
 * so a run is reproducible, and UNIQUE per (session, from, to, share) so the nonce is never reused
 * across two different shares signed by the same a_0 (nonce reuse would leak a_0).
 */
function dkgShareNonce(
  a0: bigint,
  sessionId: Uint8Array,
  from: ParticipantId,
  to: ParticipantId,
  shareBytes: Uint8Array,
  cv: CommitVec,
): bigint {
  return hashToScalar(
    concat(
      CTX,
      DKG_SHARE_NONCE_DST,
      scalarToBytes(a0),
      sessionId,
      scalarToBytes(BigInt(from)),
      scalarToBytes(BigInt(to)),
      shareBytes,
      cv.bytes,
    ),
  );
}

/** Produce the sender's Schnorr signature over a share. Returns b64u(R_s ‖ s). */
function signShareScalar(
  a0: bigint,
  cv: CommitVec,
  sessionId: Uint8Array,
  from: ParticipantId,
  to: ParticipantId,
  shareBytes: Uint8Array,
): string {
  const k = dkgShareNonce(a0, sessionId, from, to, shareBytes, cv);
  const Rs = mulBase(k);
  const e = dkgShareChallenge(sessionId, from, to, shareBytes, cv, Rs);
  const s = mod(k + mod(a0 * e));
  return b64u(concat(Rs.toRawBytes(), scalarToBytes(s)));
}

/** Verify a share signature `sig` against the sender's constant-term commitment C_0. Never throws. */
function verifyShareSig(
  sig: string,
  sessionId: Uint8Array,
  from: ParticipantId,
  to: ParticipantId,
  shareBytes: Uint8Array,
  cv: CommitVec,
): boolean {
  try {
    const raw = unb64u(sig);
    if (raw.length !== 64) return false;
    const Rs = decodePoint(raw.subarray(0, 32));
    const s = bytesToScalar(raw.subarray(32, 64));
    const e = dkgShareChallenge(sessionId, from, to, shareBytes, cv, Rs);
    // s·B == R_s + e·C_0
    return mulBase(s).equals(Rs.add(mulPoint(cv.c0, e)));
  } catch {
    return false;
  }
}

/** Verify a share signature given the SENDER's broadcast round-1 package (extracts C_0). Never throws. */
function verifyShareSigAgainstPackage(
  sig: string | undefined,
  sessionId: Uint8Array,
  from: ParticipantId,
  to: ParticipantId,
  shareBytes: Uint8Array,
  senderPackage: DkgRound1Package,
): boolean {
  try {
    if (typeof sig !== 'string' || senderPackage.coefficientCommitments.length === 0) return false;
    const cv = commitVecOf(senderPackage.coefficientCommitments);
    return verifyShareSig(sig, sessionId, from, to, shareBytes, cv);
  } catch {
    return false;
  }
}

/**
 * Sign the share `shareBytes` this participant is sending to `to`, as the sender's non-repudiable
 * token. Exposed so a caller (or the accused, during a rebuttal) can re-produce the exact signature
 * `dkgRound2` would attach for a given recipient. Uses the sender's retained secret a_0 and its own
 * broadcast C_0; `state.sessionId` and `state.identifier` fix the rest of the binding.
 */
export function dkgSignShare(state: DkgParticipantState, to: ParticipantId, shareBytes: Uint8Array): string {
  const a0 = bytesToScalar(state.coefficients[0]!);
  const cv = commitVecOf(state.package.coefficientCommitments);
  return signShareScalar(a0, cv, state.sessionId, state.identifier, to, shareBytes);
}

// ---- public types -------------------------------------------------------------------------------

/** A Schnorr proof of knowledge of the constant term a_i0 (R = k·B, mu = k + a_i0·c). */
export interface DkgProofOfKnowledge {
  /** b64u of R = k·B (the PoP nonce commitment). */
  R: string;
  /** b64u of SerializeScalar(mu), mu = k + a_i0·c. */
  mu: string;
}

/** A participant's PUBLIC round-1 broadcast package (VSS commitments + PoP). Safe to broadcast. */
export interface DkgRound1Package {
  identifier: ParticipantId;
  /** b64u of the DKG session id this package is bound to (anti-replay). */
  sessionId: string;
  /** b64u VSS commitments [g^{a_i0}, …, g^{a_i(t-1)}]; index 0 commits the constant term a_i0. */
  coefficientCommitments: string[];
  proofOfKnowledge: DkgProofOfKnowledge;
}

/**
 * A participant's RETAINED SECRET state after round 1 — an opaque handle holding the secret
 * polynomial. Never broadcast; `coefficients[0]` is this participant's contribution to the group
 * secret.
 */
export interface DkgParticipantState {
  identifier: ParticipantId;
  t: number;
  n: number;
  /** The DKG session id this run is bound to (raw 32-ish bytes, caller-supplied). */
  readonly sessionId: Uint8Array;
  /** SECRET degree-(t-1) polynomial coefficients a_i0…a_i(t-1) (32-byte LE scalars). */
  readonly coefficients: Uint8Array[];
  /** This participant's own public round-1 package (so callers needn't recompute it). */
  package: DkgRound1Package;
}

export interface DkgRound1Result {
  package: DkgRound1Package;
  state: DkgParticipantState;
}

/** A secret share this participant sends to participant `to`: f_from(to). Deliver PRIVATELY. */
export interface DkgShareToSend {
  from: ParticipantId;
  to: ParticipantId;
  /** b64u of the DKG session id this share is bound to (anti-replay). */
  sessionId: string;
  /** f_from(to) as 32-byte LE scalar. SECRET. */
  share: Uint8Array;
  /**
   * The sender's NON-REPUDIABLE Schnorr signature over this share under the sender's VSS key C_0,
   * binding (sessionId, from, to, share, C_0). b64u(R_s ‖ s), 64 bytes. The sender cannot later deny it.
   */
  sig: string;
}

/** A secret share RECEIVED from participant `from`: f_from(myIdentifier). */
export interface DkgReceivedShare {
  from: ParticipantId;
  /** b64u of the DKG session id this share is bound to (anti-replay). */
  sessionId: string;
  /** f_from(myIdentifier) as 32-byte LE scalar. */
  share: Uint8Array;
  /** The sender's non-repudiable signature over the share (see `DkgShareToSend.sig`). */
  sig?: string;
}

/**
 * The minimal shape `dkgVerifyShare` needs to verify a received share: the sender id, the share bytes,
 * and the sender's non-repudiable signature. Both `DkgShareToSend` and `DkgReceivedShare` satisfy it.
 */
export interface DkgSignedShare {
  from: ParticipantId;
  share: Uint8Array;
  /** The sender's non-repudiable signature over the share; REQUIRED by `dkgVerifyShare`. */
  sig?: string;
}

/**
 * A PUBLIC, broadcast complaint: participant `accuser` reveals the share it received from `accused`
 * so any party can recompute g^{share} against the accused's broadcast VSS commitments and confirm
 * (or refute) that the share is bad. Revealing one evaluation point is the standard Pedersen-DKG
 * complaint mechanism. Broadcast over the authenticated channel.
 */
export interface DkgComplaint {
  /** The dealer being accused of sending a bad share. */
  accused: ParticipantId;
  /** The participant that received the bad share (== the VSS evaluation point of the revealed share). */
  accuser: ParticipantId;
  /** b64u of the DKG session id this complaint is scoped to (must match the accused's package). */
  sessionId: string;
  /** b64u of the revealed share f_accused(accuser) as 32-byte LE scalar. */
  revealedShare: string;
  /**
   * The ACCUSED's non-repudiable signature over the revealed share (`DkgShareToSend.sig`). A complaint
   * is only admissible if this verifies under the accused's broadcast C_0 — so fabricated bytes cannot
   * frame an honest party, and a justified complaint carries the accused's own signature over bad bytes.
   */
  shareSig: string;
}

/** The verdict of adjudicating a complaint. */
export interface DkgComplaintVerdict {
  /** True iff the revealed share is validly signed by the accused AND fails VSS against its commitments. */
  justified: boolean;
  /** The participant to remove from the qualified set (present only when `justified` — the accused). */
  disqualify?: ParticipantId;
  /** The party at fault for a NON-justified complaint (a false or inadmissible accusation): the accuser. */
  atFault?: ParticipantId;
  /** Human-readable adjudication reason. */
  reason: string;
}

/**
 * The accused's REBUTTAL to a complaint: it re-presents the share it actually signed+sent to the
 * complaint's recipient, with its signature, so `dkgResolveBlame` can test "can the accused produce a
 * validly-signed, VSS-correct share for this recipient?" against a non-receipt / fabrication claim.
 * Broadcast over the authenticated channel.
 */
export interface DkgRebuttal {
  accused: ParticipantId;
  accuser: ParticipantId;
  /** b64u of the DKG session id (must match the complaint's). */
  sessionId: string;
  /** b64u of f_accused(accuser) as the accused actually computed it (32-byte LE scalar). */
  presentedShare: string;
  /** The accused's non-repudiable signature over `presentedShare`. */
  shareSig: string;
}

/** The adjudication of a complaint (optionally with the accused's rebuttal): who is guilty, and why. */
export interface DkgBlameResolution {
  /** The party conclusively at fault. */
  guilty: ParticipantId;
  reason: string;
}

/** A participant's verifying share (s_j·B). */
export interface DkgVerifyingShare {
  identifier: ParticipantId;
  /** s_j·B (32-byte point). */
  publicKey: Uint8Array;
}

/** The public key material every finalized participant agrees on. */
export interface DkgPublicKeyPackage {
  /** Y = f(0)·B = Σ_ℓ g^{a_ℓ0} over the qualified set (32-byte point). */
  groupPublicKey: Uint8Array;
  /** Group VSS commitment coefficients [Φ_0…Φ_{t-1}], Φ_k = Σ_ℓ g^{a_ℓk} over qualified; index 0 is the group key. */
  groupCommitment: Uint8Array[];
  /** Verifying share s_j·B for every QUALIFIED participant j. */
  verifyingShares: DkgVerifyingShare[];
}

/** The finalized per-participant key material — a drop-in for the trusted-dealer keygen output. */
export interface DkgKeyPackage {
  identifier: ParticipantId;
  /** s_i = Σ_{ℓ∈qualified} f_ℓ(i): this participant's Shamir signing share (32-byte LE). == FrostParticipantShare.share. */
  signingShare: Uint8Array;
  /** Y = f(0)·B over the qualified set (32-byte point). */
  groupPublicKey: Uint8Array;
  /** s_i·B (32-byte point). == FrostParticipantShare.publicKey. */
  verifyingShare: Uint8Array;
  publicKeyPackage: DkgPublicKeyPackage;
}

export interface DkgRound1Opts {
  /**
   * Fixed polynomial coefficients a_0…a_{t-1} (each 32-byte LE), for deterministic tests. Must have
   * length t. Random per run if omitted. a_0 is this participant's contribution to the group secret.
   */
  coefficients?: Uint8Array[];
  /** Fixed PoP nonce k (32-byte LE), for deterministic tests. Random if omitted. */
  popNonce?: Uint8Array;
}

// ---- round 1: sample polynomial, commit, prove possession ---------------------------------------

/**
 * ROUND 1. Participant `identifier` samples a degree-(t−1) secret polynomial f_i, publishes VSS
 * commitments C_i = [g^{a_i0}, …, g^{a_i(t-1)}] to its coefficients, and a Schnorr proof of possession
 * of the constant term a_i0 bound to the run's `sessionId`. Returns the PUBLIC `package` (broadcast
 * over an authenticated channel) and the SECRET `state` (the retained polynomial handle — keep
 * private). `sessionId` is a caller-supplied ceremony identifier (e.g. a random 32-byte value) that
 * MUST be the same for every participant in one DKG run and different across runs.
 */
export function dkgRound1(
  identifier: ParticipantId,
  t: number,
  n: number,
  sessionId: Uint8Array,
  opts: DkgRound1Opts = {},
): DkgRound1Result {
  if (!Number.isInteger(identifier) || identifier <= 0) {
    throw new Error('dkgRound1: identifier must be a positive integer');
  }
  if (!Number.isInteger(t) || !Number.isInteger(n) || t < 1 || n < t) {
    throw new Error(`dkgRound1: need 1 <= t <= n (got t=${t}, n=${n})`);
  }
  if (!(sessionId instanceof Uint8Array) || sessionId.length === 0) {
    throw new Error('dkgRound1: sessionId must be a non-empty byte string');
  }

  // Secret polynomial coefficients a_0…a_{t-1}.
  const coeffBytes: Uint8Array[] = [];
  const coeffs: bigint[] = [];
  if (opts.coefficients) {
    if (opts.coefficients.length !== t) {
      throw new Error(`dkgRound1: coefficients.length must equal t (${t})`);
    }
    for (const c of opts.coefficients) {
      const s = bytesToScalar(c);
      coeffs.push(s);
      coeffBytes.push(scalarToBytes(s));
    }
  } else {
    for (let j = 0; j < t; j++) {
      const s = randomScalar();
      coeffs.push(s);
      coeffBytes.push(scalarToBytes(s));
    }
  }

  // VSS commitments g^{a_j}.
  const commitmentPoints = coeffs.map((a) => mulBase(a));
  const coefficientCommitments = commitmentPoints.map((pt) => b64u(pt.toRawBytes()));

  // Schnorr proof of possession of a_0: R = k·B, c = H(sessionId, id, C_0, R), mu = k + a_0·c.
  const a0 = coeffs[0]!;
  const cv = commitVecOf(coefficientCommitments);
  const k = opts.popNonce ? bytesToScalar(opts.popNonce) : randomScalar();
  const R = mulBase(k);
  const c = dkgPopChallenge(sessionId, identifier, cv, R);
  const mu = mod(k + mod(a0 * c));

  const pkg: DkgRound1Package = {
    identifier,
    sessionId: b64u(sessionId),
    coefficientCommitments,
    proofOfKnowledge: { R: b64u(R.toRawBytes()), mu: b64u(scalarToBytes(mu)) },
  };

  return {
    package: pkg,
    state: { identifier, t, n, sessionId: Uint8Array.from(sessionId), coefficients: coeffBytes, package: pkg },
  };
}

/**
 * Verify a peer's round-1 proof of possession against the constant-term commitment in the SAME
 * package AND the expected `sessionId`: the package's stamped session must match, and the recomputed
 * challenge c = H(sessionId, fromIdentifier, C_0, R) must satisfy mu·B == R + c·C_0. Never throws.
 * `fromIdentifier` and `sessionId` are both bound into the challenge, so a PoP minted under a
 * different id OR a different DKG session is rejected (anti-replay).
 */
export function dkgVerifyRound1(
  fromIdentifier: ParticipantId,
  pkg: DkgRound1Package,
  sessionId: Uint8Array,
): boolean {
  try {
    if (pkg.sessionId !== b64u(sessionId)) return false;
    if (pkg.coefficientCommitments.length === 0) return false;
    const cv = commitVecOf(pkg.coefficientCommitments);
    const commit0 = cv.c0;
    const R = decodePoint(unb64u(pkg.proofOfKnowledge.R));
    const mu = bytesToScalar(unb64u(pkg.proofOfKnowledge.mu));
    const c = dkgPopChallenge(sessionId, fromIdentifier, cv, R);
    const lhs = mulBase(mu);
    const rhs = R.add(mulPoint(commit0, c));
    return lhs.equals(rhs);
  } catch {
    return false;
  }
}

// ---- round 2: secret-share distribution ---------------------------------------------------------

/**
 * ROUND 2. This participant computes the secret share f_i(j) it must send to EACH OTHER participant
 * j (its own f_i(i) is retained and folded in at finalize). The participant set is taken from the
 * identifiers in `allRound1Packages`, which MUST include this participant's own package. Each returned
 * share is SECRET and must be delivered to `to` over a private, authenticated channel. Each share is
 * stamped with the run's session id (anti-replay) AND SIGNED by the sender under its VSS key C_0, so
 * the share is non-repudiable (`DkgShareToSend.sig`); a mismatched-session package in the set is rejected.
 */
export function dkgRound2(state: DkgParticipantState, allRound1Packages: DkgRound1Package[]): DkgShareToSend[] {
  const ids = allRound1Packages.map((p) => p.identifier);
  if (new Set(ids).size !== ids.length) throw new Error('dkgRound2: duplicate identifiers in round-1 packages');
  if (!ids.includes(state.identifier)) throw new Error('dkgRound2: my own round-1 package is missing');
  const sidB64 = b64u(state.sessionId);
  for (const p of allRound1Packages) {
    if (p.sessionId !== sidB64) {
      throw new Error(`dkgRound2: participant ${p.identifier} round-1 package is from a different session`);
    }
  }

  const coeffs = state.coefficients.map((c) => bytesToScalar(c));
  const a0 = coeffs[0]!;
  const cv = commitVecOf(state.package.coefficientCommitments);
  const out: DkgShareToSend[] = [];
  for (const j of ids) {
    if (j === state.identifier) continue;
    const share = scalarToBytes(evalPoly(coeffs, BigInt(j)));
    const sig = signShareScalar(a0, cv, state.sessionId, state.identifier, j, share);
    out.push({ from: state.identifier, to: j, sessionId: sidB64, share, sig });
  }
  return out;
}

/**
 * Verify a received secret share against the sender's published round-1 package (reject a cheating
 * dealer's bad share). The received share MUST now carry the sender's non-repudiable signature
 * (`received.sig`): three checks must all pass —
 *   1. the sender's package is a valid round-1 package for THIS session (`dkgVerifyRound1`) — binds the
 *      commitments to the session, so a share+package pair captured from another DKG run is rejected;
 *   2. the sender's SIGNATURE over the share verifies under the package's C_0 and the binding
 *      (sessionId, from, myIdentifier, share) — so the recipient can later prove the sender sent exactly
 *      these bytes, and a share with no/invalid signature is rejected outright;
 *   3. the Pedersen-VSS check g^{share} == Π_k C_k^{(myIdentifier)^k}.
 * `received` is the signed share object from `dkgRound2` (or a `DkgReceivedShare`). Never throws.
 */
export function dkgVerifyShare(
  received: DkgSignedShare,
  senderPackage: DkgRound1Package,
  myIdentifier: ParticipantId,
  sessionId: Uint8Array,
): boolean {
  try {
    if (!received || !(received.share instanceof Uint8Array)) return false;
    // Session + authenticity binding: the sender's package (and thus its VSS commitments) must be a
    // valid round-1 package under THIS session. A package minted for another session fails here.
    if (!dkgVerifyRound1(senderPackage.identifier, senderPackage, sessionId)) return false;
    // Non-repudiation: the sender must have signed exactly these bytes under its C_0 for this recipient.
    if (!verifyShareSigAgainstPackage(received.sig, sessionId, received.from, myIdentifier, received.share, senderPackage)) {
      return false;
    }
    return vssCheck(bytesToScalar(received.share), senderPackage.coefficientCommitments, myIdentifier);
  } catch {
    return false;
  }
}

// ---- complaint / blame round --------------------------------------------------------------------

/**
 * Build a complaint. Called by `accuser` when the share it received from `accused` fails
 * `dkgVerifyShare`: it REVEALS the received share AND the accused's non-repudiable signature over it
 * (`shareSig`), so any party can confirm (1) the share was genuinely signed by the accused under its
 * broadcast C_0 and (2) it fails VSS. `senderCommitments` is accepted for symmetry (the commitments the
 * accuser checked against); the authoritative commitments used at adjudication are taken from the
 * broadcast round-1 packages, not from the complaint — so a complaint cannot lie about them. The
 * signature is likewise re-checked against the accused's broadcast C_0, so the accuser cannot lie about
 * who signed the share. `shareSig` is the `DkgShareToSend.sig` the accused actually sent with the share.
 */
export function dkgFileComplaint(params: {
  accused: ParticipantId;
  accuser: ParticipantId;
  receivedShare: Uint8Array;
  /** The accused's non-repudiable signature over `receivedShare` (from `DkgShareToSend.sig`). */
  shareSig: string;
  senderCommitments: string[];
  sessionId: Uint8Array;
}): DkgComplaint {
  const { accused, accuser, receivedShare, shareSig, sessionId } = params;
  void params.senderCommitments;
  if (!Number.isInteger(accused) || accused <= 0) throw new Error('dkgFileComplaint: accused must be a positive integer');
  if (!Number.isInteger(accuser) || accuser <= 0) throw new Error('dkgFileComplaint: accuser must be a positive integer');
  if (accused === accuser) throw new Error('dkgFileComplaint: cannot file a complaint against yourself');
  if (typeof shareSig !== 'string' || shareSig.length === 0) {
    throw new Error('dkgFileComplaint: shareSig (the accused-signed share) is required');
  }
  if (!(sessionId instanceof Uint8Array) || sessionId.length === 0) {
    throw new Error('dkgFileComplaint: sessionId must be a non-empty byte string');
  }
  return {
    accused,
    accuser,
    sessionId: b64u(sessionId),
    revealedShare: b64u(scalarToBytes(bytesToScalar(receivedShare))),
    shareSig,
  };
}

/**
 * Adjudicate a complaint INDEPENDENTLY. Looks up the accused's broadcast round-1 package, confirms the
 * complaint is scoped to the same session, requires the revealed share to be VALIDLY SIGNED BY THE
 * ACCUSED (under the accused's broadcast C_0), and recomputes the Pedersen-VSS check on the revealed
 * share. Verdicts:
 *   • accused-signed AND fails VSS  → JUSTIFIED (disqualify the accused — non-repudiable misbehavior);
 *   • accused-signed AND passes VSS → NOT justified, `atFault = accuser` (a FALSE accusation);
 *   • NOT validly signed by accused → NOT justified, `atFault = accuser` (INADMISSIBLE — fabricated
 *     bytes cannot frame an honest party, since only the accused can sign under its C_0).
 * Never throws — a malformed complaint or a missing/mismatched package is reported, not justified. For
 * the richer accused-vs-accuser adjudication (with the accused's rebuttal to a non-receipt claim), see
 * `dkgResolveBlame`.
 */
export function dkgVerifyComplaint(complaint: DkgComplaint, round1Packages: DkgRound1Package[]): DkgComplaintVerdict {
  try {
    const accusedPkg = round1Packages.find((p) => p.identifier === complaint.accused);
    if (!accusedPkg) {
      return { justified: false, reason: `accused ${complaint.accused} has no round-1 package to adjudicate against` };
    }
    // Anti-replay: the complaint must name the same session the accused's package was minted for.
    if (accusedPkg.sessionId !== complaint.sessionId) {
      return { justified: false, reason: 'complaint sessionId does not match the accused round-1 package session' };
    }
    const sidBytes = unb64u(complaint.sessionId);
    const shareBytes = unb64u(complaint.revealedShare);
    // Admissibility: only a share the ACCUSED actually signed can convict — a griefer cannot frame.
    if (!verifyShareSigAgainstPackage(complaint.shareSig, sidBytes, complaint.accused, complaint.accuser, shareBytes, accusedPkg)) {
      return {
        justified: false,
        atFault: complaint.accuser,
        reason: 'revealed share is not validly signed by the accused — inadmissible (cannot frame an honest party)',
      };
    }
    const valid = vssCheck(bytesToScalar(shareBytes), accusedPkg.coefficientCommitments, complaint.accuser);
    if (valid) {
      return {
        justified: false,
        atFault: complaint.accuser,
        reason: 'accused-signed share is VALID against the accused commitments — false accusation',
      };
    }
    return {
      justified: true,
      disqualify: complaint.accused,
      reason: 'accused non-repudiably signed a share that FAILS VSS against its broadcast commitments',
    };
  } catch {
    return { justified: false, reason: 'malformed complaint' };
  }
}

/**
 * The accused's REBUTTAL: re-present the share it actually signed+sent to the complaint's recipient.
 * Recomputes f_accused(accuser) from the accused's retained polynomial and re-signs it under C_0 (the
 * same bytes `dkgRound2` produced), so `dkgResolveBlame` can weigh it against a non-receipt claim.
 * `myRound2State` is the accused's retained round-1 state.
 */
export function dkgRebut(accused: ParticipantId, complaint: DkgComplaint, myRound2State: DkgParticipantState): DkgRebuttal {
  if (myRound2State.identifier !== accused) throw new Error('dkgRebut: myRound2State is not the accused');
  if (complaint.accused !== accused) throw new Error('dkgRebut: complaint does not name this accused');
  if (b64u(myRound2State.sessionId) !== complaint.sessionId) {
    throw new Error('dkgRebut: complaint is scoped to a different session than my state');
  }
  const coeffs = myRound2State.coefficients.map((c) => bytesToScalar(c));
  const share = scalarToBytes(evalPoly(coeffs, BigInt(complaint.accuser)));
  const shareSig = dkgSignShare(myRound2State, complaint.accuser, share);
  return {
    accused,
    accuser: complaint.accuser,
    sessionId: complaint.sessionId,
    presentedShare: b64u(share),
    shareSig,
  };
}

/**
 * Adjudicate a complaint, optionally with the accused's rebuttal, to a single guilty party — from the
 * SIGNATURES and VSS alone. Resolution:
 *   • accused has no round-1 package → `guilty = accused` (nothing to defend with);
 *   • the complaint's share is validly signed by the accused:
 *       – fails VSS → `guilty = accused` (non-repudiable: it signed a bad share — no rebuttal saves it);
 *       – passes VSS → `guilty = accuser` (false accusation about a good, signed share);
 *   • the complaint's share is NOT validly signed by the accused (a non-receipt / fabrication claim) →
 *     `guilty = accuser`: fabricated bytes cannot convict, and if the accused supplies a rebuttal whose
 *     presented share IS validly signed by the accused and passes VSS, that positively refutes the claim.
 *     Only a (rare) inadmissible complaint WITH a rebuttal that the accused cannot validly produce
 *     (invalid signature or bad VSS on its own re-presented share) flips to `guilty = accused`.
 * Never throws. Note: a cheater who sends garbage WITHOUT a valid signature is rejected at receipt and
 * surfaces as a missing share at finalize, not as an attributable conviction here (see header caveats).
 */
export function dkgResolveBlame(
  complaint: DkgComplaint,
  rebuttal: DkgRebuttal | undefined,
  round1Packages: DkgRound1Package[],
): DkgBlameResolution {
  try {
    const accusedPkg = round1Packages.find((p) => p.identifier === complaint.accused);
    if (!accusedPkg) {
      return { guilty: complaint.accused, reason: `accused ${complaint.accused} has no round-1 package to defend with` };
    }
    if (accusedPkg.sessionId !== complaint.sessionId) {
      return { guilty: complaint.accuser, reason: 'complaint names a session the accused did not run — inadmissible' };
    }
    const sidBytes = unb64u(complaint.sessionId);
    const shareBytes = unb64u(complaint.revealedShare);
    const admissible = verifyShareSigAgainstPackage(
      complaint.shareSig,
      sidBytes,
      complaint.accused,
      complaint.accuser,
      shareBytes,
      accusedPkg,
    );
    if (admissible) {
      const valid = vssCheck(bytesToScalar(shareBytes), accusedPkg.coefficientCommitments, complaint.accuser);
      if (!valid) {
        return { guilty: complaint.accused, reason: 'accused non-repudiably signed a share that fails VSS' };
      }
      return { guilty: complaint.accuser, reason: 'accused-signed share is valid against its commitments — false accusation' };
    }
    // Inadmissible: the complaint carries no accused-signed bad share (non-receipt / fabrication claim).
    if (rebuttal && rebuttal.accused === complaint.accused && rebuttal.accuser === complaint.accuser && rebuttal.sessionId === complaint.sessionId) {
      const rShare = unb64u(rebuttal.presentedShare);
      const rebuttalValid =
        verifyShareSigAgainstPackage(rebuttal.shareSig, sidBytes, complaint.accused, complaint.accuser, rShare, accusedPkg) &&
        vssCheck(bytesToScalar(rShare), accusedPkg.coefficientCommitments, complaint.accuser);
      if (rebuttalValid) {
        return {
          guilty: complaint.accuser,
          reason: 'accused produced a validly-signed, VSS-correct share for the recipient — the non-receipt/fabrication complaint is refuted',
        };
      }
      return {
        guilty: complaint.accused,
        reason: 'accused could not present a validly-signed, VSS-correct share on rebuttal',
      };
    }
    return {
      guilty: complaint.accuser,
      reason: 'complaint carries no accused-signed share and the accused offered no rebuttal — inadmissible, cannot frame the accused',
    };
  } catch {
    return { guilty: complaint.accuser, reason: 'malformed complaint — inadmissible' };
  }
}

/**
 * Compute the QUALIFIED set: the participants that (a) have a round-1 package whose PoK verifies under
 * the run's session, and (b) are not disqualified by a resolved complaint. Each complaint is resolved
 * with `dkgResolveBlame` against any matching rebuttal in `rebuttals`, and a participant is dropped iff
 * a complaint resolves with THEM guilty AS THE ACCUSED DEALER. A complaint that resolves with the
 * ACCUSER guilty (a false accusation, or an inadmissible/non-receipt griefing complaint) removes NOBODY
 * — so a griefer can neither frame nor remove an honest party. The run's session is the session the
 * broadcast packages agree on (plurality); a package on a divergent session (replay / equivocation) does
 * not qualify. Order-independent; returns the surviving ids sorted ascending.
 */
export function dkgQualifiedSet(
  participants: ParticipantId[],
  complaints: DkgComplaint[],
  round1Packages: DkgRound1Package[],
  rebuttals: DkgRebuttal[] = [],
): ParticipantId[] {
  const pkgById = new Map(round1Packages.map((p) => [p.identifier, p]));

  // The run's session = the sessionId the broadcast packages agree on (plurality).
  const sessionCounts = new Map<string, number>();
  for (const p of round1Packages) sessionCounts.set(p.sessionId, (sessionCounts.get(p.sessionId) ?? 0) + 1);
  let runSession = '';
  let best = -1;
  for (const [s, c] of sessionCounts) {
    if (c > best) {
      best = c;
      runSession = s;
    }
  }

  const qualified = new Set<ParticipantId>();
  for (const p of participants) {
    const pkg = pkgById.get(p);
    if (!pkg) continue; // no round-1 package → not qualified
    if (pkg.sessionId !== runSession) continue; // divergent session → not qualified
    let sid: Uint8Array;
    try {
      sid = unb64u(pkg.sessionId);
    } catch {
      continue;
    }
    if (dkgVerifyRound1(p, pkg, sid)) qualified.add(p);
  }

  // Drop participants whose blame resolves with THEM guilty as the accused dealer (a resolved-guilty
  // accuser — a false or inadmissible accusation — removes nobody).
  for (const c of complaints) {
    const reb = rebuttals.find((r) => r.accused === c.accused && r.accuser === c.accuser && r.sessionId === c.sessionId);
    const res = dkgResolveBlame(c, reb, round1Packages);
    if (res.guilty === c.accused) qualified.delete(res.guilty);
  }

  return [...qualified].sort((a, b) => a - b);
}

// ---- echo-broadcast / agreement round -----------------------------------------------------------

/**
 * A party's ECHO: a commitment (hash) over its OWN view of the DKG transcript — the round-1 packages
 * it received, the complaints it saw, and the qualified set it derived. Broadcast over the authenticated
 * channel AFTER the blame round and BEFORE finalize.
 *
 * WHY (Gennaro-style agreement). Without an agreement round, an equivocating dealer or a network
 * adversary can show different honest parties different round-1 packages / complaints, so they derive
 * DIFFERENT qualified sets and finalize to DIFFERENT (inconsistent) group keys without anyone noticing.
 * Requiring every qualified party to echo an IDENTICAL transcript digest before finalizing closes that
 * split: a divergent view produces a divergent digest, `dkgCheckEchoes` sees the disagreement, and
 * `dkgFinalize` ABORTS rather than committing to a key over a transcript the parties did not all agree on.
 */
export interface DkgEcho {
  identifier: ParticipantId;
  /** b64u of the DKG session id this echo is bound to (anti-replay / cross-run). */
  sessionId: string;
  /** b64u sha256 over the canonical, order-independent transcript (see `dkgTranscriptDigest`). */
  transcriptDigest: string;
}

/** Deterministic, order-independent per-package digest (binds every field of a round-1 package). */
function round1PackageDigest(p: DkgRound1Package): string {
  return hashCanonical({
    identifier: p.identifier,
    sessionId: p.sessionId,
    coefficientCommitments: p.coefficientCommitments,
    proofOfKnowledge: { R: p.proofOfKnowledge.R, mu: p.proofOfKnowledge.mu },
  });
}

/** Deterministic, order-independent per-complaint digest (binds every field of a complaint). */
function complaintDigest(c: DkgComplaint): string {
  return hashCanonical({
    accused: c.accused,
    accuser: c.accuser,
    sessionId: c.sessionId,
    revealedShare: c.revealedShare,
    shareSig: c.shareSig,
  });
}

/**
 * The CANONICAL, order-independent transcript digest a party commits to in its echo: a hash over the
 * SORTED set of round-1 package digests, the SORTED set of complaint digests, the SORTED qualified set,
 * and the session id. Sorting makes it independent of message-arrival order, so two honest parties that
 * saw the SAME transcript (in any order) produce the SAME digest, while any divergence — a different
 * package, a dropped/extra complaint, or a different qualified set — produces a different digest.
 */
export function dkgTranscriptDigest(args: {
  round1Packages: DkgRound1Package[];
  complaints: DkgComplaint[];
  qualified: ParticipantId[];
  sessionId: Uint8Array;
}): string {
  const round1 = args.round1Packages.map(round1PackageDigest).sort();
  const complaints = args.complaints.map(complaintDigest).sort();
  const qualified = [...args.qualified].sort((a, b) => a - b);
  return hashCanonical({ sessionId: b64u(args.sessionId), round1, complaints, qualified });
}

/**
 * Build this party's echo over its transcript view. A party broadcasts this after the blame round; the
 * finalizer requires every qualified party's echo to carry an identical `transcriptDigest`.
 */
export function dkgEcho(args: {
  identifier: ParticipantId;
  round1Packages: DkgRound1Package[];
  complaints: DkgComplaint[];
  qualified: ParticipantId[];
  sessionId: Uint8Array;
}): DkgEcho {
  return {
    identifier: args.identifier,
    sessionId: b64u(args.sessionId),
    transcriptDigest: dkgTranscriptDigest({
      round1Packages: args.round1Packages,
      complaints: args.complaints,
      qualified: args.qualified,
      sessionId: args.sessionId,
    }),
  };
}

/** The outcome of the echo-agreement check. */
export interface DkgEchoAgreement {
  /** True iff every qualified party echoed exactly one same-session echo and ALL digests are identical. */
  agreed: boolean;
  /** The agreed transcript digest (present only when `agreed`). */
  digest?: string;
  /** Why agreement failed (a missing echo, a cross-session echo, a duplicate, or a divergent digest). */
  reason?: string;
}

/**
 * Check the echo-broadcast round: EVERY qualified party must have contributed exactly one echo, all bound
 * to `sessionId`, all carrying the SAME `transcriptDigest`. Echoes from non-qualified parties are ignored.
 * Returns the agreed digest, or the reason agreement failed (a divergent digest signals equivocation — an
 * adversary split the honest parties onto different views). Never throws.
 */
export function dkgCheckEchoes(
  qualified: ParticipantId[],
  echoes: DkgEcho[],
  sessionId: Uint8Array,
): DkgEchoAgreement {
  try {
    const sidB64 = b64u(sessionId);
    const qSet = new Set(qualified);
    const byId = new Map<ParticipantId, DkgEcho>();
    for (const e of echoes) {
      if (!qSet.has(e.identifier)) continue; // a non-qualified party's echo does not count
      if (e.sessionId !== sidB64) {
        return { agreed: false, reason: `echo from ${e.identifier} is bound to a different session` };
      }
      if (byId.has(e.identifier)) {
        return { agreed: false, reason: `duplicate echo from qualified participant ${e.identifier}` };
      }
      byId.set(e.identifier, e);
    }
    let agreedDigest: string | undefined;
    for (const j of qSet) {
      const e = byId.get(j);
      if (!e) return { agreed: false, reason: `missing echo from qualified participant ${j}` };
      if (agreedDigest === undefined) {
        agreedDigest = e.transcriptDigest;
      } else if (e.transcriptDigest !== agreedDigest) {
        return {
          agreed: false,
          reason: `qualified participant ${j} echoed a DIFFERENT transcript (equivocation detected)`,
        };
      }
    }
    if (agreedDigest === undefined) return { agreed: false, reason: 'no qualified echoes to agree on' };
    return { agreed: true, digest: agreedDigest };
  } catch {
    return { agreed: false, reason: 'malformed echoes' };
  }
}

// ---- finalize -----------------------------------------------------------------------------------

/**
 * FINALIZE over the QUALIFIED set. Combine this participant's own polynomial with the shares received
 * from all QUALIFIED peers:
 *   signingShare  s_i = f_i(myIdentifier) + Σ_{j∈qualified, j≠i} receivedShares[j]   (= Σ_{ℓ∈qualified} f_ℓ(i))
 *   groupPublicKey Y  = Σ_{ℓ∈qualified} C_ℓ0                                          (= f(0)·B)
 *   verifyingShare    = s_i·B
 * plus the public-key package: group VSS coefficients Φ_k = Σ_{ℓ∈qualified} C_ℓk and every QUALIFIED
 * participant's verifying share Y_j = Σ_k Φ_k·j^k. `myState` is the retained round-1 handle;
 * `allCommitments` is every participant's round-1 package (including this one). `qualified` is the set
 * surviving the blame round (default: ALL participants in `allCommitments` — the honest, no-complaint
 * path, byte-identical to the pre-blame behavior). The finalizer must itself be qualified, and
 * |qualified| ≥ t. All packages/shares must name the SAME session as `myState` (anti-replay). The
 * output's `signingShare`/`groupPublicKey` are drop-in for `frostSign`.
 *
 * ECHO-BROADCAST AGREEMENT (opt-in via `agreement`). When `agreement.echoes` is supplied, finalize runs
 * the Gennaro-style agreement round BEFORE deriving any key: it recomputes its OWN transcript digest over
 * (`allCommitments`, `agreement.complaints`, the qualified set) and requires EVERY qualified party's echo
 * to carry that identical digest (`dkgCheckEchoes`). If any qualified party echoed a different transcript
 * — the signature of an equivocating dealer / network split — finalize ABORTS. Omitting `agreement`
 * preserves the exact pre-agreement behavior (byte-identical output), so existing callers are unaffected.
 */
export function dkgFinalize(
  myIdentifier: ParticipantId,
  myState: DkgParticipantState,
  receivedShares: DkgReceivedShare[],
  allCommitments: DkgRound1Package[],
  qualified?: ParticipantId[],
  agreement?: { echoes: DkgEcho[]; complaints?: DkgComplaint[] },
): DkgKeyPackage {
  if (myState.identifier !== myIdentifier) throw new Error('dkgFinalize: myState.identifier != myIdentifier');
  const ids = allCommitments.map((p) => p.identifier);
  if (new Set(ids).size !== ids.length) throw new Error('dkgFinalize: duplicate identifiers in commitments');
  if (!ids.includes(myIdentifier)) throw new Error('dkgFinalize: my own package is missing from allCommitments');

  // Session consistency (anti-replay): every package must name my run's session.
  const sidB64 = b64u(myState.sessionId);
  for (const p of allCommitments) {
    if (p.sessionId !== sidB64) {
      throw new Error(`dkgFinalize: participant ${p.identifier} round-1 package is from a different session`);
    }
  }

  // Qualified set defaults to all participants (honest, no-complaint path).
  const qset = (qualified ?? ids).filter((id) => ids.includes(id));
  const qSet = new Set(qset);
  if (!qSet.has(myIdentifier)) throw new Error('dkgFinalize: myIdentifier is not in the qualified set');
  if (qSet.size < myState.t) {
    throw new Error(`dkgFinalize: qualified set (${qSet.size}) is smaller than the threshold t=${myState.t}`);
  }

  const t = myState.t;
  for (const p of allCommitments) {
    if (!qSet.has(p.identifier)) continue; // a disqualified participant may be malformed; ignore it.
    if (p.coefficientCommitments.length !== t) {
      throw new Error(
        `dkgFinalize: participant ${p.identifier} committed to ${p.coefficientCommitments.length} coefficients, expected t=${t}`,
      );
    }
  }

  // ECHO-BROADCAST AGREEMENT ROUND (opt-in). Before deriving any key material, require every qualified
  // party to have echoed an IDENTICAL transcript (round-1 packages / complaints / qualified set). An
  // equivocating dealer or a network adversary that split honest parties onto different views yields a
  // divergent digest, which `dkgCheckEchoes` detects → we ABORT rather than finalize against a transcript
  // the parties did not all agree on (a Gennaro-style agreement break → inconsistent group keys).
  if (agreement?.echoes !== undefined) {
    const qsorted = [...qSet].sort((a, b) => a - b);
    const check = dkgCheckEchoes(qsorted, agreement.echoes, myState.sessionId);
    if (!check.agreed) {
      throw new Error(`dkgFinalize: echo-broadcast agreement failed — ${check.reason}`);
    }
    const myDigest = dkgTranscriptDigest({
      round1Packages: allCommitments,
      complaints: agreement.complaints ?? [],
      qualified: qsorted,
      sessionId: myState.sessionId,
    });
    if (check.digest !== myDigest) {
      throw new Error(
        'dkgFinalize: echo-broadcast agreement failed — my transcript view diverges from the agreed echo digest (equivocation)',
      );
    }
  }

  // Expect exactly one received share from every OTHER QUALIFIED participant; ignore the rest.
  const recvBy = new Map<ParticipantId, Uint8Array>();
  for (const r of receivedShares) {
    if (r.from === myIdentifier) continue;
    if (!qSet.has(r.from)) continue; // drop shares from disqualified senders
    if (r.sessionId !== sidB64) {
      throw new Error(`dkgFinalize: received share from ${r.from} is from a different session`);
    }
    if (recvBy.has(r.from)) throw new Error(`dkgFinalize: duplicate received share from ${r.from}`);
    recvBy.set(r.from, r.share);
  }
  for (const j of qset) {
    if (j === myIdentifier) continue;
    if (!recvBy.has(j)) throw new Error(`dkgFinalize: missing received share from qualified participant ${j}`);
  }

  // signingShare s_i = f_i(i) + Σ_{j∈qualified, j≠i} f_j(i).
  const myCoeffs = myState.coefficients.map((c) => bytesToScalar(c));
  let s = evalPoly(myCoeffs, BigInt(myIdentifier));
  for (const [, share] of recvBy) s = mod(s + bytesToScalar(share));
  const signingShare = scalarToBytes(s);

  // Group VSS coefficients Φ_k = Σ_{ℓ∈qualified} C_ℓk (points), index 0 is the group public key.
  const groupCoeffPoints: InstanceType<typeof P>[] = [];
  for (let kIdx = 0; kIdx < t; kIdx++) {
    let acc = P.ZERO;
    for (const p of allCommitments) {
      if (!qSet.has(p.identifier)) continue;
      acc = acc.add(decodePoint(unb64u(p.coefficientCommitments[kIdx]!)));
    }
    groupCoeffPoints.push(acc);
  }
  const groupPublicKey = groupCoeffPoints[0]!.toRawBytes();
  const groupCommitment = groupCoeffPoints.map((pt) => pt.toRawBytes());

  // Verifying shares Y_j = Σ_k Φ_k·j^k for every QUALIFIED participant.
  const verifyingShares: DkgVerifyingShare[] = qset.map((j) => {
    let acc = P.ZERO;
    const x = BigInt(j);
    let xk = 1n;
    for (const phi of groupCoeffPoints) {
      acc = acc.add(mulPoint(phi, xk));
      xk = mod(xk * x);
    }
    return { identifier: j, publicKey: acc.toRawBytes() };
  });

  const verifyingShare = mulBase(s).toRawBytes();
  // Consistency: my signing share must be exactly the share the group polynomial (Φ) predicts for me.
  const mine = verifyingShares.find((v) => v.identifier === myIdentifier);
  if (!mine || !mulBase(s).equals(decodePoint(mine.publicKey))) {
    throw new Error('dkgFinalize: signing share is inconsistent with the group verifying share (bad dealer share)');
  }

  return {
    identifier: myIdentifier,
    signingShare,
    groupPublicKey,
    verifyingShare,
    publicKeyPackage: { groupPublicKey, groupCommitment, verifyingShares },
  };
}

// ---- in-process simulation (tests + PCA plug-in path) -------------------------------------------

export interface DkgSimulateOpts {
  /** Participant identifiers (default 1..n). Must be `n` distinct positive integers. */
  identifiers?: ParticipantId[];
  /** Per-participant fixed polynomial coefficients (each length t), for deterministic runs. */
  coefficientsByParticipant?: Uint8Array[][];
  /** Caller-supplied session id binding this run (anti-replay). Random 32 bytes if omitted. */
  sessionId?: Uint8Array;
  /**
   * Participant ids that should act as a CHEATING DEALER: they send every recipient a share
   * inconsistent with their broadcast commitments. For exercising the complaint/blame round — each
   * recipient detects the bad share, files a complaint, and the cheater is disqualified. The run then
   * finalizes over the honest qualified set (requires |n − cheaters| ≥ t).
   */
  cheaters?: ParticipantId[];
  /**
   * Participant id whose ECHO is computed over a TAMPERED transcript view (a different qualified set),
   * modelling an equivocating dealer / network split that shows one honest party a divergent view. Its
   * echo digest then disagrees with the rest and `dkgFinalize` ABORTS the run. For exercising the
   * agreement round only.
   */
  equivocateEchoFor?: ParticipantId;
}

/**
 * Run the entire DKG ceremony in-process across `n` participants and return the shared group key plus
 * per-participant signing shares. The result mirrors `FrostKeygenResult`
 * (`{ groupPublicKey, participantShares, groupCommitment }`) so it is a LITERAL drop-in for
 * `frostTrustedDealerKeygen` in the in-process PCA path and the round-trip tests — but with no trusted
 * dealer. Also returns the finalized per-participant key packages, the round-1 packages, the qualified
 * set, any complaints raised, the accused rebuttals, and the session id.
 *
 * Internally this exercises every public step: `dkgRound1` → `dkgVerifyRound1` (asserted) → `dkgRound2`
 * (shares are signed) → `dkgVerifyShare` (requires the sender signature; → `dkgFileComplaint` with the
 * accused-signed share on failure) → `dkgRebut` → `dkgResolveBlame` / `dkgQualifiedSet` → `dkgFinalize`
 * over the qualified set, and checks all qualified participants derive the same group key. A cheater
 * signs the corrupted share it actually sends, so its complaint is admissible and it is convicted
 * non-repudiably.
 */
export function frostDkgSimulate(
  t: number,
  n: number,
  opts: DkgSimulateOpts = {},
): {
  groupPublicKey: Uint8Array;
  participantShares: FrostParticipantShare[];
  groupCommitment: Uint8Array[];
  keyPackages: DkgKeyPackage[];
  round1Packages: DkgRound1Package[];
  qualified: ParticipantId[];
  complaints: DkgComplaint[];
  rebuttals: DkgRebuttal[];
  echoes: DkgEcho[];
  sessionId: Uint8Array;
} {
  if (!Number.isInteger(t) || !Number.isInteger(n) || t < 1 || n < t) {
    throw new Error(`frostDkgSimulate: need 1 <= t <= n (got t=${t}, n=${n})`);
  }
  const ids = opts.identifiers ?? Array.from({ length: n }, (_, i) => i + 1);
  if (ids.length !== n) throw new Error('frostDkgSimulate: identifiers.length must equal n');
  if (new Set(ids).size !== n) throw new Error('frostDkgSimulate: identifiers must be distinct');
  if (ids.some((x) => !Number.isInteger(x) || x <= 0)) {
    throw new Error('frostDkgSimulate: identifiers must be positive integers');
  }
  const sessionId = opts.sessionId ?? ed25519.utils.randomPrivateKey();
  const cheaters = new Set(opts.cheaters ?? []);

  // Round 1: every participant samples a polynomial and broadcasts its session-bound package.
  const states: DkgParticipantState[] = ids.map((id, idx) =>
    dkgRound1(id, t, n, sessionId, { coefficients: opts.coefficientsByParticipant?.[idx] }).state,
  );
  const round1Packages = states.map((st) => st.package);

  // Every participant verifies every peer's proof of possession under the session (authenticated broadcast).
  for (const pkg of round1Packages) {
    if (!dkgVerifyRound1(pkg.identifier, pkg, sessionId)) {
      throw new Error(`frostDkgSimulate: PoP verification failed for participant ${pkg.identifier}`);
    }
  }

  // Round 2: each participant computes shares for every other, delivered over "private" channels. A
  // cheater corrupts the share it sends; each recipient verifies and files a complaint on failure.
  const inbox = new Map<ParticipantId, DkgReceivedShare[]>(ids.map((id) => [id, []]));
  const complaints: DkgComplaint[] = [];
  const stateById = new Map(states.map((st) => [st.identifier, st]));
  for (const st of states) {
    for (const outgoing of dkgRound2(st, round1Packages)) {
      let shareBytes = outgoing.share;
      let shareSig = outgoing.sig;
      if (cheaters.has(outgoing.from)) {
        const bad = Uint8Array.from(outgoing.share);
        bad[0] = bad[0]! ^ 0x01; // inconsistent with the broadcast commitments
        shareBytes = bad;
        // The cheater SIGNS what it actually sends → the recipient holds a non-repudiable bad share.
        shareSig = dkgSignShare(st, outgoing.to, bad);
      }
      const senderPkg = round1Packages.find((p) => p.identifier === outgoing.from)!;
      if (dkgVerifyShare({ from: outgoing.from, share: shareBytes, sig: shareSig }, senderPkg, outgoing.to, sessionId)) {
        inbox.get(outgoing.to)!.push({ from: outgoing.from, sessionId: outgoing.sessionId, share: shareBytes, sig: shareSig });
      } else {
        complaints.push(
          dkgFileComplaint({
            accused: outgoing.from,
            accuser: outgoing.to,
            receivedShare: shareBytes,
            shareSig,
            senderCommitments: senderPkg.coefficientCommitments,
            sessionId,
          }),
        );
      }
    }
  }

  // The accused may rebut each complaint by re-presenting the share it actually signed+sent.
  const rebuttals: DkgRebuttal[] = complaints.map((c) => dkgRebut(c.accused, c, stateById.get(c.accused)!));

  // Blame round → qualified set (resolving each complaint against any matching rebuttal).
  const qualified = dkgQualifiedSet(ids, complaints, round1Packages, rebuttals);
  if (qualified.length < t) {
    throw new Error(`frostDkgSimulate: only ${qualified.length} qualified participants (< t=${t}) after the blame round`);
  }

  // Echo-broadcast / agreement round: every qualified party commits to its transcript view, and the
  // finalizer requires them all to agree before deriving a key. An honest run agrees; a tampered view
  // (opts.equivocateEchoFor) echoes a divergent qualified set, so the agreement check fails at finalize.
  const echoes: DkgEcho[] = qualified.map((id) => {
    const view =
      id === opts.equivocateEchoFor
        ? qualified.filter((q) => q !== qualified[qualified.length - 1]) // a DIFFERENT qualified set
        : qualified;
    return dkgEcho({ identifier: id, round1Packages, complaints, qualified: view, sessionId });
  });

  // Finalize over the qualified set (only qualified participants hold a usable key).
  const qualifiedStates = states.filter((st) => qualified.includes(st.identifier));
  const keyPackages = qualifiedStates.map((st) =>
    dkgFinalize(st.identifier, st, inbox.get(st.identifier)!, round1Packages, qualified, { echoes, complaints }),
  );

  // Every qualified participant must derive the same group key.
  const groupPublicKey = keyPackages[0]!.groupPublicKey;
  const gpkHex = b64u(groupPublicKey);
  for (const kp of keyPackages) {
    if (b64u(kp.groupPublicKey) !== gpkHex) {
      throw new Error('frostDkgSimulate: participants disagree on the group public key');
    }
  }

  const participantShares: FrostParticipantShare[] = keyPackages.map((kp) => ({
    identifier: kp.identifier,
    share: kp.signingShare,
    publicKey: kp.verifyingShare,
  }));

  return {
    groupPublicKey,
    participantShares,
    groupCommitment: keyPackages[0]!.publicKeyPackage.groupCommitment,
    keyPackages,
    round1Packages,
    qualified,
    complaints,
    rebuttals,
    echoes,
    sessionId,
  };
}
