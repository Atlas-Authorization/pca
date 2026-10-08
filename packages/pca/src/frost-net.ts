import type { IncomingMessage, Server, ServerResponse } from 'node:http';
// `node:http` is imported LAZILY (inside startSignerHttpServer) so this module — re-exported from the
// package barrel — carries no static Node-builtin import and stays safe to bundle for the browser.
import { ed25519 } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { b64u, canonicalBytes, decodeB64uStrict, sha256, utf8 } from './hash';
import { sign as edSign, verify as edVerify } from './keys';
import {
  bytesToScalar,
  decodeSafePoint,
  frostAggregate,
  frostCommit,
  frostSign,
  frostVerifyingShare,
  L,
  scalarToBytes,
  type FrostCommitment,
  type FrostNonces,
  type ParticipantId,
} from './frost';

/**
 * MULTI-PROCESS NETWORK FROST for PCA guardian custody (closes audit boundary F-1, the PROTOCOL half).
 * ====================================================================================================
 *
 * `frost.ts` ships `frostCosign`, a CORRECT but IN-PROCESS signing round: it runs every quorum member's
 * `frostCommit`/`frostSign` inside one process, so one host compromise holds every share and the
 * "threshold" property is only notional (the module says so in its own security note). This module keeps
 * `frostCosign` untouched and adds the thing that makes the threshold REAL at the process level:
 *
 *   1. {@link GuardianSignerService} — a service that holds EXACTLY ONE FROST share and never emits it. It
 *      exposes round-1 (nonce commitment) and round-2 (signature share) over a transport. Its share bytes
 *      live only inside the service instance; a coordinator holds a {@link SignerTransport} handle, not the
 *      share. Run one per process (see `frost-net-runner.ts`) and the shares are in SEPARATE ADDRESS SPACES.
 *
 *   2. {@link NetworkCoordinator} — collects >= t round-1 commitments, forms the signing set, collects the
 *      round-2 shares, and aggregates with the EXISTING `frost.ts` primitives (`frostAggregate`). It holds
 *      NO share; it cannot sign on its own.
 *
 *   3. Each signer INDEPENDENTLY verifies a Policy-VM authorization token — a guardian-signed "allow for
 *      action-digest X under group key G" statement ({@link AllowToken}) — against the policy authority key
 *      it was CONFIGURED with, before releasing its round-2 share. A compromised coordinator cannot mint
 *      such a token (it lacks the policy key) and cannot make a signer release without one: the signer
 *      refuses (round-1 nonces are kept, never consumed, on refusal). The token is bound to the exact FROST
 *      message digest, so replaying an old allow only re-authorizes the message it already authorized —
 *      never a different action.
 *
 *   4. Threshold integrity is inherited from `frost.ts`: fewer than t shares, a refusing signer, a
 *      mismatched verification-share set, or a forged share all cause `frostAggregate` to refuse to return
 *      an invalid aggregate. A single compromised signer (or < t) cannot produce a valid group signature.
 *
 * TRANSPORT. Two interchangeable transports implement {@link SignerTransport}:
 *   - {@link inProcessTransport}: wraps a service instance behind async calls. The service is a separate
 *     object with isolated session state — genuine state isolation, but one address space (fast, for tests).
 *   - {@link httpSignerTransport} + {@link startSignerHttpServer}: JSON over loopback HTTP. With the service
 *     in its own OS process (the reference runner), this is genuine process-level trust-domain separation.
 *
 * BYZANTINE-ROBUST NETWORK HANDLING — NOW ENFORCED IN THIS MODULE (closes boundary F-1's protocol defenses):
 *   (a) ROGUE-KEY DEFENSE. Every signer proves POSSESSION of the secret scalar behind its verification share
 *       with a Schnorr proof-of-possession ({@link SignerPoP}) bound to a domain-separation context and the
 *       group key. The coordinator verifies the PoP against the verification share it has on record BEFORE
 *       admitting a signer to the signing set (every round), and {@link enrollVerificationShares} enforces the
 *       same at the enrollment / key-aggregation surface. A key presented without a valid PoP is rejected, so
 *       a participant cannot register a verification share whose discrete log it does not control. (In concert
 *       with the existing Σλ_i·PK_i == G interpolation check this closes the rogue-key vector.)
 *   (b) EQUIVOCATION DETECTION. Round messages are bound to (session_id, round_index, signer_id). The signer
 *       fails closed if the signing set carries a commitment for ITS id that differs from the one it emitted
 *       in round 1, and the coordinator runs an {@link EquivocationGuard} that rejects any second, DIFFERING
 *       message from the same (session, round, signer). Identical repeats are idempotent.
 *   (c) TIMEOUT / ABORT. The coordinator enforces a bounded round deadline (`timeoutMs`): a session that does
 *       not reach the threshold in the window aborts with a typed {@link CoordinatorTimeoutError} and produces
 *       NO signature (never a partial/ambiguous result). The signer enforces a stale-session guard
 *       (`sessionTtlMs`): a round-1 session that is completed too late is refused. The existing one-shot
 *       `#spent` set is the replay guard for a session that already produced a share.
 *
 * STILL OUT OF SCOPE (genuinely deployment concerns, not protocol code): physically separate hosts / HSMs;
 * authenticated + encrypted channels with PKI (this reference uses plaintext loopback HTTP); and the fully
 * asynchronous network-adversary / transport-layer DoS model — an attacker who controls message DELIVERY
 * (drops, reorders, delays, or floods the wire). This module's defenses make a signer/coordinator fail CLOSED
 * on adversarial *content* (forged keys, equivocation, stale/late sessions); keeping the channel itself
 * available and confidential remains the deployment's responsibility. This module makes the
 * SEPARATE-TRUST-DOMAIN guarantee real at the PROCESS level and gives the authorization gate teeth; it does
 * not make the network itself trustworthy.
 *
 * The FROST message is whatever the leaf signer signs in PCA — i.e. `thresholdMessage(pcactn)`. The group
 * public key is the capability-leaf `holder`, so a network-aggregated `sig` is an ordinary Ed25519 signature
 * that PCA's existing M0 leaf-sig check already accepts; there is nothing new for the verifier to learn.
 */

// ================================================================================================
// Allow token: a guardian / Policy-VM "allow for action-digest X under group key G" statement.
// ================================================================================================

/** Domain tag for the allow-token signed body (keeps it from colliding with any other signed blob). */
export const ALLOW_TOKEN_TYP = 'pca.frost.allow.v1' as const;

/** base64url(sha256(message)) — the "action digest" an allow token authorizes. */
export function frostActionDigest(message: Uint8Array): string {
  if (!(message instanceof Uint8Array)) throw new TypeError('frostActionDigest: message must be bytes');
  return b64u(sha256(message));
}

/** The signed body of an allow token (what the policy authority's Ed25519 key signs). */
export interface AllowTokenBody {
  typ: typeof ALLOW_TOKEN_TYP;
  /** base64url(sha256(FROST message)) this token authorizes. */
  action_digest: string;
  /** base64url(group public key) this token authorizes signing under. */
  group_pk: string;
  /** Unique per issuance (prevents accidental collisions; signers may also pin it). */
  nonce: string;
  /** epoch ms; the token is invalid before this (optional). */
  not_before?: number;
  /** epoch ms; the token is invalid at/after this (optional but recommended). */
  expires_at?: number;
}

/** An allow token: the signed body + the authority public key + its Ed25519 signature (all base64url). */
export interface AllowToken {
  body: AllowTokenBody;
  /** base64url(policy-authority Ed25519 public key) — INFORMATIONAL; a verifier pins its own trusted key. */
  authority: string;
  /** base64url(Ed25519 signature) over canonicalBytes(body). */
  sig: string;
}

export interface IssueAllowOpts {
  /** The exact FROST message being authorized (its sha256 becomes action_digest). */
  message?: Uint8Array;
  /** …or supply the action digest directly. One of message/frostActionDigest is required. */
  frostActionDigest?: string;
  groupPublicKey: Uint8Array;
  nonce?: string;
  notBefore?: number;
  expiresAt?: number;
}

/**
 * Mint an allow token with the policy authority's Ed25519 SECRET key. This is the "Policy-VM says yes"
 * signal; only the holder of the policy key can produce it. In PCA the policy decision (`policy-vm.decide`)
 * gates whether this is issued at all; here we model the signed OUTPUT the signers independently check.
 */
export function issueAllowToken(policySecretKey: Uint8Array, opts: IssueAllowOpts): AllowToken {
  const digest = opts.frostActionDigest ?? (opts.message ? frostActionDigest(opts.message) : undefined);
  if (!digest) throw new Error('issueAllowToken: provide message or frostActionDigest');
  const body: AllowTokenBody = {
    typ: ALLOW_TOKEN_TYP,
    action_digest: digest,
    group_pk: b64u(opts.groupPublicKey),
    nonce: opts.nonce ?? b64u(ed25519.utils.randomPrivateKey()),
    ...(opts.notBefore !== undefined ? { not_before: opts.notBefore } : {}),
    ...(opts.expiresAt !== undefined ? { expires_at: opts.expiresAt } : {}),
  };
  const authority = b64u(ed25519.getPublicKey(policySecretKey));
  const sig = b64u(edSign(policySecretKey, canonicalBytes(body)));
  return { body, authority, sig };
}

export interface VerifyAllowResult {
  ok: boolean;
  reason?: string;
}

/**
 * Independently verify an allow token. This is run BY EACH SIGNER against the policy authority key it was
 * configured with — never against `token.authority` (which a coordinator could set to its own key). The
 * token must: be well-formed, carry the configured typ, be signed by the configured authority key, name the
 * configured group key, name the exact message's action digest, and be within its validity window.
 */
export function verifyAllowToken(
  token: unknown,
  expect: { policyAuthorityPublicKey: Uint8Array; groupPublicKey: Uint8Array; message: Uint8Array; now: number },
): VerifyAllowResult {
  try {
    if (!token || typeof token !== 'object') return { ok: false, reason: 'allow token missing or malformed' };
    const t = token as AllowToken;
    const body = t.body;
    if (!body || typeof body !== 'object') return { ok: false, reason: 'allow token has no body' };
    if (body.typ !== ALLOW_TOKEN_TYP) return { ok: false, reason: `allow token wrong typ (${String(body.typ)})` };
    if (typeof t.sig !== 'string') return { ok: false, reason: 'allow token missing signature' };

    // Signature MUST verify under the signer's CONFIGURED authority key, not token.authority.
    const sigBytes = decodeB64uStrict(t.sig, 64);
    if (!sigBytes) return { ok: false, reason: 'allow token signature not canonical base64url' };
    if (!edVerify(expect.policyAuthorityPublicKey, canonicalBytes(body), sigBytes)) {
      return { ok: false, reason: 'allow token not signed by the trusted policy authority' };
    }
    // Bind to THIS group key and THIS message.
    if (body.group_pk !== b64u(expect.groupPublicKey)) {
      return { ok: false, reason: 'allow token authorizes a different group key' };
    }
    if (body.action_digest !== frostActionDigest(expect.message)) {
      return { ok: false, reason: 'allow token authorizes a different action digest' };
    }
    // Validity window.
    if (!Number.isFinite(expect.now)) return { ok: false, reason: 'invalid verification time' };
    if (body.not_before !== undefined && expect.now < body.not_before) {
      return { ok: false, reason: 'allow token not yet valid' };
    }
    if (body.expires_at !== undefined && expect.now >= body.expires_at) {
      return { ok: false, reason: 'allow token expired' };
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: `allow token verification error (fail closed): ${e instanceof Error ? e.message : 'unknown'}` };
  }
}

// ================================================================================================
// (1) ROGUE-KEY DEFENSE: proof-of-possession (PoP) for a signer's verification share.
// ------------------------------------------------------------------------------------------------
// A FROST verification share is PK = x·B for the signer's SECRET scalar share x. The standard defense
// against a rogue-key attack is to require each signer to PROVE it knows x before its key is accepted.
// This is a Schnorr proof of knowledge of the discrete log of PK, bound to a domain-separation context
// and the group key, built only from the curve/scalar helpers this package already ships (no new deps):
//   choose random k != 0 ; R = k·B ; e = H2S(DST ‖ group_pk ‖ id ‖ PK ‖ R) ; s = k + e·x (mod L)
// Verify:  s·B == R + e·PK. A party that does not know x cannot produce a valid (R, s).
// ================================================================================================

/** Domain-separation tag for the signer proof-of-possession (keeps it from colliding with any other blob). */
export const SIGNER_POP_DST = 'pca.frost.signer-pop.v1' as const;

/** A signer's Schnorr proof-of-possession of its verification share (all bytes base64url; JSON-safe). */
export interface SignerPoP {
  identifier: ParticipantId;
  /** base64url(verification share PK = x·B, 32-byte point) this PoP is for. */
  publicKey: string;
  /** base64url(R = k·B, 32-byte Schnorr commitment point). */
  R: string;
  /** base64url(s = k + e·x mod L, 32-byte LE scalar response). */
  s: string;
}

const EdPt = ed25519.ExtendedPoint;

function modL(a: bigint): bigint {
  const r = a % L;
  return r >= 0n ? r : r + L;
}

function popConcat(...parts: Uint8Array[]): Uint8Array {
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

/** s·B with 0 mapped to the identity (noble's multiply rejects 0). */
function popMulBase(s: bigint): InstanceType<typeof EdPt> {
  const v = modL(s);
  return v === 0n ? EdPt.ZERO : EdPt.BASE.multiply(v);
}

/** s·Q with 0 mapped to the identity. */
function popMulPoint(pt: InstanceType<typeof EdPt>, s: bigint): InstanceType<typeof EdPt> {
  const v = modL(s);
  return v === 0n ? EdPt.ZERO : pt.multiply(v);
}

/** e = OS2IP_LE(SHA-512(DST ‖ group_pk ‖ SerializeScalar(id) ‖ PK ‖ R)) mod L, never 0. */
function signerPopChallenge(groupPublicKey: Uint8Array, identifier: ParticipantId, pk: Uint8Array, r: Uint8Array): bigint {
  const h = sha512(popConcat(utf8(SIGNER_POP_DST), groupPublicKey, scalarToBytes(BigInt(identifier)), pk, r));
  const e = bytesToScalar(h);
  return e === 0n ? 1n : e;
}

/**
 * Create a signer proof-of-possession for the verification share derived from `share`, bound to `groupPublicKey`.
 * The signer (which holds the secret share) produces this; it reveals NOTHING about the secret scalar beyond
 * that the prover knows it.
 */
export function createSignerPoP(identifier: ParticipantId, share: Uint8Array, opts: { groupPublicKey: Uint8Array }): SignerPoP {
  if (!Number.isSafeInteger(identifier) || identifier <= 0) throw new Error('createSignerPoP: identifier must be a positive integer');
  if (!(share instanceof Uint8Array) || share.length !== 32) throw new Error('createSignerPoP: share must be 32 bytes');
  if (!(opts.groupPublicKey instanceof Uint8Array) || opts.groupPublicKey.length !== 32) {
    throw new Error('createSignerPoP: groupPublicKey must be 32 bytes');
  }
  const x = bytesToScalar(share);
  const pk = popMulBase(x).toRawBytes();
  let k = 0n;
  do {
    k = bytesToScalar(ed25519.utils.randomPrivateKey());
  } while (k === 0n);
  const rBytes = popMulBase(k).toRawBytes();
  const e = signerPopChallenge(opts.groupPublicKey, identifier, pk, rBytes);
  const s = modL(k + modL(e * x));
  return { identifier, publicKey: b64u(pk), R: b64u(rBytes), s: b64u(scalarToBytes(s)) };
}

/**
 * Verify a signer proof-of-possession. Never throws: any malformed input or bad proof returns false. Checks
 * s·B == R + e·PK with R and PK decoded through the STRICT point rules (rejects small-order / off-curve /
 * torsion points). Call sites additionally bind `pop.publicKey`/`pop.identifier` to the key they expect.
 */
export function verifySignerPoP(pop: unknown, expect: { groupPublicKey: Uint8Array }): boolean {
  try {
    if (!pop || typeof pop !== 'object') return false;
    const p = pop as SignerPoP;
    if (!Number.isSafeInteger(p.identifier) || p.identifier <= 0) return false;
    if (!(expect.groupPublicKey instanceof Uint8Array) || expect.groupPublicKey.length !== 32) return false;
    const pk = decodeB64uStrict(p.publicKey, 32);
    const rb = decodeB64uStrict(p.R, 32);
    const sb = decodeB64uStrict(p.s, 32);
    if (!pk || !rb || !sb) return false;
    const pkPt = decodeSafePoint(pk);
    const rPt = decodeSafePoint(rb);
    const s = bytesToScalar(sb);
    const e = signerPopChallenge(expect.groupPublicKey, p.identifier, pk, rb);
    const lhs = popMulBase(s);
    const rhs = rPt.add(popMulPoint(pkPt, e));
    return lhs.equals(rhs);
  } catch {
    return false;
  }
}

/** An enrollment record for one signer: its identifier, verification share, and proof-of-possession. */
export interface SignerEnrollment {
  identifier: ParticipantId;
  /** The verification share (share·B, 32-byte point). */
  publicKey: Uint8Array;
  /** The signer's proof-of-possession binding `publicKey`. */
  pop: SignerPoP;
}

/** Thrown by {@link enrollVerificationShares} when a signer's key has no valid proof-of-possession. */
export class PoPError extends Error {
  readonly identifier?: ParticipantId;
  constructor(message: string, identifier?: ParticipantId) {
    super(message);
    this.name = 'PoPError';
    if (identifier !== undefined) this.identifier = identifier;
  }
}

/**
 * ENFORCED enrollment / key-aggregation surface. Accepts each signer only if it carries a valid PoP binding
 * its verification share under `groupPublicKey`; returns the plain `{ identifier, publicKey }[]` for a
 * {@link NetworkCoordinator}. A missing, mismatched, or invalid PoP (a rogue key) THROWS {@link PoPError};
 * duplicate ids are rejected. This is the hardened path to build a coordinator's verification-share set.
 */
export function enrollVerificationShares(
  enrollments: SignerEnrollment[],
  expect: { groupPublicKey: Uint8Array },
): { identifier: ParticipantId; publicKey: Uint8Array }[] {
  if (!Array.isArray(enrollments) || enrollments.length === 0) throw new PoPError('enrollVerificationShares: no signer enrollments');
  if (!(expect.groupPublicKey instanceof Uint8Array) || expect.groupPublicKey.length !== 32) {
    throw new PoPError('enrollVerificationShares: groupPublicKey must be 32 bytes');
  }
  const out: { identifier: ParticipantId; publicKey: Uint8Array }[] = [];
  const seen = new Set<number>();
  for (const e of enrollments) {
    if (!e || !Number.isSafeInteger(e.identifier) || e.identifier <= 0) throw new PoPError('enrollVerificationShares: enrollment with invalid identifier');
    if (seen.has(e.identifier)) throw new PoPError(`enrollVerificationShares: duplicate enrollment for signer ${e.identifier}`, e.identifier);
    seen.add(e.identifier);
    if (!(e.publicKey instanceof Uint8Array) || e.publicKey.length !== 32) {
      throw new PoPError(`enrollVerificationShares: signer ${e.identifier} verification share must be 32 bytes`, e.identifier);
    }
    if (!e.pop || e.pop.identifier !== e.identifier || e.pop.publicKey !== b64u(e.publicKey)) {
      throw new PoPError(`enrollVerificationShares: signer ${e.identifier} missing or mismatched proof-of-possession (rogue key rejected)`, e.identifier);
    }
    if (!verifySignerPoP(e.pop, { groupPublicKey: expect.groupPublicKey })) {
      throw new PoPError(`enrollVerificationShares: signer ${e.identifier} invalid proof-of-possession (rogue key rejected)`, e.identifier);
    }
    out.push({ identifier: e.identifier, publicKey: e.publicKey });
  }
  return out;
}

// ================================================================================================
// (2) EQUIVOCATION DETECTION: bind each round message to (session_id, round_index, signer_id).
// ================================================================================================

/** Thrown when a signer sends two DIFFERENT messages for the same (session, round). */
export class EquivocationError extends Error {
  readonly session_id: string;
  readonly round: number;
  readonly identifier: ParticipantId;
  readonly previousDigest: string;
  readonly offendingDigest: string;
  constructor(session_id: string, round: number, identifier: ParticipantId, previousDigest: string, offendingDigest: string) {
    super(`equivocation: signer ${identifier} sent two different messages for session '${session_id}' round ${round}`);
    this.name = 'EquivocationError';
    this.session_id = session_id;
    this.round = round;
    this.identifier = identifier;
    this.previousDigest = previousDigest;
    this.offendingDigest = offendingDigest;
  }
}

/**
 * Records the FIRST message seen per (session_id, round_index, signer_id) and fails CLOSED on any second,
 * DIFFERING message from the same tuple (an identical repeat is idempotent and allowed — honest retransmits
 * do not trip it). The coordinator keeps one of these across sessions so a (session, round, signer) can never
 * be bound to two different values.
 */
export class EquivocationGuard {
  readonly #seen = new Map<string, string>();

  private static key(session_id: string, round: number, identifier: ParticipantId): string {
    return `${session_id}\u0000${round}\u0000${identifier}`;
  }

  /** Observe a round message; throws {@link EquivocationError} on a second, differing message for the tuple. */
  observe(session_id: string, round: number, identifier: ParticipantId, message: unknown): void {
    if (typeof session_id !== 'string' || session_id.length === 0) throw new Error('EquivocationGuard: session_id must be a non-empty string');
    if (!Number.isSafeInteger(round) || round < 1) throw new Error('EquivocationGuard: round must be a positive integer');
    if (!Number.isSafeInteger(identifier) || identifier <= 0) throw new Error('EquivocationGuard: identifier must be a positive integer');
    const key = EquivocationGuard.key(session_id, round, identifier);
    const digest = b64u(sha256(canonicalBytes(message)));
    const prev = this.#seen.get(key);
    if (prev === undefined) {
      this.#seen.set(key, digest);
      return;
    }
    if (prev !== digest) throw new EquivocationError(session_id, round, identifier, prev, digest);
    // Identical repeat: idempotent.
  }

  /** Forget every binding for a session id (bounded-memory housekeeping; optional). */
  forget(session_id: string): void {
    const prefix = `${session_id}\u0000`;
    for (const k of [...this.#seen.keys()]) if (k.startsWith(prefix)) this.#seen.delete(k);
  }
}

// ================================================================================================
// Wire types (JSON-safe; all bytes base64url).
// ================================================================================================

export interface WireCommitment {
  identifier: ParticipantId;
  hiding: string;
  binding: string;
}

export interface WireVerificationShare {
  identifier: ParticipantId;
  publicKey: string;
}

export interface Round1Request {
  typ: 'pca.frost.round1.v1';
  session_id: string;
}

export type Round1Response =
  | { ok: true; identifier: ParticipantId; commitment: WireCommitment; pop: SignerPoP }
  | { ok: false; identifier: ParticipantId; reason: string };

export interface Round2Request {
  typ: 'pca.frost.round2.v1';
  session_id: string;
  /** base64url(FROST message). */
  message: string;
  /** base64url(group public key) — echoed so the signer can refuse a mismatch. */
  group_pk: string;
  /** The full signing set's round-1 commitments. */
  commitments: WireCommitment[];
  /** The signing set's PUBLIC verification shares (checked to interpolate to the group key). */
  verification_shares: WireVerificationShare[];
  /** The guardian/Policy-VM allow token. */
  allow: AllowToken;
}

export type Round2Response =
  | { ok: true; identifier: ParticipantId; sig_share: string }
  | { ok: false; identifier: ParticipantId; refused: true; reason: string };

function encodeCommitment(c: FrostCommitment): WireCommitment {
  return { identifier: c.identifier, hiding: b64u(c.hiding), binding: b64u(c.binding) };
}

function decodeCommitment(w: WireCommitment): FrostCommitment {
  const hiding = decodeB64uStrict(w.hiding, 32);
  const binding = decodeB64uStrict(w.binding, 32);
  if (!Number.isSafeInteger(w.identifier) || w.identifier <= 0) throw new Error('bad commitment identifier');
  if (!hiding || !binding) throw new Error('bad commitment point encoding');
  return { identifier: w.identifier, hiding, binding };
}

function decodeVerificationShares(list: WireVerificationShare[]): { identifier: ParticipantId; publicKey: Uint8Array }[] {
  if (!Array.isArray(list)) throw new Error('verification_shares must be a list');
  return list.map((v) => {
    const pk = decodeB64uStrict(v.publicKey, 32);
    if (!Number.isSafeInteger(v.identifier) || v.identifier <= 0) throw new Error('bad verification-share identifier');
    if (!pk) throw new Error('bad verification-share key encoding');
    return { identifier: v.identifier, publicKey: pk };
  });
}

// ================================================================================================
// The guardian SIGNER service: holds EXACTLY ONE share; verifies the allow token independently.
// ================================================================================================

export interface GuardianSignerOpts {
  identifier: ParticipantId;
  /** This signer's ONE secret FROST share (32-byte LE scalar). Never leaves the service. */
  share: Uint8Array;
  /** The single group public key (32-byte point). */
  groupPublicKey: Uint8Array;
  /** Threshold t: this signer refuses a signing set smaller than t. */
  threshold: number;
  /** The policy authority's Ed25519 PUBLIC key this signer trusts for allow tokens. */
  policyAuthorityPublicKey: Uint8Array;
  /**
   * Stale-session guard (timeout half of boundary F-1): max age, in ms, of a round-1 session before round 2
   * is refused. A session opened in round 1 that is not completed within this window is dropped and must be
   * re-opened with a fresh round 1. Omit (default) to keep sessions until completion — no behavioral change.
   */
  sessionTtlMs?: number;
  /** Clock (default Date.now); injectable for tests. */
  now?: () => number;
}

interface SessionState {
  nonces: FrostNonces;
  commitment: FrostCommitment;
  /** Wall-clock (via `now`) at which round 1 opened this session — for the stale-session guard. */
  createdAt: number;
}

/**
 * A single-share FROST signer. One instance = one trust domain. It stores, per session, ONLY its own secret
 * nonces (which never leave), and releases a signature share in round 2 iff (a) it has live round-1 state for
 * the session, (b) the request's group key matches its configured group key, and (c) the allow token verifies
 * independently against its configured policy authority key and binds to the exact message. On any refusal the
 * round-1 nonces are KEPT (not consumed), so an honest retry with a valid token still works; on success the
 * nonces are consumed one-shot (via `frostSign`) and the session state is dropped.
 */
export class GuardianSignerService {
  readonly identifier: ParticipantId;
  readonly verificationShare: Uint8Array;
  // The secret share and the per-session secret nonces are JS #private fields: genuinely unreachable at
  // runtime — absent from Object.keys / JSON.stringify / any property access — not merely TS-private.
  readonly #share: Uint8Array;
  readonly #sessions = new Map<string, SessionState>();
  /** Session ids that have already produced a share — refuse a second round 2. */
  readonly #spent = new Set<string>();
  /** This signer's proof-of-possession of its verification share (rogue-key defense); constant per instance. */
  readonly #pop: SignerPoP;
  private readonly groupPublicKey: Uint8Array;
  private readonly threshold: number;
  private readonly policyAuthorityPublicKey: Uint8Array;
  private readonly sessionTtlMs: number | undefined;
  private readonly now: () => number;

  constructor(opts: GuardianSignerOpts) {
    if (!Number.isSafeInteger(opts.identifier) || opts.identifier <= 0) {
      throw new Error('GuardianSignerService: identifier must be a positive integer');
    }
    if (!(opts.share instanceof Uint8Array) || opts.share.length !== 32) {
      throw new Error('GuardianSignerService: share must be 32 bytes');
    }
    if (!(opts.groupPublicKey instanceof Uint8Array) || opts.groupPublicKey.length !== 32) {
      throw new Error('GuardianSignerService: groupPublicKey must be 32 bytes');
    }
    if (!Number.isSafeInteger(opts.threshold) || opts.threshold < 1) {
      throw new Error('GuardianSignerService: threshold must be a positive integer');
    }
    if (!(opts.policyAuthorityPublicKey instanceof Uint8Array) || opts.policyAuthorityPublicKey.length !== 32) {
      throw new Error('GuardianSignerService: policyAuthorityPublicKey must be 32 bytes');
    }
    if (opts.sessionTtlMs !== undefined && (!Number.isFinite(opts.sessionTtlMs) || opts.sessionTtlMs <= 0)) {
      throw new Error('GuardianSignerService: sessionTtlMs must be a positive finite number');
    }
    // Copy the share so the caller cannot mutate it out from under us (and we never hand it back).
    this.#share = opts.share.slice();
    this.identifier = opts.identifier;
    this.groupPublicKey = opts.groupPublicKey.slice();
    this.threshold = opts.threshold;
    this.policyAuthorityPublicKey = opts.policyAuthorityPublicKey.slice();
    this.sessionTtlMs = opts.sessionTtlMs;
    this.now = opts.now ?? (() => Date.now());
    this.verificationShare = frostVerifyingShare(this.#share);
    // Rogue-key defense: prove possession of the secret scalar behind our verification share once, up front.
    this.#pop = createSignerPoP(this.identifier, this.#share, { groupPublicKey: this.groupPublicKey });
  }

  /** This signer's proof-of-possession of its verification share (safe to publish; reveals nothing secret). */
  get proofOfPossession(): SignerPoP {
    return this.#pop;
  }

  /** A ready-to-enroll record (identifier + verification share + PoP) for {@link enrollVerificationShares}. */
  enrollment(): SignerEnrollment {
    return { identifier: this.identifier, publicKey: this.verificationShare.slice(), pop: this.#pop };
  }

  /** Round 1: commit to a fresh nonce pair for `session_id`; store the SECRET nonces locally. */
  round1(req: Round1Request): Round1Response {
    try {
      if (!req || req.typ !== 'pca.frost.round1.v1' || typeof req.session_id !== 'string' || req.session_id.length === 0) {
        return { ok: false, identifier: this.identifier, reason: 'malformed round-1 request' };
      }
      if (this.#spent.has(req.session_id)) {
        return { ok: false, identifier: this.identifier, reason: 'session already signed' };
      }
      if (this.#sessions.has(req.session_id)) {
        // Never overwrite live nonces for a session (would risk a nonce-reuse foot-gun).
        return { ok: false, identifier: this.identifier, reason: 'duplicate round-1 for session' };
      }
      const c = frostCommit({ identifier: this.identifier, share: this.#share, publicKey: this.verificationShare });
      this.#sessions.set(req.session_id, {
        nonces: { hiding: c.hidingNonce, binding: c.bindingNonce },
        commitment: c.commitment,
        createdAt: this.now(),
      });
      return { ok: true, identifier: this.identifier, commitment: encodeCommitment(c.commitment), pop: this.#pop };
    } catch (e) {
      return { ok: false, identifier: this.identifier, reason: e instanceof Error ? e.message : 'round-1 error' };
    }
  }

  /** Round 2: release a signature share iff the allow token verifies and the session has live round-1 state. */
  round2(req: Round2Request): Round2Response {
    const refuse = (reason: string): Round2Response => ({ ok: false, identifier: this.identifier, refused: true, reason });
    try {
      if (!req || req.typ !== 'pca.frost.round2.v1' || typeof req.session_id !== 'string') {
        return refuse('malformed round-2 request');
      }
      if (this.#spent.has(req.session_id)) return refuse('session already signed (one-shot)');
      const state = this.#sessions.get(req.session_id);
      if (!state) return refuse('no round-1 state for this session');

      // Stale-session guard (timeout): a session not completed within its window is dropped, not signed.
      if (this.sessionTtlMs !== undefined && this.now() - state.createdAt > this.sessionTtlMs) {
        this.#sessions.delete(req.session_id);
        return refuse(`session expired (stale-session guard: round-1 older than ${this.sessionTtlMs}ms)`);
      }

      const message = decodeB64uStrict(req.message);
      if (!message) return refuse('message not canonical base64url');
      // The request must be for OUR group key.
      if (req.group_pk !== b64u(this.groupPublicKey)) return refuse('request names a different group key');

      // (3) INDEPENDENT policy authorization — the heart of coordinator-compromise resistance.
      const allow = verifyAllowToken(req.allow, {
        policyAuthorityPublicKey: this.policyAuthorityPublicKey,
        groupPublicKey: this.groupPublicKey,
        message,
        now: this.now(),
      });
      if (!allow.ok) return refuse(`policy authorization failed: ${allow.reason}`);

      // Decode the signing set + the public verification shares (frostSign checks they interpolate to G).
      const commitments = (req.commitments ?? []).map(decodeCommitment);
      if (commitments.length < this.threshold) return refuse(`signing set below threshold t=${this.threshold}`);
      const own = commitments.find((c) => c.identifier === this.identifier);
      if (!own) return refuse('our commitment is not in the signing set');
      // Equivocation defense: the commitment the coordinator put in the set for OUR id must byte-match the one
      // we emitted in round 1 for this session. (frostSign would also reject a mismatch via the nonce binding;
      // this fails closed earlier with an unambiguous, typed reason.)
      if (b64u(own.hiding) !== b64u(state.commitment.hiding) || b64u(own.binding) !== b64u(state.commitment.binding)) {
        return refuse('equivocation detected: our commitment in the signing set differs from our round-1 commitment');
      }
      const verificationShares = decodeVerificationShares(req.verification_shares);

      // Produce the share with every frost.ts safety check on. frostSign consumes the nonces one-shot.
      const sigShare = frostSign(
        this.identifier,
        this.#share,
        this.groupPublicKey,
        state.nonces,
        message,
        commitments,
        { threshold: this.threshold, verificationShare: this.verificationShare, verificationShares },
      );

      // One-shot: drop the session, mark spent (nonces are already zeroized by frostSign).
      this.#sessions.delete(req.session_id);
      this.#spent.add(req.session_id);
      return { ok: true, identifier: this.identifier, sig_share: b64u(sigShare.sigShare) };
    } catch (e) {
      // A crypto-level failure (bad share set, mismatched group key, etc.) is also a refusal.
      return refuse(e instanceof Error ? e.message : 'round-2 error');
    }
  }
}

// ================================================================================================
// Transport abstraction.
// ================================================================================================

export interface SignerTransport {
  readonly identifier: ParticipantId;
  round1(req: Round1Request): Promise<Round1Response>;
  round2(req: Round2Request): Promise<Round2Response>;
  close?(): Promise<void>;
}

/**
 * In-process transport: a separate {@link GuardianSignerService} object with its own isolated session state,
 * reached only through async method calls. The coordinator holds this handle, NOT the share. This gives
 * genuine STATE isolation in one address space (fast, deterministic tests). For genuine PROCESS isolation,
 * use {@link httpSignerTransport} against a service in its own OS process (the reference runner).
 */
export function inProcessTransport(service: GuardianSignerService): SignerTransport {
  return {
    identifier: service.identifier,
    round1: (req) => Promise.resolve(service.round1(req)),
    round2: (req) => Promise.resolve(service.round2(req)),
  };
}

// ---- HTTP transport (JSON over loopback) --------------------------------------------------------

async function readJsonBody(reqStream: IncomingMessage, limitBytes = 1 << 20): Promise<unknown> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of reqStream) {
    const buf = chunk as Buffer;
    total += buf.length;
    if (total > limitBytes) throw new Error('request body too large');
    chunks.push(buf);
  }
  const raw = Buffer.concat(chunks).toString('utf8');
  return raw.length ? JSON.parse(raw) : {};
}

export interface SignerHttpServer {
  url: string;
  port: number;
  server: Server;
  close(): Promise<void>;
}

/**
 * Start an HTTP server for one signer service. Routes: POST /round1, POST /round2. Binds 127.0.0.1 and, by
 * default, an ephemeral port (pass `port` to pin one). JSON in, JSON out; all bytes base64url. A handler
 * error maps to a refusal response, never a leaked stack / share.
 */
export async function startSignerHttpServer(
  service: GuardianSignerService,
  opts: { port?: number; host?: string } = {},
): Promise<SignerHttpServer> {
  const host = opts.host ?? '127.0.0.1';
  const { createServer } = await import('node:http');
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      const send = (code: number, body: unknown): void => {
        const json = JSON.stringify(body);
        res.writeHead(code, { 'content-type': 'application/json' });
        res.end(json);
      };
      try {
        if (req.method !== 'POST') return send(405, { ok: false, reason: 'method not allowed' });
        if (req.url === '/round1') {
          const body = (await readJsonBody(req)) as Round1Request;
          return send(200, service.round1(body));
        }
        if (req.url === '/round2') {
          const body = (await readJsonBody(req)) as Round2Request;
          return send(200, service.round2(body));
        }
        return send(404, { ok: false, reason: 'not found' });
      } catch (e) {
        return send(400, { ok: false, identifier: service.identifier, refused: true, reason: e instanceof Error ? e.message : 'bad request' });
      }
    })();
  });
  return new Promise<SignerHttpServer>((resolve, reject) => {
    server.on('error', reject);
    server.listen(opts.port ?? 0, host, () => {
      const addr = server.address();
      if (!addr || typeof addr === 'string') return reject(new Error('could not determine server address'));
      const url = `http://${host}:${addr.port}`;
      resolve({
        url,
        port: addr.port,
        server,
        close: () =>
          new Promise<void>((res) => {
            server.closeAllConnections?.();
            server.close(() => res());
          }),
      });
    });
  });
}

/** HTTP transport: talks to a signer HTTP server over loopback. One instance per remote signer. */
export function httpSignerTransport(baseUrl: string, identifier: ParticipantId, opts: { timeoutMs?: number } = {}): SignerTransport {
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const post = async <T>(path: string, body: unknown): Promise<T> => {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), timeoutMs);
    try {
      const resp = await fetch(`${baseUrl}${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal: ctl.signal,
      });
      return (await resp.json()) as T;
    } finally {
      clearTimeout(timer);
    }
  };
  return {
    identifier,
    round1: (req) => post<Round1Response>('/round1', req),
    round2: (req) => post<Round2Response>('/round2', req),
  };
}

// ================================================================================================
// The COORDINATOR: collects commitments + shares, aggregates. Holds NO share.
// ================================================================================================

export interface NetworkCoordinatorOpts {
  groupPublicKey: Uint8Array;
  threshold: number;
  /** One transport per available signer. */
  signers: SignerTransport[];
  /**
   * PUBLIC verification shares for every signer (sent to signers; each checks they interpolate to G). Provide
   * this OR `enroll`. When given directly, the coordinator still enforces the rogue-key defense per round by
   * verifying each signer's round-1 proof-of-possession against the key recorded here.
   */
  verificationShares?: { identifier: ParticipantId; publicKey: Uint8Array }[];
  /**
   * Hardened alternative to `verificationShares`: PoP-bearing enrollment records. Every PoP is verified at
   * construction via {@link enrollVerificationShares} and a rogue key (missing/invalid PoP) THROWS. The
   * resulting verification shares are used exactly as `verificationShares` would be.
   */
  enroll?: SignerEnrollment[];
  /** Session id generator (default: random). */
  newSessionId?: () => string;
  /**
   * Bounded round deadline, in ms, for a whole `sign()` call. A session that does not reach the threshold in
   * the window aborts with {@link CoordinatorTimeoutError} and produces NO signature. Omit (default) for no
   * deadline — unchanged behavior. A per-call `sign({ timeoutMs })` overrides this.
   */
  timeoutMs?: number;
}

export interface NetworkSignResult {
  /** The aggregate STANDARD Ed25519 signature (verifies under the group key). */
  signature: Uint8Array;
  sessionId: string;
  /** Identifiers that contributed a valid round-2 share. */
  signers: ParticipantId[];
}

export class CoordinatorError extends Error {
  readonly refusals: { identifier: ParticipantId; reason: string }[];
  constructor(message: string, refusals: { identifier: ParticipantId; reason: string }[] = []) {
    super(message);
    this.name = 'CoordinatorError';
    this.refusals = refusals;
  }
}

/**
 * Thrown when a `sign()` session exceeds its bounded round deadline (`timeoutMs`). It is a
 * {@link CoordinatorError}, so existing `instanceof CoordinatorError` handling still catches it; no signature
 * is produced (the session aborts before aggregation).
 */
export class CoordinatorTimeoutError extends CoordinatorError {
  readonly timeoutMs: number;
  constructor(message: string, timeoutMs: number, refusals: { identifier: ParticipantId; reason: string }[] = []) {
    super(message, refusals);
    this.name = 'CoordinatorTimeoutError';
    this.timeoutMs = timeoutMs;
  }
}

/**
 * The network coordinator. Given a message and an allow token, it runs round 1 to collect >= t commitments,
 * forms the signing set, runs round 2 to collect the matching shares, and aggregates with `frostAggregate`.
 * It holds NO signing share, so it cannot sign on its own; and it cannot forge the allow token, so it cannot
 * make honest signers release without a genuine Policy-VM authorization. If fewer than t signers commit or
 * fewer than t release a valid share (refusals, unreachable signers, forged/expired allow), it throws.
 */
export class NetworkCoordinator {
  private readonly groupPublicKey: Uint8Array;
  private readonly threshold: number;
  private readonly signers: SignerTransport[];
  private readonly verificationShares: { identifier: ParticipantId; publicKey: Uint8Array }[];
  /** id -> base64url(recorded verification share); the key a round-1 PoP is checked against. */
  readonly #pkById: Map<ParticipantId, string>;
  /** Persistent across sessions: no (session, round, signer) can ever be bound to two different values. */
  readonly #equivocation = new EquivocationGuard();
  private readonly newSessionId: () => string;
  private readonly timeoutMs: number | undefined;

  constructor(opts: NetworkCoordinatorOpts) {
    if (!(opts.groupPublicKey instanceof Uint8Array) || opts.groupPublicKey.length !== 32) {
      throw new Error('NetworkCoordinator: groupPublicKey must be 32 bytes');
    }
    if (!Number.isSafeInteger(opts.threshold) || opts.threshold < 1) {
      throw new Error('NetworkCoordinator: threshold must be a positive integer');
    }
    if (opts.timeoutMs !== undefined && (!Number.isFinite(opts.timeoutMs) || opts.timeoutMs <= 0)) {
      throw new Error('NetworkCoordinator: timeoutMs must be a positive finite number');
    }
    this.groupPublicKey = opts.groupPublicKey;
    this.threshold = opts.threshold;
    this.signers = [...opts.signers];
    // Rogue-key defense at the enrollment surface: `enroll` verifies every PoP (throws on a rogue key); a
    // plain `verificationShares` set is still enforced per round via each signer's round-1 PoP.
    if (opts.enroll !== undefined) {
      this.verificationShares = enrollVerificationShares(opts.enroll, { groupPublicKey: opts.groupPublicKey });
    } else if (opts.verificationShares !== undefined) {
      this.verificationShares = [...opts.verificationShares];
    } else {
      throw new Error('NetworkCoordinator: provide verificationShares or enroll');
    }
    this.#pkById = new Map(this.verificationShares.map((v) => [v.identifier, b64u(v.publicKey)]));
    this.newSessionId = opts.newSessionId ?? (() => b64u(ed25519.utils.randomPrivateKey()));
    this.timeoutMs = opts.timeoutMs;
  }

  /**
   * Drive one t-of-n network signing session. `signerIds` picks which signers to use (default: the first
   * `threshold`). Returns the aggregate Ed25519 signature or throws {@link CoordinatorError} with the
   * per-signer refusal reasons — or {@link CoordinatorTimeoutError} if the bounded round deadline elapses.
   */
  async sign(
    message: Uint8Array,
    allow: AllowToken,
    opts: { signerIds?: ParticipantId[]; timeoutMs?: number } = {},
  ): Promise<NetworkSignResult> {
    const windowMs = opts.timeoutMs ?? this.timeoutMs;
    const run = this.#drive(message, allow, opts);
    if (windowMs === undefined || !Number.isFinite(windowMs) || windowMs <= 0) return run;
    // Swallow any late settlement of `run` so it cannot surface as an unhandled rejection after we time out.
    void run.catch(() => undefined);
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () => reject(new CoordinatorTimeoutError(`coordinator: signing session did not reach threshold within ${windowMs}ms`, windowMs)),
        windowMs,
      );
    });
    try {
      return await Promise.race([run, timeout]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  async #drive(message: Uint8Array, allow: AllowToken, opts: { signerIds?: ParticipantId[] }): Promise<NetworkSignResult> {
    if (!(message instanceof Uint8Array)) throw new Error('coordinator.sign: message must be bytes');
    const chosen = opts.signerIds
      ? this.signers.filter((s) => opts.signerIds!.includes(s.identifier))
      : this.signers.slice(0, this.threshold);
    if (chosen.length < this.threshold) {
      throw new CoordinatorError(`coordinator: only ${chosen.length} signer(s) selected, need t=${this.threshold}`);
    }
    const sessionId = this.newSessionId();

    // Round 1: collect commitments.
    const r1 = await Promise.all(
      chosen.map(async (s) => {
        try {
          return { s, resp: await s.round1({ typ: 'pca.frost.round1.v1', session_id: sessionId }) };
        } catch (e) {
          return { s, resp: { ok: false as const, identifier: s.identifier, reason: e instanceof Error ? e.message : 'unreachable' } };
        }
      }),
    );
    const refusals: { identifier: ParticipantId; reason: string }[] = [];
    const committed: { transport: SignerTransport; commitment: WireCommitment }[] = [];
    for (const { s, resp } of r1) {
      if (!resp.ok) {
        refusals.push({ identifier: resp.identifier, reason: resp.reason });
        continue;
      }
      // Rogue-key defense: the signer must prove possession of the verification share we have on record.
      const expectedPk = this.#pkById.get(resp.identifier);
      if (expectedPk === undefined) {
        refusals.push({ identifier: resp.identifier, reason: 'no verification share on record for this signer' });
        continue;
      }
      if (
        resp.pop === undefined ||
        resp.pop.identifier !== resp.identifier ||
        resp.pop.publicKey !== expectedPk ||
        !verifySignerPoP(resp.pop, { groupPublicKey: this.groupPublicKey })
      ) {
        refusals.push({ identifier: resp.identifier, reason: 'invalid or missing proof-of-possession (rogue-key defense)' });
        continue;
      }
      // Equivocation defense: a signer cannot bind this (session, round 1) to two different commitments.
      try {
        this.#equivocation.observe(sessionId, 1, resp.identifier, resp.commitment);
      } catch (e) {
        refusals.push({ identifier: resp.identifier, reason: e instanceof EquivocationError ? e.message : 'equivocation check failed' });
        continue;
      }
      committed.push({ transport: s, commitment: resp.commitment });
    }
    if (committed.length < this.threshold) {
      throw new CoordinatorError(`coordinator: round 1 produced ${committed.length} commitment(s), need t=${this.threshold}`, refusals);
    }
    // Use exactly t committed signers as the signing set (the verification shares must match this set).
    const set = committed.slice(0, this.threshold);
    const commitments = set.map((c) => c.commitment);
    const setIds = new Set(set.map((c) => c.commitment.identifier));
    const verification_shares: WireVerificationShare[] = this.verificationShares
      .filter((v) => setIds.has(v.identifier))
      .map((v) => ({ identifier: v.identifier, publicKey: b64u(v.publicKey) }));
    if (verification_shares.length !== set.length) {
      throw new CoordinatorError('coordinator: missing a verification share for a signer in the set');
    }

    // Round 2: collect signature shares.
    const r2req = (): Round2Request => ({
      typ: 'pca.frost.round2.v1',
      session_id: sessionId,
      message: b64u(message),
      group_pk: b64u(this.groupPublicKey),
      commitments,
      verification_shares,
      allow,
    });
    const r2 = await Promise.all(
      set.map(async ({ transport }) => {
        try {
          return await transport.round2(r2req());
        } catch (e) {
          return { ok: false as const, identifier: transport.identifier, refused: true as const, reason: e instanceof Error ? e.message : 'unreachable' };
        }
      }),
    );
    const sigShares: { identifier: ParticipantId; sigShare: Uint8Array }[] = [];
    for (const resp of r2) {
      if (!resp.ok) {
        refusals.push({ identifier: resp.identifier, reason: resp.reason });
        continue;
      }
      // Equivocation defense: a signer cannot bind this (session, round 2) to two different shares.
      try {
        this.#equivocation.observe(sessionId, 2, resp.identifier, { sig_share: resp.sig_share });
      } catch (e) {
        refusals.push({ identifier: resp.identifier, reason: e instanceof EquivocationError ? e.message : 'equivocation check failed' });
        continue;
      }
      const sb = decodeB64uStrict(resp.sig_share, 32);
      if (!sb) refusals.push({ identifier: resp.identifier, reason: 'malformed signature share' });
      else sigShares.push({ identifier: resp.identifier, sigShare: sb });
    }
    if (sigShares.length < this.threshold) {
      throw new CoordinatorError(`coordinator: round 2 produced ${sigShares.length} share(s), need t=${this.threshold}`, refusals);
    }

    // Aggregate with the existing frost.ts primitive (re-verifies; refuses an invalid aggregate).
    const aggCommitments: FrostCommitment[] = commitments.map(decodeCommitment);
    const signature = frostAggregate(message, aggCommitments, sigShares, this.groupPublicKey, {
      threshold: this.threshold,
      verificationShares: this.verificationShares.filter((v) => setIds.has(v.identifier)),
    });
    return { signature, sessionId, signers: set.map((c) => c.commitment.identifier) };
  }
}
