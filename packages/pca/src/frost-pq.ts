import { b64u, canonicalBytes, decodeB64uStrict, sha256, utf8 } from './hash';
import {
  type FrostParticipantShare,
  type ParticipantId,
  frostCosign,
} from './frost';
import {
  ML_DSA_65_PUBLIC_KEY_BYTES,
  type MlDsaKeyPair,
  signWithSuite,
  verifyWithSuite,
} from './pq';

/**
 * P6 — POST-QUANTUM AGILITY FOR THE FROST GUARDIAN-QUORUM CO-SIGN (interim hybrid).
 *
 * THE GAP THIS CLOSES
 * -------------------
 * `frost.ts` aggregates a guardian quorum into a SINGLE plain Ed25519 Schnorr group signature (RFC 9591
 * FROST(Ed25519, SHA-512)). That aggregate is byte-for-byte an ordinary Ed25519 signature under the group
 * public key — which is exactly why it drops into PCA's existing leaf-signature check with nothing new for
 * the verifier to learn (see `frost.ts` and `threshold.ts`). The cost is that the ENTIRE guardian-quorum
 * path rests on the discrete-log hardness of Ed25519: a cryptographically-relevant quantum computer that
 * breaks ECDLP forges the whole guardian co-sign. The rest of PCA already has post-quantum agility on every
 * OTHER signed surface (`pq.ts`: the `hybrid-ed25519-ml-dsa-65` suite, fail-closed `edOk && pqOk`); FROST was
 * the one hole.
 *
 * WHAT THIS IS (and is NOT)
 * -------------------------
 * This is the INTERIM HYBRID per the endgame plan P6: "classical FROST + an ML-DSA co-sign so a quantum
 * adversary must break BOTH." After the quorum produces its Ed25519 FROST aggregate over the threshold
 * message, the guardian key attaches an ML-DSA-65 (FIPS-204, CRYSTALS-Dilithium, lattice) CO-SIGNATURE over
 * the SAME canonical threshold message, context-bound to the FROST group public key + signer set + suite so
 * the co-sign cannot be lifted to another group, message, quorum, or suite. Verification is FAIL-CLOSED
 * HYBRID — BOTH the FROST Ed25519 group signature AND the guardian ML-DSA co-signature must verify, else
 * deny — the exact `edOk && pqOk` property that `verifyWithSuite`'s hybrid suites enforce and that
 * `threshold.ts`'s per-share `alg`/`pq_pk` hybrid shares already give the multi-signature path. A quantum
 * adversary must therefore break BOTH Ed25519 (classical) AND ML-DSA-65 (lattice) to forge a guardian
 * co-sign: the belt-and-suspenders property this file exists to provide.
 *
 * This is NOT a true post-quantum THRESHOLD signature. A single threshold ML-DSA (one lattice signature
 * jointly produced by a quorum with no party ever holding the key) is genuine, unsettled research — no
 * standardized, audited lattice-threshold signature exists, and we deliberately do NOT fake one. Here the
 * ML-DSA co-signature is minted by ONE guardian key (the long-lived guardian anchor whose release is gated
 * by the Policy VM, exactly as the classical guardian cosign is); the THRESHOLD property still rides on the
 * classical FROST aggregate, while the ML-DSA co-sign adds the post-quantum half. True PQ-threshold (a FROST
 * analogue over a lattice scheme, or an MPC lattice-signing ceremony) is FUTURE WORK; until then this hybrid
 * is the sound, deployable step, because forging it requires breaking both primitives and the quantum
 * adversary gains nothing by breaking only one.
 *
 * BACK-COMPAT
 * -----------
 * The aggregated artifact is SELF-DESCRIBING via `groupAlg`, defaulting to classical `ed25519`-only when
 * absent. An `ed25519` artifact is just `{ sig }` — byte-identical in shape to the raw FROST aggregate — and
 * verifies with only the Ed25519 check, exactly as before. `hybrid-ed25519-ml-dsa-65` additionally carries
 * (and requires) the ML-DSA co-signature. A `hybrid`-declared artifact whose PQ co-sign is MISSING or INVALID
 * is DENIED (there is no silent downgrade): the suite is part of what the co-sign binds, so a verifier told
 * to expect hybrid cannot be tricked into accepting the classical half alone.
 */

/** The post-quantum agility suites the aggregated FROST artifact supports. Default = classical `ed25519`. */
export type FrostGroupAlg = 'ed25519' | 'hybrid-ed25519-ml-dsa-65';

/** The suite used when `groupAlg` is absent — classical FROST only. MUST stay `ed25519` for back-compat. */
export const DEFAULT_FROST_GROUP_ALG: FrostGroupAlg = 'ed25519';

function isKnownFrostGroupAlg(x: unknown): x is FrostGroupAlg {
  return x === 'ed25519' || x === 'hybrid-ed25519-ml-dsa-65';
}

/** Resolve the artifact's `groupAlg` (absent => the default `ed25519`); `null` for an unknown value (fail-closed). */
export function resolveFrostGroupAlg(groupAlg: unknown): FrostGroupAlg | null {
  if (groupAlg === undefined) return DEFAULT_FROST_GROUP_ALG;
  return isKnownFrostGroupAlg(groupAlg) ? groupAlg : null;
}

/**
 * The aggregated FROST guardian co-sign artifact (wire shape; all signature material is b64u).
 *
 * `ed25519`:                   `{ sig }` only — the plain FROST aggregate, byte-identical in shape to the raw
 *                              RFC 9591 output; verifies as an ordinary Ed25519 signature under the group key.
 * `hybrid-ed25519-ml-dsa-65`:  `{ sig, groupAlg, pq_sig, pq_pk }` — `sig` is the SAME FROST Ed25519 aggregate,
 *                              `pq_sig` is the guardian's ML-DSA-65 co-signature over the context-bound
 *                              representative, `pq_pk` self-describes the guardian ML-DSA public key (but
 *                              verification binds to the verifier's REGISTERED guardian key, never this one).
 */
export interface HybridFrostSignature {
  /** b64u 64-byte FROST Ed25519 Schnorr group signature over the threshold `message` (the RFC 9591 aggregate). */
  sig: string;
  /**
   * Aggregated-artifact suite (crypto-agility). Absent == `ed25519` (classical-only, byte-identical shape to
   * the raw aggregate). `hybrid-ed25519-ml-dsa-65` means a guardian ML-DSA-65 co-sign MUST also be present and
   * valid. The suite is bound into the co-sign representative, so it cannot be stripped/downgraded on the wire.
   */
  groupAlg?: FrostGroupAlg;
  /** b64u ML-DSA-65 guardian co-signature over the co-sign representative — present (and REQUIRED) for hybrid only. */
  pq_sig?: string;
  /** b64u ML-DSA-65 guardian public key — self-describing for hybrid; verification uses the REGISTERED key, not this. */
  pq_pk?: string;
}

const FROST_COSIGN_DOMAIN = 'atlas-pca/frost-pq-cosign/v1\0';
const FROST_SIGNER_SET_DOMAIN = 'atlas-pca/frost-signer-set/v1\0';

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/**
 * Canonical digest of the FROST signer set (the quorum of participant identifiers that produced the
 * aggregate): `sha256(DOMAIN || canonical(sorted-distinct ids))`. Order-insensitive and duplicate-free, so
 * signer and verifier agree however the quorum is listed. A zero-length or non-integer id is rejected
 * (identifiers are positive integers, as in `frost.ts`).
 */
export function frostSignerSetDigest(signerSet: readonly ParticipantId[]): Uint8Array {
  if (!Array.isArray(signerSet) || signerSet.length === 0) throw new RangeError('frostSignerSetDigest: empty signer set');
  const ids = [...new Set(signerSet)];
  for (const id of ids) {
    if (typeof id !== 'number' || !Number.isSafeInteger(id) || id <= 0) {
      throw new RangeError('frostSignerSetDigest: participant identifiers must be positive safe integers');
    }
  }
  ids.sort((a, b) => a - b);
  return sha256(concat(utf8(FROST_SIGNER_SET_DOMAIN), canonicalBytes(ids)));
}

/**
 * The exact bytes the guardian ML-DSA-65 co-signature covers:
 *
 *   DOMAIN || groupAlg || 0x00 || groupPublicKey(32) || sha256(message) || signerSetDigest(32)
 *
 * Binding each component means the co-sign cannot be lifted to another CONTEXT:
 *  - `groupPublicKey` ties it to THIS FROST group (not some other group's key);
 *  - `sha256(message)` ties it to THIS threshold message (the one the FROST aggregate also signs);
 *  - `signerSetDigest` ties it to THIS quorum of signers;
 *  - `groupAlg` ties it to THIS suite, so the hybrid declaration cannot be stripped to classical.
 *
 * `groupPublicKey` MUST be a 32-byte Ed25519 point (b64u); a malformed key throws.
 */
export function frostCosignRepresentative(
  groupPublicKeyB64u: string,
  message: Uint8Array,
  signerSet: readonly ParticipantId[],
  groupAlg: FrostGroupAlg,
): Uint8Array {
  const gpk = decodeB64uStrict(groupPublicKeyB64u, 32);
  if (gpk === null) throw new RangeError('frostCosignRepresentative: groupPublicKey must be a 32-byte base64url point');
  return concat(
    utf8(FROST_COSIGN_DOMAIN),
    utf8(groupAlg),
    new Uint8Array([0]),
    gpk,
    sha256(message),
    frostSignerSetDigest(signerSet),
  );
}

export interface HybridFrostCosignOpts {
  /** Aggregated-artifact suite. Default `ed25519` (classical-only). */
  groupAlg?: FrostGroupAlg;
  /**
   * The guardian's ML-DSA-65 key pair — REQUIRED for `hybrid-ed25519-ml-dsa-65`. Its secret key mints the PQ
   * co-signature; its public key is emitted as `pq_pk`. The guardian is the long-lived anchor whose co-sign
   * the Policy VM releases, exactly as for the classical path.
   */
  guardianMlDsa?: MlDsaKeyPair;
  /** Reject a quorum smaller than `t` up front (forwarded to {@link frostCosign}). */
  threshold?: number;
}

/**
 * Produce a hybrid PQ FROST guardian co-sign over `message`.
 *
 * Runs the classical FROST signing round (round 1 → round 2 → aggregate) over `quorum` via {@link frostCosign}
 * — which keeps EVERY safety check on and refuses to return an invalid / sub-threshold aggregate — to obtain
 * the Ed25519 group signature. For the default `ed25519` suite it returns just `{ sig }` (byte-identical shape
 * to the raw aggregate). For `hybrid-ed25519-ml-dsa-65` it additionally mints an ML-DSA-65 co-signature with
 * the guardian key over {@link frostCosignRepresentative} (the SAME threshold message, context-bound) and
 * returns `{ sig, groupAlg, pq_sig, pq_pk }`. FAIL-CLOSED: a hybrid suite with no guardian ML-DSA key throws
 * (a signer must never silently emit a weaker artifact than it intended).
 */
export function signHybridFrostCosign(
  groupPublicKey: Uint8Array,
  quorum: FrostParticipantShare[],
  message: Uint8Array,
  opts: HybridFrostCosignOpts = {},
): HybridFrostSignature {
  const groupAlg = opts.groupAlg ?? DEFAULT_FROST_GROUP_ALG;
  if (!isKnownFrostGroupAlg(groupAlg)) throw new RangeError(`signHybridFrostCosign: unknown groupAlg '${String(groupAlg)}'`);

  // Classical FROST aggregate (all recommended checks on; throws on a forged / insufficient quorum).
  const aggregate = frostCosign(
    groupPublicKey,
    quorum,
    message,
    opts.threshold !== undefined ? { threshold: opts.threshold } : {},
  );
  const sig = b64u(aggregate);
  if (groupAlg === 'ed25519') return { sig };

  // hybrid-ed25519-ml-dsa-65: attach the guardian ML-DSA co-sign over the context-bound representative.
  if (!opts.guardianMlDsa || !(opts.guardianMlDsa.secretKey instanceof Uint8Array)) {
    throw new TypeError(`signHybridFrostCosign: '${groupAlg}' requires a guardian ML-DSA-65 key pair`);
  }
  const groupPublicKeyB64u = b64u(groupPublicKey);
  const representative = frostCosignRepresentative(groupPublicKeyB64u, message, quorum.map((p) => p.identifier), groupAlg);
  // Reuse the pq.ts suite seam for the lattice half (pure ml-dsa-65 over the representative).
  const pq = signWithSuite('ml-dsa-65', { mlDsa: opts.guardianMlDsa }, representative);
  return { sig, groupAlg, pq_sig: pq.sig, pq_pk: b64u(opts.guardianMlDsa.publicKey) };
}

export interface HybridFrostVerdict {
  ok: boolean;
  /** The resolved suite actually verified (`ed25519` or `hybrid-ed25519-ml-dsa-65`). */
  groupAlg?: FrostGroupAlg;
  /** Whether the FROST Ed25519 group signature verified. */
  edOk: boolean;
  /** Whether the guardian ML-DSA-65 co-signature verified (always `false` for the classical `ed25519` suite). */
  pqOk: boolean;
  reason?: string;
}

export interface VerifyHybridFrostOpts {
  /**
   * The guardian's REGISTERED ML-DSA-65 public key (b64u). REQUIRED when the artifact declares `hybrid`
   * (or when {@link expectGroupAlg} is hybrid). Mirroring `threshold.ts`, verification binds to THIS
   * registered key — never the self-asserted `pq_pk` on the artifact — so an attacker cannot swap in their
   * own ML-DSA key. If the artifact carries a `pq_pk` it MUST equal this key, else the verdict is denied.
   */
  guardianPqPublicKey?: string;
  /**
   * Pin the suite the verifier REQUIRES. When set to `hybrid-ed25519-ml-dsa-65`, an artifact that declares
   * (or carries) only `ed25519` is DENIED — this is the fail-closed guard against a downgrade: a caller that
   * knows the guardian runs hybrid refuses a classical-only artifact. When omitted, the artifact's own
   * `groupAlg` selects the suite (defaulting to `ed25519`).
   */
  expectGroupAlg?: FrostGroupAlg;
}

/**
 * Verify a hybrid PQ FROST guardian co-sign over `message`. FAIL-CLOSED HYBRID: for the hybrid suite BOTH the
 * FROST Ed25519 group signature (over `message`, under `groupPublicKey`) AND the guardian ML-DSA-65
 * co-signature (over {@link frostCosignRepresentative}, under the REGISTERED guardian key) must verify — the
 * `edOk && pqOk` property. Deterministic and TOTAL — never throws.
 *
 * Rules:
 *  - unknown `groupAlg`, or a `groupAlg` that disagrees with a pinned {@link VerifyHybridFrostOpts.expectGroupAlg}
 *    => deny (no silent downgrade);
 *  - `ed25519` => deny unless the FROST aggregate verifies;
 *  - `hybrid-ed25519-ml-dsa-65` => deny unless the FROST aggregate verifies AND a registered guardian ML-DSA key
 *    is supplied AND the ML-DSA co-signature over the context-bound representative verifies under it. A missing
 *    or invalid `pq_sig`, an absent registered guardian key, or a `pq_pk` that disagrees with the registered
 *    key all DENY.
 *
 * `signerSet` is the quorum of FROST participant identifiers the co-sign must bind (a verifier input, exactly
 * as the signer set is in `threshold.ts`); it is folded into the representative the ML-DSA half covers.
 */
export function verifyHybridFrostCosign(
  artifact: HybridFrostSignature,
  message: Uint8Array,
  groupPublicKeyB64u: string,
  signerSet: readonly ParticipantId[],
  opts: VerifyHybridFrostOpts = {},
): HybridFrostVerdict {
  const deny = (reason: string, groupAlg?: FrostGroupAlg): HybridFrostVerdict => ({ ok: false, edOk: false, pqOk: false, ...(groupAlg ? { groupAlg } : {}), reason });

  if (!artifact || typeof artifact !== 'object' || typeof artifact.sig !== 'string') return deny('malformed artifact');
  if (typeof groupPublicKeyB64u !== 'string' || decodeB64uStrict(groupPublicKeyB64u, 32) === null) return deny('malformed group public key');

  const groupAlg = resolveFrostGroupAlg(artifact.groupAlg);
  if (groupAlg === null) return deny(`unknown groupAlg '${String(artifact.groupAlg)}'`);
  // Fail-closed downgrade guard: a verifier that pins hybrid refuses an ed25519-only artifact.
  if (opts.expectGroupAlg !== undefined) {
    if (!isKnownFrostGroupAlg(opts.expectGroupAlg)) return deny(`unknown expected groupAlg '${String(opts.expectGroupAlg)}'`);
    if (opts.expectGroupAlg !== groupAlg) return deny(`groupAlg '${groupAlg}' does not match the required '${opts.expectGroupAlg}'`, groupAlg);
  }

  // The FROST Ed25519 group signature, verified as a plain Ed25519 signature under the group key — the SAME
  // check PCA's leaf-signature path performs (reuses the pq.ts ed25519 seam == verifyB64u).
  let edOk = false;
  try {
    edOk = verifyWithSuite('ed25519', { edPub: groupPublicKeyB64u }, message, { sig: artifact.sig });
  } catch {
    edOk = false;
  }

  if (groupAlg === 'ed25519') {
    if (!edOk) return deny('FROST Ed25519 group signature did not verify', groupAlg);
    return { ok: true, groupAlg, edOk: true, pqOk: false };
  }

  // hybrid-ed25519-ml-dsa-65: BOTH halves required (fail-closed).
  const registeredPq = opts.guardianPqPublicKey;
  if (typeof registeredPq !== 'string' || decodeB64uStrict(registeredPq, ML_DSA_65_PUBLIC_KEY_BYTES) === null) {
    return deny('hybrid groupAlg requires a registered guardian ML-DSA-65 public key', groupAlg);
  }
  // A self-asserted pq_pk, if present, must equal the registered key (verification binds to the registered one).
  if (artifact.pq_pk !== undefined && artifact.pq_pk !== registeredPq) {
    return deny('artifact pq_pk does not match the registered guardian ML-DSA key', groupAlg);
  }
  if (typeof artifact.pq_sig !== 'string') {
    return deny('hybrid groupAlg declared but the guardian ML-DSA co-signature is missing', groupAlg);
  }

  let pqOk = false;
  try {
    const representative = frostCosignRepresentative(groupPublicKeyB64u, message, signerSet, groupAlg);
    // Reuse the pq.ts suite seam for the lattice half (ml-dsa-65 co-sign over the representative).
    pqOk = verifyWithSuite('ml-dsa-65', { mlDsaPub: registeredPq }, representative, { sig: artifact.pq_sig });
  } catch {
    pqOk = false;
  }

  if (!edOk || !pqOk) {
    return { ok: false, groupAlg, edOk, pqOk, reason: !edOk ? 'FROST Ed25519 group signature did not verify' : 'guardian ML-DSA-65 co-signature did not verify' };
  }
  return { ok: true, groupAlg, edOk: true, pqOk: true };
}
