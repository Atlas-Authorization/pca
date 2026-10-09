/**
 * @atlasauth/pca-pq-threshold — post-quantum threshold step-up for PCActn.
 *
 * THE HONEST TWO-PART ANSWER
 * ==========================
 * There is, as of today, NO production-grade lattice-THRESHOLD signature library: Raccoon and
 * Ringtail (the leading candidate threshold/multi-party ML-DSA-style schemes) exist only as
 * academic constructions and reference code, none of it audited, constant-time, or interop-stable.
 * Shipping a "trustless post-quantum threshold" on top of that today would be dishonest.
 *
 * So this package delivers two clearly-separated things:
 *
 *  (1) A REAL, production-usable HYBRID (this file). A step-up is authorised by BOTH
 *        • a classical FROST(Ed25519) t-of-n THRESHOLD signature over the action, AND
 *        • a pqT-of-m quorum of ML-DSA-65 (FIPS-204) co-signatures over the SAME action digest.
 *      A verifier accepts the step-up only if BOTH quorums hold; it fails closed if either is short.
 *      Security intuition: a future quantum break of the classical threshold (Ed25519 discrete log
 *      via Shor) does NOT forge the step-up, because the attacker would ALSO have to forge a
 *      pqT-of-m quorum of ML-DSA signatures — a lattice problem believed quantum-hard. Conversely a
 *      classical-only adversary is stopped by the FROST threshold exactly as before. The PQ layer is
 *      strictly additive protection on top of today's shippable classical threshold. The only
 *      centralisation the PQ layer introduces is that the m ML-DSA keys are ordinary (single-party)
 *      keys held by m distinct signers — a MULTI-signature quorum, not a true threshold. That is the
 *      honest, available-today design; the trustless-threshold future is part (2).
 *
 *  (2) A clearly-labelled Raccoon/Ringtail RESEARCH design + toy prototype — see
 *      `./experimental/lattice-threshold` (re-exported here under the `experimental` namespace). It
 *      carries a loud "NOT PRODUCTION" banner, is gated behind an explicit opt-in flag, and must
 *      never be mistaken for the shippable path above.
 *
 * REUSE: every primitive here is imported from `@atlasauth/pca` — the FROST threshold
 * (`frostTrustedDealerKeygen` / `frostCosign`, verified as an Ed25519 signature under the trusted group key) and the
 * ML-DSA-65 sign/verify (`mlDsa65Sign` / `mlDsa65VerifyB64u`). Nothing cryptographic is
 * reimplemented here; this module only COMPOSES the two quorums and binds them to a PCActn step-up.
 */

import {
  type Capability,
  type FrostParticipantShare,
  ML_DSA_65_PUBLIC_KEY_BYTES,
  type MlDsaKeyPair,
  type PCActn,
  type PCActnBody,
  type Signer,
  type ThresholdShare,
  type ThresholdVerifier,
  type VerifyContext,
  type VerifyResult,
  assembleThreshold,
  b64u,
  decodeB64uStrict,
  frostCosign,
  mlDsa65Sign,
  mlDsa65VerifyB64u,
  sha256,
  thresholdMessage,
  verifyPCActnCore,
  verifyB64u,
} from '@atlasauth/pca';

export * as experimental from './experimental/lattice-threshold';

// ---------------------------------------------------------------------------------------------
// Artifact wire types
// ---------------------------------------------------------------------------------------------

export const HYBRID_ARTIFACT_VERSION = 1 as const;
/** The classical threshold part is a FROST(Ed25519) aggregate — a standard 64-byte Ed25519 signature. */
export const HYBRID_CLASSICAL_ALG = 'frost-ed25519' as const;
/** The post-quantum co-signatures are ML-DSA-65 (FIPS-204, NIST security category 3). */
export const HYBRID_PQ_ALG = 'ml-dsa-65' as const;

/** 32-byte Ed25519 point / 64-byte Ed25519 signature or 1952/3309-byte ML-DSA material — as bytes OR b64u. */
export type BytesOrB64u = Uint8Array | string;

/** The classical FROST t-of-n part of a hybrid artifact. */
export interface FrostThresholdPart {
  readonly alg: typeof HYBRID_CLASSICAL_ALG;
  /** b64u(32) FROST group public key the aggregate verifies under. */
  readonly group_pk: string;
  /** b64u(64) FROST(Ed25519) aggregate signature over `thresholdMessage(action)`. */
  readonly sig: string;
  /** The classical threshold `t` the group key was shared for (declared; the group key enforces it cryptographically). */
  readonly t: number;
  /** Number of participants that contributed to this aggregate (>= t). */
  readonly quorum: number;
}

/** One post-quantum co-signer's ML-DSA-65 signature over the action digest. */
export interface PqCoSignature {
  /** b64u(1952) ML-DSA-65 public key of the co-signer. */
  readonly pk: string;
  /** b64u(3309) ML-DSA-65 signature over `thresholdMessage(action)`. */
  readonly sig: string;
}

/** The post-quantum pqT-of-m part of a hybrid artifact. */
export interface PqCoSignBlock {
  readonly alg: typeof HYBRID_PQ_ALG;
  /** PQ quorum size recorded at signing (informational; the verifier enforces its OWN pqT). */
  readonly pqT: number;
  readonly signers: readonly PqCoSignature[];
}

/**
 * A combined hybrid threshold artifact: the classical FROST t-of-n threshold signature PLUS the
 * post-quantum pqT-of-m ML-DSA co-signature quorum, both over the SAME action digest.
 */
export interface HybridThresholdArtifact {
  readonly v: typeof HYBRID_ARTIFACT_VERSION;
  /** b64u(sha256(thresholdMessage(action))) — the single action digest both quorums cover. Audit/debug. */
  readonly digest: string;
  readonly frost: FrostThresholdPart;
  readonly pq: PqCoSignBlock;
}

// ---------------------------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------------------------

/** The classical FROST quorum material supplied to {@link hybridThresholdSign}. */
export interface FrostQuorumInput {
  /** The FROST group public key (from `frostTrustedDealerKeygen` / DKG). */
  readonly groupPublicKey: BytesOrB64u;
  /** The quorum of participant shares that will co-sign (length MUST be >= t). */
  readonly quorum: readonly FrostParticipantShare[];
  /** The classical threshold t the group key was shared for. */
  readonly t: number;
}

/** One post-quantum co-signer's ML-DSA-65 key pair. */
export interface PqSignerInput {
  readonly keyPair: MlDsaKeyPair;
}

export interface HybridSignInput {
  readonly frost: FrostQuorumInput;
  readonly pqSigners: readonly PqSignerInput[];
  /** PQ quorum size to record on the artifact (informational; defaults to the number of co-signers). */
  readonly pqT?: number;
}

function toBytes32GroupKey(k: BytesOrB64u): Uint8Array {
  if (k instanceof Uint8Array) {
    if (k.length !== 32) throw new RangeError('hybridThresholdSign: FROST group public key must be 32 bytes');
    return k;
  }
  const decoded = decodeB64uStrict(k, 32);
  if (decoded === null) throw new RangeError('hybridThresholdSign: FROST group public key is not canonical b64u(32)');
  return decoded;
}

/**
 * Produce a hybrid threshold artifact for `action`:
 *   • the classical FROST(Ed25519) t-of-n aggregate over `thresholdMessage(action)`, produced by
 *     `frostCosign` (which FAILS CLOSED — throws — on a quorum shorter than t or an invalid share), and
 *   • one ML-DSA-65 co-signature per `pqSigners` entry over the SAME message bytes.
 *
 * Both quorums sign exactly `thresholdMessage(action)`, so they are provably over the same action and
 * neither can be replayed onto a different one.
 */
export function hybridThresholdSign(action: PCActn | PCActnBody, input: HybridSignInput): HybridThresholdArtifact {
  const t = input.frost.t;
  if (!Number.isInteger(t) || t < 1) throw new RangeError(`hybridThresholdSign: frost.t must be a positive integer (got ${String(t)})`);
  if (input.frost.quorum.length < t) {
    // Fail closed at construction: a sub-threshold classical quorum cannot authorise a step-up.
    throw new RangeError(`hybridThresholdSign: FROST quorum of ${input.frost.quorum.length} is below the threshold t=${t}`);
  }
  if (input.pqSigners.length === 0) throw new RangeError('hybridThresholdSign: at least one ML-DSA co-signer is required');

  const message = thresholdMessage(action);
  const groupKey = toBytes32GroupKey(input.frost.groupPublicKey);

  // Classical FROST t-of-n aggregate (a standard Ed25519 signature under the group key). `frostCosign`
  // runs every RFC-9591 safety check and REFUSES to return an aggregate that does not verify.
  const aggregate = frostCosign(groupKey, [...input.frost.quorum], message, { threshold: t });

  const frost: FrostThresholdPart = {
    alg: HYBRID_CLASSICAL_ALG,
    group_pk: b64u(groupKey),
    sig: b64u(aggregate),
    t,
    quorum: input.frost.quorum.length,
  };

  // Post-quantum co-signature quorum: each signer's ML-DSA-65 signature over the same message.
  const signers: PqCoSignature[] = input.pqSigners.map((s) => ({
    pk: b64u(s.keyPair.publicKey),
    sig: b64u(mlDsa65Sign(s.keyPair.secretKey, message)),
  }));

  const pqT = input.pqT ?? signers.length;
  const pq: PqCoSignBlock = { alg: HYBRID_PQ_ALG, pqT, signers };

  return { v: HYBRID_ARTIFACT_VERSION, digest: b64u(sha256(message)), frost, pq };
}

// ---------------------------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------------------------

export interface HybridVerifyOpts {
  /** The TRUSTED FROST group public key (the verifier's own pinned key, NOT the artifact's self-declared one). */
  readonly groupKey: BytesOrB64u;
  /** The TRUSTED pool of ML-DSA-65 co-signer public keys (the m registered keys). */
  readonly pqPublicKeys: readonly BytesOrB64u[];
  /** Required classical FROST threshold (t-of-n). */
  readonly t: number;
  /** Required post-quantum quorum (pqT-of-m). */
  readonly pqT: number;
}

export interface PqVerdict {
  readonly ok: boolean;
  /** Number of DISTINCT trusted ML-DSA keys whose co-signature verified over this action. */
  readonly count: number;
  /** Required pqT. */
  readonly need: number;
  readonly reason?: string;
}

export interface HybridVerdict {
  readonly ok: boolean;
  /** Did the classical FROST t-of-n aggregate verify under the trusted group key? */
  readonly frost: boolean;
  readonly pq: PqVerdict;
  readonly reason?: string;
}

function normalizeGroupKeyB64u(k: BytesOrB64u): string | null {
  const s = k instanceof Uint8Array ? b64u(k) : k;
  return decodeB64uStrict(s, 32) === null ? null : s;
}

function normalizePqPool(pks: readonly BytesOrB64u[]): Set<string> {
  const pool = new Set<string>();
  for (const p of pks) {
    const s = p instanceof Uint8Array ? b64u(p) : p;
    // Only well-formed ML-DSA-65 public keys join the trusted pool; malformed entries are ignored.
    if (typeof s === 'string' && decodeB64uStrict(s, ML_DSA_65_PUBLIC_KEY_BYTES) !== null) pool.add(s);
  }
  return pool;
}

/**
 * Verify the classical FROST t-of-n aggregate as a plain Ed25519 verification: the FROST
 * aggregate is a standard Ed25519 signature under the group key, and the group key signs
 * `thresholdMessage` directly.
 *
 * Crucially the aggregate is checked under the VERIFIER'S trusted `trustedGroupKeyB64u` — not any
 * group key the artifact declares — so an attacker who swaps in a signature under a group key THEY
 * control cannot pass. And a sub-threshold / forged classical quorum can never produce an Ed25519
 * signature that verifies under a genuine t-of-n group key, so "the FROST quorum is short" fails here.
 */
function verifyFrostAggregate(sigB64u: unknown, message: Uint8Array, trustedGroupKeyB64u: string): boolean {
  if (typeof sigB64u !== 'string') return false;
  // The FROST aggregate is a plain Ed25519 signature by the group key over `thresholdMessage`, so it is
  // checked directly under the TRUSTED group key (strict canonical encodings; never throws).
  try {
    return verifyB64u(trustedGroupKeyB64u, message, sigB64u);
  } catch {
    return false;
  }
}

/**
 * Verify the post-quantum pqT-of-m quorum. Counts DISTINCT trusted ML-DSA keys whose signature
 * verifies over `message`. A co-signature from a key not in the trusted pool, a duplicate key, or a
 * signature over a DIFFERENT action (its bytes differ, so `mlDsa65VerifyB64u` fails) does not count —
 * so "the PQ quorum is short" and "a PQ co-sig is over a different action" both fail here, independently.
 */
function verifyPqQuorum(pq: unknown, message: Uint8Array, trustedPool: Set<string>, pqT: number): PqVerdict {
  if (!Number.isInteger(pqT) || pqT < 1) return { ok: false, count: 0, need: pqT, reason: 'pqT must be a positive integer' };
  if (typeof pq !== 'object' || pq === null) return { ok: false, count: 0, need: pqT, reason: 'malformed pq block' };
  const block = pq as { alg?: unknown; signers?: unknown };
  if (block.alg !== HYBRID_PQ_ALG || !Array.isArray(block.signers)) return { ok: false, count: 0, need: pqT, reason: 'malformed pq block' };
  const entries: unknown[] = block.signers;

  const counted = new Set<string>();
  for (const entry of entries) {
    if (typeof entry !== 'object' || entry === null) continue;
    const s = entry as { pk?: unknown; sig?: unknown };
    if (typeof s.pk !== 'string' || typeof s.sig !== 'string') continue;
    if (!trustedPool.has(s.pk)) continue; // not a registered co-signer
    if (counted.has(s.pk)) continue; // a key counts at most once
    if (!mlDsa65VerifyB64u(s.pk, message, s.sig)) continue; // must verify over THIS action's bytes
    counted.add(s.pk);
  }
  const count = counted.size;
  if (count >= pqT) return { ok: true, count, need: pqT };
  return { ok: false, count, need: pqT, reason: `post-quantum quorum short: ${count} of ${pqT} required ML-DSA co-signatures` };
}

/**
 * Verify a standalone hybrid threshold artifact over `action`. Requires BOTH the classical FROST
 * t-of-n AND the post-quantum pqT-of-m quorum to hold; fails closed if EITHER is short. The classical
 * declared threshold must not be below the required `t` (downgrade protection).
 */
export function verifyHybridThreshold(
  action: PCActn | PCActnBody,
  artifact: HybridThresholdArtifact,
  opts: HybridVerifyOpts,
): HybridVerdict {
  const message = thresholdMessage(action);
  const trustedGroupKey = normalizeGroupKeyB64u(opts.groupKey);
  const pool = normalizePqPool(opts.pqPublicKeys);

  let frostOk = false;
  let frostReason: string | undefined;
  if (!Number.isInteger(opts.t) || opts.t < 1) {
    frostReason = 't must be a positive integer';
  } else if (trustedGroupKey === null) {
    frostReason = 'trusted FROST group key is not a canonical b64u(32) point';
  } else if (typeof artifact?.frost !== 'object' || artifact.frost === null || artifact.frost.alg !== HYBRID_CLASSICAL_ALG) {
    frostReason = 'malformed or missing FROST part';
  } else if (!Number.isInteger(artifact.frost.t) || artifact.frost.t < opts.t) {
    frostReason = `FROST declared threshold ${String(artifact.frost.t)} is below the required t=${opts.t} (downgrade)`;
  } else if (!verifyFrostAggregate(artifact.frost.sig, message, trustedGroupKey)) {
    frostReason = 'FROST aggregate does not verify under the trusted group key (quorum short, wrong group, or forged)';
  } else {
    frostOk = true;
  }

  const pq = verifyPqQuorum(artifact?.pq, message, pool, opts.pqT);

  const ok = frostOk && pq.ok;
  if (ok) return { ok, frost: frostOk, pq };
  return { ok, frost: frostOk, pq, reason: frostOk ? pq.reason : frostReason };
}

// ---------------------------------------------------------------------------------------------
// Folding into a PCActn step-up (tier-2 / tier-3, PQ-protected)
// ---------------------------------------------------------------------------------------------

/**
 * A hybrid step-up: the PCActn with the classical FROST aggregate folded into its signed-threshold
 * container (`threshold`), plus the post-quantum co-sign block that travels ALONGSIDE it. `thresholdMessage`
 * excludes the `threshold` field, so folding the classical aggregate in does NOT change the bytes either
 * quorum signed — the agent leaf `sig` and both quorums stay valid over the identical message.
 */
export interface HybridStepUp {
  readonly pcactn: PCActn;
  readonly pq: PqCoSignBlock;
}

/**
 * Fold a hybrid artifact into a PCActn step-up. The classical FROST aggregate becomes a share in the
 * PCActn's `threshold` field (role 'guardian' — the FROST quorum IS the guardian/Policy-VM tier; its
 * `publicKey` is the FROST group key, `sig` the 64-byte aggregate). The PQ block rides alongside because
 * it cannot live in the signed body (a signature cannot sign itself), exactly like the leaf `pq_sig`.
 */
export function foldHybridStepUp(action: PCActn, artifact: HybridThresholdArtifact): HybridStepUp {
  const frostShare: ThresholdShare = { role: 'guardian', publicKey: artifact.frost.group_pk, sig: artifact.frost.sig };
  const existing = action.threshold && Array.isArray(action.threshold.shares) ? action.threshold.shares : [];
  const threshold = assembleThreshold([...existing, frostShare]);
  return { pcactn: { ...action, threshold }, pq: artifact.pq };
}

/** Locate the folded FROST aggregate in a PCActn's threshold container by its group-key `publicKey`. */
function findFrostShare(pcactn: PCActn, trustedGroupKeyB64u: string): ThresholdShare | undefined {
  const shares = pcactn.threshold && Array.isArray(pcactn.threshold.shares) ? pcactn.threshold.shares : [];
  return shares.find((s) => s && typeof s.sig === 'string' && s.publicKey === trustedGroupKeyB64u);
}

/**
 * A `ThresholdVerifier` hook (the L2/M4 PCActn threshold seam) enforcing the HYBRID step-up: the
 * classical FROST t-of-n (folded into `pcactn.threshold`, verified as an Ed25519 signature under the trusted group key)
 * AND the post-quantum pqT-of-m quorum (the co-sign block, closed over per action).
 * Returns enforced=true, ok=true only if BOTH hold — so it drops straight into `verifyPCActnCore`.
 */
export function createHybridThresholdVerifier(opts: {
  readonly groupKey: BytesOrB64u;
  readonly pqPublicKeys: readonly BytesOrB64u[];
  readonly t: number;
  readonly pqT: number;
  /** The PQ co-sign block for THIS action (it is not part of the signed body, so it is supplied here). */
  readonly pqBlock: PqCoSignBlock;
}): ThresholdVerifier {
  const trustedGroupKey = normalizeGroupKeyB64u(opts.groupKey);
  const pool = normalizePqPool(opts.pqPublicKeys);
  return (ctx: VerifyContext) => {
    const message = thresholdMessage(ctx.pcactn);
    if (trustedGroupKey === null) return { enforced: true, ok: false, reason: 'trusted FROST group key is not a canonical b64u(32) point' };
    const share = findFrostShare(ctx.pcactn, trustedGroupKey);
    if (!share) return { enforced: true, ok: false, reason: 'no FROST aggregate for the trusted group key in the step-up' };
    if (!verifyFrostAggregate(share.sig, message, trustedGroupKey)) {
      return { enforced: true, ok: false, reason: 'FROST aggregate does not verify under the trusted group key (quorum short or forged)' };
    }
    const pq = verifyPqQuorum(opts.pqBlock, message, pool, opts.pqT);
    if (!pq.ok) return { enforced: true, ok: false, reason: pq.reason ?? 'post-quantum quorum short' };
    return { enforced: true, ok: true };
  };
}

export interface HybridStepUpVerifyOpts {
  readonly grant: Capability;
  readonly groupKey: BytesOrB64u;
  readonly pqPublicKeys: readonly BytesOrB64u[];
  /** Required classical FROST threshold — this is the step-up TIER (2 = guardian quorum, 3 = higher). */
  readonly t: number;
  /** Required post-quantum quorum. */
  readonly pqT: number;
  readonly audience?: string | null;
  readonly nowEpoch?: number;
}

export interface HybridStepUpResult {
  readonly allow: boolean;
  /** The full PCActn verification (wire, audience, validity, cap-chain, leaf sig, counter, threshold hook). */
  readonly core: VerifyResult;
  /** The post-quantum quorum verdict, surfaced separately for auditing. */
  readonly pq: PqVerdict;
  readonly reason?: string;
}

/**
 * Verify a folded hybrid step-up end-to-end: runs the full `verifyPCActnCore` with the hybrid threshold
 * hook, so the step-up passes only when the whole PCActn is valid AND both the classical FROST t-of-n and
 * the post-quantum pqT-of-m quorum hold. `t` is the step-up tier (2 or 3). The PQ verdict is also computed
 * standalone for the audit surface.
 */
export async function verifyHybridStepUp(stepUp: HybridStepUp, opts: HybridStepUpVerifyOpts): Promise<HybridStepUpResult> {
  const pool = normalizePqPool(opts.pqPublicKeys);
  const pqVerdict = verifyPqQuorum(stepUp.pq, thresholdMessage(stepUp.pcactn), pool, opts.pqT);
  const hook = createHybridThresholdVerifier({
    groupKey: opts.groupKey,
    pqPublicKeys: opts.pqPublicKeys,
    t: opts.t,
    pqT: opts.pqT,
    pqBlock: stepUp.pq,
  });
  const core = await verifyPCActnCore(stepUp.pcactn, {
    grant: opts.grant,
    audience: opts.audience,
    nowEpoch: opts.nowEpoch,
    hooks: { threshold: hook },
  });
  return { allow: core.allow, core, pq: pqVerdict, reason: core.allow ? undefined : core.reason };
}
