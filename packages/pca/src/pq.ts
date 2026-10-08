import { ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_128f, slh_dsa_sha2_256s } from '@noble/post-quantum/slh-dsa.js';
import { sha512 } from '@noble/hashes/sha512';
import { b64u, decodeB64uStrict, utf8 } from './hash';
import { sign, verify, verifyB64u } from './keys';

/**
 * B4 — post-quantum crypto-agility (FIRST VERSION).
 *
 * An ADDITIVE, backward-compatible algorithm-agility slot for the PCActn leaf signature. The default
 * (no `alg`, or `alg === "ed25519"`) is BYTE-IDENTICAL to the pre-B4 wire: the signed bytes, the `sig`
 * field and every verdict are unchanged, so every existing conformance vector and all 7 non-TS SDK
 * verifiers remain valid. B4 only adds OPTIONAL post-quantum suites alongside it.
 *
 * Suites (the registry):
 *   - "ed25519"                               the current suite (classical, 64-byte Ed25519 `sig`).
 *   - "ml-dsa-65"                             pure PQ (LATTICE): `sig` carries an ML-DSA-65 (FIPS-204)
 *                                             signature, verified under the ML-DSA public key in `pq_pk`.
 *   - "hybrid-ed25519-ml-dsa-65"              classical + LATTICE PQ: `sig` is the Ed25519 signature AND
 *                                             `pq_sig` is an ML-DSA-65 signature, over the SAME canonical
 *                                             message. Verification requires BOTH to pass (fail-closed).
 *                                             This is EUF-CMA (existential unforgeability): a forger must
 *                                             break BOTH primitives to forge over a NEW message.
 *   - "hybrid-nested-ed25519-ml-dsa-65"       classical + LATTICE PQ, NESTED for STRONG unforgeability
 *                                             (SUF-CMA, draft-prabel-cfrg-suf-hybrid-sigs): `sig` is the
 *                                             Ed25519 signature over the message AND `pq_sig` is an
 *                                             ML-DSA-65 signature over `message ‖ sig_ed25519`. Same wire
 *                                             shape as the plain hybrid, but because the PQ half commits to
 *                                             the exact classical signature bytes, an attacker cannot even
 *                                             produce a DIFFERENT valid signature over an ALREADY-signed
 *                                             message (no malleability). Prefer it for LONG-LIVED authority
 *                                             tokens where signature non-malleability matters; the plain
 *                                             (EUF-CMA) hybrid is fine for short-lived per-action leaves.
 *   - "slh-dsa-sha2-128f"                     pure PQ (HASH-BASED): `sig` carries an SLH-DSA (FIPS-205,
 *                                             SPHINCS+) signature, verified under the SLH-DSA public key in
 *                                             `pq_pk`. See the assumption-diversity note below.
 *   - "hybrid-ed25519-slh-dsa-sha2-128f"      classical + HASH-BASED PQ: `sig` is the Ed25519 signature AND
 *                                             `pq_sig` is an SLH-DSA signature, over the SAME canonical
 *                                             message. Verification requires BOTH to pass (fail-closed).
 *
 * The ML-DSA primitive is `@noble/post-quantum`'s `ml_dsa65` (CRYSTALS-Dilithium / FIPS-204, 192-bit
 * category-3 parameter set). ML-DSA-65 sizes: public key 1952 bytes, signature 3309 bytes, seed 32 bytes.
 *
 * The SLH-DSA primitive is `@noble/post-quantum`'s `slh_dsa_sha2_128f` (SPHINCS+ / FIPS-205, SHA2, the
 * "fast" category-1 parameter set). SLH-DSA-SHA2-128f sizes: public key 32 bytes, secret key 64 bytes,
 * signature 17088 bytes, seed 48 bytes.
 *
 * ASSUMPTION DIVERSITY (why SLH-DSA is here at all):
 *   Every PQ suite above *except* this one rests entirely on LATTICE hardness (Module-LWE / Module-SIS:
 *   ML-DSA for signing, ML-KEM for key exchange elsewhere in PCA). A single cryptanalytic break of
 *   structured lattices would therefore take down ALL of PCA's post-quantum security at once. SLH-DSA
 *   rests on a completely different assumption — the (second-)preimage and collision resistance of a hash
 *   function — so a lattice break leaves it standing, and vice-versa. Offering a hash-based family gives
 *   PCA a PQ signature whose security is INDEPENDENT of the lattice bet. A (future) triple hybrid across
 *   ed25519 + ml-dsa + slh-dsa would be forgeable only if the CLASSICAL **and** the LATTICE **and** the
 *   HASH-BASED assumption all fell together — a far stronger belt-and-suspenders than any single family.
 *
 * THE HASH-BASED COST (honest tradeoff):
 *   SLH-DSA signatures are BIG. slh-dsa-sha2-128f is 17088 bytes (vs ML-DSA-65's 3309 and Ed25519's 64) —
 *   that is the irreducible price of a stateless hash-based scheme, not an implementation wart. We
 *   standardize on the "f" (fast) variant over "s" (small) because PCActns are signed ONCE PER ACTION on
 *   the interactive authority path, where signing LATENCY dominates: 128f signs in ~70 ms vs ~1.4 s for
 *   128s (≈20×), while 128s would only shrink the signature to ~7856 bytes (≈2.2×). Trading one agent
 *   round-trip's worth of latency for ~9 KB is the wrong way round for this use; a surface that is
 *   verify-heavy and bandwidth-bound (both variants verify in ~1 ms) could register "s" the same way.
 *   The 32-byte public key and 1-ms verify are identical across variants.
 *
 * Wire-field binding (why this is sound — IDENTICAL to the ML-DSA suites):
 *   - `alg` and `pq_pk` are SIGNED (they are part of the canonical body hashed by `thresholdMessage`), so a
 *     downgrade of the suite or a swap of the PQ key invalidates every signature over the action.
 *   - `sig` and `pq_sig` are the signatures themselves and are EXCLUDED from the signed body (like `sig`
 *     and `threshold` already are).
 *   - For `hybrid`, the trusted Ed25519 holder signature commits to `pq_pk`, binding the PQ key to the
 *     capability-chain leaf holder. For a pure PQ suite the PQ key is self-asserted in v1 (the holder↔
 *     PQ-key binding at the capability layer is a later wave); a `hybrid` is the recommended migration mode.
 *
 * WIRE LAYOUT (the SLH-DSA material reuses the EXISTING `pq_pk` / `pq_sig` fields):
 *   A PCActn (or any signed surface) uses EXACTLY ONE suite at a time, selected by `alg`, and the leaf
 *   verify dispatches purely on `alg` (see `verifyLeafSuite` / `verifyWithSuite`). So the SLH-DSA public
 *   key and signature ride in the same generic `pq_pk` / `pq_sig` slots the ML-DSA suites already use —
 *   only their byte lengths differ (per-suite, carried on the `SigSuite`). There is never ambiguity
 *   because `alg` names which PQ algorithm those bytes belong to; ml-dsa and slh-dsa material can never
 *   co-occur in one object. Concretely:
 *     - slh-dsa-sha2-128f:             `sig` = 17088-byte SLH-DSA sig, `pq_pk` = 32-byte SLH-DSA key, no `pq_sig`.
 *     - hybrid-ed25519-slh-dsa-sha2-128f: `sig` = 64-byte Ed25519 sig, `pq_pk` = 32-byte SLH-DSA key,
 *                                      `pq_sig` = 17088-byte SLH-DSA sig.
 *
 * SCOPE OF THIS CHANGE / THE MECHANICAL FOLLOW:
 *   This adds the two SLH-DSA suites to the agility SEAM (this file) and therefore to the LEAF (which
 *   verifies purely through `verifyLeafSuite` → `verifyWithSuite`). Making SLH-DSA usable on every
 *   non-leaf surface (capability hops, threshold shares, signed tree heads, witness cosigns, revocation
 *   epochs, liveness beacons, bond settlements, attestations, judge verdicts, safety certificates) is a
 *   MECHANICAL follow: each of those signers must learn to pass `slhDsa` key material the way it already
 *   passes `mlDsa` (verify already flows through this seam and needs nothing). The leaf SIGNER helper
 *   `signPCActnSuite` in pcactn.ts must likewise learn an `slhDsa` branch. The 9 non-TS SDK verifiers and
 *   the shared conformance vectors must gain the suite — the SAME path ML-DSA took. None of that is done
 *   here; this change is the seam + the leaf verify only.
 */

/** ML-DSA-65 (FIPS-204, category 3) encoded sizes, in bytes. */
export const ML_DSA_65_PUBLIC_KEY_BYTES = 1952;
export const ML_DSA_65_SIGNATURE_BYTES = 3309;
export const ML_DSA_65_SEED_BYTES = 32;
/** SLH-DSA-SHA2-128f (FIPS-205, SPHINCS+, SHA2 "fast" category-1 parameter set) encoded sizes, in bytes. */
export const SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES = 32;
export const SLH_DSA_SHA2_128F_SECRET_KEY_BYTES = 64;
export const SLH_DSA_SHA2_128F_SIGNATURE_BYTES = 17088;
export const SLH_DSA_SHA2_128F_SEED_BYTES = 48;
/** Ed25519 signature length, in bytes (unchanged classical suite). */
export const ED25519_SIGNATURE_BYTES = 64;

/**
 * LEVEL-5 / LONG-LIVED SUITES (FIPS Category 5) — opt-in registry additions, NOT new defaults.
 *
 * The default stays `ed25519`, and `ml-dsa-65` / `slh-dsa-sha2-128f` remain the general-purpose PQ
 * suites. These four Category-5 suites exist for a specific job: LONG-LIVED ANCHOR / ROOT keys and any
 * surface that must meet a Category-5 assurance bar.
 *
 * CNSA 2.0 RATIONALE (why Category 5 for anchors): NSA's Commercial National Security Algorithm Suite 2.0
 * mandates Category-5 parameter sets for national-security systems — ML-DSA-87 (FIPS-204) and, for a
 * hash-based alternative, SLH-DSA at the 256-bit security strength (FIPS-205). ML-DSA-65 (Category 3) is
 * NOT on the CNSA-2.0 list and is therefore inappropriate for a root of trust intended to outlive the
 * current cryptographic era. A PCA root / long-lived guardian anchor can thus pin a Category-5 suite:
 *   - `ml-dsa-87`                            Category-5 LATTICE (CNSA-2.0 signing). Big-but-fast.
 *   - `hybrid-ed25519-ml-dsa-87`             classical + Category-5 lattice (migration mode for anchors).
 *   - `slh-dsa-sha2-256s`                    Category-5 HASH-BASED, "small/slow" variant — the right
 *                                            tradeoff for a long-lived root: signed RARELY, so the ~seconds
 *                                            signing cost is irrelevant, while the SMALL (s) parameter set
 *                                            keeps the stored/transmitted signature as compact as a
 *                                            hash-based Category-5 scheme allows, on an assumption
 *                                            (hash preimage/collision resistance) fully INDEPENDENT of the
 *                                            lattice bet that the rest of PCA's PQ rests on.
 *   - `hybrid-ed25519-slh-dsa-sha2-256s`     classical + Category-5 hash-based (belt-and-suspenders anchor).
 *
 * These mirror the ml-dsa-65 / slh-dsa-sha2-128f suites EXACTLY (same seam, same wire-field binding, same
 * fail-closed rules); only the primitive and the byte lengths differ. Every pre-existing suite is
 * byte-identical — these are purely additive.
 */

/** ML-DSA-87 (FIPS-204, category 5) encoded sizes, in bytes. */
export const ML_DSA_87_PUBLIC_KEY_BYTES = 2592;
export const ML_DSA_87_SIGNATURE_BYTES = 4627;
export const ML_DSA_87_SEED_BYTES = 32;
/** SLH-DSA-SHA2-256s (FIPS-205, SPHINCS+, SHA2 "small" category-5 parameter set) encoded sizes, in bytes. */
export const SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES = 64;
export const SLH_DSA_SHA2_256S_SECRET_KEY_BYTES = 128;
export const SLH_DSA_SHA2_256S_SIGNATURE_BYTES = 29792;
export const SLH_DSA_SHA2_256S_SEED_BYTES = 96;

export type SigAlg =
  | 'ed25519'
  | 'ml-dsa-65'
  | 'hybrid-ed25519-ml-dsa-65'
  | 'hybrid-nested-ed25519-ml-dsa-65'
  | 'slh-dsa-sha2-128f'
  | 'hybrid-ed25519-slh-dsa-sha2-128f'
  | 'ml-dsa-87'
  | 'hybrid-ed25519-ml-dsa-87'
  | 'slh-dsa-sha2-256s'
  | 'hybrid-ed25519-slh-dsa-sha2-256s';

/** The suite used when `alg` is absent — the pre-B4 default. MUST stay "ed25519" forever. */
export const DEFAULT_SIG_ALG: SigAlg = 'ed25519';

export interface SigSuite {
  alg: SigAlg;
  /** Decoded byte length REQUIRED in the primary `sig` field for this suite. */
  sigBytes: number;
  /** Suite carries an Ed25519 component (in `sig`, under the leaf holder key). */
  hasEd25519: boolean;
  /** Suite carries an ML-DSA-65 (lattice) component. */
  hasMlDsa: boolean;
  /** Suite carries an SLH-DSA-SHA2-128f (hash-based) component. */
  hasSlhDsa: boolean;
  /** Suite carries an ML-DSA-87 (Category-5 lattice) component. */
  hasMlDsa87: boolean;
  /** Suite carries an SLH-DSA-SHA2-256s (Category-5 hash-based) component. */
  hasSlhDsa256s: boolean;
  /** A `pq_pk` (PQ public key — ML-DSA or SLH-DSA, per the suite) field is REQUIRED (and forbidden otherwise). */
  needsPqPk: boolean;
  /** A `pq_sig` field is REQUIRED — i.e. the PQ sig is separate from `sig` (hybrid). Forbidden otherwise. */
  needsPqSig: boolean;
  /** Decoded byte length REQUIRED in `pq_pk` when `needsPqPk` (ML-DSA 1952, SLH-DSA 32); `0` when unused. */
  pqPkBytes: number;
  /** Decoded byte length REQUIRED in `pq_sig` when `needsPqSig` (ML-DSA 3309, SLH-DSA 17088); `0` when unused. */
  pqSigBytes: number;
}

/** The closed algorithm registry. `ed25519` is first so the default path is the common one. */
export const SIG_SUITES: Readonly<Record<SigAlg, Readonly<SigSuite>>> = Object.freeze({
  ed25519: { alg: 'ed25519', sigBytes: ED25519_SIGNATURE_BYTES, hasEd25519: true, hasMlDsa: false, hasSlhDsa: false, hasMlDsa87: false, hasSlhDsa256s: false, needsPqPk: false, needsPqSig: false, pqPkBytes: 0, pqSigBytes: 0 },
  'ml-dsa-65': { alg: 'ml-dsa-65', sigBytes: ML_DSA_65_SIGNATURE_BYTES, hasEd25519: false, hasMlDsa: true, hasSlhDsa: false, hasMlDsa87: false, hasSlhDsa256s: false, needsPqPk: true, needsPqSig: false, pqPkBytes: ML_DSA_65_PUBLIC_KEY_BYTES, pqSigBytes: 0 },
  'hybrid-ed25519-ml-dsa-65': { alg: 'hybrid-ed25519-ml-dsa-65', sigBytes: ED25519_SIGNATURE_BYTES, hasEd25519: true, hasMlDsa: true, hasSlhDsa: false, hasMlDsa87: false, hasSlhDsa256s: false, needsPqPk: true, needsPqSig: true, pqPkBytes: ML_DSA_65_PUBLIC_KEY_BYTES, pqSigBytes: ML_DSA_65_SIGNATURE_BYTES },
  // SUF-CMA nested variant: wire shape is byte-identical to the plain hybrid above (same sig/pq_pk/pq_sig
  // lengths), but the ML-DSA component signs `message ‖ sig_ed25519` (nested), not `message`. See the
  // `hybrid-nested-ed25519-ml-dsa-65` case in signWithSuite/verifyWithSuite and the SUF-CMA note below.
  'hybrid-nested-ed25519-ml-dsa-65': { alg: 'hybrid-nested-ed25519-ml-dsa-65', sigBytes: ED25519_SIGNATURE_BYTES, hasEd25519: true, hasMlDsa: true, hasSlhDsa: false, hasMlDsa87: false, hasSlhDsa256s: false, needsPqPk: true, needsPqSig: true, pqPkBytes: ML_DSA_65_PUBLIC_KEY_BYTES, pqSigBytes: ML_DSA_65_SIGNATURE_BYTES },
  'slh-dsa-sha2-128f': { alg: 'slh-dsa-sha2-128f', sigBytes: SLH_DSA_SHA2_128F_SIGNATURE_BYTES, hasEd25519: false, hasMlDsa: false, hasSlhDsa: true, hasMlDsa87: false, hasSlhDsa256s: false, needsPqPk: true, needsPqSig: false, pqPkBytes: SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES, pqSigBytes: 0 },
  'hybrid-ed25519-slh-dsa-sha2-128f': { alg: 'hybrid-ed25519-slh-dsa-sha2-128f', sigBytes: ED25519_SIGNATURE_BYTES, hasEd25519: true, hasMlDsa: false, hasSlhDsa: true, hasMlDsa87: false, hasSlhDsa256s: false, needsPqPk: true, needsPqSig: true, pqPkBytes: SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES, pqSigBytes: SLH_DSA_SHA2_128F_SIGNATURE_BYTES },
  // ---- Level-5 / long-lived (CNSA 2.0) — opt-in, additive. ----
  'ml-dsa-87': { alg: 'ml-dsa-87', sigBytes: ML_DSA_87_SIGNATURE_BYTES, hasEd25519: false, hasMlDsa: false, hasSlhDsa: false, hasMlDsa87: true, hasSlhDsa256s: false, needsPqPk: true, needsPqSig: false, pqPkBytes: ML_DSA_87_PUBLIC_KEY_BYTES, pqSigBytes: 0 },
  'hybrid-ed25519-ml-dsa-87': { alg: 'hybrid-ed25519-ml-dsa-87', sigBytes: ED25519_SIGNATURE_BYTES, hasEd25519: true, hasMlDsa: false, hasSlhDsa: false, hasMlDsa87: true, hasSlhDsa256s: false, needsPqPk: true, needsPqSig: true, pqPkBytes: ML_DSA_87_PUBLIC_KEY_BYTES, pqSigBytes: ML_DSA_87_SIGNATURE_BYTES },
  'slh-dsa-sha2-256s': { alg: 'slh-dsa-sha2-256s', sigBytes: SLH_DSA_SHA2_256S_SIGNATURE_BYTES, hasEd25519: false, hasMlDsa: false, hasSlhDsa: false, hasMlDsa87: false, hasSlhDsa256s: true, needsPqPk: true, needsPqSig: false, pqPkBytes: SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES, pqSigBytes: 0 },
  'hybrid-ed25519-slh-dsa-sha2-256s': { alg: 'hybrid-ed25519-slh-dsa-sha2-256s', sigBytes: ED25519_SIGNATURE_BYTES, hasEd25519: true, hasMlDsa: false, hasSlhDsa: false, hasMlDsa87: false, hasSlhDsa256s: true, needsPqPk: true, needsPqSig: true, pqPkBytes: SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES, pqSigBytes: SLH_DSA_SHA2_256S_SIGNATURE_BYTES },
});

export function isKnownSigAlg(x: unknown): x is SigAlg {
  return typeof x === 'string' && Object.prototype.hasOwnProperty.call(SIG_SUITES, x);
}

/**
 * Resolve the signature suite for a PCActn's `alg`:
 *  - `undefined` (field absent)  => the default `ed25519` suite (backward compatible);
 *  - a known suite name          => that suite;
 *  - anything else (unknown name, non-string) => `null` (FAIL-CLOSED: the caller rejects it).
 */
export function resolveSigAlg(alg: unknown): SigSuite | null {
  if (alg === undefined) return SIG_SUITES[DEFAULT_SIG_ALG];
  if (isKnownSigAlg(alg)) return SIG_SUITES[alg];
  return null;
}

// ---- ML-DSA-65 primitive wrappers -------------------------------------------------------------

export interface MlDsaKeyPair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

/** Deterministic ML-DSA-65 keygen from a 32-byte seed (FIPS-204 key generation). */
export function mlDsa65Keygen(seed: Uint8Array): MlDsaKeyPair {
  return ml_dsa65.keygen(seed);
}

/** ML-DSA-65 sign (deterministic by default — no fresh randomness — so vectors are reproducible). */
export function mlDsa65Sign(secretKey: Uint8Array, msg: Uint8Array): Uint8Array {
  return ml_dsa65.sign(secretKey, msg);
}

/** ML-DSA-65 verify over raw bytes. Never throws; a wrong length or malformed input simply returns false. */
export function mlDsa65Verify(publicKey: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  try {
    if (!(publicKey instanceof Uint8Array) || publicKey.length !== ML_DSA_65_PUBLIC_KEY_BYTES) return false;
    if (!(sig instanceof Uint8Array) || sig.length !== ML_DSA_65_SIGNATURE_BYTES) return false;
    return ml_dsa65.verify(publicKey, msg, sig);
  } catch {
    return false;
  }
}

/** mlDsa65Verify over base64url-encoded key and signature; false on any decoding error. */
export function mlDsa65VerifyB64u(publicKeyB64u: unknown, msg: Uint8Array, sigB64u: unknown): boolean {
  try {
    const pk = decodeB64uStrict(publicKeyB64u, ML_DSA_65_PUBLIC_KEY_BYTES);
    const sg = decodeB64uStrict(sigB64u, ML_DSA_65_SIGNATURE_BYTES);
    if (!pk || !sg) return false;
    return mlDsa65Verify(pk, msg, sg);
  } catch {
    return false;
  }
}

/** b64u of an ML-DSA-65 public key — convenience for building `pq_pk`. */
export function encodeMlDsaPublicKey(publicKey: Uint8Array): string {
  return b64u(publicKey);
}

// ---- SLH-DSA-SHA2-128f primitive wrappers (FIPS-205 / SPHINCS+) ---------------------------------
//
// Mirrors the ML-DSA wrappers exactly, so callers mint and carry SLH-DSA keys the same way. The ONLY
// differences are the byte lengths and that this scheme is HASH-BASED (assumption-diverse from lattices).

export interface SlhDsaKeyPair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

/**
 * Deterministic SLH-DSA-SHA2-128f keygen from a 48-byte seed (FIPS-205 key generation). The seam exposes
 * this so a caller can mint SLH-DSA keys exactly like {@link mlDsa65Keygen}; supply a 48-byte seed.
 */
export function slhDsa128fKeygen(seed: Uint8Array): SlhDsaKeyPair {
  return slh_dsa_sha2_128f.keygen(seed);
}

/** SLH-DSA-SHA2-128f sign (deterministic by default — no fresh randomness — so vectors are reproducible). */
export function slhDsa128fSign(secretKey: Uint8Array, msg: Uint8Array): Uint8Array {
  return slh_dsa_sha2_128f.sign(secretKey, msg);
}

/** SLH-DSA-SHA2-128f verify over raw bytes. Never throws; a wrong length or malformed input returns false. */
export function slhDsa128fVerify(publicKey: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  try {
    if (!(publicKey instanceof Uint8Array) || publicKey.length !== SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES) return false;
    if (!(sig instanceof Uint8Array) || sig.length !== SLH_DSA_SHA2_128F_SIGNATURE_BYTES) return false;
    return slh_dsa_sha2_128f.verify(publicKey, msg, sig);
  } catch {
    return false;
  }
}

/** slhDsa128fVerify over base64url-encoded key and signature; false on any decoding error. */
export function slhDsa128fVerifyB64u(publicKeyB64u: unknown, msg: Uint8Array, sigB64u: unknown): boolean {
  try {
    const pk = decodeB64uStrict(publicKeyB64u, SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES);
    const sg = decodeB64uStrict(sigB64u, SLH_DSA_SHA2_128F_SIGNATURE_BYTES);
    if (!pk || !sg) return false;
    return slhDsa128fVerify(pk, msg, sg);
  } catch {
    return false;
  }
}

/** b64u of an SLH-DSA-SHA2-128f public key — convenience for building `pq_pk`. */
export function encodeSlhDsaPublicKey(publicKey: Uint8Array): string {
  return b64u(publicKey);
}

// ---- ML-DSA-87 primitive wrappers (FIPS-204, Category 5 / CNSA 2.0) -----------------------------
//
// Mirror the ML-DSA-65 wrappers exactly; only the byte lengths differ (pk 2592, sig 4627). The shared
// {@link MlDsaKeyPair} shape is reused (it is just {secretKey, publicKey}).

/** Deterministic ML-DSA-87 keygen from a 32-byte seed (FIPS-204 key generation). */
export function mlDsa87Keygen(seed: Uint8Array): MlDsaKeyPair {
  return ml_dsa87.keygen(seed);
}

/** ML-DSA-87 sign (deterministic by default — no fresh randomness — so vectors are reproducible). */
export function mlDsa87Sign(secretKey: Uint8Array, msg: Uint8Array): Uint8Array {
  return ml_dsa87.sign(secretKey, msg);
}

/** ML-DSA-87 verify over raw bytes. Never throws; a wrong length or malformed input simply returns false. */
export function mlDsa87Verify(publicKey: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  try {
    if (!(publicKey instanceof Uint8Array) || publicKey.length !== ML_DSA_87_PUBLIC_KEY_BYTES) return false;
    if (!(sig instanceof Uint8Array) || sig.length !== ML_DSA_87_SIGNATURE_BYTES) return false;
    return ml_dsa87.verify(publicKey, msg, sig);
  } catch {
    return false;
  }
}

/** mlDsa87Verify over base64url-encoded key and signature; false on any decoding error. */
export function mlDsa87VerifyB64u(publicKeyB64u: unknown, msg: Uint8Array, sigB64u: unknown): boolean {
  try {
    const pk = decodeB64uStrict(publicKeyB64u, ML_DSA_87_PUBLIC_KEY_BYTES);
    const sg = decodeB64uStrict(sigB64u, ML_DSA_87_SIGNATURE_BYTES);
    if (!pk || !sg) return false;
    return mlDsa87Verify(pk, msg, sg);
  } catch {
    return false;
  }
}

/** b64u of an ML-DSA-87 public key — convenience for building `pq_pk`. */
export function encodeMlDsa87PublicKey(publicKey: Uint8Array): string {
  return b64u(publicKey);
}

// ---- SLH-DSA-SHA2-256s primitive wrappers (FIPS-205 / SPHINCS+, Category 5 / CNSA 2.0) ----------
//
// Mirror the SLH-DSA-SHA2-128f wrappers exactly; only the byte lengths differ (pk 64, sk 128, sig 29792,
// seed 96). This is the "small/slow" Category-5 parameter set — signed rarely (anchors), so the seconds
// of signing latency is a non-issue while the signature stays as compact as a Category-5 hash-based
// scheme allows. The shared {@link SlhDsaKeyPair} shape is reused.

/** Deterministic SLH-DSA-SHA2-256s keygen from a 96-byte seed (FIPS-205 key generation). */
export function slhDsa256sKeygen(seed: Uint8Array): SlhDsaKeyPair {
  return slh_dsa_sha2_256s.keygen(seed);
}

/** SLH-DSA-SHA2-256s sign (deterministic by default — no fresh randomness — so vectors are reproducible). */
export function slhDsa256sSign(secretKey: Uint8Array, msg: Uint8Array): Uint8Array {
  return slh_dsa_sha2_256s.sign(secretKey, msg);
}

/** SLH-DSA-SHA2-256s verify over raw bytes. Never throws; a wrong length or malformed input returns false. */
export function slhDsa256sVerify(publicKey: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  try {
    if (!(publicKey instanceof Uint8Array) || publicKey.length !== SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES) return false;
    if (!(sig instanceof Uint8Array) || sig.length !== SLH_DSA_SHA2_256S_SIGNATURE_BYTES) return false;
    return slh_dsa_sha2_256s.verify(publicKey, msg, sig);
  } catch {
    return false;
  }
}

/** slhDsa256sVerify over base64url-encoded key and signature; false on any decoding error. */
export function slhDsa256sVerifyB64u(publicKeyB64u: unknown, msg: Uint8Array, sigB64u: unknown): boolean {
  try {
    const pk = decodeB64uStrict(publicKeyB64u, SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES);
    const sg = decodeB64uStrict(sigB64u, SLH_DSA_SHA2_256S_SIGNATURE_BYTES);
    if (!pk || !sg) return false;
    return slhDsa256sVerify(pk, msg, sg);
  } catch {
    return false;
  }
}

/** b64u of an SLH-DSA-SHA2-256s public key — convenience for building `pq_pk`. */
export function encodeSlhDsa256sPublicKey(publicKey: Uint8Array): string {
  return b64u(publicKey);
}

// ---- the GENERAL signature-suite SEAM (shared by EVERY signed surface) -------------------------
//
// `signWithSuite` / `verifyWithSuite` are the ONE reusable agility pair. Every signed surface in the
// authority + transparency chain (capability hops, guardian/principal cosigns, signed tree heads,
// witness cosignatures, revocation epochs, liveness beacons, bond settlement records, software
// attestation, semantic-judge verdicts, the safety certificate) routes its sign/verify through them,
// so the whole chain can be post-quantum under the SAME `ed25519 | ml-dsa-65 | hybrid` registry as the
// leaf. `verifyLeafSuite` (below) is now a thin specialization of `verifyWithSuite`.
//
// HARD INVARIANT: the `ed25519` path is BYTE-IDENTICAL to the pre-agility `sign` / `verifyB64u`:
//   - signWithSuite('ed25519' | undefined, {edSecret}, msg).sig === b64u(sign(edSecret, msg));
//   - verifyWithSuite('ed25519' | undefined, {edPub}, msg, {sig}) === verifyB64u(edPub, msg, sig).
// A surface keeps byte-identity by carrying `alg`/`pq_pk`/`pq_sig` ONLY for a non-default suite (see
// {@link bindSuiteFields}): an absent/`ed25519` suite leaves the signed body and every signature
// untouched, so all existing conformance vectors and the non-TS SDK verifiers still pass.

/**
 * Secret key material for signing under a suite. `edSecret` is required for ed25519/hybrid; `mlDsa` for the
 * ml-dsa-65 suites; `slhDsa` for the slh-dsa-sha2-128f suites. A caller supplies only what its chosen suite needs.
 */
export interface SuiteSecretKeys {
  /** Ed25519 secret key (32 bytes). */
  edSecret?: Uint8Array;
  /** ML-DSA-65 key pair (its secret key signs, its public key becomes `pq_pk`). */
  mlDsa?: MlDsaKeyPair;
  /** SLH-DSA-SHA2-128f key pair (its secret key signs, its public key becomes `pq_pk`). */
  slhDsa?: SlhDsaKeyPair;
  /** ML-DSA-87 (Category 5) key pair for the ml-dsa-87 suites. */
  mlDsa87?: MlDsaKeyPair;
  /** SLH-DSA-SHA2-256s (Category 5) key pair for the slh-dsa-sha2-256s suites. */
  slhDsa256s?: SlhDsaKeyPair;
}

/**
 * Public key material for verifying under a suite. `edPub` (b64u Ed25519) for ed25519/hybrid; `mlDsaPub`
 * (b64u ML-DSA-65) for the ml-dsa-65 suites; `slhDsaPub` (b64u SLH-DSA-SHA2-128f) for the slh-dsa suites.
 */
export interface SuitePublicKeys {
  edPub?: string;
  mlDsaPub?: string;
  slhDsaPub?: string;
  /** b64u ML-DSA-87 public key for the ml-dsa-87 suites. */
  mlDsa87Pub?: string;
  /** b64u SLH-DSA-SHA2-256s public key for the slh-dsa-sha2-256s suites. */
  slhDsa256sPub?: string;
}

/** The signature component(s) a suite produces. `sig` is the classical Ed25519 b64u signature for ed25519/hybrid and the ML-DSA-65 signature for pure ml-dsa-65; `pq_sig` is the ML-DSA-65 signature for hybrid only. */
export interface SuiteSignatureParts {
  sig: string;
  pq_sig?: string;
}

/** The signature component(s) as they appear on a wire artifact (every field optional / untrusted). */
export interface SuiteSignatureInput {
  sig?: unknown;
  pq_sig?: unknown;
}

/**
 * Sign `msg` under `alg` (undefined => ed25519). FAIL-CLOSED: an unknown `alg`, or a missing required
 * secret, THROWS (a signer must never silently emit a weaker signature than it intended).
 *
 *   - ed25519:  `{ sig: b64u(sign(edSecret, msg)) }` — BYTE-IDENTICAL to the classical signature.
 *   - ml-dsa-65: `{ sig: b64u(mlDsa65Sign(mlDsa.secretKey, msg)) }`.
 *   - hybrid-ed25519-ml-dsa-65: `{ sig: b64u(sign(edSecret, msg)), pq_sig: b64u(mlDsa65Sign(mlDsa.secretKey, msg)) }`
 *               — both over the SAME `msg`, so a forger must break ML-DSA (lattice) AND Ed25519 (classical).
 *   - slh-dsa-sha2-128f: `{ sig: b64u(slhDsa128fSign(slhDsa.secretKey, msg)) }` (hash-based PQ).
 *   - hybrid-ed25519-slh-dsa-sha2-128f: `{ sig: b64u(sign(edSecret, msg)), pq_sig: b64u(slhDsa128fSign(slhDsa.secretKey, msg)) }`
 *               — both over the SAME `msg`, so a forger must break SLH-DSA (hash-based) AND Ed25519 (classical).
 */
export function signWithSuite(alg: unknown, keys: SuiteSecretKeys, msg: Uint8Array): SuiteSignatureParts {
  const suite = resolveSigAlg(alg);
  if (suite === null) throw new RangeError(`signWithSuite: unknown signature alg '${String(alg)}'`);
  if (suite.hasEd25519 && !(keys.edSecret instanceof Uint8Array)) throw new TypeError(`signWithSuite: '${suite.alg}' requires edSecret`);
  if (suite.hasMlDsa && !(keys.mlDsa && keys.mlDsa.secretKey instanceof Uint8Array)) throw new TypeError(`signWithSuite: '${suite.alg}' requires mlDsa key material`);
  if (suite.hasSlhDsa && !(keys.slhDsa && keys.slhDsa.secretKey instanceof Uint8Array)) throw new TypeError(`signWithSuite: '${suite.alg}' requires slhDsa key material`);
  if (suite.hasMlDsa87 && !(keys.mlDsa87 && keys.mlDsa87.secretKey instanceof Uint8Array)) throw new TypeError(`signWithSuite: '${suite.alg}' requires mlDsa87 key material`);
  if (suite.hasSlhDsa256s && !(keys.slhDsa256s && keys.slhDsa256s.secretKey instanceof Uint8Array)) throw new TypeError(`signWithSuite: '${suite.alg}' requires slhDsa256s key material`);
  switch (suite.alg) {
    case 'ed25519':
      return { sig: b64u(sign(keys.edSecret!, msg)) };
    case 'ml-dsa-65':
      return { sig: b64u(mlDsa65Sign(keys.mlDsa!.secretKey, msg)) };
    case 'hybrid-ed25519-ml-dsa-65':
      return { sig: b64u(sign(keys.edSecret!, msg)), pq_sig: b64u(mlDsa65Sign(keys.mlDsa!.secretKey, msg)) };
    case 'hybrid-nested-ed25519-ml-dsa-65': {
      // SUF-CMA nested hybrid: ML-DSA signs `message ‖ sig_ed25519` (NOT `message`), so the PQ signature
      // commits to the exact classical signature bytes. See the SUF-CMA note on the registry entry.
      const edSig = sign(keys.edSecret!, msg);
      return { sig: b64u(edSig), pq_sig: b64u(mlDsa65Sign(keys.mlDsa!.secretKey, concatBytes(msg, edSig))) };
    }
    case 'slh-dsa-sha2-128f':
      return { sig: b64u(slhDsa128fSign(keys.slhDsa!.secretKey, msg)) };
    case 'hybrid-ed25519-slh-dsa-sha2-128f':
      return { sig: b64u(sign(keys.edSecret!, msg)), pq_sig: b64u(slhDsa128fSign(keys.slhDsa!.secretKey, msg)) };
    case 'ml-dsa-87':
      return { sig: b64u(mlDsa87Sign(keys.mlDsa87!.secretKey, msg)) };
    case 'hybrid-ed25519-ml-dsa-87':
      return { sig: b64u(sign(keys.edSecret!, msg)), pq_sig: b64u(mlDsa87Sign(keys.mlDsa87!.secretKey, msg)) };
    case 'slh-dsa-sha2-256s':
      return { sig: b64u(slhDsa256sSign(keys.slhDsa256s!.secretKey, msg)) };
    case 'hybrid-ed25519-slh-dsa-sha2-256s':
      return { sig: b64u(sign(keys.edSecret!, msg)), pq_sig: b64u(slhDsa256sSign(keys.slhDsa256s!.secretKey, msg)) };
  }
}

/**
 * Verify a suite signature over `msg`. The agility seam every surface verifies through. FAIL-CLOSED:
 * an unknown `alg`, a missing component, a missing key, or any invalid component returns false; hybrid
 * requires BOTH. Never throws. The ed25519 path is BYTE-IDENTICAL to `verifyB64u(edPub, msg, sig)`.
 */
export function verifyWithSuite(alg: unknown, keys: SuitePublicKeys, msg: Uint8Array, s: SuiteSignatureInput): boolean {
  const suite = resolveSigAlg(alg);
  if (suite === null) return false; // unknown alg => fail-closed
  const sig = s?.sig;
  switch (suite.alg) {
    case 'ed25519':
      return typeof sig === 'string' && typeof keys.edPub === 'string' && verifyB64u(keys.edPub, msg, sig);
    case 'ml-dsa-65':
      return typeof sig === 'string' && mlDsa65VerifyB64u(keys.mlDsaPub, msg, sig);
    case 'hybrid-ed25519-ml-dsa-65': {
      const edOk = typeof sig === 'string' && typeof keys.edPub === 'string' && verifyB64u(keys.edPub, msg, sig);
      const pqOk = typeof s?.pq_sig === 'string' && mlDsa65VerifyB64u(keys.mlDsaPub, msg, s.pq_sig);
      return edOk && pqOk; // fail-closed: BOTH required
    }
    case 'hybrid-nested-ed25519-ml-dsa-65': {
      // SUF-CMA nested hybrid. ed25519 verifies `message`; THEN ml-dsa verifies `message ‖ sig_ed25519`.
      // Because the PQ half is bound to the exact classical signature bytes, mauling or swapping the
      // classical half changes the nested message and the PQ verification fails too (fail-closed).
      const edOk = typeof sig === 'string' && typeof keys.edPub === 'string' && verifyB64u(keys.edPub, msg, sig);
      const edSigBytes = typeof sig === 'string' ? decodeB64uStrict(sig, ED25519_SIGNATURE_BYTES) : null;
      const pqOk =
        edSigBytes !== null &&
        typeof s?.pq_sig === 'string' &&
        mlDsa65VerifyB64u(keys.mlDsaPub, concatBytes(msg, edSigBytes), s.pq_sig);
      return edOk && pqOk; // fail-closed: BOTH required
    }
    case 'slh-dsa-sha2-128f':
      return typeof sig === 'string' && slhDsa128fVerifyB64u(keys.slhDsaPub, msg, sig);
    case 'hybrid-ed25519-slh-dsa-sha2-128f': {
      const edOk = typeof sig === 'string' && typeof keys.edPub === 'string' && verifyB64u(keys.edPub, msg, sig);
      const pqOk = typeof s?.pq_sig === 'string' && slhDsa128fVerifyB64u(keys.slhDsaPub, msg, s.pq_sig);
      return edOk && pqOk; // fail-closed: BOTH required
    }
    case 'ml-dsa-87':
      return typeof sig === 'string' && mlDsa87VerifyB64u(keys.mlDsa87Pub, msg, sig);
    case 'hybrid-ed25519-ml-dsa-87': {
      const edOk = typeof sig === 'string' && typeof keys.edPub === 'string' && verifyB64u(keys.edPub, msg, sig);
      const pqOk = typeof s?.pq_sig === 'string' && mlDsa87VerifyB64u(keys.mlDsa87Pub, msg, s.pq_sig);
      return edOk && pqOk; // fail-closed: BOTH required
    }
    case 'slh-dsa-sha2-256s':
      return typeof sig === 'string' && slhDsa256sVerifyB64u(keys.slhDsa256sPub, msg, sig);
    case 'hybrid-ed25519-slh-dsa-sha2-256s': {
      const edOk = typeof sig === 'string' && typeof keys.edPub === 'string' && verifyB64u(keys.edPub, msg, sig);
      const pqOk = typeof s?.pq_sig === 'string' && slhDsa256sVerifyB64u(keys.slhDsa256sPub, msg, s.pq_sig);
      return edOk && pqOk; // fail-closed: BOTH required
    }
  }
}

/** The suite fields optionally carried on (and SIGNED into) an artifact's canonical body. */
export interface SuiteWireFields {
  alg?: SigAlg;
  /** b64u PQ public key (ML-DSA-65 or SLH-DSA-SHA2-128f, per `alg`) — present for every non-ed25519 suite. */
  pq_pk?: string;
}

/** Every wire field a signed artifact carries for its suite: `sig` always; `alg`/`pq_pk`/`pq_sig` only for a non-default suite. */
export interface SuiteArtifactFields extends SuiteWireFields {
  sig: string;
  /** b64u PQ signature (ML-DSA-65 or SLH-DSA-SHA2-128f, per `alg`) — hybrid suites only. */
  pq_sig?: string;
}

/**
 * Sign `msg` and return ALL the wire fields an artifact carries for its suite. For the default
 * (`undefined`/`ed25519`) it returns ONLY `{ sig }` (byte-identical to pre-agility — no `alg`/`pq_*`
 * keys appear). For any non-ed25519 suite it also returns `alg`, the signer's `pq_pk`, and (hybrid)
 * `pq_sig`. The caller spreads these onto its artifact AND binds `{alg, pq_pk}` into the signed body
 * via {@link bindSuiteFields} using the SAME `pq_pk` (== `encode{MlDsa,SlhDsa}PublicKey(keys.<pq>.publicKey)`).
 */
export function signSuiteArtifact(alg: unknown, keys: SuiteSecretKeys, msg: Uint8Array): SuiteArtifactFields {
  const parts = signWithSuite(alg, keys, msg); // throws on unknown alg / missing key material
  const suite = resolveSigAlg(alg)!;
  if (suite.alg === 'ed25519') return { sig: parts.sig };
  const out: SuiteArtifactFields = { sig: parts.sig, alg: suite.alg };
  // `pq_pk` carries whichever PQ public key the suite selected — ML-DSA or SLH-DSA — in the same slot.
  if (suite.needsPqPk) {
    if (suite.hasSlhDsa && keys.slhDsa) out.pq_pk = encodeSlhDsaPublicKey(keys.slhDsa.publicKey);
    else if (suite.hasMlDsa && keys.mlDsa) out.pq_pk = encodeMlDsaPublicKey(keys.mlDsa.publicKey);
    else if (suite.hasMlDsa87 && keys.mlDsa87) out.pq_pk = encodeMlDsa87PublicKey(keys.mlDsa87.publicKey);
    else if (suite.hasSlhDsa256s && keys.slhDsa256s) out.pq_pk = encodeSlhDsa256sPublicKey(keys.slhDsa256s.publicKey);
  }
  if (parts.pq_sig !== undefined) out.pq_sig = parts.pq_sig;
  return out;
}

/**
 * Bind the suite fields that MUST be signed into a canonical body, ADDITIVELY. For a non-default suite
 * (`ml-dsa-65` / `hybrid`) it returns a shallow copy of `base` with `alg` and (when the suite needs it)
 * `pq_pk` added, so the signature commits to them and a downgrade/key-swap invalidates it. For the
 * default (`undefined` / `ed25519`), or an unknown alg, it returns `base` UNCHANGED, so the canonical
 * bytes — and therefore every signature over them — are byte-identical to pre-agility. `pq_sig` is NEVER
 * added here (it is a signature, excluded from the signed body, exactly like `sig`).
 */
export function bindSuiteFields<T extends object>(base: T, alg: unknown, pqPublicKey?: string): T & SuiteWireFields {
  const suite = resolveSigAlg(alg);
  if (suite === null || suite.alg === 'ed25519') return base as T & SuiteWireFields;
  const out: T & SuiteWireFields = { ...base, alg: suite.alg };
  if (suite.needsPqPk) out.pq_pk = pqPublicKey;
  return out;
}

// ---- the leaf/threshold signature SEAM (specialization of the general seam) --------------------

export interface LeafSuiteInput {
  /** PCActn `alg` (undefined => ed25519). */
  alg?: unknown;
  /** Leaf capability holder's Ed25519 public key (b64u). */
  holder: string;
  /** PCActn `pq_pk` (PQ public key — ML-DSA-65 or SLH-DSA-SHA2-128f per `alg`, b64u) — present for every non-ed25519 suite. */
  pqPublicKey?: unknown;
  /** The canonical signed message (== `thresholdMessage(pcactn)`). */
  message: Uint8Array;
  /** PCActn `sig` (Ed25519 sig for ed25519/hybrid; the PQ sig for a pure ml-dsa-65 / slh-dsa suite). */
  sig: unknown;
  /** PCActn `pq_sig` (PQ sig — ML-DSA-65 or SLH-DSA-SHA2-128f per `alg`, b64u) — present for hybrid suites only. */
  pqSig?: unknown;
}

/**
 * Verify the leaf signature under the PCActn's suite. The SINGLE agility seam: everything above it
 * (the full verifier) is unchanged. FAIL-CLOSED: an unknown `alg`, a missing component, or any invalid
 * component returns false. Never throws.
 *
 *   - ed25519:  Ed25519 `sig` under `holder` — BYTE-IDENTICAL to the pre-B4 `verifyB64u(holder, msg, sig)`.
 *   - ml-dsa-65: ML-DSA-65 `sig` under `pq_pk`.
 *   - hybrid-ed25519-ml-dsa-65: Ed25519 `sig` under `holder` AND ML-DSA-65 `pq_sig` under `pq_pk`, both over
 *               `message`; BOTH must verify (either missing or invalid ⇒ false).
 *   - slh-dsa-sha2-128f: SLH-DSA `sig` under `pq_pk` (hash-based).
 *   - hybrid-ed25519-slh-dsa-sha2-128f: Ed25519 `sig` under `holder` AND SLH-DSA `pq_sig` under `pq_pk`,
 *               both over `message`; BOTH must verify.
 */
export function verifyLeafSuite(i: LeafSuiteInput): boolean {
  // The leaf is just the general seam with edPub = the capability-chain leaf `holder` and the PCActn's one
  // `pq_pk` as the PQ public key. A PCActn carries ONE suite (chosen by `alg`), so the same `pq_pk` is fed
  // to BOTH PQ slots; `verifyWithSuite` reads only the slot its `alg` selects. Pure dispatch on `alg`.
  const pqPub = typeof i.pqPublicKey === 'string' ? i.pqPublicKey : undefined;
  return verifyWithSuite(
    i.alg,
    { edPub: i.holder, mlDsaPub: pqPub, slhDsaPub: pqPub, mlDsa87Pub: pqPub, slhDsa256sPub: pqPub },
    i.message,
    { sig: i.sig, pq_sig: i.pqSig },
  );
}

// ---- wire-shape validation of the signature fields (called from wire.ts) ----------------------

type Decoder = (s: unknown, len?: number) => Uint8Array | null;

/**
 * Validate the signature-carrying fields (`alg`, `sig`, `pq_pk`, `pq_sig`) of a PCActn per its suite.
 * Returns `null` when well-formed, else a short reason. Strict + fail-closed:
 *  - `alg` absent  => ed25519; `pq_pk`/`pq_sig` MUST be absent; `sig` is 64-byte canonical b64u (as today).
 *  - unknown `alg` (or non-string) => reason (wire fail).
 *  - per-suite exact decoded lengths for `sig`/`pq_pk`/`pq_sig`; any field not used by the suite MUST be absent.
 */
export function validateSignatureWire(p: Record<string, unknown>, decode: Decoder = decodeB64uStrict): string | null {
  const alg = p.alg;
  if (alg !== undefined && typeof alg !== 'string') return "'alg' must be a string";
  const suite = resolveSigAlg(alg);
  if (suite === null) return `unknown signature alg '${String(alg)}'`;

  if (decode(p.sig, suite.sigBytes) === null) {
    return `'sig' is not canonical base64url (${suite.sigBytes} bytes) for alg '${suite.alg}'`;
  }
  // `pq_pk`/`pq_sig` lengths are per-suite (ML-DSA: 1952/3309; SLH-DSA: 32/17088), carried on the SigSuite.
  if (suite.needsPqPk) {
    if (decode(p.pq_pk, suite.pqPkBytes) === null) {
      return `'pq_pk' is not canonical base64url (${suite.pqPkBytes} bytes) for alg '${suite.alg}'`;
    }
  } else if (p.pq_pk !== undefined) {
    return `'pq_pk' must be absent for alg '${suite.alg}'`;
  }
  if (suite.needsPqSig) {
    if (decode(p.pq_sig, suite.pqSigBytes) === null) {
      return `'pq_sig' is not canonical base64url (${suite.pqSigBytes} bytes) for alg '${suite.alg}'`;
    }
  } else if (p.pq_sig !== undefined) {
    return `'pq_sig' must be absent for alg '${suite.alg}'`;
  }
  return null;
}

// ---- shared byte helper -----------------------------------------------------------------------

/** Concatenate byte arrays into one fresh Uint8Array. */
function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

// ---- (A) COMPOSITE-ML-DSA WIRE FORMAT (draft-ietf-lamps-pq-composite-sigs) ----------------------
//
// A STANDARDS-WIRE ENCODER/DECODER for the IETF LAMPS composite-signature representative, so a PCA
// hybrid can be emitted to / consumed from the X.509 / PKI boundary and interoperate with any composite
// implementation. This is COMPLEMENTARY to PCA's native `hybrid-ed25519-ml-dsa-65` suite:
//   - the native suite signs the SAME canonical message with each algorithm independently and carries
//     the two signatures in separate `sig` / `pq_sig` JSON fields (that suite stays BYTE-IDENTICAL and is
//     unaffected by anything here);
//   - this composite format binds both algorithms to ONE message representative `M'` and concatenates the
//     two component signatures into a single opaque blob — the shape a CompositeSignatureValue carries at
//     an X.509 / CMS boundary. Use this ONLY when emitting/consuming composite sigs for PKI interop; use
//     the native suite inside PCA.
//
// The signed message representative is (draft-ietf-lamps-pq-composite-sigs §2.2 / §3.2):
//   M' = Prefix ‖ Label ‖ len(ctx) ‖ ctx ‖ PH(M)
// where:
//   - Prefix    = the ASCII bytes of "CompositeAlgorithmSignatures2025" (hex 436F6D...3235, 32 bytes);
//   - Label     = the per-combination domain separator — for the registered L3 Ed25519 pairing
//                 id-MLDSA65-Ed25519-SHA512 (OID 1.3.6.1.5.5.7.6.48) this is the ASCII bytes of
//                 "COMPSIG-MLDSA65-Ed25519-SHA512" (the draft spells the classical arm "Ed25519", mixed
//                 case — NOT "ED25519"; verified against the LAMPS datatracker draft);
//   - len(ctx)  = one unsigned byte, the length of the (optional) application context `ctx` (0..255);
//   - ctx       = the application context bytes (empty by default);
//   - PH(M)     = SHA-512 of the message `M` (the pre-hash for this registered combination).
//
// The composite signature is `mldsaSig ‖ tradSig` — the fixed-length ML-DSA-65 signature (3309 bytes)
// first, split at a known offset, then the Ed25519 signature (64 bytes). Verification requires BOTH
// component verifications over the SAME `M'` to pass (fail-closed).

/** The composite-signature Prefix (draft-ietf-lamps-pq-composite-sigs): ASCII "CompositeAlgorithmSignatures2025". */
export const COMPOSITE_PREFIX = 'CompositeAlgorithmSignatures2025';
/** The registered per-combination Label for id-MLDSA65-Ed25519-SHA512 (OID 1.3.6.1.5.5.7.6.48). */
export const COMPOSITE_LABEL = 'COMPSIG-MLDSA65-Ed25519-SHA512';
/** Total composite signature length: ML-DSA-65 (3309) ‖ Ed25519 (64) = 3373 bytes. */
export const COMPOSITE_SIGNATURE_BYTES = ML_DSA_65_SIGNATURE_BYTES + ED25519_SIGNATURE_BYTES;

/** Normalize an optional context: a string is UTF-8 encoded; `undefined` is the empty context. */
function compositeCtxBytes(ctx: Uint8Array | string | undefined): Uint8Array {
  if (ctx === undefined) return new Uint8Array(0);
  return typeof ctx === 'string' ? utf8(ctx) : ctx;
}

/**
 * Build the composite message representative `M' = Prefix ‖ Label ‖ len(ctx) ‖ ctx ‖ SHA-512(message)`.
 * THROWS a RangeError if `ctx` exceeds 255 bytes (its length must fit a single unsigned byte).
 */
export function compositeRepresentative(message: Uint8Array, ctx?: Uint8Array | string): Uint8Array {
  const ctxBytes = compositeCtxBytes(ctx);
  if (ctxBytes.length > 255) throw new RangeError('compositeRepresentative: ctx exceeds 255 bytes');
  return concatBytes(utf8(COMPOSITE_PREFIX), utf8(COMPOSITE_LABEL), Uint8Array.of(ctxBytes.length), ctxBytes, sha512(message));
}

/** Secret-key + message inputs for {@link compositeSign}. Keys are raw bytes (the wire/PKI boundary). */
export interface CompositeSignOpts {
  /** Ed25519 secret key (32 bytes). */
  ed25519Secret: Uint8Array;
  /** ML-DSA-65 key pair (its secret key signs the composite representative). */
  mlDsa: MlDsaKeyPair;
  /** The message `M` to sign. */
  message: Uint8Array;
  /** Optional application context (0..255 bytes; a string is UTF-8 encoded). */
  ctx?: Uint8Array | string;
}

/**
 * Produce a LAMPS composite signature over `message`: `mldsaSig ‖ tradSig`, where both components sign the
 * composite representative `M'` ({@link compositeRepresentative}). THROWS on missing key material or a
 * `ctx` over 255 bytes. The returned blob is {@link COMPOSITE_SIGNATURE_BYTES} (3373) bytes.
 */
export function compositeSign(opts: CompositeSignOpts): Uint8Array {
  if (!(opts.ed25519Secret instanceof Uint8Array)) throw new TypeError('compositeSign: ed25519Secret required');
  if (!(opts.mlDsa && opts.mlDsa.secretKey instanceof Uint8Array)) throw new TypeError('compositeSign: mlDsa key material required');
  const mPrime = compositeRepresentative(opts.message, opts.ctx);
  const mldsaSig = mlDsa65Sign(opts.mlDsa.secretKey, mPrime); // 3309 bytes
  const tradSig = sign(opts.ed25519Secret, mPrime); // 64 bytes
  return concatBytes(mldsaSig, tradSig); // mldsaSig ‖ tradSig, split at ML_DSA_65_SIGNATURE_BYTES
}

/** Public-key + signature inputs for {@link compositeVerify}. Keys/signature are raw bytes. */
export interface CompositeVerifyOpts {
  /** Ed25519 public key (32 bytes). */
  ed25519Pub: Uint8Array;
  /** ML-DSA-65 public key (1952 bytes). */
  mlDsaPub: Uint8Array;
  /** The message `M` the signature claims to cover. */
  message: Uint8Array;
  /** The composite signature blob (`mldsaSig ‖ tradSig`). */
  signature: Uint8Array;
  /** Optional application context — MUST match the one used at signing (0..255 bytes; a string is UTF-8 encoded). */
  ctx?: Uint8Array | string;
}

/**
 * Verify a LAMPS composite signature. FAIL-CLOSED: a wrong total length, a `ctx` over 255 bytes, or either
 * component failing returns false; BOTH the ML-DSA-65 half (over `M'`) and the Ed25519 half (over `M'`) must
 * verify. Never throws. The `ctx` must match the signer's exactly (it is bound into `M'`).
 */
export function compositeVerify(opts: CompositeVerifyOpts): boolean {
  try {
    if (!(opts.signature instanceof Uint8Array) || opts.signature.length !== COMPOSITE_SIGNATURE_BYTES) return false;
    const ctxBytes = compositeCtxBytes(opts.ctx);
    if (ctxBytes.length > 255) return false;
    // Split at the fixed ML-DSA offset; copy out so the component verifiers see standalone arrays.
    const mldsaSig = opts.signature.slice(0, ML_DSA_65_SIGNATURE_BYTES);
    const tradSig = opts.signature.slice(ML_DSA_65_SIGNATURE_BYTES);
    const mPrime = compositeRepresentative(opts.message, ctxBytes);
    const mldsaOk = mlDsa65Verify(opts.mlDsaPub, mPrime, mldsaSig);
    const tradOk = verify(opts.ed25519Pub, mPrime, tradSig);
    return mldsaOk && tradOk; // BOTH component verifications over M'
  } catch {
    return false;
  }
}
