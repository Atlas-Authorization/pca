/**
 * @atlasauth/pca-attest-eat — POST-QUANTUM CO-SIGNATURE for a verified attestation verdict.
 *
 * ── What this closes ────────────────────────────────────────────────────────────────────────────────
 * PCA's TEE evidence is rooted in AMD SEV-SNP silicon, whose VCEK→ASK→ARK chain is a CLASSICAL ECDSA/RSA
 * root. {@link verifyAmdAttestation} (this package) and PCA's `hardware-sevsnp.ts` verify that classical
 * root for real — but everything DOWNSTREAM of that one check then propagates the *verdict* (tier,
 * trustworthy bit, measured identity, freshness) around PCA. If that propagation is itself protected only
 * by a classical signature, then a future quantum break of ECDSA/RSA does not merely threaten NEW hardware
 * checks — it would let an adversary RETROACTIVELY FORGE PCA's own internal attestation records.
 *
 * This module adds a POST-QUANTUM CO-SIGNATURE over the verdict: once OUR verifier has checked the AMD
 * attestation (the classical hardware step), {@link coSignAttestation} binds the verdict's security-relevant
 * fields under an ML-DSA-65 (FIPS-204) signature by default — or an opt-in hybrid / nested-hybrid or a
 * Category-5 suite — using the REAL post-quantum signing seam in `@atlasauth/pca`'s `pq.ts`
 * (`signWithSuite` / `verifyWithSuite`). Downstream PCA trust in the verdict record then rests on a PQ
 * primitive, not on the classical hardware signature.
 *
 * ── HONESTY: what this is and is NOT ──────────────────────────────────────────────────────────────────
 * This does NOT make AMD's hardware root of trust post-quantum. That root is, and remains, a classical
 * ECDSA/RSA key — a hardware-vendor fact no software here can change (see
 * {@link AMD_SEV_SNP_HARDWARE_ROOT_LABEL}). The initial hardware verification is still a classical check and
 * an adversary with a quantum computer could still forge a FRESH AMD report presented to a verifier that
 * has not yet re-pinned a PQ root. What this layer provides is DEFENSE-IN-DEPTH and a FORWARD-SECURE RECORD:
 * AFTER the classical hardware check has passed, PCA's internal propagation of that verdict is bound under a
 * post-quantum signature, so a future quantum break of AMD's ECDSA/RSA root cannot RETROACTIVELY forge
 * PCA's already-recorded internal attestation verdicts. The classical caveat stays explicit, never silently
 * upgraded to a guarantee this layer cannot give.
 *
 * ── Canonical, deterministic encoding (what is actually signed) ───────────────────────────────────────
 * The PQ signature is computed over {@link canonicalVerdictBytes}: `utf8(JSON.stringify(obj))` where `obj`
 * is built in a FIXED field order with a domain-separation `typ`, and every optional field is emitted
 * explicitly (its value, or `null` when absent) so the encoding is unambiguous:
 *   { typ, tier, trustworthy, measurement, measured, nonce, iat, issuer, cosignedAt }
 * `measured` is itself re-serialized in a fixed sub-field order (nulls for absent optionals), so a caller's
 * key ordering can never change the signed bytes. These are exactly the verdict's security-relevant fields
 * the roadmap calls for: measured identity / measurement, appraisal tier, the trustworthy bit, the
 * attestation nonce + freshness anchor (`iat`), and the co-sign timestamp (`cosignedAt`).
 *
 * ── Crypto ────────────────────────────────────────────────────────────────────────────────────────────
 * No new dependency: the PQ signing is `@atlasauth/pca`'s `signWithSuite` / `verifyWithSuite` agility seam
 * (`@noble/post-quantum` ML-DSA / SLH-DSA under the hood). A pure-classical `ed25519` suite is REFUSED here
 * (fail closed): co-signing under a classical-only suite would defeat the entire purpose of this module.
 *
 * This file is PURELY ADDITIVE — it defines new exports and does not change any existing one's behaviour.
 */
import { timingSafeEqual } from 'node:crypto';
import {
  b64u,
  publicKeyOf,
  resolveSigAlg,
  signWithSuite,
  utf8,
  verifyWithSuite,
  type SigSuite,
  type SuitePublicKeys,
  type SuiteSecretKeys,
} from '@atlasauth/pca';
import type { AttestationResult, AttestationTier, EatClaims, MeasuredIdentity } from './index';

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Constants.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/**
 * Domain separator mixed (as the first `typ` field) into the canonical signed encoding, so a PQ
 * co-signature over an attestation verdict can never be confused with any other PCA signed surface.
 */
export const PQCOSIGN_DOMAIN = 'atlas-pca/attest-cosign/v1';

/**
 * The post-quantum co-signature suites this module accepts. Every one carries a POST-QUANTUM component;
 * the pure-classical `ed25519` suite is deliberately NOT here (co-signing under it would defeat the point).
 * These are a curated subset of `@atlasauth/pca`'s `SigAlg` registry:
 *   • `ml-dsa-65` (default)                    — pure lattice PQ (FIPS-204, category 3);
 *   • `ml-dsa-87`                              — pure lattice PQ (FIPS-204, category 5 / CNSA 2.0);
 *   • `slh-dsa-sha2-128f` / `-256s`            — pure hash-based PQ (FIPS-205), assumption-diverse from lattices;
 *   • `hybrid-ed25519-ml-dsa-65`               — classical + lattice PQ (EUF-CMA: a forger must break BOTH);
 *   • `hybrid-nested-ed25519-ml-dsa-65`        — classical + lattice PQ, NESTED for strong unforgeability (SUF-CMA);
 *   • `hybrid-ed25519-ml-dsa-87` / `-slh-dsa-*`— classical + category-5 PQ (belt-and-suspenders anchors).
 * A hybrid still partly rests on classical crypto, but as a strict ADDITION (both halves must verify), so it
 * is never weaker than its PQ half; the pure-PQ default removes the classical dependency entirely.
 */
export type PqCoSignSuite =
  | 'ml-dsa-65'
  | 'ml-dsa-87'
  | 'slh-dsa-sha2-128f'
  | 'slh-dsa-sha2-256s'
  | 'hybrid-ed25519-ml-dsa-65'
  | 'hybrid-nested-ed25519-ml-dsa-65'
  | 'hybrid-ed25519-ml-dsa-87'
  | 'hybrid-ed25519-slh-dsa-sha2-128f'
  | 'hybrid-ed25519-slh-dsa-sha2-256s';

/** The default co-sign suite: pure post-quantum ML-DSA-65 (no classical dependency in the propagated record). */
export const DEFAULT_PQ_COSIGN_SUITE: PqCoSignSuite = 'ml-dsa-65';

/** The accepted suites as an array (iteration / documentation). */
export const PQ_COSIGN_SUITES: readonly PqCoSignSuite[] = [
  'ml-dsa-65',
  'ml-dsa-87',
  'slh-dsa-sha2-128f',
  'slh-dsa-sha2-256s',
  'hybrid-ed25519-ml-dsa-65',
  'hybrid-nested-ed25519-ml-dsa-65',
  'hybrid-ed25519-ml-dsa-87',
  'hybrid-ed25519-slh-dsa-sha2-128f',
  'hybrid-ed25519-slh-dsa-sha2-256s',
];

const PQ_COSIGN_SUITE_SET: ReadonlySet<string> = new Set<string>(PQ_COSIGN_SUITES);

/** Type guard: `x` is one of the accepted PQ co-sign suites (rejects `ed25519`, unknown names, non-strings). */
export function isPqCoSignSuite(x: unknown): x is PqCoSignSuite {
  return typeof x === 'string' && PQ_COSIGN_SUITE_SET.has(x);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Verdict model.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/**
 * The security-relevant fields of an attestation verdict that the PQ co-signature binds. This is the
 * minimal, propagation-safe projection of a verified attestation: there is deliberately NO field here that
 * is left OUT of the signed canonical encoding, so there is no unsigned security content to tamper with.
 * Build one from an {@link AttestationResult} (plus the EAT claims / AMD verdict) via {@link verdictFromAppraisal}.
 */
export interface AttestationVerdict {
  /** The RATS appraisal tier (highest-trust first: `affirming-hw-rooted` … `rejected`). */
  tier: AttestationTier;
  /** The trustworthy bit — whether a Relying Party may accept this tier. */
  trustworthy: boolean;
  /** The measured identity this attestation established (model / weights / runtime / operator). */
  measured?: MeasuredIdentity;
  /** The launch MEASUREMENT (hex) — the measured identity at the report/EAT level. */
  measurement?: string;
  /** The attestation freshness nonce (the EAT `eat_nonce` echoed by the attester). */
  nonce?: string;
  /** The attestation issued-at, epoch SECONDS (the EAT `iat`) — the freshness anchor. */
  iat?: number;
  /** The issuer / verifier-of-record that produced the verdict (the EAT `iss`). */
  issuer?: string;
}

/** The canonical sub-shape of a {@link MeasuredIdentity}: a fixed sub-field order, `null` for every absent optional. */
interface CanonicalMeasured {
  model_id: string;
  weights_digest: string;
  weights_measured: boolean | null;
  runtime_measurement: string;
  operator: string;
  system_prompt_digest: string | null;
  tool_manifest_digest: string | null;
}

function canonicalMeasured(m: MeasuredIdentity | undefined): CanonicalMeasured | null {
  if (m === undefined) return null;
  return {
    model_id: m.model_id,
    weights_digest: m.weights_digest,
    weights_measured: typeof m.weights_measured === 'boolean' ? m.weights_measured : null,
    runtime_measurement: m.runtime_measurement,
    operator: m.operator,
    system_prompt_digest: typeof m.system_prompt_digest === 'string' ? m.system_prompt_digest : null,
    tool_manifest_digest: typeof m.tool_manifest_digest === 'string' ? m.tool_manifest_digest : null,
  };
}

/** The canonical top-level shape actually serialized and signed (fixed field order; nulls for absent optionals). */
interface CanonicalVerdict {
  typ: string;
  tier: AttestationTier;
  trustworthy: boolean;
  measurement: string | null;
  measured: CanonicalMeasured | null;
  nonce: string | null;
  iat: number | null;
  issuer: string | null;
  cosignedAt: number;
}

/**
 * Produce the CANONICAL, DETERMINISTIC bytes the PQ co-signature is computed over: `utf8(JSON.stringify(obj))`
 * with `obj` built in a fixed field order, a domain-separation `typ`, and every optional field emitted
 * explicitly (value or `null`). Exported so a Relying Party or a conformance test can reproduce exactly what
 * was signed. The same function is used by both {@link coSignAttestation} and {@link verifyCoSignedAttestation},
 * so a single source of truth defines the signed message.
 */
export function canonicalVerdictBytes(verdict: AttestationVerdict, cosignedAt: number): Uint8Array {
  const canonical: CanonicalVerdict = {
    typ: PQCOSIGN_DOMAIN,
    tier: verdict.tier,
    trustworthy: verdict.trustworthy === true,
    measurement: typeof verdict.measurement === 'string' ? verdict.measurement : null,
    measured: canonicalMeasured(verdict.measured),
    nonce: typeof verdict.nonce === 'string' ? verdict.nonce : null,
    iat: typeof verdict.iat === 'number' && Number.isFinite(verdict.iat) ? verdict.iat : null,
    issuer: typeof verdict.issuer === 'string' ? verdict.issuer : null,
    cosignedAt,
  };
  return utf8(JSON.stringify(canonical));
}

/**
 * Build an {@link AttestationVerdict} from an {@link appraise} result plus the attestation's EAT claims. A
 * convenience for the intended wiring: after `verifyFreshAttestedEAT` / `appraise` returns an
 * {@link AttestationResult}, project the security-relevant fields (tier, trustworthy, measured identity /
 * launch measurement, nonce, iat, issuer) into the verdict this module co-signs.
 */
export function verdictFromAppraisal(result: AttestationResult, claims: EatClaims): AttestationVerdict {
  const verdict: AttestationVerdict = { tier: result.tier, trustworthy: result.trustworthy };
  if (claims.measured !== undefined) verdict.measured = claims.measured;
  const measurement =
    claims.measured?.runtime_measurement && claims.measured.runtime_measurement.length > 0
      ? claims.measured.runtime_measurement
      : claims.sevsnp?.measurement;
  if (typeof measurement === 'string' && measurement.length > 0) verdict.measurement = measurement;
  if (typeof claims.eat_nonce === 'string') verdict.nonce = claims.eat_nonce;
  if (typeof claims.iat === 'number' && Number.isFinite(claims.iat)) verdict.iat = claims.iat;
  if (typeof claims.iss === 'string') verdict.issuer = claims.iss;
  return verdict;
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Co-signature artifacts.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/**
 * The co-signer's public key material. For a pure-PQ suite only `pq` (the ML-DSA / SLH-DSA public key, b64u)
 * is present; a hybrid / nested suite also carries `ed`, the classical Ed25519 public key (b64u), needed to
 * verify the classical half.
 */
export interface PqCoSignerPublicKey {
  /** b64u post-quantum public key (ML-DSA-65/87 or SLH-DSA-SHA2-128f/256s, per the suite). */
  pq: string;
  /** b64u classical Ed25519 public key — present ONLY for a hybrid / nested suite. */
  ed?: string;
}

/**
 * The post-quantum co-signature itself. `sig` / `pq_sig` follow `@atlasauth/pca`'s suite wire convention:
 *   • pure PQ suite  → `sig` is the PQ signature; `pq_sig` absent;
 *   • hybrid suite   → `sig` is the Ed25519 signature AND `pq_sig` is the PQ signature (both required).
 * `cosignedAt` is the co-sign timestamp (epoch ms) and is BOUND INTO the signed canonical encoding, so it
 * cannot be moved without invalidating the signature.
 */
export interface PqCoSig {
  /** The co-sign timestamp, epoch ms (also part of the signed canonical encoding — the staleness anchor). */
  cosignedAt: number;
  /** The primary signature component, b64u (PQ for a pure suite; Ed25519 for a hybrid suite). */
  sig: string;
  /** The PQ signature component, b64u — present ONLY for a hybrid / nested suite. */
  pq_sig?: string;
}

/** A verdict together with its post-quantum co-signature — the forward-secure attestation record. */
export interface PqCoSignedAttestation {
  /** The verdict whose security-relevant fields were co-signed. */
  verdict: AttestationVerdict;
  /** The post-quantum co-signature over {@link canonicalVerdictBytes}. */
  cosig: PqCoSig;
  /** The suite the co-signature was produced under. */
  suite: PqCoSignSuite;
  /** The co-signer's public key(s), for verification. */
  signer_pub: PqCoSignerPublicKey;
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Internal helpers.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/** Constant-time string equality (length-checked `timingSafeEqual` over UTF-8 bytes). */
function ctEq(a: string, b: string): boolean {
  const ba = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** The co-signer's PQ public key bytes for this suite, pulled from the supplied secret-key material (throws if absent). */
function pqPublicKeyBytes(suite: SigSuite, keys: SuiteSecretKeys): Uint8Array {
  if (suite.hasMlDsa) {
    if (!keys.mlDsa) throw new TypeError(`coSignAttestation: suite '${suite.alg}' requires mlDsa key material`);
    return keys.mlDsa.publicKey;
  }
  if (suite.hasSlhDsa) {
    if (!keys.slhDsa) throw new TypeError(`coSignAttestation: suite '${suite.alg}' requires slhDsa key material`);
    return keys.slhDsa.publicKey;
  }
  if (suite.hasMlDsa87) {
    if (!keys.mlDsa87) throw new TypeError(`coSignAttestation: suite '${suite.alg}' requires mlDsa87 key material`);
    return keys.mlDsa87.publicKey;
  }
  if (suite.hasSlhDsa256s) {
    if (!keys.slhDsa256s) throw new TypeError(`coSignAttestation: suite '${suite.alg}' requires slhDsa256s key material`);
    return keys.slhDsa256s.publicKey;
  }
  throw new TypeError(`coSignAttestation: suite '${suite.alg}' carries no post-quantum component (refusing to co-sign)`);
}

/** Map the co-signer's public key(s) onto the `@atlasauth/pca` verify-key slot the suite reads. */
function suiteVerifyKeys(suite: SigSuite, signerPub: PqCoSignerPublicKey): SuitePublicKeys {
  const out: SuitePublicKeys = {};
  if (suite.hasEd25519) out.edPub = signerPub.ed;
  if (suite.hasMlDsa) out.mlDsaPub = signerPub.pq;
  else if (suite.hasSlhDsa) out.slhDsaPub = signerPub.pq;
  else if (suite.hasMlDsa87) out.mlDsa87Pub = signerPub.pq;
  else if (suite.hasSlhDsa256s) out.slhDsa256sPub = signerPub.pq;
  return out;
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Co-sign.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/** Options for {@link coSignAttestation}. */
export interface CoSignOptions {
  /** The PQ co-sign suite (default {@link DEFAULT_PQ_COSIGN_SUITE} = `ml-dsa-65`). A classical-only suite is refused. */
  suite?: PqCoSignSuite;
  /**
   * The co-signer's secret key material (the `@atlasauth/pca` `SuiteSecretKeys` shape). Supply what the
   * chosen suite needs: a `mlDsa` / `slhDsa` / `mlDsa87` / `slhDsa256s` key pair, plus `edSecret` for a hybrid.
   */
  secretKey: SuiteSecretKeys;
  /** Pin the co-sign timestamp (epoch ms) for a deterministic signature (testing). Default `Date.now()`. */
  now?: number;
}

/**
 * Co-sign a verified attestation `verdict` under a POST-QUANTUM suite. Call this AFTER the classical AMD
 * hardware verification has passed ({@link verifyAmdAttestation} / `verifyFreshAttestedEAT`): it binds the
 * verdict's security-relevant fields ({@link canonicalVerdictBytes}) under an ML-DSA-65 signature by default
 * (or a hybrid / nested / category-5 suite), so PCA's propagation of the verdict no longer rests on the
 * classical hardware signature. FAIL-CLOSED on misconfiguration: a classical-only or unknown suite, or
 * missing key material for the suite, THROWS (a co-signer must never silently emit a weaker signature).
 */
export function coSignAttestation(verdict: AttestationVerdict, opts: CoSignOptions): PqCoSignedAttestation {
  const suiteName: PqCoSignSuite = opts.suite ?? DEFAULT_PQ_COSIGN_SUITE;
  if (!isPqCoSignSuite(suiteName)) {
    throw new RangeError(`coSignAttestation: '${String(suiteName)}' is not an accepted post-quantum co-sign suite`);
  }
  const suite = resolveSigAlg(suiteName);
  if (suite === null) throw new RangeError(`coSignAttestation: unknown suite '${suiteName}'`);
  if (!isRecord(opts.secretKey)) throw new TypeError('coSignAttestation: secretKey material is required');

  const cosignedAt = typeof opts.now === 'number' && Number.isFinite(opts.now) ? opts.now : Date.now();
  const msg = canonicalVerdictBytes(verdict, cosignedAt);

  // Compute the public key(s) BEFORE signing so a missing PQ key pair fails closed with a clear message.
  const signer_pub: PqCoSignerPublicKey = { pq: b64u(pqPublicKeyBytes(suite, opts.secretKey)) };
  if (suite.hasEd25519) {
    if (!(opts.secretKey.edSecret instanceof Uint8Array)) {
      throw new TypeError(`coSignAttestation: hybrid suite '${suite.alg}' requires edSecret`);
    }
    signer_pub.ed = b64u(publicKeyOf(opts.secretKey.edSecret));
  }

  const parts = signWithSuite(suiteName, opts.secretKey, msg); // throws on unknown alg / missing key material
  const cosig: PqCoSig = { cosignedAt, sig: parts.sig };
  if (parts.pq_sig !== undefined) cosig.pq_sig = parts.pq_sig;

  return { verdict, cosig, suite: suiteName, signer_pub };
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Verify.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/** Options for {@link verifyCoSignedAttestation}. */
export interface VerifyCoSignOptions {
  /**
   * Require the co-signature to be from this signer. A string matches the PQ public key (b64u); a
   * {@link PqCoSignerPublicKey} additionally matches the Ed25519 key when it supplies one. A mismatch fails
   * closed — without it, verification only proves the signature matches the key EMBEDDED in the artifact.
   */
  expectedSigner?: string | PqCoSignerPublicKey;
  /** Reject a co-signature older than this (ms), now − cosignedAt. Omit to skip the staleness gate. */
  maxAgeMs?: number;
  /** "Now", epoch ms (default `Date.now`). */
  now?: number;
}

/** The structured outcome of {@link verifyCoSignedAttestation} — fail-closed, with a specific reason on failure. */
export interface PqCoSignVerifyResult {
  /** True iff the PQ co-signature is authentic, the signer matched (if required), and it is within `maxAgeMs`. */
  ok: boolean;
  /** The specific reason the verification failed closed (absent on success). */
  reason?: string;
  /** The suite the co-signature was verified under (present once the suite resolved). */
  suite?: PqCoSignSuite;
  /** The verdict carried by the artifact (present once the structure validated). */
  verdict?: AttestationVerdict;
  /** The co-signer's public key(s) from the artifact (present once the structure validated). */
  signer_pub?: PqCoSignerPublicKey;
  /** The co-sign timestamp (epoch ms), present once the structure validated. */
  cosignedAt?: number;
  /** The co-signature's age (ms), now − cosignedAt, present once the structure validated. */
  ageMs?: number;
}

function parseSignerPub(v: unknown): PqCoSignerPublicKey | null {
  if (!isRecord(v) || typeof v.pq !== 'string' || v.pq.length === 0) return null;
  const out: PqCoSignerPublicKey = { pq: v.pq };
  if (typeof v.ed === 'string' && v.ed.length > 0) out.ed = v.ed;
  return out;
}

function signerMatches(expected: string | PqCoSignerPublicKey, got: PqCoSignerPublicKey): boolean {
  const expPq = typeof expected === 'string' ? expected : expected.pq;
  if (typeof expPq !== 'string' || !ctEq(expPq, got.pq)) return false;
  if (typeof expected !== 'string' && typeof expected.ed === 'string') {
    if (typeof got.ed !== 'string' || !ctEq(expected.ed, got.ed)) return false;
  }
  return true;
}

/**
 * Verify a {@link PqCoSignedAttestation}: recompute {@link canonicalVerdictBytes} from the artifact's OWN
 * verdict + co-sign timestamp and check the post-quantum signature under the embedded signer key. FAIL
 * CLOSED on a malformed artifact, a classical-only / unknown suite, a tampered verdict field (the recomputed
 * message no longer matches), a wrong key, an `expectedSigner` mismatch, or a co-signature older than
 * `maxAgeMs`. Returns a structured {@link PqCoSignVerifyResult}; never throws.
 */
export function verifyCoSignedAttestation(
  cosigned: PqCoSignedAttestation,
  opts: VerifyCoSignOptions = {},
): PqCoSignVerifyResult {
  try {
    if (!isRecord(cosigned)) return { ok: false, reason: 'co-signed attestation is not an object' };

    const verdict = cosigned.verdict;
    if (!isRecord(verdict) || typeof verdict.tier !== 'string' || typeof verdict.trustworthy !== 'boolean') {
      return { ok: false, reason: 'verdict is missing or has a non-string tier / non-boolean trustworthy' };
    }

    const cosig = cosigned.cosig;
    if (!isRecord(cosig) || typeof cosig.cosignedAt !== 'number' || !Number.isFinite(cosig.cosignedAt) || typeof cosig.sig !== 'string') {
      return { ok: false, reason: 'cosig is missing or has a non-numeric cosignedAt / non-string sig' };
    }

    if (!isPqCoSignSuite(cosigned.suite)) {
      return { ok: false, reason: `suite '${String(cosigned.suite)}' is not an accepted post-quantum co-sign suite` };
    }
    const suite = resolveSigAlg(cosigned.suite);
    if (suite === null) return { ok: false, reason: `unknown suite '${String(cosigned.suite)}'` };

    const signerPub = parseSignerPub(cosigned.signer_pub);
    if (signerPub === null) return { ok: false, reason: 'signer_pub is missing or has no post-quantum public key' };

    const now = typeof opts.now === 'number' && Number.isFinite(opts.now) ? opts.now : Date.now();
    const ageMs = now - cosig.cosignedAt;
    const partial: PqCoSignVerifyResult = {
      ok: false,
      suite: cosigned.suite,
      verdict: cosigned.verdict,
      signer_pub: signerPub,
      cosignedAt: cosig.cosignedAt,
      ageMs,
    };

    // Signer pinning (if required) — before anything else that could leak which gate failed.
    if (opts.expectedSigner !== undefined && !signerMatches(opts.expectedSigner, signerPub)) {
      return { ...partial, reason: 'co-signer public key does not match the expected signer' };
    }

    // Staleness (fail closed on a future timestamp or an over-age co-signature).
    if (opts.maxAgeMs !== undefined) {
      if (!Number.isFinite(opts.maxAgeMs) || opts.maxAgeMs <= 0) {
        return { ...partial, reason: 'invalid maxAgeMs' };
      }
      if (cosig.cosignedAt > now) return { ...partial, reason: 'co-sign timestamp is in the future' };
      if (ageMs > opts.maxAgeMs) return { ...partial, reason: 'co-signature is stale (older than maxAgeMs)' };
    }

    // Recompute the signed bytes from the artifact's OWN verdict — a tampered field no longer matches.
    const msg = canonicalVerdictBytes(cosigned.verdict, cosig.cosignedAt);
    const sigInput = cosig.pq_sig !== undefined ? { sig: cosig.sig, pq_sig: cosig.pq_sig } : { sig: cosig.sig };
    if (!verifyWithSuite(cosigned.suite, suiteVerifyKeys(suite, signerPub), msg, sigInput)) {
      return { ...partial, reason: 'post-quantum co-signature does not verify (tampered verdict, wrong key, or bad signature)' };
    }

    return { ...partial, ok: true };
  } catch (e) {
    return { ok: false, reason: `co-signature verification error (fail closed): ${e instanceof Error ? e.message : 'unknown'}` };
  }
}
