/**
 * Machine-readable safety certificate (PCA evolution).
 *
 * The Deep-Dive-III safety invariant is a THEOREM, machine-checked in the TLA+ model: between two
 * consecutive human recharges the total risk of autonomous (machine-only) actions is bounded a priori,
 *
 *     Σ c(Aᵢ) ≤ B_available ≤ B_max   ⇒   Σ r(Aᵢ) ≤ B_max / κ ,
 *
 * even if the agent is fully compromised. Operationally that is an SLA: a provable upper bound on blast
 * radius per human checkpoint. This module turns a grant's `risk_policy` into a signed, machine-readable
 * ASSERTION of that bound — the parameters, the derived `B_max/κ`, and a domain-separated guardian
 * signature — plus {@link verifySafetyCertificate}, which RECOMPUTES the bound from the parameters and
 * checks the signature. A certificate is therefore self-checking: a consumer never trusts the stated
 * number, it re-derives it and verifies the guardian attested to those exact parameters.
 */

import { b64u, canonicalBytesLenient, utf8, __canonicalizeLenientServerOnly } from './hash';
import { publicKeyOf } from './keys';
import {
  type MlDsaKeyPair,
  type SigAlg,
  bindSuiteFields,
  encodeMlDsaPublicKey,
  resolveSigAlg,
  signSuiteArtifact,
  verifyWithSuite,
} from './pq';
import { safetyBound, validateRiskPolicy, type RiskPolicy, type RiskWeights } from './risk';

/** Domain separation for the guardian signature (never collides with the PCActn / beacon / goal domains). */
export const SAFETY_CERT_DOMAIN = 'atlas-pca/safety-cert/v1\0';
export const SAFETY_CERT_VERSION = 1 as const;

/** The policy parameters a certificate pins. Mirrors the enforceable `risk_policy` (risk.ts). */
export interface SafetyCertificateParams {
  bMax: number;
  kappa: number;
  theta1: number;
  theta2: number;
  lambda: number;
  rho: number;
  weights: RiskWeights;
}

/** The unsigned claim. The guardian signature covers exactly this (canonically). */
export interface SafetyCertificateClaim {
  v: 1;
  /** Human-readable rendering of the invariant (advisory; the machine fields are authoritative). */
  statement: string;
  params: SafetyCertificateParams;
  /** The provable per-checkpoint bound: `Σ r(Aᵢ) ≤ bound = B_max / κ` between two human co-signs. */
  bound: number;
  /** Alias: the maximum blast radius a single human checkpoint authorizes (== `bound`). */
  blastRadiusPerCheckpoint: number;
  /** Optional binding to a specific grant / instance. */
  grant_ref?: string;
  instance?: string;
  /** Epoch ms the certificate was issued. */
  issued_at: number;
  /** Guardian public key (b64u Ed25519 identity) that signs this certificate. */
  guardian: string;
  /** Signature suite — bound into the signed claim for a non-default suite; absent == ed25519 (byte-identical). */
  alg?: SigAlg;
  /** b64u ML-DSA-65 public key of the guardian — ml-dsa-65 / hybrid (bound into the signed claim). */
  pq_pk?: string;
}

export interface SafetyCertificate extends SafetyCertificateClaim {
  /** b64u signature by the guardian over `SAFETY_CERT_DOMAIN ‖ canonical(claim)` (Ed25519 for ed25519/hybrid, ML-DSA-65 for pure). */
  sig: string;
  /** b64u ML-DSA-65 certificate signature — hybrid only. */
  pq_sig?: string;
}

/** Optional signature-suite material for a safety certificate (default ed25519). */
export interface SafetyCertificateSuiteOpts {
  alg?: SigAlg;
  /** The guardian's ML-DSA-65 key pair — required for ml-dsa-65 / hybrid. */
  mlDsa?: MlDsaKeyPair;
}

/** The provable bound for a policy: `B_max / κ` (0 if κ ≤ 0). Reuses the risk.ts theorem helper. */
export function safetyCertificateBound(p: Pick<RiskPolicy, 'bMax' | 'kappa'>): number {
  return safetyBound(p);
}

/** Canonical human-readable statement of the bound. */
export function safetyCertificateStatement(bound: number): string {
  return (
    `Between two consecutive human co-signs, the total risk of autonomous actions Σ r(Aᵢ) ≤ ${bound} ` +
    `(= B_max / κ); hence the blast radius authorized per human checkpoint is at most ${bound}.`
  );
}

function claimOf(c: SafetyCertificate | SafetyCertificateClaim): SafetyCertificateClaim {
  // The signed claim EXCLUDES both signature fields (`sig`, `pq_sig`); `alg`/`pq_pk` stay and are signed.
  const { sig: _sig, pq_sig: _pqSig, ...claim } = c as SafetyCertificate;
  void _sig;
  void _pqSig;
  return claim;
}

/** The exact bytes the guardian signs: `SAFETY_CERT_DOMAIN ‖ canonical(claim)`. */
export function safetyCertificateMessage(c: SafetyCertificate | SafetyCertificateClaim): Uint8Array {
  const body = canonicalBytesLenient(claimOf(c));
  const pre = utf8(SAFETY_CERT_DOMAIN);
  const m = new Uint8Array(pre.length + body.length);
  m.set(pre);
  m.set(body, pre.length);
  return m;
}

function paramsOf(p: RiskPolicy): SafetyCertificateParams {
  return {
    bMax: p.bMax,
    kappa: p.kappa,
    theta1: p.theta1,
    theta2: p.theta2,
    lambda: p.lambda,
    rho: p.rho,
    weights: { ...p.weights },
  };
}

/**
 * Issue a signed safety certificate for a grant's `risk_policy`. Validates the policy (throws on a
 * malformed one), derives the bound `B_max/κ`, and signs the claim with the guardian's key.
 */
export function issueSafetyCertificate(args: {
  policy: RiskPolicy;
  /** Guardian secret key (Ed25519). */
  guardianSecret: Uint8Array;
  grantRef?: string;
  instance?: string;
  /** Issue time (ms); defaults to `Date.now()`. */
  issuedAt?: number;
  /** Signature suite (default ed25519, byte-identical). For ml-dsa-65/hybrid pass the guardian ML-DSA key pair. */
  suite?: SafetyCertificateSuiteOpts;
}): SafetyCertificate {
  const bad = validateRiskPolicy(args.policy);
  if (bad) throw new Error(`issueSafetyCertificate: ${bad}`);
  if (resolveSigAlg(args.suite?.alg) === null) throw new Error(`issueSafetyCertificate: unknown signature alg '${String(args.suite?.alg)}'`);
  const bound = safetyCertificateBound(args.policy);
  const pqPk = args.suite?.mlDsa ? encodeMlDsaPublicKey(args.suite.mlDsa.publicKey) : undefined;
  const base: SafetyCertificateClaim = {
    v: SAFETY_CERT_VERSION,
    statement: safetyCertificateStatement(bound),
    params: paramsOf(args.policy),
    bound,
    blastRadiusPerCheckpoint: bound,
    ...(args.grantRef !== undefined ? { grant_ref: args.grantRef } : {}),
    ...(args.instance !== undefined ? { instance: args.instance } : {}),
    issued_at: args.issuedAt ?? Date.now(),
    guardian: b64u(publicKeyOf(args.guardianSecret)),
  };
  // Bind the suite (alg + guardian ML-DSA key) into the signed claim; ed25519 is byte-identical.
  const claim = bindSuiteFields(base, args.suite?.alg, pqPk);
  const fields = signSuiteArtifact(args.suite?.alg, { edSecret: args.guardianSecret, mlDsa: args.suite?.mlDsa }, safetyCertificateMessage(claim));
  return { ...claim, ...fields };
}

export interface SafetyCertificateVerdict {
  ok: boolean;
  reason?: string;
  /** The bound RECOMPUTED from the certificate's own parameters (independent of the stated `bound`). */
  recomputedBound?: number;
}

/**
 * Verify a safety certificate. Never throws. Checks, in order:
 *   1. shape + policy well-formedness,
 *   2. the stated `bound` / `blastRadiusPerCheckpoint` equal the bound RECOMPUTED from `params` (`B_max/κ`),
 *   3. the guardian signature over `SAFETY_CERT_DOMAIN ‖ canonical(claim)`,
 *   4. (optional) the guardian key matches a pinned key.
 * Any tampering with a parameter, the bound, or the signature fails verification.
 */
export function verifySafetyCertificate(
  cert: SafetyCertificate,
  opts: { guardian?: string } = {},
): SafetyCertificateVerdict {
  try {
    if (!cert || typeof cert !== 'object' || cert.v !== SAFETY_CERT_VERSION) return { ok: false, reason: 'malformed certificate' };
    if (typeof cert.sig !== 'string' || typeof cert.guardian !== 'string') return { ok: false, reason: 'missing guardian/signature' };
    const bad = validateRiskPolicy({ ...cert.params });
    if (bad) return { ok: false, reason: `invalid parameters: ${bad}` };

    const recomputedBound = safetyCertificateBound(cert.params);
    if (!Number.isFinite(cert.bound) || cert.bound !== recomputedBound) {
      return { ok: false, reason: 'stated bound does not equal B_max/κ recomputed from the parameters', recomputedBound };
    }
    if (cert.blastRadiusPerCheckpoint !== recomputedBound) {
      return { ok: false, reason: 'blastRadiusPerCheckpoint does not equal the recomputed bound', recomputedBound };
    }
    if (opts.guardian !== undefined && opts.guardian !== cert.guardian) {
      return { ok: false, reason: 'guardian key is not the pinned key', recomputedBound };
    }
    if (resolveSigAlg(cert.alg) === null) return { ok: false, reason: 'unknown signature alg', recomputedBound };
    // Suite-agile (ed25519 == verifyB64u(guardian, …, sig)); hybrid requires BOTH; pure ml-dsa under pq_pk.
    if (!verifyWithSuite(cert.alg, { edPub: cert.guardian, mlDsaPub: cert.pq_pk }, safetyCertificateMessage(cert), { sig: cert.sig, pq_sig: cert.pq_sig })) {
      return { ok: false, reason: 'guardian signature does not verify', recomputedBound };
    }
    return { ok: true, recomputedBound };
  } catch (e) {
    return { ok: false, reason: `malformed certificate: ${e instanceof Error ? e.message : 'unknown'}` };
  }
}

/** Serialize to a canonical JSON string (machine-readable artifact). */
export function encodeSafetyCertificate(cert: SafetyCertificate): string {
  return __canonicalizeLenientServerOnly(cert);
}

/** Parse a certificate from its JSON string (shape-guarded; never throws, returns null on garbage). */
export function decodeSafetyCertificate(s: string): SafetyCertificate | null {
  try {
    const v = JSON.parse(s) as SafetyCertificate;
    if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
    if (v.v !== SAFETY_CERT_VERSION || typeof v.sig !== 'string' || typeof v.guardian !== 'string') return null;
    if (v.params === null || typeof v.params !== 'object') return null;
    return v;
  } catch {
    return null;
  }
}
