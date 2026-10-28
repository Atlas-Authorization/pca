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
 *
 * WHAT IT IS NOT: a claim that the agent or the system is safe. It signs (1) the risk-budget arithmetic and
 * (2) an optional list of WHICH CHECKS RAN, each with an evidence link (an https URL or a SHA-256 digest of an
 * evidence artifact) and its status. The verifier can require named checks to have `passed`; it does not
 * fetch or judge the evidence, and a `passed` entry is the guardian's assertion about it.
 */

import { b64u, canonicalBytesLenient, utf8, __canonicalizeLenientServerOnly } from './hash';
import { MAX_JSON_BYTES } from './strict-json';
import { publicKeyOf } from './keys';
import {
  type SignerSuiteOpts,
  type SigAlg,
  bindSuiteFields,
  suitePqPublicKey,
  suiteKeysOf,
  type PqPinPolicy,
  resolveSigAlg,
  signSuiteArtifact,
  verifyPinnedSuite,
} from './pq';
import { safetyBound, validateRiskPolicy, type RiskPolicy, type RiskWeights } from './risk';

/** Domain separation for the guardian signature (never collides with the PCActn / beacon / goal domains). */
export const SAFETY_CERT_DOMAIN = 'atlas-pca/safety-cert/v1\0';
export const SAFETY_CERT_VERSION = 1 as const;
/** The only thing the arithmetic bound speaks about. */
export const SAFETY_CERT_SCOPE = 'risk-budget-bound' as const;
export const MAX_SAFETY_CHECKS = 64;
const MAX_CHECK_ID = 64;
const MAX_EVIDENCE_URL = 2048;

export type SafetyCheckStatus = 'passed' | 'failed' | 'not_run';
export interface SafetyCheckEvidence {
  kind: 'url' | 'sha256';
  /** An https URL, or a 64-char lowercase hex SHA-256 of the evidence artifact. */
  ref: string;
}
/** One check the guardian asserts about (id is unique within a certificate). */
export interface SafetyCheck {
  id: string;
  status: SafetyCheckStatus;
  evidence: SafetyCheckEvidence;
  /** Epoch ms the check ran (or was recorded as not run). */
  at: number;
}

/** Null if the checks are well formed, else the first problem. */
export function validateSafetyChecks(checks: unknown): string | null {
  if (!Array.isArray(checks)) return 'checks must be an array';
  if (checks.length > MAX_SAFETY_CHECKS) return `more than ${MAX_SAFETY_CHECKS} checks`;
  const seen = new Set<string>();
  for (const c of checks as unknown[]) {
    if (c === null || typeof c !== 'object') return 'check is not an object';
    const k = c as Record<string, unknown>;
    if (typeof k.id !== 'string' || k.id.length === 0 || k.id.length > MAX_CHECK_ID) return 'check id must be a 1..64 char string';
    if (seen.has(k.id)) return `duplicate check id '${k.id}'`;
    seen.add(k.id);
    if (k.status !== 'passed' && k.status !== 'failed' && k.status !== 'not_run') return `check '${k.id}' has an invalid status`;
    if (!Number.isSafeInteger(k.at) || (k.at as number) < 0) return `check '${k.id}' has an invalid time`;
    const e = k.evidence as Record<string, unknown> | null;
    if (e === null || typeof e !== 'object' || typeof e.ref !== 'string') return `check '${k.id}' has no evidence link`;
    if (e.kind === 'sha256') {
      if (!/^[0-9a-f]{64}$/.test(e.ref)) return `check '${k.id}' evidence digest is not 64 lowercase hex`;
    } else if (e.kind === 'url') {
      let u: URL | null = null;
      try {
        u = new URL(e.ref);
      } catch {
        u = null;
      }
      if (e.ref.length > MAX_EVIDENCE_URL || !u || u.protocol !== 'https:' || u.username !== '' || u.password !== '') return `check '${k.id}' evidence URL must be a plain https URL`;
    } else return `check '${k.id}' has an invalid evidence kind`;
  }
  return null;
}

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
  /** What the bound speaks about: only the risk-budget arithmetic. Verifiers refuse any other value. */
  scope: typeof SAFETY_CERT_SCOPE;
  /** Optional: which checks ran, with evidence links. Signed with the claim. Absent == no check claims made. */
  checks?: SafetyCheck[];
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
export type SafetyCertificateSuiteOpts = SignerSuiteOpts;

/** The provable bound for a policy: `B_max / κ` (0 if κ ≤ 0). Reuses the risk.ts theorem helper. */
export function safetyCertificateBound(p: Pick<RiskPolicy, 'bMax' | 'kappa'>): number {
  return safetyBound(p);
}

/** Canonical human-readable statement of the bound. */
export function safetyCertificateStatement(bound: number): string {
  return (
    `Arithmetic consequence of the signed risk parameters: between two consecutive human co-signs, the total risk of autonomous actions Σ r(Aᵢ) ≤ ${bound} ` +
    `(= B_max / κ). This is not a claim that the agent or the system is safe.`
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
  /** Checks that ran, with evidence links (validated; throws on a malformed list). */
  checks?: SafetyCheck[];
  /** Issue time (ms); defaults to `Date.now()`. */
  issuedAt?: number;
  /** Signature suite (default ed25519, byte-identical). For ml-dsa-65/hybrid pass the guardian ML-DSA key pair. */
  suite?: SafetyCertificateSuiteOpts;
}): SafetyCertificate {
  const bad = validateRiskPolicy(args.policy);
  if (bad) throw new Error(`issueSafetyCertificate: ${bad}`);
  if (resolveSigAlg(args.suite?.alg) === null) throw new Error(`issueSafetyCertificate: unknown signature alg '${String(args.suite?.alg)}'`);
  if (args.checks !== undefined) {
    const badChecks = validateSafetyChecks(args.checks);
    if (badChecks) throw new Error(`issueSafetyCertificate: ${badChecks}`);
  }
  const bound = safetyCertificateBound(args.policy);
  const pqPk = suitePqPublicKey(args.suite?.alg, args.suite);
  const base: SafetyCertificateClaim = {
    v: SAFETY_CERT_VERSION,
    statement: safetyCertificateStatement(bound),
    scope: SAFETY_CERT_SCOPE,
    ...(args.checks !== undefined ? { checks: args.checks.map((c) => ({ id: c.id, status: c.status, evidence: { kind: c.evidence.kind, ref: c.evidence.ref }, at: c.at })) } : {}),
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
  const fields = signSuiteArtifact(args.suite?.alg, suiteKeysOf(args.guardianSecret, args.suite), safetyCertificateMessage(claim));
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
  opts: {
    guardian?: string;
    /** Check ids that must be present with status `passed`. */
    requireChecks?: string[];
    /** Refuse a certificate older than this (needs `issued_at`; also refuses one issued in the future). */
    maxAgeMs?: number;
    now?: number;
  } & PqPinPolicy = {},
): SafetyCertificateVerdict {
  try {
    if (!cert || typeof cert !== 'object' || cert.v !== SAFETY_CERT_VERSION) return { ok: false, reason: 'malformed certificate' };
    if (typeof cert.sig !== 'string' || typeof cert.guardian !== 'string') return { ok: false, reason: 'missing guardian/signature' };
    if (cert.scope !== SAFETY_CERT_SCOPE) return { ok: false, reason: 'unknown scope' };
    if (cert.checks !== undefined) {
      const badChecks = validateSafetyChecks(cert.checks);
      if (badChecks) return { ok: false, reason: `invalid checks: ${badChecks}` };
    }
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
    if (!verifyPinnedSuite(cert.alg, cert.guardian, cert.pq_pk, safetyCertificateMessage(cert), { sig: cert.sig, pq_sig: cert.pq_sig }, opts)) {
      return { ok: false, reason: 'guardian signature does not verify', recomputedBound };
    }
    // Policy checks run AFTER the signature so an unsigned certificate never learns which check was missing.
    if (opts.maxAgeMs !== undefined) {
      const now = opts.now ?? Date.now();
      if (!Number.isFinite(opts.maxAgeMs) || !Number.isFinite(now) || !Number.isFinite(cert.issued_at)) return { ok: false, reason: 'invalid age policy or issue time', recomputedBound };
      if (cert.issued_at > now) return { ok: false, reason: 'certificate is issued in the future', recomputedBound };
      if (now - cert.issued_at > opts.maxAgeMs) return { ok: false, reason: 'certificate is older than maxAgeMs', recomputedBound };
    }
    for (const id of opts.requireChecks ?? []) {
      const c = cert.checks?.find((k) => k.id === id);
      if (!c) return { ok: false, reason: `required check '${id}' is not present`, recomputedBound };
      if (c.status !== 'passed') return { ok: false, reason: `required check '${id}' is ${c.status}`, recomputedBound };
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

/** Parse a certificate from its JSON string (shape-guarded and size-bounded at MAX_JSON_BYTES; never throws, returns null on garbage). */
export function decodeSafetyCertificate(s: string): SafetyCertificate | null {
  try {
    // same input-size bound as the strict wire parser (UTF-8 bytes); oversize input is garbage, not work to do
    if (typeof s !== 'string' || new TextEncoder().encode(s).length > MAX_JSON_BYTES) return null;
    const v = JSON.parse(s) as SafetyCertificate;
    if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
    if (v.v !== SAFETY_CERT_VERSION || typeof v.sig !== 'string' || typeof v.guardian !== 'string') return null;
    if (v.params === null || typeof v.params !== 'object') return null;
    return v;
  } catch {
    return null;
  }
}

/** A compliance-export row for a verified certificate: which checks ran and where the evidence is. Not a safety claim. */
export interface SafetyEvidenceRow {
  control: 'risk-budget-bound';
  guardian: string;
  issued_at: number;
  bound: number;
  checks: Array<{ id: string; status: SafetyCheckStatus; evidence: string }>;
}

/** Verify `cert` (same options as verifySafetyCertificate) and, only if it verifies, return the evidence row. Else null. */
export function safetyCertificateForCompliance(cert: SafetyCertificate, opts: Parameters<typeof verifySafetyCertificate>[1] = {}): SafetyEvidenceRow | null {
  if (!verifySafetyCertificate(cert, opts).ok) return null;
  return {
    control: SAFETY_CERT_SCOPE,
    guardian: cert.guardian,
    issued_at: cert.issued_at,
    bound: cert.bound,
    checks: (cert.checks ?? []).map((c) => ({ id: c.id, status: c.status, evidence: c.evidence.kind === 'sha256' ? `sha256:${c.evidence.ref}` : c.evidence.ref })),
  };
}
