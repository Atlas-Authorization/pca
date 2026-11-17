import { sha256 } from './hash';
import { closedMembers, isPlainObject, isSafeInt, utf8Len } from './intent-artifacts';
import type { ClaimRequirement, DischargeBody, DischargeRequest, NeedsDischargeCaveat } from './caveat-lang';
import type { WireScalar } from './intent-artifacts';

/**
 * BUILD PROVENANCE AS A K1 DISCHARGE (track K9; security contract C-520..C-526).
 *
 * A signed action pack or a pinned MCP server key proves "this key signed". It does not prove "this repository, this commit,
 * this builder". This module is the policy half of that check, kept pure so every native verifier runs the same gates:
 *
 *   1. the cryptographic half (Sigstore bundle, Fulcio chain, Rekor inclusion, DSSE signature, done by
 *      `@atlasauth/pca-attest-eat` `verifySigstoreBundle`) establishes {@link BuildProvenanceFacts};
 *   2. {@link provenanceGate} checks those facts against the VERIFIER's pins: a signer-builder pair decides the SLSA level
 *      (SLSA v1.0 "Verifying artifacts": the level is looked up from the trusted (signer, builder.id) pair, never read from the
 *      provenance), source repository and ref, build type, age, and the runtime join (the measured digest of the running
 *      image must be one of the provenance subjects);
 *   3. an attestation verifier pinned with class `artifact` signs an ordinary K1 discharge carrying {@link BuildProvenanceClaims};
 *      a grant asks for it with {@link provenanceCaveat} (`needs_discharge` with `issuer_class: "artifact"`).
 *
 * Polarity: the discharge is required by a caveat, so provenance can only remove authority. A missing, unverifiable, stale or
 * mismatched provenance yields no discharge, and the caveat refuses (escalate with a discharge request at the PEP).
 *
 * The gate returns a short `code` on refusal (shared with the natives through `conformance/provenance-vectors.json`).
 * Everything is total: malformed input is a refusal, never an exception.
 */

export const SLSA_PROVENANCE_V1 = 'https://slsa.dev/provenance/v1';
export const INTOTO_STATEMENT_V1 = 'https://in-toto.io/Statement/v1';

// ------------------------------------------------------------------------------------------------ RFC 9162 inclusion

/** RFC 9162 section 2.1.1: the hash of a leaf, SHA-256(0x00 || data). */
export function rfc9162LeafHash(data: Uint8Array): Uint8Array {
  const m = new Uint8Array(data.length + 1);
  m.set(data, 1);
  return sha256(m);
}

function nodeHash(l: Uint8Array, r: Uint8Array): Uint8Array {
  const m = new Uint8Array(65);
  m[0] = 1;
  m.set(l, 1);
  m.set(r, 33);
  return sha256(m);
}

const eqBytes = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * RFC 9162 section 2.1.3.2: verify an inclusion proof of `leafHash` at `index` in a tree of `size` leaves with root `root`.
 * `proof` runs from the leaf level up, without the leaf and the root. Index and size are non-negative safe integers
 * (BigInt arithmetic inside, so logs beyond 2^31 entries work). False on any malformed input.
 */
export function verifyRfc9162Inclusion(leafHash: Uint8Array, index: number, size: number, proof: readonly Uint8Array[], root: Uint8Array): boolean {
  try {
    if (!(isSafeInt(index) && isSafeInt(size) && index >= 0 && size >= 1 && index < size)) return false;
    if (!(leafHash instanceof Uint8Array) || leafHash.length !== 32 || !(root instanceof Uint8Array) || root.length !== 32) return false;
    if (!Array.isArray(proof) || proof.length > 64 || !proof.every((p) => p instanceof Uint8Array && p.length === 32)) return false;
    let fn = BigInt(index);
    let sn = BigInt(size - 1);
    let r = leafHash;
    for (const p of proof) {
      if (sn === 0n) return false;
      if ((fn & 1n) === 1n || fn === sn) {
        r = nodeHash(p, r);
        if ((fn & 1n) === 0n) {
          while ((fn & 1n) === 0n && fn !== 0n) {
            fn >>= 1n;
            sn >>= 1n;
          }
        }
      } else r = nodeHash(r, p);
      fn >>= 1n;
      sn >>= 1n;
    }
    return sn === 0n && eqBytes(r, root);
  } catch {
    return false;
  }
}

// ------------------------------------------------------------------------------------------------ facts and policy

export type SubjectAlg = 'sha256' | 'sha512';
export interface SubjectDigest {
  alg: SubjectAlg;
  /** Lowercase hex: 64 digits for sha256, 128 for sha512. */
  digest: string;
}

/** What the cryptographic check established. Strings are exactly as signed; nothing here is trusted before the gate. */
export interface BuildProvenanceFacts {
  v: 1;
  /** in-toto predicateType of the verified statement. */
  predicate_type: string;
  build_type: string;
  /** SLSA `runDetails.builder.id`. */
  builder_id: string;
  /** Statement subjects (1..64). */
  subjects: SubjectDigest[];
  /** Fulcio certificate SAN (URI or email): the signer identity. */
  identity: string;
  /** Fulcio OIDC issuer extension (1.3.6.1.4.1.57264.1.8, or the legacy .1.1). */
  oidc_issuer: string;
  /** Fulcio Source Repository URI / Ref / Digest extensions (.1.12 / .1.14 / .1.13), when the signer's token carried them. */
  source_repo?: string;
  source_ref?: string;
  source_digest?: string;
  /** The first `resolvedDependencies` entry of the provenance (what the builder says it built), when present. */
  provenance_source?: { uri: string; git_commit?: string };
  /** Rekor integrated time (unix seconds), verified through the signed entry timestamp. */
  integrated_time: number;
  rekor_log_index: number;
}

/** A trusted (signer, builder) pair and the highest SLSA build level it may vouch for. */
export interface BuildProvenanceRoot {
  oidc_issuer: string;
  /** Exactly one of `identity` (exact SAN) and `identity_prefix` (SAN starts with it). */
  identity?: string;
  identity_prefix?: string;
  builder_id: string;
  level: 1 | 2 | 3;
}

export interface BuildProvenancePolicy {
  /** 1..32 trusted signer-builder pairs. Nothing else decides a level. */
  roots: BuildProvenanceRoot[];
  /** Lowest acceptable level, 1..3. */
  min_level: number;
  source_repo?: string;
  /** Exactly one of these may be given. */
  source_ref?: string;
  source_ref_prefix?: string;
  /** Allowed `buildType` values (1..16), when given. */
  build_types?: string[];
  /** Maximum age of the log entry in seconds. */
  max_age_s?: number;
  /** The runtime digest must be supplied (and join a subject). */
  require_runtime?: boolean;
}

/** The claims an `artifact` discharge carries (at most 16 scalars, strings at most 256 bytes: the K1 claim rules). */
export interface BuildProvenanceClaims {
  subject_alg: SubjectAlg;
  subject_digest: string;
  slsa_level: number;
  builder_id: string;
  build_type: string;
  oidc_issuer: string;
  identity: string;
  source_repo?: string;
  source_ref?: string;
  source_digest?: string;
  rekor_log_index: number;
  /** True iff the subject was matched to the digest of the running image the verifier measured. */
  runtime_bound: boolean;
}

export type ProvenanceGateCode =
  | 'malformed_policy'
  | 'malformed_facts'
  | 'malformed_runtime'
  | 'predicate_type'
  | 'future'
  | 'stale'
  | 'no_root'
  | 'level'
  | 'source_mismatch'
  | 'source_repo'
  | 'source_ref'
  | 'build_type'
  | 'runtime_required'
  | 'runtime_mismatch'
  | 'subject_ambiguous'
  | 'claim_too_long';

export type ProvenanceGateResult = { ok: true; level: number; claims: BuildProvenanceClaims } | { ok: false; code: ProvenanceGateCode };

const HEX = { sha256: /^[0-9a-f]{64}$/, sha512: /^[0-9a-f]{128}$/ } as const;
const str = (v: unknown, max = 2048): v is string => typeof v === 'string' && v.length > 0 && utf8Len(v) <= max;

function subjectError(s: unknown): boolean {
  if (!isPlainObject(s) || closedMembers(s, ['alg', 'digest']) !== null) return true;
  return !((s.alg === 'sha256' || s.alg === 'sha512') && typeof s.digest === 'string' && HEX[s.alg].test(s.digest));
}

/** Null when well-formed (closed members, bounded strings). */
export function provenanceFactsError(f: unknown): string | null {
  if (!isPlainObject(f)) return 'facts must be an object';
  const e = closedMembers(f, ['v', 'predicate_type', 'build_type', 'builder_id', 'subjects', 'identity', 'oidc_issuer', 'integrated_time', 'rekor_log_index'], ['source_repo', 'source_ref', 'source_digest', 'provenance_source'], 'facts');
  if (e) return e;
  if (f.v !== 1) return 'facts.v must be 1';
  for (const k of ['predicate_type', 'build_type', 'builder_id', 'identity', 'oidc_issuer'] as const) if (!str(f[k])) return `facts.${k} must be a non-empty string`;
  for (const k of ['source_repo', 'source_ref', 'source_digest'] as const) if (f[k] !== undefined && !str(f[k])) return `facts.${k} must be a non-empty string`;
  if (!Array.isArray(f.subjects) || f.subjects.length < 1 || f.subjects.length > 64 || f.subjects.some(subjectError)) return 'facts.subjects must be 1..64 {alg, digest}';
  if (!(isSafeInt(f.integrated_time) && f.integrated_time >= 0)) return 'facts.integrated_time must be a non-negative integer';
  if (!(isSafeInt(f.rekor_log_index) && f.rekor_log_index >= 0)) return 'facts.rekor_log_index must be a non-negative integer';
  if (f.provenance_source !== undefined) {
    const p = f.provenance_source;
    if (!isPlainObject(p) || closedMembers(p, ['uri'], ['git_commit']) !== null || !str(p.uri) || (p.git_commit !== undefined && !str(p.git_commit))) return 'facts.provenance_source is malformed';
  }
  return null;
}

/** Null when well-formed. */
export function provenancePolicyError(p: unknown): string | null {
  if (!isPlainObject(p)) return 'policy must be an object';
  const e = closedMembers(p, ['roots', 'min_level'], ['source_repo', 'source_ref', 'source_ref_prefix', 'build_types', 'max_age_s', 'require_runtime'], 'policy');
  if (e) return e;
  if (!Array.isArray(p.roots) || p.roots.length < 1 || p.roots.length > 32) return 'policy.roots must hold 1..32 pairs';
  for (const r of p.roots) {
    if (!isPlainObject(r) || closedMembers(r, ['oidc_issuer', 'builder_id', 'level'], ['identity', 'identity_prefix']) !== null) return 'policy root is malformed';
    if (!str(r.oidc_issuer) || !str(r.builder_id)) return 'policy root needs oidc_issuer and builder_id';
    if ((r.identity === undefined) === (r.identity_prefix === undefined)) return 'policy root needs exactly one of identity and identity_prefix';
    if (r.identity !== undefined && !str(r.identity)) return 'policy root identity is malformed';
    // a prefix must at least name a scheme and a host; an empty-ish prefix would pin nothing
    if (r.identity_prefix !== undefined && !(str(r.identity_prefix) && r.identity_prefix.length >= 10)) return 'policy root identity_prefix must be at least 10 characters';
    if (r.level !== 1 && r.level !== 2 && r.level !== 3) return 'policy root level must be 1, 2 or 3';
  }
  if (!(p.min_level === 1 || p.min_level === 2 || p.min_level === 3)) return 'policy.min_level must be 1, 2 or 3';
  if (p.source_repo !== undefined && !str(p.source_repo)) return 'policy.source_repo is malformed';
  if (p.source_ref !== undefined && p.source_ref_prefix !== undefined) return 'policy takes source_ref or source_ref_prefix, not both';
  if (p.source_ref !== undefined && !str(p.source_ref)) return 'policy.source_ref is malformed';
  if (p.source_ref_prefix !== undefined && !str(p.source_ref_prefix)) return 'policy.source_ref_prefix is malformed';
  if (p.build_types !== undefined && !(Array.isArray(p.build_types) && p.build_types.length >= 1 && p.build_types.length <= 16 && p.build_types.every((b) => str(b)))) return 'policy.build_types must hold 1..16 strings';
  if (p.max_age_s !== undefined && !(isSafeInt(p.max_age_s) && p.max_age_s >= 1)) return 'policy.max_age_s must be a positive integer';
  if (p.require_runtime !== undefined && typeof p.require_runtime !== 'boolean') return 'policy.require_runtime must be a boolean';
  return null;
}

export interface ProvenanceGateInput {
  facts: unknown;
  policy: unknown;
  /** The digest of the running image the verifier measured itself (EAT/TEE), when it has one. */
  runtime?: unknown;
  /** Verifier clock, unix seconds. */
  now: number;
}

/**
 * The provenance gates, in order: policy, facts, predicate type, time (not from the future, not older than `max_age_s`),
 * a pinned signer-builder pair (its level, the highest among matching pairs), the level floor, the provenance's own source
 * against the certificate's (commit and repository must agree when both are present), the source repository and ref pins,
 * the build type, then the subject: with a runtime digest it must be one of the subjects (`runtime_bound: true`); without
 * one, `require_runtime` refuses and a statement with more than one subject is ambiguous. Every claim must fit the K1 claim
 * limits. Total.
 */
export function provenanceGate(input: ProvenanceGateInput): ProvenanceGateResult {
  const no = (code: ProvenanceGateCode): ProvenanceGateResult => ({ ok: false, code });
  try {
    if (!isPlainObject(input)) return no('malformed_facts');
    const { facts, policy, runtime, now } = input;
    if (provenancePolicyError(policy) !== null) return no('malformed_policy');
    if (provenanceFactsError(facts) !== null) return no('malformed_facts');
    if (!(isSafeInt(now) && now >= 0)) return no('malformed_facts');
    const f = facts as BuildProvenanceFacts;
    const p = policy as BuildProvenancePolicy;
    if (runtime !== undefined && subjectError(runtime)) return no('malformed_runtime');
    if (f.predicate_type !== SLSA_PROVENANCE_V1) return no('predicate_type');
    if (f.integrated_time > now) return no('future');
    if (p.max_age_s !== undefined && now - f.integrated_time > p.max_age_s) return no('stale');
    let level = 0;
    for (const r of p.roots) {
      if (r.oidc_issuer !== f.oidc_issuer || r.builder_id !== f.builder_id) continue;
      if (r.identity !== undefined ? r.identity !== f.identity : !f.identity.startsWith(r.identity_prefix!)) continue;
      if (r.level > level) level = r.level;
    }
    if (level === 0) return no('no_root');
    if (level < p.min_level) return no('level');
    const ps = f.provenance_source;
    if (ps !== undefined) {
      if (ps.git_commit !== undefined && f.source_digest !== undefined && ps.git_commit !== f.source_digest) return no('source_mismatch');
      if (f.source_repo !== undefined && !(ps.uri === `git+${f.source_repo}` || ps.uri.startsWith(`git+${f.source_repo}@`))) return no('source_mismatch');
    }
    if (p.source_repo !== undefined && f.source_repo !== p.source_repo) return no('source_repo');
    if (p.source_ref !== undefined && f.source_ref !== p.source_ref) return no('source_ref');
    if (p.source_ref_prefix !== undefined && !(f.source_ref !== undefined && f.source_ref.startsWith(p.source_ref_prefix))) return no('source_ref');
    if (p.build_types !== undefined && !p.build_types.includes(f.build_type)) return no('build_type');
    let subject: SubjectDigest;
    let bound = false;
    if (runtime !== undefined) {
      const rt = runtime as SubjectDigest;
      const hit = f.subjects.find((s) => s.alg === rt.alg && s.digest === rt.digest);
      if (!hit) return no('runtime_mismatch');
      subject = hit;
      bound = true;
    } else {
      if (p.require_runtime === true) return no('runtime_required');
      if (f.subjects.length !== 1) return no('subject_ambiguous');
      subject = f.subjects[0]!;
    }
    const claims: BuildProvenanceClaims = {
      subject_alg: subject.alg,
      subject_digest: subject.digest,
      slsa_level: level,
      builder_id: f.builder_id,
      build_type: f.build_type,
      oidc_issuer: f.oidc_issuer,
      identity: f.identity,
      ...(f.source_repo !== undefined ? { source_repo: f.source_repo } : {}),
      ...(f.source_ref !== undefined ? { source_ref: f.source_ref } : {}),
      ...(f.source_digest !== undefined ? { source_digest: f.source_digest } : {}),
      rekor_log_index: f.rekor_log_index,
      runtime_bound: bound,
    };
    for (const v of Object.values(claims)) if (typeof v === 'string' && utf8Len(v) > 256) return no('claim_too_long');
    return { ok: true, level, claims };
  } catch {
    return no('malformed_facts');
  }
}

// ------------------------------------------------------------------------------------------------ caveat and discharge

export interface ProvenanceCaveatOptions {
  /** Caveat id (K1 id syntax). Default `provenance`. */
  id?: string;
  /** Label of the verifier's `artifact` pin. */
  issuer: string;
  min_level: 1 | 2 | 3;
  source_repo?: string;
  /** Allowed builder ids (1..16), when given. */
  builder_ids?: string[];
  oidc_issuer?: string;
  /** Require `runtime_bound: true` (this exact binary runs the action). Default true. */
  require_runtime?: boolean;
  /** Default `action`: one provenance check per action. */
  bind?: 'chain_hop' | 'action';
  /** Default 300 000 (5 minutes). */
  ttl_ms?: number;
}

/** A `needs_discharge` caveat that asks the pinned `artifact` verifier for provenance claims. */
export function provenanceCaveat(o: ProvenanceCaveatOptions): NeedsDischargeCaveat {
  const require: ClaimRequirement[] = [{ claim: 'slsa_level', op: 'gte', value: o.min_level }];
  if (o.source_repo !== undefined) require.push({ claim: 'source_repo', op: 'eq', value: o.source_repo });
  if (o.builder_ids !== undefined) require.push({ claim: 'builder_id', op: 'in', value: o.builder_ids });
  if (o.oidc_issuer !== undefined) require.push({ claim: 'oidc_issuer', op: 'eq', value: o.oidc_issuer });
  if (o.require_runtime !== false) require.push({ claim: 'runtime_bound', op: 'eq', value: true });
  return { type: 'needs_discharge', id: o.id ?? 'provenance', issuer: o.issuer, issuer_class: 'artifact', bind: o.bind ?? 'action', ttl_ms: o.ttl_ms ?? 300_000, require };
}

/**
 * The unsigned discharge body an `artifact` verifier signs (with `signDischarge`) after a passing {@link provenanceGate}:
 * the request's binding and the gate's claims. Throws if the gate did not pass (no discharge without a verified provenance).
 */
export function provenanceDischargeBody(request: DischargeRequest, gate: ProvenanceGateResult, t: { iat: number; ttl_ms: number; nonce: string }): DischargeBody {
  if (!gate.ok) throw new Error(`provenanceDischargeBody: the provenance gate refused (${gate.code})`);
  if (t.ttl_ms > request.ttl_ms) throw new Error('provenanceDischargeBody: ttl_ms exceeds what the caveat accepts');
  return {
    v: 1,
    kind: 'pca-discharge',
    caveat_id: request.caveat_id,
    issuer: request.issuer,
    cap_hash: request.cap_hash,
    bind: request.bind,
    ...(request.action_digest !== undefined ? { action_digest: request.action_digest } : {}),
    claims: gate.claims as unknown as Record<string, WireScalar>,
    iat: t.iat,
    not_after: t.iat + t.ttl_ms,
    nonce: t.nonce,
  };
}
