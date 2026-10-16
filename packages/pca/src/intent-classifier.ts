import { b64u, hashCanonical } from './hash';
import { publicKeyOf } from './keys';
import {
  artifactRef,
  artifactSuiteError,
  closedMembers,
  INTENT_NAME_RE,
  isBoundedString,
  isDigest,
  isParamPath,
  isPlainObject,
  isSafeInt,
  nullRecord,
  ownGet,
  resolveParamPath,
  signArtifact,
  SUITE_MEMBERS,
  verifyArtifactSig,
} from './intent-artifacts';
import { verifyJudgeAttestation, type JudgeAttestationCheck } from './semantic-threshold';
import type { HardwareAttestationResult } from './attestation';
import type { AgentBinding } from './envelope';
import type { SignerSuiteOpts } from './pq';

/**
 * CLASSIFIER-DERIVED DIMENSIONS (Intent Layer v2 §2.7, §3.7, milestone V8; NORMATIVE conformance rule 18,
 * `primitives.intent_classifier`).
 *
 * A material `text.*` parameter (a message to a customer, a review reply) gets one categorical dimension per declared
 * classifier: `env.class.<id>` ∈ L_id (tone ∈ {neutral, apologetic, hostile, other}, data class ∈ {public, internal,
 * pii, secret}). A classifier runs attested, like a B3 judge (`semantic-threshold.ts`), and signs a verdict bound to
 * the content digest and to the session, so a verdict cannot be replayed onto other content or another session.
 * Verdicts are checked against an allowlist of classifier keys (one key, one vote) and combined k-of-n; the agent
 * commits their references in `intent_session.classes`.
 *
 * WIRE `pca-intent-classification` v1 (the B3 verdict conventions under a new domain; closed member set):
 *   v: 1, kind: "pca-intent-classification", classifier (id, `^[a-z][a-z0-9_]{0,63}$`), session (b64u 32),
 *   content_digest (b64u 32) = base64url(sha256(strictCanonical(value of the classified parameter))),
 *   label (string <= 64 B), measurement (string <= 256 B: the classifier model / enclave measurement),
 *   judge (b64u 32: the classifier's Ed25519 public key), sig (b64u 64 B).
 * Signature domain `atlas-pca/intent-classifier/v1\0` over strictCanonical(verdict without sig), verified under
 * `judge`, which must be ON THE ALLOWLIST of that classifier (an off-list key proves nothing). Reference domain
 * `atlas-pca/intent-classifier-ref/v1`, slot `c`.
 *
 * WHAT IS NOT CLAIMED (§3.7). The agent writes the content and can search for inputs the classifier mislabels. The
 * calibration bound (T20, pca-intent `classifier.ts`) holds for exchangeable, non-adaptive content only.
 */

export const INTENT_CLASSIFIER_DOMAIN = 'atlas-pca/intent-classifier/v1\0';
export const INTENT_CLASSIFIER_REF_DOMAIN = 'atlas-pca/intent-classifier-ref/v1';
export const MAX_COMMITTED_CLASSES = 8;
export const MAX_CLASSIFIER_LABELS = 32;

export interface ClassifierVerdict {
  v: 1;
  kind: 'pca-intent-classification';
  classifier: string;
  session: string;
  content_digest: string;
  label: string;
  measurement: string;
  judge: string;
  alg?: string;
  pq_pk?: string;
  sig: string;
  pq_sig?: string;
}

export interface ClassifierPolicy {
  id: string;
  /** The `action.params.*` path of the classified content. */
  param: string;
  /** L_id: the closed label set. */
  labels: string[];
  /** Allowlisted classifier keys (b64u Ed25519). */
  keys: string[];
  /** Quorum: distinct allowlisted keys that must agree on one label. */
  k: number;
  /** When present, a verdict's `measurement` must be one of these. */
  measurements?: string[];
  /** PQ keys pinned per allowlisted key (`{judge key: pq_pk}`): a post-quantum or hybrid verdict must carry its pin. */
  pq_keys?: Record<string, string>;
}

export interface ClassifierInput {
  session: string;
  action: { params?: Record<string, unknown> };
  /** `intent_session.classes` (absent = []). */
  committed?: unknown;
  verdicts?: unknown[];
  policy: { classifiers: ClassifierPolicy[] };
}

export type ClassifierDecision =
  | { ok: true; classes: Record<string, string>; votes: Record<string, Record<string, number>> }
  | { ok: false; reason: string };

/** Wire validation of a classifier verdict. Null = well-formed. */
export function validateClassifierVerdictWire(v: unknown): string | null {
  if (!isPlainObject(v)) return 'verdict must be an object';
  const m = closedMembers(v, ['v', 'kind', 'classifier', 'session', 'content_digest', 'label', 'measurement', 'judge', 'sig'], SUITE_MEMBERS, 'verdict');
  if (m) return m;
  if (v.v !== 1 || v.kind !== 'pca-intent-classification') return 'verdict must be {v: 1, kind: "pca-intent-classification"}';
  if (typeof v.classifier !== 'string' || !INTENT_NAME_RE.test(v.classifier)) return "'verdict.classifier' must match ^[a-z][a-z0-9_]{0,63}$";
  if (!isDigest(v.session)) return "'verdict.session' must be canonical base64url (32 bytes)";
  if (!isDigest(v.content_digest)) return "'verdict.content_digest' must be canonical base64url (32 bytes)";
  if (!isBoundedString(v.label, 64)) return "'verdict.label' must be a non-empty string (<= 64 bytes)";
  if (typeof v.measurement !== 'string' || !isBoundedString(v.measurement, 256)) return "'verdict.measurement' must be a non-empty string (<= 256 bytes)";
  if (!isDigest(v.judge)) return "'verdict.judge' must be canonical base64url (32 bytes)";
  if (typeof v.sig !== 'string') return "'verdict.sig' must be a string";
  return null;
}

/** The content digest a verdict binds: b64u(sha256(strictCanonical(value))). */
export function classifierContentDigest(value: unknown): string {
  return hashCanonical(value);
}

/** Sign a verdict (classifier side); `judge` is derived from the secret key. */
export function signClassifierVerdict(
  body: Omit<ClassifierVerdict, 'v' | 'kind' | 'judge' | 'sig' | 'alg' | 'pq_pk' | 'pq_sig'>,
  secretKey: Uint8Array,
  suite?: SignerSuiteOpts,
): ClassifierVerdict {
  return signArtifact(INTENT_CLASSIFIER_DOMAIN, { v: 1, kind: 'pca-intent-classification', ...body, judge: b64u(publicKeyOf(secretKey)) }, secretKey, suite) as unknown as ClassifierVerdict;
}

/** The content address committed in `intent_session.classes[]`. */
export function classifierVerdictRef(v: ClassifierVerdict): string {
  return artifactRef(INTENT_CLASSIFIER_REF_DOMAIN, 'c', v);
}

/** Policy sanity (rule 18 step 0). Null = well-formed. */
export function validateClassifierPolicy(p: { classifiers: ClassifierPolicy[] }): string | null {
  if (!isPlainObject(p) || !Array.isArray(p.classifiers)) return 'classifier policy needs a classifiers list';
  const cm = closedMembers(p, ['classifiers'], [], 'policy');
  if (cm) return cm;
  const ids = new Set<string>();
  for (const c of p.classifiers) {
    if (!isPlainObject(c) || closedMembers(c, ['id', 'param', 'labels', 'keys', 'k'], ['measurements', 'pq_keys'], 'classifier') !== null) return 'every classifier is exactly {id, param, labels, keys, k, measurements?, pq_keys?}';
    if (typeof c.id !== 'string' || !INTENT_NAME_RE.test(c.id) || ids.has(c.id)) return 'every classifier needs a unique id matching ^[a-z][a-z0-9_]{0,63}$';
    ids.add(c.id);
    if (!isParamPath(c.param)) return `classifier '${c.id}': param must be an action.params path`;
    if (!Array.isArray(c.labels) || c.labels.length === 0 || c.labels.length > MAX_CLASSIFIER_LABELS) return `classifier '${c.id}': labels must hold 1..${MAX_CLASSIFIER_LABELS} strings`;
    if (c.labels.some((l) => !isBoundedString(l, 64)) || new Set(c.labels).size !== c.labels.length) return `classifier '${c.id}': labels must be distinct non-empty strings`;
    if (!Array.isArray(c.keys) || c.keys.length === 0 || c.keys.some((k) => !isDigest(k)) || new Set(c.keys).size !== c.keys.length) return `classifier '${c.id}': keys must be distinct 32-byte keys`;
    if (!isSafeInt(c.k) || c.k < 1 || c.k > c.keys.length) return `classifier '${c.id}': k must be an integer in [1, ${c.keys.length}]`;
    if (c.measurements !== undefined && (!Array.isArray(c.measurements) || c.measurements.some((m) => typeof m !== 'string'))) return `classifier '${c.id}': measurements must be a list of strings`;
    if (c.pq_keys !== undefined && (!isPlainObject(c.pq_keys) || Object.entries(c.pq_keys).some(([k, v]) => !c.keys.includes(k) || typeof v !== 'string' || v.length === 0))) return `classifier '${c.id}': pq_keys must map allowlisted keys to PQ keys`;
  }
  return null;
}

/** Is the rule-18 check active? Iff `committed` or `policy.classifiers` is a non-empty ARRAY (strict: an object with a `length` member is not). */
export function classifierCheckActive(input: Pick<ClassifierInput, 'committed' | 'policy'>): boolean {
  if (!isPlainObject(input)) return false; // total: a non-object input has no members
  const nonEmpty = (x: unknown) => Array.isArray(x) && x.length > 0;
  return nonEmpty(input.committed) || nonEmpty(input.policy?.classifiers);
}

/**
 * NORMATIVE rule 18 (`classes`): compute `env.class`. First failure wins:
 *   0. policy sanity ({@link validateClassifierPolicy}); ABSENT optional members are empty / default, PRESENT ones of
 *      the wrong JSON type (`null` included) fail: `committed`, `verdicts`, `action.params`, `measurements`, `pq_keys`;
 *   1. `committed` (absent = []) is a list of at most 8 distinct canonical 32-byte digests;
 *   2. every committed digest is the reference of a supplied, well-formed verdict;
 *   3. per committed verdict in committed order: its suite members (`unsupported_suite` for a suite this verifier does
 *      not implement); its classifier is declared; its `judge` is on that classifier's
 *      allowlist; the signature verifies under `judge`; `session` matches; the classified parameter exists and
 *      `content_digest` equals its digest; `label` ∈ L; `measurement` ∈ measurements when pinned; no second verdict
 *      from the same (classifier, judge);
 *   4. per declared classifier in policy order: exactly one label has at least k distinct-judge votes (none: no
 *      quorum, the ⊠ cell; two or more: ambiguous). env.class.<id> = that label.
 * Never throws.
 */
export function decideClassifierDimensions(input: ClassifierInput): ClassifierDecision {
  const fail = (reason: string): ClassifierDecision => ({ ok: false, reason: `classes: ${reason}` });
  try {
    if (!isPlainObject(input)) return fail('input must be an object');
    const pe = validateClassifierPolicy(input.policy);
    if (pe) return fail(`policy misconfigured (fail closed): ${pe}`);
    // ABSENT optional members mean empty / default; PRESENT ones of the wrong JSON type (null included) fail.
    const committed = input.committed === undefined ? [] : input.committed;
    if (!Array.isArray(committed) || committed.length > MAX_COMMITTED_CLASSES) return fail(`committed verdicts must be a list of at most ${MAX_COMMITTED_CLASSES} digests`);
    const seen = new Set<string>();
    for (const d of committed) {
      if (!isDigest(d) || seen.has(d)) return fail('committed verdicts must be distinct canonical 32-byte digests');
      seen.add(d);
    }
    const supplied = input.verdicts === undefined ? [] : input.verdicts;
    if (!Array.isArray(supplied)) return fail('verdicts must be an array');
    if (!isPlainObject(input.action)) return fail('action must be an object');
    const params = input.action.params === undefined ? {} : input.action.params;
    if (!isPlainObject(params)) return fail('action.params must be an object');
    const byRef = new Map<string, ClassifierVerdict>();
    for (const v of supplied) {
      if (validateClassifierVerdictWire(v) !== null) continue;
      try {
        byRef.set(classifierVerdictRef(v as ClassifierVerdict), v as ClassifierVerdict);
      } catch {
        /* not strictly canonical: no reference */
      }
    }
    // Tallies in Maps: a classifier id or label named like an Object.prototype member is an ordinary key.
    const votes = new Map<string, Map<string, number>>();
    const pairs = new Set<string>();
    for (const d of committed as string[]) {
      const v = byRef.get(d);
      if (!v) return fail('a committed verdict was not supplied (or is malformed)');
      const se = artifactSuiteError(v as unknown as Record<string, unknown>);
      if (se) return fail(`verdict signature suite: ${se}`);
      const c = input.policy.classifiers.find((x) => x.id === v.classifier);
      if (!c) return fail(`verdict for undeclared classifier '${v.classifier}'`);
      if (!c.keys.includes(v.judge)) return fail(`classifier '${c.id}': judge key is not on the allowlist`);
      const pq = c.pq_keys === undefined ? undefined : ownGet(c.pq_keys, v.judge);
      if (!verifyArtifactSig(INTENT_CLASSIFIER_DOMAIN, v as unknown as Record<string, unknown>, pq === undefined ? { pk: v.judge } : { pk: v.judge, pq_pk: pq })) return fail(`classifier '${c.id}': bad verdict signature`);
      if (v.session !== input.session) return fail(`classifier '${c.id}': verdict bound to another session`);
      const content = resolveParamPath(params, c.param);
      if (!content.found) return fail(`classifier '${c.id}': the action carries no '${c.param}'`);
      if (classifierContentDigest(content.value) !== v.content_digest) return fail(`classifier '${c.id}': verdict is about other content`);
      if (!c.labels.includes(v.label)) return fail(`classifier '${c.id}': label '${v.label}' is not in its label set`);
      if (c.measurements !== undefined && !c.measurements.includes(v.measurement)) return fail(`classifier '${c.id}': measurement is not pinned`);
      const pair = `${c.id}\u0000${v.judge}`;
      if (pairs.has(pair)) return fail(`classifier '${c.id}': two verdicts from one judge`);
      pairs.add(pair);
      let t = votes.get(c.id);
      if (!t) votes.set(c.id, (t = new Map()));
      t.set(v.label, (t.get(v.label) ?? 0) + 1);
    }
    const classes = nullRecord<string>();
    for (const c of input.policy.classifiers) {
      const t = votes.get(c.id) ?? new Map<string, number>();
      const winners = c.labels.filter((l) => (t.get(l) ?? 0) >= c.k);
      if (winners.length === 0) return fail(`classifier '${c.id}': no label reaches the quorum ${c.k}`);
      if (winners.length > 1) return fail(`classifier '${c.id}': ambiguous, ${winners.length} labels reach the quorum`);
      classes[c.id] = winners[0]!;
    }
    const voteOut = nullRecord<Record<string, number>>();
    for (const [id, t] of votes) {
      const r = nullRecord<number>();
      for (const [l, n] of t) r[l] = n;
      voteOut[id] = r;
    }
    return { ok: true, classes, votes: voteOut };
  } catch (e) {
    return fail(`evaluation error (fail closed): ${(e as Error).message}`);
  }
}

/**
 * TS-only attested-classifier gate (not part of rule 18): bind a verdict's signed `measurement` to a verified TEE
 * exactly as a B3 judge is bound (`verifyJudgeAttestation`). Use it to build the `measurements` pin set from live
 * attestations, or to drop verdicts whose enclave is not approved before calling {@link decideClassifierDimensions}.
 */
export function verifyClassifierAttestation(v: ClassifierVerdict, attestation: HardwareAttestationResult | undefined, approved?: AgentBinding): JudgeAttestationCheck {
  if (!isPlainObject(v)) return { ok: false, reason: 'verdict must be an object' };
  try {
    return verifyJudgeAttestation(v.measurement, attestation, approved);
  } catch (e) {
    return { ok: false, reason: `attestation check error (fail closed): ${e instanceof Error ? e.message : 'unknown'}` };
  }
}
