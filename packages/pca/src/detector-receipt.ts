import { hashCanonical } from './hash';
import { artifactSuiteError, closedMembers, isBoundedString, isDigest, isPlainObject, isSafeInt, signArtifact, verifyArtifactSig, type PinnedSigner } from './intent-artifacts';
import type { ModelSignal } from './decision';
import type { SignerSuiteOpts } from './pq';

/**
 * DETECTOR RECEIPTS: guardrail products as tighten-only inputs (track K9; security contract C-527..C-531).
 *
 * A prompt-injection or data-leak detector (Lakera Guard, Prompt Security, a home-grown classifier) answers "this content
 * looks suspicious" or "I found nothing". PCA makes no detection claim and authorization never depends on one. The receipt
 * records what a PINNED detector gateway saw, bound to the exact content (`input_digest`) and optionally to a session:
 *
 *   `{v:1, kind:"pca-detector-receipt", detector, version, input_digest, verdict, categories, iat, session?, calibration_ref?, sig}`
 *   signed under domain `atlas-pca/detector-receipt/v1\0` (the W-B artifact rules: suite members `alg`/`pq_pk`/`pq_sig`).
 *
 * The one rule: `suspicious` may lower a decision, `no_finding` is exactly equivalent to no receipt at all. There is no
 * "detector required" switch, because requiring a `no_finding` would let a clean scan (or a bypassed detector) buy back
 * authority the policy withheld. {@link detectorSignal} returns a {@link ModelSignal} to fold with `tighten()` and an
 * `env.detect` object for `tighten[]` rules; `env.detect.*` is a model-derived root (rule 21), so a grant's `where` can
 * never read it. A receipt that fails verification (unknown detector, unpinned key, bad signature, other content, other
 * session, stale, from the future) is not evidence of anything: it raises `escalate` (a tighten), never `ok`.
 */

export const DETECTOR_RECEIPT_DOMAIN = 'atlas-pca/detector-receipt/v1\0';
export const DETECTOR_RECEIPT_REF_DOMAIN = 'atlas-pca/detector-receipt-ref/v1';
export const DETECTOR_VERDICTS = ['suspicious', 'no_finding'] as const;
export const MAX_DETECTOR_RECEIPTS = 32;
const ID_RE = /^[a-z][a-z0-9_]{0,63}$/;

export interface DetectorReceiptBody {
  v: 1;
  kind: 'pca-detector-receipt';
  /** Policy id of the detector (`^[a-z][a-z0-9_]{0,63}$`). */
  detector: string;
  /** Vendor model / ruleset version, as reported (1..64 bytes). */
  version: string;
  /** b64u(sha256(strictCanonical(screened content))): {@link detectorInputDigest}. */
  input_digest: string;
  verdict: (typeof DETECTOR_VERDICTS)[number];
  /** Sorted, distinct category ids (0..8). Empty on `no_finding`. */
  categories: string[];
  /** Epoch ms. */
  iat: number;
  /** b64u 32-byte session id the screening belongs to. */
  session?: string;
  /** What the detector's miss rate was measured against (a dataset or report reference), 1..256 bytes. Informational. */
  calibration_ref?: string;
  alg?: string;
  pq_pk?: string;
}
export type DetectorReceipt = DetectorReceiptBody & { sig: string; pq_sig?: string };

/** The digest a receipt binds: b64u(sha256(strictCanonical({d, content}))). Any JSON value (strings for text). */
export function detectorInputDigest(content: unknown): string {
  return hashCanonical({ d: 'atlas-pca/detector-input/v1', content });
}

/** Content address of a receipt (signature included). */
export function detectorReceiptRef(r: unknown): string {
  return hashCanonical({ d: DETECTOR_RECEIPT_REF_DOMAIN, receipt: r });
}

/** Null when well-formed. */
export function detectorReceiptShapeError(r: unknown): string | null {
  if (!isPlainObject(r)) return 'receipt must be an object';
  const e = closedMembers(r, ['v', 'kind', 'detector', 'version', 'input_digest', 'verdict', 'categories', 'iat', 'sig'], ['session', 'calibration_ref', 'alg', 'pq_pk', 'pq_sig'], 'receipt');
  if (e) return e;
  if (r.v !== 1 || r.kind !== 'pca-detector-receipt') return 'not a pca-detector-receipt v1';
  if (typeof r.detector !== 'string' || !ID_RE.test(r.detector)) return 'detector id is malformed';
  if (!isBoundedString(r.version, 64)) return 'version must be 1..64 bytes';
  if (!isDigest(r.input_digest)) return 'input_digest must be a b64u 32-byte digest';
  if (!(DETECTOR_VERDICTS as readonly unknown[]).includes(r.verdict)) return "verdict must be 'suspicious' or 'no_finding'";
  const c = r.categories;
  if (!Array.isArray(c) || c.length > 8 || !c.every((x) => typeof x === 'string' && ID_RE.test(x))) return 'categories must be 0..8 ids';
  for (let i = 1; i < c.length; i++) if (!((c[i - 1] as string) < (c[i] as string))) return 'categories must be sorted and distinct';
  if (r.verdict === 'no_finding' && c.length > 0) return 'a no_finding receipt carries no categories';
  if (!(isSafeInt(r.iat) && r.iat >= 0)) return 'iat must be a non-negative integer';
  if (r.session !== undefined && !isDigest(r.session)) return 'session must be a b64u 32-byte id';
  if (r.calibration_ref !== undefined && !isBoundedString(r.calibration_ref, 256)) return 'calibration_ref must be 1..256 bytes';
  if (typeof r.sig !== 'string') return 'sig must be a string';
  return artifactSuiteError(r);
}

/** Sign a receipt (the detector gateway's key). Throws on a malformed body. */
export function signDetectorReceipt(body: DetectorReceiptBody, secretKey: Uint8Array, suite?: SignerSuiteOpts): DetectorReceipt {
  const signed = signArtifact(DETECTOR_RECEIPT_DOMAIN, body as unknown as Record<string, unknown>, secretKey, suite) as unknown as DetectorReceipt;
  const e = detectorReceiptShapeError(signed);
  if (e) throw new Error(`signDetectorReceipt: ${e}`);
  return signed;
}

/** One detector the verifier trusts. */
export interface DetectorPolicyEntry {
  id: string;
  /** Pinned gateway keys (1..8). */
  keys: PinnedSigner[];
  /** What a valid `suspicious` receipt does. */
  on_suspicious: 'escalate' | 'deny';
  /** When given, only these categories act (others are recorded, no signal). An empty category list on a suspicious receipt always acts. */
  categories?: string[];
  /** Receipts older than this are stale (ms, 1..86 400 000). */
  max_age_ms: number;
}
export interface DetectorPolicy {
  detectors: DetectorPolicyEntry[];
}

/** Null when well-formed. */
export function detectorPolicyError(p: unknown): string | null {
  if (!isPlainObject(p) || closedMembers(p, ['detectors']) !== null) return 'policy must be {detectors}';
  if (!Array.isArray(p.detectors) || p.detectors.length > 16) return 'detectors must hold at most 16 entries';
  const ids = new Set<string>();
  for (const d of p.detectors) {
    if (!isPlainObject(d) || closedMembers(d, ['id', 'keys', 'on_suspicious', 'max_age_ms'], ['categories']) !== null) return 'detector entry is malformed';
    if (typeof d.id !== 'string' || !ID_RE.test(d.id) || d.id === 'invalid' || ids.has(d.id)) return 'detector ids must be distinct ids other than "invalid"';
    ids.add(d.id);
    if (!Array.isArray(d.keys) || d.keys.length < 1 || d.keys.length > 8 || !d.keys.every((k) => isPlainObject(k) && typeof k.pk === 'string' && (k.pq_pk === undefined || typeof k.pq_pk === 'string'))) return `detector '${d.id}': keys must hold 1..8 pins`;
    if (d.on_suspicious !== 'escalate' && d.on_suspicious !== 'deny') return `detector '${d.id}': on_suspicious must be escalate or deny`;
    if (d.categories !== undefined && !(Array.isArray(d.categories) && d.categories.length >= 1 && d.categories.every((c) => typeof c === 'string' && ID_RE.test(c)))) return `detector '${d.id}': categories must be 1+ ids`;
    if (!(isSafeInt(d.max_age_ms) && d.max_age_ms >= 1 && d.max_age_ms <= 86_400_000)) return `detector '${d.id}': max_age_ms must be 1..86400000`;
  }
  return null;
}

export interface DetectorInput {
  receipts?: readonly unknown[];
  policy: DetectorPolicy;
  /** Digests ({@link detectorInputDigest}) of the content this action carries; a receipt about anything else is not about this action. */
  input_digests: readonly string[];
  /** The session the action belongs to, when receipts are session-bound. */
  session?: string;
  now: number;
}

export interface DetectorOutcome {
  /** `ok` (no friction), `escalate` or `deny`. Never anything that raises a decision: fold with `tighten(decision, signal)`. */
  signal: ModelSignal;
  /** For `tighten[]` rules: `{ <detector id>: boolean (flagged) for every declared detector, invalid: <count> }`. */
  env: { detect: Record<string, boolean | number> };
  /** Detector ids whose valid suspicious receipt acted, sorted. */
  flagged: string[];
  /** Why each receipt was not used (index -> reason). */
  rejected: { index: number; reason: string }[];
}

const RANK: Record<ModelSignal, number> = { ok: 2, escalate: 1, deny: 0 };

/**
 * The tighten-only fold of detector receipts. Total. A malformed policy is `deny`. For each receipt: shape, declared
 * detector, a pinned key's signature, content in `input_digests`, session (when the receipt has one it must equal
 * `session`), `iat <= now`, age `<= max_age_ms`. A valid `suspicious` with an acting category lowers the signal to the
 * detector's `on_suspicious`; a valid `no_finding` does nothing; an invalid receipt lowers it to `escalate`.
 * By construction the outcome with any set of receipts is at most the outcome with none, and adding valid `no_finding`
 * receipts never changes it.
 */
export function detectorSignal(input: DetectorInput): DetectorOutcome {
  const flaggedSet = new Set<string>();
  const rejected: { index: number; reason: string }[] = [];
  let signal: ModelSignal = 'ok';
  const lower = (s: ModelSignal) => {
    if (RANK[s] < RANK[signal]) signal = s;
  };
  const env: Record<string, boolean | number> = Object.create(null);
  try {
    const pe = detectorPolicyError(input?.policy);
    if (pe) return { signal: 'deny', env: { detect: { invalid: 0 } }, flagged: [], rejected: [{ index: -1, reason: `policy: ${pe}` }] };
    for (const d of input.policy.detectors) env[d.id] = false;
    const receipts = input.receipts ?? [];
    const digests = Array.isArray(input.input_digests) ? input.input_digests : [];
    const now = input.now;
    if (!Array.isArray(receipts) || receipts.length > MAX_DETECTOR_RECEIPTS || !isSafeInt(now)) {
      lower('escalate');
      rejected.push({ index: -1, reason: 'receipt list or clock malformed' });
    } else {
      receipts.forEach((r, index) => {
        const why = receiptProblem(r, input.policy, digests, input.session, now);
        if (why) {
          rejected.push({ index, reason: why });
          lower('escalate');
          return;
        }
        const rc = r as DetectorReceipt;
        if (rc.verdict !== 'suspicious') return;
        const d = input.policy.detectors.find((x) => x.id === rc.detector)!;
        if (d.categories !== undefined && rc.categories.length > 0 && !rc.categories.some((c) => d.categories!.includes(c))) return;
        flaggedSet.add(d.id);
        env[d.id] = true;
        lower(d.on_suspicious);
      });
    }
  } catch (e) {
    lower('deny');
    rejected.push({ index: -1, reason: `evaluation error (fail closed): ${e instanceof Error ? e.message : 'unknown'}` });
  }
  env.invalid = rejected.length;
  return { signal, env: { detect: env }, flagged: [...flaggedSet].sort(), rejected };
}

function receiptProblem(r: unknown, policy: DetectorPolicy, digests: readonly string[], session: string | undefined, now: number): string | null {
  const se = detectorReceiptShapeError(r);
  if (se) return `malformed: ${se}`;
  const rc = r as DetectorReceipt;
  const d = policy.detectors.find((x) => x.id === rc.detector);
  if (!d) return `undeclared detector '${rc.detector}'`;
  if (!d.keys.some((k) => verifyArtifactSig(DETECTOR_RECEIPT_DOMAIN, rc as unknown as Record<string, unknown>, k))) return `detector '${d.id}': no pinned key signed it`;
  if (!digests.includes(rc.input_digest)) return `detector '${d.id}': the receipt is about other content`;
  if (rc.session !== undefined && rc.session !== session) return `detector '${d.id}': bound to another session`;
  if (rc.iat > now) return `detector '${d.id}': from the future`;
  if (now - rc.iat > d.max_age_ms) return `detector '${d.id}': stale`;
  return null;
}
