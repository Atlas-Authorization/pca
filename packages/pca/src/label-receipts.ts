import { compareUtf8 } from './hash';
import {
  artifactRef,
  artifactSuiteError,
  closedMembers,
  DATA_CLASS_RE,
  isBoundedString,
  isDigest,
  isPlainObject,
  isSafeInt,
  pinPqOk,
  signArtifact,
  SUITE_MEMBERS,
  verifyArtifactSig,
} from './intent-artifacts';
import type { SignerSuiteOpts } from './pq';

/**
 * READ-SIDE INTENT AND PURPOSE LIMITATION (Intent Layer v2 §3.16, milestone V14; label refs are checked inside
 * NORMATIVE conformance rule 17, see `param-provenance.ts`).
 *
 * 1. READ CELLS. A schema read verb declares `returns.classes` (field path → data class). A read is the cell
 *    (verb, data class, purpose), where purpose is a closed per-session enum derived from the statement (`booking`,
 *    `support`, `comparison`). {@link decideReadPurpose}: a returned class the purpose does not cover is
 *    MINIMISED (the site drops the field) when the field is optional, otherwise it is a question (`intent_required`)
 *    or a deny, per site policy.
 * 2. LABEL RECEIPTS. For a Tier 2+ read the site returns a site-signed `pca-labels` receipt (header `PCA-Labels`):
 *      v: 1, kind: "pca-labels", site (<= 256 B), session (b64u 32), response_digest (b64u 32),
 *      fields: { <field path>: { class (data class), value_digest (b64u 32) } }  (1..64 fields),
 *      issued_at (safe integer >= 0), kid (<= 64 B), sig (b64u 64 B).
 *    Signature domain `atlas-pca/labels/v1\0` under the key the verifier PINS for (site, kid); reference domain
 *    `atlas-pca/labels-ref/v1`, slot `l`. `value_digest` = base64url(sha256(strictCanonical(value))) of the field's
 *    value. It is what lets a sink check that the value an action carries IS the labelled value: the receipt alone
 *    binds only the response.
 * 3. FLOW RULES. allowed(class) is a set of sink audiences from the session root (`flows`: pattern → audiences;
 *    pattern = an exact class, `prefix.*`, or `*`; the MOST SPECIFIC matching pattern decides: exact > longest
 *    prefix > `*`). {@link flowAllowed}: a labelled value may always go back to the site that labelled it; a `public`
 *    value may go anywhere; otherwise the most specific rule must list the sink audience; no rule = denied.
 *
 * THE HONEST GAP (§3.16 item 4, T27). A malicious agent can omit the receipt; the value then arrives with `agent`
 * provenance and no class, and only a classifier dimension (statistical, §3.7) can catch it. Purpose limitation is
 * provable only with an attested dataflow mediator. Without one this is a DECLARED-flow check.
 */

export const LABELS_DOMAIN = 'atlas-pca/labels/v1\0';
export const LABELS_REF_DOMAIN = 'atlas-pca/labels-ref/v1';
export const MAX_LABEL_FIELDS = 64;
export const PUBLIC_CLASS = 'public';

export interface LabelField {
  class: string;
  value_digest: string;
}

export interface PcaLabels {
  v: 1;
  kind: 'pca-labels';
  site: string;
  session: string;
  response_digest: string;
  fields: Record<string, LabelField>;
  issued_at: number;
  kid: string;
  alg?: string;
  pq_pk?: string;
  sig: string;
  pq_sig?: string;
}

/** A pinned receipt signer. */
export interface LabelKey {
  site: string;
  kid: string;
  pk: string;
  /** The PQ key a post-quantum or hybrid receipt from this signer must carry. */
  pq_pk?: string;
}

/** Is `k` a well-formed pinned label key? */
export const isLabelKey = (k: unknown): boolean =>
  isPlainObject(k) && closedMembers(k, ['site', 'kid', 'pk'], ['pq_pk'], 'label_key') === null && isBoundedString(k.site, 256) && isBoundedString(k.kid, 64) && isDigest(k.pk) && pinPqOk(k.pq_pk);

/** Wire validation of a label receipt. Null = well-formed. */
export function validateLabelsWire(l: unknown): string | null {
  if (!isPlainObject(l)) return 'label receipt must be an object';
  const m = closedMembers(l, ['v', 'kind', 'site', 'session', 'response_digest', 'fields', 'issued_at', 'kid', 'sig'], SUITE_MEMBERS, 'labels');
  if (m) return m;
  if (l.v !== 1 || l.kind !== 'pca-labels') return 'label receipt must be {v: 1, kind: "pca-labels"}';
  if (!isBoundedString(l.site, 256)) return "'labels.site' must be a non-empty string (<= 256 bytes)";
  if (!isDigest(l.session)) return "'labels.session' must be canonical base64url (32 bytes)";
  if (!isDigest(l.response_digest)) return "'labels.response_digest' must be canonical base64url (32 bytes)";
  if (!isPlainObject(l.fields)) return "'labels.fields' must be an object";
  const keys = Object.keys(l.fields);
  if (keys.length === 0 || keys.length > MAX_LABEL_FIELDS) return `'labels.fields' must hold 1..${MAX_LABEL_FIELDS} fields`;
  for (const k of keys) {
    const f = l.fields[k];
    if (!isBoundedString(k, 256)) return 'label field paths must be non-empty strings (<= 256 bytes)';
    if (!isPlainObject(f) || closedMembers(f, ['class', 'value_digest']) !== null) return `label field '${k}' must be exactly {class, value_digest}`;
    if (typeof f.class !== 'string' || f.class.length > 128 || !DATA_CLASS_RE.test(f.class)) return `label field '${k}': invalid data class`;
    if (!isDigest(f.value_digest)) return `label field '${k}': value_digest must be canonical base64url (32 bytes)`;
  }
  if (!isSafeInt(l.issued_at) || l.issued_at < 0) return "'labels.issued_at' must be a non-negative safe integer";
  if (!isBoundedString(l.kid, 64)) return "'labels.kid' must be a non-empty string (<= 64 bytes)";
  if (typeof l.sig !== 'string') return "'labels.sig' must be a string";
  return null;
}

/** Sign a label receipt (site side). */
export function signLabels(body: Omit<PcaLabels, 'v' | 'kind' | 'sig' | 'alg' | 'pq_pk' | 'pq_sig'>, secretKey: Uint8Array, suite?: SignerSuiteOpts): PcaLabels {
  return signArtifact(LABELS_DOMAIN, { v: 1, kind: 'pca-labels', ...body }, secretKey, suite) as unknown as PcaLabels;
}

/** The content address committed in `intent_session.labels[]` and named by `pca-labels:<ref>#<field>` provenance refs. */
export function labelsRef(l: PcaLabels): string {
  return artifactRef(LABELS_REF_DOMAIN, 'l', l);
}

/** Verify a receipt's wire shape, suite and signature under the signer pinned for (site, kid). Null = valid. Total. */
export function verifyLabels(l: unknown, keys: readonly LabelKey[]): string | null {
  const w = validateLabelsWire(l);
  if (w) return w;
  if (!Array.isArray(keys)) return 'label keys must be an array';
  const r = l as PcaLabels;
  const se = artifactSuiteError(r as unknown as Record<string, unknown>);
  if (se) return `signature suite: ${se}`;
  const key = keys.find((k) => isPlainObject(k) && k.site === r.site && k.kid === r.kid);
  if (!key) return `no pinned label key for site '${r.site}' kid '${r.kid}'`;
  return verifyArtifactSig(LABELS_DOMAIN, r as unknown as Record<string, unknown>, key) ? null : 'bad label receipt signature';
}

/** Flow rules: class pattern → sink audiences. */
export type FlowRules = Record<string, string[]>;

/** Most specific matching flow pattern for a class (exact > longest `prefix.*` > `*`), or undefined. */
export function flowRuleFor(rules: FlowRules, cls: string): string | undefined {
  if (!isPlainObject(rules) || typeof cls !== 'string') return undefined;
  if (Object.prototype.hasOwnProperty.call(rules, cls)) return cls;
  let best: string | undefined;
  for (const p of Object.keys(rules)) {
    if (!p.endsWith('.*')) continue;
    const prefix = p.slice(0, -1); // keeps the dot: 'pii.' matches 'pii.contact', never 'piix'
    if (cls.startsWith(prefix) && (best === undefined || p.length > best.length)) best = p;
  }
  if (best !== undefined) return best;
  return Object.prototype.hasOwnProperty.call(rules, '*') ? '*' : undefined;
}

/**
 * May a value of class `cls`, labelled by `origin`, reach the sink audience `aud`? Back to its origin: yes.
 * `public`: yes. Otherwise the most specific flow rule must list `aud`; no matching rule: no.
 */
export function flowAllowed(rules: FlowRules, cls: string, origin: string, aud: string): boolean {
  if (typeof cls !== 'string' || typeof origin !== 'string' || typeof aud !== 'string') return false;
  if (aud === origin || cls === PUBLIC_CLASS) return true;
  const p = flowRuleFor(rules, cls);
  if (p === undefined) return false;
  const sinks = rules[p];
  return Array.isArray(sinks) && sinks.includes(aud);
}

/** Validate a flow rule set. Null = well-formed. */
export function validateFlowRules(rules: unknown): string | null {
  if (!isPlainObject(rules)) return 'flows must be an object';
  for (const [p, sinks] of Object.entries(rules)) {
    const base = p === '*' ? 'x' : p.endsWith('.*') ? p.slice(0, -2) : p;
    if (!DATA_CLASS_RE.test(base)) return `flow pattern '${p}' is not a class, a 'prefix.*' or '*'`;
    if (!Array.isArray(sinks) || sinks.some((s) => !isBoundedString(s, 256))) return `flow pattern '${p}' needs a list of audiences`;
  }
  return null;
}

// ---- read side: purpose limitation -----------------------------------------------------------------

/** Which data classes each purpose covers (patterns as for flows: exact, `prefix.*`, `*`). */
export type PurposeCoverage = Record<string, string[]>;

export interface ReadField {
  path: string;
  class: string;
  /** The site can drop this field without breaking the read (field-level minimisation). */
  optional?: boolean;
}

export type ReadPurposeDecision = {
  /** allow: every returned class is covered (after minimisation); question / deny: some required field is not. */
  outcome: 'allow' | 'question' | 'deny';
  /** Fields the site must drop (optional and not covered). */
  minimise: string[];
  /** Required fields whose class the purpose does not cover. */
  uncovered: string[];
};

const classCovered = (patterns: readonly string[], cls: string): boolean =>
  cls === PUBLIC_CLASS || patterns.some((p) => p === '*' || p === cls || (p.endsWith('.*') && cls.startsWith(p.slice(0, -1))));

/**
 * Read cell decision (§3.16 item 1; conformance `primitives.intent_read_purpose`): the read verb returns `fields`; the
 * session purpose covers some classes (`coverage[purpose]`, an OWN member; patterns: a class, `p.*`, `*`; `public` is
 * always covered). Optional uncovered fields are minimised; required uncovered fields make the read a question
 * (`onUncovered: 'question'`, the default) or a deny. An unknown purpose covers nothing but `public`. Both output lists
 * are de-duplicated and sorted in UTF-8 BYTE order (the canonical-ordering rule: never UTF-16 code-unit order).
 * Malformed input (fields not an array of `{path: string, class: string, optional?: boolean}`, a non-string purpose, a
 * coverage that is not an object of string arrays, an unknown onUncovered; JSON null included) is `deny` with empty
 * lists. Never throws.
 */
export function decideReadPurpose(fields: readonly ReadField[], purpose: string, coverage: PurposeCoverage, onUncovered: 'question' | 'deny' = 'question'): ReadPurposeDecision {
  const malformed: ReadPurposeDecision = { outcome: 'deny', minimise: [], uncovered: [] };
  if (!Array.isArray(fields) || typeof purpose !== 'string' || !isPlainObject(coverage) || (onUncovered !== 'question' && onUncovered !== 'deny')) return malformed;
  for (const pats of Object.values(coverage)) if (!Array.isArray(pats) || pats.some((x) => typeof x !== 'string')) return malformed;
  for (const f of fields as unknown[]) {
    if (!isPlainObject(f) || typeof f.path !== 'string' || typeof f.class !== 'string' || (f.optional !== undefined && typeof f.optional !== 'boolean')) return malformed;
  }
  const patterns = Object.prototype.hasOwnProperty.call(coverage, purpose) ? coverage[purpose]! : [];
  const minimise = new Set<string>();
  const uncovered = new Set<string>();
  for (const f of fields) {
    if (classCovered(patterns, f.class)) continue;
    (f.optional === true ? minimise : uncovered).add(f.path);
  }
  const sorted = (xs: Set<string>) => [...xs].sort(compareUtf8);
  return { outcome: uncovered.size ? onUncovered : 'allow', minimise: sorted(minimise), uncovered: sorted(uncovered) };
}
