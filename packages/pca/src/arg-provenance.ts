import { randomBytes } from '@noble/hashes/utils';
import { b64u, canonicalizeStrict, compareUtf8, hashCanonical } from './hash';
import {
  artifactRef,
  artifactSuiteError,
  closedMembers,
  isBoundedString,
  isDigest,
  isPlainObject,
  isSafeInt,
  pinPqOk,
  publicKeyB64u,
  signArtifact,
  SUITE_MEMBERS,
  utf8Len,
  verifyArtifactSig,
} from './intent-artifacts';
import { suitePqPublicKey, type SignerSuiteOpts } from './pq';

/**
 * PROVENANCE BY DEFAULT: an agent cannot be steered by injected content into choosing who, where or how much.
 * Spec: docs/pca/specs/provenance-by-default.md (threat model, the guarantee and its one assumption, proof sketch).
 *
 * The model is CaMeL's (Debenedetti et al., "Defeating Prompt Injections by Design", arXiv:2503.18813): control flow and
 * the values that reach a sensitive sink must derive from the principal, never from tool output. Here the "interpreter" is
 * the agent's context window, so the unit of provenance is a SEGMENT of that context:
 *
 *   - a MEDIATOR (the agent harness, a gateway, an MCP server: whatever sees the bytes enter the context and holds a key the
 *     model cannot reach) appends one signed receipt per segment to a per-session hash chain: the principal's own message
 *     (`principal`), a tool result (`tool`), a retrieved document (`retrieval`), a fetched page (`web`), and finally the
 *     action the model chose (`action`, bound to the exact operation digest);
 *   - the verifier re-derives every label from that chain. Nothing the agent writes can lower a label: a receipt that does not
 *     verify under a pinned mediator key, a chain with a gap, or no chain at all leaves every value at `agent` (the top);
 *   - a value is TRUSTED when the context that produced it was purely principal, when it occurs verbatim (as a whole token) in a
 *     principal message whose bytes the receipt binds, or when the principal authorized the exact operation (a plan node);
 *   - the CHOICE of the action is trusted only when the context was purely principal or the principal committed to the step
 *     (an authorized plan, an admitted workflow step).
 *
 * An action is SENSITIVE unless its definition says it only reads (effects exactly `read`, traits within
 * {@link READ_SAFE_TRAITS}); an unknown action is sensitive. Every parameter of a sensitive action is a sink whose floor is
 * `first_party` unless the signed definition sets `provenance_min` (`tool` or `agent`) for it. A sensitive action whose choice or
 * any sink argument is not trusted is `escalate`: the principal must confirm it with a signed escalation answer (the existing
 * WYSIWYS machinery), and `allow` is never reached without one. A presented chain that is forged (bad signature under a pinned
 * key, a gap, content that does not hash to its receipt, a final receipt for another operation) is `deny`.
 *
 * Every function here is pure and total (no I/O, no clock); malformed input fails closed.
 */

export const PROV_RECEIPT_DOMAIN = 'atlas-pca/prov-receipt/v1\0';
export const PROV_RECEIPT_REF_DOMAIN = 'atlas-pca/prov-receipt-ref/v1';
export const PROV_ACTION_DOMAIN = 'atlas-pca/prov-action/v1';
/** Request header carrying a bundle (base64url of its JSON). The body member is `pca_provenance`. */
export const PROV_HEADER = 'PCA-Provenance';
export const MAX_PROV_RECEIPTS = 256;
/** Largest principal message a bundle may carry (UTF-8 bytes). */
export const MAX_PROV_CONTENT_BYTES = 65_536;
/** Leaves examined per parameter; a larger value is not examined and keeps the context label. */
export const MAX_PROV_LEAVES = 4096;
const MAX_DEPTH = 32;

export const PROV_ORIGINS = ['principal', 'tool', 'retrieval', 'web', 'action'] as const;
export type ProvOrigin = (typeof PROV_ORIGINS)[number];

/** The label lattice (the L4 taint lattice): trusted < first_party < tool < web < agent. */
export const PROV_LEVELS = ['trusted', 'first_party', 'tool', 'web', 'agent'] as const;
export type ProvLevel = (typeof PROV_LEVELS)[number];
const RANK: Readonly<Record<ProvLevel, number>> = { trusted: 0, first_party: 1, tool: 2, web: 3, agent: 4 };
const join = (a: ProvLevel, b: ProvLevel): ProvLevel => (RANK[a] >= RANK[b] ? a : b);
/** The level a segment of each origin carries (`action` contributes nothing: it is the model's own output). */
const ORIGIN_LEVEL: Readonly<Record<Exclude<ProvOrigin, 'action'>, ProvLevel>> = { principal: 'trusted', tool: 'tool', retrieval: 'tool', web: 'web' };

/** Per-parameter floors a signed action definition may declare (`provenance_min`). */
export type ProvFloor = 'first_party' | 'tool' | 'agent';
const FLOORS: readonly string[] = ['first_party', 'tool', 'agent'];

/** Traits a read-only action may carry and still be non-sensitive. Any other trait makes the action sensitive. */
export const READ_SAFE_TRAITS: readonly string[] = ['pca.financial_data_read', 'pca.pii_access', 'pca.regulated_data'];

// ---------------------------------------------------------------------------------------------------------------- wire

export interface ProvReceiptBody {
  v: 1;
  kind: 'pca-prov';
  /** Who labelled the segment (pinned by the verifier together with `kid`). */
  mediator: string;
  kid: string;
  /** b64u 32 bytes: one chain per agent session. */
  session: string;
  /** Position in the chain, 0-based, contiguous. */
  seq: number;
  /** `ref` of the previous receipt; null exactly for seq 0. */
  prev: string | null;
  origin: ProvOrigin;
  /** Tool name, URL, document id, `user`; for `action`, the verb. */
  source: string;
  /** hashCanonical(content) of the segment's text; for `action`, {@link provActionDigest} of the operation. */
  content_digest: string;
  issued_at: number;
}
export type ProvReceipt = ProvReceiptBody & { sig: string; alg?: string; pq_pk?: string; pq_sig?: string };

/** A pinned mediator key. */
export interface ProvMediatorPin {
  mediator: string;
  kid: string;
  pk: string;
  pq_pk?: string;
}

/** What the agent presents with the call (unsigned as a whole; every receipt in it is signed). */
export interface ProvenanceBundle {
  v: 1;
  kind: 'pca-provenance';
  /** The session's whole chain, seq 0 first; the last receipt is the `action` receipt of this operation. */
  receipts: ProvReceipt[];
  /** The text of principal segments, keyed by decimal seq (optional per segment: without it no verbatim match is possible). */
  contents?: Record<string, string>;
}

/** The facts about an action the gate needs (from the verifier's own action definitions; `@atlasauth/pca-actions` derives them). */
export interface ProvActionInfo {
  effects?: readonly string[];
  /** The effective trait closure. */
  traits?: readonly string[];
  /** Explicit, signed `provenance_min` per parameter. Absent = `first_party` for a sensitive action, `agent` otherwise. */
  params?: Readonly<Record<string, ProvFloor>>;
}

/** Untrusted content the SERVER itself saw reach this agent's context (raise-only). */
export interface ProvObservation {
  origin: 'tool' | 'retrieval' | 'web';
  source: string;
}

export interface ArgProvenanceInput {
  /** The presented bundle; undefined or null = none. */
  bundle?: unknown;
  operation: { verb: string; resource: string; params: Record<string, unknown> };
  /** Pinned mediator keys (the verifier's own, plus any the principal's grant names). */
  mediators: readonly ProvMediatorPin[];
  /** The action's definition facts; undefined = unknown action (sensitive). */
  action?: ProvActionInfo;
  /** The principal authorized this exact operation (a node of an executable, principal-authorized plan). */
  principalPlan?: boolean;
  /** The principal committed to this step (an admitted workflow step): the CHOICE is trusted, the values are not. */
  principalControl?: boolean;
  observed?: readonly ProvObservation[];
}

export type ArgProvenanceCode =
  | 'malformed_config'
  | 'malformed_operation'
  | 'malformed_action'
  | 'malformed_bundle'
  | 'broken_chain'
  | 'bad_signature'
  | 'unbound_action'
  | 'content_mismatch'
  | 'untrusted_control'
  | 'untrusted_args'
  | 'untrusted_control_and_args';

export interface ArgProvenanceDecision {
  /** pass: provenance admits; escalate: the principal must confirm; deny: forged or malformed provenance. */
  outcome: 'pass' | 'escalate' | 'deny';
  code?: ArgProvenanceCode;
  reason?: string;
  sensitive: boolean;
  /** True when a bundle verified under a pinned mediator. */
  verified: boolean;
  /** The label of the action choice. */
  control: ProvLevel;
  /** The label of every top-level parameter. */
  labels: Record<string, ProvLevel>;
  /** Sink parameters whose label is above their floor (UTF-8 order). */
  tainted: string[];
  /** Where the untrusted content came from: `origin:source`, plus `unlabelled` without a verified chain (UTF-8 order). */
  path: string[];
}

/** The digest an `action` receipt binds: the exact operation (verb, resource, params). */
export function provActionDigest(op: { verb: string; resource: string; params: Record<string, unknown> }): string {
  return hashCanonical({ d: PROV_ACTION_DOMAIN, verb: op.verb, resource: op.resource, params: op.params });
}

/** Content address of a receipt (signature included). */
export function provReceiptRef(r: ProvReceipt): string {
  return artifactRef(PROV_RECEIPT_REF_DOMAIN, 'r', r);
}

/** Is `k` a well-formed mediator pin? */
export const isProvMediatorPin = (k: unknown): k is ProvMediatorPin =>
  isPlainObject(k) && closedMembers(k, ['mediator', 'kid', 'pk'], ['pq_pk']) === null && isBoundedString(k.mediator, 256) && isBoundedString(k.kid, 64) && isDigest(k.pk) && pinPqOk(k.pq_pk);

/** Wire validation of one receipt. Null = well-formed. */
export function provReceiptWireError(r: unknown): string | null {
  if (!isPlainObject(r)) return 'a receipt must be an object';
  const m = closedMembers(r, ['v', 'kind', 'mediator', 'kid', 'session', 'seq', 'prev', 'origin', 'source', 'content_digest', 'issued_at', 'sig'], SUITE_MEMBERS, 'receipt');
  if (m) return m;
  if (r.v !== 1 || r.kind !== 'pca-prov') return 'a receipt must be {v: 1, kind: "pca-prov"}';
  if (!isBoundedString(r.mediator, 256)) return "'mediator' must be a non-empty string (<= 256 bytes)";
  if (!isBoundedString(r.kid, 64)) return "'kid' must be a non-empty string (<= 64 bytes)";
  if (!isDigest(r.session)) return "'session' must be canonical base64url (32 bytes)";
  if (!isSafeInt(r.seq) || r.seq < 0) return "'seq' must be a non-negative safe integer";
  if (r.prev !== null && !isDigest(r.prev)) return "'prev' must be null or canonical base64url (32 bytes)";
  if (!(PROV_ORIGINS as readonly unknown[]).includes(r.origin)) return `'origin' must be one of ${PROV_ORIGINS.join(', ')}`;
  if (!isBoundedString(r.source, 256)) return "'source' must be a non-empty string (<= 256 bytes)";
  if (!isDigest(r.content_digest)) return "'content_digest' must be canonical base64url (32 bytes)";
  if (!isSafeInt(r.issued_at) || r.issued_at < 0) return "'issued_at' must be a non-negative safe integer";
  if (typeof r.sig !== 'string') return "'sig' must be a string";
  return artifactSuiteError(r);
}

/** Validate an action-info object. Null = well-formed. */
export function provActionInfoError(a: unknown): string | null {
  if (!isPlainObject(a)) return 'action info must be an object';
  const m = closedMembers(a, [], ['effects', 'traits', 'params'], 'action info');
  if (m) return m;
  for (const k of ['effects', 'traits'] as const) {
    const v = a[k];
    if (v !== undefined && !(Array.isArray(v) && v.length <= 64 && v.every((x) => isBoundedString(x, 128)))) return `action info '${k}' must be a list of strings`;
  }
  if (a.params !== undefined) {
    if (!isPlainObject(a.params)) return "action info 'params' must be an object";
    for (const [k, v] of Object.entries(a.params)) if (!isBoundedString(k, 128) || !FLOORS.includes(v as string)) return `action info param '${k}' must map to first_party | tool | agent`;
  }
  return null;
}

/** Is an action with these facts non-sensitive (it only reads)? Unknown facts are sensitive. */
export function isReadOnlyAction(a: ProvActionInfo | undefined): boolean {
  if (a === undefined || !Array.isArray(a.effects) || a.effects.length === 0) return false;
  if (!a.effects.every((e) => e === 'read')) return false;
  return (a.traits ?? []).every((t) => READ_SAFE_TRAITS.includes(t));
}

// ---------------------------------------------------------------------------------------------------------------- tokens

/** Word characters for token boundaries: ASCII letters, digits, `_`, and every non-ASCII code unit (fail closed: fewer matches). */
const isWord = (c: number): boolean => (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95 || c >= 0x80;

/**
 * Does `needle` occur in `text` as a whole token? An occurrence counts when the code unit before it is not a word character
 * (or the needle starts with a non-word character), and likewise after it. Exact, case-sensitive, on UTF-16 code units; no
 * normalization. An empty needle never occurs.
 */
export function occursAsToken(text: string, needle: string): boolean {
  if (typeof text !== 'string' || typeof needle !== 'string' || needle.length === 0) return false;
  const headWord = isWord(needle.charCodeAt(0));
  const tailWord = isWord(needle.charCodeAt(needle.length - 1));
  for (let i = text.indexOf(needle); i >= 0; i = text.indexOf(needle, i + 1)) {
    const okB = !headWord || i === 0 || !isWord(text.charCodeAt(i - 1));
    const end = i + needle.length;
    const okA = !tailWord || end === text.length || !isWord(text.charCodeAt(end));
    if (okB && okA) return true;
  }
  return false;
}

/** The text of every leaf of a value (strings as is, other scalars in strict canonical form, object keys included); null when too large or not canonical. */
export function provLeaves(v: unknown): string[] | null {
  const out: string[] = [];
  const walk = (x: unknown, depth: number): boolean => {
    if (depth > MAX_DEPTH || out.length > MAX_PROV_LEAVES) return false;
    if (typeof x === 'string') out.push(x);
    else if (Array.isArray(x)) {
      for (const y of x) if (!walk(y, depth + 1)) return false;
    } else if (isPlainObject(x)) {
      for (const [k, y] of Object.entries(x)) {
        out.push(k);
        if (!walk(y, depth + 1)) return false;
      }
    } else {
      try {
        out.push(canonicalizeStrict(x));
      } catch {
        return false;
      }
    }
    return out.length <= MAX_PROV_LEAVES;
  };
  return walk(v, 0) ? out : null;
}

// ---------------------------------------------------------------------------------------------------------------- decision

const sortU = (xs: Iterable<string>): string[] => [...new Set(xs)].sort(compareUtf8);
const operationOk = (op: unknown): op is ArgProvenanceInput['operation'] =>
  isPlainObject(op) && isBoundedString(op.verb, 256) && typeof op.resource === 'string' && isPlainObject(op.params);

interface VerifiedChain {
  verified: boolean;
  /** Label of the context before the action (join of every non-action segment); `agent` when unverified or empty. */
  context: ProvLevel;
  path: string[];
  principalTexts: string[];
}

/** Verify a bundle against the pins and the operation. A string is a deny code with its reason. */
function verifyChain(bundle: unknown, op: ArgProvenanceInput['operation'], pins: readonly ProvMediatorPin[]): VerifiedChain | { code: ArgProvenanceCode; reason: string } {
  const unverified: VerifiedChain = { verified: false, context: 'agent', path: ['unlabelled'], principalTexts: [] };
  if (bundle === undefined || bundle === null) return unverified;
  const bad = (code: ArgProvenanceCode, reason: string) => ({ code, reason });
  if (!isPlainObject(bundle)) return bad('malformed_bundle', 'the bundle must be an object');
  const m = closedMembers(bundle, ['v', 'kind', 'receipts'], ['contents'], 'bundle');
  if (m) return bad('malformed_bundle', m);
  if (bundle.v !== 1 || bundle.kind !== 'pca-provenance') return bad('malformed_bundle', 'the bundle must be {v: 1, kind: "pca-provenance"}');
  const rs = bundle.receipts;
  if (!Array.isArray(rs) || rs.length === 0 || rs.length > MAX_PROV_RECEIPTS) return bad('malformed_bundle', `the bundle must hold 1..${MAX_PROV_RECEIPTS} receipts`);
  for (let i = 0; i < rs.length; i++) {
    const e = provReceiptWireError(rs[i]);
    if (e) return bad('malformed_bundle', `receipt ${i}: ${e}`);
  }
  const contents = bundle.contents === undefined ? {} : bundle.contents;
  if (!isPlainObject(contents)) return bad('malformed_bundle', "'contents' must be an object");
  const receipts = rs as ProvReceipt[];
  const first = receipts[0]!;
  for (let i = 0; i < receipts.length; i++) {
    const r = receipts[i]!;
    if (r.seq !== i) return bad('broken_chain', `receipt ${i} has seq ${r.seq}`);
    if (r.session !== first.session || r.mediator !== first.mediator || r.kid !== first.kid) return bad('broken_chain', `receipt ${i} belongs to another session or mediator`);
    if (i === 0 ? r.prev !== null : r.prev !== provReceiptRef(receipts[i - 1]!)) return bad('broken_chain', `receipt ${i} does not link to its predecessor`);
    if (i > 0 && r.issued_at < receipts[i - 1]!.issued_at) return bad('broken_chain', `receipt ${i} is older than its predecessor`);
  }
  const last = receipts[receipts.length - 1]!;
  if (last.origin !== 'action' || last.source !== op.verb || last.content_digest !== provActionDigest(op)) return bad('unbound_action', 'the last receipt is not the action receipt of this operation');
  for (const [k, text] of Object.entries(contents)) {
    const r = /^(0|[1-9][0-9]{0,8})$/.test(k) ? receipts[Number(k)] : undefined;
    if (r === undefined || r.origin !== 'principal') return bad('malformed_bundle', `contents '${k}' does not name a principal receipt`);
    if (typeof text !== 'string' || utf8Len(text) > MAX_PROV_CONTENT_BYTES) return bad('malformed_bundle', `contents '${k}' must be a string of at most ${MAX_PROV_CONTENT_BYTES} bytes`);
    let d: string;
    try {
      d = hashCanonical(text);
    } catch {
      return bad('content_mismatch', `contents '${k}' is not canonical text`);
    }
    if (d !== r.content_digest) return bad('content_mismatch', `contents '${k}' does not hash to its receipt`);
  }
  const pin = pins.find((p) => p.mediator === first.mediator && p.kid === first.kid);
  // a chain from a mediator this verifier does not pin vouches for nothing: every value stays at the top (escalate, never allow)
  if (!pin) return unverified;
  for (let i = 0; i < receipts.length; i++) {
    if (!verifyArtifactSig(PROV_RECEIPT_DOMAIN, receipts[i] as unknown as Record<string, unknown>, pin)) return bad('bad_signature', `receipt ${i} does not verify under the pinned mediator key`);
  }
  const before = receipts.slice(0, -1).filter((r) => r.origin !== 'action');
  let context: ProvLevel = before.length === 0 ? 'agent' : 'trusted';
  const path: string[] = [];
  for (const r of before) {
    const lv = ORIGIN_LEVEL[r.origin as Exclude<ProvOrigin, 'action'>];
    context = join(context, lv);
    if (r.origin !== 'principal') path.push(`${r.origin}:${r.source}`);
  }
  if (before.length === 0) path.push('unlabelled');
  const principalTexts = Object.entries(contents).map(([, t]) => t as string);
  return { verified: true, context, path: sortU(path), principalTexts };
}

/**
 * The provenance decision for one operation (see the module doc and the spec). Steps, first failure wins:
 *   0. inputs: pins, operation and action facts well-formed, else `deny` (malformed_config / malformed_operation / malformed_action);
 *   1. the bundle (when present): wire, chain (contiguous seq, prev links, one session and mediator, non-decreasing issued_at),
 *      the last receipt is the `action` receipt of this operation, every principal content hashes to its receipt, every
 *      signature verifies under the pinned (mediator, kid). A failure is `deny`. A chain whose mediator is not pinned is
 *      ignored (no trust). context = join of the non-action segments before the action (`agent` when none or unverified);
 *   2. server observations join into context (raise only);
 *   3. control = `trusted` with principalPlan or principalControl, else context;
 *   4. each top-level parameter: `trusted` with principalPlan; else the join over its leaves, where a leaf is `trusted` when
 *      the context is trusted or it occurs as a token in a verified principal content, else context; a parameter without
 *      leaves is `trusted`; a parameter too large to examine is context;
 *   5. floors: params[p] from the action facts, else `first_party` for a sensitive action and `agent` otherwise;
 *      a parameter whose label ranks above its floor is tainted;
 *   6. a sensitive action whose control is not `trusted`, or any tainted parameter, is `escalate`; otherwise `pass`.
 * Never throws.
 */
export function decideArgProvenance(input: ArgProvenanceInput): ArgProvenanceDecision {
  const base = { sensitive: true, verified: false, control: 'agent' as ProvLevel, labels: {} as Record<string, ProvLevel>, tainted: [] as string[], path: [] as string[] };
  const deny = (code: ArgProvenanceCode, reason: string): ArgProvenanceDecision => ({ ...base, outcome: 'deny', code, reason });
  try {
    if (!isPlainObject(input)) return deny('malformed_config', 'input must be an object');
    if (!Array.isArray(input.mediators) || !input.mediators.every(isProvMediatorPin)) return deny('malformed_config', 'mediator pins must be a list of {mediator, kid, pk, pq_pk?}');
    if (!operationOk(input.operation)) return deny('malformed_operation', 'the operation needs a verb, a resource and a params object');
    if (input.action !== undefined) {
      const e = provActionInfoError(input.action);
      if (e) return deny('malformed_action', e);
    }
    const obs = input.observed ?? [];
    if (!Array.isArray(obs) || !obs.every((o) => isPlainObject(o) && (o.origin === 'tool' || o.origin === 'retrieval' || o.origin === 'web') && isBoundedString(o.source, 256))) return deny('malformed_config', 'observations must be a list of {origin, source}');
    const op = input.operation;
    const sensitive = !isReadOnlyAction(input.action);
    base.sensitive = sensitive;
    const ch = verifyChain(input.bundle, op, input.mediators);
    if ('code' in ch) return deny(ch.code, ch.reason);
    base.verified = ch.verified;
    let context = ch.context;
    const path = [...ch.path];
    for (const o of obs as readonly ProvObservation[]) {
      context = join(context, ORIGIN_LEVEL[o.origin]);
      path.push(`${o.origin}:${o.source}`);
    }
    base.path = sortU(path);
    const plan = input.principalPlan === true;
    const control: ProvLevel = plan || input.principalControl === true ? 'trusted' : context;
    base.control = control;
    const labels: Record<string, ProvLevel> = Object.create(null) as Record<string, ProvLevel>;
    for (const p of sortU(Object.keys(op.params))) {
      if (plan) {
        labels[p] = 'trusted';
        continue;
      }
      const leaves = provLeaves(op.params[p]);
      if (leaves === null) {
        labels[p] = context;
        continue;
      }
      let l: ProvLevel = 'trusted';
      for (const leaf of leaves) {
        // a leaf the principal typed verbatim is the principal's choice whatever else the context held
        const leafLevel: ProvLevel = context === 'trusted' || ch.principalTexts.some((t) => occursAsToken(t, leaf)) ? 'trusted' : context;
        l = join(l, leafLevel);
      }
      labels[p] = l;
    }
    base.labels = { ...labels };
    const floors = input.action?.params ?? {};
    const tainted: string[] = [];
    for (const p of Object.keys(labels)) {
      const f: ProvLevel = Object.prototype.hasOwnProperty.call(floors, p) ? floors[p]! : sensitive ? 'first_party' : 'agent';
      if (RANK[labels[p]!] > RANK[f]) tainted.push(p);
    }
    base.tainted = sortU(tainted);
    // no segment origin maps to first_party, so a control label is trusted or untrusted
    const badControl = sensitive && control !== 'trusted';
    if (!badControl && base.tainted.length === 0) return { ...base, outcome: 'pass' };
    const where = base.path.length ? ` [${base.path.join(', ')}]` : '';
    const code: ArgProvenanceCode = badControl && base.tainted.length ? 'untrusted_control_and_args' : badControl ? 'untrusted_control' : 'untrusted_args';
    const parts: string[] = [];
    if (badControl) parts.push(`the choice of ${op.verb} derives from untrusted content`);
    if (base.tainted.length) parts.push(`${base.tainted.join(', ')} ${base.tainted.length === 1 ? 'derives' : 'derive'} from untrusted content`);
    return { ...base, outcome: 'escalate', code, reason: `${parts.join('; ')}${where}: the principal must confirm (prompt-injection path)` };
  } catch (e) {
    return deny('malformed_config', `evaluation error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`);
  }
}

// ---------------------------------------------------------------------------------------------------------------- envelope

/**
 * The grant envelope member `provenance` (signed by the principal with the rest of the grant):
 *   - `mediators`: mediator keys the PRINCIPAL designates (the agent harness the principal runs); the verifier adds them to its own pins;
 *   - `mode: 'insecure_off'`: the DOCUMENTED DANGEROUS opt-out. The gate is not evaluated for this grant, so injected content
 *     can steer the agent's sensitive actions within the grant's limits. Only for grants whose every action is harmless or
 *     whose principal reviews every call by other means.
 */
export interface ProvEnvelope {
  mode?: 'enforce' | 'insecure_off';
  mediators?: ProvMediatorPin[];
}

/** Null when well-formed. */
export function provEnvelopeError(p: unknown): string | null {
  if (!isPlainObject(p)) return 'provenance must be an object';
  const m = closedMembers(p, [], ['mode', 'mediators'], 'provenance');
  if (m) return m;
  if (p.mode !== undefined && p.mode !== 'enforce' && p.mode !== 'insecure_off') return "provenance.mode must be 'enforce' or 'insecure_off'";
  if (p.mediators !== undefined && !(Array.isArray(p.mediators) && p.mediators.length <= 16 && p.mediators.every(isProvMediatorPin))) return 'provenance.mediators must be at most 16 {mediator, kid, pk, pq_pk?}';
  return null;
}

// ---------------------------------------------------------------------------------------------------------------- mediator side

export interface ProvenanceRecorderOptions {
  /** Mediator name (pinned by the verifier, or named in the grant envelope). */
  mediator: string;
  kid: string;
  /** Ed25519 secret key of the mediator. Generated when absent (then pin `recorder.pin`). Keep it out of the model's reach. */
  secretKey?: Uint8Array;
  suite?: SignerSuiteOpts;
  /** b64u 32-byte session id (random when absent). */
  session?: string;
  now?: () => number;
}

export interface ProvenanceRecorder {
  readonly session: string;
  /** The pin a verifier (or the principal's grant envelope) must carry for this recorder. */
  readonly pin: ProvMediatorPin;
  /** The principal's own message (TRUSTED). */
  principal(text: string): ProvReceipt;
  /** A tool result (UNTRUSTED). Non-string output is recorded as its JSON text. */
  tool(name: string, output: unknown): ProvReceipt;
  /** A retrieved document (UNTRUSTED). */
  retrieval(source: string, content: unknown): ProvReceipt;
  /** A fetched web page or HTTP response (UNTRUSTED). */
  web(url: string, content: unknown): ProvReceipt;
  /** Record the chosen action and return the bundle to present with it. */
  forAction(op: { verb: string; resource: string; params: Record<string, unknown> }): ProvenanceBundle;
  /** Every receipt so far. */
  receipts(): readonly ProvReceipt[];
}

const textOf = (c: unknown): string => {
  if (typeof c === 'string') return c;
  try {
    return JSON.stringify(c) ?? String(c);
  } catch {
    return String(c);
  }
};
const clip = (s: string): string => (utf8Len(s) <= 256 ? (s.length > 0 ? s : '-') : clip(s.slice(0, Math.max(1, Math.floor(s.length / 2)))));

/**
 * The mediator side: one recorder per agent session. It must run where the bytes enter the model's context (the harness that
 * builds the prompt, a gateway, an MCP client), with a key the model cannot reach. The framework adapters create and feed one
 * automatically (see `withProvenance`); a developer writes nothing.
 */
export function createProvenanceRecorder(o: ProvenanceRecorderOptions): ProvenanceRecorder {
  if (!isBoundedString(o?.mediator, 256) || !isBoundedString(o.kid, 64)) throw new Error('createProvenanceRecorder: mediator (<= 256 bytes) and kid (<= 64 bytes) are required');
  const sk = o.secretKey ?? randomBytes(32);
  const session = o.session ?? b64u(randomBytes(32));
  if (!isDigest(session)) throw new Error('createProvenanceRecorder: session must be canonical base64url of 32 bytes');
  const now = o.now ?? Date.now;
  const chain: ProvReceipt[] = [];
  const contents: Record<string, string> = {};
  const pq = suitePqPublicKey(o.suite?.alg, o.suite);
  const pin: ProvMediatorPin = { mediator: o.mediator, kid: o.kid, pk: publicKeyB64u(sk), ...(pq !== undefined ? { pq_pk: pq } : {}) };
  const append = (origin: ProvOrigin, source: string, digest: string): ProvReceipt => {
    const prevR = chain[chain.length - 1];
    const issued = Math.max(prevR?.issued_at ?? 0, Math.trunc(now()));
    const body: ProvReceiptBody = { v: 1, kind: 'pca-prov', mediator: o.mediator, kid: o.kid, session, seq: chain.length, prev: prevR ? provReceiptRef(prevR) : null, origin, source: clip(source), content_digest: digest, issued_at: issued };
    const r = signArtifact(PROV_RECEIPT_DOMAIN, body as unknown as Record<string, unknown>, sk, o.suite) as unknown as ProvReceipt;
    chain.push(r);
    return r;
  };
  const segment = (origin: Exclude<ProvOrigin, 'action'>, source: string, content: unknown): ProvReceipt => {
    const text = textOf(content);
    const r = append(origin, source, hashCanonical(text));
    if (origin === 'principal' && utf8Len(text) <= MAX_PROV_CONTENT_BYTES) contents[String(r.seq)] = text;
    return r;
  };
  return {
    session,
    pin,
    principal: (text) => segment('principal', 'user', text),
    tool: (name, output) => segment('tool', name, output),
    retrieval: (source, content) => segment('retrieval', source, content),
    web: (url, content) => segment('web', url, content),
    forAction(op) {
      if (chain.length >= MAX_PROV_RECEIPTS) throw new Error(`provenance: the session holds ${MAX_PROV_RECEIPTS} receipts; start a new session with the principal's message`);
      append('action', op.verb, provActionDigest(op));
      return { v: 1, kind: 'pca-provenance', receipts: [...chain], ...(Object.keys(contents).length ? { contents: { ...contents } } : {}) };
    },
    receipts: () => [...chain],
  };
}

/**
 * The bundle for an operation that came straight from the principal (the application's own UI acting on the user's explicit
 * input, no model in between): one principal segment holding the operation, then the action. Under a pinned `recorder` key
 * the operation's choice and values are trusted.
 */
export function principalDirectProvenance(recorder: ProvenanceRecorder, op: { verb: string; resource: string; params: Record<string, unknown> }): ProvenanceBundle {
  recorder.principal(canonicalizeStrict({ verb: op.verb, resource: op.resource, params: op.params }));
  return recorder.forAction(op);
}
