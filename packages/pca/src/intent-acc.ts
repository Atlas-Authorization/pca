import { b64u, canonicalBytesStrict, canonicalizeStrict, compareUtf8, decodeB64uStrict, hashCanonical, utf8 } from './hash';
import { publicKeyOf } from './keys';
import { type PqPinPolicy, type SignerSuiteOpts, type SigAlg, bindSuiteFields, resolveSigAlg, signSuiteArtifact, suiteKeysOf, suitePqPublicKey, verifyPinnedSuite } from './pq';
import { type ActionSchema, accumulationParams, schemaVerb } from './action-schema';
import type { Predicate } from './predicates';
import { RESERVED_NAMES, ownGet, suiteCapabilityError } from './intent-strict';

const suiteErr = (alg: unknown) => suiteCapabilityError(alg, (a) => resolveSigAlg(a) !== null);

/**
 * TRAJECTORY STATE AT THE VERIFIER: accumulators, monitors and sequencer reservation receipts (PCA Intent Layer v2,
 * milestones V2/V3; docs/specs/pca-intent-layer-v2.md §2.1, §3.1, §8). NORMATIVE for the `accumulators` check
 * (conformance rule 15); the `acc-*` vectors pin it.
 *
 * An accumulator ψ = (agg, val, sel, win, key) is declared in the principal-signed session root S. The verifier never
 * takes an accumulator value from the agent: it recomputes the POST-ACTION value post_ψ(ξ, ω, t) from state it holds
 * (site-local, under a row lock) or from a sequencer-signed reservation receipt, and the agent's signed claim
 * `intent_session.acc[].post` must EQUAL it (a mismatch is a deny; the claim exists for the evidence bundle). Grant
 * predicates then read `env.acc.<id>.post` (and `env.mon.<id>.state`), which only the verifier fills. A constraint on
 * the post-action value is what makes splitting useless (T11).
 *
 * The HOST applies the window and the key (it selects the counted events of this session in win(t) whose key equals the
 * action's) and hands the verifier the PRE-STATE of that group: {@link AccPreState}. The verifier then combines:
 *   sum:      post = pre.sum + val(ω)          count:    post = pre.count + 1
 *   max:      post = max(pre.max, val(ω))      distinct: post = |pre.values ∪ {key(val(ω))}|
 * (for an action OUTSIDE sel the accumulator is not claimed and post = pre).
 */

export type AccAgg = 'sum' | 'count' | 'distinct' | 'max';
export const ACC_AGGS: readonly AccAgg[] = ['sum', 'count', 'distinct', 'max'];
export type AccWindow = { kind: 'task' } | { kind: 'sliding'; ms: number } | { kind: 'period'; ms: number; t0: number };
/**
 * Who holds an accumulator's state. A SEQUENCED holder is named by its long-lived ROOT key (never by a signing key): the
 * sequencer publishes a root-signed key set (`pca-sequencer-keys`) listing its rotating receipt-signing keys by `kid` with
 * their validity windows, and every receipt names the `kid` that signed it. Rotating a signing key therefore never
 * invalidates a session root: old sessions stay valid until they expire.
 */
export type AccHolder =
  | { kind: 'site_local' }
  | { kind: 'sequenced'; uri: string; root: string; root_alg?: SigAlg; root_pq_pk?: string; keys_uri?: string }
  | { kind: 'wallet' };
/** Events an accumulator counts: actions of the named verbs, actions of verbs with a parameter feeding the unit, or wallet events. */
export interface AccSelector {
  verbs?: string[];
  accumulates_into?: string;
  /** Wallet-held event counters (e.g. `intent_required` questions); never an action selector. */
  event?: 'intent_required' | 'question' | 'clarification';
}

export interface AccumulatorDecl {
  /** `[A-Za-z0-9_]{1,64}`: the `env.acc.<id>` path segment. */
  id: string;
  agg: AccAgg;
  /** `action.params.<name>`: the value read for sum / max / distinct. Absent with `sel.accumulates_into`: the sum of
   *  every integer parameter of the verb that feeds that unit. */
  val?: string;
  unit?: string;
  sel: AccSelector;
  win: AccWindow;
  /** `action.params.<name>` grouping key (a schema-declared identity, never free text), or null. */
  key: string | null;
  /** A_ψ: the declared domain bound of X_ψ = {0..A_ψ}; a post above it is outside Ω̃ (fail closed). */
  domain_max?: number;
  /** Wallet-held caps (the question cap). */
  cap?: number;
  holder: AccHolder;
}

export type MonitorKind = 'requires_prior' | 'precedes' | 'never' | 'always' | 'responds_within';
export const MONITOR_KINDS: readonly MonitorKind[] = ['requires_prior', 'precedes', 'never', 'always', 'responds_within'];
/** A deterministic safety monitor over the session's events (compiled from the B2 contract clause forms). */
export interface MonitorDecl {
  /** `[A-Za-z0-9_]{1,64}`: the `env.mon.<id>` path segment. */
  id: string;
  kind: MonitorKind;
  /** requires_prior / precedes: the prerequisite; never / always: the watched predicate; responds_within: the stimulus. */
  p: Predicate;
  /** requires_prior / precedes: the guarded action; responds_within: the response. */
  q?: Predicate;
  /** Which event statuses advance the monitor: `admitted` = reserved or committed (default), `committed` only. */
  status?: 'admitted' | 'committed';
  /** responds_within: the deadline in actions, 1..64. */
  within?: number;
}

export const ACC_ID_RE = /^[A-Za-z0-9_]{1,64}$/;
export const MAX_SESSION_ACCUMULATORS = 16;
export const MAX_SESSION_MONITORS = 16;
export const MAX_MONITOR_WITHIN = 64;
const PARAM_PATH_RE = /^action\.params\.[A-Za-z0-9_]{1,64}$/;
const UNIT_RE = /^[a-z0-9_]+(?:\.[a-z0-9_]+)*$/;

const isObj = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v) && [Object.prototype, null].includes(Object.getPrototypeOf(v));
const isInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0);
const isNonNeg = (v: unknown): v is number => isInt(v) && v >= 0;

/** The state set Q of a monitor (closed: a categorical dimension of Ω̃ without ⊥). */
export function monitorStates(m: Pick<MonitorDecl, 'kind' | 'within'>): string[] {
  switch (m.kind) {
    case 'requires_prior':
    case 'precedes':
      return ['unmet', 'met'];
    case 'never':
      return ['clean', 'seen'];
    case 'always':
      return ['ok', 'broken'];
    case 'responds_within': {
      const w = isInt(m.within) ? m.within : 0;
      return ['idle', ...Array.from({ length: w }, (_, i) => `pending:${i + 1}`), 'missed'];
    }
  }
}
export function monitorInitialState(m: Pick<MonitorDecl, 'kind'>): string {
  return m.kind === 'requires_prior' || m.kind === 'precedes' ? 'unmet' : m.kind === 'never' ? 'clean' : m.kind === 'always' ? 'ok' : 'idle';
}

const predicateShapeOk = (p: unknown): boolean => isObj(p) && (typeof p.verb === 'string' || (Array.isArray(p.verb) && p.verb.length > 0 && p.verb.every((x) => typeof x === 'string')));

export function accumulatorDeclError(a: unknown): string | null {
  if (!isObj(a)) return 'accumulator must be an object';
  for (const k of Object.keys(a)) if (!['id', 'agg', 'val', 'unit', 'sel', 'win', 'key', 'domain_max', 'cap', 'holder'].includes(k)) return `accumulator: unknown member '${k}'`;
  if (typeof a.id !== 'string' || !ACC_ID_RE.test(a.id) || RESERVED_NAMES.has(a.id)) return 'accumulator id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype';
  const at = `accumulator '${a.id}'`;
  if (!ACC_AGGS.includes(a.agg as AccAgg)) return `${at}: unknown agg`;
  if (a.val !== undefined && (typeof a.val !== 'string' || !PARAM_PATH_RE.test(a.val))) return `${at}: val must be action.params.<name>`;
  if (a.unit !== undefined && (typeof a.unit !== 'string' || a.unit.length > 64 || !UNIT_RE.test(a.unit))) return `${at}: unit must be a unit id`;
  if (!isObj(a.sel)) return `${at}: sel must be an object`;
  const sel = a.sel;
  for (const k of Object.keys(sel)) if (!['verbs', 'accumulates_into', 'event'].includes(k)) return `${at}: sel has unknown member '${k}'`;
  if (sel.verbs !== undefined && (!Array.isArray(sel.verbs) || sel.verbs.length === 0 || sel.verbs.length > 64 || !sel.verbs.every((v) => typeof v === 'string' && v.length > 0))) return `${at}: sel.verbs must be 1..64 verb names`;
  if (sel.accumulates_into !== undefined && (typeof sel.accumulates_into !== 'string' || !UNIT_RE.test(sel.accumulates_into))) return `${at}: sel.accumulates_into must be a unit id`;
  if (sel.event !== undefined && !['intent_required', 'question', 'clarification'].includes(sel.event as string)) return `${at}: unknown sel.event`;
  const actionSel = sel.verbs !== undefined || sel.accumulates_into !== undefined;
  if (actionSel === (sel.event !== undefined)) return `${at}: sel names actions (verbs / accumulates_into) or a wallet event, exactly one kind`;
  if (!isObj(a.win)) return `${at}: win must be an object`;
  const w = a.win;
  if (w.kind === 'task') {
    if (Object.keys(w).length !== 1) return `${at}: win {kind: task} has no other member`;
  } else if (w.kind === 'sliding') {
    if (Object.keys(w).sort().join() !== 'kind,ms' || !(isInt(w.ms) && w.ms > 0)) return `${at}: win sliding needs a positive ms`;
  } else if (w.kind === 'period') {
    if (Object.keys(w).sort().join() !== 'kind,ms,t0' || !(isInt(w.ms) && w.ms > 0) || !isNonNeg(w.t0)) return `${at}: win period needs a positive ms and t0 >= 0`;
  } else return `${at}: unknown win kind`;
  if (a.key !== null && (typeof a.key !== 'string' || !PARAM_PATH_RE.test(a.key))) return `${at}: key must be null or action.params.<name>`;
  if (a.domain_max !== undefined && !isNonNeg(a.domain_max)) return `${at}: domain_max must be a non-negative safe integer`;
  if (a.cap !== undefined && !isNonNeg(a.cap)) return `${at}: cap must be a non-negative safe integer`;
  if (!isObj(a.holder)) return `${at}: holder must be an object`;
  const h = a.holder;
  if (h.kind === 'site_local' || h.kind === 'wallet') {
    if (Object.keys(h).length !== 1) return `${at}: holder ${String(h.kind)} has no other member`;
  } else if (h.kind === 'sequenced') {
    for (const k of Object.keys(h)) if (!['kind', 'uri', 'root', 'root_alg', 'root_pq_pk', 'keys_uri'].includes(k)) return `${at}: holder sequenced has unknown member '${k}'`;
    if (typeof h.uri !== 'string' || h.uri.length === 0) return `${at}: holder sequenced needs a uri`;
    if (decodeB64uStrict(h.root, 32) === null) return `${at}: holder.root is not canonical base64url (32 bytes)`;
    if (suiteErr(h.root_alg)) return `${at}: holder.root_alg: ${suiteErr(h.root_alg)}`;
    if (h.root_pq_pk !== undefined && decodeB64uStrict(h.root_pq_pk) === null) return `${at}: holder.root_pq_pk is not canonical base64url`;
    if (h.keys_uri !== undefined && (typeof h.keys_uri !== 'string' || h.keys_uri.length === 0)) return `${at}: holder.keys_uri must be a non-empty string`;
  } else return `${at}: unknown holder kind`;
  const wallet = h.kind === 'wallet';
  if (wallet !== (sel.event !== undefined)) return `${at}: wallet events are wallet-held and only wallet events are`;
  if (!wallet) {
    if (a.agg !== 'count' && a.val === undefined && sel.accumulates_into === undefined) return `${at}: ${String(a.agg)} needs val (or sel.accumulates_into for a sum)`;
    if (a.agg !== 'sum' && a.agg !== 'count' && a.val === undefined) return `${at}: ${String(a.agg)} needs val`;
    if (a.agg === 'count' && a.val !== undefined) return `${at}: count takes no val`;
  }
  return null;
}

export function monitorDeclError(m: unknown): string | null {
  if (!isObj(m)) return 'monitor must be an object';
  for (const k of Object.keys(m)) if (!['id', 'kind', 'p', 'q', 'status', 'within'].includes(k)) return `monitor: unknown member '${k}'`;
  if (typeof m.id !== 'string' || !ACC_ID_RE.test(m.id) || RESERVED_NAMES.has(m.id)) return 'monitor id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype';
  const at = `monitor '${m.id}'`;
  if (!MONITOR_KINDS.includes(m.kind as MonitorKind)) return `${at}: unknown kind`;
  if (!predicateShapeOk(m.p)) return `${at}: p must be a predicate`;
  const needsQ = m.kind === 'requires_prior' || m.kind === 'precedes' || m.kind === 'responds_within';
  if (needsQ !== (m.q !== undefined)) return `${at}: q is required exactly for requires_prior / precedes / responds_within`;
  if (m.q !== undefined && !predicateShapeOk(m.q)) return `${at}: q must be a predicate`;
  if (m.status !== undefined && m.status !== 'admitted' && m.status !== 'committed') return `${at}: status must be admitted or committed`;
  if ((m.kind === 'responds_within') !== (m.within !== undefined)) return `${at}: within is required exactly for responds_within`;
  if (m.within !== undefined && !(isInt(m.within) && m.within >= 1 && m.within <= MAX_MONITOR_WITHIN)) return `${at}: within must be an integer in 1..${MAX_MONITOR_WITHIN}`;
  return null;
}

// ---- selection, values, combination --------------------------------------------------------------------------------

/** ω ∈ sel_ψ (action selectors only): the verb is listed, or the verb has a parameter feeding `sel.accumulates_into`. */
export function accSelects(a: AccumulatorDecl, verb: string, schema?: Pick<ActionSchema, 'verbs'>): boolean {
  if (a.sel.event !== undefined) return false;
  if (a.sel.verbs?.includes(verb)) return true;
  if (a.sel.accumulates_into !== undefined && schema) {
    const v = schemaVerb(schema, verb);
    return !!v && accumulationParams(v, a.sel.accumulates_into).length > 0;
  }
  return false;
}

/** The canonical key of a `distinct` value: the strict canonical JSON text of a string or a safe integer. */
export function distinctKey(x: unknown): string | null {
  if (typeof x === 'string' || isInt(x)) {
    try {
      return canonicalizeStrict(x);
    } catch {
      return null;
    }
  }
  return null;
}

export type AccValue = { ok: true; val: number; key?: string } | { ok: false; reason: string };

/**
 * val(ω) for a selected action (NORMATIVE):
 *   count: 1;
 *   distinct: params[val] must be a string or a safe integer; its {@link distinctKey};
 *   sum / max with `val`: params[val] must be a safe integer >= 0;
 *   sum without `val` (sel.accumulates_into = u): the sum of every PRESENT integer parameter of the verb whose schema
 *     declaration lists u in `accumulates_into` (each a safe integer >= 0; absent optional ones contribute 0).
 * The result must stay a safe integer.
 */
export function accValueOf(a: AccumulatorDecl, verb: string, params: Record<string, unknown>, schema?: Pick<ActionSchema, 'verbs'>): AccValue {
  const read = (path: string): unknown => ownGet(params, path.slice('action.params.'.length));
  if (a.agg === 'count') return { ok: true, val: 1 };
  if (a.agg === 'distinct') {
    const k = distinctKey(read(a.val!));
    return k === null ? { ok: false, reason: `${a.val} must be a string or a safe integer` } : { ok: true, val: 1, key: k };
  }
  if (a.val !== undefined) {
    const x = read(a.val);
    return isNonNeg(x) ? { ok: true, val: x } : { ok: false, reason: `${a.val} must be a non-negative safe integer` };
  }
  const v = schema ? schemaVerb(schema, verb) : undefined;
  if (!v) return { ok: false, reason: `no schema entry for '${verb}' to read accumulates_into` };
  let s = 0;
  for (const p of accumulationParams(v, a.sel.accumulates_into!)) {
    const x = read(p);
    if (x === undefined) continue;
    if (!isNonNeg(x)) return { ok: false, reason: `${p} must be a non-negative safe integer` };
    s += x;
    if (!Number.isSafeInteger(s)) return { ok: false, reason: 'accumulated value exceeds 2^53-1' };
  }
  return { ok: true, val: s };
}

/** The verifier-held pre-state of one accumulator group (window and key already applied by the host). */
export type AccPreState = { sum: number } | { count: number } | { max: number } | { values: string[] };

export function preStateError(a: Pick<AccumulatorDecl, 'agg'>, s: unknown): string | null {
  if (!isObj(s)) return 'pre-state must be an object';
  const want = a.agg === 'sum' ? 'sum' : a.agg === 'count' ? 'count' : a.agg === 'max' ? 'max' : 'values';
  if (Object.keys(s).join() !== want) return `pre-state of a ${a.agg} accumulator is {${want}}`;
  if (want === 'values') {
    const vs = s.values;
    if (!Array.isArray(vs) || !vs.every((x) => typeof x === 'string')) return 'pre-state values must be strings';
    if (new Set(vs).size !== vs.length) return 'pre-state values must be distinct';
    return null;
  }
  return isNonNeg(s[want]) ? null : `pre-state ${want} must be a non-negative safe integer`;
}

/** The post-action value from the pre-state (null when it would leave the safe-integer range). */
export function combineAcc(a: Pick<AccumulatorDecl, 'agg'>, pre: AccPreState, v: { val: number; key?: string }): number | null {
  let post: number;
  switch (a.agg) {
    case 'sum':
      post = (pre as { sum: number }).sum + v.val;
      break;
    case 'count':
      post = (pre as { count: number }).count + 1;
      break;
    case 'max':
      post = Math.max((pre as { max: number }).max, v.val);
      break;
    case 'distinct': {
      const vs = (pre as { values: string[] }).values;
      post = vs.length + (vs.includes(v.key!) ? 0 : 1);
      break;
    }
  }
  return Number.isSafeInteger(post) ? post : null;
}

/** The value of an accumulator group that this action does NOT feed (post = pre). */
export function preValue(a: Pick<AccumulatorDecl, 'agg'>, pre: AccPreState): number {
  switch (a.agg) {
    case 'sum':
      return (pre as { sum: number }).sum;
    case 'count':
      return (pre as { count: number }).count;
    case 'max':
      return (pre as { max: number }).max;
    case 'distinct':
      return (pre as { values: string[] }).values.length;
  }
}

// ---- reservation receipts (sequenced holder) -------------------------------------------------------------------

export const ACC_RECEIPT_DOMAIN = 'atlas-pca/acc-receipt/v1\0';
export const ACC_RECEIPT_REF_DOMAIN = 'atlas-pca/acc-receipt-ref/v1';
export const ACC_RESERVE_DOMAIN = 'atlas-pca/acc-reserve/v1';

/** A sequencer-signed reservation receipt (`pca-acc-receipt` v1). Every receipt is a leaf of the session's transparency log. */
export interface AccReceipt {
  v: 1;
  kind: 'pca-acc-receipt';
  session: string;
  acc: string;
  /** Per-(session, acc) sequence number, contiguous from 1 in the sequencer's log. */
  seq: number;
  pre: number;
  delta: number;
  post: number;
  /** {@link pcactnReservationDigest} of the PCActn the reservation is for. */
  pcactn_digest: string;
  aud: string;
  /** When the sequencer issued the receipt (epoch ms): the signing key must be valid then. */
  issued_at: number;
  expires_at: number;
  /** The `kid` of the signing key in the sequencer's root-signed key set. */
  kid: string;
  /** The receipt's position in the sequencer's log: leaf index and the head it was appended under. */
  ledger: { index: number; head: string };
  /** The signing key (b64u Ed25519 identity): the key set entry named by `kid`. */
  signer: string;
  alg?: SigAlg;
  pq_pk?: string;
  sig: string;
  pq_sig?: string;
}
export type AccReceiptBody = Omit<AccReceipt, 'signer' | 'alg' | 'pq_pk' | 'sig' | 'pq_sig'>;

/**
 * The digest a reservation binds: the PCActn's body WITHOUT its signatures (`sig`, `pq_sig`, `threshold`) and WITHOUT
 * `intent_session` (which carries the receipt digest, so the receipt cannot bind it: the agent reserves first, then
 * signs). `b64u(sha256(strictCanonical({d: "atlas-pca/acc-reserve/v1", b: body})))`.
 */
export function pcactnReservationDigest(p: Record<string, unknown>): string {
  const { sig: _a, pq_sig: _b, threshold: _c, intent_session: _d, ...body } = p;
  void _a;
  void _b;
  void _c;
  void _d;
  return hashCanonical({ d: ACC_RESERVE_DOMAIN, b: body });
}

const RECEIPT_KEYS = ['v', 'kind', 'session', 'acc', 'seq', 'pre', 'delta', 'post', 'pcactn_digest', 'aud', 'issued_at', 'expires_at', 'kid', 'ledger', 'signer', 'alg', 'pq_pk', 'sig', 'pq_sig'];

export function accReceiptShapeError(r: unknown): string | null {
  if (!isObj(r)) return 'receipt is not an object';
  for (const k of Object.keys(r)) if (!RECEIPT_KEYS.includes(k)) return `receipt: unknown member '${k}'`;
  if (r.v !== 1 || r.kind !== 'pca-acc-receipt') return 'not a pca-acc-receipt v1';
  if (decodeB64uStrict(r.session, 32) === null) return 'receipt.session is not canonical base64url (32 bytes)';
  if (typeof r.acc !== 'string' || !ACC_ID_RE.test(r.acc)) return 'receipt.acc is not an accumulator id';
  if (!(isInt(r.seq) && r.seq >= 1)) return 'receipt.seq must be a safe integer >= 1';
  if (!isNonNeg(r.pre) || !isNonNeg(r.delta) || !isNonNeg(r.post)) return 'receipt pre / delta / post must be non-negative safe integers';
  if (decodeB64uStrict(r.pcactn_digest, 32) === null) return 'receipt.pcactn_digest is not canonical base64url (32 bytes)';
  if (typeof r.aud !== 'string' || r.aud.length === 0) return 'receipt.aud must be a non-empty string';
  if (!isNonNeg(r.issued_at) || !isNonNeg(r.expires_at)) return 'receipt.issued_at / expires_at must be non-negative safe integers';
  if (!(r.expires_at >= r.issued_at && r.expires_at - r.issued_at <= MAX_RECEIPT_LIFETIME_MS)) return `receipt.expires_at must be within ${MAX_RECEIPT_LIFETIME_MS} ms after issued_at`;
  if (typeof r.kid !== 'string' || !KID_RE.test(r.kid)) return 'receipt.kid must match [A-Za-z0-9_.:-]{1,64}';
  if (!isObj(r.ledger) || Object.keys(r.ledger).sort().join() !== 'head,index' || !isNonNeg(r.ledger.index) || decodeB64uStrict(r.ledger.head, 32) === null) return 'receipt.ledger must be {index, head}';
  if (decodeB64uStrict(r.signer, 32) === null) return 'receipt.signer is not canonical base64url (32 bytes)';
  if (suiteErr(r.alg)) return `receipt.alg: ${suiteErr(r.alg)}`;
  const suite = resolveSigAlg(r.alg)!;
  if (suite.alg === 'ed25519' && (r.pq_pk !== undefined || r.pq_sig !== undefined)) return 'an ed25519 receipt must not carry pq_pk / pq_sig';
  if (typeof r.sig !== 'string') return 'receipt.sig must be a string';
  return null;
}

function receiptBody(r: AccReceiptBody & { signer: string }): Record<string, unknown> {
  return {
    v: r.v, kind: r.kind, session: r.session, acc: r.acc, seq: r.seq, pre: r.pre, delta: r.delta, post: r.post,
    pcactn_digest: r.pcactn_digest, aud: r.aud, issued_at: r.issued_at, expires_at: r.expires_at, kid: r.kid, ledger: { index: r.ledger.index, head: r.ledger.head }, signer: r.signer,
  };
}
function receiptMessage(body: Record<string, unknown>): Uint8Array {
  const dom = utf8(ACC_RECEIPT_DOMAIN);
  const b = canonicalBytesStrict(body);
  const out = new Uint8Array(dom.length + b.length);
  out.set(dom);
  out.set(b, dom.length);
  return out;
}

export function signAccReceipt(body: AccReceiptBody, sequencerSecret: Uint8Array, suite?: SignerSuiteOpts): AccReceipt {
  const signer = b64u(publicKeyOf(sequencerSecret));
  const base = receiptBody({ ...body, signer });
  const pqPk = suitePqPublicKey(suite?.alg, suite);
  const fields = signSuiteArtifact(suite?.alg, suiteKeysOf(sequencerSecret, suite), receiptMessage(bindSuiteFields(base, suite?.alg, pqPk)));
  const out = { ...base, ...fields } as unknown as AccReceipt;
  const bad = accReceiptShapeError(out);
  if (bad) throw new Error(`signAccReceipt: ${bad}`);
  return out;
}

export function verifyAccReceiptSignature(r: AccReceipt, expectedSigner: string, pin?: PqPinPolicy): boolean {
  try {
    if (accReceiptShapeError(r) !== null || r.signer !== expectedSigner) return false;
    return verifyPinnedSuite(r.alg, r.signer, r.pq_pk, receiptMessage(bindSuiteFields(receiptBody(r), r.alg, r.pq_pk)), { sig: r.sig, pq_sig: r.pq_sig }, pin);
  } catch {
    return false;
  }
}

/** The receipt's content address (what `intent_session.acc[].receipt` carries). */
export function accReceiptDigest(r: AccReceipt): string {
  return hashCanonical({ d: ACC_RECEIPT_REF_DOMAIN, r });
}

export const ACC_RECEIPT_CORE_DOMAIN = 'atlas-pca/acc-receipt-core/v1';

/**
 * The receipt's LOG LEAF content: the receipt without its `ledger` position and its signature fields (the sequencer
 * appends `intentAnchorCommit("receipt", accReceiptCoreDigest(r))` and only then knows `ledger.index` / `ledger.head`).
 * Two receipts with the same (session, acc, seq) and different cores in one witnessed log are publicly provable
 * equivocation.
 */
export function accReceiptCoreDigest(r: Omit<AccReceiptBody, 'ledger' | 'kid'>): string {
  return hashCanonical({
    d: ACC_RECEIPT_CORE_DOMAIN,
    r: { v: r.v, kind: r.kind, session: r.session, acc: r.acc, seq: r.seq, pre: r.pre, delta: r.delta, post: r.post, pcactn_digest: r.pcactn_digest, aud: r.aud, issued_at: r.issued_at, expires_at: r.expires_at },
  });
}

// ---- the sequencer's published key set (signing-key rotation without restarting sessions) ------------------------

export const SEQUENCER_KEYS_DOMAIN = 'atlas-pca/sequencer-keys/v1\0';
export const KID_RE = /^[A-Za-z0-9_.:-]{1,64}$/;
/** Allowed clock skew between a receipt's / key set's `issued_at` and the verifier's clock. */
export const RECEIPT_SKEW_MS = 60_000;
/** A receipt lives at most this long: `issued_at <= expires_at <= issued_at + MAX_RECEIPT_LIFETIME_MS` (15 min). */
export const MAX_RECEIPT_LIFETIME_MS = 900_000;
/** Default bound on a receipt's age at verification (`now - issued_at`), policy `acc.max_receipt_age_s` (15 min). */
export const DEFAULT_MAX_RECEIPT_AGE_MS = 900_000;
/** Default bound on a key set's age (`now - issued_at`), policy `acc.max_keyset_age_s` (1 h): sequencers re-sign often. */
export const DEFAULT_MAX_KEYSET_AGE_MS = 3_600_000;

export interface SequencerKeyEntry {
  kid: string;
  /** b64u Ed25519 identity of the receipt-signing key. */
  pk: string;
  alg?: SigAlg;
  pq_pk?: string;
  /** Validity window (epoch ms): receipts issued in [not_before, not_after] verify; `not_after` absent = current key. */
  not_before: number;
  not_after?: number;
}

/** `pca-sequencer-keys` v1: the sequencer's receipt-signing keys, signed by its ROOT key (`sequencer`). */
export interface SequencerKeySet {
  v: 1;
  kind: 'pca-sequencer-keys';
  /** The root key (b64u Ed25519), = `holder.root` of the sessions it serves; it signs this document. */
  sequencer: string;
  /** Monotone version: a verifier that tracks the newest version it has seen for a root refuses an older set. */
  version: number;
  issued_at: number;
  keys: SequencerKeyEntry[];
  alg?: SigAlg;
  pq_pk?: string;
  sig: string;
  pq_sig?: string;
}
export type SequencerKeySetBody = Omit<SequencerKeySet, 'sequencer' | 'alg' | 'pq_pk' | 'sig' | 'pq_sig'>;

export function sequencerKeySetShapeError(k: unknown): string | null {
  if (!isObj(k)) return 'key set is not an object';
  for (const x of Object.keys(k)) if (!['v', 'kind', 'sequencer', 'version', 'issued_at', 'keys', 'alg', 'pq_pk', 'sig', 'pq_sig'].includes(x)) return `key set: unknown member '${x}'`;
  if (k.v !== 1 || k.kind !== 'pca-sequencer-keys') return 'not a pca-sequencer-keys v1';
  if (decodeB64uStrict(k.sequencer, 32) === null) return 'sequencer is not canonical base64url (32 bytes)';
  if (!(isNonNeg(k.version) && k.version >= 1)) return 'version must be a safe integer >= 1';
  if (!isNonNeg(k.issued_at)) return 'issued_at must be a non-negative safe integer';
  if (!Array.isArray(k.keys) || k.keys.length === 0 || k.keys.length > 256) return 'keys must be 1..256 entries';
  const kids = new Set<string>();
  for (const e of k.keys) {
    if (!isObj(e) || Object.keys(e).some((x) => !['kid', 'pk', 'alg', 'pq_pk', 'not_before', 'not_after'].includes(x))) return 'keys entries are {kid, pk, alg?, pq_pk?, not_before, not_after?}';
    if (typeof e.kid !== 'string' || !KID_RE.test(e.kid) || kids.has(e.kid)) return 'key kids must match [A-Za-z0-9_.:-]{1,64} and be distinct';
    kids.add(e.kid);
    if (decodeB64uStrict(e.pk, 32) === null) return 'key pk is not canonical base64url (32 bytes)';
    if (suiteErr(e.alg)) return `key alg: ${suiteErr(e.alg)}`;
    if (e.pq_pk !== undefined && decodeB64uStrict(e.pq_pk) === null) return 'key pq_pk is not canonical base64url';
    if (!isNonNeg(e.not_before) || (e.not_after !== undefined && !(isNonNeg(e.not_after) && e.not_after >= e.not_before))) return 'key validity must be 0 <= not_before <= not_after';
  }
  if (suiteErr(k.alg)) return `alg: ${suiteErr(k.alg)}`;
  const suite = resolveSigAlg(k.alg)!;
  if (suite.alg === 'ed25519' && (k.pq_pk !== undefined || k.pq_sig !== undefined)) return 'an ed25519 key set must not carry pq_pk / pq_sig';
  if (typeof k.sig !== 'string') return 'sig must be a string';
  return null;
}

function keySetMessage(body: Record<string, unknown>): Uint8Array {
  const dom = utf8(SEQUENCER_KEYS_DOMAIN);
  const b = canonicalBytesStrict(body);
  const out = new Uint8Array(dom.length + b.length);
  out.set(dom);
  out.set(b, dom.length);
  return out;
}
const keySetBody = (k: SequencerKeySetBody & { sequencer: string }) => ({ v: k.v, kind: k.kind, sequencer: k.sequencer, version: k.version, issued_at: k.issued_at, keys: k.keys });

export function signSequencerKeySet(body: SequencerKeySetBody, rootSecret: Uint8Array, suite?: SignerSuiteOpts): SequencerKeySet {
  const base = keySetBody({ ...body, sequencer: b64u(publicKeyOf(rootSecret)) });
  const pqPk = suitePqPublicKey(suite?.alg, suite);
  const fields = signSuiteArtifact(suite?.alg, suiteKeysOf(rootSecret, suite), keySetMessage(bindSuiteFields(JSON.parse(JSON.stringify(base)), suite?.alg, pqPk)));
  const out = { ...JSON.parse(JSON.stringify(base)), ...fields } as SequencerKeySet;
  const bad = sequencerKeySetShapeError(out);
  if (bad) throw new Error(`signSequencerKeySet: ${bad}`);
  return out;
}

/** Verify a key set under the session's pinned root (and the root's pinned PQ key for a PQ suite). Never throws. */
export function verifySequencerKeySet(k: unknown, root: string, rootPqPk?: string): boolean {
  try {
    if (sequencerKeySetShapeError(k) !== null) return false;
    const ks = k as SequencerKeySet;
    if (ks.sequencer !== root) return false;
    const pin: PqPinPolicy = rootPqPk !== undefined ? { pqPins: { [root]: rootPqPk } } : {};
    return verifyPinnedSuite(ks.alg, root, ks.pq_pk, keySetMessage(bindSuiteFields(JSON.parse(JSON.stringify(keySetBody(ks))), ks.alg, ks.pq_pk)), { sig: ks.sig, pq_sig: ks.pq_sig }, pin);
  } catch {
    return false;
  }
}

export const SEQUENCER_KEYS_REF_DOMAIN = 'atlas-pca/sequencer-keys-ref/v1';

/** A key set's content address: `base64url(sha256(strictCanonical({"d":"atlas-pca/sequencer-keys-ref/v1","k":set})))`. */
export function sequencerKeySetDigest(ks: SequencerKeySet): string {
  return hashCanonical({ d: SEQUENCER_KEYS_REF_DOMAIN, k: ks });
}

/** The newest key set a verifier has accepted for one sequencer root (tracked state, `acc.keyset_versions[root]`). */
export interface TrackedKeySet {
  version: number;
  digest: string;
}

/** `acc.keyset_versions[root]` is exactly `{version, digest}`: version a safe integer >= 1, digest 32-byte base64url. */
export function trackedKeySetError(t: unknown): string | null {
  if (t === null || typeof t !== 'object' || Array.isArray(t)) return 'a tracked key set must be an object {version, digest}';
  const o = t as Record<string, unknown>;
  for (const k of Object.keys(o)) if (k !== 'version' && k !== 'digest') return `a tracked key set has the unknown member '${k}'`;
  if (!isInt(o.version) || (o.version as number) < 1) return 'a tracked key set version must be a safe integer >= 1';
  if (typeof o.digest !== 'string' || decodeB64uStrict(o.digest, 32) === null) return 'a tracked key set digest must be canonical base64url (32 bytes)';
  return null;
}

/** Freshness bounds of receipt verification (policy `acc`); absent members take the defaults above. */
export interface ReceiptFreshness {
  maxReceiptAgeMs?: number;
  maxKeySetAgeMs?: number;
  /** The newest key set this verifier has accepted for the holder's root (absent: not tracked). */
  tracked?: TrackedKeySet;
  /** A bare version floor (a replaying verifier that knows versions only, e.g. an evidence bundle): `version >= floor`. */
  minKeySetVersion?: number;
}

/**
 * Verify a receipt against the sequenced holder of S (NORMATIVE, rule 15 step 3, sequenced). False unless ALL hold:
 *   - `now` is a safe integer and every bound is a non-negative safe integer;
 *   - the receipt is well-formed (`issued_at <= expires_at <= issued_at + 15 min`), `issued_at <= now + 60 s` and
 *     `now - issued_at <= maxReceiptAgeMs` (default 15 min);
 *   - SOME presented key set verifies under `holder.root` (PQ: `holder.root_pq_pk`), and, when the verifier tracks
 *     `{version, digest}` for the root, `version >= tracked.version` (no rollback) and, at `version == tracked.version`,
 *     `sequencerKeySetDigest(set) == tracked.digest` (two different sets under one version are an EQUIVOCATION), plus `issued_at <= now + 60 s` and `now - issued_at <= maxKeySetAgeMs` (default 1 h), and lists
 *     `receipt.kid` with `pk == receipt.signer`, `not_before <= receipt.issued_at`, and, when `not_after` is set,
 *     `receipt.issued_at <= not_after` AND `now - 60 s <= not_after` (a retired key stops verifying once retired: a leaked
 *     retired key cannot mint receipts that verify later), the entry's suite equal to the receipt's;
 *   - the receipt's signature verifies under that entry (its PQ key pinned by the entry).
 */
export function verifyReceiptAgainstHolder(r: AccReceipt, holder: Extract<AccHolder, { kind: 'sequenced' }>, keySets: readonly unknown[], now: number, f: ReceiptFreshness = {}): boolean {
  const maxAge = f.maxReceiptAgeMs ?? DEFAULT_MAX_RECEIPT_AGE_MS;
  const maxSetAge = f.maxKeySetAgeMs ?? DEFAULT_MAX_KEYSET_AGE_MS;
  if (!isInt(now) || !isNonNeg(maxAge) || !isNonNeg(maxSetAge) || (f.tracked !== undefined && trackedKeySetError(f.tracked) !== null) || (f.minKeySetVersion !== undefined && !isNonNeg(f.minKeySetVersion))) return false;
  if (!Array.isArray(keySets) || accReceiptShapeError(r) !== null) return false;
  if (!(r.issued_at <= now + RECEIPT_SKEW_MS) || !(now - r.issued_at <= maxAge)) return false;
  for (const k of keySets) {
    if (!verifySequencerKeySet(k, holder.root, holder.root_pq_pk)) continue;
    const ks = k as SequencerKeySet;
    if (f.minKeySetVersion !== undefined && ks.version < f.minKeySetVersion) continue;
    if (f.tracked !== undefined && (ks.version < f.tracked.version || (ks.version === f.tracked.version && sequencerKeySetDigest(ks) !== f.tracked.digest))) continue;
    if (!(ks.issued_at <= now + RECEIPT_SKEW_MS) || !(now - ks.issued_at <= maxSetAge)) continue;
    const e = ks.keys.find((x) => x.kid === r.kid);
    if (!e || e.pk !== r.signer || r.issued_at < e.not_before) continue;
    if (e.not_after !== undefined && (r.issued_at > e.not_after || e.not_after < now - RECEIPT_SKEW_MS)) continue;
    if ((resolveSigAlg(e.alg)?.alg ?? 'ed25519') !== (resolveSigAlg(r.alg)?.alg ?? 'x')) continue;
    if (verifyAccReceiptSignature(r, e.pk, e.pq_pk !== undefined ? { pqPins: { [e.pk]: e.pq_pk } } : {})) return true;
  }
  return false;
}

/** The arithmetic a receipt must satisfy for its accumulator (NORMATIVE, rule 15 step 5d). */
export function receiptArithmeticOk(a: Pick<AccumulatorDecl, 'agg'>, r: Pick<AccReceipt, 'pre' | 'delta' | 'post'>, val: number): boolean {
  switch (a.agg) {
    case 'sum':
      return r.delta === val && r.post === r.pre + r.delta;
    case 'count':
      return r.delta === 1 && r.post === r.pre + 1;
    case 'max':
      return r.delta === val && r.post === Math.max(r.pre, r.delta);
    case 'distinct':
      return (r.delta === 0 || r.delta === 1) && r.post === r.pre + r.delta;
  }
}

/** Order-independent helper for hosts: a set of distinct keys in canonical (UTF-8) order. */
export function sortedDistinct(keys: Iterable<string>): string[] {
  return [...new Set(keys)].sort(compareUtf8);
}
