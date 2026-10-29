/**
 * WORKFLOW (DAG) AUTHORIZATION (K5, C-300..C-309).
 *
 * A principal signs ONE commitment to a whole workflow: a DAG of steps (verb, resource, optional params digest), the dataflow
 * edges between them with per-edge constraints ("step B's amount <= step A's computed refund"), label (taint) restrictions,
 * freshness, cost budgets, and optionally the goal digest and the Merkle plan root it authorizes. Each step is then admitted ONLY
 * as part of that committed DAG, and its inputs are proven from the signed receipts of earlier steps (the resource server signs a
 * receipt per executed step: outputs as value digests, optional integer values, labels). A receipt chain is the verifiable trace.
 *
 * {@link admitStep} is a TOTAL, PURE function: no clock, no store, no I/O. Everything unknown, malformed, unsigned, out of order
 * or unplanned DENIES; there is no heuristic. Only two things ESCALATE: a pipelined step whose promised input has no domain
 * constraint, and a label the step marks as "ask a human". Integers only (no floats).
 *
 * Signed under `atlas-pca/workflow/v1` + NUL (workflow) and `atlas-pca/wf-receipt/v1` + NUL (receipts); strict canonical JSON.
 * Shared vectors: packages/pca/conformance/workflow-vectors.json.
 */
import { b64u, canonicalBytesStrict, decodeB64uStrict, hashCanonical, utf8 } from './hash';
import { publicKeyOf, sign, verifyB64u } from './keys';

export const WORKFLOW_DOMAIN = 'atlas-pca/workflow/v1\0';
export const WF_RECEIPT_DOMAIN = 'atlas-pca/wf-receipt/v1\0';
const WF_REF = 'atlas-pca/workflow-ref/v1';
const WR_REF = 'atlas-pca/wf-receipt-ref/v1';
const VAL = 'atlas-pca/wf-value/v1';

export const WORKFLOW_LIMITS = { steps: 64, edges: 256, deps: 16, labels: 16, fields: 32, cost: 8, id: 64 } as const;

export type Scalar = string | number | boolean;
export interface WfStep {
  id: string;
  verb: string;
  resource: string;
  params_digest: string | null;
  deps: string[];
  sink: string | null;
  deny_labels: string[];
  escalate_labels: string[];
  fresh_ms: number | null;
  cost: Record<string, number>;
}
export type EdgeOp = 'eq' | 'le' | 'ge' | 'lt' | 'gt';
export interface WfEdge {
  from: { step: string; field: string };
  to: { step: string; param: string };
  op: EdgeOp;
  unit: string | null;
  deny_labels: string[];
  promise: string | null;
}
export interface WorkflowBody {
  v: 1;
  id: string;
  principal: string;
  goal_digest: string | null;
  plan_root: string | null;
  issued_at: number;
  expires_at: number;
  steps: WfStep[];
  edges: WfEdge[];
  budget: { max_steps: number; caps: Record<string, number> };
}
export interface SignedWorkflow {
  body: WorkflowBody;
  sig: string;
}
export interface WfOutput {
  digest: string;
  num: number | null;
  unit: string | null;
  labels: string[];
}
export interface WfReceipt {
  v: 1;
  wf: string;
  step: string;
  seq: number;
  prev: string | null;
  outcome: 'ok' | 'failed';
  params_digest: string;
  outputs: Record<string, WfOutput>;
  issued_at: number;
  signer: string;
  sig: string;
}

// ---- shared strict helpers (also used by readside.ts) ----------------------------------------------------------------------

/** Own-property lookup: a field named `constructor` or `__proto__` must never resolve through the prototype. */
export function own<T>(o: Record<string, T>, k: string): T | undefined {
  return Object.prototype.hasOwnProperty.call(o, k) ? o[k] : undefined;
}
export const isObj = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);
export const isUint = (n: unknown): n is number => typeof n === 'number' && Number.isSafeInteger(n) && n >= 0;
export const ID_RE = /^(?!__proto__$)[A-Za-z0-9_.:-]{1,64}$/;
export const LABEL_RE = /^(?!__proto__$)[a-z0-9_.:-]{1,64}$/;
export const NAME_RE = /^(?!__proto__$)[A-Za-z0-9_.-]{1,64}$/;
export const UNIT_RE = /^[A-Za-z0-9_.:-]{1,16}$/;
export const isStr = (x: unknown, max: number): x is string => typeof x === 'string' && x.length >= 1 && x.length <= max;
export const isB32 = (x: unknown): x is string => decodeB64uStrict(x, 32) !== null;
/** Strictly ascending (bytewise; all members are ASCII) with every member matching `re`. */
export function sortedUnique(x: unknown, re: RegExp, max: number): x is string[] {
  if (!Array.isArray(x) || x.length > max) return false;
  for (let i = 0; i < x.length; i++) {
    if (typeof x[i] !== 'string' || !re.test(x[i] as string)) return false;
    if (i > 0 && !((x[i - 1] as string) < (x[i] as string))) return false;
  }
  return true;
}
export const onlyKeys = (o: Record<string, unknown>, keys: readonly string[]): boolean => Object.keys(o).length === keys.length && keys.every((k) => k in o);
const dmsg = (domain: string, body: unknown): Uint8Array => {
  const d = utf8(domain);
  const b = canonicalBytesStrict(body);
  const o = new Uint8Array(d.length + b.length);
  o.set(d);
  o.set(b, d.length);
  return o;
};
/** True iff `sig` is a canonical 64-byte base64url Ed25519 signature by `signer` over exactly `domain || canonical(body)`. */
export function verifyBody(domain: string, body: unknown, signer: unknown, sig: unknown): boolean {
  try {
    return typeof signer === 'string' && typeof sig === 'string' && decodeB64uStrict(sig, 64) !== null && verifyB64u(signer, dmsg(domain, body), sig);
  } catch {
    return false;
  }
}
export const signBody = (secret: Uint8Array, domain: string, body: unknown): string => b64u(sign(secret, dmsg(domain, body)));

/** The digest of a scalar value as it appears in step receipts (domain separated, so a value digest is never a params digest). */
export const valueDigest = (v: Scalar): string => hashCanonical({ d: VAL, v });
const isScalar = (v: unknown): v is Scalar => typeof v === 'string' || typeof v === 'boolean' || (typeof v === 'number' && Number.isSafeInteger(v));
export const isScalarMap = (x: unknown): x is Record<string, Scalar> => isObj(x) && Object.keys(x).length <= WORKFLOW_LIMITS.fields && Object.entries(x).every(([k, v]) => NAME_RE.test(k) && isScalar(v));

// ---- validation -------------------------------------------------------------------------------------------------------------

const STEP_KEYS = ['id', 'verb', 'resource', 'params_digest', 'deps', 'sink', 'deny_labels', 'escalate_labels', 'fresh_ms', 'cost'];
const EDGE_KEYS = ['from', 'to', 'op', 'unit', 'deny_labels', 'promise'];
const BODY_KEYS = ['v', 'id', 'principal', 'goal_digest', 'plan_root', 'issued_at', 'expires_at', 'steps', 'edges', 'budget'];
const OPS = ['eq', 'le', 'ge', 'lt', 'gt'];
const nullOr = <T>(x: unknown, ok: (y: unknown) => y is T): boolean => x === null || ok(x);
const isId = (x: unknown): x is string => typeof x === 'string' && ID_RE.test(x);
const isName = (x: unknown): x is string => typeof x === 'string' && NAME_RE.test(x);
const isUnit = (x: unknown): x is string => typeof x === 'string' && UNIT_RE.test(x);
const uintMap = (x: unknown, max: number): x is Record<string, number> => isObj(x) && Object.keys(x).length <= max && Object.entries(x).every(([k, v]) => NAME_RE.test(k) && isUint(v));

function validStep(s: unknown): s is WfStep {
  if (!isObj(s) || !onlyKeys(s, STEP_KEYS)) return false;
  return (
    isId(s.id) && isStr(s.verb, 128) && isStr(s.resource, 512) && nullOr(s.params_digest, isB32) && sortedUnique(s.deps, ID_RE, WORKFLOW_LIMITS.deps) &&
    nullOr(s.sink, isId) && sortedUnique(s.deny_labels, LABEL_RE, WORKFLOW_LIMITS.labels) && sortedUnique(s.escalate_labels, LABEL_RE, WORKFLOW_LIMITS.labels) &&
    nullOr(s.fresh_ms, isUint) && uintMap(s.cost, WORKFLOW_LIMITS.cost)
  );
}
function validEdge(e: unknown): e is WfEdge {
  if (!isObj(e) || !onlyKeys(e, EDGE_KEYS)) return false;
  const f = e.from;
  const t = e.to;
  return (
    isObj(f) && onlyKeys(f, ['step', 'field']) && isId(f.step) && isName(f.field) && isObj(t) && onlyKeys(t, ['step', 'param']) && isId(t.step) && isName(t.param) &&
    typeof e.op === 'string' && OPS.includes(e.op) && nullOr(e.unit, isUnit) && sortedUnique(e.deny_labels, LABEL_RE, WORKFLOW_LIMITS.labels) && nullOr(e.promise, isId)
  );
}
/** Shape of the body only (no signature, no DAG semantics). */
export function validWorkflowBody(b: unknown): b is WorkflowBody {
  if (!isObj(b) || !onlyKeys(b, BODY_KEYS) || b.v !== 1) return false;
  if (!isId(b.id) || !isB32(b.principal) || !nullOr(b.goal_digest, isB32) || !nullOr(b.plan_root, isB32) || !isUint(b.issued_at) || !isUint(b.expires_at)) return false;
  if (!Array.isArray(b.steps) || b.steps.length === 0 || b.steps.length > WORKFLOW_LIMITS.steps || !b.steps.every(validStep)) return false;
  if (!Array.isArray(b.edges) || b.edges.length > WORKFLOW_LIMITS.edges || !b.edges.every(validEdge)) return false;
  const bg = b.budget;
  if (!isObj(bg) || !onlyKeys(bg, ['max_steps', 'caps']) || !isUint(bg.max_steps) || !uintMap(bg.caps, WORKFLOW_LIMITS.cost)) return false;
  // every cost name must be capped: an uncapped cost is a budget that silently does not exist
  return (b.steps as WfStep[]).every((s) => Object.keys(s.cost).every((k) => own(bg.caps as Record<string, number>, k) !== undefined));
}

/** DAG semantics: unique ids, deps exist, acyclic, every edge runs from a (transitive) dependency, promised edges name their domain. */
export function dagError(b: WorkflowBody): string | null {
  const ids = new Map<string, WfStep>();
  for (const s of b.steps) {
    if (ids.has(s.id)) return 'duplicate step id';
    ids.set(s.id, s);
  }
  for (const s of b.steps) for (const d of s.deps) if (d === s.id || !ids.has(d)) return 'bad dependency';
  const anc = ancestors(b);
  if (anc === null) return 'cycle';
  for (const e of b.edges) {
    if (!ids.has(e.from.step) || !ids.has(e.to.step) || !(anc.get(e.to.step) as Set<string>).has(e.from.step)) return 'edge does not follow a dependency';
  }
  return null;
}
/** step id -> the set of its transitive dependencies; null on a cycle. */
export function ancestors(b: WorkflowBody): Map<string, Set<string>> | null {
  const byId = new Map(b.steps.map((s) => [s.id, s] as const));
  const out = new Map<string, Set<string>>();
  const state = new Map<string, number>();
  const visit = (id: string): boolean => {
    if (state.get(id) === 2) return true;
    if (state.get(id) === 1) return false;
    state.set(id, 1);
    const set = new Set<string>();
    for (const d of (byId.get(id) as WfStep).deps) {
      if (!visit(d)) return false;
      set.add(d);
      for (const x of out.get(d) as Set<string>) set.add(x);
    }
    out.set(id, set);
    state.set(id, 2);
    return true;
  };
  for (const s of b.steps) if (!visit(s.id)) return null;
  return out;
}

// ---- commitment and receipts (reference signers) ------------------------------------------------------------------------------

export const workflowDigest = (b: WorkflowBody): string => hashCanonical({ d: WF_REF, w: b });
export const receiptRef = (r: WfReceipt): string => hashCanonical({ d: WR_REF, r });

/** Sign the workflow commitment. Throws on a body that is malformed or not a DAG. */
export function signWorkflow(secret: Uint8Array, body: WorkflowBody): SignedWorkflow {
  if (!validWorkflowBody(body) || dagError(body) !== null) throw new RangeError('signWorkflow: malformed workflow');
  if (body.principal !== b64u(publicKeyOf(secret))) throw new RangeError('signWorkflow: principal is not the signer');
  return { body, sig: signBody(secret, WORKFLOW_DOMAIN, body) };
}
const recBody = (r: Omit<WfReceipt, 'sig'>): Omit<WfReceipt, 'sig'> => ({ v: r.v, wf: r.wf, step: r.step, seq: r.seq, prev: r.prev, outcome: r.outcome, params_digest: r.params_digest, outputs: r.outputs, issued_at: r.issued_at, signer: r.signer });
/** Sign a step receipt (resource server). `prev` is the previous receipt of the same workflow, omitted for the first. */
export function signStepReceipt(secret: Uint8Array, o: { workflow: WorkflowBody; step: string; outcome: 'ok' | 'failed'; paramsDigest: string; outputs: Record<string, WfOutput>; issuedAt: number; prev?: WfReceipt }): WfReceipt {
  const base = { v: 1 as const, wf: workflowDigest(o.workflow), step: o.step, seq: o.prev ? o.prev.seq + 1 : 0, prev: o.prev ? receiptRef(o.prev) : null, outcome: o.outcome, params_digest: o.paramsDigest, outputs: o.outputs, issued_at: o.issuedAt, signer: b64u(publicKeyOf(secret)) };
  return { ...base, sig: signBody(secret, WF_RECEIPT_DOMAIN, recBody(base)) };
}
/** A receipt output for `value`; `num` is carried only for integers an edge may compare. */
export function wfOutput(value: Scalar, o: { labels?: string[]; unit?: string; num?: boolean } = {}): WfOutput {
  return { digest: valueDigest(value), num: o.num === true && typeof value === 'number' ? value : null, unit: o.unit ?? null, labels: [...(o.labels ?? [])].sort() };
}

function validReceiptShape(r: unknown): r is WfReceipt {
  if (!isObj(r) || !onlyKeys(r, ['v', 'wf', 'step', 'seq', 'prev', 'outcome', 'params_digest', 'outputs', 'issued_at', 'signer', 'sig']) || r.v !== 1) return false;
  if (!isB32(r.wf) || !isId(r.step) || !isUint(r.seq) || !nullOr(r.prev, isB32) || (r.seq === 0) !== (r.prev === null) || (r.outcome !== 'ok' && r.outcome !== 'failed')) return false;
  if (!isB32(r.params_digest) || !isUint(r.issued_at) || !isB32(r.signer) || typeof r.sig !== 'string') return false;
  const o = r.outputs;
  if (!isObj(o) || Object.keys(o).length > WORKFLOW_LIMITS.fields) return false;
  return Object.entries(o).every(([k, v]) => NAME_RE.test(k) && isObj(v) && onlyKeys(v, ['digest', 'num', 'unit', 'labels']) && isB32(v.digest) && nullOr(v.num, isUint) && nullOr(v.unit, isUnit) && sortedUnique(v.labels, LABEL_RE, WORKFLOW_LIMITS.labels));
}

// ---- admission ---------------------------------------------------------------------------------------------------------------

export type K5Decision = 'allow' | 'deny' | 'escalate';
export interface WfResult {
  decision: K5Decision;
  code: string | null;
  step: string | null;
  /** index of the offending receipt (receipt-chain failures) */
  at: number | null;
  /** edge indexes whose source receipt does not exist yet (promise pipelining); each is re-checked by {@link bindPromises} */
  pending: number[];
}
export interface WfRequest {
  step: string;
  verb: string;
  resource: string;
  params: Record<string, Scalar>;
  units: Record<string, string>;
  goal_digest: string | null;
  plan_root: string | null;
}
export interface AdmitInput {
  workflow: unknown;
  /** the principal key the verifier pinned: a key named inside the workflow is never trusted */
  principal: string;
  /** the resource-server key the verifier pinned for step receipts */
  rsSigner: string;
  receipts: unknown[];
  now: number;
  request: unknown;
}
/**
 * Is `workflow` a well-formed, acyclic commitment signed by the pinned `principal` and valid at `now`? Returns the refusal code
 * (the same codes as {@link admitStep}) or null. Used by issuers of step receipts, which must not sign for a workflow they would refuse.
 */
export function workflowCommitmentError(workflow: unknown, principal: string, now: number): 'bad_workflow' | 'bad_dag' | 'bad_signature' | 'not_yet' | 'expired' | null {
  const sw = workflow as SignedWorkflow;
  if (!isObj(sw) || !onlyKeys(sw, ['body', 'sig']) || !validWorkflowBody(sw.body) || !isB32(principal) || !isUint(now)) return 'bad_workflow';
  if (dagError(sw.body) !== null) return 'bad_dag';
  if (sw.body.principal !== principal || !verifyBody(WORKFLOW_DOMAIN, sw.body, principal, sw.sig)) return 'bad_signature';
  if (now < sw.body.issued_at) return 'not_yet';
  if (now >= sw.body.expires_at) return 'expired';
  return null;
}
const res = (decision: K5Decision, code: string | null, step: string | null, at: number | null = null, pending: number[] = []): WfResult => ({ decision, code, step, at, pending });
const deny = (code: string, step: string | null = null, at: number | null = null): WfResult => res('deny', code, step, at);

/** Is `root` the Merkle plan root this signed, unexpired, pinned-principal workflow authorizes? (`plan_root_authorized`). */
export function planRootAuthorized(workflow: unknown, principal: string, now: number, root: string): boolean {
  const w = workflow as SignedWorkflow;
  return isObj(w) && validWorkflowBody(w.body) && dagError(w.body) === null && w.body.principal === principal && verifyBody(WORKFLOW_DOMAIN, w.body, principal, w.sig) && now >= w.body.issued_at && now < w.body.expires_at && w.body.plan_root === root;
}

const validRequest = (r: unknown): r is WfRequest =>
  isObj(r) && onlyKeys(r, ['step', 'verb', 'resource', 'params', 'units', 'goal_digest', 'plan_root']) && isId(r.step) && isStr(r.verb, 128) && isStr(r.resource, 512) && isScalarMap(r.params) &&
  isObj(r.units) && Object.entries(r.units).every(([k, v]) => NAME_RE.test(k) && isUnit(v)) && nullOr(r.goal_digest, isB32) && nullOr(r.plan_root, isB32);

/** Check the receipt chain against the workflow. Returns the offending index, or null. Exported for issuers of step receipts. */
export function workflowReceiptError(w: WorkflowBody, rsSigner: string, receipts: unknown[], now: number): { at: number } | null {
  return receiptError(w, rsSigner, receipts, now);
}
function receiptError(w: WorkflowBody, rsSigner: string, receipts: unknown[], now: number): { at: number } | null {
  const wd = workflowDigest(w);
  const byId = new Map(w.steps.map((s) => [s.id, s] as const));
  const index = new Map<string, number>();
  let prev: WfReceipt | null = null;
  for (let i = 0; i < receipts.length; i++) {
    const r = receipts[i];
    if (!validReceiptShape(r) || r.signer !== rsSigner || r.wf !== wd || r.seq !== i || r.issued_at > now) return { at: i };
    if (!byId.has(r.step) || index.has(r.step)) return { at: i };
    if ((prev === null ? r.prev !== null : r.prev !== receiptRef(prev)) || !verifyBody(WF_RECEIPT_DOMAIN, recBody(r), rsSigner, r.sig)) return { at: i };
    // a receipt may precede one of its dependencies' receipts only when every edge from that dependency is a declared promise
    for (const d of (byId.get(r.step) as WfStep).deps) {
      if (index.has(d)) continue;
      const es = w.edges.filter((e) => e.from.step === d && e.to.step === r.step);
      if (es.length === 0 || es.some((e) => e.promise === null)) return { at: i };
    }
    index.set(r.step, i);
    prev = r;
  }
  return null;
}

function evaluate(inp: AdmitInput, bind: boolean): WfResult {
  const sw = inp.workflow as SignedWorkflow;
  if (!isObj(sw) || !onlyKeys(sw, ['body', 'sig']) || !validWorkflowBody(sw.body) || !validRequest(inp.request) || !Array.isArray(inp.receipts) || !isB32(inp.principal) || !isB32(inp.rsSigner) || !isUint(inp.now)) return deny('bad_workflow');
  const w = sw.body;
  const q = inp.request;
  const err = dagError(w);
  if (err !== null) return deny('bad_dag', q.step);
  if (w.principal !== inp.principal || !verifyBody(WORKFLOW_DOMAIN, w, inp.principal, sw.sig)) return deny('bad_signature', q.step);
  if (inp.now < w.issued_at) return deny('not_yet', q.step);
  if (inp.now >= w.expires_at) return deny('expired', q.step);
  if (q.goal_digest !== w.goal_digest) return deny('goal_mismatch', q.step);
  if (q.plan_root !== w.plan_root) return deny('plan_root_mismatch', q.step);
  const bad = receiptError(w, inp.rsSigner, inp.receipts, inp.now);
  if (bad !== null) return deny('bad_receipt', q.step, bad.at);
  const rec = new Map<string, WfReceipt>((inp.receipts as WfReceipt[]).map((r) => [r.step, r] as const));
  const step = w.steps.find((s) => s.id === q.step);
  if (step === undefined) return deny('unplanned_step', q.step);
  if (step.verb !== q.verb || step.resource !== q.resource) return deny('step_mismatch', q.step);
  const pd = hashCanonical(q.params);
  if (step.params_digest !== null && step.params_digest !== pd) return deny('params_mismatch', q.step);
  const mine = rec.get(step.id);
  if (bind) {
    if (mine === undefined || mine.params_digest !== pd) return deny('params_mismatch', q.step);
  } else {
    if (mine !== undefined) return deny('already_done', q.step);
    const done = inp.receipts as WfReceipt[];
    if (done.length + 1 > w.budget.max_steps) return deny('budget_exceeded', q.step);
    for (const [name, cap] of Object.entries(w.budget.caps)) {
      const spent = done.reduce((a, r) => a + (own((w.steps.find((s) => s.id === r.step) as WfStep).cost, name) ?? 0), 0) + (own(step.cost, name) ?? 0);
      if (spent > cap) return deny('budget_exceeded', q.step);
    }
  }
  // dependencies
  const pending: number[] = [];
  let unconstrained = false;
  for (const d of step.deps) {
    const dr = rec.get(d);
    if (dr === undefined) {
      const es = w.edges.map((e, i) => [e, i] as const).filter(([e]) => e.from.step === d && e.to.step === step.id);
      if (bind || es.length === 0) return deny('deps_unmet', q.step);
      if (es.some(([e]) => e.promise === null)) unconstrained = true;
      continue;
    }
    if (dr.outcome !== 'ok') return deny('dep_failed', q.step);
    if (step.fresh_ms !== null && inp.now - dr.issued_at > step.fresh_ms) return deny('stale_dep', q.step);
  }
  // edge constraints
  for (let i = 0; i < w.edges.length; i++) {
    const e = w.edges[i] as WfEdge;
    if (e.to.step !== step.id) continue;
    const src = rec.get(e.from.step);
    if (src === undefined) {
      pending.push(i);
      continue;
    }
    const out = own(src.outputs, e.from.field);
    const val = own(q.params, e.to.param);
    if (out === undefined || val === undefined) return deny('edge_missing', q.step, i);
    if (out.unit !== (own(q.units, e.to.param) ?? null) || out.unit !== e.unit) return deny('edge_unit', q.step, i);
    if (e.op === 'eq') {
      if (valueDigest(val) !== out.digest) return deny('edge_digest', q.step, i);
    } else {
      if (typeof val !== 'number' || out.num === null) return deny('edge_value', q.step, i);
      const ok = e.op === 'le' ? val <= out.num : e.op === 'ge' ? val >= out.num : e.op === 'lt' ? val < out.num : val > out.num;
      if (!ok) return deny('edge_relation', q.step, i);
    }
    if (out.labels.some((l) => e.deny_labels.includes(l))) return deny('taint_flow', q.step, i);
  }
  if (bind && pending.length > 0) return deny('deps_unmet', q.step);
  // taint across the DAG: every label any executed ancestor produced
  const anc = ancestors(w) as Map<string, Set<string>>;
  const inherited = new Set<string>();
  for (const a of anc.get(step.id) as Set<string>) for (const o of Object.values(rec.get(a)?.outputs ?? {})) for (const l of o.labels) inherited.add(l);
  if (step.deny_labels.some((l) => inherited.has(l))) return deny('taint_flow', q.step);
  if (unconstrained) return res('escalate', 'pipeline_unconstrained', q.step);
  if (step.escalate_labels.some((l) => inherited.has(l))) return res('escalate', 'taint_escalate', q.step);
  return res('allow', null, q.step, null, pending);
}

/** Admit ONE step of the committed workflow, or deny / escalate. See the module header. */
export function admitStep(inp: AdmitInput): WfResult {
  try {
    return evaluate(inp, false);
  } catch {
    return deny('bad_workflow');
  }
}
/**
 * Promise binding (post hoc): the step already has its receipt; its params are re-checked against every edge now that all of its
 * dependencies' receipts exist. A pipelined step whose promise turns out wrong is a violation (the caller revokes / compensates).
 */
export function bindPromises(inp: AdmitInput): WfResult {
  try {
    return evaluate(inp, true);
  } catch {
    return deny('bad_workflow');
  }
}
