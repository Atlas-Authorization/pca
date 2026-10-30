import { evaluateConditionTri, type Condition } from './predicates';
import { compareUtf8, canonicalizeStrict } from './hash';
import { pepDecision, type Decision } from './decision';

/**
 * DECISION OBLIGATIONS (XACML 3.0 core, section 7.2: a PEP permits a decision that carries obligations "only if it understands
 * and it can and will discharge those obligations"). An `allow` may carry obligations: things the policy enforcement point (PEP)
 * must do for the action to proceed. The rule that makes it safe is the deny-biased PEP of section 7.2.2:
 *
 *   A PEP that cannot perform every obligation on an `allow` turns the allow into a `deny`.
 *
 * {@link pepObligationGate} is the one way to turn (decision, obligations, supported kinds) into an outcome, and an unknown or unsupported kind, a malformed list or a malformed `supported` set all deny. Obligations ride on
 * allow only: a `deny` or an unanswered `escalate` is never softened by them, and an obligation can never turn a refusal into
 * an allow. An obligation not met by its `due` time yields {@link obligationOutcome} `escalate` (freeze or step-up), never a
 * retroactive allow.
 *
 * VOCABULARY (closed; every parameter is validated; an unknown kind or member is malformed):
 *   log             {sink?}            write the decision to the named audit sink (default sink when absent)
 *   notify          {to}               tell a named channel or principal that the action happened
 *   redact          {fields[]}         remove these response fields (dotted paths) before returning to the caller
 *   watermark       {id}               mark the output with this id
 *   require_receipt {}                 the PEP must obtain and keep an execution receipt for the action
 *   undo_window     {id, window_end}   the action runs under a veto window (undo ledger record `id`, open until
 *                                      `window_end`): the PEP reports the effect and lets the window run (undo-windows.md)
 * Each may carry `due` (epoch ms): the time by which it must be reported fulfilled.
 *
 * Everything here is total and never throws. Natives implement exactly these functions (conformance `obligations-vectors.json`).
 */
export const OBLIGATION_KINDS = ['log', 'notify', 'redact', 'watermark', 'require_receipt', 'undo_window'] as const;
export type ObligationKind = (typeof OBLIGATION_KINDS)[number];
export const MAX_OBLIGATIONS = 16;
const MAX_REDACT_FIELDS = 32;
const FIELD_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}(\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,7}$/;

export interface Obligation {
  kind: ObligationKind;
  params?: Record<string, unknown>;
  /** Epoch ms by which the obligation must be reported fulfilled. */
  due?: number;
}

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && [Object.prototype, null].includes(Object.getPrototypeOf(v));
const isStr = (v: unknown, max: number): v is string => typeof v === 'string' && v.length > 0 && v.length <= max;
const own = (o: Record<string, unknown>, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);

function paramsError(kind: ObligationKind, p: Record<string, unknown>): string | null {
  const allowed: Record<ObligationKind, readonly string[]> = { log: ['sink'], notify: ['to'], redact: ['fields'], watermark: ['id'], require_receipt: [], undo_window: ['id', 'window_end'] };
  for (const k of Object.keys(p)) if (!allowed[kind].includes(k)) return `unknown parameter '${k}' for '${kind}'`;
  if (kind === 'log' && own(p, 'sink') && !isStr(p.sink, 128)) return "log.sink must be a non-empty string of at most 128 characters";
  if (kind === 'notify' && !isStr(p.to, 256)) return 'notify.to is required (a non-empty string of at most 256 characters)';
  if (kind === 'watermark' && !isStr(p.id, 128)) return 'watermark.id is required (a non-empty string of at most 128 characters)';
  if (kind === 'undo_window' && (!isStr(p.id, 128) || !(typeof p.window_end === 'number' && Number.isSafeInteger(p.window_end) && p.window_end >= 0))) return 'undo_window needs id (a non-empty string of at most 128 characters) and window_end (a non-negative safe integer)';
  if (kind === 'redact') {
    const f = p.fields;
    if (!Array.isArray(f) || f.length === 0 || f.length > MAX_REDACT_FIELDS || !f.every((x) => typeof x === 'string' && FIELD_RE.test(x))) return 'redact.fields must be 1..32 dotted field paths';
    if (new Set(f).size !== f.length) return 'redact.fields has a duplicate';
  }
  return null;
}

/** Null = well formed. */
export function obligationError(o: unknown): string | null {
  if (!isObj(o)) return 'an obligation must be an object';
  for (const k of Object.keys(o)) if (k !== 'kind' && k !== 'params' && k !== 'due') return `unknown member '${k}'`;
  if (typeof o.kind !== 'string' || !(OBLIGATION_KINDS as readonly string[]).includes(o.kind)) return `unknown obligation kind '${String(o.kind)}'`;
  if (own(o, 'due') && !(typeof o.due === 'number' && Number.isSafeInteger(o.due) && o.due >= 0)) return 'due must be a non-negative safe integer';
  const p = own(o, 'params') ? o.params : {};
  if (!isObj(p)) return 'params must be an object';
  return paramsError(o.kind as ObligationKind, p);
}

/** Null = a well-formed, duplicate-free list of at most {@link MAX_OBLIGATIONS}. Absent (`undefined`) is the empty list. */
export function obligationsError(list: unknown): string | null {
  if (list === undefined) return null;
  if (!Array.isArray(list)) return 'obligations must be an array';
  if (list.length > MAX_OBLIGATIONS) return `more than ${MAX_OBLIGATIONS} obligations`;
  const seen = new Set<string>();
  for (const [i, o] of list.entries()) {
    const e = obligationError(o);
    if (e) return `obligations[${i}]: ${e}`;
    const key = obligationKey(o as Obligation);
    if (seen.has(key)) return `obligations[${i}] duplicates an earlier obligation`;
    seen.add(key);
  }
  return null;
}

/** The canonical identity of an obligation (kind, parameters, due): equal keys are the same obligation. */
export function obligationKey(o: Obligation): string {
  return canonicalizeStrict({ kind: o.kind, params: o.params ?? {}, ...(o.due !== undefined ? { due: o.due } : {}) });
}

export type MergeResult = { ok: true; obligations: Obligation[] } | { ok: false; reason: string };

/**
 * The union of obligation lists (policy classes, chain levels, rules): deduplicated by {@link obligationKey}, sorted by key in
 * UTF-8 byte order so the result does not depend on the order the lists arrive in. A malformed input or a result over the limit
 * is a refusal. Union only ever adds obligations, so merging can only tighten.
 */
export function mergeObligations(...lists: readonly unknown[]): MergeResult {
  try {
    const by = new Map<string, Obligation>();
    for (const l of lists) {
      const e = obligationsError(l);
      if (e) return { ok: false, reason: e };
      for (const o of (l ?? []) as Obligation[]) by.set(obligationKey(o), o);
    }
    if (by.size > MAX_OBLIGATIONS) return { ok: false, reason: `more than ${MAX_OBLIGATIONS} obligations after merging` };
    return { ok: true, obligations: [...by.entries()].sort(([a], [b]) => compareUtf8(a, b)).map(([, o]) => o) };
  } catch {
    return { ok: false, reason: 'evaluation error (fail closed)' };
  }
}

export interface ObligationRule {
  id: string;
  when: Condition;
  obligations: Obligation[];
}

/**
 * Policy-side collection: the obligations of every rule whose `when` is true OR cannot be decided (a missing value adds the
 * obligations: more duties is the tightening direction). A malformed rule list or obligation list is a refusal.
 */
export function collectObligations(rules: unknown, ctx: { action?: unknown; subject?: unknown; env?: unknown }): MergeResult {
  try {
    if (rules === undefined) return { ok: true, obligations: [] };
    if (!Array.isArray(rules)) return { ok: false, reason: 'obligation rules must be an array' };
    const lists: Obligation[][] = [];
    const ids = new Set<string>();
    for (const [i, r] of rules.entries()) {
      if (!isObj(r) || !isStr(r.id, 64) || !isObj(r.when) || Object.keys(r).some((k) => k !== 'id' && k !== 'when' && k !== 'obligations')) return { ok: false, reason: `obligation rule ${i} is malformed` };
      if (ids.has(r.id)) return { ok: false, reason: `obligation rule id '${r.id}' is a duplicate` };
      ids.add(r.id);
      const e = obligationsError(r.obligations);
      if (e || !Array.isArray(r.obligations) || r.obligations.length === 0) return { ok: false, reason: `obligation rule '${r.id}': ${e ?? 'obligations must not be empty'}` };
      if (evaluateConditionTri(r.when as unknown as Condition, ctx as never) !== 'false') lists.push(r.obligations as Obligation[]);
    }
    return mergeObligations(...lists);
  } catch {
    return { ok: false, reason: 'evaluation error (fail closed)' };
  }
}

export interface GateResult {
  /** The effective decision after the answer (if any) and the obligation rule. */
  decision: Decision;
  /** On `allow`: the obligations the PEP must now perform and report. */
  perform: Obligation[];
  /** Kinds on the decision the PEP does not support (the reason an allow became a deny). */
  unsupported: string[];
  reason?: string;
}

/**
 * The PEP rule. `supported` is the set of kinds this PEP performs (its discovery `obligations_supported`). An `allow` (or an
 * `escalate` carrying a verified answer) with any obligation outside `supported` is a `deny`; so is any malformed obligation
 * list or `supported` set. A `deny` and an unanswered `escalate` pass through unchanged with nothing to perform.
 */
export function pepObligationGate(decision: Decision, answered: boolean, obligations: unknown, supported: unknown): GateResult {
  try {
    const eff = pepDecision(decision, answered);
    if (eff !== 'allow') return { decision: eff === 'escalate' ? 'escalate' : 'deny', perform: [], unsupported: [] };
    const e = obligationsError(obligations);
    if (e) return { decision: 'deny', perform: [], unsupported: [], reason: `malformed obligations: ${e}` };
    if (!Array.isArray(supported) || !supported.every((s) => typeof s === 'string')) return { decision: 'deny', perform: [], unsupported: [], reason: 'the supported obligation kinds are malformed' };
    const list = (obligations ?? []) as Obligation[];
    const missing = [...new Set(list.map((o) => o.kind).filter((k) => !supported.includes(k)))].sort(compareUtf8);
    if (missing.length > 0) return { decision: 'deny', perform: [], unsupported: missing, reason: `the enforcement point does not support obligation(s) ${missing.join(', ')}` };
    return { decision: 'allow', perform: list, unsupported: [] };
  } catch {
    return { decision: 'deny', perform: [], unsupported: [], reason: 'evaluation error (fail closed)' };
  }
}

export interface OutcomeResult {
  /** `ok`: nothing overdue. `escalate`: at least one obligation is overdue and unreported. */
  outcome: 'ok' | 'escalate';
  /** Indexes into the obligation list that are overdue (due <= now, not in `fulfilled`). */
  overdue: number[];
  /** Present on `escalate`: `obligation_unmet`, the receipt status. */
  status?: 'obligation_unmet';
}

/**
 * After the action: which obligations are overdue? `fulfilled` is the set of indexes the PEP reported. An overdue obligation
 * is `obligation_unmet` and the outcome is `escalate` (the holder is frozen or asked to step up); it never turns into an allow
 * and never rewrites the decision that was already made. A malformed input is overdue-everything (escalate).
 */
export function obligationOutcome(obligations: unknown, fulfilled: unknown, now: unknown): OutcomeResult {
  try {
    const list = (obligations ?? []) as Obligation[];
    const bad = obligationsError(obligations) !== null || !Array.isArray(fulfilled) || !fulfilled.every((i) => Number.isSafeInteger(i) && (i as number) >= 0) || !(typeof now === 'number' && Number.isSafeInteger(now) && now >= 0);
    if (bad) return { outcome: 'escalate', overdue: Array.isArray(list) ? list.map((_, i) => i) : [], status: 'obligation_unmet' };
    const done = new Set(fulfilled as number[]);
    const overdue = list.flatMap((o, i) => (o.due !== undefined && o.due <= (now as number) && !done.has(i) ? [i] : []));
    return overdue.length > 0 ? { outcome: 'escalate', overdue, status: 'obligation_unmet' } : { outcome: 'ok', overdue: [] };
  } catch {
    return { outcome: 'escalate', overdue: [], status: 'obligation_unmet' };
  }
}
