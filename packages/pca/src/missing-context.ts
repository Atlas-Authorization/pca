import { evaluateConditionTri, isGroupCondition, resolvePath, type ActionContext, type Condition, type Tri } from './predicates';
import { hashCanonical } from './hash';
import type { Decision } from './decision';

/**
 * TYPED MISSING CONTEXT (SpiceDB's CONDITIONAL made actionable and safe for agents) AND THE STORED-WINS RULE.
 *
 * When a permit condition cannot be decided because a value is absent, the verifier does not guess and does not allow: it names
 * what is missing and WHO may supply it. {@link MissingContext}`.supplier` is one of
 *   principal                  the principal can answer (an escalation to them);
 *   discharge_issuer           a pinned third party can sign a discharge for it;
 *   rs_observation             the resource server can observe it (it loops internally, no escalation);
 *   agent_declared_untrusted   only the agent could say it: such a value can never feed a permit condition.
 * The decision is therefore typed, never a silent allow:
 *   - condition true                                   -> allow
 *   - condition false                                  -> deny `condition_false`
 *   - undecidable, every missing path suppliable       -> escalate `escalate: missing_context <supplier>:<path>,...`
 *   - undecidable, any missing path is agent-only      -> deny `missing_context_untrusted: <path>,...`
 *   - undecidable for a reason other than absence      -> deny `ill_typed_context` (a present value of the wrong type)
 *   - the request supplied a value differing from one bound in the grant or chain -> deny `context_shadow: <path>,...`
 *   - the bound context is not an object with an `action` object                    -> deny `bad_context`
 *
 * STORED WINS: {@link bindContext} merges request-supplied context into the context bound by the grant or chain. A supplied value
 * never replaces a bound one (a supplied value that DIFFERS from a bound one is reported as a conflict and the call is refused:
 * the confused-deputy attempt). A supplied value for an `agent_declared_untrusted` path is dropped. Only `subject`, `env` and
 * `action.params` are mergeable; the verb and resource are never taken from the request side.
 *
 * Total; never throws; every malformed input is a deny.
 */
export const SUPPLIERS = ['principal', 'discharge_issuer', 'rs_observation', 'agent_declared_untrusted'] as const;
export type Supplier = (typeof SUPPLIERS)[number];
export interface MissingContext { path: string; supplier: Supplier }
/** Path (or prefix) -> who may supply it. The longest matching prefix wins; a path matching nothing is `principal`. */
export type SupplierTable = Readonly<Record<string, Supplier>>;

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && [Object.prototype, null].includes(Object.getPrototypeOf(v));
const has = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);
const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);

export function supplierOf(path: string, table: SupplierTable): Supplier {
  let best: string | undefined;
  for (const k of Object.keys(table)) if ((path === k || path.startsWith(`${k}.`)) && (best === undefined || k.length > best.length)) best = k;
  return best === undefined ? 'principal' : (table[best] as Supplier);
}
export function supplierTableError(t: unknown): string | null {
  if (!isObj(t)) return 'the supplier table must be an object';
  for (const [k, v] of Object.entries(t)) {
    if (!/^(action\.params|subject|env)(\.[A-Za-z_][A-Za-z0-9_]*)*$/.test(k) || k.split('.').some((s) => FORBIDDEN.has(s))) return `bad supplier path '${k}'`;
    if (typeof v !== 'string' || !(SUPPLIERS as readonly string[]).includes(v)) return `bad supplier for '${k}'`;
  }
  return null;
}

type Ctx = { action?: { params?: Record<string, unknown> } & Record<string, unknown>; subject?: Record<string, unknown>; env?: Record<string, unknown> };

/** Flatten a plain-object tree into dotted leaf paths. Arrays and non-plain values are leaves. */
function leaves(v: unknown, prefix: string, out: Map<string, unknown>, depth = 0): void {
  if (depth > 16) { out.set(prefix, v); return; }
  if (isObj(v) && Object.keys(v).length > 0) { for (const k of Object.keys(v).sort()) if (!FORBIDDEN.has(k)) leaves(v[k], `${prefix}.${k}`, out, depth + 1); } else out.set(prefix, v);
}
function setPath(root: Record<string, unknown>, segs: string[], value: unknown): void {
  let cur = root;
  for (let i = 0; i < segs.length - 1; i++) {
    const s = segs[i] as string;
    if (!has(cur, s) || !isObj(cur[s])) cur[s] = {};
    cur = cur[s] as Record<string, unknown>;
  }
  cur[segs[segs.length - 1] as string] = value;
}

export interface BoundContext { context: ActionContext; conflicts: string[]; dropped: string[] }

/** Merge request-supplied context into the bound context. Bound wins; see the module comment. */
export function bindContext(bound: ActionContext, supplied: Ctx | undefined, table: SupplierTable = {}): BoundContext {
  const ctx = structuredClone(bound) as ActionContext & Record<string, unknown>;
  const conflicts: string[] = [];
  const dropped: string[] = [];
  if (!isObj(supplied)) return { context: ctx, conflicts, dropped };
  const flat = new Map<string, unknown>();
  if (isObj(supplied.action) && isObj(supplied.action.params)) leaves(supplied.action.params, 'action.params', flat);
  if (isObj(supplied.subject)) leaves(supplied.subject, 'subject', flat);
  if (isObj(supplied.env)) leaves(supplied.env, 'env', flat);
  for (const [path, value] of [...flat.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    if (supplierOf(path, table) === 'agent_declared_untrusted') { dropped.push(path); continue; }
    const r = resolvePath(ctx, path);
    if (r.found) {
      if (hashCanonical({ v: r.value ?? null }) !== hashCanonical({ v: value ?? null })) conflicts.push(path);
      continue;
    }
    const segs = path.split('.');
    let blocked = false;
    for (let i = 2; i < segs.length; i++) {
      const r2 = resolvePath(ctx, segs.slice(0, i).join('.'));
      if (r2.found && !isObj(r2.value)) blocked = true; // a bound leaf sits above the supplied path: writing it would replace the bound value
    }
    if (blocked) { conflicts.push(path); continue; }
    if (path.startsWith('action.params')) {
      const a = (ctx.action ?? { verb: '', resource: '' }) as Record<string, unknown>;
      if (!isObj(a.params)) a.params = {};
      ctx.action = a as never;
    }
    setPath(ctx as unknown as Record<string, unknown>, path.split('.'), structuredClone(value));
  }
  return { context: ctx, conflicts, dropped };
}

function collect(c: Condition, ctx: ActionContext, out: Set<string>, ill: { v: boolean }, depth = 0): void {
  if (depth > 64 || c === null || typeof c !== 'object') { ill.v = true; return; }
  if (isGroupCondition(c)) {
    const kids = 'all_of' in c ? c.all_of : 'any_of' in c ? c.any_of : [c.not];
    if (!Array.isArray(kids) || kids.length === 0) { ill.v = true; return; }
    for (const k of kids) collect(k, ctx, out, ill, depth + 1);
    return;
  }
  if (evaluateConditionTri(c, ctx) !== 'unknown') return;
  let absent = false;
  for (const p of [c.field, c.ref]) if (typeof p === 'string' && p.length > 0 && !resolvePath(ctx, p).found) { out.add(p); absent = true; }
  if (c.field === 'action.params' || (typeof c.field === 'string' && c.field.startsWith('action.params.'))) {
    const p = ctx?.action?.params;
    if (p === undefined || p === null || typeof p !== 'object') { out.add(c.field); absent = true; }
  }
  if (!absent) ill.v = true;
}

export interface TypedDecision {
  decision: Decision;
  reason?: string;
  missing: MissingContext[];
}

/** Decide a permit condition list (implicit AND) over the bound context plus whatever the request supplied. */
export function decideWithMissing(input: { where: unknown; bound: ActionContext; supplied?: Ctx; suppliers?: SupplierTable }): TypedDecision {
  const deny = (reason: string, missing: MissingContext[] = []): TypedDecision => ({ decision: 'deny', reason, missing });
  try {
    if (!isObj(input.bound) || !isObj((input.bound as { action?: unknown }).action)) return deny('bad_context');
    const table = input.suppliers ?? {};
    const te = supplierTableError(table);
    if (te) return deny(`bad supplier table: ${te}`);
    if (!Array.isArray(input.where) || input.where.length === 0) return deny('condition_false');
    const { context, conflicts } = bindContext(input.bound, input.supplied, table);
    if (conflicts.length > 0) return deny(`context_shadow: ${conflicts.join(',')}`);
    const t: Tri = evaluateConditionTri({ all_of: input.where as Condition[] }, context);
    if (t === 'true') return { decision: 'allow', missing: [] };
    if (t === 'false') return deny('condition_false');
    const paths = new Set<string>();
    const ill = { v: false };
    for (const c of input.where as Condition[]) collect(c, context, paths, ill);
    if (paths.size === 0 || ill.v) return deny('ill_typed_context');
    const missing = [...paths].sort().map((path): MissingContext => ({ path, supplier: supplierOf(path, table) }));
    const untrusted = missing.filter((m) => m.supplier === 'agent_declared_untrusted');
    if (untrusted.length > 0) return deny(`missing_context_untrusted: ${untrusted.map((m) => m.path).join(',')}`, missing);
    return { decision: 'escalate', reason: `escalate: missing_context ${missing.map((m) => `${m.supplier}:${m.path}`).join(',')}`, missing };
  } catch {
    return deny('evaluation error (fail closed)');
  }
}
