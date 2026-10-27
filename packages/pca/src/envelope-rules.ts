/**
 * Validation of the envelope's `units` (rule 20) and `tighten` (rule 21) members. Part of PCA Core (the envelope is core), so
 * it imports nothing from the intent layer; `decision.ts` (the intent layer) re-exports it.
 */
import type { Condition } from './predicates';

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && [Object.prototype, null].includes(Object.getPrototypeOf(v));
const isSafeInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0);
const NAME_RE = /^[a-z][a-z0-9_]{0,63}$/;
function closedMembers(o: Record<string, unknown>, required: readonly string[], optional: readonly string[], where: string): string | null {
  for (const k of Object.keys(o)) if (!required.includes(k) && !optional.includes(k)) return `unknown member '${where}.${k}'`;
  for (const k of required) if (!Object.prototype.hasOwnProperty.call(o, k)) return `missing member '${where}.${k}'`;
  return null;
}

/** One `tighten[]` entry: when `when` holds (or cannot be decided), the decision is capped at `signal`. */
export interface TightenRule {
  id: string;
  when: Condition;
  signal: 'escalate' | 'deny';
  reason?: string;
}

export const MAX_TIGHTEN_RULES = 64;

/** Null = well-formed. A closed list of `{id, when, signal}` (`reason` optional); ids match the name pattern and are distinct. */
export function tightenListError(t: unknown): string | null {
  if (t === undefined) return null;
  if (!Array.isArray(t)) return 'tighten must be an array';
  if (t.length > MAX_TIGHTEN_RULES) return `tighten has more than ${MAX_TIGHTEN_RULES} rules`;
  const ids = new Set<string>();
  for (const [i, r] of t.entries()) {
    if (!isObj(r)) return `tighten[${i}] must be an object`;
    const e = closedMembers(r, ['id', 'when', 'signal'], ['reason'], `tighten[${i}]`);
    if (e) return e;
    if (typeof r.id !== 'string' || !NAME_RE.test(r.id)) return `tighten[${i}].id must match ${NAME_RE.source}`;
    if (ids.has(r.id)) return `tighten[${i}].id '${r.id}' is a duplicate`;
    ids.add(r.id);
    if (!isObj(r.when)) return `tighten[${i}].when must be a condition object`;
    if (r.signal !== 'escalate' && r.signal !== 'deny') return `tighten[${i}].signal must be 'escalate' or 'deny'`;
    if (r.reason !== undefined && (typeof r.reason !== 'string' || r.reason.length > 256)) return `tighten[${i}].reason must be a string of at most 256 characters`;
  }
  return null;
}

/** A unit tag: the shape of a schema `units` entry. */
export interface UnitTag {
  kind: string;
  currency?: string;
  exponent?: number;
}

export const PARAM_PATH_RE = /^action\.params\.[A-Za-z0-9_-]{1,64}$/;

/** Null = well-formed policy unit tags: `{ 'action.params.<name>': {kind, currency?, exponent?} }`, closed. */
export function unitTagsError(u: unknown): string | null {
  if (!isObj(u)) return 'units must be an object';
  const keys = Object.keys(u);
  if (keys.length > 64) return 'units has more than 64 entries';
  for (const k of keys) {
    if (!PARAM_PATH_RE.test(k)) return `units key '${k}' must be an action.params.<name> path`;
    const t = u[k];
    if (!isObj(t)) return `units['${k}'] must be an object`;
    const e = closedMembers(t, ['kind'], ['currency', 'exponent'], `units['${k}']`);
    if (e) return e;
    if (typeof t.kind !== 'string' || t.kind.length === 0 || t.kind.length > 64) return `units['${k}'].kind must be a string of 1..64 characters`;
    if (t.currency !== undefined && (typeof t.currency !== 'string' || t.currency.length === 0 || t.currency.length > 16)) return `units['${k}'].currency must be a string of 1..16 characters`;
    if (t.exponent !== undefined && !(isSafeInt(t.exponent) && t.exponent >= 0 && t.exponent <= 18)) return `units['${k}'].exponent must be an integer in [0, 18]`;
  }
  return null;
}

