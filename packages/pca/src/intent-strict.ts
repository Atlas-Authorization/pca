/**
 * Strictness helpers shared by the Intent Layer v2 W-A rules (13–15) and their artifacts. NORMATIVE: the rules use them so
 * that no verifier depends on a host language's coercions.
 *
 *  - NUMBERS: every numeric field is a SAFE INTEGER (and not -0) or the check fails closed: no null-as-0, no numeric
 *    strings, no fractions, no NaN / Infinity.
 *  - LISTS: every list is a real JSON array; a string, an object or null in its place fails closed (a string is never
 *    iterated).
 *  - KEYED LOOKUPS: own properties only, read by descriptor (a `__proto__` key that JSON parsing made an own property is
 *    read as data, never as the prototype); verifier outputs are prototype-free records. Names that the predicate DSL
 *    cannot address (`__proto__`, `constructor`, `prototype`) are refused as accumulator, monitor and parameter names.
 */

/** Names the predicate DSL refuses as path segments; refused as v2 names. */
export const RESERVED_NAMES: ReadonlySet<string> = new Set(['__proto__', 'constructor', 'prototype']);

export const isSafeInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0);
export const isSafeNonNeg = (v: unknown): v is number => isSafeInt(v) && v >= 0;
export const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v) && [Object.prototype, null].includes(Object.getPrototypeOf(v));

/** Own-property read by descriptor (never a prototype or getter). */
export function ownGet(o: unknown, k: string): unknown {
  if (o === null || typeof o !== 'object') return undefined;
  const d = Object.getOwnPropertyDescriptor(o, k);
  return d && 'value' in d ? d.value : undefined;
}
export function ownHas(o: unknown, k: string): boolean {
  return o !== null && typeof o === 'object' && Object.prototype.hasOwnProperty.call(o, k);
}

/** A prototype-free record (safe to key by any name, including `__proto__`). */
export function freeRecord<T>(): Record<string, T> {
  return Object.create(null) as Record<string, T>;
}

/** The distinct reason a verifier gives for a signature suite it does not implement (always a fail-closed refusal). */
export const UNSUPPORTED_SUITE = 'unsupported_suite';

/**
 * Suite capability of an artifact's `alg`: absent = ed25519 (null); a non-string is malformed; a string this verifier does
 * not implement is `unsupported_suite` (never accepted, never another reason). Takes the verifier's suite resolver.
 */
export function suiteCapabilityError(alg: unknown, implemented: (alg: string) => boolean): string | null {
  if (alg === undefined) return null;
  if (typeof alg !== 'string') return 'alg must be a string';
  return implemented(alg) ? null : `${UNSUPPORTED_SUITE}: '${alg}'`;
}
