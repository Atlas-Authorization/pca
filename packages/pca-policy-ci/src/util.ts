/**
 * Small shared helpers for the linter rules. Pure; no analyzer calls here.
 */

import { ENVELOPE_CAVEAT, type AnalyzerAction } from './deps';
import type { Caveat, Predicate } from '@atlasauth/pca';

/** The caveat `type` that carries the signed envelope payload inside a grant. */
export const ENVELOPE_CAVEAT_TYPE = ENVELOPE_CAVEAT;

/** Scope-narrowing caveat types (constrain WHAT/HOW MUCH, not merely WHEN). */
export const SCOPE_NARROWING_CAVEATS: readonly string[] = [
  'max_blast_radius',
  'rate',
  'reversibility_max',
  'budget_alloc',
  'delegation_depth',
] as const;

/** Blast/rate/budget gate caveat types (the "safety floor" gates distinct from a time bound). */
export const BUDGET_GATE_CAVEATS: readonly string[] = ['max_blast_radius', 'rate', 'budget_alloc'] as const;

/** Normalize a predicate's `verb` (string | string[] | '*') to a concrete string array. */
export function verbsOf(verb: Predicate['verb']): string[] {
  if (typeof verb === 'string') return [verb];
  if (Array.isArray(verb)) return verb.filter((x): x is string => typeof x === 'string');
  return [];
}

/** Finite-number accessor for an `unknown` caveat field. */
export function num(x: unknown): number | undefined {
  return typeof x === 'number' && Number.isFinite(x) ? x : undefined;
}

/** Case-insensitive `includes` match of a verb against a dangerous-substring set. */
export function isDangerousVerb(verb: string, dangerous: readonly string[]): boolean {
  const v = verb.toLowerCase();
  return dangerous.some((kw) => v.includes(kw.toLowerCase()));
}

/** A resource matcher that admits every resource: omitted or `'*'`. */
export function isWildcardResource(resource: Predicate['resource']): boolean {
  return resource === undefined || resource === '*';
}

/** Whether a caveat list contains any caveat of one of the given types. */
export function hasCaveatOfType(caveats: readonly Caveat[], types: readonly string[]): boolean {
  return caveats.some((c) => c !== null && typeof c === 'object' && typeof c.type === 'string' && types.includes(c.type));
}

/** A one-line, log-friendly rendering of an analyzer witness/counterexample action. */
export function describeAction(a: AnalyzerAction): string {
  const parts = [a.verb, a.resource];
  if (a.params && Object.keys(a.params).length > 0) parts.push(JSON.stringify(a.params));
  if (a.reversibilityClass !== undefined) parts.push(`[${a.reversibilityClass}]`);
  return parts.join(' ');
}

/** Unique, order-preserving strings. */
export function uniq(xs: readonly string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const x of xs) {
    if (!seen.has(x)) {
      seen.add(x);
      out.push(x);
    }
  }
  return out;
}
