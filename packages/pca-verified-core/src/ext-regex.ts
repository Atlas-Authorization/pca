/* eslint-disable @typescript-eslint/no-explicit-any */
// ext-regex.ts - typed adapter over the PROVED regex engine and `re:` guard (formal/dafny/Regex.dfy -> generated/pca_regex.js).
// The glue only converts JS strings to UTF-16 code-unit sequences and back; parsing, compilation to the Thompson NFA, the Pike
// simulation, the budget refusal and the guard are the Dafny functions.
import BigNumber from 'bignumber.js';
// eslint-disable-next-line @typescript-eslint/no-require-imports
const mod = require('../generated/pca_regex.js') as { _dafny: any; Regex: any };
const R = mod.Regex;
const dafny = mod._dafny;

/** JS string -> Dafny seq<int> of UTF-16 code units. */
function units(s: string): any {
  const q = dafny.Seq.of();
  for (let i = 0; i < s.length; i++) q.push(new BigNumber(s.charCodeAt(i)));
  return q;
}

/**
 * Proved equivalent of `safeRegexFullMatch(src, subject)` (packages/pca/src/safe-regex.ts): the full-match of `subject` against the
 * supported subset, or null when `src` is outside the subset / too large (4096 instructions) / over the 2e6 step budget.
 */
export function safeRegexFullMatchVerified(src: string, subject: string): boolean | null {
  if (typeof src !== 'string' || typeof subject !== 'string') return null;
  const r = R.__default.FullMatch(units(src), units(subject));
  return r.is_Some ? (r.dtor_v as boolean) : null;
}
/** Proved `compileSafeRegex(src) !== null`. */
export function compilesVerified(src: string): boolean {
  return typeof src === 'string' && (R.__default.Compiles(units(src)) as boolean);
}
/** Proved `isSafeRegexSource(src)` (the cost-budget guard AND the engine-compiles conjunct). */
export function isSafeRegexSourceVerified(src: string): boolean {
  return typeof src === 'string' && (R.__default.SafeSource(units(src)) as boolean);
}
/**
 * A document regex budget (structurally `RegexBudget` from packages/pca/src/regex-budget.ts): `charge` returns false when
 * one more evaluation of `src` against a subject of `subjectLen` chars would exceed the document caps.
 */
export interface RegexDocumentBudget {
  charge(src: string, subjectLen: number): boolean;
}

/** Same pre-match limits as predicates.ts (and Regex.dfy MAX_RE_SRC_LEN / MAX_RE_RESOURCE_LEN). */
const MAX_RE_SRC_LEN = 200;
const MAX_RE_RESOURCE_LEN = 512;

/**
 * Proved `re:` branch of predicates.ts resourceMatches, for `src` = pattern without the `re:` prefix.
 *
 * R6-CORE-07: the proof covers ONE match (2e6-step budget); the per-DOCUMENT budget (64 evaluations, source chars, total steps)
 * lives outside Dafny. A document `budget` is therefore REQUIRED (it throws without one) and is charged exactly where
 * production charges it: after the length and guard refusals, before matching. Pass one budget per document.
 */
export function reMatchesVerified(src: string, resource: string, budget: RegexDocumentBudget): boolean {
  if (budget === null || typeof budget !== 'object' || typeof budget.charge !== 'function') {
    throw new TypeError('reMatchesVerified: a document regex budget is required (R6-CORE-07)');
  }
  if (typeof src !== 'string' || typeof resource !== 'string') return false;
  if (src.length > MAX_RE_SRC_LEN || resource.length > MAX_RE_RESOURCE_LEN || !isSafeRegexSourceVerified(src)) return false;
  if (!budget.charge(src, resource.length)) return false;
  return R.__default.ReMatches(units(src), units(resource)) as boolean;
}
