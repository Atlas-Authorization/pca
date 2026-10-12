import type { ActionContext, Caveat, Predicate, PredicateResult } from '@atlasauth/pca';
import { evaluatePredicates } from '@atlasauth/pca';

/**
 * Shared result + report shapes for the three policy-source translators, plus the `decide`
 * helper that reproduces deny-overrides-permit semantics on top of the core allow-only
 * {@link evaluatePredicates}.
 *
 * Design note — why PCA is allow-only and what `denies` means
 * -----------------------------------------------------------
 * A PCA grant envelope is MONOTONE: its `predicates[]` only ever GRANT (an action is admitted iff
 * it matches at least one predicate; an empty list grants nothing — default deny), and `caveats[]`
 * only ever NARROW. There is deliberately no "deny predicate" inside an envelope, because a signed
 * grant that could be made broader by adding a rule would break the attenuation guarantee.
 *
 * Cedar (and, in principle, any deny-capable engine) has a global `forbid` that overrides `permit`.
 * That override cannot live inside one monotone envelope. We therefore surface it as a SEPARATE
 * `denies[]` predicate list. Two faithful ways to consume a translation with a non-empty `denies`:
 *   1. Enforce it at the adjudication layer: run {@link decide} (deny-overrides-permit) at the point
 *      of action admission, feeding both lists to the core evaluator. This is exact Cedar semantics.
 *   2. Mint the grant from `predicates` alone and treat `denies` as an out-of-band blocklist the
 *      server consults. (`predicates` plugs straight into `Envelope.predicates`.)
 * When `denies` is empty, `predicates` is the whole story and drops directly into an envelope.
 */

export type PolicySource = 'cedar' | 'rego' | 'openfga';

export interface TranslationReport {
  source: PolicySource;
  /** Human-readable notes on constructs that WERE translated. */
  translated: string[];
  /** Constructs intentionally not modeled — each one fails closed (never silently mis-translated). */
  skipped: string[];
  /** Hard parse/translation errors. A non-empty list means the translation is incomplete; callers
   *  should treat the result as fail-closed (do not grant on it). */
  errors: string[];
}

export interface BridgeResult {
  /** Permit (allow) predicates. Plug straight into `Envelope.predicates`. */
  predicates: Predicate[];
  /** Deny predicates (Cedar `forbid`, …). Empty for the monotone sources. See the module note. */
  denies: Predicate[];
  /** Emitted caveats. These policy languages express permissions, not PCA's temporal/blast-radius
   *  caveats, so this is normally empty; the field exists so a result is envelope-shaped. */
  caveats: Caveat[];
  report: TranslationReport;
}

/**
 * Decide one action under a translation using deny-overrides-permit (Cedar's combining rule),
 * built entirely on the core {@link evaluatePredicates}. If any deny matches, the action is denied;
 * otherwise the permit predicates decide. Fails closed on an incomplete translation
 * (`report.errors` non-empty) when `result` carries a report.
 */
export function decide(
  result: Pick<BridgeResult, 'predicates' | 'denies'> & Partial<Pick<BridgeResult, 'report'>>,
  ctx: ActionContext,
): PredicateResult {
  if (result.report && result.report.errors.length > 0) {
    return { allowed: false, reason: 'translation incomplete (fail closed)' };
  }
  if (result.denies.length > 0) {
    const denied = evaluatePredicates(result.denies, ctx);
    if (denied.allowed) {
      return { allowed: false, matched: denied.matched, reason: 'forbidden by deny policy' };
    }
  }
  return evaluatePredicates(result.predicates, ctx);
}
