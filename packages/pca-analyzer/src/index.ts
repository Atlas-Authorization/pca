/**
 * @atlasauth/pca-analyzer — STATIC ANALYZABILITY OF AUTHORITY.
 *
 * PCA can prove a quantitative trust-budget bound and verify a single action, but on its own it cannot
 * statically answer "what can this whole delegated authority EVER do?". This package decides that over
 * PCA's predicate/caveat policy: reachability, vacuity/totality, delegation-safety subsumption,
 * disjointness, equivalence, and — the distinct safety check — conformance to a declared intent
 * envelope (the "$14k renewal under a $10k cap on an approved vendor still violates intent" class).
 *
 * The engine is a SOUND, BOUNDED decision procedure (Cedar/SymCC-style, but with no SMT dependency):
 * it enumerates a finite, distinguishing set of representative actions built from the literals,
 * thresholds, prefixes, verbs and resource matchers in the policies, and evaluates the REAL
 * `evaluatePredicates` at each. See README.md for the exact decided fragment and the honest
 * incompleteness boundary. Soundness rule: a verdict is reported as proven only when the fragment is
 * fully decided; otherwise it fails safe and is marked `approximate`.
 */

import type { Condition } from '@atlasauth/pca';
import {
  DEFAULT_MAX_COMBINATIONS,
  admits,
  admitsAction,
  collectProbes,
  repToAction,
  representatives,
  search,
  toModel,
  type PolicyModel,
  type Rep,
} from './enumerate';
import { numericConjunctionSatisfiable } from './field';
import { REVERSIBILITY_ORDER } from './types';
import type {
  AlwaysAllowsResult,
  AlwaysDeniesResult,
  AnalyzerAction,
  DisjointResult,
  EquivalentResult,
  Intent,
  IntentConformanceResult,
  IntentViolation,
  IntentViolationKind,
  PolicyInput,
  ReachableResult,
  SubsumesResult,
} from './types';

export * from './types';
export { analyzeCaveats } from './caveats';
export type { CaveatAnalysis } from './caveats';
export {
  numericConjunctionSatisfiable,
  tightenInterval,
  intervalEmpty,
  FULL_INTERVAL,
  type NumInterval,
} from './field';
export { DEFAULT_MAX_COMBINATIONS, toModel, type PolicyModel } from './enumerate';

export interface AnalyzerOptions {
  /** Cap on the representative grid size; a larger grid fails safe (`approximate`). */
  maxCombinations?: number;
}

function reversibilityIndex(cls: string | undefined): number {
  if (cls === undefined) return -1;
  return (REVERSIBILITY_ORDER as readonly string[]).indexOf(cls);
}

// ---- reachable ------------------------------------------------------------------------------------

/**
 * Can any input complete `action` into one the policy ALLOWs? (some predicate matches AND the caveat
 * set is satisfiable). `verb` and `resource` are taken as given; unspecified `params` / `subject` /
 * `env` fields are existentially searched. A returned `witness` is a concrete action verified against
 * the real evaluator, so `reachable: true` is always proven. `reachable: false` is proven only for the
 * decided fragment; otherwise it fails safe to `reachable: true, approximate: true`.
 */
export function reachable(policy: PolicyInput, action: AnalyzerAction, opts: AnalyzerOptions = {}): ReachableResult {
  const model = toModel(policy);
  const max = opts.maxCombinations ?? DEFAULT_MAX_COMBINATIONS;
  if (!model.caveatSat) {
    return { reachable: false, reason: `caveats unsatisfiable: ${model.caveatReason ?? 'unknown'}` };
  }
  if (action.reversibilityClass !== undefined && model.revCap !== undefined) {
    const idx = reversibilityIndex(action.reversibilityClass);
    if (idx < 0 || idx > model.revCap) {
      return { reachable: false, reason: `reversibility class '${action.reversibilityClass}' exceeds the caveat cap` };
    }
  }

  // Fast path: the action is already concrete enough to decide directly.
  if (admitsAction(model, action)) {
    return { reachable: true, witness: action };
  }

  // Existential search over free fields, with verb/resource fixed and provided params pinned.
  const base = collectProbes({ predicateSets: [model.predicates], varyReversibility: model.revCap !== undefined });
  const provided = action.params ?? {};
  const fields = base.fields.map((f) => {
    if (f.path.startsWith('action.params.')) {
      const key = f.path.slice('action.params.'.length);
      if (Object.prototype.hasOwnProperty.call(provided, key)) {
        return { path: f.path, values: [provided[key]] };
      }
    }
    return f;
  });
  const revClasses =
    action.reversibilityClass !== undefined
      ? [action.reversibilityClass]
      : model.revCap !== undefined
        ? [...REVERSIBILITY_ORDER]
        : [undefined];
  const pr = { verbs: [action.verb], resources: [action.resource], revClasses, fields };

  const outcome = search(pr, (rep) => admits(model, rep), max);
  if (outcome.hit !== undefined) {
    const witness = mergeWitness(repToAction(outcome.hit), action);
    return { reachable: true, witness };
  }
  if (outcome.overflow) {
    return { reachable: true, approximate: true, reason: 'representative grid exceeded the bound; could not prove unreachable' };
  }
  if (model.undecidable.length > 0) {
    return {
      reachable: true,
      approximate: true,
      reason: `over-approximated (${model.undecidable.join('; ')}); could not construct a witness but cannot prove unreachable`,
    };
  }
  return { reachable: false, reason: 'no predicate admits this action for any input (proven over the decided fragment)' };
}

function mergeWitness(witness: AnalyzerAction, provided: AnalyzerAction): AnalyzerAction {
  const params = { ...(witness.params ?? {}), ...(provided.params ?? {}) };
  const out: AnalyzerAction = { verb: provided.verb, resource: provided.resource, params };
  const rc = provided.reversibilityClass ?? witness.reversibilityClass;
  if (rc !== undefined) out.reversibilityClass = rc;
  if (witness.subject !== undefined) out.subject = witness.subject;
  if (witness.env !== undefined) out.env = witness.env;
  return out;
}

// ---- alwaysDenies / alwaysAllows ------------------------------------------------------------------

/**
 * Is the policy vacuous — does it deny everything (optionally restricted to `verb`)? Proven only for
 * the decided fragment; any undecidable feature or grid overflow fails safe to `alwaysDenies: false`
 * (assume it can admit something).
 */
export function alwaysDenies(policy: PolicyInput, verb?: string, opts: AnalyzerOptions = {}): AlwaysDeniesResult {
  const model = toModel(policy);
  const max = opts.maxCombinations ?? DEFAULT_MAX_COMBINATIONS;
  if (!model.caveatSat) {
    return { alwaysDenies: true, reason: `caveats unsatisfiable: ${model.caveatReason ?? 'unknown'}` };
  }
  const pr = probesFor([model], verb);
  const outcome = search(pr, (rep) => admits(model, rep), max);
  if (outcome.hit !== undefined) {
    return { alwaysDenies: false, witness: repToAction(outcome.hit) };
  }
  if (outcome.overflow) {
    return { alwaysDenies: false, approximate: true, reason: 'grid exceeded the bound; cannot prove vacuity' };
  }
  if (model.undecidable.length > 0) {
    return { alwaysDenies: false, approximate: true, reason: `over-approximated (${model.undecidable.join('; ')}); cannot prove vacuity` };
  }
  return { alwaysDenies: true };
}

/**
 * Is the policy total for `verb` — does it admit EVERY action of that verb (any resource, any params)?
 * Proven only for the decided fragment; any undecidable feature or grid overflow fails safe to
 * `alwaysAllows: false`.
 */
export function alwaysAllows(policy: PolicyInput, verb: string, opts: AnalyzerOptions = {}): AlwaysAllowsResult {
  const model = toModel(policy);
  const max = opts.maxCombinations ?? DEFAULT_MAX_COMBINATIONS;
  if (!model.caveatSat) {
    return { alwaysAllows: false, reason: `caveats unsatisfiable: ${model.caveatReason ?? 'unknown'}` };
  }
  const pr = probesFor([model], verb);
  const outcome = search(pr, (rep) => !admits(model, rep), max);
  if (outcome.hit !== undefined) {
    return { alwaysAllows: false, counterexample: repToAction(outcome.hit) };
  }
  if (outcome.overflow) {
    return { alwaysAllows: false, approximate: true, reason: 'grid exceeded the bound; cannot prove totality' };
  }
  if (model.undecidable.length > 0) {
    return { alwaysAllows: false, approximate: true, reason: `over-approximated (${model.undecidable.join('; ')}); cannot prove totality` };
  }
  return { alwaysAllows: true };
}

function probesFor(models: PolicyModel[], verb?: string): ReturnType<typeof collectProbes> {
  const anyRev = models.some((m) => m.revCap !== undefined);
  const pr = collectProbes({ predicateSets: models.map((m) => m.predicates), varyReversibility: anyRev });
  if (verb !== undefined) pr.verbs = [verb];
  return pr;
}

// ---- subsumes / disjoint / equivalent -------------------------------------------------------------

/**
 * Does policy `a` permit everything `b` permits (admitted(b) ⊆ admitted(a))? This is the
 * delegation-safety check: a child capability must be subsumed by its parent. A counterexample is an
 * action `b` admits that `a` denies. Proven only for the decided fragment; any undecidable feature in
 * either policy, or grid overflow, fails safe to `subsumes: false`.
 */
export function subsumes(a: PolicyInput, b: PolicyInput, opts: AnalyzerOptions = {}): SubsumesResult {
  const ma = toModel(a);
  const mb = toModel(b);
  const max = opts.maxCombinations ?? DEFAULT_MAX_COMBINATIONS;
  const pr = probesFor([ma, mb]);
  const outcome = search(pr, (rep) => admits(mb, rep) && !admits(ma, rep), max);
  if (outcome.hit !== undefined) {
    return { subsumes: false, counterexample: repToAction(outcome.hit) };
  }
  const note = approxNote([ma, mb], outcome.overflow);
  if (note !== undefined) return { subsumes: false, approximate: true, reason: note };
  return { subsumes: true };
}

/**
 * Are the two policies' admitted sets disjoint (no action both admit)? A witness is an action both
 * admit. Proven only for the decided fragment; otherwise fails safe to `disjoint: false`.
 */
export function disjoint(a: PolicyInput, b: PolicyInput, opts: AnalyzerOptions = {}): DisjointResult {
  const ma = toModel(a);
  const mb = toModel(b);
  const max = opts.maxCombinations ?? DEFAULT_MAX_COMBINATIONS;
  const pr = probesFor([ma, mb]);
  const outcome = search(pr, (rep) => admits(ma, rep) && admits(mb, rep), max);
  if (outcome.hit !== undefined) {
    return { disjoint: false, witness: repToAction(outcome.hit) };
  }
  const note = approxNote([ma, mb], outcome.overflow);
  if (note !== undefined) return { disjoint: false, approximate: true, reason: note };
  return { disjoint: true };
}

/**
 * Do the two policies admit exactly the same actions? A counterexample is an action admitted by one
 * but not the other. Proven only for the decided fragment; otherwise fails safe to `equivalent: false`.
 */
export function equivalent(a: PolicyInput, b: PolicyInput, opts: AnalyzerOptions = {}): EquivalentResult {
  const ma = toModel(a);
  const mb = toModel(b);
  const max = opts.maxCombinations ?? DEFAULT_MAX_COMBINATIONS;
  const pr = probesFor([ma, mb]);
  const outcome = search(pr, (rep) => admits(ma, rep) !== admits(mb, rep), max);
  if (outcome.hit !== undefined) {
    return { equivalent: false, counterexample: repToAction(outcome.hit) };
  }
  const note = approxNote([ma, mb], outcome.overflow);
  if (note !== undefined) return { equivalent: false, approximate: true, reason: note };
  return { equivalent: true };
}

function approxNote(models: PolicyModel[], overflow: boolean): string | undefined {
  if (overflow) return 'representative grid exceeded the bound; cannot prove the relation';
  const reasons = models.flatMap((m) => m.undecidable);
  if (reasons.length > 0) return `over-approximated (${[...new Set(reasons)].join('; ')}); cannot prove the relation`;
  return undefined;
}

// ---- intentConformance ----------------------------------------------------------------------------

/**
 * Does the policy admit ONLY actions inside the declared `intent` envelope (allowed verbs + resource
 * scopes + an amount ceiling)? This is the key safety check distinct from the runtime trust-budget: an
 * action can pass the policy's predicates and stay under budget yet still fall outside what the
 * principal intended — e.g. a $14k renewal admitted under a $10k intent cap because the policy's own
 * ceiling is higher (or absent). Each reported violation is a concrete admitted action outside the
 * envelope, so `conforms: false` with violations is always proven. `conforms: true` is proven only for
 * the decided fragment; an undecidable policy feature, a `re:` intent scope, or grid overflow fails
 * safe to `conforms: false, approximate: true` with no violations listed.
 */
export function intentConformance(policy: PolicyInput, intent: Intent, opts: AnalyzerOptions = {}): IntentConformanceResult {
  const model = toModel(policy);
  const max = opts.maxCombinations ?? DEFAULT_MAX_COMBINATIONS;
  const amountField = intent.amountField ?? 'amount';
  const minAmount = intent.minAmount ?? 0;

  if (!model.caveatSat) {
    // Admits nothing, so it trivially admits only within-intent actions.
    return { conforms: true, violations: [] };
  }

  const extraFieldConditions: { path: string; cond: Condition }[] = [];
  if (intent.maxAmount !== undefined) {
    const path = `action.params.${amountField}`;
    extraFieldConditions.push({ path, cond: { field: path, op: 'lte', value: intent.maxAmount } });
    extraFieldConditions.push({ path, cond: { field: path, op: 'gte', value: minAmount } });
  }
  const pr = collectProbes({
    predicateSets: [model.predicates],
    extraVerbs: intent.verbs.filter((v) => v !== '*'),
    extraResources: intent.resourceScopes ?? [],
    extraFieldConditions,
    varyReversibility: model.revCap !== undefined,
  });

  if (pr.verbs.length * pr.resources.length * pr.revClasses.length * fieldProduct(pr.fields) > max) {
    return { conforms: false, approximate: true, violations: [], reason: 'grid exceeded the bound; cannot prove conformance' };
  }

  const violations: IntentViolation[] = [];
  const maxViolations = 16;
  for (const rep of representatives(pr)) {
    if (!admits(model, rep)) continue;
    const action = repToAction(rep);
    const kinds = intentViolationKinds(action, intent, amountField, minAmount);
    if (kinds.length > 0) {
      violations.push({ action, kinds });
      if (violations.length >= maxViolations) break;
    }
  }

  if (violations.length > 0) {
    return { conforms: false, violations };
  }
  const intentRegex = (intent.resourceScopes ?? []).some((s) => s.startsWith('re:'));
  if (model.undecidable.length > 0 || intentRegex) {
    const reasons = [...model.undecidable];
    if (intentRegex) reasons.push('re: intent resource scope not enumerated soundly');
    return { conforms: false, approximate: true, violations: [], reason: `over-approximated (${reasons.join('; ')}); cannot prove conformance` };
  }
  return { conforms: true, violations: [] };
}

function fieldProduct(fields: { values: unknown[] }[]): number {
  let n = 1;
  for (const f of fields) n *= f.values.length;
  return n;
}

function scopeMatches(scope: string, resource: string): boolean {
  if (scope === '*') return true;
  if (scope.startsWith('re:')) {
    try {
      return new RegExp('^(?:' + scope.slice(3) + ')$').test(resource);
    } catch {
      return false;
    }
  }
  if (scope.endsWith('*')) return resource.startsWith(scope.slice(0, -1));
  return scope === resource;
}

function intentViolationKinds(
  action: AnalyzerAction,
  intent: Intent,
  amountField: string,
  minAmount: number,
): IntentViolationKind[] {
  const kinds: IntentViolationKind[] = [];
  if (!(intent.verbs.includes('*') || intent.verbs.includes(action.verb))) kinds.push('off-verb');
  const scopes = intent.resourceScopes ?? [];
  if (scopes.length > 0 && !scopes.some((s) => scopeMatches(s, action.resource))) kinds.push('off-scope');
  if (intent.maxAmount !== undefined) {
    const amt = (action.params ?? {})[amountField];
    if (typeof amt === 'number' && Number.isFinite(amt)) {
      if (amt > intent.maxAmount) kinds.push('over-amount');
      else if (amt < minAmount) kinds.push('under-amount');
    }
  }
  return kinds;
}

// ---- convenience ----------------------------------------------------------------------------------

/** Concrete, exact admission check for a fully-specified action (no existential search). */
export function admitsConcrete(policy: PolicyInput, action: AnalyzerAction): boolean {
  return admitsAction(toModel(policy), action);
}

/**
 * Whether a predicate's own numeric `where` conjunction is satisfiable (an explicit use of the interval
 * engine; e.g. `amount >= 100 AND amount <= 10` is not). Non-numeric / `ref` conditions are ignored.
 */
export function predicateNumericSatisfiable(where: readonly Condition[] | undefined): boolean {
  if (!Array.isArray(where)) return true;
  return numericConjunctionSatisfiable(where);
}

// Re-export low-level engine pieces useful for custom analyses.
export { admits, admitsAction, collectProbes, representatives, repToAction, search, type Rep };
