import type { Caveat, CompiledPolicy, Predicate } from '@atlasauth/pca';

/**
 * Public types for the PCA authority analyzer.
 *
 * The analyzer decides static questions over PCA's predicate/caveat policy — "what can this whole
 * delegated authority EVER do?" — independently of any single runtime action. See README.md for the
 * exact decided fragment and the honest incompleteness boundary.
 */

/** Reversibility classes in increasing severity (mirrors @atlasauth/pca's `REVERSIBILITY_ORDER`). */
export const REVERSIBILITY_ORDER = ['reversible', 'rate_limited', 'irreversible'] as const;
export type ReversibilityClass = (typeof REVERSIBILITY_ORDER)[number];

/**
 * A policy to analyze: either a full `CompiledPolicy` (from `compilePolicy`/`agent().policy`) or a
 * bare predicate set with an optional caveat set. A chain's acting authority is the leaf's cumulative
 * (append-only) caveat list plus the grant's predicates.
 */
export type PolicyInput = CompiledPolicy | { predicates: Predicate[]; caveats?: Caveat[] };

/**
 * A concrete (or partially-concrete) action in the query/answer vocabulary. `params` are the
 * `action.params.*` inputs; `subject`/`env` carry witness assignments to `subject.*` / `env.*` fields
 * that a predicate's `where` may reference.
 */
export interface AnalyzerAction {
  verb: string;
  resource: string;
  params?: Record<string, unknown>;
  /** Reversibility class of the action (checked against a `reversibility_max` caveat). */
  reversibilityClass?: string;
  /** Witness assignment to `subject.*` fields (only populated when a witness needs them). */
  subject?: Record<string, unknown>;
  /** Witness assignment to `env.*` fields (only populated when a witness needs them). */
  env?: Record<string, unknown>;
}

/**
 * `true` on a result means the verdict is SOUND but could not be decided EXACTLY (it was
 * over-approximated / failed safe): e.g. a `re:` regex resource matcher, a cross-field `ref`
 * condition, or a representative grid larger than the configured bound. A fail-safe verdict never
 * claims the "safe" answer (subsumed / always-deny / disjoint / equivalent / conforms) without proof.
 */
export interface Approx {
  approximate?: boolean;
}

export interface ReachableResult extends Approx {
  reachable: boolean;
  /** A concrete action proving reachability (verified against the real evaluator). */
  witness?: AnalyzerAction;
  reason?: string;
}

export interface AlwaysDeniesResult extends Approx {
  alwaysDenies: boolean;
  /** When `false`: a concrete action the policy admits (proving it is not vacuous). */
  witness?: AnalyzerAction;
  reason?: string;
}

export interface AlwaysAllowsResult extends Approx {
  alwaysAllows: boolean;
  /** When `false`: a concrete action of the verb the policy denies. */
  counterexample?: AnalyzerAction;
  reason?: string;
}

export interface SubsumesResult extends Approx {
  subsumes: boolean;
  /** When `false`: an action `b` admits that `a` does not (a delegation-safety violation). */
  counterexample?: AnalyzerAction;
  reason?: string;
}

export interface DisjointResult extends Approx {
  disjoint: boolean;
  /** When `false`: an action both policies admit. */
  witness?: AnalyzerAction;
  reason?: string;
}

export interface EquivalentResult extends Approx {
  equivalent: boolean;
  /** When `false`: an action admitted by exactly one of the two policies. */
  counterexample?: AnalyzerAction;
  reason?: string;
}

/**
 * A declared intent envelope — the authority the principal MEANT to grant, distinct from the runtime
 * limits the policy happens to encode. `intentConformance` checks the policy admits ONLY actions
 * inside this envelope.
 */
export interface Intent {
  /** Allowed verbs. Include `'*'` to allow any verb. */
  verbs: string[];
  /** Allowed resource matchers (exact / `'*'` / trailing-`*` prefix / `re:`). Omitted/empty = any. */
  resourceScopes?: string[];
  /** Upper ceiling on the action's monetary amount, if any. */
  maxAmount?: number;
  /** Lower floor on the amount (default 0 when `maxAmount` is set). */
  minAmount?: number;
  /** The `action.params.<field>` that carries the amount (default `'amount'`). */
  amountField?: string;
}

export type IntentViolationKind = 'off-verb' | 'off-scope' | 'over-amount' | 'under-amount';

export interface IntentViolation {
  action: AnalyzerAction;
  kinds: IntentViolationKind[];
}

export interface IntentConformanceResult extends Approx {
  conforms: boolean;
  /** Concrete actions the policy admits that fall OUTSIDE the intent envelope. */
  violations: IntentViolation[];
  reason?: string;
}
