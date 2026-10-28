import type { Caveat, CompiledPolicy, Condition, Predicate } from '@atlasauth/pca';

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
export type PolicyInput =
  | CompiledPolicy
  | {
      predicates: Predicate[];
      caveats?: Caveat[];
      vetoes?: Veto[];
      tighten?: TightenLike[];
      /** Further policies that must ALSO admit (a delegation chain: the ancestors). The result is the meet of all of them. */
      meet?: PolicyInput[];
    };

/**
 * A prohibition in analyzable form (veto polarity: a trigger that cannot be decided counts as MATCHED, exactly as
 * `prohibitions.whenMatches`). `deny` vetoes remove actions from the admitted set. An `approval` veto (`require_approval_over`)
 * does not remove them: it sends them to a human, so they are admitted but not autonomous. Build them from a constitution with
 * `vetoesFromConstitution`.
 */
export interface Veto {
  id: string;
  kind: 'deny' | 'approval';
  when: Predicate;
  /** The veto holds unless EVERY condition affirmatively holds (`never_unless`, `require_approval_over.approved`). */
  unless?: Condition[];
  /** Only when the amount at `path` is over `threshold` (an unresolvable amount counts as over). */
  over?: { path: string; threshold: number };
}

/** A model-signal rule (`tighten[]`): when it holds or cannot be decided, the decision is capped at `signal`. */
export interface TightenLike {
  id: string;
  when: Condition;
  signal: 'escalate' | 'deny';
}

/** The ternary outcome of the permission layer for one action. */
export type AnalyzerDecision = 'allow' | 'escalate' | 'deny';

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

/** What a parameter is declared to be (a signed action schema `ActionParamDecl`, or an ActionDef parameter). */
export interface ParamShape {
  type?: 'string' | 'integer' | 'boolean' | 'date' | 'set' | 'array';
  /** string: the closed value set; set: the closed member set. */
  values?: string[];
  min?: number;
  max?: number;
  /** Unit id (rule 20). */
  unit?: string;
  /** Semantic type, e.g. `money.amount`. */
  semantic?: string;
  sensitivity?: 'free' | 'material' | 'critical';
  required?: boolean;
}

/** What discovery, validation and counterfactual search need to know about a verb: its declared parameters. */
export interface VerbShape {
  verb: string;
  params: Record<string, ParamShape>;
}

/**
 * The part of an `ActionDef` (`@atlasauth/pca-actions`, `def.ts`) the analysis tooling reads. It mirrors the real type's member
 * names exactly (`verb`, `params[name].{type, role, required, values, min, max, sensitivity}`), so a real `ActionDef` is assignable
 * to it. The analyzer cannot import the action kit (the kit depends on the intent package, which depends on this one), so the proof
 * that the real type is assignable lives in `@atlasauth/pca-policy-ci` (`actiondef-real.test.ts`, compiled and run in CI). Use
 * `verbShapesFromActionDefs` to turn defs into verb shapes.
 */
export interface ActionDefStructural {
  verb: string;
  params?: Record<string, { type: string; role?: string; required?: boolean; values?: string[]; min?: number; max?: number; sensitivity?: 'free' | 'material' | 'critical' }>;
}

/** @deprecated use {@link ActionDefStructural} (kept as an alias; `id` and the shape-style `params` are still accepted by `verbShapes`). */
export interface ActionDefLike {
  verb?: string;
  id?: string;
  params?: Record<string, ParamShape>;
  traits?: string[];
}
