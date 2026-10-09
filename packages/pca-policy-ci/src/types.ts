/**
 * Public types for @atlasauth/pca-policy-ci — the shift-left policy-safety CI gate.
 *
 * A {@link Finding} is one problem the linter found in a PCA policy. Every rule is toggleable and
 * every verdict is SOUND: where the underlying static analyzer cannot decide a question exactly it
 * fails safe to a `warn`/`info` that says it is undecidable, and NEVER raises a false hard `error`.
 */

/** Finding severity, in increasing order of concern (`info` < `warn` < `error`). */
export type Severity = 'error' | 'warn' | 'info';

/** Stable rule identifiers (one per implemented check, plus the structural `malformed-policy`). */
export type RuleId =
  | 'over-broad-grant'
  | 'privilege-escalation'
  | 'redundant-caveat'
  | 'dangerous-reachability'
  | 'missing-safety-floor'
  | 'malformed-policy';

/** A single problem the linter found. `where` is a human-readable location hint inside the policy. */
export interface Finding {
  rule: RuleId;
  severity: Severity;
  message: string;
  /** Location hint, e.g. `predicates[0]`, `predicates[0].where[2]`, `caveats[1]`, `hop[2]`. */
  where?: string;
}

// ---- rule configuration ---------------------------------------------------------------------------

/** Default set of verb substrings treated as dangerous (case-insensitive `includes` match). */
export const DEFAULT_DANGEROUS_VERBS: readonly string[] = [
  'delete',
  'destroy',
  'drop',
  'remove',
  'purge',
  'transfer',
  'payout',
  'wire',
  'withdraw',
  'admin',
  'grant',
  'revoke',
  'deploy',
  'shutdown',
  'rotate',
] as const;

/** A dangerous (verb, resource) target to probe for reachability. `resource` omitted = any resource. */
export interface DangerousTarget {
  verb: string;
  resource?: string;
}

export interface OverBroadConfig {
  /** Verb substrings treated as dangerous. Defaults to {@link DEFAULT_DANGEROUS_VERBS}. */
  dangerousVerbs?: readonly string[];
}

export interface DangerousReachabilityConfig {
  dangerousVerbs?: readonly string[];
  /** Explicit (verb, resource) targets to probe in addition to the derived dangerous verbs. */
  targets?: DangerousTarget[];
}

export interface SafetyFloorConfig {
  /** Flag a grant with no `expires` caveat. Default true. */
  requireExpiry?: boolean;
  /** Flag a non-trivial grant with no `max_blast_radius` / `rate` / `budget_alloc` gate. Default true. */
  requireScopeGate?: boolean;
}

/**
 * Per-rule toggles. For each rule: omit / `true` = enabled with defaults, `false` = disabled, an
 * object = enabled with that configuration. All rules are enabled by default.
 */
export interface LintRules {
  overBroadGrant?: boolean | OverBroadConfig;
  privilegeEscalation?: boolean;
  redundantCaveat?: boolean;
  dangerousReachability?: boolean | DangerousReachabilityConfig;
  missingSafetyFloor?: boolean | SafetyFloorConfig;
}

// ---- summary --------------------------------------------------------------------------------------

/** One labeled policy's findings (used by {@link LintSummary} for multi-policy runs). */
export interface LabeledFindings {
  label: string;
  findings: Finding[];
}

export interface SummaryOptions {
  /**
   * The lowest severity that fails the gate (contributes a non-zero exit code). `error` (default)
   * fails on errors only; `warn` fails on warnings and errors; `info` fails on everything.
   */
  maxSeverity?: Severity;
}

export interface LintSummary {
  results: LabeledFindings[];
  counts: { error: number; warn: number; info: number };
  /** The threshold used to compute `ok` / `exitCode`. */
  maxSeverity: Severity;
  /** True when nothing at or above `maxSeverity` was found. */
  ok: boolean;
  /** 0 when `ok`, else 1. */
  exitCode: number;
}

/** Severity ordering used for thresholds. Higher = more severe. */
export const SEVERITY_RANK: Record<Severity, number> = { info: 1, warn: 2, error: 3 };
