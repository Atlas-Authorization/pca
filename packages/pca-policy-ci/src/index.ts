/**
 * @atlasauth/pca-policy-ci — a CI gate that STATICALLY catches unsafe PCA policies before they ship.
 *
 * This is the "shift-left policy safety" boundary. It drives the real `@atlasauth/pca-analyzer`
 * decision procedure (reachability, totality/always-allow, delegation-safety subsumption, numeric
 * satisfiability) over a PCA `Envelope` / `grant` / chain and reports a list of {@link Finding}s. Five
 * rules, each toggleable:
 *
 *  - **over-broad-grant** — a wildcard verb/resource, a semantically-proven always-allow, or a
 *    dangerous verb granted with no narrowing `where` or scope-narrowing caveat.
 *  - **privilege-escalation** — a delegation hop whose effective authority is NOT a subset of its
 *    parent (a hard error if the analyzer proves it; attenuation should make this impossible).
 *  - **redundant-caveat** — a caveat (or `where` condition) that can never bite: a duplicate, one
 *    subsumed by a stricter one of the same type, an unsatisfiable predicate, a non-binding bound.
 *  - **dangerous-reachability** — a dangerous (verb, resource) the analyzer PROVES reachable with no
 *    budget / rate / step-up gate.
 *  - **missing-safety-floor** — no expiry, or no blast/rate/budget gate on a non-trivial grant.
 *
 * SOUNDNESS: a hard `error` is only ever emitted from a PROVEN analyzer verdict. Any undecidable
 * feature (a `re:` regex resource, a cross-field `ref`, an over-large grid) fails safe to a
 * `warn`/`info` that says it is undecidable — the gate never fails a build on a false positive, and
 * never silently passes a provably-unsafe policy.
 */

import { lintRulesDigest, validatePolicyAgainstSchema, type ActionDef, type AnalyzerOptions, type ValidateOptions } from './deps';
import { normalizeChain, normalizePolicyInput } from './normalize';
import {
  ruleDangerousReachability,
  ruleMissingSafetyFloor,
  ruleOverBroadGrant,
  rulePrivilegeEscalation,
  ruleRedundantCaveat,
  ruleSchemaMismatch,
} from './rules';
import {
  DEFAULT_DANGEROUS_VERBS,
  SEVERITY_RANK,
  type DangerousTarget,
  type Finding,
  type LabeledFindings,
  type LintRules,
  type LintSummary,
  type Severity,
  type SummaryOptions,
} from './types';

export * from './types';
export * from './authoring';
export { normalizePolicyInput, normalizeChain, isCapability, isEnvelope, type NormalizedPolicy } from './normalize';

/** A rule that throws is a finding, not a crash and not silence: a gate must not pass a policy it could not finish checking. */
function guarded(rule: string, run: () => Finding[]): Finding[] {
  try {
    return run();
  } catch (e) {
    return [{ rule: 'internal-error', severity: 'error', message: `rule ${rule} could not run: ${e instanceof Error ? e.message : String(e)}` }];
  }
}

export interface LintOptions extends AnalyzerOptions {
  rules?: LintRules;
  /**
   * A signed action schema, a list of verb shapes or a list of ActionDefs. When given, the policy is also checked against it
   * (rule `schema-mismatch`): undeclared verbs and parameters, type and range mismatches, enum values the schema lacks, an
   * unsatisfiable predicate, a money verb with no ceiling and (rule 20) a missing or wrong unit tag.
   */
  schema?: Parameters<typeof validatePolicyAgainstSchema>[1] | readonly ActionDef[];
  schemaOptions?: ValidateOptions;
}

// ---- resolved config ------------------------------------------------------------------------------

interface ResolvedRules {
  overBroadGrant: { enabled: boolean; dangerousVerbs: readonly string[] };
  privilegeEscalation: boolean;
  redundantCaveat: boolean;
  dangerousReachability: { enabled: boolean; dangerousVerbs: readonly string[]; targets: DangerousTarget[] };
  missingSafetyFloor: { enabled: boolean; requireExpiry: boolean; requireScopeGate: boolean };
}

function resolveRules(rules: LintRules | undefined): ResolvedRules {
  const r = rules ?? {};
  const ob = r.overBroadGrant;
  const dr = r.dangerousReachability;
  const sf = r.missingSafetyFloor;
  return {
    overBroadGrant: {
      enabled: ob !== false,
      dangerousVerbs: typeof ob === 'object' && ob.dangerousVerbs ? ob.dangerousVerbs : DEFAULT_DANGEROUS_VERBS,
    },
    privilegeEscalation: r.privilegeEscalation !== false,
    redundantCaveat: r.redundantCaveat !== false,
    dangerousReachability: {
      enabled: dr !== false,
      dangerousVerbs: typeof dr === 'object' && dr.dangerousVerbs ? dr.dangerousVerbs : DEFAULT_DANGEROUS_VERBS,
      targets: typeof dr === 'object' && dr.targets ? dr.targets : [],
    },
    missingSafetyFloor: {
      enabled: sf !== false,
      requireExpiry: typeof sf === 'object' ? sf.requireExpiry !== false : true,
      requireScopeGate: typeof sf === 'object' ? sf.requireScopeGate !== false : true,
    },
  };
}

function analyzerOpts(opts: LintOptions | undefined): AnalyzerOptions {
  return opts?.maxCombinations !== undefined ? { maxCombinations: opts.maxCombinations } : {};
}

// ---- lintPolicy / lintChain / lint ----------------------------------------------------------------

/**
 * Lint a single PCA policy: an `Envelope`, a minted `grant` (`Capability`), a `compilePolicy` result,
 * or a bare `{ predicates, caveats? }`. Returns all findings (empty = clean).
 */
export function lintPolicy(input: unknown, opts: LintOptions = {}): Finding[] {
  const norm = normalizePolicyInput(input);
  if (!norm.ok) return [{ rule: 'malformed-policy', severity: 'error', message: norm.reason }];
  const cfg = resolveRules(opts.rules);
  const ao = analyzerOpts(opts);
  const policy = norm.policy;
  const out: Finding[] = [];
  if (cfg.overBroadGrant.enabled) out.push(...guarded('over-broad-grant', () => ruleOverBroadGrant(policy, cfg.overBroadGrant.dangerousVerbs, ao)));
  if (cfg.redundantCaveat) out.push(...guarded('redundant-caveat', () => ruleRedundantCaveat(policy)));
  if (cfg.dangerousReachability.enabled) {
    out.push(...guarded('dangerous-reachability', () => ruleDangerousReachability(policy, cfg.dangerousReachability.dangerousVerbs, cfg.dangerousReachability.targets, ao)));
  }
  if (cfg.missingSafetyFloor.enabled) {
    out.push(...guarded('missing-safety-floor', () => ruleMissingSafetyFloor(policy, cfg.missingSafetyFloor, cfg.overBroadGrant.dangerousVerbs)));
  }
  if (opts.schema !== undefined) out.push(...guarded('schema-mismatch', () => ruleSchemaMismatch(policy, opts.schema!, opts.schemaOptions)));
  return out;
}

/**
 * Lint a delegation chain (root -> leaf): a `Capability[]` (a real minted chain) or an array of
 * already-effective `{ predicates, caveats }` hops. Runs the privilege-escalation check across every
 * consecutive pair, then runs the single-policy rules on the acting LEAF's effective authority.
 */
export function lintChain(chain: readonly unknown[], opts: LintOptions = {}): Finding[] {
  const norm = normalizeChain(chain);
  if (!norm.ok) return [{ rule: 'malformed-policy', severity: 'error', message: norm.reason }];
  const cfg = resolveRules(opts.rules);
  const ao = analyzerOpts(opts);
  const hops = norm.hops;
  const out: Finding[] = [];
  if (cfg.privilegeEscalation) out.push(...guarded('privilege-escalation', () => rulePrivilegeEscalation(hops, ao)));

  const leaf = hops[hops.length - 1];
  if (leaf !== undefined) {
    if (cfg.overBroadGrant.enabled) out.push(...guarded('over-broad-grant', () => ruleOverBroadGrant(leaf, cfg.overBroadGrant.dangerousVerbs, ao)));
    if (cfg.redundantCaveat) out.push(...guarded('redundant-caveat', () => ruleRedundantCaveat(leaf)));
    if (cfg.dangerousReachability.enabled) {
      out.push(...guarded('dangerous-reachability', () => ruleDangerousReachability(leaf, cfg.dangerousReachability.dangerousVerbs, cfg.dangerousReachability.targets, ao)));
    }
    if (cfg.missingSafetyFloor.enabled) {
      out.push(...guarded('missing-safety-floor', () => ruleMissingSafetyFloor(leaf, cfg.missingSafetyFloor, cfg.overBroadGrant.dangerousVerbs)));
    }
  }
  return out;
}

/** Dispatch: an array input is a delegation chain ({@link lintChain}); anything else is a single policy. */
export function lint(input: unknown, opts: LintOptions = {}): Finding[] {
  return Array.isArray(input) ? lintChain(input, opts) : lintPolicy(input, opts);
}

// ---- lintPolicies + summary -----------------------------------------------------------------------

export interface LintItem {
  label?: string;
  policy: unknown;
}

/** Lint a list of labeled policies (or chains) and roll the findings into a {@link LintSummary}. */
export function lintPolicies(items: readonly LintItem[], opts: LintOptions & SummaryOptions = {}): LintSummary {
  const results: LabeledFindings[] = items.map((item, i) => ({
    label: item.label ?? `policy[${i}]`,
    findings: lint(item.policy, opts),
  }));
  return summarize(results, opts);
}

/** Roll a set of labeled findings into counts + an exit-code mapping (`error` -> non-zero). */
export function summarize(results: LabeledFindings[], opts: SummaryOptions = {}): LintSummary {
  const maxSeverity: Severity = opts.maxSeverity ?? 'error';
  // An unknown threshold would make every comparison false and pass everything.
  if (!Object.prototype.hasOwnProperty.call(SEVERITY_RANK, maxSeverity)) throw new RangeError(`summarize: maxSeverity must be one of ${Object.keys(SEVERITY_RANK).join(', ')}`);
  const counts = { error: 0, warn: 0, info: 0 };
  // A gate that linted nothing (an empty list, a glob that matched no files) must not report success.
  if (!Array.isArray(results) || results.length === 0) {
    return { results: [], counts, maxSeverity, ok: false, exitCode: 2, reason: 'no policies were linted' };
  }
  let failing = 0;
  const threshold = SEVERITY_RANK[maxSeverity];
  for (const r of results) {
    for (const f of r.findings) {
      // A finding whose severity is not one of the three is counted as an error: it must never slip under the threshold.
      const sev: Severity = Object.prototype.hasOwnProperty.call(SEVERITY_RANK, f.severity) ? f.severity : 'error';
      counts[sev] += 1;
      if (SEVERITY_RANK[sev] >= threshold) failing += 1;
    }
  }
  const ok = failing === 0;
  return { results, counts, maxSeverity, ok, exitCode: ok ? 0 : 1 };
}

// ---- pinned lint rule list -------------------------------------------------------------------------

export interface LintRulesPinResult { ok: boolean; message: string }

/**
 * Enforce the pinned digest of the action-kit lint rule list: `pinText` is the content of the pin file (one digest, surrounding
 * whitespace ignored). The rule list is part of what a pack is checked against, so adding, removing or rewording a rule is a visible,
 * reviewed change: it fails here until the pin is updated in the same change. An empty or malformed pin fails.
 */
export function checkLintRulesPin(pinText: string, actual: string = lintRulesDigest()): LintRulesPinResult {
  const pinned = pinText.trim();
  if (!/^[A-Za-z0-9_-]{43}$/.test(pinned)) return { ok: false, message: 'the lint rules pin is not a digest (expected 43 base64url characters)' };
  return pinned === actual
    ? { ok: true, message: `lint rules digest ${actual} matches the pin` }
    : { ok: false, message: `lint rules digest ${actual} differs from the pin ${pinned}: the rule list changed; review it and update the pin` };
}
