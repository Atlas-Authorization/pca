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

import type { AnalyzerOptions } from './deps';
import { normalizeChain, normalizePolicyInput } from './normalize';
import {
  ruleDangerousReachability,
  ruleMissingSafetyFloor,
  ruleOverBroadGrant,
  rulePrivilegeEscalation,
  ruleRedundantCaveat,
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
export { normalizePolicyInput, normalizeChain, isCapability, isEnvelope, type NormalizedPolicy } from './normalize';

export interface LintOptions extends AnalyzerOptions {
  rules?: LintRules;
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
  if (cfg.overBroadGrant.enabled) out.push(...ruleOverBroadGrant(policy, cfg.overBroadGrant.dangerousVerbs, ao));
  if (cfg.redundantCaveat) out.push(...ruleRedundantCaveat(policy));
  if (cfg.dangerousReachability.enabled) {
    out.push(...ruleDangerousReachability(policy, cfg.dangerousReachability.dangerousVerbs, cfg.dangerousReachability.targets, ao));
  }
  if (cfg.missingSafetyFloor.enabled) {
    out.push(...ruleMissingSafetyFloor(policy, cfg.missingSafetyFloor, cfg.overBroadGrant.dangerousVerbs));
  }
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
  if (cfg.privilegeEscalation) out.push(...rulePrivilegeEscalation(hops, ao));

  const leaf = hops[hops.length - 1];
  if (leaf !== undefined) {
    if (cfg.overBroadGrant.enabled) out.push(...ruleOverBroadGrant(leaf, cfg.overBroadGrant.dangerousVerbs, ao));
    if (cfg.redundantCaveat) out.push(...ruleRedundantCaveat(leaf));
    if (cfg.dangerousReachability.enabled) {
      out.push(...ruleDangerousReachability(leaf, cfg.dangerousReachability.dangerousVerbs, cfg.dangerousReachability.targets, ao));
    }
    if (cfg.missingSafetyFloor.enabled) {
      out.push(...ruleMissingSafetyFloor(leaf, cfg.missingSafetyFloor, cfg.overBroadGrant.dangerousVerbs));
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
  const counts = { error: 0, warn: 0, info: 0 };
  let failing = 0;
  const threshold = SEVERITY_RANK[maxSeverity];
  for (const r of results) {
    for (const f of r.findings) {
      counts[f.severity] += 1;
      if (SEVERITY_RANK[f.severity] >= threshold) failing += 1;
    }
  }
  const ok = failing === 0;
  return { results, counts, maxSeverity, ok, exitCode: ok ? 0 : 1 };
}
