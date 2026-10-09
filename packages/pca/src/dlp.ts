/**
 * Data-flow governance — DLP for agents (spec Part 2.6). The L4 taint lattice answers "which actions
 * touched PII / untrusted content"; this is the POLICY on those flows: declare data classes (a resource
 * matcher + the maximum taint that may flow to them autonomously) and evaluate an action's provenance
 * against them. Pure + offline; composes the taint level carried in a PCActn's provenance.
 *
 * Taint convention (matches provenance.taint_level): 0 = clean / fully trusted; higher = more
 * untrusted-or-sensitive. A high-taint action reaching a sensitive sink is the classic exfiltration /
 * prompt-injection path; the policy stops it or forces a human, offline, before dispatch.
 */

export type TaintLevel = number;

export interface DataClass {
  /** Human name, e.g. `pii`, `secrets`, `external-send`. */
  name: string;
  /** Resource matcher: exact, `*` any, or trailing-`*` prefix (e.g. `customer:*`). */
  resource: string;
  /** Verbs this class applies to (default: any). */
  verbs?: string[];
  /** Max taint that may reach this class WITHOUT a human. Above it → step-up; see `hardDenyAbove`. */
  maxTaintForAuto: TaintLevel;
  /** Taint strictly above this is a hard deny (no step-up can rescue it). Default: no hard ceiling. */
  hardDenyAbove?: TaintLevel;
}

export interface DlpPolicy {
  classes: DataClass[];
  /** Applied when no class matches. Default: unlimited (no DLP constraint). */
  defaultMaxTaintForAuto?: TaintLevel;
}

export interface DlpContext {
  verb: string;
  resource: string;
  /** provenance.taint_level of the action. */
  taint: TaintLevel;
  /** provenance.trusted_refs — refs that are known-trusted (informational for the reason string). */
  trustedRefs?: string[];
}

export type DlpOutcome = 'allow' | 'step_up' | 'deny';

export interface DlpResult {
  outcome: DlpOutcome;
  /** The matched data class, if any. */
  class?: string;
  reason?: string;
}

function matches(pattern: string, resource: string): boolean {
  if (pattern === '*') return true;
  if (pattern.endsWith('*')) return resource.startsWith(pattern.slice(0, -1));
  return pattern === resource;
}

/** Find the most specific matching data class (longest non-wildcard prefix wins; exact beats prefix). */
function classFor(policy: DlpPolicy, ctx: DlpContext): DataClass | undefined {
  const applicable = policy.classes.filter(
    (c) => matches(c.resource, ctx.resource) && (!c.verbs || c.verbs.includes(ctx.verb)),
  );
  if (applicable.length === 0) return undefined;
  return applicable.sort((a, b) => specificity(b.resource) - specificity(a.resource))[0];
}

function specificity(pattern: string): number {
  if (pattern === '*') return 0;
  if (pattern.endsWith('*')) return pattern.length - 1;
  return pattern.length + 1000; // exact beats any prefix
}

/** Evaluate an action's data flow against the DLP policy. */
export function evaluateDlp(policy: DlpPolicy, ctx: DlpContext): DlpResult {
  const cls = classFor(policy, ctx);
  const max = cls ? cls.maxTaintForAuto : policy.defaultMaxTaintForAuto;
  // Fail CLOSED on a malformed taint. A non-finite taint (NaN / ±Infinity, or a non-number smuggled
  // in through untyped JSON) would make every `>` comparison below false and silently auto-allow a
  // sensitive flow — the exact exfiltration path this policy exists to stop. Treat it as maximally
  // tainted so it can never beat a ceiling. Finite values (including legitimately huge ones) are
  // unchanged, so behaviour is identical for well-formed input.
  const taint = Number.isFinite(ctx.taint) ? ctx.taint : Number.POSITIVE_INFINITY;
  if (max === undefined) {
    // No ceiling at all: nothing to compare against, so even an unknown taint is unconstrained here.
    return { outcome: 'allow', ...(cls ? { class: cls.name } : {}) };
  }

  const label = cls?.name ?? '<default>';
  if (cls?.hardDenyAbove !== undefined && taint > cls.hardDenyAbove) {
    return { outcome: 'deny', class: cls.name, reason: `taint ${taint} exceeds hard ceiling ${cls.hardDenyAbove} for '${label}'` };
  }
  if (taint > max) {
    return { outcome: 'step_up', ...(cls ? { class: cls.name } : {}), reason: `taint ${taint} > ${max} for '${label}' — needs human review` };
  }
  return { outcome: 'allow', ...(cls ? { class: cls.name } : {}) };
}

/** Convenience preset: PII resources accept only clean (taint 0) autonomously; secrets hard-deny any taint. */
export function defaultDlpPolicy(opts: { piiResource?: string; secretsResource?: string } = {}): DlpPolicy {
  const classes: DataClass[] = [];
  if (opts.piiResource) classes.push({ name: 'pii', resource: opts.piiResource, maxTaintForAuto: 0, hardDenyAbove: 2 });
  if (opts.secretsResource) classes.push({ name: 'secrets', resource: opts.secretsResource, maxTaintForAuto: 0, hardDenyAbove: 0 });
  return { classes };
}
