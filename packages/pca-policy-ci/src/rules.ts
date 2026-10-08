/**
 * The five policy-safety rules, each driving the real static analyzer. Every rule is SOUND: a verdict
 * is only ever reported as a hard `error` when the analyzer PROVES it (its result is not
 * `approximate`); an undecidable policy feature downgrades to a `warn`/`info` that says so, so the
 * gate never fails the build on a false positive.
 */

import {
  FULL_INTERVAL,
  alwaysAllows,
  alwaysDenies,
  intervalEmpty,
  predicateNumericSatisfiable,
  reachable,
  subsumes,
  tightenInterval,
  type AnalyzerOptions,
  type Caveat,
  type Condition,
  type LeafCondition,
  type NumInterval,
  type Predicate,
  type PolicyInput,
  type RiskPolicy,
} from './deps';
import { isLeafCondition } from '@atlasauth/pca';
import type { NormalizedPolicy } from './normalize';
import {
  BUDGET_GATE_CAVEATS,
  SCOPE_NARROWING_CAVEATS,
  describeAction,
  hasCaveatOfType,
  isDangerousVerb,
  isWildcardResource,
  num,
  uniq,
  verbsOf,
} from './util';
import {
  DEFAULT_DANGEROUS_VERBS,
  type DangerousTarget,
  type Finding,
  type RuleId,
} from './types';

function analyzerInput(p: NormalizedPolicy): PolicyInput {
  return { predicates: p.predicates, caveats: p.caveats };
}

function find(rule: RuleId, severity: Finding['severity'], message: string, where?: string): Finding {
  return where === undefined ? { rule, severity, message } : { rule, severity, message, where };
}

/** Every concrete verb named across the predicate set, plus whether any predicate grants `'*'`. */
function declaredVerbs(predicates: readonly Predicate[]): { concrete: string[]; hasWildcard: boolean } {
  const concrete: string[] = [];
  let hasWildcard = false;
  for (const p of predicates) {
    if (p === null || typeof p !== 'object') continue;
    for (const v of verbsOf(p.verb)) {
      if (v === '*') hasWildcard = true;
      else concrete.push(v);
    }
  }
  return { concrete: uniq(concrete), hasWildcard };
}

/** Does the policy carry a budget / step-up gate that bounds a dangerous action? */
function gateDescription(policy: NormalizedPolicy): string | undefined {
  const gates: string[] = [];
  if (hasCaveatOfType(policy.caveats, BUDGET_GATE_CAVEATS)) {
    gates.push(policy.caveats.filter((c) => BUDGET_GATE_CAVEATS.includes(c.type)).map((c) => c.type).join('/'));
  }
  const rp: RiskPolicy | undefined = policy.riskPolicy;
  if (rp !== undefined && Number.isFinite(rp.theta2) && rp.theta2 < 1) gates.push('risk step-up (theta2 < 1)');
  return gates.length > 0 ? gates.join(', ') : undefined;
}

// ---- 1. over-broad grant --------------------------------------------------------------------------

export function ruleOverBroadGrant(
  policy: NormalizedPolicy,
  dangerous: readonly string[],
  opts: AnalyzerOptions,
): Finding[] {
  const out: Finding[] = [];
  const input = analyzerInput(policy);
  const hasScopeNarrowing = hasCaveatOfType(policy.caveats, SCOPE_NARROWING_CAVEATS);

  policy.predicates.forEach((p, i) => {
    if (p === null || typeof p !== 'object') return;
    const verbs = verbsOf(p.verb);
    const where = `predicates[${i}]`;
    const hasWhere = Array.isArray(p.where) && p.where.length > 0;

    if (verbs.includes('*')) {
      out.push(find('over-broad-grant', 'error', `predicate grants a WILDCARD verb '*' — authority over any action`, where));
    }
    if (isWildcardResource(p.resource)) {
      const dangerousVerbs = verbs.filter((v) => isDangerousVerb(v, dangerous));
      if (dangerousVerbs.length > 0) {
        out.push(
          find(
            'over-broad-grant',
            'error',
            `dangerous verb(s) ${JSON.stringify(dangerousVerbs)} granted on a WILDCARD resource ('*')`,
            where,
          ),
        );
      } else if (!verbs.includes('*')) {
        out.push(find('over-broad-grant', 'warn', `predicate matches ANY resource ('*') — consider a resource prefix`, where));
      }
    }
    for (const v of verbs) {
      if (v !== '*' && isDangerousVerb(v, dangerous) && !hasWhere && !hasScopeNarrowing) {
        out.push(
          find(
            'over-broad-grant',
            'error',
            `dangerous verb '${v}' is granted with NO narrowing \`where\` and no scope-narrowing caveat (${SCOPE_NARROWING_CAVEATS.join('/')})`,
            where,
          ),
        );
      }
    }
  });

  // Semantic always-allow: a verb the analyzer PROVES is total (admits every action of that verb).
  const { concrete } = declaredVerbs(policy.predicates);
  for (const v of concrete) {
    const aa = alwaysAllows(input, v, opts);
    if (aa.alwaysAllows && aa.approximate !== true) {
      out.push(find('over-broad-grant', 'error', `grants EVERY action of '${v}' — the authority has no effective constraint (always-allow)`));
    }
  }
  return out;
}

// ---- 2. privilege escalation in a chain -----------------------------------------------------------

export function rulePrivilegeEscalation(hops: readonly NormalizedPolicy[], opts: AnalyzerOptions): Finding[] {
  const out: Finding[] = [];
  for (let i = 1; i < hops.length; i++) {
    const parent = hops[i - 1];
    const child = hops[i];
    if (parent === undefined || child === undefined) continue;
    // A well-attenuated child admits a SUBSET of its parent, i.e. the parent subsumes the child.
    const s = subsumes(analyzerInput(parent), analyzerInput(child), opts);
    const where = `hop[${i}]`;
    if (s.subsumes) continue;
    if (s.approximate === true) {
      out.push(
        find(
          'privilege-escalation',
          'warn',
          `could not prove hop ${i} attenuation (undecidable${s.reason ? `: ${s.reason}` : ''}) — attenuation not verified`,
          where,
        ),
      );
    } else {
      const ex = s.counterexample !== undefined ? ` — child admits '${describeAction(s.counterexample)}' which its parent denies` : '';
      out.push(
        find(
          'privilege-escalation',
          'error',
          `delegation hop ${i} ESCALATES authority: its effective authority is not a subset of its parent (attenuation violated)${ex}`,
          where,
        ),
      );
    }
  }
  return out;
}

// ---- 3. unused / redundant caveat -----------------------------------------------------------------

type OrderedCaveatSpec = { field: string; keep: 'min' | 'max' };
// For each type: which numeric field carries its bound, and whether the STRICTEST (binding) one is the
// min or the max. Any non-binding caveat of the same type can never bite — it is dead policy.
const ORDERED_CAVEATS: Record<string, OrderedCaveatSpec> = {
  expires: { field: 'at', keep: 'min' }, // earliest expiry dominates
  not_before: { field: 'at', keep: 'max' }, // latest not-before dominates
  max_blast_radius: { field: 'max', keep: 'min' }, // smallest radius dominates
  delegation_depth: { field: 'max', keep: 'min' }, // smallest depth dominates
  budget_alloc: { field: 'limit', keep: 'min' }, // smallest allocation dominates
};

function caveatKey(cv: Caveat): string {
  try {
    return JSON.stringify(cv);
  } catch {
    return `${cv.type}:<unserializable>`;
  }
}

export function ruleRedundantCaveat(policy: NormalizedPolicy): Finding[] {
  const out: Finding[] = [];

  // (a) exact-duplicate caveats.
  const seen = new Map<string, number>();
  policy.caveats.forEach((cv, i) => {
    if (cv === null || typeof cv !== 'object') return;
    const k = caveatKey(cv);
    const first = seen.get(k);
    if (first !== undefined) {
      out.push(find('redundant-caveat', 'warn', `caveat ${i} ('${cv.type}') is an exact duplicate of caveat ${first} — dead policy`, `caveats[${i}]`));
    } else {
      seen.set(k, i);
    }
  });

  // (b) same-type domination: a looser caveat that a stricter one of the same type always subsumes.
  for (const [type, spec] of Object.entries(ORDERED_CAVEATS)) {
    const entries = policy.caveats
      .map((cv, i) => ({ cv, i }))
      .filter((e) => e.cv !== null && typeof e.cv === 'object' && e.cv.type === type);
    const vals = entries.map((e) => ({ ...e, v: num(e.cv[spec.field]) })).filter((e): e is { cv: Caveat; i: number; v: number } => e.v !== undefined);
    if (vals.length < 2) continue;
    const binding = spec.keep === 'min' ? Math.min(...vals.map((e) => e.v)) : Math.max(...vals.map((e) => e.v));
    for (const e of vals) {
      if (e.v !== binding) {
        out.push(
          find(
            'redundant-caveat',
            'warn',
            `caveat ${e.i} ('${type}' ${spec.field}=${e.v}) is subsumed by a stricter '${type}' (${spec.field}=${binding}) — it can never bite`,
            `caveats[${e.i}]`,
          ),
        );
      }
    }
  }

  // (c) a predicate whose numeric `where` conjunction is UNSATISFIABLE never matches — dead policy.
  policy.predicates.forEach((p, i) => {
    if (p === null || typeof p !== 'object' || !Array.isArray(p.where)) return;
    if (!predicateNumericSatisfiable(p.where)) {
      out.push(find('redundant-caveat', 'warn', `predicate ${i} can never match — its numeric \`where\` constraints are unsatisfiable (dead policy)`, `predicates[${i}]`));
    } else {
      out.push(...nonBindingConditions(p.where, i));
    }
  });

  return out;
}

const NUMERIC_OPS = new Set(['lt', 'lte', 'gt', 'gte', 'eq']);

function intervalEq(a: NumInterval, b: NumInterval): boolean {
  return a.lo === b.lo && a.loInclusive === b.loInclusive && a.hi === b.hi && a.hiInclusive === b.hiInclusive;
}

/** A numeric leaf condition that does not tighten its field's interval is redundant (never binds). */
function nonBindingConditions(where: readonly Condition[], predIndex: number): Finding[] {
  const byField = new Map<string, { c: LeafCondition; i: number }[]>();
  where.forEach((c, i) => {
    if (!isLeafCondition(c)) return;
    if (c.ref !== undefined) return;
    if (typeof c.op !== 'string' || !NUMERIC_OPS.has(c.op)) return;
    if (num(c.value) === undefined) return;
    const arr = byField.get(c.field) ?? [];
    arr.push({ c, i });
    byField.set(c.field, arr);
  });

  const out: Finding[] = [];
  for (const [field, conds] of byField) {
    if (conds.length < 2) continue;
    const full = conds.reduce<NumInterval>((iv, e) => tightenInterval(iv, e.c.op, e.c.value), FULL_INTERVAL);
    if (intervalEmpty(full)) continue; // the whole-predicate unsat case is reported in (c)
    for (const e of conds) {
      const without = conds.filter((x) => x !== e).reduce<NumInterval>((iv, x) => tightenInterval(iv, x.c.op, x.c.value), FULL_INTERVAL);
      if (intervalEq(without, full)) {
        out.push(
          find(
            'redundant-caveat',
            'info',
            `condition on '${field}' (${e.c.op} ${String(e.c.value)}) does not tighten the authority — redundant with the other bounds on this field`,
            `predicates[${predIndex}].where[${e.i}]`,
          ),
        );
      }
    }
  }
  return out;
}

// ---- 4. dangerous reachability --------------------------------------------------------------------

export function ruleDangerousReachability(
  policy: NormalizedPolicy,
  dangerous: readonly string[],
  extraTargets: readonly DangerousTarget[],
  opts: AnalyzerOptions,
): Finding[] {
  const out: Finding[] = [];
  const input = analyzerInput(policy);
  const { concrete } = declaredVerbs(policy.predicates);
  const derived: DangerousTarget[] = concrete.filter((v) => isDangerousVerb(v, dangerous)).map((verb) => ({ verb }));
  const targets = [...derived, ...extraTargets];
  const gate = gateDescription(policy);

  for (const t of targets) {
    let proven = false;
    let approximate = false;
    let reason: string | undefined;
    let witness: string;

    if (t.resource !== undefined) {
      const r = reachable(input, { verb: t.verb, resource: t.resource }, opts);
      proven = r.reachable && r.approximate !== true;
      approximate = r.approximate === true;
      reason = r.reason;
      witness = `${t.verb} ${t.resource}`;
    } else {
      const ad = alwaysDenies(input, t.verb, opts);
      proven = ad.alwaysDenies === false && ad.approximate !== true;
      approximate = ad.approximate === true;
      reason = ad.reason;
      witness = ad.witness !== undefined ? describeAction(ad.witness) : t.verb;
    }

    if (approximate) {
      out.push(
        find('dangerous-reachability', 'warn', `could not decide reachability of dangerous verb '${t.verb}' (undecidable${reason ? `: ${reason}` : ''})`),
      );
    } else if (proven) {
      if (gate === undefined) {
        out.push(find('dangerous-reachability', 'error', `dangerous action '${witness}' is REACHABLE with no budget / rate / step-up gate`));
      } else {
        out.push(find('dangerous-reachability', 'info', `dangerous action '${witness}' is reachable but gated by ${gate}`));
      }
    }
  }
  return out;
}

// ---- 5. missing safety floor ----------------------------------------------------------------------

/** A grant is non-trivial when any predicate grants a dangerous/wildcard verb, a wildcard resource, or is unconstrained. */
function isNonTrivial(policy: NormalizedPolicy, dangerous: readonly string[]): boolean {
  return policy.predicates.some((p) => {
    if (p === null || typeof p !== 'object') return false;
    const verbs = verbsOf(p.verb);
    const hasWhere = Array.isArray(p.where) && p.where.length > 0;
    return (
      verbs.includes('*') ||
      verbs.some((v) => isDangerousVerb(v, dangerous)) ||
      isWildcardResource(p.resource) ||
      !hasWhere
    );
  });
}

export function ruleMissingSafetyFloor(
  policy: NormalizedPolicy,
  cfg: { requireExpiry: boolean; requireScopeGate: boolean },
  dangerous: readonly string[],
): Finding[] {
  const out: Finding[] = [];
  if (policy.predicates.length === 0) return out; // nothing is granted; default-deny needs no floor

  if (cfg.requireExpiry && !hasCaveatOfType(policy.caveats, ['expires'])) {
    out.push(find('missing-safety-floor', 'warn', 'grant has no `expires` caveat — the authority never expires'));
  }
  if (cfg.requireScopeGate && isNonTrivial(policy, dangerous) && !hasCaveatOfType(policy.caveats, BUDGET_GATE_CAVEATS)) {
    out.push(
      find('missing-safety-floor', 'warn', `non-trivial grant has no blast-radius / rate / budget gate (${BUDGET_GATE_CAVEATS.join('/')})`),
    );
  }
  return out;
}
