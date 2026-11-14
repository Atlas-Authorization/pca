import { evaluateConditionTri, isGroupCondition, isLeafCondition, predicateMatches, type Condition, type Predicate } from '@atlasauth/pca';
import { contextOfAction, decideAction, probeSet, toModel, vetoApplies, type PolicyModel } from './enumerate';
import { thresholdsOf } from './exposure';
import { alwaysDenies, equivalent } from './index';
import { policyDigestOf } from './residual';
import type { AnalyzerAction, AnalyzerDecision, PolicyInput } from './types';

/**
 * POLICY COVERAGE (borrowed-ideas item 12, security contract C-252).
 *
 * `opa test --coverage` for PCA. Over a body of traffic (or tests) it reports which clauses of a policy ever DECIDED, which
 * never even matched, which the analyzer says are unreachable, how close the traffic came to each numeric threshold, and which
 * single-edit mutations of the policy (widen a cap, drop a prohibition, flip `<=` to `<`) the traffic cannot tell from the
 * original. A surviving mutant is a missing test, and comes with the action that would kill it. A mutant the analyzer proves
 * equivalent to the policy is not a gap and is excluded from the score. This is the policy-level twin of the repository's own
 * mutation gate.
 */

export interface DecisionWitness {
  decision: AnalyzerDecision;
  winner: { kind: 'permit' | 'veto' | 'tighten' | 'caveat' | 'none'; id: string | null };
  /** Every other clause that also fired. */
  also: string[];
}

export const permitId = (i: number): string => `permit[${i}]`;

/** The decision with the clause that decided it: a forbid beats an approval rule, which beats a permit. */
export function witnessOf(model: PolicyModel, action: AnalyzerAction): DecisionWitness {
  const decision = decideAction(model, action);
  const ctx = contextOfAction(action);
  const permits = model.predicates.map((p, i) => (predicateMatches(p, ctx) ? permitId(i) : null)).filter((x): x is string => x !== null);
  const vetoes = model.vetoes.filter((v) => vetoApplies(v, ctx));
  const tighten = model.tighten.filter((t) => evaluateConditionTri(t.when, ctx) !== 'false');
  const others = (win: string | null): string[] => [...permits, ...vetoes.map((v) => v.id), ...tighten.map((t) => t.id)].filter((id) => id !== win);
  const done = (kind: DecisionWitness['winner']['kind'], id: string | null): DecisionWitness => ({ decision, winner: { kind, id }, also: others(id) });
  if (!model.caveatSat || decision === 'deny') {
    if (!model.caveatSat) return done('caveat', 'caveats');
    if (permits.length === 0) return { decision, winner: { kind: 'none', id: null }, also: others(null) };
    const veto = vetoes.find((v) => v.kind === 'deny');
    if (veto) return done('veto', veto.id);
    const t = tighten.find((x) => x.signal === 'deny');
    if (t) return done('tighten', t.id);
    return done('caveat', 'caveats'); // reversibility cap or an ancestor of the chain
  }
  if (decision === 'escalate') {
    const veto = vetoes.find((v) => v.kind === 'approval');
    if (veto) return done('veto', veto.id);
    return done('tighten', tighten[0]?.id ?? null);
  }
  return done('permit', permits[0] ?? null);
}

export interface ClauseCoverage {
  id: string;
  kind: 'permit' | 'veto' | 'tighten';
  /** Traffic actions where the clause fired (matched). */
  matched: number;
  /** Traffic actions the clause decided. */
  decisive: number;
  /** The analyzer's view: can any action reach this clause at all? */
  reachable: boolean | 'unknown';
}

export interface BoundaryCoverage {
  path: string;
  threshold: number;
  below: boolean;
  at: boolean;
  above: boolean;
}

export interface Mutant {
  id: string;
  description: string;
  /** An action on which the mutant differs from the policy: add it to the tests to kill this mutant. */
  killer?: AnalyzerAction;
}

export interface CoverageReport {
  traffic: number;
  policyDigest: string;
  clauses: ClauseCoverage[];
  /** Clauses no traffic action matched / decided. */
  neverMatched: string[];
  neverDecisive: string[];
  /** Reachable per the analyzer, but untouched by traffic. */
  untested: string[];
  unreachable: string[];
  boundaries: BoundaryCoverage[];
  mutants: { total: number; killed: number; equivalent: number; survivors: Mutant[] };
  /** Ratios in [0,1]; 1 when the denominator is empty. */
  score: { clauses: number; boundaries: number; mutation: number };
}

export interface CoverageOptions {
  /** Distance counted as "next to" a threshold (default 1, one minor unit). */
  epsilon?: number;
  /** Most mutants generated (deterministic order; default 200). */
  maxMutants?: number;
}

// ---- mutation operators ---------------------------------------------------------------------------

function variantsOfCond(c: Condition, eps: number): Array<{ cond: Condition; what: string }> {
  if (c === null || typeof c !== 'object') return [];
  if (isGroupCondition(c)) {
    const out: Array<{ cond: Condition; what: string }> = [];
    if ('not' in c) {
      for (const v of variantsOfCond(c.not, eps)) out.push({ cond: { not: v.cond }, what: `not(${v.what})` });
      return out;
    }
    const isAll = 'all_of' in c;
    const kids = isAll ? c.all_of : c.any_of;
    kids.forEach((k, i) => {
      for (const v of variantsOfCond(k, eps)) {
        const next = kids.map((x, j) => (j === i ? v.cond : x));
        out.push({ cond: isAll ? { all_of: next } : { any_of: next }, what: `${isAll ? 'all_of' : 'any_of'}[${i}] ${v.what}` });
      }
    });
    return out;
  }
  if (!isLeafCondition(c) || c.ref !== undefined) return [];
  const out: Array<{ cond: Condition; what: string }> = [];
  const name = c.field.replace(/^action\.params\./, '');
  if (typeof c.value === 'number' && Number.isFinite(c.value) && ['lt', 'lte', 'gt', 'gte', 'eq'].includes(c.op)) {
    out.push({ cond: { ...c, value: c.value + eps }, what: `${name} ${c.op} ${c.value} -> ${c.value + eps}` });
    out.push({ cond: { ...c, value: c.value - eps }, what: `${name} ${c.op} ${c.value} -> ${c.value - eps}` });
  }
  const flip: Record<string, string> = { lt: 'lte', lte: 'lt', gt: 'gte', gte: 'gt', eq: 'ne', ne: 'eq', in: 'nin', nin: 'in' };
  if (flip[c.op] !== undefined) out.push({ cond: { ...c, op: flip[c.op] as never }, what: `${name} ${c.op} -> ${flip[c.op]}` });
  return out;
}

function mutantsOf(policy: PolicyModel, eps: number): Array<{ id: string; description: string; policy: PolicyInput }> {
  const out: Array<{ id: string; description: string; policy: PolicyInput }> = [];
  const mk = (over: Partial<PolicyModel>): PolicyInput => ({ predicates: policy.predicates, caveats: policy.caveats, vetoes: policy.vetoes, tighten: policy.tighten, ...over });
  policy.predicates.forEach((p, i) => {
    out.push({ id: `drop-${permitId(i)}`, description: `drop ${permitId(i)}`, policy: mk({ predicates: policy.predicates.filter((_, j) => j !== i) }) });
    (p.where ?? []).forEach((c, j) => {
      for (const v of variantsOfCond(c, eps)) {
        const np: Predicate = { ...p, where: (p.where ?? []).map((x, k) => (k === j ? v.cond : x)) };
        out.push({ id: `${permitId(i)}.where[${j}]:${v.what}`, description: `${permitId(i)}: ${v.what}`, policy: mk({ predicates: policy.predicates.map((x, k) => (k === i ? np : x)) }) });
      }
      const rest = (p.where ?? []).filter((_, k) => k !== j);
      out.push({ id: `${permitId(i)}.where[${j}]:drop`, description: `${permitId(i)}: drop condition ${j}`, policy: mk({ predicates: policy.predicates.map((x, k) => (k === i ? { ...p, where: rest } : x)) }) });
    });
  });
  policy.vetoes.forEach((v, i) => {
    out.push({ id: `drop-veto:${v.id}`, description: `drop prohibition ${v.id}`, policy: mk({ vetoes: policy.vetoes.filter((_, j) => j !== i) }) });
    if (v.over) out.push({ id: `veto:${v.id}:threshold+`, description: `raise the ${v.id} threshold by ${eps}`, policy: mk({ vetoes: policy.vetoes.map((x, j) => (j === i ? { ...x, over: { ...v.over!, threshold: v.over!.threshold + eps } } : x)) }) });
  });
  policy.tighten.forEach((t, i) => out.push({ id: `drop-tighten:${t.id}`, description: `drop tighten rule ${t.id}`, policy: mk({ tighten: policy.tighten.filter((_, j) => j !== i) }) }));
  return out;
}

/** Coverage of `policy` by `traffic` (production traffic, simulated actions or the cases of a test document). */
export function coverage(policy: PolicyInput, traffic: readonly AnalyzerAction[], o: CoverageOptions = {}): CoverageReport {
  const model = toModel(policy);
  const eps = o.epsilon ?? 1;
  const ids: Array<{ id: string; kind: ClauseCoverage['kind'] }> = [
    ...model.predicates.map((_, i) => ({ id: permitId(i), kind: 'permit' as const })),
    ...model.vetoes.map((v) => ({ id: v.id, kind: 'veto' as const })),
    ...model.tighten.map((t) => ({ id: t.id, kind: 'tighten' as const })),
  ];
  const matched = new Map<string, number>();
  const decisive = new Map<string, number>();
  const bump = (m: Map<string, number>, k: string | null) => k !== null && m.set(k, (m.get(k) ?? 0) + 1);
  for (const a of traffic) {
    const w = witnessOf(model, a);
    bump(decisive, w.winner.id);
    for (const id of [w.winner.id, ...w.also]) bump(matched, id);
  }
  const reach = (kind: ClauseCoverage['kind'], idx: number): boolean | 'unknown' => {
    if (kind === 'permit') {
      const r = alwaysDenies({ predicates: [model.predicates[idx]!], caveats: model.caveats });
      return r.approximate ? 'unknown' : !r.alwaysDenies;
    }
    if (kind === 'veto') {
      const r = alwaysDenies({ predicates: [model.vetoes[idx]!.when] });
      return r.approximate ? 'unknown' : !r.alwaysDenies;
    }
    return 'unknown';
  };
  const clauses: ClauseCoverage[] = ids.map((c, n) => ({
    id: c.id,
    kind: c.kind,
    matched: matched.get(c.id) ?? 0,
    decisive: decisive.get(c.id) ?? 0,
    reachable: reach(c.kind, c.kind === 'permit' ? n : c.kind === 'veto' ? n - model.predicates.length : n - model.predicates.length - model.vetoes.length),
  }));
  const paths = new Set<string>();
  for (const p of probeSet(model)) {
    const walk = (c: Condition): void => {
      if (c === null || typeof c !== 'object') return;
      if (isGroupCondition(c)) {
        if ('all_of' in c) c.all_of.forEach(walk);
        else if ('any_of' in c) c.any_of.forEach(walk);
        else walk(c.not);
      } else if (isLeafCondition(c) && c.field.startsWith('action.params.') && ['lt', 'lte', 'gt', 'gte', 'eq', 'in', 'nin'].includes(c.op)) paths.add(c.field);
    };
    (p.where ?? []).forEach(walk);
  }
  for (const v of model.vetoes) if (v.over) paths.add(v.over.path);
  const boundaries: BoundaryCoverage[] = [];
  for (const path of [...paths].sort()) {
    const name = path.slice('action.params.'.length);
    const vals = traffic.map((a) => (a.params ?? {})[name]).filter((v): v is number => typeof v === 'number');
    for (const t of thresholdsOf(model, path)) {
      boundaries.push({ path, threshold: t, at: vals.some((v) => v === t), below: vals.some((v) => v < t && v >= t - eps), above: vals.some((v) => v > t && v <= t + eps) });
    }
  }
  const survivors: Mutant[] = [];
  let killed = 0;
  let equiv = 0;
  const all = mutantsOf(model, eps).slice(0, o.maxMutants ?? 200);
  const base = traffic.map((a) => decideAction(model, a));
  for (const m of all) {
    const mm = toModel(m.policy);
    if (traffic.some((a, i) => decideAction(mm, a) !== base[i])) {
      killed++;
      continue;
    }
    const eq = equivalent(policy, m.policy);
    if (eq.equivalent) {
      equiv++;
      continue;
    }
    survivors.push({ id: m.id, description: m.description, ...(eq.counterexample ? { killer: eq.counterexample } : {}) });
  }
  const ratio = (n: number, d: number): number => (d === 0 ? 1 : n / d);
  const live = clauses.filter((c) => c.reachable !== false);
  return {
    traffic: traffic.length,
    policyDigest: policyDigestOf(model),
    clauses,
    neverMatched: clauses.filter((c) => c.matched === 0).map((c) => c.id),
    neverDecisive: clauses.filter((c) => c.decisive === 0).map((c) => c.id),
    untested: clauses.filter((c) => c.reachable !== false && c.matched === 0).map((c) => c.id),
    unreachable: clauses.filter((c) => c.reachable === false).map((c) => c.id),
    boundaries,
    mutants: { total: all.length, killed, equivalent: equiv, survivors },
    score: {
      clauses: ratio(live.filter((c) => c.decisive > 0).length, live.length),
      boundaries: ratio(boundaries.filter((b) => b.at && b.below && b.above).length, boundaries.length),
      mutation: ratio(killed, all.length - equiv),
    },
  };
}

/** A CI gate over a coverage report. */
export function coverageGate(r: CoverageReport, min: { clauses?: number; boundaries?: number; mutation?: number; maxSurvivors?: number } = {}): { ok: boolean; reasons: string[] } {
  const reasons: string[] = [];
  if (r.score.clauses < (min.clauses ?? 0)) reasons.push(`clause coverage ${r.score.clauses.toFixed(2)} < ${min.clauses}`);
  if (r.score.boundaries < (min.boundaries ?? 0)) reasons.push(`boundary coverage ${r.score.boundaries.toFixed(2)} < ${min.boundaries}`);
  if (r.score.mutation < (min.mutation ?? 0)) reasons.push(`mutation score ${r.score.mutation.toFixed(2)} < ${min.mutation}`);
  if (min.maxSurvivors !== undefined && r.mutants.survivors.length > min.maxSurvivors) reasons.push(`${r.mutants.survivors.length} surviving mutants > ${min.maxSurvivors}`);
  if (r.unreachable.length > 0) reasons.push(`unreachable clauses: ${r.unreachable.join(', ')}`);
  return { ok: reasons.length === 0, reasons };
}
