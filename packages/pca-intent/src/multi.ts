import type { Caveat, Predicate } from '@atlasauth/pca';
import { boxesToPredicates } from './learner';
import { createLearner, emitIntentMap, grantDigest, intentMapDigest, mapLearnerOptions, omegaFromJSON, omegaToJSON, verifyIntentMap, type AggregationRecord, type IntentMap, type IntentMapMetrics } from './map';
import { cellOf, cellStats, decodeCell, DEFAULT_HARM, repValue, verbCellCount, type CatValue, type Dim, type Omega, type VerbSpace } from './omega';
import { regionOfCell } from './region';

/**
 * MULTI-PRINCIPAL INTENT (spec §4.3, T5; roadmap M7).
 *
 * Every rule below decides, per cell of a SHARED Ω, whether the joint grant admits it from the principals' own
 * conservative grants G_i (the `in_grant` bits of their replay-verified maps):
 *   - unanimity            : every principal admits the cell (the intersection; T5);
 *   - quorum(k)            : at least k principals admit it;
 *   - weighted(w, T)       : the admitting principals' integer weights sum to at least T.
 * Any rule may name VETOERS: principals whose own grant must admit the cell regardless of the rule. A vetoer's
 * own measure of the joint grant is then bounded by T5's argument: G ⊆ G_v, so R_v(G) ≤ R_v(G_v) (T6). A
 * weighted rule makes principal i an implicit vetoer when T > W − w_i (W the total weight): without i the
 * others cannot reach T. Nothing comparable holds for a non-vetoer under a non-unanimous rule; for them the map
 * reports their own posterior estimate of the joint grant (`per_principal`) instead of a bound.
 *
 * Joint acceptance p_ppm is the probability, under independent posteriors, that the rule would admit the cell if
 * each principal's acceptance were drawn from their p (exact dynamic programming over the weight sum).
 *
 * CROSS-ORG maps (`crossOrgAggregate`): maps built over DIFFERENT Ω are first replay-verified, then LIFTED onto the
 * common refinement of their Ω (`commonRefinement`): each map's observations are re-applied as value-space
 * regions, so nothing any organisation asserted is lost or widened. A verb a map never covered is denied for that
 * principal (∅ prior mass 1).
 */

export type AggregationRule =
  | { kind: 'unanimity'; vetoers?: string[] }
  | { kind: 'quorum'; k: number; vetoers?: string[] }
  | { kind: 'weighted'; weights: Record<string, number>; threshold: number; vetoers?: string[] };

const PPM = 1_000_000;
const ppm = (x: number) => Math.round(x * PPM);

/** A rule in normal form: integer weights, an integer threshold, and per-principal veto flags. */
export interface NormalRule {
  weights: number[];
  threshold: number;
  veto: boolean[];
}

export function normalizeRule(rule: AggregationRule, refs: string[]): NormalRule {
  const vetoers = new Set(rule.vetoers ?? []);
  for (const v of vetoers) if (!refs.includes(v)) throw new Error(`aggregateIntentMaps: vetoer ${v} is not one of the maps`);
  const veto = refs.map((r) => vetoers.has(r));
  if (rule.kind === 'unanimity') return { weights: refs.map(() => 1), threshold: refs.length, veto };
  if (rule.kind === 'quorum') {
    if (!(Number.isInteger(rule.k) && rule.k >= 1 && rule.k <= refs.length)) throw new Error(`aggregateIntentMaps: quorum k must be an integer in [1, ${refs.length}]`);
    return { weights: refs.map(() => 1), threshold: rule.k, veto };
  }
  const weights = refs.map((r) => rule.weights[r]);
  if (weights.some((w) => !(Number.isInteger(w) && w! >= 0))) throw new Error('aggregateIntentMaps: every principal needs a non-negative integer weight');
  const W = (weights as number[]).reduce((s, w) => s + w, 0);
  if (!(Number.isInteger(rule.threshold) && rule.threshold >= 1 && rule.threshold <= W)) throw new Error(`aggregateIntentMaps: threshold must be an integer in [1, ${W}]`);
  return { weights: weights as number[], threshold: rule.threshold, veto };
}

/** Principals that bound the joint grant: explicit vetoers plus implicit ones (T > W − w_i). */
export function effectiveVetoers(rule: AggregationRule, refs: string[]): string[] {
  const n = normalizeRule(rule, refs);
  const W = n.weights.reduce((s, w) => s + w, 0);
  return refs.filter((_, i) => n.veto[i] || n.threshold > W - n.weights[i]!);
}

function admitted(n: NormalRule, ins: boolean[]): boolean {
  let s = 0;
  for (let i = 0; i < ins.length; i++) {
    if (n.veto[i] && !ins[i]) return false;
    if (ins[i]) s += n.weights[i]!;
  }
  return s >= n.threshold;
}

/** Does the rule admit, given which principals admit (vetoers must, the admitting weight must reach the threshold)? */
export function ruleAdmits(n: NormalRule, ins: boolean[]): boolean {
  return admitted(n, ins);
}

/** P(rule admits) with independent Bernoulli(p_i) acceptances: DP over the (capped) admitting weight. */
export function jointAcceptance(n: NormalRule, ps: number[]): number {
  let dist = new Float64Array(n.threshold + 1);
  dist[0] = 1;
  ps.forEach((p, i) => {
    const next = new Float64Array(n.threshold + 1);
    const w = n.weights[i]!;
    for (let s = 0; s <= n.threshold; s++) {
      const m = dist[s]!;
      if (m === 0) continue;
      next[Math.min(n.threshold, s + w)] = next[Math.min(n.threshold, s + w)]! + m * p;
      if (!n.veto[i]) next[s] = next[s]! + m * (1 - p);
    }
    dist = next;
  });
  return dist[n.threshold]!;
}

export interface AggregateOptions {
  /** Organisation label per intent_ref (reported, not interpreted). */
  orgs?: Record<string, string>;
}

/**
 * Aggregate single-principal maps over a SHARED Ω under a rule. The result is a map with `aggregation` set; its
 * numbers are recomputable from the inputs (`verifyAggregate`).
 */
export function aggregateIntentMaps(maps: readonly IntentMap[], rule: AggregationRule, opts: AggregateOptions = {}): IntentMap {
  if (maps.length === 0) throw new Error('aggregateIntentMaps: no maps');
  const om = JSON.stringify(maps[0]!.omega);
  if (maps.some((m) => JSON.stringify(m.omega) !== om)) throw new Error('aggregateIntentMaps: maps must share Ω (lift them with crossOrgAggregate)');
  if (maps.some((m) => m.aggregation || m.principals.length !== 1 || typeof m.intent_ref !== 'string')) {
    throw new Error('aggregateIntentMaps: every input must be a single-principal map with an intent_ref');
  }
  const refs = maps.map((m) => m.intent_ref!);
  if (new Set(refs).size !== refs.length) throw new Error('aggregateIntentMaps: duplicate principal');
  const n = normalizeRule(rule, refs);
  const omega = omegaFromJSON(maps[0]!.omega);
  const stats: { mass: number; harm: number }[] = [];
  for (const vs of omega.verbs) for (let c = 0; c < verbCellCount(vs); c++) stats.push(cellStats(vs, decodeCell(vs, c), DEFAULT_HARM));
  const cells = maps[0]!.cells.map((c, i) => ({
    verb: c.verb,
    cell: c.cell,
    p_ppm: ppm(jointAcceptance(n, maps.map((m) => m.cells[i]!.p_ppm / PPM))),
    in_grant: admitted(n, maps.map((m) => m.cells[i]!.in_grant)),
  }));
  const predicates: Predicate[] = [];
  const order = ['reversible', 'rate_limited', 'irreversible'];
  let worst = -1;
  let off = 0;
  for (const vs of omega.verbs) {
    const nc = verbCellCount(vs);
    const allowed = new Uint8Array(nc);
    let any = false;
    for (let c = 0; c < nc; c++) if (cells[off + c]!.in_grant) (allowed[c] = 1), (any = true);
    off += nc;
    if (!any) continue;
    worst = Math.max(worst, order.indexOf(vs.reversibility));
    predicates.push(...boxesToPredicates(vs, allowed));
  }
  const grant = { predicates, caveats: worst >= 0 ? [{ type: 'reversibility_max', class: order[worst]! } as Caveat] : [] };
  // Each principal's own posterior estimate of the JOINT grant.
  const per = maps.map((m, i) => {
    let R = 0;
    let B = 0;
    let Rmax = 0;
    m.cells.forEach((c, j) => {
      const p = c.p_ppm / PPM;
      const { mass, harm } = stats[j]!;
      Rmax += mass * (1 - p) * harm;
      if (cells[j]!.in_grant) R += mass * (1 - p) * harm;
      else B += mass * p;
    });
    return { intent_ref: refs[i]!, ...(opts.orgs?.[refs[i]!] ? { org: opts.orgs[refs[i]!] } : {}), R, B, F: Rmax > 0 ? 1 - R / Rmax : 1 };
  });
  const worstMetric = (k: keyof IntentMapMetrics, f: (a: number[]) => number) => f(maps.map((m) => (m.metrics[k] as number | null) ?? 0));
  const aggregation: AggregationRecord = {
    rule: rule.kind,
    ...(rule.kind === 'quorum' ? { k: rule.k } : {}),
    ...(rule.kind === 'weighted' ? { weights: Object.fromEntries(refs.map((r, i) => [r, n.weights[i]!])), threshold: rule.threshold } : {}),
    vetoers: refs.filter((_, i) => n.veto[i]),
    per_principal: per.map((x) => ({ intent_ref: x.intent_ref, ...(x.org ? { org: x.org } : {}), residual_risk_ppm: ppm(x.R), burden_ppm: ppm(x.B) })),
  };
  return {
    v: 1,
    kind: 'pca-intent-map',
    intent_ref: null,
    principals: refs,
    omega: maps[0]!.omega,
    learner: maps[0]!.learner,
    observations: maps.flatMap((m) => m.observations),
    cells,
    grant,
    grant_digest: grantDigest(grant),
    metrics: {
      // Every principal's own posterior estimate of the joint grant; the map reports the worst of them.
      residual_risk_ppm: Math.max(...aggregation.per_principal.map((x) => x.residual_risk_ppm)),
      burden_ppm: Math.max(...aggregation.per_principal.map((x) => x.burden_ppm)),
      uncertainty_ppm: worstMetric('uncertainty_ppm', (a) => Math.max(...a)),
      disagreement_ppm: worstMetric('disagreement_ppm', (a) => Math.max(...a)),
      mean_harm_ppm: maps[0]!.metrics.mean_harm_ppm,
      fidelity_est_ppm: ppm(Math.min(...per.map((x) => x.F))),
      entropy_mbits: worstMetric('entropy_mbits', (a) => a.reduce((s, x) => s + x, 0)),
      log2_vs_mbits: maps.some((m) => m.metrics.log2_vs_mbits === null) ? null : worstMetric('log2_vs_mbits', (a) => a.reduce((s, x) => s + x, 0)),
      questions: worstMetric('questions', (a) => a.reduce((s, x) => s + x, 0)),
      conflicts: worstMetric('conflicts', (a) => a.reduce((s, x) => s + x, 0)),
    },
    aggregation,
  };
}

/** The unanimity rule (T5): the joint grant is the intersection of the principals' conservative grants. */
export function combineIntentMaps(maps: readonly IntentMap[], opts: AggregateOptions = {}): IntentMap {
  return aggregateIntentMaps(maps, { kind: 'unanimity' }, opts);
}

/** The rule an aggregated map records. */
export function ruleOf(agg: IntentMap): AggregationRule {
  const a = agg.aggregation;
  if (!a) throw new Error('ruleOf: not an aggregated map');
  if (a.rule === 'unanimity') return { kind: 'unanimity', vetoers: a.vetoers };
  if (a.rule === 'quorum') return { kind: 'quorum', k: a.k!, vetoers: a.vetoers };
  return { kind: 'weighted', weights: a.weights!, threshold: a.threshold!, vetoers: a.vetoers };
}

/**
 * Verify an aggregated map against its inputs: replay-verify every input map, then recompute the aggregate and
 * compare digests. The inputs are the maps over the SHARED Ω (for cross-org use `verifyCrossOrgAggregate`).
 */
export function verifyAggregate(agg: IntentMap, inputs: readonly IntentMap[], opts: AggregateOptions = {}): { ok: boolean; problems: string[] } {
  const problems: string[] = [];
  try {
    inputs.forEach((m, i) => {
      const r = verifyIntentMap(m);
      if (!r.ok) problems.push(`input ${i}: ${r.problems.join('; ')}`);
    });
    if (problems.length) return { ok: false, problems };
    const again = aggregateIntentMaps(inputs, ruleOf(agg), opts);
    if (intentMapDigest(again) !== intentMapDigest(agg)) problems.push('aggregate does not match its recomputation');
  } catch (e) {
    problems.push(`recompute failed: ${(e as Error).message}`);
  }
  return { ok: problems.length === 0, problems };
}

// ---- cross-org: common refinement + lifting ----------------------------------------------------------

const SEV = ['reversible', 'rate_limited', 'irreversible'];

function mergeDim(a: Dim, b: Dim): Dim {
  if (a.kind !== b.kind) throw new Error(`commonRefinement: ${a.path} is numeric in one Ω and categorical in another`);
  if (a.kind === 'num' && b.kind === 'num') {
    if (a.lo !== b.lo || a.hi !== b.hi) throw new Error(`commonRefinement: ${a.path} has different domains ([${a.lo}, ${a.hi}] vs [${b.lo}, ${b.hi}])`);
    return { kind: 'num', path: a.path, lo: a.lo, hi: a.hi, dist: a.dist, cuts: [...new Set([...a.cuts, ...b.cuts])].sort((x, y) => x - y) };
  }
  const va = (a as { values: CatValue[] }).values;
  const vb = (b as { values: CatValue[] }).values;
  const ex = new Set<string>();
  const pre = new Set<string>();
  for (const v of [...va, ...vb]) {
    if (v.kind === 'exact') ex.add(v.value);
    else if (v.kind === 'prefix') pre.add(v.value);
  }
  return {
    kind: 'cat',
    path: a.path,
    values: [
      ...[...ex].sort().map((value) => ({ kind: 'exact' as const, value })),
      ...[...pre].sort().map((value) => ({ kind: 'prefix' as const, value })),
      { kind: 'other' as const, value: '⊥' },
    ],
  };
}

/**
 * The common refinement of several Ω: the union of their verbs; per verb the union of their dimensions; per
 * numeric dimension the union of the cuts (the domains must agree); per categorical dimension the union of the
 * named values. Every input Ω's cells are unions of the result's cells, so value-space regions map exactly.
 */
export function commonRefinement(omegas: readonly Omega[]): Omega {
  const byVerb = new Map<string, VerbSpace>();
  const approx = new Set<string>();
  for (const o of omegas) {
    o.approximate.forEach((x) => approx.add(x));
    for (const vs of o.verbs) {
      const cur = byVerb.get(vs.verb);
      if (!cur) {
        byVerb.set(vs.verb, { verb: vs.verb, reversibility: vs.reversibility, weight: 0, dims: vs.dims.map((d) => JSON.parse(JSON.stringify(d)) as Dim) });
        continue;
      }
      if (SEV.indexOf(vs.reversibility) > SEV.indexOf(cur.reversibility)) cur.reversibility = vs.reversibility;
      for (const d of vs.dims) {
        const i = cur.dims.findIndex((x) => x.path === d.path);
        if (i < 0) cur.dims.push(JSON.parse(JSON.stringify(d)) as Dim);
        else cur.dims[i] = mergeDim(cur.dims[i]!, d);
      }
    }
  }
  const verbs = [...byVerb.values()].sort((a, b) => (a.verb < b.verb ? -1 : a.verb > b.verb ? 1 : 0));
  verbs.forEach((v) => {
    v.dims.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    v.weight = 1 / verbs.length;
  });
  return { v: 1, verbs, approximate: [...approx].sort() };
}

/**
 * Lift a replay-verified single-principal map onto a refinement of its Ω: same learner parameters, same
 * observations re-applied as value-space regions, and ∅ prior mass 1 for every verb the map did not cover (the
 * principal never authorised it). With τ = 1 and η = 0 the lifted conservative grant is contained in the
 * original one (pending theorem L-lift, pca-intent-formal.md).
 */
export function liftIntentMap(m: IntentMap, target: Omega): IntentMap {
  if (m.aggregation || m.principals.length > 1) throw new Error('liftIntentMap: lift single-principal maps, then aggregate');
  const src = omegaFromJSON(m.omega);
  const o = mapLearnerOptions(m);
  const known = new Set(src.verbs.map((v) => v.verb));
  // own entries only, built with Object.fromEntries (see map.ts nullMassOf): verbs spelled like Object.prototype members are ordinary keys
  const srcMass = o.nullMass as Record<string, number> | undefined;
  const nullMass: Record<string, number> = Object.fromEntries(
    target.verbs.map((vs) => [vs.verb, known.has(vs.verb) ? ((srcMass !== undefined && Object.prototype.hasOwnProperty.call(srcMass, vs.verb) ? srcMass[vs.verb] : undefined) ?? 0.2) : 1]),
  );
  const l = createLearner(target, { ...o, nullMass });
  for (const ob of m.observations) {
    const svs = src.verbs.find((v) => v.verb === ob.verb);
    const tvs = target.verbs.find((v) => v.verb === ob.verb);
    if (!svs || !tvs) throw new Error(`liftIntentMap: verb ${ob.verb} missing from Ω`);
    const values: Record<string, number | string> = { ...ob.values };
    for (const d of tvs.dims) if (!(d.path in values)) values[d.path] = repValue(d, 0);
    const own = cellOf(svs, { verb: ob.verb, values: ob.values });
    if (!own) throw new Error(`liftIntentMap: an observation of ${ob.verb} lies outside the map's own Ω`);
    const region = ob.region ?? regionOfCell(svs, own);
    l.observe({ verb: ob.verb, values }, ob.y, ob.source, region);
  }
  return emitIntentMap(l, m.intent_ref);
}

/**
 * Cross-org aggregation: replay-verify every map, lift all of them onto the common refinement of their Ω, then
 * aggregate. Throws if any input map fails replay verification.
 */
export function crossOrgAggregate(maps: readonly IntentMap[], rule: AggregationRule, opts: AggregateOptions = {}): { aggregate: IntentMap; lifted: IntentMap[]; omega: Omega } {
  maps.forEach((m, i) => {
    const r = verifyIntentMap(m);
    if (!r.ok) throw new Error(`crossOrgAggregate: map ${i} does not verify: ${r.problems.join('; ')}`);
  });
  const omega = commonRefinement(maps.map((m) => omegaFromJSON(m.omega)));
  const lifted = maps.map((m) => liftIntentMap(m, omega));
  return { aggregate: aggregateIntentMaps(lifted, rule, opts), lifted, omega };
}

/** Verify a cross-org aggregate by recomputing it from the ORIGINAL maps. */
export function verifyCrossOrgAggregate(agg: IntentMap, maps: readonly IntentMap[], opts: AggregateOptions = {}): { ok: boolean; problems: string[] } {
  try {
    const again = crossOrgAggregate(maps, ruleOf(agg), opts).aggregate;
    return intentMapDigest(again) === intentMapDigest(agg) ? { ok: true, problems: [] } : { ok: false, problems: ['aggregate does not match its recomputation'] };
  } catch (e) {
    return { ok: false, problems: [(e as Error).message] };
  }
}

/** Ω of an aggregated or single map as JSON (convenience for callers that compare maps). */
export const omegaKey = (o: Omega): string => JSON.stringify(omegaToJSON(o));
