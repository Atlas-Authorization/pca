import { hashCanonical, type Caveat, type Predicate } from '@atlasauth/pca';
import { intentMapDigest as coreIntentMapDigest } from '@atlasauth/pca/ext/intent';
import { IntentLearner, hypothesisClassName, type HypothesisClassName, type HypothesisClassSpec, type LearnerOptions, type Observation, type Strategy } from './learner';
import type { CatValue, Dim, Omega, Outcome } from './omega';
import type { PolicyInput } from './policy';
import type { Region } from './region';

/**
 * THE INTENT MAP (spec §2, §6): a content-addressed JSON artifact that holds
 *   - Ω (the typed outcome space),
 *   - the hypothesis class and prior,
 *   - every question asked and every answer (elicitation, witnesses, runtime divergences),
 *   - the learned acceptance probability p_n per cell,
 *   - the conservative grant G_τ, and
 *   - the quantified fidelity: R̂, B̂, U, H(π_n), log₂|VS_n|, F̂.
 * It binds to the intent statement by `intent_ref`, and the grant binds to the map by digest (see
 * `intentGoal`). The map is REPLAYABLE: `verifyIntentMap` rebuilds the learner from Ω + prior + observations and
 * checks that every number and the grant are reproduced, so a relying party does not trust the map's numbers.
 * All probabilities and metrics are integers in parts-per-million (ppm) so the digest is language-portable.
 */

export { INTENT_MAP_DOMAIN } from '@atlasauth/pca/ext/intent';
const PPM = 1_000_000;
const ppm = (x: number) => Math.round(x * PPM);

export interface DimJSON {
  kind: 'num' | 'cat';
  path: string;
  lo?: number;
  hi?: number;
  cuts?: number[];
  dist?: 'uniform' | 'loguniform';
  values?: CatValue[];
}

export interface OmegaJSON {
  verbs: { verb: string; reversibility: string; w: number; dims: DimJSON[] }[];
  approximate: string[];
}

export interface IntentMapMetrics {
  residual_risk_ppm: number;
  burden_ppm: number;
  uncertainty_ppm: number;
  disagreement_ppm: number;
  mean_harm_ppm: number;
  fidelity_est_ppm: number;
  entropy_mbits: number;
  log2_vs_mbits: number | null;
  questions: number;
  conflicts: number;
}

/** How a combined map was aggregated (multi-principal, spec §4.3 / M7). Absent on a single-principal map. */
export interface AggregationRecord {
  rule: 'unanimity' | 'quorum' | 'weighted';
  /** quorum: the number of principals that must admit a cell. */
  k?: number;
  /** weighted: integer weight per principal (intent_ref), and the integer threshold the admitting weight must reach. */
  weights?: Record<string, number>;
  threshold?: number;
  /** principals (intent_refs) whose own grant bounds the joint grant regardless of the rule. */
  vetoers: string[];
  /** Each principal's OWN posterior estimate of the joint grant (ppm), so nobody has to trust a summary. */
  per_principal: { intent_ref: string; org?: string; residual_risk_ppm: number; burden_ppm: number }[];
}

export interface MapAnchorJSON {
  policy: { predicates: Predicate[]; caveats: Caveat[] };
  lambda_milli: number;
}

export interface IntentMap {
  v: 1;
  kind: 'pca-intent-map';
  intent_ref: string | null;
  /** intent refs of every principal whose map was folded in (multi-principal intersection). */
  principals: string[];
  omega: OmegaJSON;
  learner: {
    /** decision-list/v1: one-dimension rule conditions (legacy); decision-list/v2: box (conjunctive) rule conditions. */
    hypothesis_class: HypothesisClassName;
    /** union: k; decision-list: max_rules; both: the Occam decay in ppm. Absent for the box class. */
    class_params?: { k?: number; max_rules?: number; decay_ppm: number };
    /** Agnostic selection slack (absent = Bayesian / version-space posterior). */
    agnostic_slack?: number;
    eta_ppm: number;
    tau_ppm: number;
    strategy: Strategy;
    null_mass_ppm: Record<string, number>;
    anchor?: MapAnchorJSON;
    /** The k-compiler committee prior (mixture of anchors), spec §4.2a. */
    anchors?: MapAnchorJSON[];
    /** v2 monotone prior (T30): downward-closed along these accumulator dimensions; off-class weight in ppm. */
    monotone?: { paths: string[]; off_ppm: number };
    /** v2 §2.5 asymmetric answer noise (absent: η⁺ = η⁻ = eta, the v1 model). */
    noise?: { eta_pos_ppm: number; eta_neg_ppm: number };
    /** v2 §3.12 population mixture prior: β and the released per-cell acceptance rates q_c (flat cell index per verb). */
    prior_mix?: { beta_ppm: number; cells: { verb: string; cell: number; q_ppm: number }[] };
  };
  observations: { verb: string; values: Record<string, number | string>; y: 0 | 1; source: Observation['source']; region?: Region }[];
  cells: { verb: string; cell: number[]; p_ppm: number; in_grant: boolean }[];
  grant: { predicates: Predicate[]; caveats: Caveat[] };
  grant_digest: string;
  metrics: IntentMapMetrics;
  aggregation?: AggregationRecord;
}

export function omegaToJSON(o: Omega): OmegaJSON {
  const ws = o.verbs.map((v) => v.weight);
  const equal = ws.every((w) => Math.abs(w - ws[0]!) < 1e-15);
  return {
    verbs: o.verbs.map((v) => ({
      verb: v.verb,
      reversibility: v.reversibility,
      w: equal ? 1 : Math.max(1, Math.round(v.weight * PPM)),
      dims: v.dims.map((d): DimJSON => (d.kind === 'num' ? { kind: 'num', path: d.path, lo: d.lo, hi: d.hi, cuts: [...d.cuts], dist: d.dist } : { kind: 'cat', path: d.path, values: d.values.map((x) => ({ ...x })) })),
    })),
    approximate: [...o.approximate],
  };
}

export function omegaFromJSON(j: OmegaJSON): Omega {
  const tot = j.verbs.reduce((s, v) => s + v.w, 0);
  return {
    v: 1,
    approximate: [...j.approximate],
    verbs: j.verbs.map((v) => ({
      verb: v.verb,
      reversibility: v.reversibility as Omega['verbs'][number]['reversibility'],
      weight: v.w / tot,
      dims: v.dims.map((d): Dim => (d.kind === 'num' ? { kind: 'num', path: d.path, lo: d.lo!, hi: d.hi!, cuts: [...(d.cuts ?? [])], dist: d.dist ?? 'uniform' } : { kind: 'cat', path: d.path, values: (d.values ?? []).map((x) => ({ ...x })) })),
    })),
  };
}

export function grantDigest(g: PolicyInput): string {
  return hashCanonical({ d: 'atlas-pca/intent-grant/v1', g: JSON.parse(JSON.stringify({ predicates: g.predicates, caveats: 'caveats' in g ? g.caveats : [] })) as unknown });
}

/** Content address of an Intent Map (the core definition, so the server and relying parties agree). */
export function intentMapDigest(m: IntentMap): string {
  return coreIntentMapDigest(m);
}

function metricsOf(l: IntentLearner): IntentMapMetrics {
  const m = l.metrics();
  let rmax = 0;
  for (const c of l.cells()) rmax += c.mass * (1 - c.p) * c.harm;
  return {
    residual_risk_ppm: ppm(m.residualRisk),
    burden_ppm: ppm(m.burden),
    uncertainty_ppm: ppm(m.uncertainty),
    disagreement_ppm: ppm(m.disagreementMass),
    mean_harm_ppm: ppm(m.meanHarm),
    fidelity_est_ppm: ppm(rmax > 0 ? 1 - m.residualRisk / rmax : 1),
    entropy_mbits: Math.round(m.entropyBits * 1000),
    log2_vs_mbits: m.log2VersionSpace === null ? null : Math.round(m.log2VersionSpace * 1000),
    questions: m.questions,
    conflicts: m.conflicts,
  };
}

/**
 * Options that are serialisable into the map. `nullMass` is resolved per verb; anchors are stored verbatim.
 */
export interface MapLearnerOptions {
  eta?: number;
  tau?: number;
  strategy?: Strategy;
  nullMass?: number | Record<string, number>;
  anchor?: { policy: { predicates: Predicate[]; caveats?: Caveat[] }; lambda: number };
  anchors?: { policy: { predicates: Predicate[]; caveats?: Caveat[] }; lambda: number }[];
  hypothesisClass?: HypothesisClassSpec;
  agnosticSlack?: number;
  /** Default prior mass of ∅ for a verb `nullMass` does not name. Default 0.2. */
  defaultNullMass?: number;
  /** v2 monotone prior (see LearnerOptions.monotone). */
  monotone?: { paths: string[]; offMass?: number };
  /** v2 asymmetric noise η⁺ / η⁻ (see LearnerOptions.etaPos / etaNeg). */
  etaPos?: number;
  etaNeg?: number;
  /**
   * v2 population mixture prior as DATA (so the map can carry it): weight(θ) = Π_c q_c^{1[c∈θ]} (1 − q_c)^{1[c∉θ]} over the
   * listed cells of each verb, mixed with weight β (LearnerOptions.priorMix; the same formula as pca-wallet populationPrior).
   */
  priorMix?: { beta: number; cells: { verb: string; cell: number; q: number }[] };
}

/** The learner's priorMix function for a data-form population prior (ppm-quantised like every map number). */
function priorMixOf(pm: NonNullable<MapLearnerOptions['priorMix']>): NonNullable<LearnerOptions['priorMix']> {
  const byVerb = new Map<string, { cell: number; lq: number; lnq: number }[]>();
  for (const c of pm.cells) {
    const q = qz(c.q);
    if (!(q >= 0 && q <= 1) || !Number.isSafeInteger(c.cell) || c.cell < 0) throw new Error('pca-intent: priorMix cells need q in [0, 1] and a cell index >= 0');
    const list = byVerb.get(c.verb) ?? [];
    list.push({ cell: c.cell, lq: Math.log(q), lnq: Math.log(1 - q) });
    byVerb.set(c.verb, list);
  }
  return {
    beta: qz(pm.beta),
    weight: (vs, contains) => {
      let lw = 0;
      for (const t of byVerb.get(vs.verb) ?? []) lw += contains(t.cell) ? t.lq : t.lnq;
      return Math.exp(lw);
    },
  };
}

const qz = (x: number) => Math.round(x * PPM) / PPM;
const anchorOpt = (a: { policy: { predicates: Predicate[]; caveats?: Caveat[] }; lambda: number }) => ({ policy: { predicates: a.policy.predicates, caveats: a.policy.caveats ?? [] }, lambda: Math.round(a.lambda * 1000) / 1000 });
const anchorJSON = (a: { policy: { predicates: Predicate[]; caveats?: Caveat[] }; lambda: number }): MapAnchorJSON => ({ policy: { predicates: a.policy.predicates, caveats: a.policy.caveats ?? [] }, lambda_milli: Math.round(a.lambda * 1000) });

function quantizeClass(h: HypothesisClassSpec | undefined): HypothesisClassSpec {
  if (!h || h.kind === 'box') return { kind: 'box' };
  const decay = qz(h.decay ?? 0.25);
  return h.kind === 'union' ? { kind: 'union', k: h.k, decay } : { kind: 'decision-list', maxRules: h.maxRules, decay, conditions: h.conditions ?? 'box' };
}

function nullMassOf(o: MapLearnerOptions, verb: string): number {
  const nm = o.nullMass;
  if (typeof nm === 'number') return nm;
  // own entries only: a verb spelled like an Object.prototype member (`toString`, `__proto__`) is an ordinary key, never
  // the inherited member (which made the learner's null mass NaN)
  const own = nm !== undefined && Object.prototype.hasOwnProperty.call(nm, verb) ? nm[verb] : undefined;
  return own ?? o.defaultNullMass ?? 0.2;
}

/** Build a learner whose parameters are exactly representable in an Intent Map (ppm-quantised). */
export function createLearner(omega: Omega, o: MapLearnerOptions = {}): IntentLearner {
  const opts: LearnerOptions = {
    eta: qz(o.eta ?? 0),
    tau: qz(o.tau ?? ((o.eta ?? 0) === 0 ? 1 : 0.95)),
    strategy: o.strategy ?? 'disagreement',
    nullMass: (vs) => qz(nullMassOf(o, vs.verb)),
    hypothesisClass: quantizeClass(o.hypothesisClass),
    ...(o.agnosticSlack !== undefined ? { agnosticSlack: o.agnosticSlack } : {}),
    ...(o.anchor ? { anchor: anchorOpt(o.anchor) } : {}),
    ...(o.anchors?.length ? { anchors: o.anchors.map(anchorOpt) } : {}),
    ...(o.monotone ? { monotone: { paths: [...o.monotone.paths], offMass: qz(o.monotone.offMass ?? 0) } } : {}),
    ...(o.etaPos !== undefined ? { etaPos: qz(o.etaPos) } : {}),
    ...(o.etaNeg !== undefined ? { etaNeg: qz(o.etaNeg) } : {}),
    ...(o.priorMix ? { priorMix: priorMixOf(o.priorMix) } : {}),
  };
  const l = new IntentLearner(omega, opts);
  learnerParams.set(l, o);
  return l;
}
const learnerParams = new WeakMap<IntentLearner, MapLearnerOptions>();

/** The serialisable parameters a learner was built with (createLearner only). */
export function learnerOptionsOf(l: IntentLearner): MapLearnerOptions {
  const o = learnerParams.get(l);
  if (!o) throw new Error('pca-intent: build the learner with createLearner() so its parameters are serialisable');
  return o;
}

export function emitIntentMap(l: IntentLearner, intentRefValue: string | null = null): IntentMap {
  const o = learnerOptionsOf(l);
  // Object.fromEntries defines own data properties: assigning `null_mass_ppm['__proto__']` silently dropped that verb
  const null_mass_ppm: Record<string, number> = Object.fromEntries(l.omega.verbs.map((vs) => [vs.verb, ppm(nullMassOf(o, vs.verb))]));
  const grant = l.synthesize();
  const hc = l.hypothesisClass;
  return {
    v: 1,
    kind: 'pca-intent-map',
    intent_ref: intentRefValue,
    principals: intentRefValue ? [intentRefValue] : [],
    omega: omegaToJSON(l.omega),
    learner: {
      hypothesis_class: hypothesisClassName(hc),
      ...(hc.kind === 'union' ? { class_params: { k: hc.k, decay_ppm: ppm(hc.decay ?? 0.25) } } : {}),
      ...(hc.kind === 'decision-list' ? { class_params: { max_rules: hc.maxRules, decay_ppm: ppm(hc.decay ?? 0.25) } } : {}),
      ...(l.agnosticSlack !== undefined ? { agnostic_slack: l.agnosticSlack } : {}),
      eta_ppm: ppm(l.eta),
      tau_ppm: ppm(l.tau),
      strategy: l.strategy,
      null_mass_ppm,
      ...(o.anchor ? { anchor: anchorJSON(o.anchor) } : {}),
      ...(o.anchors?.length ? { anchors: o.anchors.map(anchorJSON) } : {}),
      ...(o.monotone ? { monotone: { paths: [...o.monotone.paths], off_ppm: ppm(o.monotone.offMass ?? 0) } } : {}),
      ...(o.etaPos !== undefined || o.etaNeg !== undefined ? { noise: { eta_pos_ppm: ppm(l.etaPos), eta_neg_ppm: ppm(l.etaNeg) } } : {}),
      ...(o.priorMix ? { prior_mix: { beta_ppm: ppm(o.priorMix.beta), cells: o.priorMix.cells.map((c) => ({ verb: c.verb, cell: c.cell, q_ppm: ppm(c.q) })) } } : {}),
    },
    observations: l.observations.map((x) => ({ verb: x.verb, values: { ...x.values }, y: x.y, source: x.source, ...(x.region ? { region: x.region } : {}) })),
    cells: l.cells().map((c) => ({ verb: c.verb, cell: c.cell, p_ppm: ppm(c.p), in_grant: c.inGrant })),
    grant,
    grant_digest: grantDigest(grant),
    metrics: metricsOf(l),
  };
}

/** The learner parameters a map records (inverse of what emitIntentMap writes). */
export function mapLearnerOptions(m: IntentMap): MapLearnerOptions {
  const nullMass: Record<string, number> = Object.fromEntries(Object.entries(m.learner.null_mass_ppm).map(([k, v]) => [k, v / PPM]));
  const cp = m.learner.class_params;
  const hypothesisClass: HypothesisClassSpec =
    m.learner.hypothesis_class === 'per-verb-union/v1'
      ? { kind: 'union', k: cp?.k ?? 2, decay: (cp?.decay_ppm ?? 250_000) / PPM }
      : m.learner.hypothesis_class === 'per-verb-decision-list/v1' || m.learner.hypothesis_class === 'per-verb-decision-list/v2'
        ? {
            kind: 'decision-list',
            maxRules: cp?.max_rules ?? 2,
            decay: (cp?.decay_ppm ?? 250_000) / PPM,
            conditions: m.learner.hypothesis_class === 'per-verb-decision-list/v1' ? 'atomic' : 'box',
          }
        : { kind: 'box' };
  return {
    eta: m.learner.eta_ppm / PPM,
    tau: m.learner.tau_ppm / PPM,
    strategy: m.learner.strategy,
    nullMass,
    hypothesisClass,
    ...(m.learner.agnostic_slack !== undefined ? { agnosticSlack: m.learner.agnostic_slack } : {}),
    ...(m.learner.anchor ? { anchor: { policy: m.learner.anchor.policy, lambda: m.learner.anchor.lambda_milli / 1000 } } : {}),
    ...(m.learner.anchors?.length ? { anchors: m.learner.anchors.map((a) => ({ policy: a.policy, lambda: a.lambda_milli / 1000 })) } : {}),
    ...(m.learner.monotone ? { monotone: { paths: [...m.learner.monotone.paths], offMass: m.learner.monotone.off_ppm / PPM } } : {}),
    ...(m.learner.noise ? { etaPos: m.learner.noise.eta_pos_ppm / PPM, etaNeg: m.learner.noise.eta_neg_ppm / PPM } : {}),
    ...(m.learner.prior_mix ? { priorMix: { beta: m.learner.prior_mix.beta_ppm / PPM, cells: m.learner.prior_mix.cells.map((c) => ({ verb: c.verb, cell: c.cell, q: c.q_ppm / PPM })) } } : {}),
  };
}

/** Rebuild the learner a map describes (Ω + prior + observations). */
export function learnerFromMap(m: IntentMap): IntentLearner {
  const l = createLearner(omegaFromJSON(m.omega), mapLearnerOptions(m));
  for (const o of m.observations) l.observe({ verb: o.verb, values: o.values }, o.y, o.source, o.region);
  return l;
}

/** Replay a single-principal map and check every number, every cell and the grant. */
export function verifyIntentMap(m: IntentMap): { ok: boolean; problems: string[] } {
  const problems: string[] = [];
  try {
    if (m?.v !== 1 || m.kind !== 'pca-intent-map') return { ok: false, problems: ['not an intent map v1'] };
    if (m.principals.length > 1 || m.aggregation) return { ok: false, problems: ['combined map: verify each principal map and recombine with verifyAggregate'] };
    const r = emitIntentMap(learnerFromMap(m), m.intent_ref);
    if (r.grant_digest !== m.grant_digest || grantDigest(m.grant) !== m.grant_digest) problems.push('grant does not match the replayed posterior');
    if (r.cells.length !== m.cells.length) problems.push('cell count differs');
    else
      r.cells.forEach((c, i) => {
        const x = m.cells[i]!;
        if (c.verb !== x.verb || c.in_grant !== x.in_grant || Math.abs(c.p_ppm - x.p_ppm) > 2) problems.push(`cell ${i} differs`);
      });
    for (const k of Object.keys(r.metrics) as (keyof IntentMapMetrics)[]) {
      const a = r.metrics[k];
      const b = m.metrics[k];
      if (a === null || b === null ? a !== b : Math.abs(a - b) > 2) problems.push(`metric ${k} differs (${String(b)} claimed, ${String(a)} replayed)`);
    }
  } catch (e) {
    problems.push(`replay failed: ${(e as Error).message}`);
  }
  return { ok: problems.length === 0, problems };
}

/**
 * TRUST RAMP / DRIFT (spec §3.4): a runtime divergence — the principal (or an outcome check) says an action that
 * happened should not have — is one more labelled observation. It updates the posterior, and a NEGATIVE runtime
 * label also VETOES the outcome's cell: the re-synthesised grant excludes it and never re-admits it, even when the
 * answer contradicts every hypothesis (a misspecified Θ) or the noise model would discount it. Positive runtime
 * confirmations widen the grant only through the posterior, i.e. only once p_n reaches τ.
 */
export function applyDivergence(l: IntentLearner, outcome: Outcome, y: 0 | 1): { before: number; after: number; grant: { predicates: Predicate[]; caveats: Caveat[] } } {
  const count = () => l.cells().filter((c) => c.inGrant).length;
  const before = count();
  l.observe(outcome, y, 'runtime');
  return { before, after: count(), grant: l.synthesize() };
}
