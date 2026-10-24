/**
 * Intent Fidelity Benchmark harness (spec §9). Runs every layer the prototype implements against
 *   - the SEED set (bench/cases.ts + bench/cases/*.ts, 316 hand-written cases: 56 core + 26 per website task family), and
 *   - the GENERATED set (bench/generate.ts, ≥ 300 cases from a fixed phrase vocabulary with three deterministic
 *     reader-compilers; see that file for exactly what is and is not simulated),
 * and prints / writes the numbers the spec and paper quote. Deterministic: fixed seeds, exact cell sums.
 *
 * WHAT IS REAL vs SIMULATED (also printed in the report):
 *  - REAL: Ω derivation, the PCA evaluator on every admission decision, the analyzer's equivalence checks, the nl.ts
 *    grounding + facade compilation and the slot grounding of every generated compiler output, witness generation,
 *    the claim IR and its diff, the learner (every hypothesis class), partial answers and cut refinement, synthesis,
 *    and every risk / burden / fidelity number (exact over a cell grid that contains every literal of the truth, the
 *    candidate and every compiler output).
 *  - SIMULATED: the principal. For a question about a cell it answers "yes" iff every finer cell of the truth's grid
 *    inside it is acceptable, filling dimensions the question does not mention OPTIMISTICALLY (some acceptable value
 *    exists). The PARTIAL-CAPABLE principal (configs marked +partial) additionally answers "partly" when the truth
 *    splits the questioned cell along ONE dimension (a cut inside a numeric range, a named value inside a categorical
 *    cell), and volunteers "except when <field> is …" when the truth depends on exactly one dimension the question
 *    did not mention. Answer noise flips 0/1 answers with probability η. The back-translation reader is IDEAL.
 *    The generated set's compilers are deterministic readers, NOT language models.
 *  - HAND-WRITTEN: every seed case (text, captured slots, hidden truth, candidate). The Intent v2 features in the seed
 *    set (accumulators, monitors, deltas, offers, facts, provenance, classifier labels, frames, read purpose, layers)
 *    are present only as grant dimensions; the runtime that fills them (ledger, oracles, classifiers, label receipts,
 *    frame snapshots) is not run.
 *  - NOT MEASURED: runtime judges, outcome verification, the trust ramp (they need execution traces), human answers.
 */
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  acceptabilityOf,
  admitter,
  analyzeDisagreement,
  backTranslationDiff,
  boundaryWitnesses,
  cellRep,
  committeeAnchors,
  createLearner,
  decodeCell,
  deriveOmega,
  elicitAdaptive,
  measureGrantExact,
  nlFacadeCompiler,
  normalizePolicy,
  numCells,
  omegaToJSON,
  panelFlags,
  parseSlotsJSON,
  regionOfCell,
  renderGrant,
  rng,
  runCompilers,
  slotsCompiler,
  valueInRegionDim,
  verbCellCount,
  verbSpace,
  wilsonInterval,
  type AdaptiveAnswer,
  type CompilerOutput,
  type Dim,
  type HypothesisClassSpec,
  type IntentLearner,
  type IntentSlots,
  type Omega,
  type PartialAnswer,
  type PartialPart,
  type PolicyInput,
  type Question,
  type Strategy,
  type VerbSpace,
} from '../src';
import { CASES } from './cases';
import { generateCases } from './generate';

// ---- the simulated principal ---------------------------------------------------------------------------

interface Member {
  /** check-grid cell index per check dimension */
  idx: number[];
  values: Record<string, number | string>;
  y: boolean;
}

/** A simulated principal over any Ω that the check grid refines (see header). */
class Principal {
  private byVerb = new Map<string, { vs: VerbSpace; members: Member[] }>();
  constructor(check: Omega, truth: PolicyInput) {
    const t = admitter(truth);
    for (const vs of check.verbs) {
      const members: Member[] = [];
      for (let f = 0; f < verbCellCount(vs); f++) {
        const idx = decodeCell(vs, f);
        const o = cellRep(vs, idx);
        members.push({ idx, values: o.values, y: t.admits(vs, o) });
      }
      this.byVerb.set(vs.verb, { vs, members });
    }
  }

  answer(vs: VerbSpace, cell: number[], partial: boolean): AdaptiveAnswer {
    const entry = this.byVerb.get(vs.verb);
    if (!entry) return 0;
    const region = regionOfCell(vs, cell);
    const check = entry.vs;
    const mentioned = check.dims.map((d, k) => (vs.dims.some((x) => x.path === d.path) ? k : -1)).filter((k) => k >= 0);
    const unmentioned = check.dims.map((_, k) => k).filter((k) => !mentioned.includes(k));
    const members = entry.members.filter((m) => vs.dims.every((d) => valueInRegionDim(d.path, region.dims[d.path]!, m.values[d.path]!)));
    if (members.length === 0) return 0;
    const groups = new Map<string, Member[]>();
    for (const m of members) {
      const key = mentioned.map((k) => m.idx[k]).join(',');
      groups.set(key, [...(groups.get(key) ?? []), m]);
    }
    const gy = new Map<string, boolean>();
    for (const [k, ms] of groups) gy.set(k, ms.some((m) => m.y));
    const allYes = [...gy.values()].every(Boolean);
    const noneYes = [...gy.values()].every((x) => !x);
    if (!partial) return allYes ? 1 : 0;
    if (noneYes) return 0;
    if (allYes) {
      for (const u of unmentioned) {
        const p = this.split(check.dims[u]!, members.map((m) => ({ j: m.idx[u]!, y: m.y })), true);
        if (p) return p;
      }
      return 1;
    }
    for (const k of mentioned) {
      const d = check.dims[k]!;
      const labelled = [...groups.entries()].map(([key, ms]) => ({ j: ms[0]!.idx[k]!, y: gy.get(key)! }));
      const p = this.split(d, labelled, false, region.dims[d.path]);
      if (p) return p;
    }
    return 0;
  }

  /**
   * A partial answer along dimension d if the label is a function of d's check cell alone (and is not constant).
   * `newDim`: d is not in the learner's Ω (a volunteered exception).
   */
  private split(d: Dim, labelled: { j: number; y: boolean }[], newDim: boolean, rd?: { kind: string; lo?: number; hi?: number }): PartialAnswer | null {
    const lab = new Map<number, boolean>();
    for (const { j, y } of labelled) {
      if (lab.has(j) && lab.get(j) !== y) return null;
      lab.set(j, y);
    }
    const ys = [...lab.values()];
    if (ys.every(Boolean) || ys.every((x) => !x)) return null;
    const cells = [...lab.keys()].sort((a, b) => a - b);
    if (d.kind === 'num') {
      const nc = numCells(d);
      const parts: PartialPart[] = cells.map((j) => ({ lo: nc[j]!.lo, hi: nc[j]!.hi, y: lab.get(j) ? 1 : 0 }));
      if (newDim) return { kind: 'partial', path: d.path, newDim: JSON.parse(JSON.stringify(d)) as Dim, parts };
      const lo = rd && rd.kind === 'num' ? rd.lo! : -Infinity;
      const hi = rd && rd.kind === 'num' ? rd.hi! : Infinity;
      return { kind: 'partial', path: d.path, cuts: d.cuts.filter((c) => c >= lo && c <= hi), parts };
    }
    const exact = cells.filter((j) => d.values[j]!.kind === 'exact');
    const rest = cells.filter((j) => d.values[j]!.kind !== 'exact');
    const restY = new Set(rest.map((j) => lab.get(j)));
    if (restY.size > 1) return null;
    const parts: PartialPart[] = exact.map((j) => ({ values: [d.values[j]!.value], y: lab.get(j) ? 1 : 0 }));
    if (rest.length) parts.push({ other: true, y: lab.get(rest[0]!) ? 1 : 0 });
    if (newDim) return { kind: 'partial', path: d.path, newDim: JSON.parse(JSON.stringify(d)) as Dim, parts };
    return { kind: 'partial', path: d.path, values: exact.map((j) => d.values[j]!.value), parts };
  }
}

// ---- configurations -------------------------------------------------------------------------------------

interface LearnCfg {
  name: string;
  eta: number;
  principalNoise: number;
  tau?: number;
  anchor?: number;
  strategy?: Strategy;
  audit?: boolean;
  hclass?: HypothesisClassSpec;
  slack?: number;
  partial?: boolean;
  /** generated set only: Ω, prior and seed questions from the compiler panel */
  committee?: boolean;
}

const BASE_CFGS: LearnCfg[] = [
  { name: 'uninformed', eta: 0, principalNoise: 0 },
  { name: 'anchored', eta: 0, principalNoise: 0, anchor: 8 },
  { name: 'risk-weighted', eta: 0, principalNoise: 0, strategy: 'risk' },
  { name: 'noisy-5%', eta: 0.05, principalNoise: 0.05, tau: 0.95 },
  { name: 'uninformed+audit', eta: 0, principalNoise: 0, audit: true },
  { name: 'noisy-5%+audit', eta: 0.05, principalNoise: 0.05, tau: 0.95, audit: true },
];
const M6_CFGS: LearnCfg[] = [
  { name: 'union2+audit', eta: 0, principalNoise: 0, audit: true, hclass: { kind: 'union', k: 2 } },
  { name: 'dlist2+audit', eta: 0, principalNoise: 0, audit: true, hclass: { kind: 'decision-list', maxRules: 2 } },
  { name: 'partial+audit', eta: 0, principalNoise: 0, audit: true, partial: true },
  { name: 'union2+partial+audit', eta: 0, principalNoise: 0, audit: true, partial: true, hclass: { kind: 'union', k: 2 } },
  { name: 'agnostic1+noise5%+audit', eta: 0, principalNoise: 0.05, audit: true, slack: 1 },
];
const SEED_CFGS = [...BASE_CFGS, ...M6_CFGS];
const GEN_CFGS: LearnCfg[] = [
  { name: 'uninformed+audit', eta: 0, principalNoise: 0, audit: true },
  { name: 'committee+audit', eta: 0, principalNoise: 0, audit: true, committee: true, anchor: 4 },
  { name: 'noisy-5%+audit', eta: 0.05, principalNoise: 0.05, tau: 0.95, audit: true },
  ...M6_CFGS,
  { name: 'committee+union2+partial+audit', eta: 0, principalNoise: 0, audit: true, committee: true, anchor: 4, partial: true, hclass: { kind: 'union', k: 2 } },
];
const EPS_R_REL = 0.01; // ε_R = 1% of E_μ[h]
const EPS_B = 0.02;
const MAX_Q = 60;

const pct = (x: number) => `${(100 * x).toFixed(1)}%`;
const mean = (a: number[]) => (a.length ? a.reduce((s, x) => s + x, 0) / a.length : NaN);
const quant = (a: number[], q: number) => {
  const s = [...a].sort((x, y) => x - y);
  return s.length ? s[Math.min(s.length - 1, Math.floor(q * s.length))]! : NaN;
};
const ci = (k: number, n: number) => {
  const w = wilsonInterval(k, n);
  return `${k}/${n} (${pct(w.p)}; 95% CI ${pct(w.lo)}–${pct(w.hi)})`;
};

interface CaseCtx {
  truth: PolicyInput;
  candidate: PolicyInput;
  slots: IntentSlots;
  meas: Omega;
  check: Omega;
  principal: Principal;
  panel?: { omega: Omega; outputs: CompilerOutput[]; seed: { verb: string; cell: number[] }[] };
  seedIndex: number;
}

function runCfg(ctx: CaseCtx, cfg: LearnCfg) {
  if (cfg.committee && !ctx.panel) return null;
  const om = cfg.committee ? ctx.panel!.omega : ctx.meas;
  const nullMass: Record<string, number> = {};
  for (const vs of om.verbs) nullMass[vs.verb] = ctx.slots.verbs.includes(vs.verb) ? 0.05 : 0.8;
  let l: IntentLearner;
  try {
    l = createLearner(om, {
      eta: cfg.eta,
      ...(cfg.tau !== undefined ? { tau: cfg.tau } : {}),
      nullMass,
      ...(cfg.strategy ? { strategy: cfg.strategy } : {}),
      ...(cfg.anchor && !cfg.committee ? { anchor: { policy: normalizePolicy(ctx.candidate), lambda: cfg.anchor } } : {}),
      ...(cfg.committee ? { anchors: committeeAnchors(ctx.panel!.outputs, cfg.anchor ?? 4) } : {}),
      ...(cfg.hclass ? { hypothesisClass: cfg.hclass } : {}),
      ...(cfg.slack !== undefined ? { agnosticSlack: cfg.slack } : {}),
    });
  } catch (e) {
    return { skipped: (e as Error).message };
  }
  const r = rng(77 + ctx.seedIndex);
  const answer = (q: Question, cur: IntentLearner): AdaptiveAnswer => {
    const vs = verbSpace(cur.omega, q.verb)!;
    const a = ctx.principal.answer(vs, q.cell, !!cfg.partial);
    if (typeof a === 'object') return a;
    const flip = cfg.principalNoise > 0 && r() < cfg.principalNoise;
    return (flip ? 1 - a : a) as 0 | 1;
  };
  const epsR = EPS_R_REL * l.metrics().meanHarm;
  let res;
  try {
    res = elicitAdaptive(l, answer, { epsRisk: epsR, epsBurden: EPS_B, maxQuestions: MAX_Q, audit: !!cfg.audit, ...(cfg.committee ? { seed: ctx.panel!.seed } : {}) });
  } catch (e) {
    return { skipped: (e as Error).message };
  }
  const fin = res.learner;
  const est = fin.metrics();
  const grant = fin.synthesize();
  const tru = measureGrantExact(ctx.check, grant, acceptabilityOf(ctx.truth));
  return {
    stop: res.stop,
    questions: res.questions,
    audit_questions: res.auditQuestions,
    seed_questions: res.seedQuestions,
    refinements: res.refinements,
    conflicts: est.conflicts,
    est_risk: est.residualRisk / est.meanHarm,
    est_burden: est.burden,
    risk: tru.risk / tru.meanHarm,
    burden: tru.burden,
    fidelity: tru.fidelity,
    within_eps: tru.risk <= EPS_R_REL * tru.meanHarm + 1e-12,
  };
}

function exactEqual(check: Omega, a: PolicyInput, b: PolicyInput): boolean {
  const A = admitter(a);
  const B = admitter(b);
  for (const vs of check.verbs) for (let f = 0; f < verbCellCount(vs); f++) {
    const o = cellRep(vs, decodeCell(vs, f));
    if (A.admits(vs, o) !== B.admits(vs, o)) return false;
  }
  return true;
}

function oneRound(ctx: CaseCtx, idx: number) {
  const wit = boundaryWitnesses(ctx.candidate, ctx.meas);
  const ask = (verb: string, cell: number[]) => ctx.principal.answer(verbSpace(ctx.meas, verb)!, cell, false) === 1;
  const witMismatch = wit.filter((w) => ask(w.verb, w.cell) !== w.grantAllows);
  const noisy = rng(1000 + idx);
  const witMismatchNoisy = wit.filter((w) => (noisy() < 0.05 ? !ask(w.verb, w.cell) : ask(w.verb, w.cell)) !== w.grantAllows);
  const diff = backTranslationDiff(ctx.candidate, ctx.slots, ctx.meas);
  return {
    witnesses: { questions: wit.length, caught: witMismatch.length > 0, caught_noisy: witMismatchNoisy.length > 0 },
    backtranslation: { lines: renderGrant(ctx.candidate).split('\n').length, diffs: diff.length, caught: diff.length > 0 },
  };
}

/** Does the truth give one verb more than one predicate (a union of boxes, outside the single-box class)? */
function truthIsUnion(truth: PolicyInput): boolean {
  const verbs = normalizePolicy(truth).predicates.flatMap((p) => (Array.isArray(p.verb) ? p.verb : [p.verb]));
  return new Set(verbs).size !== verbs.length;
}

function runSeed() {
  const rows: Record<string, unknown>[] = [];
  for (const c of CASES) {
    const meas = deriveOmega({ policies: [c.candidate], slots: c.slots });
    const check = deriveOmega({ policies: [c.candidate, c.truth], slots: c.slots });
    const ctx: CaseCtx = { truth: c.truth, candidate: c.candidate, slots: c.slots, meas, check, principal: new Principal(check, c.truth), seedIndex: rows.length };
    const naive = measureGrantExact(check, c.candidate, acceptabilityOf(c.truth));
    const learned: Record<string, unknown> = {};
    for (const cfg of SEED_CFGS) learned[cfg.name] = runCfg(ctx, cfg);
    rows.push({
      id: c.id,
      category: c.category,
      family: c.family ?? 'core',
      features: c.features ?? [],
      tags: c.tags ?? [],
      truth_union: truthIsUnion(c.truth),
      faithful: c.faithful,
      label_ok: exactEqual(check, c.candidate, c.truth) === c.faithful,
      same_omega: JSON.stringify(omegaToJSON(meas)) === JSON.stringify(omegaToJSON(check)),
      cells_meas: meas.verbs.reduce((s, v) => s + verbCellCount(v), 0),
      naive: { risk: naive.risk / naive.meanHarm, burden: naive.burden, fidelity: naive.fidelity },
      ...oneRound(ctx, rows.length),
      learned,
    });
  }
  return rows;
}

async function runGenerated() {
  const rows: Record<string, unknown>[] = [];
  for (const g of generateCases()) {
    const compilers = [
      slotsCompiler({ id: 'L', family: 'A', complete: () => g.raw.L }),
      slotsCompiler({ id: 'C', family: 'B', complete: () => g.raw.C }),
      nlFacadeCompiler({ id: 'G', family: 'C', complete: () => g.raw.G }),
    ];
    const outputs = await runCompilers({ text: g.text }, compilers);
    const byId = Object.fromEntries(outputs.map((o) => [o.compiler, o])) as Record<string, CompilerOutput>;
    const candidate = byId[g.candidate]!.policy;
    const slots = parseSlotsJSON(g.raw[g.captureFrom]).slots;
    const meas = deriveOmega({ policies: [candidate], slots });
    const check = deriveOmega({ policies: [candidate, g.truth, ...outputs.map((o) => o.policy)], slots });
    const rep = analyzeDisagreement(outputs, { slots });
    const ctx: CaseCtx = { truth: g.truth, candidate, slots, meas, check, principal: new Principal(check, g.truth), panel: { omega: rep.omega, outputs, seed: rep.questions }, seedIndex: rows.length };
    const naive = measureGrantExact(check, candidate, acceptabilityOf(g.truth));
    const equal = exactEqual(check, candidate, g.truth);
    const learned: Record<string, unknown> = {};
    for (const cfg of GEN_CFGS) learned[cfg.name] = runCfg(ctx, cfg);
    rows.push({
      id: g.id,
      group: g.group,
      category: g.category,
      candidate_reader: g.candidate,
      out_of_class: g.outOfClass ?? null,
      faithful: equal,
      label_ok: equal === g.expectedFaithful,
      cells_meas: meas.verbs.reduce((s, v) => s + verbCellCount(v), 0),
      naive: { risk: naive.risk / naive.meanHarm, burden: naive.burden, fidelity: naive.fidelity },
      ...oneRound(ctx, rows.length),
      panel: { flagged: panelFlags(rep), unanimous: rep.unanimous, disagreement_mass: rep.disagreementMass, questions: rep.questions.length, notes: outputs.flatMap((o) => o.notes) },
      learned,
    });
  }
  return rows;
}

// ---- reporting ------------------------------------------------------------------------------------------

type Row = Record<string, any>;

function learnedTable(out: string[], set: Row[], cfgs: LearnCfg[]) {
  out.push('| grant | n run | skipped | mean risk | cases risk ≤ ε_R | zero-risk cases | mean burden | mean F | questions mean / median / p90 / max (audit mean) | refinements (mean) | converged | conflicts |');
  out.push('|---|---|---|---|---|---|---|---|---|---|---|---|');
  out.push(`| naive single-shot | ${set.length} | 0 | ${pct(mean(set.map((r) => r.naive.risk)))} | ${set.filter((r) => r.naive.risk <= EPS_R_REL + 1e-12).length}/${set.length} | ${set.filter((r) => r.naive.risk < 1e-12).length}/${set.length} | ${pct(mean(set.map((r) => r.naive.burden)))} | ${mean(set.map((r) => r.naive.fidelity)).toFixed(3)} | 0 | - | - | - |`);
  for (const cfg of cfgs) {
    const all = set.map((r) => r.learned[cfg.name]).filter((x) => x !== null && x !== undefined);
    const L = all.filter((x: any) => !x.skipped);
    const skipped = all.length - L.length;
    if (all.length === 0) continue;
    const q = L.map((x: any) => x.questions);
    out.push(`| learned: ${cfg.name} | ${L.length} | ${skipped} | ${pct(mean(L.map((x: any) => x.risk)))} | ${L.filter((x: any) => x.within_eps).length}/${L.length} | ${L.filter((x: any) => x.risk < 1e-12).length}/${L.length} | ${pct(mean(L.map((x: any) => x.burden)))} | ${mean(L.map((x: any) => x.fidelity)).toFixed(3)} | ${mean(q).toFixed(1)} / ${quant(q, 0.5)} / ${quant(q, 0.9)} / ${Math.max(...q)} (${mean(L.map((x: any) => x.audit_questions)).toFixed(1)}) | ${mean(L.map((x: any) => x.refinements)).toFixed(2)} | ${L.filter((x: any) => x.stop === 'converged').length}/${L.length} | ${L.reduce((s: number, x: any) => s + x.conflicts, 0)} |`);
  }
}

function report(seed: Row[], gen: Row[]) {
  const out: string[] = [];
  out.push(`# Intent Fidelity Benchmark`);
  out.push('');
  for (const [name, rows, cfgs] of [['seed set (hand-written)', seed, SEED_CFGS], ['generated set (phrase vocabulary × deterministic readers)', gen, GEN_CFGS]] as const) {
    if (!rows.length) continue;
    const unf = rows.filter((r) => !r.faithful);
    const fai = rows.filter((r) => r.faithful);
    out.push(`## ${name}: ${rows.length} cases (${fai.length} faithful, ${unf.length} unfaithful)`);
    out.push(`label check (exact, joint grid): ${rows.filter((r) => r.label_ok).length}/${rows.length} labels confirmed`);
    const bad = rows.filter((r) => !r.label_ok).map((r) => r.id);
    if (bad.length) out.push(`label mismatches: ${bad.join(', ')}`);
    out.push('');
    out.push('### One-round layers on the single-shot candidate grant (Wilson 95% CIs)');
    out.push('| layer | catch rate (unfaithful) | false escalation (faithful) |');
    out.push('|---|---|---|');
    const rate = (a: Row[], f: (r: Row) => boolean) => ci(a.filter(f).length, a.length);
    out.push(`| boundary witnesses, ideal principal | ${rate(unf, (r) => r.witnesses.caught)} | ${rate(fai, (r) => r.witnesses.caught)} |`);
    out.push(`| boundary witnesses, 5% answer noise | ${rate(unf, (r) => r.witnesses.caught_noisy)} | ${rate(fai, (r) => r.witnesses.caught_noisy)} |`);
    out.push(`| back-translation diff, ideal reader | ${rate(unf, (r) => r.backtranslation.caught)} | ${rate(fai, (r) => r.backtranslation.caught)} |`);
    if (rows[0]!.panel) {
      out.push(`| k-compiler disagreement (3 readers) | ${rate(unf, (r) => r.panel.flagged)} | ${rate(fai, (r) => r.panel.flagged)} |`);
      out.push(`| any of the three | ${rate(unf, (r) => r.panel.flagged || r.witnesses.caught || r.backtranslation.caught)} | ${rate(fai, (r) => r.panel.flagged || r.witnesses.caught || r.backtranslation.caught)} |`);
    } else out.push(`| either | ${rate(unf, (r) => r.witnesses.caught || r.backtranslation.caught)} | ${rate(fai, (r) => r.witnesses.caught || r.backtranslation.caught)} |`);
    out.push('');
    out.push('### Catch rate by category');
    const hasPanel = !!rows[0]!.panel;
    out.push(`| category | n | witnesses | back-translation |${hasPanel ? ' k-compiler |' : ''} naive risk (mean, % of E[h]) |`);
    out.push(`|---|---|---|---|${hasPanel ? '---|' : ''}---|`);
    for (const cat of [...new Set(rows.map((r) => r.category as string))]) {
      const a = rows.filter((r) => r.category === cat);
      out.push(`| ${cat} | ${a.length} | ${a.filter((r) => r.witnesses.caught).length} | ${a.filter((r) => r.backtranslation.caught).length} |${hasPanel ? ` ${a.filter((r) => r.panel.flagged).length} |` : ''} ${pct(mean(a.map((r) => r.naive.risk)))} |`);
    }
    if (rows[0]!.family !== undefined) {
      out.push('');
      const byKey = (title: string, keyOf: (r: Row) => string[]) => {
        out.push(`### Catch rate by ${title}`);
        out.push(`| ${title} | n | faithful | unfaithful | caught by witnesses or back-translation (unfaithful) | false escalation (faithful) | naive risk (mean, % of E[h]) |`);
        out.push('|---|---|---|---|---|---|---|');
        const keys = [...new Set(rows.flatMap(keyOf))];
        for (const k of keys) {
          const a = rows.filter((r) => keyOf(r).includes(k));
          const u = a.filter((r) => !r.faithful);
          const f = a.filter((r) => r.faithful);
          out.push(`| ${k} | ${a.length} | ${f.length} | ${u.length} | ${u.filter((r) => r.witnesses.caught || r.backtranslation.caught).length}/${u.length} | ${f.filter((r) => r.witnesses.caught || r.backtranslation.caught).length}/${f.length} | ${pct(mean(a.map((r) => r.naive.risk)))} |`);
        }
        out.push('');
      };
      byKey('family', (r) => [r.family]);
      byKey('feature', (r) => r.features);
      byKey('tag', (r) => r.tags);
    } else out.push('');
    out.push(`### Elicitation vs the naive grant (ε_R = ${pct(EPS_R_REL)} of E[h], ε_B = ${EPS_B}, ≤ ${MAX_Q} questions; exact risk R/E_μ[h], burden B, F)`);
    // out of the box class: the out_of_class category, plus (seed set) any case whose truth is a union of boxes for one verb
    // (e.g. a session's task grant ∪ a delta grant), whatever its error category
    const isOoc = (r: Row) => r.category === 'out_of_class' || r.truth_union === true;
    const ooc = rows.filter(isOoc);
    for (const [label, set] of [['all', rows], ['in-class', rows.filter((r) => !isOoc(r))], ['out-of-class (category out_of_class, or a union truth)', ooc]] as const) {
      if (!set.length) continue;
      out.push('');
      out.push(`#### ${label} (n=${set.length})`);
      learnedTable(out, set, [...cfgs]);
    }
    out.push('');
    out.push('### Cases with non-zero true risk under some learned grant (risk % of E[h])');
    out.push(`| case | category | naive | ${cfgs.map((c) => c.name).join(' | ')} |`);
    out.push(`|---|---|---|${cfgs.map(() => '---').join('|')}|`);
    let shown = 0;
    for (const r of rows) {
      const L = cfgs.map((c) => r.learned[c.name]);
      if (L.every((x: any) => !x || x.skipped || x.risk < 1e-12)) continue;
      if (shown++ >= 60) continue;
      out.push(`| ${r.id} | ${r.category} | ${pct(r.naive.risk)} | ${L.map((x: any) => (!x ? '-' : x.skipped ? 'skip' : pct(x.risk))).join(' | ')} |`);
    }
    if (shown > 60) out.push(`(… ${shown - 60} more rows in the JSON)`);
    out.push('');
  }
  out.push('Hand-written: every seed case; Intent v2 features appear only as grant dimensions (their runtime is not run).');
  out.push('Simulated: the principal (cell-universal answers, optimistic on unmentioned dimensions, optional flip noise; partial answers only in +partial configs), the ideal back-translation reader, and the generated set\'s compilers (deterministic readers, not LLMs). Not measured: runtime judges, outcome verification, trust ramp, real users.');
  return out.join('\n');
}

async function main() {
  const dir = process.argv[2] ?? join(__dirname);
  const which = process.env.INTENT_BENCH_SET ?? 'all';
  const seed = which === 'generated' ? [] : runSeed();
  const gen = which === 'seed' ? [] : await runGenerated();
  if (seed.length) writeFileSync(join(dir, 'results.json'), JSON.stringify(seed, null, 1));
  if (gen.length) writeFileSync(join(dir, 'results-generated.json'), JSON.stringify(gen, null, 1));
  const md = report(seed, gen);
  writeFileSync(join(dir, 'results.md'), md);
  console.log(md);
}

void main();
