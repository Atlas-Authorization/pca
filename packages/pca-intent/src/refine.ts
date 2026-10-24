import type { ElicitOptions, ElicitResult, IntentLearner, Observation, Question } from './learner';
import { createLearner, learnerOptionsOf } from './map';
import { catCellOf, cellRep, numCells, OTHER, repValue, type CatValue, type Dim, type Omega, type VerbSpace } from './omega';
import { regionOfCell, restrictRegion, type Region } from './region';

/**
 * CUT REFINEMENT AND PARTIAL ANSWERS (spec §4.2c "Cut refinement", roadmap M6).
 *
 * Θ only knows the cuts in K_d. When the principal would say "yes" to part of a questioned cell and "no" to the
 * rest, the honest answer is `partial`: "yes up to 120, no above", "yes except 12", "yes except for recipient
 * reseller". A partial answer
 *   1. refines Ω: inserts the stated cuts into K_d, names the stated categorical values, or ADDS a dimension the
 *      Ω did not have (a constraint nobody captured, benchmark X02);
 *   2. re-enumerates Θ_v over the refined cells and REPLAYS every earlier observation as a value-space region
 *      (`region.ts`): every old cell is a union of new cells, so each earlier answer keeps exactly its meaning;
 *   3. records one observation per new sub-cell of the questioned cell with the label the principal gave it.
 *
 * Adding a dimension needs one modelling choice, stated here and in the spec: earlier "yes" answers on that verb
 * did not mention the new dimension, and a principal who volunteers "except for X" was answering about the
 * typical case. So earlier "yes" answers are RE-SCOPED to the values the partial answer accepts; earlier "no"
 * answers keep the whole dimension (a "no" about a larger region is weaker, so this is sound).
 *
 * With τ = 1 and η = 0, refinement never widens the conservative grant (every coarse hypothesis is also a fine one
 * and stays consistent, so the fine version space contains the coarse one): pending theorem T8 in
 * pca-intent-formal.md, property-tested in refine.test.ts.
 */

export interface Refinement {
  verb: string;
  path: string;
  /** Numeric cuts to insert into K_d. */
  cuts?: number[];
  /** Exact categorical values to name. */
  values?: string[];
  /** Categorical prefixes to name. */
  prefixes?: string[];
  /** A dimension Ω did not have for this verb (its full definition; `path` must equal newDim.path). */
  newDim?: Dim;
}

function sortedCat(values: CatValue[]): CatValue[] {
  const ex = [...new Set(values.filter((v) => v.kind === 'exact').map((v) => v.value))].sort();
  const pre = [...new Set(values.filter((v) => v.kind === 'prefix').map((v) => v.value))].sort();
  return [...ex.map((value) => ({ kind: 'exact' as const, value })), ...pre.map((value) => ({ kind: 'prefix' as const, value })), { kind: 'other', value: OTHER }];
}

/** Ω with one verb's dimension refined (a deep copy; other verbs and the weights are unchanged). */
export function refineOmega(omega: Omega, r: Refinement): Omega {
  const out: Omega = JSON.parse(JSON.stringify(omega)) as Omega;
  const vs = out.verbs.find((v) => v.verb === r.verb);
  if (!vs) throw new Error(`refineOmega: no verb ${r.verb} in Ω`);
  const i = vs.dims.findIndex((d) => d.path === r.path);
  if (r.newDim) {
    if (i >= 0) throw new Error(`refineOmega: ${r.path} is already a dimension of ${r.verb}`);
    if (r.newDim.path !== r.path) throw new Error('refineOmega: newDim.path must equal path');
    const d = JSON.parse(JSON.stringify(r.newDim)) as Dim;
    if (d.kind === 'cat') d.values = sortedCat(d.values);
    else d.cuts = [...new Set(d.cuts)].filter((c) => c >= d.lo && c <= d.hi).sort((a, b) => a - b);
    vs.dims.push(d);
    vs.dims.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    return out;
  }
  if (i < 0) throw new Error(`refineOmega: ${r.verb} has no dimension ${r.path} (pass newDim to add it)`);
  const d = vs.dims[i]!;
  if (d.kind === 'num') {
    if (r.values?.length || r.prefixes?.length) throw new Error(`refineOmega: ${r.path} is numeric`);
    const cuts = (r.cuts ?? []).filter((c) => Number.isInteger(c));
    d.cuts = [...new Set([...d.cuts, ...cuts])].filter((c) => c >= d.lo && c <= d.hi).sort((a, b) => a - b);
  } else {
    if (r.cuts?.length) throw new Error(`refineOmega: ${r.path} is categorical`);
    d.values = sortedCat([...d.values, ...(r.values ?? []).map((value) => ({ kind: 'exact' as const, value })), ...(r.prefixes ?? []).map((value) => ({ kind: 'prefix' as const, value }))]);
    if (d.values.length > 20) throw new Error(`refineOmega: ${r.path} would have more than 20 values`);
  }
  return out;
}

/** The value-space region an observation was about, in the Ω it was recorded in. */
export function regionOfObservation(omega: Omega, o: Observation): Region {
  if (o.region) return o.region;
  const vs = omega.verbs.find((v) => v.verb === o.verb);
  if (!vs) throw new Error(`regionOfObservation: no verb ${o.verb}`);
  return regionOfCell(vs, o.cell);
}

/**
 * Rebuild a learner over a refined Ω and replay every observation as a region. `rescope` may rewrite the region
 * of an earlier observation (used when a dimension is added; see the module comment).
 */
export function refineLearner(l: IntentLearner, r: Refinement, rescope?: (o: Observation, region: Region) => Region): IntentLearner {
  const omega = refineOmega(l.omega, r);
  const next = createLearner(omega, learnerOptionsOf(l));
  for (const o of l.observations) {
    let region = regionOfObservation(l.omega, o);
    if (rescope) region = rescope(o, region);
    const vs = omega.verbs.find((v) => v.verb === o.verb)!;
    const values: Record<string, number | string> = { ...o.values };
    for (const d of vs.dims) if (!(d.path in values)) values[d.path] = repValue(d, 0);
    next.observe({ verb: o.verb, values }, o.y, o.source, region);
  }
  return next;
}

export type PartialPart =
  | { lo: number; hi: number; y: 0 | 1 }
  | { values: string[]; y: 0 | 1 }
  | { other: true; y: 0 | 1 };

/**
 * "Partly": the refinement the answer implies (cuts / values on `path`, or a whole new dimension) and the label of
 * every part. A sub-cell no part covers is left unanswered.
 */
export interface PartialAnswer {
  kind: 'partial';
  path: string;
  cuts?: number[];
  values?: string[];
  newDim?: Dim;
  parts: PartialPart[];
}

function partLabel(d: Dim, j: number, parts: readonly PartialPart[]): 0 | 1 | null {
  const x = repValue(d, j);
  for (const p of parts) {
    if ('lo' in p) {
      if (d.kind !== 'num') continue;
      const c = numCells(d)[j]!;
      if (c.lo >= p.lo && c.hi <= p.hi) return p.y;
    } else if ('values' in p) {
      if (d.kind === 'cat' && d.values[j]!.kind === 'exact' && p.values.includes(String(x))) return p.y;
    } else if (d.kind === 'cat' && d.values[j]!.kind !== 'exact') return p.y;
  }
  return null;
}

/** Sub-cells of dimension `d` (in the refined Ω) that lie inside the questioned region's dimension. */
function subCells(d: Dim, region: Region): number[] {
  const n = d.kind === 'num' ? numCells(d).length : d.values.length;
  const rd = region.dims[d.path];
  const out: number[] = [];
  for (let j = 0; j < n; j++) {
    if (!rd) out.push(j);
    else if (d.kind === 'num' && rd.kind === 'num') {
      const c = numCells(d)[j]!;
      if (c.lo >= rd.lo && c.hi <= rd.hi) out.push(j);
    } else if (d.kind === 'cat' && rd.kind === 'cat') {
      const cell = catCellOf({ kind: 'cat', path: d.path, values: rd.values }, repValue(d, j) as string);
      if (rd.cells.includes(cell)) out.push(j);
    }
  }
  return out;
}

/**
 * Apply a partial answer to question q. Returns a NEW learner over the refined Ω (the old one is untouched) and the
 * observations the answer added.
 */
export function answerPartial(l: IntentLearner, q: Question, a: PartialAnswer): { learner: IntentLearner; added: Observation[] } {
  const oldVs = l.omega.verbs.find((v) => v.verb === q.verb);
  if (!oldVs) throw new Error(`answerPartial: no verb ${q.verb}`);
  const qRegion = regionOfCell(oldVs, q.cell);
  const r: Refinement = { verb: q.verb, path: a.path, ...(a.cuts ? { cuts: a.cuts } : {}), ...(a.values ? { values: a.values } : {}), ...(a.newDim ? { newDim: a.newDim } : {}) };
  const refinedOmega = refineOmega(l.omega, r);
  const nvs = refinedOmega.verbs.find((v) => v.verb === q.verb)!;
  const d = nvs.dims.find((x) => x.path === a.path)!;
  let rescope: ((o: Observation, region: Region) => Region) | undefined;
  if (a.newDim) {
    const yesCells = Array.from({ length: d.kind === 'num' ? numCells(d).length : d.values.length }, (_, j) => j).filter((j) => partLabel(d, j, a.parts) === 1);
    rescope = (o, region) => {
      if (o.verb !== q.verb || o.y !== 1) return region;
      if (d.kind === 'cat') return restrictRegion(region, d, { cells: yesCells });
      // numeric: restrict to the contiguous accepted span (the "typical" range the earlier yes was about)
      if (yesCells.length === 0) return restrictRegion(region, d, { lo: d.hi + 1, hi: d.hi + 1 });
      const cells = numCells(d);
      return restrictRegion(region, d, { lo: cells[yesCells[0]!]!.lo, hi: cells[yesCells[yesCells.length - 1]!]!.hi });
    };
  }
  const next = refineLearner(l, r, rescope);
  const added: Observation[] = [];
  for (const j of subCells(d, qRegion)) {
    const y = partLabel(d, j, a.parts);
    if (y === null) continue;
    const region = d.kind === 'num' ? restrictRegion(qRegion, d, { lo: numCells(d)[j]!.lo, hi: numCells(d)[j]!.hi }) : restrictRegion(qRegion, d, { cells: [j] });
    const values: Record<string, number | string> = { ...q.outcome.values, [d.path]: repValue(d, j) };
    for (const x of nvs.dims) if (!(x.path in values)) values[x.path] = repValue(x, 0);
    const ob = next.observe({ verb: q.verb, values }, y, 'elicitation', region);
    if (ob) added.push(ob);
  }
  return { learner: next, added };
}

export type AdaptiveAnswer = 0 | 1 | PartialAnswer;

export interface AdaptiveElicitOptions extends ElicitOptions {
  /** Cap on the number of partial answers (each re-enumerates Θ_v). Default 8. */
  maxRefinements?: number;
}

export interface AdaptiveElicitResult extends ElicitResult {
  learner: IntentLearner;
  refinements: number;
}

/**
 * Elicitation that accepts "yes", "no" and "partly" (spec §4.2c, M6). Same stop rule and audit as `elicit`; a
 * partial answer counts as one question and swaps in the refined learner. After `maxRefinements` partial answers,
 * further partial answers are treated as "no" (cell-universal semantics, §2.7: burden, never risk).
 */
export function elicitAdaptive(learner: IntentLearner, answer: (q: Question, l: IntentLearner) => AdaptiveAnswer, o: AdaptiveElicitOptions): AdaptiveElicitResult {
  let l = learner;
  const asked: Question[] = [];
  let refinements = 0;
  const maxRef = o.maxRefinements ?? 8;
  const apply = (q: Question): void => {
    const a = answer(q, l);
    asked.push(q);
    if (typeof a === 'object') {
      if (refinements < maxRef) {
        l = answerPartial(l, q, a).learner;
        refinements++;
      } else l.observe(q.outcome, 0, 'elicitation');
    } else l.observe(q.outcome, a, 'elicitation');
  };
  let seedQuestions = 0;
  for (const s of o.seed ?? []) {
    if (asked.length >= o.maxQuestions) break;
    const vs = l.omega.verbs.find((v: VerbSpace) => v.verb === s.verb);
    if (!vs || s.cell.length !== vs.dims.length) continue;
    const outcome = { verb: s.verb, values: Object.fromEntries(vs.dims.map((d, k) => [d.path, repValue(d, s.cell[k]!)])) };
    const p = l.acceptance(outcome);
    if (p <= 1e-9 || p >= 1 - 1e-9 || l.isVetoed(outcome)) continue;
    apply({ verb: s.verb, cell: [...s.cell], outcome, p, score: 0 });
    seedQuestions++;
  }
  let stop: ElicitResult['stop'] | null = null;
  while (stop === null) {
    const m = l.metrics();
    if (m.residualRisk <= o.epsRisk && m.burden <= o.epsBurden) stop = 'converged';
    else if (asked.length >= o.maxQuestions) stop = 'budget';
    else {
      const q = l.nextQuestion();
      if (!q) stop = 'no-disagreement';
      else apply(q);
    }
  }
  let auditQuestions = 0;
  if (o.audit) {
    for (;;) {
      const pending = l.unconfirmedGrantCells();
      if (pending.length === 0 || pending.reduce((s, x) => s + x.weight, 0) <= o.epsRisk) break;
      if (asked.length >= o.maxQuestions) {
        stop = 'budget';
        break;
      }
      const top = pending[0]!;
      const vs = l.omega.verbs.find((v) => v.verb === top.verb)!;
      const outcome = cellRep(vs, top.cell);
      apply({ verb: top.verb, cell: top.cell, outcome, p: l.acceptance(outcome), score: top.weight });
      auditQuestions++;
    }
  }
  return { stop, questions: asked.length, auditQuestions, seedQuestions, asked, learner: l, refinements };
}
