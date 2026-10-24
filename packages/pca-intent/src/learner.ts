import type { Caveat, Condition, Predicate } from '@atlasauth/pca';
import {
  cellOf,
  cellRep,
  cellStats,
  decodeCell,
  DEFAULT_HARM,
  numCells,
  verbCellCount,
  type CatDim,
  type Dim,
  type HarmModel,
  type Omega,
  type Outcome,
  type VerbSpace,
} from './omega';
import { admitter, type PolicyInput } from './policy';
import { regionCells, type Region } from './region';

/**
 * ELICITATION AS LEARNING (spec §2.4–2.5, §4).
 *
 * Hypothesis class Θ = Π_v Θ_v. The default Θ_v (spec §2.4, `box`) = {∅ (deny the verb)} ∪ {boxes Π_d S_d}: S_d a
 * non-empty contiguous range of numeric cells or a non-empty subset of categorical values. A hypothesis θ says
 * a_θ(ω) = 1[ω ∈ θ]. Two richer classes (spec §11 item 1, roadmap M6) are available:
 *   - `union`         : unions of at most k boxes (deduplicated as cell sets);
 *   - `decision-list` : ordered lists of at most L rules "if <condition> then yes/no", then a default (a Rivest-style
 *                       decision list over conjunctive terms). With `conditions: 'box'` (the default, class name
 *                       `per-verb-decision-list/v2`) a condition is a BOX, i.e. a conjunction over the dimensions of one
 *                       contiguous numeric range / non-empty categorical subset each. With `conditions: 'atomic'` (the
 *                       legacy v1 class, kept so v1 Intent Maps replay) a condition is a single one-dimensional test: a
 *                       threshold, a single numeric cell, or a single categorical value.
 * SUPERSET (exact, for every k ≥ 1 and L ≥ 1): every box θ is the union class's 1-box union and the box-condition decision
 * list [(θ, yes)] with default no, so both classes contain every cell set of the box class, at complexity 1. Every
 * atomic test is itself a box (the other sides full), so the v2 decision-list class also contains the v1 class for the
 * same L. The v1 class is NOT a superset of `box`: a box that excludes three or more one-dimensional pieces needs
 * more than L = 2 atomic rules (spec §9.1a). Prior: an Occam prior, weight ∝ decay^(complexity − 1), complexity = the
 * fewest boxes / rules that produce the cell set, so on box-shaped cell sets the prior ratio is the box class's (all at
 * complexity 1). Under misspecification of `box` they are what turns a CONFLICT into a realizable answer (X01-style).
 *
 * The learner keeps the EXACT Bayesian posterior π_n over Θ (an explicit weight per hypothesis; Θ_v are a priori
 * independent and each question touches one verb, so the posterior factorises by verb). With noise rate η = 0
 * the support of π_n is the version space VS_n and an inconsistent answer is reported as a CONFLICT (evidence
 * that the true intent is outside Θ, i.e. the cuts are too coarse or the intent is not box-shaped).
 *
 * AGNOSTIC SELECTION (`agnosticSlack` = s, η = 0 only): instead of discarding every hypothesis that contradicts an
 * answer, keep the hypotheses whose number of mistakes is within s of the fewest any hypothesis makes (the
 * candidate set of A², Balcan, Beygelzimer and Langford 2006). The posterior is the prior restricted to that set.
 * s = 0 with a realizable truth is exactly the version space.
 *
 * Answers are about REGIONS (value-space products of cells, `region.ts`): y = 1 iff every outcome in the region is
 * acceptable, so a_θ(R) = 1[R ⊆ θ]. A plain cell question is the region of one cell (spec §2.7).
 *
 * From π_n it derives, per cell: p_n(cell) = π_n({θ ∋ cell}). Everything else follows:
 *   conservative grant  G_τ = {cells : p_n ≥ τ, not vetoed},  τ = 1 − δ
 *   residual risk       R̂ = Σ_{c∈G} μ(c)·(1 − p_n(c))·E[h|c]
 *   burden              B̂ = Σ_{c∉G} μ(c)·p_n(c)
 *   uncertainty         U = Σ_c μ(c)·min(p_n, 1 − p_n),   H(π_n),   log₂|VS_n|
 * The next question is the cell with the most expected information (query-by-committee with the whole
 * posterior as the committee), optionally weighted by μ·h ("risk" strategy).
 */

export type Strategy = 'disagreement' | 'risk';

export type HypothesisClassSpec =
  | { kind: 'box' }
  | { kind: 'union'; k: number; decay?: number }
  | {
      kind: 'decision-list';
      maxRules: number;
      decay?: number;
      /** Rule conditions: 'box' (default; a conjunction over dimensions, class v2) or 'atomic' (one-dimension tests, class v1). */
      conditions?: DecisionListConditions;
    };

export type DecisionListConditions = 'box' | 'atomic';

export type HypothesisClassName = 'per-verb-box/v1' | 'per-verb-union/v1' | 'per-verb-decision-list/v1' | 'per-verb-decision-list/v2';

/** The canonical name of a hypothesis class (stored in the Intent Map). */
export function hypothesisClassName(h: HypothesisClassSpec): HypothesisClassName {
  if (h.kind === 'box') return 'per-verb-box/v1';
  if (h.kind === 'union') return 'per-verb-union/v1';
  return (h.conditions ?? 'box') === 'atomic' ? 'per-verb-decision-list/v1' : 'per-verb-decision-list/v2';
}

export interface AnchorSpec {
  policy: PolicyInput;
  lambda: number;
}

export interface LearnerOptions {
  /** Assumed answer-noise rate η ∈ [0, 1/2). Default 0. */
  eta?: number;
  /**
   * v2 §2.5 asymmetric noise: false-yes rate η⁺ = P(y=1 | a=0) and false-no rate η⁻ = P(y=0 | a=1), each in [0, 1/2).
   * Each defaults to `eta` (so η⁺ = η⁻ = η is exactly v1).
   */
  etaPos?: number;
  etaNeg?: number;
  /**
   * v2 §3.12 mixture prior (population priors): w_h ← (1 − beta)·w_h + beta·weight(h)/Σ weight, applied after every
   * other prior term. beta ∈ [0, 1) keeps full support, which is what makes the prior neutral at τ = 1 (T23).
   */
  priorMix?: { beta: number; weight: (vs: VerbSpace, contains: (cell: number) => boolean) => number };
  /** Synthesis threshold τ = 1 − δ. Default 1 when η = 0, else 0.95. */
  tau?: number;
  /** Prior mass of the deny-verb hypothesis ∅, per verb. Default 0.2. */
  nullMass?: number | ((vs: VerbSpace) => number);
  /** Prior anchored on a draft grant (e.g. the single-shot compiled grant): w ∝ exp(−λ·d(θ, anchor)). */
  anchor?: AnchorSpec;
  /**
   * Prior anchored on SEVERAL draft grants (the k-compiler committee, spec §4.2a): w ∝ mean_i exp(−λ_i·d(θ, g_i)),
   * a mixture, so every compiler's reading keeps prior mass. Combined with `anchor` if both are given.
   */
  anchors?: AnchorSpec[];
  harm?: HarmModel;
  /** Hard cap on |Θ_v| (exact enumeration). Default 400 000. */
  maxHypotheses?: number;
  /** Work cap for enumerating the `union` / `decision-list` classes (set operations). Default 4 000 000. */
  maxEnumeration?: number;
  strategy?: Strategy;
  /** Θ_v. Default `{ kind: 'box' }` (spec §2.4). */
  hypothesisClass?: HypothesisClassSpec;
  /** Agnostic selection slack s ≥ 0 (requires η = 0). Undefined = the Bayesian / version-space posterior. */
  agnosticSlack?: number;
  /**
   * Intent Layer v2 monotone prior (spec v2 §2.2, T30): a hypothesis is ψ-monotone when its cell set is DOWNWARD-CLOSED
   * along every listed numeric dimension (sum / count accumulators: more spend is never more acceptable). Non-monotone
   * hypotheses keep `offMass` × their weight (default 0: the prior lives on Θ̃^mono).
   */
  monotone?: { paths: string[]; offMass?: number };
}

export interface Observation {
  verb: string;
  values: Record<string, number | string>;
  /** Per-dimension cell indices of `values`. */
  cell: number[];
  y: 0 | 1;
  source: 'elicitation' | 'runtime' | 'witness' | 'import';
  /** Present when the answer was about an explicit region (partial answers, lifted / refined observations). */
  region?: Region;
  /** true when the answer contradicted every hypothesis still alive and was honoured by veto (a "no") or set aside. */
  conflict?: boolean;
}

interface VerbModel {
  vs: VerbSpace;
  /** Number of choices per dimension (box class). */
  nChoice: number[];
  /** contains[d][choice * nCells_d + cell] (box class). */
  contains: Uint8Array[];
  nCellsD: number[];
  /** Hypotheses: index 0 = ∅; for the box class row h (≥1) holds D choice indices at choice[(h-1)*D + d]. */
  nh: number;
  choice: Int32Array;
  /** Explicit membership table for the non-box classes: member[h * nCells + c]; row 0 is ∅. Null for `box`. */
  member: Uint8Array | null;
  /** Complexity of each hypothesis (boxes or rules), for the Occam prior; null for `box`. */
  complexity: Uint16Array | null;
  /** Prior weights (kept for agnostic re-selection). */
  prior: Float64Array;
  w: Float64Array;
  /** Mistake counts per hypothesis (agnostic selection). */
  err: Int32Array;
  /** Flat cells. */
  nCells: number;
  cellIdx: Int32Array; // nCells * D
  mass: Float64Array;
  harm: Float64Array;
  p: Float64Array;
  /** Cells vetoed by a negative RUNTIME observation, or by a negative answer that contradicts every hypothesis
   *  (the class cannot represent it): never in the grant again (the ratchet). */
  veto: Uint8Array;
  /** Cells with at least one direct observation (asked or observed at run time). */
  seen: Uint8Array;
  dirty: boolean;
}

function binEnt(p: number): number {
  if (p <= 0 || p >= 1) return 0;
  return -(p * Math.log2(p) + (1 - p) * Math.log2(1 - p));
}

/** Numeric choices: all contiguous ranges [i, j] of n cells. */
function rangeChoices(n: number): [number, number][] {
  const out: [number, number][] = [];
  for (let i = 0; i < n; i++) for (let j = i; j < n; j++) out.push([i, j]);
  return out;
}

type FullOpts = Required<Pick<LearnerOptions, 'maxHypotheses' | 'maxEnumeration'>> & LearnerOptions;

function buildBoxTables(vs: VerbSpace, nCellsD: number[]): { contains: Uint8Array[]; nChoice: number[] } {
  const contains: Uint8Array[] = [];
  const nChoice: number[] = [];
  vs.dims.forEach((d, k) => {
    const n = nCellsD[k]!;
    if (d.kind === 'num') {
      const ch = rangeChoices(n);
      const t = new Uint8Array(ch.length * n);
      ch.forEach(([i, j], c) => {
        for (let x = i; x <= j; x++) t[c * n + x] = 1;
      });
      contains.push(t);
      nChoice.push(ch.length);
    } else {
      if (n > 20) throw new Error(`pca-intent: categorical dimension ${d.path} has ${n} values (max 20 for exact enumeration)`);
      const m = (1 << n) - 1; // non-empty subsets: masks 1..2^n-1 -> choice = mask-1
      const t = new Uint8Array(m * n);
      for (let mask = 1; mask <= m; mask++) for (let x = 0; x < n; x++) if (mask & (1 << x)) t[(mask - 1) * n + x] = 1;
      contains.push(t);
      nChoice.push(m);
    }
  });
  return { contains, nChoice };
}

/** Every box of the verb as a cell bitmask (one byte per cell). */
function boxMasks(vs: VerbSpace, nCells: number, cellIdx: Int32Array, nCellsD: number[], contains: Uint8Array[], nChoice: number[], cap: number): Uint8Array[] {
  const D = vs.dims.length;
  let boxes = 1;
  for (const c of nChoice) boxes *= c;
  if (boxes > cap) throw new Error(`pca-intent: ${boxes} boxes for ${vs.verb} exceed the enumeration cap; coarsen the cuts`);
  const out: Uint8Array[] = [];
  const cur = new Array<number>(D).fill(0);
  for (let b = 0; b < boxes; b++) {
    const mask = new Uint8Array(nCells);
    for (let c = 0; c < nCells; c++) {
      let inside = true;
      for (let d = 0; d < D && inside; d++) if (contains[d]![cur[d]! * nCellsD[d]! + cellIdx[c * D + d]!] === 0) inside = false;
      if (inside) mask[c] = 1;
    }
    out.push(mask);
    for (let d = D - 1; d >= 0; d--) {
      cur[d] = cur[d]! + 1;
      if (cur[d]! < nChoice[d]!) break;
      cur[d] = 0;
    }
  }
  return out;
}

const keyOf = (m: Uint8Array): string => {
  let s = '';
  for (let i = 0; i < m.length; i += 16) s += String.fromCharCode(...Array.from(m.subarray(i, i + 16), (x) => 48 + x));
  return s;
};

/** Unions of at most k boxes, deduplicated by cell set; complexity = fewest boxes. Excludes the empty set. */
function enumerateUnions(boxes: Uint8Array[], k: number, cap: number, verb: string): { sets: Uint8Array[]; complexity: number[] } {
  const seen = new Map<string, number>();
  const sets: Uint8Array[] = [];
  const complexity: number[] = [];
  let frontier: Uint8Array[] = [];
  for (const b of boxes) {
    const key = keyOf(b);
    if (seen.has(key)) continue;
    seen.set(key, sets.length);
    sets.push(b);
    complexity.push(1);
    frontier.push(b);
  }
  let work = 0;
  for (let level = 2; level <= k; level++) {
    const next: Uint8Array[] = [];
    for (const s of frontier) {
      for (const b of boxes) {
        work += 1;
        if (work > cap) throw new Error(`pca-intent: the union-of-${k}-boxes class for ${verb} exceeds the enumeration cap; coarsen the cuts or lower k`);
        const u = new Uint8Array(s.length);
        for (let i = 0; i < s.length; i++) u[i] = s[i]! | b[i]!;
        const key = keyOf(u);
        if (seen.has(key)) continue;
        seen.set(key, sets.length);
        sets.push(u);
        complexity.push(level);
        next.push(u);
      }
    }
    frontier = next;
  }
  return { sets, complexity };
}

/** Atomic one-dimensional tests of a verb as cell masks (thresholds, single numeric cells, single categorical values). */
function atomicTests(vs: VerbSpace, nCells: number, cellIdx: Int32Array, nCellsD: number[]): Uint8Array[] {
  const D = vs.dims.length;
  const tests: Uint8Array[] = [];
  const add = (k: number, pred: (i: number) => boolean) => {
    const m = new Uint8Array(nCells);
    let any = false;
    let all = true;
    for (let c = 0; c < nCells; c++) {
      if (pred(cellIdx[c * D + k]!)) (m[c] = 1), (any = true);
      else all = false;
    }
    if (any && !all) tests.push(m);
  };
  vs.dims.forEach((d, k) => {
    const n = nCellsD[k]!;
    if (d.kind === 'num') {
      for (let i = 0; i < n - 1; i++) add(k, (x) => x <= i);
      for (let i = 1; i < n; i++) add(k, (x) => x >= i);
      if (n > 2) for (let i = 1; i < n - 1; i++) add(k, (x) => x === i);
    } else for (let i = 0; i < n; i++) add(k, (x) => x === i);
  });
  return dedupMasks(tests);
}

/** Drop repeated cell masks, keeping the first occurrence (deterministic order). */
function dedupMasks(masks: Uint8Array[]): Uint8Array[] {
  const seen = new Set<string>();
  return masks.filter((t) => {
    const key = keyOf(t);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Decision lists of at most L rules plus a default, over the given rule conditions (cell masks: atomic tests or boxes).
 * State after j rules = (decided cells, accepted cells); states are deduplicated per depth, so the work is bounded by
 * the number of distinct partial decisions, not by T^L. Cell sets are emitted in order of depth, so a set's
 * complexity is the fewest rules that produce it (a box condition θ gives θ itself at depth 1).
 */
function enumerateDecisionLists(tests: Uint8Array[], nCells: number, L: number, cap: number, verb: string): { sets: Uint8Array[]; complexity: number[] } {
  const seen = new Map<string, number>();
  const sets: Uint8Array[] = [];
  const complexity: number[] = [];
  const emit = (acc: Uint8Array, decided: Uint8Array, rules: number) => {
    for (const def of [0, 1]) {
      const s = new Uint8Array(nCells);
      let any = false;
      for (let c = 0; c < nCells; c++) {
        s[c] = decided[c] ? acc[c]! : def;
        if (s[c]) any = true;
      }
      if (!any) continue;
      const key = keyOf(s);
      if (seen.has(key)) continue;
      seen.set(key, sets.length);
      sets.push(s);
      complexity.push(Math.max(1, rules));
    }
  };
  let frontier: { decided: Uint8Array; acc: Uint8Array }[] = [{ decided: new Uint8Array(nCells), acc: new Uint8Array(nCells) }];
  emit(frontier[0]!.acc, frontier[0]!.decided, 0);
  let work = 0;
  for (let depth = 1; depth <= L; depth++) {
    const states = new Map<string, { decided: Uint8Array; acc: Uint8Array }>();
    for (const st of frontier) {
      for (const t of tests) {
        for (const label of [0, 1]) {
          work += 1;
          if (work > cap) throw new Error(`pca-intent: the decision-list class (≤ ${L} rules) for ${verb} exceeds the enumeration cap`);
          const decided = new Uint8Array(nCells);
          const acc = new Uint8Array(nCells);
          let fresh = false;
          for (let c = 0; c < nCells; c++) {
            if (st.decided[c]) (decided[c] = 1), (acc[c] = st.acc[c]!);
            else if (t[c]) (decided[c] = 1), (acc[c] = label), (fresh = true);
          }
          if (!fresh) continue; // a rule that decides nothing new is redundant
          const key = keyOf(decided) + '|' + keyOf(acc);
          if (states.has(key)) continue;
          states.set(key, { decided, acc });
        }
      }
    }
    frontier = [...states.values()];
    for (const st of frontier) emit(st.acc, st.decided, depth);
  }
  return { sets, complexity };
}

function buildVerbModel(vs: VerbSpace, opts: FullOpts, harm: HarmModel): VerbModel {
  const D = vs.dims.length;
  const nCellsD = vs.dims.map((d) => (d.kind === 'num' ? numCells(d).length : d.values.length));
  const { contains, nChoice } = buildBoxTables(vs, nCellsD);
  const nCells = verbCellCount(vs);
  const cellIdx = new Int32Array(nCells * D);
  const mass = new Float64Array(nCells);
  const hm = new Float64Array(nCells);
  for (let c = 0; c < nCells; c++) {
    const idx = decodeCell(vs, c);
    for (let d = 0; d < D; d++) cellIdx[c * D + d] = idx[d]!;
    const s = cellStats(vs, idx, harm);
    mass[c] = s.mass;
    hm[c] = s.harm;
  }
  const hc = opts.hypothesisClass ?? { kind: 'box' };
  let nh: number;
  let choice = new Int32Array(1);
  let member: Uint8Array | null = null;
  let complexity: Uint16Array | null = null;
  if (hc.kind === 'box') {
    let boxes = 1;
    for (const c of nChoice) boxes *= c;
    if (boxes + 1 > opts.maxHypotheses) {
      throw new Error(`pca-intent: |Θ_${vs.verb}| = ${boxes + 1} exceeds maxHypotheses ${opts.maxHypotheses}; coarsen the cuts`);
    }
    nh = boxes + 1;
    choice = new Int32Array(Math.max(1, boxes * D));
    const cur = new Array<number>(D).fill(0);
    for (let h = 0; h < boxes; h++) {
      for (let d = 0; d < D; d++) choice[h * D + d] = cur[d]!;
      for (let d = D - 1; d >= 0; d--) {
        cur[d] = cur[d]! + 1;
        if (cur[d]! < nChoice[d]!) break;
        cur[d] = 0;
      }
    }
  } else {
    let sets: Uint8Array[];
    let cx: number[];
    if (hc.kind === 'union') {
      if (!(Number.isInteger(hc.k) && hc.k >= 1)) throw new Error('pca-intent: union class needs an integer k ≥ 1');
      const boxes = boxMasks(vs, nCells, cellIdx, nCellsD, contains, nChoice, opts.maxEnumeration);
      ({ sets, complexity: cx } = enumerateUnions(boxes, hc.k, opts.maxEnumeration, vs.verb));
    } else {
      if (!(Number.isInteger(hc.maxRules) && hc.maxRules >= 1)) throw new Error('pca-intent: decision-list class needs an integer maxRules ≥ 1');
      const cond = hc.conditions ?? 'box';
      if (cond !== 'box' && cond !== 'atomic') throw new Error("pca-intent: decision-list conditions must be 'box' or 'atomic'");
      const tests = cond === 'atomic' ? atomicTests(vs, nCells, cellIdx, nCellsD) : dedupMasks(boxMasks(vs, nCells, cellIdx, nCellsD, contains, nChoice, opts.maxEnumeration));
      ({ sets, complexity: cx } = enumerateDecisionLists(tests, nCells, hc.maxRules, opts.maxEnumeration, vs.verb));
    }
    if (sets.length + 1 > opts.maxHypotheses) {
      throw new Error(`pca-intent: |Θ_${vs.verb}| = ${sets.length + 1} exceeds maxHypotheses ${opts.maxHypotheses}; coarsen the cuts`);
    }
    nh = sets.length + 1;
    member = new Uint8Array(nh * nCells);
    complexity = new Uint16Array(nh);
    sets.forEach((s, i) => {
      member!.set(s, (i + 1) * nCells);
      complexity![i + 1] = cx[i]!;
    });
  }
  return {
    vs,
    nChoice,
    contains,
    nCellsD,
    nh,
    choice,
    member,
    complexity,
    prior: new Float64Array(nh),
    w: new Float64Array(nh),
    err: new Int32Array(nh),
    nCells,
    cellIdx,
    mass,
    harm: hm,
    p: new Float64Array(nCells),
    veto: new Uint8Array(nCells),
    seen: new Uint8Array(nCells),
    dirty: true,
  };
}

/** Does hypothesis h (≥ 1) contain flat cell c? */
function holds(m: VerbModel, h: number, c: number): boolean {
  if (m.member) return m.member[h * m.nCells + c] === 1;
  const D = m.vs.dims.length;
  const base = (h - 1) * D;
  for (let d = 0; d < D; d++) {
    const n = m.nCellsD[d]!;
    if (m.contains[d]![m.choice[base + d]! * n + m.cellIdx[c * D + d]!] === 0) return false;
  }
  return true;
}

/**
 * The non-empty hypotheses of Θ_v for a hypothesis class, as cell masks over the verb's flat cells (index 0 = ∅ is
 * omitted), each with its Occam complexity (1 for the box class). Exposed for the class-inclusion property tests.
 */
export function hypothesisCellSets(
  vs: VerbSpace,
  hypothesisClass: HypothesisClassSpec = { kind: 'box' },
  caps: { maxHypotheses?: number; maxEnumeration?: number } = {},
): { sets: Uint8Array[]; complexity: number[] } {
  const m = buildVerbModel(vs, { maxHypotheses: 400_000, maxEnumeration: 4_000_000, ...caps, hypothesisClass }, DEFAULT_HARM);
  const sets: Uint8Array[] = [];
  const complexity: number[] = [];
  for (let h = 1; h < m.nh; h++) {
    const s = new Uint8Array(m.nCells);
    for (let c = 0; c < m.nCells; c++) if (holds(m, h, c)) s[c] = 1;
    sets.push(s);
    complexity.push(m.complexity ? m.complexity[h]! : 1);
  }
  return { sets, complexity };
}

/** Scale every hypothesis that is not downward-closed along the listed numeric dimensions by `offMass` (T30). */
function applyMonotonePrior(m: VerbModel, mono: { paths: string[]; offMass?: number }): void {
  const off = mono.offMass ?? 0;
  if (!(off >= 0 && off <= 1)) throw new Error('pca-intent: monotone.offMass must be in [0, 1]');
  const D = m.vs.dims.length;
  const ks = m.vs.dims.flatMap((d, k) => (d.kind === 'num' && mono.paths.includes(d.path) ? [k] : []));
  if (ks.length === 0) return;
  const stride = ks.map((k) => m.nCellsD.slice(k + 1).reduce((a, b) => a * b, 1));
  for (let h = 1; h < m.nh; h++) {
    let isMono = true;
    for (let c = 0; c < m.nCells && isMono; c++) {
      if (!holds(m, h, c)) continue;
      for (let i = 0; i < ks.length; i++) {
        if (m.cellIdx[c * D + ks[i]!]! > 0 && !holds(m, h, c - stride[i]!)) {
          isMono = false;
          break;
        }
      }
    }
    if (!isMono) m.w[h] = m.w[h]! * off;
  }
}

/** a_θ(R) for a region given as its cell list: 1 iff every cell is in θ. */
function holdsAll(m: VerbModel, h: number, cells: readonly number[]): boolean {
  if (h === 0) return false;
  for (const c of cells) if (!holds(m, h, c)) return false;
  return true;
}

export interface Question {
  verb: string;
  cell: number[];
  /** The concrete boundary-witness outcome asked about. */
  outcome: Outcome;
  /** Current p_n(cell). */
  p: number;
  score: number;
}

export interface LearnerMetrics {
  /** R̂_n(G_τ). */
  residualRisk: number;
  /** B̂_n(G_τ). */
  burden: number;
  /** U_n. */
  uncertainty: number;
  /** H(π_n) in bits (sum over verbs). */
  entropyBits: number;
  /** log₂|VS_n| (sum over verbs); null when η > 0 (no hard version space). */
  log2VersionSpace: number | null;
  /** μ(DIS(VS_n)) — mass of cells with 0 < p < 1 (η = 0: exactly the disagreement region). */
  disagreementMass: number;
  /** Σ μ(c)·E[h|c]: the scale ε_R is usually expressed in. */
  meanHarm: number;
  questions: number;
  conflicts: number;
}

export interface CellView {
  verb: string;
  cell: number[];
  p: number;
  mass: number;
  harm: number;
  inGrant: boolean;
  vetoed: boolean;
}

export class IntentLearner {
  readonly omega: Omega;
  readonly eta: number;
  /** η⁺ (false yes) and η⁻ (false no); both equal `eta` unless set (v2 §2.5). */
  readonly etaPos: number;
  readonly etaNeg: number;
  private readonly noisy: boolean;
  readonly tau: number;
  readonly strategy: Strategy;
  readonly harm: HarmModel;
  readonly hypothesisClass: HypothesisClassSpec;
  readonly agnosticSlack: number | undefined;
  readonly observations: Observation[] = [];
  private readonly models: VerbModel[];
  private readonly opts: LearnerOptions;

  constructor(omega: Omega, opts: LearnerOptions = {}) {
    this.omega = omega;
    this.opts = opts;
    this.eta = opts.eta ?? 0;
    if (!(this.eta >= 0 && this.eta < 0.5)) throw new Error('pca-intent: eta must be in [0, 0.5)');
    this.etaPos = opts.etaPos ?? this.eta;
    this.etaNeg = opts.etaNeg ?? this.eta;
    if (!(this.etaPos >= 0 && this.etaPos < 0.5 && this.etaNeg >= 0 && this.etaNeg < 0.5)) throw new Error('pca-intent: etaPos and etaNeg must be in [0, 0.5)');
    this.noisy = this.etaPos !== 0 || this.etaNeg !== 0;
    this.tau = opts.tau ?? (this.noisy ? 0.95 : 1);
    this.strategy = opts.strategy ?? 'disagreement';
    this.harm = opts.harm ?? DEFAULT_HARM;
    this.hypothesisClass = opts.hypothesisClass ?? { kind: 'box' };
    this.agnosticSlack = opts.agnosticSlack;
    if (this.agnosticSlack !== undefined) {
      if (!(Number.isInteger(this.agnosticSlack) && this.agnosticSlack >= 0)) throw new Error('pca-intent: agnosticSlack must be a non-negative integer');
      if (this.noisy) throw new Error('pca-intent: agnostic selection replaces the noise model; use eta = 0');
    }
    const full: FullOpts = { maxHypotheses: 400_000, maxEnumeration: 4_000_000, ...opts };
    this.models = omega.verbs.map((vs) => buildVerbModel(vs, full, this.harm));
    this.initPrior();
  }

  private initPrior(): void {
    const anchors: AnchorSpec[] = [...(this.opts.anchor ? [this.opts.anchor] : []), ...(this.opts.anchors ?? [])].filter((a) => a.lambda > 0);
    const admitters = anchors.map((a) => ({ adm: admitter(a.policy), lambda: a.lambda }));
    const decay = this.hypothesisClass.kind === 'box' ? 1 : (this.hypothesisClass.decay ?? 0.25);
    if (!(decay > 0 && decay <= 1)) throw new Error('pca-intent: decay must be in (0, 1]');
    for (const m of this.models) {
      const nm = typeof this.opts.nullMass === 'function' ? this.opts.nullMass(m.vs) : (this.opts.nullMass ?? 0.2);
      if (!(nm >= 0 && nm <= 1)) throw new Error('pca-intent: nullMass must be in [0, 1]');
      m.w[0] = nm;
      let z = 0;
      for (let h = 1; h < m.nh; h++) {
        const raw = m.complexity ? Math.pow(decay, m.complexity[h]! - 1) : 1;
        m.w[h] = raw;
        z += raw;
      }
      for (let h = 1; h < m.nh; h++) m.w[h] = ((1 - nm) * m.w[h]!) / (z || 1);
      if (this.opts.monotone) applyMonotonePrior(m, this.opts.monotone);
      if (admitters.length) {
        let tot = 0;
        for (let c = 0; c < m.nCells; c++) tot += m.mass[c]!;
        const accs = admitters.map(({ adm }) => {
          const acc = new Uint8Array(m.nCells);
          for (let c = 0; c < m.nCells; c++) acc[c] = adm.admits(m.vs, cellRep(m.vs, decodeCell(m.vs, c))) ? 1 : 0;
          return acc;
        });
        for (let h = 0; h < m.nh; h++) {
          let mix = 0;
          accs.forEach((acc, i) => {
            let dist = 0;
            for (let c = 0; c < m.nCells; c++) {
              const inH = h === 0 ? 0 : holds(m, h, c) ? 1 : 0;
              if (inH !== acc[c]) dist += m.mass[c]!;
            }
            mix += Math.exp((-admitters[i]!.lambda * dist) / (tot || 1));
          });
          m.w[h] = m.w[h]! * (mix / accs.length);
        }
      }
      normalize(m.w);
      if (this.opts.priorMix) mixPrior(m, this.opts.priorMix);
      m.prior.set(m.w);
      m.dirty = true;
    }
  }

  private inGrant(m: VerbModel, c: number): boolean {
    return m.veto[c] === 0 && m.p[c]! >= this.tau - 1e-12;
  }

  private model(verb: string): VerbModel | undefined {
    return this.models.find((m) => m.vs.verb === verb);
  }

  private refresh(m: VerbModel): void {
    if (!m.dirty) return;
    m.p.fill(0);
    // Certainty is decided COMBINATORIALLY, not by the float sum: p = 1 exactly iff every hypothesis with positive weight
    // contains the cell, p = 0 exactly iff none does. Summing renormalised weights can land at 1 - 2^-52 for a cell all
    // live hypotheses agree on, which would make a settled cell "uncertain" again (U must only shrink: T13).
    const anyIn = new Uint8Array(m.nCells);
    const anyOut = new Uint8Array(m.nCells);
    let live = false;
    for (let h = 0; h < m.nh; h++) {
      const w = m.w[h]!;
      if (w === 0) continue;
      live = true;
      for (let c = 0; c < m.nCells; c++) {
        if (h > 0 && holds(m, h, c)) {
          m.p[c] = m.p[c]! + w;
          anyIn[c] = 1;
        } else anyOut[c] = 1;
      }
    }
    // no live hypothesis (an empty posterior) admits nothing
    for (let c = 0; c < m.nCells; c++) m.p[c] = !live || anyIn[c] === 0 ? 0 : anyOut[c] === 0 ? 1 : Math.min(1, Math.max(0, m.p[c]!));
    m.dirty = false;
  }

  /** p_n(ω) for a concrete outcome (0 if outside Ω: the conservative reading). */
  acceptance(o: Outcome): number {
    const m = this.model(o.verb);
    if (!m) return 0;
    const idx = cellOf(m.vs, o);
    if (!idx) return 0;
    this.refresh(m);
    return m.p[flat(m, idx)]!;
  }

  /** Is ω inside the current conservative grant (p_n ≥ τ and not vetoed)? Outside Ω: no. */
  admitsOutcome(o: Outcome): boolean {
    const m = this.model(o.verb);
    if (!m) return false;
    const idx = cellOf(m.vs, o);
    if (!idx) return false;
    this.refresh(m);
    return this.inGrant(m, flat(m, idx));
  }

  /** Has ω's cell been vetoed (the ratchet)? */
  isVetoed(o: Outcome): boolean {
    const m = this.model(o.verb);
    const idx = m ? cellOf(m.vs, o) : null;
    return !!m && !!idx && m.veto[flat(m, idx)] === 1;
  }

  /** Every vetoed cell, as "verb|flat" keys (for ratchet checks). */
  vetoedCells(): string[] {
    const out: string[] = [];
    for (const m of this.models) for (let c = 0; c < m.nCells; c++) if (m.veto[c]) out.push(`${m.vs.verb}|${c}`);
    return out;
  }

  /**
   * Record the principal's answer y to "should ω be allowed?" (or, with `region`, "should EVERY outcome in this
   * region be allowed?") and update the posterior. Returns null when the outcome is outside Ω or the region
   * covers no cell of Ω.
   */
  observe(o: Outcome, y: 0 | 1, source: Observation['source'] = 'elicitation', region?: Region): Observation | null {
    const m = this.model(o.verb);
    if (!m) return null;
    const idx = cellOf(m.vs, o);
    if (!idx) return null;
    const cells = region ? regionCells(m.vs, region, y === 1 ? 'inner' : 'outer') : [flat(m, idx)];
    if (cells.length === 0) return null;
    this.refresh(m);
    const obs: Observation = { verb: o.verb, values: { ...o.values }, cell: idx, y, source, ...(region ? { region } : {}) };
    // A "no" about a region every live hypothesis contains contradicts the whole class (the CONFLICT of §4.2c).
    let regionP = 0;
    for (let h = 1; h < m.nh; h++) if (m.w[h]! > 0 && holdsAll(m, h, cells)) regionP += m.w[h]!;
    const contradictsAll = y === 0 ? regionP >= 1 - 1e-12 : regionP <= 1e-12;
    if (source === 'runtime' && y === 0) for (const c of cells) m.veto[c] = 1;
    for (const c of cells) m.seen[c] = 1;
    if (this.agnosticSlack !== undefined) {
      for (let h = 0; h < m.nh; h++) if ((holdsAll(m, h, cells) ? 1 : 0) !== y) m.err[h] = m.err[h]! + 1;
      let minErr = Infinity;
      for (let h = 0; h < m.nh; h++) if (m.prior[h]! > 0) minErr = Math.min(minErr, m.err[h]!);
      for (let h = 0; h < m.nh; h++) m.w[h] = m.err[h]! <= minErr + this.agnosticSlack ? m.prior[h]! : 0;
      normalize(m.w);
      if (contradictsAll) {
        obs.conflict = true;
        if (y === 0) for (const c of cells) m.veto[c] = 1;
      }
    } else {
      // Likelihood P(y | a_θ) (v2 §2.5): 1−η⁻ / η⁻ when θ accepts, η⁺ / 1−η⁺ when it rejects.
      const prev = this.etaPos === 0 || this.etaNeg === 0 ? Float64Array.from(m.w) : null;
      const lik = (inH: number): number => (inH === 1 ? (y === 1 ? 1 - this.etaNeg : this.etaNeg) : y === 1 ? this.etaPos : 1 - this.etaPos);
      let sum = 0;
      for (let h = 0; h < m.nh; h++) {
        m.w[h] = m.w[h]! * lik(holdsAll(m, h, cells) ? 1 : 0);
        sum += m.w[h]!;
      }
      if (sum === 0 && prev) {
        m.w.set(prev); // every hypothesis contradicted: the truth is outside Θ; keep VS, flag the conflict
        obs.conflict = true;
        if (y === 0) for (const c of cells) m.veto[c] = 1; // a "no" the class cannot explain: honour it by veto
      } else normalize(m.w);
    }
    m.dirty = true;
    this.observations.push(obs);
    return obs;
  }

  /** Cells of every verb with their posterior acceptance (for the Intent Map and synthesis). */
  cells(): CellView[] {
    const out: CellView[] = [];
    for (const m of this.models) {
      this.refresh(m);
      for (let c = 0; c < m.nCells; c++) {
        out.push({ verb: m.vs.verb, cell: decodeCell(m.vs, c), p: m.p[c]!, mass: m.mass[c]!, harm: m.harm[c]!, inGrant: this.inGrant(m, c), vetoed: m.veto[c] === 1 });
      }
    }
    return out;
  }

  metrics(): LearnerMetrics {
    let R = 0;
    let B = 0;
    let U = 0;
    let H = 0;
    let vs = 0;
    let dis = 0;
    let meanHarm = 0;
    for (const m of this.models) {
      this.refresh(m);
      for (let c = 0; c < m.nCells; c++) {
        const p = m.p[c]!;
        const mu = m.mass[c]!;
        meanHarm += mu * m.harm[c]!;
        if (this.inGrant(m, c)) R += mu * (1 - p) * m.harm[c]!;
        else B += mu * p;
        U += mu * Math.min(p, 1 - p);
        if (p > 1e-12 && p < 1 - 1e-12) dis += mu;
      }
      let alive = 0;
      for (let h = 0; h < m.nh; h++) {
        const w = m.w[h]!;
        if (w > 0) {
          alive++;
          H -= w * Math.log2(w);
        }
      }
      vs += Math.log2(Math.max(1, alive));
    }
    return {
      residualRisk: R,
      burden: B,
      uncertainty: U,
      entropyBits: H,
      log2VersionSpace: this.noisy ? null : vs,
      disagreementMass: dis,
      meanHarm,
      questions: this.observations.filter((o) => o.source === 'elicitation').length,
      conflicts: this.observations.filter((o) => o.conflict).length,
    };
  }

  /** The next question: argmax expected information (×μ·h for the `risk` strategy). Null when nothing is uncertain. */
  nextQuestion(): Question | null {
    let best: Question | null = null;
    const hPos = binEnt(this.etaPos);
    const hNeg = binEnt(this.etaNeg);
    for (const m of this.models) {
      this.refresh(m);
      for (let c = 0; c < m.nCells; c++) {
        if (m.veto[c]) continue; // a vetoed cell is settled: asking cannot change the grant
        const p = m.p[c]!;
        if (p <= 1e-9 || p >= 1 - 1e-9) continue;
        // I(y; a) = H(P(y = 1)) − E[H(y | a)], with P(y = 1) = p(1−η⁻) + (1−p)η⁺ (η⁺ = η⁻ = η is v1's formula).
        const pe = p * (1 - this.etaNeg) + (1 - p) * this.etaPos;
        let score = binEnt(pe) - (this.etaPos === this.etaNeg ? hPos : p * hNeg + (1 - p) * hPos);
        if (this.strategy === 'risk') score *= m.mass[c]! * m.harm[c]!;
        if (score <= 1e-15) continue;
        if (!best || score > best.score + 1e-12) {
          const cell = decodeCell(m.vs, c);
          best = { verb: m.vs.verb, cell, outcome: cellRep(m.vs, cell), p, score };
        }
      }
    }
    return best;
  }

  /**
   * Cells in the grant that were INFERRED (via the hull of other answers) but never directly observed, with
   * their μ(c)·E[h|c], most consequential first. Under realizability they are safe (T1); when the intent is not in
   * Θ they are exactly where the residual risk hides, which is what the audit round asks about.
   */
  unconfirmedGrantCells(): { verb: string; cell: number[]; weight: number }[] {
    const out: { verb: string; cell: number[]; weight: number }[] = [];
    for (const m of this.models) {
      this.refresh(m);
      for (let c = 0; c < m.nCells; c++) {
        if (m.seen[c] || !this.inGrant(m, c)) continue;
        out.push({ verb: m.vs.verb, cell: decodeCell(m.vs, c), weight: m.mass[c]! * m.harm[c]! });
      }
    }
    return out.sort((a, b) => b.weight - a.weight);
  }

  /** The conservative grant G_τ as a real PCA policy (spec §2.5): allow only cells with p_n ≥ τ. */
  synthesize(): { predicates: Predicate[]; caveats: Caveat[] } {
    const predicates: Predicate[] = [];
    const order = ['reversible', 'rate_limited', 'irreversible'];
    let worst = -1;
    for (const m of this.models) {
      this.refresh(m);
      const allowed = new Uint8Array(m.nCells);
      let any = false;
      for (let c = 0; c < m.nCells; c++) if (this.inGrant(m, c)) (allowed[c] = 1), (any = true);
      if (!any) continue;
      worst = Math.max(worst, order.indexOf(m.vs.reversibility));
      predicates.push(...boxesToPredicates(m.vs, allowed));
    }
    const caveats: Caveat[] = worst >= 0 ? [{ type: 'reversibility_max', class: order[worst]! }] : [];
    return { predicates, caveats };
  }

  /** Replay observations onto a fresh learner (used to verify an Intent Map). */
  static replay(omega: Omega, opts: LearnerOptions, observations: readonly Observation[]): IntentLearner {
    const l = new IntentLearner(omega, opts);
    for (const o of observations) l.observe({ verb: o.verb, values: o.values }, o.y, o.source, o.region);
    return l;
  }
}

function normalize(w: Float64Array): void {
  let s = 0;
  for (let i = 0; i < w.length; i++) s += w[i]!;
  if (s > 0) for (let i = 0; i < w.length; i++) w[i] = w[i]! / s;
}

/** v2 §3.12: w ← (1 − β)·w + β·mix, mix ∝ weight(h). β < 1 keeps every hypothesis the base prior supports. */
function mixPrior(m: VerbModel, mix: NonNullable<LearnerOptions['priorMix']>): void {
  if (!(mix.beta >= 0 && mix.beta < 1)) throw new Error('pca-intent: priorMix.beta must be in [0, 1)');
  const pop = new Float64Array(m.nh);
  let z = 0;
  for (let h = 0; h < m.nh; h++) {
    const x = mix.weight(m.vs, (c) => h !== 0 && Number.isInteger(c) && c >= 0 && c < m.nCells && holds(m, h, c));
    if (!(Number.isFinite(x) && x >= 0)) throw new Error('pca-intent: priorMix.weight must be finite and >= 0');
    pop[h] = x;
    z += x;
  }
  if (!(z > 0)) return; // an all-zero mixture carries no information: keep the base prior
  for (let h = 0; h < m.nh; h++) m.w[h] = (1 - mix.beta) * m.w[h]! + (mix.beta * pop[h]!) / z;
}

function flat(m: VerbModel, idx: readonly number[]): number {
  let f = 0;
  for (let d = 0; d < idx.length; d++) f = f * m.nCellsD[d]! + idx[d]!;
  return f;
}

// ---- synthesis: allowed cells -> union of boxes -> predicates --------------------------------------

interface Box {
  /** numeric: [lo, hi] cell range; categorical: value set */
  ranges: ([number, number] | Set<number>)[];
}

function boxCells(vs: VerbSpace, box: Box): number[][] {
  let acc: number[][] = [[]];
  box.ranges.forEach((r) => {
    const vals = Array.isArray(r) ? Array.from({ length: r[1] - r[0] + 1 }, (_, i) => r[0] + i) : [...r].sort((a, b) => a - b);
    acc = acc.flatMap((pre) => vals.map((v) => [...pre, v]));
  });
  void vs;
  return acc;
}

function encode(vs: VerbSpace, idx: readonly number[]): number {
  let f = 0;
  vs.dims.forEach((d, i) => (f = f * (d.kind === 'num' ? numCells(d).length : d.values.length) + idx[i]!));
  return f;
}

function catCondition(d: CatDim, S: Set<number>): Condition | null {
  if (S.size === d.values.length) return null;
  const exacts = d.values.filter((v) => v.kind === 'exact').map((v) => v.value);
  const prefixes = d.values.filter((v) => v.kind === 'prefix').map((v) => v.value);
  const alts: Condition[] = [];
  const allowedExacts = [...S].map((i) => d.values[i]!).filter((v) => v.kind === 'exact').map((v) => v.value);
  if (allowedExacts.length === 1) alts.push({ field: d.path, op: 'eq', value: allowedExacts[0] });
  else if (allowedExacts.length > 1) alts.push({ field: d.path, op: 'in', value: allowedExacts });
  for (const i of [...S].sort((a, b) => a - b)) {
    const v = d.values[i]!;
    if (v.kind === 'exact') continue;
    const parts: Condition[] = [];
    if (v.kind === 'prefix') {
      parts.push({ field: d.path, op: 'prefix', value: v.value });
      const under = exacts.filter((e) => e.startsWith(v.value));
      if (under.length) parts.push({ field: d.path, op: 'nin', value: under });
      for (const q of prefixes) if (q !== v.value && q.startsWith(v.value)) parts.push({ not: { field: d.path, op: 'prefix', value: q } });
    } else {
      if (exacts.length) parts.push({ field: d.path, op: 'nin', value: exacts });
      for (const q of prefixes) parts.push({ not: { field: d.path, op: 'prefix', value: q } });
    }
    if (parts.length === 1) alts.push(parts[0]!);
    else if (parts.length > 1) alts.push({ all_of: parts });
  }
  if (alts.length === 0) return null;
  return alts.length === 1 ? alts[0]! : { any_of: alts };
}

function boxToPredicate(vs: VerbSpace, box: Box): Predicate {
  const where: Condition[] = [];
  vs.dims.forEach((d: Dim, k) => {
    const r = box.ranges[k]!;
    if (d.kind === 'num' && Array.isArray(r)) {
      const cells = numCells(d);
      where.push({ field: d.path, op: 'gte', value: cells[r[0]]!.lo });
      where.push({ field: d.path, op: 'lte', value: cells[r[1]]!.hi });
    } else if (d.kind === 'cat' && r instanceof Set) {
      const c = catCondition(d, r);
      if (c) where.push(c);
    }
  });
  return { verb: vs.verb, resource: '*', ...(where.length ? { where } : {}) };
}

/** Cover the allowed cell set exactly with greedily-grown maximal boxes; one predicate per box. */
export function boxesToPredicates(vs: VerbSpace, allowed: Uint8Array): Predicate[] {
  const covered = new Uint8Array(allowed.length);
  const out: Predicate[] = [];
  const all = (b: Box) => boxCells(vs, b).every((idx) => allowed[encode(vs, idx)] === 1);
  for (let c = 0; c < allowed.length; c++) {
    if (!allowed[c] || covered[c]) continue;
    const idx = decodeCell(vs, c);
    const box: Box = { ranges: vs.dims.map((d, k) => (d.kind === 'num' ? [idx[k]!, idx[k]!] : new Set([idx[k]!]))) };
    vs.dims.forEach((d, k) => {
      if (d.kind === 'num') {
        const n = numCells(d).length;
        const r = box.ranges[k] as [number, number];
        while (r[1] + 1 < n) {
          r[1]++;
          if (!all(box)) {
            r[1]--;
            break;
          }
        }
        while (r[0] > 0) {
          r[0]--;
          if (!all(box)) {
            r[0]++;
            break;
          }
        }
      } else {
        const s = box.ranges[k] as Set<number>;
        for (let v = 0; v < d.values.length; v++) {
          if (s.has(v)) continue;
          s.add(v);
          if (!all(box)) s.delete(v);
        }
      }
    });
    for (const bi of boxCells(vs, box)) covered[encode(vs, bi)] = 1;
    out.push(boxToPredicate(vs, box));
  }
  return out;
}

/** Ask questions until the stop rule of spec §2.5 holds. */
export interface ElicitOptions {
  /** ε_R in harm units. */
  epsRisk: number;
  /** ε_B as a probability mass. */
  epsBurden: number;
  maxQuestions: number;
  /**
   * AUDIT ROUND (spec §4.2c): after the main loop, ask about inferred-but-unconfirmed grant cells, most
   * consequential first, until their total μ·h is ≤ ε_R (or the budget runs out). Costs nothing to safety under
   * realizability (every answer is "yes") and catches hull over-reach when the intent is not in Θ.
   */
  audit?: boolean;
  /**
   * SEED QUESTIONS (spec §4.2a/§4.2b): questions produced outside the learner (compiler disagreement cells,
   * back-translation diff cells), asked first, in order, while their cell is still uncertain (0 < p_n < 1).
   * Each is asked at most once and counts against `maxQuestions`.
   */
  seed?: readonly { verb: string; cell: number[] }[];
}

export interface ElicitResult {
  stop: 'converged' | 'no-disagreement' | 'budget';
  /** Questions asked in total (seed + main loop + audit). */
  questions: number;
  /** Of which in the audit round. */
  auditQuestions: number;
  /** Of which seed questions. */
  seedQuestions: number;
  asked: Question[];
}

function seedQuestion(learner: IntentLearner, s: { verb: string; cell: number[] }): Question | null {
  const vs = learner.omega.verbs.find((v) => v.verb === s.verb);
  if (!vs || s.cell.length !== vs.dims.length) return null;
  const outcome = cellRep(vs, s.cell);
  const p = learner.acceptance(outcome);
  if (p <= 1e-9 || p >= 1 - 1e-9 || learner.isVetoed(outcome)) return null;
  return { verb: s.verb, cell: [...s.cell], outcome, p, score: 0 };
}

export function elicit(learner: IntentLearner, answer: (q: Question) => 0 | 1, o: ElicitOptions): ElicitResult {
  const asked: Question[] = [];
  let seedQuestions = 0;
  for (const s of o.seed ?? []) {
    if (asked.length >= o.maxQuestions) break;
    const m = learner.metrics();
    if (m.residualRisk <= o.epsRisk && m.burden <= o.epsBurden) break;
    const q = seedQuestion(learner, s);
    if (!q) continue;
    learner.observe(q.outcome, answer(q), 'elicitation');
    asked.push(q);
    seedQuestions++;
  }
  let stop: ElicitResult['stop'] | null = null;
  while (stop === null) {
    const m = learner.metrics();
    if (m.residualRisk <= o.epsRisk && m.burden <= o.epsBurden) stop = 'converged';
    else if (asked.length >= o.maxQuestions) stop = 'budget';
    else {
      const q = learner.nextQuestion();
      if (!q) stop = 'no-disagreement';
      else {
        learner.observe(q.outcome, answer(q), 'elicitation');
        asked.push(q);
      }
    }
  }
  const audit = auditRound(learner, answer, o, asked);
  if (audit.exhausted) stop = 'budget';
  return { stop, questions: asked.length, auditQuestions: audit.asked, seedQuestions, asked };
}

/**
 * The audit round on its own (spec §4.2c): the number of audit questions asked, and whether the budget ran out
 * before the unconfirmed weight fell to ε_R. Appends to `asked`.
 */
export function auditRound(learner: IntentLearner, answer: (q: Question) => 0 | 1, o: Pick<ElicitOptions, 'epsRisk' | 'maxQuestions' | 'audit'>, asked: Question[]): { asked: number; exhausted: boolean } {
  let n = 0;
  if (!o.audit) return { asked: 0, exhausted: false };
  for (;;) {
    const pending = learner.unconfirmedGrantCells();
    const mass = pending.reduce((s, x) => s + x.weight, 0);
    if (pending.length === 0 || mass <= o.epsRisk) return { asked: n, exhausted: false };
    if (asked.length >= o.maxQuestions) return { asked: n, exhausted: true };
    const top = pending[0]!;
    const vs = learner.omega.verbs.find((v) => v.verb === top.verb)!;
    const q: Question = { verb: top.verb, cell: top.cell, outcome: cellRep(vs, top.cell), p: learner.acceptance(cellRep(vs, top.cell)), score: top.weight };
    learner.observe(q.outcome, answer(q), 'elicitation');
    asked.push(q);
    n++;
  }
}
