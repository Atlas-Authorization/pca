import {
  isGroupCondition,
  isLeafCondition,
  type Condition,
  type Predicate,
} from '@atlasauth/pca';
import { DEFAULT_CATALOG, type Catalog, type Reversibility } from '@atlasauth/pca/ext/research';
import { normalizePolicy, type PolicyInput } from './policy';
import type { IntentSlots } from './slots';

/**
 * THE OUTCOME SPACE Ω (spec §2.1).
 *
 * Ω = ⊎_v {v} × Π_{d ∈ D_v} X_d. Each verb carries its own ordered list of typed dimensions:
 *   - numeric:     an integer range [lo, hi] partitioned by a finite cut set K_d into ordered CELLS
 *                  `[lo, c1)`, `{c1}`, `(c1, c2)`, …, `{ck}`, `(ck, hi]` (empty cells dropped);
 *   - categorical: a finite list of values, each its own cell, always ending in OTHER (⊥, "any value not
 *                  named"). A value is either an exact literal or a prefix literal (`/shared/*`); a concrete
 *                  string falls in the MOST SPECIFIC matching value (exact > longest prefix > OTHER).
 *
 * Ω is DERIVED from the caveat/predicate vocabulary of the policies under study plus the structured slots of
 * the intent statement: every literal any of them mentions becomes a cut or a value, so every such policy is
 * a union of cells (constant on each cell) and the cell grid is exact for them. The workload μ is a product
 * measure (uniform verb weights × per-dimension distributions); the harm model is separable.
 */

/** The categorical "any other value" sentinel ⊥. */
export const OTHER = '⊥';

export type NumDist = 'uniform' | 'loguniform';

export interface NumDim {
  kind: 'num';
  /** Dotted path rooted at `action.params`, `env`, or `subject` (the predicate DSL's paths). */
  path: string;
  lo: number;
  hi: number;
  /** Sorted, de-duplicated integer cuts strictly inside or on [lo, hi]. */
  cuts: number[];
  dist: NumDist;
}

export interface CatValue {
  /** `exact` literal, `prefix` literal (matches strings starting with it), or the OTHER cell. */
  kind: 'exact' | 'prefix' | 'other';
  value: string;
}

export interface CatDim {
  kind: 'cat';
  /** Dotted path, or `action.resource` for the resource matcher. */
  path: string;
  /** Exact values (sorted), then prefixes (sorted), then exactly one OTHER. */
  values: CatValue[];
}

export type Dim = NumDim | CatDim;

export interface VerbSpace {
  verb: string;
  reversibility: Reversibility;
  /** π_v (verbs' weights sum to 1). Stored as an integer ppm in the Intent Map; a float here. */
  weight: number;
  dims: Dim[];
}

export interface Omega {
  v: 1;
  verbs: VerbSpace[];
  /** Features of the source policies the cell grid cannot represent exactly (regex, cross-field refs, ...). */
  approximate: string[];
}

/** A concrete outcome ω = (verb, one value per dimension path). */
export interface Outcome {
  verb: string;
  values: Record<string, number | string>;
}

/** Built-in numeric domains for common fields (others are derived from their literals). */
export const DEFAULT_DOMAINS: Record<string, { lo: number; hi: number; dist: NumDist }> = {
  'action.params.amount': { lo: 0, hi: 100_000, dist: 'loguniform' },
  'env.hour': { lo: 0, hi: 23, dist: 'uniform' },
  'action.params.count': { lo: 0, hi: 1_000, dist: 'loguniform' },
};

// ---- cells ------------------------------------------------------------------------------------------

export interface NumCell {
  lo: number;
  hi: number;
}

const cellCache = new WeakMap<NumDim, NumCell[]>();

/** The ordered cells of a numeric dimension (inclusive integer ranges; empty cells dropped). */
export function numCells(d: NumDim): NumCell[] {
  const hit = cellCache.get(d);
  if (hit) return hit;
  const out: NumCell[] = [];
  let cur = d.lo;
  for (const c of d.cuts) {
    if (c < d.lo || c > d.hi) continue;
    if (cur <= c - 1) out.push({ lo: cur, hi: c - 1 });
    out.push({ lo: c, hi: c });
    cur = c + 1;
  }
  if (cur <= d.hi) out.push({ lo: cur, hi: d.hi });
  cellCache.set(d, out);
  return out;
}

export function cellCount(d: Dim): number {
  return d.kind === 'num' ? numCells(d).length : d.values.length;
}

/** Number of cells of a verb (the product of per-dimension cell counts). */
export function verbCellCount(vs: VerbSpace): number {
  return vs.dims.reduce((n, d) => n * cellCount(d), 1);
}

/** Decode a flat cell index into per-dimension cell indices (last dimension varies fastest). */
export function decodeCell(vs: VerbSpace, flat: number): number[] {
  const idx = new Array<number>(vs.dims.length);
  for (let i = vs.dims.length - 1; i >= 0; i--) {
    const n = cellCount(vs.dims[i]!);
    idx[i] = flat % n;
    flat = Math.floor(flat / n);
  }
  return idx;
}

export function encodeCell(vs: VerbSpace, idx: readonly number[]): number {
  let flat = 0;
  for (let i = 0; i < vs.dims.length; i++) flat = flat * cellCount(vs.dims[i]!) + idx[i]!;
  return flat;
}

/** Which cell of a categorical dimension a concrete string falls in (exact > longest prefix > OTHER). */
export function catCellOf(d: CatDim, s: string): number {
  let best = -1;
  let bestLen = -1;
  for (let i = 0; i < d.values.length; i++) {
    const v = d.values[i]!;
    if (v.kind === 'exact' && v.value === s) return i;
    if (v.kind === 'prefix' && s.startsWith(v.value) && v.value.length > bestLen) {
      best = i;
      bestLen = v.value.length;
    }
  }
  if (best >= 0) return best;
  return d.values.findIndex((v) => v.kind === 'other');
}

/** Which cell a concrete value falls in, or -1 when it is outside the dimension's domain/type. */
export function cellOfValue(d: Dim, x: number | string | undefined): number {
  if (d.kind === 'num') {
    if (typeof x !== 'number' || !Number.isFinite(x)) return -1;
    const cells = numCells(d);
    for (let i = 0; i < cells.length; i++) if (x >= cells[i]!.lo && x <= cells[i]!.hi) return i;
    return -1;
  }
  if (typeof x !== 'string') return -1;
  return catCellOf(d, x);
}

/** Per-dimension cell indices of an outcome, or null if any value lies outside Ω. */
export function cellOf(vs: VerbSpace, o: Outcome): number[] | null {
  const idx: number[] = [];
  for (const d of vs.dims) {
    const i = cellOfValue(d, o.values[d.path]);
    if (i < 0) return null;
    idx.push(i);
  }
  return idx;
}

/** A concrete string that falls in categorical cell `i` (exact: itself; prefix/OTHER: a fresh extension). */
export function catRep(d: CatDim, i: number): string {
  const v = d.values[i]!;
  if (v.kind === 'exact') return v.value;
  const base = v.kind === 'prefix' ? v.value + 'x' : 'other';
  for (let k = 0; k < 64; k++) {
    const s = base + (k === 0 ? '' : String(k));
    if (catCellOf(d, s) === i) return s;
  }
  return base;
}

/**
 * The QUESTION POINT of a numeric cell: a boundary witness. A cell that has a left neighbour is represented by
 * its lowest value (just above the cut on its left); the first cell by its highest value (just below the
 * lowest cut). So every representative sits immediately across a literal of the grant or the intent.
 */
export function numRep(d: NumDim, i: number): number {
  const c = numCells(d)[i]!;
  return i > 0 ? c.lo : c.hi;
}

export function repValue(d: Dim, i: number): number | string {
  return d.kind === 'num' ? numRep(d, i) : catRep(d, i);
}

/** The representative (question) outcome of a cell. */
export function cellRep(vs: VerbSpace, idx: readonly number[]): Outcome {
  const values: Record<string, number | string> = {};
  vs.dims.forEach((d, i) => {
    values[d.path] = repValue(d, idx[i]!);
  });
  return { verb: vs.verb, values };
}

// ---- workload μ and harm h --------------------------------------------------------------------------

/** Unnormalized per-point weight of μ_d. loguniform over integers ≥ 0 is the discrete 1/(x+1) law. */
function pointWeight(d: NumDim, x: number): number {
  if (d.dist === 'loguniform' && d.lo >= 0) return 1 / (x + 1);
  return 1;
}

export interface HarmModel {
  /** h_v: the verb factor. */
  verb(vs: VerbSpace): number;
  /** g_d: the per-dimension factor at a concrete value. */
  dim(d: Dim, x: number | string): number;
  /**
   * Optional closed form of E_μ[g_d | x ∈ [lo, hi]] for a numeric dimension (the μ-weighted mean of `dim` over an integer
   * interval). Supply it for a harm whose dimension factor is not linear, so a huge cell is exact without enumeration.
   */
  dimMean?(d: NumDim, lo: number, hi: number): number;
}

const linearAmount = (d: Dim): boolean => d.kind === 'num' && /(^|\.)amount$/.test(d.path);

/** Default separable harm: irreversible 10, rate-limited 3, reversible 1; amounts scale as 1 + x/100. */
export const DEFAULT_HARM: HarmModel = {
  verb: (vs) => (vs.reversibility === 'irreversible' ? 10 : vs.reversibility === 'rate_limited' ? 3 : 1),
  dim: (d, x) => (linearAmount(d) && typeof x === 'number' ? 1 + Math.max(0, x) / 100 : 1),
  // linear in x on x >= 0: the mean is 1 + E[max(0, x)] / 100 (closed form below); constant 1 elsewhere
  dimMean: (d, lo, hi) => (linearAmount(d) ? 1 + Math.max(0, intervalMeanX(d, Math.max(lo, 0), hi, lo)) / 100 : 1),
};

/** Upper bound H_max of the harm model over Ω (needed by the Hoeffding bound, spec T4). */
export function harmMax(omega: Omega, harm: HarmModel = DEFAULT_HARM): number {
  let m = 0;
  for (const vs of omega.verbs) {
    let f = harm.verb(vs);
    for (const d of vs.dims) {
      if (d.kind === 'num') f *= Math.max(harm.dim(d, d.lo), harm.dim(d, d.hi));
      else f *= Math.max(...d.values.map((_, i) => harm.dim(d, catRep(d, i))));
    }
    m = Math.max(m, f);
  }
  return m;
}

// ---- per-INTERVAL statistics of a numeric dimension: O(1) per cell, never one entry per integer value ----------------
//
// A cell is an integer interval [a, b]. Its μ-weight is Σ_{x=a}^{b} w(x): (b − a + 1) for the uniform law, and
// H(b + 1) − H(a) for the loguniform law w(x) = 1/(x + 1) (H = harmonic numbers). An interval of at most
// EXACT_SPAN values is summed directly (bit-for-bit the old prefix-sum figures up to rounding); a longer one uses
// H(n) = ln n + γ + 1/(2n) − 1/(12n²) + 1/(120n⁴) − 1/(252n⁶), whose error is below 1e-16 relative for n > EXACT_SPAN.
// So a declared domain of any size (a money amount up to 2^53 − 1) costs O(cells), not O(range).

/** Intervals up to this many values are summed exactly. */
export const EXACT_SPAN = 4096;
/** Pieces of the deterministic quadrature for E[g | cell] when the harm has no closed form and the cell is long. */
export const HARM_QUADRATURE_PIECES = 1024;
const EULER_GAMMA = 0.5772156649015329;

/** H(n) = Σ_{k=1}^{n} 1/k (n ≥ 0 integer). */
function harmonic(n: number): number {
  if (n <= 0) return 0;
  if (n <= EXACT_SPAN) {
    let s = 0;
    for (let k = n; k >= 1; k--) s += 1 / k;
    return s;
  }
  const n2 = n * n;
  return Math.log(n) + EULER_GAMMA + 1 / (2 * n) - 1 / (12 * n2) + 1 / (120 * n2 * n2) - 1 / (252 * n2 * n2 * n2);
}

/** Σ_{x=a}^{b} w(x) for the dimension's law (0 for an empty interval). */
export function intervalWeight(d: NumDim, a: number, b: number): number {
  if (b < a) return 0;
  if (!(d.dist === 'loguniform' && d.lo >= 0)) return b - a + 1;
  if (b - a + 1 <= EXACT_SPAN) {
    let s = 0;
    for (let x = b; x >= a; x--) s += 1 / (x + 1);
    return s;
  }
  return harmonic(b + 1) - harmonic(a);
}

/** Σ_{x=a}^{b} w(x)·x (the first moment), closed form. */
function intervalFirstMoment(d: NumDim, a: number, b: number): number {
  if (b < a) return 0;
  if (!(d.dist === 'loguniform' && d.lo >= 0)) return ((a + b) * (b - a + 1)) / 2;
  // x/(x+1) = 1 − 1/(x+1)
  return b - a + 1 - intervalWeight(d, a, b);
}

/** E_μ[max(0, x) | x ∈ [cellLo, b]] given a = max(cellLo, 0): values below 0 contribute 0 (the default harm). */
function intervalMeanX(d: NumDim, a: number, b: number, cellLo: number): number {
  const whole = intervalWeight(d, cellLo, b);
  return whole > 0 ? intervalFirstMoment(d, a, b) / whole : 0;
}

/** E_μ[g_d | x ∈ [a, b]]: exact for short cells, the harm's closed form when given, else a deterministic quadrature. */
function intervalHarm(d: NumDim, a: number, b: number, harm: HarmModel): number {
  if (harm.dimMean) return harm.dimMean(d, a, b);
  const n = b - a + 1;
  const wTot = intervalWeight(d, a, b);
  if (!(wTot > 0)) return harm.dim(d, a);
  if (n <= EXACT_SPAN) {
    let s = 0;
    for (let x = a; x <= b; x++) s += pointWeight(d, x) * harm.dim(d, x);
    return s / wTot;
  }
  // split into HARM_QUADRATURE_PIECES equal integer pieces: exact mass per piece, harm at the piece's mass midpoint
  let s = 0;
  for (let i = 0; i < HARM_QUADRATURE_PIECES; i++) {
    const pa = a + Math.floor((i * n) / HARM_QUADRATURE_PIECES);
    const pb = a + Math.floor(((i + 1) * n) / HARM_QUADRATURE_PIECES) - 1;
    if (pb < pa) continue;
    const w = intervalWeight(d, pa, pb);
    s += w * harm.dim(d, Math.round((pa + pb) / 2));
  }
  return s / wTot;
}

const totalCache = new WeakMap<NumDim, number>();
function dimTotal(d: NumDim): number {
  let t = totalCache.get(d);
  if (t === undefined) totalCache.set(d, (t = intervalWeight(d, d.lo, d.hi)));
  return t;
}

/** μ_d(cell) and E[g_d | cell] for one dimension cell. Categorical values are uniform. */
export function dimCellStats(d: Dim, i: number, harm: HarmModel = DEFAULT_HARM): { mass: number; harm: number } {
  if (d.kind === 'cat') return { mass: 1 / d.values.length, harm: harm.dim(d, catRep(d, i)) };
  const c = numCells(d)[i]!;
  const wm = intervalWeight(d, c.lo, c.hi);
  return { mass: wm / dimTotal(d), harm: wm > 0 ? intervalHarm(d, c.lo, c.hi, harm) : harm.dim(d, c.lo) };
}

/** The value of `d` at μ-quantile `target` ∈ [0, total) (exact on short cells, continuous inverse on long loguniform ones). */
function quantileValue(d: NumDim, target: number): number {
  let acc = 0;
  const cells = numCells(d);
  for (const c of cells) {
    const w = intervalWeight(d, c.lo, c.hi);
    if (target < acc + w || c === cells[cells.length - 1]) {
      let r = target - acc;
      if (c.hi - c.lo + 1 <= EXACT_SPAN) {
        for (let x = c.lo; x < c.hi; x++) {
          r -= pointWeight(d, x);
          if (r < 0) return x;
        }
        return c.hi;
      }
      if (!(d.dist === 'loguniform' && d.lo >= 0)) return Math.min(c.hi, c.lo + Math.floor(r));
      // Σ_{x=lo}^{X} 1/(x+1) ≈ ln((X+2)/(lo+1)) on a long cell: invert, clamp into the cell
      const x = Math.floor((c.lo + 1) * Math.exp(r) - 1);
      return Math.max(c.lo, Math.min(c.hi, x));
    }
    acc += w;
  }
  return d.hi;
}

/** Exact μ(cell) and E[h | cell] for a whole cell (product measure, separable harm). */
export function cellStats(vs: VerbSpace, idx: readonly number[], harm: HarmModel = DEFAULT_HARM): { mass: number; harm: number } {
  let mass = vs.weight;
  let h = harm.verb(vs);
  vs.dims.forEach((d, k) => {
    const s = dimCellStats(d, idx[k]!, harm);
    mass *= s.mass;
    h *= s.harm;
  });
  return { mass, harm: h };
}

/** Exact h(ω) for a concrete outcome. */
export function harmOf(vs: VerbSpace, o: Outcome, harm: HarmModel = DEFAULT_HARM): number {
  let h = harm.verb(vs);
  for (const d of vs.dims) h *= harm.dim(d, o.values[d.path]!);
  return h;
}

/** A small seeded PRNG (mulberry32) so every Monte Carlo number in the benchmark is reproducible. */
export function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Draw ω ~ μ. */
export function sampleOutcome(omega: Omega, rand: () => number, _harm: HarmModel = DEFAULT_HARM): { vs: VerbSpace; o: Outcome } {
  let u = rand();
  let vs = omega.verbs[omega.verbs.length - 1]!;
  for (const v of omega.verbs) {
    if (u < v.weight) {
      vs = v;
      break;
    }
    u -= v.weight;
  }
  const values: Record<string, number | string> = {};
  for (const d of vs.dims) {
    if (d.kind === 'cat') {
      values[d.path] = catRep(d, Math.min(d.values.length - 1, Math.floor(rand() * d.values.length)));
      continue;
    }
    values[d.path] = quantileValue(d, rand() * dimTotal(d));
  }
  return { vs, o: { verb: vs.verb, values } };
}

// ---- derivation from policies + slots ---------------------------------------------------------------

interface FieldLits {
  nums: Set<number>;
  exacts: Set<string>;
  prefixes: Set<string>;
}

function lits(m: Map<string, FieldLits>, path: string): FieldLits {
  let f = m.get(path);
  if (!f) m.set(path, (f = { nums: new Set(), exacts: new Set(), prefixes: new Set() }));
  return f;
}

function addNum(f: FieldLits, x: number): void {
  if (!Number.isFinite(x)) return;
  f.nums.add(Math.floor(x));
  f.nums.add(Math.ceil(x));
}

function collectCond(c: Condition, m: Map<string, FieldLits>, approx: Set<string>): void {
  if (c === null || typeof c !== 'object') return;
  if (isGroupCondition(c)) {
    if ('all_of' in c && Array.isArray(c.all_of)) c.all_of.forEach((x) => collectCond(x, m, approx));
    else if ('any_of' in c && Array.isArray(c.any_of)) c.any_of.forEach((x) => collectCond(x, m, approx));
    else if ('not' in c) collectCond(c.not, m, approx);
    return;
  }
  if (!isLeafCondition(c)) return;
  if (c.ref !== undefined) approx.add(`cross-field ref on ${c.field}`);
  if (c.op === 'like' || c.op === 'matches' || c.op === 'is_a' || c.op === 'member_of') approx.add(`${c.op} on ${c.field}`);
  if (c.op === 'exists') {
    lits(m, c.field);
    return;
  }
  const f = lits(m, c.field);
  const vals = Array.isArray(c.value) ? c.value : [c.value];
  for (const v of vals) {
    if (typeof v === 'number') addNum(f, v);
    else if (typeof v === 'string') (c.op === 'prefix' ? f.prefixes : f.exacts).add(v);
  }
}

function addResource(r: string | undefined, m: Map<string, FieldLits>, approx: Set<string>): void {
  if (r === undefined || r === '*') return;
  if (r.startsWith('re:')) {
    approx.add('re: resource matcher');
    return;
  }
  const f = lits(m, 'action.resource');
  if (r.endsWith('*')) f.prefixes.add(r.slice(0, -1));
  else f.exacts.add(r);
}

function verbsOf(p: Predicate): string[] | '*' {
  if (typeof p.verb === 'string') return p.verb === '*' ? '*' : [p.verb];
  if (Array.isArray(p.verb)) return p.verb.includes('*') ? '*' : p.verb.filter((x): x is string => typeof x === 'string');
  return [];
}

export interface DeriveOmegaOptions {
  policies: PolicyInput[];
  slots?: IntentSlots;
  catalog?: Catalog;
  /** Overrides for numeric domains, keyed by path. */
  domains?: Record<string, { lo: number; hi: number; dist?: NumDist }>;
  /** Extra verbs to include (e.g. sibling verbs of a connector the principal may not have meant). */
  extraVerbs?: string[];
}

/**
 * Derive Ω from the vocabulary of the policies and the intent slots (spec §2.1). Wildcard verbs expand to the
 * catalog verbs of every connector that appears anywhere (or the whole catalog when none does), so a `*` grant
 * is measured against concrete actions rather than skipped.
 */
export function deriveOmega(opts: DeriveOmegaOptions): Omega {
  const catalog = opts.catalog ?? DEFAULT_CATALOG;
  const approx = new Set<string>();
  const preds = opts.policies.flatMap((p) => normalizePolicy(p).predicates);
  const explicit = new Set<string>(opts.extraVerbs ?? []);
  let wildcard = false;
  for (const p of preds) {
    const vs = verbsOf(p);
    if (vs === '*') wildcard = true;
    else vs.forEach((v) => explicit.add(v));
  }
  for (const v of opts.slots?.verbs ?? []) explicit.add(v);
  if (wildcard) {
    const connectors = new Set([...explicit].map((v) => v.split('.')[0]!));
    const pool = connectors.size > 0 ? catalog.all().filter((s) => connectors.has(s.connector)) : catalog.all();
    pool.forEach((s) => explicit.add(s.verb));
  }
  const verbs = [...explicit].sort();
  const out: VerbSpace[] = [];
  for (const verb of verbs) {
    const m = new Map<string, FieldLits>();
    for (const p of preds) {
      const pv = verbsOf(p);
      if (pv !== '*' && !pv.includes(verb)) continue;
      addResource(typeof p.resource === 'string' ? p.resource : undefined, m, approx);
      if (Array.isArray(p.where)) p.where.forEach((c) => collectCond(c, m, approx));
    }
    for (const sc of opts.slots?.constraints ?? []) {
      if (sc.verb !== undefined && sc.verb !== verb) continue;
      const f = lits(m, sc.path);
      if (sc.max !== undefined) addNum(f, sc.max);
      if (sc.min !== undefined) addNum(f, sc.min);
      sc.oneOf?.forEach((x) => f.exacts.add(x));
      sc.noneOf?.forEach((x) => f.exacts.add(x));
      sc.prefixOneOf?.forEach((x) => f.prefixes.add(x));
    }
    const dims: Dim[] = [];
    for (const path of [...m.keys()].sort()) {
      const f = m.get(path)!;
      if (f.nums.size > 0 || (f.exacts.size === 0 && f.prefixes.size === 0 && path in DEFAULT_DOMAINS)) {
        const cuts = [...f.nums].sort((a, b) => a - b);
        const dom = opts.domains?.[path] ?? DEFAULT_DOMAINS[path];
        const maxCut = cuts.length ? cuts[cuts.length - 1]! : 0;
        const minCut = cuts.length ? cuts[0]! : 0;
        const lo = dom?.lo ?? Math.min(0, minCut - 1);
        const hi = dom?.hi ?? Math.max(10, 2 * maxCut, maxCut + 10);
        const dist: NumDist = dom?.dist ?? (lo >= 0 ? 'loguniform' : 'uniform');
        dims.push({ kind: 'num', path, lo, hi, cuts: cuts.filter((c) => c >= lo && c <= hi), dist });
      } else {
        const values: CatValue[] = [
          ...[...f.exacts].sort().map((value) => ({ kind: 'exact' as const, value })),
          ...[...f.prefixes].sort().map((value) => ({ kind: 'prefix' as const, value })),
          { kind: 'other', value: OTHER },
        ];
        dims.push({ kind: 'cat', path, values });
      }
    }
    const spec = catalog.get(verb);
    out.push({ verb, reversibility: spec?.reversibility ?? 'irreversible', weight: 0, dims });
  }
  out.forEach((v) => (v.weight = 1 / out.length));
  return { v: 1, verbs: out, approximate: [...approx].sort() };
}

export function verbSpace(omega: Omega, verb: string): VerbSpace | undefined {
  return omega.verbs.find((v) => v.verb === verb);
}
