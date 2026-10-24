import { catCellOf, catRep, numCells, type CatDim, type CatValue, type Dim, type VerbSpace } from './omega';

/**
 * REGIONS (spec §2.7, §4.2c "cut refinement"): the part of Ω a cell question was about, written in VALUE terms
 * rather than as cell indices, so an observation keeps its meaning when Ω is refined (a cut inserted, a value
 * named, a dimension added) or lifted onto another organisation's Ω (§4.3, cross-org maps).
 *
 * Semantics of an answer y about a region R (cell-universal, §2.7): y = 1 iff every outcome in R is acceptable.
 * So a hypothesis θ predicts a_θ(R) = 1[R ⊆ θ].
 *
 * Mapping a region onto a (possibly finer) Ω is EXACT when the target refines the Ω the region was written in
 * (every target cell lies inside or outside R). When it does not, the mapping weakens the answer soundly:
 *   - a "yes" claims only the cells that lie wholly inside R (inner approximation);
 *   - a "no"  ("not all of R is acceptable") is widened to every cell that meets R (outer approximation),
 *     because "not all of R" implies "not all of any superset of R".
 */

export interface NumRegionDim {
  kind: 'num';
  /** Inclusive value range. */
  lo: number;
  hi: number;
}

export interface CatRegionDim {
  kind: 'cat';
  /** The value list of the categorical dimension the region was written against (its reference partition). */
  values: CatValue[];
  /** Indices into `values`: a concrete string is in the region iff its cell under `values` is listed. */
  cells: number[];
}

export type RegionDim = NumRegionDim | CatRegionDim;

export interface Region {
  verb: string;
  /** Keyed by dimension path. A path that is absent places no restriction (the whole dimension). */
  dims: Record<string, RegionDim>;
}

/** The value-space region of one cell. */
export function regionOfCell(vs: VerbSpace, idx: readonly number[]): Region {
  const dims: Record<string, RegionDim> = {};
  vs.dims.forEach((d, k) => {
    if (d.kind === 'num') {
      const c = numCells(d)[idx[k]!]!;
      dims[d.path] = { kind: 'num', lo: c.lo, hi: c.hi };
    } else dims[d.path] = { kind: 'cat', values: d.values.map((v) => ({ ...v })), cells: [idx[k]!] };
  });
  return { verb: vs.verb, dims };
}

/** Restrict one dimension of a region to a value range / a set of cells of the given dimension. */
export function restrictRegion(r: Region, d: Dim, part: { lo: number; hi: number } | { cells: number[] }): Region {
  const dims = { ...r.dims };
  if (d.kind === 'num' && 'lo' in part) dims[d.path] = { kind: 'num', lo: part.lo, hi: part.hi };
  else if (d.kind === 'cat' && 'cells' in part) dims[d.path] = { kind: 'cat', values: d.values.map((v) => ({ ...v })), cells: [...part.cells] };
  else throw new Error(`restrictRegion: part does not match the kind of ${d.path}`);
  return { verb: r.verb, dims };
}

function refDim(path: string, rd: CatRegionDim): CatDim {
  return { kind: 'cat', path, values: rd.values };
}

/**
 * The cells of dimension `d` covered by region dimension `rd`. `mode` = 'inner' (cells wholly inside: used for a
 * "yes") or 'outer' (cells meeting it: used for a "no"). Categorical cells are tested by their representative,
 * which is exact whenever `d` refines the region's reference partition.
 */
export function dimCellsIn(d: Dim, rd: RegionDim | undefined, mode: 'inner' | 'outer'): number[] {
  const n = d.kind === 'num' ? numCells(d).length : d.values.length;
  const all = Array.from({ length: n }, (_, i) => i);
  if (!rd) return all;
  if (d.kind === 'num') {
    if (rd.kind !== 'num') throw new Error(`region: ${d.path} is numeric in Ω but categorical in the region`);
    return all.filter((i) => {
      const c = numCells(d)[i]!;
      return mode === 'inner' ? c.lo >= rd.lo && c.hi <= rd.hi : c.hi >= rd.lo && c.lo <= rd.hi;
    });
  }
  if (rd.kind !== 'cat') throw new Error(`region: ${d.path} is categorical in Ω but numeric in the region`);
  const ref = refDim(d.path, rd);
  const inSet = new Set(rd.cells);
  return all.filter((i) => inSet.has(catCellOf(ref, catRep(d, i))));
}

/**
 * Flat cell indices of `vs` covered by the region (row-major, last dimension fastest). Throws if the region
 * restricts a dimension the verb space does not have: dropping that restriction would turn a narrow "yes" into a
 * broad one.
 */
export function regionCells(vs: VerbSpace, r: Region, mode: 'inner' | 'outer'): number[] {
  if (r.verb !== vs.verb) throw new Error(`region: verb ${r.verb} does not match ${vs.verb}`);
  for (const p of Object.keys(r.dims)) {
    if (!vs.dims.some((d) => d.path === p)) throw new Error(`region: restricts ${p}, which Ω has no dimension for`);
  }
  const per = vs.dims.map((d) => dimCellsIn(d, r.dims[d.path], mode));
  if (per.some((x) => x.length === 0)) return [];
  const sizes = vs.dims.map((d) => (d.kind === 'num' ? numCells(d).length : d.values.length));
  let acc: number[] = [0];
  per.forEach((cells, k) => {
    const next: number[] = [];
    for (const f of acc) for (const c of cells) next.push(f * sizes[k]! + c);
    acc = next;
  });
  return acc;
}

/** Is a concrete value inside a region dimension? */
export function valueInRegionDim(path: string, rd: RegionDim, x: number | string): boolean {
  if (rd.kind === 'num') return typeof x === 'number' && x >= rd.lo && x <= rd.hi;
  return typeof x === 'string' && rd.cells.includes(catCellOf(refDim(path, rd), x));
}
