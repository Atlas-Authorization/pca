import { cellCount, cellOf, numCells, type Dim, type Omega, type VerbSpace } from '@atlasauth/pca-intent';
import type { ActionValues, CellCoords } from './wire';

/**
 * CELL COORDINATES <-> THE WALLET'S OWN Ω (§4 M5). A site names a question's cell by coordinates over Ω̃, never by
 * text: an inclusive cell-index range per numeric dimension, a value set per categorical one. The wallet resolves them
 * against ITS OWN copy of Ω and refuses anything it cannot resolve exactly (fail closed): an unknown dimension, an
 * index out of range, an unknown value, or a dimension of the verb the coordinates leave out.
 *
 * Coordinate keys and labels follow the core (`@atlasauth/pca-intent` `cellCoords`): a dimension is keyed by its full
 * path and a categorical cell by its raw value (`⊥` for "any other"). On input the wallet also accepts the spec's short
 * aliases for lifted dimensions (§4 M5): `env.acc.<id>.post` → `<id>`, `env.world.<name>` → `<name>`,
 * `env.prov.<path>` → `prov:<path>`, `env.mon.<id>.state` → `mon:<id>`. Naming a dimension twice, or a value that two
 * cells share (an exact value and a prefix with the same text), is refused.
 */

export function coordKeyOf(path: string): string {
  let m = /^env\.acc\.([A-Za-z0-9_.-]+)\.post$/.exec(path);
  if (m) return m[1]!;
  m = /^env\.mon\.([A-Za-z0-9_.-]+)\.state$/.exec(path);
  if (m) return `mon:${m[1]!}`;
  m = /^env\.prov\.(.+)$/.exec(path);
  if (m) return `prov:${m[1]!}`;
  m = /^env\.world\.([A-Za-z0-9_.-]+)$/.exec(path);
  if (m) return m[1]!;
  return path;
}

/** The label of categorical value i of a dimension, as used in coordinates: its raw value (`⊥` for "any other"). */
export function catLabel(d: Extract<Dim, { kind: 'cat' }>, i: number): string {
  return d.values[i]!.value;
}

/** Per-dimension allowed cell indices (sorted, de-duplicated). */
export type CellBox = number[][];

export type BoxResult = { ok: true; vs: VerbSpace; box: CellBox } | { ok: false; reason: string };

/** Resolve coordinates to a box of cells of the verb's space. Every dimension must be named exactly once. */
export function resolveCoords(omega: Omega, verb: string, coords: CellCoords): BoxResult {
  const vs = omega.verbs.find((v) => v.verb === verb);
  if (!vs) return { ok: false, reason: `verb ${verb} is not in the wallet's outcome space` };
  const byKey = new Map<string, number>();
  vs.dims.forEach((d, k) => {
    byKey.set(d.path, k);
    byKey.set(coordKeyOf(d.path), k);
  });
  const named = new Set<number>();
  for (const key of Object.keys(coords)) {
    const k = byKey.get(key);
    if (k === undefined) return { ok: false, reason: `unknown dimension ${key}` };
    if (named.has(k)) return { ok: false, reason: `dimension ${vs.dims[k]!.path} is named twice` };
    named.add(k);
  }
  const box: CellBox = [];
  for (let k = 0; k < vs.dims.length; k++) {
    const d = vs.dims[k]!;
    const c = coords[d.path] ?? coords[coordKeyOf(d.path)];
    if (c === undefined) return { ok: false, reason: `coordinates leave out dimension ${d.path}` };
    if (d.kind === 'num') {
      if (!(c.length === 2 && typeof c[0] === 'number' && typeof c[1] === 'number')) return { ok: false, reason: `dimension ${d.path} is numeric: expected an index range` };
      const [lo, hi] = c as [number, number];
      if (!(Number.isInteger(lo) && Number.isInteger(hi) && lo >= 0 && lo <= hi && hi < numCells(d).length)) return { ok: false, reason: `index range of ${d.path} is out of range` };
      const ids: number[] = [];
      for (let i = lo; i <= hi; i++) ids.push(i);
      box.push(ids);
    } else {
      if (!c.every((x) => typeof x === 'string')) return { ok: false, reason: `dimension ${d.path} is categorical: expected a value set` };
      const ids: number[] = [];
      for (const label of c as string[]) {
        const hits = d.values.flatMap((v, j) => (v.value === label ? [j] : []));
        if (hits.length === 0) return { ok: false, reason: `unknown value ${JSON.stringify(label)} for ${d.path}` };
        if (hits.length > 1) return { ok: false, reason: `value ${JSON.stringify(label)} names two cells of ${d.path}` };
        ids.push(hits[0]!);
      }
      box.push([...new Set(ids)].sort((a, b) => a - b));
    }
  }
  return { ok: true, vs, box };
}

/** The coordinates of a box (the inverse of {@link resolveCoords}; numeric sides must be contiguous). */
export function coordsOfBox(vs: VerbSpace, box: CellBox): CellCoords {
  const out: CellCoords = {};
  vs.dims.forEach((d, k) => {
    const ids = box[k]!;
    if (d.kind === 'num') {
      const lo = Math.min(...ids);
      const hi = Math.max(...ids);
      if (hi - lo + 1 !== ids.length) throw new Error(`coordsOfBox: numeric side of ${d.path} is not contiguous`);
      out[d.path] = [lo, hi];
    } else out[d.path] = ids.map((i) => catLabel(d, i));
  });
  return out;
}

/** Coordinates of one cell. */
export function coordsOfCell(vs: VerbSpace, idx: readonly number[]): CellCoords {
  return coordsOfBox(vs, idx.map((i) => [i]));
}

export function cellInBox(box: CellBox, idx: readonly number[]): boolean {
  return box.length === idx.length && box.every((ids, k) => ids.includes(idx[k]!));
}

/** Every cell (per-dimension indices) of a box, in lexicographic order. */
export function boxCells(box: CellBox): number[][] {
  let out: number[][] = [[]];
  for (const ids of box) out = out.flatMap((pre) => ids.map((i) => [...pre, i]));
  return out;
}

export function boxSize(box: CellBox): number {
  return box.reduce((n, ids) => n * ids.length, 1);
}

/** The cell of a concrete action in the wallet's Ω (null when the action falls outside it: fail closed). */
export function cellOfAction(omega: Omega, a: ActionValues): { vs: VerbSpace; idx: number[] } | null {
  const vs = omega.verbs.find((v) => v.verb === a.verb);
  if (!vs) return null;
  for (const d of vs.dims) if (!(d.path in a.values)) return null;
  const idx = cellOf(vs, { verb: a.verb, values: a.values });
  return idx ? { vs, idx } : null;
}

/** Flat lexicographic index of a cell (the tie-breaker "cell index" of §3.4). */
export function flatIndex(vs: VerbSpace, idx: readonly number[]): number {
  let f = 0;
  vs.dims.forEach((d, k) => (f = f * cellCount(d) + idx[k]!));
  return f;
}
