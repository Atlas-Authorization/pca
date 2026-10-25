import { DEFAULT_CATALOG, type Catalog } from '@atlasauth/pca';
import { cellRep, cellStats, decodeCell, encodeCell, numCells, verbCellCount, type Omega, type Outcome, type VerbSpace } from './omega';
import { admitter, type PolicyInput } from './policy';
import { renderQuestion } from './render';

/**
 * SPECIFICATION BY EXAMPLE for a FIXED grant (spec §3.2c): the non-adaptive, one-round form of elicitation.
 *
 * Over Ω the grant is a union of cells. A BOUNDARY FACET is a place where admission changes when exactly one
 * dimension moves to an adjacent cell (numeric: neighbouring cells across a cut; categorical: one value to
 * another). Every facet is a literal of the grant doing work, so every facet is a decision the principal
 * should confirm. For each facet we emit ONE pair of witnesses: the action just inside and the action just
 * outside, both differing from the grant's most typical allowed action in that one dimension only (so the
 * question isolates the literal). We also emit:
 *   - a VERB witness per verb: its most typical allowed action ("should it be able to do this at all?") —
 *     catches injected / scope-creep verbs; or, for a verb in Ω the grant denies, its most typical action —
 *     catches over-restriction;
 *   - an UNCONSTRAINED witness per dimension the grant ignores entirely but the intent mentions: the typical
 *     allowed action pushed to the dimension's most extreme cell (largest numeric cell or OTHER) — catches
 *     the missing-constraint class that pure boundary probing cannot see (no literal, no boundary).
 * The question count is linear in the number of facets, not in |Ω|.
 */

export type WitnessKind = 'boundary' | 'verb' | 'unconstrained';

export interface Witness {
  kind: WitnessKind;
  side: 'inside' | 'outside';
  verb: string;
  cell: number[];
  outcome: Outcome;
  grantAllows: boolean;
  facet: string;
  question: string;
}

export function boundaryWitnesses(grant: PolicyInput, omega: Omega, catalog: Catalog = DEFAULT_CATALOG): Witness[] {
  const g = admitter(grant);
  const out: Witness[] = [];
  const seen = new Set<string>();
  const push = (vs: VerbSpace, kind: WitnessKind, idx: number[], allows: boolean, facet: string) => {
    const key = `${vs.verb}|${idx.join(',')}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ kind, side: allows ? 'inside' : 'outside', verb: vs.verb, cell: idx, outcome: cellRep(vs, idx), grantAllows: allows, facet, question: renderQuestion(vs, idx, catalog) });
  };
  for (const vs of omega.verbs) {
    const n = verbCellCount(vs);
    const acc = new Uint8Array(n);
    const mass = new Float64Array(n);
    let typical = -1;
    let typicalOut = -1;
    for (let c = 0; c < n; c++) {
      const idx = decodeCell(vs, c);
      acc[c] = g.admits(vs, cellRep(vs, idx)) ? 1 : 0;
      mass[c] = cellStats(vs, idx).mass;
      if (acc[c] && (typical < 0 || mass[c]! > mass[typical]!)) typical = c;
      if (typicalOut < 0 || mass[c]! > mass[typicalOut]!) typicalOut = c;
    }
    if (typical < 0) {
      push(vs, 'verb', decodeCell(vs, typicalOut), false, `${vs.verb}|verb`);
      continue;
    }
    const base = decodeCell(vs, typical);
    push(vs, 'verb', base, true, `${vs.verb}|verb`);
    // Facets: best (inside, outside) pair per facet, preferring pairs that share the typical action's other coordinates.
    const best = new Map<string, { ins: number[]; outs: number[]; score: number }>();
    for (let c = 0; c < n; c++) {
      if (!acc[c]) continue;
      const idx = decodeCell(vs, c);
      vs.dims.forEach((d, k) => {
        const nk = d.kind === 'num' ? numCells(d).length : d.values.length;
        const neigh = d.kind === 'num' ? [idx[k]! - 1, idx[k]! + 1].filter((x) => x >= 0 && x < nk) : Array.from({ length: nk }, (_, x) => x).filter((x) => x !== idx[k]);
        for (const x of neigh) {
          const j = idx.slice();
          j[k] = x;
          const cj = encodeCell(vs, j);
          if (acc[cj]) continue;
          const facet = d.kind === 'num' ? `${vs.verb}|${d.path}|${Math.min(x, idx[k]!)}~${Math.max(x, idx[k]!)}` : `${vs.verb}|${d.path}|${x}`;
          const shared = idx.filter((v, t) => t !== k && v === base[t]).length;
          const score = shared * 10 + mass[c]!;
          const prev = best.get(facet);
          if (!prev || score > prev.score) best.set(facet, { ins: idx, outs: j, score });
        }
      });
    }
    for (const [facet, b] of [...best.entries()].sort(([a], [z]) => (a < z ? -1 : a > z ? 1 : 0))) {
      push(vs, 'boundary', b.ins, true, facet);
      push(vs, 'boundary', b.outs, false, facet);
    }
    // Unconstrained dimensions: acceptance never depends on d.
    vs.dims.forEach((d, k) => {
      const nk = d.kind === 'num' ? numCells(d).length : d.values.length;
      if (nk < 2) return;
      let depends = false;
      for (let c = 0; c < n && !depends; c++) {
        const idx = decodeCell(vs, c);
        for (let x = 0; x < nk && !depends; x++) {
          const j = idx.slice();
          j[k] = x;
          if (acc[encodeCell(vs, j)] !== acc[c]) depends = true;
        }
      }
      if (depends) return;
      const j = base.slice();
      j[k] = d.kind === 'num' ? nk - 1 : d.values.findIndex((v) => v.kind === 'other');
      push(vs, 'unconstrained', j, true, `${vs.verb}|${d.path}|unconstrained`);
    });
  }
  return out;
}

export interface WitnessCheck {
  questions: number;
  mismatches: Witness[];
}

/** Ask an oracle (the principal) about each witness; a mismatch is a place where grant and intent disagree. */
export function checkWitnesses(witnesses: readonly Witness[], oracle: (w: Witness) => boolean): WitnessCheck {
  const mismatches = witnesses.filter((w) => oracle(w) !== w.grantAllows);
  return { questions: witnesses.length, mismatches };
}
