import { commitMap, hashCanonical, type CommittedMap, type MapDim, type MapMetricsLeaf } from '@atlasauth/pca';
import type { IntentMap } from './map';

/**
 * The wallet side of V15 (Intent Layer v2 §3.10, conformance README rule 19): the committed (Merkle, per-leaf salted) form of
 * an Intent Map. The verifier side (leaf / node / commit hashing, the cell of ω, the Z0 `map` check) is normative in
 * `@atlasauth/pca` `intent-map-commit.ts`; this module only maps an {@link IntentMap} onto that leaf layout:
 *   - one header per verb of Ω: `{verb, first, cells, dims}` with the dimensions as `{kind: "num", path, lo, hi, cuts}` or
 *     `{kind: "cat", path, values}` (the sampling distribution `dist` is not part of the cell geometry and is not committed);
 *   - the map's cells in flat order (every cell of the grid must be present);
 *   - the metrics (`log2_vs_mbits` omitted when the map has none);
 *   - the learner leaf `{learner_digest: hashCanonical(map.learner)}`.
 * `secret` (32 random bytes, kept by the wallet per session) derives every leaf salt, so the same map in two sessions has
 * unrelated commitments. Use `map_commit` as the session's `layers.task.map_digest` and the PCActn's `intent.map_digest`
 * with `intent_session.map_form: "commit"` (goal `pca-intent:v2c:<σ>:<map_commit>`), and `disclose(action, params)` for the
 * verifier context `intent_v2.map.disclosure`.
 */
export function commitIntentMap(m: IntentMap, secret: Uint8Array): CommittedMap {
  const headers = m.omega.verbs.map((v) => ({
    verb: v.verb,
    dims: v.dims.map((d): MapDim =>
      d.kind === 'num'
        ? { kind: 'num', path: d.path, lo: d.lo!, hi: d.hi!, cuts: (d.cuts ?? []).filter((c) => c >= d.lo! && c <= d.hi!) }
        : { kind: 'cat', path: d.path, values: (d.values ?? []).map((x) => ({ kind: x.kind, value: x.value })) },
    ),
  }));
  const cells: Record<string, { cell: number[]; p_ppm: number; in_grant: boolean }[]> = Object.create(null);
  for (const v of m.omega.verbs) {
    const counts = v.dims.map((d) => (d.kind === 'num' ? numCellCount(d.lo!, d.hi!, d.cuts ?? []) : (d.values ?? []).length));
    const total = counts.reduce((a, b) => a * b, 1);
    const slots: ({ cell: number[]; p_ppm: number; in_grant: boolean } | undefined)[] = new Array(total);
    for (const c of m.cells) {
      if (c.verb !== v.verb) continue;
      if (c.cell.length !== counts.length) throw new Error(`commitIntentMap: cell of ${v.verb} has the wrong arity`);
      let flat = 0;
      c.cell.forEach((i, j) => {
        if (!(Number.isSafeInteger(i) && i >= 0 && i < counts[j]!)) throw new Error(`commitIntentMap: cell index out of range for ${v.verb}`);
        flat = flat * counts[j]! + i;
      });
      slots[flat] = { cell: [...c.cell], p_ppm: c.p_ppm, in_grant: c.in_grant };
    }
    if (slots.some((s) => s === undefined) || slots.length !== total) throw new Error(`commitIntentMap: the map does not list every cell of ${v.verb}`);
    cells[v.verb] = slots as { cell: number[]; p_ppm: number; in_grant: boolean }[];
  }
  const { log2_vs_mbits, ...rest } = m.metrics;
  const metrics: MapMetricsLeaf = { ...rest, ...(log2_vs_mbits !== null ? { log2_vs_mbits } : {}) };
  return commitMap({ headers, cells, metrics, learner_digest: hashCanonical(m.learner) }, secret);
}

function numCellCount(lo: number, hi: number, cuts: number[]): number {
  let n = 0;
  let cur = lo;
  for (const c of cuts) {
    if (c < lo || c > hi) continue;
    if (cur <= c - 1) n++;
    n++;
    cur = c + 1;
  }
  return cur <= hi ? n + 1 : n;
}
