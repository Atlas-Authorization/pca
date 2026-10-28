// pack-trait-diff.ts - how many pack defs changed their effective trait set between two pack trees, and how many became stricter.
//   tsx scripts/pack-trait-diff.ts <old-packs-dir> <new-packs-dir>
// "changed": the closure of declared + implied traits differs (or the review state does). "stricter": the new set is a superset of the old,
// or the def became `unreviewed` (the maximal floor). A def that LOST a trait and gained none is "looser" and is listed separately.
import { resolve } from 'node:path';
import { CORE_REGISTRY, effective } from '../src';
import { loadPackDefs, packTraits } from './lib/xcheck-core';

const [a, b] = [resolve(process.argv[2] ?? ''), resolve(process.argv[3] ?? '')];
const old = new Map(loadPackDefs(a).map((x) => [`${x.pack}:${x.def.verb}`, x.def]));
let n = 0, changed = 0, stricter = 0, looser = 0, mixed = 0, added = 0, removed = 0, becameUnreviewed = 0;
const gained: Record<string, number> = {}, lost: Record<string, number> = {};
const byPack: Record<string, { changed: number; stricter: number }> = {};
const seen = new Set<string>();
for (const { pack, def } of loadPackDefs(b)) {
  const k = `${pack}:${def.verb}`; seen.add(k); n++;
  const o = old.get(k);
  if (!o) { added++; continue; }
  const [ot, nt] = [packTraits(o), packTraits(def)];
  const [ou, nu] = [o.review?.state === 'unreviewed', def.review?.state === 'unreviewed'];
  const g = [...nt].filter((t) => !ot.has(t)), l = [...ot].filter((t) => !nt.has(t));
  if (!g.length && !l.length && ou === nu) continue;
  changed++;
  const bp = (byPack[pack] ??= { changed: 0, stricter: 0 }); bp.changed++;
  for (const t of g) gained[t] = (gained[t] ?? 0) + 1;
  for (const t of l) lost[t] = (lost[t] ?? 0) + 1;
  if (nu && !ou) becameUnreviewed++;
  const sup = l.length === 0 && (g.length > 0 || (nu && !ou));
  if (sup) { stricter++; bp.stricter++; } else if (g.length === 0 && !(nu && !ou)) looser++; else mixed++;
  void effective; void CORE_REGISTRY;
}
for (const k of old.keys()) if (!seen.has(k)) removed++;
console.log(JSON.stringify({ defs_new: n, changed, stricter, looser, mixed, became_unreviewed: becameUnreviewed, added, removed, gained, lost, byPack }, null, 1));
