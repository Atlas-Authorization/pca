// rule-stats.ts - per-rule precision for the suggestion rules, on data a rule edit may look at: the `tune` half of the real corpus (A3's
// split by specification) and the adjudicated pack defs whose key hashes to the tune side. The hold-out halves are never printed.
//   tsx scripts/rule-stats.ts [--trait money_moving]
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { CORE_REGISTRY, DEFAULT_RULES, suggestWithRules } from '../src';
import { importCorpus, parseCorpusJsonl, realSplit } from '../src/import/eval';
import { adjSplit, blankOf, loadPackDefs } from './lib/xcheck-core';

const root = join(__dirname, '..');
const only = process.argv.includes('--trait') ? process.argv[process.argv.indexOf('--trait') + 1] : undefined;
type Row = { fired: string[]; label: (t: string) => boolean | undefined };
const rows: Row[] = [];
const entries = parseCorpusJsonl(readFileSync(join(root, 'corpus', 'real.jsonl'), 'utf8')).filter((e) => realSplit(e.spec) === 'tune');
const { defs } = importCorpus(entries);
for (const e of entries) { const d = defs.get(e.id); if (d) rows.push({ fired: suggestWithRules(d, DEFAULT_RULES, CORE_REGISTRY).fired, label: (t) => e.labels.includes(t) }); }
const adj = new Map<string, Map<string, string>>();
for (const l of readFileSync(join(root, 'corpus', 'adjudication.tsv'), 'utf8').trim().split('\n').slice(1)) {
  const c = l.split('\t'); const k = `${c[3]}:${c[4]}`;
  if (adjSplit(k) !== 'tune' || c[8] === 'u') continue;
  adj.set(k, (adj.get(k) ?? new Map()).set(c[1]!, c[8]!));
}
const packDefs = new Map(loadPackDefs(join(root, 'packs')).map((x) => [`${x.pack}:${x.def.verb}`, x.def]));
for (const [k, tv] of adj) { const d = packDefs.get(k); if (d) rows.push({ fired: suggestWithRules(blankOf(d), DEFAULT_RULES, CORE_REGISTRY).fired, label: (t) => (tv.has(t) ? tv.get(t) === 'y' : undefined) }); }
const out: { id: string; trait: string; fired: number; tp: number; fp: number; note: string }[] = [];
for (const r of DEFAULT_RULES.rules) {
  for (const a of r.adds.filter((x) => x.startsWith('pca.'))) {
    const t = a.replace('pca.', ''); if (only && t !== only) continue;
    let fired = 0, tp = 0, fp = 0;
    for (const row of rows) if (row.fired.includes(r.id)) { const lab = row.label(t); if (lab === undefined) continue; fired++; if (lab) tp++; else fp++; }
    out.push({ id: r.id, trait: t, fired, tp, fp, note: r.note });
  }
}
out.sort((a, b) => b.fp - a.fp);
for (const o of out.filter((x) => x.fired > 0)) console.log(`${o.id}\t${o.trait}\tfired ${o.fired}\ttp ${o.tp}\tfp ${o.fp}\tprec ${(o.tp / o.fired * 100).toFixed(0)}%\t${o.note}`);
