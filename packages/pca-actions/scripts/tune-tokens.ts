// tune-tokens.ts - token-level view of the name rules on the TUNE data only (tune half of the real corpus + adjudicated pack defs on the tune
// side), to decide which tokens to prune from the shipped rules. Each token of each `name_tokens` rule is run as its own rule; a token is
// reported with how often it fired, how often it was right, and how often it was the ONLY rule saying so (its unique contribution to recall).
//   tsx scripts/tune-tokens.ts [--min 12] [--prec 0.2]
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { CORE_REGISTRY, DEFAULT_RULES, suggestWithRules } from '../src';
import type { SuggestRule, SuggestRules } from '../src/import/suggest';
import { importCorpus, parseCorpusJsonl, realSplit } from '../src/import/eval';
import { adjSplit, blankOf, loadPackDefs } from './lib/xcheck-core';

const a = process.argv.slice(2);
const flag = (n: string, d: number): number => { const i = a.indexOf(`--${n}`); return i >= 0 ? Number(a[i + 1]) : d; };
const MIN = flag('min', 12), PREC = flag('prec', 0.2);
const CORE = ['money_moving', 'destructive', 'external_communication', 'privilege_change', 'code_execution', 'public_exposure', 'financial_data_read', 'scheduled', 'data_export'];
const singles: (SuggestRule & { src: string; tok?: string })[] = [];
for (const r of DEFAULT_RULES.rules) {
  const toks = r.match.name_tokens;
  if (toks && toks.length > 1) toks.forEach((t, i) => singles.push({ ...r, id: `${r.id}.${i}`, match: { ...r.match, name_tokens: [t] }, src: r.id, tok: t }));
  else singles.push({ ...r, src: r.id });
}
const rules = { ...DEFAULT_RULES, rules: singles } as SuggestRules;
const root = join(__dirname, '..');
type Row = { fired: Set<string>; label: (t: string) => boolean | undefined };
const rows: Row[] = [];
const entries = parseCorpusJsonl(readFileSync(join(root, 'corpus', 'real.jsonl'), 'utf8')).filter((e) => realSplit(e.spec) === 'tune');
const { defs } = importCorpus(entries);
for (const e of entries) { const d = defs.get(e.id); if (d) rows.push({ fired: new Set(suggestWithRules(d, rules, CORE_REGISTRY).fired), label: (t) => e.labels.includes(t) }); }
const adj = new Map<string, Map<string, string>>();
for (const l of readFileSync(join(root, 'corpus', 'adjudication.tsv'), 'utf8').trim().split('\n').slice(1)) {
  const c = l.split('\t'); const k = `${c[3]}:${c[4]}`;
  if (adjSplit(k) !== 'tune' || c[8] === 'u') continue;
  adj.set(k, (adj.get(k) ?? new Map()).set(c[1]!, c[8]!));
}
const packDefs = new Map(loadPackDefs(join(root, 'packs')).map((x) => [`${x.pack}:${x.def.verb}`, x.def]));
for (const [k, tv] of adj) { const d = packDefs.get(k); if (d) rows.push({ fired: new Set(suggestWithRules(blankOf(d), rules, CORE_REGISTRY).fired), label: (t) => (tv.has(t) ? tv.get(t) === 'y' : undefined) }); }
console.error(`${rows.length} tune rows`);
for (const t of CORE) {
  const adders = singles.filter((r) => r.adds.includes(`pca.${t}`));
  const lines: string[] = [];
  for (const r of adders) {
    let fired = 0, tp = 0, uniq = 0;
    for (const row of rows) {
      if (!row.fired.has(r.id)) continue;
      const lab = row.label(t); if (lab === undefined) continue;
      fired++; if (lab) { tp++; if (adders.filter((o) => o.id !== r.id && row.fired.has(o.id)).length === 0) uniq++; }
    }
    if (fired >= MIN && tp / fired < PREC) lines.push(`${r.src}\t${t}\t${r.tok ?? '(whole rule)'}\tfired ${fired}\ttp ${tp}\tprec ${(100 * tp / fired).toFixed(0)}%\tunique ${uniq}`);
  }
  console.log(lines.join('\n'));
}
