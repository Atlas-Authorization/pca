// adj-rules.ts - the suggestion rules scored against the adjudicated pack defs, split into the tune side and the hold-out side by a hash of
// pack:verb (the hold-out side is never read when editing rules). The sample is the DISAGREEMENT sets, so these are comparison figures between
// rule versions, not population estimates: TP = flagged and adjudicated yes, FP = flagged and no, FN = not flagged and yes.
//   tsx scripts/adj-rules.ts [--old]      (--old scores src/import/rules_old.ts, a copy of the previous rule set kept only while comparing)
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { CORE_REGISTRY, applySuggestion, closure, suggestWithRules, hintTraits } from '../src';
import { adjSplit, blankOf, loadPackDefs } from './lib/xcheck-core';

const old = process.argv.includes('--old');
const { DEFAULT_RULES } = (old ? require('../src/import/rules_old') : require('../src/import/rules')) as typeof import('../src/import/rules');
const root = join(__dirname, '..');
const m = new Map(loadPackDefs(join(root, 'packs')).map((x) => [`${x.pack}:${x.def.verb}`, x.def]));
const acc: Record<string, { tp: number; fp: number; fn: number }> = {};
const cache = new Map<string, Set<string>>();
for (const l of readFileSync(join(root, 'corpus', 'adjudication.tsv'), 'utf8').trim().split('\n').slice(1)) {
  const c = l.split('\t'); const k = `${c[3]}:${c[4]}`; if (c[8] === 'u') continue;
  let got = cache.get(k);
  if (!got) { const d = blankOf(m.get(k)!); got = new Set(closure(CORE_REGISTRY, hintTraits(applySuggestion(d, suggestWithRules(d, DEFAULT_RULES, CORE_REGISTRY), {})))); cache.set(k, got); }
  const flagged = got.has(`pca.${c[1]}`), y = c[8] === 'y';
  const a = (acc[`${adjSplit(k)}\t${c[1]}`] ??= { tp: 0, fp: 0, fn: 0 });
  if (flagged && y) a.tp++; else if (flagged) a.fp++; else if (y) a.fn++;
}
const pct = (x: number, y: number): string => (y === 0 ? '-' : `${((100 * x) / y).toFixed(0)}%`);
for (const side of ['tune', 'holdout']) {
  console.log(`## ${side}`);
  for (const [k, a] of Object.entries(acc).filter(([k]) => k.startsWith(side + '\t'))) console.log(`${k.split('\t')[1]}\ttp ${a.tp}\tfp ${a.fp}\tfn ${a.fn}\tprecision ${pct(a.tp, a.tp + a.fp)}\trecall ${pct(a.tp, a.tp + a.fn)}`);
}
