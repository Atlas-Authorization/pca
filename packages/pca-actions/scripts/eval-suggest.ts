// eval-suggest.ts - `pca actions eval-suggest`: measure the suggestion rules on the labeled corpus, print the table, and fail
// when the corpus is too small or recall for a core trait drops below its recorded floor.
//   tsx scripts/eval-suggest.ts [--out DIR] [--update-floors]
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { evalSuggest, floorFailures, parseCorpusJsonl, parseHandTsv, renderEvalMarkdown, type Floors } from '../src/import/eval';

const root = join(__dirname, '..');
const corpus = [
  ...parseHandTsv(readFileSync(join(root, 'corpus', 'hand.tsv'), 'utf8')),
  ...parseCorpusJsonl(readFileSync(join(root, 'corpus', 'real.jsonl'), 'utf8')),
  ...parseCorpusJsonl(readFileSync(join(root, 'corpus', 'synthetic.jsonl'), 'utf8')),
];
const report = evalSuggest(corpus);
const md = renderEvalMarkdown(report);
console.log(md);
const argv = process.argv.slice(2);
const outIdx = argv.indexOf('--out');
if (outIdx >= 0) {
  const dir = resolve(argv[outIdx + 1] ?? '.');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'eval-suggest.md'), md);
  writeFileSync(join(dir, 'eval-suggest.json'), JSON.stringify(report, null, 2));
}
const floorsPath = join(root, 'corpus', 'recall-floors.json');
if (argv.includes('--update-floors')) {
  // Floors come from the REAL-spec numbers only, 3 points under the measured lower bound (rounded down) so noise in a rule edit does not
  // trip CI but a real loss does. A trait is floored only with at least 10 hold-out positives (the count is recorded beside the floor; below 30 the bound is wide); the generated set gets regression floors.
  const traits = ['money_moving', 'destructive', 'external_communication', 'privilege_change', 'code_execution', 'public_exposure', 'financial_data_read', 'scheduled'];
  const real = report.by_source['real/holdout']!;
  const syn = report.by_source['syn']!;
  const f: Floors = { v: 2, alpha: report.alpha, real: { min_entries: 2000, min_positives: {}, recall_lower: {} }, regression: { recall_lower: {} } };
  const down = (x: number | null): number => Math.max(0, Math.floor(((x ?? 0) - 0.03) * 100) / 100);
  for (const t of traits) {
    const r = real.flagged.find((s) => s.trait === t);
    if (r && r.positives >= 10) { f.real.recall_lower[t] = down(r.recall_lower); f.real.min_positives[t] = Math.min(r.positives, 150); }
    const g = syn.flagged.find((s) => s.trait === t);
    if (g && g.positives >= 30) f.regression.recall_lower[t] = down(g.recall_lower);
  }
  writeFileSync(floorsPath, JSON.stringify(f, null, 2) + '\n');
  console.log('floors updated');
} else {
  const floors = JSON.parse(readFileSync(floorsPath, 'utf8')) as Floors;
  const bad = floorFailures(report, floors);
  if (bad.length > 0) { for (const b of bad) console.error('FAIL ' + b); process.exit(1); }
  console.log('recall floors hold');
}
