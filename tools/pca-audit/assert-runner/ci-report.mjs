#!/usr/bin/env node
// ci-report.mjs <artifact-dir> <ledger.json>   (assert-mutants.yml report job)
// Reads every slice's results.jsonl and prints, per file, the count of each detection kind, then every mutant that is not
// KILLED_ASSERT. A SURVIVED mutant is fine only when a ledger entry (package pca) lists its exact site. Exit 1 when anything
// is left: KILLED_ERROR / CRASH / NOLOC / NOT_RUN, or a survivor without a ledger entry. TIMEOUT is listed but does not fail
// (an infinite loop cannot fail an assertion; Stryker records it as detected).
import fs from 'node:fs';
import path from 'node:path';

const [dir, ledgerPath] = process.argv.slice(2);
const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : e.name === 'results.jsonl' ? [path.join(d, e.name)] : []));
const rows = walk(dir).flatMap((f) => fs.readFileSync(f, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)));
const ledger = JSON.parse(fs.readFileSync(ledgerPath, 'utf8')).equivalents.filter((e) => (e.package ?? 'pca') === 'pca');
const listed = (r) => ledger.some((e) => e.file === r.file && e.mutator === r.mutator && e.replacement === String(r.repl)
  && (e.original === r.orig || (e.original === '<multiline>' && r.orig.includes('\n'))) && e.line === String(r.lineText).trim());
const byFile = new Map();
for (const r of rows) (byFile.get(r.file) ?? byFile.set(r.file, []).get(r.file)).push(r);
const BAD = new Set(['KILLED_ERROR', 'CRASH', 'NOLOC', 'NOT_RUN']);
let problems = 0;
const detail = [];
console.log(`${rows.length} mutants in ${byFile.size} files`);
for (const [file, rs] of [...byFile].sort()) {
  const c = {};
  for (const r of rs) c[r.result] = (c[r.result] || 0) + 1;
  const unlisted = rs.filter((r) => r.result === 'SURVIVED' && !listed(r));
  const bad = rs.filter((r) => BAD.has(r.result));
  problems += unlisted.length + bad.length;
  console.log(`${unlisted.length + bad.length ? 'FAIL' : 'ok  '} ${file}  ${JSON.stringify(c)}${unlisted.length ? `  unlisted survivors: ${unlisted.length}` : ''}`);
  for (const r of [...bad, ...unlisted, ...rs.filter((r) => r.result === 'TIMEOUT')].sort((a, b) => a.line - b.line)) {
    const why = r.result === 'SURVIVED' ? 'UNLISTED SURVIVOR' : r.result;
    detail.push(`${why} pca/${file}:${r.line}:${r.col} ${r.mutator} ${JSON.stringify(String(r.orig).slice(0, 80))} -> ${JSON.stringify(String(r.repl).slice(0, 80))}${r.error?.length ? `  [${r.error[0]}]` : ''}`);
  }
}
console.log('');
for (const d of detail) console.log(d);
console.log(`\n${problems ? 'FAIL' : 'OK'}: ${problems} mutant(s) not killed by an assertion and not a listed equivalent`);
if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `## Assertion-only mutant check\n\n${problems} problem(s) over ${rows.length} mutants in ${byFile.size} files (full list: the assert-report artifact).\n`);
process.exit(problems ? 1 : 0);
