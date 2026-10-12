#!/usr/bin/env node
// Equivalent-mutant ledger checker (Stryker / TypeScript).
//   node check-equivalents.mjs                      static check (cheap mode): every entry is well formed and names exactly one
//                                                   site of packages/<package>/<file> (ambiguous text without occurrence fails)
//   node check-equivalents.mjs report.json ...      full check: every surviving / no-coverage mutant in the reports matches exactly
//                                                   one entry, and every entry for a reported file matches exactly one survivor
//                                                   site (a listed site that is now killed means the entry is stale: delete it).
//   --package=<pkg> (default pca)  --root=<dir> --ledger=<file>   (root / ledger overrides are used by the self-test)
//
// A SITE is (package, file, mutator, original text, replacement, trimmed line, occurrence): occurrence = which copy of that
// line text in the file (1-based). It is computed from the source embedded in the report, so line-number churn elsewhere in
// the file does not matter; `lineno` is stored as a hint only. `multiplicity` (>= 2) covers the same mutant reported more
// than once on one line (the same original fragment appearing twice). See ../site-key.mjs.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkEntrySite, checkSites, occurrenceAt } from '../site-key.mjs';
const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const opt = (n) => args.find((a) => a.startsWith(`--${n}=`))?.slice(n.length + 3);
const root = path.resolve(opt('root') ?? path.resolve(here, '../../..'));
const pcaDir = (pkg) => path.join(root, 'packages', pkg);
const ledgerPath = path.resolve(opt('ledger') ?? path.join(here, '..', 'mutation-equivalents.json'));
const ledger = JSON.parse(fs.readFileSync(ledgerPath, 'utf8'));
const errors = [];
const siteKey = (pkg, file, mutator, original, replacement, line, occ) => [pkg, file, mutator, original, replacement, line, occ].join('\u0000');
const label = (e, ln) => `${e.package ?? 'pca'}/${e.file}:${ln ?? e.lineno ?? '?'}${e.occurrence ? ` (#${e.occurrence})` : ''} ${e.mutator} '${String(e.original).slice(0, 50)}' -> '${String(e.replacement).slice(0, 50)}'`;
const entries = [];
const seen = new Set();
const sources = new Map();
let drift = 0;
for (const e of ledger.equivalents) {
  let bad = false;
  for (const f of ['file', 'mutator', 'original', 'replacement', 'line', 'reason']) {
    if (typeof e[f] !== 'string' || (f === 'reason' && e[f].length < 12)) { errors.push(`entry missing/short '${f}': ${JSON.stringify(e).slice(0, 120)}`); bad = true; }
  }
  if (bad) continue;
  const pkg = e.package ?? 'pca';
  const src = path.join(pcaDir(pkg), e.file);
  if (!sources.has(src)) sources.set(src, fs.existsSync(src) ? fs.readFileSync(src, 'utf8').split('\n') : null);
  const lines = sources.get(src);
  if (!lines) { errors.push(`source file gone: ${pkg}/${e.file}`); continue; }
  const r = checkEntrySite(lines, e, label(e));
  errors.push(...r.errors);
  if (e.differential) {
    const [tf, tn] = e.differential.split('#');
    const p = path.join(pcaDir(pkg), tf);
    if (!fs.existsSync(p)) errors.push(`differential test file missing: ${e.differential}`);
    else if (tn && !fs.readFileSync(p, 'utf8').includes(tn)) errors.push(`differential test name not found: ${e.differential}`);
  }
  if (r.errors.length) continue;
  if (e.lineno !== undefined && e.lineno !== r.lineno) drift++;
  const k = siteKey(pkg, e.file, e.mutator, e.original, e.replacement, e.line, e.occurrence ?? 1);
  if (seen.has(k)) errors.push(`duplicate entry: ${label(e)}`);
  seen.add(k);
  entries.push({ key: k, multiplicity: e.multiplicity, unit: `${pkg}\u0000${e.file}`, label: label(e, r.lineno) });
}
const reports = args.filter((a) => !a.startsWith('--'));
const pkg = opt('package') ?? 'pca';
let survivors = 0;
if (reports.length) {
  const surv = [];
  const units = new Set();
  for (const r of reports) {
    const rep = JSON.parse(fs.readFileSync(r, 'utf8'));
    for (const [file, f] of Object.entries(rep.files)) {
      units.add(`${pkg}\u0000${file}`);
      const src = f.source.split('\n');
      for (const m of f.mutants) {
        if (m.status !== 'Survived' && m.status !== 'NoCoverage') continue;
        survivors++;
        const l = m.location;
        const lineText = src[l.start.line - 1].trim();
        const original = l.start.line === l.end.line ? src[l.start.line - 1].slice(l.start.column - 1, l.end.column - 1) : '<multiline>';
        const occ = occurrenceAt(src, l.start.line);
        surv.push({
          key: siteKey(pkg, file, m.mutatorName, original, String(m.replacement), lineText, occ),
          unit: `${pkg}\u0000${file}`,
          label: `${pkg}/${file}:${l.start.line}:${l.start.column} (#${occ}) ${m.mutatorName} '${original.slice(0, 60)}' -> '${String(m.replacement).slice(0, 60)}'`,
        });
      }
    }
  }
  errors.push(...checkSites(entries, surv, units));
}
const nEq = ledger.equivalents.length;
if (errors.length) { console.error(errors.join('\n')); console.error(`FAIL: ${errors.length} problem(s); ${nEq} listed equivalents`); process.exit(1); }
console.log(`OK: ${nEq} justified equivalents, one site each${drift ? ` (${drift} line hint(s) drifted, informational)` : ''}${reports.length ? `, ${survivors} survivors all listed` : ' (static check)'}`);
