#!/usr/bin/env node
// Usage: add-equivalent.mjs <report.json> <file-substr> "<line>:<col>[,<line>:<col>...]" "<reason>" [differential] [--package=x]
// Appends the survivors at those positions to ../mutation-equivalents.json, one entry per mutation site: keyed by text plus
// `occurrence` (which copy of that line text in the file), with `lineno` as a hint only (see ../site-key.mjs).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { occurrenceAt } from '../site-key.mjs';
const here = path.dirname(fileURLToPath(import.meta.url));
const lp = path.join(here, '..', 'mutation-equivalents.json');
const args = process.argv.slice(2).filter((a) => !a.startsWith('--package='));
const pkg = (process.argv.find((a) => a.startsWith('--package=')) ?? '--package=pca').slice(10);
const [rp, fsub, poss, reason, diff] = args;
const rep = JSON.parse(fs.readFileSync(rp, 'utf8'));
const led = JSON.parse(fs.readFileSync(lp, 'utf8'));
const want = new Set(poss.split(','));
let n = 0;
const added = new Set();
for (const [file, f] of Object.entries(rep.files)) {
  if (!file.includes(fsub)) continue;
  const src = f.source.split('\n');
  for (const m of f.mutants) {
    if (m.status !== 'Survived' && m.status !== 'NoCoverage') continue;
    const l = m.location;
    if (!want.has(`L${l.start.line}`) && !want.has(`${l.start.line}:${l.start.column}`) && !want.has(`${l.start.line}:${l.start.column}:${m.mutatorName}`)) continue;
    const original = l.start.line === l.end.line ? src[l.start.line - 1].slice(l.start.column - 1, l.end.column - 1) : '<multiline>';
    const e = { ...(pkg !== 'pca' ? { package: pkg } : {}), file, mutator: m.mutatorName, original, replacement: String(m.replacement), line: src[l.start.line - 1].trim(), occurrence: occurrenceAt(src, l.start.line), lineno: l.start.line, reason, ...(diff ? { differential: diff } : {}) };
    const site = (x) => JSON.stringify([x.package, x.file, x.mutator, x.original, x.replacement, x.line, x.occurrence ?? 1]);
    const prev = led.equivalents.find((x) => site(x) === site(e));
    if (!prev) { led.equivalents.push(e); n++; } else if (prev !== e && added.has(prev)) prev.multiplicity = (prev.multiplicity ?? 1) + 1; // same mutant twice on one line
    added.add(prev ?? e);
  }
}
fs.writeFileSync(lp, JSON.stringify(led, null, 1) + '\n');
console.log(`added ${n}`);
