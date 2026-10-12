#!/usr/bin/env node
// Summarise a Stryker JSON report: per-file score and the surviving / uncovered mutants (line, mutator, replacement).
// Usage: node survivors.mjs <report.json> [--list] [--file substr]
import fs from 'node:fs';
const [, , path, ...rest] = process.argv;
const list = rest.includes('--list');
const fi = rest.indexOf('--file');
const only = fi >= 0 ? rest[fi + 1] : '';
const ledger = rest.includes('--ledger'); // print survivors NOT in the ledger, as paste-ready candidate entries

const rep = JSON.parse(fs.readFileSync(path, 'utf8'));
for (const [file, f] of Object.entries(rep.files)) {
  if (only && !file.includes(only)) continue;
  const c = {};
  for (const m of f.mutants) c[m.status] = (c[m.status] ?? 0) + 1;
  const killed = (c.Killed ?? 0) + (c.Timeout ?? 0);
  const valid = killed + (c.Survived ?? 0) + (c.NoCoverage ?? 0);
  console.log(`${file}: score ${(100 * killed / valid).toFixed(2)}% (killed ${killed}, survived ${c.Survived ?? 0}, nocov ${c.NoCoverage ?? 0}, ignored ${c.Ignored ?? 0})`);
  if (list) {
    const src = f.source.split('\n');
    for (const m of f.mutants.filter((x) => x.status === 'Survived' || x.status === 'NoCoverage')) {
      const l = m.location;
      const orig = l.start.line === l.end.line ? src[l.start.line - 1].slice(l.start.column - 1, l.end.column - 1) : '<multiline>';
      console.log(`  L${l.start.line}:${l.start.column} ${m.status === 'NoCoverage' ? 'NOCOV' : 'SURV '} ${m.mutatorName} [${orig.slice(0, 60).replace(/\n/g, ' ')}] -> [${String(m.replacement).slice(0, 60).replace(/\n/g, ' ')}]   | ${src[l.start.line - 1].trim().slice(0, 110)}`);
    }
  }
}
