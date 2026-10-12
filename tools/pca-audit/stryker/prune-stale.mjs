#!/usr/bin/env node
// Usage: prune-stale.mjs <package>   Removes ledger entries of that package whose site no longer exists (the line text is gone,
// or fewer copies of it remain than the entry's occurrence; the code changed: re-measure and re-add what still survives).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const here = path.dirname(fileURLToPath(import.meta.url));
const lp = path.join(here, '..', 'mutation-equivalents.json');
const root = path.resolve(here, '../../..');
const pkg = process.argv[2] ?? 'pca';
const led = JSON.parse(fs.readFileSync(lp, 'utf8'));
const keep = [];
let dropped = 0;
for (const e of led.equivalents) {
  if ((e.package ?? 'pca') !== pkg) { keep.push(e); continue; }
  const p = path.join(root, 'packages', pkg, e.file);
  const ok = fs.existsSync(p) && fs.readFileSync(p, 'utf8').split('\n').filter((l) => l.trim() === e.line).length >= (e.occurrence ?? 1);
  if (ok) keep.push(e); else dropped++;
}
led.equivalents = keep;
fs.writeFileSync(lp, JSON.stringify(led, null, 1) + '\n');
console.log(`dropped ${dropped} stale ${pkg} entries`);
