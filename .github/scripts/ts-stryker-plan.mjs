#!/usr/bin/env node
// ts-stryker-plan.mjs <k> <n>   (repo root) Print shard k of n of the TypeScript mutation-testing plan, one line per package:
//   <package-dir> <src-file> <src-file> ...      (src files relative to packages/<package-dir>)
// Scope: every non-test source file (src/**/*.ts) of every package that has entries in the equivalent-mutant ledger
// (tools/pca-audit/mutation-equivalents.json) - the audited set. Units are kept in package order and cut into n contiguous
// slices of about equal line count, so a shard touches as few packages (= Stryker dry runs) as possible.
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const [k, n] = process.argv.slice(2, 4).map(Number);
if (!(n >= 1 && k >= 1 && k <= n)) { console.error('usage: ts-stryker-plan.mjs <k> <n>'); process.exit(2); }
const ledger = JSON.parse(readFileSync('tools/pca-audit/mutation-equivalents.json', 'utf8'));
const pkgs = [...new Set(ledger.equivalents.map((e) => e.package ?? 'pca'))].filter((p) => existsSync(join('packages', p, 'src'))).sort();
const walk = (d) => readdirSync(d).flatMap((e) => { const p = join(d, e); return statSync(p).isDirectory() ? walk(p) : [p]; });
const units = [];
for (const p of pkgs) {
  const base = join('packages', p);
  for (const f of walk(join(base, 'src')).sort()) {
    if (!f.endsWith('.ts') || f.endsWith('.test.ts') || f.endsWith('.d.ts')) continue;
    units.push({ pkg: p, file: f.slice(base.length + 1), w: readFileSync(f, 'utf8').split('\n').length });
  }
}
const total = units.reduce((s, u) => s + u.w, 0);
let acc = 0;
const mine = units.filter((u) => { const mid = acc + u.w / 2; acc += u.w; return Math.min(n, Math.floor((mid / total) * n) + 1) === k; });
const by = new Map();
for (const u of mine) by.set(u.pkg, [...(by.get(u.pkg) ?? []), u.file]);
for (const [p, files] of by) console.log([p, ...files].join(' '));
