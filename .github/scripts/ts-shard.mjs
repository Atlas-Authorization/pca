#!/usr/bin/env node
// Print the pnpm --filter arguments for shard K of N over packages/* (stable, size-balanced by source file count).
//   node .github/scripts/ts-shard.mjs <k> <n> [--deps]     k is 1-based; --deps appends "..." (the package + its dependencies)
import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';

const [k, n] = process.argv.slice(2, 4).map(Number);
const deps = process.argv.includes('--deps');
if (!(n >= 1 && k >= 1 && k <= n)) { console.error('usage: ts-shard.mjs <k> <n> [--deps]'); process.exit(2); }
const count = (d) => { let c = 0; for (const e of readdirSync(d)) { if (e === 'node_modules' || e === 'dist') continue; const p = join(d, e); c += statSync(p).isDirectory() ? count(p) : 1; } return c; };
const pkgs = readdirSync('packages')
  .filter((d) => existsSync(join('packages', d, 'package.json')))
  .map((d) => ({ name: JSON.parse(readFileSync(join('packages', d, 'package.json'), 'utf8')).name, weight: count(join('packages', d)) }))
  .sort((a, b) => b.weight - a.weight || a.name.localeCompare(b.name));
const bins = Array.from({ length: n }, () => ({ w: 0, names: [] }));
for (const p of pkgs) { const b = bins.reduce((m, x) => (x.w < m.w ? x : m)); b.w += p.weight; b.names.push(p.name); }
process.stdout.write(bins[k - 1].names.sort().map((x) => `--filter=${x}${deps ? '...' : ''}`).join(' ') + '\n');
