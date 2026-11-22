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
// create-pca-app's tests type-check its templates against the workspace packages the templates depend on (and their
// express devDependency in the pnpm store), none of which it declares, so its shard installs and builds them too.
const mine = bins[k - 1].names;
const extra = [];
if (deps && mine.includes('create-pca-app')) {
  for (const t of readdirSync('packages/create-pca-app/templates')) {
    const f = join('packages/create-pca-app/templates', t, 'package.json');
    if (!existsSync(f)) continue;
    for (const d of Object.keys(JSON.parse(readFileSync(f, 'utf8')).dependencies ?? {})) if (d.startsWith('@atlasauth/') && !mine.includes(d) && !extra.includes(d)) extra.push(d);
  }
}
// its tests also import and run examples/pca-quickstart (express and its workspace links) and examples/pca-demo: install them too.
if (deps && mine.includes('create-pca-app')) for (const d of ['pca-quickstart', 'pca-demo']) if (!extra.includes(d)) extra.push(d);
// the core package's shard also runs the vector-generator --check steps of pca-grants, pca-a2a and pca-attest-eat (ci.yml,
// `cd ../<pkg> && npx tsx ...`), which need those packages installed and built.
if (deps && mine.includes('@atlasauth/pca')) for (const d of ['@atlasauth/pca-grants', '@atlasauth/pca-a2a', '@atlasauth/pca-attest-eat']) if (!mine.includes(d) && !extra.includes(d)) extra.push(d);
// pca-analyzer's differential test imports the arbitraries of the pca-invariants source tree, so that package must be installed and built too.
if (deps && mine.includes('@atlasauth/pca-analyzer') && !mine.includes('@atlasauth/pca-invariants') && !extra.includes('@atlasauth/pca-invariants')) extra.push('@atlasauth/pca-invariants');
process.stdout.write([...mine.sort().map((x) => `--filter=${x}${deps ? '...' : ''}`), ...extra.sort().map((x) => `--filter=${x}...`)].join(' ') + '\n');
