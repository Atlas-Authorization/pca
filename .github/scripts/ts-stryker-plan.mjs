#!/usr/bin/env node
// ts-stryker-plan.mjs <k> <n>   (repo root) Print shard k of n of the TypeScript mutation-testing plan, one line per package:
//   <package-dir> <src-file> <src-file> ...      (src files relative to packages/<package-dir>)
// Scope: every non-test source file (src/**/*.ts) of every package that has entries in the equivalent-mutant ledger
// (tools/pca-audit/mutation-equivalents.json) plus its `also_audited_packages` (new packages with no entries yet) - the audited set. Units are kept in package order and cut into n contiguous
// slices of about equal line count, so a shard touches as few packages (= Stryker dry runs) as possible.
// ISOLATED packages (a suite too slow to share a shard: pca-invariants) are not cut: they run alone in the LAST shard (k === n),
// and the other packages are cut into n - 1 slices. The merge script uses this same plan, so completeness stays consistent.
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const [k, n] = process.argv.slice(2, 4).map(Number);
if (!(n >= 1 && k >= 1 && k <= n)) { console.error('usage: ts-stryker-plan.mjs <k> <n>'); process.exit(2); }
const ledger = JSON.parse(readFileSync('tools/pca-audit/mutation-equivalents.json', 'utf8'));
const pkgs = [...new Set([...ledger.equivalents.map((e) => e.package ?? 'pca'), ...(ledger.also_audited_packages ?? [])])].filter((p) => existsSync(join('packages', p, 'src'))).sort();
const walk = (d) => readdirSync(d).flatMap((e) => { const p = join(d, e); return statSync(p).isDirectory() ? walk(p) : [p]; });
const excludeCache = new Map();
/** The non-test "exclude" globs of a package's tsconfig.build.json as RegExps over paths relative to the package. */
function buildExcluded(pkg) {
  if (excludeCache.has(pkg)) return excludeCache.get(pkg);
  let res = [];
  const f = join('packages', pkg, 'tsconfig.build.json');
  if (existsSync(f)) {
    const cfg = JSON.parse(readFileSync(f, 'utf8').replace(/^\s*\/\/.*$/gm, ''));
    res = (cfg.exclude ?? [])
      .filter((g) => !/\.test\.tsx?$/.test(g))
      .map((g) => new RegExp('^' + g.split('**/').map((a) => a.split('**').map((b) => b.split('*').map((c) => c.replace(/[.+^${}()|[\]\\]/g, '\\$&')).join('[^/]*')).join('.*')).join('(?:.*/)?') + '$'));
  }
  excludeCache.set(pkg, res);
  return res;
}
// Cost weights: lines of source are a poor proxy for a package whose test suite is slow (every mutant re-runs its covering
// tests). pca-mpc's suite takes ~14 min unloaded (network / OT protocol tests), so its files count 4x when slices are cut:
// shard 14 (pca-mpc + oidc + oprf + policy-bridge) ran past the 6 h cap. No file is dropped, only spread over more shards.
// Shard 14 of Stryker run 39706550807 (pca-mpc ot / otx / party / runner / sharing / spdz-runner / spdz, 1417 mutants) hit the
// 350-minute job limit (its dry run alone took 38 min against 6 min for the src/net shard): the elliptic-curve OT and SPDZ
// modules re-run slow covering tests per mutant. Those files count 16x, the rest of pca-mpc 4x.
const COST = { 'pca-mpc': 4 };
const FILE_COST = { 'pca-mpc': { 'src/ot.ts': 16, 'src/otx.ts': 16, 'src/spdz.ts': 16, 'src/spdz-runner.ts': 16, 'src/runner.ts': 16, 'src/party.ts': 16, 'src/sharing.ts': 16 } };
const ISOLATED = new Set(['pca-invariants']);
const units = [];
for (const p of pkgs) {
  const base = join('packages', p);
  for (const f of walk(join(base, 'src')).sort()) {
    if (!f.endsWith('.ts') || f.endsWith('.test.ts') || f.endsWith('.d.ts')) continue;
    // Test-only helpers shipped in src/ are excluded from the build (tsconfig.build.json "exclude"): no production behaviour to mutate.
    if (buildExcluded(p).some((re) => re.test(f.slice(base.length + 1)))) continue;
    units.push({ pkg: p, file: f.slice(base.length + 1), w: readFileSync(f, 'utf8').split('\n').length * (FILE_COST[p]?.[f.slice(base.length + 1)] ?? COST[p] ?? 1) });
  }
}
const hasIsolated = units.some((u) => ISOLATED.has(u.pkg)) && n >= 2;
const shared = hasIsolated ? units.filter((u) => !ISOLATED.has(u.pkg)) : units;
const cut = hasIsolated ? n - 1 : n;
const total = shared.reduce((s, u) => s + u.w, 0);
let acc = 0;
const mine = hasIsolated && k === n
  ? units.filter((u) => ISOLATED.has(u.pkg))
  : shared.filter((u) => { const mid = acc + u.w / 2; acc += u.w; return Math.min(cut, Math.floor((mid / total) * cut) + 1) === k; });
const by = new Map();
for (const u of mine) by.set(u.pkg, [...(by.get(u.pkg) ?? []), u.file]);
for (const [p, files] of by) console.log([p, ...files].join(' '));
