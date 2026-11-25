#!/usr/bin/env node
// ts-stryker-plan.mjs <k> <n>   (repo root) Print shard k of n of the TypeScript mutation-testing plan, one line per package:
//   <package-dir> <src-file> <src-file> ...      (src files relative to packages/<package-dir>; `file:a-b` = Stryker line range a..b)
// ts-stryker-plan.mjs count     print the number of shards of the default (time-budgeted) plan
// Shape: the plan is cut by PREDICTED WALL TIME (ts-stryker-cost.json: mutants and seconds per mutant of every file, measured on the
// 0.5.1 release-candidate run) so that no shard is predicted to run longer than TARGET minutes: units are packed in package order
// until the next one would pass TARGET (each package in a shard also pays a dry run, DRY minutes), and a file predicted longer than
// CAPU minutes is cut into line ranges at mutant-free boundaries (no mutant straddles two ranges, so none is dropped; every
// shard's report carries the whole file name and the ledger check unions the ranges). A <n> other than the default count falls back
// to n equal-time contiguous slices. Scope: every non-test source file (src/**/*.ts) of every package that has entries in the equivalent-mutant ledger
// (tools/pca-audit/mutation-equivalents.json) plus its `also_audited_packages` (new packages with no entries yet) - the audited set.
// ISOLATED packages (a suite too slow to share a shard: pca-invariants) run alone in the LAST shard. The merge script uses this same
// plan, so completeness stays consistent.
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const [k, n] = process.argv.slice(2, 4).map(Number);
if (!['count', 'stats'].includes(process.argv[2]) && !(n >= 1 && k >= 1 && k <= n)) { console.error('usage: ts-stryker-plan.mjs <k> <n>'); process.exit(2); }
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
// ---- cost model --------------------------------------------------------------------------------------------------------------------
const TARGET = 34, DRY = 4, CAPU = 8; // minutes: shard wall budget (the job limit is for a hung run, not the plan), per-package dry run, largest unit
// files whose shard.sh special case matches the whole file token (a line range would skip it)
const WHOLE = new Set(['pca-mpc/src/otx.ts', 'pca-mpc/src/net/party-main.ts', 'pca/src/frost-net-runner.ts']);
const cost = JSON.parse(readFileSync(new URL('./ts-stryker-cost.json', import.meta.url), 'utf8'));
const ISOLATED = new Set(['pca-invariants']);
const med = (a) => { const s = [...a].sort((x, y) => x - y); return s[Math.floor(s.length / 2)] ?? 0; };
const known = new Map(); // package -> [mutants, lines]
const units0 = [];
for (const p of pkgs) {
  const base = join('packages', p);
  for (const f of walk(join(base, 'src')).sort()) {
    if (!f.endsWith('.ts') || f.endsWith('.test.ts') || f.endsWith('.d.ts')) continue;
    // Test-only helpers shipped in src/ are excluded from the build (tsconfig.build.json "exclude"): no production behaviour to mutate.
    if (buildExcluded(p).some((re) => re.test(f.slice(base.length + 1)))) continue;
    const file = f.slice(base.length + 1), lines = readFileSync(f, 'utf8').split('\n').length, c = cost.files[`${p}/${file}`];
    if (c) { const k = known.get(p) ?? [0, 0]; known.set(p, [k[0] + c.m, k[1] + lines]); }
    units0.push({ pkg: p, file, lines, c });
  }
}
const allRatio = med([...known.values()].map(([m, l]) => m / l)), allRate = med(Object.values(cost.pkg));
const units = [];
for (const u of units0) {
  // a file the cost run never saw (new since): mutants from its lines at the package's mutants-per-line, the package's seconds per mutant
  const m = u.c?.m ?? Math.round(u.lines * (known.has(u.pkg) ? known.get(u.pkg)[0] / known.get(u.pkg)[1] : allRatio));
  const s = u.c?.s ?? cost.pkg[u.pkg] ?? allRate;
  const t = (m * s) / 60;
  if (t <= CAPU || !u.c?.l || WHOLE.has(`${u.pkg}/${u.file}`)) { units.push({ pkg: u.pkg, file: u.file, t }); continue; }
  // cut at the boundaries no mutant straddles, nearest to equal mutant counts
  const iv = [...u.c.l].sort((x, y) => x[0] - y[0] || x[1] - y[1]);
  const cuts = []; let maxEnd = 0;
  iv.forEach(([s0, e0], i) => { maxEnd = Math.max(maxEnd, e0); if (i + 1 < iv.length && iv[i + 1][0] > maxEnd) cuts.push([maxEnd, i + 1]); });
  const q = Math.ceil(t / CAPU), chosen = [];
  for (let j = 1; j < q; j++) {
    const want = (iv.length * j) / q; let best = null;
    for (const c of cuts) if (!chosen.some((x) => x[0] === c[0]) && (!best || Math.abs(c[1] - want) < Math.abs(best[1] - want))) best = c;
    if (best) chosen.push(best);
  }
  chosen.sort((x, y) => x[0] - y[0]);
  let from = 1, prev = 0;
  for (const [line, cnt] of [...chosen, [999999, iv.length]]) {
    units.push({ pkg: u.pkg, file: `${u.file}:${from}-${line}`, t: (t * (cnt - prev)) / iv.length });
    from = line + 1; prev = cnt;
  }
}
const hasIsolated = units.some((u) => ISOLATED.has(u.pkg));
const shared = hasIsolated ? units.filter((u) => !ISOLATED.has(u.pkg)) : units;
/** Sequential packing under TARGET; the isolated packages (a suite too slow to share a shard) run alone in the last shard. */
const shardsOf = () => {
  const out = [];
  let cur = null;
  for (const u of shared) {
    const add = u.t + (cur?.pkgs.has(u.pkg) ? 0 : DRY);
    if (!cur || cur.t + add > TARGET) { cur = { t: 0, pkgs: new Set(), units: [] }; out.push(cur); }
    if (!cur.pkgs.has(u.pkg)) { cur.pkgs.add(u.pkg); cur.t += DRY; }
    cur.t += u.t; cur.units.push(u);
  }
  if (hasIsolated) out.push({ t: 0, pkgs: new Set(), units: units.filter((u) => ISOLATED.has(u.pkg)) });
  return out;
};
const auto = shardsOf();
if (process.argv[2] === 'count') { console.log(auto.length); process.exit(0); }
if (process.argv[2] === 'stats') { // predicted minutes per shard (for tuning TARGET / CAPU)
  const ts = auto.map((s) => s.t).sort((a, b) => b - a);
  console.log(`shards ${auto.length}; predicted minutes: max ${ts[0].toFixed(1)}, median ${ts[ts.length >> 1].toFixed(1)}; largest units: ${[...units].sort((a, b) => b.t - a.t).slice(0, 5).map((u) => `${u.pkg}/${u.file} ${u.t.toFixed(0)}m`).join(', ')}`);
  process.exit(0);
}
let mine;
if (n === auto.length) mine = auto[k - 1].units;
else {
  // another shard count: contiguous slices of about equal predicted time (the isolated packages still run alone, last)
  const cut = hasIsolated && n >= 2 ? n - 1 : n, total = shared.reduce((s, u) => s + u.t, 0);
  let acc = 0;
  mine = hasIsolated && n >= 2 && k === n ? units.filter((u) => ISOLATED.has(u.pkg))
    : shared.filter((u) => { const mid = acc + u.t / 2; acc += u.t; return Math.min(cut, Math.floor((mid / total) * cut) + 1) === k; });
}
const by = new Map();
for (const u of mine) by.set(u.pkg, [...(by.get(u.pkg) ?? []), u.file]);
for (const [p, files] of by) console.log([p, ...files].join(' '));
