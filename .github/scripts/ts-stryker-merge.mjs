#!/usr/bin/env node
// ts-stryker-merge.mjs <reports-dir> <n>   (repo root) Merge the shard reports of a sharded Stryker run:
//  1. completeness: every package of every shard plan (ts-stryker-plan.mjs) has its report <package>__<k>.json;
//  2. score per package and overall (killed + timeout) / (killed + timeout + survived + no coverage);
//  3. the equivalence-ledger check: tools/pca-audit/stryker/check-equivalents.mjs --package=<p> <its reports> - every survivor
//     must be a listed equivalent and every listed equivalent of a mutated file must still survive (else stale).
// Exit 0 only if all three pass. Writes a markdown summary to $GITHUB_STEP_SUMMARY when set.
import { readFileSync, readdirSync, appendFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';

const [dir, nArg] = process.argv.slice(2);
const n = Number(nArg);
const files = readdirSync(dir, { recursive: true }).map(String).filter((f) => /__\d+\.json$/.test(f));
const byPkg = new Map();
for (const f of files) {
  const pkg = /^(.+)__\d+\.json$/.exec(basename(f))[1];
  byPkg.set(pkg, [...(byPkg.get(pkg) ?? []), join(dir, f)]);
}
const problems = [];
for (let k = 1; k <= n; k++) {
  for (const line of execFileSync(process.execPath, ['.github/scripts/ts-stryker-plan.mjs', String(k), String(n)], { encoding: 'utf8' }).split('\n')) {
    const pkg = line.split(' ')[0];
    if (pkg && !files.some((f) => basename(f) === `${pkg}__${k}.json`)) problems.push(`missing report: shard ${k} package ${pkg}`);
  }
}
const rows = [];
const tot = { killed: 0, timeout: 0, survived: 0, nocov: 0, other: 0 };
for (const [pkg, reps] of [...byPkg].sort()) {
  const c = { killed: 0, timeout: 0, survived: 0, nocov: 0, other: 0 };
  for (const r of reps) for (const f of Object.values(JSON.parse(readFileSync(r, 'utf8')).files)) for (const m of f.mutants) {
    const s = m.status; c[s === 'Killed' ? 'killed' : s === 'Timeout' ? 'timeout' : s === 'Survived' ? 'survived' : s === 'NoCoverage' ? 'nocov' : 'other']++;
  }
  for (const key of Object.keys(tot)) tot[key] += c[key];
  const chk = spawnSync(process.execPath, ['tools/pca-audit/stryker/check-equivalents.mjs', `--package=${pkg}`, ...reps], { encoding: 'utf8' });
  const ok = chk.status === 0;
  if (!ok) problems.push(`ledger check failed for ${pkg}:\n${(chk.stderr || chk.stdout).trim().split('\n').slice(0, 40).join('\n')}`);
  rows.push({ pkg, ...c, ledger: ok ? 'ok' : 'FAIL' });
}
const score = (c) => { const d = c.killed + c.timeout + c.survived + c.nocov; return d ? ((100 * (c.killed + c.timeout)) / d).toFixed(1) + ' %' : '-'; };
const md = ['| package | killed | timeout | survived | no coverage | other | score | ledger |', '|---|---:|---:|---:|---:|---:|---:|---|',
  ...rows.map((r) => `| ${r.pkg} | ${r.killed} | ${r.timeout} | ${r.survived} | ${r.nocov} | ${r.other} | ${score(r)} | ${r.ledger} |`),
  `| **all** | ${tot.killed} | ${tot.timeout} | ${tot.survived} | ${tot.nocov} | ${tot.other} | ${score(tot)} | ${problems.length ? 'FAIL' : 'ok'} |`].join('\n');
console.log(md);
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `## Stryker (TypeScript), ${n} shards\n\n${md}\n`);
if (problems.length) { console.error('\n' + problems.join('\n\n')); process.exit(1); }
console.log('\nOK: every planned report present; every survivor is a listed equivalent and no listed equivalent is stale');
