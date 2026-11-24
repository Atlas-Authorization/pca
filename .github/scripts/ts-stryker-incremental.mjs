#!/usr/bin/env node
// Incremental Stryker for fix rounds (the release gate never uses it). Selection is by FILE around the 48-shard plan:
//   manifest <out.json> <shards>            tracked-file blob map of everything that can influence a result (git ls-files -s) + shard count
//   plan <baseline-manifest.json> <baseline-reports-dir> <shards> <out.json>
//        diff the manifests. Any changed path that is not a mutated source file of the plan (a test, a helper, a config, a script,
//        the lockfile, an unplanned source) = FULL (no carry). Otherwise re-test (a) every changed source file and (b) every file
//        that had a Survived / NoCoverage mutant in the baseline (ledgered equivalents included) or is absent from the baseline report.
//        out = {full, reason, shards:[k...], files:{k:{pkg:[file]}}}
//   filter <k> <inc-plan.json> <plan-k.txt>   print the shard's plan restricted to the files to re-test
//   carry <k> <inc-plan.json> <full-plan-k.txt> <baseline-shard-dir> <out-dir>
//        complete <out-dir>/<pkg>__<k>.json: baseline entries of every file not re-tested + the new entries of the re-tested ones
// Files of a re-tested file are replaced wholesale, so a shard still reports its COMPLETE mutant set and the ledger check
// (survivors listed, no stale entry) sees the full picture.
import { execFileSync } from 'node:child_process';
import { copyFileSync, existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';

const OPEN = new Set(['Survived', 'NoCoverage']);
const SKIP = /^(docs|examples)\/|\.md$|^tools\/pca-audit\/mutation-equivalents[^/]*\.json$|^tools\/pca-audit\/stryker\/equivalent-mutants\.md$/; // prose and the ledger (the merge always re-checks the ledger) are not inputs

export function manifestOf(root) {
  const m = {};
  for (const rec of execFileSync('git', ['-C', root, 'ls-files', '-s', '-z'], { encoding: 'utf8', maxBuffer: 1 << 29 }).split('\0').filter(Boolean)) {
    const tab = rec.indexOf('\t'), p = rec.slice(tab + 1);
    if (!SKIP.test(p)) m[p] = rec.split(' ')[1];
  }
  return m;
}

const planOf = (k, n) => execFileSync(process.execPath, ['.github/scripts/ts-stryker-plan.mjs', String(k), String(n)], { encoding: 'utf8' })
  .split('\n').filter(Boolean).map((l) => { const [pkg, ...files] = l.trim().split(/\s+/); return { pkg, files }; });

const readJson = (f) => JSON.parse(readFileSync(f, 'utf8'));

export function decide({ cur, base, shards, plans, reports }) {
  if (base.shards !== shards) return { full: true, reason: `shard count changed (${base.shards} -> ${shards})` };
  const planned = new Map(); // repo path -> {k, pkg, file}
  for (const [k, entries] of Object.entries(plans)) for (const { pkg, files } of entries) for (const f of files) planned.set(`packages/${pkg}/${f}`, { k, pkg, file: f });
  const changed = [];
  for (const p of new Set([...Object.keys(cur), ...Object.keys(base.files)])) if (cur[p] !== base.files[p]) changed.push(p);
  const foreign = changed.filter((p) => !planned.has(p));
  if (foreign.length) return { full: true, reason: `${foreign.length} changed path(s) are not mutated sources (tests/helpers/scripts/config), e.g. ${foreign.slice(0, 3).join(', ')}` };
  const files = {};
  const add = (k, pkg, file) => { ((files[k] ??= {})[pkg] ??= new Set()).add(file); };
  for (const p of changed) { const { k, pkg, file } = planned.get(p); add(k, pkg, file); }
  for (const [k, entries] of Object.entries(plans)) for (const { pkg, files: fs } of entries) {
    const rep = reports[`${pkg}__${k}`];
    for (const f of fs) {
      const r = rep?.files?.[f];
      if (!r || r.mutants.some((m) => OPEN.has(m.status))) add(k, pkg, f);
    }
  }
  const out = {};
  for (const [k, by] of Object.entries(files)) out[k] = Object.fromEntries(Object.entries(by).map(([pkg, s]) => [pkg, [...s]]));
  return { full: false, reason: `${changed.length} changed source file(s); survivors re-tested`, shards: Object.keys(out).map(Number).sort((a, b) => a - b), files: out };
}

if (import.meta.url === `file://${process.argv[1]}`) {
const [cmd, ...a] = process.argv.slice(2);
if (cmd === 'manifest') {
  writeFileSync(a[0], JSON.stringify({ shards: Number(a[1]), files: manifestOf('.') }));
} else if (cmd === 'plan') {
  const [bm, rdir, nArg, out] = a, shards = Number(nArg);
  const base = readJson(bm);
  const plans = {}, reports = {};
  for (let k = 1; k <= shards; k++) plans[k] = planOf(k, shards);
  for (const f of readdirSync(rdir, { recursive: true }).map(String).filter((f) => /__\d+\.json$/.test(f))) reports[basename(f, '.json')] = readJson(join(rdir, f));
  const d = decide({ cur: manifestOf('.'), base, shards, plans, reports });
  writeFileSync(out, JSON.stringify(d));
  console.log(d.full ? `FULL run: ${d.reason}` : `incremental: ${d.reason}; ${d.shards.length}/${shards} shard(s) to run: ${d.shards.join(',')}`);
} else if (cmd === 'filter') {
  const [k, planFile, plan] = a, d = readJson(planFile);
  for (const l of readFileSync(plan, 'utf8').split('\n').filter(Boolean)) {
    const [pkg, ...fs] = l.trim().split(/\s+/);
    const keep = new Set(d.files?.[k]?.[pkg] ?? []);
    const kept = fs.filter((f) => keep.has(f));
    if (kept.length) console.log(`${pkg} ${kept.join(' ')}`);
  }
} else if (cmd === 'carry') {
  const [k, planFile, fullPlan, bdir, out] = a, d = readJson(planFile);
  let bad = 0;
  for (const l of readFileSync(fullPlan, 'utf8').split('\n').filter(Boolean)) {
    const pkg = l.trim().split(/\s+/)[0], name = `${pkg}__${k}.json`;
    const bf = readdirSync(bdir, { recursive: true }).map(String).find((f) => basename(f) === name);
    if (!bf) { console.error(`::error::baseline has no report ${name}`); bad = 1; continue; }
    const rerun = new Set(d.files?.[k]?.[pkg] ?? []);
    const np = join(out, name);
    if (!rerun.size) { copyFileSync(join(bdir, bf), np); continue; }
    if (!existsSync(np)) { console.error(`::error::re-tested ${pkg} shard ${k} produced no report`); bad = 1; continue; }
    const base = readJson(join(bdir, bf)), fresh = readJson(np);
    for (const f of rerun) { if (!fresh.files?.[f]) { console.error(`::error::re-tested file ${f} missing from the new ${name}`); bad = 1; } }
    const files = { ...base.files };
    for (const f of rerun) delete files[f];
    Object.assign(files, fresh.files);
    writeFileSync(np, JSON.stringify({ ...base, files }));
  }
  process.exit(bad);
} else { console.error('usage: ts-stryker-incremental.mjs manifest|plan|filter|carry'); process.exit(2); }
}
