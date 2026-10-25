#!/usr/bin/env node
// Fetch the carry-forward pool for a targeted mutation run.
//   node baseline.mjs --repo=<owner/repo> --branch=<b> --exclude-run=<id> [--explicit=<run id>] --snapshot=<this run's snapshot dir>
//        --out=<dir>                      (needs the gh CLI and GH_TOKEN with actions:read)
// For the explicit run, else the newest <= 8 earlier runs of mutation.yml on the branch: download its mut-snapshot and
// mut-results-* artifacts, and USE the run only when (a) its snapshot's tool_hash equals this run's (same mutator + config),
// and (b) the tests and corpus only grew since (snapshot.mjs compare). Results of the used runs are pooled, newest wins by key.
// Anything missing from the pool is simply re-run by the tool, so a partial (cancelled) baseline is safe. Writes <out>/pool.json
// = {runs, skipped, entries:{key:{s,d,h,a}}} and prints BASE_POOL=<path> (append it to $GITHUB_ENV); prints nothing when no run is usable.
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { compareSnapshots, walk } from './lib.mjs';

const opt = (n) => process.argv.slice(2).find((a) => a.startsWith(`--${n}=`))?.slice(n.length + 3);
const [repo, branch, excl, explicit, snap, out] = ['repo', 'branch', 'exclude-run', 'explicit', 'snapshot', 'out'].map(opt);
const gh = (args) => execFileSync('gh', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 1 << 28 });
let ids = explicit ? [explicit] : [];
if (!ids.length) {
  try { ids = JSON.parse(gh(['run', 'list', '-R', repo, '--workflow', 'mutation.yml', '--branch', branch, '--limit', '12', '--json', 'databaseId'])).map((r) => String(r.databaseId)).filter((i) => i !== excl).slice(0, 8); }
  catch (e) { console.error(`::notice::cannot list earlier runs: ${String(e.stderr || e).slice(0, 200)}`); }
}
const mine = JSON.parse(fs.readFileSync(path.join(snap, 'meta.json'), 'utf8'));
const entries = {}, used = [], skipped = [];
fs.mkdirSync(out, { recursive: true });
for (const id of ids) {
  const d = path.join(out, `run-${id}`);
  try { gh(['run', 'download', id, '-R', repo, '-p', 'mut-snapshot', '-p', 'mut-results-*', '-D', d]); }
  catch { skipped.push(`${id}: no artifacts`); continue; }
  // upload-artifact@v4 puts each artifact in its own folder (mut-snapshot/, mut-results-<k>/)
  const sdir = path.join(d, 'mut-snapshot');
  if (!fs.existsSync(path.join(sdir, 'meta.json'))) { skipped.push(`${id}: no snapshot`); continue; }
  const meta = JSON.parse(fs.readFileSync(path.join(sdir, 'meta.json'), 'utf8'));
  if (meta.tool_hash !== mine.tool_hash) { skipped.push(`${id}: other mutator/config (tool hash differs)`); continue; }
  const cmp = compareSnapshots(sdir, snap);
  if (!cmp.ok) { skipped.push(`${id}: tests/corpus changed beyond additions (${cmp.reasons.length}: ${cmp.reasons.slice(0, 3).join('; ')})`); continue; }
  let n = 0;
  for (const rel of walk(d).filter((f) => /^mut-results-[^/]+\/results\.json$/.test(f))) {
    for (const r of JSON.parse(fs.readFileSync(path.join(d, rel), 'utf8'))) {
      if (!r.key || !r.status || r.def_hash === undefined || r.shell_hash === undefined) continue;
      if (!(r.key in entries)) { entries[r.key] = { s: r.status, d: r.def_hash, h: r.shell_hash, a: r.src_hash }; n++; }
    }
  }
  if (n) used.push(`${id} (+${n})`); else skipped.push(`${id}: no results`);
}
for (const s of skipped) console.error(`baseline skipped ${s}`);
console.error(`baseline: ${used.length ? `pooled ${Object.keys(entries).length} result(s) from run(s) ${used.join(', ')}` : 'no usable earlier run: full run'}`);
if (used.length) {
  const f = path.join(out, 'pool.json');
  fs.writeFileSync(f, JSON.stringify({ runs: used, skipped, entries }));
  console.log(`BASE_POOL=${path.resolve(f)}`);
}
