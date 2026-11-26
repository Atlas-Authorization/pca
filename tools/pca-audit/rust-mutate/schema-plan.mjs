#!/usr/bin/env node
// Schema groups for the pca-rust mutation workflow: every source file of the plan goes to ONE group (a group is one schema
// build, see schema-gen), files packed largest first into the least loaded group; each group gets run shards in proportion to
// its mutants (largest remainder, at least one).
//   node schema-plan.mjs --cm=<cm.json> --stmt=<stmt.json> --groups=<G> --runs=<R> --out=<groups.json>
//   node schema-plan.mjs --self-test
import fs from 'node:fs';

const opt = (n) => process.argv.slice(2).find((a) => a.startsWith(`--${n}=`))?.slice(n.length + 3);

export function groups(cm, stmt, G, R) {
  const per = new Map();
  for (const m of [...cm, ...stmt]) per.set(m.file, (per.get(m.file) ?? 0) + 1);
  const files = [...per].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  const gs = Array.from({ length: Math.min(G, files.length) }, () => ({ files: [], n: 0 }));
  for (const [f, n] of files) {
    const g = gs.reduce((best, x, i) => (x.n < gs[best].n ? i : best), 0);
    gs[g].files.push(f); gs[g].n += n;
  }
  const total = gs.reduce((a, g) => a + g.n, 0);
  if (R < gs.length) throw new Error(`${R} run shards for ${gs.length} groups`);
  const exact = gs.map((g) => (R * g.n) / total);
  const runs = exact.map((x) => Math.max(1, Math.floor(x)));
  let left = R - runs.reduce((a, b) => a + b, 0);
  for (const i of exact.map((x, i) => [x - Math.floor(x), i]).sort((a, b) => b[0] - a[0] || a[1] - b[1]).map((x) => x[1])) {
    if (left <= 0) break;
    runs[i]++; left--;
  }
  if (left < 0) throw new Error('more groups than run shards can cover');
  return gs.map((g, i) => ({ files: g.files.sort(), n: g.n, runs: runs[i] }));
}

if (process.argv.includes('--self-test')) {
  const mk = (f, n) => Array.from({ length: n }, () => ({ file: f }));
  const g = groups([...mk('a', 50), ...mk('b', 30), ...mk('c', 20)], mk('c', 10), 2, 5);
  const all = g.flatMap((x) => x.files).sort();
  if (JSON.stringify(all) !== '["a","b","c"]' || g.reduce((a, x) => a + x.runs, 0) !== 5 || g.some((x) => x.runs < 1)) throw new Error('self-test: ' + JSON.stringify(g));
  if (g.reduce((a, x) => a + x.n, 0) !== 110) throw new Error('self-test: mutants lost');
  console.log('schema-plan self-test ok', JSON.stringify(g.map((x) => [x.n, x.runs])));
  process.exit(0);
}
const cm = JSON.parse(fs.readFileSync(opt('cm'), 'utf8')), stmt = JSON.parse(fs.readFileSync(opt('stmt'), 'utf8'));
const g = groups(cm, stmt, Number(opt('groups')), Number(opt('runs')));
fs.writeFileSync(opt('out'), JSON.stringify({ groups: g }));
for (const [i, x] of g.entries()) console.log(`group ${i}: ${x.files.length} file(s), ${x.n} mutant(s), ${x.runs} run shard(s)`);
