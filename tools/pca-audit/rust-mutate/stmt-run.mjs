#!/usr/bin/env node
// Statement-form mutants for the pca-rust mutation workflow, alongside cargo-mutants (which replaces function bodies and swaps
// operators but never forces a plain boolean `if`, an `if let` or a `let ... else`, nor deletes continue / break, a bare `x?;`
// or an early `return Err`). The mutants come from stmt-mut (syn); one on a line where cargo-mutants already has a mutant is
// dropped. Each is built and tested as cargo-mutants does it (same profile, nextest, timeouts and memory cap).
//   node stmt-run.mjs list --tool=<stmt-mut binary> --pkg=<crate> [--exclude=<glob>[,<glob>]] -> stdout: {count, files, mutants:[...]}
//   node stmt-run.mjs run  --tool=<bin> --pkg=<crate> --shard=<k0> --of=<N> --out=<dir> --run-errors=<file> [-j=2]
//                          [--min-timeout=60] [--multiplier=3] -- <extra cargo nextest run args>
// `run` writes <dir>/mutants.out/{caught,missed,timeout,unviable}.txt (names `<file>:<line>:<col>: <desc>`, as cargo-mutants),
// <dir>/results.json and the run-error list (a caught mutant whose tests died by a signal with no plain FAIL: it decided
// nothing; same rule and format as the cargo-mutants shards).
import fs from 'node:fs';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';

const argv = process.argv.slice(2);
const cmd = argv[0];
const dd = argv.indexOf('--');
const mine = dd < 0 ? argv.slice(1) : argv.slice(1, dd), extra = dd < 0 ? [] : argv.slice(dd + 1);
const opt = (n, d) => mine.find((a) => a.startsWith(`--${n}=`))?.slice(n.length + 3) ?? d;
const pkg = opt('pkg');

export function plan(tool, pkg, exclude = '') {
  const excl = exclude.split(',').filter(Boolean).flatMap((g) => ['--exclude', g]);
  const r = spawnSync('cargo', ['mutants', '-p', pkg, '--all-features', '--no-shuffle', ...excl, '--list', '--json'], { encoding: 'utf8', maxBuffer: 1 << 29 });
  if (r.status !== 0) { console.error(r.stderr); throw new Error('cargo mutants --list failed'); }
  const cm = JSON.parse(r.stdout);
  const taken = new Set(cm.map((m) => { const p = /^(.+?):(\d+):\d+: /.exec(m.name); if (!p) throw new Error('unparsed: ' + m.name); return `${p[1]}:${p[2]}`; }));
  const files = [...new Set(cm.map((m) => m.file))].sort();
  const s = spawnSync(tool, files, { encoding: 'utf8', maxBuffer: 1 << 29 });
  if (s.status !== 0) { console.error(s.stderr); throw new Error('stmt-mut failed'); }
  const all = JSON.parse(s.stdout);
  const mutants = all.filter((m) => !taken.has(`${m.file}:${m.line}`))
    .sort((a, b) => a.file.localeCompare(b.file) || a.start - b.start || a.end - b.end || a.desc.localeCompare(b.desc));
  for (const m of mutants) m.name = `${m.file}:${m.line}:${m.col}: ${m.desc}`;
  return { count: mutants.length, generated: all.length, skipped_lines_with_a_cargo_mutant: all.length - mutants.length, cargo_mutants: cm.length, files: files.length, mutants };
}

if (cmd === 'list') {
  const p = plan(opt('tool'), pkg, opt('exclude', ''));
  console.log(JSON.stringify(p));
  process.exit(0);
}
if (cmd !== 'run') { console.error('usage: stmt-run.mjs list|run'); process.exit(2); }

const [k0, of, out, j] = [Number(opt('shard')), Number(opt('of')), path.resolve(opt('out')), Number(opt('j', '2'))];
const shard = plan(opt('tool'), pkg, opt('exclude', '')).mutants.filter((_, i) => i % of === k0);
console.error(`stmt shard ${k0}/${of}: ${shard.length} mutant(s)`);
fs.rmSync(out, { recursive: true, force: true }); fs.mkdirSync(path.join(out, 'logs'), { recursive: true });
const T = process.env.RUNNER_TEMP || '/tmp', kb = process.env.CARRY_ULIMIT_KB;
const root = process.cwd();
const base = ['nextest', 'run', '-p', pkg, '--all-features', ...extra];

// a command in its own process group (a timeout kills every test process), under the per-process memory cap
function run(cwd, target, args, log, limitS) {
  return new Promise((res) => {
    const fd = fs.openSync(log, 'a'), t0 = Date.now();
    const c = spawn('bash', ['-c', `${kb ? `ulimit -v ${Number(kb)}; ` : ''}exec "$@"`, 'bash', 'cargo', ...args],
      { cwd, detached: true, stdio: ['ignore', fd, fd], env: { ...process.env, CARGO_TARGET_DIR: target } });
    let timedOut = false;
    const timer = limitS ? setTimeout(() => { timedOut = true; try { process.kill(-c.pid, 'SIGKILL'); } catch {} }, limitS * 1000) : null;
    c.on('exit', (code, sig) => { if (timer) clearTimeout(timer); fs.closeSync(fd); try { process.kill(-c.pid, 'SIGKILL'); } catch {} res({ code: code ?? 128, sig, timedOut, s: (Date.now() - t0) / 1000 }); });
  });
}

// one copy of the tree per worker (cargo-mutants' scratch copies), each with its own target dir
const workers = [];
for (let w = 0; w < j; w++) {
  const dir = path.join(T, `stmt-w${w}`);
  fs.rmSync(dir, { recursive: true, force: true });
  const cp = spawnSync('rsync', ['-a', '--exclude=/target', '--exclude=/.git', root + '/', dir + '/'], { stdio: 'inherit' });
  if (cp.status !== 0) throw new Error('copy failed');
  workers.push({ dir, target: path.join(T, `stmt-t${w}`) });
}
// baseline: the unmutated tree builds and passes in every copy; the test timeout follows from its duration
const baseline = await Promise.all(workers.map(async (w, i) => {
  const log = path.join(out, 'logs', `baseline-${i}.log`);
  const b = await run(w.dir, w.target, [...base, '--no-run'], log);
  const t = b.code === 0 ? await run(w.dir, w.target, base, log) : b;
  if (t.code !== 0) { console.error(fs.readFileSync(log, 'utf8').slice(-4000)); console.error(`::error::the unmutated tree fails in copy ${i}`); process.exit(1); }
  return t.s;
}));
const limit = Math.max(Number(opt('min-timeout', '60')), Number(opt('multiplier', '3')) * Math.max(...baseline));
console.error(`baseline tests ${baseline.map((s) => s.toFixed(0)).join(' / ')} s; test timeout ${limit.toFixed(0)} s`);

const status = new Map(), runErrors = [];
let sigkilled = 0, next = 0;
async function work(w, wi) {
  while (next < shard.length) {
    const m = shard[next++], f = path.join(w.dir, m.file), orig = fs.readFileSync(f);
    const b = Buffer.from(orig);
    fs.writeFileSync(f, Buffer.concat([b.subarray(0, m.start), Buffer.from(m.repl), b.subarray(m.end)]));
    const log = path.join(out, 'logs', `${status.size + runErrors.length}-${wi}-${Date.now()}.log`);
    fs.writeFileSync(log, `${m.name}\n`);
    try {
      const bld = await run(w.dir, w.target, [...base, '--no-run'], log);
      if (bld.code !== 0) { status.set(m.name, 'unviable'); continue; }
      const t = await run(w.dir, w.target, base, log, limit);
      if (t.timedOut) { status.set(m.name, 'timeout'); continue; }
      if (t.code === 0) { status.set(m.name, 'missed'); continue; }
      status.set(m.name, 'caught');
      const txt = fs.readFileSync(log, 'utf8');
      const sig = [...new Set([...txt.matchAll(/^\s*(?:TRY \d+ )?(SIG[A-Z0-9]+|ABORT)\s+\[/gm)].map((x) => x[1]))];
      if (sig.includes('SIGKILL')) sigkilled++;
      if (!/^\s*(?:TRY \d+ )?FAIL\s+\[/m.test(txt)) {
        const ev = txt.match(/memory allocation of \d+ bytes failed|has overflowed its stack/);
        const text = (orig.toString('utf8').split('\n')[m.line - 1] || '').trim();
        runErrors.push({ file: m.file.replace(/^crates\/[^/]+\//, ''), fn: m.fn, text, mutant: m.desc, lineno: m.line,
          kind: sig.length ? sig.join('+') : 'no FAIL line', evidence: ev ? ev[0] : '', name: m.name });
      }
    } finally {
      fs.writeFileSync(f, orig);
    }
  }
}
await Promise.all(workers.map((w, i) => work(w, i)));

const missing = shard.filter((m) => !status.has(m.name));
if (missing.length) { console.error(`::error::no outcome for ${missing.length} mutant(s), e.g. ${missing[0].name}`); process.exit(1); }
const bad = new Set(runErrors.map((e) => e.name));
const lists = { caught: [], missed: [], timeout: [], unviable: [] }, results = [];
for (const m of shard) {
  const s = status.get(m.name);
  lists[s].push(m.name);
  results.push({ key: `stmt|${m.file}|${m.fn}|${m.genre}|${m.desc}|${m.start}`, status: bad.has(m.name) ? 'run_error' : s, name: m.name });
}
fs.mkdirSync(path.join(out, 'mutants.out'), { recursive: true });
for (const [k, v] of Object.entries(lists)) fs.writeFileSync(path.join(out, 'mutants.out', `${k}.txt`), v.length ? v.join('\n') + '\n' : '');
fs.writeFileSync(path.join(out, 'results.json'), JSON.stringify(results));
fs.writeFileSync(opt('run-errors'), JSON.stringify(runErrors.map(({ name, ...e }) => e), null, 1));
fs.writeFileSync(path.join(out, 'sigkilled.txt'), String(sigkilled));
for (const e of runErrors) console.log(`::warning::run error (${e.kind}${e.evidence ? ', ' + e.evidence : ''}): ${e.file}:${e.lineno} ${e.mutant}`);
console.error(`stmt shard ${k0}/${of}: ${Object.entries(lists).map(([k, v]) => `${k} ${v.length}`).join(', ')}`);
