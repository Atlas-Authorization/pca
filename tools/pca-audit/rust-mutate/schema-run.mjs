#!/usr/bin/env node
// One run shard of a schema group (pca-rust mutation workflow; the build is schema-build.mjs): every schema mutant of the group
// whose index i (by id) has i % runs == run is decided against the group's prebuilt binaries, one mutant active at a time
// (PCA_MUTANT=id), at full strength:
//   1. first against only the tests that reach the mutant (schema-build's reach map); a plain FAIL there is a real failing test:
//      caught. A mutant no test reaches, reached from a process that names no test, or reached by 60% of the tests or more,
//      skips this step.
//   2. anything not caught there runs the FULL suite before it is recorded, exactly as cargo-mutants decides it: our timeout
//      (max(min-timeout, multiplier x this runner's unmutated suite)) -> timeout; exit 0 -> missed; else caught, and a caught one
//      with no plain FAIL line (signal-killed or terminated tests only) is a run error.
//   node schema-run.mjs --bundle=<schema-build out dir> --run=<r> --runs=<R> --out=<dir> --run-errors=<file> [-j=2]
//                       [--min-timeout=60] [--multiplier=5] -- <extra cargo nextest run args>
// Writes <out>/results.json ({name, status, key}), <out>/sigkilled.txt and the run-error list (the statement shards' format).
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { run, plainFail, signals, evidence, filterOf, srcLine, parseName } from './schema-lib.mjs';

const argv = process.argv.slice(2);
const dd = argv.indexOf('--');
const mine = dd < 0 ? argv : argv.slice(0, dd), extra = dd < 0 ? [] : argv.slice(dd + 1);
const opt = (n, d) => mine.find((a) => a.startsWith(`--${n}=`))?.slice(n.length + 3) ?? d;
const B = path.resolve(opt('bundle')), out = path.resolve(opt('out')), r = Number(opt('run')), R = Number(opt('runs')), j = Number(opt('j', '2'));
const T = process.env.RUNNER_TEMP || '/tmp', ws = process.cwd();
const fail = (m) => { console.error(`::error::${m}`); process.exit(1); };
fs.rmSync(out, { recursive: true, force: true }); fs.mkdirSync(path.join(out, 'logs'), { recursive: true });

const meta = JSON.parse(fs.readFileSync(path.join(B, 'meta.json'), 'utf8')), reach = JSON.parse(fs.readFileSync(path.join(B, 'reach.json'), 'utf8'));
const mine2 = meta.mutants.filter((m) => m.st === 'schema').sort((a, b) => a.id - b.id).filter((_, i) => i % R === r);
console.error(`group ${meta.group} run ${r}/${R}: ${mine2.length} schema mutant(s)`);

// the archive is extracted ONCE; every run re-uses it (nextest's reuse build, remapped to this checkout)
const X = path.join(T, 'schema-bins');
fs.rmSync(X, { recursive: true, force: true }); fs.mkdirSync(X);
if (spawnSync('tar', ['-C', X, '--zstd', '-xf', path.join(B, 'bins.tar.zst')], { stdio: 'inherit' }).status !== 0) fail('extracting the archive failed');
const reuse = ['nextest', 'run', '--binaries-metadata', path.join(X, 'target/nextest/binaries-metadata.json'), '--cargo-metadata', path.join(X, 'target/nextest/cargo-metadata.json'),
  '--target-dir-remap', path.join(X, 'target'), '--workspace-remap', ws, ...extra];

// baseline on THIS runner: the unmutated schema binaries pass the full suite; the full-suite timeout follows from its duration
const blog = path.join(out, 'logs', 'baseline.log');
const bl = await run(reuse, { PCA_MUTANT: undefined, PCA_SCHEMA_TRACE: undefined }, blog);
if (bl.code !== 0) { console.error(fs.readFileSync(blog, 'utf8').slice(-6000)); fail('the schema binaries with no mutant active fail the suite on this runner'); }
const limitFull = Math.max(Number(opt('min-timeout', '60')), Number(opt('multiplier', '5')) * bl.s);
console.error(`baseline suite ${bl.s.toFixed(0)} s; full-suite timeout ${limitFull.toFixed(0)} s`);

const tests = reach.tests, all = new Set(reach.all);
const status = new Map(), runErrors = [], stat = { subset: 0, subsetCaught: 0, full: 0 };
let sigkilled = 0, next = 0;
async function decide(m, wi) {
  const sel = all.has(m.id) ? null : reach.sites[m.id] ?? [];
  const log = (k) => path.join(out, 'logs', `${m.id}-${k}.log`);
  const env = { PCA_MUTANT: String(m.id), PCA_SCHEMA_TRACE: undefined };
  let sub = null;
  if (sel && sel.length && sel.length < 0.6 * tests.length) {
    stat.subset++;
    const lim = Math.min(limitFull, Math.max(Number(opt('min-timeout', '60')), Number(opt('multiplier', '5')) * sel.reduce((a, i) => a + tests[i][2], 0)));
    sub = await run([...reuse, '-E', filterOf(sel.map((i) => tests[i]))], env, log('subset'), lim);
    const txt = fs.readFileSync(log('subset'), 'utf8');
    if (sub.code !== 0 && !sub.timedOut && plainFail(txt)) {
      stat.subsetCaught++; status.set(m.name, 'caught');
      if (signals(txt).includes('SIGKILL')) sigkilled++;
      return `caught (${sel.length} reaching test(s)) in ${sub.s.toFixed(0)}s`;
    }
  }
  stat.full++;
  const f = await run(reuse, env, log('full'), limitFull);
  const txt = fs.readFileSync(log('full'), 'utf8');
  const sig = signals(txt);
  if (sig.includes('SIGKILL')) sigkilled++;
  if (f.timedOut) status.set(m.name, 'timeout');
  else if (f.code === 0) status.set(m.name, 'missed');
  else {
    status.set(m.name, 'caught');
    if (!plainFail(txt)) {
      const p = parseName(m.name);
      runErrors.push({ file: p.file.replace(/^crates\/[^/]+\//, ''), fn: m.fn, text: srcLine(p.file, p.line), mutant: p.desc, lineno: p.line,
        kind: sig.length ? sig.join('+') : 'no FAIL line', evidence: evidence(txt), name: m.name });
    }
  }
  return `${status.get(m.name)} (full suite${sub ? ', after the reaching tests' : ''}) in ${((sub?.s ?? 0) + f.s).toFixed(0)}s`;
}
async function work(wi) {
  while (next < mine2.length) {
    const m = mine2[next++];
    const how = await decide(m, wi);
    // one line per mutant (as cargo-mutants' --caught/--unviable output): the per-mutant cost is measurable from the job log
    console.error(`${how.split(' ')[0]} ${m.name} ${how.slice(how.indexOf(' ') + 1)}`);
  }
}
await Promise.all(Array.from({ length: j }, (_, i) => work(i)));

const missing = mine2.filter((m) => !status.has(m.name));
if (missing.length) fail(`no outcome for ${missing.length} mutant(s), e.g. ${missing[0].name}`);
const bad = new Set(runErrors.map((e) => e.name));
// timeouts go to the run-error list, as in the cargo-mutants shards (fn: cargo-mutants' function; statement mutants: "")
for (const m of mine2) if (status.get(m.name) === 'timeout') {
  const p = parseName(m.name);
  console.log(`::warning::timeout: ${m.name}`);
  runErrors.push({ file: p.file.replace(/^crates\/[^/]+\//, ''), fn: m.kind === 'cm' ? m.fn : '', text: srcLine(p.file, p.line), mutant: p.desc, lineno: p.line, kind: 'timeout', evidence: '' });
}
fs.writeFileSync(path.join(out, 'results.json'), JSON.stringify(mine2.map((m) => ({ key: `schema|${m.name}`, name: m.name, kind: m.kind, status: bad.has(m.name) ? 'run_error' : status.get(m.name) }))));
fs.writeFileSync(opt('run-errors'), JSON.stringify(runErrors.map(({ name, ...e }) => e), null, 1));
fs.writeFileSync(path.join(out, 'sigkilled.txt'), String(sigkilled));
for (const e of runErrors) if (e.kind !== 'timeout') console.log(`::warning::run error (${e.kind}${e.evidence ? ', ' + e.evidence : ''}): ${e.file}:${e.lineno} ${e.mutant}`);
const c = {}; for (const s of status.values()) c[s] = (c[s] ?? 0) + 1;
console.error(`run ${r}/${R}: ${JSON.stringify(c)}; ${stat.subset} first against their reaching tests (${stat.subsetCaught} caught there), ${stat.full} on the full suite`);
