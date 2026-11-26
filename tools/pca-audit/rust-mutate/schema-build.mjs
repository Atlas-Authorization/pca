#!/usr/bin/env node
// One schema group of the pca-rust mutation workflow (see schema-gen): writes the group's mutants into the checkout behind the
// runtime switch, builds the test binaries ONCE, runs the full suite with no mutant active (the baseline: it must pass) while
// recording which test reaches which mutant, and packs the binaries for the run shards.
//   node schema-build.mjs --list=<dir: cm.json, stmt.json, groups.json> --group=<g> --pkg=<crate> --crate=<lib name>
//                         --root=<crate>/src/lib.rs --gen=<schema-gen binary> --out=<dir> -- <extra nextest run args>
// A mutant the generator cannot hold, or whose schema text does not compile (rustc's errors are mapped back to the mutant through
// the generator's byte ranges; the build is retried without it), is a FALLBACK: it is decided later by a real per-mutant build
// (cargo-mutants / stmt-run), never dropped. Writes <out>/meta.json (every mutant: id, name, schema or fallback + why),
// <out>/reach.json (tests, their baseline seconds, the tests reaching each mutant; `all`: mutants reached from a process that names
// no test, which get the full suite), <out>/bins.tar.zst (nextest's archive), and <out>/dec.json (for the fallback plan).
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { run, durations } from './schema-lib.mjs';

const argv = process.argv.slice(2);
const dd = argv.indexOf('--');
const mine = dd < 0 ? argv : argv.slice(0, dd), extra = dd < 0 ? [] : argv.slice(dd + 1);
const opt = (n) => mine.find((a) => a.startsWith(`--${n}=`))?.slice(n.length + 3);
const [L, g, pkg, krate, root, genBin, out] = [opt('list'), Number(opt('group')), opt('pkg'), opt('crate'), opt('root'), opt('gen'), path.resolve(opt('out'))];
const T = process.env.RUNNER_TEMP || '/tmp', ws = process.cwd();
const fail = (m) => { console.error(`::error::${m}`); process.exit(1); };
fs.rmSync(out, { recursive: true, force: true }); fs.mkdirSync(out, { recursive: true });

const cm = JSON.parse(fs.readFileSync(path.join(L, 'cm.json'), 'utf8')), stmt = JSON.parse(fs.readFileSync(path.join(L, 'stmt.json'), 'utf8'));
const G = JSON.parse(fs.readFileSync(path.join(L, 'groups.json'), 'utf8')).groups[g];
if (!G) fail(`no group ${g}`);
const files = new Set(G.files);
const muts = [];
for (const m of cm) if (files.has(m.file)) muts.push({ id: muts.length + 1, kind: 'cm', name: m.name, file: m.file, genre: m.genre, span: m.span, replacement: m.replacement, fn: m.fn, desc: m.name.replace(/^[^:]+:\d+:\d+: /, '') });
for (const m of stmt) if (files.has(m.file)) muts.push({ id: muts.length + 1, kind: 'stmt', name: m.name, file: m.file, genre: m.genre, start: m.start, end: m.end, repl: m.repl, fn: m.fn, desc: m.desc });
if (muts.length !== G.n) fail(`group ${g}: ${muts.length} mutant(s) found, the plan has ${G.n}`);
console.error(`group ${g}: ${files.size} file(s), ${muts.length} mutant(s)`);

// the switch travels in the environment (PCA_MUTANT): a child process started with a cleared environment would run unmutated
const crateDir = path.dirname(path.dirname(root));
const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => e.isDirectory() ? walk(path.join(d, e.name)) : e.name.endsWith('.rs') ? [path.join(d, e.name)] : []);
for (const f of [...walk(path.join(crateDir, 'src')), ...walk(path.join(crateDir, 'tests'))]) {
  if (/\benv_clear\s*\(|env_remove\s*\(\s*"PCA_MUTANT"/.test(fs.readFileSync(f, 'utf8'))) fail(`${f} clears the environment of a child process: the schema switch (PCA_MUTANT) would not reach it`);
}

// pristine copies (the generator reads them; restored after the build so the tests see the real sources)
const orig = path.join(T, 'schema-orig');
fs.rmSync(orig, { recursive: true, force: true });
for (const f of new Set([...files, root])) { fs.mkdirSync(path.join(orig, path.dirname(f)), { recursive: true }); fs.copyFileSync(f, path.join(orig, f)); }
const modFile = path.join(path.dirname(root), '__pca_schema.rs');
const restore = () => { for (const f of new Set([...files, root])) fs.copyFileSync(path.join(orig, f), f); fs.rmSync(modFile, { force: true }); };

const fallback = new Map();
const strip = (m) => m.kind === 'cm' ? { id: m.id, kind: 'cm', file: m.file, genre: m.genre, span: m.span, replacement: m.replacement } : { id: m.id, kind: 'stmt', file: m.file, genre: m.genre, start: m.start, end: m.end, repl: m.repl };
const build = ['test', '--no-run', '-p', pkg, '--all-features', '--profile', 'mutants', '--message-format', 'json'];
let ranges;
for (let it = 1; ; it++) {
  if (it > 10) fail('the schema build still fails after 10 rounds');
  restore();
  const inFile = path.join(T, 'schema-in.json'), outFile = path.join(T, 'schema-out.json');
  fs.writeFileSync(inFile, JSON.stringify({ root, crate: krate, orig, mutants: muts.filter((m) => !fallback.has(m.id)).map(strip) }));
  const gr = spawnSync(genBin, [inFile, outFile], { stdio: 'inherit' });
  if (gr.status !== 0) fail('schema-gen failed');
  const go = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  for (const [id, why] of Object.entries(go.fallback)) fallback.set(Number(id), why);
  ranges = go.ranges;
  const t0 = Date.now();
  const b = spawnSync('cargo', build, { encoding: 'utf8', maxBuffer: 1 << 30, stdio: ['ignore', 'pipe', 'inherit'] });
  const errs = [];
  for (const l of (b.stdout || '').split('\n')) {
    if (!l.startsWith('{')) continue;
    let j; try { j = JSON.parse(l); } catch { continue; }
    if (j.reason !== 'compiler-message' || j.message?.level !== 'error') continue;
    const sp = (j.message.spans || []).find((s) => s.is_primary);
    errs.push({ file: sp?.file_name, at: sp?.byte_start, code: j.message.code?.code || '', text: j.message.rendered || j.message.message });
  }
  console.error(`round ${it}: build ${b.status === 0 ? 'ok' : `failed with ${errs.length} error(s)`} in ${((Date.now() - t0) / 1000).toFixed(0)}s; ${fallback.size} fallback so far`);
  if (b.status === 0) break;
  const now = new Set(), unmapped = [];
  for (const e of errs) {
    const rs = e.file && ranges[e.file];
    if (!rs) { if (e.file) unmapped.push(e); continue; }
    let best = null;
    for (const [s, t, ids] of rs) if (s <= e.at && e.at <= t && (!best || t - s < best[1] - best[0])) best = [s, t, ids];
    // an error in a rewritten file outside every mutated region: every mutant of that file goes to the real build
    const ids = best ? best[2] : muts.filter((m) => m.file === e.file && !fallback.has(m.id)).map((m) => m.id);
    for (const id of ids) if (!fallback.has(id)) { now.add(id); fallback.set(id, `schema build: ${e.code || 'error'}${best ? '' : ' (outside every mutated region; whole file)'}`); }
  }
  for (const e of [...errs.slice(0, 5), ...unmapped.slice(0, 5)]) console.error(e.text.split('\n').slice(0, 12).join('\n'));
  if (unmapped.length) fail(`${unmapped.length} build error(s) in files the schema does not rewrite (e.g. ${unmapped[0].file}): a schema form that leaks out of its function`);
  if (!now.size) fail(`the schema build failed (exit ${b.status}) and no error maps to a mutant`);
}

// the run shards' binaries: nextest's archive (test binaries, the non-test binaries behind CARGO_BIN_EXE_*, linked paths, build
// metadata), taken while the schema sources are in place (its build is a no-op then: same profile, features and flags)
const arch = path.join(out, 'bins.tar.zst');
const ar = spawnSync('cargo', ['nextest', 'archive', '-p', pkg, '--all-features', '--cargo-profile', 'mutants', '--archive-file', arch], { stdio: 'inherit' });
if (ar.status !== 0) fail('cargo nextest archive failed');
console.error(`archive: ${(fs.statSync(arch).size / 1e6).toFixed(0)} MB`);
restore();
const fromArchive = ['--archive-file', arch, '--workspace-remap', ws];
const ls = spawnSync('cargo', ['nextest', 'list', ...fromArchive, '--list-type', 'binaries-only', '--message-format', 'json'], { encoding: 'utf8', maxBuffer: 1 << 28, stdio: ['ignore', 'pipe', 'inherit'] });
if (ls.status !== 0) fail('cargo nextest list (archive) failed');

// baseline: the schema binaries with no mutant active pass the full suite; every test process records the mutants it reaches
const trace = path.join(T, 'schema-trace');
fs.rmSync(trace, { recursive: true, force: true }); fs.mkdirSync(trace);
const reuse = ['nextest', 'run', ...fromArchive, ...extra];
const blog = path.join(out, 'baseline.log');
const bl = await run(reuse, { PCA_MUTANT: undefined, PCA_SCHEMA_TRACE: trace }, blog);
if (bl.code !== 0) { console.error(fs.readFileSync(blog, 'utf8').slice(-6000)); fail('the schema build with no mutant active fails the suite (a schema form changed behaviour, or the baseline itself fails)'); }
console.error(`baseline (no mutant active, tracing) passed in ${bl.s.toFixed(0)}s`);

const meta = JSON.parse(ls.stdout);
// by file name: the archive extracts to a temporary directory per run (the name carries cargo's hash, unique per binary)
const binOf = new Map(Object.values(meta['rust-binaries']).map((b) => [path.basename(b['binary-path']), b['binary-id']]));
const dur = durations(fs.readFileSync(blog, 'utf8'));
const tests = [...dur.keys()], tix = new Map(tests.map((k, i) => [k, i]));
// no parsed result line would silently send every mutant to the full suite: a format change must fail here instead
if (!tests.length) fail('no PASS lines parsed from the baseline log (nextest output format?)');
const sites = {}, all = new Set();
let unattributed = 0;
for (const f of fs.readdirSync(trace)) {
  const ls2 = fs.readFileSync(path.join(trace, f), 'utf8').split('\n').filter(Boolean);
  if (!ls2.length || !ls2[0].startsWith('#')) continue;
  const args = ls2[0].slice(1).split('\x1f'), x = args.indexOf('--exact');
  const key = x >= 0 ? `${binOf.get(path.basename(args[0])) ?? '?'}\t${args[x + 1]}` : null;
  const ti = key != null ? tix.get(key) : undefined;
  if (ti === undefined) unattributed++;
  for (const l of ls2.slice(1)) {
    const id = Number(l);
    if (ti === undefined) all.add(id);
    else (sites[id] ??= new Set()).add(ti);
  }
}
const reach = { tests: tests.map((k) => [...k.split('\t'), dur.get(k)]), sites: Object.fromEntries(Object.entries(sites).map(([k, v]) => [k, [...v]])), all: [...all] };
fs.writeFileSync(path.join(out, 'reach.json'), JSON.stringify(reach));
const schema = muts.filter((m) => !fallback.has(m.id));
const reached = schema.filter((m) => sites[m.id] || all.has(m.id)).length;
console.error(`reach: ${tests.length} test(s); ${reached} of ${schema.length} schema mutant(s) reached by some test (${all.size} from ${unattributed} process(es) naming no test: those get the full suite)`);

fs.writeFileSync(path.join(out, 'meta.json'), JSON.stringify({ group: g, baseline_s: bl.s, mutants: muts.map((m) => ({ id: m.id, kind: m.kind, name: m.name, file: m.file, fn: m.fn, desc: m.desc, st: fallback.has(m.id) ? 'fallback' : 'schema', ...(fallback.has(m.id) ? { why: fallback.get(m.id) } : {}) })) }));
fs.writeFileSync(path.join(out, 'dec.json'), JSON.stringify({ group: g, runs: G.runs, fallback: muts.filter((m) => fallback.has(m.id)).map((m) => ({ name: m.name, kind: m.kind, why: fallback.get(m.id) })), schema: schema.map((m) => m.name) }));
const why = {}; for (const w of fallback.values()) why[w] = (why[w] ?? 0) + 1;
console.error(`group ${g}: ${schema.length} mutant(s) in the schema, ${fallback.size} fallback (real per-mutant build): ${JSON.stringify(why)}`);
