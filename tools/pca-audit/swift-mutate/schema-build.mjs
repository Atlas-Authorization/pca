#!/usr/bin/env node
// One schema group of the Swift mutation workflow: writes the group's mutants into the restored baseline tree behind the runtime switch
// (schema.mjs), builds the package and its tests ONCE, then runs every test class of the oracle targets in a process of its own with no
// mutant active (the baseline: every class must pass) while each process records which switches it reaches.
//   node schema-build.mjs --list=<group list: mutate.mjs schema-plan --group --list> --group=<g> --tree=<w0>/sdks/swift-pca
//                         --pkg=<pristine sdks/swift-pca> --adv=<adv.json> --out=<dir> [--trace-workers=4] [--rounds=6]
// A mutant the generator cannot hold, or whose schema text the compiler rejects (errors map back to the mutant's line, else to the
// innermost enclosing block that holds mutants, else the whole file; the build is retried without them), is a FALLBACK: decided later by
// a real per-mutant build, never dropped. An error in a file the schema does not rewrite fails the job.
// Writes <out>/meta.json (every mutant: id, key, schema or fallback + why), <out>/reach.json (classes [target, class, seconds], the classes
// reaching each mutant, `unattributed`: mutants reached by a process that names no class, which skip straight to the full suite).
import fs from 'node:fs';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { schemaFile, switchSource, blameIds } from './schema.mjs';

const opt = (n, d) => process.argv.slice(2).find((a) => a.startsWith(`--${n}=`))?.slice(n.length + 3) ?? d;
const fail = (m) => { console.error(`::error::${m}`); process.exit(1); };
const list = JSON.parse(fs.readFileSync(opt('list'), 'utf8')), g = Number(opt('group'));
const tree = path.resolve(opt('tree')), pkg = path.resolve(opt('pkg')), out = path.resolve(opt('out')), adv = path.resolve(opt('adv'));
const TW = Number(opt('trace-workers', '4')), ROUNDS = Number(opt('rounds', '6'));
const t0 = Date.now(), el = () => `${Math.round((Date.now() - t0) / 1000)} s`;
fs.mkdirSync(out, { recursive: true });
const targetOfFile = (file) => file.includes('/AtlasPCASQLite/') ? 'AtlasPCASQLiteTests' : file.includes('/AtlasPCAStepUp/') ? 'AtlasPCAStepUpTests' : 'AtlasPCAVerifyTests';

// the switch travels in the environment: a child process started with an environment of its own would run unmutated
const ENV_OK = { 'Sources/AtlasPCAVerify/SandboxHost.swift': 'the child is the wasmtime host (Rust), which holds no switch' };
for (const top of ['Sources', 'Tests']) for (const f of fs.readdirSync(path.join(pkg, top), { recursive: true }).map(String).filter((x) => x.endsWith('.swift'))) {
  const rel = `${top}/${f}`;
  if (/^Sources\/(AtlasPCA(VDF|Pairing|Fhe|LweOt|Mpc|MpcNet|FnDsa|Wasm|Ada|OpenSSL|Less|DkgNet|Zk)|pca-mpc-party)\//.test(rel) || /^Tests\/(?!AtlasPCA(Verify|SQLite|StepUp)Tests\/)/.test(rel)) continue;
  if (/\.environment\s*=\s*\[/.test(fs.readFileSync(path.join(pkg, rel), 'utf8')) && !ENV_OK[rel]) fail(`${rel} starts a child process with an environment of its own: the schema switch (PCA_MUTANT) would not reach it`);
}

const files = [...new Set(list.map((m) => m.file))];
const maxId = list.reduce((a, m) => Math.max(a, m.id), 0);
const fallback = new Map(); // id -> why
let held = new Map(); // file -> Map(id -> line)
const SWITCH = '_PcaMutSchema.swift';
const modOf = (f) => f.split('/').slice(0, 2).join('/');
function write() {
  held = new Map();
  const mods = new Set();
  for (const f of files) {
    const src = fs.readFileSync(path.join(pkg, f), 'utf8');
    const r = schemaFile(src, list.filter((m) => m.file === f && !fallback.has(m.id)));
    for (const [id, why] of r.fallback) fallback.set(id, why);
    held.set(f, r.held);
    if (r.held.size) mods.add(modOf(f));
    fs.writeFileSync(path.join(tree, f), r.text);
  }
  for (const d of fs.readdirSync(path.join(tree, 'Sources'))) {
    const p = path.join(tree, 'Sources', d, SWITCH);
    if (mods.has(`Sources/${d}`)) fs.writeFileSync(p, switchSource(maxId)); else fs.rmSync(p, { force: true });
  }
}
const flags = process.env.SWIFT_TEST_FLAGS ? process.env.SWIFT_TEST_FLAGS.split(/\s+/) : [];
for (let round = 1; ; round++) {
  if (round > ROUNDS) fail(`the schema build still fails after ${ROUNDS} rounds`);
  write();
  const b = spawnSync('nice', ['-n', '19', 'swift', 'build', '--build-tests', ...flags, '--scratch-path', path.join(tree, '.b'), '-Xswiftc', '-continue-building-after-errors'],
    { cwd: tree, encoding: 'utf8', maxBuffer: 1 << 30, stdio: ['ignore', 'pipe', 'pipe'] });
  const log = (b.stdout || '') + (b.stderr || '');
  fs.writeFileSync(path.join(out, `build-${round}.log`), log);
  const errs = [...log.matchAll(/^(\/[^:\n]+\.swift):(\d+):\d+: error: (.*)$/gm)].map((x) => ({ file: path.relative(tree, x[1]), line: +x[2], msg: x[3] }));
  const nHeld = [...held.values()].reduce((a, h) => a + h.size, 0);
  console.error(`round ${round}: build ${b.status === 0 ? 'ok' : `failed (${errs.length} error line(s))`} at ${el()}; ${nHeld} held, ${fallback.size} fallback`);
  if (b.status === 0) break;
  const unmapped = errs.filter((e) => !held.has(e.file));
  for (const e of unmapped.slice(0, 10)) console.error(`  ${e.file}:${e.line}: ${e.msg}`);
  if (unmapped.length) fail(`${unmapped.length} build error(s) outside the rewritten files (e.g. ${unmapped[0].file}:${unmapped[0].line}: ${unmapped[0].msg})`);
  if (!errs.length) { console.error(log.slice(-6000)); fail(`the schema build failed (exit ${b.status}) and no error names a source line`); }
  let moved = 0;
  for (const e of errs) {
    const h = held.get(e.file);
    if (!h.size) continue;
    const { ids, how } = blameIds(fs.readFileSync(path.join(pkg, e.file), 'utf8'), h, e.line);
    for (const id of ids) if (!fallback.has(id)) { fallback.set(id, `schema build (${how}): ${e.msg.slice(0, 80)}`); h.delete(id); moved++; }
  }
  if (!moved) fail('the schema build failed and its errors blame no held mutant');
}
const schemaIds = new Set(list.filter((m) => !fallback.has(m.id)).map((m) => m.id));

// ---- trace: every class of the oracle targets, one process each, no mutant active ----
const targets = [...new Set(files.map(targetOfFile))];
const ls = spawnSync('swift', ['test', 'list', '--skip-build', ...flags, '--scratch-path', path.join(tree, '.b')], { cwd: tree, encoding: 'utf8', maxBuffer: 1 << 28 });
if (ls.status !== 0) fail(`swift test list failed: ${(ls.stderr || '').slice(-2000)}`);
const classes = [...new Set(ls.stdout.split('\n').map((l) => /^(\w+)\.(\w+)\/\w+$/.exec(l.trim())).filter((x) => x && targets.includes(x[1])).map((x) => `${x[1]}.${x[2]}`))].sort();
if (!classes.length) fail(`no test class listed for ${targets.join(', ')}`);
console.error(`trace: ${classes.length} class(es) of ${targets.join(', ')}, ${TW} at a time, at ${el()}`);
const wroot = path.dirname(path.dirname(tree)), copies = [tree];
for (let k = 1; k < TW; k++) {
  const c = path.join(path.dirname(wroot), `trace${k}`);
  fs.rmSync(c, { recursive: true, force: true });
  if (spawnSync('cp', ['-al', wroot, c]).status !== 0) fail('copying the tree for the trace failed');
  copies.push(path.join(c, path.relative(wroot, tree)));
}
for (const c of copies) fs.rmSync(path.join(c, '.b', '.lock'), { force: true });
const traceDir = path.join(out, 'trace'); fs.mkdirSync(traceDir, { recursive: true });
const env = { ...process.env, PCA_CONFORMANCE_ADV: adv };
for (const k of ['PCA_MUTANT', 'SWIFTMUT_FILE', 'SWIFTMUT_FILTER']) delete env[k];
const runClass = (dir, cls, i) => new Promise((res) => {
  const tf = path.join(traceDir, `${i}.txt`);
  fs.writeFileSync(tf, '');
  const [t, c] = cls.split('.'), st = Date.now();
  const p = spawn('nice', ['-n', '19', 'swift', 'test', '--skip-build', ...flags, '--scratch-path', path.join(dir, '.b'), '--filter', `^${t}\\.${c}/`],
    { cwd: dir, env: { ...env, PCA_SCHEMA_TRACE: tf }, stdio: ['ignore', 'pipe', 'pipe'], detached: true });
  let o = ''; const add = (d) => { if (o.length < 8 << 20) o += d; };
  p.stdout.on('data', add); p.stderr.on('data', add);
  const to = setTimeout(() => { try { process.kill(-p.pid, 'SIGKILL'); } catch {} }, 1800_000);
  p.on('close', (code) => {
    clearTimeout(to);
    const passed = [...o.matchAll(/Test Case '([^']+)' passed \(([\d.]+) seconds\)/g)].reduce((a, x) => a + Number(x[2]), 0);
    const failed = /: error: (-\[[\w.]+ \w+\]|[\w.]+\.\w+) : /m.test(o);
    res({ cls, i, code, failed, s: passed, wall: (Date.now() - st) / 1000, tail: o.slice(-3000) });
  });
});
const results = [];
let next = 0;
await Promise.all(copies.map(async (dir) => { while (next < classes.length) { const i = next++; results.push(await runClass(dir, classes[i], i)); } }));
for (let k = 1; k < copies.length; k++) fs.rmSync(path.join(path.dirname(wroot), `trace${k}`), { recursive: true, force: true });
const bad = results.filter((r) => r.code !== 0 || r.failed);
for (const r of bad.slice(0, 5)) console.error(`baseline FAILED: ${r.cls} (exit ${r.code})\n${r.tail}`);
if (bad.length) fail(`${bad.length} class(es) fail with no mutant active: a schema form changed behaviour, or the baseline itself fails`);
results.sort((a, b) => a.i - b.i);
const sites = {};
for (const r of results) for (const l of fs.readFileSync(path.join(traceDir, `${r.i}.txt`), 'utf8').split('\n')) {
  const id = Number(l); if (!l || !schemaIds.has(id)) continue;
  (sites[id] ??= []).includes(r.i) || sites[id].push(r.i);
}
fs.rmSync(traceDir, { recursive: true, force: true });
const reach = { classes: results.map((r) => [...r.cls.split('.'), Math.max(r.s, 0.1)]), sites, unattributed: [] };
fs.writeFileSync(path.join(out, 'reach.json'), JSON.stringify(reach));
const meta = { group: g, maxId, trace_s: results.reduce((a, r) => a + r.wall, 0), mutants: list.map((m) => ({ id: m.id, key: m.key, file: m.file, line: m.line, op: m.op, st: fallback.has(m.id) ? 'fallback' : 'schema', ...(fallback.has(m.id) ? { why: fallback.get(m.id) } : {}) })) };
fs.writeFileSync(path.join(out, 'meta.json'), JSON.stringify(meta));
const why = {}; for (const w of fallback.values()) { const k = w.replace(/: .*/, ''); why[k] = (why[k] ?? 0) + 1; }
const reached = [...schemaIds].filter((id) => sites[id]).length;
console.error(`group ${g}: ${schemaIds.size} mutant(s) in the schema (${reached} reached by some class), ${fallback.size} fallback ${JSON.stringify(why)}; done at ${el()}`);
