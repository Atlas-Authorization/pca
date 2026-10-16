#!/usr/bin/env node
// PCA cross-language conformance: ONE entry point that runs EVERY available language verifier over the SAME
// adversarial/malformed corpus (+ regression vectors + a seeded mutation fuzz), prints a vector x language matrix and
// exits non-zero on ANY cross-language disagreement, crash, hang or reference-vs-intent finding that is not waived in
// packages/pca-conformance/adversarial/known-differences.json.
//
//   node scripts/pca-conformance-all.mjs [options]        (wrapper: scripts/pca-conformance-all.sh)
//     --fuzz N          mutation-fuzz iterations (default 600; 0 disables)
//     --sweep N         structural path-sweep mutants (default 6000; needs --fuzz > 0)
//     --seed N          fuzz seed (default 20261008)
//     --langs a,b       restrict implementations (go,python,ruby,php,dotnet,rust,java,kotlin,swift)
//     --require a,b     fail if any of these did not run (CI passes all of them: no silent green)
//     --budget-ms N     per-vector time budget; a vector exceeding it is a HANG (default 15000)
//     --no-native       skip the per-language native conformance suites (go test, unittest, ...)
//     --out DIR         scratch/report dir (default $TMPDIR/pca-conformance-all)
//     --write-matrix    refresh packages/pca-conformance/adversarial/MATRIX.md from this run
//     --strict          also fail on error-vs-clean-reject (soft) differences
//     --no-minimize     do not minimise/commit fuzz disagreements
// Toolchains that are not installed are reported SKIPPED (never passed). TypeScript is the reference/oracle.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync, statSync } from 'node:fs';
import { homedir, tmpdir, loadavg, cpus } from 'node:os';
import { join, dirname, delimiter } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';
import { LEGACY_SUITES, REGISTERED_SUITES, SUITES_QUERY, judgeSuite, manifestOf } from '../tools/pca-diff-fuzz/suites.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const ADV = join(ROOT, 'packages/pca-conformance/adversarial');
const DRV = join(ROOT, 'tools/pca-diff-fuzz/drivers');
const TSX = join(ROOT, 'packages/pca/node_modules/.bin/tsx');
const argv = process.argv.slice(2);
const opt = (k, d) => { const i = argv.indexOf(k); return i >= 0 ? argv[i + 1] : d; };
const flag = (k) => argv.includes(k);
const FUZZ_N = Number(opt('--fuzz', 600));
const SEED = Number(opt('--seed', 20261008));
const SWEEP_N = Number(opt('--sweep', 6000));
const BUDGET = Number(opt('--budget-ms', 15000));
const OUT = opt('--out', process.env.PCA_CONF_OUT ?? join(tmpdir(), 'pca-conformance-all'));
const WANT = (opt('--langs', '') || '').split(',').filter(Boolean);
const REQUIRE = (opt('--require', '') || '').split(',').filter(Boolean);
const STRICT = flag('--strict');
const WORK = join(OUT, 'work');
rmSync(WORK, { recursive: true, force: true });
mkdirSync(WORK, { recursive: true });
process.env.PATH = [join(homedir(), '.cargo/bin'), '/usr/local/bin', process.env.PATH, join(homedir(), 'swift/usr/bin')].join(delimiter);

const log = (...a) => console.log(...a);
const run = (cmd, args, o = {}) => spawnSync(cmd, args, { encoding: 'utf8', maxBuffer: 1 << 28, ...o });
const have = (cmd, args = ['--version']) => { const r = run(cmd, args, { timeout: 20000 }); return !r.error && r.status === 0; };
const CHECK_ORDER = ['wire', 'version', 'audience', 'validity', 'chain', 'grant_ref_bound', 'plan_inclusion', 'leaf_signature', 'counter', 'intent'];

// ------------------------------------------------------------------ implementations
/** @type {{name:string, prep:()=>string|null, cmd:(i:string,o:string)=>string[]}[]} */
const IMPLS = [];
function impl(name, prep, cmd) { IMPLS.push({ name, prep, cmd }); }

impl('go', () => {
  if (!have('go', ['version'])) return 'go not installed';
  // `-tags less`: the LESS suites through cgo and the patched reference C (sdks/pca-less-c); without cgo the build is pure Go
  // and its manifest leaves LESS out (refused as unsupported_suite).
  const r = run('go', ['build', '-tags', 'less', '-o', join(OUT, 'go-driver'), '.'], { cwd: join(DRV, 'go') });
  return r.status === 0 ? null : 'go build failed: ' + (r.stderr || '').slice(0, 300);
}, (i, o) => [join(OUT, 'go-driver'), i, o]);
// LESS: the patched reference C (sdks/pca-less-c) as the shared library libatlas_less, built once and named in
// ATLAS_PCA_LIBLESS for every FFI backend (Python ctypes, Ruby Fiddle, PHP FFI, .NET P/Invoke, Java / Kotlin FFM). Without a C
// compiler those languages' manifests simply leave LESS out (refused as unsupported_suite).
let LESS_LIB = null;
function lessLib() {
  if (LESS_LIB !== null) return LESS_LIB;
  const l = run('bash', [join(ROOT, 'sdks/pca-less-c/build.sh'), join(OUT, 'less-lib')], { timeout: 300000 });
  LESS_LIB = l.status === 0 ? (l.stdout || '').trim().split('\n').pop() : '';
  if (LESS_LIB) process.env.ATLAS_PCA_LIBLESS = LESS_LIB;
  else log('  LESS library not built (LESS suites refused by the FFI backends): ' + (l.stderr || '').slice(-160).replace(/\s+/g, ' '));
  return LESS_LIB;
}
impl('python', () => {
  if (!have('python3', ['-V'])) return 'python3 not installed';
  lessLib();
  return null;
}, (i, o) => ['python3', '-I', join(DRV, 'python/driver.py'), i, o]);
impl('ruby', () => { if (!have('ruby', ['-v'])) return 'ruby not installed'; lessLib(); return null; }, (i, o) => ['ruby', join(DRV, 'ruby/driver.rb'), i, o]);
impl('php', () => {
  if (!have('php', ['-v'])) return 'php not installed';
  lessLib();
  return run('php', ['-r', 'exit(extension_loaded("sodium")?0:1);']).status === 0 ? null : 'php sodium extension missing';
}, (i, o) => ['php', join(DRV, 'php/driver.php'), i, o]);
impl('dotnet', () => {
  if (!have('dotnet', ['--version'])) return 'dotnet not installed';
  lessLib();
  const r = run('dotnet', ['build', '-c', 'Release', '-o', join(OUT, 'dotnet-bin'), '-v', 'q', '--nologo'], { cwd: join(DRV, 'dotnet'), timeout: 600000 });
  return r.status === 0 ? null : 'dotnet build failed: ' + ((r.stdout || '') + (r.stderr || '')).slice(0, 300);
}, (i, o) => ['dotnet', join(OUT, 'dotnet-bin/Driver.dll'), i, o]);
impl('rust', () => {
  if (!have('cargo', ['--version'])) return 'cargo not installed';
  const r = run('cargo', ['build', '--release'], { cwd: join(DRV, 'rust'), env: { ...process.env, CARGO_TARGET_DIR: join(OUT, 'rust-target') }, timeout: 1200000 });
  return r.status === 0 ? null : 'cargo build failed: ' + (r.stderr || '').slice(-300);
}, (i, o) => [join(OUT, 'rust-target/release/pcadriver'), i, o]);

// --selftest-faults: a fake implementation that HANGS on one vector and CRASHES on another, proving the time-budget
// bisection isolates them (and that the gate fails on them) instead of hanging the whole run.
if (flag('--selftest-faults')) {
  const code = "import sys,json,time,os\nfor l in open(sys.argv[1]):\n c=json.loads(l)\n if c['id']=='adv0010': time.sleep(600)\n if c['id']=='adv0020': os._exit(139)\n open(sys.argv[2],'a').write(json.dumps({'id':c['id'],'error':'x'})+'\\n')";
  impl('selftest', () => null, (i, o) => ['python3', '-c', code, i, o]);
}
const JAVA = findJava();
function findJava() {
  const homes = [process.env.JAVA_HOME, ...['/opt/homebrew/opt/openjdk', '/opt/homebrew/opt/openjdk@21', '/opt/homebrew/opt/openjdk@17', '/usr/lib/jvm/default-java'].map((p) => (existsSync(join(p, 'libexec/openjdk.jdk/Contents/Home')) ? join(p, 'libexec/openjdk.jdk/Contents/Home') : p))].filter(Boolean);
  const cands = [...homes.map((h) => join(h, 'bin')), ''];
  for (const bin of cands) {
    const javac = bin ? join(bin, 'javac') : 'javac', java = bin ? join(bin, 'java') : 'java';
    if (have(javac, ['-version']) && have(java, ['-version'])) return { javac, java };
  }
  return null;
}
function findBc() {
  if (process.env.PCA_BC_JAR && existsSync(process.env.PCA_BC_JAR)) return process.env.PCA_BC_JAR;
  const roots = [join(homedir(), '.m2/repository/org/bouncycastle/bcprov-jdk18on'), join(homedir(), '.gradle/caches/modules-2/files-2.1/org.bouncycastle/bcprov-jdk18on'), join(homedir(), 'Library/Android/sdk/cmdline-tools/latest/lib/external/org/bouncycastle/bcprov-jdk18on')];
  const jars = [];
  const walk = (d, depth) => { if (depth > 4 || !existsSync(d)) return; for (const e of readdirSync(d)) { const p = join(d, e); let st; try { st = statSync(p); } catch { continue; } if (st.isDirectory()) walk(p, depth + 1); else if (/^bcprov-jdk18on-[\d.]+\.jar$/.test(e)) jars.push(p); } };
  roots.forEach((r) => walk(r, 0));
  const ver = (p) => p.match(/bcprov-jdk18on-([\d.]+)\.jar/)[1].split('.').map(Number);
  jars.sort((a, b) => { const x = ver(a), y = ver(b); for (let i = 0; i < 4; i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (y[i] ?? 0) - (x[i] ?? 0); return 0; });
  return jars[0] ?? null;
}
const BC = JAVA ? findBc() : null;
impl('java', () => {
  if (!JAVA) return 'no working JDK (javac)';
  lessLib();
  if (!BC) return 'bcprov-jdk18on jar not found (set PCA_BC_JAR)';
  const d = join(OUT, 'java-classes');
  mkdirSync(d, { recursive: true });
  const srcs = readdirSync(join(ROOT, 'sdks/java-pca/src/net/atlasauth/pca')).filter((f) => f.endsWith('.java')).map((f) => join(ROOT, 'sdks/java-pca/src/net/atlasauth/pca', f));
  const r = run(JAVA.javac, ['-cp', BC, '-d', d, ...srcs, join(DRV, 'java/Driver.java')]);
  return r.status === 0 ? null : 'javac failed: ' + (r.stderr || '').slice(0, 300);
}, (i, o) => [JAVA.java, '-Xss4m', '--enable-native-access=ALL-UNNAMED', '-cp', `${join(OUT, 'java-classes')}${delimiter}${BC}`, 'Driver', i, o]);
let KOTLIN_TC = null;
impl('kotlin', () => {
  const tc = kotlinToolchain();
  if (tc.skip) return tc.skip;
  KOTLIN_TC = tc;
  lessLib();
  return kotlinCompile(tc, join(OUT, 'kotlin-driver-classes'), [join(DRV, 'kotlin/Driver.kt')]);
}, (i, o) => [JAVA.java, '-Xss4m', '--enable-native-access=ALL-UNNAMED', '-cp', [join(OUT, 'kotlin-driver-classes'), KOTLIN_TC.stdlib, KOTLIN_TC.bc].join(delimiter), 'DriverKt', i, o]);
// Swift: macOS builds the driver package against sdks/swift-pca as is (CryptoKit); Linux against the patched copy that
// swiftLinuxTree() lays out (swift-crypto + liboqs ML-DSA), at the same relative path. Release, with testability on (the driver
// reaches the verifier's internal strict parser / canonicalizer / chain verifier through @testable import).
impl('swift', () => {
  if (!have('swift', ['--version'])) return 'no swift toolchain';
  let pkg = join(DRV, 'swift');
  if (process.platform !== 'darwin') {
    const t = swiftLinuxTree();
    if (t.fail) return t.fail;
    pkg = join(t.root, 'tools/pca-diff-fuzz/drivers/swift');
    rmSync(pkg, { recursive: true, force: true });
    mkdirSync(pkg, { recursive: true });
    for (const d of ['Sources', 'Package.swift']) run('cp', ['-R', join(DRV, 'swift', d), pkg]);
  }
  const r = run('swift', ['build', '-c', 'release', '-Xswiftc', '-enable-testing', '--scratch-path', join(OUT, 'swift-driver-build')], { cwd: pkg, timeout: 1800000 });
  return r.status === 0 ? null : 'swift build failed: ' + ((r.stdout || '') + (r.stderr || '')).slice(-300).replace(/\s+/g, ' ');
}, (i, o) => [join(OUT, 'swift-driver-build/release/pcadriver'), i, o]);

// ------------------------------------------------------------------ driver execution with per-vector time budget
const lineOf = (c) => JSON.stringify({ id: c.id, kind: c.kind, raw: c.raw, grant: c.grant, now: c.now, aud: c.aud, ...(c.allowed_suites !== undefined ? { allowed_suites: c.allowed_suites } : {}), ...(c.intent_policy !== undefined ? { intent_policy: c.intent_policy } : {}), ...(c.intent_policy_json !== undefined ? { intent_policy_json: c.intent_policy_json } : {}), ...(c.intent_v2 !== undefined ? { intent_v2: c.intent_v2 } : {}) });
let seq = 0;
function execOnce(argvFn, items, timeoutMs) {
  const inp = join(WORK, `in-${++seq}.jsonl`), outp = join(WORK, `out-${seq}.jsonl`);
  writeFileSync(inp, items.map(lineOf).join('\n') + '\n');
  const [cmd, ...args] = argvFn(inp, outp);
  const t0 = Date.now();
  const r = run(cmd, args, { timeout: timeoutMs, killSignal: 'SIGKILL', cwd: ROOT });
  const res = new Map();
  if (existsSync(outp)) for (const l of readFileSync(outp, 'utf8').split('\n')) { if (!l) continue; try { const o = JSON.parse(l); res.set(o.id, o); } catch { /* torn last line */ } }
  rmSync(inp, { force: true }); rmSync(outp, { force: true });
  const timedOut = r.error?.code === 'ETIMEDOUT' || r.signal === 'SIGKILL';
  return { res, timedOut, status: r.status, ms: Date.now() - t0, stderr: (r.stderr || '').slice(-300) };
}
/** Resolve every item to a result; vectors that hang / crash the driver are isolated by bisection and marked. */
function resolve(argvFn, items, label) {
  const results = new Map();
  const timeoutFor = (n) => BUDGET + n * 100;
  const go = (batch, top) => {
    if (!batch.length) return;
    const r = execOnce(argvFn, batch, batch.length === 1 ? BUDGET : timeoutFor(batch.length));
    for (const [k, v] of r.res) if (!results.has(k)) results.set(k, v);
    const missing = batch.filter((c) => !r.res.has(c.id));
    if (!missing.length && !r.timedOut && r.status === 0) return;
    if (!missing.length) return; // nonzero exit but all answered
    if (missing.length === 1 && (batch.length === 1 || r.res.size > 0 || missing.length === batch.length)) {
      if (batch.length > 1) { go(missing, false); return; }
      results.set(missing[0].id, { id: missing[0].id, marker: r.timedOut ? 'HANG' : 'CRASH', detail: r.timedOut ? `exceeded ${BUDGET}ms budget` : `exit ${r.status}: ${r.stderr.replace(/\s+/g, ' ').trim()}` });
      return;
    }
    const mid = missing.length >> 1;
    go(missing.slice(0, mid), false); go(missing.slice(mid), false);
  };
  for (let i = 0; i < items.length; i += 200) go(items.slice(i, i + 200), false);
  void label;
  return results;
}

// ------------------------------------------------------------------ corpus
const sha = (s) => createHash('sha256').update(s).digest('hex');
function readJsonl(p) { return readFileSync(p, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)); }

function genCorpus() {
  const corpus = join(OUT, 'adversarial-corpus.jsonl');
  const regen = join(OUT, 'manifest.regen.jsonl');
  const r = run(TSX, [join(ADV, 'gen-adversarial.ts'), '--corpus', corpus, '--out', regen], { cwd: ROOT, timeout: 300000 });
  if (r.status !== 0) { console.error('generator failed:\n' + r.stdout + r.stderr); process.exit(2); }
  const committed = existsSync(join(ADV, 'manifest.jsonl')) ? readFileSync(join(ADV, 'manifest.jsonl'), 'utf8') : '';
  const drift = committed !== readFileSync(regen, 'utf8');
  return { items: readJsonl(corpus), drift, refSource: /using packages\/pca\/dist/.test(r.stderr) ? 'dist (source tree not loadable)' : 'src' };
}

function loadRegressions() {
  const d = join(ADV, 'regressions');
  if (!existsSync(d)) return [];
  return readdirSync(d).filter((f) => f.endsWith('.json')).sort().map((f) => {
    const j = JSON.parse(readFileSync(join(d, f), 'utf8'));
    return { id: 'reg-' + f.replace(/\.json$/, ''), category: 'regression', name: j.name ?? f, intent: 'either', kind: j.kind, raw: j.raw, grant: j.grant ?? '', now: j.now, aud: j.aud };
  });
}

function genDos() {
  const f = join(OUT, 'dos.jsonl');
  const r = run('node', [join(DRV, '../gen/dos.mjs'), f], { cwd: ROOT, timeout: 300000 });
  if (r.status !== 0) { console.error('dos generator failed:\n' + r.stdout + r.stderr); process.exit(2); }
  return readJsonl(f).map((v) => ({ ...v, name: v.name, intent: v.expect }));
}

// ------------------------------------------------------------------ mutation fuzzer (seeded, bounded)
function mulberry32(a) { return () => { a |= 0; a = (a + 0x6d2b79f5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
const TOKENS = ['"', '\\', '{', '}', '[', ']', ',', ':', 'null', 'true', '-0', '1e400', '9007199254740993', '1.0', '\u0000', '​', '﻿', '//', '/*', '*/', '"__proto__":{}', '\\u0000', '\\ud800', '=', ' ', '\n', 'é', 'é', '\u{1F600}', '+', '-', '_', '0', 'NaN', 'Infinity', '\\/', '\\"', '"a":1,"a":2'];
const EDGE_VALS = [null, true, false, 0, -1, 1, 2, 9007199254740991, '', 'x', [], {}, 'A'.repeat(86), 'A'.repeat(43), '=', '\u0000', 'é'];
function fuzzer(seed) {
  const rnd = mulberry32(seed);
  const int = (n) => Math.floor(rnd() * n);
  const pick = (a) => a[int(a.length)];
  const textOps = [
    (s) => { const i = int(s.length); return s.slice(0, i) + pick(TOKENS).slice(0, 1) + s.slice(i + 1); },
    (s) => { const i = int(s.length), n = 1 + int(8); return s.slice(0, i) + s.slice(i + n); },
    (s) => { const i = int(s.length + 1); return s.slice(0, i) + pick(TOKENS) + s.slice(i); },
    (s) => { const i = int(s.length), n = 1 + int(40); return s.slice(0, i) + s.slice(i, i + n) + s.slice(i); },
    (s) => s.slice(0, int(s.length)),
    (s) => { const i = int(Math.max(1, s.length - 1)); return s.slice(0, i) + s[i + 1] + s[i] + s.slice(i + 2); },
    (s) => { const i = int(s.length), c = s[i] ?? ''; return s.slice(0, i) + (c === c.toUpperCase() ? c.toLowerCase() : c.toUpperCase()) + s.slice(i + 1); },
    (s) => s.replace(/[,:]/, (m) => ` ${m}\n`),
    (s) => s + pick(['', ' ', '\n', 'x', ',', '}', '\0']),
  ];
  const walk = (o, path = []) => { const out = []; if (o && typeof o === 'object') for (const k of Object.keys(o)) { out.push([...path, k]); out.push(...walk(o[k], [...path, k])); } return out; };
  const structOps = [
    (o) => { const ps = walk(o); const p = pick(ps); const par = p.slice(0, -1).reduce((a, k) => a[k], o); if (Array.isArray(par)) par.splice(Number(p.at(-1)), 1); else delete par[p.at(-1)]; },
    (o) => { const ps = walk(o); const p = pick(ps); const par = p.slice(0, -1).reduce((a, k) => a[k], o); par[p.at(-1)] = pick(EDGE_VALS); },
    (o) => { const ps = walk(o).filter((p) => { let v = o; for (const k of p) v = v[k]; return typeof v === 'string' && v.length > 20; }); if (!ps.length) return; const p = pick(ps); const par = p.slice(0, -1).reduce((a, k) => a[k], o); const s = par[p.at(-1)]; const i = int(s.length); par[p.at(-1)] = pick([s + '=', ' ' + s, s.slice(0, i) + (s[i] === 'A' ? 'B' : 'A') + s.slice(i + 1), s.slice(0, -1), s + 'A', s.replace(/[-_]/, '+')]); },
    (o) => { o[pick(['__proto__', 'constructor', 'extra', 'alg', 'pq_sig', 'sig2'])] = pick(EDGE_VALS); },
    (o) => { const ps = walk(o).filter((p) => { let v = o; for (const k of p) v = v[k]; return Array.isArray(v) && v.length; }); if (!ps.length) return; const p = pick(ps); let v = o; for (const k of p) v = v[k]; v.push(v[int(v.length)]); },
    (o) => { const ps = walk(o).filter((p) => { let v = o; for (const k of p) v = v[k]; return typeof v === 'number'; }); if (!ps.length) return; const p = pick(ps); const par = p.slice(0, -1).reduce((a, k) => a[k], o); par[p.at(-1)] += pick([1, -1, 60000, -60000, 3600000]); },
  ];
  const formatOps = [(o) => JSON.stringify(o, null, int(4) + 1), (o) => JSON.stringify(Object.fromEntries(Object.entries(o).reverse())), (o) => JSON.stringify(o).replace(/:/g, ' : ').replace(/,/g, ' ,\n')];
  return function mutate(seedItem) {
    let raw = seedItem.raw;
    const trail = [];
    const nOps = 1 + int(3);
    for (let k = 0; k < nOps; k++) {
      const choice = rnd();
      if (seedItem.kind === 'verify' && choice < 0.45) {
        let o; try { o = JSON.parse(raw); } catch { o = null; }
        if (o && typeof o === 'object' && !Array.isArray(o)) {
          if (rnd() < 0.2) { const f = int(formatOps.length); raw = formatOps[f](o); trail.push('fmt' + f); } else { const f = int(structOps.length); try { structOps[f](o); raw = JSON.stringify(o); trail.push('struct' + f); } catch { /* skip */ } }
          continue;
        }
      }
      const f = int(textOps.length);
      if (raw.length > 0) { raw = textOps[f](raw); trail.push('text' + f); }
    }
    return { raw, trail: trail.join('+') };
  };
}
function makeFuzz(n, seed, adv) {
  const seeds = adv.filter((c) => c.ref && (c.kind === 'verify' ? c.ref.allow === true : c.ref.canon !== undefined) && c.raw.length < 30000 && ['control', 'golden', 'golden-json', 'key-order', 'number', 'unicode', 'base64', 'plan-commit', 'attenuation', 'epoch'].includes(c.category));
  const mutate = fuzzer(seed);
  const rnd = mulberry32(seed ^ 0x5bd1e995);
  const out = [];
  for (let i = 0; i < n; i++) {
    const s = seeds[Math.floor(rnd() * seeds.length)];
    const m = mutate(s);
    // lone UTF-16 surrogates cannot cross the UTF-8/JSON-lines transport (PHP/.NET reject the corpus line itself); the
    // escaped forms (\\ud800 text) are covered by the adversarial corpus, so neutralise raw ones here.
    m.raw = m.raw.replace(/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g, '\ufffd');
    out.push({ id: `fz${seed}-${String(i).padStart(5, '0')}`, category: 'fuzz', name: `${s.category}/${s.name}~${m.trail}`, intent: 'either', kind: s.kind, raw: m.raw, grant: s.grant, now: s.now, aud: s.aud, allowed_suites: s.allowed_suites, intent_policy: s.intent_policy, intent_policy_json: s.intent_policy_json, intent_v2: s.intent_v2, seedId: s.id });
  }
  return out;
}

/** Deterministic structural sweep: for each distinct-SHAPE valid seed, hit EVERY path (container and leaf) with a fixed
 *  battery of replacements. Random mutation rarely lands on one specific container (e.g. `threshold.shares`), the sweep does. */
function makeSweep(max, adv) {
  const valid = adv.filter((c) => c.kind === 'verify' && c.ref && c.ref.allow === true && c.raw.length < 30000);
  const paths = (o, pre = []) => { const out = []; if (o && typeof o === 'object') for (const k of Object.keys(o)) { out.push([...pre, k]); out.push(...paths(o[k], [...pre, k])); } return out; };
  const shapes = new Set();
  const seeds = [];
  for (const c of valid) {
    let o; try { o = JSON.parse(c.raw); } catch { continue; }
    const sig = paths(o).map((p) => p.map((k) => (/^\d+$/.test(k) ? '#' : k)).join('/')).sort().join('|');
    if (!shapes.has(sig)) { shapes.add(sig); seeds.push([c, o]); }
  }
  const battery = [(par, k) => { if (Array.isArray(par)) par.splice(Number(k), 1); else delete par[k]; }, (par, k) => { par[k] = null; }, (par, k) => { par[k] = {}; }, (par, k) => { par[k] = []; }, (par, k) => { par[k] = ''; }, (par, k) => { par[k] = 0; }, (par, k) => { par[k] = 'x'; }, (par, k) => { par[k] = [par[k]]; }, (par, k) => { par[k] = true; }];
  const out = [];
  for (const [c, o0] of seeds) {
    for (const p of paths(o0)) {
      for (const [bi, op] of battery.entries()) {
        if (out.length >= max) return out;
        const o = JSON.parse(c.raw);
        const par = p.slice(0, -1).reduce((a, k) => a[k], o);
        op(par, p.at(-1));
        out.push({ id: `sw-${String(out.length).padStart(5, '0')}`, category: 'sweep', name: `${c.name}@${p.join('.')}#${bi}`, intent: 'either', kind: 'verify', raw: JSON.stringify(o), grant: c.grant, now: c.now, aud: c.aud, allowed_suites: c.allowed_suites, intent_policy: c.intent_policy, intent_policy_json: c.intent_policy_json, intent_v2: c.intent_v2 });
      }
    }
  }
  return out;
}

// ------------------------------------------------------------------ verdict normalisation + comparison
function norm(r, kind) {
  if (!r) return { cls: 'FAULT', key: '!MISSING', full: '!MISSING', allow: false, tag: 'MISSING' };
  if (r.marker) return { cls: 'FAULT', key: '!' + r.marker, full: '!' + r.marker, allow: false, tag: r.marker, detail: r.detail };
  if (r.error !== undefined) return { cls: 'ERR', key: 'reject:error', full: 'ERR', allow: false, tag: 'ERR', detail: r.error };
  if (kind === 'canon') {
    if (r.canon === undefined) return { cls: 'OK', key: 'reject:parse', full: 'reject:parse', allow: false, tag: 'R:parse' };
    return { cls: 'OK', key: 'accept', full: 'accept:' + r.hash + ':' + sha(r.canon).slice(0, 12), allow: true, tag: 'A' };
  }
  const checks = r.checks ?? {};
  const bits = CHECK_ORDER.filter((k) => k in checks).map((k) => `${k}=${checks[k] ? 1 : 0}`).join(',');
  if (r.allow) return { cls: 'OK', key: 'accept', full: 'accept:' + bits, allow: true, tag: 'A' };
  const first = CHECK_ORDER.find((k) => k in checks && !checks[k]) ?? '?';
  return { cls: 'OK', key: 'reject:' + first, full: 'reject:' + bits, allow: false, tag: 'R:' + first };
}
const known = existsSync(join(ADV, 'known-differences.json')) ? JSON.parse(readFileSync(join(ADV, 'known-differences.json'), 'utf8')) : [];
const knownMap = new Map(known.map((k) => [k.vector, k]));

/** Classify one vector given verdicts per implementation (incl. 'ts' = reference). Returns list of finding types. */
function classify(item, verdicts) {
  const names = Object.keys(verdicts);
  const types = new Set();
  const vs = names.map((n) => verdicts[n]);
  if (vs.some((v) => v.cls === 'FAULT')) types.add('FAULT');
  const ok = names.filter((n) => verdicts[n].cls !== 'FAULT');
  const allows = new Set(ok.map((n) => verdicts[n].allow));
  if (allows.size > 1) types.add('ACCEPT-REJECT');
  else {
    const fulls = new Set(ok.filter((n) => verdicts[n].cls === 'OK').map((n) => verdicts[n].full));
    if (fulls.size > 1) types.add('DETAIL');
    else if (ok.some((n) => verdicts[n].cls === 'ERR') && ok.some((n) => verdicts[n].cls === 'OK')) types.add('ERR-VS-REJECT');
  }
  if (types.has('ACCEPT-REJECT') || types.has('DETAIL')) {
    const tally = new Map();
    for (const n of ok) tally.set(verdicts[n].full, (tally.get(verdicts[n].full) ?? 0) + 1);
    const odd = ok.filter((n) => tally.get(verdicts[n].full) === 1 && tally.size > 1);
    const natives = ok.filter((n) => n !== 'ts');
    if (odd.length === 1 && odd[0] === 'ts' && natives.length >= 2) types.add('REF-ODD-ONE-OUT');
  }
  if (!types.size && item.intent && item.intent !== 'either') {
    const consensus = verdicts.ts?.cls === 'OK' || verdicts.ts?.cls === 'ERR' ? verdicts.ts.allow : null;
    if (consensus !== null && (item.intent === 'accept') !== consensus) types.add('INTENT');
  }
  return [...types];
}

// ------------------------------------------------------------------ minimiser for fuzz disagreements
function minimise(item, active, tsRes) {
  let cur = item.raw;
  const stillBad = (cands) => {
    const batch = cands.map((raw, i) => ({ ...item, id: `min${i}`, raw }));
    const ts = resolve((i, o) => [TSX, join(ADV, 'ref-driver.ts'), i, o], batch, 'ts');
    const per = {};
    for (const im of active) per[im.name] = resolve(im.cmd, batch, im.name);
    return batch.map((b) => {
      const v = { ts: norm(ts.get(b.id), b.kind) };
      for (const im of active) v[im.name] = norm(per[im.name].get(b.id), b.kind);
      const t = classify({ intent: 'either' }, v).filter((x) => x !== 'ERR-VS-REJECT' && x !== 'INTENT');
      return t.length > 0;
    });
  };
  void tsRes;
  // Phase 1: JSON-tree delta debugging (drop keys / array elements / collapse subtrees) while the disagreement persists.
  let tree; try { tree = JSON.parse(cur); } catch { tree = null; }
  if (tree && typeof tree === 'object') {
    const paths = (o, pre = []) => { const out = []; if (o && typeof o === 'object') for (const k of Object.keys(o)) { out.push([...pre, k]); out.push(...paths(o[k], [...pre, k])); } return out; };
    for (let round = 0; round < 10; round++) {
      const ps = paths(tree);
      const cands = [];
      for (const p of ps) {
        for (const mode of ['delete', 'collapse']) {
          const o = JSON.parse(JSON.stringify(tree));
          const par = p.slice(0, -1).reduce((x, k) => x[k], o);
          const k = p.at(-1);
          if (mode === 'delete') { if (Array.isArray(par)) par.splice(Number(k), 1); else delete par[k]; }
          else { const v = par[k]; if (v && typeof v === 'object') par[k] = Array.isArray(v) ? [] : {}; else continue; }
          cands.push({ p, mode, text: JSON.stringify(o) });
        }
      }
      if (!cands.length) break;
      const bad = [];
      for (let i = 0; i < cands.length; i += 150) bad.push(...stillBad(cands.slice(i, i + 150).map((c) => c.text)));
      // greedily keep every independent reduction that still disagrees: apply them one at a time, longest-path first
      const hits = cands.filter((_, i) => bad[i]);
      if (!hits.length) break;
      tree = JSON.parse(hits.sort((x, y) => x.text.length - y.text.length)[0].text);
    }
    cur = JSON.stringify(tree);
  }
  // Phase 2: bounded text ddmin on whatever remains.
  for (let round = 0; round < 6; round++) {
    const n = cur.length;
    if (n <= 1) break;
    let chunk = Math.max(1, Math.floor(n / 2));
    let progressed = false;
    while (chunk >= 1 && !progressed) {
      const cands = [];
      for (let i = 0; i < n && cands.length < 150; i += chunk) cands.push(cur.slice(0, i) + cur.slice(i + chunk));
      const bad = stillBad(cands);
      const k = bad.findIndex(Boolean);
      if (k >= 0) { cur = cands[k]; progressed = true; } else if (chunk === 1) break; else chunk = Math.max(1, Math.floor(chunk / 2));
    }
    if (!progressed) break;
  }
  return cur;
}

// ------------------------------------------------------------------ native per-language suites
function nativeSuites() {
  const out = [];
  const S = (name, req, dir, cmd, args, skipReason) => {
    if (skipReason || (req && !have(req[0], req.slice(1)))) { out.push({ name, status: 'SKIPPED', note: skipReason ?? `no ${req[0]}` }); return; }
    const r = run(cmd, args, { cwd: join(ROOT, dir), timeout: 900000 });
    const text = (r.stdout || '') + (r.stderr || '');
    const m = text.match(/(OK: [^\n]+|assertions: [^\n]+|ok\s+\S+\s+[\d.]+s|Ran \d+ tests?[^\n]*|\d+ passed[^\n]*|test result: [^\n]+)/);
    out.push({ name, status: r.status === 0 ? 'PASS' : 'FAIL', note: (m?.[0] ?? '').slice(0, 110) || (r.status === 0 ? '' : text.slice(-200).replace(/\s+/g, ' ')) });
  };
  S('go', ['go', 'version'], 'sdks/go-pca', 'go', ['test', '-tags', 'less', './...']); // less: LESS via cgo when available
  S('python', ['python3', '-V'], 'sdks/python-pca', 'python3', ['-m', 'unittest', 'test_conformance']);
  S('ruby', ['ruby', '-v'], 'sdks/ruby-pca', 'ruby', ['conformance.rb']);
  S('php', ['php', '-v'], 'sdks/php-pca', 'php', ['conformance.php']);
  S('dotnet', ['dotnet', '--version'], 'sdks/dotnet-pca', 'dotnet', ['run', '--project', 'Conformance', '-c', 'Release']);
  S('rust', ['cargo', '--version'], 'sdks/rust-pca', 'cargo', ['test', '--locked']);
  if (JAVA && BC) {
    const d = join(OUT, 'java-native');
    mkdirSync(d, { recursive: true });
    const javaDir = join(ROOT, 'sdks/java-pca');
    const srcs = readdirSync(join(javaDir, 'src/net/atlasauth/pca')).filter((f) => f.endsWith('.java')).map((f) => join(javaDir, 'src/net/atlasauth/pca', f));
    const c = run(JAVA.javac, ['-cp', BC, '-d', d, ...srcs, join(javaDir, 'ConformanceTest.java')]);
    if (c.status !== 0) out.push({ name: 'java', status: 'FAIL', note: 'javac: ' + (c.stderr || '').slice(0, 150) });
    else { const r = run(JAVA.java, ['--enable-native-access=ALL-UNNAMED', '-cp', `${d}${delimiter}${BC}`, 'ConformanceTest'], { cwd: javaDir, timeout: 600000 }); const t = (r.stdout || '') + (r.stderr || ''); out.push({ name: 'java', status: r.status === 0 ? 'PASS' : 'FAIL', note: (t.match(/(OK[^\n]*|assertions[^\n]*)/)?.[0] ?? '').slice(0, 110) }); }
  } else out.push({ name: 'java', status: 'SKIPPED', note: JAVA ? 'bcprov jar not found (PCA_BC_JAR)' : 'no working JDK' });
  // The full adversarial set (vectors-adversarial.json.gz) is also fed to the Kotlin and Swift runners (core + full), via an
  // uncompressed temp copy named in PCA_CONFORMANCE_ADV; the language mirrors only ever see the curated core.
  const advGz = join(ROOT, 'packages/pca/conformance/vectors-adversarial.json.gz');
  const advPlain = join(ROOT, 'packages/pca/conformance/vectors-adversarial.json');
  let advTmp = '';
  if (existsSync(advGz)) { advTmp = join(OUT, 'vectors-adversarial.json'); writeFileSync(advTmp, gunzipSync(readFileSync(advGz))); } else if (existsSync(advPlain)) advTmp = advPlain;
  lessLib(); // the native suites' FFI backends find libatlas_less through ATLAS_PCA_LIBLESS
  const advEnv = { ...process.env, ...(advTmp ? { PCA_CONFORMANCE_ADV: advTmp } : {}) };
  out.push(kotlinNative(advEnv));
  if (!have('swift', ['--version'])) out.push({ name: 'swift', status: 'SKIPPED', note: 'no swift toolchain' });
  else {
    // macOS: the package as is (CryptoKit). Linux: the patched COPY from swiftLinuxTree() (swift-crypto for CryptoKit, liboqs
    // for ML-DSA-65 / -87), laid out like the repo so the tests find packages/pca/conformance.
    let swiftDir = join(ROOT, 'sdks/swift-pca');
    let prepFail = null;
    if (process.platform !== 'darwin') {
      const t = swiftLinuxTree();
      prepFail = t.fail;
      swiftDir = join(t.root, 'sdks/swift-pca');
    }
    const r = prepFail ? { status: 1, stdout: prepFail, stderr: '' } : run('swift', ['test', '--scratch-path', join(OUT, 'swift-build'), '--filter', 'ConformanceTests'], { cwd: swiftDir, timeout: 1500000, env: advEnv });
    const t = (r.stdout || '') + (r.stderr || '');
    out.push({ name: 'swift', status: r.status === 0 ? 'PASS' : 'FAIL', note: (t.match(/PCA conformance: [^\n]+/)?.[0] ?? t.slice(-160).replace(/\s+/g, ' ')).slice(0, 110) });
  }
  return out;
}

/** Linux only: a patched COPY of sdks/swift-pca at OUT/swift-linux/sdks/swift-pca (tools/pca-audit/swift-mutate/linux-prep.sh:
 *  swift-crypto for CryptoKit, liboqs for ML-DSA), with OUT/swift-linux/packages -> the repo's packages. Prepared once per run
 *  and shared by the Swift driver and the Swift native suite. {root, fail}. */
let SWIFT_LINUX = null;
function swiftLinuxTree() {
  if (SWIFT_LINUX) return SWIFT_LINUX;
  const w = join(OUT, 'swift-linux');
  rmSync(join(w, 'sdks'), { recursive: true, force: true });
  mkdirSync(join(w, 'sdks/swift-pca'), { recursive: true });
  for (const d of ['Sources', 'Tests', 'Package.swift']) run('cp', ['-R', join(ROOT, 'sdks/swift-pca', d), join(w, 'sdks/swift-pca')]);
  rmSync(join(w, 'packages'), { force: true });
  run('ln', ['-s', join(ROOT, 'packages'), join(w, 'packages')]);
  const p = run('bash', [join(ROOT, 'tools/pca-audit/swift-mutate/linux-prep.sh'), 'sdks/swift-pca'], { cwd: w, timeout: 1800000 });
  SWIFT_LINUX = { root: w, fail: p.status === 0 ? null : 'linux-prep failed: ' + ((p.stdout || '') + (p.stderr || '')).slice(-200).replace(/\s+/g, ' ') };
  return SWIFT_LINUX;
}

/** The Kotlin toolchain (plain JVM: no Android/Gradle project): the kotlin-compiler-embeddable jar that ships inside any
 *  Gradle distribution (PCA_KOTLIN_LIB overrides the lib dir), its stdlib and BouncyCastle. {skip} when something is missing. */
function kotlinToolchain() {
  if (!JAVA) return { skip: 'no working JDK' };
  const bc = BC ?? process.env.PCA_BC_JAR;
  if (!bc) return { skip: 'bcprov jar not found (PCA_BC_JAR)' };
  let lib = process.env.PCA_KOTLIN_LIB;
  if (!lib) {
    const dists = join(homedir(), '.gradle/wrapper/dists');
    const cands = [];
    const walk = (dir, depth) => {
      let ents; try { ents = readdirSync(dir, { withFileTypes: true }); } catch { return; }
      if (ents.some((e) => e.isFile() && e.name.startsWith('kotlin-compiler-embeddable-'))) { cands.push(dir); return; }
      if (depth < 4) for (const e of ents) if (e.isDirectory()) walk(join(dir, e.name), depth + 1);
    };
    walk(dists, 0);
    lib = cands.sort().pop();
  }
  if (!lib) return { skip: 'no kotlin-compiler-embeddable (a Gradle distribution under ~/.gradle/wrapper/dists, or PCA_KOTLIN_LIB)' };
  const jar = (prefix) => { const f = readdirSync(lib).find((n) => n.startsWith(prefix) && n.endsWith('.jar') && !n.includes('sources')); return f ? join(lib, f) : null; };
  const need = ['kotlin-compiler-embeddable-', 'kotlin-stdlib-', 'kotlin-script-runtime-', 'kotlin-reflect-', 'kotlin-daemon-embeddable-', 'kotlinx-coroutines-core-jvm-', 'annotations-'].map(jar);
  if (need.some((j) => !j)) return { skip: 'incomplete kotlin compiler jars in ' + lib };
  const trove = jar('trove4j-'); if (trove) need.push(trove); // the embeddable compiler needs it when it is not bundled
  return { compilerCp: need.join(delimiter), stdlib: jar('kotlin-stdlib-'), bc };
}
/** kotlinc the verifier sources (src/main) plus `extra` into `dir`; null on success, else the compiler's complaint. */
function kotlinCompile(tc, dir, extra) {
  rmSync(dir, { recursive: true, force: true }); mkdirSync(dir, { recursive: true });
  const vd = join(ROOT, 'sdks/kotlin-pca/src/main/kotlin/net/atlasauth/pca/verifier');
  const srcs = [...readdirSync(vd).filter((f) => f.endsWith('.kt')).map((f) => join(vd, f)), ...extra];
  const c = run(JAVA.java, ['-cp', tc.compilerCp, 'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-no-stdlib', '-no-reflect', '-cp', `${tc.stdlib}${delimiter}${tc.bc}`, '-d', dir, ...srcs], { timeout: 900000 });
  return c.status === 0 ? null : 'kotlinc: ' + ((c.stdout || '') + (c.stderr || '')).slice(-200).replace(/\s+/g, ' ');
}

/** Kotlin verifier: compile src/main + the test ConformanceRunner, run its main(). */
function kotlinNative(env) {
  const tc = kotlinToolchain();
  if (tc.skip) return { name: 'kotlin', status: 'SKIPPED', note: tc.skip };
  const d = join(OUT, 'kotlin-classes');
  const err = kotlinCompile(tc, d, [join(ROOT, 'sdks/kotlin-pca/src/test/kotlin/net/atlasauth/pca/verifier/ConformanceRunner.kt')]);
  if (err) return { name: 'kotlin', status: 'FAIL', note: err };
  const r = run(JAVA.java, ['-Xss64m', '-Xmx3g', '--enable-native-access=ALL-UNNAMED', '-cp', `${d}${delimiter}${tc.stdlib}${delimiter}${tc.bc}`, 'net.atlasauth.pca.verifier.ConformanceRunnerKt', join(ROOT, 'packages/pca/conformance') + '/', join(ROOT, 'tools/pca-diff-fuzz/counterexamples') + '/'], { timeout: 900000, env });
  const t = (r.stdout || '') + (r.stderr || '');
  return { name: 'kotlin', status: r.status === 0 ? 'PASS' : 'FAIL', note: ((t.match(/VECTORS: [^\n]+/)?.[0] ?? '') + ' ' + (t.match(/ASSERTIONS: [^\n]+/)?.[0] ?? '')).trim().slice(0, 110) };
}

// ------------------------------------------------------------------ DoS timing check (robust under load)
const TIMING_RUNS = Number(opt('--timing-baseline-runs', 7));       // >= 7: median of this many control-vector runs per language
const TIMING_ABS_MS = Number(opt('--timing-abs-ms', 1000));        // overrun needs ms - baseline > this ...
const TIMING_RATIO = Number(opt('--timing-ratio', 3));             // ... AND ms > baseline * this
const TIMING_ATTEMPTS = Number(opt('--timing-attempts', 3));       // re-runs of an overrunning vector; fail only if ALL overrun
const quantile = (xs, q) => { const a = [...xs].sort((x, y) => x - y); return a.length ? a[Math.min(a.length - 1, Math.floor(q * a.length))] : 0; };
const median = (xs) => quantile(xs, 0.5);
/** box-wide mutex so two gates (or a stryker/fuzz job that honours it) never time vectors concurrently on one machine */
function acquireTimingLock(maxWaitMs = 20 * 60 * 1000) {
  const f = process.env.PCA_TIMING_LOCK ?? join(tmpdir(), 'pca-conformance-timing.lock');
  const t0 = Date.now();
  for (;;) {
    try { writeFileSync(f, String(process.pid), { flag: 'wx' }); break; } catch {
      let pid = 0; try { pid = Number(readFileSync(f, 'utf8')); } catch { /* raced */ }
      let alive = false; if (pid) { try { process.kill(pid, 0); alive = true; } catch { /* stale */ } }
      if (!alive) { rmSync(f, { force: true }); continue; }
      if (Date.now() - t0 > maxWaitMs) return { f: null, waitedMs: Date.now() - t0, held: false };
      spawnSync('sleep', ['2']);
    }
  }
  const release = () => { try { if (readFileSync(f, 'utf8') === String(process.pid)) rmSync(f, { force: true }); } catch { /* gone */ } };
  process.on('exit', release);
  return { f, waitedMs: Date.now() - t0, held: true, release };
}
function timingCheck(dos, active) {
  const lock = acquireTimingLock();
  const ctl = dos.at(-1);
  const vecs = dos.slice(0, -1);
  log(`\nDoS timing (separate from verdict agreement; serial; lock ${lock.held ? 'held' : 'NOT acquired (proceeding, results flagged)'}; baseline = median of ${Math.max(7, TIMING_RUNS)} control runs per language;`);
  log(`  overrun = excess > ${TIMING_ABS_MS} ms AND > ${TIMING_RATIO}x baseline; re-run up to ${TIMING_ATTEMPTS}x, fail only if all attempts overrun)`);
  const out = { params: { baselineRuns: Math.max(7, TIMING_RUNS), absMs: TIMING_ABS_MS, ratio: TIMING_RATIO, attempts: TIMING_ATTEMPTS }, lock: { held: lock.held, waitedMs: lock.waitedMs }, loadavgAtStart: loadavg(), cpus: cpus().length, langs: {}, failures: [], suspect: [] };
  for (const im of [{ name: 'ts', cmd: (i, o) => [TSX, join(ADV, 'ref-driver.ts'), i, o] }, ...active]) {
    execOnce(im.cmd, [ctl], 120000); // warm file cache, not counted
    const bruns = Array.from({ length: Math.max(7, TIMING_RUNS) }, () => execOnce(im.cmd, [ctl], 120000).ms);
    const base = median(bruns);
    const limitMs = Math.max(base + TIMING_ABS_MS, Math.ceil(base * TIMING_RATIO));
    const firsts = [];
    let worst = 0, worstName = '', retried = 0, flaky = 0;
    for (const d of vecs) {
      const attempts = [];
      for (let k = 0; k < TIMING_ATTEMPTS; k++) {
        const r = execOnce(im.cmd, [d], 120000);
        attempts.push({ ms: r.ms, timedOut: r.timedOut });
        if (!r.timedOut && r.ms <= limitMs) break;
      }
      firsts.push(attempts[0].ms);
      const best = Math.min(...attempts.map((a) => (a.timedOut ? Infinity : a.ms)));
      if (best !== Infinity && best - base > worst) { worst = best - base; worstName = d.name; }
      const overran = (a) => a.timedOut || a.ms > limitMs;
      if (attempts.length > 1) retried++;
      if (attempts.every(overran)) out.failures.push({ lang: im.name, vector: d.name, base, limitMs, attempts });
      else if (attempts.some(overran)) flaky++;
    }
    const baseAfter = median(Array.from({ length: 3 }, () => execOnce(im.cmd, [ctl], 120000).ms));
    const rec = { baselineMedianMs: base, baselineRunsMs: bruns, baselineAfterMedianMs: baseAfter, limitMs, vectors: vecs.length, p50Ms: median(firsts), p95Ms: quantile(firsts, 0.95), maxMs: Math.max(...firsts), worstExcessMs: worst, worstVector: worstName, retriedVectors: retried, recoveredOnRetry: flaky, loadavgAfter: loadavg() };
    if (baseAfter > base * 2 && baseAfter - base > 200) out.suspect.push(`${im.name}: baseline drifted ${base} -> ${baseAfter} ms during the run (box load)`);
    out.langs[im.name] = rec;
    log(`  ${im.name.padEnd(7)} baseline ${String(base).padStart(5)} ms (med of ${bruns.length}; after ${baseAfter})  p50 ${rec.p50Ms} p95 ${rec.p95Ms} max ${rec.maxMs} ms  worst +${worst} ms (${worstName})  retried ${retried} recovered ${flaky}`);
  }
  out.loadavgAtEnd = loadavg();
  if (lock.held) lock.release();
  for (const x of out.suspect) log('  NOTE ' + x);
  log(`  loadavg start ${out.loadavgAtStart.map((x) => x.toFixed(1)).join('/')} end ${out.loadavgAtEnd.map((x) => x.toFixed(1)).join('/')} on ${out.cpus} cpus`);
  return out;
}

// ------------------------------------------------------------------ main
async function main() {
  mkdirSync(OUT, { recursive: true });
  log(`PCA conformance (all languages)  out=${OUT}`);
  if (!existsSync(TSX)) { console.error(`tsx not found at ${TSX} (run pnpm install)`); process.exit(2); }

  const gen = genCorpus();
  const adv = gen.items;
  const regs = loadRegressions();
  const fuzz = FUZZ_N > 0 && !flag('--no-fuzz') ? makeFuzz(FUZZ_N, SEED, adv) : [];
  const sweep = SWEEP_N > 0 && FUZZ_N > 0 ? makeSweep(SWEEP_N, adv) : [];
  const confAdv = []; // vectors.json adv-* are already ingested by gen-adversarial.ts as category 'golden' (full check map compared)
  const dos = FUZZ_N > 0 && !flag('--no-dos') ? genDos() : [];
  const all = [...adv, ...regs, ...confAdv, ...dos, ...sweep, ...fuzz];
  log(`corpus: ${adv.length} adversarial + ${regs.length} regression + ${dos.length} size/time-DoS + ${sweep.length} structural-sweep + ${fuzz.length} fuzz (seed ${SEED}) = ${all.length} vectors; reference source: ${gen.refSource}`);

  // toolchain detection / driver build
  const status = {};
  const active = [];
  for (const im of IMPLS) {
    if (WANT.length && !WANT.includes(im.name)) { status[im.name] = 'not selected'; continue; }
    const why = im.prep();
    if (why) { status[im.name] = 'SKIPPED: ' + why; log(`  [${im.name}] SKIPPED (${why})`); } else { status[im.name] = 'ran'; active.push(im); log(`  [${im.name}] available`); }
  }

  // reference + implementations
  const t0 = Date.now();
  const tsRes = resolve((i, o) => [TSX, join(ADV, 'ref-driver.ts'), i, o], all, 'ts');
  log(`  [ts reference] ${all.length} vectors in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
  const res = { ts: tsRes };
  const timing = {};
  for (const im of active) { const s = Date.now(); res[im.name] = resolve(im.cmd, all, im.name); timing[im.name] = (Date.now() - s) / 1000; log(`  [${im.name}] ${all.length} vectors in ${timing[im.name].toFixed(1)}s`); }
  const langs = ['ts', ...active.map((a) => a.name)];

  // suite capability (packages/pca/conformance/README.md "Suite capability"): each language's declared suites, asked once
  // through the driver protocol ({kind:"suites"}). A driver that does not answer is assumed to declare the legacy set.
  const suites = {};
  for (const im of active) {
    const m = manifestOf(execOnce(im.cmd, [SUITES_QUERY], 120000).res.get(SUITES_QUERY.id));
    suites[im.name] = { declared: m ?? [...LEGACY_SUITES], answered: m !== null };
    log(`  [${im.name}] suites${m ? '' : ' (no manifest answer: legacy set assumed)'}: ${suites[im.name].declared.join(', ')}; refused: ${REGISTERED_SUITES.filter((a) => !suites[im.name].declared.includes(a)).join(', ') || 'none'}`);
  }
  const declaredSet = Object.fromEntries(Object.entries(suites).map(([n, x]) => [n, new Set(x.declared)]));

  // compare
  const rows = [];
  const problems = [];
  const waived = [];
  const findings = [];
  const byFinding = {};
  for (const c of all) {
    const verdicts = {};
    for (const l of langs) verdicts[l] = norm(res[l].get(c.id), c.kind);
    // Suite capability: a language that does not declare a suite the vector carries is judged by the refusal rule and left
    // out of the cross-language comparison; a language refusing a suite it declares is a finding.
    const compared = { ...verdicts };
    let suiteBad = false;
    if (c.kind === 'verify' || c.kind === 'chain') {
      for (const l of langs) {
        if (l === 'ts') continue;
        const j = judgeSuite(declaredSet[l], c.raw, res[l].get(c.id), res.ts.get(c.id), c.intent_v2);
        if (j.gated) { delete compared[l]; verdicts[l] = { ...verdicts[l], tag: `U(${j.missing.join('+')})${j.ok ? '' : '!'}` }; }
        if (!j.ok) suiteBad = true;
      }
    }
    const types = classify(c, compared);
    if (suiteBad) types.push('SUITE-CAPABILITY');
    // committed expectation drift: the live reference must still match the manifest's recorded ref
    if (c.ref && verdicts.ts.cls === 'OK') {
      const refNorm = norm(c.ref, c.kind);
      if (refNorm.full !== verdicts.ts.full) types.push('REF-DRIFT');
    }
    rows.push({ c, verdicts, types });
    if (!types.length) continue;
    const k = knownMap.get(`${c.category}/${c.name}`);
    const unwaived = types.filter((t) => !(k && (k.types.includes('*') || k.types.includes(t))) && (STRICT || t !== 'ERR-VS-REJECT'));
    for (const t of types) byFinding[t] = (byFinding[t] ?? 0) + 1;
    if (unwaived.length) problems.push({ c, verdicts, types: unwaived });
    else if (types.some((t) => k)) waived.push({ c, verdicts, types, reason: k?.reason });
    else findings.push({ c, verdicts, types });
  }

  // fuzz minimisation: commit regression vectors for fuzz-found disagreements
  const newRegs = [];
  if (!flag('--no-minimize')) {
    const seenSig = new Set();
    const fuzzBad = problems.filter((p) => (p.c.category === 'fuzz' || p.c.category === 'sweep') && p.types.some((t) => t !== 'INTENT' && t !== 'REF-DRIFT' && t !== 'SUITE-CAPABILITY')).filter((p) => { const sg = p.types.join(',') + '|' + langs.map((l) => p.verdicts[l].tag).join(','); if (seenSig.has(sg)) return false; seenSig.add(sg); return true; }).slice(0, 5);
    for (const p of fuzzBad) {
      const mraw = minimise(p.c, active, tsRes);
      const slug = sha(mraw + p.c.kind + p.c.grant + p.c.aud + p.c.now).slice(0, 12);
      const dir = join(ADV, 'regressions');
      mkdirSync(dir, { recursive: true });
      const v = {};
      for (const l of langs) v[l] = p.verdicts[l].tag;
      writeFileSync(join(dir, `fuzz-${slug}.json`), JSON.stringify({ name: `fuzz-min-${slug}`, kind: p.c.kind, raw: mraw, grant: p.c.grant, now: p.c.now, aud: p.c.aud, found: { seed: SEED, id: p.c.id, types: p.types }, verdictsAtDiscovery: v }, null, 1) + '\n');
      newRegs.push({ file: `regressions/fuzz-${slug}.json`, originalLen: p.c.raw.length, minLen: mraw.length, types: p.types });
    }
  }

  // DoS TIMING (recorded SEPARATELY from verdict agreement; a slow box must never read as a disagreement). Serial, under a
  // box-wide lock, per-language baseline = median of >= 7 runs of the control vector taken immediately before that language's
  // vectors; an overrun needs BOTH ratio and absolute excess; an overrunning vector is re-run (<= 3 attempts, stop at the first
  // clean one) and only fails when EVERY attempt overruns. See timingCheck().
  let timingChecks = null;
  if (dos.length) timingChecks = timingCheck(dos, active);
  const slow = timingChecks ? timingChecks.failures : [];

  // reports
  const cats = [...new Set(all.map((c) => c.category))];
  const header = `| category | vectors | ${langs.map((l) => l).join(' | ')} |\n|---|---|${langs.map(() => '---').join('|')}|`;
  const catLines = cats.map((cat) => {
    const rs = rows.filter((r) => r.c.category === cat);
    const cells = langs.map((l) => { if (l === 'ts') return `${rs.filter((r) => r.verdicts.ts.allow).length}A/${rs.filter((r) => !r.verdicts.ts.allow).length}R`; const agree = rs.filter((r) => r.verdicts[l].full === r.verdicts.ts.full).length; return agree === rs.length ? `${agree}/${rs.length}` : `**${agree}/${rs.length}**`; });
    return `| ${cat} | ${rs.length} | ${cells.join(' | ')} |`;
  });
  const summaryTable = [header, ...catLines].join('\n');
  const matrixRows = rows.filter((r) => r.c.category !== 'fuzz' && r.c.category !== 'sweep').map((r) => `| ${r.c.id} | ${r.c.category} | ${r.c.name.replace(/\|/g, '\\|')} | ${r.c.intent} | ${langs.map((l) => r.verdicts[l].tag).join(' | ')} | ${r.types.join(',')} |`);
  const matrix = `# PCA adversarial conformance matrix\n\nGenerated by \`scripts/pca-conformance-all.mjs\`. Cell: \`A\` = accept, \`R:<check>\` = reject with first failing check (reason class), \`ERR\` = driver raised instead of returning a verdict, \`HANG\`/\`CRASH\` = fault. \`U(<suite>)\` = the language does not declare that suite and refused it as required (\`U(...)!\` = it did not: finding SUITE-CAPABILITY); such cells are not compared with the reference. Languages in this run: ${langs.join(', ')}. Skipped: ${Object.entries(status).filter(([, s]) => s !== 'ran').map(([n, s]) => `${n} (${s})`).join('; ') || 'none'}.\n\n## Per-category agreement with the TS reference (full verdict incl. check map)\n\n${summaryTable}\n\n## Every vector\n\n| id | category | name | intent | ${langs.join(' | ')} | findings |\n|---|---|---|---|${langs.map(() => '---').join('|')}|---|\n${matrixRows.join('\n')}\n`;
  writeFileSync(join(OUT, 'MATRIX.md'), matrix);
  if (flag('--write-matrix')) writeFileSync(join(ADV, 'MATRIX.md'), matrix);
  writeFileSync(join(OUT, 'report.json'), JSON.stringify({ langs, status, suites, timing, timingChecks, counts: { adversarial: adv.length, regressions: regs.length, sweep: sweep.length, fuzz: fuzz.length }, byFinding, problems: problems.map((p) => ({ id: p.c.id, name: `${p.c.category}/${p.c.name}`, types: p.types, verdicts: Object.fromEntries(langs.map((l) => [l, p.verdicts[l].tag])) })), waived: waived.map((p) => ({ name: `${p.c.category}/${p.c.name}`, types: p.types, reason: p.reason })), newRegressions: newRegs }, null, 1));

  // native suites
  let native = [];
  if (!flag('--no-native')) { log('\nnative per-language conformance suites:'); native = nativeSuites(); for (const n of native) log(`  ${n.name.padEnd(8)} ${n.status.padEnd(8)} ${n.note}`); }

  // output
  log('\n' + summaryTable);
  const dis = [...problems, ...findings];
  if (dis.length) {
    log(`\nDISAGREEMENTS / FINDINGS (${dis.length}):`);
    for (const p of dis.slice(0, 60)) log(`  ${p.c.id} ${p.c.category}/${p.c.name.slice(0, 70)} [${p.types.join(',')}] intent=${p.c.intent}  ${langs.map((l) => `${l}:${p.verdicts[l].tag}`).join(' ')}`);
    if (dis.length > 60) log(`  ... ${dis.length - 60} more (see ${join(OUT, 'report.json')})`);
  }
  if (waived.length) { log(`\nWAIVED (known-differences.json): ${waived.length}`); for (const w of waived) log(`  ${w.c.category}/${w.c.name} [${w.types.join(',')}] ${w.reason ?? ''}`); }
  if (newRegs.length) { log(`\nNEW REGRESSION VECTORS from fuzz (commit them):`); for (const r of newRegs) log(`  ${r.file} ${r.originalLen} -> ${r.minLen} chars [${r.types.join(',')}]`); }

  const skipped = Object.entries(status).filter(([, s]) => s !== 'ran' && s !== 'not selected');
  const fails = [];
  if (gen.drift) fails.push('adversarial manifest drifted from a fresh regeneration (re-run gen-adversarial.ts and commit)');
  if (problems.length) fails.push(`${problems.length} unwaived disagreement(s)/fault(s)/finding(s): ${Object.entries(byFinding).map(([k, v]) => `${k}=${v}`).join(' ')}`);
  const timingFails = slow.map((x) => `TIMING (not a verdict disagreement): ${x.lang} overran on ALL ${x.attempts.length} attempts on ${x.vector}: ${x.attempts.map((t) => t.ms + (t.timedOut ? 'ms TIMEOUT' : 'ms')).join(', ')} (baseline median ${x.base} ms, limit ${x.limitMs} ms)`);
  for (const n of native) if (n.status === 'FAIL') fails.push(`native suite failed: ${n.name}`);
  for (const r of REQUIRE) {
    if (status[r] === 'ran') continue;
    // a name with no diff driver is required via its native conformance suite
    const n = !(r in status) ? native.find((x) => x.name === r) : undefined;
    if (n && n.status === 'PASS') continue;
    fails.push(`required implementation did not run: ${r} (${status[r] ?? (n ? `native ${n.status}: ${n.note ?? ''}` : 'unknown')})`);
  }
  log(`\nRAN: ${langs.join(', ')}   SKIPPED: ${skipped.map(([n, s]) => `${n} (${s.replace('SKIPPED: ', '')})`).join('; ') || 'none'}`);
  log(`vectors=${all.length} cross-language disagreements (unwaived)=${problems.length} waived=${waived.length} unlisted-findings=${findings.length}`);
  log(`report: ${join(OUT, 'report.json')}  matrix: ${join(OUT, 'MATRIX.md')}`);
  if (fails.length) { console.error('\nFAIL:\n  ' + [...fails, ...timingFails].join('\n  ')); process.exit(1); }
  if (timingFails.length) { console.error('\nFAIL (TIMING ONLY: every verdict agrees; box was too slow or a verifier regressed; exit 3):\n  ' + timingFails.join('\n  ')); process.exit(3); }
  log('\nPASS: every language that ran agrees on every vector' + (skipped.length ? ' (skipped languages are NOT counted as passed)' : ''));
}
main();
