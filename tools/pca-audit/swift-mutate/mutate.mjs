#!/usr/bin/env node
// Small operator mutator for the Swift verifier (Muter is not available here). Works on COPIES of the package (never edits the repo):
//   node mutate.mjs list  <file.swift>...                      list mutants (id, line, op, original => replacement)
//   node mutate.mjs run   <workers> <budget-minutes> <out.json> <file.swift>... [--only=ids] [--every=N --offset=K]
// Each worker owns a private copy of sdks/swift-pca under $TMPDIR/swiftmut/wN, applies one mutant, runs the oracle
// (swift test: existing unit tests + core conformance + the FULL adversarial corpus via PCA_CONFORMANCE_ADV) under nice,
// and records KILLED / SURVIVED / NONVIABLE (compile error) / TIMEOUT. A mutant is killed iff the oracle exits non-zero.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { sha, normText, mayCarry, loadPool } from '../mut-carry/lib.mjs';
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../../..');
const pkg = path.join(root, 'sdks/swift-pca');

function maskLine(l) { // blank out string literals and // comments so operators inside them are ignored
  let out = '', inStr = false;
  for (let i = 0; i < l.length; i++) {
    const c = l[i];
    if (!inStr && c === '/' && l[i + 1] === '/') { out += ' '.repeat(l.length - i); break; }
    if (!inStr && c === '/' && l[i + 1] === '*') { // same-line /* ... */ comment
      const e = l.indexOf('*/', i + 2);
      const end = e < 0 ? l.length : e + 2;
      out += ' '.repeat(end - i); i = end - 1; continue;
    }
    if (c === '"' && l[i - 1] !== '\\') { inStr = !inStr; out += '"'; continue; }
    out += inStr ? ' ' : c;
  }
  return out;
}
const RULES = [
  [/ == /g, ' != '], [/ != /g, ' == '], [/ <= /g, ' < '], [/ >= /g, ' > '], [/ < /g, ' <= '], [/ > /g, ' >= '],
  [/ && /g, ' || '], [/ \|\| /g, ' && '], [/ \+ /g, ' - '], [/ - /g, ' + '], [/ \* /g, ' / '], [/ & /g, ' | '], [/ \| /g, ' & '], [/ \^ /g, ' | '],
  [/ << /g, ' >> '], [/ >> /g, ' << '], [/\btrue\b/g, 'false'], [/\bfalse\b/g, 'true'],
];
function mutantsFor(file) {
  const src = fs.readFileSync(file, 'utf8').split('\n');
  const out = [];
  const add = (ln, repl, op) => { if (repl !== src[ln]) out.push({ line: ln + 1, op, orig: src[ln].trim(), repl: repl.trim(), text: src.map((x, i) => (i === ln ? repl : x)).join('\n') }); };
  // Lines the oracle does not compile: on Linux the `#else` branch of an `#if os(Linux)` block (e.g. the macOS CryptoKit
  // ML-DSA path that linux-prep replaces with liboqs). Mutating them would only report fake survivors.
  const dead = new Set();
  if (process.platform === 'linux') {
    let st = 0; // 0 outside, 1 in the Linux branch, 2 in the non-Linux branch
    src.forEach((l, i) => {
      const t = l.trim();
      if (/^#if os\(Linux\)/.test(t)) st = 1; else if (st && t === '#else') st = 2; else if (st && t === '#endif') st = 0; else if (st === 2) dead.add(i);
    });
  }
  src.forEach((raw, ln) => {
    if (dead.has(ln)) return;
    const m = maskLine(raw);
    if (/^\s*(\/\/|\/\*|\*|import |@|\/\/\/)/.test(raw) || /^\s*(static let|let|var)\s+\w+(:\s*[\w\[\]]+)?\s*=\s*\d/.test(raw) && false) return;
    for (const [re, rep] of RULES) {
      re.lastIndex = 0;
      let mm;
      while ((mm = re.exec(m))) {
        // skip generics / closures / arrows: ' -> ' and '<' in type position are not spaced operators in practice
        if (mm[0] === ' - ' && m[mm.index + 3] === '>') continue;
        add(ln, raw.slice(0, mm.index) + rep + raw.slice(mm.index + mm[0].length), `${mm[0].trim()}->${rep.trim()}`);
      }
    }
    // integer literals
    const numRe = /(?<![\w.\]"])(\d[\d_]*)(?![\w."])/g;
    let nm;
    while ((nm = numRe.exec(m))) {
      const v = parseInt(nm[1].replace(/_/g, ''), 10);
      if (!Number.isFinite(v) || v > 2 ** 52) continue;
      add(ln, raw.slice(0, nm.index) + (v + 1) + raw.slice(nm.index + nm[1].length), `${v}->${v + 1}`);
      if (v >= 1) add(ln, raw.slice(0, nm.index) + (v - 1) + raw.slice(nm.index + nm[1].length), `${v}->${v - 1}`);
    }
    // prefix negation removal:  !(x) / !x  (only when preceded by space, '(' or '&&')
    const nr = /(?<=[\s(])!(?=[\w(])/g;
    let bm;
    while ((bm = nr.exec(m))) add(ln, raw.slice(0, bm.index) + raw.slice(bm.index + 1), 'drop-!');
    // returns
    if (/^\s*return false\s*$/.test(m)) add(ln, raw.replace('return false', 'return true'), 'return false->true');
    if (/^\s*return true\s*$/.test(m)) add(ln, raw.replace('return true', 'return false'), 'return true->false');
    if (/^\s*return nil\s*$/.test(m) || /^\s*continue\s*$/.test(m) === false && /^\s*break\s*$/.test(m) === false && false) { /* keep nil returns unmutated */ }
    // if/guard conditions: negate whole condition
    const cm = /^(\s*)(if|guard|while)\s+(?!let\b|case\b|var\b)(.+?)\s*(\{|else \{)\s*$/.exec(m);
    if (cm && !/\blet\b|\bcase\b/.test(cm[3]) && cm[2] !== 'while') {
      const idx = raw.indexOf(cm[2]) + cm[2].length + 1;
      const endIdx = raw.length - raw.slice(raw.indexOf(cm[3]) + cm[3].length).length;
      add(ln, raw.slice(0, idx) + '!(' + raw.slice(idx, endIdx) + ')' + raw.slice(endIdx), `${cm[2]}-negate`);
    }
  });
  return out;
}

// ---- carry-forward identity (targeted mode, see ../mut-carry): every mutant gets a stable key, the hash of its enclosing
// func/init/subscript ("def") and the hash of the file's code outside every def ("shell"; comments/blank lines ignored).
// Source masked across lines: string literals (incl. multi-line """ and raw #"..."#), // and nested /* */ comments blanked
// (newlines kept), so braces inside them never confuse the def scanner.
function maskAll(src) {
  const out = []; let i = 0; const n = src.length; let cmt = 0;
  const put = (c) => out.push(c === '\n' ? '\n' : ' ');
  while (i < n) {
    const c = src[i];
    if (cmt) { if (c === '*' && src[i + 1] === '/') { cmt--; put(c); put(src[i + 1]); i += 2; } else if (c === '/' && src[i + 1] === '*') { cmt++; put(c); put(src[i + 1]); i += 2; } else { put(c); i++; } continue; }
    if (c === '/' && src[i + 1] === '/') { while (i < n && src[i] !== '\n') { put(src[i]); i++; } continue; }
    if (c === '/' && src[i + 1] === '*') { cmt = 1; put(c); put(src[i + 1]); i += 2; continue; }
    let hashes = 0, j = i; while (src[j] === '#') { hashes++; j++; }
    if (src[j] === '"') {
      const triple = src.startsWith('"""', j); const q = triple ? '"""' : '"'; const close = q + '#'.repeat(hashes);
      for (let k = i; k < j + q.length; k++) put(' ');
      i = j + q.length;
      while (i < n && !src.startsWith(close, i)) { if (src[i] === '\\' && !hashes) { put(src[i]); i++; } if (!triple && src[i] === '\n') break; put(src[i]); i++; }
      if (src.startsWith(close, i)) for (let k = 0; k < close.length; k++) { put(src[i]); i++; }
      continue;
    }
    out.push(c); i++;
  }
  return out.join('');
}
const DEF_RE = /^\s*(?:(?:public|private|fileprivate|internal|open|static|class|final|override|mutating|nonmutating|required|convenience|@\w+(?:\([^)]*\))?)\s+)*(?:func|init[?!]?|deinit|subscript)\b/;
function defRanges(rawText) {
  const masked = maskAll(rawText), lines = masked.split('\n'), raw = rawText.split('\n');
  const starts = []; let off = 0; for (const l of lines) { starts.push(off); off += l.length + 1; }
  const ranges = [];
  for (let li = 0; li < lines.length; li++) {
    if (ranges.length && li <= ranges[ranges.length - 1].end) continue; // nested in an outer def
    if (!DEF_RE.test(lines[li])) continue;
    let pos = starts[li] + lines[li].search(/\S/), par = 0, body = -1;
    for (; pos < masked.length; pos++) {
      const c = masked[pos];
      if (c === '(' || c === '[') par++; else if (c === ')' || c === ']') par--;
      else if (c === '{' && par === 0) { body = pos; break; }
      else if (c === ';' || (c === '}' && par <= 0)) break;
      else if (c === '\n' && pos > starts[li] && par === 0) { const nx = masked.slice(pos + 1, pos + 400).split('\n')[0]; if (DEF_RE.test(nx) || /^\s*(\}|case\b|var\b|let\b)/.test(nx)) break; }
    }
    if (body < 0) continue;
    let depth = 0, end = -1;
    for (let p = body; p < masked.length; p++) { if (masked[p] === '{') depth++; else if (masked[p] === '}' && --depth === 0) { end = p; break; } }
    if (end < 0) continue;
    const endLine = masked.slice(0, end).split('\n').length - 1;
    ranges.push({ start: li, end: endLine, sig: raw[li].trim() });
  }
  return ranges;
}
// per-file carry info: { spans:[{start,end,label,hash}], shell, lineSpan(lineNo1) }
function carryInfo(file) {
  const text = fs.readFileSync(file, 'utf8'), lines = text.split('\n');
  const ranges = defRanges(text), seen = {};
  const spans = ranges.map((r) => { seen[r.sig] = (seen[r.sig] || 0) + 1; return { ...r, label: `${r.sig}#${seen[r.sig]}`, hash: sha(normText(lines.slice(r.start, r.end + 1).join('\n'), { keepDoc: false })) }; });
  const inDef = new Set(); for (const r of ranges) for (let l = r.start; l <= r.end; l++) inDef.add(l);
  const shell = sha(normText(lines.filter((_, i) => !inDef.has(i)).join('\n'), { keepDoc: false }));
  return { spans, shell, spanOf: (ln) => spans.find((sp) => ln - 1 >= sp.start && ln - 1 <= sp.end) };
}
function annotate(file, ms, srcHash) {
  const info = carryInfo(file), occ = {};
  for (const m of ms) {
    const sp = info.spanOf(m.line), label = sp ? sp.label : '';
    const base = `${path.basename(file)}|${label}|${m.op}|${m.orig}|${m.repl}`;
    m.key = `${base}|${occ[base] = (occ[base] ?? -1) + 1}`;
    m.def_hash = sp ? sp.hash : sha(''); m.shell_hash = info.shell; m.src_hash = srcHash;
  }
}

const [cmd, ...rest] = process.argv.slice(2);
if (cmd === 'list') {
  for (const f of rest) { const ms = mutantsFor(f); ms.forEach((m, i) => console.log(`${path.basename(f)}\t${i}\t${m.line}\t${m.op}\t${m.orig.slice(0, 70)} => ${m.repl.slice(0, 70)}`)); console.error(path.basename(f), ms.length); }
  process.exit(0);
}
if (cmd === 'plan') {
  // node mutate.mjs plan <pool.json|-> <file.swift>... [--emit=out.json]: the carry decision per mutant WITHOUT running anything
  // (dry run); --emit writes a synthetic results file (every mutant KILLED, every 5th SURVIVED) to seed a pool in tests.
  const emit = rest.find((a) => a.startsWith('--emit='))?.slice(7);
  const pool = rest[0] === '-' ? {} : loadPool(rest[0]); const files = rest.slice(1).filter((a) => !a.startsWith('--'));
  const emitted = [];
  const srcHash = sha(files.map((f) => f + '\0' + fs.readFileSync(path.join(pkg, f), 'utf8')).join('\0'));
  for (const f of files) {
    const ms = mutantsFor(path.join(pkg, f)); annotate(path.join(pkg, f), ms, srcHash);
    ms.forEach((m, i) => emitted.push({ file: f, idx: i, key: m.key, status: i % 5 === 4 ? 'SURVIVED' : 'KILLED', def_hash: m.def_hash, shell_hash: m.shell_hash, src_hash: m.src_hash }));
    for (const m of ms) { const e = pool[m.key]; const v = !e ? 'RUN unseen' : e.d !== m.def_hash || e.h !== m.shell_hash ? 'RUN changed' : mayCarry(e, m, { killed: ['KILLED', 'TIMEOUT'], uncompilable: ['NONVIABLE'] }) ? `CARRY ${e.s}` : `RUN was ${e.s}`; console.log(`${f}\t${m.line}\t${m.op}\t${v}`); }
  }
  if (emit) fs.writeFileSync(emit, JSON.stringify(emitted));
  process.exit(0);
}
if (cmd === 'survivors') {
  // node mutate.mjs survivors [--src=<sdks/swift-pca checkout the run mutated>] <results.json>...
  //   -> stdout: [{crate,file,mutant,line,occurrence?,lineno}] for native-check-equivalents.mjs. One record per mutation SITE
  //   (later result files win for the same file + line + op + replacement; TIMEOUT counts as detected, NONVIABLE as not a
  //   mutant). occurrence = which copy of the line text in the file, computed from --src (default: this checkout) and emitted
  //   only when that source still has the text at the recorded line; otherwise the checker places the site by the line hint.
  const srcDir = rest.find((a) => a.startsWith('--src='))?.slice(6) ?? pkg;
  const by = new Map();
  for (const f of rest.filter((a) => !a.startsWith('--'))) for (const r of JSON.parse(fs.readFileSync(f, 'utf8'))) by.set(`${r.file}#${r.line}#${r.op}#${r.repl}`, r);
  const srcs = new Map();
  const occ = (file, ln, text) => {
    if (!srcs.has(file)) { const p = path.join(srcDir, file); srcs.set(file, fs.existsSync(p) ? fs.readFileSync(p, 'utf8').split('\n').map((l) => l.trim()) : null); }
    const L = srcs.get(file);
    if (!L || L[ln - 1] !== text.trim()) return undefined;
    let n = 0;
    for (let i = 0; i < ln; i++) if (L[i] === text.trim()) n++;
    return n;
  };
  // a survivor the current mutator no longer generates on that source (non-compiled #else branch, same-line comment) is not a mutant
  const gen = new Map();
  const generated = (r) => {
    if (!gen.has(r.file)) { const p = path.join(srcDir, r.file); gen.set(r.file, fs.existsSync(p) ? new Set(mutantsFor(p).map((m) => `${m.line}#${m.op}#${m.repl}`)) : null); }
    const g = gen.get(r.file);
    return !g || g.has(`${r.line}#${r.op}#${r.repl}`);
  };
  const out = [...by.values()].filter((r) => r.status === 'SURVIVED' && generated(r))
    .sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.idx - b.idx)
    .map((r) => ({ crate: 'swift-pca', file: r.file, mutant: `${r.op} => ${r.repl}`, line: r.orig.trim(), occurrence: occ(r.file, r.line, r.orig), lineno: r.line }));
  console.log(JSON.stringify(out, null, 1));
  const st = {};
  for (const r of by.values()) st[r.status] = (st[r.status] || 0) + 1;
  console.error(JSON.stringify(st));
  process.exit(0);
}
if (cmd === 'run') {
  const flags = rest.filter((a) => a.startsWith('--'));
  const pos = rest.filter((a) => !a.startsWith('--'));
  const workers = +pos[0], budget = +pos[1] * 60_000, outFile = pos[2], files = pos.slice(3);
  const every = +(flags.find((f) => f.startsWith('--every='))?.slice(8) ?? 1), offset = +(flags.find((f) => f.startsWith('--offset='))?.slice(9) ?? 0);
  const tmp = path.join(process.env.TMPDIR || os.tmpdir(), 'swiftmut');
  fs.mkdirSync(tmp, { recursive: true });
  const advPath = path.join(tmp, 'adv.json');
  if (!fs.existsSync(advPath)) {
    const z = await import('node:zlib');
    fs.writeFileSync(advPath, z.gunzipSync(fs.readFileSync(path.join(root, 'packages/pca/conformance/vectors-adversarial.json.gz'))));
  }
  let all = [];
  const srcHash = sha(files.map((f) => f + '\0' + fs.readFileSync(path.join(pkg, f), 'utf8')).join('\0'));
  for (const f of files) { const ms = mutantsFor(path.join(pkg, f)); annotate(path.join(pkg, f), ms, srcHash); ms.forEach((m, i) => all.push({ file: f, idx: i, ...m })); }
  all = all.filter((_, i) => i % every === offset);
  // --retry=a.json,b.json: only the mutants that SURVIVED in earlier result files (matched by file + source text + op +
  // replacement, so line shifts from edits elsewhere in the file do not matter)
  const retry = flags.find((f) => f.startsWith('--retry='))?.slice(8);
  if (retry) {
    const want = new Set();
    for (const f of retry.split(',')) for (const r of JSON.parse(fs.readFileSync(f, 'utf8'))) if (r.status === 'SURVIVED') want.add(`${r.file}#${r.orig}#${r.op}#${r.repl}`);
    all = all.filter((m) => want.has(`${m.file}#${m.orig}#${m.op}#${m.repl}`));
  }
  const results = fs.existsSync(outFile) ? JSON.parse(fs.readFileSync(outFile, 'utf8')) : [];
  const rec = (m, status, extra = {}) => ({ file: m.file, idx: m.idx, line: m.line, op: m.op, orig: m.orig, repl: m.repl, status, key: m.key, def_hash: m.def_hash, shell_hash: m.shell_hash, src_hash: m.src_hash, ...extra });
  // --carry=pool.json (targeted mode): a pooled result stands only when the mutant's def and the file's non-def code are
  // unchanged (KILLED/TIMEOUT), or the whole production source is (NONVIABLE); survivors, unseen and changed mutants run again.
  const carryFile = flags.find((f) => f.startsWith('--carry='))?.slice(8);
  if (carryFile) {
    const pool = loadPool(carryFile);
    if (!pool) { console.error(`cannot read --carry ${carryFile}`); process.exit(1); }
    const have = new Set(results.map((r) => `${r.file}#${r.idx}`));
    let c = 0, unseen = 0, changed = 0, nonkill = 0;
    for (const m of all) {
      if (have.has(`${m.file}#${m.idx}`)) continue;
      const e = pool[m.key];
      if (!e) unseen++;
      else if (e.d !== m.def_hash || e.h !== m.shell_hash) changed++;
      else if (mayCarry(e, m, { killed: ['KILLED', 'TIMEOUT'], uncompilable: ['NONVIABLE'] })) { results.push(rec(m, e.s, { carried: true })); c++; }
      else nonkill++;
    }
    console.error(`carry: ${c} result(s) carried, ${all.length - c} to run (${unseen} unseen, ${changed} def/file changed, ${nonkill} earlier survivors or uncompilable under changed sources)`);
  }
  const done = new Set(results.map((r) => `${r.file}#${r.idx}`));
  const queue = all.filter((m) => !done.has(`${m.file}#${m.idx}`));
  console.error(`mutants ${all.length}, remaining ${queue.length}`);
  const t0 = Date.now();
  const save = () => fs.writeFileSync(outFile, JSON.stringify(results, null, 1));
  let baselineSig = null, baselineCode = null;
  const MAX_RSS = (+process.env.SWIFTMUT_MAX_RSS_MB || 4096) * 1048576; // per worker (process group)
  const runOne = (w, m) => new Promise((resolve) => {
    const dir = path.join(tmp, `w${w}`, 'sdks/swift-pca');
    const target = path.join(dir, m.file);
    const orig = fs.readFileSync(path.join(pkg, m.file), 'utf8');
    fs.writeFileSync(target, m.text);
    // own process group, so a timeout / memory kill takes the compiler and the test binary down with the driver
    // ulimit -d: a hard per-process heap cap, so a runaway allocation fails (the oracle crashes == detected) instead of
    // exhausting the job's cgroup before the watchdog below can react.
    const p = spawn('bash', ['-c', `ulimit -d ${Math.floor(MAX_RSS / 1024)}; exec nice -n 19 swift test --scratch-path "$0" --filter "\${SWIFTMUT_FILTER:-${m.file.includes('/AtlasPCASQLite/') ? 'AtlasPCASQLiteTests' : 'AtlasPCAVerifyTests'}}"`, path.join(dir, '.b')], { cwd: dir, env: { ...process.env, PCA_CONFORMANCE_ADV: advPath, SWIFTMUT_FILE: m.file }, stdio: ['ignore', 'pipe', 'pipe'], detached: true });
    let out = '';
    const add = (d) => { if (out.length < 16 << 20) out += d; };
    p.stdout.on('data', add); p.stderr.on('data', add);
    const killGroup = () => { try { process.kill(-p.pid, 'SIGKILL'); } catch { try { p.kill('SIGKILL'); } catch {} } };
    const to = setTimeout(killGroup, 150_000);
    // memory watchdog: a mutant that allocates without bound (e.g. a loop that keeps appending) would otherwise exhaust
    // the job's memory cap within seconds and the OOM kill would lose the whole run. Over the cap == detected (TIMEOUT).
    let memKilled = false;
    const wd = setInterval(() => {
      // RSS of the whole descendant tree of the oracle (children may run in their own process groups)
      const kids = new Map(), rss = new Map();
      try {
        for (const e of fs.readdirSync('/proc')) {
          if (!/^\d+$/.test(e)) continue;
          let st; try { st = fs.readFileSync(`/proc/${e}/stat`, 'utf8'); } catch { continue; }
          const f = st.slice(st.lastIndexOf(')') + 2).split(' ');
          const pp = +f[1];
          if (!kids.has(pp)) kids.set(pp, []);
          kids.get(pp).push(+e); rss.set(+e, +f[21]);
        }
      } catch { return; }
      let pages = 0; const tree = [p.pid];
      for (let k = 0; k < tree.length; k++) { pages += rss.get(tree[k]) ?? 0; for (const c of kids.get(tree[k]) ?? []) tree.push(c); }
      if (pages * 4096 > MAX_RSS) { memKilled = true; killGroup(); for (const t of tree) { try { process.kill(t, 'SIGKILL'); } catch {} } }
    }, 250);
    p.on('close', (code, sig) => {
      clearTimeout(to); clearInterval(wd);
      fs.writeFileSync(target, orig);
      let status;
      const lines = out.split('\n').filter((l) => /error:/.test(l));
      const compileErr = lines.some((l) => /\/Sources\//.test(l));
      const sig2 = JSON.stringify(lines.filter((l) => /\/Tests\//.test(l)).map((l) => l.replace(/^.*\/Tests\//, 'Tests/')).sort());
      if (sig === 'SIGKILL' || memKilled) status = 'TIMEOUT';
      else if (compileErr) status = 'NONVIABLE';
      else if (m.baseline === true) { baselineSig = sig2; status = 'SURVIVED'; }
      else status = sig2 === baselineSig && code === (baselineCode ?? code) ? 'SURVIVED' : 'KILLED';
      if (m.baseline === true) baselineCode = code;
      resolve(status);
    });
  });
  const wk = async (w) => {
    const wroot = path.join(tmp, `w${w}`);
    const dir = path.join(wroot, 'sdks/swift-pca');
    fs.rmSync(path.join(dir, 'Sources'), { recursive: true, force: true });
    fs.mkdirSync(dir, { recursive: true });
    fs.mkdirSync(path.join(wroot, 'tools'), { recursive: true });
    for (const [l, t] of [['packages', path.join(root, 'packages')], ['tools/pca-diff-fuzz', path.join(root, 'tools/pca-diff-fuzz')]]) { try { fs.rmSync(path.join(wroot, l), { force: true }); fs.symlinkSync(t, path.join(wroot, l)); } catch {} }
    for (const d of ['Sources', 'Tests', 'test-data', 'Package.swift']) spawnSync('cp', ['-R', path.join(pkg, d), dir]);
    // warm build
    spawnSync('nice', ['-n', '19', 'swift', 'build', '--build-tests', '--scratch-path', path.join(dir, '.b')], { cwd: dir, stdio: 'ignore' });
    // baseline: the unmutated copy must pass the oracle, otherwise every mutant would be trivially 'killed'
    const base = await runOne(w, { file: files[0], text: fs.readFileSync(path.join(pkg, files[0]), 'utf8'), baseline: true });
    if (base !== 'SURVIVED') { console.error(`worker ${w}: BASELINE FAILED (${base}); aborting`); process.exit(3); }
    while (queue.length && Date.now() - t0 < budget) {
      const m = queue.shift();
      const status = await runOne(w, m);
      results.push(rec(m, status));
      if (results.length % 5 === 0) save();
    }
  };
  // nothing to run (everything carried): no worker copies, no warm build, no baseline
  await Promise.all(Array.from({ length: Math.min(workers, queue.length) }, (_, w) => wk(w)));
  save();
  const by = {};
  for (const r of results) by[r.status] = (by[r.status] || 0) + 1;
  console.error(JSON.stringify(by));
}
