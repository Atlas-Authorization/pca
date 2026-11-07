#!/usr/bin/env node
// Small operator mutator for the Swift verifier (Muter is not available here). Works on COPIES of the package (never edits the repo):
//   node mutate.mjs list  <file.swift>...                      list mutants (id, line, op, original => replacement)
//   node mutate.mjs run   <workers> <budget-minutes> <out.json> <file.swift>... [--only=ids] [--every=N --offset=K: contiguous slice K of N]
// Each worker owns a private copy of sdks/swift-pca under $TMPDIR/swiftmut/wN, applies one mutant, runs the oracle
// (swift test: existing unit tests + core conformance + the FULL adversarial corpus via PCA_CONFORMANCE_ADV) under nice,
// and records KILLED / SURVIVED / NONVIABLE (compile error) / TIMEOUT / TRAP / RUNERR. A mutant is KILLED iff a test assertion failed;
// a deterministic Swift runtime trap with no assertion failing is TRAP (reported with its failing test and message); any other crash,
// or a memory-cap kill, is RUNERR (each needs a reason in sdks/swift-pca/mutation-run-errors.json).
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
// The 0-based lines of a source that a Linux build does not compile: the inactive branches of every #if / #elseif / #else. A
// condition outside the known set throws (it must be classified here, never silently guessed).
const LINUX_CAN_IMPORT = { FoundationNetworking: true, Glibc: true, COQS: true, Crypto: true, CSQLite3: true,
  Security: false, CryptoKit: false, SQLite3: false, Darwin: false, LocalAuthentication: false };
function linuxCond(c, file, ln) {
  const t = c.trim();
  if (t.startsWith('!')) return !linuxCond(t.slice(1), file, ln);
  let m;
  if ((m = /^os\((\w+)\)$/.exec(t))) return m[1] === 'Linux';
  if ((m = /^canImport\((\w+)\)$/.exec(t)) && m[1] in LINUX_CAN_IMPORT) return LINUX_CAN_IMPORT[m[1]];
  throw new Error(`${file}:${ln + 1}: unclassified compile condition '${t}' (add it to linuxCond)`);
}
function linuxDead(file, src) {
  const dead = new Set();
  const stack = []; // {active: this branch compiles, taken: an earlier branch of the block compiled, outer: the enclosing block compiles}
  src.forEach((l, i) => {
    const t = l.trim();
    let m;
    const live = stack.length ? stack[stack.length - 1].active : true;
    if ((m = /^#if\s+(.+)$/.exec(t))) { const c = live && linuxCond(m[1], file, i); stack.push({ active: c, taken: c, outer: live }); return; }
    if ((m = /^#elseif\s+(.+)$/.exec(t))) { const f = stack[stack.length - 1]; const c = f.outer && !f.taken && linuxCond(m[1], file, i); f.active = c; f.taken ||= c; return; }
    if (t === '#else') { const f = stack[stack.length - 1]; f.active = f.outer && !f.taken; f.taken = true; return; }
    if (t === '#endif') { stack.pop(); return; }
    if (!live) dead.add(i);
  });
  if (stack.length) throw new Error(`${file}: unterminated #if`);
  return dead;
}
// Where the condition starting at `from` ends on this masked line: before the body's `{` (guard: before ` else`), at bracket depth 0. -1 when it continues on the next line.
function condEnd(m, from, kw) {
  let depth = 0;
  for (let i = from; i < m.length; i++) {
    const c = m[i];
    if (c === '(' || c === '[') depth++;
    else if (c === ')' || c === ']') depth--;
    else if (depth === 0 && (kw === 'guard' ? m.startsWith(' else', i) && /^ else\s*(\{|$)/.test(m.slice(i)) : c === '{')) return m.slice(0, i).trimEnd().length;
  }
  return -1;
}
function hasTopComma(c) {
  let depth = 0;
  for (const ch of c) { if (ch === '(' || ch === '[') depth++; else if (ch === ')' || ch === ']') depth--; else if (ch === ',' && depth === 0) return true; }
  return false;
}
function mutantsFor(file) {
  const src = fs.readFileSync(file, 'utf8').split('\n');
  const out = [];
  const add = (ln, repl, op) => { if (repl !== src[ln]) out.push({ line: ln + 1, op, orig: src[ln].trim(), repl: repl.trim(), text: src.map((x, i) => (i === ln ? repl : x)).join('\n') }); };
  // Lines this platform does not compile (#if conditions evaluated for it). A mutant there changes nothing the oracle runs, so it
  // would only report a fake survivor. The Linux shards mutate what Linux compiles; the macOS leg (SWIFTMUT_APPLE=1) mutates
  // exactly the lines Linux does NOT compile (the Keychain store, the CryptoKit ML-DSA branch), so every line is mutated once.
  const dead = new Set();
  if (process.platform === 'linux' || process.env.SWIFTMUT_APPLE === '1') {
    const notLinux = linuxDead(file, src);
    if (process.env.SWIFTMUT_APPLE === '1') { src.forEach((_, i) => { if (!notLinux.has(i)) dead.add(i); }); }
    else for (const i of notLinux) dead.add(i);
  }
  src.forEach((raw, ln) => {
    if (dead.has(ln)) return;
    const m = maskLine(raw);
    const before = out.length;
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
    // if/guard conditions: negate the whole condition. A condition that cannot be negated (a let/case binding, or a comma list) is forced false instead.
    const head = /^(\s*(?:\}\s*else\s+)?)(if|guard|while)\s/.exec(m);
    if (head) {
      const start = head[0].length;
      const end = condEnd(m, start, head[2]);
      const c = end < 0 ? m.slice(start) : m.slice(start, end);
      if (end < 0 || /\b(let|case|var)\b/.test(c) || hasTopComma(c)) add(ln, `${raw.slice(0, start)}false, ${raw.slice(start)}`, `${head[2]}-false`);
      else if (head[2] !== 'while') add(ln, `${raw.slice(0, start)}!(${raw.slice(start, end)})${raw.slice(end)}`, `${head[2]}-negate`);
    }
    // a statement no other operator touches: an assignment or a call whose only effect (a check that throws, a state change) would otherwise never be tested
    if (out.length === before && !raw.includes(';') && !/^\s*self\.(\w+) = \1\s*$/.test(m)
      && (/^\s*[A-Za-z_][\w.]*(\[[^\]]*\])? = \S/.test(m) || /^\s*(try\s+)?[A-Za-z_][\w.]*\(.*\)\s*$/.test(m)) && !/^\s*(if|guard|while|return|throw|case|let|var|func|init|for|switch)\b/.test(m)) {
      add(ln, `${raw.slice(0, raw.length - raw.trimStart().length)}/* dropped */`, 'drop-stmt');
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

// A Swift runtime trap: SIGILL (Linux) or SIGTRAP (Darwin) with the runtime's own message, in the test that was running. An allocation
// failure traps too, but that is the memory limit (ulimit -d), so it stays a run error, as does a signal with no message.
const trapOf = (out) => {
  // swift test does not always print the signal code; the backtracer's own header says the same thing
  if (!/signal code (4|5)\b|Program crashed: (Illegal instruction|Trace\/BPT trap|Breakpoint)/.test(out)) return null;
  // a crash while listing the tests: no test ran, so it is a run error whatever it printed
  if (/--dump-tests-json output:/.test(out)) return null;
  const message = out.match(/Fatal error:[^\n]*/)?.[0] ?? out.match(/Swift runtime failure:[^\n]*/i)?.[0];
  if (!message || /allocat|memory/i.test(message)) return null;
  // the started line can be lost with the crashed process's buffered stdout; then the backtrace names the test. No test, no trap: a run error.
  const test = [...out.matchAll(/Test Case '([^']+)' started/g)].pop()?.[1] ?? out.match(/\b(\w+\.test\w*)\(\)/)?.[1];
  return test ? { message: message.trim().slice(0, 300), test } : null;
};

const [cmd, ...rest] = process.argv.slice(2);
if (cmd === 'plan-check') { // every source file must yield mutants on some platform, or be named in mutation-no-logic.json with a reason
  const named = new Map(JSON.parse(fs.readFileSync(path.join(pkg, 'mutation-no-logic.json'), 'utf8')).map((e) => [e.file, e.reason]));
  const files = fs.readdirSync(path.join(pkg, 'Sources'), { recursive: true }).map(String).filter((f) => f.endsWith('.swift')).sort().map((f) => `Sources/${f}`);
  const count = (f, apple) => { const was = process.env.SWIFTMUT_APPLE; if (apple) process.env.SWIFTMUT_APPLE = '1'; else delete process.env.SWIFTMUT_APPLE; const n = mutantsFor(path.join(pkg, f)).length; if (was === undefined) delete process.env.SWIFTMUT_APPLE; else process.env.SWIFTMUT_APPLE = was; return n; };
  let bad = 0, total = 0;
  for (const f of files) {
    const n = count(f, false) + (process.platform === 'linux' ? count(f, true) : 0); total += n;
    const r = named.get(f); named.delete(f);
    if (n === 0 && !(r && r.length >= 12)) { console.error(`::error::${f} yields 0 mutants and is not named with a reason in mutation-no-logic.json`); bad++; }
    if (n > 0 && r) { console.error(`::error::${f} is named as no-logic but yields ${n} mutants: stale entry`); bad++; }
  }
  for (const f of named.keys()) { console.error(`::error::mutation-no-logic.json names ${f}, which is not a source file`); bad++; }
  console.log(`plan-check: ${files.length} files, ${total} mutants, ${bad} problem(s)`);
  process.exit(bad ? 1 : 0);
}
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
  // contiguous slices (not round-robin): a shard then spans a file or two, so it verifies one or two oracle groups on the
  // unmutated sources instead of all ~40 (each a 2-3 min suite run). The workflow's count check uses the same formula.
  { const n = all.length, lo = Math.floor(offset * n / every), hi = Math.floor((offset + 1) * n / every); all = all.slice(lo, hi); }
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
  const MAX_RSS = (+process.env.SWIFTMUT_MAX_RSS_MB || 4096) * 1048576; // per worker (process group)
  const targetOf = (file) => file.includes('/AtlasPCASQLite/') ? 'AtlasPCASQLiteTests' : file.includes('/AtlasPCAStepUp/') ? 'AtlasPCAStepUpTests' : 'AtlasPCAVerifyTests';
  // fail-fast phase: the test classes named after the mutated file (e.g. Actions.swift -> ActionsVectorTests, K05ActionsOracleTests).
  // Each passes on the unmutated sources (the full suite is green), so a failure there is the mutant's doing: KILLED without
  // paying for the rest of the suite. A mutant they do not kill still faces the WHOLE suite (phase 2), so no survivor is lost.
  const classesOf = new Map();
  const phase1 = (file) => {
    if (process.env.SWIFTMUT_FILTER) return null;
    const t = targetOf(file);
    if (!classesOf.has(t)) {
      const names = [];
      const dir = path.join(pkg, 'Tests', t);
      for (const f of fs.existsSync(dir) ? fs.readdirSync(dir).filter((x) => x.endsWith('.swift')) : []) {
        for (const mm of fs.readFileSync(path.join(dir, f), 'utf8').matchAll(/\bclass\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*XCTestCase\b/g)) names.push(mm[1]);
      }
      classesOf.set(t, names);
    }
    const stem = path.basename(file, '.swift');
    const hit = classesOf.get(t).filter((c) => c.includes(stem));
    return hit.length ? `${t}\\.(${hit.join('|')})/` : null;
  };
  // Oracle groups. Under mutation the heavy oracles run only for the files they cover (K042.requireCovers: SWIFTMUT_FILE contains
  // one of the class's cover tokens), so the suite a mutant faces depends on its file. Files whose path contains the same cover
  // tokens face the same suite: one group. Before the first mutant of a group is judged, the UNMUTATED sources must pass that
  // group's suite (exit 0, no failure): otherwise every mutant of the group would be counted killed by a suite that fails anyway
  // (e.g. an oracle that cannot run in the mutation sandbox). The same run sets the group's time limit, max(150 s, 2 x its
  // duration + 60 s): a fixed limit would turn every mutant of a heavily covered file into a false TIMEOUT (= counted detected).
  const DEFAULT_LIMIT = 150_000;
  const coverTokens = (() => {
    const toks = new Set();
    let opaque = false;
    for (const t of ['AtlasPCAVerifyTests', 'AtlasPCASQLiteTests', 'AtlasPCAStepUpTests']) {
      const dir = path.join(pkg, 'Tests', t);
      for (const f of fs.existsSync(dir) ? fs.readdirSync(dir).filter((x) => x.endsWith('.swift')) : []) {
        const src = fs.readFileSync(path.join(dir, f), 'utf8');
        for (const mm of src.matchAll(/static\s+let\s+covers\s*=\s*\[([^\]]*)\]/g)) for (const q of mm[1].matchAll(/"([^"]+)"/g)) toks.add(q[1]);
        for (const mm of src.matchAll(/requireCovers\(([^)]*)\)/g)) {
          const a = mm[1].trim();
          if (a === 'Self.covers' || a === '_ files: [String]') continue;
          if (/^\[[^\]]*\]$/.test(a)) { for (const q of a.matchAll(/"([^"]+)"/g)) toks.add(q[1]); } else opaque = true;
        }
      }
    }
    return { toks: [...toks].sort(), opaque };
  })();
  // an unparsed requireCovers argument: every file is its own group (still correct, only slower)
  const groupOf = (file) => coverTokens.opaque ? file : `${targetOf(file)}|${coverTokens.toks.filter((t) => file.includes(t)).join(',')}`;
  const groups = new Map(); // group -> Promise<limit ms>
  const verifyGroup = (w, file) => {
    const g = groupOf(file);
    if (!groups.has(g)) groups.set(g, (async () => {
      const r = await exec(w, file, process.env.SWIFTMUT_FILTER || targetOf(file), false, 3_600_000);
      if (r.timedOut || r.memKilled || r.compileErr || r.code !== 0 || r.sig !== '[]') {
        console.error(`worker ${w}: UNMUTATED ORACLE FAILED for group [${g}] (file ${file}): ${JSON.stringify({ code: r.code, ms: r.ms, memKilled: r.memKilled, timedOut: r.timedOut, compileErr: r.compileErr, sig: r.sig.slice(0, 400) })}\n${r.tail}\naborting`);
        process.exit(3);
      }
      const lim = Math.max(DEFAULT_LIMIT, 3 * r.ms + 120_000); // margin for a slow runner; a timeout is then re-judged at twice this
      console.error(`group [${g}]: unmutated ${Math.round(r.ms / 1000)} s, limit ${Math.round(lim / 1000)} s`);
      return lim;
    })());
    return groups.get(g);
  };
  const exec = (w, file, filter, skipBuild, limit) => new Promise((resolve) => {
    const dir = path.join(tmp, `w${w}`, 'sdks/swift-pca');
    // own process group, so a timeout / memory kill takes the compiler and the test binary down with the driver
    // ulimit -d: a hard per-process backstop, so a runaway allocation fails (the oracle crashes == detected) instead of
    // exhausting the job's cgroup before the watchdog below can react. RLIMIT_DATA counts VIRTUAL private mappings (malloc arenas,
    // reservations), so it sits at 3x the RSS cap: at 1x the unmutated k05 oracles (170 MB files read whole) crashed.
    const t0 = Date.now();
    const p = spawn('bash', ['-c', `ulimit -d ${Math.floor(3 * MAX_RSS / 1024)}; exec nice -n 19 $(command -v stdbuf >/dev/null && echo stdbuf -oL) swift test ${skipBuild ? '--skip-build ' : ''}--scratch-path "$0" --filter "$1"`, path.join(dir, '.b'), filter], { cwd: dir, env: { ...process.env, PCA_CONFORMANCE_ADV: advPath, SWIFTMUT_FILE: file }, stdio: ['ignore', 'pipe', 'pipe'], detached: true });
    let out = '';
    const add = (d) => { if (out.length < 16 << 20) out += d; };
    p.stdout.on('data', add); p.stderr.on('data', add);
    const killGroup = () => { try { process.kill(-p.pid, 'SIGKILL'); } catch { try { p.kill('SIGKILL'); } catch {} } };
    const to = setTimeout(killGroup, limit);
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
      const lines = out.split('\n').filter((l) => /error:/.test(l));
      resolve({
        code, ms: Date.now() - t0, memKilled, timedOut: sig === 'SIGKILL' && !memKilled, signal: sig,
        // the build finished and the tests ran (SwiftPM flushes 'Build complete!'; the test binary's own output may sit in a pipe buffer)
        started: skipBuild || /Build complete!|Test Suite '/.test(out),
        // an ordinary XCTest failure (an assertion, or a test that threw): Linux `file:line: error: Class.test : msg`, Darwin
        // `file:line: error: -[Module.Class test] : msg`. A non-zero exit WITHOUT one is a crash (trap, fatalError, overflow, signal).
        asserted: /: error: (-\[[\w.]+ \w+\]|[\w.]+\.\w+) : /m.test(out),
        trap: trapOf(out),
        // the runtime's own message first; the last-match fallback must skip the backtracer's register dump, which can quote "Fatal error" from memory
        crash: `${/--dump-tests-json output:/.test(out) ? 'crashed listing the tests, no test ran: ' : ''}${(out.match(/Fatal error:[^\n]*/)?.[0] ?? out.split('\n').filter((l) => !/^\s*r\w+ 0x/.test(l) && /Fatal error|fatal error|Illegal instruction|Segmentation fault|Trace\/breakpoint|Aborted|signal|exited with|Bus error|stack overflow/i.test(l)).pop() ?? '').trim().slice(0, 300)}`,
        tail: out.split('\n').filter((l) => !/^\s*Executed \d+ tests?,/.test(l) && /error|fatal|signal|crash|killed|exited|illegal|segmentation|abort|unexpected|threw/i.test(l)).slice(-40).join('\n').slice(-6000),
        // a COMPILER diagnostic in a source (path:line:col: error:). Not any "error:" line naming a source: a runtime trap prints
        // "<path>/Sources/X.swift:12: Fatal error: ..." (no column) and is the mutant being detected, not an uncompilable mutant.
        compileErr: lines.find((l) => /\/Sources\/[^:]+\.swift:\d+:\d+: error:/.test(l)) ?? null,
        sig: JSON.stringify(lines.filter((l) => /\/Tests\//.test(l)).map((l) => l.replace(/^.*\/Tests\//, 'Tests/')).sort()),
      });
    });
  });
  const lastCompileErr = new Map(); // worker -> the compile error line of its last NONVIABLE verdict
  // A run whose test binary never started and that shows no compiler error is neither a kill nor an uncompilable mutant (a broken
  // build, the toolchain): run it once more, and if it repeats stop the shard loudly, so nothing is counted on a run that did not run.
  const run = async (w, m, filter, skipBuild, limit) => {
    // a time limit hit while still BUILDING is no detection either (the limit is sized on the unmutated test run): retry with twice the time
    const ran = (r) => r.started || r.compileErr || r.memKilled;
    let r = await exec(w, m.file, filter, skipBuild, limit);
    if (ran(r)) return r;
    console.error(`worker ${w}: ${m.file}:${m.line} ${m.op}: the tests did not start (exit ${r.code}, timed out ${r.timedOut}), retrying\n${r.tail}`);
    r = await exec(w, m.file, filter, false, 2 * limit);
    if (ran(r)) return r;
    console.error(`worker ${w}: ${m.file}:${m.line} ${m.op}: the tests did not start again (exit ${r.code}): aborting\n${r.tail}`);
    process.exit(3);
  };
  // A mutant is KILLED only when an ordinary test assertion failed. A deterministic runtime trap (fatalError, index out of range,
  // overflow) with no assertion failing is TRAP: never a plain kill, reported per mutant with its test and message. A memory-cap kill,
  // or a test process that died any other way, is a RUN ERROR, and the merge requires a reason for each one in
  // sdks/swift-pca/mutation-run-errors.json (BRIEF: crash / out-of-memory mutants are run errors, not kills).
  const crashOf = (r) => r.memKilled ? `memory cap (${MAX_RSS / 1048576} MiB RSS) exceeded` : `exit ${r.code}${r.signal ? ` signal ${r.signal}` : ''}: ${r.crash || 'no assertion failed'}`;
  const crashed = (r) => r.asserted ? { status: 'KILLED' } : r.trap ? { status: 'TRAP', trap: r.trap } : { status: 'RUNERR', evidence: crashOf(r) };
  const judge = async (w, m, limit) => {
    let built = false;
    const p1 = phase1(m.file);
    if (p1) {
      const r = await run(w, m, p1, false, limit);
      if (r.memKilled) return { status: 'RUNERR', evidence: crashOf(r) };
      if (r.compileErr) { lastCompileErr.set(w, r.compileErr); return { status: 'NONVIABLE' }; }
      if (!r.timedOut && r.code !== 0) return crashed(r);
      if (!r.timedOut) built = true;
    }
    let r = await run(w, m, process.env.SWIFTMUT_FILTER || targetOf(m.file), built, limit);
    // a timeout is no verdict: judge once more at twice the limit, so a slow runner or GC pause cannot leave a behaviour-preserving
    // mutant undecided. A second timeout is TIMEOUT, a run error that needs a ledger entry proving the mutant itself never ends.
    if (r.timedOut) r = await run(w, m, process.env.SWIFTMUT_FILTER || targetOf(m.file), built || r.started, 2 * limit);
    if (r.memKilled) return { status: 'RUNERR', evidence: crashOf(r) };
    if (r.timedOut) return { status: 'TIMEOUT', evidence: `no verdict within ${limit} ms nor within ${2 * limit} ms (the unmutated group passed well inside the first)` };
    if (r.compileErr) { lastCompileErr.set(w, r.compileErr); return { status: 'NONVIABLE' }; }
    // the unmutated group suite passed with exit 0 and no failure line
    if (r.code === 0 && r.sig === '[]') return { status: 'SURVIVED' };
    return crashed(r);
  };
  const runOne = async (w, m) => {
    const limit = await verifyGroup(w, m.file); // runs on the unmutated copy, before the mutant is written
    const target = path.join(tmp, `w${w}`, 'sdks/swift-pca', m.file);
    const orig = fs.readFileSync(path.join(pkg, m.file), 'utf8');
    fs.writeFileSync(target, m.text);
    try {
      const st = await judge(w, m, limit);
      // every uncompilable verdict and every run error is auditable in the log
      if (st.status === 'NONVIABLE') console.error(`NONVIABLE ${m.file}:${m.line} ${m.op}: ${String(lastCompileErr.get(w)).replace(/^.*\/Sources\//, 'Sources/').slice(0, 300)}`);
      if (st.status === 'RUNERR') console.error(`RUNERR ${m.file}:${m.line} ${m.op}: ${st.evidence}`);
      return st;
    } finally { fs.writeFileSync(target, orig); }
  };
  const wk = async (w) => {
    const wroot = path.join(tmp, `w${w}`);
    const dir = path.join(wroot, 'sdks/swift-pca');
    fs.rmSync(path.join(dir, 'Sources'), { recursive: true, force: true });
    fs.mkdirSync(dir, { recursive: true });
    fs.mkdirSync(path.join(wroot, 'tools'), { recursive: true });
    for (const [l, t] of [['packages', path.join(root, 'packages')], ['tools/pca-diff-fuzz', path.join(root, 'tools/pca-diff-fuzz')]]) { try { fs.rmSync(path.join(wroot, l), { force: true }); fs.symlinkSync(t, path.join(wroot, l)); } catch {} }
    // README.md: AuthorizeTests.testReadmeSampleIsThisCode reads ../../README.md (missing => it throws, the unmutated suite fails)
    for (const d of ['Sources', 'Tests', 'test-data', 'Package.swift', 'README.md']) spawnSync('cp', ['-R', path.join(pkg, d), dir]);
    // warm build
    spawnSync('nice', ['-n', '19', 'swift', 'build', '--build-tests', '--scratch-path', path.join(dir, '.b')], { cwd: dir, stdio: 'ignore' });
    // no separate baseline: runOne verifies each oracle group on the unmutated copy before judging its first mutant
    while (queue.length && Date.now() - t0 < budget) {
      const m = queue.shift();
      const st = await runOne(w, m);
      results.push(rec(m, st.status, st.evidence ? { evidence: st.evidence } : st.trap ? { trap: st.trap } : {}));
      if (results.length % 5 === 0) save();
    }
  };
  // nothing to run (everything carried): no worker copies, no warm build, no group verification
  await Promise.all(Array.from({ length: Math.min(workers, queue.length) }, (_, w) => wk(w)));
  save();
  const by = {};
  for (const r of results) by[r.status] = (by[r.status] || 0) + 1;
  console.error(JSON.stringify(by));
}
