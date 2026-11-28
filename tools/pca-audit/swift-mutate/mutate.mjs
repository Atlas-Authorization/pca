#!/usr/bin/env node
// Small operator mutator for the Swift verifier (Muter is not available here). Works on COPIES of the package (never edits the repo):
//   node mutate.mjs list  <file.swift>...                      list mutants (id, line, op, original => replacement)
//   node mutate.mjs torun <pool.json|-> --every=N --offset=K <file.swift>...   how many of a slice's mutants a --carry run still has to run
//   node mutate.mjs run   <workers> <budget-minutes> <out.json> <file.swift>... [--only=ids] [--every=N --offset=K: contiguous slice K of N]
//        slicing: --weighted = the N slices are contiguous but equal in estimated COST (mutants x the test set each faces, see staticCost), not equal in
//        mutant count; --range=LO-HI = mutant indices LO..HI-1 of the whole list. `torun` and `run` take the same flags, so a count check agrees.
//        --oracle-out=<dir>: run no mutant; build once, verify the unmutated oracle of every group, write <dir>/oracle.json (tree hash, per-group
//        duration and time limit) and mark the worker copies (<tmp>/swiftmut/wN) restorable. --oracle-in=<dir>: reuse that oracle.json (the groups are not
//        verified again) and the worker copies restored from the baseline job's tarball (no copy, no warm build), only when its tree hash equals this
//        tree's; otherwise the slice verifies and builds itself, with a warning.
//        --oracle-part=K/N (with --oracle-out): verify only the oracle groups whose index (in plan order, over the files that have mutants) is K mod N, so
//        N parallel jobs verify all of them; each writes its share plus the total group count (oracle-merge.mjs joins the shares and checks they are
//        complete). --oracle-part=build: verify nothing, only build and mark the copies restorable (the build the parts and the slices restore).
//        --items=<file> (item mode, the schema pipeline): instead of a slice, the items of one job of the mutation plan (schema-jobs.mjs):
//          {mode: 'schema', bundle: <dir>, items: [{id, att?}]}: mutants of a schema build (schema-build.mjs), run from its prebuilt tree
//            (restored at <tmp>/swiftmut/w0) with PCA_MUTANT=<id>: first only the test classes that reach the mutant, then the full suite
//          {mode: 'real', items: [{key, att?, sample?}]}: real per-mutant builds (the fallback and the self-check samples), as in a slice
//          att: 2 or 3 = one more full-suite attempt at 1.5x the limit for a mutant whose first full suite timed out
//          --deadline=<epoch ms>: no item starts after it, and the runs still going are killed; --pending-out=<file> gets every item not
//          decided here (not started, killed at the deadline, or a first full-suite timeout: then its attempts 2 and 3), for the next level.
// Each worker owns a private copy of sdks/swift-pca under $TMPDIR/swiftmut/wN, applies one mutant, runs the oracle
// (swift test: existing unit tests + core conformance + the FULL adversarial corpus via PCA_CONFORMANCE_ADV) under nice,
// and records KILLED / SURVIVED / NONVIABLE (compile error) / TIMEOUT / TRAP / RUNERR. A mutant is KILLED iff a test assertion failed;
// a deterministic Swift runtime trap with no assertion failing is TRAP (reported with its failing test and message); any other crash,
// or a memory-cap kill, is RUNERR (each needs a reason in sdks/swift-pca/mutation-run-errors.json).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { sha, normText, mayCarry, loadPool } from '../mut-carry/lib.mjs';
import { maskLine, maskAll, schemaFile } from './schema.mjs';
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../../..');
const pkg = path.join(root, 'sdks/swift-pca');

// ---- shared slicing + cost model ----
const targetOfFile = (file) => file.includes('/AtlasPCASQLite/') ? 'AtlasPCASQLiteTests' : file.includes('/AtlasPCAStepUp/') ? 'AtlasPCAStepUpTests' : 'AtlasPCAVerifyTests';
// What a baseline oracle proves: the unmutated sources, tests and manifest of this exact tree (and the test flags) pass. The shard recomputes this and
// refuses an oracle of another tree.
function treeHash() {
  const h = createHash('sha256');
  const walkFiles = (d, out) => { for (const e of fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) { const q = path.join(d, e.name); if (e.isDirectory()) walkFiles(q, out); else out.push(q); } return out; };
  for (const f of [...walkFiles(path.join(pkg, 'Sources'), []), ...walkFiles(path.join(pkg, 'Tests'), []), path.join(pkg, 'Package.swift'), path.join(pkg, 'README.md')]) {
    if (fs.existsSync(f)) h.update(path.relative(pkg, f) + '\0').update(fs.readFileSync(f)).update('\0');
  }
  // the VDF replay's case selection (ATLAS_VDF_*) decides which cases the oracle runs, so an oracle of one selection never vouches for another
  h.update(`${process.env.SWIFT_TEST_FLAGS ?? ''}\0${process.env.SWIFTMUT_FILTER ?? ''}\0${process.env.SWIFTMUT_APPLE ?? ''}\0${process.platform}`);
  h.update(['ATLAS_VDF_FULL', 'ATLAS_VDF_SHARD', 'ATLAS_VDF_SOLO'].map((k) => `${k}=${process.env[k] ?? ''}`).join('\0'));
  return h.digest('hex');
}
// Static cost of ONE mutant of `file`, in units of "one run of the test classes named after the file". Every mutant pays that fail-fast run (plus the
// incremental rebuild, 1 unit); a mutant those classes do not kill faces the WHOLE target suite, whose size relative to them is R (test source bytes,
// capped). p is the share of mutants assumed to get that far: small when named classes exist (they kill most), large when none exist (the whole suite
// is the only oracle). The constants are a model, not a measurement: they only have to rank files so hot regions get smaller slices.
const COST = { build: 1, pNamed: 0.12, pUnnamed: 0.4, rCap: 120, minBytes: 20000 };
const costMemo = new Map(), suiteBytes = new Map();
function staticCost(file) {
  if (costMemo.has(file)) return costMemo.get(file);
  const t = targetOfFile(file), dir = path.join(pkg, 'Tests', t);
  if (!suiteBytes.has(t)) {
    const fl = []; let total = 0;
    for (const f of fs.existsSync(dir) ? fs.readdirSync(dir).filter((x) => x.endsWith('.swift')) : []) {
      const src = fs.readFileSync(path.join(dir, f), 'utf8'); total += src.length;
      fl.push({ size: src.length, classes: [...src.matchAll(/\bclass\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*XCTestCase\b/g)].map((m) => m[1]) });
    }
    suiteBytes.set(t, { total, files: fl });
  }
  const { total, files } = suiteBytes.get(t);
  const stem = path.basename(file, '.swift');
  const named = files.filter((f) => f.classes.some((c) => c.includes(stem)));
  const p1 = named.reduce((a, f) => a + f.size, 0);
  const R = Math.min(COST.rCap, Math.max(1, total / Math.max(p1, COST.minBytes)));
  const c = COST.build + 1 + (named.length ? COST.pNamed : COST.pUnnamed) * R;
  costMemo.set(file, c);
  return c;
}
// the slice of `all` (mutants in plan order, each carrying .file) that flag set `flags` selects; contiguous, every mutant in exactly one of the N slices
function sliceMutants(all, every, offset, flags) {
  const range = flags.find((f) => f.startsWith('--range='));
  if (range) { const [lo, hi] = range.slice(8).split('-').map(Number); return all.slice(lo, hi); }
  if (!flags.includes('--weighted')) { const n = all.length; return all.slice(Math.floor(offset * n / every), Math.floor((offset + 1) * n / every)); }
  const w = all.map((m) => staticCost(m.file)), total = w.reduce((a, b) => a + b, 0);
  const out = []; let before = 0;
  all.forEach((m, i) => { const mid = (before + w[i] / 2) / total * every; before += w[i]; if (Math.floor(mid) === offset) out.push(m); });
  return out;
}
const RULES = [
  [/ == /g, ' != '], [/ != /g, ' == '], [/ <= /g, ' < '], [/ >= /g, ' > '], [/ < /g, ' <= '], [/ > /g, ' >= '],
  [/ && /g, ' || '], [/ \|\| /g, ' && '], [/ \+ /g, ' - '], [/ - /g, ' + '], [/ \* /g, ' / '], [/ & /g, ' | '], [/ \| /g, ' & '], [/ \^ /g, ' | '],
  [/ << /g, ' >> '], [/ >> /g, ' << '], [/\btrue\b/g, 'false'], [/\bfalse\b/g, 'true'],
];
// The 0-based lines of a source that a Linux build does not compile: the inactive branches of every #if / #elseif / #else. A
// condition outside the known set throws (it must be classified here, never silently guessed).
const LINUX_CAN_IMPORT = { FoundationNetworking: true, Glibc: true, Crypto: true, CSQLite3: true,
  Security: false, CryptoKit: false, SQLite3: false, Darwin: false, LocalAuthentication: false,
  // the opt-in LWE-OT module (MpcNet's #if): no Linux or apple-leg shard builds it (the macOS module job does, unfiltered); plan-check counts it as live
  AtlasPCALweOt: true };
// The same for the macOS leg (Xcode 26: Swift 6.2): what macOS compiles. A line neither platform compiles (the iOS / tvOS / watchOS stub
// of an `#if os(macOS) || os(Linux)`) is mutated by no runner of this workflow; plan-check lists those lines.
const MAC_CAN_IMPORT = { FoundationNetworking: false, Glibc: false, Crypto: false, CSQLite3: false, AtlasPCALweOt: true,
  Security: true, CryptoKit: true, SQLite3: true, Darwin: true, LocalAuthentication: true };
function platCond(c, file, ln, os, canImport, compilerOk) {
  const t = c.trim();
  const rec = (x) => platCond(x, file, ln, os, canImport, compilerOk);
  if (t.includes('||')) return t.split('||').some(rec);
  if (t.includes('&&')) return t.split('&&').every(rec);
  if (t.startsWith('!')) return !rec(t.slice(1));
  let m;
  if ((m = /^os\((\w+)\)$/.exec(t))) return m[1] === os;
  if ((m = /^canImport\((\w+)\)$/.exec(t)) && m[1] in canImport) return canImport[m[1]];
  if (/^compiler\(>=\s*[\d.]+\)$/.test(t)) return compilerOk(t);
  throw new Error(`${file}:${ln + 1}: unclassified compile condition '${t}' (add it to platCond)`);
}
const linuxCond = (c, file, ln) => platCond(c, file, ln, 'Linux', LINUX_CAN_IMPORT, () => true);
const macCond = (c, file, ln) => platCond(c, file, ln, 'macOS', MAC_CAN_IMPORT, () => true);
function linuxDead(file, src, cond = linuxCond) {
  const dead = new Set();
  const stack = []; // {active: this branch compiles, taken: an earlier branch of the block compiled, outer: the enclosing block compiles}
  src.forEach((l, i) => {
    const t = l.trim();
    let m;
    const live = stack.length ? stack[stack.length - 1].active : true;
    if ((m = /^#if\s+(.+)$/.exec(t))) { const c = live && cond(m[1], file, i); stack.push({ active: c, taken: c, outer: live }); return; }
    if ((m = /^#elseif\s+(.+)$/.exec(t))) { const f = stack[stack.length - 1]; const c = f.outer && !f.taken && cond(m[1], file, i); f.active = c; f.taken ||= c; return; }
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
let UNREACHED = null; // plan-check collects the lines no runner compiles here
const mutantText = (m) => m.lines.map((x, i) => (i === m.line - 1 ? m.raw : x)).join('\n');
function mutantsFor(file) {
  const src = fs.readFileSync(file, 'utf8').split('\n');
  const out = [];
  // raw: the mutant's whole line; the file text is built only when the mutant is written (mutantText), not kept per mutant
  const add = (ln, repl, op) => { if (repl !== src[ln]) out.push({ line: ln + 1, op, orig: src[ln].trim(), repl: repl.trim(), raw: repl, lines: src }); };
  // Lines this platform does not compile (#if conditions evaluated for it). A mutant there changes nothing the oracle runs, so it
  // would only report a fake survivor. The Linux shards mutate what Linux compiles; the macOS leg (SWIFTMUT_APPLE=1) mutates
  // exactly the lines Linux does NOT compile (the Keychain store, the CryptoKit ML-DSA branch), so every line is mutated once.
  const dead = new Set();
  if (process.platform === 'linux' || process.env.SWIFTMUT_APPLE === '1') {
    const notLinux = linuxDead(file, src);
    if (process.env.SWIFTMUT_APPLE === '1') {
      const notMac = linuxDead(file, src, macCond);
      src.forEach((raw, i) => {
        if (!notLinux.has(i)) dead.add(i);
        else if (notMac.has(i)) { dead.add(i); if (raw.trim() && !/^\s*(\/\/|#)/.test(raw) && UNREACHED) UNREACHED.push(`${path.relative(pkg, file)}:${i + 1}`); }
      });
    }
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
// (maskAll, in schema.mjs, blanks strings and comments across lines, so braces inside them never confuse the def scanner.)
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

// one result record (the shape every report, pool and carry decision reads)
const recOf = (m, status, extra = {}) => ({ file: m.file, idx: m.idx, line: m.line, op: m.op, orig: m.orig, repl: m.repl, status, key: m.key, def_hash: m.def_hash, shell_hash: m.shell_hash, src_hash: m.src_hash, ...extra });
const carryRule = { killed: ['KILLED'], uncompilable: ['NONVIABLE'], survived: ['SURVIVED'] };

const [cmd, ...rest] = process.argv.slice(2);
if (cmd === 'schema-plan') {
  // node mutate.mjs schema-plan <pool.json|-> --groups=G <file.swift>... --out=<dir>
  //   Every mutant of the files, with its key and carry decision exactly as `run --carry` makes them: a carried one keeps its pooled
  //   result (<out>/carried.json, result records); every other one goes to one of G schema groups (files packed largest first into the
  //   least loaded group), ids 1..n in the group in file order (PCA_MUTANT) -> <out>/plan.json (per group: files, n, sha of the keys).
  //   Each group is ONE schema build (schema-build.mjs). Prints how many mutants the generator holds and why the others fall back.
  // node mutate.mjs schema-plan <pool.json|-> --groups=G <file.swift>... --group=g --list=<file> [--plan=<plan.json>]
  //   the same plan, recomputed; writes group g's mutants [{id, key, file, line, op, raw}] (and refuses when --plan disagrees)
  const flags = rest.filter((a) => a.startsWith('--')), pos = rest.filter((a) => !a.startsWith('--'));
  const fv = (n) => flags.find((f) => f.startsWith(`--${n}=`))?.slice(n.length + 3);
  const G = +(fv('groups') ?? 0), out = fv('out'), only = fv('group'), list = fv('list');
  if (!(G >= 1) || !(out || (only !== undefined && list))) { console.error('usage: schema-plan <pool|-> --groups=G <files> --out=<dir> | --group=g --list=<file>'); process.exit(2); }
  const pool = pos[0] === '-' ? {} : loadPool(pos[0]); const files = pos.slice(1);
  if (!pool) { console.error(`cannot read pool ${pos[0]}`); process.exit(1); }
  const srcHash = sha(files.map((f) => f + '\0' + fs.readFileSync(path.join(pkg, f), 'utf8')).join('\0'));
  const carried = [], per = new Map(), seen = new Set();
  for (const f of files) {
    const ms = mutantsFor(path.join(pkg, f)); annotate(path.join(pkg, f), ms, srcHash);
    ms.forEach((m, i) => {
      const x = { file: f, idx: i, ...m };
      if (seen.has(x.key)) { console.error(`::error::two mutants share the key ${x.key}`); process.exit(1); }
      seen.add(x.key);
      const e = pool[x.key];
      if (e && e.d === x.def_hash && e.h === x.shell_hash && mayCarry(e, x, carryRule)) carried.push(recOf(x, e.s, { carried: true }));
      else { if (!per.has(f)) per.set(f, []); per.get(f).push(x); }
    });
  }
  const gs = Array.from({ length: Math.min(G, per.size) }, () => ({ files: [], n: 0 }));
  for (const [f, ms] of [...per].sort((a, b) => b[1].length - a[1].length || (a[0] < b[0] ? -1 : 1))) {
    const g = gs.reduce((best, x, i) => (x.n < gs[best].n ? i : best), 0);
    gs[g].files.push(f); gs[g].n += ms.length;
  }
  const listOf = (g) => { let id = 0; return g.files.slice().sort().flatMap((f) => per.get(f).map((m) => ({ id: ++id, key: m.key, file: f, line: m.line, op: m.op, raw: m.raw }))); };
  const keysSha = (ms) => sha(ms.map((m) => m.key).join('\n'));
  if (only !== undefined) {
    const g = gs[+only];
    if (!g) { console.error(`::error::no schema group ${only} (${gs.length} groups)`); process.exit(1); }
    const ms = listOf(g), want = fv('plan') ? JSON.parse(fs.readFileSync(fv('plan'), 'utf8')).groups[+only] : null;
    if (want && (want.n !== ms.length || want.keys_sha !== keysSha(ms))) { console.error(`::error::group ${only} recomputed differs from the plan (${ms.length} vs ${want.n} mutants): another tree or pool`); process.exit(1); }
    fs.writeFileSync(list, JSON.stringify(ms));
    console.log(`group ${only}: ${g.files.length} file(s), ${ms.length} mutant(s)`);
    process.exit(0);
  }
  let heldAll = 0; const why = {};
  const groups = gs.map((g, gi) => {
    const ms = listOf(g); let held = 0;
    for (const f of g.files) {
      const r = schemaFile(fs.readFileSync(path.join(pkg, f), 'utf8'), ms.filter((m) => m.file === f));
      held += r.held.size;
      for (const w of r.fallback.values()) why[w] = (why[w] ?? 0) + 1;
    }
    heldAll += held;
    console.log(`group ${gi}: ${g.files.length} file(s), ${ms.length} mutant(s), ${held} held by the generator`);
    return { g: gi, files: g.files.slice().sort(), n: ms.length, keys_sha: keysSha(ms) };
  });
  fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(path.join(out, 'plan.json'), JSON.stringify({ tree: treeHash(), src_hash: srcHash, files, groups }));
  fs.writeFileSync(path.join(out, 'carried.json'), JSON.stringify(carried));
  const n = groups.reduce((a, g) => a + g.n, 0);
  console.log(`schema plan: ${n + carried.length} mutant(s), ${carried.length} carried, ${n} to run in ${groups.length} group(s); the generator holds ${heldAll} (${n ? (100 * heldAll / n).toFixed(1) : 0}%); fallback before the build: ${JSON.stringify(why)}`);
  process.exit(0);
}
if (cmd === 'plan-check') { // every source file must yield mutants on some platform, or be named in mutation-no-logic.json with a reason
  const named = new Map(JSON.parse(fs.readFileSync(path.join(pkg, 'mutation-no-logic.json'), 'utf8')).map((e) => [e.file, e.reason]));
  const files = fs.readdirSync(path.join(pkg, 'Sources'), { recursive: true }).map(String).filter((f) => f.endsWith('.swift')).sort().map((f) => `Sources/${f}`);
  const count = (f, apple) => { const was = process.env.SWIFTMUT_APPLE; if (apple) process.env.SWIFTMUT_APPLE = '1'; else delete process.env.SWIFTMUT_APPLE; const n = mutantsFor(path.join(pkg, f)).length; if (was === undefined) delete process.env.SWIFTMUT_APPLE; else process.env.SWIFTMUT_APPLE = was; return n; };
  let bad = 0, total = 0;
  UNREACHED = [];
  for (const f of files) {
    const n = count(f, false) + (process.platform === 'linux' ? count(f, true) : 0); total += n;
    const r = named.get(f); named.delete(f);
    if (n === 0 && !(r && r.length >= 12)) { console.error(`::error::${f} yields 0 mutants and is not named with a reason in mutation-no-logic.json`); bad++; }
    if (n > 0 && r) { console.error(`::error::${f} is named as no-logic but yields ${n} mutants: stale entry`); bad++; }
  }
  for (const f of named.keys()) { console.error(`::error::mutation-no-logic.json names ${f}, which is not a source file`); bad++; }
  if (UNREACHED.length) console.log(`::notice::${new Set(UNREACHED).size} line(s) compiled by no build of this workflow (Linux, macOS; the iOS/tvOS/watchOS stub of an #if os(macOS) || os(Linux), or the no-liblweot branch) are not mutated: ${[...new Set(UNREACHED)].join(' ')}`);
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
    for (const m of ms) { const e = pool[m.key]; const v = !e ? 'RUN unseen' : e.d !== m.def_hash || e.h !== m.shell_hash ? 'RUN changed' : mayCarry(e, m, { killed: ['KILLED'], uncompilable: ['NONVIABLE'], survived: ['SURVIVED'] }) ? `CARRY ${e.s}` : `RUN was ${e.s}`; console.log(`${f}\t${m.line}\t${m.op}\t${v}`); }
  }
  if (emit) fs.writeFileSync(emit, JSON.stringify(emitted));
  process.exit(0);
}
if (cmd === 'torun') {
  // node mutate.mjs torun <pool.json|-> --every=N --offset=K <file.swift>...: prints how many mutants of that slice `run --carry` would
  // still have to run (the workflow skips the toolchain install when it is 0). Same slice and carry rule as `run`.
  const flags = rest.filter((a) => a.startsWith('--')), pos = rest.filter((a) => !a.startsWith('--'));
  const every = +(flags.find((f) => f.startsWith('--every='))?.slice(8) ?? 1), offset = +(flags.find((f) => f.startsWith('--offset='))?.slice(9) ?? 0);
  const pool = pos[0] === '-' ? {} : loadPool(pos[0]); const files = pos.slice(1);
  if (!pool) { console.log('unreadable pool'); process.exit(1); }
  const srcHash = sha(files.map((f) => f + '\0' + fs.readFileSync(path.join(pkg, f), 'utf8')).join('\0'));
  let all = [];
  for (const f of files) { const ms = mutantsFor(path.join(pkg, f)); annotate(path.join(pkg, f), ms, srcHash); ms.forEach((m) => all.push({ file: f, ...m })); }
  all = sliceMutants(all, every, offset, flags);
  console.log(all.filter((m) => { const e = pool[m.key]; return !(e && e.d === m.def_hash && e.h === m.shell_hash && mayCarry(e, m, { killed: ['KILLED'], uncompilable: ['NONVIABLE'], survived: ['SURVIVED'] })); }).length);
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
  const flagVal = (n) => flags.find((f) => f.startsWith(`--${n}=`))?.slice(n.length + 3);
  const oracleOut = flagVal('oracle-out'), oracleInDir = flagVal('oracle-in');
  const partFlag = flagVal('oracle-part') ?? '0/1';
  const buildOnly = partFlag === 'build';
  const [partK, partN] = buildOnly ? [0, 1] : partFlag.split('/').map(Number);
  if (!buildOnly && !(Number.isInteger(partK) && Number.isInteger(partN) && partN >= 1 && partK >= 0 && partK < partN)) { console.error(`bad --oracle-part ${partFlag}`); process.exit(2); }
  const tree = treeHash();
  // the baseline job's oracle, accepted only for this exact tree (a stale one would vouch for sources it never ran)
  let oracleIn = null;
  if (oracleInDir) {
    try { const o = JSON.parse(fs.readFileSync(path.join(oracleInDir, 'oracle.json'), 'utf8')); if (o.tree === tree) oracleIn = o; else console.error(`::warning::baseline oracle is for tree ${String(o.tree).slice(0, 12)}, this tree is ${tree.slice(0, 12)}: verifying the groups here`); }
    catch (e) { console.error(`::warning::no usable baseline oracle (${e.message}): verifying the groups here`); }
  }
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
  const itemsFile = flagVal('items'), items = itemsFile ? JSON.parse(fs.readFileSync(itemsFile, 'utf8')) : null;
  const pendingOut = flagVal('pending-out'), deadline = +(flagVal('deadline') ?? 0);
  const schema = items?.mode === 'schema' ? { meta: JSON.parse(fs.readFileSync(path.join(items.bundle, 'meta.json'), 'utf8')), reach: JSON.parse(fs.readFileSync(path.join(items.bundle, 'reach.json'), 'utf8')) } : null;
  if (items) {
    const byKey = new Map(all.map((m) => [m.key, m]));
    const idKey = schema ? new Map(schema.meta.mutants.map((x) => [x.id, x])) : null;
    const sel = [];
    for (const it of items.items) {
      const x = schema ? idKey.get(it.id) : null;
      if (schema && (!x || x.st !== 'schema')) { console.error(`::error::item ${it.id} is no schema mutant of this bundle`); process.exit(2); }
      const m = byKey.get(schema ? x.key : it.key);
      if (!m) { console.error(`::error::item ${JSON.stringify(it)} names no mutant of this tree`); process.exit(2); }
      sel.push({ ...m, item: it, sid: schema ? it.id : 0 });
    }
    all = sel;
  } else all = sliceMutants(all, every, offset, flags);
  // --retry=a.json,b.json: only the mutants that SURVIVED or TIMED OUT (no verdict) in earlier result files (matched by file + source text + op +
  // replacement, so line shifts from edits elsewhere in the file do not matter)
  const retry = flags.find((f) => f.startsWith('--retry='))?.slice(8);
  if (retry) {
    const want = new Set();
    for (const f of retry.split(',')) for (const r of JSON.parse(fs.readFileSync(f, 'utf8'))) if (r.status === 'SURVIVED' || r.status === 'TIMEOUT') want.add(`${r.file}#${r.orig}#${r.op}#${r.repl}`);
    all = all.filter((m) => want.has(`${m.file}#${m.orig}#${m.op}#${m.repl}`));
  }
  const results = fs.existsSync(outFile) ? JSON.parse(fs.readFileSync(outFile, 'utf8')) : [];
  const rec = (m, status, extra = {}) => recOf(m, status, { ...(m.item ? { via: schema ? 'schema' : 'real', ...(m.item.att ? { att: m.item.att } : {}), ...(m.item.sample ? { sample: true } : {}) } : {}), ...extra });
  // --carry=pool.json (targeted mode): a pooled result stands only when the mutant's def and the file's non-def code are
  // unchanged (KILLED/TIMEOUT), or the whole production source is (NONVIABLE); a SURVIVED one stands only when the baseline ran against
  // byte-identical tests + corpus and the whole production source is unchanged; unseen and changed mutants run again.
  const carryFile = flags.find((f) => f.startsWith('--carry='))?.slice(8);
  if (carryFile && !items) {
    const pool = loadPool(carryFile);
    if (!pool) { console.error(`cannot read --carry ${carryFile}`); process.exit(1); }
    const have = new Set(results.map((r) => `${r.file}#${r.idx}`));
    let c = 0, unseen = 0, changed = 0, nonkill = 0;
    for (const m of all) {
      if (have.has(`${m.file}#${m.idx}`)) continue;
      const e = pool[m.key];
      if (!e) unseen++;
      else if (e.d !== m.def_hash || e.h !== m.shell_hash) changed++;
      else if (mayCarry(e, m, { killed: ['KILLED'], uncompilable: ['NONVIABLE'], survived: ['SURVIVED'] })) { results.push(rec(m, e.s, { carried: true })); c++; }
      else nonkill++;
    }
    console.error(`carry: ${c} result(s) carried, ${all.length - c} to run (${unseen} unseen, ${changed} def/file changed, ${nonkill} earlier survivors or uncompilable under changed sources)`);
  }
  const done = new Set(items ? [] : results.map((r) => `${r.file}#${r.idx}`));
  const queue = all.filter((m) => !done.has(`${m.file}#${m.idx}`));
  const pending = [];
  console.error(`mutants ${all.length}, remaining ${queue.length}`);
  const t0 = Date.now();
  const save = () => fs.writeFileSync(outFile, JSON.stringify(results, null, 1));
  const MAX_RSS = (+process.env.SWIFTMUT_MAX_RSS_MB || 4096) * 1048576; // per worker (process group)
  const targetOf = targetOfFile;
  // the suite a mutant of `file` faces: SWIFTMUT_FILTER when the job pins one (a module's own test classes), else the file's test target
  const oracleOf = (file) => process.env.SWIFTMUT_FILTER || targetOf(file);
  // fail-fast phase: the test classes named after the mutated file (e.g. Actions.swift -> ActionsVectorTests, BaseActionsOracleTests).
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
  // keyed by the suite that really runs (oracleOf), so the log and a baseline oracle.json name the filter a module job pins, not the default target
  // A pinned SWIFTMUT_FILTER is one suite for every file (K042.requireCovers does not gate under it), so one group.
  const groupOf = (file) => process.env.SWIFTMUT_FILTER ? `${oracleOf(file)}|*` : coverTokens.opaque ? `${oracleOf(file)}|${file}` : `${oracleOf(file)}|${coverTokens.toks.filter((t) => file.includes(t)).join(',')}`;
  const groups = new Map(); // group -> Promise<limit ms>
  const groupInfo = new Map(); // group -> { ms: the unmutated duration, limit }
  const verifyGroup = (w, file) => {
    const g = groupOf(file);
    if (!groups.has(g) && oracleIn?.groups[g]) { groupInfo.set(g, oracleIn.groups[g]); groups.set(g, Promise.resolve(oracleIn.groups[g].limit)); }
    if (!groups.has(g)) groups.set(g, (async () => {
      const r = await exec(w, file, oracleOf(file), false, 3_600_000);
      if (r.timedOut || r.memKilled || r.compileErr || r.code !== 0 || r.sig !== '[]') {
        console.error(`worker ${w}: UNMUTATED ORACLE FAILED for group [${g}] (file ${file}): ${JSON.stringify({ code: r.code, ms: r.ms, memKilled: r.memKilled, timedOut: r.timedOut, compileErr: r.compileErr, sig: r.sig.slice(0, 400) })}\n${r.tail}\naborting`);
        process.exit(3);
      }
      // a suite that ran no test (a filter matching nothing, a target the manifest left out) passes every mutant: no oracle at all
      if (!r.passed.length) { console.error(`worker ${w}: UNMUTATED ORACLE RAN NO TEST for group [${g}] (filter ${oracleOf(file)}, file ${file}): aborting`); process.exit(3); }
      const lim = Math.max(DEFAULT_LIMIT, 2 * r.ms + 120_000); // margin for a slow runner; a timeout is then re-judged at twice this
      console.error(`group [${g}]: unmutated ${Math.round(r.ms / 1000)} s, limit ${Math.round(lim / 1000)} s, ${r.passed.length} test(s) passed, ${r.skipped} skipped`);
      // where the oracle's time goes (what a cheaper, equally strong oracle has to start from)
      console.error(`group [${g}]: slowest: ${[...r.passed].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([n, sec]) => `${n} ${sec.toFixed(1)} s`).join('; ')}`);
      groupInfo.set(g, { ms: r.ms, limit: lim });
      return lim;
    })());
    return groups.get(g);
  };
  // the runs going on (the deadline kills them: their items go to the next level undecided)
  const active = new Set();
  let stopping = false;
  const stopAll = () => { stopping = true; for (const k of active) k(); };
  if (deadline) { const ms = deadline - Date.now(); if (ms <= 0) stopping = true; else setTimeout(stopAll, ms).unref(); }
  // the suite as `swift test --filter` runs: the core target in its four parts (as always), a list of regexes in turn, or one filter
  const filtersOf = (filter) => Array.isArray(filter) ? filter : filter === 'AtlasPCAVerifyTests' ? ['A', '[B-K]', '[L-R]', '[^A-R]'].map((r) => `^AtlasPCAVerifyTests\\.${r}`) : [filter];
  const exec = (w, file, filter, skipBuild, limit, env = {}) => new Promise((resolve) => {
    const dir = path.join(tmp, `w${w}`, 'sdks/swift-pca');
    // own process group, so a timeout / memory kill takes the compiler and the test binary down with the driver
    // ulimit -d: a hard per-process backstop, so a runaway allocation fails (the oracle crashes == detected) instead of
    // exhausting the job's cgroup before the watchdog below can react. RLIMIT_DATA counts VIRTUAL private mappings (malloc arenas,
    // reservations), so it sits at 3x the RSS cap: at 1x the unmutated base oracles (170 MB files read whole) crashed.
    const t0 = Date.now();
    const penv = { ...process.env, PCA_CONFORMANCE_ADV: advPath, SWIFTMUT_FILE: file, ...env };
    delete penv.PCA_SCHEMA_TRACE; if (!env.PCA_MUTANT) delete penv.PCA_MUTANT;
    const p = spawn('bash', ['-c', `ulimit -d ${Math.floor(3 * MAX_RSS / 1024)}; S="nice -n 19 $(command -v stdbuf >/dev/null && echo stdbuf -oL) swift test $SWIFT_TEST_FLAGS"; b="$0"; for f in "$@"; do $S ${skipBuild ? '--skip-build ' : ''}--scratch-path "$b" --filter "$f" || exit $?; done`, path.join(dir, '.b'), ...filtersOf(filter)], { cwd: dir, env: penv, stdio: ['ignore', 'pipe', 'pipe'], detached: true });
    let out = '';
    let early = false, tail = ''; // the first ordinary assertion failure decides the mutant: stop there, so a LATER test that hangs or crashes cannot turn the kill into a TIMEOUT/RUNERR
    const ASSERT = /: error: (-\[[\w.]+ \w+\]|[\w.]+\.\w+) : /m;
    const add = (d) => {
      if (out.length < 16 << 20) out += d;
      if (!early) { const chunk = tail + d; if (ASSERT.test(chunk)) { early = true; setTimeout(killGroup, 1000); } tail = chunk.slice(-400); }
    };
    p.stdout.on('data', add); p.stderr.on('data', add);
    const killGroup = () => { try { process.kill(-p.pid, 'SIGKILL'); } catch { try { p.kill('SIGKILL'); } catch {} } };
    const to = setTimeout(killGroup, limit);
    let aborted = false;
    const abort = () => { aborted = true; killGroup(); };
    active.add(abort);
    if (stopping) abort();
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
      clearTimeout(to); clearInterval(wd); active.delete(abort);
      const lines = out.split('\n').filter((l) => /error:/.test(l));
      resolve({
        code, ms: Date.now() - t0, memKilled, aborted, timedOut: sig === 'SIGKILL' && !memKilled && !early && !aborted, signal: sig,
        // the build finished and the tests ran (SwiftPM flushes 'Build complete!'; the test binary's own output may sit in a pipe buffer)
        started: skipBuild || /Build complete!|Test Suite '/.test(out),
        // an ordinary XCTest failure (an assertion, or a test that threw): Linux `file:line: error: Class.test : msg`, Darwin
        // `file:line: error: -[Module.Class test] : msg`. A non-zero exit WITHOUT one is a crash (trap, fatalError, overflow, signal).
        asserted: /: error: (-\[[\w.]+ \w+\]|[\w.]+\.\w+) : /m.test(out),
        trap: trapOf(out),
        // evidence for the audit: the first failing assertion's location and name, and the last test that had started (the one a hang sits in)
        killer: (lines.find((l) => /\/Tests\//.test(l)) ?? '').replace(/^.*\/Tests\//, 'Tests/').slice(0, 300),
        lastTest: [...out.matchAll(/Test Case '([^']+)' started/g)].pop()?.[1] ?? '',
        passed: [...out.matchAll(/Test Case '([^']+)' passed \(([\d.]+) seconds\)/g)].map((x) => [x[1], +x[2]]),
        skipped: [...out.matchAll(/Test Case '[^']+' skipped/g)].length,
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
    let r = await exec(w, m.file, filter, skipBuild, limit, m.sid ? { PCA_MUTANT: String(m.sid) } : {});
    if (r.aborted || ran(r)) return r;
    console.error(`worker ${w}: ${m.file}:${m.line} ${m.op}: the tests did not start (exit ${r.code}, timed out ${r.timedOut}), retrying\n${r.tail}`);
    r = await exec(w, m.file, filter, false, 2 * limit, m.sid ? { PCA_MUTANT: String(m.sid) } : {});
    if (r.aborted || ran(r)) return r;
    // The BUILD never finished (swiftc ran past the time limit twice, or gave up on an expression: "unable to type-check this expression
    // in reasonable time"): the mutant was never compiled into a test binary, so no test saw it. It is NONVIABLE (not a kill), logged with why.
    if (r.timedOut || /unable to type-check this expression/.test(r.tail)) {
      const why = `build did not finish (timed out ${r.timedOut}, exit ${r.code})`;
      console.error(`worker ${w}: ${m.file}:${m.line} ${m.op}: ${why} twice: NONVIABLE (never built, not killed)\n${r.tail}`);
      return { ...r, compileErr: `${m.file}:${m.line}: ${why}` };
    }
    // anything else: a genuine test-start failure on a build that finished
    console.error(`worker ${w}: ${m.file}:${m.line} ${m.op}: the tests did not start again (exit ${r.code}): aborting\n${r.tail}`);
    process.exit(3);
  };
  // A mutant is KILLED only when an ordinary test assertion failed. A deterministic runtime trap (fatalError, index out of range,
  // overflow) with no assertion failing is TRAP: never a plain kill, reported per mutant with its test and message. A memory-cap kill,
  // or a test process that died any other way, is a RUN ERROR, and the merge requires a reason for each one in
  // sdks/swift-pca/mutation-run-errors.json (BRIEF: crash / out-of-memory mutants are run errors, not kills).
  const crashOf = (r) => r.memKilled ? `memory cap (${MAX_RSS / 1048576} MiB RSS) exceeded` : `exit ${r.code}${r.signal ? ` signal ${r.signal}` : ''}: ${r.crash || 'no assertion failed'}`;
  const crashed = (r) => r.asserted ? { status: 'KILLED', killer: r.killer } : r.trap ? { status: 'TRAP', trap: r.trap } : { status: 'RUNERR', evidence: crashOf(r) };
  // one more full-suite attempt (att 2 or 3) at 1.5x the limit, built first (a real mutant) so the limit times the tests alone
  const attempt = async (w, m, limit) => {
    if (!schema) {
      const dir = path.join(tmp, `w${w}`, 'sdks/swift-pca');
      const b = await new Promise((res) => { const c = spawn('nice', ['-n', '19', 'swift', 'build', '--build-tests', ...(process.env.SWIFT_TEST_FLAGS ? process.env.SWIFT_TEST_FLAGS.split(/\s+/) : []), '--scratch-path', path.join(dir, '.b')], { cwd: dir, stdio: 'ignore', detached: true }); const k = () => { try { process.kill(-c.pid, 'SIGKILL'); } catch {} }; active.add(k); if (stopping) k(); c.on('close', (code) => { active.delete(k); res(code); }); });
      if (stopping) return { requeue: true };
      if (b !== 0) return { status: 'NONVIABLE' };
    }
    const r = await run(w, m, oracleOf(m.file), true, Math.round(1.5 * limit));
    if (r.aborted) return { requeue: true };
    if (r.timedOut) return { status: 'TIMEOUT', ended: false, evidence: `no verdict within ${Math.round(1.5 * limit)} ms (attempt ${m.item.att}); last test started: ${r.lastTest || 'none'}` };
    if (r.memKilled) return { status: 'RUNERR', evidence: crashOf(r) };
    if (r.compileErr) { lastCompileErr.set(w, r.compileErr); return { status: 'NONVIABLE' }; }
    if (r.code === 0 && r.sig === '[]') return { status: 'SURVIVED' };
    return crashed(r);
  };
  // schema mutant: the test classes that reach it (the build's trace) first, when they are well under the full suite
  const reachSets = schema ? (() => { const un = new Set(schema.reach.unattributed); return { un }; })() : null;
  const subsetOf = (m, limit) => {
    if (!schema || process.env.SWIFTMUT_FILTER || reachSets.un.has(m.sid)) return null;
    const t = targetOf(m.file);
    const cs = (schema.reach.sites[m.sid] ?? []).map((i) => schema.reach.classes[i]).filter((c) => c[0] === t);
    if (!cs.length) return null;
    const est = cs.reduce((a, c) => a + c[2], 0), full = (groupInfo.get(groupOf(m.file))?.ms ?? Infinity) / 1000;
    if (est >= 0.6 * full) return null;
    // the core target's classes in the same four parts as its full suite (one process each)
    const parts = t === 'AtlasPCAVerifyTests' ? [/^A/, /^[B-K]/, /^[L-R]/, /^[^A-R]/] : [/./];
    const filters = parts.map((re) => cs.filter((c) => re.test(c[1])).map((c) => c[1])).filter((x) => x.length).map((x) => `^${t}\\.(${x.join('|')})/`);
    return { filters, limit: Math.min(limit, Math.max(180_000, 2000 * est + 120_000)), n: cs.length };
  };
  const judge = async (w, m, limit) => {
    if (m.item?.att) return attempt(w, m, limit);
    let built = !!schema;
    const sub = subsetOf(m, limit);
    if (sub) {
      const r = await run(w, m, sub.filters, true, sub.limit);
      if (r.aborted) return { requeue: true };
      if (r.memKilled) return { status: 'RUNERR', evidence: crashOf(r) };
      if (!r.timedOut && r.code !== 0) return { ...crashed(r), by: `reaching classes (${sub.n})` };
    }
    const p1 = schema ? null : phase1(m.file);
    if (p1) {
      const r = await run(w, m, p1, false, Math.min(limit, 180_000)); // the matching classes only: a hang here falls through to the full suite, so cap its cost
      if (r.aborted) return { requeue: true };
      if (r.memKilled) return { status: 'RUNERR', evidence: crashOf(r) };
      if (r.compileErr) { lastCompileErr.set(w, r.compileErr); return { status: 'NONVIABLE' }; }
      if (!r.timedOut && r.code !== 0) return crashed(r);
      if (!r.timedOut) built = true;
    }
    let r = await run(w, m, oracleOf(m.file), built, limit);
    if (r.aborted) return { requeue: true };
    // item mode: attempts 2 and 3 are items of the next level (each fits a job; three in a row may not)
    if (pendingOut && r.timedOut) return { attempts: true };
    // a timeout is no verdict: judge once more at twice the limit, so a slow runner or GC pause cannot leave a behaviour-preserving
    // mutant undecided. A second timeout is TIMEOUT, a run error that needs a ledger entry proving the mutant itself never ends.
    // up to three attempts in all (the second and third at 1.5x): a runner stall must not decide a verdict, a mutant that loops ends all three
    for (let a = 0; a < 2 && r.timedOut; a++) { r = await run(w, m, oracleOf(m.file), built || r.started, Math.round(1.5 * limit)); if (r.aborted) return { requeue: true }; }
    if (r.memKilled) return { status: 'RUNERR', evidence: crashOf(r) };
    if (r.timedOut) return { status: 'TIMEOUT', evidence: `no verdict within ${limit} ms nor within ${Math.round(1.5 * limit)} ms, three attempts (the unmutated group passed well inside the first); last test started: ${r.lastTest || 'none'}` };
    if (r.compileErr) { lastCompileErr.set(w, r.compileErr); return { status: 'NONVIABLE' }; }
    // the unmutated group suite passed with exit 0 and no failure line
    if (r.code === 0 && r.sig === '[]') return { status: 'SURVIVED' };
    return crashed(r);
  };
  const runOne = async (w, m) => {
    const limit = await verifyGroup(w, m.file); // runs on the unmutated copy, before the mutant is written
    const target = path.join(tmp, `w${w}`, 'sdks/swift-pca', m.file);
    const orig = fs.readFileSync(path.join(pkg, m.file), 'utf8');
    if (!schema) fs.writeFileSync(target, mutantText(m)); // a schema mutant is already in the build, behind its switch
    try {
      const st = await judge(w, m, limit);
      // every uncompilable verdict and every run error is auditable in the log
      if (st.status === 'NONVIABLE') console.error(`NONVIABLE ${m.file}:${m.line} ${m.op}: ${String(lastCompileErr.get(w)).replace(/^.*\/Sources\//, 'Sources/').slice(0, 300)}`);
      if (st.status === 'RUNERR') console.error(`RUNERR ${m.file}:${m.line} ${m.op}: ${st.evidence}`);
      return st;
    } finally { if (!schema) fs.writeFileSync(target, orig); }
  };
  const wk = async (w) => {
    const wroot = path.join(tmp, `w${w}`);
    const dir = path.join(wroot, 'sdks/swift-pca');
    // restored from the baseline job (same tree, same absolute paths, mtimes kept): its build products stay valid, so no copy and no warm build
    // (an oracle-part job restores the build job's copies the same way; the marker holds the tree hash it was built from)
    const okFile = path.join(wroot, '.oracle-ok');
    const restored = (oracleIn || oracleOut) && fs.existsSync(okFile) && fs.readFileSync(okFile, 'utf8') === tree;
    if (restored) console.error(`worker ${w}: baseline build restored`);
    if (schema) {
      // the schema build's tree (restored as w0, same absolute path as built); the other workers get hard-linked copies, each with its
      // own SwiftPM lock (a shared lock would run the workers one after the other)
      if (w > 0 && !fs.existsSync(wroot)) { const c = spawnSync('cp', ['-al', path.join(tmp, 'w0'), wroot]); if (c.status !== 0) { console.error(`worker ${w}: copying the schema tree failed`); process.exit(3); } }
      fs.rmSync(path.join(dir, '.b', '.lock'), { force: true });
      if (!fs.existsSync(path.join(dir, '.b'))) { console.error(`worker ${w}: no schema build at ${dir}`); process.exit(3); }
    } else if (!restored) {
    fs.rmSync(path.join(dir, 'Sources'), { recursive: true, force: true });
    fs.mkdirSync(dir, { recursive: true });
    fs.mkdirSync(path.join(wroot, 'tools'), { recursive: true });
    for (const [l, t] of [['packages', path.join(root, 'packages')], ['tools/pca-diff-fuzz', path.join(root, 'tools/pca-diff-fuzz')]]) { try { fs.rmSync(path.join(wroot, l), { force: true }); fs.symlinkSync(t, path.join(wroot, l)); } catch {} }
    // README.md: AuthorizeTests.testReadmeSampleIsThisCode reads ../../README.md (missing => it throws, the unmutated suite fails)
    for (const d of ['Sources', 'Tests', 'test-data', 'Package.swift', 'README.md']) spawnSync('cp', ['-R', path.join(pkg, d), dir]);
    // warm build, asynchronous: a spawnSync here blocked the event loop for the whole build, so the other worker's unmutated oracle (already running)
    // was timed across this build and stalled on its unread pipe; its limit, and the cost of every TIMEOUT judged against it, came out inflated
    await new Promise((res) => spawn('nice', ['-n', '19', 'swift', 'build', '--build-tests', ...(process.env.SWIFT_TEST_FLAGS ? process.env.SWIFT_TEST_FLAGS.split(/\s+/) : []), '--scratch-path', path.join(dir, '.b')], { cwd: dir, stdio: 'ignore' }).on('close', res));
    }
    // barrier: the unmutated oracles are timed (and the mutants judged) only once no worker is still building
    if (--warmLeft === 0) warmRelease();
    await warmAll;
    if (oracleOut) { // baseline job: verify every oracle group (one representative file each), run no mutant
      while (oracleFiles.length) await verifyGroup(w, oracleFiles.shift());
      return;
    }
    // no separate baseline: runOne verifies each oracle group on the unmutated copy before judging its first mutant
    while (queue.length && Date.now() - t0 < budget && !stopping) {
      const m = queue.shift();
      const st = await runOne(w, m);
      if (st.requeue) { pending.push(m.item); continue; }
      if (st.attempts) { pending.push({ ...m.item, att: 2 }, { ...m.item, att: 3 }); continue; }
      if (m.item?.att) { results.push(rec(m, st.status, { ended: st.ended !== false, ...(st.evidence ? { evidence: st.evidence } : st.trap ? { trap: st.trap } : st.killer ? { killer: st.killer } : {}) })); continue; }
      results.push(rec(m, st.status, st.evidence ? { evidence: st.evidence } : st.trap ? { trap: st.trap } : st.killer ? { killer: st.killer } : {}));
      if (results.length % 5 === 0) save();
    }
  };
  // baseline job: the first file of every distinct oracle group
  // only the files that have mutants need a verified group (the apple leg mutates 8 of ~480 files: its other groups are never consulted)
  const withMutants = new Set(all.map((m) => m.file));
  const groupFiles = oracleOut ? [...new Map(files.filter((f) => withMutants.has(f)).map((f) => [groupOf(f), f])).values()] : [];
  const oracleFiles = buildOnly ? [] : groupFiles.filter((_, i) => i % partN === partK);
  // nothing to run (everything carried): no worker copies, no warm build, no group verification
  const nWorkers = oracleOut ? workers : Math.min(workers, queue.length);
  let warmLeft = nWorkers, warmRelease;
  const warmAll = new Promise((res) => { warmRelease = res; });
  await Promise.all(Array.from({ length: nWorkers }, (_, w) => wk(w)));
  if (oracleOut) {
    fs.mkdirSync(oracleOut, { recursive: true });
    fs.writeFileSync(path.join(oracleOut, 'oracle.json'), JSON.stringify({ tree, part: partFlag, all: groupFiles.length, assigned: buildOnly ? [] : groupFiles.filter((_, i) => i % partN === partK).map(groupOf), groups: Object.fromEntries(groupInfo) }, null, 1));
    for (let w = 0; w < workers; w++) fs.writeFileSync(path.join(tmp, `w${w}`, '.oracle-ok'), tree);
    console.error(`oracle: ${groupInfo.size} group(s) verified on tree ${tree.slice(0, 12)}`);
    process.exit(0);
  }
  save();
  if (pendingOut) {
    for (const m of queue) pending.push(m.item);
    fs.writeFileSync(pendingOut, JSON.stringify(pending));
    console.error(`pending for the next level: ${pending.length} item(s)`);
  }
  const by = {};
  for (const r of results) by[r.status] = (by[r.status] || 0) + 1;
  console.error(JSON.stringify(by));
}
