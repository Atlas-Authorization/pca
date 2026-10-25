// Shared pieces of the targeted-mutation ("carry-forward") mode of the Go / Rust / Swift mutation workflows.
// See README in snapshot.mjs / baseline.mjs. Nothing here runs a test suite.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';

export const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

// Whitespace / plain-comment insensitive normal form of a code region (line based; keeps doc comments, which are tests in
// Rust). Blank lines and lines that are only a `//` comment (not `///`, `//!`) vanish; indentation is trimmed.
export function normText(text, { keepDoc = true } = {}) {
  const out = [];
  for (const raw of text.split('\n')) {
    const t = raw.trim();
    if (!t) continue;
    if (t.startsWith('//') && !(keepDoc && (t.startsWith('///') || t.startsWith('//!')))) continue;
    out.push(t);
  }
  return out.join('\n');
}

export const isText = (buf) => !buf.subarray(0, 8192).includes(0);

// JSON "covers": every datum of OLD is still present in NEW (objects: keys, arrays: elements as a set), i.e. NEW only grew.
export function jsonCovers(o, n) {
  if (Array.isArray(o)) {
    if (!Array.isArray(n)) return false;
    const have = new Set(n.map((x) => JSON.stringify(x)));
    for (const x of o) {
      if (have.has(JSON.stringify(x))) continue;
      if (!n.some((y) => jsonCovers(x, y))) return false;
    }
    return true;
  }
  if (o && typeof o === 'object') {
    if (!n || typeof n !== 'object' || Array.isArray(n)) return false;
    for (const k of Object.keys(o)) if (!(k in n) || !jsonCovers(o[k], n[k])) return false;
    return true;
  }
  return Object.is(o, n);
}

// OLD's lines are a subsequence of NEW's (pure insertions).
export function linesSubsequence(oldText, newText) {
  const a = oldText.split('\n'), b = newText.split('\n');
  let i = 0;
  for (let j = 0; j < b.length && i < a.length; j++) if (a[i] === b[j]) i++;
  return i === a.length;
}

export function walk(dir, base = dir, acc = []) {
  if (!fs.existsSync(dir)) return acc;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, base, acc); else if (e.isFile()) acc.push(path.relative(base, p));
  }
  return acc.sort();
}

// May a file go from OLD to NEW without invalidating any carried kill? Returns null when yes, else the reason.
export function fileChange(rel, oldBuf, newBuf) {
  if (oldBuf.equals(newBuf)) return null;
  let o = oldBuf, n = newBuf, name = rel;
  try {
    if (name.endsWith('.gz')) { o = zlib.gunzipSync(o); n = zlib.gunzipSync(n); name = name.slice(0, -3); }
  } catch { return 'unreadable gzip'; }
  if (name.endsWith('.json')) {
    try { return jsonCovers(JSON.parse(o.toString('utf8')), JSON.parse(n.toString('utf8'))) ? null : 'JSON data changed or removed'; }
    catch { return 'unparsable JSON'; }
  }
  if (isText(o) && isText(n)) return linesSubsequence(o.toString('utf8'), n.toString('utf8')) ? null : 'existing lines changed or removed';
  return 'binary file changed';
}

// compare two snapshot dirs (made by snapshot.mjs make): new files and pure insertions are fine, anything else is not.
export function compareSnapshots(oldDir, newDir) {
  const reasons = [];
  for (const scope of ['sdk', 'corpus']) {
    for (const rel of walk(path.join(oldDir, scope))) {
      const np = path.join(newDir, scope, rel);
      if (!fs.existsSync(np)) { reasons.push(`${scope}/${rel}: removed`); continue; }
      const r = fileChange(rel, fs.readFileSync(path.join(oldDir, scope, rel)), fs.readFileSync(np));
      if (r) reasons.push(`${scope}/${rel}: ${r}`);
    }
  }
  return { ok: reasons.length === 0, reasons };
}

export function toolHash(files, cfg) {
  return sha(JSON.stringify([cfg, files.map((f) => sha(fs.readFileSync(f)))]));
}

// Which carried result may stand for a re-generated mutant (shared rule; the tools call it with their own status sets).
//   e = pooled entry {s,d,h,a}; m = {def_hash, shell_hash, src_hash}
//   killed: carried when its def and the file's non-def code are unchanged.
//   uncompilable: carried only when the WHOLE production source is unchanged (another file may have made it compile).
//   anything else (survivors, timeouts the tool does not count as detection, unknown): re-run.
export function mayCarry(e, m, { killed, uncompilable }) {
  if (!e || e.d !== m.def_hash || e.h !== m.shell_hash) return false;
  if (killed.includes(e.s)) return true;
  return uncompilable.includes(e.s) && e.a === m.src_hash;
}

export function loadPool(file) {
  if (!file || !fs.existsSync(file)) return null;
  return JSON.parse(fs.readFileSync(file, 'utf8')).entries;
}
