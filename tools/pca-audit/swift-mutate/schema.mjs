#!/usr/bin/env node
// Mutant schemata for swift-mutate: many of one file's line mutants in ONE source text, each behind a runtime switch, so a group of
// mutants is compiled once instead of once per mutant. `_pcaMut(id)` is true only in a process started with PCA_MUTANT=id (read once,
// see switchSource). The forms, chosen per mutant at the smallest site of the line that holds its whole change:
//   expression site   (_pcaMut(3) ? (<mutant's text>) : _pcaMut(7) ? (<…>) : (<original text>))
//                     sites: a call argument / array or dictionary element / subscript (label and key kept outside), an operand of a
//                     top-level || / && chain or of a single comparison, an if/guard/while clause, a for sequence or where clause, a
//                     switch subject, the value of a return / throw / declaration / assignment, a one-line closure or block body
//   statement site    if _pcaMut(3) { <mutant's line> } else { <original line> }   (a whole one-line statement; drop-stmt uses it)
//   condition prefix  if !_pcaMut(3), <original condition> {                       (if-false / guard-false / while-false)
// A site is always delimited (brackets, commas, keywords, `=`), so the added parentheses never change how the line parses. Every
// held mutant is round-trip checked: the line rendered with that mutant active and the switch syntax left out must be exactly the
// real mutant's line (and with none active, the original line). A mutant with no such site, or inside a multi-line string or comment,
// is a FALLBACK: it is decided by a real per-mutant build, never dropped. Whatever the compiler rejects is moved to the fallback by
// schema-build.mjs (errors are mapped back through `lineIds` / `blockIds`). Lines are never added or removed.
//   node schema.mjs --self-test
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

export const SW = '_pcaMut';
export const MAX_CHAIN = 8; // mutants on one site; more makes one expression the type checker may give up on

export function maskLine(l) { // blank out string literals and // comments so operators inside them are ignored
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

// Source masked across lines: string literals (incl. multi-line """ and raw #"..."#), // and nested /* */ comments blanked
// (newlines kept), so braces inside them never confuse a scanner.
// strCh: what a string literal's characters become (schema analysis uses STR, so a site never ends inside a literal)
export const STR = '\u0001';
export function maskAll(src, strCh = ' ') {
  const out = []; let i = 0; const n = src.length; let cmt = 0;
  const put = (c) => out.push(c === '\n' ? '\n' : ' ');
  const sput = (c) => out.push(c === '\n' ? '\n' : strCh);
  while (i < n) {
    const c = src[i];
    if (cmt) { if (c === '*' && src[i + 1] === '/') { cmt--; put(c); put(src[i + 1]); i += 2; } else if (c === '/' && src[i + 1] === '*') { cmt++; put(c); put(src[i + 1]); i += 2; } else { put(c); i++; } continue; }
    if (c === '/' && src[i + 1] === '/') { while (i < n && src[i] !== '\n') { put(src[i]); i++; } continue; }
    if (c === '/' && src[i + 1] === '*') { cmt = 1; put(c); put(src[i + 1]); i += 2; continue; }
    let hashes = 0, j = i; while (src[j] === '#') { hashes++; j++; }
    if (src[j] === '"') {
      const triple = src.startsWith('"""', j); const q = triple ? '"""' : '"'; const close = q + '#'.repeat(hashes);
      for (let k = i; k < j + q.length; k++) sput(' ');
      i = j + q.length;
      while (i < n && !src.startsWith(close, i)) { if (src[i] === '\\' && !hashes) { sput(src[i]); i++; } if (!triple && src[i] === '\n') break; sput(src[i]); i++; }
      if (src.startsWith(close, i)) for (let k = 0; k < close.length; k++) { sput(src[i]); i++; }
      continue;
    }
    out.push(c); i++;
  }
  return out.join('');
}

// ---- one line ----
const OPEN = { '(': ')', '[': ']', '{': '}' }, CLOSE = { ')': '(', ']': '[', '}': '{' };
// bracket depth before each position; matched pairs on the line; whether the span [a,b) is balanced on its own
function scan(M) {
  const depth = new Array(M.length + 1).fill(0), pairs = [], st = [];
  let d = 0, stray = false;
  for (let i = 0; i < M.length; i++) {
    depth[i] = d;
    const c = M[i];
    if (OPEN[c]) { st.push([c, i]); d++; }
    else if (CLOSE[c]) { const top = st.pop(); if (!top || top[0] !== CLOSE[c]) stray = true; else pairs.push([top[1], i, top[0]]); d--; }
  }
  depth[M.length] = d;
  return { depth, pairs, open: st.length, stray };
}
function balanced(M, a, b) {
  let d = 0;
  for (let i = a; i < b; i++) { if (OPEN[M[i]]) d++; else if (CLOSE[M[i]]) { if (--d < 0) return false; } }
  return d === 0;
}
const trim = (M, a, b) => { while (a < b && M[a] === ' ') a++; while (b > a && M[b - 1] === ' ') b--; return [a, b]; };
// positions in [a,b) at the depth of a where `sep` starts
function tops(M, D, a, b, sep) {
  const out = [];
  for (let i = a; i < b; i++) if (D[i] === D[a] && M.startsWith(sep, i) && i + sep.length <= b) out.push(i);
  return out;
}
function splitAt(M, D, a, b, sep) {
  const at = tops(M, D, a, b, sep), segs = []; let s = a;
  for (const i of at) { segs.push(trim(M, s, i)); s = i + sep.length; }
  segs.push(trim(M, s, b));
  return segs.filter(([x, y]) => y > x);
}
const KNOWN_OPS = new Set(['+', '-', '*', '/', '%', '&', '|', '^', '<<', '>>', '&+', '&-', '&*', '&<<', '&>>', '??', '...', '..<',
  '==', '!=', '<', '<=', '>', '>=', '===', '!==', '~=', '&&', '||']);
const CMP = ['==', '!=', '<=', '>=', '<', '>', '===', '!==', '~='];
const ASSIGN_RE = /^(=|\+=|-=|\*=|\/=|%=|&=|\|=|\^=|<<=|>>=|&\+=|&-=|&\*=)$/;
// the top-level spaced operator tokens of [a,b): [{i, op}]
function topOps(M, D, a, b) {
  const out = [], re = /(?<= )([=!<>&|^~?:+\-*/%.]+)(?= )/g;
  re.lastIndex = a;
  for (let m; (m = re.exec(M)) && m.index < b;) if (m.index + m[1].length <= b && D[m.index] === D[a]) out.push({ i: m.index, op: m[1] });
  return out;
}
// expression sites of a complete expression [a,b): itself, and the operands of its top-level || / && chain or single comparison
function exprSites(M, D, a, b, out) {
  [a, b] = trim(M, a, b);
  if (b <= a) return;
  out.push({ a, b, kind: 'expr' });
  if (/^(try|await)\b/.test(M.slice(a, b))) return; // `try` must stay leftmost
  const ops = topOps(M, D, a, b);
  if (ops.some((o) => o.op === '?' || o.op === ':' || ASSIGN_RE.test(o.op) || !KNOWN_OPS.has(o.op))) return;
  for (const sep of ['||', '&&']) {
    if (ops.some((o) => o.op === sep)) { for (const [x, y] of splitAt(M, D, a, b, ` ${sep} `)) exprSites(M, D, x, y, out); return; }
  }
  const cmp = ops.filter((o) => CMP.includes(o.op));
  if (cmp.length === 1) { const o = cmp[0]; exprSites(M, D, a, o.i - 1, out); exprSites(M, D, o.i + o.op.length + 1, b, out); }
}
// a body (one-line closure / block): a statement site when it is a statement, else its expression sites
function bodySites(M, D, a, b, out) {
  [a, b] = trim(M, a, b);
  if (b <= a) return;
  const semis = tops(M, D, a, b, ';');
  if (semis.length) { let x = a; for (const i of [...semis, b]) { bodySites(M, D, x, i, out); x = i + 1; } return; }
  const hd = /^(if|guard|while)\s/.exec(M.slice(a, b));
  if (hd) { headSites(M, D, a + hd[0].length, b, hd[1], out); return; }
  const s = M.slice(a, b);
  if (/^(return|throw)\b/.test(s)) { out.push({ a, b, kind: 'stmt' }); const k = s.indexOf(' '); if (k > 0) exprSites(M, D, a + k + 1, b, out); return; }
  if (/^(break|continue|fallthrough)\b/.test(s)) { out.push({ a, b, kind: 'stmt' }); return; }
  if (topOps(M, D, a, b).some((o) => ASSIGN_RE.test(o.op))) { out.push({ a, b, kind: 'stmt' }); assignSites(M, D, a, b, out); return; }
  if (/^(let|var|if|guard|for|while|switch|do|defer|case|default)\b/.test(s)) return;
  exprSites(M, D, a, b, out);
}
function assignSites(M, D, a, b, out) {
  const o = topOps(M, D, a, b).find((x) => ASSIGN_RE.test(x.op));
  if (o) exprSites(M, D, o.i + o.op.length + 1, b, out);
}
function elementSites(M, D, x, y, out) {
  [x, y] = trim(M, x, y);
  if (y <= x) return;
  const s = M.slice(x, y);
  if (/^(&|inout\b|let\b|var\b|\.\.\.)/.test(s) || /^\s*$/.test(s)) return;
  const ops = topOps(M, D, x, y);
  if (ops.some((o) => o.op === '?')) { exprSites(M, D, x, y, out); return; } // a ternary: its ':' is no label
  const colon = (() => { for (let i = x; i < y; i++) if (D[i] === D[x] && M[i] === ':' && M[i + 1] !== ':' && M[i - 1] !== ':') return i; return -1; })();
  if (colon < 0) { exprSites(M, D, x, y, out); return; }
  const [lx, ly] = trim(M, x, colon), [rx, ry] = trim(M, colon + 1, y);
  const left = M.slice(lx, ly);
  if (left && !/^[A-Za-z_]\w*$/.test(left)) exprSites(M, D, lx, ly, out); // a dictionary key (a blank one is a string literal)
  const eq = tops(M, D, rx, ry, ' = ');
  if (eq.length) exprSites(M, D, eq[0] + 3, ry, out); // a parameter's default value (the type before it is no site)
  else exprSites(M, D, rx, ry, out);
}
const DECL_START = /^(?:(?:public|private|fileprivate|internal|open|package|static|class|final|override|lazy|weak|unowned|nonisolated|mutating|nonmutating|convenience|required|indirect|@\w+(?:\([^)]*\))?)\s+)*(?:let|var|func|init|deinit|subscript|class|struct|enum|extension|protocol|actor|typealias|associatedtype|import|case|precedencegroup|operator|prefix|postfix|infix|macro)\b/;
const NOT_STMT_START = /^(if|guard|while|for|switch|repeat|do|else|catch|defer|default|where|get|set|willSet|didSet|#|@|\}|\)|\]|\.|,|\?|:)/;
const OPCH = '+-*/%&|^<>=!?:.';
// every site of line `ln` (0-based) of the masked file
export function lineSites(MA, ln) {
  const M = MA[ln];
  const { depth: D, pairs } = scan(M);
  const out = [];
  const t = M.search(/\S/); if (t < 0) return { out, t: 0, codeEnd: 0, D };
  const codeEnd = M.trimEnd().length;
  for (const [o, c, ch] of pairs) {
    if (ch === '{') {
      let bs = o + 1;
      const ins = tops(M, D, o + 1, c, ' in ');
      if (ins.length) bs = ins[0] + 4;
      bodySites(M, D, bs, c, out);
    } else for (const [x, y] of splitAt(M, D, o + 1, c, ',')) elementSites(M, D, x, y, out);
  }
  const head = /^(\s*(?:\}?\s*else\s+)?)(if|guard|while)\s/.exec(M);
  if (head) {
    headSites(M, D, head[0].length, codeEnd, head[2], out);
    return { out, t, codeEnd, D, head: { start: head[0].length, kw: head[2] } };
  }
  const s = M.slice(t, codeEnd);
  let m;
  if ((m = /^for\s/.exec(s))) {
    const ins = tops(M, D, t, codeEnd, ' in '), br = tops(M, D, t, codeEnd, '{');
    if (ins.length && br.length && ins[0] < br[0]) {
      const wh = tops(M, D, ins[0] + 4, br[0], ' where ');
      exprSites(M, D, ins[0] + 4, wh.length ? wh[0] : br[0], out);
      if (wh.length) exprSites(M, D, wh[0] + 7, br[0], out);
    }
  } else if ((m = /^switch\s/.exec(s))) {
    const br = tops(M, D, t, codeEnd, '{');
    if (br.length) exprSites(M, D, t + 7, br[0], out);
  } else if ((m = /^(return|throw)\s+/.exec(s)) && balanced(M, t, codeEnd) && M[codeEnd - 1] !== '{') {
    exprSites(M, D, t + m[0].length, codeEnd, out);
  } else if (DECL_START.test(s)) {
    const eq = tops(M, D, t, codeEnd, ' = ');
    if (eq.length && /^(?:\S+\s+)*?(let|var|case)\b/.test(s) && balanced(M, eq[0], codeEnd) && M[codeEnd - 1] !== '{') exprSites(M, D, eq[0] + 3, codeEnd, out);
  } else if (balanced(M, t, codeEnd)) assignSites(M, D, t, codeEnd, out);
  // the whole line as one statement
  const prev = (() => { for (let i = ln - 1; i >= 0; i--) { const p = MA[i].trimEnd(); if (p.trim()) return p; } return ''; })();
  const next = (() => { for (let i = ln + 1; i < MA.length; i++) { const p = MA[i].trim(); if (p) return p; } return ''; })();
  const lastPrev = prev.slice(-1), endCh = M[codeEnd - 1];
  if (balanced(M, t, codeEnd) && !DECL_START.test(s) && !NOT_STMT_START.test(s) && !OPCH.includes(s[0]) && !tops(M, D, t, codeEnd, ';').length
    && !'{,([+-*/%&|^<>=?:.'.includes(endCh) && !(prev && ',([=+-*/%&|^<>?:.'.includes(lastPrev))
    && !(next && (/^[.{)\]]/.test(next) || '+-*/%&|^<>=!?:'.includes(next[0]) || /^(else|where|catch)\b/.test(next))))
    out.push({ a: t, b: codeEnd, kind: 'stmt', line: true });
  return { out, t, codeEnd, D };
}
// the clauses of an if/guard/while condition starting at `start` (up to `lim`)
function headSites(M, D, start, lim, kw, out) {
  const end0 = condEnd(M.slice(0, lim), start, kw), end = end0 < 0 ? lim : end0;
  if (!(balanced(M, start, end) || end0 < 0)) return;
  for (const [x, y] of splitAt(M, D, start, end, ',')) {
    const cl = M.slice(x, y);
    if (/^(let|var|case)\b/.test(cl)) { const eq = tops(M, D, x, y, ' = '); if (eq.length) exprSites(M, D, eq[0] + 3, y, out); }
    else if (!/^#/.test(cl) && balanced(M, x, y)) exprSites(M, D, x, y, out);
  }
}
// Where the condition starting at `from` ends on this masked line: before the body's `{` (guard: before ` else`), at bracket depth 0. -1 when it continues on the next line.
export function condEnd(m, from, kw) {
  let depth = 0;
  for (let i = from; i < m.length; i++) {
    const c = m[i];
    if (c === '(' || c === '[') depth++;
    else if (c === ')' || c === ']') depth--;
    else if (depth === 0 && (kw === 'guard' ? m.startsWith(' else', i) && /^ else\s*(\{|$)/.test(m.slice(i)) : c === '{')) return m.slice(0, i).trimEnd().length;
  }
  return -1;
}

// ---- one file ----
// text: the original source; muts: [{id, line (1-based), op, raw (the mutant's whole line)}]
// -> { text: the schema source, held: Map(id -> line), fallback: Map(id -> why) }
export function schemaFile(text, muts) {
  const O = text.split('\n'), MA = maskAll(text, STR).split('\n');
  const fallback = new Map(), held = new Map();
  const byLine = new Map();
  for (const m of muts) { if (!byLine.has(m.line)) byLine.set(m.line, []); byLine.get(m.line).push(m); }
  const outLines = O.slice();
  for (const [line, ms] of byLine) {
    const ln = line - 1;
    if (ln < 0 || ln >= O.length) { for (const m of ms) fallback.set(m.id, 'line out of range'); continue; }
    const r = schemaLine(O[ln], MA, ln, ms);
    for (const [id, why] of r.fallback) fallback.set(id, why);
    for (const id of r.held) held.set(id, line);
    outLines[ln] = r.text;
  }
  return { text: outLines.join('\n'), held, fallback };
}

function schemaLine(O, MA, ln, ms) {
  const M = MA[ln], ML = maskLine(O);
  const fb = new Map();
  if (M.length !== O.length) { for (const m of ms) fb.set(m.id, 'mask length'); return { text: O, held: [], fallback: fb }; }
  const S = lineSites(MA, ln);
  let live = ms.slice();
  for (;;) {
    const holes = new Map(), ins = [];
    for (const m of live) {
      const R = m.raw;
      if (/-false$/.test(m.op)) {
        const at = S.head?.start;
        if (at === undefined || R !== O.slice(0, at) + 'false, ' + O.slice(at)) { fb.set(m.id, 'condition prefix: not a plain insertion'); continue; }
        ins.push(m); continue;
      }
      let p = 0; while (p < O.length && p < R.length && O[p] === R[p]) p++;
      let s = 0; while (s < O.length - p && s < R.length - p && O[O.length - 1 - s] === R[R.length - 1 - s]) s++;
      const lo = p, hi = O.length - s;
      // the change must be code on this line in the multi-line mask too (not inside a """ string or a /* */ comment)
      if (m.op !== 'drop-stmt' && [...O.slice(lo, Math.max(hi, lo + 1))].some((c, k) => c !== ' ' && (M[lo + k] === ' ' || M[lo + k] === STR) && ML[lo + k] !== ' ' && ML[lo + k] !== '"' && ML[lo + k] !== '#')) { fb.set(m.id, 'inside a multi-line string or comment'); continue; }
      if (/^\d+->\d+$/.test(m.op) && O[lo - 1] === '$') { fb.set(m.id, 'closure parameter index'); continue; }
      let best = null;
      if (m.op === 'drop-stmt') best = S.out.find((h) => h.line);
      else for (const h of S.out) if (h.a <= lo && hi <= h.b && (!best || h.b - h.a < best.b - best.a || (h.b - h.a === best.b - best.a && h.kind === 'expr'))) best = h;
      if (!best) { fb.set(m.id, m.op === 'drop-stmt' ? 'drop-stmt: the line is no complete statement' : 'no site holds the change'); continue; }
      const k = `${best.a}:${best.b}:${best.kind}`;
      if (!holes.has(k)) holes.set(k, { ...best, ms: [] });
      const h = holes.get(k);
      if (h.ms.length >= MAX_CHAIN) { fb.set(m.id, `more than ${MAX_CHAIN} mutants on one site`); continue; }
      const text = m.op === 'drop-stmt' ? R.trim() : R.slice(h.a, h.b + (R.length - O.length));
      h.ms.push({ id: m.id, text, raw: R, drop: m.op === 'drop-stmt' });
    }
    // a tree of the used sites (they nest or are disjoint by construction; anything else is a bug, so both sides fall back)
    const hs = [...holes.values()].sort((x, y) => x.a - y.a || y.b - x.b);
    const root = { a: 0, b: O.length, kids: [] }, stack = [root];
    let clash = null;
    for (const h of hs) {
      h.kids = [];
      while (stack.length > 1 && !(stack[stack.length - 1].a <= h.a && h.b <= stack[stack.length - 1].b)) stack.pop();
      const par = stack[stack.length - 1], prevKid = par.kids[par.kids.length - 1];
      if (prevKid && prevKid.b > h.a) { clash = [prevKid, h]; break; }
      par.kids.push(h); stack.push(h);
    }
    if (clash) { for (const h of clash) for (const x of h.ms) fb.set(x.id, 'overlapping sites'); live = live.filter((m) => !fb.has(m.id)); continue; }
    const at = S.head?.start ?? 0;
    const render = (node, active, plain) => {
      let out = '', pos = node.a;
      for (const kid of node.kids) {
        if (node === root && ins.length && at >= pos && at <= kid.a) { out += O.slice(pos, at) + insText(active, plain); pos = at; }
        out += O.slice(pos, kid.a) + holeText(kid, active, plain); pos = kid.b;
      }
      if (node === root && ins.length && at >= pos) { out += O.slice(pos, at) + insText(active, plain); pos = at; }
      return out + O.slice(pos, node.b);
    };
    const insText = (active, plain) => plain ? (ins.some((m) => m.id === active) ? 'false, ' : '') : ins.map((m) => `!${SW}(${m.id}), `).join('');
    const holeText = (h, active, plain) => {
      const inner = render(h, active, plain);
      if (plain) { const x = h.ms.find((y) => y.id === active); return x ? x.text : inner; }
      if (h.kind === 'expr') return `(${h.ms.map((x) => `${SW}(${x.id}) ? (${x.text})`).join(' : ')} : (${inner}))`;
      return `${h.ms.map((x, i) => `${i ? 'else ' : ''}if ${SW}(${x.id}) { ${x.text} } `).join('')}else { ${inner} }`;
    };
    // round trip: with one mutant active and the switch syntax left out, the line is exactly that mutant's line
    const all = [...ins.map((m) => ({ id: m.id, raw: m.raw })), ...hs.flatMap((h) => h.ms)];
    let bad = false;
    if (render(root, 0, true) !== O) { for (const x of all) fb.set(x.id, 'round trip (original)'); bad = true; }
    else for (const x of all) {
      const want = x.drop ? x.raw + O.slice(S.codeEnd) : x.raw;
      if (render(root, x.id, true) !== want) { fb.set(x.id, 'round trip'); bad = true; }
    }
    if (bad) { live = live.filter((m) => !fb.has(m.id)); continue; }
    return { text: all.length ? render(root, -1, false) : O, held: all.map((x) => x.id), fallback: fb };
  }
}

// ---- error mapping (schema-build.mjs) ----
// the brace blocks of a source: [{open, close}] (0-based lines), from the multi-line mask
export function blocks(text) {
  const M = maskAll(text), out = [], st = [];
  let line = 0;
  for (let i = 0; i < M.length; i++) {
    const c = M[i];
    if (c === '\n') line++;
    else if (c === '{') st.push(line);
    else if (c === '}' && st.length) out.push({ open: st.pop(), close: line });
  }
  return out;
}
// the held mutants a compiler error on `line` (1-based) is blamed on: that line's, else those of the innermost enclosing brace
// block that holds any, else every held mutant of the file
export function blameIds(text, held, line) {
  const on = [...held].filter(([, l]) => l === line).map(([id]) => id);
  if (on.length) return { ids: on, how: 'line' };
  const bs = blocks(text).filter((b) => b.open + 1 <= line && line <= b.close + 1).sort((x, y) => (x.close - x.open) - (y.close - y.open));
  for (const b of bs) {
    const ids = [...held].filter(([, l]) => l >= b.open + 1 && l <= b.close + 1).map(([id]) => id);
    if (ids.length) return { ids, how: `block ${b.open + 1}-${b.close + 1}` };
  }
  return { ids: [...held.keys()], how: 'file' };
}

// The switch, one copy per module that holds mutants (each module sees only its own internal declarations). PCA_MUTANT is read once.
// With PCA_SCHEMA_TRACE=<file> every switch evaluated appends its id to that file the first time this process reaches it.
export function switchSource(maxId) {
  return `// Generated by the mutation schema build (schema-build.mjs); never committed.
import Foundation

@usableFromInline let _pcaMutActive: Int = Int(ProcessInfo.processInfo.environment["PCA_MUTANT"] ?? "") ?? 0

@usableFromInline final class _PcaMutTrace: @unchecked Sendable {
    let seen: UnsafeMutablePointer<UInt8>
    let fd: Int32
    init?() {
        guard let p = ProcessInfo.processInfo.environment["PCA_SCHEMA_TRACE"], !p.isEmpty else { return nil }
        fd = open(p, O_WRONLY | O_APPEND | O_CREAT, 0o644)
        if fd < 0 { return nil }
        seen = UnsafeMutablePointer<UInt8>.allocate(capacity: ${maxId + 1})
        seen.initialize(repeating: 0, count: ${maxId + 1})
    }
    @usableFromInline func hit(_ id: Int) {
        if id < 0 || id > ${maxId} || seen[id] != 0 { return }
        seen[id] = 1
        var s = "\\(id)\\n"
        s.withUTF8 { b in _ = write(fd, b.baseAddress, b.count) }
    }
}
@usableFromInline let _pcaMutTrace: _PcaMutTrace? = _PcaMutTrace()

@usableFromInline @inline(__always) func ${SW}(_ id: Int) -> Bool {
    if let t = _pcaMutTrace { t.hit(id) }
    return id == _pcaMutActive
}
`;
}

// ---- self-test ----
function selfTest() {
  const t = [];
  const ok = (c, w) => t.push([!!c, w]);
  const run = (src, muts) => schemaFile(src, muts.map((m, i) => ({ id: i + 1, ...m })));
  const line = (src, ln) => src.split('\n')[ln - 1];
  // a comparison operand inside an if condition
  let s = 'func f(a: Int, b: Int) -> Bool {\n    if a == b {\n        return true\n    }\n    return false\n}';
  let r = run(s, [{ line: 2, op: '==->!=', raw: '    if a != b {' }, { line: 2, op: 'if-negate', raw: '    if !(a == b) {' }]);
  ok(line(r.text, 2) === `    if (${SW}(1) ? (a != b) : ${SW}(2) ? (!(a == b)) : (a == b)) {`, 'one site, two mutants: ' + line(r.text, 2));
  ok(r.held.size === 2 && r.fallback.size === 0, 'both held');
  // if-false prefix + a site inside the same condition
  s = 'func f(x: Int?) {\n    if let y = x, y > 3 {\n        print(y)\n    }\n}';
  r = run(s, [{ line: 2, op: 'if-false', raw: '    if false, let y = x, y > 3 {' }, { line: 2, op: '3->4', raw: '    if let y = x, y > 4 {' }]);
  ok(line(r.text, 2) === `    if !${SW}(1), let y = x, y > (${SW}(2) ? (4) : (3)) {`, 'condition prefix + operand: ' + line(r.text, 2));
  // drop-stmt on a call statement, and an argument site on the same line
  s = 'func f() {\n    check(a + 1, label: b) // note\n}';
  r = run(s, [{ line: 2, op: 'drop-stmt', raw: '    /* dropped */' }, { line: 2, op: '+->-', raw: '    check(a - 1, label: b) // note' }]);
  ok(line(r.text, 2) === `    if ${SW}(1) { /* dropped */ } else { check((${SW}(2) ? (a - 1) : (a + 1)), label: b) } // note`, 'statement site keeps the comment outside: ' + line(r.text, 2));
  // a labelled argument keeps its label outside the site
  s = 'let v = make(count: n * 2, flag: true)';
  r = run(s, [{ line: 1, op: '2->3', raw: 'let v = make(count: n * 3, flag: true)' }, { line: 1, op: 'true->false', raw: 'let v = make(count: n * 2, flag: false)' }]);
  ok(line(r.text, 1) === `let v = make(count: (${SW}(1) ? (n * 3) : (n * 2)), flag: (${SW}(2) ? (false) : (true)))`, 'labels stay outside: ' + line(r.text, 1));
  // return value
  s = 'func f() -> Bool {\n    return x >= limit\n}';
  r = run(s, [{ line: 2, op: '>=->>', raw: '    return x > limit' }]);
  ok(line(r.text, 2) === `    return (${SW}(1) ? (x > limit) : (x >= limit))`, 'return value: ' + line(r.text, 2));
  // && chain operand: the smallest site
  s = 'if a > 0 && b < 5 || c {\n}';
  r = run(s, [{ line: 1, op: '5->6', raw: 'if a > 0 && b < 6 || c {' }, { line: 1, op: '&&->||', raw: 'if a > 0 || b < 5 || c {' }]);
  ok(line(r.text, 1) === `if (${SW}(2) ? (a > 0 || b < 5) : (a > 0 && b < (${SW}(1) ? (6) : (5)))) || c {`, 'chain operands: ' + line(r.text, 1));
  // string literals inside the change are fine; a mutant inside a multi-line string falls back
  s = 'if p["t"] != .string("x") { throw bad("no") }';
  r = run(s, [{ line: 1, op: 'if-negate', raw: 'if !(p["t"] != .string("x")) { throw bad("no") }' }]);
  ok(r.held.size === 1, 'strings inside the condition: ' + [...r.fallback.values()]);
  // an else-if without the brace, and an if inside a one-line body after a ;
  s = 'func f() {\n    else if role == "m" { add("x") }\n}';
  r = run(s, [{ line: 2, op: '==->!=', raw: '    else if role != "m" { add("x") }' }]);
  ok(r.held.size === 1 && line(r.text, 2) === `    else if (${SW}(1) ? (role != "m") : (role == "m")) { add("x") }`, 'else if: ' + line(r.text, 2));
  s = 'func d(_ xs: [Int]) -> Bool { var seen: [Int] = []; for x in xs { if seen.contains(x) { return false }; seen.append(x) }; return true }';
  r = run(s, [{ line: 1, op: 'true->false', raw: 'func d(_ xs: [Int]) -> Bool { var seen: [Int] = []; for x in xs { if seen.contains(x) { return true }; seen.append(x) }; return true }' },
    { line: 1, op: 'if-negate', raw: 'func d(_ xs: [Int]) -> Bool { var seen: [Int] = []; for x in xs { if !(seen.contains(x)) { return false }; seen.append(x) }; return true }' }]);
  ok(r.held.size === 2, 'statements after ; and an inner if: ' + [...r.fallback.values()] + ' ' + line(r.text, 1));
  // a mutant inside a multi-line string falls back
  s = 'let q = """\n    a == b\n    """';
  r = run(s, [{ line: 2, op: '==->!=', raw: '    a != b' }]);
  ok(r.fallback.get(1) === 'inside a multi-line string or comment' && line(r.text, 2) === '    a == b', 'multi-line string falls back');
  // a declaration line is never a statement site, but its value is
  s = 'struct S {\n    static let k = 5\n}';
  r = run(s, [{ line: 2, op: '5->6', raw: '    static let k = 6' }]);
  ok(line(r.text, 2) === `    static let k = (${SW}(1) ? (6) : (5))`, 'declaration value: ' + line(r.text, 2));
  // a continuation line (previous line ends with `=`) is no statement: drop-stmt falls back
  s = 'func f() {\n    let x =\n        g(1)\n}';
  r = run(s, [{ line: 3, op: 'drop-stmt', raw: '        /* dropped */' }]);
  ok(r.fallback.has(1), 'continuation line is no statement');
  // closure parameter index
  s = 'let y = xs.map { $0 + 1 }';
  r = run(s, [{ line: 1, op: '0->1', raw: 'let y = xs.map { $1 + 1 }' }, { line: 1, op: '1->2', raw: 'let y = xs.map { $0 + 2 }' }]);
  ok(r.fallback.get(1) === 'closure parameter index' && line(r.text, 1) === `let y = xs.map { (${SW}(2) ? ($0 + 2) : ($0 + 1)) }`, 'closure body site: ' + line(r.text, 1));
  // guard else, one-line body
  s = 'func f(n: Int) -> Int {\n    guard n > 0 else { return 0 }\n    return n\n}';
  r = run(s, [{ line: 2, op: 'guard-negate', raw: '    guard !(n > 0) else { return 0 }' }, { line: 2, op: '0->1', raw: '    guard n > 1 else { return 0 }' }, { line: 2, op: '0->1', raw: '    guard n > 0 else { return 1 }' }]);
  ok(line(r.text, 2) === `    guard (${SW}(1) ? (!(n > 0)) : (n > (${SW}(2) ? (1) : (0)))) else { return (${SW}(3) ? (1) : (0)) }`, 'guard: ' + line(r.text, 2));
  // assignment statement + its value
  s = 'func f() {\n    total += step * 2\n}';
  r = run(s, [{ line: 2, op: '*->/', raw: '    total += step / 2' }, { line: 2, op: 'drop-stmt', raw: '    /* dropped */' }]);
  ok(line(r.text, 2) === `    if ${SW}(2) { /* dropped */ } else { total += (${SW}(1) ? (step / 2) : (step * 2)) }`, 'assignment: ' + line(r.text, 2));
  // blame: a line, a block, the file
  const held = new Map([[1, 2], [2, 5]]);
  const src = 'func a() {\n  x\n}\nfunc b() {\n  y\n  z\n}';
  ok(blameIds(src, held, 2).ids.join() === '1', 'blame the line');
  ok(blameIds(src, held, 6).ids.join() === '2' && blameIds(src, held, 6).how.startsWith('block'), 'blame the enclosing block');
  ok(blameIds(src, new Map([[1, 2]]), 6).how === 'file', 'blame the file');
  // the switch source names the largest id
  ok(switchSource(41).includes('capacity: 42') && switchSource(41).includes('id > 41'), 'switch source');
  const bad = t.filter(([c]) => !c);
  for (const [, w] of bad) console.error('self-test failed: ' + w);
  if (bad.length) process.exit(1);
  console.log(`schema self-test ok (${t.length} checks)`);
}
if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1]) && process.argv.includes('--self-test')) selfTest();
