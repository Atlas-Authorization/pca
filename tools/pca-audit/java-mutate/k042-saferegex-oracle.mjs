// Oracle for the Java K042SafeRegex*Test kill tests (SafeRegex.java vs packages/pca/src/safe-regex.ts + predicates.ts guard).
//   cd <repo root> && npx tsx tools/pca-audit/java-mutate/k042-saferegex-oracle.mjs sdks/java-pca/test-data/k042-saferegex.txt.gz
//   (no node_modules? NODE_PATH=<dir holding @noble/hashes@1 @noble/curves@1 @noble/post-quantum@0.4 @scure/base@1 + a stub
//    @atlasauth/pca-verified-core>: the verified-core opt-in is off here, so the stub is never called)
// Deterministic (fixed PRNG seed). Gzipped lines (every string is the hex of its UTF-16 code units, '' = "-"):
//   P <pattern> <isSafeRegexSource 0|1> <program or N>      program = inst;inst;...  inst = op,x,y,neg,lo-hi:lo-hi (neg/ranges '-' when no set,
//                                                           ranges 'E' when empty); a program text over 1000 chars is H<sha256 hex of it>
//   M <subject> <T|F|N>                                       runSafeRegex(compileSafeRegex(pattern), subject), for the preceding P
import fs from 'node:fs';
import zlib from 'node:zlib';
import { createHash } from 'node:crypto';
delete process.env.PCA_VERIFIED_CORE;
const sr = await import(new URL('../../../packages/pca/src/safe-regex.ts', import.meta.url).href);
const pr = await import(new URL('../../../packages/pca/src/predicates.ts', import.meta.url).href);

let seed = 0x9e3779b9;
const rnd = () => {
  seed ^= seed << 13; seed >>>= 0;
  seed ^= seed >>> 17;
  seed ^= seed << 5; seed >>>= 0;
  return seed / 0x100000000;
};
const pick = (a) => a[Math.floor(rnd() * a.length)];
const hex = (s) => (s.length === 0 ? '-' : [...Array(s.length).keys()].map((k) => s.charCodeAt(k).toString(16).padStart(4, '0')).join(''));

const patterns = new Set();
const add = (p) => patterns.add(p);

// ---- hand-written: every parser / escape / class / quantifier branch and both sides of every bound ----
const hand = [
  '', 'a', 'ab', 'abc', '.', '..', 'a.b', '^', '$', '^a', 'a$', '^a$', '^$', '$^', 'a^', '$a', '^*', '$+', '^?', '${2}', '(^)*', '(?:$)+',
  '(?:^a|b$)', 'a|^b', '^|$', '(?:)', '()', '(?:)*', '(?:|)', '(?:|)*', '|', 'a|', '|a', 'a||b', 'a|b|c', 'a|b|c|d', '(a|b)c', 'x(a|bc|)y',
  '(', ')', 'a)', '(a', '((a)', '(a))', '(?', '(?=a)', '(?!a)', '(?<a>b)', '(?<=a)', '(?:a', '(?:a)', '(?a)', '(a)(b)', '((a|b)|(c|d))',
  '*', '+', '?', '{', '{1}', 'a**', 'a*+', 'a+?', 'a*?', 'a??', 'a{2}?', 'a{2}{3}', 'a?*',
  'a*', 'a+', 'a?', 'a{0}', 'a{1}', 'a{2}', 'a{3}', 'a{0,}', 'a{1,}', 'a{2,}', 'a{0,1}', 'a{0,2}', 'a{1,3}', 'a{2,2}', 'a{3,2}', 'a{2,1}',
  'a{64}', 'a{65}', 'a{0,64}', 'a{0,65}', 'a{64,}', 'a{65,}', 'a{64,64}', 'a{63,64}', 'a{64,65}', 'a{1,64}', 'a{9999}', 'a{0,9999}', 'a{10000}',
  'a{12345}', 'a{0,12345}', 'a{,3}', 'a{1', 'a{1,', 'a{1,2', 'a{a}', 'a{1,a}', 'a{ 1}', 'a{01}', 'a{00,02}', 'a{0064}', 'a{0065}', 'a{1,0064}',
  'a{1,0065}', '{2}', 'a|{2}', '(?:{2})', 'a{1}{', 'x{',
  '(?:ab){2}', '(?:ab){0,2}', '(?:a|b){2,3}', '(?:a|b)*', '(?:a*)*', '(a+)+', '(?:ab)+', '(?:a?){3}', 'a{2,}b', '(?:a{2}){2}', '(?:a{0,2}){2,}',
  '[]', '[^]', '[a]', '[ab]', '[abc]', '[^a]', '[^ab]', '[a-c]', '[c-a]', '[a-a]', '[a-]', '[-a]', '[a-]]', '[]a]', '[^]a]', '[a-z0-9_]',
  '[\\d]', '[\\D]', '[\\w]', '[\\W]', '[\\s]', '[\\S]', '[^\\d]', '[^\\D]', '[\\d-z]', '[a-\\d]', '[\\d-\\w]', '[\\D-a]', '[a-\\S]', '[\\b]', '[\\b-z]',
  '[a\\-z]', '[\\]]', '[\\\\]', '[\\^]', '[\\x41-\\x5a]', '[\\x5a-\\x41]', '[\\u0041-\\u005A]', '[\\t-\\r]', '[\\n]', '[\\0]', '[\\cA-\\cZ]', '[',
  '[a', '[^', '[a-', '[\\', '[\\x4', '[\\q]', '[.]', '[$^]', '[(]', '[)|*+?{}]', '[a-z]{2,3}', '[^\\n\\r]*', '[\\s\\S]', '[\\w\\W]', '[\\d\\D]',
  '[A-Za-z]', '[z-a]', '[!-/]', '[0-9a-fA-F]', '[\\u0000-\\uffff]', '[^\\u0000-\\uffff]', '[\\u00ff-\\u0100]', '[a-cb-d]', '[a-ce-g]', '[a-cd-f]',
  '[ab][cd]', '[a][b]?', '[^/]+', '/acct/[^/]+/items/\\d+', '(?:GET|POST) /x',
  '\\', 'a\\', '\\d', '\\D', '\\w', '\\W', '\\s', '\\S', '\\t', '\\n', '\\v', '\\f', '\\r', '\\0', '\\00', '\\01', '\\09', '\\0a', '\\0/', '\\0:',
  '\\x', '\\x4', '\\x41', '\\x4g', '\\xg1', '\\x7f', '\\xff', '\\xFF', '\\xfF', '\\x00', '\\x09', '\\x0a', '\\x0A', '\\x/0', '\\x:0', '\\x@0', '\\xG0',
  '\\x`0', '\\xa0', '\\xf0', '\\xA0', '\\xF0', '\\x0/', '\\x0:', '\\x0@', '\\x0G', '\\x0`', '\\x0g', '\\x41b',
  '\\u', '\\u0', '\\u00', '\\u004', '\\u0041', '\\u00e9', '\\uFFFF', '\\uffff', '\\u12g4', '\\u/000', '\\u:000', '\\u0041b', '\\u{41}', '\\uD83D',
  '\\c', '\\cA', '\\ca', '\\cZ', '\\cz', '\\cM', '\\cj', '\\c@', '\\c[', '\\c`', '\\c{', '\\c1', '\\c_', '\\cAb',
  '\\b', '\\B', '\\k', '\\k<a>', '\\1', '\\9', '\\p{L}', '\\P', '\\a', '\\e', '\\g', '\\q', '\\z', '\\A', '\\Z', '\\_', '\\8', '\\5',
  '\\.', '\\*', '\\+', '\\?', '\\(', '\\)', '\\[', '\\]', '\\{', '\\}', '\\|', '\\^', '\\$', '\\\\', '\\/', '\\-', '\\ ', '\\@', '\\`', '\\~', '\\!',
  '\\é', '\\{2}', 'a\\{2}', 'a\\{0,99}', '\\{0,99}',
  'é', '\u2028', 'a\u00a0b', '\ud83d\ude00', '.{3}', '.*', '.+a', 'a.*b', '(?:.)', '(?:a(?:b(?:c)))', '((((a))))', '(?:(?:(?:a?)?)?)?',
  '(?:(?:(?:(?:(?:(?:a?)?)?)?)?)?)?', '(?:(?:)?)?', '(?:(?:(?:)?)?)?', '(?:(?:(?:(?:)*)*)*)*', '(?:a?){5}', '(?:(?:a|)|)', '(?:(?:(?:a|b)|c)|d)',
];
for (const h of hand) add(h);
// every printable ASCII char escaped, inside and outside a class, plain, and in a range with itself
for (let c = 0x20; c < 0x7f; c++) {
  const ch = String.fromCharCode(c);
  add('\\' + ch); add('[\\' + ch + ']'); add(ch); add('[' + ch + ']'); add('a' + ch); add(ch + 'a'); add('[\\' + ch + '-z]'); add('[!-\\' + ch + ']');
  add('\\c' + ch); add('[\\c' + ch + ']'); add('\\0' + ch);
}
// \x / \u with every hex-boundary character in every position
const hexProbe = ['0', '9', 'a', 'f', 'A', 'F', '/', ':', '@', 'G', '`', 'g'];
for (const p of hexProbe) for (const q of hexProbe) { add('\\x' + p + q); add('[\\x' + p + q + ']'); }
for (const p of hexProbe) { add('\\u' + p + '000'); add('\\u0' + p + '00'); add('\\u00' + p + '0'); add('\\u000' + p); add('[\\u000' + p + ']'); }
add('\\x0'); add('[\\x0'); add('\\u004'); add('[\\u004]'); add('\\u00'); add('\\u0');

// NFA-size boundary: emit's two 'pattern too large' checks and compile's final check
for (const k of [1, 2, 3, 4, 60, 61, 62, 63, 64]) {
  add(`(?:a{64}){${k}}`); add(`(?:a{63}){${k}}`); add(`(?:(?:a{64}){64}){${k}}`); add(`(?:a{0,64}){${k}}`);
}
for (let n = 4090; n <= 4100; n++) add('a'.repeat(n));
for (let n = 4090; n <= 4100; n++) add('a'.repeat(n - 4096 + 4032) + 'b{64}');
add('a'.repeat(4094) + '|');
add('a'.repeat(4093) + '|b');
add('(?:' + 'a'.repeat(4094) + ')');
for (const n of [2046, 2047, 2048, 2049]) add('a?'.repeat(n));
for (const n of [1364, 1365, 1366]) add('a*'.repeat(n));
for (const k of [63, 64, 65]) { add(`(?:a|b){${k}}`); add(`(?:a{8}){${k}}`); }
for (let k = 0; k < 70; k++) add(`(?:a{64}){${k}}` + 'b'.repeat(k));
add('(?:(?:a{64}){64}){64}');
add('(?:a{64}){64}a');
add('(?:a{64}){63}' + 'a'.repeat(63) + '(?:b)');
add('(?:a{64}){63}' + 'a'.repeat(62) + '(?:b|c)');

// ---- guard: cost bits (22), unbounded = 8, ceil(log2(options)), nesting, backrefs, groups ----
for (let n = 20; n <= 24; n++) { add('a|'.repeat(n) + 'a'); add('(?:' + 'a|'.repeat(n) + 'a)'); }
for (const q of ['*', '+', '{2,}', '{0,}', '*?', '+?']) {
  add('a' + q); add('a' + q + 'b' + q); add('a' + q + 'b' + q + 'c' + q); add('a' + q + 'b' + q + 'c?'); add('a' + q + 'b' + q + 'c{0,7}');
  add('a' + q + 'b' + q + 'c{0,3}'); add('a' + q + 'b' + q + 'c{0,2}'); add('a' + q + 'b' + q + 'c{0,1}'); add('a' + q + 'b' + q + 'c{0,4}');
  add('a' + q + 'b' + q + 'c|d'); add('a' + q + 'b' + q + 'c|d|e|f|g|h|i'); add('a' + q + 'b' + q + 'c|d|e|f|g|h|i|j'); add('a' + q + 'b' + q + '|||||');
  add('a' + q + 'b' + q + '||||||'); add('a' + q + 'b' + q + '|||||||');
}
for (const [lo, hi] of [[0, 1], [0, 2], [0, 3], [1, 4], [0, 4], [0, 7], [0, 8], [1, 8], [0, 15], [0, 16], [0, 31], [0, 63], [0, 64], [1, 64], [2, 64], [3, 3], [5, 5], [64, 64]]) {
  add(`a{${lo},${hi}}`);
  for (const pad of ['a{0,63}', 'a{0,31}', 'a{0,15}', 'a?', 'a{0,2}', 'a{0,3}', 'a*', 'a|b', 'a{0,7}']) {
    add(`a{${lo},${hi}}${pad}${pad}`); add(`a{${lo},${hi}}${pad}${pad}${pad}`); add(`${pad}${pad}${pad}a{${lo},${hi}}`); add(`a*${pad}a{${lo},${hi}}`);
    add(`a*b*${pad}a{${lo},${hi}}`); add(`a+b+a{${lo},${hi}}${pad}`);
  }
}
for (let n = 1; n <= 24; n++) add('a?'.repeat(n));
for (let n = 1; n <= 12; n++) add('a{0,2}'.repeat(n));
for (let n = 1; n <= 12; n++) add('a{0,3}'.repeat(n));
for (let n = 1; n <= 8; n++) add('a{0,7}'.repeat(n));
for (let n = 1; n <= 8; n++) add('a{1,8}'.repeat(n));
for (let n = 1; n <= 6; n++) add('a{0,15}'.repeat(n));
for (let n = 1; n <= 6; n++) add('a{2,6}'.repeat(n));
for (let n = 1; n <= 6; n++) add('a{3,5}'.repeat(n));
for (let n = 1; n <= 5; n++) add('a*'.repeat(n));
for (let n = 1; n <= 23; n++) add('a{3}'.repeat(n) + 'a?'.repeat(n));
add('a{99999999999}'); add('a{0,99999999999}'); add('a{99999999999,}'); add('a{2,99999999999}'); add('a{99999999999,1}'); add('a{5,4}'); add('a{4,5}');
add('(a+)*'); add('(a*)?'); add('(a?)+'); add('(a|b)+'); add('(a|b)?'); add('(?:a|b){2}'); add('(?:ab)*'); add('(?:a(?:b+))+'); add('(?:a(?:b|c))*');
add('(?:a(?:b+)c)d*'); add('(?:(?:a+)b)*'); add('(?:(?:a|b)c)?'); add('((a))+'); add('((a)+)'); add('((a)|b)+'); add('(a)(b+)*'); add('(a+)(b)*');
add('(a)+(b|c)'); add('(?:a|b)(c)+'); add('(a|b)c+'); add('(?:a+)'); add('(?:a+)b'); add('(?:a+)?');
add('\\1'); add('a\\1'); add('(a)\\1'); add('\\k<x>'); add('(?<x>a)\\k<x>'); add('\\2'); add('\\9a'); add('\\0'); add('\\:'); add('\\j'); add('\\l');
add('[\\]a+]+'); add('[^](a+)+]'); add('[](a+)+]'); add('[^]]'); add('[\\]'); add('[\\\\]+'); add('[^\\]]*'); add('[a\\]'); add('[a\\]]'); add('[a\\');
add('[]]'); add('[^'); add('[^]'); add('[^^]'); add('[^^]+'); add('[^]*'); add('x[^]*'); add('[a]+[b]+'); add('[a]{2}');
add('(?'); add('(?:'); add('(?='); add('(?:a))'); add('a)('); add('(?:a)(?:b)'); add(')('); add('())'); add('(()'); add('(?:)?'); add('(?:?)');
add('a{2,3}{2}'); add('a{2,3}?'); add('a{2,3}??'); add('a??b'); add('a*?b'); add('a+??'); add('?a'); add('|*'); add('(*)'); add('(?:*)');
add('a{'); add('a{}'); add('a{,}'); add('a{1,2,3}'); add('{'); add('}'); add('a}'); add(']'); add('a]'); add('a{1}}'); add('a{2}b{');

// ---- random: token soup ----
const tokens = ['a', 'b', 'c', '.', '|', '(', ')', '(?:', '*', '+', '?', '{2}', '{0,2}', '{1,}', '{,1}', '{', '}', '[ab]', '[^a]', '[a-c]', '[]',
  '[^]', '\\d', '\\w', '\\s', '\\D', '^', '$', '\\', '\\.', '\\x41', '\\u0062', '\\n', '\\b', '\\1', '[', ']', '-', '{65}', '{64}', '(?=', 'é', '\\cA', '\\0'];
for (let k = 0; k < 4000; k++) {
  const len = 1 + Math.floor(rnd() * 8);
  let p = '';
  for (let t = 0; t < len; t++) p += pick(tokens);
  add(p);
}
// random but valid-ish: nested groups of quantified atoms
const atoms = ['a', 'b', '.', '[ab]', '[^b]', '\\d', 'x', '[a-c]', '\\w'];
const quants = ['', '', '*', '+', '?', '{2}', '{0,2}', '{1,3}', '{2,}', '?', '*?'];
const gen = (d) => {
  const r = rnd();
  if (d > 2 || r < 0.5) return pick(atoms) + pick(quants);
  if (r < 0.7) return '(?:' + gen(d + 1) + gen(d + 1) + ')' + pick(quants);
  if (r < 0.85) return '(?:' + gen(d + 1) + '|' + gen(d + 1) + ')' + pick(quants);
  return '(' + gen(d + 1) + ')' + pick(quants);
};
for (let k = 0; k < 2500; k++) {
  const n = 1 + Math.floor(rnd() * 3);
  let p = rnd() < 0.15 ? '^' : '';
  for (let t = 0; t < n; t++) p += gen(0);
  if (rnd() < 0.15) p += '$';
  add(p);
}

// ---- subjects ----
const charPool = ['a', 'b', 'c', 'x', '0', '9', '5', '_', '-', ' ', '\n', '\r', '\t', '\u000b', '\u000c', '\u2028', '\u2029', '\u00a0', 'A', 'Z',
  '/', ':', '@', '[', '`', '{', 'z', '\u0000', '\u0001', '\u001a', '\u0008', '\uffff', '\u0100', '\u00ff', 'é', '\ufeff', '\u3000', '\u1680',
  '\u2000', '\u200a', '\u200b', '\u202f', '\u205f', '\u0009', '\u000d', '\u000e', '\u001f', '\u0020', '\u0021', '\u2027', '\u202a', '.', '\\', '|', 'é'];
const sampleFromSet = (set) => {
  // a code unit in the set (or any if impossible), preferring range edges
  for (let tries = 0; tries < 40; tries++) {
    let c;
    if (set.negated || set.ranges.length === 0) c = rnd() < 0.7 ? pick(charPool).charCodeAt(0) : Math.floor(rnd() * 0x10000);
    else {
      const r = pick(set.ranges);
      const t = rnd();
      c = t < 0.3 ? r[0] : t < 0.6 ? r[1] : r[0] + Math.floor(rnd() * (r[1] - r[0] + 1));
    }
    if (set.has(c)) return String.fromCharCode(c);
  }
  return null;
};
// random walk of the NFA: a (probably) matching subject
const walk = (prog) => {
  let pc = 0, out = '';
  for (let steps = 0; steps < 300; steps++) {
    const ins = prog[pc];
    switch (ins.op) {
      case 0: { const c = sampleFromSet(ins.set); if (c === null) return null; out += c; pc++; break; }
      case 1: pc = rnd() < 0.5 ? ins.x : ins.y; break;
      case 2: pc = ins.x; break;
      case 3: case 4: pc++; break;
      case 5: return out;
    }
    if (out.length > 40) return out;
  }
  return out;
};
const subjectsFor = (p, prog) => {
  const subs = new Set(['']);
  const lits = [...p].filter((ch) => !'()|*+?{}[]^$\\'.includes(ch));
  for (let k = 0; k < 6; k++) {
    const len = 1 + Math.floor(rnd() * 5);
    let s = '';
    for (let t = 0; t < len; t++) s += rnd() < 0.5 && lits.length ? pick(lits) : pick(charPool);
    subs.add(s);
  }
  for (let k = 0; k < 8; k++) {
    const w = walk(prog);
    if (w === null) continue;
    subs.add(w);
    if (w.length > 0) {
      subs.add(w.slice(1)); subs.add(w.slice(0, -1)); subs.add(w + w.slice(-1)); subs.add(w[0] + w);
      const at = Math.floor(rnd() * w.length);
      subs.add(w.slice(0, at) + pick(charPool) + w.slice(at + 1));
    }
  }
  return [...subs];
};
// exhaustive single-code-unit probes for the small set-defining patterns (CharSet.has, escapes, class/complement edges)
const unitProbe = [];
for (let c = 0; c < 0x80; c++) unitProbe.push(String.fromCharCode(c));
for (const c of [0x9f, 0xa0, 0xa1, 0xfe, 0xff, 0x100, 0x167f, 0x1680, 0x1681, 0x1fff, 0x2000, 0x2005, 0x200a, 0x200b, 0x2027, 0x2028, 0x2029, 0x202a, 0x202e,
  0x202f, 0x2030, 0x205e, 0x205f, 0x2060, 0x2fff, 0x3000, 0x3001, 0xd83d, 0xde00, 0xfefe, 0xfeff, 0xff00, 0xfffe, 0xffff]) unitProbe.push(String.fromCharCode(c));

const lines = [];
let nP = 0, nM = 0, nC = 0, nS = 0;
for (const p of patterns) {
  const re = sr.compileSafeRegex(p);
  const safe = pr.isSafeRegexSource(p) ? 1 : 0;
  let progStr = 'N';
  if (re) {
    progStr = re.program.map((ins) => [ins.op, ins.x, ins.y, ins.set ? (ins.set.negated ? 1 : 0) : '-',
      ins.set ? (ins.set.ranges.length ? ins.set.ranges.map((r) => `${r[0]}-${r[1]}`).join(':') : 'E') : '-'].join(',')).join(';');
    if (progStr.length > 1000) progStr = 'H' + createHash('sha256').update(progStr).digest('hex');
    nC++;
  }
  nS += safe;
  nP++;
  lines.push(`P ${hex(p)} ${safe} ${progStr}`);
  if (!re) continue;
  const small = re.program.length <= 4 && p.length <= 16;
  const subs = new Set(subjectsFor(p, re.program));
  if (small) for (const u of unitProbe) { subs.add(u); subs.add(u + u); }
  for (const s of subs) {
    const v = sr.runSafeRegex(re, s);
    lines.push(`M ${hex(s)} ${v === null ? 'N' : v ? 'T' : 'F'}`);
    nM++;
  }
}
fs.writeFileSync(process.argv[2], zlib.gzipSync(Buffer.from(lines.join('\n') + '\n'), { level: 9 }));
console.error(`patterns ${nP} compiled ${nC} safe ${nS} match-cases ${nM}`);
