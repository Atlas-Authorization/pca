// Oracle for the Kotlin SafeRegex kill tests (KillRegexTest.kt): runs the TS reference (packages/pca/src/safe-regex.ts,
// predicates.ts isSafeRegexSource, regex-budget.ts) over a pattern corpus (every escape / class / quantifier / anchor / refusal
// branch, size and step boundaries) crossed with boundary-probing subjects, plus seeded random patterns. Deterministic.
//   <tsx> tools/pca-audit/kotlin-mutate/killRegex-oracle-gen.mjs <pca-src-dir> sdks/kotlin-pca/test-data/killRegex.json.gz
// <pca-src-dir> = a copy of packages/pca/src with its deps installed beside it (the verified-core package resolves from there).
import fs from 'node:fs';
import zlib from 'node:zlib';
const src = process.argv[2];
const out = process.argv[3];
const sr = await import(`${src}/safe-regex.ts`);
const pr = await import(`${src}/predicates.ts`);
const rb = await import(`${src}/regex-budget.ts`);

let seedS = 0x9e3779b9;
const rnd = () => { seedS ^= seedS << 13; seedS >>>= 0; seedS ^= seedS >>> 17; seedS ^= seedS << 5; seedS >>>= 0; return seedS / 4294967296; };
const pick = (a) => a[Math.floor(rnd() * a.length)];

const P = [];
const add = (...ps) => { for (const p of ps) P.push(p); };
// literals, escapes
add('', 'a', 'abc', 'a.c', '\\d', '\\D', '\\w', '\\W', '\\s', '\\S', '\\t', '\\n', '\\v', '\\f', '\\r', '\\0', '\\00', '\\01', '\\09', '\\08',
  '\\x41', '\\x4', '\\x', '\\xZZ', '\\x4G', '\\xG4', '\\xff', '\\xFF', '\\u0041', '\\u004', '\\u', '\\u00G1', '\\u00g1', '\\uffff', '\\uFFFF', '\\u0000', '\\u2028',
  '\\cA', '\\ca', '\\cz', '\\cZ', '\\c1', '\\c', '\\c@', '\\c[', '\\c`', '\\c{', '\\cJ', '\\b', '\\B', '\\a', '\\e', '\\_', '\\-', '\\.', '\\\\', '\\/', '\\\\\\\\', '\\', 'a\\', '\\1', '\\9', '\\k', '\\p', '\\P', '\\A', '\\Z', '\\z', '\\G',
  '\\(', '\\)', '\\[', '\\]', '\\{', '\\}', '\\*', '\\+', '\\?', '\\|', '\\^', '\\$', '\\ ', '\\@', '\\0a', '\\x4a', '\\u004a', '\\x00', '\\u00e9', 'é', '😀', '\\ud83d\\ude00');
// classes
add('[]', '[^]', '[a]', '[abc]', '[a-c]', '[a-a]', '[c-a]', '[a-]', '[-a]', '[a\\-c]', '[\\d-x]', '[x-\\d]', '[\\d-\\w]', '[\\w-z]', '[a-\\d]', '[\\D]', '[\\W]', '[\\S]', '[^\\s]', '[\\b]', '[\\B]',
  '[\\s\\S]', '[\\da-f]', '[^a-z]', '[a', '[a\\', '[^', '[', '[^a', '[\\x41-\\x43]', '[\\u0041-\\u0043]', '[\\0]', '[\\cJ]', '[.]', '[$^]', '[a-z0-9_]', '[0-9]', '[\\u0000-\\uffff]', '[\\uffff]', '[^\\uffff]',
  '[\\u0100-\\u0200]', '[a-fc-k]', '[a-cd-f]', '[a-cc-f]', '[e-ga-c]', '[a-ce-g]', '[ace]', '[eca]', '[a-ca-c]', '[a-zA-Z]', '[\\w]', '[\\d\\D]', '[\\w\\W]', '[^\\d\\D]', '[^\\w\\W]', '[\\s]', '[\\u0000]', '[^\\u0000]',
  '[\\0-\\x7f]', '[^\\0-\\x7f]', '[\\x00-\\uffff]', '[\\u0000-\\ufffe]', '[^\\u0001-\\uffff]', '[^\\u0000-\\ufffe]', '[^\\x00-\\x7f]', '[\\W\\d]', '[\\D\\w]', '[^\\W]', '[^\\D]', '[^\\S]', '[\\u2028-\\u2029]', '[\\n\\r]', '[^\\n\\r\\u2028\\u2029]',
  '[]a]', '[a-]]', '[--a]', '[+--]', '[\\--\\-]', '[a-\\x62]', '[\\x61-b]', '[\\]]', '[\\[]', '[\\\\]', '[^\\]]', '[\\^]', '[a^]', '[\\.-\\/]', '[!-~]', '[ -~]', '[\\t-\\r]', '[\\s-a]', '[a-\\s]', '[\\d-]', '[-\\d]', '[\\d-\\d]',
  '[\\ca-\\cz]', '[\\c1]', '[\\x4]', '[\\u004]', '[\\1]', '[\\9]', '[\\k]', '[\\p]', '[\\00]', '[\\01]', '[é-ü]', '[😀]', '[\\ud83d\\ude00]', '[^😀]', '[a-c-e]', '[a-c-]', '[%--]', '[a\\d-z]', '[\\d-z]', '[\\d-\\s]', '[a-b-c-d]');
// quantifiers
for (const q of ['*', '+', '?', '{0}', '{1}', '{2}', '{3}', '{0,}', '{1,}', '{2,}', '{0,1}', '{0,2}', '{1,2}', '{2,3}', '{1,3}', '{3,3}', '{0,0}', '{2,1}', '{64}', '{65}', '{63}', '{64,}', '{65,}', '{63,}', '{0,64}', '{0,65}', '{1,64}', '{1,65}', '{64,64}', '{64,65}',
  '{65,65}', '{64,63}', '{,5}', '{,}', '{a}', '{', '{1', '{1,', '{1,2', '{1,a}', '{a,1}', '{12345}', '{1234}', '{0001}', '{00064}', '{0064}', '{1,12345}', '{1,1234}', '{1234,}', '{ 1}', '{1 }', '{1, 2}', '{1,2 }', '}', '{}', '{-1}', '{1,-2}', '{+1}', '{1.5}'])
  add(`a${q}`, `a${q}?`, `(?:ab)${q}`, `[ab]${q}`, `.${q}`, `\\d${q}`);
add('a**', 'a+*', 'a*?', 'a*??', 'a?+', 'a?*', 'a??', 'a+?', 'a{2}?', 'a{2}??', 'a{2}*', 'a{2}+', 'a*{2}', '^*', '$+', '^?', '$?', '^{2}', '${2}', '(?:^)*', '(?:$)*', '(^)*', '(^)+', '(^){2}', '*', '+', '?', '*a', '+a', '?a', '{1}a', '|*', '(*)', '(+a)', '(?:*)', 'a|*', '(|*)', '(a|*b)',
  'a?{2}', 'a{1}{2}', 'a{1}?{2}', 'a*b*c*', 'a+b+c+', 'a?b?c?', 'a{2,3}b{1,2}', '(?:a|b){2,3}', '(a|b)*c', 'x*y', 'x+y', 'xy?', 'a{0}', 'ab{0}c', 'a{0,0}b', '(?:ab){0}', '(?:ab){0,0}c', '(?:){3}', '(){3}', '(?:a*){2}', '(?:a|){2}', '(?:|a){2}', 'a{3}b', 'a{3,}b', 'a{0,3}b', 'a{1,3}b');
// groups, alternation
add('(a)', '(?:a)', '(?a)', '(?', '(?:', '(?=a)', '(?!a)', '(?<n>a)', '(?<=a)', '(?<!a)', '(?i)a', '(?:?)', '(?::a)', '()', '(?:)', '(|a)', '(a|)', '|', '||', 'a|b', 'a||b', '|a', 'a|', 'a|b|c', 'ab|cd', 'a|bc|d', '(a|b)c', '((a))', '(a(b|c)d)*', '(a', 'a)', ')', '(a))', '((a)', '((a)))', '(a|b', 'a|b)', '(?:a|b)+', '(?:a|b)*c', '(?:a|b|c|d)', '(?:ab|a)b', '(a|ab)(c|bcd)(d*)', '(?:(?:a))', '(?:(?:a)|b)', '((((a))))', '(((a)|b)|c)', 'a(b|c)*d', '(?:a?){3}b', '(?:a|b)?c', '(?:a+)?', '(?:a?)+', '(?:a|b)+?c', '(?:a|b)*?c', '(?:a{2}|b{3})c');
// anchors, dot
add('^', '$', '^a$', 'a^b', 'a$b', '^^', '$$', '^$', '$^', '(^a|b$)', 'a|^', '^|a', '(?:^|a)b', '^a|b$', '^a*$', '^(?:a|b)*$', 'a$|b', '(?:a$)b', '(?:^a)b', '^^a', 'a$$', '(?:^)a', 'a(?:$)', '(^|x)a', 'a($|x)', '.', '..', '.*', '.+', 'a.b', '.{2,3}', '^.$', '^.*$', '.|a', '[.]', '\\.', 'a.', '.a');
// shapes with literal classes from the docs
add('/acct/[^/]+/items/\\d+', '(?:GET|POST) /x', 'skyair\\.example/bookings/[0-9]+', '[a-z]+@[a-z]+\\.com', '\\w+', '\\s*', '[^,]*,', '\\d{3}-\\d{4}', '\\d{1,3}(?:\\.\\d{1,3}){3}', '(?:[a-f0-9]{2}:){5}[a-f0-9]{2}', '[A-Z][a-z]{2,}', 'x{0,3}y', '(?:ab|cd){1,2}e?');
// sizes around MAX_NFA_INSTRUCTIONS (4096)
for (const k of [4093, 4094, 4095, 4096, 4097]) add('a'.repeat(k));
add('(?:a{64}){63}', '(?:a{64}){63}a', '(?:a{64}){63}aaa', '(?:a{64}){64}', '(?:a{64}){62}a{62}', 'a{64}'.repeat(63), 'a{64}'.repeat(63) + 'aaaa', 'a{64}'.repeat(64), 'a{64}'.repeat(62) + 'a{63}aa', 'a?'.repeat(2047), 'a?'.repeat(2048), 'a?'.repeat(1365), 'a?'.repeat(1366),
  '(?:a|b)'.repeat(100), '(?:a|b|c)'.repeat(200), 'a|'.repeat(2000) + 'a', 'a|'.repeat(1365) + 'a', 'a|'.repeat(1366) + 'a', 'a'.repeat(2047) + '|' + 'a'.repeat(2047), 'a'.repeat(2048) + '|' + 'a'.repeat(2047), '(?:' + 'a'.repeat(2000) + ')' + '{2}', '(?:' + 'a'.repeat(2040) + '){2}', '(?:' + 'a'.repeat(1365) + '){3}',
  '^' + 'a'.repeat(4094), '^' + 'a'.repeat(4094) + '$', '^' + 'a'.repeat(4093) + '$', 'a'.repeat(4094) + '$', 'a{0,64}'.repeat(60), 'a{0,64}'.repeat(63), 'a{0,64}'.repeat(64), '(?:a{0,64}){64}', '(?:a{0,64}){63}', '(?:a{0,63}){64}', '(?:a{0,63}){65}');
// nesting depth (the stack-overflow refusal itself is engine-specific, so only moderate depths are pinned)
add('('.repeat(300) + 'a' + ')'.repeat(300), '['.repeat(10), '(?:a|'.repeat(300) + 'b' + ')'.repeat(300));

const PROBE = ['', ' ', '\n', '\r', ' ', ' ', ' ', ' ', ' ', ' ', '​', '‧', '‪', ' ', ' ', '　', '﻿', '﻾', '᠎', '\u000b', '\u000c', '\u0008', '\u0009', '\u000d', '\u000e', '\u001f',
  '0', '9', '/', ':', 'A', 'Z', '@', '[', '_', '`', 'a', 'z', '{', '\u0000', '\u0001', '\u007f', '\u0080', 'ÿ', 'Ā', '￿', '￾', 'é', '😀', '-', '.', '\\', ']', '^', '$', '(', ')', '*', '+', '?', '|', ',', 'b', 'c'];
const litChars = (p) => { const s = new Set(); for (const ch of p.replace(/\\[a-zA-Z0-9]/g, '')) if (!'[]()*+?{}|^$.\\-,'.includes(ch)) s.add(ch); return [...s]; };
const nb = (c) => { const k = c.codePointAt(0); return k > 0xffff ? [] : [String.fromCharCode(Math.max(0, k - 1)), String.fromCharCode(Math.min(0xffff, k + 1))]; };
const hexLits = (p) => { const r = []; for (const m of p.matchAll(/\\x([0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})/g)) { const k = parseInt(m[1] ?? m[2], 16); r.push(String.fromCharCode(k)); r.push(...nb(String.fromCharCode(k))); } return r; };
const rangeEnds = (p) => { const r = []; for (const m of p.matchAll(/(.)-(.)/g)) for (const c of [m[1], m[2]]) if (c.length === 1) { r.push(c, ...nb(c)); } return r; };

const fm = [];
const seen = new Set();
const pushFm = (p, s) => { const key = p + '\u0001' + s; if (seen.has(key)) return; seen.add(key); const r = sr.safeRegexFullMatch(p, s); fm.push([p, s, r === null ? -1 : r ? 1 : 0]); };
const subjectsFor = (p) => {
  const alpha = [...new Set([...litChars(p), ...hexLits(p), ...rangeEnds(p), 'a', 'b'])].filter((c) => c.length <= 2);
  const base = [...new Set([...litChars(p).flatMap((c) => [c, ...nb(c)]), ...hexLits(p), ...rangeEnds(p), 'a', 'b', 'c', '0', ' '])].slice(0, 7);
  const ss = new Set(PROBE);
  for (const x of base) { ss.add(x); for (const y of base) { ss.add(x + y); } }
  const c0 = base[0] ?? 'a';
  for (const n of [2, 3, 4, 5, 6, 62, 63, 64, 65, 66, 67, 128]) ss.add(c0.repeat(n));
  for (const x of base.slice(0, 3)) for (const y of base.slice(0, 3)) { ss.add(x + y + x); ss.add(x.repeat(2) + y); ss.add(x + y.repeat(2)); ss.add(x.repeat(3) + y.repeat(3)); }
  void alpha;
  return [...ss];
};
for (const p of P) for (const s of subjectsFor(p)) pushFm(p, s);
// exact subjects for sized patterns
for (const [p, s] of [['a'.repeat(4094), 'a'.repeat(4094)], ['a'.repeat(4094), 'a'.repeat(4093)], ['a'.repeat(4095), 'a'.repeat(4095)], ['a'.repeat(4094), 'a'.repeat(4095)]]) pushFm(p, s);

// compiled sizes
const size = [];
const sizeSrc = new Set(P);
for (const p of sizeSrc) { const c = sr.compileSafeRegex(p); size.push([p, c === null ? -1 : c.program.length]); }

// step boundary: |prog| * (n + 1) vs MAX_MATCH_STEPS = 2_000_000
const steps = [];
for (const p of ['a*', 'a', 'a'.repeat(100), 'a'.repeat(1000), '(?:a|b)*c', 'a'.repeat(4000), '[ab]{0,64}', 'a{64}']) {
  const len = sr.compileSafeRegex(p).program.length;
  const nmax = Math.floor(2_000_000 / len) - 1;
  for (const n of [nmax - 1, nmax, nmax + 1, nmax + 2]) { if (n < 0) continue; const s = 'a'.repeat(n); const r = sr.safeRegexFullMatch(p, s); steps.push([p, n, r === null ? -1 : r ? 1 : 0]); }
}

// random fullMatch fuzz
const ATOMS = ['a', 'b', 'c', '.', '[ab]', '[^a]', '\\d', '\\w', '\\s', '\\S', '[a-c]', '[^b-c]', '(?:a|b)', '(a|bc)', '(?:ab)', '(?:a*)', '(?:)', '[\\d\\s]', '[\\W]', '\\x61', '\\u0062'];
const QS = ['', '', '', '*', '+', '?', '{2}', '{1,2}', '{2,}', '{0,1}', '*?', '+?', '??', '{1,2}?'];
const rndPattern = () => {
  const n = 1 + Math.floor(rnd() * 5); let p = '';
  if (rnd() < 0.2) p += '^';
  for (let i = 0; i < n; i++) { p += pick(ATOMS) + pick(QS); if (rnd() < 0.15) p += '|'; }
  if (rnd() < 0.2) p += '$';
  return p;
};
const rndSubject = () => { const n = Math.floor(rnd() * 7); let s = ''; for (let i = 0; i < n; i++) s += pick(['a', 'b', 'c', '1', ' ', '\n', 'ab', 'é']); return s; };
for (let i = 0; i < 2500; i++) { const p = rndPattern(); for (let j = 0; j < 8; j++) pushFm(p, rndSubject()); const c = sr.compileSafeRegex(p); size.push([p, c === null ? -1 : c.program.length]); }

// isSafeRegexSource
const safe = [];
const safeSeen = new Set();
const pushSafe = (p) => { if (safeSeen.has(p)) return; safeSeen.add(p); safe.push([p, pr.isSafeRegexSource(p)]); };
for (const p of P) pushSafe(p);
for (const p of ['\\1', '(a)\\1', '\\9', '\\k<n>', '(?<n>a)\\k<n>', '\\k', 'a\\', '[a', '[a\\]', '[a\\]]', '[^]', '[]', '[^', '[\\', '[a]]', '(a', 'a)', '(?', '(?:', '(?=a)', '(?:a', '(?:a)', '(?:a)+', '(?:a+)', '(?:a+)+', '(?:a|b)+', '(?:a|b)', '(?:a?)?', '(?:a?)*', '(?:a*)?', '(?:a{2})+', '(?:a{2})?', '(?:(?:a)+)', '(?:(?:a)|b)+', '(?:(?:a|b))+', '(?:(?:a+))', '((a))+', '((a+))', '((a|b))', '(a|b)', '(a)+', '(a)*', '(a)?', '(a){2}', '(a{2})', '(a){2,}', 'a|b|c', '|', '||', '|||', '*', '+', '?', '{2}', '^*', '$*', '(|)*', '()*', '()+', '(?:)+', '(?:)*', '(?:^)*', 'a{2}{3}', 'a**', 'a*?', 'a*?*', 'a{', 'a{1', 'a{1,', 'a{,1}', 'a{1,2}', 'a{2,1}', 'a{64}', 'a{65}', 'a{0,64}', 'a{0,65}', 'a{64,}', 'a{65,}', 'a{1,64}', 'a{1,65}', 'a{64,65}', 'a{65,64}', 'a{ 1}', 'a{1 }', 'a{00064}', 'a{000065}', 'a{99999999999}', 'a{99999999999,}', 'a{1,99999999999}', 'a{0,99999999999999999999}', 'a{12345}', 'a{1}{2}', 'a{1}?', 'a{1}??', 'a{1,}?', 'a{1,}??', '\\d{65}', '[a]{65}', '.{65}', '(?:a){65}', '(?:a){64}', '(?:a){0,64}', '(?:a){0,65}', '(?:a|b){0,64}', '(?:a|b){2}'])
  pushSafe(p);
const TOK = [['*', 8], ['+', 8], ['?', 1], ['{2}', 0], ['{1,2}', 1], ['{1,3}', 2], ['{1,4}', 2], ['{1,5}', 3], ['{0,64}', 7], ['{0,63}', 6], ['{3,9}', 3], ['{1,}', 8], ['{0,1}', 1], ['{5,70}', 99], ['{0,0}', 0], ['{1,1}', 0], ['{2,3}', 1], ['{1,17}', 5], ['{1,16}', 4], ['{1,33}', 6], ['{1,32}', 5], ['{1,9}', 4], ['{1,8}', 3], ['{1,64}', 6], ['{0,2}', 2], ['{0,3}', 2], ['{0,4}', 3], ['{4,4}', 0]];
const lazy = ['', '', '?'];
for (let i = 0; i < 3000; i++) {
  const n = 1 + Math.floor(rnd() * 5); let p = '';
  for (let k = 0; k < n; k++) {
    const kind = rnd();
    const atom = kind < 0.6 ? 'a' : kind < 0.75 ? '[ab]' : kind < 0.85 ? '\\d' : kind < 0.93 ? '(?:ab)' : '(a|b)';
    p += atom + (rnd() < 0.8 ? pick(TOK)[0] + pick(lazy) : '');
    if (rnd() < 0.25) p += '|';
  }
  pushSafe(p);
}
// bit-budget boundaries: exactly 21 / 22 / 23 bits from stars, '|' and bounded repeats
for (const stars of [0, 1, 2, 3]) for (const bars of [0, 1, 5, 6, 7, 8, 13, 14, 15, 21, 22, 23]) for (const bq of ['', '{1,2}', '{1,3}', '{0,64}', '?']) {
  pushSafe('a*'.repeat(stars) + 'b|'.repeat(bars) + 'c' + bq);
  pushSafe('a+'.repeat(stars) + 'b'.repeat(2) + bq + '|'.repeat(bars));
}
for (const k of [21, 22, 23, 24]) { pushSafe('a?'.repeat(k)); pushSafe('a?'.repeat(k - 8) + 'b*'); pushSafe('a'.repeat(3) + '|a'.repeat(k)); pushSafe('a{1,2}'.repeat(k)); pushSafe('a{1,3}'.repeat(Math.ceil(k / 2))); pushSafe('a{1,5}'.repeat(Math.ceil(k / 3))); pushSafe('a{0,64}'.repeat(Math.ceil(k / 7))); }

// budgets
const budgets = [];
const runBudget = (ops, scale = 1) => {
  const b = new rb.RegexBudget(scale);
  const res = ops.map(([s, n]) => b.charge(s, n));
  budgets.push({ ops, res, fin: [b.evaluations, b.chars, b.steps, b.refusals] });
};
runBudget([['a', 1], ['b+', 5], ['(?:a|b)*c', 10]]);
runBudget([['a(', 3], ['a', 1], ['(?=a)', 1], ['b', 2]]);
runBudget(Array.from({ length: 70 }, (_, i) => ['a', i]));
runBudget(Array.from({ length: 64 }, () => ['a', 0]));
runBudget([...Array.from({ length: 64 }, () => ['a', 0]), ['a', 0], ['a', 0]]);
runBudget([...Array.from({ length: 65 }, () => ['a', 0]), ['(', 0], ['b', 0]]);
runBudget([['a'.repeat(4000), 0], ['a'.repeat(4000), 0], ['a'.repeat(192), 0], ['a', 0]]);
runBudget([['a'.repeat(4000), 0], ['a'.repeat(4000), 0], ['a'.repeat(193), 0], ['a', 0]]);
runBudget([['a'.repeat(4000), 0], ['a'.repeat(4000), 0], ['a'.repeat(192), 0], ['b', 0], ['a', 0]]);
// 5_000_000 steps: |prog| * (n + 1)
runBudget([['a', 1_249_999], ['a', 1_249_999]]);
runBudget([['a', 1_249_999], ['a', 1_249_999], ['a', 0]]);
runBudget([['a', 1_249_999], ['a', 1_250_000]]);
runBudget([['a', 1_249_999], ['a', 1_249_998], ['a', 0]]);
runBudget([['a', 2_499_999], ['', 0]]);
runBudget([['a', 2_499_999], ['', 1]]);
runBudget([['a', 4_999_999]]);
runBudget([['', 4_999_999], ['', 1]]);
runBudget([['', 4_999_999], ['', 0]]);
runBudget([['', 5_000_000]]);
runBudget([['', 4_999_999]]);
runBudget([['a*', 1_249_999]]);
runBudget([['a*', 1_250_000]]);
runBudget([['a*', 1_249_999], ['', 0], ['', 0]]);
runBudget([['a', 100], ['a(', 100], ['a', 100], ['(?:', 5]]);
runBudget([['a', 1], ['a'.repeat(5000), 1], ['b', 1]]);

const by = new Map();
for (const [p, sub, r] of fm) { if (!by.has(p)) by.set(p, [[], '']); const e = by.get(p); e[0].push(sub); e[1] += r < 0 ? 'n' : String(r); }
const fmc = [...by].map(([p, [ss, rs]]) => [p, ss, rs]);
const data = { fm: fmc, size, steps, safe, budgets };
const json = JSON.stringify(data);
fs.writeFileSync(out, zlib.gzipSync(Buffer.from(json), { level: 9 }));
console.log(JSON.stringify({ fm: fm.length, pats: fmc.length, size: size.length, steps: steps.length, safe: safe.length, budgets: budgets.length, bytes: json.length }));
