/* eslint-disable @typescript-eslint/no-explicit-any */
// Differential test: PROVED regex engine + `re:` guard (formal/dafny/Regex.dfy via src/ext-regex.ts) vs production
// packages/pca/src/safe-regex.ts + isSafeRegexSource (predicates.ts), and (for every pattern the engine accepts) vs V8
// `new RegExp('^(?:' + src + ')$').test(subject)`. FUZZ_N scales the random sections (default 3000 on the Mac; millions on a cloud box).
import { writeFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { compileSafeRegex, safeRegexFullMatch } from '../../pca/src/safe-regex';
import { isSafeRegexSource } from '../../pca/src/predicates';
import { RegexBudget } from '../../pca/src/regex-budget';
import { compilesVerified, isSafeRegexSourceVerified, reMatchesVerified, safeRegexFullMatchVerified } from '../src/ext-regex';

const FUZZ_N = Number(process.env.FUZZ_N ?? 3000);
const SEED = Number(process.env.FUZZ_SEED ?? 4242);

function rng(seed: number) {
  let a = seed >>> 0;
  const f = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  return { f, int: (n: number) => Math.floor(f() * n), pick: <T,>(a: readonly T[]): T => a[Math.floor(f() * a.length)]! };
}

const CORPUS = [
  '', 'a', 'abc', 'a|b', '(?:a|b)c', '/acct/[^/]+/items/\\d+', '(?:GET|POST) /x', '^abc$', '^$', 'a*', 'a+b?', 'a{2,5}', 'a{3}', 'a{2,}',
  '.', '.*', '[a-z]+', '[^a-z]', '[]', '[^]', '\\d{1,3}', '\\w+@\\w+', '\\s*', '[\\d-x]', '[\\w-]', '\\x41', '\\u0041', '\\cJ', '[\\b]', '\\0',
  '(a+)+', '(a|aa)+', '(.*a){10}', '(?=a)', '(?!a)', '(?<n>a)', '\\1', '\\k<n>', '\\b', '\\B', '\\p{L}', 'a**', 'a{', 'a{,3}', 'a{3,2}', 'a{65}',
  '^*', '$+', '(', ')', 'a)', '(a', '[a', 'a\\', '[z-a]', 'a??', 'a+?', 'a{2}?', 'a{2}{3}', '\\_', '\\q', '(?:)', '()', '(|a)', 'a||b', '|',
  '(?:a?){8}', 'a?{12}a{12}b', '(?:a|b|c|d){5}', '[\\u0100-\\uffff]', '[\\ud800-\\udfff]', 'é', '\\.', '\\/', '\\-', '[.]', '\\$', '\\^',
];
const ALPHA = ['a', 'b', 'c', 'A', '0', '9', '_', '-', ' ', '\n', '\r', ' ', 'é', 'Ā', '\ud800', '\udc00', '\ud83d', '\ude00', '/', '.', '@', '\t', '﻿', ' '];
const PAT_ATOMS = ['a', 'b', 'c', '.', '\\d', '\\D', '\\w', '\\W', '\\s', '\\S', '[a-c]', '[^a]', '[]', '[^]', '[\\d_]', '[\\w-]', '[a\\-c]', '\\n', '\\x41', '\\u00e9', '\\.', '^', '$', '[\\s\\S]', '[^\\d]'];
const QUANTS = ['', '', '', '*', '+', '?', '{2}', '{0,3}', '{1,}', '{2,4}', '*?', '+?', '??', '{3}?'];

function genAst(r: ReturnType<typeof rng>, d: number): string {
  const k = r.int(d <= 0 ? 1 : 6);
  if (k <= 1) {
    const at = r.pick(PAT_ATOMS);
    const q = at === '^' || at === '$' ? '' : r.pick(QUANTS);
    return at + q;
  }
  if (k === 2) return Array.from({ length: 1 + r.int(3) }, () => genAst(r, d - 1)).join('');
  if (k === 3) return '(?:' + Array.from({ length: 1 + r.int(3) }, () => genAst(r, d - 1)).join('|') + ')' + r.pick(QUANTS);
  if (k === 4) return '(' + genAst(r, d - 1) + ')' + r.pick(QUANTS);
  return genAst(r, d - 1) + '|' + genAst(r, d - 1);
}
function genGarbage(r: ReturnType<typeof rng>): string {
  const chars = '()[]{}|*+?\\^$.-:,0123456789abcdxuwsdbBkpP\n';
  return Array.from({ length: r.int(14) }, () => chars[r.int(chars.length)]!).join('');
}
function genSubject(r: ReturnType<typeof rng>): string {
  return Array.from({ length: r.int(12) }, () => r.pick(ALPHA)).join('');
}
function v8(src: string, subj: string): boolean | undefined {
  try {
    return new RegExp('^(?:' + src + ')$').test(subj);
  } catch {
    return undefined;
  }
}

/** One pattern against several subjects: all three oracles must agree where defined. */
const TRACE = process.env.RX_TRACE; // file: the case being evaluated is written before each oracle call (locates a stall)
function checkPattern(src: string, subjects: string[], strictV8 = true): void {
  if (TRACE) writeFileSync(TRACE, JSON.stringify({ src, subjects, phase: 'compile' }));
  const pc = compileSafeRegex(src) !== null;
  expect(compilesVerified(src), `compiles ${JSON.stringify(src)}`).toBe(pc);
  expect(isSafeRegexSourceVerified(src), `guard ${JSON.stringify(src)}`).toBe(isSafeRegexSource(src));
  for (const s of subjects) {
    const prod = safeRegexFullMatch(src, s);
    if (TRACE) writeFileSync(TRACE, JSON.stringify({ src, s, phase: 'verified' }));
    const ver = safeRegexFullMatchVerified(src, s);
    expect(ver, `match ${JSON.stringify(src)} ~ ${JSON.stringify(s)}`).toBe(prod);
    // V8 is consulted only for guard-admitted patterns: V8 backtracks, and a nested-quantifier pattern the guard rejects (but the
    // linear engine accepts) can take minutes on a 12-char subject (seeds 202/303 stalled there). tools/pca-regex-diff covers
    // every engine-accepted pattern against V8 with a per-case timeout.
    if (strictV8 && ver !== null && isSafeRegexSource(src)) {
      if (TRACE) writeFileSync(TRACE, JSON.stringify({ src, s, phase: 'v8' }));
      const ref = v8(src, s);
      if (ref !== undefined) expect(ver, `V8 ${JSON.stringify(src)} ~ ${JSON.stringify(s)}`).toBe(ref);
    }
  }
}

describe('Regex.dfy engine vs production safe-regex.ts (and V8)', () => {
  it('corpus x alphabet subjects', () => {
    const r = rng(SEED);
    for (const src of CORPUS) {
      const subs = ['', 'a', 'abc', 'ab', 'aaaa', '/acct/x/items/42', 'GET /x', 'POST /x', 'x@y', ' \t', '1', '-', ...Array.from({ length: 40 }, () => genSubject(r))];
      checkPattern(src, subs);
    }
  });
  it('random ASTs', () => {
    const r = rng(SEED + 1);
    for (let i = 0; i < FUZZ_N; i++) {
      const src = genAst(r, 3);
      checkPattern(src, Array.from({ length: 6 }, () => genSubject(r)));
    }
  });
  it('random garbage patterns (parser/refusal agreement)', () => {
    const r = rng(SEED + 2);
    for (let i = 0; i < FUZZ_N; i++) {
      const src = genGarbage(r);
      checkPattern(src, [genSubject(r), 'a', '', '(a)', '{}'], false);
    }
  });
  it('nested-quantifier / ReDoS shapes and budget boundary', () => {
    const shapes = ['(a+)+b', '(a*)*b', '(a|aa)+b', '(.*a){12}', '(?:a?){40}a{40}', 'a?{30}a{30}', '(a|a)*b', '(?:[a-z]+)*x', 'a{64}{64}', '(?:a{64}){64}', '((((a))))*'];
    const subs = ['a'.repeat(64), 'a'.repeat(200) + 'c', 'b', '', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!'];
    for (const src of shapes) checkPattern(src, subs, false);
    // budget refusal: |program| x (|subject|+1) > 2e6 -> null in both
    const big = '(?:a{64}b?){30}';
    for (const n of [0, 100, 500, 1000, 1500]) checkPattern(big, ['a'.repeat(n)], false);
  });
  it('re: entry point agrees with predicates.ts semantics', () => {
    const r = rng(SEED + 3);
    for (let i = 0; i < Math.max(200, FUZZ_N / 5); i++) {
      const src = i % 3 === 0 ? genGarbage(r) : genAst(r, 2);
      const subj = genSubject(r);
      const prod = src.length <= 200 && subj.length <= 512 && isSafeRegexSource(src) && safeRegexFullMatch(src, subj) === true;
      expect(reMatchesVerified(src, subj, new RegexBudget()), `re: ${JSON.stringify(src)} ~ ${JSON.stringify(subj)}`).toBe(prod);
    }
    expect(reMatchesVerified('a', 'a'.repeat(513), new RegexBudget())).toBe(false);
    expect(reMatchesVerified('a'.repeat(201), 'a', new RegexBudget())).toBe(false);
  });
});
