import { describe, expect, it } from 'vitest';
import { compileSafeRegex, safeRegexFullMatch, MAX_NFA_INSTRUCTIONS } from './safe-regex';
import { isSafeRegexSource, predicateMatches } from './predicates';

/**
 * R3-02 regression. The guard read `]` right after `[` / `[^` as a POSIX literal, but JavaScript treats `[]` as the empty
 * class and `[^]` as any character, so `[^](a+)+]` was "safe" to the guard and exponential in V8. The fix removes the
 * differential at the root: untrusted patterns are parsed once, by safe-regex.ts, and run on a linear-time NFA engine.
 */
const ref = (p: string, s: string): boolean => new RegExp('^(?:' + p + ')$').test(s);

describe('R3-02: the round-3 PoC', () => {
  it('the guard rejects /[^](a+)+]/ (and the [] variant) instantly', () => {
    const t = Date.now();
    expect(isSafeRegexSource('[^](a+)+]')).toBe(false);
    expect(isSafeRegexSource('[](a+)+]')).toBe(false);
    expect(isSafeRegexSource('[^](a*)*]')).toBe(false);
    expect(Date.now() - t).toBeLessThan(50);
  });

  it('predicateMatches on the PoC subject returns false in milliseconds (was 9.5 s at n=32, doubling per char)', () => {
    for (const n of [32, 60, 400]) {
      const t = Date.now();
      const r = predicateMatches({ verb: 'read', resource: 're:/[^](a+)+]' } as never, { action: { verb: 'read', resource: '/' + 'a'.repeat(n) + ']x' } } as never);
      expect(r).toBe(false);
      expect(Date.now() - t).toBeLessThan(100);
    }
  });

  it('even a pattern the legacy heuristic would never accept runs in linear time on the engine (no backtracking exists)', () => {
    for (const p of ['(a+)+$', '(a|aa)+$', '(.*a){10}', '([^]a?)+b', '[^](a+)+]', '(?:[^]|a)+]']) {
      const t = Date.now();
      expect(safeRegexFullMatch(p, 'a'.repeat(500) + 'x')).toBe(false);
      expect(Date.now() - t, p).toBeLessThan(200);
    }
    expect(safeRegexFullMatch('(a+)+b', 'a'.repeat(100) + 'b')).toBe(true);
  });
});

describe('R3-02: class semantics are JavaScript, not POSIX', () => {
  const cases: Array<[string, string[]]> = [
    ['[]', ['', 'a', ']']],
    ['[^]', ['', 'a', ']', '\n', 'ab']],
    ['[^]]', ['a]', ']]', 'a', '']],
    ['[]a]', ['a', ']', '', 'a]']],
    ['[^]a]', ['x', 'a', ']', 'x]', '']],
    ['[]]', [']', '', 'a']],
    ['a[]b', ['ab', 'a', '']],
    ['x[^]*y', ['xy', 'xaay', 'xy ', 'x']],
    ['[a-c]+', ['abc', 'abd', 'cab']],
    ['[^a-c]+', ['xyz', 'abc', 'xay']],
    ['[\\d-x]+', ['1-x', '1x', '-', 'a']],
    ['[\\]]+', [']]', 'a']],
    ['[\\b]', ['\b', 'b']],
    ['[a\\-z]+', ['a-z', 'b']],
    ['[-a]+', ['-a-', 'b']],
    ['[a-]+', ['a-', 'b']],
    ['\\d+\\.\\d{2}', ['1.00', '12.5', '123.45']],
    ['.+', ['a', '', 'a\nb', 'a b']],
    ['^a$', ['a', 'aa']],
    ['a|', ['a', '', 'b']],
    ['(|a)b', ['b', 'ab', 'a']],
    ['(?:ab)?c', ['c', 'abc', 'ab']],
    ['a{2,3}', ['a', 'aa', 'aaa', 'aaaa']],
    ['a{0}b', ['b', 'ab']],
    ['a{2,}?b', ['aab', 'ab', 'aaaab']],
    ['\\s\\S\\w\\W', [' aa ', ' a1!', 'a a ']],
    ['\\x41\\u0042\\cJ', ['AB\n']],
    ['/acct/[^/]+/items/\\d+', ['/acct/x/items/1', '/acct//items/1', '/acct/a/b/items/1']],
    ['(?:GET|POST) /x', ['GET /x', 'POST /x', 'PUT /x']],
  ];
  for (const [p, subs] of cases) {
    it(`/${p}/ agrees with V8`, () => {
      for (const s of subs) expect(safeRegexFullMatch(p, s), JSON.stringify(s)).toBe(ref(p, s));
    });
  }
});

describe('R3-02: unsupported constructs are refused (fail closed), never mis-parsed', () => {
  for (const p of ['(?=a)a', '(?!a)b', '(?<=a)b', '(?<n>a)\\k<n>', '(a)\\1', '\\b', '\\B', '\\p{L}', 'a{', 'a{x}', 'a{3,2}', '{2}', '*a', 'a**', '^*', '(', ')', '[a', '[z-a]', '\\', '\\q', 'a{999}', '(?i)a', '[\\p]', '\\c1']) {
    it(`refuses ${JSON.stringify(p)}`, () => {
      expect(compileSafeRegex(p)).toBeNull();
      expect(safeRegexFullMatch(p, 'a')).toBeNull();
      expect(isSafeRegexSource(p)).toBe(false);
    });
  }
  it('refuses a pattern that would compile to more than the instruction budget', () => {
    expect(compileSafeRegex('(?:(?:a{64}){64}){64}')).toBeNull();
    expect(MAX_NFA_INSTRUCTIONS).toBeGreaterThan(64);
  });
});

describe('R3-02: guard + engine agree with V8 on random patterns (small differential fuzz; the 100k+ run is tools/pca-audit/fuzz/safe-regex-fuzz.ts)', () => {
  it('every accepted pattern matches V8 on short subjects', () => {
    let seed = 12345;
    const rnd = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
    const pick = <T>(a: T[]) => a[Math.floor(rnd() * a.length)]!;
    const atoms = ['a', 'b', ']', '.', '\\d', '\\w', '[ab]', '[^a]', '[]', '[^]', '[^]b]', '(?:ab)', '(a|b)', '^', '$', 'x'];
    const quants = ['', '', '', '*', '+', '?', '{2}', '{1,2}', '{0,}'];
    let checked = 0;
    for (let i = 0; i < 1500; i++) {
      let p = '';
      for (let k = 1 + Math.floor(rnd() * 4); k > 0; k--) p += pick(atoms) + pick(quants);
      if (rnd() < 0.2) p += '|' + pick(atoms);
      if (compileSafeRegex(p) === null) continue;
      let r: RegExp;
      try {
        r = new RegExp('^(?:' + p + ')$');
      } catch {
        throw new Error(`engine accepted a pattern V8 rejects: ${p}`);
      }
      for (const s of ['', 'a', 'b', 'ab', 'aab', ']', 'a]', 'ab]b', '1', 'x', 'bb', 'aaa']) {
        checked++;
        expect(safeRegexFullMatch(p, s), `${p} on ${JSON.stringify(s)}`).toBe(r.test(s));
      }
    }
    expect(checked).toBeGreaterThan(5000);
  });
});
