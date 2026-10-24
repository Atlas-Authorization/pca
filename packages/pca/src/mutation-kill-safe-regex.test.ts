/**
 * Mutation-kill tests for safe-regex.ts: differential against V8 for every accepted construct (class escapes, complement
 * boundaries, range merging, escapes), the exact accept/refuse boundary of every numeric limit, and the work-budget edge.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { compileSafeRegex, MAX_MATCH_STEPS, MAX_NFA_INSTRUCTIONS, runSafeRegex, safeRegexFullMatch } from './safe-regex';
import { RegexBudget } from './regex-budget';
import { REGEX_CACHE_MAX_PER_SOURCE, regexCacheHas } from './regex-cache';
import { __setVerifiedCoreModeForTests, VERIFIED_CORE_OPT_IN_MODULES, verifiedCoreOptIn } from './verified-core-mode';

const ref = (src: string, s: string): boolean => new RegExp('^(?:' + src + ')$').test(s);

/** Code units chosen at every boundary of the digit / word / space / line-terminator tables. */
const CH = [
  '\0', '\b', '\t', '\n', '\x0b', '\x0c', '\r', '\x0e', '\x1f', ' ', '!', '-', '.', '/', '0', '1', '5', '9', ':', '@', 'A', 'M', 'Z', '[', '^', '_',
  '`', 'a', 'b', 'c', 'd', 'e', 'f', 'm', 'x', 'y', 'z', '{', '|', '~', '\x7f', '\x9f', '\xa0', '\xa1', '\u167f', '\u1680', '\u1681', '\u1fff',
  '\u2000', '\u2005', '\u200a', '\u200b', '\u2027', '\u2028', '\u2029', '\u202a', '\u202e', '\u202f', '\u2030', '\u205e', '\u205f', '\u2060',
  '\u2fff', '\u3000', '\u3001', '\ufefe', '\ufeff', '\uff00', '\uff80', '\ufffe', '\uffff', 'é',
];

function agree(src: string, subjects: string[] = CH): void {
  for (const s of subjects) {
    expect(safeRegexFullMatch(src, s), `${src} vs ${JSON.stringify(s)}`).toBe(ref(src, s));
  }
}

describe('class escapes outside and inside classes (differential vs V8)', () => {
  it.each(['\\d', '\\D', '\\w', '\\W', '\\s', '\\S', '.'])('%s', (src) => agree(src));
  it.each(['\\d', '\\D', '\\w', '\\W', '\\s', '\\S'])('[%s] and [^%s]', (e) => {
    agree(`[${e}]`);
    agree(`[^${e}]`);
  });
  it('complement tables hit both ends (0x0000 and 0xFFFF) and every internal boundary', () => {
    agree('[\\D]', ['\0', '/', '0', '5', '9', ':', '\uffff', '\u0100']);
    agree('[\\W]', ['\0', '/', '0', '9', ':', '@', 'A', 'Z', '[', '^', '_', '`', 'a', 'z', '{', '\uffff']);
    agree('[\\S]', ['\0', '\b', '\t', '\r', '\x0e', ' ', '!', '\x9f', '\xa0', '\xa1', '\u1680', '\u1681', '\u2000', '\u200a', '\u200b', '\u2028', '\u2029', '\u202a', '\u202f', '\u2030', '\u205f', '\u2060', '\u3000', '\u3001', '\ufeff', '\uff00', '\uffff']);
    // digits are NOT in [\D]; letters are
    expect(safeRegexFullMatch('[\\D]', '5')).toBe(false);
    expect(safeRegexFullMatch('[\\D]', 'x')).toBe(true);
    expect(safeRegexFullMatch('[\\D]', '\0')).toBe(true);
    expect(safeRegexFullMatch('[\\D]', '\uffff')).toBe(true);
    expect(safeRegexFullMatch('[\\D]', '/')).toBe(true);
    expect(safeRegexFullMatch('[\\D]', ':')).toBe(true);
    expect(safeRegexFullMatch('[\\D]', '0')).toBe(false);
    expect(safeRegexFullMatch('[\\D]', '9')).toBe(false);
    expect(safeRegexFullMatch('[\\S]', '\u3000')).toBe(false);
    expect(safeRegexFullMatch('[\\S]', '\u3001')).toBe(true);
    expect(safeRegexFullMatch('[\\S]', '\uff00')).toBe(true);
    expect(safeRegexFullMatch('[\\S]', '\ufeff')).toBe(false);
  });
  it('multi-escape classes', () => {
    agree('[\\D\\d]');
    agree('[\\W\\w]');
    agree('[\\S\\s]');
    agree('[\\D\\W]');
    agree('[\\d\\s]+', ['', '1', ' ', '1 2', 'a', '1a']);
  });
  it('a class escape as a range endpoint makes the "-" a literal (Annex B)', () => {
    for (const e of ['\\d', '\\D', '\\w', '\\W', '\\s', '\\S']) {
      agree(`[${e}-z]`);
      agree(`[a-${e}]`);
      agree(`[${e}-${e}]`);
    }
    expect(safeRegexFullMatch('[\\d-z]', '-')).toBe(true);
    expect(safeRegexFullMatch('[\\d-z]', 'z')).toBe(true);
    expect(safeRegexFullMatch('[\\d-z]', 'y')).toBe(false);
  });
});

describe('single-char escapes', () => {
  it.each([
    ['\\t', '\t'],
    ['\\n', '\n'],
    ['\\v', '\x0b'],
    ['\\f', '\x0c'],
    ['\\r', '\r'],
    ['\\0', '\0'],
    ['\\x41', 'A'],
    ['\\x4a', 'J'],
    ['\\x4A', 'J'],
    ['\\u0041', 'A'],
    ['\\u00e9', 'é'],
    ['\\u00E9', 'é'],
    ['\\cJ', '\n'],
    ['\\ca', '\x01'],
    ['\\cZ', '\x1a'],
    ['\\.', '.'],
    ['\\-', '-'],
    ['\\/', '/'],
    ['\\ ', ' '],
    ['\\$', '$'],
  ])('%s matches exactly its char', (src, ch) => {
    expect(safeRegexFullMatch(src, ch)).toBe(true);
    expect(safeRegexFullMatch(src, ch + ch)).toBe(false);
    expect(safeRegexFullMatch(src, '')).toBe(false);
    agree(src);
  });
  it('the same escapes as range endpoints are real ranges (not class escapes)', () => {
    agree('[\\x41-\\x43]');
    expect(safeRegexFullMatch('[\\x41-\\x43]', 'B')).toBe(true);
    expect(safeRegexFullMatch('[\\x41-\\x43]', 'D')).toBe(false);
    expect(safeRegexFullMatch('[\\x41-\\x43]', '-')).toBe(false);
    agree('[\\u0041-\\u0043]');
    agree('[a-\\x63]');
    agree('[\\x61-c]');
    agree('[\\t-\\r]');
    expect(safeRegexFullMatch('[\\t-\\r]', '\x0b')).toBe(true);
    expect(safeRegexFullMatch('[\\t-\\r]', '-')).toBe(false);
    agree('[\\cA-\\cC]');
    agree('[\\0-\\x05]');
    agree('[\\n-\\r]');
    agree('[\\v-\\f]');
  });
  it('\\b is backspace inside a class, refused outside', () => {
    expect(safeRegexFullMatch('[\\b]', '\b')).toBe(true);
    expect(safeRegexFullMatch('[\\b]', 'b')).toBe(false);
    expect(compileSafeRegex('\\b')).toBeNull();
    expect(compileSafeRegex('a\\b')).toBeNull();
  });
  it('\\0 followed by a digit is an octal escape (refused); followed by anything else is NUL + that char', () => {
    expect(compileSafeRegex('\\00')).toBeNull();
    expect(compileSafeRegex('\\01')).toBeNull();
    expect(compileSafeRegex('\\05')).toBeNull();
    expect(compileSafeRegex('\\09')).toBeNull();
    expect(safeRegexFullMatch('\\0a', '\0a')).toBe(true);
    expect(safeRegexFullMatch('\\0/', '\0/')).toBe(true); // '/' is just below '0'
    expect(safeRegexFullMatch('\\0:', '\0:')).toBe(true); // ':' is just above '9'
    expect(safeRegexFullMatch('\\0', '\0')).toBe(true);
    expect(safeRegexFullMatch('\\0\\0', '\0\0')).toBe(true);
    expect(safeRegexFullMatch('[\\0]', '\0')).toBe(true);
    expect(compileSafeRegex('[\\00]')).toBeNull();
  });
});

describe('refusals (compile returns null)', () => {
  it.each([
    'a)',
    ')',
    '(a',
    '((a)',
    '(?=a)',
    '(?!a)',
    '(?<n>a)',
    '(?<=a)',
    '(?a)',
    '(?',
    '+a',
    '?a',
    '*a',
    'a|+',
    'a|*',
    '(+)',
    '{',
    '{a',
    '{1}',
    'a{',
    'a{2',
    'a{x}',
    'a{,2}',
    'a{2,1}',
    'a{.{2}',
    'a{1,2,3}',
    'a{12345}',
    '^*',
    '$+',
    '^{2}',
    '$?',
    '^?',
    '$*',
    'a**',
    'a+*',
    'a*+',
    'a???',
    'a*??',
    'a{2}{3}',
    'a{2}*',
    'a*{2}',
    'a*{x',
    'a+{1,2}',
    '\\',
    'a\\',
    '[\\',
    '\\B',
    '\\1',
    '\\9',
    '\\k',
    '\\p',
    '\\P',
    '\\a',
    '\\e',
    '\\z',
    '\\Z',
    '\\A',
    '\\_',
    '\\x4',
    '\\x',
    '\\xZZ',
    '\\x4G',
    '\\xG4',
    '\\u12',
    '\\u',
    '\\u12G4',
    '\\uGGGG',
    '\\c',
    '\\c1',
    '\\c_',
    '\\c-',
    '\\00',
    '[a',
    '[a-',
    '[',
    '[^',
    '[b-a]',
    '[z-a]',
    '[\\x43-\\x41]',
    'a{65}',
    'a{1,65}',
    'a{65,}',
    'a{65,70}',
    'a{0,65}',
    'a{9999}',
    'a{0,9999}',
  ])('%s', (src) => {
    expect(compileSafeRegex(src)).toBeNull();
    expect(safeRegexFullMatch(src, 'a')).toBeNull();
  });
  it('a non-string source compiles to null (not an empty program)', () => {
    expect(compileSafeRegex(123 as unknown as string)).toBeNull();
    expect(compileSafeRegex(['a'] as unknown as string)).toBeNull();
    expect(compileSafeRegex([] as unknown as string)).toBeNull();
    expect(compileSafeRegex(undefined as unknown as string)).toBeNull();
    expect(compileSafeRegex(null as unknown as string)).toBeNull();
    expect(compileSafeRegex({ length: 0 } as unknown as string)).toBeNull();
  });
});

describe('acceptance and quantifier bounds', () => {
  it.each(['', '()', '(?:)', '(|)', 'a|', '|a', 'a||b', '(?:a)', '(a)', 'a*?b', 'a+?b', 'a??'.slice(0, 2), 'a{2}?', 'a{2,}?', 'a{1,3}?b', '[a-a]', '[]', '[^]', '^', '$', '^a$', '^$', '^^', 'a$b', 'a{0}', 'a{0,0}', 'a{1,1}', 'a{64}', 'a{1,64}', 'a{0,64}', 'a{64,}', 'a{63,64}', 'a{64,64}', 'a{0064}', '\\^', '\\\\', '(?:a|b)+c'])(
    '%s compiles',
    (src) => {
      expect(compileSafeRegex(src), src).not.toBeNull();
    },
  );
  it('the lazy marker is consumed (and has no effect on a full match)', () => {
    expect(safeRegexFullMatch('a*?b', 'aab')).toBe(true);
    expect(safeRegexFullMatch('a*?b', 'b')).toBe(true);
    expect(safeRegexFullMatch('a+?b', 'b')).toBe(false);
    expect(safeRegexFullMatch('a??b', 'ab')).toBe(true);
    expect(safeRegexFullMatch('a{2}?b', 'aab')).toBe(true);
    expect(safeRegexFullMatch('a{1,2}?', 'aa')).toBe(true);
  });
  it('quantifier semantics match V8', () => {
    for (const [src, subs] of [
      ['a{2}', ['', 'a', 'aa', 'aaa']],
      ['a{2,}', ['a', 'aa', 'aaa', 'aaaa']],
      ['a{2,3}', ['a', 'aa', 'aaa', 'aaaa']],
      ['a{0}', ['', 'a']],
      ['a{0,2}', ['', 'a', 'aa', 'aaa']],
      ['(?:ab){2}', ['ab', 'abab', 'ababab']],
      ['a{1,64}', ['', 'a', 'a'.repeat(64), 'a'.repeat(65)]],
      ['a{64}', ['a'.repeat(63), 'a'.repeat(64), 'a'.repeat(65)]],
      ['a{64,}', ['a'.repeat(63), 'a'.repeat(64), 'a'.repeat(200)]],
      ['a{0,64}', ['', 'a'.repeat(64), 'a'.repeat(65)]],
      ['a{63,64}', ['a'.repeat(62), 'a'.repeat(63), 'a'.repeat(64), 'a'.repeat(65)]],
      ['a{0064}', ['a'.repeat(64)]],
    ] as Array<[string, string[]]>) {
      agree(src, subs);
    }
  });
  it('anchors', () => {
    agree('^a', ['a', 'ab', '']);
    agree('a$', ['a', 'ba', '']);
    agree('^$', ['', 'a']);
    agree('a^b', ['ab', 'a^b']);
    agree('a$b', ['ab', 'a$b']);
    agree('(^a|b)c', ['ac', 'bc', 'xc']);
    agree('^', ['', 'a']);
    agree('$', ['', 'a']);
    agree('(?:^)*a', ['a']);
  });
});

describe('class construction', () => {
  it('negation', () => {
    expect(safeRegexFullMatch('[^a]', 'a')).toBe(false);
    expect(safeRegexFullMatch('[^a]', 'b')).toBe(true);
    expect(safeRegexFullMatch('[^ab]', 'c')).toBe(true);
    expect(safeRegexFullMatch('[^ab]', 'b')).toBe(false);
    expect(safeRegexFullMatch('[a^]', '^')).toBe(true);
    expect(safeRegexFullMatch('[^]', 'x')).toBe(true);
    expect(safeRegexFullMatch('[^]', '\n')).toBe(true);
    expect(safeRegexFullMatch('[]', 'x')).toBe(false);
    expect(safeRegexFullMatch('[]', '')).toBe(false);
    agree('[^a-c]');
    agree('[^\\n]');
    agree('[^]]', [']', 'x', '']);
    agree('[]]', [']', 'x', '']);
  });
  it('ranges, trailing/leading dash, equal-endpoint range, overlap merging', () => {
    expect(safeRegexFullMatch('[a-a]', 'a')).toBe(true);
    expect(safeRegexFullMatch('[a-a]', 'b')).toBe(false);
    expect(safeRegexFullMatch('[a-]', '-')).toBe(true);
    expect(safeRegexFullMatch('[a-]', 'a')).toBe(true);
    expect(safeRegexFullMatch('[-a]', '-')).toBe(true);
    expect(safeRegexFullMatch('[a-]', 'b')).toBe(false);
    expect(safeRegexFullMatch('[a-c]', 'b')).toBe(true);
    expect(safeRegexFullMatch('[a-c]', 'd')).toBe(false);
    expect(safeRegexFullMatch('[a-c]', '`')).toBe(false);
    // overlapping ranges must be merged so the binary search is sound
    for (const src of ['[a-zb-cd-e]', '[a-zb-cd-ef-g]', '[0-9a-zb-cd-e]', '[a-mb-cd-ef-gh-i]', '[a-ca-cd-f]', '[d-fa-cb-e]', '[a-eb-fc-g]', '[m-pa-zb-c]']) agree(src, 'abcdefghimnopqxyz09-'.split(''));
    expect(safeRegexFullMatch('[a-zb-cd-e]', 'x')).toBe(true);
    expect(safeRegexFullMatch('[a-zb-cd-e]', 'm')).toBe(true);
    expect(safeRegexFullMatch('[a-zb-cd-e]', 'A')).toBe(false);
    // adjacent ranges
    agree('[a-cd-f]', 'abcdefg`'.split(''));
    agree('[a-cc-f]', 'abcdefg`'.split(''));
    agree('[a-dd-f]', 'abcdefg`'.split(''));
    agree('[a-ce-g]', 'abcdefgh`'.split(''));
    agree('[ace]', 'abcdef'.split(''));
    agree('[eca]', 'abcdef'.split(''));
    agree('[c-ea-b]', 'abcdef'.split(''));
  });
  it('a class with many pieces matches every member and no non-member', () => {
    const members = 'aegikmoqsuwy02468';
    const src = '[' + members + ']';
    for (const ch of 'abcdefghijklmnopqrstuvwxyz0123456789') expect(safeRegexFullMatch(src, ch)).toBe(members.includes(ch));
  });
});

describe('structure: alternation, grouping, repetition (differential vs V8)', () => {
  it('matches V8', () => {
    for (const [src, subs] of [
      ['a|b|c', ['a', 'b', 'c', 'd', '', 'ab']],
      ['(?:a|b)*c', ['c', 'ac', 'abc', 'abab', 'abcc']],
      ['ab|cd|ef', ['ab', 'cd', 'ef', 'ad', 'abcd']],
      ['(a|)b', ['b', 'ab', 'aab']],
      ['(a|b|)c', ['c', 'ac', 'bc', 'abc']],
      ['x(a|b|c|d)y', ['xay', 'xdy', 'xey', 'xy']],
      ['(?:a*)*b', ['b', 'aab', 'aaa']],
      ['(a+)+b', ['aab', 'ab', 'b']],
      ['(a?)?', ['', 'a', 'aa']],
      ['(?:a?){3}', ['', 'a', 'aa', 'aaa', 'aaaa']],
      ['((a|b)(c|d))+', ['ac', 'bd', 'acbd', 'ab']],
      ['a.c', ['abc', 'a\nc', 'a\rc', 'a\u2028c', 'a\u2029c', 'ac', 'a\u0085c']],
      ['.*', ['', 'abc', 'a\nb']],
      ['a.*b', ['ab', 'axxb', 'ax\nb']],
    ] as Array<[string, string[]]>) {
      agree(src, subs);
    }
  });
  it('deep optional nesting exercises the epsilon-closure stack', () => {
    const src = '(?:'.repeat(12) + 'a?' + ')?'.repeat(12);
    agree(src, ['', 'a', 'aa', 'b']);
    const src2 = '(?:'.repeat(30) + 'a?' + ')?'.repeat(30);
    agree(src2, ['', 'a', 'aa']);
    // 16 (not 40): the V8 side of the differential backtracks exponentially on the failing subjects
    const alt = 'a?'.repeat(16) + 'a'.repeat(16);
    agree(alt, ['a'.repeat(16), 'a'.repeat(24), 'a'.repeat(32), 'a'.repeat(15), 'a'.repeat(33)]);
    agree('(?:a|b|c|d|e|f|g|h)*z', ['z', 'abcz', 'abcdefghz', 'abcdefgh', 'y']);
  });
  it('the empty pattern is a one-instruction program that matches only the empty string', () => {
    const re = compileSafeRegex('')!;
    expect(re).not.toBeNull();
    expect(re.program.length).toBe(1);
    expect(runSafeRegex(re, '')).toBe(true);
    expect(runSafeRegex(re, 'a')).toBe(false);
    expect(safeRegexFullMatch('', '')).toBe(true);
    expect(safeRegexFullMatch('', 'a')).toBe(false);
    expect(safeRegexFullMatch('()', '')).toBe(true);
    expect(safeRegexFullMatch('^$', '')).toBe(true);
  });
  it('matches the whole subject only (not a prefix, not a suffix, not a substring)', () => {
    expect(safeRegexFullMatch('abc', 'abc')).toBe(true);
    expect(safeRegexFullMatch('abc', 'abcd')).toBe(false);
    expect(safeRegexFullMatch('abc', 'xabc')).toBe(false);
    expect(safeRegexFullMatch('abc', 'ab')).toBe(false);
    expect(safeRegexFullMatch('a*', 'aab')).toBe(false);
    expect(safeRegexFullMatch('a|ab', 'ab')).toBe(true);
    expect(safeRegexFullMatch('ab|a', 'a')).toBe(true);
    expect(safeRegexFullMatch('a', '')).toBe(false);
    expect(safeRegexFullMatch('b*', 'bbb')).toBe(true);
    expect(safeRegexFullMatch('b*', '')).toBe(true);
    expect(safeRegexFullMatch('b*', 'bba')).toBe(false);
    expect(safeRegexFullMatch('a*b*', 'aabb')).toBe(true);
    expect(safeRegexFullMatch('a*b*', 'abab')).toBe(false);
  });
});

describe('size limit (MAX_NFA_INSTRUCTIONS) boundary', () => {
  it('N literals compile to N+1 instructions: 4095 accepted, 4096 refused', () => {
    expect(MAX_NFA_INSTRUCTIONS).toBe(4096);
    const ok = compileSafeRegex('a'.repeat(MAX_NFA_INSTRUCTIONS - 1));
    expect(ok).not.toBeNull();
    expect(ok!.program.length).toBe(MAX_NFA_INSTRUCTIONS);
    expect(compileSafeRegex('a'.repeat(MAX_NFA_INSTRUCTIONS))).toBeNull();
    expect(compileSafeRegex('a'.repeat(MAX_NFA_INSTRUCTIONS + 1))).toBeNull();
    expect(compileSafeRegex('a'.repeat(MAX_NFA_INSTRUCTIONS + 600))).toBeNull();
  });
  it('a bounded repeat that expands past the limit is refused, one that fits is accepted', () => {
    // (a{64}){63} = 4032 Set + 0 splits + Match = 4033
    expect(compileSafeRegex('(?:a{64}){63}')!.program.length).toBe(64 * 63 + 1);
    expect(compileSafeRegex('(?:a{64}){64}')).toBeNull(); // 4096 + 1
    expect(compileSafeRegex('(?:a{64}){64}b')).toBeNull();
    expect(compileSafeRegex('(?:a{64}){65}')).toBeNull();
    expect(compileSafeRegex('(?:(?:a{64}){64}){64}')).toBeNull();
    expect(compileSafeRegex('(?:(?:(?:a{64}){64}){64}){64}')).toBeNull();
  });
  it('an unbounded/optional repeat that crosses the limit during expansion is refused', () => {
    expect(compileSafeRegex('(?:a?){64}' + 'b'.repeat(4000))).toBeNull();
    expect(compileSafeRegex('(?:a{0,64}){64}')).toBeNull(); // 64*(64*2) = 8192
    expect(compileSafeRegex('(?:a{0,64}){31}')).not.toBeNull(); // 31*128 = 3968
  });
});

describe('matching work budget (MAX_MATCH_STEPS)', () => {
  it('runs when program x (n+1) is exactly the budget, refuses (null) one character beyond', () => {
    const re = compileSafeRegex('a*')!;
    expect(re.program.length).toBe(4);
    const n = MAX_MATCH_STEPS / 4 - 1; // 4 * (n + 1) === MAX_MATCH_STEPS
    expect(re.program.length * (n + 1)).toBe(MAX_MATCH_STEPS);
    expect(runSafeRegex(re, 'a'.repeat(n))).toBe(true);
    expect(runSafeRegex(re, 'a'.repeat(n) + 'b')).toBeNull();
    expect(runSafeRegex(re, 'a'.repeat(n + 1))).toBeNull();
    expect(runSafeRegex(re, 'a'.repeat(n * 2))).toBeNull();
    expect(safeRegexFullMatch('a*', 'a'.repeat(n + 1))).toBeNull();
    expect(safeRegexFullMatch('a*', 'a'.repeat(n))).toBe(true);
    // a mismatch within the budget is false, not null
    expect(runSafeRegex(re, 'a'.repeat(n - 1) + 'b')).toBe(false);
  });
  it('a larger program shrinks the admissible subject proportionally', () => {
    const re = compileSafeRegex('a*b')!; // Split, Set, Jmp, Set, Match = 5
    expect(re.program.length).toBe(5);
    const n = MAX_MATCH_STEPS / 5 - 1;
    expect(runSafeRegex(re, 'a'.repeat(n - 1) + 'b')).toBe(true);
    expect(runSafeRegex(re, 'a'.repeat(n) + 'b')).toBeNull();
  });
});

describe('cache returns consistent results', () => {
  it('the same source gives the same answers repeatedly, including for refused sources', () => {
    for (let i = 0; i < 3; i++) {
      expect(safeRegexFullMatch('x+y', 'xxy')).toBe(true);
      expect(safeRegexFullMatch('x+y', 'y')).toBe(false);
      expect(safeRegexFullMatch('x+(', 'x')).toBeNull();
    }
  });
  it('more distinct sources than the cache holds still all answer correctly', () => {
    for (let i = 0; i < 1300; i++) expect(safeRegexFullMatch(`k${i}`, `k${i}`)).toBe(true);
    for (let i = 0; i < 1300; i += 97) expect(safeRegexFullMatch(`k${i}`, `k${i + 1}`)).toBe(false);
    expect(safeRegexFullMatch('k5', 'k5')).toBe(true);
  });
});

describe('class range normalisation (internal representation)', () => {
  const rangesOf = (src: string) => (compileSafeRegex(src)!.program[0] as unknown as { set: { ranges: Array<[number, number]> } }).set.ranges;
  it('adjacent ranges are merged into one', () => {
    expect(rangesOf('[a-cd-f]')).toEqual([[97, 102]]);
    expect(rangesOf('[d-fa-c]')).toEqual([[97, 102]]);
  });
  it('ranges overlapping by exactly one code unit are merged; a gap of one is not', () => {
    expect(rangesOf('[a-cc-f]')).toEqual([[97, 102]]);
    expect(rangesOf('[a-ce-f]')).toEqual([[97, 99], [101, 102]]);
    expect(rangesOf('[a-fb-c]')).toEqual([[97, 102]]);
  });
});

describe('survivor kills (round 4): early abort and compile cache are observable through allocation counts', () => {
  // These observe the hand-written compiler and its compile cache; under PCA_VERIFIED_CORE=regex safeRegexFullMatch runs the proved
  // engine, which has no cache. Pin the regex opt-in off here (every other opt-in stays as configured).
  beforeAll(() => __setVerifiedCoreModeForTests(VERIFIED_CORE_OPT_IN_MODULES.filter((m) => m !== 'regex' && verifiedCoreOptIn(m)).join(',') || 'none'));
  afterAll(() => __setVerifiedCoreModeForTests(undefined));
  /** Number of Array.prototype.push calls made while fn runs (the compiler builds its AST and program with push; the matcher does not). */
  const pushes = (fn: () => void): number => {
    let n = 0;
    const orig = Array.prototype.push;
    Array.prototype.push = function (this: unknown[], ...a: unknown[]) {
      n++;
      return orig.apply(this, a as never);
    } as typeof Array.prototype.push;
    try {
      fn();
    } finally {
      Array.prototype.push = orig;
    }
    return n;
  };

  it('an over-large expansion is abandoned as soon as the program passes the cap (not built in full, then rejected)', () => {
    // 12800 instructions if built in full; the per-atom check stops it at the cap (the end-of-repeat check alone would only fire after the whole repeat)
    for (const huge of ['(?:' + 'a'.repeat(200) + '){64}', '(?:(?:(?:a{64}){64}){64}){64}']) {
      let result: unknown = 'unset';
      const n = pushes(() => {
        result = compileSafeRegex(huge);
      });
      expect(result).toBeNull();
      expect(n).toBeLessThan(MAX_NFA_INSTRUCTIONS + 600);
    }
  });

  it('the compile cache: a repeated pattern is not recompiled, a hit does not allocate', () => {
    const src = 'cache-hit-probe-\\d+';
    expect(pushes(() => safeRegexFullMatch(src, 'cache-hit-probe-1'))).toBeGreaterThan(0);
    expect(pushes(() => safeRegexFullMatch(src, 'cache-hit-probe-2'))).toBe(0);
    // unsupported patterns are cached too (null)
    expect(pushes(() => safeRegexFullMatch('cache-null-probe(?=x)', 'x'))).toBeGreaterThan(0);
    expect(pushes(() => safeRegexFullMatch('cache-null-probe(?=x)', 'x'))).toBe(0);
  });

  it('R5-API-05/06: the compile cache is a per-source LRU, never cleared: a source evicts exactly its own least-recently-used entry at its share', () => {
    const src = `mk-lru-${Math.random()}`; // a fresh source so earlier tests' entries do not count
    const asSrc = <T>(f: () => T): T => RegexBudget.request(src).run(f);
    let k = 0;
    const fresh = () => asSrc(() => safeRegexFullMatch(`lru-${k++}-x`, 'q'));
    const sentinel = 'lru-sentinel-\\w';
    const cached = (p: string) => pushes(() => asSrc(() => safeRegexFullMatch(p, 'q'))) === 0;
    asSrc(() => safeRegexFullMatch(sentinel, 'q'));
    // the sentinel is this source's oldest entry; the source may hold REGEX_CACHE_MAX_PER_SOURCE entries
    for (let i = 0; i < REGEX_CACHE_MAX_PER_SOURCE - 1; i++) fresh();
    expect(regexCacheHas(sentinel)).toBe(true); // exactly at its share: nothing evicted yet
    const firstFresh = 'lru-0-x';
    fresh(); // one past the share: evicts the source's least-recently-used entry, the sentinel, and nothing else
    expect(regexCacheHas(sentinel)).toBe(false);
    expect(regexCacheHas(firstFresh)).toBe(true); // not a wholesale clear
    // LRU, not FIFO: touching the oldest entry protects it, the next-oldest goes instead
    expect(cached(firstFresh)).toBe(true);
    fresh();
    expect(regexCacheHas(firstFresh)).toBe(true);
    expect(regexCacheHas('lru-1-x')).toBe(false);
  });
});
