/**
 * isSafeRegexSource accepts only sources that V8's RegExp also compiles (as `^(?:src)$`, the form validateWhen checks).
 * Differential over a seeded token-grammar fuzz that is dense in the constructs where the two parsers could differ (class ranges
 * and escapes, quantifier forms, group openers, anchors, lone brackets/braces) plus hand-picked edge sources. Any accepted source that
 * V8 rejects would make the compile check in prohibitions.ts validateWhen reachable.
 */
import { describe, expect, it } from 'vitest';
import { isSafeRegexSource } from './predicates';

const TOKENS = [
  'a', 'b', 'z', '0', '5', '_', '-', ' ', '/', '.', '^', '$', '|', '(', ')', '(?:', '(?', '(?=', '(?<n>', '[', ']', '[^', '{', '}', '*', '+', '?',
  '{2}', '{0}', '{1,}', '{2,5}', '{5,2}', '{,3}', '{64}', '{65}', '{a}', '{', '*?', '+?', '??', '{2}?',
  '\\', '\\d', '\\D', '\\w', '\\W', '\\s', '\\S', '\\b', '\\B', '\\t', '\\n', '\\v', '\\f', '\\r', '\\0', '\\00', '\\1', '\\k', '\\p', '\\x41', '\\x4', '\\u0041', '\\u00', '\\cA', '\\c1', '\\c',
  '\\-', '\\.', '\\]', '\\[', '\\(', '\\)', '\\{', '\\}', '\\/', '\\\\', '\\_', '\\e',
  'a-c', 'c-a', '\\d-x', 'x-\\d', '\\w-\\d', '\\x41-\\x43', '\\u0041-\\u0043', '\\0-\\x7f', 'é', '😀', '\\ud83d', '\\ude00', '\n', ' ',
];
const EDGE = ['', '()', '(?:)', '|', '||', '[]', '[^]', '[]a]', '[a-]', '[-a]', '[a-\\d]', '[\\d-a]', '[\\d-\\w]', '[\\b]', '[\\B]', '[c-a]', '[\\x62-\\x61]', '[\\u0062-\\u0061]', 'a{2}{3}', 'a**', '^*', '$+', '(^)*', '(a|)+', '(?:a|b)c{2,3}', ']', '}', 'a]b', 'a}b', '\\c', '\\cZ', '\\0', '\\00', '\\8', '(?:^|x)$'];

let seed = 0x1234abcd;
const rnd = (): number => {
  seed ^= seed << 13; seed >>>= 0; seed ^= seed >>> 17; seed ^= seed << 5; seed >>>= 0;
  return seed / 4294967296;
};
const gen = (): string => {
  const n = 1 + Math.floor(rnd() * 9);
  let s = '';
  for (let i = 0; i < n; i++) s += TOKENS[Math.floor(rnd() * TOKENS.length)];
  return s;
};
const compiles = (src: string): boolean => {
  try {
    new RegExp('^(?:' + src + ')$');
    return true;
  } catch {
    return false;
  }
};

describe('guard-accepts implies V8-compiles', () => {
  it('hand-picked edge sources', () => {
    for (const s of EDGE) if (isSafeRegexSource(s)) expect(compiles(s), JSON.stringify(s)).toBe(true);
  });
  it('seeded token fuzz', () => {
    let accepted = 0;
    const bad: string[] = [];
    for (let i = 0; i < 300_000; i++) {
      const s = gen();
      if (!isSafeRegexSource(s)) continue;
      accepted++;
      if (!compiles(s)) bad.push(s);
    }
    expect(bad.slice(0, 5)).toEqual([]);
    expect(accepted).toBeGreaterThan(5_000);
  });
});
