// 0.4.2 mutation kills (Stryker run 39706550807) for src/ext-regex.ts: the typed glue refuses non-strings and over-long inputs itself
// (before the proved engine), and the document budget argument is validated structurally.
import { describe, expect, it } from 'vitest';
import { compilesVerified, isSafeRegexSourceVerified, reMatchesVerified, safeRegexFullMatchVerified } from '../src/ext-regex';

const budget = () => {
  const charged: Array<[string, number]> = [];
  return { charged, charge: (src: string, n: number) => (charged.push([src, n]), true) };
};

describe('ext-regex glue: input typing', () => {
  it('safeRegexFullMatchVerified returns null (never throws) unless BOTH arguments are strings', () => {
    expect(safeRegexFullMatchVerified('a+', 'aaa')).toBe(true);
    expect(safeRegexFullMatchVerified('a+', 'b')).toBe(false);
    for (const bad of [undefined, null, 5, {}, ['a'], 7n]) {
      expect(safeRegexFullMatchVerified(bad as never, 'a')).toBeNull();
      expect(safeRegexFullMatchVerified('a', bad as never)).toBeNull();
      expect(safeRegexFullMatchVerified(bad as never, bad as never)).toBeNull();
    }
  });
  it('compilesVerified / isSafeRegexSourceVerified are false for a non-string and decide for a string', () => {
    expect(compilesVerified('a+')).toBe(true);
    expect(isSafeRegexSourceVerified('a+')).toBe(true);
    expect(compilesVerified('(')).toBe(false);
    for (const bad of [undefined, null, 5, {}, ['a+'], 7n]) {
      expect(compilesVerified(bad as never)).toBe(false);
      expect(isSafeRegexSourceVerified(bad as never)).toBe(false);
    }
  });
  it('compilesVerified and isSafeRegexSourceVerified agree with the engine on strings (true / false are both reachable)', () => {
    expect(isSafeRegexSourceVerified('(a+)+b')).toBe(false);
    expect(isSafeRegexSourceVerified('ab|cd')).toBe(true);
  });
});

describe('reMatchesVerified', () => {
  it('a non-string source or resource is false and is never charged; the budget is validated first', () => {
    for (const bad of [undefined, null, 5, {}, ['a']]) {
      const a = budget();
      expect(reMatchesVerified(bad as never, 'a', a)).toBe(false);
      expect(reMatchesVerified('a', bad as never, a)).toBe(false);
      expect(reMatchesVerified(bad as never, bad as never, a)).toBe(false);
      expect(a.charged).toEqual([]);
    }
  });
  it('the source / resource length caps are exclusive of the cap itself (200 and 512 are accepted, one more is not)', () => {
    const a = budget();
    expect(reMatchesVerified('a'.repeat(200), 'a'.repeat(200), a)).toBe(true);
    expect(reMatchesVerified('a', 'a'.repeat(512), a)).toBe(false); // a full match needs the whole 512; 'a' does not match it
    expect(reMatchesVerified('a+', 'a'.repeat(512), a)).toBe(true);
    expect(a.charged.length).toBe(3);
    expect(reMatchesVerified('a'.repeat(201), 'a'.repeat(201), a)).toBe(false);
    expect(reMatchesVerified('a+', 'a'.repeat(513), a)).toBe(false);
    expect(a.charged.length).toBe(3);
  });
  it('the budget must have a charge function (a plain object, a number, a string all throw)', () => {
    for (const b of [{}, { charge: 1 }, { charge: 'x' }, { charge: null }, 5, 'x', undefined, null]) {
      expect(() => reMatchesVerified('a', 'a', b as never)).toThrow('reMatchesVerified: a document regex budget is required (R6-CORE-07)');
    }
  });
});
