/** hash.ts residual mutants: suite constants, hasLoneSurrogate on every surrogate shape, compareUtf8's lone-surrogate tie-break direction. */
import { describe, expect, it } from 'vitest';
import { DEFAULT_HASH_SUITE, HASH_LEN, compareUtf8, hasLoneSurrogate } from './hash';

describe('hash suite constants', () => {
  it('default suite and digest lengths', () => {
    expect(DEFAULT_HASH_SUITE).toBe('sha256');
    expect(HASH_LEN).toEqual({ sha256: 32, sha384: 48 });
  });
});

describe('hasLoneSurrogate', () => {
  it.each([
    ['', false],
    ['a', false],
    ['😀', false],
    ['x😀y', false],
    ['\ud800', true],
    ['\ud800a', true],
    ['a\ud800', true],
    ['\udc00', true],
    ['a\udc00', true],
    ['\udc00a', true],
    ['\udc00\ud800', true],
  ] as const)('%j -> %s', (s, want) => {
    expect(hasLoneSurrogate(s)).toBe(want);
  });
});

describe('compareUtf8 tie-break', () => {
  it('distinct strings with equal UTF-8 bytes order by UTF-16 code units, antisymmetrically', () => {
    expect(compareUtf8('\ud800', '\ud801')).toBe(-1);
    expect(compareUtf8('\ud801', '\ud800')).toBe(1);
    expect(compareUtf8('\ud800', '\ud800')).toBe(0);
  });
});
