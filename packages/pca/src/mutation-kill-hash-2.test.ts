/** Round 2 for hash.ts: suite constants, strict base64url anchors and the lone-surrogate detector. */
import { describe, expect, it } from 'vitest';
import { DEFAULT_HASH_SUITE, HASH_LEN, decodeB64uStrict, hasLoneSurrogate, hashWithSuite, isHashSuite } from './hash';

describe('hash suite constants', () => {
  it('values', () => {
    expect(DEFAULT_HASH_SUITE).toBe('sha256');
    expect(HASH_LEN).toStrictEqual({ sha256: 32, sha384: 48 });
    expect(hashWithSuite(new Uint8Array(1))).toHaveLength(32);
    expect(hashWithSuite(new Uint8Array(1), 'sha384')).toHaveLength(48);
    expect(isHashSuite('sha256') && isHashSuite('sha384')).toBe(true);
    for (const x of ['sha512', '', null, undefined, 5]) expect(isHashSuite(x)).toBe(false);
  });
});
describe('strict base64url anchors', () => {
  it('rejects characters outside the alphabet anywhere in the string', () => {
    for (const bad of ['!AAA', 'AAA!', 'AA!A', ' AAA', 'AAA ', 'AAAA\n', '\nAAAA', 'AA==', 'A+AA', 'A/AA']) expect(decodeB64uStrict(bad)).toBeNull();
    expect(decodeB64uStrict('AAAA')).toEqual(new Uint8Array(3));
    expect(decodeB64uStrict('')).toEqual(new Uint8Array(0));
  });
});
describe('hasLoneSurrogate', () => {
  const H = '\ud83d', L = '\ude00';
  it.each([
    [H, true], [L, true], [`a${H}`, true], [`${H}a`, true], [`${L}a`, true], [`a${L}`, true], [`${H}${H}${L}`, true], [`${H}${L}${L}`, true], [`${L}${H}`, true],
    [`${H}${L}`, false], ['', false], ['abc', false], [`x${H}${L}y`, false], [`${H}${L}${H}${L}`, false], ['퟿', false],
  ])('%j -> %s', (s, want) => {
    expect(hasLoneSurrogate(s)).toBe(want);
  });
});
