import { describe, expect, it } from 'vitest';
import { generateKeyPair } from '@atlasauth/pca';
import { isObj, isSafeInt, isStr, signBody, signerOf, verifyBody } from './sig';

const k = generateKeyPair();
const other = generateKeyPair();
const D = 'atlas-pca/test/v1\0';

describe('domain-separated signatures', () => {
  const body = { a: 1, b: ['x'] };
  const sig = signBody(D, body, k.secretKey);
  it('verify only for the exact domain, body and signer', () => {
    expect(verifyBody(D, body, signerOf(k.secretKey), sig)).toBe(true);
    expect(verifyBody(D, { b: ['x'], a: 1 }, signerOf(k.secretKey), sig)).toBe(true); // canonical key order
    expect(verifyBody('atlas-pca/other/v1\0', body, signerOf(k.secretKey), sig)).toBe(false);
    expect(verifyBody(D, { ...body, a: 2 }, signerOf(k.secretKey), sig)).toBe(false);
    expect(verifyBody(D, body, signerOf(other.secretKey), sig)).toBe(false);
  });
  it('never throws and refuses a malformed signature or signer', () => {
    const who = signerOf(k.secretKey);
    for (const bad of [undefined, null, 5, {}, '', 'AAAA', `${sig}A`, sig.slice(0, -2), `${sig.slice(0, -1)}=`]) expect(verifyBody(D, body, who, bad)).toBe(false);
    expect(verifyBody(D, body, 'not-a-key', sig)).toBe(false);
    expect(verifyBody(D, body, '', sig)).toBe(false);
  });
});

describe('shape guards', () => {
  it('isSafeInt is a non-negative safe integer', () => {
    expect([0, 1, Number.MAX_SAFE_INTEGER].map(isSafeInt)).toEqual([true, true, true]);
    expect([-1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '1', null, undefined].map(isSafeInt)).toEqual([false, false, false, false, false, false, false, false]);
  });
  it('isObj is a plain non-null non-array object', () => {
    expect([{}, { a: 1 }].map(isObj)).toEqual([true, true]);
    expect([null, undefined, [], 'x', 1].map(isObj)).toEqual([false, false, false, false, false]);
  });
  it('isStr is non-empty and bounded (default 512)', () => {
    expect(isStr('a')).toBe(true);
    expect(isStr('a'.repeat(512))).toBe(true);
    expect(isStr('a'.repeat(513))).toBe(false);
    expect(isStr('')).toBe(false);
    expect(isStr(1)).toBe(false);
    expect(isStr('abc', 3)).toBe(true);
    expect(isStr('abcd', 3)).toBe(false);
  });
});
