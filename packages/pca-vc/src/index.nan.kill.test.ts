import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { signRequestMessage, verifyRequestSignature } from './index';

const kp = generateKeyPairSync('ed25519');
const URL1 = 'https://api.example.com/v1/pay?x=1';
const NOW = 1_700_000_000;
const hdr = { 'X-Req': ' val ', Host: 'api.example.com' };
const s = signRequestMessage({ method: 'POST', url: URL1, headers: hdr, key: kp.privateKey, keyid: 'k1', created: NOW });
const args = { method: 'POST', url: URL1, headers: hdr, signatureInput: s.signatureInput, signature: s.signature };
const ok = (o: Record<string, unknown>) => verifyRequestSignature({ ...args, ...o } as never, kp.publicKey);

describe('verifyRequestSignature with a non-finite clock or window never admits', () => {
  it('a finite clock inside the window admits', () => {
    expect(ok({ maxAgeSec: 60, nowSec: NOW + 10 })).toBe(true);
  });
  // pre-fix: `now - c > max` and `c - now > 5` were both false for a NaN operand
  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])('nowSec of %s', (nowSec) => {
    expect(ok({ maxAgeSec: 60, nowSec })).toBe(false);
  });
  it('maxAgeSec of NaN', () => {
    expect(ok({ maxAgeSec: Number.NaN, nowSec: NOW + 10 })).toBe(false);
  });
  // old code: with an infinite window and an infinite clock both checks passed (`Infinity - c <= Infinity`, `c - Infinity <= 5`)
  it.each([Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])('an unbounded window with nowSec of %s', (nowSec) => {
    expect(ok({ maxAgeSec: Number.POSITIVE_INFINITY, nowSec })).toBe(false);
  });
});
