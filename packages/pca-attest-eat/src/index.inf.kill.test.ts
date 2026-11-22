import { describe, expect, it } from 'vitest';
import { verifyFreshness, type EatClaims } from './index';

const NOW = 1_800_000_000_000;
const claims = (iat: number): EatClaims => ({ iss: 'https://iss.example', iat, eat_nonce: 'n1', cnf: { tls_exporter: 'x' } }) as EatClaims;
const f = (iat: number, o: Partial<Parameters<typeof verifyFreshness>[1]> = {}) => verifyFreshness(claims(iat), { expectedNonce: 'n1', maxAgeMs: 60_000, now: NOW, ...o });

describe('freshness never admits on a non-finite window', () => {
  it('a fresh iat is accepted (control)', () => {
    expect(f(NOW / 1000).ok).toBe(true);
  });
  // an iat whose millisecond value overflows to +/-Infinity lands on the future / stale side
  it.each([1e306, -1e306])('iat of %s', (iat) => {
    expect(f(iat).ok).toBe(false);
  });
  it.each([Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, Number.NaN])('maxAgeMs or clockSkewMs of %s', (v) => {
    expect(f(NOW / 1000 - 3600, { maxAgeMs: v }).ok).toBe(false);
    expect(f(NOW / 1000 - 3600, { clockSkewMs: v }).ok).toBe(false);
  });
});
