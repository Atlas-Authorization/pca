import { describe, expect, it } from 'vitest';
import { isMillerRabinProbablePrime, modpow } from './vdf';

// 211 * 421 * 631: a Carmichael number whose prime factors all exceed the trial-division primes, so a^(n-1) = 1
// (mod n) for every base and a plain Fermat test accepts it. The strong test must still refuse it.
const CARMICHAEL = 211n * 421n * 631n;

describe('isMillerRabinProbablePrime', () => {
  it('is a strong test, not a Fermat test: refuses a Carmichael number every base passes Fermat on', () => {
    for (const a of [2n, 3n, 5n, 97n]) expect(modpow(a, CARMICHAEL - 1n, CARMICHAEL)).toBe(1n);
    expect(isMillerRabinProbablePrime(CARMICHAEL)).toBe(false);
  });
  it('refuses the other Carmichael numbers with large factors', () => {
    for (const n of [271n * 541n * 811n, 1801n * 3601n * 5401n]) expect(isMillerRabinProbablePrime(n), String(n)).toBe(false);
  });
  it('accepts primes above and below the base range, including one with a large power of two in n - 1', () => {
    for (const n of [3n, 5n, 97n, 101n, 65537n, 998244353n, 2n ** 61n - 1n]) expect(isMillerRabinProbablePrime(n), String(n)).toBe(true);
  });
  it('refuses even numbers and numbers below three', () => {
    for (const n of [-7n, 0n, 1n, 2n, 4n, 65536n]) expect(isMillerRabinProbablePrime(n), String(n)).toBe(false);
  });
});
