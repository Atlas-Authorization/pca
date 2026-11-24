import { describe, expect, it } from 'vitest';
import { isStrongLucasProbablePrime } from './vdf';

describe('isStrongLucasProbablePrime input screening', () => {
  it('refuses zero, one, two and every even number, whatever its factorisation', () => {
    for (const n of [0n, 1n, 2n, 4n, 6n, 8n, 10n, 12n, 14n, 152n, 1016n, 2n ** 20n]) expect(isStrongLucasProbablePrime(n), String(n)).toBe(false);
  });
  it('refuses odd perfect squares', () => {
    for (const n of [9n, 25n, 49n, 121n, 625n, 1000003n * 1000003n]) expect(isStrongLucasProbablePrime(n), String(n)).toBe(false);
  });
  it('refuses a composite whose first candidate discriminant shares a factor with it', () => {
    for (const n of [15n, 35n, 55n, 95n, 22786799n]) expect(isStrongLucasProbablePrime(n), String(n)).toBe(false);
  });
  it('still accepts odd primes, including those that divide a candidate discriminant', () => {
    for (const n of [3n, 5n, 7n, 11n, 13n, 101n, 2n ** 31n - 1n]) expect(isStrongLucasProbablePrime(n), String(n)).toBe(true);
  });
});
