import { describe, expect, it } from 'vitest';
import { isProbablePrime, isStrongLucasProbablePrime } from './vdf';

const sieve = (n: number): boolean[] => {
  const p = new Array<boolean>(n + 1).fill(true);
  p[0] = p[1] = false;
  for (let i = 2; i * i <= n; i++) if (p[i]) for (let j = i * i; j <= n; j += i) p[j] = false;
  return p;
};

describe('primality: Miller-Rabin bases plus strong Lucas (Baillie-PSW structure)', () => {
  it('agrees with a sieve on every n below 60000', () => {
    const p = sieve(60000);
    for (let n = 0; n <= 60000; n++) expect(isProbablePrime(BigInt(n)), String(n)).toBe(p[n]);
  });
  it('the strong Lucas test accepts every odd prime and the known strong Lucas pseudoprimes, nothing else small', () => {
    const p = sieve(30000);
    const psp = new Set([5459, 5777, 10877, 16109, 18971, 22499, 24569, 25199]);
    for (let n = 3; n <= 30000; n += 2) expect(isStrongLucasProbablePrime(BigInt(n)), String(n)).toBe(p[n] || psp.has(n));
  });
  it('the combined test refuses the strong Lucas pseudoprimes and the base-2 strong pseudoprimes', () => {
    for (const n of [5459n, 5777n, 10877n, 16109n, 18971n, 2047n, 3277n, 4033n, 4681n, 8321n]) expect(isProbablePrime(n)).toBe(false);
  });
  it('refuses Carmichael numbers and perfect squares of primes, accepts large known primes', () => {
    for (const n of [561n, 1105n, 1729n, 2465n, 6601n, 41041n, 825265n, 321197185n, 1000003n * 1000003n, 2n ** 61n * 2n ** 61n]) expect(isProbablePrime(n)).toBe(false);
    for (const n of [2n ** 61n - 1n, 2n ** 89n - 1n, 2n ** 127n - 1n, 2n ** 521n - 1n]) expect(isProbablePrime(n)).toBe(true);
    expect(isProbablePrime(2n ** 128n + 1n)).toBe(false); // F7 is composite
  });
});
