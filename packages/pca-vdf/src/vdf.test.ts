import { describe, expect, it } from 'vitest';
import {
  CHALLENGE_PRIME_BITS,
  DEFAULT_MODULUS,
  RSA_2048_CHALLENGE_MODULUS,
  hashToPrime,
  isProbablePrime,
  modpow,
  sequentialSquare,
  insecureDevSetup,
  vdf,
  vdfEval,
  vdfVerify,
} from './vdf';

// Use the shipped honest default modulus (RSA-2048) for the core round-trips: it
// is deterministic and fast for the small T these tests use (a few hundred
// squarings of 2048-bit numbers is microseconds; verify is O(log)).
const N = DEFAULT_MODULUS;
const X = 123456789n;

describe('modpow', () => {
  it('matches a naive reference', () => {
    expect(modpow(2n, 10n, 1000n)).toBe(24n); // 1024 mod 1000
    expect(modpow(7n, 0n, 13n)).toBe(1n);
    expect(modpow(5n, 3n, 1000000n)).toBe(125n);
  });
  it('rejects a negative exponent (no inverse in an unknown-order group)', () => {
    expect(() => modpow(2n, -1n, 7n)).toThrow();
  });
});

describe('isProbablePrime', () => {
  it('classifies small numbers', () => {
    expect(isProbablePrime(2n)).toBe(true);
    expect(isProbablePrime(97n)).toBe(true);
    expect(isProbablePrime(1n)).toBe(false);
    expect(isProbablePrime(0n)).toBe(false);
    expect(isProbablePrime(91n)).toBe(false); // 7 * 13
    expect(isProbablePrime(561n)).toBe(false); // Carmichael number
  });
  it('recognises a known large prime', () => {
    // 2^127 - 1 (Mersenne prime).
    expect(isProbablePrime((1n << 127n) - 1n)).toBe(true);
    expect(isProbablePrime((1n << 127n) - 1n + 2n)).toBe(false);
  });
});

describe('hashToPrime', () => {
  it('is deterministic and returns a prime of the requested size', () => {
    const l1 = hashToPrime(X, 42n, 1000, N);
    const l2 = hashToPrime(X, 42n, 1000, N);
    expect(l1).toBe(l2);
    expect(isProbablePrime(l1)).toBe(true);
    expect(l1.toString(2).length).toBe(CHALLENGE_PRIME_BITS);
  });
  it('binds to the transcript: changing x, y, or T changes l', () => {
    const base = hashToPrime(X, 42n, 1000, N);
    expect(hashToPrime(X + 1n, 42n, 1000, N)).not.toBe(base);
    expect(hashToPrime(X, 43n, 1000, N)).not.toBe(base);
    expect(hashToPrime(X, 42n, 1001, N)).not.toBe(base);
  });
});

describe('sequentialSquare — the enforced delay is REAL math', () => {
  it('equals the closed form x^(2^T) mod N for small T', () => {
    for (const T of [0, 1, 2, 10, 32, 64]) {
      const expected = modpow(X, 2n ** BigInt(T), N);
      expect(sequentialSquare(X, T, N)).toBe(expected);
    }
  });
  it('each extra step advances the chain (one more squaring)', () => {
    const yT = sequentialSquare(X, 50, N);
    const yT1 = sequentialSquare(X, 51, N);
    expect(yT1).toBe((yT * yT) % N); // step 51 is exactly one more squaring of step 50
    expect(yT1).not.toBe(yT);
  });
  it('rejects a non-integer / negative step count', () => {
    expect(() => sequentialSquare(X, 1.5, N)).toThrow();
    expect(() => sequentialSquare(X, -1, N)).toThrow();
  });
});

describe('vdfEval / vdfVerify — Wesolowski round-trip', () => {
  it('eval then verify accepts for a modest T', () => {
    for (const T of [1, 2, 37, 250]) {
      const { y, pi } = vdfEval(X, T, N);
      expect(y).toBe(sequentialSquare(X, T, N)); // y really is x^(2^T)
      expect(vdfVerify(X, y, pi, T, N)).toBe(true);
    }
  });

  it('the spec-named vdf.eval / vdf.verify behave identically', () => {
    const { y, pi } = vdf.eval(X, 120, N);
    expect(vdf.verify(X, y, pi, 120, N)).toBe(true);
  });

  it('REJECTS a wrong y', () => {
    const { y, pi } = vdfEval(X, 200, N);
    expect(vdfVerify(X, y + 1n, pi, 200, N)).toBe(false);
    expect(vdfVerify(X, (y + 7n) % N, pi, 200, N)).toBe(false);
  });

  it('REJECTS a wrong pi', () => {
    const { y, pi } = vdfEval(X, 200, N);
    expect(vdfVerify(X, y, pi + 1n, 200, N)).toBe(false);
    expect(vdfVerify(X, y, (pi * 2n) % N, 200, N)).toBe(false);
  });

  it('REJECTS a wrong T (shorter or longer than claimed)', () => {
    const T = 200;
    const { y, pi } = vdfEval(X, T, N);
    expect(vdfVerify(X, y, pi, T - 1, N)).toBe(false);
    expect(vdfVerify(X, y, pi, T + 1, N)).toBe(false);
  });

  it('REJECTS a wrong x (an input not the one that was evaluated)', () => {
    const T = 200;
    const { y, pi } = vdfEval(X, T, N);
    expect(vdfVerify(X + 1n, y, pi, T, N)).toBe(false);
    expect(vdfVerify(987654321n, y, pi, T, N)).toBe(false);
  });

  it('fails closed on malformed input instead of throwing', () => {
    const { y, pi } = vdfEval(X, 50, N);
    expect(vdfVerify(X, y, pi, -1, N)).toBe(false);
    expect(vdfVerify(X, y, pi, 1.5, N)).toBe(false);
    expect(vdfVerify(X, y, pi, 50, 3n)).toBe(false); // N too small
  });
});

describe('insecureDevSetup — DEV-only modulus generation (holds the trapdoor)', () => {
  it('produces N = p*q with prime factors, and the VDF round-trips on it', () => {
    const s = insecureDevSetup({ bits: 256 });
    expect(s.p * s.q).toBe(s.N);
    expect(isProbablePrime(s.p)).toBe(true);
    expect(isProbablePrime(s.q)).toBe(true);
    expect(s.p).not.toBe(s.q);
    expect(s.N.toString(2).length).toBeGreaterThanOrEqual(255);

    const { y, pi } = vdfEval(X % s.N, 120, s.N);
    expect(vdfVerify(X % s.N, y, pi, 120, s.N)).toBe(true);
  });

  it('demonstrates the trapdoor: the factor holder shortcuts the delay', () => {
    const s = insecureDevSetup({ bits: 256 });
    const x = (X % s.N) + 2n;
    const T = 300;
    const slow = sequentialSquare(x, T, s.N); // T real squarings
    // Trapdoor shortcut: reduce the exponent 2^T modulo the group order phi(N).
    const phi = (s.p - 1n) * (s.q - 1n);
    const fast = modpow(x, modpow(2n, BigInt(T), phi), s.N); // two modpows, no chain
    expect(fast).toBe(slow);
  });
});

describe('RSA-2048 default modulus', () => {
  it('is the documented 2048-bit challenge number', () => {
    expect(DEFAULT_MODULUS).toBe(RSA_2048_CHALLENGE_MODULUS);
    expect(RSA_2048_CHALLENGE_MODULUS.toString(2).length).toBe(2048);
    expect(RSA_2048_CHALLENGE_MODULUS.toString().length).toBe(617);
  });
});
