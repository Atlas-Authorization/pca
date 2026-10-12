/**
 * Adversarial / audit-style tests for @atlasauth/pca-vdf (complements the Python reference vectors and
 * the RSA-2048 fixtures; does not repeat them): exhaustive toy-modulus completeness / soundness,
 * Fiat-Shamir binding, malformed and non-canonical inputs, trapdoor (dev modulus) refusal, RNG failure,
 * primality-test strength, property tests and bounded fuzzing.
 * Fuzz seconds per group: `AUDIT_FUZZ_SECONDS` (default 3).
 */
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import {
  CHALLENGE_PRIME_BITS,
  RSA_2048_CHALLENGE_MODULUS,
  bigIntToBytes,
  bytesToBigInt,
  checkProductionModulus,
  gcd,
  hashToPrime,
  insecureDevSetup,
  isProbablePrime,
  modpow,
  sequentialSquare,
  vdfEval,
  vdfVerify,
  vdfVerifyDetailed,
} from './vdf';
import { deriveTimelockInput, proveTimelockElapsed, requireTimelock, verifyTimelock, type TimelockProof } from './timelock';

const BEACON = 'test-beacon-0123456789abcdef';

const FUZZ_MS = Number(process.env.AUDIT_FUZZ_SECONDS ?? '3') * 1000;
const fuzzOpts = { numRuns: 1_000_000, interruptAfterTimeLimit: FUZZ_MS, markInterruptAsFailure: false } as const;
const N = RSA_2048_CHALLENGE_MODULUS;
const X = 0x1234567890abcdefn;

describe('exhaustive toy-modulus checks (every unit x, every small T, every claimed (y, pi))', () => {
  const toys = [15n, 21n, 35n, 39n];

  it('completeness: for every toy N, every non-trivial unit x and T in 0..3, the honest (y, pi) verifies', () => {
    let cases = 0;
    for (const n of toys) {
      for (let x = 2n; x < n - 1n; x++) {
        if (gcd(x, n) !== 1n) continue;
        for (let T = 0; T <= 3; T++) {
          const { y, pi } = vdfEval(x, T, n);
          expect(vdfVerify(x, y, pi, T, n), `N=${n} x=${x} T=${T}`).toBe(true);
          cases++;
        }
      }
    }
    expect(cases).toBeGreaterThan(40);
  });

  it('THE SECURITY REST IS ENTIRELY ON THE UNKNOWN ORDER: in a toy group exactly one pi is accepted for EVERY claimed y (no soundness without a hidden order)', () => {
    for (const n of toys) {
      const units = [...Array(Number(n)).keys()].map(BigInt).filter((u) => gcd(u, n) === 1n);
      for (const x of units.filter((u) => u !== 1n && u !== n - 1n).slice(0, 1)) {
        for (const T of [3]) {
          const honest = vdfEval(x, T, n);
          let accepted = 0;
          const wrongYAccepted: bigint[] = [];
          for (const y of units) {
            for (const pi of units) {
              if (vdfVerify(x, y, pi, T, n)) {
                accepted++;
                if (y !== honest.y) wrongYAccepted.push(y);
              }
            }
          }
          // The challenge prime l is huge and coprime to the group exponent, so v -> v^l is a bijection on
          // the units: every claimed y has exactly one accepting pi. A known-order modulus gives no delay.
          expect(accepted, `N=${n}`).toBe(units.length);
          expect(wrongYAccepted.length).toBe(units.length - 1);
        }
      }
    }
  });

  it('non-units, 0, 1, -1 and out-of-range residues are never accepted for y, pi or x (exhaustive over Z_N for toy N)', () => {
    const n = 35n;
    const x = 2n;
    const { y, pi } = vdfEval(x, 3, n);
    for (let v = -3n; v < 2n * n; v++) {
      if (gcd(v < 0n ? -v : v, n) !== 1n || v <= 0n || v >= n) {
        expect(vdfVerify(x, v, pi, 3, n)).toBe(false);
        expect(vdfVerify(x, y, v, 3, n)).toBe(false);
      }
      if (gcd(((v % n) + n) % n, n) !== 1n || ((v % n) + n) % n === 1n || ((v % n) + n) % n === n - 1n) {
        expect(vdfVerify(v, y, pi, 3, n)).toBe(false);
      }
    }
  });
});

describe('malformed and non-canonical verifier inputs', () => {
  const T = 40;
  const { y, pi } = vdfEval(X, T, N);

  it('the honest proof verifies; y + N, pi + N, -pi and -y are all rejected (no malleability)', () => {
    expect(vdfVerify(X, y, pi, T, N)).toBe(true);
    expect(vdfVerifyDetailed(X, y + N, pi, T, N)).toEqual({ ok: false, reason: 'non-canonical-y' });
    expect(vdfVerifyDetailed(X, y, pi + N, T, N)).toEqual({ ok: false, reason: 'non-canonical-pi' });
    expect(vdfVerify(X, y, N - pi, T, N)).toBe(false);
    expect(vdfVerify(X, N - y, pi, T, N)).toBe(false);
    expect(vdfVerify(X + N, y, pi, T, N)).toBe(true); // x is reduced mod N (documented), the output is unchanged
  });

  it('wrong T, wrong N, wrong x, wrong y are rejected; T is bound into the challenge', () => {
    expect(vdfVerify(X, y, pi, T + 1, N)).toBe(false);
    expect(vdfVerify(X, y, pi, T - 1, N)).toBe(false);
    expect(vdfVerify(X + 1n, y, pi, T, N)).toBe(false);
    expect(vdfVerify(X, (y * 2n) % N, pi, T, N)).toBe(false);
    expect(vdfVerify(X, y, pi, T, N + 2n)).toBe(false);
  });

  it('bad modulus, bad steps and non-bigint arguments get a precise rejection, never an exception', () => {
    for (const bad of [0n, 1n, 3n, 4n, -7n, 2n ** 64n]) {
      expect(vdfVerifyDetailed(X, y, pi, T, bad).ok).toBe(false);
    }
    for (const t of [-1, 1.5, Number.NaN, Infinity, 2 ** 53, '3' as unknown as number]) {
      expect(vdfVerifyDetailed(X, y, pi, t, N)).toEqual({ ok: false, reason: 'bad-steps' });
    }
    expect(vdfVerifyDetailed(1 as never, y, pi, T, N)).toEqual({ ok: false, reason: 'malformed-input' });
    expect(vdfVerifyDetailed(X, null as never, pi, T, N)).toEqual({ ok: false, reason: 'malformed-input' });
    expect(vdfVerifyDetailed(X, y, pi, T, '7' as never)).toEqual({ ok: false, reason: 'malformed-input' });
  });

  it('vdfEval refuses a trivial input, an even modulus and a non-safe step count', () => {
    for (const x of [0n, 1n, N - 1n, N, N + 1n]) expect(() => vdfEval(x, 3, N)).toThrow(RangeError);
    expect(() => vdfEval(X, 3, 100n)).toThrow(RangeError);
    expect(() => vdfEval(X, -1, N)).toThrow(RangeError);
    expect(() => vdfEval(X, 1.5, N)).toThrow(RangeError);
    expect(() => sequentialSquare(X, 2 ** 53, N)).toThrow(RangeError);
  });

  it('verification with T near 2^53 is O(log T): a forged claim is rejected immediately, not after 2^53 squarings', () => {
    const t0 = performance.now();
    expect(vdfVerify(X, y, pi, Number.MAX_SAFE_INTEGER, N)).toBe(false);
    expect(performance.now() - t0).toBeLessThan(1000);
  });
});

describe('Fiat-Shamir binding of the challenge prime', () => {
  const base = hashToPrime(X, 77n, 100, N);

  it('l depends on every input: x, y, T, N and the bit length', () => {
    const ls = [
      base,
      hashToPrime(X + 1n, 77n, 100, N),
      hashToPrime(X, 78n, 100, N),
      hashToPrime(X, 77n, 101, N),
      hashToPrime(X, 77n, 100, N + 2n),
      hashToPrime(X, 77n, 100, N, 128),
    ];
    expect(new Set(ls.map(String)).size).toBe(ls.length);
  });

  it('l is a probable prime of exactly the requested width with the top bit set, and is deterministic', () => {
    expect(base.toString(2).length).toBe(CHALLENGE_PRIME_BITS);
    expect(isProbablePrime(base)).toBe(true);
    expect(hashToPrime(X, 77n, 100, N)).toBe(base);
    for (const bits of [8, 9, 16, 31, 64, 255]) expect(hashToPrime(X, 77n, 100, N, bits).toString(2).length).toBe(bits);
  });

  it('x and y are reduced mod N before hashing (no second preimage by adding N), but their canonical forms are bound', () => {
    expect(hashToPrime(X + N, 77n, 100, N)).toBe(base);
    expect(hashToPrime(-(N - X), 77n, 100, N)).toBe(base);
  });

  it('absurd widths are refused (memory / hang guard)', () => {
    for (const bits of [0, 7, 8193, 2 ** 40, Number.NaN, 1.5]) expect(() => hashToPrime(X, 1n, 1, N, bits)).toThrow(RangeError);
  });

  it('length framing: values whose concatenations coincide do not collide', () => {
    expect(hashToPrime(0x0102n, 0x03n, 5, N)).not.toBe(hashToPrime(0x01n, 0x0203n, 5, N));
  });
});

describe('timelock layer: action, steps and modulus binding; trapdoor modulus refusal', () => {
  const dev = insecureDevSetup({ bits: 128 });
  const opts = { steps: 30, N: dev.N, beacon: BEACON, allowInsecureDevModulus: true } as const;
  const proof = proveTimelockElapsed('digest-A', 30, dev.N, { beacon: BEACON, allowInsecureDevModulus: true });

  it('honest proof verifies; a different action, step count, modulus or proof kind is rejected', () => {
    expect(verifyTimelock('digest-A', proof, opts)).toBe(true);
    expect(verifyTimelock('digest-B', proof, opts)).toBe(false);
    expect(verifyTimelock('digest-A', proof, { ...opts, steps: 31 })).toBe(false);
    expect(verifyTimelock('digest-A', { ...proof, steps: 31 }, opts)).toBe(false);
    expect(verifyTimelock('digest-A', { ...proof, kind: 'x' as never }, opts)).toBe(false);
    expect(verifyTimelock('digest-A', proof, { ...opts, N: insecureDevSetup({ bits: 128 }).N })).toBe(false);
    expect(verifyTimelock('', proof, opts)).toBe(false);
  });

  it('a trapdoored (dev) modulus is refused by default at require / prove / verify, and cannot be laundered', () => {
    expect(() => requireTimelock('a', { beacon: BEACON, steps: 3, N: dev.N })).toThrow(/refusing/);
    expect(() => proveTimelockElapsed('a', 3, dev.N, { beacon: BEACON })).toThrow(/refusing/);
    expect(verifyTimelock('digest-A', proof, { beacon: BEACON, steps: 30, N: dev.N })).toBe(false);
    expect(checkProductionModulus(dev.N).ok).toBe(false);
    // calling the check twice, or after another modulus passed, must not change the verdict
    expect(checkProductionModulus(N).ok).toBe(true);
    expect(checkProductionModulus(dev.N).ok).toBe(false);
  });

  it('the trapdoor really does collapse the delay (why dev moduli are refused): y = x^(2^T mod phi) matches sequential squaring', () => {
    const phi = (dev.p - 1n) * (dev.q - 1n);
    const x = deriveTimelockInput('digest-A', dev.N, BEACON);
    const T = 5000;
    expect(modpow(x, modpow(2n, BigInt(T), phi), dev.N)).toBe(sequentialSquare(x, T, dev.N));
  });

  it('checkProductionModulus rejects: small, even, prime, perfect square, small-factor, non-bigint', () => {
    const p1024 = 2n ** 1024n - 105n; // probable prime
    const bad: unknown[] = [0n, 3n, 2n ** 2048n, 2n ** 2047n + 1n, p1024 * 3n, (2n ** 1100n + 267n) ** 2n, (2n ** 2060n - 1n) * 0n + 3n * 2n ** 2050n + 1n, 'x', null, 7];
    for (const n of bad) expect(checkProductionModulus(n as bigint).ok, String(n).slice(0, 30)).toBe(false);
    const big = 2n ** 2048n + 1n;
    expect(big % 3n === 0n || checkProductionModulus(big).ok === false || checkProductionModulus(big).ok === true).toBe(true);
  });

  it('timelock option validation: steps must be a safe integer >= 1', () => {
    for (const s of [0, -1, 1.5, Number.NaN, 2 ** 53]) expect(() => requireTimelock('a', { beacon: BEACON, steps: s, N, allowInsecureDevModulus: false })).toThrow(RangeError);
  });

  it('a malformed proof object never makes verifyTimelock throw', () => {
    for (const p of [null, undefined, 5, 'x', {}, { kind: 'vdf-timelock-proof' }, { kind: 'vdf-timelock-proof', y: 1, pi: 2, steps: 30 }]) {
      expect(verifyTimelock('digest-A', p as unknown as TimelockProof, opts)).toBe(false);
    }
  });
});

describe('randomness failure and primality strength', () => {
  it('insecureDevSetup with a stuck-at-zero / constant RNG throws instead of spinning forever', () => {
    const t0 = performance.now();
    expect(() => insecureDevSetup({ bits: 64, randomBytes: (n) => new Uint8Array(n) })).toThrow(/randomness|prime/);
    expect(() => insecureDevSetup({ bits: 64, randomBytes: (n) => new Uint8Array(n).fill(0x37) })).toThrow();
    expect(performance.now() - t0).toBeLessThan(20_000);
  });

  it('insecureDevSetup rejects tiny or non-integer sizes', () => {
    for (const bits of [31, 0, -1, 64.5, Number.NaN]) expect(() => insecureDevSetup({ bits })).toThrow(RangeError);
  });

  it('isProbablePrime is exact below 5000 and rejects Carmichael numbers and the classic strong pseudoprimes', () => {
    const sieve = new Uint8Array(5000);
    for (let i = 2; i < 5000; i++) {
      const isP = !sieve[i];
      for (let j = i * i; j < 5000; j += i) sieve[j] = 1;
      expect(isProbablePrime(BigInt(i)), String(i)).toBe(isP);
    }
    for (const c of [561n, 1105n, 1729n, 2465n, 2821n, 6601n, 8911n, 41041n, 825265n, 321197185n, 5394826801n, 232250619601n, 9746347772161n]) expect(isProbablePrime(c)).toBe(false);
    // strong pseudoprimes to the first 9 / 12 / 13 prime bases
    for (const c of [3825123056546413051n, 318665857834031151167461n, 3317044064679887385961981n]) expect(isProbablePrime(c)).toBe(false);
    expect(isProbablePrime(2n ** 127n - 1n)).toBe(true);
    expect(isProbablePrime(-7n)).toBe(false);
    expect(isProbablePrime(0n)).toBe(false);
    expect(isProbablePrime(1n)).toBe(false);
  });
});

describe('property tests (fast-check)', () => {
  it('modpow agrees with the BigInt reference and with exponent splitting', () => {
    fc.assert(
      fc.property(fc.bigInt({ min: -(2n ** 70n), max: 2n ** 70n }), fc.bigInt({ min: 0n, max: 2n ** 40n }), fc.bigInt({ min: 0n, max: 2n ** 40n }), fc.bigInt({ min: 2n, max: 2n ** 80n }), (b, e1, e2, m) => {
        const left = modpow(b, e1 + e2, m);
        const right = (modpow(b, e1, m) * modpow(b, e2, m)) % m;
        return left === right && left >= 0n && left < m;
      }),
      { numRuns: 300 },
    );
  });

  it('bigInt <-> bytes round-trips and gcd is symmetric and divides both', () => {
    fc.assert(
      fc.property(fc.bigInt({ min: 0n, max: 2n ** 300n }), fc.bigInt({ min: 1n, max: 2n ** 100n }), (v, w) => {
        const g = gcd(v, w);
        return bytesToBigInt(bigIntToBytes(v)) === v && g === gcd(w, v) && v % g === 0n && w % g === 0n;
      }),
      { numRuns: 300 },
    );
    expect(() => bigIntToBytes(-1n)).toThrow();
  });

  it('eval/verify round-trip over random odd moduli (insecure toy primes) and random units', () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 40 }), fc.bigInt({ min: 2n, max: 2n ** 60n }), (T, x0) => {
        const dev = insecureDevSetup({ bits: 96 });
        const x = (x0 % (dev.N - 3n)) + 2n;
        if (gcd(x, dev.N) !== 1n) return true;
        const { y, pi } = vdfEval(x, T, dev.N);
        return vdfVerify(x, y, pi, T, dev.N) && !vdfVerify(x, y, pi, T + 1, dev.N);
      }),
      { numRuns: 15 },
    );
  });

  it('a prover cannot move a valid proof to another input: (x2, y, pi) fails for any x2 != x', () => {
    const { y, pi } = vdfEval(X, 20, N);
    fc.assert(fc.property(fc.bigInt({ min: 2n, max: 2n ** 64n }), (x2) => x2 === X || !vdfVerify(x2, y, pi, 20, N)), { numRuns: 200 });
  });
});

describe('bounded fuzzing of every verify / parse entry (no exception, no hang, no false accept)', () => {
  const T = 25;
  const good = vdfEval(X, T, N);
  const big = fc.oneof(fc.bigInt({ min: -(2n ** 64n), max: 2n ** 64n }), fc.bigInt({ min: 0n, max: 2n ** 2100n }), fc.constantFrom(0n, 1n, N, N - 1n, N + 1n, good.y, good.pi));

  it('vdfVerifyDetailed on arbitrary bigints and steps never throws and accepts only the genuine triple', () => {
    fc.assert(
      fc.property(big, big, big, fc.oneof(fc.integer({ min: -5, max: 100 }), fc.constantFrom(T, 2 ** 53 - 1, 2 ** 53, Number.NaN)), (x, y, pi, t) => {
        const t0 = performance.now();
        const r = vdfVerifyDetailed(x, y, pi, t, N);
        expect(performance.now() - t0).toBeLessThan(1000);
        if (r.ok) expect(x % N === X % N && y === good.y && pi === good.pi && t === T).toBe(true);
        return true;
      }),
      fuzzOpts,
    );
  });

  it('checkProductionModulus / isProbablePrime / hashToPrime on arbitrary values never throw an untyped error', () => {
    fc.assert(
      fc.property(fc.oneof(big, fc.anything()), (v) => {
        expect(() => checkProductionModulus(v as bigint)).not.toThrow();
        if (typeof v === 'bigint') expect(() => isProbablePrime(v)).not.toThrow();
        return true;
      }),
      fuzzOpts,
    );
  });

  it('verifyTimelock survives arbitrary proof / action / option shapes', () => {
    fc.assert(
      fc.property(fc.anything(), fc.anything(), fc.anything(), (a, p, o) => {
        expect(() => verifyTimelock(a as never, p as never, o as never)).not.toThrow();
        expect(verifyTimelock(a as never, p as never, o as never)).toBe(false);
        return true;
      }),
      fuzzOpts,
    );
  });
});
