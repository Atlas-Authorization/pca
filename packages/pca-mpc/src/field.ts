/**
 * Arithmetic in the prime field F_p used for additive secret sharing.
 *
 * p = 2^61 - 1 (the Mersenne prime M61). It is wider than any value the composition ever shares
 * (bits, thermometer bits, small sums), so no secret ever wraps; sharing randomness lives in the
 * full field so that any single share is (information-theoretically) uniform and independent of the
 * secret. All arithmetic is BigInt and exact — never floating point — so the protocol is
 * bit-deterministic and verifier-reproducible.
 *
 * RANDOMNESS (docs §7.1 item "CSPRNG — done"): the `FieldRng` below is a deterministic SplitMix64, kept
 * ONLY for bit-reproducible tests behind an explicit seed. It is NOT the default: the protocol draws
 * all sharing/triple/MAC randomness from the CSPRNG `SecureFieldRng` / `secureOtRandom` in `csprng.ts`
 * (`node:crypto.randomBytes`) unless a test explicitly asks for the seeded stream. `SecureFieldRng`
 * extends this class and overrides `next()`, so it is a drop-in wherever a `FieldRng` is accepted.
 */

export const PRIME = 2n ** 61n - 1n;

const MASK64 = (1n << 64n) - 1n;

/** Canonical representative in [0, p). */
export function mod(x: bigint): bigint {
  const r = x % PRIME;
  return r >= 0n ? r : r + PRIME;
}

export const fadd = (a: bigint, b: bigint): bigint => mod(a + b);
export const fsub = (a: bigint, b: bigint): bigint => mod(a - b);
export const fmul = (a: bigint, b: bigint): bigint => mod(a * b);
export const fneg = (a: bigint): bigint => mod(-a);

/**
 * Deterministic SplitMix64, drawing UNBIASED field elements by rejection sampling (reject the top
 * 2^64 mod p = 8 residues so the modulo is exactly uniform). Deterministic for reproducible tests;
 * see the security note above for production.
 */
export class FieldRng {
  private s: bigint;

  constructor(seed: bigint = 0x243f6a8885a308d3n) {
    this.s = seed & MASK64;
  }

  private nextU64(): bigint {
    this.s = (this.s + 0x9e3779b97f4a7c15n) & MASK64;
    let z = this.s;
    z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & MASK64;
    z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & MASK64;
    z = (z ^ (z >> 31n)) & MASK64;
    return z;
  }

  /** Uniform element of F_p (unbiased). */
  next(): bigint {
    // Largest multiple of p that fits in 64 bits; drop anything at or above it so `% PRIME` is uniform.
    const limit = ((MASK64 + 1n) / PRIME) * PRIME;
    for (;;) {
      const u = this.nextU64();
      if (u < limit) return u % PRIME;
    }
  }
}
