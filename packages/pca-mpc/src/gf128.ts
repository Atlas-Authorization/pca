/**
 * GF(2^128) arithmetic — the field the KOS correlation check lives in (`ot.ts`).
 *
 * The malicious-secure OT-extension consistency check (KOS) folds every row of the extension matrix
 * into a single random linear combination over GF(2^κ) with κ = 128, and verifies one field equation.
 * A cheating receiver who deviates in the extension matrix passes that equation with probability at
 * most `2^{-128}` (the field size), which is what upgrades IKNP from semi-honest to malicious-secure.
 *
 * We use the standard GF(2^128) with reduction polynomial `x^128 + x^7 + x^2 + x + 1` (the GCM /
 * "0x87" polynomial). Elements are 128-bit `bigint`s, bit `i` = coefficient of `x^i`. Addition is XOR.
 * Multiplication is schoolbook carryless multiply with reduction; `mulByXi` (multiply by `x^i`) is the
 * repeated-shift form used by the column-domain check so the hot path pays no full 128×128 multiply
 * per row. This is a textbook field (BigInt, not constant-time) — sound for the in-process prototype;
 * see docs §7.1 for the constant-time boundary.
 */

/** 128-bit mask. */
const MASK128 = (1n << 128n) - 1n;

/**
 * The reduction tail for `x^128 + x^7 + x^2 + x + 1`: when a shift pushes a 1 past bit 127, we have
 * `x^128 ≡ x^7 + x^2 + x + 1 = 0x87`, so we XOR `0x87` back in.
 */
const GF128_RED = (1n << 7n) | (1n << 2n) | (1n << 1n) | 1n; // 0x87

/** Field addition in GF(2^128): XOR (masked to 128 bits). */
export function gf128Add(a: bigint, b: bigint): bigint {
  return (a ^ b) & MASK128;
}

/** Multiply by `x` (one step of the LFSR): shift left 1, reduce if it overflowed bit 127. */
export function gf128MulX(v: bigint): bigint {
  const carry = (v >> 127n) & 1n;
  let r = (v << 1n) & MASK128;
  if (carry) r ^= GF128_RED;
  return r;
}

/** Multiply by `x^i` (i ≥ 0): i LFSR steps. Used by the column-domain KOS fold. */
export function gf128MulByXi(v: bigint, i: number): bigint {
  let r = v & MASK128;
  for (let k = 0; k < i; k++) r = gf128MulX(r);
  return r;
}

/** Full GF(2^128) multiplication (carryless multiply + reduction), right-to-left over the bits of `b`. */
export function gf128Mul(a: bigint, b: bigint): bigint {
  let res = 0n;
  let v = a & MASK128;
  for (let i = 0; i < 128; i++) {
    if ((b >> BigInt(i)) & 1n) res ^= v;
    v = gf128MulX(v);
  }
  return res & MASK128;
}
