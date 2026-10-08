/**
 * Additive secret sharing over F_p for N parties (the semi-honest primitive).
 *
 * A secret v is split into N shares s_0..s_{N-1} with s_0+...+s_{N-1} = v (mod p). The first N-1
 * shares are drawn uniformly at random; the last is the complement v - Σ(others). Reconstruction is
 * the field sum of ALL N shares — any single missing share makes the sum a uniform field element,
 * which is why reconstruction is all-or-nothing (and why we fail CLOSED when a share is absent).
 *
 * Additive sharing is LINEAR for free: parties can add two sharings, or add/scale by a PUBLIC
 * constant, purely locally (no interaction). Only MULTIPLICATION of two secret-shared values needs
 * interaction — that is the Beaver-triple protocol in `beaver.ts`.
 */

import { FieldRng, fadd, fmul, fneg, mod } from './field';

/** A single party's share. */
export type Share = bigint;

/** A secret shared across N parties: `shares[i]` is held by party i. */
export type SharedValue = bigint[];

/** Split `secret` into `n` additive shares using `rng`. First n-1 uniform; last is the complement. */
export function share(secret: bigint, n: number, rng: FieldRng): SharedValue {
  if (!Number.isInteger(n) || n < 1) throw new Error('share: n must be a positive integer');
  const shares: bigint[] = [];
  let acc = 0n;
  for (let i = 0; i < n - 1; i++) {
    const s = rng.next();
    shares.push(s);
    acc = fadd(acc, s);
  }
  shares.push(fsubLocal(mod(secret), acc));
  return shares;
}

const fsubLocal = (a: bigint, b: bigint): bigint => fadd(a, fneg(b));

/**
 * Reconstruct the secret from ALL shares. Fails CLOSED: an empty vector, or any `undefined`
 * (missing) share, throws rather than returning a plausible-looking wrong value. A partial subset of
 * shares reconstructs to a uniform field element, never the secret, so partial reconstruction is
 * meaningless by design.
 */
export function reconstruct(shares: ReadonlyArray<bigint | undefined>): bigint {
  if (shares.length === 0) throw new Error('reconstruct: no shares (fail closed)');
  let acc = 0n;
  for (const s of shares) {
    if (s === undefined) throw new Error('reconstruct: missing share (fail closed)');
    acc = fadd(acc, s);
  }
  return acc;
}

/** Sharing of a PUBLIC constant: party 0 holds c, everyone else holds 0 (sums to c, no randomness). */
export function shareConstant(c: bigint, n: number): SharedValue {
  if (!Number.isInteger(n) || n < 1) throw new Error('shareConstant: n must be a positive integer');
  const out = new Array<bigint>(n).fill(0n);
  out[0] = mod(c);
  return out;
}

/** x + y, elementwise (local; no interaction). */
export function addSV(x: SharedValue, y: SharedValue): SharedValue {
  requireSameLength(x, y);
  return x.map((xi, i) => fadd(xi, y[i]!));
}

/** x - y, elementwise (local; no interaction). */
export function subSV(x: SharedValue, y: SharedValue): SharedValue {
  requireSameLength(x, y);
  return x.map((xi, i) => fsubLocal(xi, y[i]!));
}

/** -x, elementwise (local). */
export function negSV(x: SharedValue): SharedValue {
  return x.map((xi) => fneg(xi));
}

/** x * c for a PUBLIC scalar c (local). */
export function scaleSV(x: SharedValue, c: bigint): SharedValue {
  return x.map((xi) => fmul(xi, c));
}

/** x + c for a PUBLIC constant c: added to party 0's share only (local). Preserves the sum. */
export function addPublicSV(x: SharedValue, c: bigint): SharedValue {
  const out = x.slice();
  out[0] = fadd(out[0]!, mod(c));
  return out;
}

/** The logical complement of a shared BIT b: returns a sharing of (1 - b) (local). */
export function notBitSV(b: SharedValue): SharedValue {
  return addPublicSV(negSV(b), 1n);
}

function requireSameLength(x: SharedValue, y: SharedValue): void {
  if (x.length !== y.length) throw new Error('shared values must have the same party count');
}
