/**
 * Privacy-amplified OT choice bits (the MASCOT remedy for selective failure, RT-04).
 *
 * In Gilboa multiplication the OT RECEIVER chooses with the bits of its additive share x. A malicious SENDER
 * can corrupt chosen message pairs so that the result is wrong exactly when some predicate of those bits
 * holds; the sacrifice / MAC-check then aborts exactly when the predicate holds, and abort / no-abort leaks
 * the predicate (with plain binary choice bits: a bit of x itself).
 *
 * Remedy (Keller-Orsini-Scholl, MASCOT, CCS 2016, section 3.2): the receiver does NOT choose with the bits of x.
 * It draws `m = 61 + 3s` UNIFORM bits `b` and takes `x := <g, b> = sum_k g_k b_k (mod p)` for a PUBLIC
 * gadget vector `g` in F_p^m. The sender offers `(rho_k, rho_k + g_k y)`, so the receiver still obtains
 * `x*y + sum rho`. A predicate of the sender's choosing that holds with probability >= 2^-s fixes at most s bits
 * of entropy of `b`; the remaining `m - s >= 61 + 2s` bits make `<g, b>` statistically within 2^-s of uniform
 * (leftover hash lemma: the map b -> <g,b> is a universal hash into a 61-bit range). A predicate that holds with
 * probability < 2^-s is observed (no abort) with probability < 2^-s. Total advantage <= 1.5 * 2^-s per
 * attacked sharing; `s = 64` (default) gives about 2^-63 and costs `m = 253` OTs per multiplication instead of 61; `s < 40` is refused.
 *
 * `s = 0` (`m = 61`, `g_k = 2^k`) is the LEGACY encoding (plain binary); it is vulnerable and exists only so the
 * regression test can show the attack works against it.
 */

import { FieldRng, mod, PRIME } from './field';

/** Bits per field element: p = 2^61 - 1. */
export const FIELD_BITS = 61;
/** Default statistical security parameter for the OT choice-bit encoding (leakage bound about 2^-s). */
export const STAT_SEC = 64;
/** Smallest `s` accepted without the explicit unsafe test flag. */
export const MIN_STAT_SEC = 40;

/** Number of encoded choice bits for statistical parameter `s`: 61 + 3s (s = 0: legacy 61). */
export const encBits = (s: number): number => FIELD_BITS + 3 * s;

/** A receiver operand: its field value together with the choice bits that encode it. */
export interface EncShare {
  value: bigint;
  bits: number[];
}

/** The public gadget vector for parameter `s`: 2^k for s = 0, else m uniform field elements from `next`. */
export function makeGadget(s: number, next: () => bigint, unsafe = false): bigint[] {
  if (!Number.isInteger(s) || s < 0 || s > 64) throw new RangeError('statSec must be an integer in [0, 64]');
  if (s < MIN_STAT_SEC && !unsafe) {
    throw new RangeError(`statSec ${s} is below ${MIN_STAT_SEC}: refused (tests may pass the explicit unsafe flag)`);
  }
  const m = encBits(s);
  const g: bigint[] = new Array(m);
  for (let k = 0; k < m; k++) g[k] = s === 0 ? (1n << BigInt(k)) % PRIME : next();
  return g;
}

/** Evaluate <g, bits> in F_p. */
export function encValue(g: readonly bigint[], bits: readonly number[]): bigint {
  if (g.length !== bits.length) throw new RangeError('encValue: gadget / bits length mismatch');
  let v = 0n;
  for (let k = 0; k < g.length; k++) if (bits[k] === 1) v += g[k]!;
  return mod(v);
}

/** The plain binary encoding of an arbitrary field element (61 bits, weights 2^k). */
export function plainShare(x: bigint): EncShare {
  const v = mod(x);
  const bits: number[] = new Array(FIELD_BITS);
  for (let k = 0; k < FIELD_BITS; k++) bits[k] = Number((v >> BigInt(k)) & 1n);
  return { value: v, bits };
}

/** The weights of the plain binary encoding. */
export const PLAIN_GADGET: readonly bigint[] = Array.from({ length: FIELD_BITS }, (_, k) => (1n << BigInt(k)) % PRIME);

/** Draw `m` uniform bits from a field-element source (60 low bits of each draw are uniform). */
export function randomBits(m: number, rng: Pick<FieldRng, 'next'>): number[] {
  const out: number[] = new Array(m);
  let k = 0;
  while (k < m) {
    const w = rng.next();
    for (let i = 0; i < 60 && k < m; i++, k++) out[k] = Number((w >> BigInt(i)) & 1n);
  }
  return out;
}

/** A fresh uniform operand: uniform bits and the value they encode under `g`. */
export function sampleEnc(g: readonly bigint[], rng: Pick<FieldRng, 'next'>): EncShare {
  const bits = randomBits(g.length, rng);
  return { value: encValue(g, bits), bits };
}
