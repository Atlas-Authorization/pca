/**
 * Secure MULTIPLICATION of two additively-shared values via Beaver triples.
 *
 * Additive sharing gives addition and public-scalar ops for free, but NOT multiplication (the
 * product of two secrets is quadratic in the shares and has no local form). Beaver's trick turns one
 * multiplication into two PUBLIC openings plus local arithmetic, using a pre-shared random triple
 * (a, b, c=a*b):
 *
 *   x*y = (d+a)(e+b) = d*e + d*b + e*a + a*b     where d = x-a, e = y-b
 *
 * The parties open d and e (reconstruct them in the clear). Because a and b are uniform and secret,
 * d = x-a and e = y-b are uniform masks that reveal NOTHING about x or y. Given public d, e each
 * party then forms its share of the product locally:
 *
 *   z_i = c_i + d*b_i + e*a_i     (and party 0 additionally adds the public term d*e)
 *
 * so Σ z_i = c + d*b + e*a + d*e = a*b + d*b + e*a + d*e = x*y.
 *
 * PREPROCESSING MODEL (prototype): a TRUSTED DEALER generates the triples and shares them. This is a
 * standard and legitimate semi-honest preprocessing choice; the correctness/privacy of the ONLINE
 * phase (what the parties exchange) does not depend on the dealer beyond "the triples are correct and
 * the a,b stay secret." A production system removes the trusted dealer with an offline triple
 * generation protocol (OT-based or homomorphic-encryption-based), and adds MACs (SPDZ) for malicious
 * security. See the design doc.
 */

import { FieldRng, fadd, fmul } from './field';
import { reconstruct, subSV, type SharedValue } from './sharing';
import { share } from './sharing';

/** A Beaver multiplication triple, each component additively shared across the N parties. */
export interface Triple {
  a: SharedValue;
  b: SharedValue;
  c: SharedValue; // c = a*b
}

/** One opened (reconstructed, public) protocol message. `shares` are the per-party broadcasts. */
export interface OpenedMsg {
  label: 'd' | 'e';
  value: bigint;
  shares: bigint[];
}

/** Trusted-dealer preprocessing: generate `count` correct multiplication triples for `n` parties. */
export function genTriples(count: number, n: number, rng: FieldRng): Triple[] {
  const triples: Triple[] = [];
  for (let i = 0; i < count; i++) triples.push(genTriple(n, rng));
  return triples;
}

/** Trusted-dealer preprocessing: one correct triple (a, b, c=a*b), each component shared. */
export function genTriple(n: number, rng: FieldRng): Triple {
  const a = rng.next();
  const b = rng.next();
  const c = fmul(a, b);
  return { a: share(a, n, rng), b: share(b, n, rng), c: share(c, n, rng) };
}

/**
 * Secure multiply: returns a sharing of x*y, consuming `triple`. Every opened value (d, e) is pushed
 * to `transcript` when provided — that transcript IS the adversary's view of the online messages, and
 * the privacy tests assert it reveals nothing about the inputs.
 */
export function beaverMul(
  x: SharedValue,
  y: SharedValue,
  triple: Triple,
  transcript?: OpenedMsg[],
): SharedValue {
  if (x.length !== y.length) throw new Error('beaverMul: operand party counts differ');
  const dShares = subSV(x, triple.a);
  const eShares = subSV(y, triple.b);
  const d = reconstruct(dShares);
  const e = reconstruct(eShares);
  if (transcript) {
    transcript.push({ label: 'd', value: d, shares: dShares });
    transcript.push({ label: 'e', value: e, shares: eShares });
  }
  const de = fmul(d, e);
  return triple.c.map((ci, i) => {
    let zi = fadd(ci, fadd(fmul(d, triple.b[i]!), fmul(e, triple.a[i]!)));
    if (i === 0) zi = fadd(zi, de); // the public d*e term lives on exactly one party
    return zi;
  });
}
