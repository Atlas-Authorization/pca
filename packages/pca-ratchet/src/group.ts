import { RistrettoPoint, ed25519 } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha2';
import { randomBytes } from '@noble/hashes/utils';
import { b64u, unb64u } from '@atlasauth/pca';

/**
 * Prime-order group layer for the homomorphic risk accumulator (Mechanism 2).
 *
 * Group: ristretto255 (RFC 9496) via @noble/curves. It is a prime-order group of order
 * `L` (the ed25519 subgroup order), which is exactly what a Pedersen commitment / Schnorr
 * Sigma-protocol needs: no cofactor, every non-identity point generates the whole group,
 * and binding rests on the hardness of discrete log between the two independent generators.
 *
 *   G = RistrettoPoint.BASE                         (the standard generator)
 *   H = RistrettoPoint.hashToCurve(sha512(label))   ("nothing-up-my-sleeve": nobody knows
 *                                                     dlog_G(H), which is what makes the
 *                                                     commitment binding)
 *
 * All Pedersen/Schnorr arithmetic is done on bigint scalars reduced mod L.
 */

export type Point = InstanceType<typeof RistrettoPoint>;

/** Prime order of ristretto255 (= ed25519 subgroup order L). */
export const L: bigint = ed25519.CURVE.n;

/** The standard generator G. */
export const G: Point = RistrettoPoint.BASE;

/** The identity element (commitment to 0 with blinding 0). */
export const ZERO: Point = RistrettoPoint.ZERO;

const H_LABEL = 'atlas-pca-ratchet/pedersen-generator-H/v1';

/**
 * The second Pedersen generator H, derived by hash-to-group of a constant domain-separation
 * label — independent of G, and with an unknown discrete log relative to G (nobody chose it
 * with a known offset). Deterministic: the same label always yields the same H.
 */
export const H: Point = RistrettoPoint.hashToCurve(sha512(new TextEncoder().encode(H_LABEL)));

/** Reduce an integer into the scalar field [0, L). */
export function mod(x: bigint): bigint {
  const r = x % L;
  return r < 0n ? r + L : r;
}

export function scalarAdd(a: bigint, b: bigint): bigint {
  return mod(a + b);
}

export function scalarSub(a: bigint, b: bigint): bigint {
  return mod(a - b);
}

export function scalarMul(a: bigint, b: bigint): bigint {
  return mod(a * b);
}

/**
 * Scalar multiplication `k·P` that tolerates k ≡ 0 (mod L) by returning the identity —
 * @noble's `multiply` rejects 0 and values ≥ L, so we reduce first and special-case 0.
 */
export function mul(P: Point, k: bigint): Point {
  const s = mod(k);
  return s === 0n ? ZERO : P.multiply(s);
}

export function add(a: Point, b: Point): Point {
  return a.add(b);
}

export function sub(a: Point, b: Point): Point {
  return a.subtract(b);
}

/** A uniformly random non-zero scalar in [1, L). */
export function randScalar(): bigint {
  for (;;) {
    const s = mod(bytesToNumberLE(randomBytes(64)));
    if (s !== 0n) return s;
  }
}

// ---- little-endian scalar <-> bytes ---------------------------------------------------

export function numberToBytesLE(n: bigint, len: number): Uint8Array {
  if (n < 0n) throw new RangeError('numberToBytesLE: negative');
  const out = new Uint8Array(len);
  let x = n;
  for (let i = 0; i < len; i++) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  if (x !== 0n) throw new RangeError('numberToBytesLE: overflow');
  return out;
}

export function bytesToNumberLE(b: Uint8Array): bigint {
  let x = 0n;
  for (let i = b.length - 1; i >= 0; i--) {
    x = (x << 8n) | BigInt(b[i] ?? 0);
  }
  return x;
}

// ---- wire encoding (base64url, shared with @atlasauth/pca) ----------------------------

export function encodePoint(P: Point): string {
  return b64u(P.toRawBytes());
}

/** Decode a wire point; throws on a non-canonical / invalid ristretto encoding. */
export function decodePoint(s: string): Point {
  return RistrettoPoint.fromHex(unb64u(s));
}

export function encodeScalar(k: bigint): string {
  return b64u(numberToBytesLE(mod(k), 32));
}

export function decodeScalar(s: string): bigint {
  return mod(bytesToNumberLE(unb64u(s)));
}

// ---- Fiat-Shamir transcript -----------------------------------------------------------

/**
 * Length-prefixed concatenation so distinct part sequences can never collide (each part is
 * prefixed with its 4-byte big-endian length). The transcript is hashed with SHA-512 and the
 * digest reduced mod L to yield a challenge scalar.
 */
export function hashToScalar(parts: Uint8Array[]): bigint {
  let total = 0;
  for (const p of parts) total += 4 + p.length;
  const buf = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    buf[o] = (p.length >>> 24) & 0xff;
    buf[o + 1] = (p.length >>> 16) & 0xff;
    buf[o + 2] = (p.length >>> 8) & 0xff;
    buf[o + 3] = p.length & 0xff;
    o += 4;
    buf.set(p, o);
    o += p.length;
  }
  return mod(bytesToNumberLE(sha512(buf)));
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}
