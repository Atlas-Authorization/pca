import { bls12_381 } from '@noble/curves/bls12-381';
import { bytesToNumberBE, numberToBytesBE } from '@noble/curves/abstract/utils';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from '@noble/hashes/utils';

/**
 * Low-level BLS12-381 helpers for the ABE scheme. All group/field work goes through `@noble/curves`'s
 * audited `bls12_381` implementation (G1/G2/GT, the ate pairing, RFC 9380 hash-to-curve); nothing here
 * re-implements field or point arithmetic.
 *
 * Group placement (type-3 / asymmetric pairing `e: G1 x G2 -> GT`):
 *   - attribute identity points `Q_attr = H1(attr)` live in G1 (hash-to-curve),
 *   - the master public `P_pub = s * g2` and ephemerals `U = x * g2` live in G2,
 *   - decryption keys `d_attr = s * Q_attr` live in G1,
 *   - KEM secrets live in GT.
 */

/** Curve subgroup (scalar field) order r — a 255-bit prime, so every scalar fits in 32 bytes. */
export const R: bigint = bls12_381.params.r;

const Fr = bls12_381.fields.Fr;
const Fp12 = bls12_381.fields.Fp12;

/** Domain-separation tag for hashing an attribute string to a point in G1 (RFC 9380 SSWU_RO). */
const ATTR_DST = 'ATLAS-PCA-ABE:BF-IBE:G1:SHA256-SSWU-RO:v1';

/** The fixed G2 generator the whole system is parameterised over. */
export const G2_BASE = bls12_381.G2.ProjectivePoint.BASE;

export type G1Point = ReturnType<typeof bls12_381.G1.ProjectivePoint.fromAffine>;
export type G2Point = ReturnType<typeof bls12_381.G2.ProjectivePoint.fromAffine>;

// ---- field scalars (Z_r) --------------------------------------------------------------------

/** Reduce a bigint into the canonical scalar field Z_r. */
export function frCreate(n: bigint): bigint {
  return Fr.create(n);
}

export function frAdd(a: bigint, b: bigint): bigint {
  return Fr.add(a, b);
}

export function frSub(a: bigint, b: bigint): bigint {
  return Fr.sub(a, b);
}

export function frMul(a: bigint, b: bigint): bigint {
  return Fr.mul(a, b);
}

export function frInv(a: bigint): bigint {
  return Fr.inv(a);
}

/** A uniformly random NON-ZERO scalar in Z_r (48 bytes of entropy reduced mod r — negligible bias). */
export function randomScalar(): bigint {
  for (;;) {
    const v = Fr.create(bytesToNumberBE(randomBytes(48)));
    if (v !== 0n) return v;
  }
}

/** Fixed 32-byte big-endian encoding of a scalar (r < 2^255, so 32 bytes always suffice). */
export function scalarToBytes(v: bigint): Uint8Array {
  return numberToBytesBE(Fr.create(v), 32);
}

/** Decode a 32-byte big-endian scalar back into Z_r. Returns null if not exactly 32 bytes. */
export function bytesToScalar(bytes: Uint8Array): bigint | null {
  if (bytes.length !== 32) return null;
  return Fr.create(bytesToNumberBE(bytes));
}

// ---- points ---------------------------------------------------------------------------------

/** Hash an attribute string to its identity point `Q_attr` in G1 (prime-order subgroup, RO model). */
export function hashAttrToG1(attr: string): G1Point {
  const msg = new TextEncoder().encode(attr);
  const h = bls12_381.G1.hashToCurve(msg, { DST: ATTR_DST });
  // Normalise the hash-to-curve result into a ProjectivePoint so the full (de)serialisation API is available.
  return bls12_381.G1.ProjectivePoint.fromAffine(h.toAffine());
}

/** Scalar-multiply a G1 point. */
export function g1Mul(p: G1Point, k: bigint): G1Point {
  return p.multiply(Fr.create(k));
}

/** Scalar-multiply a G2 point. */
export function g2Mul(p: G2Point, k: bigint): G2Point {
  return p.multiply(Fr.create(k));
}

/** Serialise a G1 point (compressed, 48 bytes). */
export function g1ToBytes(p: G1Point): Uint8Array {
  return p.toRawBytes(true);
}

/** Serialise a G2 point (compressed, 96 bytes). */
export function g2ToBytes(p: G2Point): Uint8Array {
  return p.toRawBytes(true);
}

/** Parse a compressed G1 point; null (never throws) on any malformed / off-curve / wrong-subgroup input. */
export function g1FromBytes(bytes: Uint8Array): G1Point | null {
  try {
    const p = bls12_381.G1.ProjectivePoint.fromHex(bytes);
    p.assertValidity();
    return p;
  } catch {
    return null;
  }
}

/** Parse a compressed G2 point; null (never throws) on any malformed / off-curve / wrong-subgroup input. */
export function g2FromBytes(bytes: Uint8Array): G2Point | null {
  try {
    const p = bls12_381.G2.ProjectivePoint.fromHex(bytes);
    p.assertValidity();
    return p;
  } catch {
    return null;
  }
}

// ---- pairing / GT ---------------------------------------------------------------------------

/** The (final-exponentiated) ate pairing `e(P, Q)` in GT. */
export function pairing(p: G1Point, q: G2Point): ReturnType<typeof bls12_381.pairing> {
  return bls12_381.pairing(p, q, true);
}

/** Raise a GT element to a scalar power. */
export function gtPow(gt: ReturnType<typeof bls12_381.pairing>, k: bigint): ReturnType<typeof bls12_381.pairing> {
  return Fp12.pow(gt, Fr.create(k));
}

/** Canonical byte serialisation of a GT element (576 bytes) — the KEM secret material fed into the KDF. */
export function gtToBytes(gt: ReturnType<typeof bls12_381.pairing>): Uint8Array {
  return Fp12.toBytes(gt);
}

// ---- symmetric KDF --------------------------------------------------------------------------

/** HKDF-SHA256 to exactly 32 bytes, with explicit salt + info domain separation. */
export function kdf32(ikm: Uint8Array, salt: Uint8Array, info: string): Uint8Array {
  return hkdf(sha256, ikm, salt, new TextEncoder().encode(info), 32);
}
