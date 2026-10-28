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
 * Group placement (type-3 / asymmetric pairing `e: G1 x G2 -> GT`), see `abe.ts` for the scheme:
 *   - the attribute hash `H(attr)` lives in G1 (hash-to-curve),
 *   - user-key components D, D_j live in G1 and D'_j in G2,
 *   - ciphertext components C_0 and C_x live in G2 and C'_x in G1,
 *   - the blinding value e(g1,g2)^alpha and every recovered quantity live in GT.
 */

/** Curve subgroup (scalar field) order r — a 255-bit prime, so every scalar fits in 32 bytes. */
export const R: bigint = bls12_381.params.r;

const Fr = bls12_381.fields.Fr;
const Fp = bls12_381.fields.Fp;
const Fp12 = bls12_381.fields.Fp12;

/** Domain-separation tag for hashing an attribute string to a point in G1 (RFC 9380 SSWU_RO). */
const ATTR_DST = 'ATLAS-PCA-ABE:FAME:H-G1:SHA256-SSWU-RO:v1';

/** The fixed G1 generator the whole system is parameterised over. */
export const G1_BASE = bls12_381.G1.ProjectivePoint.BASE;

/** The fixed G2 generator the whole system is parameterised over. */
export const G2_BASE = bls12_381.G2.ProjectivePoint.BASE;

export type G1Point = ReturnType<typeof bls12_381.G1.ProjectivePoint.fromAffine>;
export type GtElement = ReturnType<typeof bls12_381.pairing>;
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

/** True iff `s` contains an unpaired UTF-16 surrogate (such strings alias each other once UTF-8 encoded). */
export function isIllFormedUtf16(s: string): boolean {
  return /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(s);
}

/**
 * Hash an attribute string to its identity point `Q_attr` in G1 (prime-order subgroup, RO model).
 * Throws on ill-formed UTF-16: `TextEncoder` maps every lone surrogate to U+FFFD, so two different JS strings
 * would otherwise hash to the SAME identity and a key issued for one would open ciphertexts for the other.
 */
export function hashAttrToG1(attr: string): G1Point {
  if (isIllFormedUtf16(attr)) throw new RangeError('attribute is not well-formed UTF-16');
  return hashToG1(new TextEncoder().encode(attr));
}

/** RFC 9380 hash-to-curve of arbitrary bytes into G1 under the package's domain-separation tag (a random oracle). */
export function hashToG1(msg: Uint8Array): G1Point {
  const h = bls12_381.G1.hashToCurve(msg, { DST: ATTR_DST });
  // Normalise the hash-to-curve result into a ProjectivePoint so the full (de)serialisation API is available.
  return bls12_381.G1.ProjectivePoint.fromAffine(h.toAffine());
}

/** The G1 identity (sums of terms whose coefficient is 0 need it; `multiply` refuses a zero scalar). */
export const G1_ZERO = bls12_381.G1.ProjectivePoint.ZERO;

/** Scalar-multiply a G1 point. */
export function g1Mul(p: G1Point, k: bigint): G1Point {
  return p.multiply(Fr.create(k));
}

/** Like {@link g1Mul} but a scalar that is 0 mod r gives the identity instead of throwing. */
export function g1MulZ(p: G1Point, k: bigint): G1Point {
  const c = Fr.create(k);
  return c === 0n ? G1_ZERO : p.multiply(c);
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

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return d === 0;
}

/**
 * Parse a G1 point; null (never throws) on any malformed / off-curve / wrong-subgroup input AND on the point at
 * infinity (no honest key, ephemeral or public element is ever the identity, and pairing with it is undefined).
 */
export function g1FromBytes(bytes: Uint8Array): G1Point | null {
  try {
    const p = bls12_381.G1.ProjectivePoint.fromHex(bytes);
    p.assertValidity();
    if (p.equals(bls12_381.G1.ProjectivePoint.ZERO)) return null;
    if (!bytesEqual(p.toRawBytes(true), bytes)) return null; // strict: only the canonical compressed encoding
    return p;
  } catch {
    return null;
  }
}

/** Parse a G2 point; null (never throws) on any malformed / off-curve / wrong-subgroup / identity input. */
export function g2FromBytes(bytes: Uint8Array): G2Point | null {
  try {
    const p = bls12_381.G2.ProjectivePoint.fromHex(bytes);
    p.assertValidity();
    if (p.equals(bls12_381.G2.ProjectivePoint.ZERO)) return null;
    if (!bytesEqual(p.toRawBytes(true), bytes)) return null; // strict: only the canonical compressed encoding
    return p;
  } catch {
    return null;
  }
}

// ---- pairing / GT ---------------------------------------------------------------------------

/** The (final-exponentiated) ate pairing `e(P, Q)` in GT. */
export function pairing(p: G1Point, q: G2Point): GtElement {
  return bls12_381.pairing(p, q, true);
}

/** Raise a GT element to a scalar power. */
export function gtPow(gt: GtElement, k: bigint): GtElement {
  return Fp12.pow(gt, Fr.create(k));
}

/** Product of pairings `prod e(P_i, Q_i)` with ONE shared final exponentiation (a multi-Miller loop). Throws on an identity point. */
export function pairingProduct(pairs: readonly { g1: G1Point; g2: G2Point }[]): GtElement {
  return bls12_381.pairingBatch([...pairs], true);
}

export function gtEql(a: GtElement, b: GtElement): boolean {
  return Fp12.eql(a, b);
}

/**
 * Parse a GT element (576 bytes). Null unless the bytes are the canonical encoding of an element of the
 * prime-order subgroup GT (x^r = 1) other than the identity.
 */
export function gtFromBytes(bytes: Uint8Array): GtElement | null {
  if (bytes.length !== 576) return null;
  // @noble's Fp12.fromBytes does NOT reduce coordinates: a coordinate c + p parses as a distinct, structurally
  // unequal value that still behaves as c in arithmetic (so 1 + p would slip past the identity test below) and
  // re-serialises to the same unreduced bytes (so the round-trip check cannot see it). Require every Fp coordinate < p.
  for (let off = 0; off < 576; off += 48) if (bytesToNumberBE(bytes.subarray(off, off + 48)) >= Fp.ORDER) return null;
  try {
    const x = Fp12.fromBytes(bytes);
    if (Fp12.eql(x, Fp12.ONE)) return null;
    if (!Fp12.eql(Fp12.pow(x, R), Fp12.ONE)) return null;
    if (!bytesEqual(Fp12.toBytes(x), bytes)) return null;
    return x;
  } catch {
    return null;
  }
}

/** Canonical byte serialisation of a GT element (576 bytes) — the secret material fed into the KDF. */
export function gtToBytes(gt: GtElement): Uint8Array {
  return Fp12.toBytes(gt);
}

// ---- symmetric KDF --------------------------------------------------------------------------

/** HKDF-SHA256 to exactly 32 bytes, with explicit salt + info domain separation. */
export function kdf32(ikm: Uint8Array, salt: Uint8Array, info: string): Uint8Array {
  return hkdf(sha256, ikm, salt, new TextEncoder().encode(info), 32);
}
