import { bls12_381 as bls } from '@noble/curves/bls12-381';
import { numberToBytesBE } from '@noble/curves/abstract/utils';
import type { AbeCiphertext, KemTree } from '../abe';

/** Test-only helpers for the adversarial suites. Never imported by library code. */

const Fp = bls.fields.Fp;
const Fp2 = bls.fields.Fp2;
const P = Fp.ORDER;
const HALF = (P - 1n) / 2n;

/** Compressed-G1 encoding of an arbitrary affine (x, y) WITHOUT any subgroup / validity check. */
export function g1CompressUnchecked(x: bigint, y: bigint): Uint8Array {
  const o = numberToBytesBE(x, 48);
  o[0] = (o[0] ?? 0) | 0x80 | (y > HALF ? 0x20 : 0);
  return o;
}

/** A point ON the G1 curve y^2 = x^3 + 4 that is NOT in the prime-order subgroup (a small-subgroup/cofactor point). */
export function g1OffSubgroup(): Uint8Array {
  for (let x = 1n; x < 1000n; x++) {
    const rhs = Fp.add(Fp.pow(x, 3n), 4n);
    let y: bigint;
    try {
      y = Fp.sqrt(rhs);
    } catch {
      continue;
    }
    if (Fp.mul(y, y) !== rhs) continue;
    const enc = g1CompressUnchecked(x, y);
    try {
      bls.G1.ProjectivePoint.fromHex(enc).assertValidity();
    } catch {
      return enc; // decodes onto the curve but is rejected by the subgroup check: exactly what we want
    }
  }
  throw new Error('no off-subgroup G1 point found');
}

/** Compressed-G2 encoding of an arbitrary affine (x, y) over Fp2 WITHOUT validity checks. */
export function g2CompressUnchecked(x: { c0: bigint; c1: bigint }, y: { c0: bigint; c1: bigint }): Uint8Array {
  const o = new Uint8Array(96);
  o.set(numberToBytesBE(x.c1, 48), 0);
  o.set(numberToBytesBE(x.c0, 48), 48);
  const big = y.c1 !== 0n ? y.c1 > HALF : y.c0 > HALF;
  o[0] = (o[0] ?? 0) | 0x80 | (big ? 0x20 : 0);
  return o;
}

/** A point on the G2 twist y^2 = x^3 + 4(1+i) that is NOT in the prime-order subgroup. */
export function g2OffSubgroup(): Uint8Array {
  for (let c = 1n; c < 1000n; c++) {
    const x = { c0: c, c1: 1n };
    const rhs = Fp2.add(Fp2.mul(Fp2.sqr(x), x), { c0: 4n, c1: 4n });
    let y: { c0: bigint; c1: bigint };
    try {
      y = Fp2.sqrt(rhs);
    } catch {
      continue;
    }
    if (!Fp2.eql(Fp2.sqr(y), rhs)) continue;
    const enc = g2CompressUnchecked(x, y);
    try {
      bls.G2.ProjectivePoint.fromHex(enc).assertValidity();
    } catch {
      return enc;
    }
  }
  throw new Error('no off-subgroup G2 point found');
}

/** Compressed G1 point-at-infinity (0xc0 then zeros). */
export function g1Infinity(): Uint8Array {
  const o = new Uint8Array(48);
  o[0] = 0xc0;
  return o;
}

/** Compressed G2 point-at-infinity. */
export function g2Infinity(): Uint8Array {
  const o = new Uint8Array(96);
  o[0] = 0xc0;
  return o;
}

export const b64 = (u: Uint8Array): string => Buffer.from(u).toString('base64url');

/** Deep-clone a ciphertext into a freely mutable plain object. */
export function clone(ct: AbeCiphertext): AbeCiphertext {
  return structuredClone(ct);
}

/** Every leaf (depth-first) of a KEM tree. */
export function leaves(t: KemTree): Extract<KemTree, { kind: 'leaf' }>[] {
  return t.kind === 'leaf' ? [t] : t.of.flatMap((b) => leaves(b.sub));
}

/** Flip one bit of a base64url string's decoded bytes and re-encode (always yields canonical base64url). */
export function flipBit(s: string, bit: number): string {
  const b = new Uint8Array(Buffer.from(s, 'base64url'));
  const i = Math.floor(bit / 8) % b.length;
  b[i] = (b[i] ?? 0) ^ (1 << bit % 8);
  return Buffer.from(b).toString('base64url');
}
