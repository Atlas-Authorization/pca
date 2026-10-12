/**
 * Round-2: the ledger claims that @noble/curves' decoders already enforce on-curve / subgroup / canonical form
 * ("fromHex asserts validity and subgroup"). These inputs test the claims directly through the package parsers:
 * an on-curve point OUTSIDE the prime-order subgroup, and GT inputs of other lengths, must all be refused.
 */
import { bls12_381 } from '@noble/curves/bls12-381';
import { describe, expect, it } from 'vitest';
import { g1FromBytes, g2FromBytes, gtFromBytes, gtToBytes, pairing, G1_BASE, G2_BASE } from './bls';

const Fp = bls12_381.fields.Fp;
const Fp2 = bls12_381.fields.Fp2;
const P = Fp.ORDER;
const be48 = (v: bigint): Uint8Array => { const b = new Uint8Array(48); for (let i = 47; i >= 0; i--, v >>= 8n) b[i] = Number(v & 0xffn); return b; };

/** Compressed ZCash encoding of an affine G1 curve point, written by hand (noble's toRawBytes would assert validity). */
function encG1(x: bigint, y: bigint): Uint8Array {
  const b = be48(x);
  b[0]! |= 0x80 | (y > P - y ? 0x20 : 0);
  return b;
}
function encG2(x: { c0: bigint; c1: bigint }, y: { c0: bigint; c1: bigint }): Uint8Array {
  const out = new Uint8Array(96);
  out.set(be48(x.c1), 0);
  out.set(be48(x.c0), 48);
  const big = y.c1 !== 0n ? y.c1 > P - y.c1 : y.c0 > P - y.c0;
  out[0]! |= 0x80 | (big ? 0x20 : 0);
  return out;
}

describe('r2: library-claim probes (BLS12-381)', () => {
  it('an on-curve G1 point outside the prime-order subgroup is refused', () => {
    let tested = 0;
    for (let x = 1n; x < 400n && tested < 3; x++) {
      const rhs = Fp.add(Fp.mul(Fp.mul(x, x), x), 4n);
      let y: bigint;
      try { y = Fp.sqrt(rhs); } catch { continue; }
      if (Fp.mul(y, y) !== rhs) continue;
      const pt = bls12_381.G1.ProjectivePoint.fromAffine({ x, y });
      if (pt.isTorsionFree()) continue;
      expect(g1FromBytes(encG1(x, y))).toBeNull();
      tested++;
    }
    expect(tested).toBeGreaterThan(0);
  });
  it('an on-curve G2 point outside the prime-order subgroup is refused', () => {
    const b2 = Fp2.mul(Fp2.fromBigTuple([4n, 4n]), Fp2.ONE);
    let tested = 0;
    for (let k = 1n; k < 400n && tested < 2; k++) {
      const x = Fp2.fromBigTuple([k, 1n]);
      const rhs = Fp2.add(Fp2.mul(Fp2.mul(x, x), x), b2);
      let y;
      try { y = Fp2.sqrt(rhs); } catch { continue; }
      if (!Fp2.eql(Fp2.mul(y, y), rhs)) continue;
      const pt = bls12_381.G2.ProjectivePoint.fromAffine({ x, y });
      if (pt.isTorsionFree()) continue;
      expect(g2FromBytes(encG2(x, y))).toBeNull();
      tested++;
    }
    expect(tested).toBeGreaterThan(0);
  });
  it('GT parsing refuses every length other than 576, including 48-aligned ones', () => {
    const good = gtToBytes(pairing(G1_BASE, G2_BASE));
    for (const b of [good.subarray(0, 528), Uint8Array.from([...good, ...new Uint8Array(48)]), Uint8Array.from([...good, 0]), new Uint8Array(0)]) {
      expect(gtFromBytes(b)).toBeNull();
    }
  });
});
