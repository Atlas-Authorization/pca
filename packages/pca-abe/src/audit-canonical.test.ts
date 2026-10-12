/**
 * Canonical-encoding regression: every G1/G2 element has exactly ONE accepted byte string
 * (compressed, flag set, round-trips). Found by the repo-wide canonical-encoding audit: the pinned
 * @noble/curves parser also accepted the uncompressed form of a valid point.
 */
import { describe, expect, it } from 'vitest';
import { bls12_381 as bls } from '@noble/curves/bls12-381';
import { g1FromBytes, g2FromBytes } from './bls';

const g1 = bls.G1.ProjectivePoint.BASE.multiply(7n);
const g2 = bls.G2.ProjectivePoint.BASE.multiply(7n);

describe('G1/G2 canonical encoding', () => {
  it('accepts the canonical compressed form', () => {
    expect(g1FromBytes(g1.toRawBytes(true))).not.toBeNull();
    expect(g2FromBytes(g2.toRawBytes(true))).not.toBeNull();
  });
  it('rejects the uncompressed alias of a valid point', () => {
    expect(g1FromBytes(g1.toRawBytes(false))).toBeNull();
    expect(g2FromBytes(g2.toRawBytes(false))).toBeNull();
  });
  it('rejects a cleared compression flag', () => {
    const a = g1.toRawBytes(true); a[0] = a[0]! & 0x7f;
    const b = g2.toRawBytes(true); b[0] = b[0]! & 0x7f;
    expect(g1FromBytes(a)).toBeNull();
    expect(g2FromBytes(b)).toBeNull();
  });
  it('rejects trailing/short bytes', () => {
    expect(g1FromBytes(new Uint8Array([...g1.toRawBytes(true), 0]))).toBeNull();
    expect(g2FromBytes(g2.toRawBytes(true).slice(0, 95))).toBeNull();
  });
});
