/** Canonical-encoding audit: every point in a BBS signature/proof/public key has one accepted encoding. */
import { describe, expect, it } from 'vitest';
import { generateKeyPair, proofGen, proofVerify, sign, verify } from './bbs';

const T = new TextEncoder();
const m = [T.encode('a'), T.encode('b')];
const h = new Uint8Array(0);
const mutate = (b: Uint8Array, i: number, f: (x: number) => number): Uint8Array => {
  const c = b.slice();
  c[i] = f(c[i]!);
  return c;
};

describe('BBS: non-canonical point encodings are rejected', () => {
  const { sk, pk } = generateKeyPair();
  const sig = sign(sk, pk, h, m);
  const proof = proofGen(pk, sig, h, h, m, [0]);
  it('baseline verifies', () => {
    expect(verify(pk, sig, h, m)).toBe(true);
    expect(proofVerify(pk, proof, h, h, [m[0]!], [0])).toBe(true);
  });
  it('cleared compression flag / infinity flag on the signature point', () => {
    expect(verify(pk, mutate(sig, 0, (x) => x & 0x7f), h, m)).toBe(false);
    expect(verify(pk, mutate(sig, 0, (x) => x | 0x40), h, m)).toBe(false);
  });
  it('cleared compression flag on the G2 public key', () => {
    expect(verify(mutate(pk, 0, (x) => x & 0x7f), sig, h, m)).toBe(false);
  });
  it('cleared compression flag on each of the three proof points', () => {
    for (const o of [0, 48, 96]) expect(proofVerify(pk, mutate(proof, o, (x) => x & 0x7f), h, h, [m[0]!], [0])).toBe(false);
  });
});
