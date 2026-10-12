// R6-ALIAS-08: the zk binding tag reduces a 256-bit sha256 commitment mod the BN254 scalar field. This pins the facts the
// proof note in zk.ts relies on: the map is at most 6-to-1 and the only collisions are commitments k*r apart (|k| <= 5).
import { describe, expect, it } from 'vitest';
import { b64u } from './hash';
import { commitmentField } from './zk';

const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const toBytes = (x: bigint) => {
  const o = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) { o[i] = Number(x & 0xffn); x >>= 8n; }
  return o;
};
const tag = (x: bigint) => commitmentField(b64u(toBytes(x)));

describe('R6-ALIAS-08 zk binding tag', () => {
  it('2^256 = 5r + e with 0 < e < r: every residue has 5 or 6 preimages', () => {
    const e = 2n ** 256n - 5n * R;
    expect(e > 0n && e < R).toBe(true);
    expect(2n ** 253n < R && R < 2n ** 254n).toBe(true);
  });
  it('commitments k*r apart share a tag; that is the only aliasing (at most 6 per tag)', () => {
    const v = 123456789n;
    const preimages = [0n, 1n, 2n, 3n, 4n, 5n].map((k) => v + k * R).filter((x) => x < 2n ** 256n);
    expect(preimages.length).toBe(6); // v < e, so this residue has the maximal 6 preimages
    const tags = new Set(preimages.map(tag));
    expect(tags.size).toBe(1);
    expect(tag(v + 1n)).not.toBe(tag(v));
    expect(v + 6n * R >= 2n ** 256n).toBe(true); // no seventh preimage
  });
  it('the tag is a canonical decimal field element', () => {
    const t = tag(2n ** 256n - 1n);
    expect(BigInt(t) < R).toBe(true);
    expect(t).toBe(((2n ** 256n - 1n) % R).toString());
  });
});
