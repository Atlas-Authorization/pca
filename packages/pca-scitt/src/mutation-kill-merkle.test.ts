/** Exhaustive RFC 9162 Merkle tests: every (size, index) inclusion proof and every (first, second) consistency proof for small trees,
 *  each checked against all the wrong claims (so every boundary comparison and loop bound in the verifiers is pinned). */
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  consistencyPath,
  emptyRoot,
  inclusionPath,
  leafHash,
  nodeHash,
  rootFromInclusionPath,
  treeHash,
  verifyConsistencyPath,
  verifyInclusionPath,
} from './rfc9162';

const hex = (u: Uint8Array | null) => (u === null ? null : Buffer.from(u).toString('hex'));
const sha = (...p: Uint8Array[]) => {
  const h = createHash('sha256');
  for (const x of p) h.update(x);
  return new Uint8Array(h.digest());
};
const entries = (n: number) => Array.from({ length: n }, (_, i) => new TextEncoder().encode(`entry-${i}`));
const leaves = (n: number) => entries(n).map(leafHash);
/** Independent reference of RFC 6962 MTH using the "largest power of two strictly less than n" rule. */
function mth(l: Uint8Array[]): Uint8Array {
  if (l.length === 0) return sha();
  if (l.length === 1) return l[0] as Uint8Array;
  let k = 1;
  while (k * 2 < l.length) k *= 2;
  return sha(Uint8Array.of(1), mth(l.slice(0, k)), mth(l.slice(k)));
}

describe('hash primitives', () => {
  it('domain separation and known values', () => {
    expect(hex(emptyRoot())).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(hex(leafHash(new Uint8Array(0)))).toBe('6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d');
    const a = leafHash(Uint8Array.of(1));
    const b = leafHash(Uint8Array.of(2));
    expect(hex(leafHash(Uint8Array.of(1)))).toBe(hex(sha(Uint8Array.of(0), Uint8Array.of(1))));
    expect(hex(nodeHash(a, b))).toBe(hex(sha(Uint8Array.of(1), a, b)));
    expect(hex(nodeHash(a, b))).not.toBe(hex(nodeHash(b, a)));
  });
  it('treeHash matches the reference for 0..70 leaves', () => {
    expect(hex(treeHash([]))).toBe(hex(emptyRoot()));
    for (let n = 1; n <= 70; n++) expect(hex(treeHash(leaves(n)))).toBe(hex(mth(leaves(n))));
  });
  it('RFC 6962 / CT test-vector roots (leaves "", 00, 10, 2021, 3031, 40414243, ...)', () => {
    const d = ['', '00', '10', '2021', '3031', '40414243', '5051525354555657', '606162636465666768696a6b6c6d6e6f'].map((h) => leafHash(Buffer.from(h, 'hex')));
    const want = [
      '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
      'fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125',
      'aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77',
      'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
      '4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4',
      '76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef',
      'ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c',
      '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328',
    ];
    for (let n = 1; n <= 8; n++) expect(hex(treeHash(d.slice(0, n)))).toBe(want[n - 1]);
  });
});

/** Independent recursive reference for the RFC 9162 audit-path reconstruction (null when the path length does not fit the shape). */
function refInclusionRoot(leaf: Uint8Array, i: number, n: number, path: readonly Uint8Array[]): Uint8Array | null {
  if (n === 1) return path.length === 0 && i === 0 ? leaf : null;
  if (path.length === 0) return null;
  let k = 1;
  while (k * 2 < n) k *= 2;
  const sib = path[path.length - 1] as Uint8Array;
  const rest = path.slice(0, -1);
  if (i < k) {
    const sub = refInclusionRoot(leaf, i, k, rest);
    return sub === null ? null : sha(Uint8Array.of(1), sub, sib);
  }
  const sub = refInclusionRoot(leaf, i - k, n - k, rest);
  return sub === null ? null : sha(Uint8Array.of(1), sib, sub);
}

describe('inclusion proofs (exhaustive up to 17 leaves)', () => {
  const MAXN = 17;
  const L = leaves(MAXN + 1);
  it('generate + verify, differential against a recursive reference for every (index, size) claim', () => {
    for (let n = 1; n <= MAXN; n++) {
      const ls = L.slice(0, n);
      const root = treeHash(ls);
      for (let i = 0; i < n; i++) {
        const leaf = ls[i] as Uint8Array;
        const p = inclusionPath(ls, i);
        expect(hex(rootFromInclusionPath(leaf, i, n, p))).toBe(hex(root));
        expect(verifyInclusionPath(leaf, i, n, p, root)).toBe(true);
        expect(verifyInclusionPath(L[(i + 1) % (MAXN + 1)] as Uint8Array, i, n, p, root)).toBe(false);
        expect(verifyInclusionPath(leaf, i, n, p, treeHash(L.slice(0, n + 1)))).toBe(false);
        for (let j = 0; j < p.length; j++) {
          const bad = p.map((x, k) => (k === j ? Uint8Array.from(x, (v, q) => (q === 0 ? v ^ 1 : v)) : x));
          expect(verifyInclusionPath(leaf, i, n, bad, root)).toBe(false);
        }
        for (const variant of [p.slice(1), p.slice(0, -1), [...p, L[0] as Uint8Array], [L[0] as Uint8Array, ...p], [...p].reverse()]) {
          for (let n2 = 1; n2 <= MAXN; n2++) {
            for (let i2 = 0; i2 < n2; i2++) {
              const got = rootFromInclusionPath(leaf, i2, n2, variant);
              const want = refInclusionRoot(leaf, i2, n2, variant);
              expect(hex(got)).toBe(hex(want));
            }
          }
        }
        for (let n2 = 1; n2 <= MAXN; n2++) {
          for (let i2 = 0; i2 < n2; i2++) {
            const got = rootFromInclusionPath(leaf, i2, n2, p);
            expect(hex(got)).toBe(hex(refInclusionRoot(leaf, i2, n2, p)));
            if (n2 !== n || i2 !== i) expect(verifyInclusionPath(leaf, i2, n2, p, treeHash(L.slice(0, n2)))).toBe(false);
          }
        }
      }
    }
  });
  it('out-of-range and malformed arguments return null / throw RangeError', () => {
    const l = leaves(5);
    const p = inclusionPath(l, 2);
    for (const [idx, size] of [[-1, 5], [5, 5], [6, 5], [0, 0], [0, -1], [1.5, 5], [2, 5.5], [NaN, 5], [2, NaN], [Infinity, 5], [2, Infinity], [2 ** 53, 5], [2, 2 ** 53]] as [number, number][]) {
      expect(rootFromInclusionPath(l[2]!, idx, size, p)).toBeNull();
      expect(verifyInclusionPath(l[2]!, idx, size, p, treeHash(l))).toBe(false);
    }
    expect(rootFromInclusionPath(l[0]!, 0, 1, [])).not.toBeNull();
    expect(rootFromInclusionPath(l[0]!, 0, 1, [])).toStrictEqual(l[0]);
    expect(rootFromInclusionPath(l[2]!.slice(1), 2, 5, p)).toBeNull();
    expect(rootFromInclusionPath(new Uint8Array(33), 2, 5, p)).toBeNull();
    expect(rootFromInclusionPath(l[2]!, 2, 5, [p[0]!.slice(1), ...p.slice(1)])).toBeNull();
    expect(rootFromInclusionPath(l[2]!, 2, 5, [...p.slice(0, -1), new Uint8Array(33)])).toBeNull();
    expect(rootFromInclusionPath(l[2]!, 2, 5, p.map(() => new Uint8Array(0)))).toBeNull();
    // root of the wrong length never matches even when it extends the right one
    const root = treeHash(l);
    expect(verifyInclusionPath(l[2]!, 2, 5, p, Uint8Array.of(...root, 0))).toBe(false);
    expect(verifyInclusionPath(l[2]!, 2, 5, p, root.slice(0, 31))).toBe(false);
    const two = Uint8Array.from(root);
    two[31] = (two[31] ?? 0) ^ 1;
    expect(verifyInclusionPath(l[2]!, 2, 5, p, two)).toBe(false);
    for (const [leaves_, idx] of [[l, -1], [l, 5], [l, 1.5], [l, NaN], [[], 0], [l, 2 ** 53]] as [Uint8Array[], number][]) {
      expect(() => inclusionPath(leaves_, idx)).toThrow('rfc9162: leaf index out of range');
    }
    expect(inclusionPath([l[0]!], 0)).toStrictEqual([]);
    expect(inclusionPath(l, 4).length).toBe(1);
  });
});

describe('consistency proofs (exhaustive up to 17 leaves)', () => {
  const MAXN = 17;
  const L = leaves(MAXN);
  const R = (n: number) => treeHash(L.slice(0, n));
  const flip = (u: Uint8Array) => Uint8Array.from(u, (v, q) => (q === 0 ? v ^ 1 : v));
  it('generate + verify, and every wrong claim is refused', () => {
    for (let second = 1; second <= MAXN; second++) {
      for (let first = 1; first <= second; first++) {
        const p = consistencyPath(L.slice(0, second), first);
        expect(verifyConsistencyPath(first, second, R(first), R(second), p)).toBe(true);
        if (first === second) expect(p).toStrictEqual([]);
        expect(verifyConsistencyPath(first, second, flip(R(first)), R(second), p)).toBe(false);
        expect(verifyConsistencyPath(first, second, R(first), flip(R(second)), p)).toBe(false);
        expect(verifyConsistencyPath(first, second, R(second), R(first), p)).toBe(first === second);
        for (let j = 0; j < p.length; j++) expect(verifyConsistencyPath(first, second, R(first), R(second), p.map((x, k) => (k === j ? flip(x) : x)))).toBe(false);
        for (const variant of [p.slice(1), p.slice(0, -1), [...p, L[0] as Uint8Array], [L[0] as Uint8Array, ...p], [...p].reverse()]) {
          if (variant.length === p.length && variant.every((v, q) => hex(v) === hex(p[q] as Uint8Array))) continue;
          expect(verifyConsistencyPath(first, second, R(first), R(second), variant)).toBe(false);
        }
        for (let s2 = 1; s2 <= MAXN; s2++) {
          for (let f2 = 1; f2 <= s2; f2++) {
            if (f2 === first && s2 === second) continue;
            if (first === second && f2 === s2) continue; // the empty proof only says "equal roots", whatever the size
            if (verifyConsistencyPath(f2, s2, R(f2), R(s2), p)) throw new Error(`proof (${first},${second}) accepted as (${f2},${s2}) len=${p.length}`);
          }
        }
      }
    }
  });
  it('argument validation', () => {
    const l = leaves(8);
    const p = consistencyPath(l, 3);
    const r3 = treeHash(l.slice(0, 3));
    const r8 = treeHash(l);
    expect(verifyConsistencyPath(3, 8, r3, r8, p)).toBe(true);
    for (const [f, s] of [[0, 8], [-1, 8], [3.5, 8], [3, 8.5], [NaN, 8], [3, NaN], [9, 8], [3, 2 ** 53], [2 ** 53, 2 ** 53 + 1], [Infinity, Infinity]] as [number, number][]) {
      expect(verifyConsistencyPath(f, s, r3, r8, p)).toBe(false);
    }
    expect(verifyConsistencyPath(3, 8, r3.slice(1), r8, p)).toBe(false);
    expect(verifyConsistencyPath(3, 8, r3, r8.slice(1), p)).toBe(false);
    expect(verifyConsistencyPath(3, 8, Uint8Array.of(...r3, 0), r8, p)).toBe(false);
    expect(verifyConsistencyPath(3, 8, r3, Uint8Array.of(...r8, 0), p)).toBe(false);
    expect(verifyConsistencyPath(3, 8, r3, r8, [...p.slice(0, -1), p[p.length - 1]!.slice(1)])).toBe(false);
    expect(verifyConsistencyPath(3, 8, r3, r8, [p[0]!.slice(1), ...p.slice(1)])).toBe(false);
    expect(verifyConsistencyPath(3, 8, r3, r8, [])).toBe(false);
    expect(verifyConsistencyPath(8, 8, r8, r8, [])).toBe(true);
    expect(verifyConsistencyPath(8, 8, r8, r8, [r8])).toBe(false);
    expect(verifyConsistencyPath(8, 8, r3, r8, [])).toBe(false);
    expect(verifyConsistencyPath(1, 1, l[0]!, l[0]!, [])).toBe(true);
    expect(verifyConsistencyPath(1, 2, l[0]!, treeHash(l.slice(0, 2)), [l[1]!])).toBe(true);
    for (const m of [0, -1, 9, 1.5, NaN, 2 ** 53]) expect(() => consistencyPath(l, m)).toThrow('rfc9162: consistency size out of range');
    expect(() => consistencyPath([], 1)).toThrow('rfc9162: consistency size out of range');
    expect(consistencyPath(l, 8)).toStrictEqual([]);
    expect(consistencyPath(l, 1).length).toBe(3);
  });
});
