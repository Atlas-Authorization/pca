/* eslint-disable @typescript-eslint/no-explicit-any */
// Regression + mutation-kill tests for src/ext-merkle.ts, checked against production ledger.ts.
import { describe, expect, it } from 'vitest';
import { EMPTY_TREE_ROOT, verifyLedgerConsistency } from '../../pca/src/ledger';
import { createHash } from 'node:crypto';
import {
  b64uDecodeStrict,
  b64uEncode,
  consistencyProofVerified,
  inclusionProofVerified,
  inclusionRootVerified,
  merkleRootVerified,
  verifyConsistencyVerified,
  verifyInclusionVerified,
  verifyMembershipVerified,
} from '../src/ext-merkle';

const other = b64uEncode(new Uint8Array(32).fill(7));

describe('verifyConsistencyVerified: empty trees (RFC 9162 s2.1.4.1)', () => {
  const cases: Array<[string, string, number, number, string[]]> = [
    [EMPTY_TREE_ROOT, EMPTY_TREE_ROOT, 0, 0, []],
    [EMPTY_TREE_ROOT, other, 0, 0, []], // FINDING: glue accepted a non-empty newRoot for an empty new tree
    [other, EMPTY_TREE_ROOT, 0, 0, []],
    [EMPTY_TREE_ROOT, other, 0, 5, []],
    [other, other, 0, 5, []],
    [EMPTY_TREE_ROOT, other, 0, 5, [other]],
  ];
  it.each(cases.map((c, i) => [i, ...c] as const))('case %i agrees with ledger.ts', (_i, o, n, a, b, path) => {
    const proof = { oldSize: a, newSize: b, path };
    expect(verifyConsistencyVerified(o, n, proof)).toBe(verifyLedgerConsistency(o, n, proof));
  });
  it('pinned outcomes', () => {
    expect(verifyConsistencyVerified(EMPTY_TREE_ROOT, EMPTY_TREE_ROOT, { oldSize: 0, newSize: 0, path: [] })).toBe(true);
    expect(verifyConsistencyVerified(EMPTY_TREE_ROOT, other, { oldSize: 0, newSize: 0, path: [] })).toBe(false);
    expect(verifyConsistencyVerified(EMPTY_TREE_ROOT, other, { oldSize: 0, newSize: 5, path: [] })).toBe(true);
    expect(verifyConsistencyVerified(other, other, { oldSize: 0, newSize: 5, path: [] })).toBe(false);
  });
});

const leaf = (i: number) => new TextEncoder().encode(`leaf-${i}`);
const leaves = (n: number) => Array.from({ length: n }, (_, i) => leaf(i));
const H = (suite: 'sha256' | 'sha384', ...parts: Uint8Array[]) => new Uint8Array(createHash(suite).update(Buffer.concat(parts.map((x) => Buffer.from(x)))).digest());
const lh = (suite: 'sha256' | 'sha384', d: Uint8Array) => H(suite, Uint8Array.of(0), d);
const nh = (suite: 'sha256' | 'sha384', a: Uint8Array, b: Uint8Array) => H(suite, Uint8Array.of(1), a, b);
function rfcRoot(suite: 'sha256' | 'sha384', ds: Uint8Array[]): Uint8Array {
  if (ds.length === 0) return H(suite);
  if (ds.length === 1) return lh(suite, ds[0]!);
  let k = 1;
  while (k * 2 < ds.length) k *= 2;
  return nh(suite, rfcRoot(suite, ds.slice(0, k)), rfcRoot(suite, ds.slice(k)));
}

describe('b64u strict codec', () => {
  it('encode agrees with Buffer base64url for every length 0..12; decode inverts it', () => {
    for (let n = 0; n <= 12; n++) {
      const u = Uint8Array.from({ length: n }, (_, i) => (i * 53 + 17) & 255);
      const e = b64uEncode(u);
      expect(e).toBe(Buffer.from(u).toString('base64url'));
      expect(Array.from(b64uDecodeStrict(e)!)).toEqual(Array.from(u));
    }
    expect(b64uEncode(new Uint8Array(0))).toBe('');
    expect(Array.from(b64uDecodeStrict('')!)).toEqual([]);
  });
  it('rejects every deviation', () => {
    for (const bad of ['A', 'AAAAA', 'AB', 'AAB', 'A+', 'A/', 'AA==', 'AA=', ' AA', 'A A', '\u0080A', 'AA\u0080', 'é', '\uffff', 'AAA\n', '\x00', 'AAAA\u0100']) expect(b64uDecodeStrict(bad), JSON.stringify(bad)).toBeNull();
    for (const bad of [undefined, null, 5, {}, ['AAAA'], new Uint8Array(3)]) expect(b64uDecodeStrict(bad as any)).toBeNull();
    expect(Array.from(b64uDecodeStrict('AQ')!)).toEqual([1]);
    expect(Array.from(b64uDecodeStrict('AAE')!)).toEqual([0, 1]);
    expect(Array.from(b64uDecodeStrict('-_8')!)).toEqual([251, 255]);
    expect(b64uDecodeStrict('AAAA')!.length).toBe(3);
    expect(b64uDecodeStrict('AAAAAA')!.length).toBe(4);
    expect(b64uDecodeStrict('AAAAAAA')!.length).toBe(5);
    expect(b64uEncode(Uint8Array.of(251, 255, 191))).toBe('-_-_');
  });
});

describe('tree builders and inclusion proofs', () => {
  it('root: default suite is sha256, sha384 honoured, empty list is H(""), matches an independent RFC 6962 fold', () => {
    for (let n = 0; n <= 13; n++) {
      expect(Array.from(merkleRootVerified(leaves(n)))).toEqual(Array.from(rfcRoot('sha256', leaves(n))));
      expect(Array.from(merkleRootVerified(leaves(n), 'sha256'))).toEqual(Array.from(rfcRoot('sha256', leaves(n))));
      expect(Array.from(merkleRootVerified(leaves(n), 'sha384'))).toEqual(Array.from(rfcRoot('sha384', leaves(n))));
    }
  });
  it('inclusion proofs: honest proofs verify (both suites) and carry hash_suite only for sha384; default suite is sha256', () => {
    for (let n = 1; n <= 9; n++) for (let i = 0; i < n; i++) {
      const p = inclusionProofVerified(leaves(n), i);
      expect(p.index).toBe(i);
      expect(p.size).toBe(n);
      expect('hash_suite' in p).toBe(false);
      const root = b64uEncode(rfcRoot('sha256', leaves(n)));
      expect(verifyInclusionVerified(root, p, leaf(i))).toBe(true);
      expect(verifyInclusionVerified(root, p, leaf((i + 1) % (n + 1) === i ? n : (i + 1) % (n + 1)))).toBe(n === 1 ? false : false);
      const p3 = inclusionProofVerified(leaves(n), i, 'sha384');
      expect(p3.hash_suite).toBe('sha384');
      expect(verifyInclusionVerified(b64uEncode(rfcRoot('sha384', leaves(n))), p3, leaf(i))).toBe(true);
      expect(verifyInclusionVerified(b64uEncode(rfcRoot('sha384', leaves(n))), { ...p3, hash_suite: 'sha256' }, leaf(i))).toBe(false);
      expect(verifyInclusionVerified(root, { ...p, hash_suite: 'sha256' }, leaf(i))).toBe(true);
      expect(Array.from(inclusionRootVerified(p, leaf(i))!)).toEqual(Array.from(rfcRoot('sha256', leaves(n))));
      expect(Array.from(inclusionRootVerified(p3, leaf(i))!)).toEqual(Array.from(rfcRoot('sha384', leaves(n))));
      expect(Array.from(inclusionRootVerified({ ...p, hash_suite: 'sha256' }, leaf(i))!)).toEqual(Array.from(rfcRoot('sha256', leaves(n))));
    }
  });
  it('inclusionProofVerified rejects out-of-range indices with RangeError("index out of range")', () => {
    for (const i of [-1, 3, 4, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) expect(() => inclusionProofVerified(leaves(3), i)).toThrow(new RangeError('index out of range'));
    expect(() => inclusionProofVerified([], 0)).toThrow('index out of range');
    expect(() => inclusionProofVerified(leaves(3), 2)).not.toThrow();
    expect(() => inclusionProofVerified(leaves(3), 0)).not.toThrow();
  });
  it('verifyInclusion: every malformed shape is false, never throws', () => {
    const n = 5, i = 2;
    const good: any = inclusionProofVerified(leaves(n), i);
    const root = b64uEncode(rfcRoot('sha256', leaves(n)));
    const ok = (r: unknown, p: unknown) => verifyInclusionVerified(r, p, leaf(i));
    expect(ok(root, good)).toBe(true);
    for (const p of [null, undefined, 5, 'x', {}, { ...good, path: 'x' }, { ...good, path: null }, { ...good, hash_suite: 'md5' }, { ...good, hash_suite: 'SHA256' }, { ...good, hash_suite: null }, { ...good, index: 1.5 }, { ...good, index: '2' }, { ...good, size: 5.5 }, { ...good, size: Number.NaN }, { ...good, index: 2 ** 60 }, { ...good, path: [null, ...good.path] }, { ...good, path: [{ side: 'X', hash: good.path[0].hash }, ...good.path.slice(1)] }, { ...good, path: [{ side: 'L', hash: 'bad!' }, ...good.path.slice(1)] }, { ...good, path: [{ side: 'L', hash: 5 }, ...good.path.slice(1)] }, { ...good, path: [{ hash: good.path[0].hash }, ...good.path.slice(1)] }]) {
      expect(ok(root, p), JSON.stringify(p)).toBe(false);
    }
    for (const r of [undefined, null, 5, '', 'bad!', root + 'A', root.slice(0, -1), b64uEncode(new Uint8Array(32))]) expect(ok(r, good), String(r)).toBe(false);
    expect(verifyInclusionVerified(root, good, leaf(3))).toBe(false);
    // shapes that nothing guards: a swapped side flips the decision
    const flip = { ...good, path: good.path.map((s: any) => ({ ...s, side: s.side === 'L' ? 'R' : 'L' })) };
    expect(ok(root, flip)).toBe(false);
    for (const p of [null, undefined, 5, {}, { ...good, path: 'x' }, { ...good, hash_suite: 'md5' }, { ...good, index: 1.5 }, { ...good, size: 1.5 }, { ...good, path: [null] }, { ...good, path: [{ side: 'Q', hash: 'AAAA' }] }, { ...good, path: [{ side: 'L', hash: '!' }] }]) {
      expect(inclusionRootVerified(p, leaf(i)), JSON.stringify(p)).toBeNull();
    }
  });
});

describe('consistency proofs', () => {
  it('honest proofs verify for every (m, n); path is empty when m is 0 or m == n; roots must be canonical', () => {
    for (let n = 0; n <= 10; n++) for (let m = 0; m <= n; m++) {
      const pr = consistencyProofVerified(leaves(n), m);
      expect(pr.oldSize).toBe(m);
      expect(pr.newSize).toBe(n);
      if (m === 0 || m === n) expect(pr.path).toEqual([]);
      else expect(pr.path.length).toBeGreaterThan(0);
      const o = b64uEncode(rfcRoot('sha256', leaves(m)));
      const nw = b64uEncode(rfcRoot('sha256', leaves(n)));
      expect(verifyConsistencyVerified(o, nw, pr), `${m}/${n}`).toBe(true);
      expect(verifyConsistencyVerified(o, nw, pr)).toBe(verifyLedgerConsistency(o, nw, pr));
      if (m > 0 && m < n) {
        expect(verifyConsistencyVerified(nw, o, pr)).toBe(false);
        expect(verifyConsistencyVerified(o, nw, { ...pr, path: pr.path.slice(1) })).toBe(false);
        expect(verifyConsistencyVerified(o, nw, { ...pr, path: [...pr.path, pr.path[0]!] })).toBe(false);
      }
    }
  });
  it('malformed proofs and roots are false, never throw', () => {
    const pr = consistencyProofVerified(leaves(6), 3);
    const o = b64uEncode(rfcRoot('sha256', leaves(3)));
    const nw = b64uEncode(rfcRoot('sha256', leaves(6)));
    for (const p of [null, undefined, 5, {}, { ...pr, path: 'x' }, { ...pr, oldSize: 1.5 }, { ...pr, newSize: Number.NaN }, { ...pr, oldSize: '3' }, { ...pr, path: [5] }, { ...pr, path: ['bad!'] }, { ...pr, path: [pr.path[0] + 'A'] }, { ...pr, oldSize: -1 }, { ...pr, oldSize: 7 }]) {
      expect(verifyConsistencyVerified(o, nw, p as any), JSON.stringify(p)).toBe(false);
    }
    for (const r of [undefined, null, 5, 'bad!', o + 'A']) {
      expect(verifyConsistencyVerified(r, nw, pr)).toBe(false);
      expect(verifyConsistencyVerified(o, r, pr)).toBe(false);
    }
    expect(verifyConsistencyVerified(o, nw, { ...pr, path: new Array(200).fill(pr.path[0]) })).toBe(false);
    // equal sizes compare the two roots
    expect(verifyConsistencyVerified(o, o, { oldSize: 3, newSize: 3, path: [] })).toBe(true);
    expect(verifyConsistencyVerified(o, nw, { oldSize: 3, newSize: 3, path: [] })).toBe(false);
  });
});

describe('membership', () => {
  it('root is the size-bound sha256 of the revocation-set body; wrong root / size / id are false', () => {
    const n = 4, i = 1;
    const proof: any = inclusionProofVerified(leaves(n), i);
    const tree = b64uEncode(rfcRoot('sha256', leaves(n)));
    const body = `pca-revset/v1\0{"size":${n},"tree":"${tree}"}`;
    const root = b64uEncode(new Uint8Array(createHash('sha256').update(new TextEncoder().encode(body)).digest()));
    expect(verifyMembershipVerified(root, proof, leaf(i))).toBe(true);
    expect(verifyMembershipVerified(root, proof, leaf(i + 1))).toBe(false);
    expect(verifyMembershipVerified(root, { ...proof, size: n + 1 }, leaf(i))).toBe(false);
    expect(verifyMembershipVerified(tree, proof, leaf(i))).toBe(false);
    for (const r of [undefined, null, 5]) expect(verifyMembershipVerified(r, proof, leaf(i))).toBe(false);
    for (const p of [null, undefined, {}, { ...proof, size: 1.5 }, { ...proof, path: 'x' }]) expect(verifyMembershipVerified(root, p, leaf(i))).toBe(false);
  });
});

describe('ext-merkle glue edges', () => {
  const md5Leaf = (d: Uint8Array) => new Uint8Array(createHash('md5').update(Buffer.concat([Buffer.of(0), Buffer.from(d)])).digest());
  it('an array-like (non-array) path is refused even when its elements would verify', () => {
    const p: any = inclusionProofVerified(leaves(2), 0);
    expect(p.path.length).toBe(1);
    const root = b64uEncode(rfcRoot('sha256', leaves(2)));
    expect(verifyInclusionVerified(root, p, leaf(0))).toBe(true);
    const arrayLike = { ...p, path: { length: 1, 0: p.path[0] } };
    expect(verifyInclusionVerified(root, arrayLike, leaf(0))).toBe(false);
    expect(inclusionRootVerified(arrayLike, leaf(0))).toBeNull();
    expect(Array.from(inclusionRootVerified(p, leaf(0))!)).toEqual(Array.from(rfcRoot('sha256', leaves(2))));
  });
  it('an unknown hash_suite is refused even when the root is that suite\'s leaf hash', () => {
    const root = b64uEncode(md5Leaf(leaf(0)));
    for (const s of ['md5', 'sha1', 'sha512']) {
      expect(verifyInclusionVerified(root, { index: 0, size: 1, path: [], hash_suite: s }, leaf(0))).toBe(false);
      expect(inclusionRootVerified({ index: 0, size: 1, path: [], hash_suite: s }, leaf(0))).toBeNull();
    }
  });
  it('non-integer index / size never yield a root', () => {
    for (const [index, size] of [[0, 1.5], [0.5, 1], [0, Number.NaN], [Number.NaN, 1], [0, 2 ** 60], ['0', 1], [0, '1']] as const) {
      expect(inclusionRootVerified({ index, size, path: [] }, leaf(0)), `${index}/${size}`).toBeNull();
    }
  });
  it('a non-byte leaf or a throwing getter is false / null, never a throw', () => {
    const p: any = inclusionProofVerified(leaves(2), 0);
    const root = b64uEncode(rfcRoot('sha256', leaves(2)));
    expect(verifyInclusionVerified(root, p, null as any)).toBe(false);
    expect(inclusionRootVerified(p, null as any)).toBeNull();
    const boom = { get path(): string[] { throw new Error('boom'); }, oldSize: 1, newSize: 2 };
    expect(verifyConsistencyVerified(root, root, boom as any)).toBe(false);
    const boomSize = { ...p, get size(): number { throw new Error('boom'); } };
    expect(verifyMembershipVerified('x', boomSize, leaf(0))).toBe(false);
  });
  it('consistencyProofVerified: an old size at or past the new size has an empty path', () => {
    for (const m of [3, 4, 9]) expect(consistencyProofVerified(leaves(3), m)).toEqual({ oldSize: m, newSize: 3, path: [] });
  });
});
