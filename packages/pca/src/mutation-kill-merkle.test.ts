/**
 * Mutation-kill tests for merkle.ts: exact thrown messages, and verifyInclusion's binding of index/size/suite/path type.
 * The index/size guards matter because pathShape() of an out-of-range or non-integer index can coincide with the shape of
 * a real leaf's proof (index -1 or NaN in a 2-leaf tree looks like index 0 or 1).
 */
import { describe, expect, it } from 'vitest';
import { commitPlan, merkleProof, merkleRoot, verifyInclusion } from './merkle';

const L = [{ a: 0 }, { a: 1 }];
const root2 = merkleRoot(L);

describe('merkleRoot / merkleProof / commitPlan errors', () => {
  it('empty leaf set', () => {
    expect(() => merkleRoot([])).toThrow(new RangeError('merkleRoot: empty leaf set'));
  });
  it('index out of range (negative, non-integer, == length)', () => {
    for (const i of [-1, 0.5, 2]) expect(() => merkleProof(L, i)).toThrow(new RangeError('merkleProof: index out of range'));
  });
  it('commitPlan duplicate and unknown node ids', () => {
    const n = { id: 'a', verb: 'v', resource: 'r' };
    expect(() => commitPlan([n, n])).toThrow(new Error('commitPlan: duplicate node id a'));
    expect(() => commitPlan([n]).proofFor('zz')).toThrow(new Error('commitPlan: unknown node zz'));
  });
});

describe('verifyInclusion binds index and size', () => {
  const p0 = merkleProof(L, 0);
  const p1 = merkleProof(L, 1);
  it('control: the real proofs verify', () => {
    expect(verifyInclusion(root2, p0, L[0])).toBe(true);
    expect(verifyInclusion(root2, p1, L[1])).toBe(true);
  });
  it('index -1 / 2 / NaN reusing a real path shape are refused', () => {
    expect(verifyInclusion(root2, { ...p0, index: -1 }, L[0])).toBe(false);
    expect(verifyInclusion(root2, { ...p1, index: 2 }, L[1])).toBe(false);
    expect(verifyInclusion(root2, { ...p1, index: Number.NaN }, L[1])).toBe(false);
    expect(verifyInclusion(root2, { ...p1, index: 1.5 }, L[1])).toBe(false);
  });
});

describe('verifyInclusion input shape', () => {
  const root1 = merkleRoot([L[0]]);
  it('control: a single-leaf proof has an empty path', () => {
    expect(verifyInclusion(root1, { index: 0, size: 1, path: [] }, L[0])).toBe(true);
  });
  it('a null proof, a non-array (even empty-string) path, an unknown hash suite are refused with false', () => {
    expect(verifyInclusion(root1, null as never, L[0])).toBe(false);
    expect(verifyInclusion(root1, { index: 0, size: 1, path: '' as never }, L[0])).toBe(false);
    expect(verifyInclusion(root1, { index: 0, size: 1, path: [], hash_suite: 'sha512' as never }, L[0])).toBe(false);
  });
  it('a leaf that cannot be canonicalised is false, not a throw', () => {
    expect(verifyInclusion(root1, { index: 0, size: 1, path: [] }, { x: Number.NaN })).toBe(false);
  });
});
