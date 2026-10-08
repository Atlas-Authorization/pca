import { describe, expect, it } from 'vitest';
import { commitPlan, merkleProof, merkleRoot, verifyInclusion } from './merkle';

const leaves = (n: number) => Array.from({ length: n }, (_, i) => ({ i, v: `leaf${i}` }));

describe('merkle', () => {
  it('root is stable and order/content sensitive', () => {
    expect(merkleRoot(leaves(5))).toBe(merkleRoot(leaves(5)));
    expect(merkleRoot(leaves(5))).not.toBe(merkleRoot(leaves(5).reverse()));
    expect(() => merkleRoot([])).toThrow();
  });
  it('every leaf of every size verifies', () => {
    for (let n = 1; n <= 17; n++) {
      const ls = leaves(n);
      const root = merkleRoot(ls);
      for (let i = 0; i < n; i++) expect(verifyInclusion(root, merkleProof(ls, i), ls[i])).toBe(true);
    }
  });
  it('wrong leaf, tampered proof, wrong root fail', () => {
    const ls = leaves(6);
    const root = merkleRoot(ls);
    const p = merkleProof(ls, 2);
    expect(verifyInclusion(root, p, ls[3])).toBe(false);
    const bad = { ...p, path: p.path.map((s, i) => (i === 0 ? { ...s, side: s.side === 'L' ? ('R' as const) : ('L' as const) } : s)) };
    expect(verifyInclusion(root, bad, ls[2])).toBe(false);
    const bad2 = { ...p, path: [...p.path.slice(1)] };
    expect(verifyInclusion(root, bad2, ls[2])).toBe(false);
    expect(verifyInclusion(merkleRoot(leaves(7)), p, ls[2])).toBe(false);
    expect(verifyInclusion(root, { index: 0, size: 1, path: [{ side: 'L', hash: '***' }] }, ls[2])).toBe(false);
  });
  it('domain separation: an internal node cannot pass as a leaf', () => {
    const ls = leaves(2);
    const root = merkleRoot(ls);
    // 1-leaf tree whose "leaf" is the concatenated children must not reproduce the root
    expect(merkleRoot([ls[0], ls[1]])).toBe(root);
    expect(merkleRoot([root])).not.toBe(root);
  });
  it('commitPlan: proofs per node; unknown/duplicate rejected', () => {
    const nodes = [
      { id: 'a', verb: 'read', resource: 'r1' },
      { id: 'b', verb: 'write', resource: 'r2', pre: { x: 1 }, post: { y: 2 } },
      { id: 'c', verb: 'del', resource: 'r3' },
    ];
    const plan = commitPlan(nodes);
    expect(plan.root).toBe(commitPlan(nodes).root);
    expect(() => plan.proofFor('zzz')).toThrow();
    expect(() => commitPlan([nodes[0]!, nodes[0]!])).toThrow();
    expect(plan.proofFor('b').size).toBe(3);
  });
});

describe('merkle verifyInclusion binds index and size (P5-3)', () => {
  const leaves = Array.from({ length: 11 }, (_, i) => ({ i }));
  const root = merkleRoot(leaves);
  it('valid proofs for every index/size still verify', () => {
    for (let n = 1; n <= 11; n++) {
      const ls = leaves.slice(0, n);
      const r = merkleRoot(ls);
      for (let i = 0; i < n; i++) expect(verifyInclusion(r, merkleProof(ls, i), ls[i])).toBe(true);
    }
  });
  it('rejects a lying index, a lying size, or a non-integer/out-of-range value', () => {
    const p = merkleProof(leaves, 3);
    expect(verifyInclusion(root, p, leaves[3])).toBe(true);
    expect(verifyInclusion(root, { ...p, index: 4 }, leaves[3])).toBe(false);
    expect(verifyInclusion(root, { ...p, size: 5 }, leaves[3])).toBe(false);
    expect(verifyInclusion(root, { ...p, index: 11 }, leaves[3])).toBe(false);
    expect(verifyInclusion(root, { ...p, index: -1 }, leaves[3])).toBe(false);
    expect(verifyInclusion(root, { ...p, index: 1.5 }, leaves[3])).toBe(false);
    expect(verifyInclusion(root, { ...p, size: 0 }, leaves[3])).toBe(false);
  });
  it('rejects a path with a wrong shape (extra step / flipped side / bad sibling length)', () => {
    const p = merkleProof(leaves, 3);
    expect(verifyInclusion(root, { ...p, path: [...p.path, p.path[0]!] }, leaves[3])).toBe(false);
    expect(verifyInclusion(root, { ...p, path: p.path.slice(1) }, leaves[3])).toBe(false);
    const flipped = p.path.map((s, i) => (i === 0 ? { ...s, side: s.side === 'L' ? ('R' as const) : ('L' as const) } : s));
    expect(verifyInclusion(root, { ...p, path: flipped }, leaves[3])).toBe(false);
    expect(verifyInclusion(root, { ...p, path: p.path.map((s, i) => (i === 0 ? { ...s, hash: 'AAAA' } : s)) }, leaves[3])).toBe(false);
  });
});
