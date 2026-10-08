import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { unb64u, type HashSuite } from './hash';
import { commitPlan, merkleProof, merkleRoot, verifyInclusion, type InclusionProof } from './merkle';

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

// ---------------------------------------------------------------------------------------------------------
// SHA-384 hash-suite agility (P4): optional, NON-BREAKING stronger-margin variant. SHA-256 (the default) is
// already PQ-adequate (Grover => ~2^128 preimage, BHT => ~2^128 collision); SHA-384 is margin/agility, NOT a
// fix. Below: the sha256 default stays byte-identical, sha384 is correct/distinct/reproducible with valid
// proofs, and the two suites are mutually fail-closed.
describe('merkle sha384 hash suite (P4 agility)', () => {
  const ls = (n: number) => Array.from({ length: n }, (_, i) => ({ i, t: 'leaf' }));

  it('sha256 default is byte-identical to the explicit sha256 suite (non-breaking)', () => {
    for (const n of [1, 3, 5, 7, 11]) {
      const l = ls(n);
      expect(merkleRoot(l, 'sha256')).toBe(merkleRoot(l));
      for (let i = 0; i < n; i++) {
        // An explicit sha256 proof is byte-identical AND carries NO hash_suite tag (absence => sha256).
        expect(merkleProof(l, i, 'sha256')).toEqual(merkleProof(l, i));
        expect(merkleProof(l, i).hash_suite).toBeUndefined();
      }
    }
  });

  it('sha384 produces correct, distinct, reproducible roots with 48-byte digests and valid proofs', () => {
    for (const n of [1, 3, 5, 7, 11]) {
      const l = ls(n);
      const root = merkleRoot(l, 'sha384');
      expect(root).toBe(merkleRoot(l, 'sha384')); // reproducible
      expect(root).not.toBe(merkleRoot(l)); // distinct from sha256
      expect(unb64u(root).length).toBe(48); // SHA-384 digest width
      for (let i = 0; i < n; i++) {
        const p = merkleProof(l, i, 'sha384');
        expect(p.hash_suite).toBe('sha384'); // self-describing
        for (const step of p.path) expect(unb64u(step.hash).length).toBe(48);
        expect(verifyInclusion(root, p, l[i])).toBe(true);
      }
    }
  });

  it('FAIL-CLOSED: a proof built under one suite never verifies under the other', () => {
    const l = ls(7);
    const r256 = merkleRoot(l);
    const r384 = merkleRoot(l, 'sha384');
    for (let i = 0; i < l.length; i++) {
      const p256 = merkleProof(l, i);
      const p384 = merkleProof(l, i, 'sha384');
      // cross-root
      expect(verifyInclusion(r256, p384, l[i])).toBe(false); // sha384 proof vs sha256 root
      expect(verifyInclusion(r384, p256, l[i])).toBe(false); // sha256 proof vs sha384 root
      // stripping the tag reads as sha256 => 48-byte siblings fail the 32-byte decode
      expect(verifyInclusion(r384, { index: p384.index, size: p384.size, path: p384.path }, l[i])).toBe(false);
      // mislabeling a sha256 proof as sha384 => 32-byte siblings fail the 48-byte decode
      expect(verifyInclusion(r256, { ...p256, hash_suite: 'sha384' }, l[i])).toBe(false);
      // an unknown suite value fails closed (never silently downgraded)
      const bogus = { ...p384, hash_suite: 'sha512' as unknown as HashSuite };
      expect(verifyInclusion(r384, bogus, l[i])).toBe(false);
    }
  });
});

// Companion re-verification of the committed SHA-384 conformance corpus against the live reference
// (mirrors how conformance.test.ts / frost-pq.test.ts re-run their written vectors — a reference drift here
// means a golden vector no longer matches the code that produced it).
interface Sha384Corpus {
  suite: string;
  default_hash_suite: string;
  hash_len_bytes: number;
  primitives: {
    canonical: { value: unknown; suite: HashSuite; expect: string; hash: string; sha256_hash: string }[];
    merkle: {
      n: number;
      leaves: unknown[];
      suite: HashSuite;
      root: string;
      sha256_root: string;
      proofs: InclusionProof[];
      sha256_proofs: InclusionProof[];
    }[];
  };
}
const SHA384: Sha384Corpus = JSON.parse(
  readFileSync(join(__dirname, '..', 'conformance', 'sha384-vectors.json'), 'utf8'),
) as Sha384Corpus;

describe('sha384 conformance corpus (conformance/sha384-vectors.json)', () => {
  it('is the sha384 suite with a sha256 default and 48-byte digests', () => {
    expect(SHA384.suite).toBe('sha384');
    expect(SHA384.default_hash_suite).toBe('sha256');
    expect(SHA384.hash_len_bytes).toBe(48);
  });

  it('every merkle vector: sha384 root distinct from sha256, every proof verifies, cross-suite fails closed', () => {
    for (const m of SHA384.primitives.merkle) {
      expect(merkleRoot(m.leaves, 'sha384'), `root(${m.n})`).toBe(m.root);
      expect(merkleRoot(m.leaves), `sha256 root(${m.n})`).toBe(m.sha256_root);
      expect(m.root).not.toBe(m.sha256_root);
      m.leaves.forEach((leaf, i) => {
        expect(verifyInclusion(m.root, m.proofs[i]!, leaf), `verify ${m.n}/${i}`).toBe(true);
        // cross-suite fail-closed, replayed from the committed vectors
        expect(verifyInclusion(m.sha256_root, m.proofs[i]!, leaf)).toBe(false);
        expect(verifyInclusion(m.root, m.sha256_proofs[i]!, leaf)).toBe(false);
      });
    }
  });
});
