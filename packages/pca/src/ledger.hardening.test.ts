import { describe, expect, it } from 'vitest';
import { TransparencyLedger } from './ledger';
import { merkleProof, verifyInclusion } from './merkle';

// A3d/A2g enabler: the generic opaque-commitment append path on the ledger.
describe('TransparencyLedger.appendCommitment (opaque leaves)', () => {
  it('appends an opaque commit, grows the tree, and inclusion verifies against the head root', () => {
    const l = new TransparencyLedger('p');
    const r0 = l.appendCommitment('commit-A');
    const r1 = l.appendCommitment('commit-B');
    expect(r0.index).toBe(0);
    expect(r1.index).toBe(1);
    expect(l.size).toBe(2);
    const root = l.head().root;
    expect(l.verifyInclusion(root, l.inclusionProof(0), 'commit-A')).toBe(true);
    expect(l.verifyInclusion(root, l.inclusionProof(1), 'commit-B')).toBe(true);
    // a wrong leaf never verifies against a genuine proof
    expect(l.verifyInclusion(root, l.inclusionProof(0), 'commit-B')).toBe(false);
  });

  it('stores NO opening for an opaque leaf (auditOpenings ignores it)', () => {
    const l = new TransparencyLedger('p');
    l.appendCommitment('opaque');
    expect(l.entry(0).opening).toBeUndefined();
    expect(l.auditOpenings()).toEqual([]);
  });

  it('refuses an empty / non-string commit (fail closed)', () => {
    const l = new TransparencyLedger('p');
    expect(() => l.appendCommitment('')).toThrow();
    expect(() => l.appendCommitment(undefined as unknown as string)).toThrow();
  });

  it('opaque and salted commits coexist and the merkle root is leaf-order deterministic', () => {
    const a = new TransparencyLedger('p');
    a.appendCommitment('x');
    a.appendCommitment('y');
    expect(a.head().root).toBe(TransparencyLedger.fromEntries(a.commits().map((c) => ({ commit: c })), 'p').head().root);
    // cross-check against a from-scratch merkle root over the same commits
    expect(verifyInclusion(a.head().root, merkleProof(a.commits(), 1), 'y')).toBe(true);
  });
});
