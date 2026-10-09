import { describe, expect, it } from 'vitest';
import {
  type RatchetSignature,
  RatchetError,
  availableLeaves,
  deriveRatchetRoot,
  isLeafAvailable,
  signAtLeaf,
  verifyLeafSignature,
} from './ratchet';

const seed = (n: number): Uint8Array => new Uint8Array(32).fill(n);
const msg = (s: string): Uint8Array => new TextEncoder().encode(s);

describe('Mechanism 1 — puncturable forward-secure capability keys', () => {
  it('derives a stable root commitment and full leaf set', () => {
    const a = deriveRatchetRoot(seed(1), 4);
    const b = deriveRatchetRoot(seed(1), 4);
    expect(a.rootCommitment).toBe(b.rootCommitment);
    expect(a.state.leafCount).toBe(16);
    expect(a.state.leafPubKeys).toHaveLength(16);
    expect(availableLeaves(a.state)).toHaveLength(16);
    // A different seed yields a different commitment.
    expect(deriveRatchetRoot(seed(2), 4).rootCommitment).not.toBe(a.rootCommitment);
  });

  it('signs at a leaf and verifies offline against the root', () => {
    const { rootCommitment, state } = deriveRatchetRoot(seed(7), 3);
    const m = msg('transfer 10 USDC');
    const { signature } = signAtLeaf(state, 5, m);
    expect(verifyLeafSignature(rootCommitment, 5, m, signature)).toBe(true);
    // The signing leaf's public key is exactly the committed leaf.
    expect(signature.leafPubKey).toBe(state.leafPubKeys[5]);
    expect(signature.merklePath.index).toBe(5);
  });

  it('REFUSES to sign a punctured leaf (cryptographic one-time-use)', () => {
    const { state } = deriveRatchetRoot(seed(3), 3);
    const { newState } = signAtLeaf(state, 2, msg('spend'));
    expect(isLeafAvailable(state, 2)).toBe(true); // original state unchanged (immutable)
    expect(isLeafAvailable(newState, 2)).toBe(false);
    expect(() => signAtLeaf(newState, 2, msg('spend again'))).toThrowError(RatchetError);
    try {
      signAtLeaf(newState, 2, msg('spend again'));
      expect.unreachable('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(RatchetError);
      expect((e as RatchetError).code).toBe('leaf_punctured');
    }
  });

  it('a punctured leaf key is unrecoverable: the state no longer holds it and re-signing refuses', () => {
    const { state } = deriveRatchetRoot(seed(9), 4);
    expect(availableLeaves(state)).toContain(6);
    const { newState } = signAtLeaf(state, 6, msg('once'));
    const avail = availableLeaves(newState);
    expect(avail).not.toContain(6);
    expect(avail).toHaveLength(15);
    // No covering node in the new state can reach leaf 6 — its seed/path is gone for good.
    expect(isLeafAvailable(newState, 6)).toBe(false);
    for (const node of newState.covering.values()) {
      const span = 2 ** (newState.depth - node.level);
      const base = node.nodeIndex * span;
      expect(6 < base || 6 >= base + span).toBe(true);
    }
    expect(() => signAtLeaf(newState, 6, msg('again'))).toThrowError(/punctured/);
  });

  it('untouched leaves still sign and verify after a puncture', () => {
    const { rootCommitment, state } = deriveRatchetRoot(seed(11), 4);
    let s = state;
    const spent: Array<{ i: number; sig: RatchetSignature; m: Uint8Array }> = [];
    for (const i of [0, 3, 8, 15, 9]) {
      const m = msg(`action-${i}`);
      const r = signAtLeaf(s, i, m);
      s = r.newState;
      spent.push({ i, sig: r.signature, m });
    }
    // Every produced signature still verifies against the (unchanging) root.
    for (const { i, sig, m } of spent) {
      expect(verifyLeafSignature(rootCommitment, i, m, sig)).toBe(true);
    }
    // A fresh untouched leaf still signs.
    expect(availableLeaves(s)).toContain(7);
    const r = signAtLeaf(s, 7, msg('action-7'));
    expect(verifyLeafSignature(rootCommitment, 7, msg('action-7'), r.signature)).toBe(true);
  });

  it('every leaf of a full tree can be spent exactly once, each verifying', () => {
    const depth = 3;
    const { rootCommitment, state } = deriveRatchetRoot(seed(21), depth);
    let s = state;
    for (let i = 0; i < 2 ** depth; i++) {
      const m = msg(`leaf-${i}`);
      const r = signAtLeaf(s, i, m);
      expect(verifyLeafSignature(rootCommitment, i, m, r.signature)).toBe(true);
      s = r.newState;
    }
    expect(availableLeaves(s)).toHaveLength(0);
    expect(() => signAtLeaf(s, 0, msg('x'))).toThrowError(RatchetError);
  });

  it('rejects tampered signatures: bad path, wrong index, wrong message, swapped leaf key', () => {
    const { rootCommitment, state } = deriveRatchetRoot(seed(33), 4);
    const m = msg('authorize');
    const { signature } = signAtLeaf(state, 10, m);
    expect(verifyLeafSignature(rootCommitment, 10, m, signature)).toBe(true);

    // wrong message
    expect(verifyLeafSignature(rootCommitment, 10, msg('authorize!'), signature)).toBe(false);
    // wrong leaf index (claimed index differs from the proof's committed slot)
    expect(verifyLeafSignature(rootCommitment, 11, m, signature)).toBe(false);
    // tampered merkle path (flip one sibling hash)
    const firstStep = signature.merklePath.path[0];
    expect(firstStep).toBeDefined();
    const badHash = firstStep!.hash.slice(0, -2) + (firstStep!.hash.endsWith('AA') ? 'BB' : 'AA');
    const tamperedPath: RatchetSignature = {
      ...signature,
      merklePath: {
        ...signature.merklePath,
        path: [{ side: firstStep!.side, hash: badHash }, ...signature.merklePath.path.slice(1)],
      },
    };
    expect(verifyLeafSignature(rootCommitment, 10, m, tamperedPath)).toBe(false);
    // swapped leaf public key (a different real leaf's key — breaks both sig and inclusion)
    const swapped: RatchetSignature = { ...signature, leafPubKey: state.leafPubKeys[11]! };
    expect(verifyLeafSignature(rootCommitment, 10, m, swapped)).toBe(false);
    // wrong root commitment
    const other = deriveRatchetRoot(seed(34), 4).rootCommitment;
    expect(verifyLeafSignature(other, 10, m, signature)).toBe(false);
  });

  it('rejects malformed input and out-of-range / invalid construction without throwing in verify', () => {
    const { rootCommitment, state } = deriveRatchetRoot(seed(5), 3);
    expect(() => deriveRatchetRoot(seed(5), 0)).toThrowError(RatchetError);
    expect(() => deriveRatchetRoot(new Uint8Array(8), 3)).toThrowError(/seed/);
    expect(() => signAtLeaf(state, 8, msg('x'))).toThrowError(/out of range/);
    expect(() => signAtLeaf(state, -1, msg('x'))).toThrowError(RatchetError);
    const { signature } = signAtLeaf(state, 1, msg('y'));
    expect(verifyLeafSignature(rootCommitment, 1, msg('y'), { ...signature, edSig: 'not-base64!!' })).toBe(false);
  });
});
