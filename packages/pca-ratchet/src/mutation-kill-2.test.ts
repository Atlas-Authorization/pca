/** Round 2: cross-leaf signing (a key for leaf j must not be accepted as leaf i) and an independent leaf-message layout. */
import { ed25519 } from '@noble/curves/ed25519';
import { describe, expect, it } from 'vitest';
import { b64u } from '@atlasauth/pca';
import { deriveRatchetRoot, leafNullifier, signAtLeaf, verifyLeafSignature } from './ratchet';
import { deriveLeafSeed, leafSigningSeed } from './ggm';

const seed = new Uint8Array(32).fill(4);
const msg = new TextEncoder().encode('m');
const idxMsg = (i: number, m: Uint8Array) => {
  const d = new TextEncoder().encode('atlas-pca-ratchet/leaf-sig/v1\0');
  const o = new Uint8Array(d.length + 8 + m.length);
  o.set(d); new DataView(o.buffer).setBigUint64(d.length, BigInt(i), false); o.set(m, d.length + 8);
  return o;
};

describe('leaf binding', () => {
  const { rootCommitment, state } = deriveRatchetRoot(seed, 3);
  const root = [...state.covering.values()][0]!;
  it('the signed message is domain || u64be(index) || message', () => {
    const { signature } = signAtLeaf(state, 5, msg);
    expect(ed25519.verify(Buffer.from(signature.edSig, 'base64url'), idxMsg(5, msg), Buffer.from(signature.leafPubKey, 'base64url'))).toBe(true);
  });
  it('multi-byte leaf indexes are encoded big-endian in full', () => {
    const big = deriveRatchetRoot(seed, 9);
    const { signature } = signAtLeaf(big.state, 258, msg);
    expect(ed25519.verify(Buffer.from(signature.edSig, 'base64url'), idxMsg(258, msg), Buffer.from(signature.leafPubKey, 'base64url'))).toBe(true);
  });
  it("leaf j's key cannot be presented as leaf i (merkle index must equal the claimed index)", () => {
    const j = 2, i = 5;
    const sk = leafSigningSeed(deriveLeafSeed(root, j, 3));
    const pathJ = signAtLeaf(state, j, msg).signature;
    const forged = { ...pathJ, edSig: b64u(ed25519.sign(idxMsg(i, msg), sk)), nullifier: leafNullifier(rootCommitment, i) };
    expect(verifyLeafSignature(rootCommitment, i, msg, forged)).toBe(false);
    // control: the same forgery is the honest signature when the index is its own
    const honest = { ...pathJ, edSig: b64u(ed25519.sign(idxMsg(j, msg), sk)) };
    expect(verifyLeafSignature(rootCommitment, j, msg, honest)).toBe(true);
  });
});
