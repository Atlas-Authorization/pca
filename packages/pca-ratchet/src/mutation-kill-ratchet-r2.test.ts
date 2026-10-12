/**
 * Round-2 adversarial kills of mutants that were ledgered as equivalent but are observable:
 *  - the Fiat-Shamir transcript terms (a proof produced by the unmutated code must verify: known-answer fixture),
 *  - proof/list length strictness (trailing junk must not be accepted),
 *  - attestation type strictness (String() coercion in the signed message must not let a non-string pass).
 */
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ed25519 } from '@noble/curves/ed25519';
import { b64u } from '@atlasauth/pca';
import { N_BITS, proveBudget, verifyBoundedBudget, verifyBudget, verifyRiskRange, type BudgetProof, type RiskRangeProof } from './accumulator';
import { issueRiskCommitment, verifyAttestedBudget, verifyRiskAttestation } from './binding';
import { deriveRatchetRoot, signAtLeaf, verifyLeafSignature } from './ratchet';

const KAT = JSON.parse(readFileSync(join(__dirname, 'mutation-kill-ratchet-r2.kat.json'), 'utf8')) as {
  commitments: string[]; rangeProofs: RiskRangeProof[]; bMax: number; budgetProof: BudgetProof; sum: string;
};
const clone = <T,>(x: T): T => JSON.parse(JSON.stringify(x));

describe('r2: known-answer transcripts (proofs made by the reference code must verify)', () => {
  it('risk range proof and bounded budget from the fixture verify', () => {
    expect(verifyRiskRange(KAT.commitments[0]!, KAT.rangeProofs[0]!)).toBe(true);
    expect(verifyRiskRange(KAT.commitments[1]!, KAT.rangeProofs[1]!)).toBe(true);
    expect(verifyBudget(KAT.sum, KAT.bMax, KAT.budgetProof)).toBe(true);
    expect(verifyBoundedBudget(KAT.commitments, KAT.rangeProofs, KAT.bMax, KAT.budgetProof)).toBe(true);
    // and are bound to their statement
    expect(verifyRiskRange(KAT.commitments[1]!, KAT.rangeProofs[0]!)).toBe(false);
    expect(verifyBudget(KAT.sum, KAT.bMax + 1, KAT.budgetProof)).toBe(false);
  });
});

describe('r2: proofs are not malleable by trailing material', () => {
  it('an extra OR proof (ignored by the verification loop) is refused', () => {
    const p = clone(KAT.rangeProofs[0]!);
    p.or.push(p.or[0]!);
    expect(verifyRiskRange(KAT.commitments[0]!, p)).toBe(false);
    const b = clone(KAT.budgetProof);
    b.or.push(b.or[0]!);
    expect(verifyBudget(KAT.sum, KAT.bMax, b)).toBe(false);
    const q = clone(KAT.rangeProofs[0]!);
    q.or.pop();
    expect(verifyRiskRange(KAT.commitments[0]!, q)).toBe(false);
    expect(N_BITS).toBe(32);
  });
  it('more range proofs than commitments is refused (the extra is never examined)', () => {
    expect(verifyBoundedBudget(KAT.commitments, [...KAT.rangeProofs, KAT.rangeProofs[0]!], KAT.bMax, KAT.budgetProof)).toBe(false);
    expect(verifyBoundedBudget(KAT.commitments, [KAT.rangeProofs[0]!], KAT.bMax, KAT.budgetProof)).toBe(false);
    expect(verifyBoundedBudget([...KAT.commitments, KAT.commitments[0]!], KAT.rangeProofs, KAT.bMax, KAT.budgetProof)).toBe(false);
  });
});

describe('r2: attestations are strictly typed', () => {
  const sk = ed25519.utils.randomPrivateKey();
  const pk = b64u(ed25519.getPublicKey(sk));
  it('a non-string actionDigest that stringifies to the signed digest is refused', () => {
    const iss = issueRiskCommitment(5, 'd', sk);
    expect(verifyRiskAttestation(iss.commitment, iss.attestation, pk)).toBe(true);
    for (const weird of [['d'], { toString: () => 'd' }, new String('d')]) {
      expect(verifyRiskAttestation(iss.commitment, { ...iss.attestation, actionDigest: weird as never }, pk)).toBe(false);
    }
    expect(verifyRiskAttestation(iss.commitment, { ...iss.attestation, sig: [iss.attestation.sig] as never }, pk)).toBe(false);
    expect(verifyRiskAttestation(iss.commitment, null as never, pk)).toBe(false);
    expect(verifyRiskAttestation(iss.commitment, 'x' as never, pk)).toBe(false);
  });
  it('verifyAttestedBudget requires the verifier\'s expected digests to be a real array (a string of one-char digests is not)', () => {
    const digests = ['a', 'b'];
    const items = digests.map((d, i) => ({ d, risk: [3, 4][i]! })).map(({ d, risk }) => issueRiskCommitment(risk, d, sk));
    const budgetProof = proveBudget([3, 4], items.map((i) => i.blinding), 50);
    const mk = items.map((i) => ({ commitment: i.commitment, rangeProof: i.rangeProof, attestation: i.attestation }));
    expect(verifyAttestedBudget(mk, digests, pk, 50, budgetProof)).toBe(true);
    expect(verifyAttestedBudget(mk, 'ab' as never, pk, 50, budgetProof)).toBe(false);
    expect(verifyAttestedBudget(mk as never, { length: 2, 0: 'a', 1: 'b' } as never, pk, 50, budgetProof)).toBe(false);
    expect(verifyAttestedBudget({ length: 2, 0: mk[0], 1: mk[1] } as never, digests, pk, 50, budgetProof)).toBe(false);
  });
});

describe('r2: verifyLeafSignature shape strictness (nothing but strings and an object path is accepted)', () => {
  const { rootCommitment, state } = deriveRatchetRoot(new Uint8Array(32).fill(9), 3);
  const m = new TextEncoder().encode('m');
  const { signature } = signAtLeaf(state, 2, m);
  const bytes = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));
  it('baseline', () => expect(verifyLeafSignature(rootCommitment, 2, m, signature)).toBe(true));
  it('alternate representations of otherwise valid members are refused', () => {
    const variants: unknown[] = [
      { ...signature, edSig: bytes(signature.edSig) },
      { ...signature, leafPubKey: bytes(signature.leafPubKey) },
      { ...signature, edSig: [signature.edSig] },
      { ...signature, leafPubKey: [signature.leafPubKey] },
      { ...signature, edSig: new String(signature.edSig) },
      { ...signature, leafPubKey: new String(signature.leafPubKey) },
      { ...signature, merklePath: null },
      { ...signature, merklePath: 'x' },
      { ...signature, merklePath: 5 },
      { ...signature, merklePath: [] },
      { ...signature, nullifier: [signature.nullifier] },
      { ...signature, nullifier: new String(signature.nullifier) },
      null, 5, 'x', [], undefined,
    ];
    for (const v of variants) expect(verifyLeafSignature(rootCommitment, 2, m, v as never)).toBe(false);
  });
});
