import { describe, expect, it } from 'vitest';
import {
  type BudgetProof,
  type RiskCommitment,
  N_BITS,
  addCommitments,
  commitRisk,
  openCommitment,
  proveBudget,
  verifyBudget,
} from './accumulator';
import { decodeScalar, encodeScalar } from './group';

function commitAll(risks: number[]): { commitments: RiskCommitment[]; sum: string } {
  const commitments = risks.map((r) => commitRisk(r));
  const sum = addCommitments(commitments.map((c) => c.commitment));
  return { commitments, sum };
}

describe('Mechanism 2 — homomorphic Pedersen risk accumulator', () => {
  it('commits and opens a single risk', () => {
    const c = commitRisk(7);
    expect(openCommitment(c.commitment, 7, c.blinding)).toBe(true);
    expect(openCommitment(c.commitment, 8, c.blinding)).toBe(false);
    expect(openCommitment(c.commitment, 7, c.blinding + 1n)).toBe(false);
  });

  it('adds homomorphically: the sum opens to (Σrisk, Σblinding)', () => {
    const risks = [3, 11, 0, 25];
    const { commitments, sum } = commitAll(risks);
    const sumRisk = risks.reduce((a, b) => a + b, 0);
    const sumBlind = commitments.reduce((acc, c) => acc + c.blinding, 0n);
    expect(openCommitment(sum, sumRisk, sumBlind)).toBe(true);
    // It is NOT a commitment to a different aggregate.
    expect(openCommitment(sum, sumRisk + 1, sumBlind)).toBe(false);
  });

  it('empty sum is a commitment to zero', () => {
    expect(openCommitment(addCommitments([]), 0, 0n)).toBe(true);
  });
});

describe('Mechanism 2 — zero-knowledge budget ceiling (Σrisk ≤ bMax)', () => {
  it('accepts an under-budget aggregate', () => {
    const risks = [10, 20, 5]; // Σ = 35
    const bMax = 100;
    const { commitments, sum } = commitAll(risks);
    const proof = proveBudget(risks, commitments.map((c) => c.blinding), bMax);
    expect(proof.n).toBe(N_BITS);
    expect(verifyBudget(sum, bMax, proof)).toBe(true);
  });

  it('accepts the exact-boundary aggregate (Σrisk === bMax, slack 0)', () => {
    const risks = [40, 60]; // Σ = 100
    const bMax = 100;
    const { commitments, sum } = commitAll(risks);
    const proof = proveBudget(risks, commitments.map((c) => c.blinding), bMax);
    expect(verifyBudget(sum, bMax, proof)).toBe(true);
  });

  it('REJECTS an over-budget aggregate', () => {
    const risks = [80, 50]; // Σ = 130 > 100
    const bMax = 100;
    const { commitments, sum } = commitAll(risks);
    const proof = proveBudget(risks, commitments.map((c) => c.blinding), bMax);
    expect(verifyBudget(sum, bMax, proof)).toBe(false);
  });

  it('REJECTS a tampered commitment sum', () => {
    const risks = [10, 20];
    const bMax = 100;
    const { commitments, sum } = commitAll(risks);
    const proof = proveBudget(risks, commitments.map((c) => c.blinding), bMax);
    expect(verifyBudget(sum, bMax, proof)).toBe(true);
    // Swap the real sum for a commitment to a different (smaller, flattering) aggregate.
    const fakeSum = addCommitments([commitRisk(1).commitment]);
    expect(verifyBudget(fakeSum, bMax, proof)).toBe(false);
  });

  it('REJECTS a proof with a mutated Fiat-Shamir sub-challenge (soundness)', () => {
    const risks = [10, 20];
    const bMax = 100;
    const { commitments, sum } = commitAll(risks);
    const proof = proveBudget(risks, commitments.map((c) => c.blinding), bMax);
    expect(verifyBudget(sum, bMax, proof)).toBe(true);

    // Mutate one bit-OR sub-challenge: the verifier re-derives the challenge from the transcript,
    // so e0 + e1 no longer matches H(...).
    const bit = proof.or[0];
    expect(bit).toBeDefined();
    const mutated: BudgetProof = {
      ...proof,
      or: [{ ...bit!, e0: encodeScalar(decodeScalar(bit!.e0) + 1n) }, ...proof.or.slice(1)],
    };
    expect(verifyBudget(sum, bMax, mutated)).toBe(false);

    // Mutate the aggregation response: z·H ≠ a + e·D.
    const mutatedAgg: BudgetProof = {
      ...proof,
      agg: { ...proof.agg, z: encodeScalar(decodeScalar(proof.agg.z) + 1n) },
    };
    expect(verifyBudget(sum, bMax, mutatedAgg)).toBe(false);
  });

  it('REJECTS a forged bit commitment (bit outside {0,1})', () => {
    // A malicious prover cannot make the OR proof pass for a non-boolean bit; splice a bad
    // commitment and the per-bit OR verification fails.
    const risks = [10];
    const bMax = 100;
    const { commitments, sum } = commitAll(risks);
    const proof = proveBudget(risks, commitments.map((c) => c.blinding), bMax);
    const forged = commitRisk(2); // commits to value 2, not a bit
    const bad: BudgetProof = {
      ...proof,
      bitCommitments: [forged.commitment, ...proof.bitCommitments.slice(1)],
    };
    expect(verifyBudget(sum, bMax, bad)).toBe(false);
  });

  it('rejects structurally malformed proofs without throwing', () => {
    const { sum } = commitAll([1]);
    expect(verifyBudget(sum, 100, { n: 8, bitCommitments: [], or: [], agg: { a: '', z: '' } })).toBe(false);
    expect(verifyBudget('not-a-point', 100, proveBudget([1], [commitRisk(1).blinding], 100))).toBe(false);
  });

  it('zero-knowledge sanity: proof is aggregate-only and randomized', () => {
    // Two different per-risk breakdowns with the SAME aggregate and SAME total blinding produce the
    // SAME commitment sum; both proofs verify and neither proof encodes the individual risks.
    const bMax = 100;
    const bA = [11n, 22n, 33n];
    const bB = [33n, 22n, 11n];
    const risksA = [5, 15, 30];
    const risksB = [25, 10, 15]; // same Σ = 50, same Σblinding (66)
    const sumA = addCommitments(risksA.map((r, i) => commitRisk(r, bA[i]).commitment));
    const sumB = addCommitments(risksB.map((r, i) => commitRisk(r, bB[i]).commitment));
    expect(sumA).toBe(sumB);
    const proofA = proveBudget(risksA, bA, bMax);
    const proofB = proveBudget(risksB, bB, bMax);
    expect(verifyBudget(sumA, bMax, proofA)).toBe(true);
    expect(verifyBudget(sumB, bMax, proofB)).toBe(true);

    // No individual risk value leaks as a scalar in the serialized proof.
    const blob = JSON.stringify(proofA);
    for (const r of risksA) {
      if (r === 0) continue;
      expect(blob.includes(encodeScalar(BigInt(r)))).toBe(false);
    }

    // Two independent proofs of the same statement differ (fresh randomness each time).
    const p1 = proveBudget(risksA, bA, bMax);
    const p2 = proveBudget(risksA, bA, bMax);
    expect(JSON.stringify(p1)).not.toBe(JSON.stringify(p2));
  });

  it('works across the full range (large under-budget slack near 2^32)', () => {
    const bMax = 4_000_000_000; // < 2^32
    const risks = [1_000_000, 2_000_000];
    const { commitments, sum } = commitAll(risks);
    const proof = proveBudget(risks, commitments.map((c) => c.blinding), bMax);
    expect(verifyBudget(sum, bMax, proof)).toBe(true);
  });
});
