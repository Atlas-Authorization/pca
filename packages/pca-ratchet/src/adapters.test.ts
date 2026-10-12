import { describe, expect, it } from 'vitest';
import { DEFAULT_RISK_POLICY, safetyBound } from '@atlasauth/pca';
import {
  RISK_SCALE,
  budgetCeilingUnits,
  counterToLeafIndex,
  leafIndexForAction,
  leafIndexToCounter,
  riskToUnits,
} from './adapters';
import { RatchetError, deriveRatchetRoot, signAtLeaf, verifyLeafSignature } from './ratchet';
import { addCommitments, commitRisk, proveBudget, verifyBudget } from './accumulator';

describe('adapters — ratchet leaf index ↔ PCActn.counter', () => {
  it('maps a counter to its leaf index within capacity', () => {
    expect(counterToLeafIndex(0, 4)).toBe(0);
    expect(counterToLeafIndex(15, 4)).toBe(15);
    expect(leafIndexToCounter(15)).toBe(15);
    expect(leafIndexForAction({ counter: 5 }, 4)).toBe(5);
  });

  it('rejects a counter beyond the ratchet capacity', () => {
    expect(() => counterToLeafIndex(16, 4)).toThrowError(RatchetError);
    expect(() => counterToLeafIndex(-1, 4)).toThrowError(RatchetError);
    try {
      counterToLeafIndex(16, 4);
    } catch (e) {
      expect((e as RatchetError).code).toBe('leaf_out_of_range');
    }
  });

  it('the counter drives one-time-use end to end: spending counter c punctures leaf c', () => {
    const depth = 4;
    const { rootCommitment, state } = deriveRatchetRoot(new Uint8Array(32).fill(42), depth);
    const counter = 9;
    const leaf = leafIndexForAction({ counter }, depth);
    const m = new TextEncoder().encode(`action#${counter}`);
    const { signature, newState } = signAtLeaf(state, leaf, m);
    expect(verifyLeafSignature(rootCommitment, leaf, m, signature)).toBe(true);
    // Replaying the same counter is cryptographically impossible — the leaf is gone.
    expect(() => signAtLeaf(newState, leafIndexForAction({ counter }, depth), m)).toThrowError(/punctured/);
  });
});

describe('adapters — accumulator units ↔ RiskPolicy budget (bMax/κ)', () => {
  it('quantizes a core risk score to accumulator units', () => {
    expect(riskToUnits(0)).toBe(0n);
    expect(riskToUnits(0.123)).toBe(BigInt(Math.round(0.123 * RISK_SCALE)));
    expect(riskToUnits(1)).toBe(BigInt(RISK_SCALE));
    expect(() => riskToUnits(-0.1)).toThrowError();
    expect(() => riskToUnits(Number.POSITIVE_INFINITY)).toThrowError();
  });

  it('derives the budget ceiling from the core safety bound Σrisk ≤ bMax/κ', () => {
    const policy = { bMax: 10, kappa: 2 };
    expect(safetyBound(policy)).toBe(5);
    expect(budgetCeilingUnits(policy)).toBe(BigInt(Math.floor(5 * RISK_SCALE)));
    // Matches the default policy's bound.
    expect(budgetCeilingUnits(DEFAULT_RISK_POLICY)).toBe(
      BigInt(Math.floor(safetyBound(DEFAULT_RISK_POLICY) * RISK_SCALE)),
    );
  });

  it('the ZK budget proof enforces the SAME inequality the control plane does', () => {
    // Policy bMax/κ = 5 → ceiling 5000 units. A sequence of per-action risks that sums under the
    // bound proves; one that exceeds it is rejected — the accumulator is the budget.
    const policy = { bMax: 10, kappa: 2 };
    const ceiling = budgetCeilingUnits(policy); // 5000n

    const underRisks = [riskToUnits(1.5), riskToUnits(2.0), riskToUnits(1.0)]; // Σ = 4500 ≤ 5000
    const underBlind = underRisks.map(() => commitRisk(0).blinding);
    const underCommits = underRisks.map((r, i) => commitRisk(r, underBlind[i]));
    const underSum = addCommitments(underCommits.map((c) => c.commitment));
    expect(verifyBudget(underSum, ceiling, proveBudget(underRisks, underBlind, ceiling))).toBe(true);

    const overRisks = [riskToUnits(3.0), riskToUnits(2.5)]; // Σ = 5500 > 5000
    const overBlind = overRisks.map(() => commitRisk(0).blinding);
    const overCommits = overRisks.map((r, i) => commitRisk(r, overBlind[i]));
    const overSum = addCommitments(overCommits.map((c) => c.commitment));
    expect(verifyBudget(overSum, ceiling, proveBudget(overRisks, overBlind, ceiling))).toBe(false);
  });
});
