import { describe, expect, it } from 'vitest';
import { fraudProofWireCheck, type BondedClaim, type FraudProof } from './optimistic';

const claim = { pcactn_digest: 'd', bond_ref: 'b', claimed_r: 0.5, reversibility_class: 'reversible', issued_at: 1, challenge_window_ms: 1000, sig: 's' } as BondedClaim;
const decision = { releaseGuardianShare: false, r: 1, optimisticAllowed: false };
const proof = (over: Record<string, unknown> = {}): FraudProof =>
  ({ pcactn_digest: 'd', bond_ref: 'b', claimed_r: 0.5, kind: 'policy-denied', decision, evidence: {}, r_margin: 1e-9, reason: 'x', ...over }) as FraudProof;

describe('fraudProofWireCheck object-ness and failure edges', () => {
  it('a function carrying the right members is still not a proof', () => {
    const fn = Object.assign(() => 1, proof());
    expect(fraudProofWireCheck(claim, fn as unknown as FraudProof)).toBe('malformed');
    expect(fraudProofWireCheck(claim, proof())).toBe('ok');
  });
  it('a function carrying the right members is still not a decision', () => {
    const fn = Object.assign(() => 1, decision);
    expect(fraudProofWireCheck(claim, proof({ decision: fn }))).toBe('malformed');
  });
  it('a proof that throws when read is malformed', () => {
    const hostile = new Proxy({}, { get() { throw new Error('boom'); } });
    expect(fraudProofWireCheck(claim, hostile as FraudProof)).toBe('malformed');
  });
});
