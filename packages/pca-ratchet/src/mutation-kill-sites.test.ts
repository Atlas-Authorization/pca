/**
 * Site kills for the per-site ledger migration: the catch blocks of verifyRiskAttestation (binding.ts:138/139) and
 * verifyAttestedBudget (binding.ts:169/170) are REACHABLE and must return exactly `false` (never `undefined`, never
 * `true`): both functions are documented "never throws" boolean verifiers.
 */
import { ed25519 } from '@noble/curves/ed25519';
import { describe, expect, it } from 'vitest';
import { b64u } from '@atlasauth/pca';
import { issueRiskCommitment, verifyAttestedBudget, verifyRiskAttestation } from './binding';

const sk = ed25519.utils.randomPrivateKey();
const pk = b64u(ed25519.getPublicKey(sk));

describe('binding verifiers: a thrown input is a refusal (false)', () => {
  it('verifyRiskAttestation: a commitment the UTF-8 encoder cannot coerce (Symbol / throwing toString) gives false', () => {
    const r = issueRiskCommitment(5n, 'digest-1', sk);
    expect(verifyRiskAttestation(r.commitment, r.attestation, pk)).toBe(true);
    expect(verifyRiskAttestation(Symbol('c') as never, r.attestation, pk)).toBe(false);
    const evil = { toString() { throw new Error('boom'); } };
    expect(verifyRiskAttestation(evil as never, r.attestation, pk)).toBe(false);
  });
  it('verifyAttestedBudget: a null item (it.attestation throws) gives false', () => {
    expect(verifyAttestedBudget([null] as never, ['x'], pk, 10n, {} as never)).toBe(false);
  });
});
