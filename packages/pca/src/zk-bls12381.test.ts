import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  type PolicyVmComplianceProof,
  type PolicyVmComplianceProofBls12381,
  POLICYVM_BLS12381_SAMPLE_PROOF_PATH,
  POLICYVM_BLS12381_VKEY_PATH,
  POLICYVM_PUBLIC_SIGNAL,
  POLICYVM_SAMPLE_PROOF_PATH,
  POLICYVM_VKEY_PATH,
  createPolicyVmSnarkBackendBls12381,
  decodePolicyVmPublic,
  policyVmStructHash,
  verifyPolicyVmProof,
} from './zk';
import type { PCActn, VerifyContext } from './pcactn';
import type { Capability } from './capability';

// FULL Policy-VM Groth16 proof migrated to the BLS12-381 curve (128-bit security, the end-game P2
// "BN254 -> BLS12-381"). The trusted setup was run fresh on a dedicated compute VM; these tests verify
// the COMMITTED bls12381 sample proof against the COMMITTED bls12381 verifying key fully OFFLINE — real
// snarkjs Groth16, curve-agnostic given the vkey, no wasm/zkey/network. The public signals are the SAME
// small fixed-point integers as the BN254 proof (they encode identically in either scalar field); only
// the proof group elements + verifying key are BLS12-381 points.
describe('full Policy-VM SNARK proof-of-compliance on BLS12-381 (§9B, committed fixture, REAL proof)', () => {
  const vkey = JSON.parse(readFileSync(POLICYVM_BLS12381_VKEY_PATH(), 'utf8')) as object;
  const sample = JSON.parse(readFileSync(POLICYVM_BLS12381_SAMPLE_PROOF_PATH(), 'utf8')) as PolicyVmComplianceProofBls12381;
  const ctx = { pcactn: {} as PCActn, grant: {} as Capability } as unknown as VerifyContext;
  const pub = { action_commit: '', policy_commit: '', plan_commit: '' };

  it('the committed bls12381 sample proof is a well-formed bls envelope', () => {
    expect(sample.system).toBe('groth16-bls12-381');
    expect(sample.circuit).toBe('pca-policyvm-v1');
    expect(sample.publicSignals).toHaveLength(15);
    // snarkjs writes the curve label without a hyphen ("bls12381"); the PCA envelope
    // system tag is the hyphenated "groth16-bls12-381". Assert the real snarkjs value.
    expect((vkey as { curve?: string }).curve).toBe('bls12381');
  });

  it('the committed bls12381 sample proof verifies against the committed bls12381 verifying key', async () => {
    expect(await verifyPolicyVmProof(sample, { verificationKey: vkey })).toBe(true);
  });

  it('verifies with NO explicit vkey — the bls12381 fixture is the default for a bls proof', async () => {
    expect(await verifyPolicyVmProof(sample)).toBe(true);
  });

  it('the proven public statement is release at t=1, auto-admit, r=0 (same as BN254)', () => {
    const d = decodePolicyVmPublic(sample.publicSignals);
    expect(d.allow).toBe('1');
    expect(d.admit).toBe('1');
    expect(d.t).toBe('1');
    expect(d.r).toBe('0');
    expect(d.now).toBe('1000000000');
    expect(d.allocChild).toBe('500000');
  });

  it('BINDING: sha256 is proven IN-CIRCUIT — the public hash halves equal sha256(fixed struct)', () => {
    const d = decodePolicyVmPublic(sample.publicSignals);
    // action struct = [verb, resource, reversibility, paramScalar]
    expect(policyVmStructHash([7, 42, 0, 100])).toEqual(d.actionHash);
    // plan struct = [planVerb, planResource, semanticDist, planSalt]
    expect(policyVmStructHash([7, 42, 0, 12345])).toEqual(d.planHash);
    // policy struct = the 20 quantized policy fields (DEFAULT_RISK_POLICY at S=1e6 + caveat/chain bounds)
    expect(
      policyVmStructHash([
        250000, 200000, 200000, 200000, 100000, 50000, // weights alpha..zeta
        250000, 600000, // theta1, theta2
        1000000, 1000000, // kappa, budgetB
        7, 42, 1000, // policyVerb, policyResource, policyParamBound
        9000000000000, 0, // expiresAt, notBefore
        1000000, 16, 2, 100, // maxBlast, maxDepth, revMax, rateMax
        1000000, // allocParent
      ]),
    ).toEqual(d.policyHash);
  });

  it('a tampered proof element is rejected', async () => {
    const tampered = JSON.parse(JSON.stringify(sample)) as PolicyVmComplianceProofBls12381;
    const pi = (tampered.proof as { pi_a: string[] }).pi_a;
    pi[0] = (BigInt(pi[0]!) ^ 1n).toString(); // flip one bit of a proof group element
    expect(await verifyPolicyVmProof(tampered, { verificationKey: vkey })).toBe(false);
  });

  it('a tampered / wrong public signal is rejected (the proof binds every public signal)', async () => {
    const tampered = JSON.parse(JSON.stringify(sample)) as PolicyVmComplianceProofBls12381;
    tampered.publicSignals[POLICYVM_PUBLIC_SIGNAL.now] = '999';
    expect(await verifyPolicyVmProof(tampered, { verificationKey: vkey })).toBe(false);
  });

  it('allow != 1 is rejected (fail-closed, before running the SNARK)', async () => {
    const denied = JSON.parse(JSON.stringify(sample)) as PolicyVmComplianceProofBls12381;
    denied.publicSignals[POLICYVM_PUBLIC_SIGNAL.allow] = '0';
    expect(await verifyPolicyVmProof(denied, { verificationKey: vkey })).toBe(false);
  });

  it('a malformed bls envelope is rejected (fails closed)', async () => {
    expect(await verifyPolicyVmProof({ system: 'groth16-bls12-381', circuit: 'pca-policyvm-v1', proof: null, publicSignals: [] }, { verificationKey: vkey })).toBe(false);
    expect(await verifyPolicyVmProof({ system: 'nope' }, { verificationKey: vkey })).toBe(false);
    expect(await verifyPolicyVmProof(null, { verificationKey: vkey })).toBe(false);
  });

  it('the bls12381 backend verifies and BINDS the in-circuit struct hashes', async () => {
    const backend = createPolicyVmSnarkBackendBls12381({ verificationKey: vkey, expectActionHash: policyVmStructHash([7, 42, 0, 100]) });
    expect(await backend.verify({ proof: sample, publicInputs: pub, ctx })).toBe(true);

    // A wrong expected action struct (different verb) no longer matches the proof's bound hash halves.
    const wrong = createPolicyVmSnarkBackendBls12381({ verificationKey: vkey, expectActionHash: policyVmStructHash([9, 42, 0, 100]) });
    expect(await wrong.verify({ proof: sample, publicInputs: pub, ctx })).toBe(false);
  });

  it('CROSS-CURVE: the bls proof does NOT verify under the BN254 verifying key', async () => {
    const bn254Vkey = JSON.parse(readFileSync(POLICYVM_VKEY_PATH(), 'utf8')) as object;
    expect(await verifyPolicyVmProof(sample, { verificationKey: bn254Vkey })).toBe(false);
  });

  it('the BN254 path is UNCHANGED — the committed BN254 sample still verifies under its own vkey', async () => {
    const bn254Vkey = JSON.parse(readFileSync(POLICYVM_VKEY_PATH(), 'utf8')) as object;
    const bn254Sample = JSON.parse(readFileSync(POLICYVM_SAMPLE_PROOF_PATH(), 'utf8')) as PolicyVmComplianceProof;
    expect(bn254Sample.system).toBe('groth16-bn254');
    expect(await verifyPolicyVmProof(bn254Sample, { verificationKey: bn254Vkey })).toBe(true);
    // and the bls proof is rejected by the bn254-tagged default path would never be taken — the sample
    // carries its own `system`, so dispatch picks the right default. Sanity: bn254 default still works.
    expect(await verifyPolicyVmProof(bn254Sample)).toBe(true);
  });
});
