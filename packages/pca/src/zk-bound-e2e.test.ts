/**
 * End to end for the risk-bound circuit: real Groth16 proving and verification with the key built by
 * circuits/policyvm_bound.setup.sh (dev-only, single party). Runs in the circuit CI job; skipped locally when the key is
 * absent, and FAILS (never skips) when PCA_REQUIRE_CIRCUITS=1 and it is missing.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { useSingleThreadSnarkCurvesInWorkerThreads } from './test-support/snarkjs-single-thread';
import type { VerifyContext } from './pcactn';
import {
  POLICYVM_BOUND_PUBLIC_SIGNAL as P,
  POLICYVM_BOUND_VKEY_PATH,
  POLICYVM_BOUND_WASM_PATH,
  POLICYVM_BOUND_ZKEY_PATH,
  createPolicyVmBoundSnarkBackend,
  policyVmRiskHash,
  policyVmStructHash,
  provePolicyVmBoundCompliance,
  verifyPolicyVmProof,
} from './zk';

const REQUIRE = process.env.PCA_REQUIRE_CIRCUITS === '1';
const have = [POLICYVM_BOUND_VKEY_PATH(), POLICYVM_BOUND_WASM_PATH(), POLICYVM_BOUND_ZKEY_PATH()].every((f) => existsSync(f));
beforeAll(useSingleThreadSnarkCurvesInWorkerThreads);

if (REQUIRE) {
  it('the risk-bound key and prover artifacts exist (a missing one fails, never skips)', () => {
    expect(have).toBe(true);
  });
}

describe.skipIf(!have)('pca-policyvm-v2 end to end', () => {
  const sample = JSON.parse(readFileSync(join(__dirname, '..', 'circuits', 'policyvm_sample_input.json'), 'utf8')) as Record<string, string>;
  const vkey = () => JSON.parse(readFileSync(POLICYVM_BOUND_VKEY_PATH(), 'utf8')) as object;
  const risk = policyVmRiskHash([sample.revScore!, sample.taint!, sample.conf!, sample.age!, sample.rFloorIn!]);
  const ctx = {} as VerifyContext;

  it('proves the sample witness; the proof verifies and carries exactly the risk commitment of the five inputs', async () => {
    const proof = await provePolicyVmBoundCompliance(sample);
    expect(proof.publicSignals).toHaveLength(17);
    expect([proof.publicSignals[P.riskHi], proof.publicSignals[P.riskLo]]).toEqual([risk.hi, risk.lo]);
    expect(await verifyPolicyVmProof(proof, { verificationKey: vkey(), expectRiskHash: risk })).toBe(true);
  }, 1_800_000);

  it('refuses a tampered signal, a wrong risk pin, and a proof moved to the v1 circuit id', async () => {
    const proof = await provePolicyVmBoundCompliance(sample);
    const k = vkey();
    for (const i of Object.values(P)) {
      const ps = [...proof.publicSignals];
      ps[i] = (BigInt(ps[i]!) + 1n).toString();
      expect(await verifyPolicyVmProof({ ...proof, publicSignals: ps }, { verificationKey: k }), `signal ${i}`).toBe(false);
    }
    const other = policyVmRiskHash([0, 0, 0, 0, 1]);
    expect(await verifyPolicyVmProof(proof, { verificationKey: k, expectRiskHash: other })).toBe(false);
    expect(await verifyPolicyVmProof({ ...proof, circuit: 'pca-policyvm-v1' }, { verificationKey: k })).toBe(false);
  }, 1_800_000);

  it('the backend accepts the proof only with all four commitments pinned correctly, and is labelled policyvm_snark', async () => {
    const proof = await provePolicyVmBoundCompliance(sample);
    const f = (ks: string[]) => policyVmStructHash(ks.map((x) => sample[x]!));
    const pins = {
      verificationKey: vkey(),
      expectActionHash: f(['verb', 'resource', 'reversibility', 'paramScalar']),
      expectPlanHash: f(['planVerb', 'planResource', 'semanticDist', 'planSalt']),
      expectPolicyHash: f(['wAlpha', 'wBeta', 'wGamma', 'wDelta', 'wEpsilon', 'wZeta', 'theta1', 'theta2', 'kappa', 'budgetB', 'policyVerb', 'policyResource', 'policyParamBound', 'expiresAt', 'notBefore', 'maxBlast', 'maxDepth', 'revMax', 'rateMax', 'allocParent']),
      expectRiskHash: risk,
    };
    const b = createPolicyVmBoundSnarkBackend(pins);
    expect(await b.verify({ proof, publicInputs: {} as never, ctx })).toBe(true);
    const bad = createPolicyVmBoundSnarkBackend({ ...pins, expectRiskHash: policyVmRiskHash([1, 0, 0, 0, 0]) });
    expect(await bad.verify({ proof, publicInputs: {} as never, ctx })).toBe(false);
  }, 1_800_000);

  it('a witness with a deny condition cannot be proven', async () => {
    await expect(provePolicyVmBoundCompliance({ ...sample, verb: '8' })).rejects.toThrow();
  }, 1_800_000);
});
