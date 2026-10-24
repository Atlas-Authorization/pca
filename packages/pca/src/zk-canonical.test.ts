/**
 * Canonical-encoding regression for Groth16 envelopes (BN254 and BLS12-381). snarkjs reduces coordinates and
 * public signals mod the field, so before the `isCanonicalGroth16Envelope` gate a valid proof ALSO verified as
 * x + p, with leading zeros, a `0x` public signal, an unreduced z, or extra keys (many encodings per proof).
 */
import { readFileSync } from 'node:fs';
import { beforeAll, describe, expect, it } from 'vitest';
import { useSingleThreadSnarkCurvesInWorkerThreads } from './test-support/snarkjs-single-thread';
import {
  POLICYVM_BLS12381_SAMPLE_PROOF_PATH,
  POLICYVM_BLS12381_VKEY_PATH,
  POLICYVM_SAMPLE_PROOF_PATH,
  POLICYVM_VKEY_PATH,
  isCanonicalGroth16Envelope,
  verifyPolicyVmProof,
} from './zk';

// snarkjs single-threaded when this file runs in a worker thread (Stryker's vitest runner): see test-support/snarkjs-single-thread.ts
beforeAll(useSingleThreadSnarkCurvesInWorkerThreads);

const FQ = { bn254: 21888242871839275222246405745257275088696311157297823662689037894645226208583n, bls: 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn };
type Env = { system: string; circuit: string; proof: { pi_a: string[]; pi_b: string[][]; [k: string]: unknown }; publicSignals: string[] } & Record<string, unknown>;

for (const [name, sp, vp, fq, curve] of [
  ['bn254', POLICYVM_SAMPLE_PROOF_PATH, POLICYVM_VKEY_PATH, FQ.bn254, 'bn254'],
  ['bls12-381', POLICYVM_BLS12381_SAMPLE_PROOF_PATH, POLICYVM_BLS12381_VKEY_PATH, FQ.bls, 'bls12-381'],
] as const) {
  describe(`Groth16 ${name}: one accepted encoding per proof`, () => {
    const sample = JSON.parse(readFileSync(sp(), 'utf8')) as Env;
    const verificationKey = JSON.parse(readFileSync(vp(), 'utf8')) as object;
    const mut = (f: (e: Env) => void): Env => {
      const c = JSON.parse(JSON.stringify(sample)) as Env;
      f(c);
      return c;
    };
    const ok = (e: Env) => verifyPolicyVmProof(e, { verificationKey });

    it('canonical sample verifies and passes the gate', async () => {
      expect(isCanonicalGroth16Envelope(sample, curve)).toBe(true);
      expect(await ok(sample)).toBe(true);
    });
    const aliases: Array<[string, (e: Env) => void]> = [
      ['pi_a.x + p', (e) => (e.proof.pi_a[0] = (BigInt(e.proof.pi_a[0]!) + fq).toString())],
      ['pi_a.x leading zeros', (e) => (e.proof.pi_a[0] = '000' + e.proof.pi_a[0]!)],
      ['pi_b.x1 + p', (e) => (e.proof.pi_b[0]![1] = (BigInt(e.proof.pi_b[0]![1]!) + fq).toString())],
      ['pi_a.z "01"', (e) => (e.proof.pi_a[2] = '01')],
      ['public signal 0x-hex', (e) => (e.publicSignals[1] = '0x' + BigInt(e.publicSignals[1]!).toString(16))],
      ['public signal leading zero', (e) => (e.publicSignals[1] = '0' + e.publicSignals[1])],
      ['extra key in proof', (e) => (e.proof.extra = 1)],
      ['extra envelope key', (e) => (e.extra = 1)],
    ];
    for (const [label, f] of aliases) {
      it(`rejects alias: ${label}`, async () => {
        const m = mut(f);
        expect(isCanonicalGroth16Envelope(m, curve)).toBe(false);
        expect(await ok(m)).toBe(false);
      });
    }
  });
}
