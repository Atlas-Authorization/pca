/**
 * Round-2 SECURITY: createPufVerifier / createPqSoftwareVerifier refuse an EMPTY measurement allowlist at construction
 * ("accept-all is not permitted"), but kept the caller's policy object by reference and skipped the allowlist gate
 * when the array was empty at verify time. A caller that later clears the list (e.g. to revoke every measurement)
 * turned the verifier into ACCEPT-ALL. The ledger called the `length > 0` re-check redundant ("the constructor
 * guarantees a non-empty array"); it was the fail-open branch.
 */
import { describe, expect, it } from 'vitest';
import { type ExpectedAttestationBinding, type HardwareAttestationVerifier } from './attestation';
import { createPufAttestor, createPufEnrollmentRegistry, createPufVerifier, createSimulatedPuf, enrollPuf } from './attest-puf';
import { createPqSoftwareAttestor, createPqSoftwareVerifier } from './attest-pq-software';
import { encodeKey, generateKeyPair } from './keys';
import { mlDsa65Keygen } from './pq';

const T = 1_000_000;
const A = generateKeyPair();
const EXPECTED: ExpectedAttestationBinding = { holderPub: encodeKey(A.publicKey), grantRef: 'g-r2', epoch: 1, nonce: 'n-r2', nonceIssuedAt: T - 1000 };
const CLAIMS = (measurement: string) => ({ measurement, holder_pub: EXPECTED.holderPub, grant_ref: EXPECTED.grantRef, epoch: EXPECTED.epoch, nonce: EXPECTED.nonce });
const detRng = (n: number): Uint8Array => { const o = new Uint8Array(n); for (let i = 0; i < n; i++) o[i] = (i * 7 + 1) & 0xff; return o; };
const run = (v: HardwareAttestationVerifier) => v.verify({ document: {}, ctx: {}, nowMs: T, expected: EXPECTED } as never);

describe('r2: measurement allowlists cannot be emptied into accept-all after construction', () => {
  it('PUF verifier', async () => {
    const base = createSimulatedPuf({ id: 'dev-r2', seed: new Uint8Array(32).fill(0x33), length: 28 });
    const enrollment = enrollPuf(base, new Uint8Array([1, 2, 3]), { rep: 7, messageBits: 4, alg: 'ml-dsa-65', randomBytes: detRng });
    const registry = createPufEnrollmentRegistry([enrollment]);
    const policy = { measurements: ['good'], weightsMeasurements: ['w-good'] };
    let st = createPufAttestor(base, enrollment).attest({ ...CLAIMS('evil'), weights_digest: 'w-good' } as never);
    const v = createPufVerifier({ resolveEnrollment: (id) => registry.lookup(id), policy, resolveEvidence: () => st });
    expect((await run(v)).ok).toBe(false);
    policy.measurements.length = 0; // the operator "revokes everything"
    expect((await run(v)).ok).toBe(false);
    st = createPufAttestor(base, enrollment).attest({ ...CLAIMS('good'), weights_digest: 'w-evil' } as never);
    policy.measurements.push('good');
    policy.weightsMeasurements.length = 0;
    expect((await run(v)).ok).toBe(false);
  });
  it('PQ software verifier', async () => {
    const attestor = createPqSoftwareAttestor({ alg: 'ml-dsa-65', mlDsa: mlDsa65Keygen(new Uint8Array(32).fill(9)) });
    let st = attestor.attest(CLAIMS('evil'));
    const policy = { measurements: ['good'] };
    const v = createPqSoftwareVerifier({ trustedPqPublicKeys: [attestor.pqPublicKey], policy, resolveEvidence: () => st });
    expect((await run(v)).ok).toBe(false);
    policy.measurements.length = 0;
    expect((await run(v)).ok).toBe(false);
    st = attestor.attest(CLAIMS('good'));
    policy.measurements.push('good');
    expect((await run(v)).ok).toBe(true); // the snapshot taken at construction still admits the original allowlist
  });
});
