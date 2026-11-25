/**
 * Fail-closed table for the post-quantum software attestation root: "missing / invalid X => exact result".
 * The root is labelled `software` (a signed statement, not silicon), and cannot back a hardware-bound prover key.
 */
import { describe, expect, it } from 'vitest';
import { createPqSoftwareAttestor, createPqSoftwareVerifier, type PqAttestationStatement, type PqSoftwareVerifierOptions } from './attest-pq-software';
import { assuranceLabelOf } from './assurance';
import type { ExpectedAttestationBinding } from './attestation';
import { createZkVerifier } from './zk';
import { generateKeyPair, encodeKey } from './keys';
import { mlDsa65Keygen } from './pq';

const T = 1_000_000;
const A = generateKeyPair();
const EXPECTED: ExpectedAttestationBinding = { holderPub: encodeKey(A.publicKey), grantRef: 'grant-pq-1', epoch: 1, nonce: 'nonce-pq-1', nonceIssuedAt: T - 1000 };
const MEAS = 'workload-measurement-abc';
const CLAIMS = { measurement: MEAS, holder_pub: EXPECTED.holderPub, grant_ref: EXPECTED.grantRef, epoch: EXPECTED.epoch, nonce: EXPECTED.nonce };
const mlDsa = mlDsa65Keygen(new Uint8Array(32).fill(7));
const other = mlDsa65Keygen(new Uint8Array(32).fill(8));
const ed = generateKeyPair();
const pure = createPqSoftwareAttestor({ alg: 'ml-dsa-65', mlDsa });
const hybrid = createPqSoftwareAttestor({ alg: 'hybrid-ed25519-ml-dsa-65', mlDsa, edSecret: ed.secretKey });
const st = pure.attest(CLAIMS);

const verifier = (statement: PqAttestationStatement | undefined, over: Partial<PqSoftwareVerifierOptions> = {}) =>
  createPqSoftwareVerifier({ trustedPqPublicKeys: [pure.pqPublicKey], policy: { measurements: [MEAS] }, resolveEvidence: () => statement, ...over });
const run = async (v: ReturnType<typeof verifier>, expected: ExpectedAttestationBinding = EXPECTED) => {
  const r = await v.verify({ document: {} as never, ctx: {} as never, nowMs: T, expected });
  return { ok: r.ok, reason: r.reason, bound: r.bound, runtime: r.measured?.runtime_measurement, weightsMeasured: r.measured?.weights_measured };
};
const denied = (reason: string) => ({ ok: false, reason, bound: undefined, runtime: undefined, weightsMeasured: undefined });

describe('attest-pq-software: missing or invalid X => exact result', () => {
  it('the baseline passes and the identity is honestly marked not silicon-measured', async () => {
    expect(await run(verifier(st))).toEqual({ ok: true, reason: undefined, bound: true, runtime: MEAS, weightsMeasured: false });
  });

  const rows: Array<[string, () => Promise<unknown>, string]> = [
    ['no evidence resolver configured', () => run(createPqSoftwareVerifier({ trustedPqPublicKeys: [pure.pqPublicKey], policy: { measurements: [MEAS] } })), 'no PQ-software evidence resolver configured (fail closed)'],
    ['the resolver returns nothing', () => run(verifier(undefined)), 'no PQ-software attestation statement for this action'],
    ['an unknown signature algorithm', () => run(verifier({ ...st, alg: 'rot13' as never })), "PQ statement declares an unknown signature alg 'rot13'"],
    ['a classical-only suite when PQ is required', () => run(verifier({ ...st, alg: 'ed25519' })), "PQ required: a classical-only suite 'ed25519' is not accepted by the post-quantum root"],
    ['a pure-PQ statement when a hybrid is required', () => run(verifier(st, { requireHybrid: true })), "hybrid required: suite 'ml-dsa-65' is not a classical+PQ hybrid"],
    ['a suite outside the allowed list', () => run(verifier(st, { allowedSuites: ['slh-dsa-sha2-128f'] })), "suite 'ml-dsa-65' is not in the allowed-suites list"],
    ['an untrusted PQ key', () => run(verifier(st, { trustedPqPublicKeys: [createPqSoftwareAttestor({ alg: 'ml-dsa-65', mlDsa: other }).pqPublicKey] })), 'PQ attestor key is not trusted'],
    ['a hybrid statement whose Ed25519 key is not trusted', () => run(verifier(hybrid.attest(CLAIMS), { trustedEd25519PublicKeys: [] })), 'hybrid Ed25519 attestor key is not trusted'],
    ['a measurement edited after signing', () => run(verifier({ ...st, measurement: 'evil' })), 'PQ attestation signature does not verify'],
    ['a signature removed', () => run(verifier({ ...st, sig: '' })), 'PQ attestation signature does not verify'],
    ['a binding for another nonce', () => run(verifier(st), { ...EXPECTED, nonce: 'another-nonce' }), 'PQ statement binding mismatch (holder/grant/epoch/nonce)'],
    ['a binding for another holder', () => run(verifier(st), { ...EXPECTED, holderPub: 'someone-else' }), 'PQ statement binding mismatch (holder/grant/epoch/nonce)'],
    ['a measurement outside the allowlist', () => run(verifier(st, { policy: { measurements: ['other-measurement'] } })), 'measurement not in policy allowlist'],
    ['a weights digest outside the allowlist', () => run(verifier(pure.attest({ ...CLAIMS, weights_digest: 'w1' }), { policy: { measurements: [MEAS], weightsMeasurements: ['w2'] } })), 'measured weights digest not in policy allowlist'],
    ['a weights allowlist and a statement without weights', () => run(verifier(st, { policy: { measurements: [MEAS], weightsMeasurements: ['w2'] } })), 'measured weights digest not in policy allowlist'],
  ];
  it.each(rows)('%s', async (_n, go, reason) => {
    expect(await go()).toEqual(denied(reason));
  });

  it('construction refuses an empty measurement allowlist and an empty trusted-key set', () => {
    expect(() => verifier(st, { policy: { measurements: [] } })).toThrow('createPqSoftwareVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)');
    expect(() => verifier(st, { trustedPqPublicKeys: [] })).toThrow('createPqSoftwareVerifier: at least one trusted PQ public key is required (fail closed)');
  });

  it('is labelled software, so it can neither satisfy a hardware requirement nor back a hardware-bound prover key', () => {
    const v = verifier(st);
    expect(assuranceLabelOf(v)).toEqual({ level: 'software', vendor: 'pq-software' });
    expect(() => createZkVerifier({ trustedProverKeys: ['k'], proverAttestation: { hardwareVerifier: v, expectedBinding: () => EXPECTED, measurements: [MEAS] } })).toThrow('proverAttestation.hardwareVerifier must carry a hardware or multi_root assurance label');
  });
});
