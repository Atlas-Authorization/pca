/**
 * VALIDATION of the POST-QUANTUM software/HSM attestation root (`attest-pq-software.ts`).
 *
 * This is the one genuinely post-quantum root: statements are signed with ML-DSA (FIPS-204) / SLH-DSA
 * (FIPS-205), optionally hybrid with Ed25519, via the project's `pq.ts` suite seam. The tests prove an
 * ML-DSA statement verifies, a classical-only statement is rejected when PQ is required, every fail-closed
 * branch denies, and (honest) the measured identity carries `weights_measured: false` because a software
 * root is not a silicon TEE.
 */
import { describe, expect, it } from 'vitest';
import { canonicalBytes, utf8 } from './hash';
import { generateKeyPair, publicKeyOf } from './keys';
import { mlDsa65Keygen, signWithSuite } from './pq';
import { b64u } from './hash';
import {
  type PqAttestationStatement,
  PQ_ATTEST_DOMAIN,
  createPqSoftwareAttestor,
  createPqSoftwareVerifier,
} from './attest-pq-software';
import { attestationBinding, type ExpectedAttestationBinding } from './attestation';
import { encodeKey } from './keys';

const T = 1_000_000;
const A = generateKeyPair();
const EXPECTED: ExpectedAttestationBinding = {
  holderPub: encodeKey(A.publicKey),
  grantRef: 'grant-pq-1',
  epoch: 1,
  nonce: 'nonce-pq-1',
  nonceIssuedAt: T - 1000,
};
const MEASUREMENT = 'workload-measurement-abc';
const CLAIMS = { measurement: MEASUREMENT, holder_pub: EXPECTED.holderPub, grant_ref: EXPECTED.grantRef, epoch: EXPECTED.epoch, nonce: EXPECTED.nonce };

const mlDsa = mlDsa65Keygen(new Uint8Array(32).fill(7));
const edKp = generateKeyPair();

function run(v: ReturnType<typeof createPqSoftwareVerifier>) {
  return v.verify({ document: {} as never, ctx: {} as never, nowMs: T, expected: EXPECTED });
}

describe('attest-pq-software: ML-DSA statement (pure PQ)', () => {
  const attestor = createPqSoftwareAttestor({ alg: 'ml-dsa-65', mlDsa });
  const st = attestor.attest(CLAIMS);

  it('VERIFIES a valid ML-DSA-65 statement (bound + measured, weights NOT silicon-measured)', async () => {
    const v = createPqSoftwareVerifier({ trustedPqPublicKeys: [attestor.pqPublicKey], policy: { measurements: [MEASUREMENT] }, resolveEvidence: () => st });
    const r = await run(v);
    expect(r.ok).toBe(true);
    expect(r.bound).toBe(true);
    expect(r.measured?.runtime_measurement).toBe(MEASUREMENT);
    expect(r.measured?.weights_measured).toBe(false); // HONEST: software/HSM root, not silicon-measured
    expect(r.hostAsserted?.suite).toBe('ml-dsa-65');
  });

  it('a tampered signature is denied', async () => {
    const bad: PqAttestationStatement = { ...st, sig: st.sig.slice(0, -2) + (st.sig.endsWith('A') ? 'B' : 'A') };
    const v = createPqSoftwareVerifier({ trustedPqPublicKeys: [attestor.pqPublicKey], policy: { measurements: [MEASUREMENT] }, resolveEvidence: () => bad });
    const r = await run(v);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/signature does not verify/);
  });

  it('an untrusted PQ attestor key is denied', async () => {
    const other = createPqSoftwareAttestor({ alg: 'ml-dsa-65', mlDsa: mlDsa65Keygen(new Uint8Array(32).fill(9)) });
    const v = createPqSoftwareVerifier({ trustedPqPublicKeys: [other.pqPublicKey], policy: { measurements: [MEASUREMENT] }, resolveEvidence: () => st });
    const r = await run(v);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/attestor key is not trusted/);
  });

  it('RELAY: a binding to another action is denied', async () => {
    const relayed = attestor.attest({ ...CLAIMS, nonce: 'other-nonce' });
    const v = createPqSoftwareVerifier({ trustedPqPublicKeys: [attestor.pqPublicKey], policy: { measurements: [MEASUREMENT] }, resolveEvidence: () => relayed });
    const r = await run(v);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/binding mismatch/);
  });

  it('a measurement not in the policy allowlist is denied', async () => {
    const v = createPqSoftwareVerifier({ trustedPqPublicKeys: [attestor.pqPublicKey], policy: { measurements: ['something-else'] }, resolveEvidence: () => st });
    const r = await run(v);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/measurement not in policy allowlist/);
  });

  it('absent evidence (no resolver) is denied', async () => {
    const v = createPqSoftwareVerifier({ trustedPqPublicKeys: [attestor.pqPublicKey], policy: { measurements: [MEASUREMENT] } });
    const r = await run(v);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/no PQ-software evidence resolver/);
  });
});

describe('attest-pq-software: PQ requirement (rejects classical-only)', () => {
  // Hand-craft a well-formed, correctly-signed CLASSICAL (ed25519) statement.
  function classicalStatement(): PqAttestationStatement {
    const edPub = b64u(publicKeyOf(edKp.secretKey));
    const binding = b64u(attestationBinding(EXPECTED));
    const body = { measurement: MEASUREMENT, binding, alg: 'ed25519' as const, attestor_ed25519: edPub };
    const message = new Uint8Array([...utf8(PQ_ATTEST_DOMAIN), ...canonicalBytes(body)]);
    const parts = signWithSuite('ed25519', { edSecret: edKp.secretKey }, message);
    return { ...body, sig: parts.sig };
  }

  it('REJECTS a classical-only (ed25519) statement when PQ is required (default)', async () => {
    const v = createPqSoftwareVerifier({ trustedPqPublicKeys: ['ignored'], trustedEd25519PublicKeys: [b64u(publicKeyOf(edKp.secretKey))], policy: { measurements: [MEASUREMENT] }, resolveEvidence: () => classicalStatement() });
    const r = await run(v);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/PQ required: a classical-only suite/);
  });

  it('with requirePq:false a correctly-signed classical statement is accepted (branch proof)', async () => {
    const v = createPqSoftwareVerifier({ requirePq: false, trustedPqPublicKeys: ['ignored'], trustedEd25519PublicKeys: [b64u(publicKeyOf(edKp.secretKey))], policy: { measurements: [MEASUREMENT] }, resolveEvidence: () => classicalStatement() });
    const r = await run(v);
    expect(r.ok).toBe(true);
  });
});

describe('attest-pq-software: hybrid (ed25519 + ML-DSA)', () => {
  const attestor = createPqSoftwareAttestor({ alg: 'hybrid-ed25519-ml-dsa-65', mlDsa, edSecret: edKp.secretKey });
  const st = attestor.attest(CLAIMS);

  it('VERIFIES a hybrid statement when both attestor keys are trusted and hybrid is required', async () => {
    const v = createPqSoftwareVerifier({
      requireHybrid: true,
      trustedPqPublicKeys: [attestor.pqPublicKey],
      trustedEd25519PublicKeys: [attestor.ed25519PublicKey!],
      policy: { measurements: [MEASUREMENT] },
      resolveEvidence: () => st,
    });
    const r = await run(v);
    expect(r.ok).toBe(true);
    expect(r.bound).toBe(true);
  });

  it('a pure ML-DSA statement is denied when a hybrid is required', async () => {
    const pure = createPqSoftwareAttestor({ alg: 'ml-dsa-65', mlDsa }).attest(CLAIMS);
    const v = createPqSoftwareVerifier({ requireHybrid: true, trustedPqPublicKeys: [attestor.pqPublicKey], trustedEd25519PublicKeys: [attestor.ed25519PublicKey!], policy: { measurements: [MEASUREMENT] }, resolveEvidence: () => pure });
    const r = await run(v);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/hybrid required/);
  });

  it('an untrusted hybrid Ed25519 key is denied', async () => {
    const v = createPqSoftwareVerifier({ trustedPqPublicKeys: [attestor.pqPublicKey], trustedEd25519PublicKeys: ['not-the-attestor'], policy: { measurements: [MEASUREMENT] }, resolveEvidence: () => st });
    const r = await run(v);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/Ed25519 attestor key is not trusted/);
  });
});

describe('attest-pq-software: construction fail-closed', () => {
  it('rejects a classical suite at the attestor', () => {
    expect(() => createPqSoftwareAttestor({ alg: 'ed25519', edSecret: edKp.secretKey })).toThrow(/classical; the PQ root requires a post-quantum suite/);
  });
  it('rejects an empty measurement allowlist', () => {
    expect(() => createPqSoftwareVerifier({ trustedPqPublicKeys: ['x'], policy: { measurements: [] } })).toThrow(/NON-EMPTY/);
  });
  it('rejects an empty trusted-key set', () => {
    expect(() => createPqSoftwareVerifier({ trustedPqPublicKeys: [], policy: { measurements: [MEASUREMENT] } })).toThrow(/at least one trusted PQ public key/);
  });
});
