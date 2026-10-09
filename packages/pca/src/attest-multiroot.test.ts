/**
 * Validation of the multi-root N-of-M attestation policy (`createMultiRootVerifier` in `attestation.ts`).
 *
 * The threshold / required-root / identity-reconciliation logic is independent of any vendor wire format, so
 * the CPU-TEE and GPU roots here are small TEST-DOUBLE `HardwareAttestationVerifier`s (plain objects that
 * check the PCA binding and return a fixed measured identity). The two software roots, PQ-software
 * (ML-DSA) and PUF, use their REAL constructors. Real-silicon verification is covered in
 * `attest-multiroot-real.test.ts`, `attest-amd-snp.test.ts`, `attest-intel-dcap.test.ts` and
 * `attest-nvidia-spdm.test.ts`.
 *
 * Every root binds to the SAME action (holder/grant/epoch/nonce) and corroborates the SAME measured
 * workload. The tests prove: the threshold logic passes at/above the threshold and fails below; a REQUIRED
 * root that is missing/invalid denies regardless of threshold; a disagreement between roots on the measured
 * identity denies; the "(AMD OR Intel) AND NVIDIA AND PQ" combination is expressible; and the composed
 * verifier plugs into `createAttestationVerifier` so the reconciled identity flows through agent_binding.
 */
import { describe, expect, it } from 'vitest';
import {
  type AttestationRoot,
  type ExpectedAttestationBinding,
  type HardwareAttestationResult,
  type HardwareAttestationVerifier,
  type MeasuredIdentity,
  attestationBinding,
  createAttestationVerifier,
  createMultiRootVerifier,
} from './attestation';
import { createPqSoftwareAttestor, createPqSoftwareVerifier } from './attest-pq-software';
import { createPufAttestor, createPufEnrollmentRegistry, createPufVerifier, createSimulatedPuf, enrollPuf } from './attest-puf';
import { mlDsa65Keygen } from './pq';
import { encodeKey, generateKeyPair } from './keys';
import { mintGrant, type AgentBinding } from './envelope';
import { buildPCActn, type PCActn } from './pcactn';
import { DEFAULT_RISK_POLICY } from './risk';
import type { Capability } from './capability';
import type { AttestationDocument } from './attestation';

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

// ── the shared action + the one workload measurement every root corroborates ──────────────────────
const SHARED_HEX = toHex(new Uint8Array(48).fill(0xab)); // the measured workload
const CHIP_HEX = toHex(new Uint8Array(64).fill(0x5c));
const T = 1_000_000;
const P = generateKeyPair();
const A = generateKeyPair();
const NONCE = 'nonce-multiroot-1';
const EXPECTED: ExpectedAttestationBinding = {
  holderPub: encodeKey(A.publicKey),
  grantRef: 'grant-multiroot-1',
  epoch: 1,
  nonce: NONCE,
  nonceIssuedAt: T - 1000,
};

// ══ TEST-DOUBLE hardware roots ══
interface DoubleOpts {
  present?: boolean;
  required?: boolean;
  measurement?: string;
  operator?: string;
  /** The binding the double's "quote" was produced for; a mismatch with `expected` fails the root. */
  boundTo?: ExpectedAttestationBinding;
}
/** A HardwareAttestationVerifier double: fails without evidence or on a binding mismatch, else returns a fixed identity. */
function hwDouble(id: string, suite: string, opts: DoubleOpts & { defaultOperator?: string } = {}): AttestationRoot {
  const verifier: HardwareAttestationVerifier = {
    verify({ expected }): HardwareAttestationResult {
      if (opts.present === false) return { ok: false, reason: `${id}: no evidence resolver` };
      const bound = toHex(attestationBinding(opts.boundTo ?? EXPECTED));
      if (bound !== toHex(attestationBinding(expected))) return { ok: false, reason: `${id}: report_data does not bind holder/grant/epoch/nonce` };
      const measured: MeasuredIdentity = {
        model_id: '',
        weights_digest: '',
        weights_measured: false,
        runtime_measurement: opts.measurement ?? SHARED_HEX,
        operator: opts.operator ?? opts.defaultOperator ?? '',
      };
      return { ok: true, bound: true, measured };
    },
  };
  return { id, verifier, required: opts.required, suite };
}
// Only the CPU TEE asserts an operator (the chip id); the others leave it empty so reconciliation takes it.
const sevRoot = (o: DoubleOpts = {}) => hwDouble('amd-sev-snp', 'ecdsa-p384-sha384', { ...o, defaultOperator: CHIP_HEX });
const intelRoot = (o: DoubleOpts = {}) => hwDouble('intel-tdx', 'ecdsa-p256-sha256', o);
const nvidiaRoot = (o: DoubleOpts = {}) => hwDouble('nvidia-gpu-cc', 'ecdsa-p256-sha256', o);

// ══ PQ-software evidence (REAL constructors) ══
const PQ_ATTESTOR = createPqSoftwareAttestor({ alg: 'ml-dsa-65', mlDsa: mlDsa65Keygen(new Uint8Array(32).fill(3)) });
function pqRoot(opts: { present?: boolean; required?: boolean; measurement?: string } = {}): AttestationRoot {
  const st = PQ_ATTESTOR.attest({ measurement: opts.measurement ?? SHARED_HEX, holder_pub: EXPECTED.holderPub, grant_ref: EXPECTED.grantRef, epoch: EXPECTED.epoch, nonce: EXPECTED.nonce });
  const verifier = createPqSoftwareVerifier({ trustedPqPublicKeys: [PQ_ATTESTOR.pqPublicKey], policy: { measurements: [opts.measurement ?? SHARED_HEX] }, resolveEvidence: () => (opts.present === false ? undefined : st) });
  return { id: 'pq-software', verifier, required: opts.required, suite: 'ml-dsa-65' };
}

// ══ PUF evidence (REAL constructors) ══
const PUF_PROVIDER = createSimulatedPuf({ id: 'node-1', seed: new Uint8Array(32).fill(0x44), length: 28 });
const PUF_ENROLLMENT = enrollPuf(PUF_PROVIDER, new Uint8Array([0x01]), { rep: 7, messageBits: 4, alg: 'ml-dsa-65', randomBytes: (n) => new Uint8Array(n).map((_, i) => (i * 5 + 1) & 0xff) });
const PUF_REGISTRY = createPufEnrollmentRegistry([PUF_ENROLLMENT]);
function pufRoot(opts: { present?: boolean; required?: boolean; measurement?: string } = {}): AttestationRoot {
  const st = createPufAttestor(PUF_PROVIDER, PUF_ENROLLMENT).attest({ measurement: opts.measurement ?? SHARED_HEX, holder_pub: EXPECTED.holderPub, grant_ref: EXPECTED.grantRef, epoch: EXPECTED.epoch, nonce: EXPECTED.nonce });
  const verifier = createPufVerifier({ resolveEnrollment: (id) => PUF_REGISTRY.lookup(id), policy: { measurements: [opts.measurement ?? SHARED_HEX] }, resolveEvidence: () => (opts.present === false ? undefined : st) });
  return { id: 'puf', verifier, required: opts.required, suite: 'ml-dsa-65' };
}

function directVerify(v: HardwareAttestationVerifier) {
  return v.verify({ document: {} as never, ctx: {} as never, nowMs: T, expected: EXPECTED });
}

describe('multi-root N-of-M: all five roots corroborate one action', () => {
  it('ACCEPTS when all five roots verify (threshold 5) and reconciles the identity', async () => {
    const v = createMultiRootVerifier({ roots: [sevRoot(), intelRoot(), nvidiaRoot(), pqRoot(), pufRoot()], threshold: 5 });
    const r = await directVerify(v);
    expect(r.ok).toBe(true);
    expect(r.bound).toBe(true);
    expect(r.measured?.runtime_measurement).toBe(SHARED_HEX);
    expect(r.measured?.operator).toBe(CHIP_HEX); // only the CPU TEE asserts operator; reconciliation takes it
  });

  it('ACCEPTS at threshold 3 with two roots absent (below-count roots skipped, not fatal)', async () => {
    const v = createMultiRootVerifier({ roots: [sevRoot(), intelRoot({ present: false }), nvidiaRoot(), pqRoot(), pufRoot({ present: false })], threshold: 3 });
    const r = await directVerify(v);
    expect(r.ok).toBe(true);
  });

  it('DENIES below threshold (only 2 of a required 4 corroborate)', async () => {
    const v = createMultiRootVerifier({ roots: [sevRoot(), intelRoot({ present: false }), nvidiaRoot({ present: false }), pqRoot(), pufRoot({ present: false })], threshold: 4 });
    const r = await directVerify(v);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/below threshold \(2\/4/);
  });

  it('a root bound to a DIFFERENT action (relayed quote) does not count toward the threshold', async () => {
    const relayed = { ...EXPECTED, nonce: 'other-nonce' };
    const v = createMultiRootVerifier({ roots: [sevRoot(), intelRoot({ boundTo: relayed }), nvidiaRoot(), pqRoot()], threshold: 4 });
    const r = await directVerify(v);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/below threshold \(3\/4/);
  });
});

describe('multi-root N-of-M: required roots + identity reconciliation', () => {
  it('DENIES when a REQUIRED root is missing, regardless of threshold being met by others', async () => {
    // nvidia required but absent; sev+intel+pq+puf (4) would otherwise exceed threshold 3
    const v = createMultiRootVerifier({ roots: [sevRoot(), intelRoot(), nvidiaRoot({ present: false, required: true }), pqRoot(), pufRoot()], threshold: 3 });
    const r = await directVerify(v);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/required attestation root 'nvidia-gpu-cc' failed/);
  });

  it('DENIES when two roots DISAGREE on the measured identity (conflict)', async () => {
    const other = toHex(new Uint8Array(48).fill(0x22));
    const v = createMultiRootVerifier({ roots: [sevRoot(), intelRoot({ measurement: other }), nvidiaRoot(), pqRoot(), pufRoot()], threshold: 5 });
    const r = await directVerify(v);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/identity conflict/);
  });

  it('DENIES when roots disagree on the operator identity', async () => {
    const v = createMultiRootVerifier({ roots: [sevRoot(), intelRoot({ operator: 'another-operator' })], threshold: 2 });
    const r = await directVerify(v);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/identity conflict/);
  });

  it('expresses "(AMD OR Intel) AND NVIDIA AND PQ": needs a CPU TEE plus the two required roots', async () => {
    const make = (sevPresent: boolean, intelPresent: boolean) =>
      createMultiRootVerifier({
        roots: [sevRoot({ present: sevPresent }), intelRoot({ present: intelPresent }), nvidiaRoot({ required: true }), pqRoot({ required: true })],
        threshold: 3,
      });
    // AMD present, Intel absent -> AMD + NVIDIA + PQ = 3 -> OK
    expect((await directVerify(make(true, false))).ok).toBe(true);
    // Intel present, AMD absent -> Intel + NVIDIA + PQ = 3 -> OK
    expect((await directVerify(make(false, true))).ok).toBe(true);
    // BOTH CPU TEEs absent -> only NVIDIA + PQ = 2 < 3 -> DENIED (required roots pass, threshold not met)
    const neither = await directVerify(make(false, false));
    expect(neither.ok).toBe(false);
    expect(neither.reason).toMatch(/below threshold \(2\/3/);
  });

  it('construction rejects duplicate root ids / out-of-range threshold', () => {
    expect(() => createMultiRootVerifier({ roots: [sevRoot(), sevRoot()], threshold: 1 })).toThrow(/duplicate root id/);
    expect(() => createMultiRootVerifier({ roots: [sevRoot()], threshold: 2 })).toThrow(/threshold must be an integer/);
  });
});

// ── integration: the composed verifier plugs into createAttestationVerifier + agent_binding ─────────
function grantWith(binding: AgentBinding): Capability {
  return mintGrant({
    principalSecret: P.secretKey,
    principalPublic: encodeKey(P.publicKey),
    holder: encodeKey(A.publicKey),
    goal: 'secure my account',
    envelope: { predicates: [{ verb: 'read', resource: '/acct/*' }], caveats: [], agent_binding: binding, risk_policy: DEFAULT_RISK_POLICY },
  }).grant;
}
function pcactn(grant: Capability): PCActn {
  return buildPCActn({
    aud: 'test-aud',
    grant,
    chain: [grant],
    plan: [{ id: 'n1', verb: 'read', resource: '/acct/1', reversibility_class: 'reversible' }],
    nodeId: 'n1',
    counter: 1,
    signerSecret: A.secretKey,
    attestation: { quote_digest: NONCE, epoch: 1, model_id: 'gpt-x', measurement: SHARED_HEX, operator: CHIP_HEX },
  });
}
function hwDoc(): AttestationDocument {
  return { model_id: 'ignored', weights_digest: 'ignored', runtime_measurement: 'ignored', operator: 'ignored', nonce: NONCE, issued_at: T - 1000, expires_at: T + 60_000, attestor: 'n/a', mode: 'hardware', sig: 'n/a' };
}

describe('multi-root N-of-M: plugs into createAttestationVerifier (reconciled identity → agent_binding)', () => {
  function run(grant: Capability, mkRoots: (base: ExpectedAttestationBinding, grantRef: string) => AttestationRoot[], threshold = 3) {
    const p = pcactn(grant);
    const base: ExpectedAttestationBinding = { ...EXPECTED, grantRef: p.grant_ref };
    const hw = createMultiRootVerifier({ roots: mkRoots(base, p.grant_ref), threshold });
    const verify = createAttestationVerifier({
      trustedAttestorKeys: [],
      hardwareVerifier: hw,
      resolveDocument: () => hwDoc(),
      expectedBinding: () => base,
      now: () => T,
    });
    return verify({ pcactn: p, grant });
  }
  const roots = (base: ExpectedAttestationBinding, grantRef: string): AttestationRoot[] => [
    hwDouble('amd-sev-snp', 'ecdsa-p384-sha384', { required: true, boundTo: base, defaultOperator: CHIP_HEX }),
    hwDouble('nvidia-gpu-cc', 'ecdsa-p256-sha256', { required: true, boundTo: base }),
    {
      id: 'pq-software',
      required: true,
      suite: 'ml-dsa-65',
      verifier: createPqSoftwareVerifier({
        trustedPqPublicKeys: [PQ_ATTESTOR.pqPublicKey],
        policy: { measurements: [SHARED_HEX] },
        resolveEvidence: () => PQ_ATTESTOR.attest({ measurement: SHARED_HEX, holder_pub: base.holderPub, grant_ref: grantRef, epoch: base.epoch, nonce: base.nonce }),
      }),
    },
  ];

  it('FULL PATH: a 3-of-3 multi-root verifier satisfies a grant pinning the shared measurement', async () => {
    const res = await run(grantWith({ min_measurement: SHARED_HEX, operator: CHIP_HEX }), roots);
    expect(res).toEqual({ enforced: true, ok: true, present: true, bound: true });
  });

  it('the RECONCILED identity (not the document) is matched against agent_binding', async () => {
    const res = await run(grantWith({ min_measurement: SHARED_HEX, operator: 'some-other-operator' }), roots);
    expect(res).toMatchObject({ enforced: true, ok: false, bound: false });
    expect((res as { reason: string }).reason).toMatch(/operator/);
  });

  it('a required root that fails denies the whole attestation through the hook', async () => {
    const res = await run(grantWith({ min_measurement: SHARED_HEX }), (base, ref) => [
      hwDouble('amd-sev-snp', 'ecdsa-p384-sha384', { boundTo: base }),
      hwDouble('nvidia-gpu-cc', 'ecdsa-p256-sha256', { required: true, present: false }),
      roots(base, ref)[2]!,
    ], 2);
    expect(res).toMatchObject({ enforced: true, ok: false });
    expect((res as { reason: string }).reason).toMatch(/required attestation root 'nvidia-gpu-cc' failed/);
  });
});
