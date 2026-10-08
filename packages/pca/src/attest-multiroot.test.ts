/**
 * CROSS-ROOT validation of the multi-root N-of-M attestation policy (`createMultiRootVerifier` in
 * `attestation.ts`) wired with ALL FIVE independent roots:
 *   - AMD SEV-SNP   (hardware-sevsnp.ts)       CLASSICAL ECDSA-P384 CPU TEE
 *   - Intel TDX     (attest-intel-tdx.ts)      CLASSICAL ECDSA-P256 CPU TEE
 *   - NVIDIA GPU-CC (attest-nvidia-cc.ts)      CLASSICAL ECDSA-P256 GPU TEE
 *   - PQ software   (attest-pq-software.ts)    POST-QUANTUM ML-DSA (HSM root)
 *   - PUF           (attest-puf.ts)            UNCLONABLE (classical property); PQ-derived key here
 *
 * Every root binds to the SAME action (holder/grant/epoch/nonce) and corroborates the SAME measured
 * workload. The tests prove: the threshold logic passes at/above the threshold and fails below; a REQUIRED
 * root that is missing/invalid denies regardless of threshold; a disagreement between roots on the measured
 * identity denies; the "(AMD OR Intel) AND NVIDIA AND PQ" combination is expressible; and the composed
 * verifier plugs into `createAttestationVerifier` so the reconciled identity flows through agent_binding.
 */
import { describe, expect, it } from 'vitest';
import { p384 } from '@noble/curves/p384';
import { p256 } from '@noble/curves/p256';
import { sha384 } from '@noble/hashes/sha512';
import { sha256 } from './hash';
import {
  type AttestationRoot,
  type ExpectedAttestationBinding,
  type HardwareAttestationVerifier,
  attestationBinding,
  createAttestationVerifier,
  createMultiRootVerifier,
} from './attestation';
import {
  type SevSnpCertChain,
  type SevSnpEvidence,
  createSevSnpVerifier,
  ecdsaP384PublicKey,
  parseSevSnpReport,
  serializeSevSnpReport,
  toHex,
} from './hardware-sevsnp';
import {
  type IntelPckChain,
  type IntelTdxQuote,
  createIntelTdxVerifier,
  ecdsaP256PublicKey,
  encodeTdxTbs,
  serializeTdReport,
} from './attest-intel-tdx';
import {
  type NvidiaCertChain,
  type NvidiaGpuAttestation,
  createNvidiaCcVerifier,
  encodeNvidiaTbs,
  serializeNvidiaReport,
} from './attest-nvidia-cc';
import { createPqSoftwareAttestor, createPqSoftwareVerifier } from './attest-pq-software';
import { createPufAttestor, createPufEnrollmentRegistry, createPufVerifier, createSimulatedPuf, enrollPuf } from './attest-puf';
import { mlDsa65Keygen } from './pq';
import { encodeKey, generateKeyPair } from './keys';
import { mintGrant, type AgentBinding } from './envelope';
import { buildPCActn, type PCActn } from './pcactn';
import { DEFAULT_RISK_POLICY } from './risk';
import type { Capability } from './capability';
import type { AttestationDocument } from './attestation';

// ── the shared action + the one workload measurement every root corroborates ──────────────────────
const SHARED = new Uint8Array(48).fill(0xab); // the measured workload (48-byte launch/TD/GPU measurement)
const SHARED_HEX = toHex(SHARED);
const CHIP_ID = new Uint8Array(64).fill(0x5c);
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
const BOUND = attestationBinding(EXPECTED);
function cat(...a: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(a.reduce((n, x) => n + x.length, 0));
  let o = 0;
  for (const x of a) {
    out.set(x, o);
    o += x.length;
  }
  return out;
}

// ══ AMD SEV-SNP evidence (synthetic P-384 chain, real ECDSA — ported from hardware-sevsnp.test.ts) ══
function genP384() {
  const priv = p384.utils.randomPrivateKey();
  return { priv, pub: ecdsaP384PublicKey(p384.getPublicKey(priv, false)) };
}
const ARK = genP384();
const ASK = genP384();
const VCEK = genP384();
function signP384(priv: Uint8Array, msg: Uint8Array): Uint8Array {
  return p384.sign(sha384(msg), priv, { lowS: false }).toCompactRawBytes();
}
function toLe72(be: Uint8Array): Uint8Array {
  const le = new Uint8Array(72);
  for (let i = 0; i < be.length; i++) le[i] = be[be.length - 1 - i]!;
  return le;
}
const OID_ARC = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x9c, 0x78, 0x01];
const oidTlv = (tail: number[]) => Uint8Array.from([0x06, OID_ARC.length + tail.length, ...OID_ARC, ...tail]);
const spki384 = (pt: Uint8Array) => cat(Uint8Array.from([0x03, 0x62, 0x00]), pt);
const extInt = (tail: number[], v: number) => cat(oidTlv(tail), Uint8Array.from([0x04, 0x03, 0x02, 0x01, v]));
const extHwId = (chip: Uint8Array) => cat(oidTlv([0x04]), Uint8Array.from([0x04, 0x42, 0x04, 0x40]), chip);
const pre = (s: string) => new TextEncoder().encode(s);
function sevChain(): SevSnpCertChain {
  const ask_tbs = cat(pre('ASK-tbs|'), spki384(ASK.pub.point), pre('|end'));
  const vcek_tbs = cat(pre('VCEK-tbs|'), spki384(VCEK.pub.point), extHwId(CHIP_ID), extInt([0x03, 0x01], 7), extInt([0x03, 0x02], 0), extInt([0x03, 0x03], 3), extInt([0x03, 0x08], 0));
  return { ark: ARK.pub, ask: ASK.pub, vcek: VCEK.pub, ask_tbs, ask_sig: signP384(ARK.priv, ask_tbs), vcek_tbs, vcek_sig: signP384(ASK.priv, vcek_tbs) };
}
function sevReport(reportData: Uint8Array = BOUND): Uint8Array {
  const over = { version: 2, guest_svn: 3, vmpl: 0, reported_tcb: 0x0003_0000_0000_0007n, report_data: reportData, measurement: SHARED, chip_id: CHIP_ID, host_data: new Uint8Array(32).fill(0x7d) };
  const base = serializeSevSnpReport(over);
  const parsed = parseSevSnpReport(base);
  const compact = signP384(VCEK.priv, parsed.signed);
  return serializeSevSnpReport({ ...over, signature: { r: toLe72(compact.subarray(0, 48)), s: toLe72(compact.subarray(48, 96)) } });
}
function sevRoot(opts: { present?: boolean; required?: boolean; reportData?: Uint8Array } = {}): AttestationRoot {
  const evidence: SevSnpEvidence = { report: sevReport(opts.reportData), chain: sevChain() };
  const verifier = createSevSnpVerifier({
    trustAnchorArk: ARK.pub,
    policy: { measurements: [SHARED_HEX], chipIds: [toHex(CHIP_ID)], requireVmpl: 0, minGuestSvn: 1 },
    resolveEvidence: () => (opts.present === false ? undefined : evidence),
  });
  return { id: 'amd-sev-snp', verifier, required: opts.required, suite: 'ecdsa-p384-sha384' };
}

// ══ Intel TDX evidence ══
const TDX_ROOT = { priv: p256.utils.randomPrivateKey() };
const TDX_ROOT_PUB = ecdsaP256PublicKey(p256.getPublicKey(TDX_ROOT.priv, false));
const TDX_PCK = p256.utils.randomPrivateKey();
const TDX_PCK_PUB = ecdsaP256PublicKey(p256.getPublicKey(TDX_PCK, false));
const TDX_AK = p256.utils.randomPrivateKey();
const TDX_AK_PUB = ecdsaP256PublicKey(p256.getPublicKey(TDX_AK, false));
const FMSPC = new Uint8Array(6).fill(0x5c);
function signP256(priv: Uint8Array, msg: Uint8Array): Uint8Array {
  return p256.sign(sha256(msg), priv, { lowS: false }).toCompactRawBytes();
}
function u16be(n: number): Uint8Array {
  const b = new Uint8Array(2);
  new DataView(b.buffer).setUint16(0, n, false);
  return b;
}
function intelQuote(mrtd: Uint8Array = SHARED, reportData: Uint8Array = BOUND): IntelTdxQuote {
  const header = new Uint8Array([0x04, 0x00, 0x81, 0x00]);
  const reportBody = serializeTdReport({ report_data: reportData, mrtd, tee_tcb_svn: 3 });
  const qeAuth = new Uint8Array([0x11, 0x22]);
  const qeReportBody = new Uint8Array(384);
  qeReportBody.set(cat(sha256(cat(TDX_AK_PUB.point, qeAuth)), new Uint8Array(32)), 0x140);
  const leafTbs = encodeTdxTbs([{ tag: 0x01, value: TDX_PCK_PUB.point }, { tag: 0x02, value: FMSPC }, { tag: 0x03, value: u16be(5) }]);
  const chain: IntelPckChain = { rootCa: TDX_ROOT_PUB, intermediates: [], leaf: { subject: TDX_PCK_PUB, tbs: leafTbs, sig: signP256(TDX_ROOT.priv, leafTbs) } };
  return { header, reportBody, quoteSignature: signP256(TDX_AK, cat(header, reportBody)), akPub: TDX_AK_PUB, qeAuthData: qeAuth, qeReportBody, qeReportSignature: signP256(TDX_PCK, qeReportBody), pckChain: chain };
}
function intelRoot(opts: { present?: boolean; required?: boolean; mrtd?: Uint8Array } = {}): AttestationRoot {
  const q = intelQuote(opts.mrtd ?? SHARED);
  const verifier = createIntelTdxVerifier({ trustAnchorRootCa: TDX_ROOT_PUB, policy: { mrtds: [SHARED_HEX], fmspcs: [toHex(FMSPC)] }, resolveEvidence: () => (opts.present === false ? undefined : q) });
  return { id: 'intel-tdx', verifier, required: opts.required, suite: 'ecdsa-p256-sha256' };
}

// ══ NVIDIA GPU-CC evidence ══
const NV_ROOT = p256.utils.randomPrivateKey();
const NV_ROOT_PUB = ecdsaP256PublicKey(p256.getPublicKey(NV_ROOT, false));
const NV_DEV = p256.utils.randomPrivateKey();
const NV_DEV_PUB = ecdsaP256PublicKey(p256.getPublicKey(NV_DEV, false));
const GPU_ID = new Uint8Array(16).fill(0x5c);
function nvAttestation(measurement: Uint8Array = SHARED): NvidiaGpuAttestation {
  const reportBody = serializeNvidiaReport({ report_data: BOUND, measurement, gpu_id: GPU_ID });
  const devTbs = encodeNvidiaTbs([{ tag: 0x01, value: NV_DEV_PUB.point }, { tag: 0x02, value: GPU_ID }]);
  const chain: NvidiaCertChain = { root: NV_ROOT_PUB, intermediates: [], leaf: { subject: NV_DEV_PUB, tbs: devTbs, sig: signP256(NV_ROOT, devTbs) } };
  return { reportBody, reportSignature: signP256(NV_DEV, reportBody), certChain: chain };
}
function nvidiaRoot(opts: { present?: boolean; required?: boolean; measurement?: Uint8Array } = {}): AttestationRoot {
  const a = nvAttestation(opts.measurement ?? SHARED);
  const verifier = createNvidiaCcVerifier({ trustAnchorRoot: NV_ROOT_PUB, policy: { measurements: [SHARED_HEX], gpuIds: [toHex(GPU_ID)] }, resolveEvidence: () => (opts.present === false ? undefined : a) });
  return { id: 'nvidia-gpu-cc', verifier, required: opts.required, suite: 'ecdsa-p256-sha256' };
}

// ══ PQ-software evidence ══
const PQ_ATTESTOR = createPqSoftwareAttestor({ alg: 'ml-dsa-65', mlDsa: mlDsa65Keygen(new Uint8Array(32).fill(3)) });
function pqRoot(opts: { present?: boolean; required?: boolean; measurement?: string } = {}): AttestationRoot {
  const st = PQ_ATTESTOR.attest({ measurement: opts.measurement ?? SHARED_HEX, holder_pub: EXPECTED.holderPub, grant_ref: EXPECTED.grantRef, epoch: EXPECTED.epoch, nonce: EXPECTED.nonce });
  const verifier = createPqSoftwareVerifier({ trustedPqPublicKeys: [PQ_ATTESTOR.pqPublicKey], policy: { measurements: [opts.measurement ?? SHARED_HEX] }, resolveEvidence: () => (opts.present === false ? undefined : st) });
  return { id: 'pq-software', verifier, required: opts.required, suite: 'ml-dsa-65' };
}

// ══ PUF evidence ══
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
    expect(r.measured?.operator).toBe(toHex(CHIP_ID)); // only SEV-SNP asserts operator; reconciliation takes it
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
    const other = new Uint8Array(48).fill(0x22);
    // intel attests a DIFFERENT mrtd than the others, with its own single-value allowlist so it verifies
    // but yields a conflicting runtime_measurement the reconciler must reject.
    const vConflict = createMultiRootVerifier({
      roots: [
        sevRoot(),
        { id: 'intel-tdx', verifier: createIntelTdxVerifier({ trustAnchorRootCa: TDX_ROOT_PUB, policy: { mrtds: [toHex(other)], fmspcs: [toHex(FMSPC)] }, resolveEvidence: () => intelQuote(other) }) },
        nvidiaRoot(),
        pqRoot(),
        pufRoot(),
      ],
      threshold: 5,
    });
    const r = await directVerify(vConflict);
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
    attestation: { quote_digest: NONCE, epoch: 1, model_id: 'gpt-x', measurement: SHARED_HEX, operator: toHex(CHIP_ID) },
  });
}
function hwDoc(): AttestationDocument {
  return { model_id: 'ignored', weights_digest: 'ignored', runtime_measurement: 'ignored', operator: 'ignored', nonce: NONCE, issued_at: T - 1000, expires_at: T + 60_000, attestor: 'n/a', mode: 'hardware', sig: 'n/a' };
}

describe('multi-root N-of-M: plugs into createAttestationVerifier (reconciled identity → agent_binding)', () => {
  it('FULL PATH: a 3-of-5 multi-root verifier satisfies a grant pinning the shared measurement', async () => {
    const grant = grantWith({ min_measurement: SHARED_HEX, operator: toHex(CHIP_ID) });
    const p = pcactn(grant);
    const base: ExpectedAttestationBinding = { ...EXPECTED, grantRef: p.grant_ref };
    // rebuild roots bound to the grant's ref
    const boundTo = (gr: string): ExpectedAttestationBinding => ({ ...base, grantRef: gr });
    const rd = attestationBinding(boundTo(p.grant_ref));
    const roots: AttestationRoot[] = [
      { id: 'amd-sev-snp', required: true, verifier: createSevSnpVerifier({ trustAnchorArk: ARK.pub, policy: { measurements: [SHARED_HEX], chipIds: [toHex(CHIP_ID)], requireVmpl: 0, minGuestSvn: 1 }, resolveEvidence: () => ({ report: sevReport(rd), chain: sevChain() }) }) },
      { id: 'nvidia-gpu-cc', required: true, verifier: createNvidiaCcVerifier({ trustAnchorRoot: NV_ROOT_PUB, policy: { measurements: [SHARED_HEX], gpuIds: [toHex(GPU_ID)] }, resolveEvidence: () => ({ reportBody: serializeNvidiaReport({ report_data: rd, measurement: SHARED, gpu_id: GPU_ID }), reportSignature: signP256(NV_DEV, serializeNvidiaReport({ report_data: rd, measurement: SHARED, gpu_id: GPU_ID })), certChain: { root: NV_ROOT_PUB, intermediates: [], leaf: { subject: NV_DEV_PUB, tbs: encodeNvidiaTbs([{ tag: 0x01, value: NV_DEV_PUB.point }, { tag: 0x02, value: GPU_ID }]), sig: signP256(NV_ROOT, encodeNvidiaTbs([{ tag: 0x01, value: NV_DEV_PUB.point }, { tag: 0x02, value: GPU_ID }])) } } }) }) },
      { id: 'pq-software', required: true, verifier: createPqSoftwareVerifier({ trustedPqPublicKeys: [PQ_ATTESTOR.pqPublicKey], policy: { measurements: [SHARED_HEX] }, resolveEvidence: () => PQ_ATTESTOR.attest({ measurement: SHARED_HEX, holder_pub: base.holderPub, grant_ref: p.grant_ref, epoch: base.epoch, nonce: base.nonce }) }) },
    ];
    const hw = createMultiRootVerifier({ roots, threshold: 3 });
    const verify = createAttestationVerifier({
      trustedAttestorKeys: [],
      hardwareVerifier: hw,
      resolveDocument: () => hwDoc(),
      expectedBinding: () => boundTo(p.grant_ref),
      now: () => T,
    });
    const res = await verify({ pcactn: p, grant });
    expect(res).toEqual({ enforced: true, ok: true, present: true, bound: true });
  });
});
