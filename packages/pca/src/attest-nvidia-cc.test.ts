/**
 * HONEST VALIDATION of the NVIDIA GPU-CC attestation VERIFIER (`attest-nvidia-cc.ts`).
 *
 * No NVIDIA confidential-computing GPU in CI, so these build SYNTHETIC-but-cryptographically-real P-256
 * evidence (fresh NVIDIA root → device keypairs, real ECDSA-P256/SHA-256 signatures, a GPU report crafted
 * with known measurements + report_data and signed by a test device key). The decisive test asserts the
 * full path verifies end-to-end; the negatives exercise every fail-closed branch. CLASSICAL ECDSA-P256 root
 * (see the module header's honest-scope note) — it attests the GPU runtime, but is not post-quantum.
 */
import { describe, expect, it } from 'vitest';
import { p256 } from '@noble/curves/p256';
import { sha256 } from './hash';
import {
  type EcdsaP256PublicKey,
  type NvidiaCertChain,
  type NvidiaGpuAttestation,
  NVIDIA_CC_SUITE,
  checkNvidiaCcPolicy,
  createNvidiaCcVerifier,
  ecdsaP256PublicKey,
  encodeNvidiaTbs,
  parseNvidiaReport,
  serializeNvidiaReport,
  toHex,
} from './attest-nvidia-cc';
import { attestationBinding, type ExpectedAttestationBinding } from './attestation';
import { encodeKey, generateKeyPair } from './keys';

interface P256Key {
  priv: Uint8Array;
  pub: EcdsaP256PublicKey;
}
function genP256(): P256Key {
  const priv = p256.utils.randomPrivateKey();
  return { priv, pub: ecdsaP256PublicKey(p256.getPublicKey(priv, false)) };
}
function signP256(priv: Uint8Array, msg: Uint8Array): Uint8Array {
  return p256.sign(sha256(msg), priv, { lowS: false }).toCompactRawBytes();
}

const ROOT = genP256();
const DEVICE = genP256();
const MEASUREMENT = new Uint8Array(48).fill(0xc1);
const VBIOS = new Uint8Array(16).fill(0x01);
const DRIVER = new Uint8Array(16).fill(0x02);
const GPU_ID = new Uint8Array(16).fill(0x5c);
const WEIGHTS = new Uint8Array(48).fill(0x9e);
const T = 1_000_000;
const A = generateKeyPair();
const EXPECTED: ExpectedAttestationBinding = {
  holderPub: encodeKey(A.publicKey),
  grantRef: 'grant-nv-1',
  epoch: 1,
  nonce: 'nonce-nv-1',
  nonceIssuedAt: T - 1000,
};
const BOUND = attestationBinding(EXPECTED);

interface DeviceOpts {
  subject?: EcdsaP256PublicKey;
  gpuId?: Uint8Array;
  issuerPriv?: Uint8Array;
}
function buildDevice(o: DeviceOpts = {}): NvidiaCertChain['leaf'] {
  const subject = o.subject ?? DEVICE.pub;
  const tbs = encodeNvidiaTbs([
    { tag: 0x01, value: subject.point },
    { tag: 0x02, value: o.gpuId ?? GPU_ID },
  ]);
  return { subject, tbs, sig: signP256(o.issuerPriv ?? ROOT.priv, tbs) };
}
function buildChain(over: Partial<NvidiaCertChain> = {}, dev: DeviceOpts = {}): NvidiaCertChain {
  return { root: ROOT.pub, intermediates: [], leaf: buildDevice(dev), ...over };
}
interface AttOpts {
  reportOver?: Parameters<typeof serializeNvidiaReport>[0];
  reportBind?: Partial<ExpectedAttestationBinding>;
  chain?: NvidiaCertChain;
  dev?: DeviceOpts;
  signer?: Uint8Array;
  tamperSig?: boolean;
}
function buildAttestation(o: AttOpts = {}): NvidiaGpuAttestation {
  const reportBody = serializeNvidiaReport({
    report_data: o.reportBind ? attestationBinding({ ...EXPECTED, ...o.reportBind }) : BOUND,
    measurement: MEASUREMENT,
    vbios_version: VBIOS,
    driver_version: DRIVER,
    gpu_id: GPU_ID,
    ...(o.reportOver ?? {}),
  });
  let reportSignature = signP256(o.signer ?? DEVICE.priv, reportBody);
  if (o.tamperSig) {
    const s = reportSignature.slice();
    s[0] = (s[0]! ^ 0xff) & 0xff;
    reportSignature = s;
  }
  return { reportBody, reportSignature, certChain: o.chain ?? buildChain({}, o.dev ?? {}) };
}

const POLICY = { measurements: [toHex(MEASUREMENT)], gpuIds: [toHex(GPU_ID)] };
function verifier(over: Partial<Parameters<typeof createNvidiaCcVerifier>[0]> = {}, att: NvidiaGpuAttestation = buildAttestation()) {
  return createNvidiaCcVerifier({ trustAnchorRoot: ROOT.pub, policy: POLICY, resolveEvidence: () => att, ...over });
}
function run(v: ReturnType<typeof createNvidiaCcVerifier>) {
  return v.verify({ document: {} as never, ctx: {} as never, nowMs: T, expected: EXPECTED });
}

describe('attest-nvidia-cc: suite label + parse', () => {
  it('declares the classical ECDSA-P256 suite', () => {
    expect(NVIDIA_CC_SUITE).toBe('ecdsa-p256-sha256');
  });
  it('round-trips the GPU report body layout', () => {
    const r = parseNvidiaReport(serializeNvidiaReport({ report_data: BOUND, measurement: MEASUREMENT, gpu_id: GPU_ID, weights_measurement: WEIGHTS }));
    expect(toHex(r.measurement)).toBe(toHex(MEASUREMENT));
    expect(toHex(r.gpu_id)).toBe(toHex(GPU_ID));
    expect(toHex(r.weights_measurement)).toBe(toHex(WEIGHTS));
  });
});

describe('attest-nvidia-cc: decisive end-to-end path', () => {
  it('ACCEPTS a correctly-bound synthetic root→device GPU report (bound + measured)', async () => {
    const r = await run(verifier());
    expect(r.ok).toBe(true);
    expect(r.bound).toBe(true);
    expect(r.measured?.runtime_measurement).toBe(toHex(MEASUREMENT));
    expect(r.hostAsserted?.gpu_id).toBe(toHex(GPU_ID));
  });
  it('exposes a GPU-TEE-measured weights digest with weights_measured:true', async () => {
    const r = await run(verifier({}, buildAttestation({ reportOver: { report_data: BOUND, measurement: MEASUREMENT, gpu_id: GPU_ID, weights_measurement: WEIGHTS } })));
    expect(r.ok).toBe(true);
    expect(r.measured?.weights_digest).toBe(toHex(WEIGHTS));
    expect(r.measured?.weights_measured).toBe(true);
  });
});

describe('attest-nvidia-cc: fail-closed branches', () => {
  it('construction rejects an empty measurement allowlist', () => {
    expect(() => createNvidiaCcVerifier({ trustAnchorRoot: ROOT.pub, policy: { measurements: [] } })).toThrow(/NON-EMPTY/);
  });
  it('tampered report signature denied', async () => {
    const r = await run(verifier({}, buildAttestation({ tamperSig: true })));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/report signature does not verify/);
  });
  it('wrong NVIDIA root anchor denied', async () => {
    const r = await run(verifier({ trustAnchorRoot: genP256().pub }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/root does not match/);
  });
  it('device cert not signed by root denied', async () => {
    const r = await run(verifier({}, buildAttestation({ chain: buildChain({ leaf: buildDevice({ issuerPriv: DEVICE.priv }) }) })));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/not signed by its issuer/);
  });
  it('forged key/TBS pairing denied', async () => {
    const evil = genP256();
    const genuine = buildDevice();
    const r = await run(verifier({}, buildAttestation({ chain: buildChain({ leaf: { subject: evil.pub, tbs: genuine.tbs, sig: genuine.sig } }) })));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/subject key is not bound in its TBS/);
  });
  it('a certificate for a DIFFERENT GPU cannot vouch (gpu-id binding) denied', async () => {
    // device cert binds a different gpu id than the report
    const r = await run(verifier({}, buildAttestation({ dev: { gpuId: new Uint8Array(16).fill(0x11) } })));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/GPU id does not match/);
  });
  it('absent evidence (no resolver) denied', async () => {
    const r = await run(createNvidiaCcVerifier({ trustAnchorRoot: ROOT.pub, policy: POLICY }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/no NVIDIA GPU-CC evidence resolver/);
  });
  it('mismatched measurement denied', async () => {
    const r = await run(verifier({ policy: { measurements: ['00'.repeat(48)], gpuIds: [toHex(GPU_ID)] } }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/measurement not in policy allowlist/);
  });
  it('RELAY: report_data bound to another holder/grant/epoch/nonce denied', async () => {
    for (const wrong of [{ holderPub: encodeKey(generateKeyPair().publicKey) }, { grantRef: 'other' }, { epoch: 2 }, { nonce: 'other' }]) {
      const r = await run(verifier({}, buildAttestation({ reportBind: wrong })));
      expect(r.ok).toBe(false);
      expect(r.reason).toMatch(/report_data does not bind/);
    }
  });
  it('checkNvidiaCcPolicy gates measurement / vbios / driver / weights', () => {
    const report = parseNvidiaReport(serializeNvidiaReport({ measurement: MEASUREMENT, vbios_version: VBIOS, driver_version: DRIVER, gpu_id: GPU_ID, weights_measurement: WEIGHTS }));
    expect(checkNvidiaCcPolicy(report, { measurements: [toHex(MEASUREMENT)] })).toBeNull();
    expect(checkNvidiaCcPolicy(report, { measurements: ['00'] })).toMatch(/measurement/);
    expect(checkNvidiaCcPolicy(report, { measurements: [toHex(MEASUREMENT)], vbiosVersions: ['00'] })).toMatch(/VBIOS/);
    expect(checkNvidiaCcPolicy(report, { measurements: [toHex(MEASUREMENT)], driverVersions: ['00'] })).toMatch(/driver/);
    expect(checkNvidiaCcPolicy(report, { measurements: [toHex(MEASUREMENT)], weightsMeasurements: ['00'.repeat(48)] })).toMatch(/weights/);
  });
});
