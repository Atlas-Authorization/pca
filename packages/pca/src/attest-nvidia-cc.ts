/**
 * L0 HARDWARE backend — NVIDIA GPU Confidential Computing (GPU-CC) attestation VERIFIER.
 *
 * A GPU attestation root for the multi-root N-of-M policy in `attestation.ts`, built to the SAME
 * `HardwareAttestationVerifier` seam as the AMD SEV-SNP (`hardware-sevsnp.ts`) and Intel TDX
 * (`attest-intel-tdx.ts`) backends and modelled on their structure. It verifies an NVIDIA GPU attestation
 * report (Hopper H100 / Blackwell confidential-computing mode): the measured GPU / driver / VBIOS state
 * plus a challenge, signed by the GPU's device-identity attestation key, whose certificate chains to the
 * NVIDIA Device Identity CA and the NVIDIA root.
 *
 * ── WHY A GPU ROOT AT ALL. ──────────────────────────────────────────────────────────────────────────
 * A CPU TEE (SEV-SNP / TDX) attests the confidential VM; but for AI agents the MODEL EXECUTES ON THE GPU.
 * In NVIDIA confidential computing the GPU is itself a measured, attestable TEE, so a GPU-CC attestation
 * is what actually binds "these weights ran on this attested accelerator in CC mode", not just "a CC VM
 * launched". That is the GPU-CC root's distinct contribution to the N-of-M policy.
 *
 * ── HONEST SCOPE — PQ STATUS: CLASSICAL. ────────────────────────────────────────────────────────────
 * NVIDIA's GPU attestation identity chain is ECDSA over NIST P-256 today. This root is therefore
 * CLASSICAL: it attests the GPU runtime (where the model executes) but a quantum adversary able to forge
 * ECDSA-P256 can forge it. It is NOT post-quantum and nothing here claims otherwise; its value is an
 * INDEPENDENT, GPU-rooted corroboration alongside the CPU-TEE roots. The genuinely post-quantum root is
 * `attest-pq-software.ts`. The suite seam ({@link NVIDIA_CC_SUITE}) is alg-agile for a future NVIDIA PQ
 * attestation suite.
 *
 * ── WHAT IS CRYPTOGRAPHICALLY VERIFIED (real @noble/curves P-256, exercised end-to-end by the tests). ─
 *   1. The device certificate chain to the configured NVIDIA root anchor: each link's TBS embeds its own
 *      subject key (the forged-pairing defence) and is ECDSA-P256-signed by its issuer; the root public key
 *      must byte-equal the configured anchor (never trusted from the chain).
 *   2. The device identity binding: the device leaf's signed TBS carries the GPU id, and the verifier
 *      requires it to equal the report's GPU id, so a certificate for a DIFFERENT GPU cannot vouch for this
 *      report (the analogue of SEV-SNP's CHIP_ID binding).
 *   3. The report signature: ECDSA-P256 over SHA-256(signed report body) under the device key.
 *   4. report_data === attestationBinding({holderPub, grantRef, epoch, nonce}) (see `attestation.ts`);
 *      NVIDIA's native nonce is 32 bytes, this PCA profile binds the full 64-byte attestationBinding into
 *      the report's challenge slot (documented adaptation).
 *   5. Policy gates: a NON-EMPTY measured-state allowlist (enforced at construction — no accept-all),
 *      optional VBIOS / driver / GPU-id / measured-weights allowlists.
 *
 * ── HONESTY: SYNTHETIC TEST VECTORS (no real GPU). ─────────────────────────────────────────────────
 * There is no NVIDIA confidential-computing GPU in CI to emit a genuine attestation report or genuine
 * device certificates. The tests build SYNTHETIC-but-cryptographically-real P-256 evidence (fresh root →
 * device keypairs, real ECDSA-P256 signatures, a report crafted with known measurements + report_data and
 * signed by a test device key), with the certificate TBS in a compact tagged-record encoding rather than
 * full X.509 DER. A production deployment replaces the evidence seam with a real NVIDIA attestation report
 * (via NVIDIA's attestation SDK / NRAS) and the X.509-decoded NVIDIA device/CA/root certificates and RIM
 * reference measurements; the cryptographic machinery proven here is unchanged.
 *
 * References: NVIDIA Confidential Computing attestation (Hopper/Blackwell); NVIDIA Remote Attestation
 * Service (NRAS); NVIDIA GPU attestation report + device identity certificate format.
 */
import { p256 } from '@noble/curves/p256';
import { sha256 } from './hash';
import { attestationBinding } from './attestation';
import type {
  AttestationDocument,
  HardwareAttestationResult,
  HardwareAttestationVerifier,
  MeasuredIdentity,
} from './attestation';
import type { VerifyContext } from './pcactn';

/** The signature suite NVIDIA GPU attestation produces today — classical ECDSA over NIST P-256 / SHA-256. */
export const NVIDIA_CC_SUITE = 'ecdsa-p256-sha256' as const;

// ── P-256 public keys + primitives ───────────────────────────────────────────────────────────────

/** A NIST P-256 public key, carried as the uncompressed SEC1 point (`0x04 ‖ X(32) ‖ Y(32)`, 65 bytes). */
export interface EcdsaP256PublicKey {
  readonly point: Uint8Array;
}

/** Wrap/validate a P-256 public key (uncompressed or compressed SEC1). Throws on an off-curve point. */
export function ecdsaP256PublicKey(sec1: Uint8Array): EcdsaP256PublicKey {
  const pt = p256.ProjectivePoint.fromHex(sec1);
  return { point: pt.toRawBytes(false) };
}

function verifyP256(msg: Uint8Array, sigCompact: Uint8Array, key: EcdsaP256PublicKey): boolean {
  try {
    return p256.verify(sigCompact, sha256(msg), key.point, { lowS: false });
  } catch {
    return false;
  }
}

function timingSafeEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

function isAllZero(b: Uint8Array): boolean {
  for (let i = 0; i < b.length; i++) if (b[i] !== 0) return false;
  return true;
}

/** Lowercase hex of a byte array. */
export function toHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i]!.toString(16).padStart(2, '0');
  return s;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

// ── compact tagged-record TBS codec (NOT X.509 — the documented synthetic cert body) ──────────────

const TAG_SUBJECT = 0x01;
const TAG_GPU_ID = 0x02;

/** Build a tagged-record TBS (`tag(1) ‖ len(u32be) ‖ value`, unique tags). The issuer signs SHA-256(tbs). */
export function encodeNvidiaTbs(records: ReadonlyArray<{ tag: number; value: Uint8Array }>): Uint8Array {
  const parts: Uint8Array[] = [];
  const seen = new Set<number>();
  for (const r of records) {
    if (seen.has(r.tag)) throw new RangeError(`encodeNvidiaTbs: duplicate tag ${r.tag}`);
    seen.add(r.tag);
    const head = new Uint8Array(5);
    head[0] = r.tag & 0xff;
    new DataView(head.buffer).setUint32(1, r.value.length, false);
    parts.push(head, r.value);
  }
  return concat(...parts);
}

function decodeNvidiaTbs(tbs: Uint8Array): Map<number, Uint8Array> | null {
  const out = new Map<number, Uint8Array>();
  let off = 0;
  while (off < tbs.length) {
    if (off + 5 > tbs.length) return null;
    const tag = tbs[off]!;
    const len = new DataView(tbs.buffer, tbs.byteOffset + off + 1, 4).getUint32(0, false);
    const start = off + 5;
    const end = start + len;
    if (end > tbs.length) return null;
    if (out.has(tag)) return null;
    out.set(tag, tbs.slice(start, end));
    off = end;
  }
  return out;
}

// ── GPU attestation report layout (synthetic PCA profile — documented, fixed offsets) ──────────────

const NV = {
  REPORT_DATA: 0x000, //         64 B  the PCA challenge binding (NVIDIA's 32-byte nonce, widened here)
  MEASUREMENT: 0x040, //         48 B  aggregate measured GPU / driver / firmware state
  VBIOS_VERSION: 0x070, //       16 B  measured VBIOS version
  DRIVER_VERSION: 0x080, //      16 B  measured driver version
  // PCA CONVENTION (NOT a standard NVIDIA field): the model runtime's MEASURED loaded-weights digest, inside
  // the signed region so the device-key signature covers it (rooted in the GPU TEE). All-zero => ABSENT.
  WEIGHTS_MEASUREMENT: 0x090, // 48 B
  GPU_ID: 0x0c0, //              16 B  GPU device identity (serial / UUID)
  SIGNED_END: 0x0d0, //          report body is [0x000, 0x0D0)
} as const;

/** The report-body length (bytes) covered by the device-key signature. */
export const NVIDIA_REPORT_BODY_LEN = NV.SIGNED_END;

/** A parsed NVIDIA GPU attestation report body. Byte-array fields are fresh copies. */
export interface ParsedNvidiaReport {
  report_data: Uint8Array; // 64
  measurement: Uint8Array; // 48
  vbios_version: Uint8Array; // 16
  driver_version: Uint8Array; // 16
  /** PCA convention: measured loaded-weights digest (48 B). All-zero => ABSENT. */
  weights_measurement: Uint8Array; // 48
  gpu_id: Uint8Array; // 16
  raw: Uint8Array;
}

/** Parse a GPU report body. Throws if too short. */
export function parseNvidiaReport(bytes: Uint8Array): ParsedNvidiaReport {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('parseNvidiaReport: expected Uint8Array');
  if (bytes.length < NV.SIGNED_END) throw new RangeError(`parseNvidiaReport: body too short (${bytes.length} < ${NV.SIGNED_END})`);
  return {
    report_data: bytes.slice(NV.REPORT_DATA, NV.REPORT_DATA + 64),
    measurement: bytes.slice(NV.MEASUREMENT, NV.MEASUREMENT + 48),
    vbios_version: bytes.slice(NV.VBIOS_VERSION, NV.VBIOS_VERSION + 16),
    driver_version: bytes.slice(NV.DRIVER_VERSION, NV.DRIVER_VERSION + 16),
    weights_measurement: bytes.slice(NV.WEIGHTS_MEASUREMENT, NV.WEIGHTS_MEASUREMENT + 48),
    gpu_id: bytes.slice(NV.GPU_ID, NV.GPU_ID + 16),
    raw: bytes.slice(),
  };
}

/** Serialize a GPU report body (TOOLING / TEST utility). */
export function serializeNvidiaReport(
  fields: Partial<{
    report_data: Uint8Array;
    measurement: Uint8Array;
    vbios_version: Uint8Array;
    driver_version: Uint8Array;
    weights_measurement: Uint8Array;
    gpu_id: Uint8Array;
  }>,
): Uint8Array {
  const out = new Uint8Array(NV.SIGNED_END);
  const put = (off: number, len: number, src?: Uint8Array) => {
    if (src) out.set(src.subarray(0, len), off);
  };
  put(NV.REPORT_DATA, 64, fields.report_data);
  put(NV.MEASUREMENT, 48, fields.measurement);
  put(NV.VBIOS_VERSION, 16, fields.vbios_version);
  put(NV.DRIVER_VERSION, 16, fields.driver_version);
  put(NV.WEIGHTS_MEASUREMENT, 48, fields.weights_measurement);
  put(NV.GPU_ID, 16, fields.gpu_id);
  return out;
}

// ── evidence + certificate-chain types ─────────────────────────────────────────────────────────────

/** One device-chain certificate: a subject key, its tagged TBS, and the issuer's ECDSA-P256 signature. */
export interface NvidiaCert {
  subject: EcdsaP256PublicKey;
  tbs: Uint8Array;
  sig: Uint8Array;
}

/** The NVIDIA device certificate chain: device leaf → (Device Identity CA) → NVIDIA root. */
export interface NvidiaCertChain {
  /** NVIDIA root public key — compared for equality against the configured anchor (never trusted from the chain). */
  root: EcdsaP256PublicKey;
  /** Intermediate certs (Device Identity CA), outermost first; each signed by the previous issuer. May be empty. */
  intermediates: NvidiaCert[];
  /** The device leaf certificate (signs the report); its TBS carries the GPU id. */
  leaf: NvidiaCert;
}

/** All the evidence to verify one action's NVIDIA GPU-CC attestation. */
export interface NvidiaGpuAttestation {
  /** The raw GPU report body (parsed by {@link parseNvidiaReport}); the device key signs SHA-256(reportBody). */
  reportBody: Uint8Array;
  /** The report signature: ECDSA-P256 (compact r‖s) over SHA-256(reportBody) under the device leaf key. */
  reportSignature: Uint8Array;
  /** The device certificate chain. */
  certChain: NvidiaCertChain;
}

/**
 * Acceptance policy for a verified GPU report. `measurements` is REQUIRED and NON-EMPTY (no accept-all);
 * every other gate is optional. All hex comparisons are lowercase.
 */
export interface NvidiaCcPolicy {
  /** Allowed aggregate measured-state values (lowercase hex of the 48-byte MEASUREMENT). REQUIRED and NON-EMPTY. */
  measurements: string[];
  /** Allowed VBIOS versions (lowercase hex of the 16-byte slot). Omitted => not gated. */
  vbiosVersions?: string[];
  /** Allowed driver versions (lowercase hex of the 16-byte slot). Omitted => not gated. */
  driverVersions?: string[];
  /** Allowed GPU ids (lowercase hex of the 16-byte id). Omitted => any (cert-bound) GPU. */
  gpuIds?: string[];
  /** Allowed MEASURED-weights digests (lowercase hex). Omitted/empty => not gated here. */
  weightsMeasurements?: string[];
  /** Map a verified report into the `MeasuredIdentity` agent_binding is checked against (override to customise). */
  deriveIdentity?: (report: ParsedNvidiaReport) => MeasuredIdentity;
}

export interface NvidiaCcVerifierOptions {
  /** The configured NVIDIA root trust anchor. The chain's root must byte-equal this. */
  trustAnchorRoot: EcdsaP256PublicKey;
  /** Acceptance policy (measured-state allowlist required). */
  policy: NvidiaCcPolicy;
  /**
   * EVIDENCE SEAM: produce the attestation report + device chain for an action. Production reads the
   * NVIDIA attestation report + X.509 device chain. If omitted, the verifier fails closed (no evidence).
   */
  resolveEvidence?: (
    document: AttestationDocument,
    ctx: VerifyContext,
  ) => NvidiaGpuAttestation | undefined | Promise<NvidiaGpuAttestation | undefined>;
}

function tbsBindsSubject(records: Map<number, Uint8Array>, key: EcdsaP256PublicKey): boolean {
  const s = records.get(TAG_SUBJECT);
  return s !== undefined && timingSafeEq(s, key.point);
}

function verifyDeviceChain(chain: NvidiaCertChain, anchor: EcdsaP256PublicKey): { ok: true; leaf: Map<number, Uint8Array> } | { ok: false; reason: string } {
  if (!timingSafeEq(chain.root.point, anchor.point)) return { ok: false, reason: 'NVIDIA root does not match the configured trust anchor' };
  let issuer = chain.root;
  const links: NvidiaCert[] = [...(Array.isArray(chain.intermediates) ? chain.intermediates : []), chain.leaf];
  let leafRecords: Map<number, Uint8Array> | null = null;
  for (let i = 0; i < links.length; i++) {
    const cert = links[i]!;
    const records = decodeNvidiaTbs(cert.tbs);
    if (!records) return { ok: false, reason: `malformed certificate TBS at chain index ${i}` };
    if (!tbsBindsSubject(records, cert.subject)) return { ok: false, reason: `certificate subject key is not bound in its TBS at chain index ${i}` };
    if (!verifyP256(cert.tbs, cert.sig, issuer)) return { ok: false, reason: `certificate at chain index ${i} is not signed by its issuer` };
    issuer = cert.subject;
    if (i === links.length - 1) leafRecords = records;
  }
  if (!leafRecords) return { ok: false, reason: 'empty device chain (no leaf)' };
  return { ok: true, leaf: leafRecords };
}

/**
 * Build a `HardwareAttestationVerifier` backed by NVIDIA GPU confidential computing. Given an attestation
 * document + context it resolves the GPU report + device chain (the evidence seam), then:
 *   1. parses the report body;
 *   2. verifies the device chain to the configured NVIDIA root anchor;
 *   3. binds the device cert's GPU id to the report's GPU id (a cert for another GPU cannot vouch);
 *   4. verifies the report signature under the device leaf key;
 *   5. confirms report_data === attestationBinding(expected);
 *   6. applies the acceptance policy and returns the measured GPU-runtime identity.
 * Fails CLOSED with a specific reason on any mismatch or error. Classical ECDSA-P256 — see the header.
 */
export function createNvidiaCcVerifier(opts: NvidiaCcVerifierOptions): HardwareAttestationVerifier {
  if (!opts?.policy || !Array.isArray(opts.policy.measurements) || opts.policy.measurements.length === 0) {
    throw new TypeError('createNvidiaCcVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)');
  }
  if (!opts.trustAnchorRoot || !(opts.trustAnchorRoot.point instanceof Uint8Array)) {
    throw new TypeError('createNvidiaCcVerifier: trustAnchorRoot is required');
  }
  const policy = opts.policy;
  const deriveIdentity = policy.deriveIdentity ?? defaultNvidiaIdentity;

  return {
    async verify(input): Promise<HardwareAttestationResult> {
      const fail = (reason: string): HardwareAttestationResult => ({ ok: false, reason });
      try {
        if (!opts.resolveEvidence) return fail('no NVIDIA GPU-CC evidence resolver configured (fail closed)');
        const a = await opts.resolveEvidence(input.document, input.ctx);
        if (!a || !(a.reportBody instanceof Uint8Array) || !a.certChain) return fail('no NVIDIA GPU-CC evidence for this action');

        // (1) parse
        let report: ParsedNvidiaReport;
        try {
          report = parseNvidiaReport(a.reportBody);
        } catch (e) {
          return fail(`GPU report parse failed: ${e instanceof Error ? e.message : 'unknown'}`);
        }

        // (2) device chain to the NVIDIA root anchor
        const chain = verifyDeviceChain(a.certChain, opts.trustAnchorRoot);
        if (!chain.ok) return fail(`device chain invalid: ${chain.reason}`);

        // (3) device-cert GPU-id binding (block a cert for a different GPU vouching for this report)
        const certGpuId = chain.leaf.get(TAG_GPU_ID);
        if (!certGpuId) return fail('device leaf certificate carries no GPU id');
        if (!timingSafeEq(certGpuId, report.gpu_id)) return fail('device certificate GPU id does not match the report GPU id');

        // (4) report signature under the device leaf
        if (!verifyP256(a.reportBody, a.reportSignature, a.certChain.leaf.subject)) return fail('GPU report signature does not verify under the device key');

        // (5) report_data === attestationBinding(expected)
        if (!input.expected) return fail('no expected attestation binding supplied');
        let expectedData: Uint8Array;
        try {
          expectedData = attestationBinding(input.expected);
        } catch (e) {
          return fail(`binding not constructible: ${e instanceof Error ? e.message : 'invalid'}`);
        }
        if (!timingSafeEq(expectedData, report.report_data)) return fail('report_data does not bind holder/grant/epoch/nonce (relayed or unbound quote)');

        // (6) acceptance policy
        const polErr = checkNvidiaCcPolicy(report, policy);
        if (polErr) return fail(polErr);

        const measured = deriveIdentity(report);
        return { ok: true, bound: true, measured, hostAsserted: { gpu_id: toHex(report.gpu_id), vbios: toHex(report.vbios_version), driver: toHex(report.driver_version) } };
      } catch (e) {
        return fail(`nvidia-cc verification error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`);
      }
    },
  };
}

/** Check a parsed GPU report against the acceptance policy. Returns a reason on the first failure, else null. */
export function checkNvidiaCcPolicy(report: ParsedNvidiaReport, policy: NvidiaCcPolicy): string | null {
  if (Array.isArray(policy.measurements) && policy.measurements.length > 0) {
    if (!policy.measurements.map((x) => x.toLowerCase()).includes(toHex(report.measurement))) return 'GPU measurement not in policy allowlist';
  }
  if (Array.isArray(policy.vbiosVersions) && policy.vbiosVersions.length > 0) {
    if (!policy.vbiosVersions.map((x) => x.toLowerCase()).includes(toHex(report.vbios_version))) return 'VBIOS version not in policy allowlist';
  }
  if (Array.isArray(policy.driverVersions) && policy.driverVersions.length > 0) {
    if (!policy.driverVersions.map((x) => x.toLowerCase()).includes(toHex(report.driver_version))) return 'driver version not in policy allowlist';
  }
  if (Array.isArray(policy.gpuIds) && policy.gpuIds.length > 0) {
    if (!policy.gpuIds.map((x) => x.toLowerCase()).includes(toHex(report.gpu_id))) return 'GPU id not in policy allowlist';
  }
  if (Array.isArray(policy.weightsMeasurements) && policy.weightsMeasurements.length > 0) {
    if (isAllZero(report.weights_measurement)) return 'no measured weights digest in report (weightsMeasurements required)';
    if (!policy.weightsMeasurements.map((x) => x.toLowerCase()).includes(toHex(report.weights_measurement))) return 'measured weights digest not in policy allowlist';
  }
  return null;
}

/**
 * Default identity mapping for a verified GPU report:
 *   runtime_measurement = hex(MEASUREMENT)  — the measured GPU/driver/firmware state (where the model runs)
 *   weights_digest      = hex(WEIGHTS_MEASUREMENT) when non-zero (GPU-TEE-MEASURED, weights_measured: true);
 *                         else '' (false)
 *   operator / model_id = ''                — NVIDIA GPU attestation carries no operator/model id; override
 * The GPU id / VBIOS / driver are surfaced as `hostAsserted` for audit.
 */
function defaultNvidiaIdentity(report: ParsedNvidiaReport): MeasuredIdentity {
  if (!isAllZero(report.weights_measurement)) {
    return { model_id: '', weights_digest: toHex(report.weights_measurement), weights_measured: true, runtime_measurement: toHex(report.measurement), operator: '' };
  }
  return { model_id: '', weights_digest: '', weights_measured: false, runtime_measurement: toHex(report.measurement), operator: '' };
}
