/**
 * L0 HARDWARE backend — NVIDIA GPU confidential-computing attestation, REAL WIRE FORMAT.
 *
 * This module verifies the genuine evidence a
 * Hopper (H100/H200) or Blackwell GPU in CC mode emits: an SPDM 1.1 GET_MEASUREMENTS exchange, signed by
 * the GPU's device-identity key, plus its X.509 device certificate chain rooted at the NVIDIA Device
 * Identity CA. It is the NVIDIA analogue of the Intel DCAP parser in `attest-intel-tdx.ts`.
 *
 * ── EVIDENCE ────────────────────────────────────────────────────────────────────────────────────
 *   evidence  = SPDM request ‖ SPDM response, concatenated (this is the exact transcript the GPU signs):
 *     request   : version(1) code=0xE0(1) param1(1) param2(1) nonce(32) slot(1)            = 37 bytes
 *     response  : version(1) code=0x60(1) param1(1) param2(1) numBlocks(1) recLen(3 LE)
 *                 measurement records[recLen] (index(1) spec(1) size(2 LE) { type(1) vsize(2 LE) digest }),
 *                 responder nonce(32) opaqueLen(2 LE) opaque TLVs[opaqueLen] signature(96)
 *     signature = ECDSA P-384 r‖s (big-endian, IEEE P1363) over SHA-384(request ‖ response-without-signature)
 *   certChain = PEM, leaf first: device leaf → … → NVIDIA Device Identity CA (self-signed root), P-384.
 *
 * ── WHAT IS VERIFIED (node:crypto X.509 + ECDSA; nothing hand-rolled) ───────────────────────────
 *   1. Every certificate link is signature-verified, every issuer is a CA, every cert is inside its
 *      validity window at the server clock, and the chain's root is PINNED by SPKI SHA-256 (never trusted
 *      from the evidence alone). At least one pin is required at construction — no accept-all.
 *   2. The report signature verifies under the device leaf key over the full request‖response transcript.
 *   3. PCA binding: the SPDM REQUEST nonce (inside the signed transcript) equals
 *      sha256(attestationBinding({holderPub,grantRef,epoch,nonce})). NVIDIA's native challenge is 32 bytes;
 *      this binds the 64-byte PCA binding through SHA-256 (documented profile, same as the GCP root).
 *   4. Policy: a NON-EMPTY pinned set of measurement-block digests (index → SHA-384 hex) must all match.
 *
 * ── HONEST SCOPE ────────────────────────────────────────────────────────────────────────────────
 * CLASSICAL (ECDSA-P384/SHA-384); not post-quantum. This module pins whatever measurement digests the operator
 * supplies. Golden values from NVIDIA's RIM service, the driver/VBIOS version binding and CRL revocation are in
 * `attest-nvidia-rim.ts` and plug in through `postVerify`; OCSP is `attest-nvidia-ocsp.ts`. NOT done anywhere:
 * firmware-version policy beyond RIM equality.
 *
 * Sources: DMTF DSP0274 (SPDM 1.1) GET_MEASUREMENTS; NVIDIA nvtrust local GPU verifier
 * (attestation/spdm_msrt_{req,resp}_msg.py) for the opaque-data TLVs and 96-byte Hopper/Blackwell signature.
 */
import { X509Certificate, createHash, verify as cryptoVerify } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { sha256 } from './hash';
import { attestationBinding } from './attestation';
import type {
  AttestationDocument,
  HardwareAttestationResult,
  HardwareAttestationVerifier,
  MeasuredIdentity,
} from './attestation';
import type { VerifyContext } from './pcactn';

/** Suite identifier for this root (classical ECDSA-P384 / SHA-384). */
export const NVIDIA_SPDM_SUITE = 'nvidia-gpu-spdm-ecdsa-p384-sha384' as const;

const REQ_LEN = 37;
const NONCE_LEN = 32;
const SIG_LEN = 96;
const SPDM_GET_MEASUREMENTS = 0xe0;
const SPDM_MEASUREMENTS_RESP = 0x60;
const MAX_CHAIN = 5;

/** Opaque-data TLV field ids (nvtrust `OpaqueData.OPAQUE_DATA_TYPES`) that this module surfaces by name. */
export const NVIDIA_OPAQUE = {
  CERT_ISSUER_NAME: 1,
  CERT_AUTHORITY_KEY_IDENTIFIER: 2,
  DRIVER_VERSION: 3,
  GPU_INFO: 4,
  SKU: 5,
  VBIOS_VERSION: 6,
  MANUFACTURER_ID: 7,
  TAMPER_DETECTION: 8,
  MSRSCNT: 12,
  BOARD_ID: 14,
  FWID: 20,
  OPAQUE_DATA_VERSION: 34,
  /** Chip family string (`GB100`); present on Blackwell reports, absent on Hopper (GH100). */
  CHIP_INFO: 35,
  FEATURE_FLAG: 36,
} as const;

export interface NvidiaSpdmMeasurement {
  index: number;
  valueType: number;
  /** The measurement digest (48 bytes for Hopper/Blackwell). */
  digest: Uint8Array;
}

export interface ParsedNvidiaSpdmReport {
  request: { version: number; code: number; param1: number; param2: number; nonce: Uint8Array; slot: number };
  response: {
    version: number;
    code: number;
    numBlocks: number;
    measurements: NvidiaSpdmMeasurement[];
    /** The GPU's own (responder) nonce — distinct from the request nonce that carries the PCA challenge. */
    responderNonce: Uint8Array;
    /** Opaque-data TLVs, keyed by numeric data type. */
    opaque: Map<number, Uint8Array>;
    signature: Uint8Array;
  };
  /** The exact bytes the device key signs: request ‖ response-without-signature. */
  signedBytes: Uint8Array;
}

function u16le(b: Uint8Array, o: number): number {
  return (b[o] ?? 0) | ((b[o + 1] ?? 0) << 8);
}
function u24le(b: Uint8Array, o: number): number {
  return (b[o] ?? 0) | ((b[o + 1] ?? 0) << 8) | ((b[o + 2] ?? 0) << 16);
}
function toHex(b: Uint8Array): string {
  return Buffer.from(b).toString('hex');
}

/**
 * Parse an SPDM request‖response GPU attestation transcript. Total: throws a RangeError/TypeError on any
 * structural problem (never reads out of bounds, never returns a partially parsed report).
 */
export function parseNvidiaSpdmEvidence(bytes: Uint8Array): ParsedNvidiaSpdmReport {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('parseNvidiaSpdmEvidence: expected Uint8Array');
  if (bytes.length < REQ_LEN + 8 + NONCE_LEN + 2 + SIG_LEN) throw new RangeError(`parseNvidiaSpdmEvidence: transcript too short (${bytes.length})`);
  const code = bytes[1] ?? 0;
  if (code !== SPDM_GET_MEASUREMENTS) throw new RangeError(`parseNvidiaSpdmEvidence: request code 0x${code.toString(16)} is not GET_MEASUREMENTS`);
  const request = {
    version: bytes[0] ?? 0,
    code,
    param1: bytes[2] ?? 0,
    param2: bytes[3] ?? 0,
    nonce: bytes.slice(4, 4 + NONCE_LEN),
    slot: bytes[4 + NONCE_LEN] ?? 0,
  };
  const r = bytes.subarray(REQ_LEN);
  if ((r[1] ?? 0) !== SPDM_MEASUREMENTS_RESP) throw new RangeError('parseNvidiaSpdmEvidence: response code is not MEASUREMENTS');
  const numBlocks = r[4] ?? 0;
  const recLen = u24le(r, 5);
  let o = 8;
  if (o + recLen + NONCE_LEN + 2 + SIG_LEN > r.length) throw new RangeError('parseNvidiaSpdmEvidence: measurement record length overruns transcript');
  const measurements: NvidiaSpdmMeasurement[] = [];
  const recEnd = o + recLen;
  while (o < recEnd) {
    if (o + 4 > recEnd) throw new RangeError('parseNvidiaSpdmEvidence: truncated measurement block header');
    const index = r[o] ?? 0;
    const size = u16le(r, o + 2);
    const bodyStart = o + 4;
    if (bodyStart + size > recEnd || size < 3) throw new RangeError('parseNvidiaSpdmEvidence: measurement block overruns record');
    const valueType = r[bodyStart] ?? 0;
    const vsize = u16le(r, bodyStart + 1);
    if (3 + vsize > size) throw new RangeError('parseNvidiaSpdmEvidence: DMTF value overruns measurement block');
    measurements.push({ index, valueType, digest: r.slice(bodyStart + 3, bodyStart + 3 + vsize) });
    o = bodyStart + size;
  }
  if (measurements.length !== numBlocks) throw new RangeError(`parseNvidiaSpdmEvidence: header says ${numBlocks} blocks, parsed ${measurements.length}`);
  const responderNonce = r.slice(o, o + NONCE_LEN);
  o += NONCE_LEN;
  const opaqueLen = u16le(r, o);
  o += 2;
  if (o + opaqueLen + SIG_LEN !== r.length) throw new RangeError('parseNvidiaSpdmEvidence: opaque length + signature do not exactly fill the transcript');
  const opaque = new Map<number, Uint8Array>();
  const opaqueEnd = o + opaqueLen;
  while (o < opaqueEnd) {
    if (o + 4 > opaqueEnd) throw new RangeError('parseNvidiaSpdmEvidence: truncated opaque TLV header');
    const t = u16le(r, o);
    const l = u16le(r, o + 2);
    o += 4;
    if (o + l > opaqueEnd) throw new RangeError('parseNvidiaSpdmEvidence: opaque TLV overruns opaque data');
    opaque.set(t, r.slice(o, o + l));
    o += l;
  }
  const signature = r.slice(r.length - SIG_LEN);
  return {
    request,
    response: { version: r[0] ?? 0, code: r[1] ?? 0, numBlocks, measurements, responderNonce, opaque, signature },
    signedBytes: bytes.slice(0, bytes.length - SIG_LEN),
  };
}

/** NVIDIA's VBIOS version rendering (`format_vbios_version`): byte-reverse, then re-pair as dotted hex, e.g. `96.00.9f.00.04`. */
export function formatVbiosVersion(raw: Uint8Array): string {
  const hex = Buffer.from(raw).reverse().toString('hex');
  const half = hex.length / 2;
  const temp = hex.slice(half) + hex.slice(half - 2, half);
  return temp.match(/.{1,2}/g)?.join('.') ?? '';
}

/** SHA-256 of a certificate's SubjectPublicKeyInfo DER, lowercase hex — the pin format for the root. */
export function spkiSha256Hex(cert: X509Certificate): string {
  const der = cert.publicKey.export({ type: 'spki', format: 'der' });
  return createHash('sha256').update(der).digest('hex');
}

/** Split a PEM bundle into certificates (leaf first). Throws on none / too many. */
export function parsePemChain(pem: string): X509Certificate[] {
  const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
  if (blocks.length === 0) throw new RangeError('parsePemChain: no certificates found');
  if (blocks.length > MAX_CHAIN) throw new RangeError(`parsePemChain: chain longer than ${MAX_CHAIN}`);
  return blocks.map((b) => new X509Certificate(b));
}

export type NvidiaChainResult = { ok: true; leaf: X509Certificate; chain: X509Certificate[] } | { ok: false; reason: string };

/**
 * Verify the device chain: signature of every link, CA flag on every issuer, validity windows, and the
 * root's SPKI pinned against `rootSpkiSha256` (lowercase hex). The root must be self-signed.
 */
export function verifyNvidiaDeviceChain(pem: string, rootSpkiSha256: string[], nowMs: number): NvidiaChainResult {
  let chain: X509Certificate[];
  try {
    chain = parsePemChain(pem);
  } catch (e) {
    return { ok: false, reason: `device chain unparseable: ${e instanceof Error ? e.message : 'unknown'}` };
  }
  const now = new Date(nowMs);
  for (const [i, c] of chain.entries()) {
    if (now < new Date(c.validFrom) || now > new Date(c.validTo)) return { ok: false, reason: `device chain cert #${i} is outside its validity window` };
    if (c.publicKey.asymmetricKeyType !== 'ec' || c.publicKey.asymmetricKeyDetails?.namedCurve !== 'secp384r1') {
      return { ok: false, reason: `device chain cert #${i} is not an ECDSA P-384 key` };
    }
  }
  for (let i = 0; i < chain.length - 1; i++) {
    const issuer = chain[i + 1]!;
    if (!issuer.ca) return { ok: false, reason: `device chain cert #${i + 1} issues a certificate but is not a CA` };
    if (!chain[i]!.verify(issuer.publicKey)) return { ok: false, reason: `device chain link #${i} signature does not verify under its issuer` };
  }
  const root = chain[chain.length - 1]!;
  if (!root.ca || !root.verify(root.publicKey)) return { ok: false, reason: 'device chain root is not a self-signed CA' };
  const pins = new Set(rootSpkiSha256.map((p) => p.toLowerCase()));
  if (!pins.has(spkiSha256Hex(root))) return { ok: false, reason: 'chain root is not a pinned NVIDIA root' };
  return { ok: true, leaf: chain[0]!, chain };
}

/** ECDSA P-384 / SHA-384 verification of the report signature (IEEE P1363 r‖s) under the device key. */
export function verifyNvidiaSpdmSignature(report: ParsedNvidiaSpdmReport, devicePublicKey: KeyObject): boolean {
  return cryptoVerify('sha384', report.signedBytes, { key: devicePublicKey, dsaEncoding: 'ieee-p1363' }, report.response.signature);
}

/** The 32-byte SPDM challenge that carries the PCA binding: sha256(attestationBinding(expected)). */
export function nvidiaSpdmChallenge(expected: Parameters<typeof attestationBinding>[0]): Uint8Array {
  return sha256(attestationBinding(expected));
}

export interface NvidiaSpdmPolicy {
  /**
   * REQUIRED + NON-EMPTY: measurement-block index → expected digest (hex, case-insensitive). Every listed
   * block must be present and equal. Source golden values from NVIDIA's RIM service; there is no accept-all.
   */
  measurements: Record<number, string>;
  /** Optional: required substring of the device leaf certificate subject (e.g. `GH100` for Hopper). */
  leafSubjectIncludes?: string;
  /** Map a verified report to the identity agent_binding is checked against. */
  deriveIdentity?: (report: ParsedNvidiaSpdmReport) => MeasuredIdentity;
}

export interface NvidiaSpdmEvidence {
  /** request ‖ response transcript (see module header). */
  evidence: Uint8Array;
  /** PEM device chain, leaf first. */
  certChainPem: string;
}

/** What a `postVerify` collateral hook sees once chain, signature, PCA binding and pinned measurements passed. */
export interface NvidiaSpdmPostVerifyContext {
  report: ParsedNvidiaSpdmReport;
  /** The verified device chain, leaf first. */
  chain: X509Certificate[];
  leaf: X509Certificate;
  nowMs: number;
}

export interface NvidiaSpdmVerifierOptions {
  /** Lowercase-hex SPKI SHA-256 pin(s) of the NVIDIA Device Identity CA root. REQUIRED + non-empty. */
  rootSpkiSha256: string[];
  policy: NvidiaSpdmPolicy;
  /** Evidence seam; if omitted the verifier fails closed. */
  resolveEvidence?: (document: AttestationDocument, ctx: VerifyContext) => NvidiaSpdmEvidence | undefined | Promise<NvidiaSpdmEvidence | undefined>;
  /**
   * Optional collateral hook (RIM golden measurements, CRL revocation — see `attest-nvidia-rim.ts`), run after
   * every offline check passed. Return a failure reason to reject, or `undefined` to accept. When set, the
   * pinned `policy.measurements` set may be empty (the RIM then supplies the reference values).
   */
  postVerify?: (ctx: NvidiaSpdmPostVerifyContext) => string | undefined | Promise<string | undefined>;
}

/**
 * Default identity: EMPTY. A GPU in a known-good state is a GATE on the platform, not a workload identity, and in a
 * CPU-TEE + GPU deployment the workload identity (e.g. the TD's MRTD) comes from the CPU root. If this root also
 * asserted a `runtime_measurement`, the multi-root reconciliation would (correctly) deny the two roots as contradicting
 * each other. The GPU measurement digest is surfaced in `hostAsserted.gpu_measurements_sha384` for audit; a standalone
 * GPU deployment that needs an identity passes `policy.deriveIdentity`.
 */
function defaultIdentity(_report: ParsedNvidiaSpdmReport): MeasuredIdentity {
  return { model_id: '', weights_digest: '', weights_measured: false, runtime_measurement: '', operator: '' };
}

/** SHA-384 over the measurement blocks in index order — an audit digest of the GPU state. */
function gpuMeasurementsDigest(report: ParsedNvidiaSpdmReport): string {
  const h = createHash('sha384');
  for (const m of [...report.response.measurements].sort((a, b) => a.index - b.index)) h.update(m.digest);
  return h.digest('hex');
}

/** Build a `HardwareAttestationVerifier` for genuine NVIDIA Hopper/Blackwell GPU-CC evidence. Fails closed. */
export function createNvidiaSpdmVerifier(opts: NvidiaSpdmVerifierOptions): HardwareAttestationVerifier {
  if (!opts || !Array.isArray(opts.rootSpkiSha256) || opts.rootSpkiSha256.length === 0) {
    throw new TypeError('createNvidiaSpdmVerifier: rootSpkiSha256 must pin at least one NVIDIA root (accept-all is not permitted)');
  }
  const pinned = Object.entries(opts.policy?.measurements ?? {});
  if (pinned.length === 0 && !opts.postVerify) throw new TypeError('createNvidiaSpdmVerifier: policy.measurements must be a NON-EMPTY pinned set unless a postVerify collateral hook supplies reference values (accept-all is not permitted)');
  const want = pinned.map(([i, d]) => [Number(i), String(d).toLowerCase()] as const);
  for (const [i] of want) if (!Number.isInteger(i) || i < 0 || i > 255) throw new TypeError('createNvidiaSpdmVerifier: measurement index out of range');
  const derive = opts.policy.deriveIdentity ?? defaultIdentity;

  return {
    async verify(input): Promise<HardwareAttestationResult> {
      const fail = (reason: string): HardwareAttestationResult => ({ ok: false, reason });
      try {
        if (!opts.resolveEvidence) return fail('no NVIDIA GPU evidence resolver configured (fail closed)');
        const ev = await opts.resolveEvidence(input.document, input.ctx);
        if (!ev || !(ev.evidence instanceof Uint8Array) || typeof ev.certChainPem !== 'string') return fail('no NVIDIA GPU evidence for this action');

        const chain = verifyNvidiaDeviceChain(ev.certChainPem, opts.rootSpkiSha256, input.nowMs);
        if (!chain.ok) return fail(chain.reason);
        if (opts.policy.leafSubjectIncludes && !chain.leaf.subject.includes(opts.policy.leafSubjectIncludes)) {
          return fail(`device leaf subject does not contain '${opts.policy.leafSubjectIncludes}'`);
        }

        let report: ParsedNvidiaSpdmReport;
        try {
          report = parseNvidiaSpdmEvidence(ev.evidence);
        } catch (e) {
          return fail(`GPU attestation report parse failed: ${e instanceof Error ? e.message : 'unknown'}`);
        }
        if (!verifyNvidiaSpdmSignature(report, chain.leaf.publicKey)) return fail('GPU attestation report signature does not verify under the device identity key');

        if (!input.expected) return fail('no expected attestation binding supplied');
        let challenge: Uint8Array;
        try {
          challenge = nvidiaSpdmChallenge(input.expected);
        } catch (e) {
          return fail(`binding not constructible: ${e instanceof Error ? e.message : 'invalid'}`);
        }
        if (Buffer.compare(Buffer.from(report.request.nonce), Buffer.from(challenge)) !== 0) {
          return fail('SPDM request nonce does not bind holder/grant/epoch/nonce (relayed or unbound report)');
        }

        const byIndex = new Map(report.response.measurements.map((m) => [m.index, m] as const));
        for (const [idx, digestHex] of want) {
          const m = byIndex.get(idx);
          if (!m) return fail(`measurement block ${idx} missing from report`);
          if (toHex(m.digest) !== digestHex) return fail(`measurement block ${idx} does not match the pinned digest`);
        }

        if (opts.postVerify) {
          const why = await opts.postVerify({ report, chain: chain.chain, leaf: chain.leaf, nowMs: input.nowMs });
          if (why) return fail(why);
        }

        const hostAsserted: Record<string, string> = { attestation_type: 'nvidia-gpu-cc', gpu_measurements_sha384: gpuMeasurementsDigest(report), leaf_subject: chain.leaf.subject.replace(/\n/g, ', ') };
        const drv = report.response.opaque.get(NVIDIA_OPAQUE.DRIVER_VERSION);
        const vbios = report.response.opaque.get(NVIDIA_OPAQUE.VBIOS_VERSION);
        if (drv) hostAsserted.driver_version = Buffer.from(drv).toString('utf8').replace(/\0+$/, '');
        if (vbios) hostAsserted.vbios_version = formatVbiosVersion(vbios);
        return { ok: true, bound: true, measured: derive(report), hostAsserted };
      } catch (e) {
        return fail(`nvidia-spdm verification error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`);
      }
    },
  };
}
