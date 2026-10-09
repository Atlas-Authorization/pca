/**
 * L0 HARDWARE backend — AMD SEV-SNP attestation report parsing and verification primitives.
 *
 * Parses a genuine AMD SEV-SNP `ATTESTATION_REPORT`, verifies its ECDSA-P384/SHA-384 signature under the
 * VCEK public key, verifies the VCEK->ASK->ARK X.509 chain to the PINNED AMD root, and binds the VCEK
 * certificate's CHIP_ID and reported-TCB SPL extensions to the report. The `HardwareAttestationVerifier`
 * built on these primitives is `attest-amd-snp.ts` (`createAmdSnpVerifier`).
 *
 * WHAT IS CRYPTOGRAPHICALLY VERIFIED (see {@link verifyGenuineSevSnpReport}, validated against a captured
 * real report in testdata/sevsnp-real/ from an Azure confidential VM, AMD EPYC Milan):
 *   1. ECDSA-P384 / SHA-384 signature over the report's signed region [0x000, 0x2A0) using the VCEK
 *      public key. AMD stores the signature as little-endian r||s (72-byte fields); we convert to the
 *      big-endian scalar form @noble/curves expects.
 *   2. The VCEK->ASK->ARK chain. AMD's VCEK is an EC-P384 leaf, but the ASK/ARK are RSA-4096 signed with
 *      RSASSA-PSS carrying an EXPLICIT, DEFAULT-valued `trailerField` that strict ASN.1 parsers reject and
 *      OpenSSL tolerates. The chain is therefore verified through node's OpenSSL-backed
 *      `crypto.X509Certificate.verify()`, and the ARK must hash to the pinned {@link AMD_MILAN_ARK_SPKI_SHA384}
 *      (the root is never taken from the supplied chain). `node:crypto` is imported lazily.
 *   3. The VCEK's CHIP_ID (1.3.6.1.4.1.3704.1.4) and reported-TCB SPL (...1.3.1/.2/.3/.8) extensions equal
 *      the report's chip_id / reported_tcb (blocks old-VCEK-signs-new-report TCB downgrade).
 *   4. Optionally, report_data === attestationBinding({holderPub, grantRef, epoch, nonce}).
 *   5. Policy gates ({@link SevSnpPolicy}): DEBUG policy bit, CHIP_ID, TCB, VMPL, GUEST_SVN, measurements.
 *
 * AMD KDS fetching. Genuine VCEK/ASK/ARK certs are fetched from the AMD Key Distribution Service
 * (https://kdsintf.amd.com/vcek/v1/...) keyed by CHIP_ID + reported TCB. {@link fetchVcekFromKds} is a
 * guarded, never-auto-invoked network helper; this module does no network I/O on its own.
 *
 * AZURE CONFIDENTIAL-VM NUANCE: on an Azure CVM the paravisor (VMPL0) mediates the guest request and
 * places the digest of the guest's vTPM Attestation Key into the report's `report_data`. The PCA nonce
 * binding on such platforms is carried by a vTPM quote signed by that attested AK, so
 * `verifyGenuineSevSnpReport` makes the report_data binding check OPTIONAL.
 *
 * PQ STATUS: CLASSICAL. AMD's root of trust (ECDSA-P384 report, RSA-4096 ASK/ARK) is not post-quantum and
 * AMD publishes no post-quantum report signature suite. Its value in a multi-root policy is independence
 * from other vendors' roots.
 *
 * WEIGHTS: SEV-SNP HAS NO NATIVE WEIGHTS FIELD. The ATTESTATION_REPORT carries the guest LAUNCH measurement
 * (MEASUREMENT), a guest-chosen REPORT_DATA, a host-chosen HOST_DATA and the TCB / identity fields listed
 * in the layout below, and nothing else. Every byte of the signed region is a field AMD defines, so this
 * parser never derives a hardware-measured weights digest and the default derived identity always has
 * `weights_measured: false` and an empty `weights_digest`. Supported ways to tie weights to a SEV-SNP guest:
 *   - Put the weights (or the image that pins them by digest) in the launch image, so they are covered by
 *     MEASUREMENT, and allowlist that MEASUREMENT via `SevSnpPolicy.measurements`.
 *   - Have the guest bind the weights digest into REPORT_DATA (or into a vTPM / Confidential-Space token it
 *     attests) and verify that binding at the verifier.
 *   - For GPU-resident weights, use the NVIDIA GPU attestation path (`attest-nvidia-*`) and its RIM
 *     reference manifest.
 *   - INSECURE opt-in `weightsFromHostData`: treat the host-chosen HOST_DATA as a weights digest. It is
 *     host-asserted, so it is reported with `weights_measured: false` and can never satisfy
 *     `require_measured_weights`.
 *
 * References: AMD SEV-SNP ABI Specification (Rev. 1.55+), "ATTESTATION_REPORT Structure" and
 * "ECDSA_P384_SHA384 Signature" tables; AMD KDS interface documentation.
 */
import { sha384 } from '@noble/hashes/sha512';
import { p384 } from '@noble/curves/p384';
import { attestationBinding } from './attestation';
import { checkChainRoles, ecPointFromKey, parseCertExtensions, parseTbsExtensions, tbsOfCertificate } from './x509-strict';
import type { CertExtension } from './x509-strict';
import type { MeasuredIdentity } from './attestation';

// ════════════════════════════════════════════════════════════════════════════════════════════════
// ATTESTATION_REPORT binary layout — AMD SEV-SNP ABI Specification, "ATTESTATION_REPORT Structure".
// All multi-byte integers are LITTLE-ENDIAN. Byte offsets are quoted from the spec.
// ════════════════════════════════════════════════════════════════════════════════════════════════
const OFF = {
  VERSION: 0x000, //            u32   report format version (>= 2 for the layout below)
  GUEST_SVN: 0x004, //          u32   guest security version
  POLICY: 0x008, //             u64   guest policy
  FAMILY_ID: 0x010, //          16 B  guest family id
  IMAGE_ID: 0x020, //           16 B  guest image id
  VMPL: 0x030, //               u32   VMPL the report was requested at
  SIGNATURE_ALGO: 0x034, //     u32   1 = ECDSA_P384_SHA384
  CURRENT_TCB: 0x038, //        u64   current TCB version
  PLATFORM_INFO: 0x040, //      u64   platform info (SMT / TSME ...)
  // 0x048 u32 flags (AUTHOR_KEY_EN bit0, MASK_CHIP_KEY bit1, SIGNING_KEY bits4:2); 0x04C u32 reserved
  REPORT_DATA: 0x050, //        64 B  guest-supplied data — the nonce binding lives here
  MEASUREMENT: 0x090, //        48 B  launch measurement (hardware-authoritative)
  HOST_DATA: 0x0c0, //          32 B  data the host/owner supplied at launch
  ID_KEY_DIGEST: 0x0e0, //      48 B  SHA-384 of the ID key
  AUTHOR_KEY_DIGEST: 0x110, //  48 B  SHA-384 of the author key (zero if AUTHOR_KEY_EN=0)
  REPORT_ID: 0x140, //          32 B  report id
  REPORT_ID_MA: 0x160, //       32 B  report id of the migration agent
  REPORTED_TCB: 0x180, //       u64   reported TCB version
  CPUID_FAM_ID: 0x188, //       u8    CPUID family (report version >= 3; 0 on older reports)
  CPUID_MOD_ID: 0x189, //       u8    CPUID model  (version >= 3)
  CPUID_STEP: 0x18a, //         u8    CPUID stepping (version >= 3)
  // 0x18B..0x19F reserved
  CHIP_ID: 0x1a0, //            64 B  unique chip id (hardware operator identity)
  COMMITTED_TCB: 0x1e0, //      u64   committed TCB version (AMD-defined; the TCB the platform cannot roll back below)
  CURRENT_BUILD: 0x1e8, //      u8    current SNP firmware build number
  CURRENT_MINOR: 0x1e9, //      u8    current SNP firmware minor version
  CURRENT_MAJOR: 0x1ea, //      u8    current SNP firmware major version
  // 0x1EB reserved
  COMMITTED_BUILD: 0x1ec, //    u8    committed SNP firmware build number
  COMMITTED_MINOR: 0x1ed, //    u8    committed SNP firmware minor version
  COMMITTED_MAJOR: 0x1ee, //    u8    committed SNP firmware major version
  // 0x1EF reserved
  LAUNCH_TCB: 0x1f0, //         u64   TCB version at guest launch
  LAUNCH_MIT_VECTOR: 0x1f8, //  u64   mitigation vector at launch (report version >= 5)
  CURRENT_MIT_VECTOR: 0x200, // u64   current mitigation vector (version >= 5)
  // 0x208..0x29F reserved (zero)
  SIGNED_END: 0x2a0, //         signed region is [0x000, 0x2A0)
  SIG_R: 0x2a0, //              72 B  signature r, LITTLE-ENDIAN (P-384 uses the low 48 B)
  SIG_S: 0x2e8, //              72 B  signature s, LITTLE-ENDIAN
  REPORT_LEN: 0x4a0, //         1184  canonical report size (signature block is 0x2A0..0x4A0)
} as const;

/** The SIGNATURE_ALGO value for ECDSA over P-384 with SHA-384 (the only algo SEV-SNP uses today). */
export const SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384 = 1;

/** A fully parsed AMD SEV-SNP `ATTESTATION_REPORT`. Byte-array fields are fresh copies. */
export interface ParsedSevSnpReport {
  version: number;
  guest_svn: number;
  policy: bigint;
  family_id: Uint8Array; // 16
  image_id: Uint8Array; // 16
  vmpl: number;
  signature_algo: number;
  current_tcb: bigint;
  platform_info: bigint;
  report_data: Uint8Array; // 64
  measurement: Uint8Array; // 48
  host_data: Uint8Array; // 32
  id_key_digest: Uint8Array; // 48
  author_key_digest: Uint8Array; // 48
  report_id: Uint8Array; // 32
  report_id_ma: Uint8Array; // 32
  reported_tcb: bigint;
  /** CPUID family / model / stepping of the processor (report version >= 3; 0 before). */
  cpuid_fam_id: number;
  cpuid_mod_id: number;
  cpuid_step: number;
  chip_id: Uint8Array; // 64
  /** Committed TCB version (raw u64; same byte layout as reported_tcb). */
  committed_tcb: bigint;
  /** SNP firmware version currently running / committed, as defined by AMD (major.minor build N). */
  current_version: { major: number; minor: number; build: number };
  committed_version: { major: number; minor: number; build: number };
  /** TCB version at guest launch (raw u64). */
  launch_tcb: bigint;
  /** Mitigation vectors (report version >= 5; 0n on older reports). */
  launch_mit_vector: bigint;
  current_mit_vector: bigint;
  /** AMD's little-endian r‖s, each a 72-byte field exactly as it sits in the report. */
  signature: { r: Uint8Array; s: Uint8Array };
  /** The signed region, report bytes [0x000, 0x2A0). The ECDSA signature is over SHA-384 of this. */
  signed: Uint8Array;
  /** The full report bytes (a copy). */
  raw: Uint8Array;
}

function u32le(dv: DataView, off: number): number {
  return dv.getUint32(off, true);
}
function u64le(dv: DataView, off: number): bigint {
  return dv.getBigUint64(off, true);
}
function slice(bytes: Uint8Array, off: number, len: number): Uint8Array {
  return bytes.slice(off, off + len);
}

/** Interpret a little-endian byte array as a non-negative bigint. */
function leToBigInt(le: Uint8Array): bigint {
  let n = 0n;
  for (let i = le.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(le[i]!);
  return n;
}

/** Lowercase hex of a byte array (stable identity string for measurement / chip_id / host_data). */
export function toHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i]!.toString(16).padStart(2, '0');
  return s;
}

/**
 * Parse the AMD SEV-SNP `ATTESTATION_REPORT` binary layout (see `OFF` above). Throws on a buffer too
 * short to contain the signed region and the r/s signature fields. Does NOT verify anything — call
 * `verifySevSnpReportSignature` and the chain checks for that.
 */
export function parseSevSnpReport(bytes: Uint8Array): ParsedSevSnpReport {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('parseSevSnpReport: expected Uint8Array');
  const minLen = OFF.SIG_S + 72; // everything up to and including s must be present
  if (bytes.length < minLen) {
    throw new RangeError(`parseSevSnpReport: report too short (${bytes.length} < ${minLen})`);
  }
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    version: u32le(dv, OFF.VERSION),
    guest_svn: u32le(dv, OFF.GUEST_SVN),
    policy: u64le(dv, OFF.POLICY),
    family_id: slice(bytes, OFF.FAMILY_ID, 16),
    image_id: slice(bytes, OFF.IMAGE_ID, 16),
    vmpl: u32le(dv, OFF.VMPL),
    signature_algo: u32le(dv, OFF.SIGNATURE_ALGO),
    current_tcb: u64le(dv, OFF.CURRENT_TCB),
    platform_info: u64le(dv, OFF.PLATFORM_INFO),
    report_data: slice(bytes, OFF.REPORT_DATA, 64),
    measurement: slice(bytes, OFF.MEASUREMENT, 48),
    host_data: slice(bytes, OFF.HOST_DATA, 32),
    id_key_digest: slice(bytes, OFF.ID_KEY_DIGEST, 48),
    author_key_digest: slice(bytes, OFF.AUTHOR_KEY_DIGEST, 48),
    report_id: slice(bytes, OFF.REPORT_ID, 32),
    report_id_ma: slice(bytes, OFF.REPORT_ID_MA, 32),
    reported_tcb: u64le(dv, OFF.REPORTED_TCB),
    cpuid_fam_id: bytes[OFF.CPUID_FAM_ID]!,
    cpuid_mod_id: bytes[OFF.CPUID_MOD_ID]!,
    cpuid_step: bytes[OFF.CPUID_STEP]!,
    chip_id: slice(bytes, OFF.CHIP_ID, 64),
    committed_tcb: u64le(dv, OFF.COMMITTED_TCB),
    current_version: { major: bytes[OFF.CURRENT_MAJOR]!, minor: bytes[OFF.CURRENT_MINOR]!, build: bytes[OFF.CURRENT_BUILD]! },
    committed_version: { major: bytes[OFF.COMMITTED_MAJOR]!, minor: bytes[OFF.COMMITTED_MINOR]!, build: bytes[OFF.COMMITTED_BUILD]! },
    launch_tcb: u64le(dv, OFF.LAUNCH_TCB),
    launch_mit_vector: u64le(dv, OFF.LAUNCH_MIT_VECTOR),
    current_mit_vector: u64le(dv, OFF.CURRENT_MIT_VECTOR),
    signature: { r: slice(bytes, OFF.SIG_R, 72), s: slice(bytes, OFF.SIG_S, 72) },
    signed: slice(bytes, 0, OFF.SIGNED_END),
    raw: bytes.slice(),
  };
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// EC public keys + signature primitives (P-384 / SHA-384).
// ════════════════════════════════════════════════════════════════════════════════════════════════

/**
 * A P-384 public key, carried as the uncompressed SEC1 point encoding (`0x04 ‖ X(48) ‖ Y(48)`, 97
 * bytes). Production decodes this out of an X.509 SubjectPublicKeyInfo with a vetted library and calls
 * `ecdsaP384PublicKey` — see the module header's X.509 SEAM note.
 */
export interface EcdsaP384PublicKey {
  /** Uncompressed SEC1 point bytes: 0x04 ‖ X(48) ‖ Y(48). */
  readonly point: Uint8Array;
}

/**
 * Wrap/validate a P-384 public key. Accepts the uncompressed (97-byte) or compressed (49-byte) SEC1
 * encoding; normalizes to uncompressed. Throws if the bytes are not a valid curve point.
 */
export function ecdsaP384PublicKey(sec1: Uint8Array): EcdsaP384PublicKey {
  const pt = p384.ProjectivePoint.fromHex(sec1); // throws on an off-curve / malformed point
  return { point: pt.toRawBytes(false) };
}

/**
 * Convert AMD's little-endian r‖s (72-byte fields) into the big-endian compact (r‖s, 96-byte) form
 * @noble/curves expects. The P-384 scalars occupy the low 48 bytes; the remaining field bytes must be
 * zero. Throws if r or s is zero or ≥ curve order (a structurally invalid signature).
 */
export function sevSnpSignatureToCompact(sig: { r: Uint8Array; s: Uint8Array }): Uint8Array {
  const n = p384.CURVE.n;
  const r = leToBigInt(sig.r);
  const s = leToBigInt(sig.s);
  if (r <= 0n || r >= n) throw new RangeError('sev-snp signature: r out of range');
  if (s <= 0n || s >= n) throw new RangeError('sev-snp signature: s out of range');
  return new p384.Signature(r, s).toCompactRawBytes();
}

/**
 * Verify the report's ECDSA-P384/SHA-384 signature over its signed region [0x000, 0x2A0) with the VCEK
 * public key. Never throws: a malformed signature or key simply returns false (fail closed).
 */
export function verifySevSnpReportSignature(report: ParsedSevSnpReport, vcek: EcdsaP384PublicKey): boolean {
  try {
    const digest = sha384(report.signed);
    const compact = sevSnpSignatureToCompact(report.signature);
    // lowS:false — ECDSA validity does not require a low-S value, and AMD hardware does not normalize.
    return p384.verify(compact, digest, vcek.point, { lowS: false });
  } catch {
    return false;
  }
}

// ── AMD VCEK extension profile (AMD KDS "VCEK Certificate Extensions"), read from the REAL X.509 extension table ──

/** AMD VCEK extension OIDs. */
const OID_HWID = '1.3.6.1.4.1.3704.1.4';
const OID_BL_SPL = '1.3.6.1.4.1.3704.1.3.1';
const OID_TEE_SPL = '1.3.6.1.4.1.3704.1.3.2';
const OID_SNP_SPL = '1.3.6.1.4.1.3704.1.3.3';
const OID_UCODE_SPL = '1.3.6.1.4.1.3704.1.3.8';

/** hwID / CHIP_ID is exactly 64 bytes (the extnValue content itself, no inner wrapper). */
const HWID_LEN = 64;

/**
 * Decode an SPL extension value: one DER INTEGER, minimally encoded, 0..255 (content 1 byte, or 2 bytes with a
 * leading 0x00 sign pad for 128..255). Returns the number, or a failure string.
 */
function decodeSpl(v: Uint8Array): number | string {
  if (v.length < 3 || v[0] !== 0x02) return 'is not a DER INTEGER';
  const len = v[1]!;
  if (len < 1 || len > 2 || v.length !== 2 + len) return 'has a wrong-length INTEGER';
  const c0 = v[2]!;
  if (c0 & 0x80) return 'is negative';
  if (len === 2) {
    if (c0 !== 0x00) return 'is out of range (> 255)';
    if ((v[3]! & 0x80) === 0) return 'is a non-minimal INTEGER';
    return v[3]!;
  }
  return c0;
}

/**
 * Bind the VCEK certificate body to the report: its hwID (CHIP_ID) extension must equal the report's
 * chip_id and its four SPL extensions must equal the corresponding bytes of REPORTED_TCB
 * (bootloader = byte 0, TEE = byte 1, SNP = byte 6, microcode = byte 7). Without this, a genuine but
 * OLD VCEK (low TCB) could sign a report claiming a NEW TCB, or one chip's VCEK could vouch for
 * another's report. Fail-closed when any extension is missing/unparseable.
 */
export function checkVcekReportBinding(vcekTbs: Uint8Array, report: ParsedSevSnpReport): string | null {
  let exts: Map<string, CertExtension>;
  try {
    exts = parseTbsExtensions(vcekTbs);
  } catch (e) {
    return `VCEK extensions malformed: ${e instanceof Error ? e.message : 'invalid'}`;
  }
  const hw = exts.get(OID_HWID);
  if (!hw) return 'VCEK certificate has no CHIP_ID (hwID) extension';
  if (hw.critical) return 'VCEK CHIP_ID (hwID) extension is marked critical (the AMD profile is non-critical)';
  if (hw.value.length !== HWID_LEN) return `VCEK CHIP_ID (hwID) extension is ${hw.value.length} bytes, expected ${HWID_LEN}`;
  if (!timingSafeEq(hw.value, report.chip_id)) return 'VCEK CHIP_ID does not match report chip_id';
  const t = report.reported_tcb;
  const byteAt = (i: number) => Number((t >> BigInt(8 * i)) & 0xffn);
  const pairs: Array<[string, string, number]> = [
    [OID_BL_SPL, 'bootloader', byteAt(0)],
    [OID_TEE_SPL, 'tee', byteAt(1)],
    [OID_SNP_SPL, 'snp', byteAt(6)],
    [OID_UCODE_SPL, 'microcode', byteAt(7)],
  ];
  for (const [oid, name, want] of pairs) {
    const ext = exts.get(oid);
    if (!ext) return `VCEK certificate has no ${name} SPL extension`;
    if (ext.critical) return `VCEK ${name} SPL extension is marked critical (the AMD profile is non-critical)`;
    const got = decodeSpl(ext.value);
    if (typeof got === 'string') return `VCEK ${name} SPL extension ${got}`;
    if (got !== want) return `VCEK ${name} SPL ${got} does not match report reported_tcb (${want}) — TCB downgrade?`;
  }
  return null;
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// GENUINE-SILICON PATH — real X.509 decode + the AMD RSA-PSS chain + KDS fetch (the F-4 seams, closed).
// `node:crypto` (OpenSSL) is loaded LAZILY so the portable @noble core carries no hard Node dependency.
// ════════════════════════════════════════════════════════════════════════════════════════════════

type NodeCrypto = typeof import('node:crypto');
let _nodeCryptoPromise: Promise<NodeCrypto> | null = null;
/** Lazily import `node:crypto`. Only the genuine-silicon helpers (Node/CI deployments) call this. */
async function nodeCrypto(): Promise<NodeCrypto> {
  return (_nodeCryptoPromise ??= import('node:crypto'));
}

/**
 * The AMD SEV Milan ARK (AMD Root Key) trust anchor, pinned as the SHA-384 of its DER
 * SubjectPublicKeyInfo. This is the root `openssl verify` chains to; `verifyAmdCertChain` compares the
 * chain's self-signed ARK against it so the root of trust is NEVER taken from the supplied chain. Value
 * captured from the genuine AMD KDS ASK+ARK chain (RSA-4096). Replace/extend for other product lines
 * (Genoa, Bergamo, ...) — each AMD CPU generation has its own ARK.
 */
export const AMD_MILAN_ARK_SPKI_SHA384 =
  '1249f67f15cf229a4069195e1a9ce537d1765ef706a1f4a123c36be9518786515d25ecc007f366b564d2b3f31c48082e';

/**
 * Slice the `tbsCertificate` DER bytes out of an X.509 certificate DER: the first inner element of the
 * outer SEQUENCE. These are the bytes `checkVcekReportBinding` scans for the AMD CHIP_ID / SPL
 * extensions. Throws on a structurally invalid certificate.
 */
export function extractTbsCertificate(certDer: Uint8Array): Uint8Array {
  return tbsOfCertificate(certDer);
}

/**
 * Decode the GENUINE AMD VCEK certificate (DER) and return its EC-P384 public key (for the report
 * signature check) and its `tbsCertificate` bytes (for `checkVcekReportBinding`). Uses node's
 * OpenSSL-backed X.509 parser to read the SubjectPublicKeyInfo, asserting the key is EC secp384r1.
 */
export async function extractVcekPublicKey(
  vcekDer: Uint8Array,
): Promise<{ key: EcdsaP384PublicKey; tbs: Uint8Array }> {
  const { X509Certificate } = await nodeCrypto();
  const cert = new X509Certificate(Buffer.from(vcekDer));
  const pk = cert.publicKey;
  if (pk.asymmetricKeyType !== 'ec' || pk.asymmetricKeyDetails?.namedCurve !== 'secp384r1') {
    throw new TypeError(`VCEK is not EC secp384r1 (got ${pk.asymmetricKeyType}/${pk.asymmetricKeyDetails?.namedCurve})`);
  }
  // Point via the JWK export (exact curve + full-width coordinates, FAIL CLOSED otherwise); never a byte scan of the SPKI.
  return { key: ecdsaP384PublicKey(ecPointFromKey(pk, 'P-384')), tbs: extractTbsCertificate(vcekDer) };
}

/** Split a PEM bundle into its individual `-----BEGIN CERTIFICATE-----` blocks. */
export function splitPemCertificates(pem: string): string[] {
  const out: string[] = [];
  const re = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(pem)) !== null) out.push(m[0]);
  return out;
}

/** Result of verifying the genuine AMD VCEK→ASK→ARK chain. */
export interface AmdChainResult {
  ok: boolean;
  reason?: string;
  /** The VCEK EC-P384 public key (present iff the chain verified). */
  vcek?: EcdsaP384PublicKey;
  /** The VCEK certificate's tbsCertificate bytes (for `checkVcekReportBinding`). */
  vcekTbs?: Uint8Array;
}

/**
 * Verify the GENUINE AMD certificate chain VCEK → ASK → ARK, as captured from the AMD KDS:
 *   • VCEK (EC-P384 leaf) is signed by ASK;
 *   • ASK (RSA-4096 intermediate) is signed by ARK;
 *   • ARK (RSA-4096 root) is self-signed AND its SPKI SHA-384 equals the pinned trust anchor
 *     (`trustAnchorArkSpkiSha384`, default `AMD_MILAN_ARK_SPKI_SHA384`) — the root is NOT taken from the
 *     supplied chain.
 * AMD's ASK/ARK use RSASSA-PSS with an EXPLICIT default `trailerField`; we verify through node/OpenSSL's
 * `X509Certificate.verify`, which tolerates it (strict WebCrypto/@noble parsers reject the explicit
 * default — see the module header). Fails CLOSED on any broken link. `askArkPem` is the ASK+ARK bundle.
 */
export async function verifyAmdCertChain(opts: {
  vcekDer: Uint8Array;
  askArkPem: string;
  trustAnchorArkSpkiSha384?: string;
  /** The verifier's clock (epoch ms). REQUIRED: every certificate's validity window is checked against it. */
  nowMs: number;
  /** Tolerated clock skew (ms) applied to both ends of each validity window. Default 0. */
  clockSkewMs?: number;
}): Promise<AmdChainResult> {
  try {
    if (typeof opts.nowMs !== 'number' || !Number.isFinite(opts.nowMs)) return { ok: false, reason: 'nowMs (verifier clock) is required for the AMD chain validity check' };
    const skew = opts.clockSkewMs ?? 0;
    if (typeof skew !== 'number' || !Number.isFinite(skew) || skew < 0) return { ok: false, reason: 'clockSkewMs must be a non-negative number' };
    const { X509Certificate, createHash } = await nodeCrypto();
    const vcek = new X509Certificate(Buffer.from(opts.vcekDer));
    const pems = splitPemCertificates(opts.askArkPem);
    // The AMD KDS `cert_chain` is exactly ASK then ARK; anything else is a malformed / smuggled bundle.
    if (pems.length !== 2) return { ok: false, reason: 'ASK+ARK chain must contain exactly two certificates (ASK then ARK)' };
    const [askPem, arkPem] = pems as [string, string];
    const ask = new X509Certificate(askPem);
    const ark = new X509Certificate(arkPem);
    // Order is fixed: [0] = ASK (issuer of the VCEK), [1] = ARK (self-signed root).
    if (ark.subject !== ark.issuer || !ark.verify(ark.publicKey)) return { ok: false, reason: 'second certificate of the chain is not a self-signed ARK (chain out of order?)' };
    if (ask.subject === ask.issuer) return { ok: false, reason: 'first certificate of the chain is self-signed, not an ASK (chain out of order?)' };
    if (ask.subject !== vcek.issuer) return { ok: false, reason: 'ASK subject does not match the VCEK issuer' };

    // Pin the ARK: its SPKI SHA-384 must equal the configured trust anchor (root never self-asserted).
    const pin = (opts.trustAnchorArkSpkiSha384 ?? AMD_MILAN_ARK_SPKI_SHA384).toLowerCase();
    const arkSpki = new Uint8Array(ark.publicKey.export({ type: 'spki', format: 'der' }));
    const arkFp = createHash('sha384').update(Buffer.from(arkSpki)).digest('hex');
    if (arkFp !== pin) return { ok: false, reason: 'ARK does not match the pinned AMD trust anchor' };

    if (ask.issuer !== ark.subject || !ask.verify(ark.publicKey)) return { ok: false, reason: 'ASK is not signed by ARK' };
    if (!vcek.verify(ask.publicKey)) return { ok: false, reason: 'VCEK is not signed by ASK' };

    // CA roles + critical-extension profile, from the real X.509 extension table.
    const ders: Array<[string, Uint8Array, InstanceType<typeof X509Certificate>]> = [
      ['VCEK', opts.vcekDer, vcek],
      ['ASK', new Uint8Array(ask.raw), ask],
      ['ARK', new Uint8Array(ark.raw), ark],
    ];
    const roleErr = checkChainRoles(ders.map((d) => d[1]));
    if (roleErr) return { ok: false, reason: `AMD chain role check failed: ${roleErr}` };
    for (const [label, der, cert] of ders) {
      const exts = parseCertExtensions(der);
      for (const [oid, ext] of exts) {
        if (ext.critical && !KNOWN_CRITICAL_OK.has(oid)) return { ok: false, reason: `${label} certificate has an unrecognised critical extension ${oid}` };
      }
      if (label !== 'VCEK' && exts.get('2.5.29.19')?.critical !== true) return { ok: false, reason: `${label} certificate BasicConstraints is not marked critical` };
      const from = cert.validFromDate.getTime();
      const to = cert.validToDate.getTime();
      if (!Number.isFinite(from) || !Number.isFinite(to)) return { ok: false, reason: `${label} certificate validity is unparseable` };
      if (opts.nowMs + skew < from) return { ok: false, reason: `${label} certificate is not yet valid` };
      if (opts.nowMs - skew > to) return { ok: false, reason: `${label} certificate has expired` };
    }

    const { key, tbs } = await extractVcekPublicKey(opts.vcekDer);
    return { ok: true, vcek: key, vcekTbs: tbs };
  } catch (e) {
    return { ok: false, reason: `AMD chain verification error: ${e instanceof Error ? e.message : 'unknown'}` };
  }
}

/** Critical extensions this verifier understands (RFC 5280 §4.2: an unrecognised critical extension is fatal). */
const KNOWN_CRITICAL_OK: ReadonlySet<string> = new Set(['2.5.29.19', '2.5.29.15']);

/** The outcome of a full genuine-report verification. */
export interface GenuineReportResult {
  ok: boolean;
  reason?: string;
  report?: ParsedSevSnpReport;
  measured?: MeasuredIdentity;
}

/**
 * Parse + verify a GENUINE AMD SEV-SNP attestation report END-TO-END, OFFLINE, from raw fixtures:
 *   1. parse the ATTESTATION_REPORT;
 *   2. verify the VCEK → ASK → ARK chain (`verifyAmdCertChain`, RSA-PSS via OpenSSL, ARK pinned);
 *   3. verify the report's ECDSA-P384 signature (AMD little-endian r‖s) under the chain-trusted VCEK;
 *   4. bind the VCEK cert body (CHIP_ID + reported-TCB SPLs) to the report (`checkVcekReportBinding`);
 *   5. OPTIONALLY (`expected`) bind report_data to the PCA attestation nonce — NOT used for Azure CVM
 *      captures, whose report_data carries the vTPM-AK digest (see the AZURE nuance in the header);
 *   6. OPTIONALLY apply the acceptance `policy`.
 * Returns the parsed report + derived measured identity on success; fails CLOSED with a reason.
 */
export async function verifyGenuineSevSnpReport(opts: {
  report: Uint8Array;
  vcekDer: Uint8Array;
  askArkPem: string;
  trustAnchorArkSpkiSha384?: string;
  /** The verifier's clock (epoch ms); REQUIRED — certificate validity windows are checked against it. */
  nowMs: number;
  clockSkewMs?: number;
  expected?: import('./attestation').ExpectedAttestationBinding;
  policy?: SevSnpPolicy;
}): Promise<GenuineReportResult> {
  try {
    let report: ParsedSevSnpReport;
    try {
      report = parseSevSnpReport(opts.report);
    } catch (e) {
      return { ok: false, reason: `report parse failed: ${e instanceof Error ? e.message : 'unknown'}` };
    }

    const chain = await verifyAmdCertChain({
      vcekDer: opts.vcekDer,
      askArkPem: opts.askArkPem,
      trustAnchorArkSpkiSha384: opts.trustAnchorArkSpkiSha384,
      nowMs: opts.nowMs,
      ...(opts.clockSkewMs !== undefined ? { clockSkewMs: opts.clockSkewMs } : {}),
    });
    if (!chain.ok || !chain.vcek || !chain.vcekTbs) return { ok: false, reason: `cert chain invalid: ${chain.reason}` };

    if (!verifySevSnpReportSignature(report, chain.vcek)) {
      return { ok: false, reason: 'report signature does not verify under VCEK' };
    }

    const bindErr = checkVcekReportBinding(chain.vcekTbs, report);
    if (bindErr) return { ok: false, reason: bindErr };

    if (opts.expected) {
      const expectedData = attestationBinding(opts.expected);
      if (!timingSafeEq(expectedData, report.report_data)) {
        return { ok: false, reason: 'report_data does not bind holder/grant/epoch/nonce' };
      }
    }

    if (opts.policy) {
      const polErr = checkSevSnpPolicy(report, opts.policy);
      if (polErr) return { ok: false, reason: polErr };
    }

    const measured = makeDefaultDeriveIdentity(false)(report);
    return { ok: true, report, measured };
  } catch (e) {
    return { ok: false, reason: `genuine verification error (fail closed): ${e instanceof Error ? e.message : 'unknown'}` };
  }
}

/**
 * GUARDED, OPTIONAL real AMD KDS fetch (NETWORK I/O — never called by this module on its own). Fetch the
 * VCEK certificate (DER) for a live report, keyed by its CHIP_ID + the four reported-TCB SPL bytes:
 *   https://kdsintf.amd.com/vcek/v1/<product>/<chip_id_hex>?blSPL=&teeSPL=&snpSPL=&ucodeSPL=
 * `reportedTcb` is the raw REPORTED_TCB u64 (bootloader = byte 0, TEE = byte 1, SNP = byte 6,
 * microcode = byte 7 — the same decode `checkVcekReportBinding` uses). Pair it with
 * `https://kdsintf.amd.com/vcek/v1/<product>/cert_chain` for the ASK+ARK PEM bundle. `product` defaults
 * to 'Milan'. Throws on a non-2xx response.
 */
export async function fetchVcekFromKds(
  chipId: Uint8Array,
  reportedTcb: bigint,
  opts: { product?: string; fetch?: typeof fetch; baseUrl?: string } = {},
): Promise<Uint8Array> {
  const product = opts.product ?? 'Milan';
  const base = opts.baseUrl ?? 'https://kdsintf.amd.com/vcek/v1';
  const f = opts.fetch ?? (globalThis.fetch as typeof fetch | undefined);
  if (!f) throw new Error('fetchVcekFromKds: no fetch implementation available');
  const byteAt = (i: number) => Number((reportedTcb >> BigInt(8 * i)) & 0xffn);
  const q = `blSPL=${byteAt(0)}&teeSPL=${byteAt(1)}&snpSPL=${byteAt(6)}&ucodeSPL=${byteAt(7)}`;
  const url = `${base}/${product}/${toHex(chipId)}?${q}`;
  const res = await f(url);
  if (!res.ok) throw new Error(`KDS VCEK fetch failed: HTTP ${res.status} for ${url}`);
  return new Uint8Array(await res.arrayBuffer());
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Policy + identity mapping.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/**
 * Acceptance policy for a verified report. Every gate is optional; an omitted/empty gate accepts any
 * value. All hex comparisons are lowercase.
 */
export interface SevSnpPolicy {
  /**
   * Allowed MEASUREMENT values (lowercase hex of the 48-byte register). REQUIRED and NON-EMPTY:
   * `createAmdSnpVerifier` throws at construction otherwise (no accept-all).
   */
  measurements?: string[];
  /**
   * Allowed HOST_DATA values (hex). HOST_DATA is supplied by the HOST at launch, not by the guest:
   * it is a launch-config gate only. Omitted => HOST_DATA is not gated.
   */
  hostData?: string[];
  /**
   * INSECURE opt-in: map HOST_DATA to `weights_digest`. SEV-SNP has no native weights field, and
   * HOST_DATA is host-asserted, so a malicious host can claim any weights; only enable if the host is
   * inside your trust boundary. Default off. A weights digest derived this way is marked
   * `weights_measured: false`, so it can satisfy a plain `weights_allowlist` but NEVER a
   * `require_measured_weights` pin.
   */
  weightsFromHostData?: boolean;
  /** INSECURE opt-in: accept reports whose guest policy has the DEBUG bit (19) set. Default false. */
  allowDebug?: boolean;
  /** Allowed CHIP_ID values (lowercase hex of the 64-byte id). Empty/omitted => any (VCEK-bound) chip. */
  chipIds?: string[];
  /** Minimum acceptable GUEST_SVN. */
  minGuestSvn?: number;
  /** Minimum acceptable REPORTED_TCB (raw u64). Rejects down-rev / rolled-back TCB. */
  minReportedTcb?: bigint;
  /**
   * Minimum acceptable COMMITTED_TCB / LAUNCH_TCB (raw u64, compared as AMD packs it: SPL bytes
   * bootloader=0, tee=1, snp=6, microcode=7). Compared as whole integers, like `minReportedTcb`, so
   * pick a value whose high (microcode/snp) bytes dominate as intended.
   */
  minCommittedTcb?: bigint;
  minLaunchTcb?: bigint;
  /** Required VMPL the report must have been requested at (e.g. 0). Omitted => accept any. */
  requireVmpl?: number;
  /** Require SIGNATURE_ALGO === ECDSA_P384_SHA384 (default true). */
  requireEcdsaP384?: boolean;
  /**
   * Map a verified report into the `MeasuredIdentity` that `agent_binding` is checked against. Default:
   *   runtime_measurement = hex(MEASUREMENT)        — hardware-authoritative launch measurement
   *   operator            = hex(CHIP_ID)            — hardware operator identity
   *   weights_digest      = '' (SEV-SNP has no weights field), or host-asserted HOST_DATA with the
   *                         INSECURE weightsFromHostData; weights_measured is ALWAYS false
   *   model_id            = ''                       — SEV-SNP carries no model id; override to supply one
   * Override to match your deployment (e.g. a measurement → model_id / weights registry).
   */
  deriveIdentity?: (report: ParsedSevSnpReport) => MeasuredIdentity;
}

/** The default report -> measured-identity mapping (see {@link SevSnpPolicy.deriveIdentity}). */
export function makeDefaultDeriveIdentity(weightsFromHostData: boolean) {
  return (report: ParsedSevSnpReport): MeasuredIdentity => {
    return {
      model_id: '',
      weights_digest: weightsFromHostData ? toHex(report.host_data) : '',
      weights_measured: false, // SEV-SNP has no weights field; HOST_DATA is host-asserted
      runtime_measurement: toHex(report.measurement),
      operator: toHex(report.chip_id),
    };
  };
}

/** SEV-SNP guest POLICY bit 19: DEBUG (host may read/modify guest memory => no confidentiality). */
export const SEV_SNP_POLICY_DEBUG_BIT = 1n << 19n;

/** Check the report against the acceptance policy. Returns a reason on the first failure, else null. */
export function checkSevSnpPolicy(report: ParsedSevSnpReport, policy: SevSnpPolicy): string | null {
  if (policy.requireEcdsaP384 !== false && report.signature_algo !== SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384) {
    return `unexpected signature_algo ${report.signature_algo}`;
  }
  if (policy.allowDebug !== true && (report.policy & SEV_SNP_POLICY_DEBUG_BIT) !== 0n) {
    return 'guest policy has the DEBUG bit set (host can inspect the guest)';
  }
  if (typeof policy.minGuestSvn === 'number' && report.guest_svn < policy.minGuestSvn) {
    return `guest_svn ${report.guest_svn} below minimum ${policy.minGuestSvn}`;
  }
  if (typeof policy.minReportedTcb === 'bigint' && report.reported_tcb < policy.minReportedTcb) {
    return `reported_tcb below minimum (rollback?)`;
  }
  if (typeof policy.minCommittedTcb === 'bigint' && report.committed_tcb < policy.minCommittedTcb) {
    return 'committed_tcb below minimum (rollback?)';
  }
  if (typeof policy.minLaunchTcb === 'bigint' && report.launch_tcb < policy.minLaunchTcb) {
    return 'launch_tcb below minimum';
  }
  if (typeof policy.requireVmpl === 'number' && report.vmpl !== policy.requireVmpl) {
    return `vmpl ${report.vmpl} is not the required ${policy.requireVmpl}`;
  }
  if (Array.isArray(policy.measurements) && policy.measurements.length > 0) {
    const m = toHex(report.measurement);
    if (!policy.measurements.map((x) => x.toLowerCase()).includes(m)) {
      return 'measurement not in policy allowlist';
    }
  }
  if (Array.isArray(policy.hostData) && policy.hostData.length > 0) {
    const h = toHex(report.host_data);
    if (!policy.hostData.map((x) => x.toLowerCase()).includes(h)) return 'host_data not in policy allowlist';
  }
  if (Array.isArray(policy.chipIds) && policy.chipIds.length > 0) {
    const c = toHex(report.chip_id);
    if (!policy.chipIds.map((x) => x.toLowerCase()).includes(c)) {
      return 'chip_id not in policy allowlist';
    }
  }
  return null;
}

function timingSafeEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
