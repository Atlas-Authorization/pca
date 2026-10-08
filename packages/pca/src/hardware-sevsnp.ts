/**
 * L0 HARDWARE backend — AMD SEV-SNP attestation report VERIFIER.
 *
 * This is the production implementation of the `HardwareAttestationVerifier` seam declared in
 * attestation.ts. Where the software mode trusts a key that VOUCHED for self-asserted measurements,
 * this module roots the identity in silicon: it parses an AMD SEV-SNP `ATTESTATION_REPORT`, verifies
 * its ECDSA-P384 signature with the VCEK public key, verifies the VCEK→ASK→ARK certificate chain up
 * to a configured ARK trust anchor, and confirms the report's `report_data` cryptographically binds
 * the PCActn's attestation nonce. The HARDWARE-measured identity it returns then flows through the
 * same freshness / nonce / agent_binding gates in `createAttestationVerifier`, so a lying document
 * cannot pass a genuine hardware check.
 *
 * ──────────────────────────────────────────────────────────────────────────────────────────────────
 * WHAT IS CRYPTOGRAPHICALLY VERIFIED HERE (real crypto, exercised end-to-end by the tests):
 *   1. ECDSA-P384 / SHA-384 signature over the report's signed region [0x000, 0x2A0) using the VCEK
 *      public key. AMD stores the signature as little-endian r‖s (72-byte fields); we convert to the
 *      big-endian scalar form @noble/curves expects.
 *   2. The VCEK→ASK→ARK chain: VCEK's TBS is ECDSA-P384-signed by ASK, ASK's TBS by ARK, the ARK
 *      public key byte-equals the configured `trustAnchorArk`, AND each TBS actually CONTAINS (as its
 *      SubjectPublicKeyInfo point) the `chain.ask` / `chain.vcek` key being used — so a genuine
 *      ARK-signed ASK TBS cannot be paired with an attacker's ASK key. Fail-closed on any broken link.
 *   3. The VCEK's CHIP_ID (1.3.6.1.4.1.3704.1.4) and reported-TCB SPL (…1.3.1/.2/.3/.8) extensions
 *      equal the report's chip_id / reported_tcb (blocks old-VCEK-signs-new-report TCB downgrade).
 *   4. report_data === attestationBinding({holderPub, grantRef, epoch, nonce}) (see attestation.ts).
 *   5. Policy gates: NON-EMPTY measurement allowlist (enforced at construction), DEBUG policy bit
 *      rejected, CHIP_ID / TCB / VMPL / GUEST_SVN. HOST_DATA is host-asserted and NOT used as identity
 *      by default.
 *
 * GENUINE-SILICON PATH (the X.509/KDS seams the security review (F-4) flagged are now CLOSED):
 *   • `verifyGenuineSevSnpReport` parses + verifies a REAL AMD SEV-SNP report end-to-end, OFFLINE, from
 *     a captured `snp_report.bin` + `vcek.der` + ASK/ARK `chain.pem` (see testdata/sevsnp-real/, captured
 *     from an Azure confidential VM — AMD EPYC Milan). It (a) extracts the VCEK EC-P384 point out of the
 *     genuine `vcek.der` SubjectPublicKeyInfo, (b) verifies the report's ECDSA-P384 signature (AMD's
 *     little-endian r‖s) under that key, (c) verifies the VCEK→ASK→ARK chain, (d) binds the VCEK cert's
 *     CHIP_ID + reported-TCB SPL extensions to the report. This upgrades the suite from mock-only to
 *     validated-against-real-silicon.
 *   • X.509 / PEM DECODING + the RSA-PSS chain. AMD's VCEK is an EC-P384 leaf, but the ASK/ARK
 *     intermediates/root are RSA-4096 signed with RSASSA-PSS carrying an EXPLICIT, DEFAULT-valued
 *     `trailerField` (trailerFieldBC / 0x01). Strict ASN.1 parsers (incl. node's WebCrypto and @noble,
 *     which has no RSA at all) reject that explicit default; OpenSSL tolerates it. We therefore verify
 *     the RSA-PSS chain through node's `crypto.X509Certificate.verify()` (OpenSSL-backed — an audited
 *     dependency, the same engine `openssl verify` used out-of-band), and extract the VCEK EC point from
 *     its SPKI. The EC report-signature core is still our own @noble/curves P-384 code. `node:crypto` is
 *     imported LAZILY so the portable @noble core carries no hard Node dependency; the genuine path is a
 *     Node deployment/CI concern.
 *   • The synthetic ECDSA chain model below (`SevSnpCertChain` / `verifyVcekChain`) is RETAINED: it is
 *     the portable, library-free relationship check the mock suite exercises and a fallback for callers
 *     who pre-decode certs themselves. The genuine path does not use it (AMD's ASK/ARK are RSA).
 *   • AMD KDS fetching. Genuine VCEK/ASK/ARK certs are fetched from the AMD Key Distribution Service
 *     (https://kdsintf.amd.com/vcek/v1/...) keyed by CHIP_ID + reported TCB. `fetchVcekFromKds` is a real
 *     (guarded, never auto-invoked, network) implementation of that fetch; `kdsFetch` on the verifier is
 *     the hook to wire it into your own `resolveEvidence`. This module does no network I/O on its own.
 *   • The raw report bytes + the parsed chain for a given action are produced by `resolveEvidence`
 *     (the evidence seam). A real deployment carries the base64 report + cert bundle alongside the
 *     attestation document (or fetches the certs via `kdsFetch`) and hands back `SevSnpEvidence`.
 *
 * AZURE CONFIDENTIAL-VM NUANCE (important for the report_data binding): on an Azure CV2 confidential VM
 * the guest does NOT issue the SNP guest-request directly — the Azure paravisor (VMPL0) mediates it and
 * places the digest of the guest's vTPM Attestation Key (AK) into the report's `report_data`. So on
 * Azure CVMs the PCA action-binding is indirect: the SNP report attests the vTPM AK, and the PCActn
 * nonce/holder/grant binding is carried in a vTPM quote signed by that now-attested AK (report_data ==
 * H(vTPM AK pub)). On DIRECT guest-request platforms (bare-metal / clouds that expose the guest request
 * to the guest) the guest controls `report_data` and puts the PCA `attestationBinding` there directly —
 * which is the model `createSevSnpVerifier` enforces (report_data === attestationBinding(expected)). The
 * genuine Azure fixture therefore verifies cryptographically (chain + report signature + VCEK↔report
 * binding) but its `report_data` is the vTPM-AK digest, NOT a PCA binding; `verifyGenuineSevSnpReport`
 * makes the PCA-binding check OPTIONAL for exactly this reason.
 *
 * STANDARDIZATION GAP (spec §15): SEV-SNP attests the confidential-VM LAUNCH measurement, not the
 * loaded model weights. The MEASUREMENT register and CHIP_ID are hardware-authoritative; `model_id` /
 * `operator` are not fields a raw SEV-SNP report carries, so `deriveIdentity` maps them from
 * launch-bound fields (CHIP_ID for the hardware operator) — honest about what hardware can and cannot
 * prove. Override `deriveIdentity` to match your launch convention.
 *
 * WEIGHTS-LEVEL ATTESTATION (the gap, partially closed — approach (a) of the attestation.ts header).
 * There is no native SEV-SNP field for the loaded model weights, so this backend defines a CONVENTION:
 * the model runtime measures the loaded weights and reflects the 48-byte digest into a dedicated slot
 * (`OFF.WEIGHTS_MEASUREMENT`) that sits INSIDE the report's signed region [0x000,0x2A0). Because the
 * VCEK signs that region, the measured weights digest is HARDWARE-ROOTED and tamper-evident: a host or
 * guest cannot change it without invalidating the report signature, exactly like MEASUREMENT. The
 * default `deriveIdentity` extracts it and returns it as `weights_digest` WITH `weights_measured: true`
 * so `agent_binding.require_measured_weights` can fail closed on anything self-/host-asserted. An
 * all-zero slot means "the runtime measured no weights" (ABSENT): `weights_digest` then falls back to
 * '' (or, with the INSECURE `weightsFromHostData`, host-asserted HOST_DATA) and `weights_measured` is
 * false. HONESTY: like the rest of this module, the convention + extraction + enforcement are proven
 * against SYNTHETIC/MOCK reports (real P-384 crypto, no silicon). Which signed field a given deployment
 * reflects the weights measurement into — this slot, an extended-report measurement register, or the
 * launch MEASUREMENT of a weights-inclusive image — is a launch-convention seam; override
 * `deriveIdentity` to match it. Live proof needs a real SEV-SNP/TDX machine.
 *
 * References: AMD SEV-SNP ABI Specification (Rev. 1.55+), "ATTESTATION_REPORT Structure" and
 * "ECDSA_P384_SHA384 Signature" tables; AMD KDS interface documentation.
 */
import { sha384, sha512 } from '@noble/hashes/sha512';
import { p384 } from '@noble/curves/p384';
import { b64u } from './hash';
import { mlDsa65Verify, mlDsa87Verify } from './pq';
import { attestationBinding } from './attestation';
import type {
  AttestationDocument,
  HardwareAttestationResult,
  HardwareAttestationVerifier,
  MeasuredIdentity,
} from './attestation';
import type { VerifyContext } from './pcactn';

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
  // 0x188 reserved (24 B)
  CHIP_ID: 0x1a0, //            64 B  unique chip id (hardware operator identity)
  // ── PCA CONVENTION (NOT a standard AMD field — see the WEIGHTS-LEVEL ATTESTATION note in the module
  //    header). A 48-byte slot inside the SIGNED region carrying the model runtime's MEASURED weights
  //    digest, so the VCEK signature covers it and it is hardware-rooted + tamper-evident. All-zero =>
  //    the runtime measured no weights (treated as ABSENT). ──
  WEIGHTS_MEASUREMENT: 0x1e0, // 48 B  measured loaded-model-weights digest (PCA convention)
  // ... reserved / build fields ...
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
  /**
   * PCA CONVENTION (see the module header's WEIGHTS-LEVEL ATTESTATION note): the model runtime's
   * MEASURED loaded-weights digest (48 B), carried in the report's signed region so it is
   * hardware-rooted. All-zero => no weights were measured (ABSENT).
   */
  weights_measurement: Uint8Array; // 48
  id_key_digest: Uint8Array; // 48
  author_key_digest: Uint8Array; // 48
  report_id: Uint8Array; // 32
  report_id_ma: Uint8Array; // 32
  reported_tcb: bigint;
  chip_id: Uint8Array; // 64
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
    weights_measurement: slice(bytes, OFF.WEIGHTS_MEASUREMENT, 48),
    id_key_digest: slice(bytes, OFF.ID_KEY_DIGEST, 48),
    author_key_digest: slice(bytes, OFF.AUTHOR_KEY_DIGEST, 48),
    report_id: slice(bytes, OFF.REPORT_ID, 32),
    report_id_ma: slice(bytes, OFF.REPORT_ID_MA, 32),
    reported_tcb: u64le(dv, OFF.REPORTED_TCB),
    chip_id: slice(bytes, OFF.CHIP_ID, 64),
    signature: { r: slice(bytes, OFF.SIG_R, 72), s: slice(bytes, OFF.SIG_S, 72) },
    signed: slice(bytes, 0, OFF.SIGNED_END),
    raw: bytes.slice(),
  };
}

/**
 * Serialize a report back to its binary layout. Primarily a TOOLING / TEST utility (the inverse of
 * `parseSevSnpReport`, keeping the field offsets in one place); production only ever PARSES reports
 * produced by real hardware. Fields default to zero; byte fields are left-padded/truncated to size.
 */
export function serializeSevSnpReport(
  fields: Partial<{
    version: number;
    guest_svn: number;
    policy: bigint;
    family_id: Uint8Array;
    image_id: Uint8Array;
    vmpl: number;
    signature_algo: number;
    current_tcb: bigint;
    platform_info: bigint;
    report_data: Uint8Array;
    measurement: Uint8Array;
    host_data: Uint8Array;
    weights_measurement: Uint8Array;
    id_key_digest: Uint8Array;
    author_key_digest: Uint8Array;
    report_id: Uint8Array;
    report_id_ma: Uint8Array;
    reported_tcb: bigint;
    chip_id: Uint8Array;
    signature: { r: Uint8Array; s: Uint8Array };
  }>,
): Uint8Array {
  const out = new Uint8Array(OFF.REPORT_LEN);
  const dv = new DataView(out.buffer);
  const put = (off: number, len: number, src?: Uint8Array) => {
    if (!src) return;
    out.set(src.subarray(0, len), off);
  };
  dv.setUint32(OFF.VERSION, fields.version ?? 2, true);
  dv.setUint32(OFF.GUEST_SVN, fields.guest_svn ?? 0, true);
  dv.setBigUint64(OFF.POLICY, fields.policy ?? 0n, true);
  put(OFF.FAMILY_ID, 16, fields.family_id);
  put(OFF.IMAGE_ID, 16, fields.image_id);
  dv.setUint32(OFF.VMPL, fields.vmpl ?? 0, true);
  dv.setUint32(OFF.SIGNATURE_ALGO, fields.signature_algo ?? SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384, true);
  dv.setBigUint64(OFF.CURRENT_TCB, fields.current_tcb ?? 0n, true);
  dv.setBigUint64(OFF.PLATFORM_INFO, fields.platform_info ?? 0n, true);
  put(OFF.REPORT_DATA, 64, fields.report_data);
  put(OFF.MEASUREMENT, 48, fields.measurement);
  put(OFF.HOST_DATA, 32, fields.host_data);
  put(OFF.WEIGHTS_MEASUREMENT, 48, fields.weights_measurement);
  put(OFF.ID_KEY_DIGEST, 48, fields.id_key_digest);
  put(OFF.AUTHOR_KEY_DIGEST, 48, fields.author_key_digest);
  put(OFF.REPORT_ID, 32, fields.report_id);
  put(OFF.REPORT_ID_MA, 32, fields.report_id_ma);
  dv.setBigUint64(OFF.REPORTED_TCB, fields.reported_tcb ?? 0n, true);
  put(OFF.CHIP_ID, 64, fields.chip_id);
  if (fields.signature) {
    put(OFF.SIG_R, 72, fields.signature.r);
    put(OFF.SIG_S, 72, fields.signature.s);
  }
  return out;
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

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Certificate chain (VCEK → ASK → ARK). X.509 decoding / KDS fetching are the documented SEAM; this
// module checks the cryptographic signature RELATIONSHIPS given already-parsed inputs.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/**
 * The AMD cert chain as ALREADY-PARSED inputs. Each link carries the signer-independent "to be signed"
 * bytes (`*_tbs`, the X.509 tbsCertificate DER) and the ECDSA-P384 signature over SHA-384 of them
 * (`*_sig`, big-endian compact r‖s, 96 bytes). Production fills this by X.509-decoding the genuine AMD
 * VCEK / ASK / ARK certificates (see the module header). The ARK public key must equal the configured
 * `trustAnchorArk`; it is the root of trust, never taken from the chain itself.
 */
export interface SevSnpCertChain {
  /** AMD Root Key public key — compared for equality against the configured trust anchor. */
  ark: EcdsaP384PublicKey;
  /** AMD SEV Key (intermediate) public key — must be signed by ARK. */
  ask: EcdsaP384PublicKey;
  /** Versioned Chip Endorsement Key (leaf) public key — must be signed by ASK; signs the report. */
  vcek: EcdsaP384PublicKey;
  /** ASK certificate's tbsCertificate DER bytes (signed by ARK). */
  ask_tbs: Uint8Array;
  /** ECDSA-P384 signature over SHA-384(ask_tbs), big-endian compact r‖s. */
  ask_sig: Uint8Array;
  /** VCEK certificate's tbsCertificate DER bytes (signed by ASK). */
  vcek_tbs: Uint8Array;
  /** ECDSA-P384 signature over SHA-384(vcek_tbs), big-endian compact r‖s. */
  vcek_sig: Uint8Array;
}

/** All the evidence needed to verify one action's attestation: the raw report + its cert chain. */
export interface SevSnpEvidence {
  /** The raw ATTESTATION_REPORT bytes exactly as the hardware emitted them. */
  report: Uint8Array;
  /** The parsed VCEK/ASK/ARK chain (X.509-decoded and/or KDS-fetched — the SEAM). */
  chain: SevSnpCertChain;
}

function pubEq(a: EcdsaP384PublicKey, b: EcdsaP384PublicKey): boolean {
  if (a.point.length !== b.point.length) return false;
  let diff = 0;
  for (let i = 0; i < a.point.length; i++) diff |= a.point[i]! ^ b.point[i]!;
  return diff === 0;
}

function verifyTbsSig(tbs: Uint8Array, sig: Uint8Array, signer: EcdsaP384PublicKey): boolean {
  try {
    return p384.verify(sig, sha384(tbs), signer.point, { lowS: false });
  } catch {
    return false;
  }
}

/** The outcome of chain verification: ok, or a specific reason it failed closed. */
export interface SevSnpChainResult {
  ok: boolean;
  reason?: string;
}

// ── minimal DER helpers (NOT an X.509 parser — only enough to bind keys/extensions inside a TBS) ──

function indexOfBytes(hay: Uint8Array, needle: Uint8Array, from = 0): number {
  outer: for (let i = from; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

/**
 * True iff the TBS contains `key`'s uncompressed point EXACTLY ONCE, framed as the SubjectPublicKeyInfo
 * BIT STRING payload (`03 62 00 ‖ 04 ‖ X ‖ Y`, the P-384 encoding). The TBS is signed by the parent,
 * so a genuine TBS contains only its own subject key; pairing it with any other key fails here.
 */
export function tbsContainsSubjectKey(tbs: Uint8Array, key: EcdsaP384PublicKey): boolean {
  const framed = new Uint8Array(3 + key.point.length);
  framed.set([0x03, 0x62, 0x00], 0);
  framed.set(key.point, 3);
  const first = indexOfBytes(tbs, framed);
  if (first < 0) return false;
  return indexOfBytes(tbs, framed, first + 1) < 0;
}

/** Read one DER TLV at `off` (short or 1-2 byte long-form lengths). */
function readTlv(b: Uint8Array, off: number): { tag: number; start: number; end: number } | null {
  if (off + 2 > b.length) return null;
  const tag = b[off]!;
  let len = b[off + 1]!;
  let start = off + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 2 || off + 2 + n > b.length) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | b[off + 2 + i]!;
    start = off + 2 + n;
  }
  const end = start + len;
  return end <= b.length ? { tag, start, end } : null;
}

/** DER OID TLV bytes for a dotted OID (arcs < 2^28). */
function oidDer(dotted: string): Uint8Array {
  const arcs = dotted.split('.').map(Number);
  const body: number[] = [arcs[0]! * 40 + arcs[1]!];
  for (const a of arcs.slice(2)) {
    const stack = [a & 0x7f];
    for (let v = a >>> 7; v > 0; v >>>= 7) stack.unshift((v & 0x7f) | 0x80);
    body.push(...stack);
  }
  return Uint8Array.from([0x06, body.length, ...body]);
}

/**
 * Extract an X.509 extension's inner value bytes by OID from a TBS: finds the OID TLV, skips an
 * optional `critical` BOOLEAN, reads the extnValue OCTET STRING and returns its content. Returns
 * undefined when absent or malformed (callers fail closed). Requires exactly one occurrence.
 */
function extensionValue(tbs: Uint8Array, dotted: string): Uint8Array | undefined {
  const oid = oidDer(dotted);
  const at = indexOfBytes(tbs, oid);
  if (at < 0 || indexOfBytes(tbs, oid, at + 1) >= 0) return undefined;
  let off = at + oid.length;
  const maybeBool = readTlv(tbs, off);
  if (maybeBool && maybeBool.tag === 0x01) off = maybeBool.end;
  const oct = readTlv(tbs, off);
  if (!oct || oct.tag !== 0x04) return undefined;
  return tbs.slice(oct.start, oct.end);
}

/** AMD VCEK extension OIDs (AMD KDS "VCEK Certificate Extensions"). */
const OID_HWID = '1.3.6.1.4.1.3704.1.4';
const OID_BL_SPL = '1.3.6.1.4.1.3704.1.3.1';
const OID_TEE_SPL = '1.3.6.1.4.1.3704.1.3.2';
const OID_SNP_SPL = '1.3.6.1.4.1.3704.1.3.3';
const OID_UCODE_SPL = '1.3.6.1.4.1.3704.1.3.8';

function spl(tbs: Uint8Array, dotted: string): number | undefined {
  const v = extensionValue(tbs, dotted);
  if (!v) return undefined;
  // inner DER INTEGER (02 len value) or a bare single byte
  if (v.length >= 3 && v[0] === 0x02) {
    const t = readTlv(v, 0);
    if (!t || t.end !== v.length || t.end - t.start < 1 || t.end - t.start > 2) return undefined;
    let n = 0;
    for (let i = t.start; i < t.end; i++) n = (n << 8) | v[i]!;
    return n;
  }
  return v.length === 1 ? v[0] : undefined;
}

/**
 * Bind the VCEK certificate body to the report: its hwID (CHIP_ID) extension must equal the report's
 * chip_id and its four SPL extensions must equal the corresponding bytes of REPORTED_TCB
 * (bootloader = byte 0, TEE = byte 1, SNP = byte 6, microcode = byte 7). Without this, a genuine but
 * OLD VCEK (low TCB) could sign a report claiming a NEW TCB, or one chip's VCEK could vouch for
 * another's report. Fail-closed when any extension is missing/unparseable.
 */
export function checkVcekReportBinding(vcekTbs: Uint8Array, report: ParsedSevSnpReport): string | null {
  const hw = extensionValue(vcekTbs, OID_HWID);
  if (!hw) return 'VCEK certificate has no CHIP_ID (hwID) extension';
  const chip = hw.length === 66 && hw[0] === 0x04 && hw[1] === 0x40 ? hw.subarray(2) : hw;
  if (chip.length !== 64 || !timingSafeEq(chip, report.chip_id)) return 'VCEK CHIP_ID does not match report chip_id';
  const t = report.reported_tcb;
  const byteAt = (i: number) => Number((t >> BigInt(8 * i)) & 0xffn);
  const pairs: Array<[string, string, number]> = [
    [OID_BL_SPL, 'bootloader', byteAt(0)],
    [OID_TEE_SPL, 'tee', byteAt(1)],
    [OID_SNP_SPL, 'snp', byteAt(6)],
    [OID_UCODE_SPL, 'microcode', byteAt(7)],
  ];
  for (const [oid, name, want] of pairs) {
    const got = spl(vcekTbs, oid);
    if (got === undefined) return `VCEK certificate has no ${name} SPL extension`;
    if (got !== want) return `VCEK ${name} SPL ${got} does not match report reported_tcb (${want}) — TCB downgrade?`;
  }
  return null;
}

/**
 * Verify the SEV-SNP certificate chain cryptographically:
 *   1. the chain's ARK byte-equals the configured `trustAnchorArk` (root of trust is NOT self-asserted);
 *   2. ASK's tbsCertificate contains the `chain.ask` key as its SPKI point, and is signed by ARK;
 *   3. VCEK's tbsCertificate contains the `chain.vcek` key as its SPKI point, and is signed by ASK.
 * The key↔TBS binding (2,3) is what stops an attacker pairing a genuine ARK-signed TBS with their own
 * key. Returns the first failing link's reason. Producing the TBS/sig bytes from real X.509 certs is
 * the caller's SEAM (vetted X.509 library); this checks the relationships.
 */
export function verifyVcekChain(input: { chain: SevSnpCertChain; trustAnchorArk: EcdsaP384PublicKey }): SevSnpChainResult {
  const { chain, trustAnchorArk } = input;
  try {
    if (!pubEq(chain.ark, trustAnchorArk)) return { ok: false, reason: 'ARK does not match the configured trust anchor' };
    if (!tbsContainsSubjectKey(chain.ask_tbs, chain.ask)) return { ok: false, reason: 'ASK key is not the subject key of the ASK certificate body' };
    if (!verifyTbsSig(chain.ask_tbs, chain.ask_sig, chain.ark)) return { ok: false, reason: 'ASK is not signed by ARK' };
    if (!tbsContainsSubjectKey(chain.vcek_tbs, chain.vcek)) return { ok: false, reason: 'VCEK key is not the subject key of the VCEK certificate body' };
    if (!verifyTbsSig(chain.vcek_tbs, chain.vcek_sig, chain.ask)) return { ok: false, reason: 'VCEK is not signed by ASK' };
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: `chain verification error: ${e instanceof Error ? e.message : 'unknown'}` };
  }
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// POST-QUANTUM CRYPTO-AGILITY SEAM (report signature + certificate chain).
//
// ── HONEST SCOPE — READ THIS FIRST. ──────────────────────────────────────────────────────────────
// This seam FUTURE-PROOFS the verifier for the day AMD ships a post-quantum report / endorsement-key
// suite, and it lets one attestation root be PQ while another stays classical (see the multi-root
// policy in attestation.ts). It DOES NOT, and CANNOT, make a single AMD SEV-SNP attestation
// post-quantum. The SEV-SNP root of trust is the VCEK→ASK→ARK signature chain AMD burns around its
// silicon, and TODAY that is ECDSA-P384 (the report) rooted in an RSA-4096-PSS (ASK/ARK) chain. A
// quantum adversary able to forge that CLASSICAL chain can forge ANY report body — INCLUDING any PQ
// public key an honest guest might place in report_data — so no amount of PQ wrapping at THIS layer
// upgrades AMD's silicon root. Only AMD re-rooting SEV-SNP in a PQ signature scheme does that. What
// this seam genuinely buys: (1) agility — when AMD publishes a PQ SIGNATURE_ALGO, mapping it into
// `SEV_SNP_REPORT_SUITE_BY_ALGO` is a ONE-LINE change and the dispatch needs NO rework; (2) the
// ability to combine an AMD root with an INDEPENDENT second root (one of which may be PQ), removing
// sole dependence on one vendor's classical root; (3) PQ-signed accountability (attestation.ts) so a
// forged/anomalous attestation is detectable and attributable after the fact.
//
// The `ml-dsa-*` suites below are SYNTHETIC PLACEHOLDERS — AMD does not ship a PQ SEV-SNP suite as of
// this writing. They are verified with @noble/post-quantum and exercised ONLY by clearly-labelled
// synthetic tests; the genuine ECDSA-P384 Milan path is unchanged and byte-identical.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/**
 * The signature suite of a SEV-SNP report or a certificate-chain link — the crypto-agility discriminant.
 * `ecdsa-p384-sha384` is the ONLY suite real AMD silicon produces today. The `ml-dsa-*` suites are
 * SYNTHETIC placeholders for a future AMD PQ roadmap (see the section header's honest-scope note).
 */
export type SevSnpSigSuite = 'ecdsa-p384-sha384' | 'ml-dsa-65' | 'ml-dsa-87';

/**
 * SYNTHETIC placeholder SIGNATURE_ALGO ids for the PQ report suites — NOT assigned by AMD. They sit in
 * a clearly non-AMD experimental band so a report built with them can never be mistaken for a genuine
 * AMD report (whose `signature_algo` is {@link SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384} === 1). Replace or
 * extend with AMD's real PQ algo ids when published — a one-line registry edit, no dispatcher rework.
 */
export const SEV_SNP_SIG_ALGO_SYNTHETIC_ML_DSA_65 = 0xf065;
export const SEV_SNP_SIG_ALGO_SYNTHETIC_ML_DSA_87 = 0xf087;

/**
 * The report-suite dispatch table, keyed by the report's `SIGNATURE_ALGO` u32. This is the SINGLE place
 * the verifier learns "which algorithm signed this report". Adding AMD's real PQ algo id here is the
 * only change needed to accept a PQ report — `resolveReportSuite`, `verifyReportSignatureAgile`, the
 * agile verifier, the multi-root policy and the accountability anchor all dispatch through it.
 */
export const SEV_SNP_REPORT_SUITE_BY_ALGO: ReadonlyMap<number, SevSnpSigSuite> = new Map<number, SevSnpSigSuite>([
  [SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384, 'ecdsa-p384-sha384'],
  [SEV_SNP_SIG_ALGO_SYNTHETIC_ML_DSA_65, 'ml-dsa-65'],
  [SEV_SNP_SIG_ALGO_SYNTHETIC_ML_DSA_87, 'ml-dsa-87'],
]);

/** Resolve a report's declared signature suite from its `SIGNATURE_ALGO` field. `null` => fail closed. */
export function resolveReportSuite(signatureAlgo: number): SevSnpSigSuite | null {
  return SEV_SNP_REPORT_SUITE_BY_ALGO.get(signatureAlgo) ?? null;
}

/**
 * A suite-tagged public key — the crypto-agility key union. For `ecdsa-p384-sha384` it carries the AMD
 * EC-P384 point (as today); for a PQ suite it carries the raw ML-DSA public-key bytes. One shape, so the
 * report-signature check and every chain link dispatch the same way.
 */
export type SevSnpSuiteKey =
  | { readonly suite: 'ecdsa-p384-sha384'; readonly ecdsa: EcdsaP384PublicKey }
  | { readonly suite: 'ml-dsa-65'; readonly mlDsaPub: Uint8Array }
  | { readonly suite: 'ml-dsa-87'; readonly mlDsaPub: Uint8Array };

/**
 * A detached report signature for a NON-ECDSA suite. Absent for `ecdsa-p384-sha384`, which reads AMD's
 * little-endian r‖s from the report's fixed signature block. A real AMD PQ report format would carry a
 * larger signature area than today's 2×72-byte ECDSA block (ML-DSA-65 signatures are 3309 bytes), so the
 * PQ signature is modeled as evidence-carried bytes until such a format exists.
 */
export interface AgileReportSignature {
  pqSig?: Uint8Array;
}

/**
 * Verify a report's signature under a suite-tagged key, DISPATCHING on the report's declared
 * `SIGNATURE_ALGO`. Fail-closed: an unknown algo, a report whose declared suite does not equal the key's
 * suite, a missing PQ signature, or any invalid signature returns false. The ECDSA branch delegates to
 * the proven `verifySevSnpReportSignature` (byte-identical to today); the PQ branches verify the ML-DSA
 * signature over the report's signed region [0x000, 0x2A0).
 */
export function verifyReportSignatureAgile(
  report: ParsedSevSnpReport,
  key: SevSnpSuiteKey,
  sig: AgileReportSignature = {},
): boolean {
  try {
    const declared = resolveReportSuite(report.signature_algo);
    if (declared === null) return false; // unknown algo => fail closed
    if (declared !== key.suite) return false; // the report must agree with the key it is checked under
    switch (key.suite) {
      case 'ecdsa-p384-sha384':
        return verifySevSnpReportSignature(report, key.ecdsa);
      case 'ml-dsa-65':
        return sig.pqSig instanceof Uint8Array && mlDsa65Verify(key.mlDsaPub, report.signed, sig.pqSig);
      case 'ml-dsa-87':
        return sig.pqSig instanceof Uint8Array && mlDsa87Verify(key.mlDsaPub, report.signed, sig.pqSig);
    }
  } catch {
    return false;
  }
}

/** One endorsement-certificate link in the crypto-agile chain. */
export interface AgileCertLink {
  /** The subject public key this certificate endorses (for VCEK, the key that signs the report). */
  subject: SevSnpSuiteKey;
  /** The `tbsCertificate` bytes signed by the issuer. */
  tbs: Uint8Array;
  /** The issuer's signature over `tbs`, in the ISSUER's suite. */
  sig: Uint8Array;
}

/**
 * The AMD endorsement chain as suite-tagged links: ARK (root) → ASK (intermediate) → VCEK (leaf). Each
 * link may carry its OWN suite, so one link can be PQ while another stays classical (e.g. a PQ VCEK
 * endorsed by a still-classical ASK, or vice-versa, during an AMD migration). The ecdsa-only
 * `SevSnpCertChain` / `verifyVcekChain` above remain for the classical path; this is the agile superset.
 */
export interface AgileCertChain {
  /** AMD Root Key — compared (suite-aware) against the configured trust anchor; never self-asserted. */
  ark: SevSnpSuiteKey;
  /** ASK link (its TBS is signed by ARK; its subject key signs the VCEK TBS). */
  ask: AgileCertLink;
  /** VCEK link (its TBS is signed by ASK; its subject key signs the report). */
  vcek: AgileCertLink;
}

/** Suite-aware constant-time key equality. */
function suiteKeyEq(a: SevSnpSuiteKey, b: SevSnpSuiteKey): boolean {
  if (a.suite !== b.suite) return false;
  if (a.suite === 'ecdsa-p384-sha384' && b.suite === 'ecdsa-p384-sha384') return pubEq(a.ecdsa, b.ecdsa);
  if (a.suite !== 'ecdsa-p384-sha384' && b.suite !== 'ecdsa-p384-sha384') return timingSafeEq(a.mlDsaPub, b.mlDsaPub);
  return false;
}

/** The TBS must embed its subject key EXACTLY ONCE (ecdsa: SPKI framing; ml-dsa: the raw pub bytes). */
function agileTbsContainsSubjectKey(tbs: Uint8Array, key: SevSnpSuiteKey): boolean {
  if (key.suite === 'ecdsa-p384-sha384') return tbsContainsSubjectKey(tbs, key.ecdsa);
  const first = indexOfBytes(tbs, key.mlDsaPub);
  if (first < 0) return false;
  return indexOfBytes(tbs, key.mlDsaPub, first + 1) < 0;
}

/** Verify a TBS signature by the issuer, dispatching on the ISSUER's suite. Never throws. */
function verifyTbsSigAgile(tbs: Uint8Array, sig: Uint8Array, signer: SevSnpSuiteKey): boolean {
  try {
    switch (signer.suite) {
      case 'ecdsa-p384-sha384':
        return p384.verify(sig, sha384(tbs), signer.ecdsa.point, { lowS: false });
      case 'ml-dsa-65':
        return mlDsa65Verify(signer.mlDsaPub, tbs, sig);
      case 'ml-dsa-87':
        return mlDsa87Verify(signer.mlDsaPub, tbs, sig);
    }
  } catch {
    return false;
  }
}

/**
 * Crypto-agile VCEK→ASK→ARK chain verification — the suite-dispatching analogue of `verifyVcekChain`:
 *   1. the chain's ARK equals the configured `trustAnchorArk` (suite-aware; root never self-asserted);
 *   2. ASK's TBS embeds `ask.subject` and is signed by ARK (dispatched on ARK's suite);
 *   3. VCEK's TBS embeds `vcek.subject` and is signed by ASK (dispatched on ASK's suite).
 * Each link dispatches on its signer's suite, so a classical and a PQ link can coexist. Fail-closed on
 * the first broken link.
 */
export function verifyAgileCertChain(input: { chain: AgileCertChain; trustAnchorArk: SevSnpSuiteKey }): SevSnpChainResult {
  const { chain, trustAnchorArk } = input;
  try {
    if (!suiteKeyEq(chain.ark, trustAnchorArk)) return { ok: false, reason: 'ARK does not match the configured trust anchor' };
    if (!agileTbsContainsSubjectKey(chain.ask.tbs, chain.ask.subject)) return { ok: false, reason: 'ASK key is not the subject key of the ASK certificate body' };
    if (!verifyTbsSigAgile(chain.ask.tbs, chain.ask.sig, chain.ark)) return { ok: false, reason: 'ASK is not signed by ARK' };
    if (!agileTbsContainsSubjectKey(chain.vcek.tbs, chain.vcek.subject)) return { ok: false, reason: 'VCEK key is not the subject key of the VCEK certificate body' };
    if (!verifyTbsSigAgile(chain.vcek.tbs, chain.vcek.sig, chain.ask.subject)) return { ok: false, reason: 'VCEK is not signed by ASK' };
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: `chain verification error: ${e instanceof Error ? e.message : 'unknown'}` };
  }
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
  const outer = readTlv(certDer, 0);
  if (!outer || outer.tag !== 0x30) throw new RangeError('extractTbsCertificate: not a DER SEQUENCE');
  const tbs = readTlv(certDer, outer.start);
  if (!tbs || tbs.tag !== 0x30) throw new RangeError('extractTbsCertificate: no tbsCertificate SEQUENCE');
  // tbsCertificate bytes INCLUDING its own tag+length header (that is what is hashed/signed).
  return certDer.slice(outer.start, tbs.end);
}

/**
 * Extract the uncompressed EC P-384 point (`0x04 ‖ X(48) ‖ Y(48)`) from a DER SubjectPublicKeyInfo. A
 * P-384 SPKI ends with the BIT STRING `03 62 00 04 X Y`; we locate that framing (and fall back to the
 * trailing 97 bytes). Returned via `ecdsaP384PublicKey`, which rejects an off-curve point.
 */
function extractEcP384PointFromSpki(spkiDer: Uint8Array): EcdsaP384PublicKey {
  const framed = Uint8Array.from([0x03, 0x62, 0x00, 0x04]);
  const at = indexOfBytes(spkiDer, framed);
  const pt = at >= 0 ? spkiDer.slice(at + 3, at + 3 + 97) : spkiDer.slice(spkiDer.length - 97);
  return ecdsaP384PublicKey(pt); // validates the point is on-curve
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
  const spki = new Uint8Array(pk.export({ type: 'spki', format: 'der' }));
  return { key: extractEcP384PointFromSpki(spki), tbs: extractTbsCertificate(vcekDer) };
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
}): Promise<AmdChainResult> {
  try {
    const { X509Certificate, createHash } = await nodeCrypto();
    const vcek = new X509Certificate(Buffer.from(opts.vcekDer));
    const pems = splitPemCertificates(opts.askArkPem);
    if (pems.length < 2) return { ok: false, reason: 'ASK+ARK chain must contain at least two certificates' };
    const certs = pems.map((p) => new X509Certificate(p));
    // ARK = the self-signed root; ASK = the intermediate that issued the VCEK.
    const ark = certs.find((c) => c.subject === c.issuer && c.verify(c.publicKey));
    if (!ark) return { ok: false, reason: 'no self-signed ARK (root) in the chain' };
    const ask = certs.find((c) => c !== ark && c.subject === vcek.issuer);
    if (!ask) return { ok: false, reason: 'no ASK whose subject matches the VCEK issuer' };

    // Pin the ARK: its SPKI SHA-384 must equal the configured trust anchor (root never self-asserted).
    const pin = (opts.trustAnchorArkSpkiSha384 ?? AMD_MILAN_ARK_SPKI_SHA384).toLowerCase();
    const arkSpki = new Uint8Array(ark.publicKey.export({ type: 'spki', format: 'der' }));
    const arkFp = createHash('sha384').update(Buffer.from(arkSpki)).digest('hex');
    if (arkFp !== pin) return { ok: false, reason: 'ARK does not match the pinned AMD trust anchor' };

    if (ask.issuer !== ark.subject || !ask.verify(ark.publicKey)) return { ok: false, reason: 'ASK is not signed by ARK' };
    if (!vcek.verify(ask.publicKey)) return { ok: false, reason: 'VCEK is not signed by ASK' };

    const { key, tbs } = await extractVcekPublicKey(opts.vcekDer);
    return { ok: true, vcek: key, vcekTbs: tbs };
  } catch (e) {
    return { ok: false, reason: `AMD chain verification error: ${e instanceof Error ? e.message : 'unknown'}` };
  }
}

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
   * `createSevSnpVerifier` throws at construction otherwise (no accept-all).
   */
  measurements?: string[];
  /**
   * Allowed HOST_DATA values (hex). HOST_DATA is supplied by the HOST at launch, not by the guest:
   * it is a launch-config gate only. Omitted => HOST_DATA is not gated.
   */
  hostData?: string[];
  /**
   * INSECURE opt-in: map HOST_DATA to `weights_digest` WHEN no measured-weights slot is present.
   * HOST_DATA is host-asserted, so a malicious host can claim any weights; only enable if the host is
   * inside your trust boundary. Default off. A weights digest derived this way is marked
   * `weights_measured: false`, so it can satisfy a plain `weights_allowlist` but NEVER a
   * `require_measured_weights` pin. The hardware-rooted `OFF.WEIGHTS_MEASUREMENT` slot, when present,
   * always takes precedence over HOST_DATA.
   */
  weightsFromHostData?: boolean;
  /**
   * Allowed MEASURED-weights digests (lowercase hex of the 48-byte `OFF.WEIGHTS_MEASUREMENT` slot).
   * A verifier-side allowlist, gated like `measurements`: when non-empty, a report whose measured
   * weights digest is not listed is rejected. Only the hardware-measured slot is checked (never
   * HOST_DATA). Omitted/empty => not gated here (the grant's `weights_allowlist` still applies). An
   * all-zero slot (no weights measured) is never accepted by a non-empty list.
   */
  weightsMeasurements?: string[];
  /** INSECURE opt-in: accept reports whose guest policy has the DEBUG bit (19) set. Default false. */
  allowDebug?: boolean;
  /** Allowed CHIP_ID values (lowercase hex of the 64-byte id). Empty/omitted => any (VCEK-bound) chip. */
  chipIds?: string[];
  /** Minimum acceptable GUEST_SVN. */
  minGuestSvn?: number;
  /** Minimum acceptable REPORTED_TCB (raw u64). Rejects down-rev / rolled-back TCB. */
  minReportedTcb?: bigint;
  /** Required VMPL the report must have been requested at (e.g. 0). Omitted => accept any. */
  requireVmpl?: number;
  /** Require SIGNATURE_ALGO === ECDSA_P384_SHA384 (default true). */
  requireEcdsaP384?: boolean;
  /**
   * Map a verified report into the `MeasuredIdentity` that `agent_binding` is checked against. Default:
   *   runtime_measurement = hex(MEASUREMENT)        — hardware-authoritative launch measurement
   *   operator            = hex(CHIP_ID)            — hardware operator identity
   *   weights_digest      = hex(WEIGHTS_MEASUREMENT) when that signed slot is non-zero (HARDWARE-MEASURED,
   *                         weights_measured: true); else '' (or host-asserted HOST_DATA with the
   *                         INSECURE weightsFromHostData, weights_measured: false)
   *   model_id            = ''                       — SEV-SNP carries no model id; override to supply one
   * Override to match your launch convention (e.g. a measurement → model_id registry, or a different
   * signed field your runtime reflects the weights measurement into).
   */
  deriveIdentity?: (report: ParsedSevSnpReport) => MeasuredIdentity;
}

/** True iff every byte is zero (an unmeasured / ABSENT fixed-width slot). */
function isAllZero(b: Uint8Array): boolean {
  for (let i = 0; i < b.length; i++) if (b[i] !== 0) return false;
  return true;
}

function makeDefaultDeriveIdentity(weightsFromHostData: boolean) {
  return (report: ParsedSevSnpReport): MeasuredIdentity => {
    // HARDWARE-ROOTED weights: a non-zero measured-weights slot is covered by the VCEK signature, so it
    // is silicon-measured, not self-asserted. It wins over the (host-asserted) HOST_DATA fallback.
    if (!isAllZero(report.weights_measurement)) {
      return {
        model_id: '',
        weights_digest: toHex(report.weights_measurement),
        weights_measured: true,
        runtime_measurement: toHex(report.measurement),
        operator: toHex(report.chip_id),
      };
    }
    return {
      model_id: '',
      weights_digest: weightsFromHostData ? toHex(report.host_data) : '',
      weights_measured: false, // absent, or host-asserted HOST_DATA: NOT silicon-measured
      runtime_measurement: toHex(report.measurement),
      operator: toHex(report.chip_id),
    };
  };
}

/** SEV-SNP guest POLICY bit 19: DEBUG (host may read/modify guest memory => no confidentiality). */
export const SEV_SNP_POLICY_DEBUG_BIT = 1n << 19n;

// ════════════════════════════════════════════════════════════════════════════════════════════════
// The SEV-SNP HardwareAttestationVerifier.
// ════════════════════════════════════════════════════════════════════════════════════════════════

export interface SevSnpVerifierOptions {
  /** The configured ARK trust anchor. The chain's ARK must byte-equal this; it is the root of trust. */
  trustAnchorArk: EcdsaP384PublicKey;
  /** Acceptance policy for the verified report (measurements, chip ids, TCB floor, VMPL, ...). */
  policy: SevSnpPolicy;
  /**
   * EVIDENCE SEAM: produce the raw report bytes + parsed cert chain for an action. Production reads the
   * base64 report + cert bundle carried with the attestation document, or fetches certs via `kdsFetch`.
   * If omitted, the verifier fails closed (no evidence) — there is no safe default source of a report.
   */
  resolveEvidence?: (
    document: AttestationDocument,
    ctx: VerifyContext,
  ) => SevSnpEvidence | undefined | Promise<SevSnpEvidence | undefined>;
  /**
   * KDS SEAM (optional, documented, NEVER called by this module on its own): fetch the genuine AMD
   * VCEK/ASK/ARK certs from https://kdsintf.amd.com keyed by CHIP_ID + reported TCB, returning a parsed
   * chain. Wire it into your own `resolveEvidence` if you fetch certs lazily.
   */
  kdsFetch?: (chipId: Uint8Array, reportedTcb: bigint) => Promise<SevSnpCertChain>;
}

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
  if (Array.isArray(policy.weightsMeasurements) && policy.weightsMeasurements.length > 0) {
    if (isAllZero(report.weights_measurement)) return 'no measured weights digest in report (weightsMeasurements required)';
    const w = toHex(report.weights_measurement);
    if (!policy.weightsMeasurements.map((x) => x.toLowerCase()).includes(w)) return 'measured weights digest not in policy allowlist';
  }
  if (Array.isArray(policy.chipIds) && policy.chipIds.length > 0) {
    const c = toHex(report.chip_id);
    if (!policy.chipIds.map((x) => x.toLowerCase()).includes(c)) {
      return 'chip_id not in policy allowlist';
    }
  }
  return null;
}

/**
 * Build a `HardwareAttestationVerifier` backed by AMD SEV-SNP. Given an attestation document + context
 * it resolves the raw report + cert chain (the evidence seam), then:
 *   1. parses the ATTESTATION_REPORT;
 *   2. verifies the VCEK→ASK→ARK chain up to the configured ARK trust anchor;
 *   3. verifies the report's ECDSA-P384 signature with the (now chain-trusted) VCEK;
 *   4. confirms report_data === attestationBinding(expected) (holder/grant/epoch/server nonce);
 *   5. applies the acceptance policy to MEASUREMENT / CHIP_ID / TCB / VMPL / GUEST_SVN;
 *   6. returns the hardware-measured identity (`deriveIdentity`) — which `createAttestationVerifier`
 *      then matches against the grant's agent_binding (the MEASURED identity wins over the document).
 * Fails CLOSED with a specific reason on any mismatch or error.
 *
 * Wire it in: `createAttestationVerifier({ trustedAttestorKeys: [], hardwareVerifier: createSevSnpVerifier(opts), resolveDocument })`.
 */
export function createSevSnpVerifier(opts: SevSnpVerifierOptions): HardwareAttestationVerifier {
  if (!opts?.policy || !Array.isArray(opts.policy.measurements) || opts.policy.measurements.length === 0) {
    throw new TypeError('createSevSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)');
  }
  const deriveIdentity = opts.policy.deriveIdentity ?? makeDefaultDeriveIdentity(opts.policy.weightsFromHostData === true);

  return {
    async verify(input): Promise<HardwareAttestationResult> {
      const fail = (reason: string): HardwareAttestationResult => ({ ok: false, reason });
      try {
        if (!opts.resolveEvidence) return fail('no SEV-SNP evidence resolver configured (fail closed)');
        const evidence = await opts.resolveEvidence(input.document, input.ctx);
        if (!evidence || !(evidence.report instanceof Uint8Array) || !evidence.chain) {
          return fail('no SEV-SNP evidence for this action');
        }

        // (1) parse
        let report: ParsedSevSnpReport;
        try {
          report = parseSevSnpReport(evidence.report);
        } catch (e) {
          return fail(`report parse failed: ${e instanceof Error ? e.message : 'unknown'}`);
        }

        // (2) chain to the ARK trust anchor
        const chain = verifyVcekChain({ chain: evidence.chain, trustAnchorArk: opts.trustAnchorArk });
        if (!chain.ok) return fail(`cert chain invalid: ${chain.reason}`);

        // (3) report signature with the chain-trusted VCEK
        if (!verifySevSnpReportSignature(report, evidence.chain.vcek)) {
          return fail('report signature does not verify under VCEK');
        }

        // (3b) VCEK body ↔ report: CHIP_ID + reported-TCB SPLs (blocks TCB downgrade / chip swap)
        const vErr = checkVcekReportBinding(evidence.chain.vcek_tbs, report);
        if (vErr) return fail(vErr);

        // (4) report_data must equal H(domain ‖ holder ‖ grant ‖ epoch ‖ server nonce)
        if (!input.expected) return fail('no expected attestation binding supplied');
        let expectedData: Uint8Array;
        try {
          expectedData = attestationBinding(input.expected);
        } catch (e) {
          return fail(`binding not constructible: ${e instanceof Error ? e.message : 'invalid'}`);
        }
        if (!timingSafeEq(expectedData, report.report_data)) {
          return fail('report_data does not bind holder/grant/epoch/nonce (relayed or unbound quote)');
        }

        // (5) acceptance policy
        const polErr = checkSevSnpPolicy(report, opts.policy);
        if (polErr) return fail(polErr);

        // (6) hardware-measured identity
        const measured = deriveIdentity(report);
        return { ok: true, bound: true, measured, hostAsserted: { host_data: toHex(report.host_data) } };
      } catch (e) {
        return fail(`sev-snp verification error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`);
      }
    },
  };
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// CRYPTO-AGILE SEV-SNP verifier — the same `HardwareAttestationVerifier` seam, dispatching report +
// chain verification on the DECLARED suite. For `ecdsa-p384-sha384` (the only suite AMD ships today) it
// yields verdicts identical to `createSevSnpVerifier`; for a (synthetic, future) `ml-dsa-*` suite it
// verifies the PQ report + PQ chain. See the honest-scope note on the agility seam above: this does NOT
// make AMD's silicon root post-quantum — it readies the verifier for AMD's PQ roadmap with no rework.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/** Crypto-agile evidence: the raw report, a suite-tagged chain, and (PQ only) a detached report sig. */
export interface AgileSevSnpEvidence {
  /** The raw ATTESTATION_REPORT bytes exactly as the hardware emitted them. */
  report: Uint8Array;
  /** The suite-tagged VCEK/ASK/ARK chain (each link may be classical or PQ). */
  chain: AgileCertChain;
  /** The detached report signature for a PQ suite (absent for ecdsa — read from the report's r‖s block). */
  reportSig?: AgileReportSignature;
}

export interface AgileSevSnpVerifierOptions {
  /** The configured ARK trust anchor (suite-tagged). The chain's ARK must equal this; it is the root. */
  trustAnchorArk: SevSnpSuiteKey;
  /**
   * Acceptance policy for the verified report. The SAME `SevSnpPolicy` as the classical verifier; for a
   * PQ report suite set `requireEcdsaP384: false` (the report's `SIGNATURE_ALGO` is non-ECDSA by design,
   * and suite agreement is already enforced by `resolveReportSuite` + the VCEK key suite match).
   */
  policy: SevSnpPolicy;
  /** EVIDENCE SEAM — as `SevSnpVerifierOptions.resolveEvidence`, but yields {@link AgileSevSnpEvidence}. */
  resolveEvidence?: (
    document: AttestationDocument,
    ctx: VerifyContext,
  ) => AgileSevSnpEvidence | undefined | Promise<AgileSevSnpEvidence | undefined>;
}

/**
 * Build a crypto-agile `HardwareAttestationVerifier` backed by AMD SEV-SNP. It resolves the raw report +
 * suite-tagged chain, then:
 *   1. parses the report and resolves its declared suite from `SIGNATURE_ALGO` (`resolveReportSuite`);
 *   2. requires the VCEK key's suite to equal the report's declared suite (fail-closed on mismatch);
 *   3. verifies the VCEK→ASK→ARK chain to the ARK anchor (`verifyAgileCertChain`, per-link suite);
 *   4. verifies the report signature under the chain-trusted VCEK key (`verifyReportSignatureAgile`);
 *   5. binds the VCEK cert body (CHIP_ID + reported-TCB SPLs) to the report (`checkVcekReportBinding`);
 *   6. confirms report_data === attestationBinding(expected);
 *   7. applies the acceptance policy and returns the hardware-measured identity.
 * Fails CLOSED with a specific reason on any mismatch or error.
 */
export function createAgileSevSnpVerifier(opts: AgileSevSnpVerifierOptions): HardwareAttestationVerifier {
  if (!opts?.policy || !Array.isArray(opts.policy.measurements) || opts.policy.measurements.length === 0) {
    throw new TypeError('createAgileSevSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)');
  }
  const deriveIdentity = opts.policy.deriveIdentity ?? makeDefaultDeriveIdentity(opts.policy.weightsFromHostData === true);

  return {
    async verify(input): Promise<HardwareAttestationResult> {
      const fail = (reason: string): HardwareAttestationResult => ({ ok: false, reason });
      try {
        if (!opts.resolveEvidence) return fail('no SEV-SNP evidence resolver configured (fail closed)');
        const evidence = await opts.resolveEvidence(input.document, input.ctx);
        if (!evidence || !(evidence.report instanceof Uint8Array) || !evidence.chain) {
          return fail('no SEV-SNP evidence for this action');
        }

        // (1) parse
        let report: ParsedSevSnpReport;
        try {
          report = parseSevSnpReport(evidence.report);
        } catch (e) {
          return fail(`report parse failed: ${e instanceof Error ? e.message : 'unknown'}`);
        }

        // (1b) resolve the declared suite + require the VCEK key to match it (crypto-agility dispatch)
        const declared = resolveReportSuite(report.signature_algo);
        if (declared === null) return fail(`unknown report signature suite (signature_algo ${report.signature_algo})`);
        if (evidence.chain.vcek.subject.suite !== declared) {
          return fail(`report suite ${declared} does not match the VCEK key suite ${evidence.chain.vcek.subject.suite}`);
        }

        // (2) chain to the ARK trust anchor (per-link suite dispatch)
        const chain = verifyAgileCertChain({ chain: evidence.chain, trustAnchorArk: opts.trustAnchorArk });
        if (!chain.ok) return fail(`cert chain invalid: ${chain.reason}`);

        // (3) report signature with the chain-trusted VCEK, dispatched on the declared suite
        if (!verifyReportSignatureAgile(report, evidence.chain.vcek.subject, evidence.reportSig ?? {})) {
          return fail('report signature does not verify under VCEK');
        }

        // (3b) VCEK body ↔ report: CHIP_ID + reported-TCB SPLs (blocks TCB downgrade / chip swap)
        const vErr = checkVcekReportBinding(evidence.chain.vcek.tbs, report);
        if (vErr) return fail(vErr);

        // (4) report_data must equal H(domain ‖ holder ‖ grant ‖ epoch ‖ server nonce)
        if (!input.expected) return fail('no expected attestation binding supplied');
        let expectedData: Uint8Array;
        try {
          expectedData = attestationBinding(input.expected);
        } catch (e) {
          return fail(`binding not constructible: ${e instanceof Error ? e.message : 'invalid'}`);
        }
        if (!timingSafeEq(expectedData, report.report_data)) {
          return fail('report_data does not bind holder/grant/epoch/nonce (relayed or unbound quote)');
        }

        // (5) acceptance policy
        const polErr = checkSevSnpPolicy(report, opts.policy);
        if (polErr) return fail(polErr);

        // (6) hardware-measured identity
        const measured = deriveIdentity(report);
        return { ok: true, bound: true, measured, hostAsserted: { host_data: toHex(report.host_data) } };
      } catch (e) {
        return fail(`sev-snp verification error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`);
      }
    },
  };
}

function timingSafeEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/** base64url of a public key point — handy for logging / pinning a trust anchor. */
export function fingerprintPublicKey(pk: EcdsaP384PublicKey): string {
  return b64u(sha384(pk.point)).slice(0, 16);
}
