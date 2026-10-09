/**
 * L0 HARDWARE backend — Intel TDX (DCAP) quote primitives and offline verification.
 *
 * Parses and verifies a GENUINE Intel DCAP v4 / ECDSA-P256 TDX quote, the exact wire format Intel's
 * Quote Generation Library emits and Azure/GCP TDX guests return. The `HardwareAttestationVerifier` built
 * on these primitives is `attest-intel-dcap.ts` (`createIntelDcapVerifier`); this module holds the format
 * parsing and the cryptographic checks it composes.
 *
 * PQ STATUS: CLASSICAL. Intel's DCAP root of trust is an ECDSA chain over NIST P-256 today; a quantum
 * adversary able to forge ECDSA-P256 can forge this attestation. Its value in the multi-root policy is
 * INDEPENDENCE from AMD and NVIDIA roots, not post-quantum strength.
 *
 * WHAT IS VERIFIED (see {@link verifyGenuineTdxQuote}, real @noble/curves P-256 + node X.509):
 *   1. the embedded PCK X.509 chain to the PINNED Intel SGX Root CA;
 *   2. FMSPC and the PCK leaf's issued TCB from the Intel SGX extension;
 *   3. the QE report signature under the PCK leaf, and that the QE report binds the attestation key
 *      (report_data[0:32] == SHA-256(AK_pub || QE_AUTH), [32:64] == 0);
 *   4. the TD quote signature under that attestation key;
 *   5. optionally report_data == attestationBinding(...), and MRTD / FMSPC / RTMR0 allowlists.
 * TCB status and QE identity against Intel PCS collateral are handled in `attest-intel-collateral.ts`.
 *
 * References: Intel TDX DCAP Quote Generation Library; Intel SGX ECDSA Quote (DCAP) format; Intel SGX
 * PCK Certificate and CRL Specification (FMSPC / TCB SVN extensions).
 */
import { p256 } from '@noble/curves/p256';
import { sha256 } from './hash';
import { checkChainRoles, ecPointFromKey } from './x509-strict';
import { attestationBinding } from './attestation';
import type { ExpectedAttestationBinding, MeasuredIdentity } from './attestation';

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

/** Verify an ECDSA-P256/SHA-256 signature (compact r‖s) over `msg`. Never throws (fail closed on error). */
function verifyP256(msg: Uint8Array, sigCompact: Uint8Array, key: EcdsaP256PublicKey): boolean {
  try {
    // lowS:false — ECDSA validity does not require low-S and Intel hardware does not normalize it.
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

/** Lowercase hex of a byte array (stable identity string for MRTD / FMSPC / RTMR). */
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
// ════════════════════════════════════════════════════════════════════════════════════════════════
// GENUINE-SILICON PATH — a REAL Intel DCAP ECDSA quote (v4 / TDX) + an X.509-decoded Intel PCK
// certificate chain, verified end-to-end to the PINNED Intel SGX Root CA.
//
// This path consumes the exact wire format Intel's DCAP Quote Generation Library emits and Azure's
// IMDS `/acc/tdquote` returns: a v4 ECDSA-P256 TD quote whose signature-data section embeds the QE report,
// the QE-report signature, and a REAL PEM X.509 PCK chain (PCK leaf → Intel SGX PCK Platform CA → Intel
// SGX Root CA). The chain is decoded by node's OpenSSL-backed `X509Certificate` (the same engine
// `hardware-sevsnp.ts` uses for AMD's ASK/ARK), the FMSPC + TCB are read from the Intel SGX extensions,
// and every signature is checked with the @noble/curves P-256 core.
// Exercised against a captured real Azure Intel TDX quote in `fixtures/real-tdx/`.
//
// ── HONEST SCOPE — what this path PROVES vs what still needs ONLINE Intel PCS collateral. ───────────
// PROVEN, SELF-CONTAINED in the quote (no network):
//   • the PCK chain is well-formed X.509 and each link is signed by the next, up to a self-signed root
//     whose SPKI SHA-256 byte-equals the PINNED Intel SGX Root CA ({@link INTEL_SGX_ROOT_CA_SPKI_SHA256});
//   • the QE report is ECDSA-P256-signed by the PCK leaf;
//   • the QE report binds the attestation key: report_data[0:32] == SHA-256(AK_pub ‖ QE_AUTH), [32:64]==0;
//   • the TD quote is ECDSA-P256-signed by that attestation key over SHA-256(header ‖ TD-report-body);
//   • the FMSPC + the PCK leaf's issued TCB (16 SGX component SVNs + PCESVN) are extracted from the
//     leaf's Intel SGX extension (OID 1.2.840.113741.1.13.1) under the issuer signature.
// NOT done here (requires fetching live Intel PCS / Azure THIM collateral — do NOT fake it):
//   • TCB STATUS: mapping the platform FMSPC + the TD's TEE_TCB_SVN + the PCK's SGX TCB/PCESVN against
//     the signed Intel PCS "TCB info" JSON to decide UpToDate / OutOfDate / Revoked. The PCK's SGX TCB
//     and the TD report's TEE_TCB_SVN live in different TCB domains; relating them is exactly what the
//     signed TCB-info collateral is for. Surfaced raw here ({@link GenuineTdxResult.pckTcb},
//     `report.teeTcbSvn`) for an online evaluator — never silently asserted up-to-date.
//   • QE IDENTITY: checking the QE report's MRSIGNER / ISV-SVN against the signed Intel PCS "QE identity"
//     JSON. (The QE report IS verified to chain to Intel via the PCK leaf; its ISV identity-vs-policy is
//     the online step.)
//   • PCK / Root CRLs (revocation).
// ════════════════════════════════════════════════════════════════════════════════════════════════

type NodeCrypto = typeof import('node:crypto');
let _nodeCryptoPromise: Promise<NodeCrypto> | null = null;
/** Lazily import `node:crypto` (OpenSSL). Only the genuine-silicon helpers call this; the @noble core does not. */
async function nodeCrypto(): Promise<NodeCrypto> {
  return (_nodeCryptoPromise ??= import('node:crypto'));
}

/**
 * The Intel SGX Root CA trust anchor, PINNED as the SHA-256 of its DER SubjectPublicKeyInfo. The PCK
 * chain's self-signed root must hash to this — the root of trust is NEVER taken from the supplied chain.
 * This is Intel's public, well-known SGX Provisioning Certification Root CA (ECDSA P-256); its SPKI is
 * `04 0ba9c4c0…ae7394`, published at
 * https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem .
 */
export const INTEL_SGX_ROOT_CA_SPKI_SHA256 = 'a0af031289f5d5d4132f9186068a7fc13628633ba235777472e29b6b6c67a49e' as const;

/** Intel DCAP quote / TD-report wire constants (v4 ECDSA-P256, TDX). */
const DCAP = {
  HEADER_LEN: 48, //                       quote header
  TD_REPORT_LEN: 584, //                   TD report body (TDX 1.0 "TD10")
  VERSION_V4: 4,
  ATT_KEY_TYPE_ECDSA_P256: 2, //           ECDSA-256-with-P-256
  TEE_TYPE_TDX: 0x81,
  SGX_REPORT_LEN: 384, //                  the QE's SGX report
  QE_ATTRIBUTES_OFF: 48, //                ATTRIBUTES.FLAGS in the SGX report
  QE_REPORT_DATA_OFF: 0x140, //            report_data slot in the SGX report (320)
  CERT_TYPE_QE_REPORT: 6, //               outer cert-data: QE report + sig + auth + inner cert
  CERT_TYPE_PCK_CHAIN: 5, //               inner cert-data: PEM PCK certificate chain
} as const;

/** TD report (TDX 1.0 / "TD10") field offsets within the 584-byte body. */
const TD10 = {
  TEE_TCB_SVN: 0, //      16
  MR_SEAM: 16, //         48
  MR_SIGNER_SEAM: 64, //  48
  SEAM_ATTRIBUTES: 112, // 8
  TD_ATTRIBUTES: 120, //   8
  XFAM: 128, //            8
  MRTD: 136, //           48
  MR_CONFIG_ID: 184, //   48
  MR_OWNER: 232, //       48
  MR_OWNER_CONFIG: 280, //48
  RTMR0: 328, //          48
  RTMR1: 376, //          48
  RTMR2: 424, //          48
  RTMR3: 472, //          48
  REPORT_DATA: 520, //    64
} as const;

/** A parsed genuine TD report (TD10). Byte fields are fresh copies. */
export interface DcapTdReport {
  teeTcbSvn: Uint8Array; // 16 — the TD's TEE TCB SVN (TDX-module TCB domain; evaluate vs PCS TCB info)
  mrSeam: Uint8Array; //    48
  mrSignerSeam: Uint8Array; //48 — signer of the TDX module (Intel)
  tdAttributes: Uint8Array; // 8 — TD_ATTRIBUTES; bit 0 (byte 0, LSB) is DEBUG
  mrTd: Uint8Array; //      48 — the TD launch measurement
  mrConfigId: Uint8Array; //48
  rtmr0: Uint8Array; //     48
  rtmr1: Uint8Array; //     48
  rtmr2: Uint8Array; //     48
  rtmr3: Uint8Array; //     48
  reportData: Uint8Array; //64 — guest-supplied (on Azure FDE: SHA-256(vTPM-AK), not a PCA binding)
  raw: Uint8Array;
}

/** Parse a genuine 584-byte TD10 report body. Throws if too short. */
export function parseDcapTdReport(body: Uint8Array): DcapTdReport {
  if (!(body instanceof Uint8Array)) throw new TypeError('parseDcapTdReport: expected Uint8Array');
  if (body.length < DCAP.TD_REPORT_LEN) throw new RangeError(`parseDcapTdReport: body too short (${body.length} < ${DCAP.TD_REPORT_LEN})`);
  const at = (off: number, len: number) => body.slice(off, off + len);
  return {
    teeTcbSvn: at(TD10.TEE_TCB_SVN, 16),
    mrSeam: at(TD10.MR_SEAM, 48),
    mrSignerSeam: at(TD10.MR_SIGNER_SEAM, 48),
    tdAttributes: at(TD10.TD_ATTRIBUTES, 8),
    mrTd: at(TD10.MRTD, 48),
    mrConfigId: at(TD10.MR_CONFIG_ID, 48),
    rtmr0: at(TD10.RTMR0, 48),
    rtmr1: at(TD10.RTMR1, 48),
    rtmr2: at(TD10.RTMR2, 48),
    rtmr3: at(TD10.RTMR3, 48),
    reportData: at(TD10.REPORT_DATA, 64),
    raw: body.slice(0, DCAP.TD_REPORT_LEN),
  };
}

/** A parsed Intel DCAP quote: the signed region, the AK + its QE endorsement, and the PEM PCK chain. */
export interface ParsedDcapQuote {
  version: number;
  attKeyType: number;
  teeType: number;
  /** The 48-byte quote header (part of the AK-signed region). */
  header: Uint8Array;
  /** The 584-byte TD report body (part of the AK-signed region). */
  tdReportBody: Uint8Array;
  /** The TD quote signature — ECDSA-P256 compact r‖s over SHA-256(header ‖ tdReportBody). */
  quoteSignature: Uint8Array;
  /** The attestation key as raw 64-byte X‖Y (as Intel carries it; prefix 0x04 for SEC1). */
  akPubRaw: Uint8Array;
  /** The Quoting Enclave's 384-byte SGX report. */
  qeReportBody: Uint8Array;
  /** The QE report signature — ECDSA-P256 compact r‖s over SHA-256(qeReportBody) under the PCK leaf. */
  qeReportSignature: Uint8Array;
  /** The QE authentication data bound into the QE report's report_data. */
  qeAuthData: Uint8Array;
  /** The PEM PCK certificate chain (PCK leaf → Platform CA → Intel SGX Root CA). */
  pckChainPem: string;
}

function u16le(dv: DataView, off: number): number {
  return dv.getUint16(off, true);
}
function u32le(dv: DataView, off: number): number {
  return dv.getUint32(off, true);
}

/**
 * Parse a genuine Intel DCAP v4 / ECDSA-P256 / TDX quote into {@link ParsedDcapQuote}. Bounds-checked and
 * fail-closed: throws a specific `RangeError`/`TypeError` on any structural violation (wrong version /
 * att-key type / tee type, truncation, unexpected cert-data wrapper types). Trailing bytes after the
 * declared signature-data length are ignored.
 */
export function parseDcapQuote(quote: Uint8Array): ParsedDcapQuote {
  if (!(quote instanceof Uint8Array)) throw new TypeError('parseDcapQuote: expected Uint8Array');
  if (quote.length < DCAP.HEADER_LEN + DCAP.TD_REPORT_LEN + 4) throw new RangeError('parseDcapQuote: too short for header + TD report + sig length');
  const dv = new DataView(quote.buffer, quote.byteOffset, quote.byteLength);
  const version = u16le(dv, 0);
  const attKeyType = u16le(dv, 2);
  const teeType = u32le(dv, 4);
  if (version !== DCAP.VERSION_V4) throw new RangeError(`parseDcapQuote: unsupported quote version ${version} (expected ${DCAP.VERSION_V4})`);
  if (attKeyType !== DCAP.ATT_KEY_TYPE_ECDSA_P256) throw new RangeError(`parseDcapQuote: unsupported attestation key type ${attKeyType} (expected ECDSA-P256 = ${DCAP.ATT_KEY_TYPE_ECDSA_P256})`);
  if (teeType !== DCAP.TEE_TYPE_TDX) throw new RangeError(`parseDcapQuote: unexpected TEE type 0x${teeType.toString(16)} (expected TDX = 0x${DCAP.TEE_TYPE_TDX.toString(16)})`);

  const header = quote.slice(0, DCAP.HEADER_LEN);
  const tdReportBody = quote.slice(DCAP.HEADER_LEN, DCAP.HEADER_LEN + DCAP.TD_REPORT_LEN);

  let o = DCAP.HEADER_LEN + DCAP.TD_REPORT_LEN;
  const sigDataLen = u32le(dv, o);
  o += 4;
  const sigEnd = o + sigDataLen;
  if (sigEnd > quote.length) throw new RangeError(`parseDcapQuote: signature data (${sigDataLen}) overruns the quote`);

  const need = (n: number, what: string) => {
    if (o + n > sigEnd) throw new RangeError(`parseDcapQuote: truncated reading ${what}`);
  };
  need(64, 'quote signature');
  const quoteSignature = quote.slice(o, o + 64);
  o += 64;
  need(64, 'attestation public key');
  const akPubRaw = quote.slice(o, o + 64);
  o += 64;

  // Outer cert-data wrapper = QE_REPORT_CERTIFICATION_DATA (type 6).
  need(6, 'outer cert-data header');
  const outerType = u16le(dv, o);
  const outerSize = u32le(dv, o + 2);
  o += 6;
  if (outerType !== DCAP.CERT_TYPE_QE_REPORT) throw new RangeError(`parseDcapQuote: outer cert-data type ${outerType} (expected QE-report-cert-data = ${DCAP.CERT_TYPE_QE_REPORT})`);
  const outerEnd = o + outerSize;
  if (outerEnd > sigEnd) throw new RangeError('parseDcapQuote: outer cert-data overruns signature data');

  need(DCAP.SGX_REPORT_LEN, 'QE report');
  const qeReportBody = quote.slice(o, o + DCAP.SGX_REPORT_LEN);
  o += DCAP.SGX_REPORT_LEN;
  need(64, 'QE report signature');
  const qeReportSignature = quote.slice(o, o + 64);
  o += 64;
  need(2, 'QE auth-data size');
  const authSize = u16le(dv, o);
  o += 2;
  need(authSize, 'QE auth-data');
  const qeAuthData = quote.slice(o, o + authSize);
  o += authSize;

  // Inner cert-data wrapper = PCK_CERT_CHAIN (type 5) carrying PEM.
  need(6, 'inner cert-data header');
  const innerType = u16le(dv, o);
  const innerSize = u32le(dv, o + 2);
  o += 6;
  if (innerType !== DCAP.CERT_TYPE_PCK_CHAIN) throw new RangeError(`parseDcapQuote: inner cert-data type ${innerType} (expected PCK-cert-chain = ${DCAP.CERT_TYPE_PCK_CHAIN})`);
  if (o + innerSize > outerEnd) throw new RangeError('parseDcapQuote: inner cert-data overruns outer cert-data');
  // The PEM may carry a trailing NUL; decode as latin1 and keep only up to the last END CERTIFICATE.
  const pckChainPem = new TextDecoder('latin1').decode(quote.slice(o, o + innerSize));

  return { version, attKeyType, teeType, header, tdReportBody, quoteSignature, akPubRaw, qeReportBody, qeReportSignature, qeAuthData, pckChainPem };
}

// ── minimal DER walker (for the Intel SGX extension) ───────────────────────────────────────────────

interface DerTlv {
  tag: number;
  start: number; // first content byte
  end: number; //   one past the last content byte
}

/** Read one DER TLV at `off`. Returns null on any malformed/overrunning length. */
function readDerTlv(buf: Uint8Array, off: number): DerTlv | null {
  if (off + 2 > buf.length) return null;
  const tag = buf[off]!;
  let len = buf[off + 1]!;
  let p = off + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || p + n > buf.length) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | buf[p++]!;
  }
  const end = p + len;
  if (end > buf.length) return null;
  return { tag, start: p, end };
}

/** Index of the first occurrence of `needle` in `hay` at or after `from`, else -1. */
function indexOfBytes(hay: Uint8Array, needle: Uint8Array, from = 0): number {
  outer: for (let i = Math.max(0, from); i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

// DER-encoded OIDs under the Intel SGX extension (1.2.840.113741.1.13.1):
//   .4 = FMSPC, .2 = TCB (a SEQUENCE of {OID, value} components: 16 SGX SVNs .1-.16, PCESVN .17, CPUSVN .18)
const OID_SGX_FMSPC = Uint8Array.from([0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x04]);
const OID_SGX_TCB = Uint8Array.from([0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02]);

/** The PCK leaf's platform identity + the TCB it was ISSUED at (from the Intel SGX extension). */
export interface IntelPckTcb {
  /** Platform family (6-byte FMSPC). */
  fmspc: Uint8Array;
  /** The 16 SGX TCB component SVNs (OID .2.1 … .2.16). */
  sgxTcbComponents: Uint8Array;
  /** PCE security version (OID .2.17). */
  pcesvn: number;
  /** The platform CPUSVN (OID .2.18), when present. */
  cpusvn: Uint8Array;
}

/**
 * Extract the FMSPC + the PCK leaf's issued TCB from a PCK certificate's DER, reading the Intel SGX
 * extension (OID 1.2.840.113741.1.13.1). Everything returned is under the issuer signature verified by
 * {@link verifyIntelPckChainX509}. Throws on a missing/malformed extension (fail closed).
 */
export function extractPckFmspcAndTcb(leafDer: Uint8Array): IntelPckTcb {
  const fi = indexOfBytes(leafDer, OID_SGX_FMSPC);
  if (fi < 0) throw new RangeError('extractPckFmspcAndTcb: FMSPC OID not found in certificate');
  const fv = readDerTlv(leafDer, fi + OID_SGX_FMSPC.length);
  if (!fv || fv.tag !== 0x04 || fv.end - fv.start !== 6) throw new RangeError('extractPckFmspcAndTcb: malformed FMSPC OCTET STRING');
  const fmspc = leafDer.slice(fv.start, fv.end);

  const ti = indexOfBytes(leafDer, OID_SGX_TCB);
  if (ti < 0) throw new RangeError('extractPckFmspcAndTcb: TCB OID not found in certificate');
  const seq = readDerTlv(leafDer, ti + OID_SGX_TCB.length);
  if (!seq || seq.tag !== 0x30) throw new RangeError('extractPckFmspcAndTcb: malformed TCB SEQUENCE');

  const sgxTcbComponents = new Uint8Array(16);
  let pcesvn = -1;
  let cpusvn = new Uint8Array(0);
  let p = seq.start;
  let idx = 0;
  while (p < seq.end) {
    const pair = readDerTlv(leafDer, p);
    if (!pair || pair.tag !== 0x30) throw new RangeError('extractPckFmspcAndTcb: malformed TCB component');
    const oid = readDerTlv(leafDer, pair.start);
    if (!oid || oid.tag !== 0x06) throw new RangeError('extractPckFmspcAndTcb: TCB component missing OID');
    const val = readDerTlv(leafDer, oid.end);
    if (!val) throw new RangeError('extractPckFmspcAndTcb: TCB component missing value');
    const last = leafDer[oid.end - 1]!; // final OID arc (.1 … .18)
    if (val.tag === 0x02) {
      // INTEGER (big-endian, unsigned): SGX SVN component (.1-.16, 1 byte) or PCESVN (.17, 1-2 bytes)
      let n = 0;
      for (let b = val.start; b < val.end; b++) n = (n << 8) | leafDer[b]!;
      if (last >= 1 && last <= 16) sgxTcbComponents[last - 1] = n & 0xff;
      else if (last === 17) pcesvn = n & 0xffff;
    } else if (val.tag === 0x04 && last === 18) {
      cpusvn = leafDer.slice(val.start, val.end); // CPUSVN OCTET STRING
    }
    p = pair.end;
    idx++;
    if (idx > 64) break; // defensive bound
  }
  if (pcesvn < 0) throw new RangeError('extractPckFmspcAndTcb: PCESVN not found in TCB extension');
  return { fmspc, sgxTcbComponents, pcesvn, cpusvn };
}

/** The PCK leaf's P-256 point from the certificate key's JWK export (no byte scanning); throws on anything unexpected. */
function p256KeyFromCertKey(key: import('node:crypto').KeyObject): EcdsaP256PublicKey {
  return ecdsaP256PublicKey(ecPointFromKey(key, 'P-256')); // exact curve + full-width coordinates, then on-curve check
}

/** Result of X.509-verifying the Intel PCK chain to the pinned Intel SGX Root CA. */
export interface IntelPckChainX509Result {
  ok: boolean;
  reason?: string;
  /** The PCK leaf's EC-P256 public key (present iff the chain verified) — it signs the QE report. */
  leafKey?: EcdsaP256PublicKey;
  /** The PCK leaf certificate's DER bytes (for {@link extractPckFmspcAndTcb}). */
  leafDer?: Uint8Array;
  /** Chain length (leaf … self-signed root), for audit. */
  depth?: number;
  /** Machine-readable failure class (set for validity failures so callers can map the reason). */
  failure?: 'validity';
}

/**
 * X.509-verify a genuine Intel PCK certificate chain (PEM) to the PINNED Intel SGX Root CA, using node's
 * OpenSSL-backed `X509Certificate`:
 *   • orders the certs leaf → … → self-signed root by issuer/subject linkage;
 *   • each cert's issuer DN equals the next cert's subject DN AND verifies under the next cert's key;
 *   • the final cert is self-signed, and its SPKI SHA-256 byte-equals the pinned anchor
 *     (`trustAnchorRootCaSpkiSha256`, default {@link INTEL_SGX_ROOT_CA_SPKI_SHA256}) — the root is NEVER
 *     taken from the supplied chain.
 *   • EVERY certificate must be inside its validity period at `nowMs` (default `Date.now()`);
 *   • every issuer must be a CA (BasicConstraints CA:TRUE, keyCertSign if keyUsage present, pathLen respected) and
 *     the leaf must NOT be a CA ({@link checkChainRoles}).
 * Fails CLOSED with a reason on any broken link. Does NOT check CRLs or PCS collateral (see the section
 * header's honest-scope note).
 */
export async function verifyIntelPckChainX509(opts: {
  pckChainPem: string;
  trustAnchorRootCaSpkiSha256?: string;
  /**
   * Evaluation time (ms since epoch) for the MANDATORY validity check of every certificate in the chain. If absent,
   * `Date.now()` (the host wall clock) is used.
   */
  nowMs?: number;
}): Promise<IntelPckChainX509Result> {
  try {
    const { X509Certificate, createHash } = await nodeCrypto();
    const blocks = typeof opts.pckChainPem === 'string' ? opts.pckChainPem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) : null;
    if (!blocks || blocks.length === 0) return { ok: false, reason: 'no PEM certificates in the PCK chain' };
    const certs = blocks.map((b) => new X509Certificate(b));

    // Order leaf → … → root: the leaf's subject is never another cert's issuer.
    const issuers = new Set(certs.map((c) => c.issuer));
    const bySubject = new Map(certs.map((c) => [c.subject, c] as const));
    const leaf = certs.find((c) => !issuers.has(c.subject)) ?? certs[0]!;
    const ordered: InstanceType<NodeCrypto['X509Certificate']>[] = [];
    const seen = new Set<string>();
    let cur: InstanceType<NodeCrypto['X509Certificate']> | undefined = leaf;
    while (cur && !seen.has(cur.subject)) {
      ordered.push(cur);
      seen.add(cur.subject);
      if (cur.subject === cur.issuer) break;
      cur = bySubject.get(cur.issuer);
    }
    const root = ordered[ordered.length - 1]!;
    if (root.subject !== root.issuer) return { ok: false, reason: 'PCK chain does not terminate in a self-signed root' };
    if (ordered.length !== certs.length) return { ok: false, reason: 'PCK chain is not a single connected path (orphan/duplicate certificates)' };

    // Validity of EVERY certificate at the evaluation time.
    const now = opts.nowMs ?? Date.now();
    if (!Number.isFinite(now)) return { ok: false, reason: 'nowMs is not a finite number' };
    for (const c of ordered) {
      if (!(now >= Date.parse(c.validFrom) && now <= Date.parse(c.validTo))) return { ok: false, reason: 'PCK chain certificate outside its validity period', failure: 'validity' };
    }

    // Each cert signed by the next; issuer/subject DN linkage.
    for (let i = 0; i < ordered.length - 1; i++) {
      const child = ordered[i]!;
      const parent = ordered[i + 1]!;
      if (child.issuer !== parent.subject) return { ok: false, reason: `certificate at depth ${i} issuer does not match its parent subject` };
      if (!child.verify(parent.publicKey)) return { ok: false, reason: `certificate at depth ${i} is not signed by its issuer` };
    }
    // Root self-signed AND pinned.
    if (!root.verify(root.publicKey)) return { ok: false, reason: 'root certificate is not self-signed' };
    const pin = (opts.trustAnchorRootCaSpkiSha256 ?? INTEL_SGX_ROOT_CA_SPKI_SHA256).toLowerCase();
    const rootSpki = new Uint8Array(root.publicKey.export({ type: 'spki', format: 'der' }));
    const rootFp = createHash('sha256').update(Buffer.from(rootSpki)).digest('hex');
    if (rootFp !== pin) return { ok: false, reason: 'Intel SGX Root CA does not match the pinned trust anchor' };

    // CA roles: issuers are CAs, the leaf is not.
    const roleFail = checkChainRoles(ordered.map((c) => new Uint8Array(c.raw)));
    if (roleFail) return { ok: false, reason: roleFail };

    const leafPk = leaf.publicKey;
    if (leafPk.asymmetricKeyType !== 'ec') return { ok: false, reason: `PCK leaf key is not EC (got ${leafPk.asymmetricKeyType ?? 'unknown'})` };
    const leafKey = p256KeyFromCertKey(leafPk);
    return { ok: true, leafKey, leafDer: new Uint8Array(leaf.raw), depth: ordered.length };
  } catch (e) {
    return { ok: false, reason: `PCK chain X.509 verification error (fail closed): ${e instanceof Error ? e.message : 'unknown'}` };
  }
}

/** Acceptance policy for the genuine DCAP path (all gates optional; lowercase-hex compares). */
export interface GenuineTdxPolicy {
  /** Allowed MRTD values (lowercase hex of the 48-byte TD measurement). Omitted => not gated. */
  mrtds?: string[];
  /** Allowed FMSPC platform ids (lowercase hex of the 6-byte FMSPC). Omitted => not gated. */
  fmspcs?: string[];
  /** Allowed RTMR0 values (lowercase hex). Omitted => not gated. */
  rtmrs?: string[];
  /** Allowed MRSEAM values (lowercase hex of the 48-byte TDX-module measurement). Omitted => not gated; an EMPTY list rejects everything (fail closed). */
  mrSeams?: string[];
  /** Allowed MRSIGNERSEAM values (lowercase hex of the 48 bytes; all-zero is Intel's value for the production module). Omitted => not gated; an EMPTY list rejects everything (fail closed). */
  mrSignerSeams?: string[];
  /** INSECURE opt-in: accept a TD whose TD_ATTRIBUTES.DEBUG bit (bit 0) is set (host can read TD memory). Default false. */
  allowDebug?: boolean;
}

/** The outcome of verifying a genuine Intel DCAP TDX quote end-to-end. */
export interface GenuineTdxResult {
  ok: boolean;
  reason?: string;
  /** The parsed TD report (present iff ok). */
  report?: DcapTdReport;
  /** The platform FMSPC (lowercase hex). */
  fmspc?: string;
  /** The PCK leaf's issued TCB (raw — evaluate vs Intel PCS TCB info online). */
  pckTcb?: IntelPckTcb;
  /** The attestation key the quote was signed under (validated on-curve). */
  akPub?: EcdsaP256PublicKey;
  /** The chain depth that verified (leaf … root). */
  chainDepth?: number;
  /** The hardware-measured identity (runtime_measurement = hex(MRTD)). */
  measured?: MeasuredIdentity;
}

/**
 * Verify a GENUINE Intel DCAP v4 / ECDSA-P256 / TDX quote END-TO-END, OFFLINE (no PCS collateral):
 *   1. parse the quote (fail-closed on any structural violation);
 *   2. X.509-verify the embedded PCK chain to the PINNED Intel SGX Root CA ({@link verifyIntelPckChainX509});
 *   3. extract FMSPC + the PCK leaf's issued TCB from the Intel SGX extension;
 *   4. verify the QE report's ECDSA-P256 signature under the PCK leaf;
 *   5. verify the QE report binds the attestation key (report_data[0:32] == SHA-256(AK ‖ QE_AUTH), [32:64]==0);
 *   6. verify the TD quote's ECDSA-P256 signature over SHA-256(header ‖ TD-report) under the AK;
 *   7. OPTIONALLY (`expected`) bind report_data to the PCA nonce — NOT used for Azure FDE captures, whose
 *      report_data carries SHA-256(vTPM-AK), not a PCA binding (see the section header);
 *   8. OPTIONALLY apply the MRTD / FMSPC / RTMR0 acceptance `policy`.
 * Returns the parsed report + FMSPC + PCK TCB + measured identity on success; fails CLOSED with a reason.
 * TCB STATUS and QE IDENTITY vs Intel PCS collateral are the remaining ONLINE steps — see the header.
 */
export async function verifyGenuineTdxQuote(opts: {
  quote: Uint8Array;
  trustAnchorRootCaSpkiSha256?: string;
  expected?: ExpectedAttestationBinding;
  policy?: GenuineTdxPolicy;
  /** Evaluation time (ms since epoch) for the PCK chain validity check. If absent, `Date.now()` (host wall clock). */
  nowMs?: number;
}): Promise<GenuineTdxResult> {
  try {
    let q: ParsedDcapQuote;
    try {
      q = parseDcapQuote(opts.quote);
    } catch (e) {
      return { ok: false, reason: `quote parse failed: ${e instanceof Error ? e.message : 'unknown'}` };
    }

    let report: DcapTdReport;
    try {
      report = parseDcapTdReport(q.tdReportBody);
    } catch (e) {
      return { ok: false, reason: `TD report parse failed: ${e instanceof Error ? e.message : 'unknown'}` };
    }

    // (2) PCK chain → pinned Intel SGX Root CA
    const chain = await verifyIntelPckChainX509({ pckChainPem: q.pckChainPem, trustAnchorRootCaSpkiSha256: opts.trustAnchorRootCaSpkiSha256, ...(opts.nowMs !== undefined ? { nowMs: opts.nowMs } : {}) });
    if (!chain.ok || !chain.leafKey || !chain.leafDer) return { ok: false, reason: `PCK chain invalid: ${chain.reason ?? 'unknown'}` };

    // (3) FMSPC + PCK TCB
    let pckTcb: IntelPckTcb;
    try {
      pckTcb = extractPckFmspcAndTcb(chain.leafDer);
    } catch (e) {
      return { ok: false, reason: `PCK FMSPC/TCB extraction failed: ${e instanceof Error ? e.message : 'unknown'}` };
    }

    // (4) QE report signed by the PCK leaf
    if (!verifyP256(q.qeReportBody, q.qeReportSignature, chain.leafKey)) return { ok: false, reason: 'QE report signature does not verify under the PCK leaf' };

    // (4b) the QE must not be a DEBUG enclave (SGX REPORT.ATTRIBUTES.FLAGS bit 1) — a debug QE can forge endorsements
    if ((q.qeReportBody[DCAP.QE_ATTRIBUTES_OFF]! & 0x02) !== 0) return { ok: false, reason: 'QE report ATTRIBUTES.DEBUG is set (debug quoting enclave)' };

    // (5) QE report binds the attestation key
    const qeReportData = q.qeReportBody.slice(DCAP.QE_REPORT_DATA_OFF, DCAP.QE_REPORT_DATA_OFF + 64);
    const akBinding = sha256(concat(q.akPubRaw, q.qeAuthData));
    if (!timingSafeEq(qeReportData.slice(0, 32), akBinding) || !isAllZero(qeReportData.slice(32, 64))) {
      return { ok: false, reason: 'QE report_data does not bind the attestation key (AK not endorsed by this QE)' };
    }

    // (6) TD quote signed by the AK
    let akPub: EcdsaP256PublicKey;
    try {
      akPub = ecdsaP256PublicKey(concat(Uint8Array.of(0x04), q.akPubRaw));
    } catch {
      return { ok: false, reason: 'attestation public key is not a valid P-256 point' };
    }
    if (!verifyP256(concat(q.header, q.tdReportBody), q.quoteSignature, akPub)) return { ok: false, reason: 'TD quote signature does not verify under the attestation key' };

    // (7) optional PCA nonce binding
    if (opts.expected) {
      let expectedData: Uint8Array;
      try {
        expectedData = attestationBinding(opts.expected);
      } catch (e) {
        return { ok: false, reason: `binding not constructible: ${e instanceof Error ? e.message : 'invalid'}` };
      }
      if (!timingSafeEq(expectedData, report.reportData)) return { ok: false, reason: 'report_data does not bind holder/grant/epoch/nonce' };
    }

    // (7b) a DEBUG TD offers no confidentiality (Intel TDX module spec: TD_ATTRIBUTES bit 0)
    if (opts.policy?.allowDebug !== true && (report.tdAttributes[0]! & 1) !== 0) {
      return { ok: false, reason: 'TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)' };
    }

    // (8) optional policy
    const fmspcHex = toHex(pckTcb.fmspc);
    if (opts.policy) {
      const pol = opts.policy;
      if (Array.isArray(pol.mrtds) && pol.mrtds.length > 0 && !pol.mrtds.map((x) => x.toLowerCase()).includes(toHex(report.mrTd))) {
        return { ok: false, reason: 'MRTD not in policy allowlist' };
      }
      if (Array.isArray(pol.fmspcs) && pol.fmspcs.length > 0 && !pol.fmspcs.map((x) => x.toLowerCase()).includes(fmspcHex)) {
        return { ok: false, reason: 'FMSPC not in policy allowlist' };
      }
      if (Array.isArray(pol.mrSeams) && !pol.mrSeams.map((x) => x.toLowerCase()).includes(toHex(report.mrSeam))) {
        return { ok: false, reason: 'MRSEAM not in policy allowlist' };
      }
      if (Array.isArray(pol.mrSignerSeams) && !pol.mrSignerSeams.map((x) => x.toLowerCase()).includes(toHex(report.mrSignerSeam))) {
        return { ok: false, reason: 'MRSIGNERSEAM not in policy allowlist' };
      }
      if (Array.isArray(pol.rtmrs) && pol.rtmrs.length > 0 && !pol.rtmrs.map((x) => x.toLowerCase()).includes(toHex(report.rtmr0))) {
        return { ok: false, reason: 'RTMR0 not in policy allowlist' };
      }
    }

    const measured: MeasuredIdentity = { model_id: '', weights_digest: '', weights_measured: false, runtime_measurement: toHex(report.mrTd), operator: '' };
    return { ok: true, report, fmspc: fmspcHex, pckTcb, akPub, chainDepth: chain.depth, measured };
  } catch (e) {
    return { ok: false, reason: `genuine TDX verification error (fail closed): ${e instanceof Error ? e.message : 'unknown'}` };
  }
}
