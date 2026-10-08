/**
 * L0 HARDWARE backend — Intel TDX (with SGX/DCAP roots) attestation VERIFIER.
 *
 * A second, INDEPENDENT CPU-TEE attestation root for the multi-root N-of-M policy in `attestation.ts`,
 * built to the SAME `HardwareAttestationVerifier` seam as the AMD SEV-SNP backend (`hardware-sevsnp.ts`)
 * and modelled on its structure. Where SEV-SNP roots the identity in AMD's VCEK→ASK→ARK chain, this
 * roots it in Intel's DCAP quote-signing chain: a TD quote whose body carries the TD measurement (MRTD),
 * a runtime measurement register (RTMR) and the guest-supplied report_data is signed by an ECDSA-P256
 * Attestation Key (AK); the AK is vouched for by a Quoting-Enclave (QE) report; and the QE report is
 * signed by the platform's PCK leaf, whose certificate chains to the Intel SGX Root CA.
 *
 * ── HONEST SCOPE — PQ STATUS: CLASSICAL. ────────────────────────────────────────────────────────────
 * Intel's DCAP root of trust is an ECDSA over NIST P-256 (secp256r1) chain today. This root is therefore
 * CLASSICAL: a quantum adversary able to forge ECDSA-P256 can forge this attestation. It is NOT
 * post-quantum and nothing in this file claims otherwise. Its value in the multi-root policy is
 * INDEPENDENCE: pairing it with AMD SEV-SNP means a break (quantum or cryptanalytic) of ONE vendor's
 * classical root no longer silently forges the whole attestation, because the other required roots must
 * still corroborate. The genuinely post-quantum root is `attest-pq-software.ts`; see also the honest-scope
 * notes in `attestation.ts` and `hardware-sevsnp.ts`. The suite seam ({@link INTEL_TDX_SUITE}) is
 * alg-agile so a future Intel PQ DCAP suite maps in without reworking the dispatch.
 *
 * ── WHAT IS CRYPTOGRAPHICALLY VERIFIED (real @noble/curves P-256, exercised end-to-end by the tests). ─
 *   1. The PCK certificate chain to the configured Intel SGX Root CA anchor: each link's TBS embeds its
 *      own subject key (so a genuine issuer-signed TBS cannot be paired with an attacker's key — the same
 *      forged-pairing defence SEV-SNP's `verifyVcekChain` uses) and is ECDSA-P256-signed by its issuer;
 *      the root public key must byte-equal the configured anchor (never taken from the chain).
 *   2. FMSPC + TCB binding: the PCK leaf's signed TBS carries the platform FMSPC and the TCB SVN the PCK
 *      was ISSUED at. The verifier requires the TD report's TEE_TCB_SVN be <= the PCK's TCB SVN, so an OLD
 *      PCK (lower TCB) cannot vouch for a report claiming a NEWER TCB, and gates the FMSPC via policy.
 *   3. The QE report signature under the PCK leaf, and that the QE report's report_data binds the AK
 *      public key (`report_data[0:32] == SHA-256(AK_pub ‖ QE_AUTH)`, `[32:64] == 0`, exactly as DCAP does),
 *      so only an AK a PCK-endorsed QE vouched for is trusted.
 *   4. The TD quote signature: ECDSA-P256 over SHA-256(header ‖ TD-report-body) under that AK.
 *   5. report_data === attestationBinding({holderPub, grantRef, epoch, nonce}) (see `attestation.ts`).
 *   6. Policy gates: a NON-EMPTY MRTD allowlist (enforced at construction — no accept-all), optional FMSPC
 *      / RTMR / measured-weights allowlists and a TCB-SVN floor.
 *
 * ── HONESTY: SYNTHETIC CHAIN (same convention as SEV-SNP's mock path). ─────────────────────────────
 * There is no Intel TDX machine in CI to emit a genuine quote or genuine PCK certificates. The tests
 * build a SYNTHETIC-but-cryptographically-real P-256 trust chain (fresh Root CA → PCK leaf keypairs, real
 * ECDSA-P256 signatures, a TD report crafted with a known MRTD + report_data and signed by a test AK). The
 * certificate TBS uses a compact, self-describing tagged-record encoding ({@link encodeTdxTbs}) rather than
 * full X.509 DER — enough to bind the subject key + FMSPC + TCB tamper-evidently under the issuer
 * signature. A production deployment replaces the evidence seam with a real DCAP quote + X.509-decoded
 * Intel PCK/Processor-CA/Root-CA certificates (and the Intel PCS/PCCS collateral); the cryptographic
 * machinery proven here — parse → P-256 chain → QE/AK binding → report-signature → nonce bind → policy →
 * measured identity — is unchanged.
 *
 * References: Intel TDX DCAP Quote Generation Library; Intel SGX ECDSA Quote (DCAP) format; Intel SGX
 * PCK Certificate and CRL Specification (FMSPC / TCB SVN extensions).
 */
import { p256 } from '@noble/curves/p256';
import { sha256 } from './hash';
import { attestationBinding } from './attestation';
import type {
  AttestationDocument,
  ExpectedAttestationBinding,
  HardwareAttestationResult,
  HardwareAttestationVerifier,
  MeasuredIdentity,
} from './attestation';
import type { VerifyContext } from './pcactn';

/** The signature suite Intel DCAP produces today — classical ECDSA over NIST P-256 with SHA-256. */
export const INTEL_TDX_SUITE = 'ecdsa-p256-sha256' as const;

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

// ── compact tagged-record TBS codec (NOT X.509 — the documented synthetic cert body) ──────────────
//
// A certificate's TBS is a concatenation of records `tag(1) ‖ len(u32be) ‖ value`. The issuer signs
// SHA-256(tbs), so every embedded field (subject key + FMSPC + TCB SVN) is tamper-evident. Production
// swaps this for an X.509 decode of the genuine Intel PCK certificate; the binding semantics are the same.

const TAG_SUBJECT = 0x01;
const TAG_FMSPC = 0x02;
const TAG_TCB_SVN = 0x03;

/** Build a tagged-record TBS. Records are emitted in the given order; each tag MUST be unique. */
export function encodeTdxTbs(records: ReadonlyArray<{ tag: number; value: Uint8Array }>): Uint8Array {
  const parts: Uint8Array[] = [];
  const seen = new Set<number>();
  for (const r of records) {
    if (seen.has(r.tag)) throw new RangeError(`encodeTdxTbs: duplicate tag ${r.tag}`);
    seen.add(r.tag);
    const head = new Uint8Array(5);
    head[0] = r.tag & 0xff;
    new DataView(head.buffer).setUint32(1, r.value.length, false);
    parts.push(head, r.value);
  }
  return concat(...parts);
}

/** Parse a tagged-record TBS into a tag→value map. Returns null on any malformed/duplicate record. */
function decodeTdxTbs(tbs: Uint8Array): Map<number, Uint8Array> | null {
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

// ── TD report body layout (synthetic PCA profile — documented, fixed offsets) ──────────────────────

const TD = {
  REPORT_DATA: 0x000, //         64 B  guest-supplied data — the PCA challenge binding lives here
  MRTD: 0x040, //                48 B  TD measurement (hardware-authoritative launch measurement)
  MRCONFIGID: 0x070, //          48 B  TD config id
  RTMR0: 0x0a0, //               48 B  runtime measurement register 0
  // PCA CONVENTION (NOT a standard TDX field): the model runtime's MEASURED loaded-weights digest, inside
  // the signed region so the AK signature covers it (hardware-rooted). All-zero => no weights measured.
  WEIGHTS_MEASUREMENT: 0x0d0, // 48 B
  TEE_TCB_SVN: 0x100, //         u16   the TD's TEE TCB security version
  SIGNED_END: 0x102, //          TD report body is [0x000, 0x102)
} as const;

/** The TD report-body length (bytes) covered by the AK signature. */
export const TDX_REPORT_BODY_LEN = TD.SIGNED_END;

/** A parsed TD report body. Byte-array fields are fresh copies. */
export interface ParsedTdReport {
  report_data: Uint8Array; // 64
  mrtd: Uint8Array; // 48
  mrconfigid: Uint8Array; // 48
  rtmr0: Uint8Array; // 48
  /** PCA convention: measured loaded-weights digest (48 B). All-zero => ABSENT (no weights measured). */
  weights_measurement: Uint8Array; // 48
  tee_tcb_svn: number;
  raw: Uint8Array;
}

/** Parse a TD report body. Throws if too short to contain the documented layout. */
export function parseTdReport(bytes: Uint8Array): ParsedTdReport {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('parseTdReport: expected Uint8Array');
  if (bytes.length < TD.SIGNED_END) throw new RangeError(`parseTdReport: body too short (${bytes.length} < ${TD.SIGNED_END})`);
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    report_data: bytes.slice(TD.REPORT_DATA, TD.REPORT_DATA + 64),
    mrtd: bytes.slice(TD.MRTD, TD.MRTD + 48),
    mrconfigid: bytes.slice(TD.MRCONFIGID, TD.MRCONFIGID + 48),
    rtmr0: bytes.slice(TD.RTMR0, TD.RTMR0 + 48),
    weights_measurement: bytes.slice(TD.WEIGHTS_MEASUREMENT, TD.WEIGHTS_MEASUREMENT + 48),
    tee_tcb_svn: dv.getUint16(TD.TEE_TCB_SVN, true),
    raw: bytes.slice(),
  };
}

/** Serialize a TD report body (TOOLING / TEST utility — the inverse of {@link parseTdReport}). */
export function serializeTdReport(
  fields: Partial<{
    report_data: Uint8Array;
    mrtd: Uint8Array;
    mrconfigid: Uint8Array;
    rtmr0: Uint8Array;
    weights_measurement: Uint8Array;
    tee_tcb_svn: number;
  }>,
): Uint8Array {
  const out = new Uint8Array(TD.SIGNED_END);
  const dv = new DataView(out.buffer);
  const put = (off: number, len: number, src?: Uint8Array) => {
    if (src) out.set(src.subarray(0, len), off);
  };
  put(TD.REPORT_DATA, 64, fields.report_data);
  put(TD.MRTD, 48, fields.mrtd);
  put(TD.MRCONFIGID, 48, fields.mrconfigid);
  put(TD.RTMR0, 48, fields.rtmr0);
  put(TD.WEIGHTS_MEASUREMENT, 48, fields.weights_measurement);
  dv.setUint16(TD.TEE_TCB_SVN, fields.tee_tcb_svn ?? 0, true);
  return out;
}

/** Offset of the 64-byte report_data slot in the QE (Quoting Enclave) SGX report. */
const QE_REPORT_DATA_OFF = 0x140; // 320, the SGX report report_data offset
const QE_REPORT_MIN_LEN = QE_REPORT_DATA_OFF + 64;

// ── evidence + certificate-chain types ─────────────────────────────────────────────────────────────

/** One PCK-chain certificate: a subject key, its tagged TBS, and the issuer's ECDSA-P256 signature. */
export interface IntelPckCert {
  /** The subject public key this certificate endorses. */
  subject: EcdsaP256PublicKey;
  /** The tagged-record TBS (embeds the subject key, and for the leaf the FMSPC + TCB SVN). */
  tbs: Uint8Array;
  /** The issuer's ECDSA-P256 signature (compact r‖s) over SHA-256(tbs). */
  sig: Uint8Array;
}

/** The Intel PCK certificate chain: PCK leaf → (Processor/Platform CA) → Intel SGX Root CA. */
export interface IntelPckChain {
  /** Intel SGX Root CA public key — compared for equality against the configured anchor (never trusted from the chain). */
  rootCa: EcdsaP256PublicKey;
  /** Intermediate certs (Processor/Platform CA), outermost first; each signed by the previous issuer (root signs the first). May be empty. */
  intermediates: IntelPckCert[];
  /** The PCK leaf certificate (signs the QE report); its TBS carries FMSPC + TCB SVN. */
  leaf: IntelPckCert;
}

/** All the evidence to verify one action's Intel TDX attestation. */
export interface IntelTdxQuote {
  /** The DCAP quote header bytes (version / attestation-key type / QE vendor id ...). */
  header: Uint8Array;
  /** The raw TD report body (parsed by {@link parseTdReport}); the AK signs SHA-256(header ‖ reportBody). */
  reportBody: Uint8Array;
  /** The TD quote signature: ECDSA-P256 (compact r‖s) over SHA-256(header ‖ reportBody) under `akPub`. */
  quoteSignature: Uint8Array;
  /** The Attestation Key that signed the quote (vouched for by the QE report). */
  akPub: EcdsaP256PublicKey;
  /** QE authentication data bound into the QE report's report_data. */
  qeAuthData: Uint8Array;
  /** The Quoting Enclave's SGX report body; its report_data binds `akPub` ‖ `qeAuthData`. */
  qeReportBody: Uint8Array;
  /** The QE report signature: ECDSA-P256 (compact r‖s) over SHA-256(qeReportBody) under the PCK leaf. */
  qeReportSignature: Uint8Array;
  /** The PCK certificate chain. */
  pckChain: IntelPckChain;
}

/**
 * Acceptance policy for a verified TD quote. `mrtds` is REQUIRED and NON-EMPTY (no accept-all); every
 * other gate is optional. All hex comparisons are lowercase.
 */
export interface IntelTdxPolicy {
  /** Allowed MRTD values (lowercase hex of the 48-byte TD measurement). REQUIRED and NON-EMPTY. */
  mrtds: string[];
  /** Allowed FMSPC platform ids (lowercase hex of the 6-byte FMSPC). Omitted => not gated. */
  fmspcs?: string[];
  /** Allowed RTMR0 values (lowercase hex). Omitted => not gated. */
  rtmrs?: string[];
  /** Allowed MEASURED-weights digests (lowercase hex of the 48-byte slot). Omitted/empty => not gated here. */
  weightsMeasurements?: string[];
  /** Minimum acceptable TD TEE_TCB_SVN. */
  minTeeTcbSvn?: number;
  /** Map a verified report into the `MeasuredIdentity` agent_binding is checked against (override to customise). */
  deriveIdentity?: (report: ParsedTdReport, fmspc: Uint8Array) => MeasuredIdentity;
}

export interface IntelTdxVerifierOptions {
  /** The configured Intel SGX Root CA trust anchor. The chain's root must byte-equal this. */
  trustAnchorRootCa: EcdsaP256PublicKey;
  /** Acceptance policy (MRTD allowlist required). */
  policy: IntelTdxPolicy;
  /**
   * EVIDENCE SEAM: produce the quote + chain for an action. Production reads the DCAP quote + X.509 PCK
   * chain carried with the attestation document. If omitted, the verifier fails closed (no evidence).
   */
  resolveEvidence?: (
    document: AttestationDocument,
    ctx: VerifyContext,
  ) => IntelTdxQuote | undefined | Promise<IntelTdxQuote | undefined>;
}

/** True iff the TBS embeds `key`'s uncompressed point as its SUBJECT record exactly. */
function tbsBindsSubject(records: Map<number, Uint8Array>, key: EcdsaP256PublicKey): boolean {
  const s = records.get(TAG_SUBJECT);
  return s !== undefined && timingSafeEq(s, key.point);
}

/** Verify the PCK chain to the Root CA anchor. Returns the leaf's parsed records on success. */
function verifyPckChain(chain: IntelPckChain, anchor: EcdsaP256PublicKey): { ok: true; leaf: Map<number, Uint8Array> } | { ok: false; reason: string } {
  if (!timingSafeEq(chain.rootCa.point, anchor.point)) return { ok: false, reason: 'Intel SGX Root CA does not match the configured trust anchor' };
  let issuer = chain.rootCa;
  const links: IntelPckCert[] = [...(Array.isArray(chain.intermediates) ? chain.intermediates : []), chain.leaf];
  let leafRecords: Map<number, Uint8Array> | null = null;
  for (let i = 0; i < links.length; i++) {
    const cert = links[i]!;
    const records = decodeTdxTbs(cert.tbs);
    if (!records) return { ok: false, reason: `malformed certificate TBS at chain index ${i}` };
    if (!tbsBindsSubject(records, cert.subject)) return { ok: false, reason: `certificate subject key is not bound in its TBS at chain index ${i}` };
    if (!verifyP256(cert.tbs, cert.sig, issuer)) return { ok: false, reason: `certificate at chain index ${i} is not signed by its issuer` };
    issuer = cert.subject;
    if (i === links.length - 1) leafRecords = records;
  }
  if (!leafRecords) return { ok: false, reason: 'empty PCK chain (no leaf)' };
  return { ok: true, leaf: leafRecords };
}

/**
 * Build a `HardwareAttestationVerifier` backed by Intel TDX/DCAP. Given an attestation document + context
 * it resolves the quote + PCK chain (the evidence seam), then:
 *   1. parses the TD report body;
 *   2. verifies the PCK chain to the configured Intel SGX Root CA anchor;
 *   3. binds FMSPC + TCB: the report's TEE_TCB_SVN must be <= the PCK leaf's issued TCB SVN (no downgrade),
 *      and the FMSPC is gated by policy;
 *   4. verifies the QE report signature under the PCK leaf and that the QE report binds the AK public key;
 *   5. verifies the TD quote signature under that AK;
 *   6. confirms report_data === attestationBinding(expected);
 *   7. applies the acceptance policy and returns the hardware-measured identity.
 * Fails CLOSED with a specific reason on any mismatch or error. Classical ECDSA-P256 — see the honest-scope
 * note in the module header.
 */
export function createIntelTdxVerifier(opts: IntelTdxVerifierOptions): HardwareAttestationVerifier {
  if (!opts?.policy || !Array.isArray(opts.policy.mrtds) || opts.policy.mrtds.length === 0) {
    throw new TypeError('createIntelTdxVerifier: policy.mrtds must be a NON-EMPTY allowlist (accept-all is not permitted)');
  }
  if (!opts.trustAnchorRootCa || !(opts.trustAnchorRootCa.point instanceof Uint8Array)) {
    throw new TypeError('createIntelTdxVerifier: trustAnchorRootCa is required');
  }
  const policy = opts.policy;
  const deriveIdentity = policy.deriveIdentity ?? defaultTdxIdentity;

  return {
    async verify(input): Promise<HardwareAttestationResult> {
      const fail = (reason: string): HardwareAttestationResult => ({ ok: false, reason });
      try {
        if (!opts.resolveEvidence) return fail('no Intel TDX evidence resolver configured (fail closed)');
        const q = await opts.resolveEvidence(input.document, input.ctx);
        if (!q || !(q.reportBody instanceof Uint8Array) || !q.pckChain) return fail('no Intel TDX evidence for this action');

        // (1) parse
        let report: ParsedTdReport;
        try {
          report = parseTdReport(q.reportBody);
        } catch (e) {
          return fail(`TD report parse failed: ${e instanceof Error ? e.message : 'unknown'}`);
        }

        // (2) PCK chain to the Root CA anchor
        const chain = verifyPckChain(q.pckChain, opts.trustAnchorRootCa);
        if (!chain.ok) return fail(`PCK chain invalid: ${chain.reason}`);

        // (3) FMSPC + TCB binding (block old-PCK-vouches-newer-TD downgrade)
        const fmspc = chain.leaf.get(TAG_FMSPC);
        const tcbBytes = chain.leaf.get(TAG_TCB_SVN);
        if (!fmspc) return fail('PCK leaf certificate carries no FMSPC');
        if (!tcbBytes || tcbBytes.length !== 2) return fail('PCK leaf certificate carries no TCB SVN');
        const pckTcbSvn = new DataView(tcbBytes.buffer, tcbBytes.byteOffset, 2).getUint16(0, false);
        if (report.tee_tcb_svn > pckTcbSvn) {
          return fail(`TD report TEE_TCB_SVN ${report.tee_tcb_svn} exceeds the PCK leaf TCB SVN ${pckTcbSvn} (old PCK cannot vouch a newer TD)`);
        }
        if (Array.isArray(policy.fmspcs) && policy.fmspcs.length > 0) {
          if (!policy.fmspcs.map((x) => x.toLowerCase()).includes(toHex(fmspc))) return fail('FMSPC not in policy allowlist');
        }

        // (4) QE report binds the AK, and the PCK leaf signed the QE report
        if (!(q.qeReportBody instanceof Uint8Array) || q.qeReportBody.length < QE_REPORT_MIN_LEN) return fail('QE report too short');
        if (!verifyP256(q.qeReportBody, q.qeReportSignature, q.pckChain.leaf.subject)) return fail('QE report signature does not verify under the PCK leaf');
        const qeReportData = q.qeReportBody.slice(QE_REPORT_DATA_OFF, QE_REPORT_DATA_OFF + 64);
        const akBinding = sha256(concat(q.akPub.point, q.qeAuthData instanceof Uint8Array ? q.qeAuthData : new Uint8Array(0)));
        if (!timingSafeEq(qeReportData.slice(0, 32), akBinding) || !isAllZero(qeReportData.slice(32, 64))) {
          return fail('QE report_data does not bind the attestation key (AK not endorsed by this QE)');
        }

        // (5) TD quote signature under the AK
        const signedData = concat(q.header instanceof Uint8Array ? q.header : new Uint8Array(0), q.reportBody);
        if (!verifyP256(signedData, q.quoteSignature, q.akPub)) return fail('TD quote signature does not verify under the attestation key');

        // (6) report_data === attestationBinding(expected)
        if (!input.expected) return fail('no expected attestation binding supplied');
        let expectedData: Uint8Array;
        try {
          expectedData = attestationBinding(input.expected);
        } catch (e) {
          return fail(`binding not constructible: ${e instanceof Error ? e.message : 'invalid'}`);
        }
        if (!timingSafeEq(expectedData, report.report_data)) return fail('report_data does not bind holder/grant/epoch/nonce (relayed or unbound quote)');

        // (7) acceptance policy
        const polErr = checkIntelTdxPolicy(report, policy);
        if (polErr) return fail(polErr);

        const measured = deriveIdentity(report, fmspc);
        return { ok: true, bound: true, measured, hostAsserted: { fmspc: toHex(fmspc) } };
      } catch (e) {
        return fail(`intel-tdx verification error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`);
      }
    },
  };
}

/** Check a parsed TD report against the acceptance policy. Returns a reason on the first failure, else null. */
export function checkIntelTdxPolicy(report: ParsedTdReport, policy: IntelTdxPolicy): string | null {
  if (typeof policy.minTeeTcbSvn === 'number' && report.tee_tcb_svn < policy.minTeeTcbSvn) {
    return `TEE_TCB_SVN ${report.tee_tcb_svn} below minimum ${policy.minTeeTcbSvn}`;
  }
  if (Array.isArray(policy.mrtds) && policy.mrtds.length > 0) {
    if (!policy.mrtds.map((x) => x.toLowerCase()).includes(toHex(report.mrtd))) return 'MRTD not in policy allowlist';
  }
  if (Array.isArray(policy.rtmrs) && policy.rtmrs.length > 0) {
    if (!policy.rtmrs.map((x) => x.toLowerCase()).includes(toHex(report.rtmr0))) return 'RTMR0 not in policy allowlist';
  }
  if (Array.isArray(policy.weightsMeasurements) && policy.weightsMeasurements.length > 0) {
    if (isAllZero(report.weights_measurement)) return 'no measured weights digest in report (weightsMeasurements required)';
    if (!policy.weightsMeasurements.map((x) => x.toLowerCase()).includes(toHex(report.weights_measurement))) return 'measured weights digest not in policy allowlist';
  }
  return null;
}

/**
 * Default identity mapping for a verified TD quote:
 *   runtime_measurement = hex(MRTD)        — hardware-authoritative TD launch measurement
 *   weights_digest      = hex(WEIGHTS_MEASUREMENT) when the signed slot is non-zero (HARDWARE-MEASURED,
 *                         weights_measured: true); else '' (false)
 *   operator / model_id = ''               — TDX carries no operator/model id; override to supply one
 * The FMSPC is surfaced as `hostAsserted.fmspc` for audit (it is the platform family, not the agent).
 */
function defaultTdxIdentity(report: ParsedTdReport, _fmspc: Uint8Array): MeasuredIdentity {
  if (!isAllZero(report.weights_measurement)) {
    return { model_id: '', weights_digest: toHex(report.weights_measurement), weights_measured: true, runtime_measurement: toHex(report.mrtd), operator: '' };
  }
  return { model_id: '', weights_digest: '', weights_measured: false, runtime_measurement: toHex(report.mrtd), operator: '' };
}
