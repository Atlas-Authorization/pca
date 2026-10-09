/**
 * TEST-ONLY forger of genuine-format Intel DCAP v4 / ECDSA-P256 TDX quotes and Intel PCS collateral.
 *
 * WHY: a captured real quote cannot be re-signed with the debug bit set, a lower TCB, a different MRTD, a revoked
 * PCK, ... because only Intel silicon holds the keys. The production verifiers (`attest-intel-tdx.ts`,
 * `attest-intel-dcap.ts`, `attest-intel-collateral.ts`) take their trust anchor as an option (SPKI SHA-256 pin), so
 * this module mints evidence in the REAL vendor wire format under a TEST root with a REAL X.509 chain (including
 * Intel's SGX extension, OID 1.2.840.113741.1.13.1) and lets the UNMODIFIED production code run end to end.
 *
 * It is NOT a trust anchor and must never be imported by production code. Everything is deterministic (seeded keys,
 * RFC 6979 signatures), so a given option set always produces the identical byte string.
 *
 * Wire layout produced (all offsets from the start of the quote), identical to a captured Azure quote:
 *   0   header(48): version u16=4, attKeyType u16=2, teeType u32=0x81, reserved u32, QE vendor id(16), user data(20)
 *   48  TD10 report body(584)
 *   632 signature-data length u32
 *   636 quote signature r‖s (64) · 700 attestation key X‖Y (64)
 *   764 outer cert-data type u16=6, size u32 · 770 QE report(384) · 1154 QE report sig(64) ·
 *   1218 QE auth size u16 · auth data · inner cert-data type u16=5, size u32 · PEM chain (leaf, CA, root) + NUL
 */
import {
  type Extension,
  type ForgeKey,
  type ForgedCert,
  bytesToHex,
  cat,
  digest,
  ecdsaSign,
  enumerated,
  extension,
  ext,
  fill,
  forgeCert,
  forgeCrl,
  forgeKey,
  hexToBytes,
  integer,
  octets,
  oid,
  seq,
  serialFor,
  boolean as derBool,
  u16,
  u32,
} from './forge-x509';
import type { TcbStatus, IntelTdxCollateral } from '../attest-intel-collateral';

export const DCAP_OFFSETS = {
  HEADER: 0,
  BODY: 48,
  SIG_DATA_LEN: 632,
  QUOTE_SIG: 636,
  AK: 700,
  OUTER_TYPE: 764,
  OUTER_SIZE: 766,
  QE_REPORT: 770,
  QE_SIG: 1154,
  QE_AUTH_SIZE: 1218,
  QE_AUTH: 1220,
} as const;

/** Offsets inside the 584-byte TD10 body (independent restatement of the Intel layout). */
export const TD10_FIELDS = {
  TEE_TCB_SVN: 0,
  MR_SEAM: 16,
  MR_SIGNER_SEAM: 64,
  SEAM_ATTRIBUTES: 112,
  TD_ATTRIBUTES: 120,
  XFAM: 128,
  MRTD: 136,
  MR_CONFIG_ID: 184,
  MR_OWNER: 232,
  MR_OWNER_CONFIG: 280,
  RTMR0: 328,
  RTMR1: 376,
  RTMR2: 424,
  RTMR3: 472,
  REPORT_DATA: 520,
} as const;

/** Offsets inside the 384-byte SGX (QE) report. */
export const SGX_REPORT_FIELDS = {
  CPU_SVN: 0,
  MISC_SELECT: 16,
  ATTRIBUTES: 48,
  MR_ENCLAVE: 64,
  MR_SIGNER: 128,
  ISV_PROD_ID: 256,
  ISV_SVN: 258,
  REPORT_DATA: 320,
} as const;

/** Intel's real QE vendor id (939a7233-f79c-4ca9-940a-0db3957f0607). */
export const INTEL_QE_VENDOR_ID = hexToBytes('939a7233f79c4ca9940a0db3957f0607');
/** TD_ATTRIBUTES bit 0 — DEBUG. */
export const TD_ATTR_DEBUG = 0x01;

type Bytes = Uint8Array | string;
const asBytes = (v: Bytes, len: number, what: string): Uint8Array => {
  const b = typeof v === 'string' ? hexToBytes(v) : v;
  if (b.length !== len) throw new RangeError(`forge-dcap: ${what} must be ${len} bytes (got ${b.length})`);
  return b;
};

// ── PKI ──────────────────────────────────────────────────────────────────────────────────────────

const INTEL_DN = (cn: string) => [['CN', cn], ['O', 'Intel Corporation'], ['L', 'Santa Clara'], ['ST', 'CA'], ['C', 'US']] as const;
const D = (iso: string) => new Date(iso);
const ROOT_CRL_URI = 'https://certificates.trustedservices.intel.com/IntelSGXRootCA.der';

export interface IntelTestPki {
  seed: string;
  rootKey: ForgeKey;
  caKey: ForgeKey;
  tcbSigningKey: ForgeKey;
  root: ForgedCert;
  /** "Intel SGX PCK Platform CA" — issues PCK leaves, path length 0. */
  platformCa: ForgedCert;
  /** "Intel SGX TCB Signing" leaf directly under the root (as on the real PCS). */
  tcbSigning: ForgedCert;
  /** SHA-256 of the TEST root's SPKI — pass as `trustAnchorRootCaSpkiSha256`. */
  rootSpkiSha256: string;
  rootDn: ReturnType<typeof INTEL_DN>;
  caDn: ReturnType<typeof INTEL_DN>;
  tcbDn: ReturnType<typeof INTEL_DN>;
}

/** Mint a TEST Intel-like PKI: Root CA → Platform CA, plus a TCB-signing leaf under the root. Deterministic per seed. */
export interface IntelPkiOptions {
  /** Sign the Platform CA with this key instead of the root's (broken link at depth 1). */
  caSignedBy?: ForgeKey;
  /** `false` signs the "self-signed" root with a different key. */
  rootSelfSigned?: boolean;
  /** Platform CA BasicConstraints: default CA:TRUE pathlen 0. */
  caBasicConstraints?: 'default' | 'absent' | 'ca-false';
  rootValidity?: readonly [Date, Date];
  caValidity?: readonly [Date, Date];
  tcbSigningValidity?: readonly [Date, Date];
}

export function forgeIntelPki(seed = 'intel-test-pki', po: IntelPkiOptions = {}): IntelTestPki {
  const rootKey = forgeKey(`${seed}/root`, 'P-256');
  const caKey = forgeKey(`${seed}/platform-ca`, 'P-256');
  const tcbSigningKey = forgeKey(`${seed}/tcb-signing`, 'P-256');
  const rootDn = INTEL_DN('Intel SGX Root CA');
  const caDn = INTEL_DN('Intel SGX PCK Platform CA');
  const tcbDn = INTEL_DN('Intel SGX TCB Signing');
  const root = forgeCert({
    subject: rootDn,
    issuer: rootDn,
    subjectKey: rootKey,
    signer: po.rootSelfSigned === false ? forgeKey(`${seed}/not-the-root`, 'P-256') : rootKey,
    serial: serialFor(`${seed}/root`),
    notBefore: po.rootValidity?.[0] ?? D('2018-05-21T10:45:10Z'),
    notAfter: po.rootValidity?.[1] ?? D('2049-12-31T23:59:59Z'),
    extensions: [ext.authorityKeyId(rootKey), ext.crlDistributionPoint(ROOT_CRL_URI), ext.subjectKeyId(rootKey), ext.keyUsage(['keyCertSign', 'cRLSign']), ext.basicConstraints(true, 1)],
  });
  const platformCa = forgeCert({
    subject: caDn,
    issuer: rootDn,
    subjectKey: caKey,
    signer: po.caSignedBy ?? rootKey,
    serial: serialFor(`${seed}/platform-ca`),
    notBefore: po.caValidity?.[0] ?? D('2018-05-21T10:50:10Z'),
    notAfter: po.caValidity?.[1] ?? D('2033-05-21T10:50:10Z'),
    extensions: [
      ext.authorityKeyId(rootKey),
      ext.crlDistributionPoint(ROOT_CRL_URI),
      ext.subjectKeyId(caKey),
      ext.keyUsage(['keyCertSign', 'cRLSign']),
      ...(po.caBasicConstraints === 'absent' ? [] : [po.caBasicConstraints === 'ca-false' ? ext.basicConstraints(false) : ext.basicConstraints(true, 0)]),
    ],
  });
  const tcbSigning = forgeCert({
    subject: tcbDn,
    issuer: rootDn,
    subjectKey: tcbSigningKey,
    signer: rootKey,
    serial: serialFor(`${seed}/tcb-signing`),
    notBefore: po.tcbSigningValidity?.[0] ?? D('2018-05-21T10:50:10Z'),
    notAfter: po.tcbSigningValidity?.[1] ?? D('2034-05-21T10:50:10Z'),
    extensions: [ext.authorityKeyId(rootKey), ext.crlDistributionPoint(ROOT_CRL_URI), ext.subjectKeyId(tcbSigningKey), ext.keyUsage(['digitalSignature']), ext.basicConstraints(false)],
  });
  return { seed, rootKey, caKey, tcbSigningKey, root, platformCa, tcbSigning, rootSpkiSha256: rootKey.spkiSha256, rootDn, caDn, tcbDn };
}

// ── SGX extension ────────────────────────────────────────────────────────────────────────────────

const SGX = '1.2.840.113741.1.13.1';
export interface PckExtensionSpec {
  /** 6-byte FMSPC (bytes or 12 hex chars). */
  fmspc: Bytes;
  /** The 16 SGX TCB component SVNs (OID .2.1 … .2.16). */
  sgxTcb: readonly number[];
  pcesvn: number;
  /** 16-byte CPUSVN (OID .2.18). */
  cpusvn: Bytes;
  ppid?: Uint8Array;
  pceId?: Uint8Array;
  /** Omit named sub-extensions to exercise the extractor's missing-field branches. */
  omit?: readonly ('fmspc' | 'tcb' | 'pcesvn')[];
  /** Replace the FMSPC OCTET STRING with `len` bytes (malformed length). */
  fmspcLen?: number;
}

/** Encode the Intel SGX extension value exactly as a real PCK certificate carries it. */
export function sgxExtensionValue(s: PckExtensionSpec): Uint8Array {
  if (s.sgxTcb.length !== 16) throw new RangeError('forge-dcap: sgxTcb needs 16 components');
  const omit = new Set(s.omit ?? []);
  const comp = (n: number, v: Uint8Array) => seq(oid(`${SGX}.2.${n}`), v);
  const tcbComps = [
    ...s.sgxTcb.map((svn, i) => comp(i + 1, integer(svn))),
    ...(omit.has('pcesvn') ? [] : [comp(17, integer(s.pcesvn))]),
    comp(18, octets(asBytes(s.cpusvn, 16, 'cpusvn'))),
  ];
  const fmspc = typeof s.fmspc === 'string' ? hexToBytes(s.fmspc) : s.fmspc;
  const fmspcBytes = s.fmspcLen !== undefined ? fill('fmspc-len', s.fmspcLen) : asBytes(fmspc, 6, 'fmspc');
  return seq(
    seq(oid(`${SGX}.1`), octets(s.ppid ?? fill('ppid', 16))),
    ...(omit.has('tcb') ? [] : [seq(oid(`${SGX}.2`), seq(...tcbComps))]),
    seq(oid(`${SGX}.3`), octets(s.pceId ?? Uint8Array.of(0, 0))),
    ...(omit.has('fmspc') ? [] : [seq(oid(`${SGX}.4`), octets(fmspcBytes))]),
    seq(oid(`${SGX}.5`), enumerated(0)),
    seq(oid(`${SGX}.6`), octets(fill('platform-instance-id', 16))),
    seq(oid(`${SGX}.7`), seq(seq(oid(`${SGX}.7.1`), derBool(false)), seq(oid(`${SGX}.7.2`), derBool(false)), seq(oid(`${SGX}.7.3`), derBool(false)))),
  );
}
export const sgxExtension = (s: PckExtensionSpec): Extension => extension(SGX, false, sgxExtensionValue(s));

// ── quote options ────────────────────────────────────────────────────────────────────────────────

export interface ForgeTdxOptions {
  pki?: IntelTestPki;
  header?: { version?: number; attKeyType?: number; teeType?: number; userData?: Uint8Array; vendorId?: Uint8Array };
  td?: {
    mrTd?: Bytes;
    mrConfigId?: Bytes;
    mrOwner?: Bytes;
    mrOwnerConfig?: Bytes;
    rtmr0?: Bytes;
    rtmr1?: Bytes;
    rtmr2?: Bytes;
    rtmr3?: Bytes;
    /** 64 bytes. Default: all zero. */
    reportData?: Bytes;
    teeTcbSvn?: Bytes;
    mrSeam?: Bytes;
    mrSignerSeam?: Bytes;
    seamAttributes?: Bytes;
    tdAttributes?: Bytes;
    xfam?: Bytes;
    /** Convenience: set TD_ATTRIBUTES.DEBUG. */
    debug?: boolean;
  };
  pck?: {
    fmspc?: Bytes;
    sgxTcb?: readonly number[];
    pcesvn?: number;
    cpusvn?: Bytes;
    notBefore?: Date;
    notAfter?: Date;
    /** `'absent'` omits BasicConstraints; `true` marks the PCK leaf as a CA. Default: CA:FALSE. */
    ca?: boolean | 'absent';
    serialLabel?: string;
    ext?: Pick<PckExtensionSpec, 'omit' | 'fmspcLen'>;
    /** Key that signs the PCK leaf (default: the Platform CA key). */
    issuerKey?: ForgeKey;
    /** Do not add the SGX extension at all. */
    noSgxExtension?: boolean;
    /** Publish this SubjectPublicKeyInfo instead of the leaf's P-256 key (e.g. RSA, off-curve point). */
    spkiOverride?: Uint8Array;
  };
  qe?: {
    cpusvn?: Bytes;
    miscSelect?: Bytes;
    attributes?: Bytes;
    mrEnclave?: Bytes;
    mrSigner?: Bytes;
    isvProdId?: number;
    isvSvn?: number;
    /** Override the 64 report_data bytes (default: SHA-256(AK ‖ auth) ‖ 32 zero). */
    reportData?: Bytes;
    /** Key that signs the QE report (default: the PCK leaf key). */
    signer?: ForgeKey;
  };
  qeAuth?: Uint8Array;
  /** The embedded attestation key (default derived from the seed). */
  ak?: ForgeKey;
  /** Key that signs the TD region (default: the embedded AK). */
  tdSigner?: ForgeKey;
  chain?: {
    /** Certificates (PEM) in the order written; default `[pck, platformCa, root]`. */
    order?: readonly ForgedCert[];
    /** Raw PEM to append (e.g. a stranger cert). */
    appendPem?: string;
    /** Do not NUL-terminate the PEM (the Azure quote does). */
    noNul?: boolean;
    /** Replace the whole PEM text. */
    pemOverride?: string;
  };
  outerCertType?: number;
  innerCertType?: number;
  /** Trailing zero padding after the signature data (Azure appends 70). */
  trailingPad?: number;
  /** Added to the declared signature-data length (negative = understates). */
  sigDataLenDelta?: number;
  seed?: string;
}

export interface ForgedTdxQuote {
  quote: Uint8Array;
  pki: IntelTestPki;
  rootSpkiSha256: string;
  ak: ForgeKey;
  pck: ForgedCert;
  pckKey: ForgeKey;
  platformCa: ForgedCert;
  qeAuth: Uint8Array;
  qeReport: Uint8Array;
  tdBody: Uint8Array;
  pckPem: string;
  /** What the PCK leaf was issued at (lowercase hex fmspc etc.). */
  pckSpec: { fmspcHex: string; sgxTcb: number[]; pcesvn: number; cpusvn: Uint8Array };
  /** Offsets that depend on the PEM/auth lengths. */
  offsets: { innerType: number; innerSize: number; pem: number; pemLen: number; end: number; quoteLen: number };
}

const DEFAULT_TEE_TCB_SVN = hexToBytes('0d010500000000000000000000000000');
/** SEPT_VE_DISABLE (bit 28), as on a real Azure TD. */
const DEFAULT_TD_ATTRIBUTES = hexToBytes('0000001000000000');

/** Forge a genuine-format Intel DCAP v4 TDX quote. */
export function forgeTdxQuote(o: ForgeTdxOptions = {}): ForgedTdxQuote {
  const seed = o.seed ?? 'forge-tdx';
  const pki = o.pki ?? forgeIntelPki(`${seed}/pki`);
  const ak = o.ak ?? forgeKey(`${seed}/ak`, 'P-256');
  const pckKey = forgeKey(`${seed}/pck/${o.pck?.serialLabel ?? 'leaf'}`, 'P-256');

  // PCK leaf (issued by the Platform CA) with the Intel SGX extension
  const pckSpec = {
    fmspcHex: bytesToHex(asBytes(o.pck?.fmspc ?? '90c06f000000', 6, 'fmspc')),
    sgxTcb: [...(o.pck?.sgxTcb ?? [5, 5, 2, 2, 6, 1, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0])],
    pcesvn: o.pck?.pcesvn ?? 13,
    cpusvn: asBytes(o.pck?.cpusvn ?? '05050202060100050000000000000000', 16, 'cpusvn'),
  };
  const caExt = o.pck?.ca;
  const pckExts: Extension[] = [
    ext.authorityKeyId(pki.caKey),
    ext.crlDistributionPoint('https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der'),
    ext.subjectKeyId(pckKey),
    ext.keyUsage(['digitalSignature', 'nonRepudiation']),
    ...(caExt === 'absent' ? [] : [ext.basicConstraints(caExt === true)]),
    ...(o.pck?.noSgxExtension ? [] : [sgxExtension({ fmspc: pckSpec.fmspcHex, sgxTcb: pckSpec.sgxTcb, pcesvn: pckSpec.pcesvn, cpusvn: pckSpec.cpusvn, ...(o.pck?.ext ?? {}) })]),
  ];
  const pck = forgeCert({
    subject: INTEL_DN('Intel SGX PCK Certificate'),
    issuer: pki.caDn,
    subjectKey: o.pck?.spkiOverride ? { ...pckKey, spki: o.pck.spkiOverride } : pckKey,
    signer: o.pck?.issuerKey ?? pki.caKey,
    serial: serialFor(`${seed}/pck/${o.pck?.serialLabel ?? 'leaf'}`),
    notBefore: o.pck?.notBefore ?? D('2026-09-30T16:45:11Z'),
    notAfter: o.pck?.notAfter ?? D('2033-09-30T16:45:11Z'),
    extensions: pckExts,
  });

  // chain PEM
  const order = o.chain?.order ?? [pck, pki.platformCa, pki.root];
  const pemText = o.chain?.pemOverride ?? order.map((c) => c.pem).join('') + (o.chain?.appendPem ?? '');
  const pemBytes = cat(new TextEncoder().encode(pemText), o.chain?.noNul ? new Uint8Array(0) : Uint8Array.of(0));

  // TD10 body
  const body = new Uint8Array(584);
  const put = (off: number, v: Bytes | undefined, len: number, what: string, dflt: Uint8Array) => body.set(v === undefined ? dflt : asBytes(v, len, what), off);
  const t = o.td ?? {};
  put(TD10_FIELDS.TEE_TCB_SVN, t.teeTcbSvn, 16, 'teeTcbSvn', DEFAULT_TEE_TCB_SVN);
  put(TD10_FIELDS.MR_SEAM, t.mrSeam, 48, 'mrSeam', fill(`${seed}/mrseam`, 48));
  put(TD10_FIELDS.MR_SIGNER_SEAM, t.mrSignerSeam, 48, 'mrSignerSeam', new Uint8Array(48));
  put(TD10_FIELDS.SEAM_ATTRIBUTES, t.seamAttributes, 8, 'seamAttributes', new Uint8Array(8));
  put(TD10_FIELDS.TD_ATTRIBUTES, t.tdAttributes, 8, 'tdAttributes', DEFAULT_TD_ATTRIBUTES);
  if (t.debug) body[TD10_FIELDS.TD_ATTRIBUTES] = body[TD10_FIELDS.TD_ATTRIBUTES]! | TD_ATTR_DEBUG;
  put(TD10_FIELDS.XFAM, t.xfam, 8, 'xfam', hexToBytes('e718060000000000'));
  put(TD10_FIELDS.MRTD, t.mrTd, 48, 'mrTd', fill(`${seed}/mrtd`, 48));
  put(TD10_FIELDS.MR_CONFIG_ID, t.mrConfigId, 48, 'mrConfigId', new Uint8Array(48));
  put(TD10_FIELDS.MR_OWNER, t.mrOwner, 48, 'mrOwner', new Uint8Array(48));
  put(TD10_FIELDS.MR_OWNER_CONFIG, t.mrOwnerConfig, 48, 'mrOwnerConfig', new Uint8Array(48));
  put(TD10_FIELDS.RTMR0, t.rtmr0, 48, 'rtmr0', fill(`${seed}/rtmr0`, 48));
  put(TD10_FIELDS.RTMR1, t.rtmr1, 48, 'rtmr1', fill(`${seed}/rtmr1`, 48));
  put(TD10_FIELDS.RTMR2, t.rtmr2, 48, 'rtmr2', new Uint8Array(48));
  put(TD10_FIELDS.RTMR3, t.rtmr3, 48, 'rtmr3', new Uint8Array(48));
  put(TD10_FIELDS.REPORT_DATA, t.reportData, 64, 'reportData', new Uint8Array(64));

  // header
  const h = o.header ?? {};
  const header = cat(u16(h.version ?? 4), u16(h.attKeyType ?? 2), u32(h.teeType ?? 0x81), u32(0), h.vendorId ?? INTEL_QE_VENDOR_ID, h.userData ?? fill(`${seed}/userdata`, 20));
  if (header.length !== 48) throw new RangeError('forge-dcap: header must be 48 bytes');

  // quote signature (AK over header ‖ body)
  const akRaw = ak.pub.subarray(1);
  const quoteSig = ecdsaSign(o.tdSigner ?? ak, 'sha256', cat(header, body)).raw;

  // QE report (384) endorsing the AK
  const qeAuth = o.qeAuth ?? fill(`${seed}/qeauth`, 32);
  const q = o.qe ?? {};
  const qeReport = new Uint8Array(384);
  qeReport.set(asBytes(q.cpusvn ?? '0505191b06ff00060000000000000000', 16, 'qe.cpusvn'), SGX_REPORT_FIELDS.CPU_SVN);
  qeReport.set(asBytes(q.miscSelect ?? '00000000', 4, 'qe.miscSelect'), SGX_REPORT_FIELDS.MISC_SELECT);
  qeReport.set(asBytes(q.attributes ?? '1500000000000000e700000000000000', 16, 'qe.attributes'), SGX_REPORT_FIELDS.ATTRIBUTES);
  qeReport.set(asBytes(q.mrEnclave ?? fill(`${seed}/qe-mrenclave`, 32), 32, 'qe.mrEnclave'), SGX_REPORT_FIELDS.MR_ENCLAVE);
  qeReport.set(asBytes(q.mrSigner ?? 'dc9e2a7c6f948f17474e34a7fc43ed030f7c1563f1babddf6340c82e0e54a8c5', 32, 'qe.mrSigner'), SGX_REPORT_FIELDS.MR_SIGNER);
  qeReport.set(u16(q.isvProdId ?? 2), SGX_REPORT_FIELDS.ISV_PROD_ID);
  qeReport.set(u16(q.isvSvn ?? 7), SGX_REPORT_FIELDS.ISV_SVN);
  qeReport.set(q.reportData !== undefined ? asBytes(q.reportData, 64, 'qe.reportData') : cat(digest('sha256', akRaw, qeAuth), new Uint8Array(32)), SGX_REPORT_FIELDS.REPORT_DATA);
  const qeSig = ecdsaSign(q.signer ?? pckKey, 'sha256', qeReport).raw;

  // signature data
  const innerCert = cat(u16(o.innerCertType ?? 5), u32(pemBytes.length), pemBytes);
  const outerBody = cat(qeReport, qeSig, u16(qeAuth.length), qeAuth, innerCert);
  const sigData = cat(quoteSig, akRaw, u16(o.outerCertType ?? 6), u32(outerBody.length), outerBody);
  const quote = cat(header, body, u32(sigData.length + (o.sigDataLenDelta ?? 0)), sigData, new Uint8Array(o.trailingPad ?? 0));

  const innerType = DCAP_OFFSETS.QE_AUTH + qeAuth.length;
  return {
    quote,
    pki,
    rootSpkiSha256: pki.rootSpkiSha256,
    ak,
    pck,
    pckKey,
    platformCa: pki.platformCa,
    qeAuth,
    qeReport,
    tdBody: body,
    pckPem: pemText,
    pckSpec: { fmspcHex: pckSpec.fmspcHex, sgxTcb: pckSpec.sgxTcb, pcesvn: pckSpec.pcesvn, cpusvn: pckSpec.cpusvn },
    offsets: { innerType, innerSize: innerType + 2, pem: innerType + 6, pemLen: pemBytes.length, end: innerType + 6 + pemBytes.length, quoteLen: quote.length },
  };
}

// ── Intel PCS collateral ─────────────────────────────────────────────────────────────────────────

export interface TdxTcbLevelSpec {
  sgx: readonly number[];
  pcesvn: number;
  tdx: readonly number[];
  status: TcbStatus;
  advisories?: readonly string[];
}
export interface ModuleLevelSpec {
  isvsvn: number;
  status: TcbStatus;
  advisories?: readonly string[];
}
export interface TdxTcbInfoSpec {
  id?: string;
  version?: number;
  issueDate?: string;
  nextUpdate?: string;
  fmspc?: string;
  tcbEvaluationDataNumber?: number | null;
  tdxModule?: { mrsigner: string; attributes: string; attributesMask: string } | null;
  tdxModuleIdentities?: { id: string; mrsigner?: string; attributes?: string; attributesMask?: string; levels: readonly ModuleLevelSpec[] }[];
  levels: readonly TdxTcbLevelSpec[];
  /** Replace tcbLevels wholesale (malformed-level cases). */
  rawLevels?: unknown;
}

const z48 = '0'.repeat(96);
const comps = (a: readonly number[]) => a.map((svn) => ({ svn }));

export function tcbInfoBody(s: TdxTcbInfoSpec): Record<string, unknown> {
  const body: Record<string, unknown> = {
    id: s.id ?? 'TDX',
    version: s.version ?? 3,
    issueDate: s.issueDate ?? '2026-10-08T21:32:59Z',
    nextUpdate: s.nextUpdate ?? '2026-11-07T21:32:59Z',
    fmspc: s.fmspc ?? '90c06f000000',
    pceId: '0000',
    tcbType: 0,
  };
  if (s.tcbEvaluationDataNumber !== null) body.tcbEvaluationDataNumber = s.tcbEvaluationDataNumber ?? 20;
  if (s.tdxModule !== null) body.tdxModule = s.tdxModule ?? { mrsigner: z48, attributes: '0000000000000000', attributesMask: 'FFFFFFFFFFFFFFFF' };
  body.tdxModuleIdentities = (s.tdxModuleIdentities ?? []).map((m) => ({
    id: m.id,
    mrsigner: m.mrsigner ?? z48,
    attributes: m.attributes ?? '0000000000000000',
    attributesMask: m.attributesMask ?? 'FFFFFFFFFFFFFFFF',
    tcbLevels: m.levels.map((l) => ({ tcb: { isvsvn: l.isvsvn }, tcbDate: '2025-08-13T00:00:00Z', tcbStatus: l.status, ...(l.advisories ? { advisoryIDs: [...l.advisories] } : {}) })),
  }));
  body.tcbLevels =
    s.rawLevels ??
    s.levels.map((l) => ({
      tcb: { sgxtcbcomponents: comps(l.sgx), pcesvn: l.pcesvn, tdxtcbcomponents: comps(l.tdx) },
      tcbDate: '2025-08-13T00:00:00Z',
      tcbStatus: l.status,
      ...(l.advisories ? { advisoryIDs: [...l.advisories] } : {}),
    }));
  return body;
}

export interface QeIdentitySpec {
  id?: string;
  version?: number;
  issueDate?: string;
  nextUpdate?: string;
  tcbEvaluationDataNumber?: number | null;
  miscselect?: string;
  miscselectMask?: string;
  attributes?: string;
  attributesMask?: string;
  mrsigner?: string;
  isvprodid?: number | string;
  levels?: readonly ModuleLevelSpec[];
}
export function qeIdentityBody(s: QeIdentitySpec = {}): Record<string, unknown> {
  const body: Record<string, unknown> = {
    id: s.id ?? 'TD_QE',
    version: s.version ?? 2,
    issueDate: s.issueDate ?? '2026-10-08T21:27:34Z',
    nextUpdate: s.nextUpdate ?? '2026-11-07T21:27:34Z',
  };
  if (s.tcbEvaluationDataNumber !== null) body.tcbEvaluationDataNumber = s.tcbEvaluationDataNumber ?? 20;
  body.miscselect = s.miscselect ?? '00000000';
  body.miscselectMask = s.miscselectMask ?? 'FFFFFFFF';
  body.attributes = s.attributes ?? '11000000000000000000000000000000';
  body.attributesMask = s.attributesMask ?? 'FBFFFFFFFFFFFFFF0000000000000000';
  body.mrsigner = s.mrsigner ?? 'DC9E2A7C6F948F17474E34A7FC43ED030F7C1563F1BABDDF6340C82E0E54A8C5';
  body.isvprodid = s.isvprodid ?? 2;
  body.tcbLevels = (s.levels ?? [{ isvsvn: 4, status: 'UpToDate' }]).map((l) => ({ tcb: { isvsvn: l.isvsvn }, tcbDate: '2025-08-13T00:00:00Z', tcbStatus: l.status, ...(l.advisories ? { advisoryIDs: [...l.advisories] } : {}) }));
  return body;
}

/**
 * Sign a collateral document the way Intel PCS does: `{"<name>":<json>,"signature":"<hex r‖s>"}` where the signature
 * is ECDSA-P256/SHA-256 over the EXACT bytes of the `<json>` value.
 */
export function signCollateralJson(name: 'tcbInfo' | 'enclaveIdentity', body: Record<string, unknown>, signer: ForgeKey, tamperAfterSigning?: (rawJson: string) => string): string {
  const raw = JSON.stringify(body);
  const sig = bytesToHex(ecdsaSign(signer, 'sha256', new TextEncoder().encode(raw)).raw);
  return `{"${name}":${tamperAfterSigning ? tamperAfterSigning(raw) : raw},"signature":"${sig}"}`;
}

export interface ForgeCollateralOptions {
  tcbInfo?: Partial<TdxTcbInfoSpec>;
  qeIdentity?: QeIdentitySpec;
  /** Serials (hex) listed on the PCK CRL / Root CA CRL. */
  pckCrlRevoked?: readonly string[];
  rootCrlRevoked?: readonly string[];
  crlThisUpdate?: Date;
  crlNextUpdate?: Date;
  /** Sign collateral with this key instead of the PKI's TCB-signing key. */
  signerKey?: ForgeKey;
  /** Chain PEM for TCB info / QE identity (default: signing leaf then root). */
  tcbInfoChainPem?: string;
  qeIdentityChainPem?: string;
  /** Key that signs the PCK CRL (default: Platform CA key) and the root CRL (default: root key). */
  pckCrlSigner?: ForgeKey;
  rootCrlSigner?: ForgeKey;
  tamperTcbInfo?: (raw: string) => string;
  tamperQeIdentity?: (raw: string) => string;
}

/** Default platform level set for `q`: one UpToDate level exactly at the PCK/TD TCB, plus the TDX module identity. */
export function defaultTcbInfoSpec(q: ForgedTdxQuote): TdxTcbInfoSpec {
  const tee = q.tdBody.subarray(0, 16);
  const minor = tee[1]!;
  return {
    fmspc: q.pckSpec.fmspcHex,
    ...(minor > 0 ? { tdxModuleIdentities: [{ id: `TDX_${minor.toString(16).toUpperCase().padStart(2, '0')}`, levels: [{ isvsvn: tee[0]!, status: 'UpToDate' as TcbStatus }] }] } : {}),
    levels: [{ sgx: q.pckSpec.sgxTcb, pcesvn: q.pckSpec.pcesvn, tdx: [...tee], status: 'UpToDate' }],
  };
}

/** Forge complete PCS collateral for `q` under the test PKI; defaults evaluate to UpToDate. */
export function forgeTdxCollateral(q: ForgedTdxQuote, o: ForgeCollateralOptions = {}): IntelTdxCollateral {
  const pki = q.pki;
  const signer = o.signerKey ?? pki.tcbSigningKey;
  const chain = pki.tcbSigning.pem + pki.root.pem;
  const info = { ...defaultTcbInfoSpec(q), ...(o.tcbInfo ?? {}) } as TdxTcbInfoSpec;
  const thisUpdate = o.crlThisUpdate ?? D('2026-10-08T21:28:48Z');
  const nextUpdate = o.crlNextUpdate ?? D('2026-11-07T21:28:48Z');
  return {
    tcbInfoJson: signCollateralJson('tcbInfo', tcbInfoBody(info), signer, o.tamperTcbInfo),
    tcbInfoIssuerChainPem: o.tcbInfoChainPem ?? chain,
    qeIdentityJson: signCollateralJson('enclaveIdentity', qeIdentityBody(o.qeIdentity), signer, o.tamperQeIdentity),
    qeIdentityIssuerChainPem: o.qeIdentityChainPem ?? chain,
    pckCrlDer: forgeCrl({ issuer: pki.caDn, signer: o.pckCrlSigner ?? pki.caKey, revoked: o.pckCrlRevoked ?? [], thisUpdate, nextUpdate, authorityKey: pki.rootKey }),
    rootCrlDer: forgeCrl({ issuer: pki.rootDn, signer: o.rootCrlSigner ?? pki.rootKey, revoked: o.rootCrlRevoked ?? [], thisUpdate, nextUpdate, authorityKey: pki.rootKey }),
  };
}
