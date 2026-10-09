/**
 * TEST-ONLY forger of genuine-format NVIDIA GPU-CC evidence and collateral.
 *
 * Real NVIDIA evidence cannot be re-signed (we hold no NVIDIA CA or GPU keys), so a captured transcript can never show
 * a different golden measurement, a mismatching driver version, a revoked device certificate, an expired chain, ...
 * This module mints evidence in the REAL wire formats under a TEST root so the UNMODIFIED production verifiers
 * (`attest-nvidia-spdm.ts`, `attest-nvidia-rim.ts`, `attest-nvidia-ocsp.ts`) run end to end; the trust anchors are
 * injected through their existing SPKI-pin options.
 *
 *   - SPDM 1.1 GET_MEASUREMENTS transcript (37-byte request with the caller's nonce; response with N SHA-384
 *     measurement blocks, responder nonce, opaque TLVs, 96-byte ECDSA P-384 r‖s over SHA-384(request‖response-sans-sig)),
 *   - a 5-certificate P-384 device chain named like NVIDIA's (leaf → BROM → Provisioner ICA → Identity → Device Identity CA),
 *   - RIM (SWID) XML, enveloped XMLDSig, C14N 1.1 + ECDSA-SHA384, signed through a test CoRIM chain,
 *   - CRLs (ecdsa-with-SHA256 over P-384, exactly as NVIDIA publishes them) and RFC 6960 OCSP responses.
 *
 * Never import from production code; deterministic (seeded keys, RFC 6979 signatures).
 */
import { C14nCanonicalization } from 'xml-crypto';
import { DOMParser } from '@xmldom/xmldom';
import {
  type DnAttr,
  type Extension,
  type ForgeKey,
  type ForgedCert,
  type Curve,
  bytesToHex,
  cat,
  ctx,
  ctxPrim,
  digest,
  dn,
  ecdsaSign,
  enumerated,
  ext,
  extension,
  fill,
  forgeCert,
  forgeCrl,
  forgeKey,
  generalizedTime,
  hexToBytes,
  integer,
  nul,
  octets,
  oid,
  seq,
  serialFor,
  bitString,
  tlv,
  u16,
} from './forge-x509';

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// Device certificate chain
// ═══════════════════════════════════════════════════════════════════════════════════════════════


/** Names exactly as in a captured H100 chain (index 0 = leaf … 4 = Device Identity CA). */
export function nvidiaDeviceNames(serialLeaf = '6EE6DBA820B5F95345D7FBF632B369B500C8C60A', serialBrom = '41A8EC658CB07C44D2'): readonly (readonly DnAttr[])[] {
  return [
    [['serialNumber', serialLeaf], ['C', 'US'], ['O', 'NVIDIA Corporation'], ['CN', 'GH100 A01 GSP FMC LF']],
    [['serialNumber', serialBrom], ['C', 'US'], ['O', 'NVIDIA Corporation'], ['CN', 'GH100 A01 GSP BROM']],
    [['CN', 'NVIDIA GH100 Provisioner ICA 1'], ['O', 'NVIDIA Corporation'], ['C', 'US']],
    [['CN', 'NVIDIA GH100 Identity'], ['O', 'NVIDIA Corporation']],
    [['CN', 'NVIDIA Device Identity CA'], ['O', 'NVIDIA']],
  ];
}

export const NVIDIA_OCSP_URI = 'http://ocsp.ndis.nvidia.com';
export const NVIDIA_L2_CRL_URI = 'http://crl.ndis.nvidia.com/crl/l2-gh100.crl';
export const NVIDIA_L1_CRL_URI = 'http://crl.ndis.nvidia.com/crl/l1-root.crl';

const aia = (uri: string): Extension => extension('1.3.6.1.5.5.7.1.1', false, seq(seq(oid('1.3.6.1.5.5.7.48.1'), ctxPrim(6, new TextEncoder().encode(uri)))));

export interface ChainCertOverride {
  notBefore?: Date;
  notAfter?: Date;
  /** `true` (default for issuers) / `false` (CA:FALSE) / `'absent'` (no BasicConstraints). */
  ca?: boolean | 'absent';
  /** Curve of THIS certificate's subject key (default P-384). */
  curve?: Curve;
  /** Sign this certificate with a key other than its parent's. */
  signedBy?: ForgeKey;
  /** Replace the certificate's subject name. */
  subject?: readonly DnAttr[];
}
export interface NvidiaDevicePkiOptions {
  seed?: string;
  /** Per chain index overrides (0 = leaf … 4 = root). */
  override?: Partial<Record<0 | 1 | 2 | 3 | 4, ChainCertOverride>>;
  /** Issue the chain with this many certificates, dropping the INTERMEDIATES nearest the leaf side (leaf kept). */
  names?: readonly (readonly DnAttr[])[];
}

export interface NvidiaDevicePki {
  seed: string;
  /** Leaf first. */
  keys: ForgeKey[];
  certs: ForgedCert[];
  chainPem: string;
  leafKey: ForgeKey;
  rootKey: ForgeKey;
  /** SHA-256 of the root SPKI — the pin (`rootSpkiSha256`). */
  rootSpkiSha256: string;
  names: readonly (readonly DnAttr[])[];
}

/** Mint a TEST NVIDIA device-identity chain with the real subject names and extension layout. */
export function forgeNvidiaDevicePki(o: NvidiaDevicePkiOptions = {}): NvidiaDevicePki {
  const seed = o.seed ?? 'nvidia-device-pki';
  const names = o.names ?? nvidiaDeviceNames();
  const ov = (i: number): ChainCertOverride => (o.override as Record<number, ChainCertOverride | undefined> | undefined)?.[i] ?? {};
  const keys = names.map((_, i) => forgeKey(`${seed}/key${i}`, ov(i).curve ?? 'P-384'));
  const last = names.length - 1;
  const FAR = new Date('9999-12-31T23:59:59Z');
  const certs: ForgedCert[] = [];
  for (let i = 0; i < names.length; i++) {
    const parentIdx = Math.min(i + 1, last);
    const isLeaf = i === 0;
    const isRoot = i === last;
    const ca = ov(i).ca ?? !isLeaf;
    const parentKey = keys[parentIdx]!;
    const bc: Extension[] = ca === 'absent' ? [] : [ext.basicConstraints(ca === true)];
    const extensions: Extension[] = isLeaf
      ? [ext.keyUsage(['digitalSignature']), ext.subjectKeyId(keys[i]!), ext.authorityKeyId(parentKey), extension('2.5.29.17', false, seq(ctx(0, oid('1.3.6.1.4.1.412.274.1'), ctx(0, tlv(0x0c, new TextEncoder().encode('NVIDIA:GH100:48B02DA1BDF7A9DE')))))), extension('2.23.133.5.4.1', false, seq(octets(fill(`${seed}/dice`, 183))))]
      : [
          ...bc,
          ext.keyUsage(isRoot ? ['keyCertSign', 'cRLSign'] : ['keyCertSign']),
          ...(i === 2 ? [ext.crlDistributionPoint(NVIDIA_L2_CRL_URI), aia(NVIDIA_OCSP_URI)] : []),
          ...(i === 3 ? [ext.crlDistributionPoint(NVIDIA_L1_CRL_URI), aia(NVIDIA_OCSP_URI)] : []),
          ext.subjectKeyId(keys[i]!),
          ext.authorityKeyId(parentKey),
        ];
    certs.push(
      forgeCert({
        subject: ov(i).subject ?? names[i]!,
        issuer: names[parentIdx]!,
        subjectKey: keys[i]!,
        signer: ov(i).signedBy ?? parentKey,
        serial: serialFor(`${seed}/serial${i}`),
        notBefore: ov(i).notBefore ?? new Date(i === 4 ? '2021-11-05T00:00:00Z' : i === 3 ? '2022-01-12T00:00:00Z' : i === 2 ? '2022-03-01T00:00:00Z' : '2020-10-17T00:00:00Z'),
        notAfter: ov(i).notAfter ?? FAR,
        sigDigest: 'sha384',
        extensions,
      }),
    );
  }
  return { seed, keys, certs, chainPem: certs.map((c) => c.pem).join(''), leafKey: keys[0]!, rootKey: keys[last]!, rootSpkiSha256: keys[last]!.spkiSha256, names };
}

/** A CRL issued by chain certificate `issuerIdx` (as NVIDIA publishes them: P-384 key, ecdsa-with-SHA256). */
export function forgeNvidiaCrl(pki: NvidiaDevicePki, issuerIdx: number, o: { revoked?: readonly string[]; thisUpdate?: Date; nextUpdate?: Date; signer?: ForgeKey; omitNextUpdate?: boolean; crlNumber?: number } = {}): Uint8Array {
  return forgeCrl({
    issuer: pki.names[issuerIdx]!,
    signer: o.signer ?? pki.keys[issuerIdx]!,
    revoked: o.revoked ?? [],
    authorityKey: pki.keys[Math.min(issuerIdx + 1, pki.keys.length - 1)]!,
    thisUpdate: o.thisUpdate ?? new Date('2026-01-16T21:06:11Z'),
    nextUpdate: o.nextUpdate ?? new Date('2028-01-16T21:06:11Z'),
    ...(o.omitNextUpdate ? { omitNextUpdate: true } : {}),
    ...(o.crlNumber !== undefined ? { crlNumber: o.crlNumber } : {}),
  });
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// SPDM transcript
// ═══════════════════════════════════════════════════════════════════════════════════════════════

export const SPDM = { REQ_LEN: 37, SIG_LEN: 96, NONCE_LEN: 32, DIGEST_LEN: 48 } as const;

/** Opaque TLV types of interest (nvtrust `OpaqueData`). */
export const OPAQUE_TYPE = {
  DRIVER_VERSION: 3,
  GPU_INFO: 4,
  VBIOS_VERSION: 6,
  NVDEC0_STATUS: 11,
  MSRSCNT: 12,
  BOARD_ID: 14,
  CHIP_SKU: 15,
  CHIP_SKU_MOD: 16,
  PROJECT: 17,
  PROJECT_SKU: 18,
  PROJECT_SKU_MOD: 19,
  FWID: 20,
  NVDEC1_STATUS: 21,
  OPAQUE_VERSION: 34,
  FEATURE_FLAG: 36,
} as const;

const asc = (s: string, len: number): Uint8Array => {
  const out = new Uint8Array(len);
  out.set(new TextEncoder().encode(s).subarray(0, len));
  return out;
};

/** The H100's opaque set, in the real order and with the real sizes (434 bytes of TLVs). */
export function defaultOpaque(over: { driver?: string; vbiosRaw?: string; project?: string; projectSku?: string; chipSku?: string; nvdec0?: number } = {}): [number, Uint8Array][] {
  return [
    [OPAQUE_TYPE.VBIOS_VERSION, hexToBytes(over.vbiosRaw ?? '009f009604000000')],
    [OPAQUE_TYPE.BOARD_ID, hexToBytes('08050000')],
    [OPAQUE_TYPE.CHIP_SKU, asc(over.chipSku ?? '886', 9)],
    [OPAQUE_TYPE.CHIP_SKU_MOD, asc('0', 5)],
    [OPAQUE_TYPE.PROJECT, asc(over.project ?? '1010', 5)],
    [OPAQUE_TYPE.PROJECT_SKU, asc(over.projectSku ?? '0210', 5)],
    [OPAQUE_TYPE.PROJECT_SKU_MOD, new Uint8Array(2)],
    [OPAQUE_TYPE.DRIVER_VERSION, asc(over.driver ?? '595.71.05', 10)],
    [OPAQUE_TYPE.GPU_INFO, hexToBytes('8001000000000000')],
    [OPAQUE_TYPE.MSRSCNT, fill('msrscnt', 256)],
    [13, hexToBytes('00c00100')],
    [OPAQUE_TYPE.NVDEC0_STATUS, Uint8Array.of(over.nvdec0 ?? 0x55)],
    [OPAQUE_TYPE.FWID, fill('fwid', 48)],
    [OPAQUE_TYPE.NVDEC1_STATUS, Uint8Array.of(0x55)],
    [OPAQUE_TYPE.OPAQUE_VERSION, hexToBytes('0100')],
    [OPAQUE_TYPE.FEATURE_FLAG, hexToBytes('0000')],
  ];
}

/** The deterministic digest the forger gives SPDM measurement block `blockIndex` (1-based) unless overridden. */
export function goldenDigest(blockIndex: number): Uint8Array {
  return fill(`gpu-measurement/${blockIndex}`, SPDM.DIGEST_LEN);
}

export interface ForgeSpdmOptions {
  /** 32-byte request nonce (the PCA challenge). */
  challenge?: Uint8Array;
  version?: number;
  requestCode?: number;
  responseCode?: number;
  param1?: number;
  slot?: number;
  /** Number of measurement blocks (default 64, indices 1..N). */
  blocks?: number;
  /** Digest overrides keyed by SPDM block index (1-based). */
  digests?: Record<number, Uint8Array>;
  /** Replace the whole measurement list (index, DMTF value type, digest). */
  measurements?: readonly { index: number; digest: Uint8Array; valueType?: number; dmtfSizeDelta?: number; blockSizeDelta?: number }[];
  responderNonce?: Uint8Array;
  /** Opaque TLVs in order; defaults to {@link defaultOpaque}. */
  opaque?: readonly (readonly [number, Uint8Array])[];
  /** Key that signs the report (default: the device leaf key). */
  signer: ForgeKey;
  /** `'bad'` flips the signature; a byte array replaces it (e.g. a wrong length). */
  signature?: 'bad' | Uint8Array;
  /** Header lies (for the parser's consistency checks). */
  numBlocksHeader?: number;
  recLenDelta?: number;
  opaqueLenDelta?: number;
  /** Raw bytes appended INSIDE the opaque region after the last TLV (e.g. a truncated TLV header). */
  opaqueTail?: Uint8Array;
  trailing?: Uint8Array;
}

export interface ForgedSpdm {
  evidence: Uint8Array;
  request: Uint8Array;
  response: Uint8Array;
  /** request ‖ response-without-signature (what the device key signs). */
  signedBytes: Uint8Array;
  signature: Uint8Array;
  /** Offsets within `evidence` (valid for the default layout). */
  layout: { responseOff: number; recordsOff: number; recordsLen: number; responderNonceOff: number; opaqueLenOff: number; opaqueOff: number; opaqueLen: number; sigOff: number; opaqueTlvOff: Record<number, number> };
  measurements: { index: number; digest: Uint8Array }[];
}

export function forgeSpdmTranscript(o: ForgeSpdmOptions): ForgedSpdm {
  const challenge = o.challenge ?? fill('spdm-challenge', 32);
  if (challenge.length !== 32) throw new RangeError('forge-spdm: challenge must be 32 bytes');
  const request = cat(Uint8Array.of(o.version ?? 0x11, o.requestCode ?? 0xe0, o.param1 ?? 0x01, 0xff), challenge, Uint8Array.of(o.slot ?? 0));

  const n = o.blocks ?? 64;
  const list = o.measurements ?? Array.from({ length: n }, (_, k) => ({ index: k + 1, digest: o.digests?.[k + 1] ?? goldenDigest(k + 1) }));
  const records = cat(
    ...list.map((m) => {
      const dmtf = cat(Uint8Array.of(('valueType' in m && m.valueType !== undefined ? m.valueType : 1) & 0xff), u16(m.digest.length + (('dmtfSizeDelta' in m && m.dmtfSizeDelta) || 0)), m.digest);
      return cat(Uint8Array.of(m.index, 1), u16(dmtf.length + (('blockSizeDelta' in m && m.blockSizeDelta) || 0)), dmtf);
    }),
  );
  const opaqueList = o.opaque ?? defaultOpaque();
  const tlvOff: Record<number, number> = {};
  let acc = 0;
  const opaque = cat(
    ...opaqueList.map(([t, v]) => {
      tlvOff[t] = acc + 4;
      acc += 4 + v.length;
      return cat(u16(t), u16(v.length), v);
    }),
    o.opaqueTail ?? new Uint8Array(0),
  );
  const responderNonce = o.responderNonce ?? fill('spdm-responder-nonce', 32);
  const recLen = records.length + (o.recLenDelta ?? 0);
  const respHead = Uint8Array.of(o.version ?? 0x11, o.responseCode ?? 0x60, 0, 0, (o.numBlocksHeader ?? list.length) & 0xff, recLen & 0xff, (recLen >> 8) & 0xff, (recLen >> 16) & 0xff);
  const respNoSig = cat(respHead, records, responderNonce, u16(opaque.length + (o.opaqueLenDelta ?? 0)), opaque);
  const signedBytes = cat(request, respNoSig);
  let signature = ecdsaSign(o.signer, 'sha384', signedBytes).raw;
  if (o.signature === 'bad') signature = Uint8Array.from(signature, (b, i) => (i === 7 ? b ^ 1 : b));
  else if (o.signature instanceof Uint8Array) signature = o.signature;
  const response = cat(respNoSig, signature);
  const evidence = cat(request, response, o.trailing ?? new Uint8Array(0));
  const recordsOff = SPDM.REQ_LEN + 8;
  const responderNonceOff = recordsOff + records.length;
  const opaqueLenOff = responderNonceOff + 32;
  const opaqueOff = opaqueLenOff + 2;
  return {
    evidence,
    request,
    response,
    signedBytes,
    signature,
    layout: { responseOff: SPDM.REQ_LEN, recordsOff, recordsLen: records.length, responderNonceOff, opaqueLenOff, opaqueOff, opaqueLen: opaque.length, sigOff: opaqueOff + opaque.length, opaqueTlvOff: Object.fromEntries(Object.entries(tlvOff).map(([k, v]) => [k, opaqueOff + v])) },
    measurements: list.map((m) => ({ index: m.index, digest: m.digest })),
  };
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// OCSP (RFC 6960), hand-encoded
// ═══════════════════════════════════════════════════════════════════════════════════════════════

const HASH_OID: Readonly<Record<'sha1' | 'sha256' | 'sha384' | 'sha512', string>> = { sha1: '1.3.14.3.2.26', sha256: '2.16.840.1.101.3.4.2.1', sha384: '2.16.840.1.101.3.4.2.2', sha512: '2.16.840.1.101.3.4.2.3' };

export interface ForgeOcspOptions {
  /** The certificate the response speaks for and its issuer. */
  cert: ForgedCert;
  issuer: ForgedCert;
  status?: 'good' | 'revoked' | 'unknown';
  revokedAt?: Date;
  reason?: number;
  thisUpdate: Date;
  nextUpdate?: Date;
  producedAt?: Date;
  /** Who signs: the issuer itself or a delegated responder certificate (embedded in the response). */
  responder?: { kind: 'issuer' } | { kind: 'delegated'; cert: ForgedCert; embed?: boolean };
  /** Embed exactly these certificates instead of the responder's own (responderID / embedded-cert mismatch cases). */
  embedCerts?: readonly ForgedCert[];
  responderId?: 'name' | 'key';
  /** Signing key (default: the responder certificate's key / the issuer's key). */
  signer?: ForgeKey;
  certIdHash?: 'sha1' | 'sha256' | 'sha384' | 'sha512';
  nonce?: Uint8Array;
  /** OCSPResponse.responseStatus (0 = successful). */
  responseStatus?: number;
  /** Serial number to put in the CertID instead of `cert`'s. */
  serialOverride?: Uint8Array;
  /** Extra single responses for the same CertID (ambiguity). */
  duplicate?: boolean;
  responseType?: string;
  /** Trailing garbage after the DER response. */
  trailing?: Uint8Array;
}

/** Forge an OCSP responder certificate (delegated, EKU id-kp-OCSPSigning) issued by `issuer`. */
export function forgeOcspResponderCert(issuer: ForgedCert, issuerKey: ForgeKey, o: { seed?: string; eku?: readonly string[] | null; notBefore?: Date; notAfter?: Date; cn?: string } = {}): ForgedCert {
  const key = forgeKey(`${o.seed ?? 'ocsp-responder'}/key`, 'P-384');
  return forgeCert({
    subject: [['CN', o.cn ?? 'NVIDIA OCSP Responder'], ['O', 'NVIDIA Corporation'], ['C', 'US']],
    issuer: issuer.subject,
    subjectKey: key,
    signer: issuerKey,
    serial: serialFor(`${o.seed ?? 'ocsp-responder'}/serial`),
    notBefore: o.notBefore ?? new Date('2025-01-01T00:00:00Z'),
    notAfter: o.notAfter ?? new Date('2035-01-01T00:00:00Z'),
    sigDigest: 'sha384',
    extensions: [extension('2.5.29.19', false, seq()), ext.keyUsage(['digitalSignature']), ...(o.eku === null ? [] : [ext.extKeyUsage(o.eku ?? ['1.3.6.1.5.5.7.3.9'], true)]), ext.subjectKeyId(key), ext.authorityKeyId(issuerKey)],
  });
}

export function forgeOcspResponse(o: ForgeOcspOptions): Uint8Array {
  const hashName = o.certIdHash ?? 'sha384';
  const issuerNameHash = digest(hashName, dn(o.issuer.subject));
  const issuerKeyHash = digest(hashName, o.issuer.key.pub);
  const serial = o.serialOverride ?? hexToBytes(o.cert.serialHex.length % 2 ? `0${o.cert.serialHex}` : o.cert.serialHex);
  const certId = seq(seq(oid(HASH_OID[hashName]), nul()), octets(issuerNameHash), octets(issuerKeyHash), integer(serial));
  const st = o.status ?? 'good';
  const certStatus =
    st === 'good'
      ? Uint8Array.of(0x80, 0x00)
      : st === 'unknown'
        ? Uint8Array.of(0x82, 0x00)
        : tlv(0xa1, generalizedTime(o.revokedAt ?? new Date(o.thisUpdate.getTime() - 3600_000)), ...(o.reason !== undefined ? [ctx(0, enumerated(o.reason))] : []));
  const single = seq(certId, certStatus, generalizedTime(o.thisUpdate), ...(o.nextUpdate ? [ctx(0, generalizedTime(o.nextUpdate))] : []));

  const responder = o.responder ?? { kind: 'issuer' as const };
  const rCert = responder.kind === 'issuer' ? o.issuer : responder.cert;
  const signKey = o.signer ?? rCert.key;
  const rid = (o.responderId ?? (responder.kind === 'delegated' ? 'key' : 'name')) === 'key' ? ctx(2, octets(digest('sha1', rCert.key.pub))) : ctx(1, dn(rCert.subject));
  const exts = o.nonce ? [ctx(1, seq(extension('1.3.6.1.5.5.7.48.1.2', false, octets(o.nonce))))] : [];
  const tbs = seq(rid, generalizedTime(o.producedAt ?? o.thisUpdate), seq(single, ...(o.duplicate ? [single] : [])), ...exts);
  const sigAlg = seq(oid('1.2.840.10045.4.3.3'));
  const sig = ecdsaSign(signKey, 'sha384', tbs).der;
  const embedList = o.embedCerts ?? (responder.kind === 'delegated' && responder.embed !== false ? [responder.cert] : []);
  const embed = embedList.length > 0 ? [ctx(0, seq(...embedList.map((c) => c.der)))] : [];
  const basic = seq(tbs, sigAlg, bitString(sig), ...embed);
  const body = tlv(0xa0, seq(oid(o.responseType ?? '1.3.6.1.5.5.7.48.1.1'), octets(basic)));
  const status = o.responseStatus ?? 0;
  return cat(seq(enumerated(status), ...(status === 0 ? [body] : [])), o.trailing ?? new Uint8Array(0));
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// RIM (SWID) with enveloped XMLDSig / C14N 1.1 / ECDSA-SHA384
// ═══════════════════════════════════════════════════════════════════════════════════════════════

const NS_DSIG = 'http://www.w3.org/2000/09/xmldsig#';
const NS_SWID = 'http://standards.iso.org/iso/19770/-2/2015/schema.xsd';
export const RIM_ALG = {
  C14N11: 'http://www.w3.org/2006/12/xml-c14n11',
  ENVELOPED: 'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
  ECDSA384: 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384',
  SHA384: 'http://www.w3.org/2001/04/xmldsig-more#sha384',
} as const;

export interface RimMeasurementSpec {
  index: number;
  active: boolean;
  /** Lowercase hex digest alternatives (`Hash0`, `Hash1`, …). */
  hashes: readonly string[];
  size?: number;
  alternatives?: number;
  name?: string;
  /** Raw attribute text to splice into the Resource element (malformed-attribute cases). */
  rawAttrs?: string;
  /** Replace the `type` attribute (default "Measurement"). */
  type?: string;
}

export interface ForgeRimOptions {
  tagId?: string;
  product?: string;
  /** `colloquialVersion` (driver `595.71.05` / VBIOS `96.00.9F.00.04`). */
  version: string;
  measurements: readonly RimMeasurementSpec[];
  /** Signer certificates, leaf first, placed in KeyInfo/X509Data. */
  signerChain: readonly ForgedCert[];
  signerKey: ForgeKey;
  // ── structural / algorithm variants (all still carry a valid signature unless noted) ──
  rootName?: string;
  c14nUri?: string;
  sigMethodUri?: string;
  digestMethodUri?: string;
  transforms?: readonly string[];
  referenceUri?: string;
  extraReference?: boolean;
  doctype?: boolean;
  comment?: boolean;
  processingInstruction?: boolean;
  xmlAttrOnPayload?: boolean;
  /** Add a second Signature: `'sibling'` (direct child) or `'nested'` (inside Payload). */
  extraSignature?: 'sibling' | 'nested';
  omitMeta?: boolean;
  omitPayload?: boolean;
  omitKeyInfo?: boolean;
  omitDigestValue?: boolean;
  omitSignatureValue?: boolean;
  /** Replace the signature bytes with this many random-looking bytes (default 96). */
  signatureBytes?: number;
  /** Put the Signature element inside a wrapper element instead of directly under the root. */
  wrapSignature?: boolean;
  /** Use this DigestValue instead of the correct one. */
  digestOverride?: string;
  /** Sign SignedInfo with this key instead of `signerKey` (SignatureValue will not verify under the leaf). */
  signWith?: ForgeKey;
}

const escAttr = (s: string) => s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');

function resource(m: RimMeasurementSpec): string {
  const hashes = m.hashes.map((h, k) => `ns2:Hash${k}="${h}"`).join(' ');
  return `        <ns0:Resource type="${m.type ?? 'Measurement'}" index="${m.index}" active="${m.active ? 'True' : 'False'}" alternatives="${m.alternatives ?? m.hashes.length}" ${hashes} name="${escAttr(m.name ?? `Measurement_${m.index}`)}" size="${m.size ?? (m.hashes[0] ?? '').length / 2}"${m.rawAttrs ? ` ${m.rawAttrs}` : ''}/>`;
}

type XmlEl = {
  tagName: string;
  localName: string;
  namespaceURI: string | null;
  attributes: { length: number; item(i: number): { name: string; value: string } | null };
  parentNode: unknown;
  childNodes: { length: number; item(i: number): unknown };
  getElementsByTagNameNS(ns: string, local: string): { length: number; item(i: number): XmlEl | null };
  removeChild(c: unknown): unknown;
};

function parseXml(xml: string): { documentElement: XmlEl } {
  const raise = (m: string) => {
    throw new Error(m);
  };
  return new DOMParser({ errorHandler: { warning: () => undefined, error: raise, fatalError: raise } }).parseFromString(xml, 'text/xml') as unknown as { documentElement: XmlEl };
}

function ancestorNamespaces(node: XmlEl): { prefix: string; namespaceURI: string }[] {
  const seen = new Set<string>();
  const out: { prefix: string; namespaceURI: string }[] = [];
  for (let p = node.parentNode as XmlEl | null; p && (p as { nodeType?: number }).nodeType === 1; p = p.parentNode as XmlEl | null) {
    for (let i = 0; i < p.attributes.length; i++) {
      const a = p.attributes.item(i)!;
      const prefix = a.name === 'xmlns' ? '' : a.name.startsWith('xmlns:') ? a.name.slice(6) : undefined;
      if (prefix === undefined || seen.has(prefix)) continue;
      seen.add(prefix);
      out.push({ prefix, namespaceURI: a.value });
    }
  }
  return out;
}

/** base64(SHA-384(C14N(document minus its Signature))) — the enveloped-signature digest, as the verifier computes it. */
export function rimDigestB64(xml: string): string {
  const doc = parseXml(xml);
  const root = doc.documentElement;
  const sig = root.getElementsByTagNameNS(NS_DSIG, 'Signature').item(0);
  if (sig) root.removeChild(sig);
  const canon = new C14nCanonicalization().process(root as never, { ancestorNamespaces: [] } as never);
  return Buffer.from(digest('sha384', new TextEncoder().encode(canon))).toString('base64');
}

/** The canonical bytes of SignedInfo "in context" (ancestor namespace declarations in scope) — what is signed. */
export function rimSignedInfoCanonical(xml: string): string {
  const doc = parseXml(xml);
  const si = doc.documentElement.getElementsByTagNameNS(NS_DSIG, 'SignedInfo').item(0);
  if (!si) throw new Error('no SignedInfo');
  return new C14nCanonicalization().process(si as never, { ancestorNamespaces: ancestorNamespaces(si) } as never);
}

export function forgeRim(o: ForgeRimOptions): string {
  const root = o.rootName ?? 'SoftwareIdentity';
  const product = o.product ?? 'GH100';
  const tagId = o.tagId ?? bytesToHex(fill(`rim/${o.version}`, 48));
  const transforms = o.transforms ?? [RIM_ALG.ENVELOPED, RIM_ALG.C14N11];
  const resources = o.measurements.map(resource).join('\n');
  const meta = o.omitMeta
    ? ''
    : `    <ns0:Meta xmlns:ns1="https://trustedcomputinggroup.org/resource/tcg-reference-integrity-manifest-rim-information-model/" colloquialVersion="${escAttr(o.version)}" edition="GPU" product="${product}" revision="r1" PayloadType="direct" ns1:BindingSpec="RIMIM" ns1:BindingSpecVersion="1.01" ns1:PlatformManufacturerId="5703" ns1:PlatformManufacturerStr="NVIDIA Corporation" ns1:PlatformModel="${product}" ns1:FirmwareManufacturer="NVIDIA Corporation" ns1:FirmwareManufacturerId="5703"/>\n`;
  const nestedSig = o.extraSignature === 'nested' ? `        <ds:Signature xmlns:ds="${NS_DSIG}"><ds:SignedInfo/></ds:Signature>\n` : '';
  const payload = o.omitPayload
    ? ''
    : `    <ns0:Payload xmlns:SHA384="http://www.w3.org/2001/04/xmlenc#sha384"${o.xmlAttrOnPayload ? ' xml:space="preserve"' : ''}>\n${o.comment ? '        <!-- a comment -->\n' : ''}${resources}\n${nestedSig}    </ns0:Payload>\n`;
  const certs = o.signerChain.map((c) => `<ds:X509Certificate>${b64(c.der)}</ds:X509Certificate>`).join('');
  const keyInfo = o.omitKeyInfo ? '' : `<ds:KeyInfo><ds:X509Data>${certs}</ds:X509Data></ds:KeyInfo>`;

  const sigXml = (digestB64: string, sigB64: string): string => {
    const signedInfo =
      `<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="${o.c14nUri ?? RIM_ALG.C14N11}"/><ds:SignatureMethod Algorithm="${o.sigMethodUri ?? RIM_ALG.ECDSA384}"/>` +
      `<ds:Reference URI="${o.referenceUri ?? ''}"><ds:Transforms>${transforms.map((t) => `<ds:Transform Algorithm="${t}"/>`).join('')}</ds:Transforms><ds:DigestMethod Algorithm="${o.digestMethodUri ?? RIM_ALG.SHA384}"/>${o.omitDigestValue ? '' : `<ds:DigestValue>${digestB64}</ds:DigestValue>`}</ds:Reference>` +
      `${o.extraReference ? `<ds:Reference URI="#other"><ds:DigestMethod Algorithm="${RIM_ALG.SHA384}"/><ds:DigestValue>${digestB64}</ds:DigestValue></ds:Reference>` : ''}</ds:SignedInfo>`;
    const sigEl = `<ds:Signature xmlns:ds="${NS_DSIG}">${signedInfo}${o.omitSignatureValue ? '' : `<ds:SignatureValue>${sigB64}</ds:SignatureValue>`}${keyInfo}</ds:Signature>`;
    const second = o.extraSignature === 'sibling' ? `<ds:Signature xmlns:ds="${NS_DSIG}"><ds:SignedInfo/></ds:Signature>` : '';
    return o.wrapSignature ? `<ns0:Wrapper>${sigEl}</ns0:Wrapper>${second}` : sigEl + second;
  };
  const head = `${o.doctype ? '<!DOCTYPE SoftwareIdentity [<!ENTITY e "x">]>\n' : ''}${o.processingInstruction ? '<?pi data?>\n' : ''}`;
  const build = (d: string, s: string) =>
    `${head}<${root} xmlns="${NS_SWID}" xmlns:ns0="${NS_SWID}" xmlns:ns2="http://www.w3.org/2001/04/xmlenc#sha384" corpus="false" name="${product}" patch="false" supplemental="false" tagId="${tagId}" version="1.0" tagVersion="0">\n    <ns0:Entity name="NVIDIA Corporation" role="softwareCreator tagCreator"/>\n${meta}${payload}${sigXml(d, s)}</${root}>\n`;

  // 1) digest of the document minus Signature, 2) sign canonical SignedInfo (in context), 3) assemble
  const digestB64 = o.digestOverride ?? rimDigestB64(build('', ''));
  const withDigest = build(digestB64, '');
  const canon = rimSignedInfoCanonical(withDigest);
  const sigKey = o.signWith ?? o.signerKey;
  let sigRaw = ecdsaSign(sigKey, 'sha384', new TextEncoder().encode(canon)).raw;
  if (o.signatureBytes !== undefined) sigRaw = fill('sigbytes', o.signatureBytes);
  return build(digestB64, b64(sigRaw));
}

/** The test CoRIM signing PKI: Root CA → Reference Value GH100 CA → L3 → RIM signer (CA:FALSE leaf), real names. */
export interface CorimPki {
  keys: ForgeKey[];
  /** Leaf first. */
  certs: ForgedCert[];
  signerKey: ForgeKey;
  rootSpkiSha256: string;
}
export function forgeCorimPki(o: { seed?: string; leafValidity?: readonly [Date, Date]; override?: Partial<Record<0 | 1 | 2 | 3, ChainCertOverride>> } = {}): CorimPki {
  const seed = o.seed ?? 'corim-pki';
  const names: (readonly DnAttr[])[] = [
    [['C', 'US'], ['ST', 'CA'], ['L', 'Santa Clara'], ['O', 'NVIDIA Corporation'], ['CN', 'HCC RIM L4 Signer']],
    [['C', 'US'], ['O', 'NVIDIA'], ['CN', 'NVIDIA Reference Value L3 GH100 003']],
    [['CN', 'NVIDIA Reference Value GH100 CA'], ['O', 'NVIDIA Corporation'], ['C', 'US']],
    [['C', 'US'], ['O', 'NVIDIA'], ['CN', 'NVIDIA CoRIM signing Root CA']],
  ];
  const ov = (i: number): ChainCertOverride => (o.override as Record<number, ChainCertOverride | undefined> | undefined)?.[i] ?? {};
  const keys = names.map((_, i) => forgeKey(`${seed}/k${i}`, ov(i).curve ?? 'P-384'));
  const validity: readonly (readonly [Date, Date])[] = [
    o.leafValidity ?? [new Date('2026-03-12T23:38:13Z'), new Date('2028-03-11T23:38:13Z')],
    [new Date('2025-11-07T00:00:00Z'), new Date('2035-11-07T23:59:59Z')],
    [new Date('2023-05-11T00:00:00Z'), new Date('2033-05-11T23:59:59Z')],
    [new Date('2023-03-16T15:37:34Z'), new Date('2053-03-08T15:37:34Z')],
  ];
  const certs = names.map((nm, i) => {
    const parent = Math.min(i + 1, 3);
    const ca = ov(i).ca ?? i > 0;
    return forgeCert({
      subject: ov(i).subject ?? nm,
      issuer: names[parent]!,
      subjectKey: keys[i]!,
      signer: ov(i).signedBy ?? keys[parent]!,
      serial: serialFor(`${seed}/s${i}`),
      notBefore: ov(i).notBefore ?? validity[i]![0],
      notAfter: ov(i).notAfter ?? validity[i]![1],
      sigDigest: 'sha384',
      extensions: [...(ca === 'absent' ? [] : [ext.basicConstraints(ca === true, i === 1 ? 0 : undefined)]), ext.keyUsage(i === 0 ? ['digitalSignature'] : ['keyCertSign', 'cRLSign']), ext.subjectKeyId(keys[i]!), ext.authorityKeyId(keys[parent]!)],
    });
  });
  return { keys, certs, signerKey: keys[0]!, rootSpkiSha256: keys[3]!.spkiSha256 };
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// A complete, self-consistent scenario
// ═══════════════════════════════════════════════════════════════════════════════════════════════

/** SPDM block `i` (1-based) is compared with RIM golden index `i-1`; NVDEC0 lives in block 35 (index 34). */
export const NVDEC_GOLDEN_INDEX = 34;

export interface ForgeScenarioOptions {
  seed?: string;
  challenge?: Uint8Array;
  driver?: string;
  vbiosRaw?: string;
  /** colloquialVersion strings the RIMs declare (default: derived from the report). */
  driverRimVersion?: string;
  vbiosRimVersion?: string;
  nvdec0?: number;
  /** SPDM digest overrides for the report (block index → digest). */
  reportDigests?: Record<number, Uint8Array>;
  /** Golden digest overrides for the RIMs (RIM index = block - 1 → hex). They replace the otherwise-matching golden value. */
  goldenOverride?: Record<number, string>;
  /** Golden indices that are active in the VBIOS RIM; the driver RIM owns `driverIndices`. */
  vbiosIndices?: readonly number[];
  driverIndices?: readonly number[];
  /** RIM entries to make inactive. */
  inactive?: readonly number[];
  device?: NvidiaDevicePkiOptions;
  corim?: Parameters<typeof forgeCorimPki>[0];
  rim?: Partial<Pick<ForgeRimOptions, 'comment' | 'doctype' | 'processingInstruction' | 'extraSignature' | 'wrapSignature'>>;
  spdm?: Partial<ForgeSpdmOptions>;
  opaque?: readonly (readonly [number, Uint8Array])[];
  now?: Date;
}

export interface ForgedNvidiaScenario {
  device: NvidiaDevicePki;
  corim: CorimPki;
  spdm: ForgedSpdm;
  evidence: { evidence: Uint8Array; certChainPem: string };
  driverRimXml: string;
  vbiosRimXml: string;
  driverId: string;
  vbiosId: string;
  /** CRLs: [Identity-issued (l2-gh100), root-issued (l1-root)], both empty. */
  crls: Uint8Array[];
  /** OCSP responses for chain certs 1..3, each GOOD, answered by the issuer itself (nonce-less). */
  ocsp: Uint8Array[];
  deviceRootSpkiSha256: string;
  rimRootSpkiSha256: string;
  nowMs: number;
  /** Re-sign a RIM with different measurements, keeping the scenario's signing PKI. */
  rim(version: string, measurements: readonly RimMeasurementSpec[], over?: Partial<ForgeRimOptions>): string;
}

export function forgeNvidiaScenario(o: ForgeScenarioOptions = {}): ForgedNvidiaScenario {
  const seed = o.seed ?? 'nvidia-scenario';
  const device = forgeNvidiaDevicePki({ seed: `${seed}/device`, ...(o.device ?? {}) });
  const corim = forgeCorimPki({ seed: `${seed}/corim`, ...(o.corim ?? {}) });
  const driver = o.driver ?? '595.71.05';
  const vbiosRaw = o.vbiosRaw ?? '009f009604000000';
  const opaque = o.opaque ?? defaultOpaque({ driver, vbiosRaw, ...(o.nvdec0 !== undefined ? { nvdec0: o.nvdec0 } : {}) });
  const spdm = forgeSpdmTranscript({ signer: device.leafKey, opaque, ...(o.challenge ? { challenge: o.challenge } : {}), ...(o.reportDigests ? { digests: o.reportDigests } : {}), ...(o.spdm ?? {}) });

  // RIM ids exactly as `nvidiaRimIdsForReport` derives them (the verifier computes them again from the report)
  const vbHex = Buffer.from(hexToBytes(vbiosRaw)).reverse().toString('hex');
  const half = vbHex.length / 2;
  const vbiosVersion = (vbHex.slice(half) + vbHex.slice(half - 2, half)).match(/.{1,2}/g)!.join('.');
  const driverId = `NV_GPU_DRIVER_GH100_${driver}`;
  const vbiosId = `NV_GPU_VBIOS_1010_0210_886_${vbiosVersion.replace(/\./g, '').toUpperCase()}`;

  const vbiosIdx = new Set(o.vbiosIndices ?? Array.from({ length: 12 }, (_, i) => i));
  const driverIdx = new Set(o.driverIndices ?? Array.from({ length: 23 }, (_, i) => i + 12));
  const inactive = new Set(o.inactive ?? []);
  const golden = (index: number): string => o.goldenOverride?.[index] ?? bytesToHex(spdm.measurements.find((m) => m.index === index + 1)?.digest ?? new Uint8Array(48));
  const specs = (idxSet: Set<number>): RimMeasurementSpec[] =>
    Array.from({ length: 64 }, (_, index) => ({ index, active: idxSet.has(index) && !inactive.has(index), hashes: [idxSet.has(index) ? golden(index) : '00'.repeat(48)], size: 48, name: `Measurement_${index}` }));

  const rim = (version: string, measurements: readonly RimMeasurementSpec[], over: Partial<ForgeRimOptions> = {}) =>
    forgeRim({ version, measurements, signerChain: corim.certs, signerKey: corim.signerKey, ...(o.rim ?? {}), ...over });
  const nowMs = (o.now ?? new Date('2026-10-20T00:00:00Z')).getTime();
  const issuedAt = new Date(nowMs - 86400_000);
  const nextAt = new Date(nowMs + 30 * 86400_000);

  return {
    device,
    corim,
    spdm,
    evidence: { evidence: spdm.evidence, certChainPem: device.chainPem },
    driverRimXml: rim(o.driverRimVersion ?? driver, specs(driverIdx)),
    vbiosRimXml: rim(o.vbiosRimVersion ?? vbiosVersion.toUpperCase(), specs(vbiosIdx)),
    driverId,
    vbiosId,
    crls: [forgeNvidiaCrl(device, 3), forgeNvidiaCrl(device, 4)],
    ocsp: [1, 2, 3].map((i) => forgeOcspResponse({ cert: device.certs[i]!, issuer: device.certs[i + 1]!, thisUpdate: issuedAt, nextUpdate: nextAt })),
    deviceRootSpkiSha256: device.rootSpkiSha256,
    rimRootSpkiSha256: corim.rootSpkiSha256,
    nowMs,
    rim,
  };
}

