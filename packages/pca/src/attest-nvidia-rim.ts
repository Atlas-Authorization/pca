/**
 * NVIDIA GPU-CC COLLATERAL — Reference Integrity Manifests (golden measurements) and certificate revocation.
 *
 * `attest-nvidia-spdm.ts` proves "a genuine NVIDIA GPU signed these measurements over our challenge". This
 * module answers "are those measurements the RIGHT ones?" by verifying NVIDIA's signed RIMs and comparing the
 * report against them, exactly as NVIDIA's own local verifier does, and checks the device chain against
 * NVIDIA's published CRLs.
 *
 * ── RIM (SWID/CoRIM XML, enveloped XMLDSig) ──────────────────────────────────────────────────────
 * Fetched from the NVIDIA RIM service by id: driver `NV_GPU_DRIVER_GH100_<driver version>` (Hopper) or `NV_GPU_CC_DRIVER_<chip>_<driver version>` (Blackwell) and VBIOS
 * `NV_GPU_VBIOS_<PROJECT>_<PROJECT_SKU>_<CHIP_SKU>_<VBIOS VERSION, dots removed, upper>` (both derived from the
 * signed opaque data in the GPU report, so the GPU itself names the RIMs it must match).
 * Verified here: strict XMLDSig profile (exactly one Signature, `Reference URI=""` with exactly the
 * enveloped-signature and C14N 1.1 transforms, SHA-384 digest, ECDSA-SHA384, no DTD / comments / PIs / `xml:*`
 * attributes), the digest over the canonicalized document minus the Signature, the ECDSA P-384 signature over
 * the canonicalized SignedInfo, and the embedded signer chain to the PINNED NVIDIA CoRIM signing root.
 * Golden values are read ONLY from the document that was just verified.
 *
 * Canonicalization uses the vetted `xml-crypto` C14N implementation (optional dependency, loaded lazily); hashing
 * and signature verification use `node:crypto`. C14N 1.1 differs from C14N 1.0 only in `xml:*` attribute
 * handling; this module rejects any `xml:*` attribute, so for accepted documents the two are identical.
 *
 * ── MEASUREMENT COMPARISON (NVIDIA's rules) ───────────────────────────────────────────────────────
 * Active measurements of the driver RIM and the VBIOS RIM are merged (the same index active in both is an error);
 * each golden index `i` is compared with SPDM block `i+1` and must equal one of the listed alternatives with the
 * declared size; block index 35 is skipped when the report's NVDEC0 status is DISABLED (0x55).
 *
 * ── REVOCATION ────────────────────────────────────────────────────────────────────────────────────
 * NVIDIA publishes CRLs for its device CAs (`crl.ndis.nvidia.com`). Supplied CRLs must verify under one of the
 * chain certificates and be fresh; no chain certificate may be listed; and the caller can require that specific
 * issuers are covered. NVIDIA's own verifier uses OCSP: that is `attest-nvidia-ocsp.ts` (vetted pkijs/asn1js,
 * optional + lazy) and `nvidiaCollateralHook({ revocation: 'ocsp' | 'both' })` runs it. Fetching is never
 * automatic: `fetchNvidiaRim` / `fetchNvidiaCrl` / `fetchNvidiaOcsp` are explicit, guarded helpers.
 */
import { createHash, verify as cryptoVerify, X509Certificate } from 'node:crypto';
import { verifyCrl, serialIsRevoked } from './attest-intel-collateral';
import { NVIDIA_OPAQUE, formatVbiosVersion, verifyNvidiaDeviceChain } from './attest-nvidia-spdm';
import type { NvidiaSpdmPostVerifyContext, ParsedNvidiaSpdmReport } from './attest-nvidia-spdm';

/** NVIDIA RIM service base URL (the default used by NVIDIA's local verifier). */
export const NVIDIA_RIM_BASE_URL = 'https://rim.attestation.nvidia.com/v1/rim/';
/** NVIDIA's published CRLs for the Hopper device-identity CAs. */
export const NVIDIA_GH100_CRL_URLS = ['https://crl.ndis.nvidia.com/crl/l2-gh100.crl', 'https://crl.ndis.nvidia.com/crl/l1-root.crl'] as const;
/** NVIDIA's published CRLs for the Blackwell (GB100) device-identity CAs (the L1 root CRL is shared with Hopper). */
export const NVIDIA_GB100_CRL_URLS = ['https://crl.ndis.nvidia.com/crl/l2-gb100.crl', 'https://crl.ndis.nvidia.com/crl/l1-root.crl'] as const;

const NS_DSIG = 'http://www.w3.org/2000/09/xmldsig#';
const ALG_C14N11 = 'http://www.w3.org/2006/12/xml-c14n11';
const ALG_ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
const ALG_ECDSA384 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384';
const ALG_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
const NVDEC0_DISABLED = 0x55;
const NVDEC_BLOCK_INDEX = 35;

export interface RimGoldenMeasurement {
  index: number;
  active: boolean;
  alternatives: number;
  size: number;
  /** Lowercase hex digests (one per alternative). */
  hashes: string[];
}

export interface VerifiedRim {
  tagId: string;
  /** Product / chip family, e.g. `GH100`. */
  product: string;
  /** `colloquialVersion` — driver version (`580.95.05`) or VBIOS version (`96.00.D0.00.03`). */
  version: string;
  golden: Map<number, RimGoldenMeasurement>;
  signerSubject: string;
}

export type RimResult = { ok: true; rim: VerifiedRim } | { ok: false; reason: string };

interface XmlNode {
  nodeType: number;
  nodeName: string;
  localName?: string;
  namespaceURI?: string | null;
  textContent?: string | null;
  attributes?: ArrayLike<{ name: string; value: string; localName?: string; namespaceURI?: string | null }>;
  childNodes: ArrayLike<XmlNode>;
  parentNode: XmlNode | null;
  getAttribute(name: string): string;
  removeChild(child: XmlNode): XmlNode;
  getElementsByTagNameNS(ns: string, local: string): ArrayLike<XmlNode>;
}

function children(n: XmlNode): XmlNode[] {
  return Array.from({ length: n.childNodes.length }, (_, i) => n.childNodes[i]!);
}
function elementChildren(n: XmlNode, ns?: string, local?: string): XmlNode[] {
  return children(n).filter((c) => c.nodeType === 1 && (ns === undefined || c.namespaceURI === ns) && (local === undefined || c.localName === local));
}
function attrs(n: XmlNode) {
  return Array.from({ length: n.attributes?.length ?? 0 }, (_, i) => n.attributes![i]!);
}

/** Reject anything outside the strict profile before any cryptography: DTD, comments, PIs, `xml:*` attrs. */
function assertStrictProfile(n: XmlNode): string | undefined {
  for (const c of children(n)) {
    if (c.nodeType === 8) return 'XML comments are not permitted';
    if (c.nodeType === 7) return 'XML processing instructions are not permitted';
    if (c.nodeType === 10) return 'DTD / DOCTYPE is not permitted';
    if (c.nodeType === 1) {
      for (const a of attrs(c)) if (a.name.toLowerCase().startsWith('xml:')) return `xml:* attribute '${a.name}' is not permitted (C14N 1.1 profile)`;
      const bad = assertStrictProfile(c);
      if (bad) return bad;
    }
  }
  return undefined;
}

/** In-scope namespace declarations inherited from the ancestors of `node` (nearest declaration wins). */
function ancestorNamespaces(node: XmlNode): { prefix: string; namespaceURI: string }[] {
  const seen = new Set<string>();
  const out: { prefix: string; namespaceURI: string }[] = [];
  for (let p = node.parentNode; p && p.nodeType === 1; p = p.parentNode) {
    for (const a of attrs(p)) {
      let prefix: string | undefined;
      if (a.name === 'xmlns') prefix = '';
      else if (a.name.startsWith('xmlns:')) prefix = a.name.slice(6);
      if (prefix === undefined || seen.has(prefix)) continue;
      seen.add(prefix);
      out.push({ prefix, namespaceURI: a.value });
    }
  }
  return out;
}

function pemOfDerB64(b64: string): string {
  const body = b64.replace(/\s+/g, '');
  return `-----BEGIN CERTIFICATE-----\n${body.match(/.{1,64}/g)?.join('\n') ?? ''}\n-----END CERTIFICATE-----`;
}

/**
 * Verify a RIM document (XML text) and return its golden measurements. Async only because the canonicalization
 * library is imported lazily. Fails closed with a reason on any deviation.
 */
export async function verifyNvidiaRim(xml: string, opts: { rimRootSpkiSha256: string[]; nowMs: number }): Promise<RimResult> {
  const fail = (reason: string): RimResult => ({ ok: false, reason });
  try {
    if (typeof xml !== 'string' || xml.length === 0 || xml.length > 4_000_000) return fail('RIM: empty or oversized document');
    if (!Array.isArray(opts.rimRootSpkiSha256) || opts.rimRootSpkiSha256.length === 0) return fail('RIM: no pinned RIM root configured');
    let xc: typeof import('xml-crypto');
    let xd: typeof import('@xmldom/xmldom');
    try {
      xc = await import('xml-crypto');
      xd = await import('@xmldom/xmldom');
    } catch {
      return fail('RIM verification needs the optional dependencies xml-crypto and @xmldom/xmldom (not installed)');
    }
    const raiseOnError = (m: string) => {
      throw new Error(m);
    };
    const doc = new xd.DOMParser({ errorHandler: { warning: () => undefined, error: raiseOnError, fatalError: raiseOnError } }).parseFromString(xml, 'text/xml') as unknown as {
      documentElement: XmlNode;
      childNodes: ArrayLike<XmlNode>;
    };
    const bad = assertStrictProfile(doc as unknown as XmlNode);
    if (bad) return fail(`RIM: ${bad}`);
    const root = doc.documentElement;
    if (root.localName !== 'SoftwareIdentity') return fail('RIM: root element is not SoftwareIdentity');

    // exactly one Signature in the whole document, as a direct child of the root
    if (root.getElementsByTagNameNS(NS_DSIG, 'Signature').length !== 1) return fail('RIM: expected exactly one Signature element');
    const sigs = elementChildren(root, NS_DSIG, 'Signature');
    if (sigs.length !== 1) return fail('RIM: the Signature must be a direct child of the root');
    const sig = sigs[0]!;

    const signedInfo = elementChildren(sig, NS_DSIG, 'SignedInfo');
    if (signedInfo.length !== 1) return fail('RIM: expected exactly one SignedInfo');
    const si = signedInfo[0]!;
    const algOf = (el: XmlNode | undefined) => el?.getAttribute('Algorithm');
    if (algOf(elementChildren(si, NS_DSIG, 'CanonicalizationMethod')[0]) !== ALG_C14N11) return fail('RIM: CanonicalizationMethod must be C14N 1.1');
    if (algOf(elementChildren(si, NS_DSIG, 'SignatureMethod')[0]) !== ALG_ECDSA384) return fail('RIM: SignatureMethod must be ECDSA-SHA384');
    const refs = elementChildren(si, NS_DSIG, 'Reference');
    if (refs.length !== 1) return fail('RIM: expected exactly one Reference');
    const ref = refs[0]!;
    if (ref.getAttribute('URI') !== '') return fail('RIM: Reference URI must be "" (the whole document)');
    const transforms = elementChildren(elementChildren(ref, NS_DSIG, 'Transforms')[0] ?? ref, NS_DSIG, 'Transform').map((t) => t.getAttribute('Algorithm'));
    if (transforms.length !== 2 || transforms[0] !== ALG_ENVELOPED || transforms[1] !== ALG_C14N11) return fail('RIM: transforms must be exactly [enveloped-signature, C14N 1.1]');
    if (algOf(elementChildren(ref, NS_DSIG, 'DigestMethod')[0]) !== ALG_SHA384) return fail('RIM: DigestMethod must be SHA-384');
    const digestValue = elementChildren(ref, NS_DSIG, 'DigestValue')[0]?.textContent?.replace(/\s+/g, '');
    const sigValueB64 = elementChildren(sig, NS_DSIG, 'SignatureValue')[0]?.textContent?.replace(/\s+/g, '');
    if (!digestValue || !sigValueB64) return fail('RIM: missing DigestValue / SignatureValue');

    // signer chain (leaf first) → pinned NVIDIA CoRIM signing root
    const keyInfo = elementChildren(sig, NS_DSIG, 'KeyInfo')[0];
    const x509Data = keyInfo ? elementChildren(keyInfo, NS_DSIG, 'X509Data')[0] : undefined;
    const certB64 = x509Data ? elementChildren(x509Data, NS_DSIG, 'X509Certificate').map((c) => c.textContent ?? '') : [];
    if (certB64.length === 0) return fail('RIM: no signer certificates in KeyInfo');
    const chain = verifyNvidiaDeviceChain(certB64.map(pemOfDerB64).join('\n'), opts.rimRootSpkiSha256, opts.nowMs);
    if (!chain.ok) return fail(`RIM signer chain: ${chain.reason}`);

    // SignedInfo is canonicalized IN CONTEXT (before the enveloped Signature is removed)
    const c14n = new xc.C14nCanonicalization();
    const siCanon = c14n.process(si as never, { ancestorNamespaces: ancestorNamespaces(si) } as never);
    const sigRaw = Buffer.from(sigValueB64, 'base64');
    if (sigRaw.length !== 96) return fail('RIM: SignatureValue is not a 96-byte P-384 signature');
    if (!cryptoVerify('sha384', Buffer.from(siCanon, 'utf8'), { key: chain.leaf.publicKey, dsaEncoding: 'ieee-p1363' }, sigRaw)) {
      return fail('RIM: SignedInfo signature does not verify under the signer certificate');
    }

    // enveloped-signature transform, then digest the canonicalized remainder
    root.removeChild(sig);
    const canon = new xc.C14nCanonicalization().process(root as never, { ancestorNamespaces: [] } as never);
    if (createHash('sha384').update(canon, 'utf8').digest('base64') !== digestValue) return fail('RIM: document digest does not match the signed DigestValue');

    // ── extraction, from the verified tree only ──
    const meta = children(root).find((c) => c.nodeType === 1 && c.localName === 'Meta');
    const payload = children(root).find((c) => c.nodeType === 1 && c.localName === 'Payload');
    if (!meta || !payload) return fail('RIM: missing Meta / Payload');
    const golden = new Map<number, RimGoldenMeasurement>();
    for (const r of elementChildren(payload)) {
      if (r.localName !== 'Resource' || r.getAttribute('type') !== 'Measurement') continue;
      const index = Number(r.getAttribute('index'));
      const alternatives = Number(r.getAttribute('alternatives'));
      const size = Number(r.getAttribute('size'));
      const hashes = attrs(r)
        .filter((a) => /^Hash\d+$/.test(a.localName ?? a.name.split(':').pop() ?? ''))
        .sort((a, b) => Number((a.localName ?? a.name).slice(4)) - Number((b.localName ?? b.name).slice(4)))
        .map((a) => a.value.toLowerCase());
      if (!Number.isInteger(index) || index < 0 || !Number.isInteger(alternatives) || alternatives < 1 || !Number.isInteger(size) || size < 1) return fail('RIM: malformed Measurement resource');
      if (hashes.length !== alternatives || hashes.some((h) => !/^[0-9a-f]+$/.test(h) || h.length !== size * 2)) return fail(`RIM: Measurement ${index} hash list is inconsistent with alternatives/size`);
      if (golden.has(index)) return fail(`RIM: duplicate Measurement index ${index}`);
      golden.set(index, { index, active: r.getAttribute('active').toLowerCase() === 'true', alternatives, size, hashes });
    }
    if (golden.size === 0) return fail('RIM: no measurements');
    return {
      ok: true,
      rim: {
        tagId: root.getAttribute('tagId'),
        product: meta.getAttribute('product'),
        version: meta.getAttribute('colloquialVersion'),
        golden,
        signerSubject: chain.leaf.subject.replace(/\n/g, ', '),
      },
    };
  } catch (e) {
    return fail(`RIM: verification error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`);
  }
}

// ── RIM ids derived from the (signed) GPU report ────────────────────────────────────────────────

const ascii = (b: Uint8Array | undefined) => Buffer.from(b ?? []).toString('latin1').replace(/\0+$/g, '').trim();

export { formatVbiosVersion };

export interface NvidiaRimIds {
  /** Chip family the GPU reports about itself (`GH100` Hopper, `GB100` Blackwell, ...). */
  chip: string;
  driver: string;
  vbios: string;
  driverVersion: string;
  vbiosVersion: string;
}

/**
 * The RIM ids this report requires (read from the GPU's own signed opaque data).
 *
 * Hopper reports carry no CHIP_INFO (opaque field 35): chip `GH100`, driver RIM `NV_GPU_DRIVER_GH100_<ver>`.
 * Blackwell reports carry it (`GB100`): driver RIM `NV_GPU_CC_DRIVER_<chip>_<ver>`. Fetching the Hopper-style id
 * for a Blackwell GPU SUCCEEDS and returns a validly signed but WRONG manifest, so {@link nvidiaCollateralHook}
 * additionally requires each verified RIM's `product` to equal `chip`. A present-but-malformed CHIP_INFO yields
 * `undefined` (fail closed).
 */
export function nvidiaRimIdsForReport(report: ParsedNvidiaSpdmReport): NvidiaRimIds | undefined {
  const o = report.response.opaque;
  const driverVersion = ascii(o.get(NVIDIA_OPAQUE.DRIVER_VERSION));
  const vb = o.get(NVIDIA_OPAQUE.VBIOS_VERSION);
  const project = ascii(o.get(17)).toUpperCase();
  const projectSku = ascii(o.get(18)).toUpperCase();
  const chipSku = ascii(o.get(15)).toUpperCase();
  if (!driverVersion || !vb || !project || !projectSku || !chipSku) return undefined;
  const chipRaw = o.get(NVIDIA_OPAQUE.CHIP_INFO);
  let chip = 'GH100';
  if (chipRaw !== undefined) {
    chip = ascii(chipRaw); // verbatim: the GPU's own spelling, no case folding
    if (!/^[A-Z][A-Z0-9]{2,11}$/.test(chip)) return undefined;
  }
  const vbiosVersion = formatVbiosVersion(vb);
  return {
    chip,
    driver: chip === 'GH100' ? `NV_GPU_DRIVER_GH100_${driverVersion}` : `NV_GPU_CC_DRIVER_${chip}_${driverVersion}`,
    vbios: `NV_GPU_VBIOS_${project}_${projectSku}_${chipSku}_${vbiosVersion.replace(/\./g, '').toUpperCase()}`,
    driverVersion,
    vbiosVersion,
  };
}

// ── comparison ──────────────────────────────────────────────────────────────────────────────────

export type RimCompareResult = { ok: true; checked: number } | { ok: false; reason: string; mismatches?: { index: number; source: 'driver' | 'vbios' }[] };

/** Compare a report with the driver + VBIOS RIMs using NVIDIA's merge / alternatives / NVDEC0 rules. */
export function compareReportToRims(report: ParsedNvidiaSpdmReport, driver: VerifiedRim, vbios: VerifiedRim): RimCompareResult {
  const merged = new Map<number, { g: RimGoldenMeasurement; source: 'driver' | 'vbios' }>();
  for (const g of driver.golden.values()) if (g.active) merged.set(g.index, { g, source: 'driver' });
  for (const g of vbios.golden.values()) {
    if (!g.active) continue;
    if (merged.has(g.index)) return { ok: false, reason: `driver and VBIOS RIMs both have an active measurement at index ${g.index}` };
    merged.set(g.index, { g, source: 'vbios' });
  }
  if (merged.size === 0) return { ok: false, reason: 'RIMs carry no active golden measurements' };
  const runtime = new Map(report.response.measurements.map((m) => [m.index - 1, m.digest] as const));
  if (merged.size > runtime.size) return { ok: false, reason: 'RIMs list more active measurements than the report carries' };
  const nvdec = report.response.opaque.get(11);
  const nvdecDisabled = nvdec !== undefined && nvdec.length > 0 && nvdec[0] === NVDEC0_DISABLED;
  const mismatches: { index: number; source: 'driver' | 'vbios' }[] = [];
  let checked = 0;
  for (const [index, { g, source }] of [...merged.entries()].sort((a, b) => a[0] - b[0])) {
    if (index + 1 === NVDEC_BLOCK_INDEX && nvdecDisabled) continue;
    const digest = runtime.get(index);
    const hex = digest ? Buffer.from(digest).toString('hex') : '';
    checked++;
    if (!digest || digest.length !== g.size || !g.hashes.includes(hex)) mismatches.push({ index, source });
  }
  if (mismatches.length > 0) return { ok: false, reason: `runtime measurements differ from the golden RIM values at ${mismatches.length} index(es)`, mismatches };
  return { ok: true, checked };
}

// ── revocation ──────────────────────────────────────────────────────────────────────────────────

export type RevocationResult = { ok: true; verifiedCrls: number } | { ok: false; reason: string };

/**
 * Check the device chain against CRLs. Every supplied CRL must verify under one chain certificate's key and be
 * fresh; no chain certificate (other than the self-signed root) may appear on a CRL issued by its issuer;
 * `requireIssuers` demands that a verified CRL issued by a chain cert whose subject contains each string exists.
 */
export function checkNvidiaChainRevocation(chain: X509Certificate[], crls: Uint8Array[], nowMs: number, requireIssuers: string[] = []): RevocationResult {
  if (crls.length === 0) return { ok: false, reason: 'no CRLs supplied' };
  const now = new Date(nowMs);
  const covered = new Set<number>();
  for (const [ci, crl] of crls.entries()) {
    let issuerIdx = -1;
    let revoked: ReadonlySet<string> | undefined;
    let lastReason = 'no chain certificate verifies it';
    for (const [i, cert] of chain.entries()) {
      const r = verifyCrl(crl, cert.publicKey, now);
      if (r.ok) {
        issuerIdx = i;
        revoked = r.revoked;
        break;
      }
      // keep the most informative failure: a CRL that verifies under its issuer but is stale / not yet valid must not be
      // reported as "signature does not verify" merely because a LATER chain certificate (wrong key) was tried last
      if (lastReason === 'no chain certificate verifies it' || lastReason.includes('signature does not verify')) lastReason = r.reason;
    }
    if (issuerIdx < 0 || !revoked) return { ok: false, reason: `CRL #${ci} rejected: ${lastReason}` };
    covered.add(issuerIdx);
    // certificates issued by this CRL's issuer are the ones it can revoke
    for (let i = 0; i < chain.length - 1; i++) {
      if (i + 1 === issuerIdx && serialIsRevoked(revoked, chain[i]!.serialNumber)) {
        return { ok: false, reason: `chain certificate '${chain[i]!.subject.replace(/\n/g, ', ')}' is revoked` };
      }
    }
    // a CRL issued by the root also covers every chain cert directly issued by it (checked above by index)
  }
  for (const need of requireIssuers) {
    if (![...covered].some((i) => chain[i]!.subject.includes(need))) return { ok: false, reason: `no verified CRL issued by a certificate matching '${need}'` };
  }
  return { ok: true, verifiedCrls: crls.length };
}

// ── glue: a postVerify hook for createNvidiaSpdmVerifier ────────────────────────────────────────

export interface NvidiaCollateralBundle {
  driverRimXml: string;
  vbiosRimXml: string;
  crls?: Uint8Array[];
  /** DER OCSP responses for the chain certificates (see `attest-nvidia-ocsp.ts`). */
  ocsp?: Uint8Array[];
}

export interface NvidiaCollateralOptions {
  /** Pinned NVIDIA CoRIM signing root SPKI SHA-256 (hex). REQUIRED + non-empty. */
  rimRootSpkiSha256: string[];
  /** Supply the RIMs (and CRLs) for the ids the report names. Network fetching is the caller's business. */
  resolve: (ids: NvidiaRimIds) => NvidiaCollateralBundle | undefined | Promise<NvidiaCollateralBundle | undefined>;
  /**
   * Which revocation evidence is REQUIRED: `crl` (default), `ocsp`, or `both`. Evidence that is supplied but not
   * required is still enforced. OCSP is verified by `attest-nvidia-ocsp.ts` (optional pkijs dependency, lazy).
   */
  revocation?: 'crl' | 'ocsp' | 'both';
  /** Legacy switch: `false` makes CRLs optional (supplied ones are still enforced). Ignored when `revocation` is set. */
  requireCrls?: boolean;
  /** Issuer subject substrings that must have a verified CRL (default: none beyond `requireCrls`). */
  requireCrlIssuers?: string[];
  /** Firmware version floor / deny list, enforced on the versions the GPU itself reports (signed). */
  firmware?: NvidiaFirmwarePolicy;
}

export interface NvidiaFirmwarePolicy {
  /** Minimum driver version, dotted decimal (e.g. `580.95.05`). Compared numerically, component by component. */
  minDriverVersion?: string;
  /** Minimum VBIOS version, dotted hex byte pairs (e.g. `96.00.9f.00.04`), compared as unsigned hex components. */
  minVbiosVersion?: string;
  /** Driver versions that are never acceptable (known-vulnerable), exact dotted-decimal match after normalisation. */
  denyDriverVersions?: string[];
  /** VBIOS versions that are never acceptable, exact match after normalisation. */
  denyVbiosVersions?: string[];
}

/** Parse a dotted version into numeric components; `null` when malformed. */
function parseVersion(v: string, radix: 10 | 16): number[] | null {
  const pat = radix === 10 ? /^\d+(\.\d+)*$/ : /^[0-9a-fA-F]{1,4}(\.[0-9a-fA-F]{1,4})*$/;
  if (typeof v !== 'string' || !pat.test(v)) return null;
  return v.split('.').map((x) => parseInt(x, radix));
}
function cmpVersion(a: number[], b: number[]): number {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

/** Validate a firmware policy at construction (throws on malformed versions) and return the checker. */
function compileFirmwarePolicy(fw: NvidiaFirmwarePolicy | undefined): (ids: NvidiaRimIds) => string | undefined {
  if (!fw) return () => undefined;
  const need = (v: string, radix: 10 | 16, what: string): number[] => {
    const p = parseVersion(v, radix);
    if (!p) throw new TypeError(`nvidiaCollateralHook: malformed ${what} '${v}'`);
    return p;
  };
  const minD = fw.minDriverVersion ? need(fw.minDriverVersion, 10, 'minDriverVersion') : undefined;
  const minV = fw.minVbiosVersion ? need(fw.minVbiosVersion, 16, 'minVbiosVersion') : undefined;
  const denyD = (fw.denyDriverVersions ?? []).map((v) => need(v, 10, 'denyDriverVersions entry'));
  const denyV = (fw.denyVbiosVersions ?? []).map((v) => need(v, 16, 'denyVbiosVersions entry'));
  return (ids) => {
    const d = parseVersion(ids.driverVersion, 10);
    const v = parseVersion(ids.vbiosVersion, 16);
    if (!d) return `driver version '${ids.driverVersion}' in the GPU report is not parseable`;
    if (!v) return `VBIOS version '${ids.vbiosVersion}' in the GPU report is not parseable`;
    if (minD && cmpVersion(d, minD) < 0) return `driver ${ids.driverVersion} is below the minimum ${fw.minDriverVersion}`;
    if (minV && cmpVersion(v, minV) < 0) return `VBIOS ${ids.vbiosVersion} is below the minimum ${fw.minVbiosVersion}`;
    if (denyD.some((x) => cmpVersion(d, x) === 0)) return `driver ${ids.driverVersion} is on the deny list`;
    if (denyV.some((x) => cmpVersion(v, x) === 0)) return `VBIOS ${ids.vbiosVersion} is on the deny list`;
    return undefined;
  };
}

/** Build a `postVerify` hook: RIM signature + golden comparison + driver/VBIOS version binding + revocation. */
export function nvidiaCollateralHook(opts: NvidiaCollateralOptions): (ctx: NvidiaSpdmPostVerifyContext) => Promise<string | undefined> {
  if (!Array.isArray(opts?.rimRootSpkiSha256) || opts.rimRootSpkiSha256.length === 0) throw new TypeError('nvidiaCollateralHook: rimRootSpkiSha256 must pin at least one root');
  const firmwareCheck = compileFirmwarePolicy(opts.firmware);
  return async (ctx) => {
    const ids = nvidiaRimIdsForReport(ctx.report);
    if (!ids) return 'GPU report does not carry the opaque fields needed to name its RIMs';
    // the device identity must be of the chip family the (signed) report names — before any collateral is fetched
    if (!new RegExp(`(^|[^A-Za-z0-9])${ids.chip}([^A-Za-z0-9]|$)`).test(ctx.leaf.subject)) {
      return `device leaf subject '${ctx.leaf.subject.replace(/\n/g, ', ')}' is not a ${ids.chip} device certificate (chip family mismatch)`;
    }
    const fwWhy = firmwareCheck(ids);
    if (fwWhy) return `firmware policy: ${fwWhy}`;
    const bundle = await opts.resolve(ids);
    if (!bundle) return 'no RIM collateral supplied for this report';
    const [d, v] = await Promise.all([
      verifyNvidiaRim(bundle.driverRimXml, { rimRootSpkiSha256: opts.rimRootSpkiSha256, nowMs: ctx.nowMs }),
      verifyNvidiaRim(bundle.vbiosRimXml, { rimRootSpkiSha256: opts.rimRootSpkiSha256, nowMs: ctx.nowMs }),
    ]);
    if (!d.ok) return `driver RIM: ${d.reason}`;
    if (!v.ok) return `VBIOS RIM: ${v.reason}`;
    if (d.rim.product !== ids.chip) return `driver RIM product '${d.rim.product}' does not match the GPU chip '${ids.chip}' (wrong-family manifest)`;
    if (v.rim.product !== ids.chip) return `VBIOS RIM product '${v.rim.product}' does not match the GPU chip '${ids.chip}' (wrong-family manifest)`;
    if (d.rim.version !== ids.driverVersion) return `driver RIM version '${d.rim.version}' does not match the report's driver '${ids.driverVersion}'`;
    if (v.rim.version.replace(/\./g, '').toUpperCase() !== ids.vbiosVersion.replace(/\./g, '').toUpperCase()) {
      return `VBIOS RIM version '${v.rim.version}' does not match the report's VBIOS '${ids.vbiosVersion}'`;
    }
    const cmp = compareReportToRims(ctx.report, d.rim, v.rim);
    if (!cmp.ok) return cmp.reason;
    const mode = opts.revocation ?? (opts.requireCrls === false ? undefined : 'crl');
    const crls = bundle.crls ?? [];
    if (crls.length > 0 || mode === 'crl' || mode === 'both') {
      const rev = checkNvidiaChainRevocation(ctx.chain, crls, ctx.nowMs, opts.requireCrlIssuers);
      if (!rev.ok) return `revocation: ${rev.reason}`;
    }
    const ocspResponses = bundle.ocsp ?? [];
    if (ocspResponses.length > 0 || mode === 'ocsp' || mode === 'both') {
      let ocspMod: typeof import('./attest-nvidia-ocsp');
      try {
        ocspMod = await import('./attest-nvidia-ocsp');
      } catch {
        return 'revocation: OCSP verification needs the optional dependencies pkijs and asn1js (not installed)';
      }
      const o = await ocspMod.checkNvidiaChainOcsp(ctx.chain, ocspResponses, ctx.nowMs);
      if (!o.ok) return `revocation (OCSP): ${o.reason}`;
    }
    return undefined;
  };
}

// ── guarded network helpers (never called automatically) ────────────────────────────────────────

/** Fetch a RIM document from the NVIDIA RIM service and return its XML text. */
export async function fetchNvidiaRim(id: string, opts: { fetch?: typeof fetch; baseUrl?: string } = {}): Promise<string> {
  const f = opts.fetch ?? (globalThis.fetch as typeof fetch | undefined);
  if (!f) throw new Error('fetchNvidiaRim: no fetch implementation available');
  if (!/^[A-Za-z0-9_.-]+$/.test(id)) throw new TypeError('fetchNvidiaRim: invalid RIM id');
  const res = await f(`${opts.baseUrl ?? NVIDIA_RIM_BASE_URL}${id}`);
  if (!res.ok) throw new Error(`RIM fetch failed: HTTP ${res.status} for ${id}`);
  const body = (await res.json()) as { rim?: unknown };
  if (typeof body.rim !== 'string') throw new Error('RIM fetch: response has no rim field');
  return Buffer.from(body.rim, 'base64').toString('utf8');
}

/** Fetch a DER CRL (follows redirects). */
export async function fetchNvidiaCrl(url: string, opts: { fetch?: typeof fetch } = {}): Promise<Uint8Array> {
  const f = opts.fetch ?? (globalThis.fetch as typeof fetch | undefined);
  if (!f) throw new Error('fetchNvidiaCrl: no fetch implementation available');
  const res = await f(url);
  if (!res.ok) throw new Error(`CRL fetch failed: HTTP ${res.status} for ${url}`);
  return new Uint8Array(await res.arrayBuffer());
}
