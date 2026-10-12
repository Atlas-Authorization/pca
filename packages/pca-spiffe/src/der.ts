/**
 * Minimal, bounds-checked DER reader for the X.509 extensions the SPIFFE X.509-SVID rules depend on
 * (basicConstraints, keyUsage, subjectAltName) plus the list of critical extensions. It performs no
 * cryptography: signatures, names and validity are checked with `node:crypto`'s X509Certificate.
 */

interface Tlv {
  readonly tag: number;
  /** Offset of the first content byte. */
  readonly start: number;
  /** Offset one past the last content byte. */
  readonly end: number;
}

function readTlv(buf: Uint8Array, off: number, limit: number): Tlv {
  if (off + 2 > limit) throw new RangeError('der: truncated header');
  const tag = buf[off]!;
  if ((tag & 0x1f) === 0x1f) throw new RangeError('der: high-tag-number form is not supported');
  let len = buf[off + 1]!;
  let p = off + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new RangeError('der: unsupported length form');
    if (p + n > limit) throw new RangeError('der: truncated length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[p + i]!;
    p += n;
  }
  if (p + len > limit) throw new RangeError('der: content exceeds container');
  return { tag, start: p, end: p + len };
}

/** Children of a constructed value. */
function children(buf: Uint8Array, parent: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let off = parent.start;
  while (off < parent.end) {
    const t = readTlv(buf, off, parent.end);
    out.push(t);
    off = t.end;
  }
  return out;
}

function oidHex(buf: Uint8Array, t: Tlv): string {
  return Buffer.from(buf.subarray(t.start, t.end)).toString('hex');
}

const OID_KEY_USAGE = '551d0f';
const OID_SAN = '551d11';
const OID_BASIC_CONSTRAINTS = '551d13';
/** Extension OIDs this package understands well enough to ignore when marked critical. */
const KNOWN_CRITICAL: ReadonlySet<string> = new Set([
  OID_KEY_USAGE,
  OID_SAN,
  OID_BASIC_CONSTRAINTS,
  '551d25', // extendedKeyUsage
  '551d0e', // subjectKeyIdentifier
  '551d23', // authorityKeyIdentifier
]);

export interface CertFacts {
  /** basicConstraints present, and its `cA` value (false when absent). */
  readonly basicConstraintsPresent: boolean;
  readonly isCa: boolean;
  /** `pathLenConstraint`, or null when absent. */
  readonly pathLen: number | null;
  /** keyUsage extension present. */
  readonly keyUsagePresent: boolean;
  readonly digitalSignature: boolean;
  readonly keyCertSign: boolean;
  readonly crlSign: boolean;
  /** URI subjectAltName entries, read from DER (not from a formatted string). */
  readonly uriSans: readonly string[];
  /** Hex OIDs of critical extensions this package does not understand. */
  readonly unknownCritical: readonly string[];
}

/** Read the X.509 facts the SVID rules need from a DER certificate. Throws on malformed DER. */
export function readCertFacts(der: Uint8Array): CertFacts {
  const cert = readTlv(der, 0, der.length);
  if (cert.tag !== 0x30 || cert.end !== der.length) throw new RangeError('der: certificate is not a single SEQUENCE');
  const tbs = children(der, cert)[0];
  if (tbs === undefined || tbs.tag !== 0x30) throw new RangeError('der: missing tbsCertificate');
  const fields = children(der, tbs);
  const extWrap = fields.find((f) => f.tag === 0xa3);
  const facts = {
    basicConstraintsPresent: false,
    isCa: false,
    pathLen: null as number | null,
    keyUsagePresent: false,
    digitalSignature: false,
    keyCertSign: false,
    crlSign: false,
    uriSans: [] as string[],
    unknownCritical: [] as string[],
  };
  if (extWrap === undefined) return facts;
  const extSeq = children(der, extWrap)[0];
  if (extSeq === undefined || extSeq.tag !== 0x30) throw new RangeError('der: malformed extensions');
  const seen = new Set<string>();
  for (const ext of children(der, extSeq)) {
    const parts = children(der, ext);
    const oidT = parts[0];
    if (oidT === undefined || oidT.tag !== 0x06) throw new RangeError('der: malformed extension');
    const oid = oidHex(der, oidT);
    if (seen.has(oid)) throw new RangeError('der: duplicate extension');
    seen.add(oid);
    const critical = parts.length === 3 && parts[1]!.tag === 0x01 && der[parts[1]!.start] === 0xff;
    const valueT = parts[parts.length - 1];
    if (valueT === undefined || valueT.tag !== 0x04) throw new RangeError('der: malformed extension value');
    if (critical && !KNOWN_CRITICAL.has(oid)) facts.unknownCritical.push(oid);
    const inner = readTlv(der, valueT.start, valueT.end);
    if (oid === OID_BASIC_CONSTRAINTS) {
      facts.basicConstraintsPresent = true;
      for (const c of children(der, inner)) {
        if (c.tag === 0x01) facts.isCa = der[c.start] === 0xff;
        else if (c.tag === 0x02) {
          let n = 0;
          for (let i = c.start; i < c.end; i++) n = n * 256 + der[i]!;
          facts.pathLen = n;
        }
      }
    } else if (oid === OID_KEY_USAGE) {
      if (inner.tag !== 0x03 || inner.end - inner.start < 2) throw new RangeError('der: malformed keyUsage');
      const b0 = der[inner.start + 1]!;
      facts.keyUsagePresent = true;
      facts.digitalSignature = (b0 & 0x80) !== 0;
      facts.keyCertSign = (b0 & 0x04) !== 0;
      facts.crlSign = (b0 & 0x02) !== 0;
    } else if (oid === OID_SAN) {
      for (const gn of children(der, inner)) {
        if (gn.tag === 0x86) facts.uriSans.push(Buffer.from(der.subarray(gn.start, gn.end)).toString('latin1'));
      }
    }
  }
  return facts;
}
