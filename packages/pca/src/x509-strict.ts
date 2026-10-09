/**
 * Strict X.509 helpers shared by the hardware-attestation chain verifiers (Intel PCK / PCS issuer chains, AMD VCEK).
 *
 * Node's OpenSSL-backed `X509Certificate` verifies signatures and DNs but exposes neither `pathLenConstraint` nor the
 * `keyUsage` bits, so the CA-role rules are enforced here from a small, strict DER read of the extensions:
 *   • every certificate that ISSUES another certificate must carry BasicConstraints CA:TRUE;
 *   • when keyUsage is present on an issuer it must assert keyCertSign;
 *   • a pathLenConstraint on an issuer must admit the number of intermediates below it;
 *   • the end-entity (leaf) must NOT assert CA:TRUE.
 * Public-key points are taken from the certificate's JWK export — never by scanning bytes of a DER SPKI.
 * Everything throws / returns a reason (fail closed) on any structural surprise.
 */
import type { KeyObject } from 'node:crypto';

interface Tlv {
  tag: number;
  start: number; // content start
  end: number; // content end (exclusive)
}

function readTlv(b: Uint8Array, off: number, limit = b.length): Tlv {
  if (off + 2 > limit) throw new RangeError('DER: truncated header');
  const tag = b[off]!;
  if ((tag & 0x1f) === 0x1f) throw new RangeError('DER: multi-byte tags are not supported');
  let len = b[off + 1]!;
  let p = off + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 3) throw new RangeError('DER: unsupported length form');
    if (p + n > limit) throw new RangeError('DER: truncated length');
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | b[p + i]!;
    p += n;
  }
  if (p + len > limit) throw new RangeError('DER: element overruns its parent');
  return { tag, start: p, end: p + len };
}

export interface CertRoleInfo {
  /** BasicConstraints present at all. */
  hasBasicConstraints: boolean;
  /** BasicConstraints cA (false when absent or when DEFAULT-false is encoded). */
  ca: boolean;
  /** pathLenConstraint when present. */
  pathLen?: number;
  /** keyUsage present. */
  hasKeyUsage: boolean;
  /** keyUsage asserts keyCertSign (bit 5). */
  keyCertSign: boolean;
}

const OID_BASIC_CONSTRAINTS = Uint8Array.of(0x55, 0x1d, 0x13);
const OID_KEY_USAGE = Uint8Array.of(0x55, 0x1d, 0x0f);

function oidEquals(b: Uint8Array, t: Tlv, want: Uint8Array): boolean {
  if (t.tag !== 0x06 || t.end - t.start !== want.length) return false;
  for (let i = 0; i < want.length; i++) if (b[t.start + i] !== want[i]) return false;
  return true;
}

/** Read the CA-role-relevant extensions of a DER certificate. Throws on a malformed / duplicated extension. */
export function readCertRoleInfo(certDer: Uint8Array): CertRoleInfo {
  const outer = readTlv(certDer, 0);
  if (outer.tag !== 0x30) throw new RangeError('certificate is not a DER SEQUENCE');
  const tbs = readTlv(certDer, outer.start, outer.end);
  if (tbs.tag !== 0x30) throw new RangeError('certificate has no tbsCertificate');
  const info: CertRoleInfo = { hasBasicConstraints: false, ca: false, hasKeyUsage: false, keyCertSign: false };
  let p = tbs.start;
  while (p < tbs.end) {
    const el = readTlv(certDer, p, tbs.end);
    p = el.end;
    if (el.tag !== 0xa3) continue; // [3] EXPLICIT extensions
    const seq = readTlv(certDer, el.start, el.end);
    if (seq.tag !== 0x30) throw new RangeError('extensions is not a SEQUENCE');
    let q = seq.start;
    while (q < seq.end) {
      const ext = readTlv(certDer, q, seq.end);
      q = ext.end;
      if (ext.tag !== 0x30) throw new RangeError('extension is not a SEQUENCE');
      const id = readTlv(certDer, ext.start, ext.end);
      let r = id.end;
      let next = readTlv(certDer, r, ext.end);
      if (next.tag === 0x01) {
        r = next.end;
        next = readTlv(certDer, r, ext.end);
      }
      if (next.tag !== 0x04) throw new RangeError('extension value is not an OCTET STRING');
      if (oidEquals(certDer, id, OID_BASIC_CONSTRAINTS)) {
        if (info.hasBasicConstraints) throw new RangeError('duplicate BasicConstraints extension');
        info.hasBasicConstraints = true;
        const bc = readTlv(certDer, next.start, next.end);
        if (bc.tag !== 0x30) throw new RangeError('BasicConstraints is not a SEQUENCE');
        let c = bc.start;
        if (c < bc.end) {
          const first = readTlv(certDer, c, bc.end);
          if (first.tag === 0x01) {
            if (first.end - first.start !== 1) throw new RangeError('BasicConstraints cA is not one byte');
            info.ca = certDer[first.start] !== 0;
            c = first.end;
          }
        }
        if (c < bc.end) {
          const pl = readTlv(certDer, c, bc.end);
          if (pl.tag !== 0x02 || pl.end - pl.start < 1 || pl.end - pl.start > 2 || (certDer[pl.start]! & 0x80) !== 0) throw new RangeError('BasicConstraints pathLenConstraint malformed');
          let n = 0;
          for (let i = pl.start; i < pl.end; i++) n = (n << 8) | certDer[i]!;
          info.pathLen = n;
          c = pl.end;
        }
        if (c !== bc.end) throw new RangeError('BasicConstraints has trailing data');
      } else if (oidEquals(certDer, id, OID_KEY_USAGE)) {
        if (info.hasKeyUsage) throw new RangeError('duplicate keyUsage extension');
        info.hasKeyUsage = true;
        const bs = readTlv(certDer, next.start, next.end);
        if (bs.tag !== 0x03 || bs.end - bs.start < 2) throw new RangeError('keyUsage is not a BIT STRING');
        info.keyCertSign = (certDer[bs.start + 1]! & 0x04) !== 0;
      }
    }
  }
  return info;
}

export interface CertExtension {
  critical: boolean;
  /** The extnValue OCTET STRING content (the DER of the extension's own value). */
  value: Uint8Array;
}

function oidToDotted(b: Uint8Array, t: Tlv): string {
  if (t.tag !== 0x06 || t.end <= t.start) throw new RangeError('extension OID is malformed');
  const arcs: bigint[] = [];
  let v = 0n;
  let open = false;
  for (let i = t.start; i < t.end; i++) {
    const byte = b[i]!;
    if (!open && byte === 0x80) throw new RangeError('extension OID has a non-minimal arc');
    v = (v << 7n) | BigInt(byte & 0x7f);
    open = (byte & 0x80) !== 0;
    if (!open) {
      arcs.push(v);
      v = 0n;
    }
  }
  if (open) throw new RangeError('extension OID is truncated');
  const first = arcs[0]!;
  const head = first < 40n ? [0n, first] : first < 80n ? [1n, first - 40n] : [2n, first - 80n];
  return [...head, ...arcs.slice(1)].join('.');
}

/**
 * STRICT extension table of a tbsCertificate (the DER SEQUENCE INCLUDING its header), keyed by dotted OID. Unlike a
 * byte scan this walks the real structure, so an OID that merely appears inside a name, a key or another extension's
 * value is never mistaken for an extension. Throws (fail closed) on: a malformed element, a duplicate extension OID,
 * more than one `[3] extensions` block, a non-DER `critical` encoding (explicit FALSE, or TRUE other than 0xFF),
 * trailing bytes inside an Extension / the Extensions SEQUENCE / the TBS, or an empty Extensions block.
 */
export function parseTbsExtensions(tbsDer: Uint8Array): Map<string, CertExtension> {
  const tbs = readTlv(tbsDer, 0);
  if (tbs.tag !== 0x30) throw new RangeError('tbsCertificate is not a SEQUENCE');
  if (tbs.end !== tbsDer.length) throw new RangeError('trailing bytes after tbsCertificate');
  const out = new Map<string, CertExtension>();
  let seen = false;
  let blockEnd = -1;
  let p = tbs.start;
  while (p < tbs.end) {
    const el = readTlv(tbsDer, p, tbs.end);
    p = el.end;
    if (el.tag !== 0xa3) continue; // [3] EXPLICIT extensions
    if (seen) throw new RangeError('duplicate [3] extensions block');
    seen = true;
    blockEnd = el.end;
    const seq = readTlv(tbsDer, el.start, el.end);
    if (seq.tag !== 0x30) throw new RangeError('extensions is not a SEQUENCE');
    if (seq.end !== el.end) throw new RangeError('trailing bytes after the Extensions SEQUENCE');
    if (seq.start === seq.end) throw new RangeError('empty Extensions SEQUENCE');
    let q = seq.start;
    while (q < seq.end) {
      const ext = readTlv(tbsDer, q, seq.end);
      q = ext.end;
      if (ext.tag !== 0x30) throw new RangeError('extension is not a SEQUENCE');
      const id = readTlv(tbsDer, ext.start, ext.end);
      const dotted = oidToDotted(tbsDer, id);
      let r = id.end;
      let next = readTlv(tbsDer, r, ext.end);
      let critical = false;
      if (next.tag === 0x01) {
        if (next.end - next.start !== 1 || tbsDer[next.start] !== 0xff) throw new RangeError(`extension ${dotted} has a non-DER critical flag`);
        critical = true;
        r = next.end;
        next = readTlv(tbsDer, r, ext.end);
      }
      if (next.tag !== 0x04) throw new RangeError(`extension ${dotted} value is not an OCTET STRING`);
      if (next.end !== ext.end) throw new RangeError(`extension ${dotted} has trailing bytes`);
      if (out.has(dotted)) throw new RangeError(`duplicate extension ${dotted}`);
      out.set(dotted, { critical, value: tbsDer.slice(next.start, next.end) });
    }
  }
  if (seen && blockEnd !== tbs.end) throw new RangeError('extensions block is not the last TBS element');
  return out;
}

/** The tbsCertificate bytes (header included) of a DER certificate; rejects trailing bytes after the certificate. */
export function tbsOfCertificate(certDer: Uint8Array): Uint8Array {
  const outer = readTlv(certDer, 0);
  if (outer.tag !== 0x30) throw new RangeError('certificate is not a DER SEQUENCE');
  if (outer.end !== certDer.length) throw new RangeError('trailing bytes after the certificate');
  const tbs = readTlv(certDer, outer.start, outer.end);
  if (tbs.tag !== 0x30) throw new RangeError('certificate has no tbsCertificate');
  return certDer.slice(outer.start, tbs.end);
}

/** {@link parseTbsExtensions} over a whole certificate. */
export function parseCertExtensions(certDer: Uint8Array): Map<string, CertExtension> {
  return parseTbsExtensions(tbsOfCertificate(certDer));
}

/**
 * Enforce CA roles over an ordered chain (index 0 = leaf … last = self-signed root). Returns a failure reason or
 * undefined. A chain of one certificate (a bare root) has no leaf/issuer relationship to check.
 */
export function checkChainRoles(orderedDer: readonly Uint8Array[]): string | undefined {
  try {
    const n = orderedDer.length;
    for (let i = 0; i < n; i++) {
      const info = readCertRoleInfo(orderedDer[i]!);
      if (i === 0 && n > 1) {
        if (info.ca) return 'leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)';
        continue;
      }
      if (i === 0) continue;
      if (!info.hasBasicConstraints) return `issuer certificate at depth ${i} has no BasicConstraints (not a CA)`;
      if (!info.ca) return `issuer certificate at depth ${i} is not a CA (BasicConstraints CA:FALSE)`;
      if (info.hasKeyUsage && !info.keyCertSign) return `issuer certificate at depth ${i} keyUsage lacks keyCertSign`;
      if (info.pathLen !== undefined && info.pathLen < i - 1) return `issuer certificate at depth ${i} pathLenConstraint ${info.pathLen} is exceeded (${i - 1} intermediate(s) below)`;
    }
    return undefined;
  } catch (e) {
    return `certificate extension parse failed: ${e instanceof Error ? e.message : 'invalid'}`;
  }
}

const CURVES = {
  'P-256': { crv: 'P-256', coord: 32 },
  'P-384': { crv: 'P-384', coord: 48 },
} as const;

function b64uDecode(s: unknown, len: number, what: string): Uint8Array {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]+$/.test(s)) throw new TypeError(`${what} is not base64url`);
  const out = new Uint8Array(Buffer.from(s, 'base64url'));
  if (out.length !== len) throw new TypeError(`${what} is ${out.length} bytes, expected ${len}`);
  return out;
}

/**
 * The uncompressed SEC1 point (`0x04 ‖ X ‖ Y`) of an EC public key, via the JWK export. Throws unless the key is an
 * EC key on exactly the named curve with full-width coordinates (so no compressed / short / alien-curve points).
 */
export function ecPointFromKey(key: KeyObject, curve: 'P-256' | 'P-384'): Uint8Array {
  const want = CURVES[curve];
  if (key.type !== 'public' || key.asymmetricKeyType !== 'ec') throw new TypeError(`public key is not EC (got ${key.asymmetricKeyType ?? 'unknown'})`);
  const jwk = key.export({ format: 'jwk' });
  if (jwk.kty !== 'EC' || jwk.crv !== want.crv) throw new TypeError(`public key is not on ${want.crv} (got ${String(jwk.crv)})`);
  if (jwk.d !== undefined) throw new TypeError('unexpected private component');
  const x = b64uDecode(jwk.x, want.coord, 'EC x');
  const y = b64uDecode(jwk.y, want.coord, 'EC y');
  const out = new Uint8Array(1 + 2 * want.coord);
  out[0] = 0x04;
  out.set(x, 1);
  out.set(y, 1 + want.coord);
  return out;
}
