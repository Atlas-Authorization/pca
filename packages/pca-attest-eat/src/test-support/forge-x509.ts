/**
 * TEST-ONLY X.509 / CRL / DER toolkit shared by the evidence forgers (`forge-dcap.ts`, `forge-spdm.ts`).
 *
 * Real vendor roots cannot be re-signed, so the verifiers' policy branches cannot be driven with captured
 * evidence. The forgers instead mint evidence in the REAL wire format under a TEST root whose SPKI is injected
 * through the verifiers' existing trust-anchor options. This module supplies the cryptographic plumbing:
 *   - a tiny DER writer (no ASN.1 library, fully deterministic),
 *   - deterministic ECDSA P-256 / P-384 keys derived from a seed string (RFC 6979 signatures, so the same seed
 *     always yields byte-identical output),
 *   - REAL X.509 v3 certificates (parsed by node's OpenSSL), CRLs, and the extension encoders the vendors use.
 *
 * NEVER import this from production code. Nothing here is a trust anchor; it only fabricates a TEST one.
 */
import { createHash } from 'node:crypto';
import { p256 } from '@noble/curves/p256';
import { p384 } from '@noble/curves/p384';

export type Curve = 'P-256' | 'P-384';
export type DigestName = 'sha256' | 'sha384';

// ── byte helpers ─────────────────────────────────────────────────────────────────────────────────
export function cat(...parts: Uint8Array[]): Uint8Array {
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
export function hexToBytes(h: string): Uint8Array {
  if (h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) throw new TypeError('hexToBytes: bad hex');
  return new Uint8Array(Buffer.from(h, 'hex'));
}
export function bytesToHex(b: Uint8Array): string {
  return Buffer.from(b).toString('hex');
}
export function digest(alg: DigestName | 'sha1' | 'sha512', ...parts: Uint8Array[]): Uint8Array {
  const h = createHash(alg);
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
}
export function u16(n: number): Uint8Array {
  return Uint8Array.of(n & 0xff, (n >> 8) & 0xff);
}
export function u32(n: number): Uint8Array {
  return Uint8Array.of(n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff);
}
/** Deterministic filler: `len` bytes derived from `seed` (SHA-256 counter mode). */
export function fill(seed: string, len: number): Uint8Array {
  const out = new Uint8Array(len);
  let o = 0;
  for (let i = 0; o < len; i++) {
    const block = digest('sha256', new TextEncoder().encode(`${seed}#${i}`));
    out.set(block.subarray(0, Math.min(32, len - o)), o);
    o += 32;
  }
  return out;
}

// ── DER writer ───────────────────────────────────────────────────────────────────────────────────
export function derLen(n: number): Uint8Array {
  if (n < 0x80) return Uint8Array.of(n);
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}
export function tlv(tag: number, ...content: Uint8Array[]): Uint8Array {
  const body = cat(...content);
  return cat(Uint8Array.of(tag), derLen(body.length), body);
}
export const seq = (...c: Uint8Array[]): Uint8Array => tlv(0x30, ...c);
export const set = (...c: Uint8Array[]): Uint8Array => tlv(0x31, ...c);
export const octets = (b: Uint8Array): Uint8Array => tlv(0x04, b);
export const bitString = (b: Uint8Array, unused = 0): Uint8Array => tlv(0x03, Uint8Array.of(unused), b);
export const boolean = (v: boolean): Uint8Array => tlv(0x01, Uint8Array.of(v ? 0xff : 0x00));
export const enumerated = (n: number): Uint8Array => tlv(0x0a, Uint8Array.of(n));
export const nul = (): Uint8Array => Uint8Array.of(0x05, 0x00);
export const utf8 = (s: string): Uint8Array => tlv(0x0c, new TextEncoder().encode(s));
export const printable = (s: string): Uint8Array => tlv(0x13, new TextEncoder().encode(s));
/** Context-specific constructed `[n]` (EXPLICIT wrapper). */
export const ctx = (n: number, ...c: Uint8Array[]): Uint8Array => tlv(0xa0 | n, ...c);
/** Context-specific primitive `[n]` (IMPLICIT primitive). */
export const ctxPrim = (n: number, b: Uint8Array): Uint8Array => tlv(0x80 | n, b);

export function integer(v: bigint | number | Uint8Array): Uint8Array {
  let b: Uint8Array;
  if (v instanceof Uint8Array) {
    let i = 0;
    while (i < v.length - 1 && v[i] === 0) i++;
    b = v.subarray(i);
    if (b.length === 0) b = Uint8Array.of(0);
  } else {
    let x = BigInt(v);
    if (x < 0n) throw new RangeError('integer: negative');
    const out: number[] = [];
    do {
      out.unshift(Number(x & 0xffn));
      x >>= 8n;
    } while (x > 0n);
    b = Uint8Array.from(out);
  }
  return tlv(0x02, b[0]! & 0x80 ? cat(Uint8Array.of(0), b) : b);
}

export function oidBytes(dotted: string): Uint8Array {
  const arcs = dotted.split('.').map((x) => BigInt(x));
  if (arcs.length < 2) throw new TypeError('oid: too short');
  const out: number[] = [];
  const enc = (v: bigint) => {
    const tmp: number[] = [Number(v & 0x7fn)];
    for (let x = v >> 7n; x > 0n; x >>= 7n) tmp.unshift(Number(x & 0x7fn) | 0x80);
    out.push(...tmp);
  };
  enc(arcs[0]! * 40n + arcs[1]!);
  for (const a of arcs.slice(2)) enc(a);
  return Uint8Array.from(out);
}
export const oid = (dotted: string): Uint8Array => tlv(0x06, oidBytes(dotted));

function pad2(n: number): string {
  return String(n).padStart(2, '0');
}
/** UTCTime for 1950..2049, GeneralizedTime otherwise (RFC 5280 profile). */
export function derTime(d: Date): Uint8Array {
  const y = d.getUTCFullYear();
  const rest = `${pad2(d.getUTCMonth() + 1)}${pad2(d.getUTCDate())}${pad2(d.getUTCHours())}${pad2(d.getUTCMinutes())}${pad2(d.getUTCSeconds())}Z`;
  const enc = new TextEncoder();
  if (y >= 1950 && y <= 2049) return tlv(0x17, enc.encode(`${pad2(y % 100)}${rest}`));
  return tlv(0x18, enc.encode(`${String(y).padStart(4, '0')}${rest}`));
}
export function generalizedTime(d: Date): Uint8Array {
  const y = d.getUTCFullYear();
  return tlv(0x18, new TextEncoder().encode(`${String(y).padStart(4, '0')}${pad2(d.getUTCMonth() + 1)}${pad2(d.getUTCDate())}${pad2(d.getUTCHours())}${pad2(d.getUTCMinutes())}${pad2(d.getUTCSeconds())}Z`));
}

// ── minimal DER reader (used by layout-equivalence checks) ───────────────────────────────────────
export interface DerNode {
  tag: number;
  start: number;
  end: number;
  children?: DerNode[];
}
export function readDer(b: Uint8Array, off = 0, limit = b.length): DerNode {
  if (off + 2 > limit) throw new RangeError('DER truncated');
  const tag = b[off]!;
  let len = b[off + 1]!;
  let p = off + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[p + i]!;
    p += n;
  }
  const end = p + len;
  if (end > limit) throw new RangeError('DER overrun');
  const node: DerNode = { tag, start: p, end };
  if (tag & 0x20) {
    node.children = [];
    let q = p;
    while (q < end) {
      const c = readDer(b, q, end);
      node.children.push(c);
      q = c.end;
    }
  }
  return node;
}
export function oidToString(b: Uint8Array, n: DerNode): string {
  const raw = b.subarray(n.start, n.end);
  const arcs: bigint[] = [];
  let v = 0n;
  for (const byte of raw) {
    v = (v << 7n) | BigInt(byte & 0x7f);
    if (!(byte & 0x80)) {
      arcs.push(v);
      v = 0n;
    }
  }
  const first = arcs.shift() ?? 0n;
  const a0 = first >= 80n ? 2n : first / 40n;
  return [a0, first - a0 * 40n, ...arcs].join('.');
}
/**
 * Structural skeleton of a DER value: constructed tags, OIDs (dotted) and primitive tags, with INTEGER magnitudes,
 * times and string payloads erased. Two certificates with equal skeletons have the same wire layout.
 */
export function derShape(b: Uint8Array, n: DerNode = readDer(b), keepOctetLen = false): string {
  const t = n.tag.toString(16);
  if (n.children) return `${t}(${n.children.map((c) => derShape(b, c, keepOctetLen)).join(',')})`;
  if (n.tag === 0x06) return `oid:${oidToString(b, n)}`;
  if (n.tag === 0x04 && keepOctetLen) return `04[${n.end - n.start}]`;
  return t;
}

// ── keys ─────────────────────────────────────────────────────────────────────────────────────────
export interface ForgeKey {
  curve: Curve;
  priv: Uint8Array;
  /** Uncompressed SEC1 point `04 ‖ X ‖ Y`. */
  pub: Uint8Array;
  /** DER SubjectPublicKeyInfo. */
  spki: Uint8Array;
  /** SHA-256 of {@link spki} (the pin format both verifiers use). */
  spkiSha256: string;
}

const OID_EC_PUBKEY = '1.2.840.10045.2.1';
const OID_P256 = '1.2.840.10045.3.1.7';
const OID_P384 = '1.3.132.0.34';

function curveOf(c: Curve) {
  return c === 'P-256' ? p256 : p384;
}
function scalarBytes(c: Curve): number {
  return c === 'P-256' ? 32 : 48;
}

/** Deterministic keypair: the same `seed` always yields the same key. */
export function forgeKey(seed: string, curve: Curve): ForgeKey {
  const cv = curveOf(curve);
  const n = cv.CURVE.n;
  const raw = fill(`forge-key/${curve}/${seed}`, scalarBytes(curve) + 16);
  let x = 0n;
  for (const b of raw) x = (x << 8n) | BigInt(b);
  const d = (x % (n - 1n)) + 1n;
  const priv = hexToBytes(d.toString(16).padStart(scalarBytes(curve) * 2, '0'));
  const pub = cv.getPublicKey(priv, false);
  const spki = seq(seq(oid(OID_EC_PUBKEY), oid(curve === 'P-256' ? OID_P256 : OID_P384)), bitString(pub));
  return { curve, priv, pub, spki, spkiSha256: bytesToHex(digest('sha256', spki)) };
}

/** Raw 64/96-byte `r ‖ s` (IEEE P1363) and DER ECDSA-Sig-Value over `msg` hashed with `alg`. Deterministic. */
export function ecdsaSign(key: ForgeKey, alg: DigestName, msg: Uint8Array): { raw: Uint8Array; der: Uint8Array } {
  const h = digest(alg, msg);
  const sig = curveOf(key.curve).sign(h, key.priv, { lowS: false });
  return { raw: sig.toCompactRawBytes(), der: sig.toDERRawBytes() };
}

// ── names + extensions + certificates ────────────────────────────────────────────────────────────
const OID_ATTR: Readonly<Record<string, string>> = {
  C: '2.5.4.6',
  ST: '2.5.4.8',
  L: '2.5.4.7',
  O: '2.5.4.10',
  CN: '2.5.4.3',
  serialNumber: '2.5.4.5',
};
/** One attribute of a distinguished name, in the order it is written to the wire. */
export type DnAttr = readonly [attr: keyof typeof OID_ATTR, value: string];

export function dn(attrs: readonly DnAttr[]): Uint8Array {
  return seq(
    ...attrs.map(([k, v]) => {
      const t = k === 'C' || k === 'serialNumber' ? printable(v) : utf8(v);
      return set(seq(oid(OID_ATTR[k]!), t));
    }),
  );
}

/** An already-DER-encoded `Extension ::= SEQUENCE { extnID, critical?, extnValue OCTET STRING }`. */
export type Extension = Uint8Array;
export function extension(oidStr: string, critical: boolean, value: Uint8Array): Extension {
  return seq(oid(oidStr), ...(critical ? [boolean(true)] : []), octets(value));
}
export const ext = {
  basicConstraints: (ca: boolean, pathLen?: number): Extension => extension('2.5.29.19', true, seq(...(ca ? [boolean(true)] : []), ...(ca && pathLen !== undefined ? [integer(pathLen)] : []))),
  /** `bits` is the KeyUsage bit mask with bit 0 = digitalSignature (MSB of the first byte), as in RFC 5280. */
  keyUsage: (names: readonly ('digitalSignature' | 'nonRepudiation' | 'keyCertSign' | 'cRLSign')[]): Extension => {
    const idx = { digitalSignature: 0, nonRepudiation: 1, keyCertSign: 5, cRLSign: 6 } as const;
    let v = 0;
    for (const n of names) v |= 0x80 >> idx[n];
    const unused = names.length === 0 ? 0 : Math.max(0, 7 - Math.max(...names.map((n) => idx[n])));
    return extension('2.5.29.15', true, bitString(Uint8Array.of(v), unused));
  },
  subjectKeyId: (key: ForgeKey): Extension => extension('2.5.29.14', false, octets(digest('sha1', key.pub))),
  authorityKeyId: (issuer: ForgeKey): Extension => extension('2.5.29.35', false, seq(ctxPrim(0, digest('sha1', issuer.pub)))),
  extKeyUsage: (oids: readonly string[], critical = false): Extension => extension('2.5.29.37', critical, seq(...oids.map(oid))),
  crlDistributionPoint: (uri: string): Extension =>
    extension('2.5.29.31', false, seq(seq(ctx(0, ctx(0, ctxPrim(6, new TextEncoder().encode(uri))))))),
};

export interface CertOptions {
  subject: readonly DnAttr[];
  issuer: readonly DnAttr[];
  subjectKey: ForgeKey;
  /** The signing key (the subject's own key for a self-signed root). */
  signer: ForgeKey;
  serial: bigint | Uint8Array;
  notBefore: Date;
  notAfter: Date;
  /** ECDSA digest; default sha256 for P-256 signers and sha384 for P-384 signers. */
  sigDigest?: DigestName;
  extensions?: readonly Extension[];
}

export interface ForgedCert {
  der: Uint8Array;
  pem: string;
  subject: readonly DnAttr[];
  key: ForgeKey;
  serialHex: string;
}

const SIG_OID: Readonly<Record<DigestName, string>> = { sha256: '1.2.840.10045.4.3.2', sha384: '1.2.840.10045.4.3.3' };

export function pemOf(der: Uint8Array, label = 'CERTIFICATE'): string {
  const b64 = Buffer.from(der).toString('base64');
  return `-----BEGIN ${label}-----\n${b64.match(/.{1,64}/g)?.join('\n') ?? ''}\n-----END ${label}-----\n`;
}

export function forgeCert(o: CertOptions): ForgedCert {
  const sigDigest = o.sigDigest ?? (o.signer.curve === 'P-256' ? 'sha256' : 'sha384');
  const sigAlg = seq(oid(SIG_OID[sigDigest]));
  const serialBytes = o.serial instanceof Uint8Array ? o.serial : hexToBytes(o.serial.toString(16).padStart(Math.ceil(o.serial.toString(16).length / 2) * 2, '0'));
  const tbs = seq(
    ctx(0, integer(2)),
    integer(serialBytes),
    sigAlg,
    dn(o.issuer),
    seq(derTime(o.notBefore), derTime(o.notAfter)),
    dn(o.subject),
    o.subjectKey.spki,
    ...(o.extensions && o.extensions.length > 0 ? [ctx(3, seq(...o.extensions))] : []),
  );
  const sig = ecdsaSign(o.signer, sigDigest, tbs);
  const der = seq(tbs, sigAlg, bitString(sig.der));
  return { der, pem: pemOf(der), subject: o.subject, key: o.subjectKey, serialHex: bytesToHex(serialBytes).replace(/^0+/, '') };
}

// ── CRL ──────────────────────────────────────────────────────────────────────────────────────────
export interface CrlOptions {
  issuer: readonly DnAttr[];
  signer: ForgeKey;
  /** Serial numbers (hex, any case) to list as revoked. */
  revoked?: readonly string[];
  thisUpdate: Date;
  nextUpdate: Date;
  crlNumber?: number;
  /** Real vendor CRLs (Intel and NVIDIA) are ecdsa-with-SHA256 even over P-384; default sha256. */
  sigDigest?: DigestName;
  /** Omit nextUpdate entirely (a malformed CRL for the parser branch). */
  omitNextUpdate?: boolean;
  /** Add the Authority Key Identifier CRL extension (issuer key), as both vendors' CRLs carry. */
  authorityKey?: ForgeKey;
  /** Malformed-structure knobs for the CRL parser's branches (each still carries a valid signature over its TBS). */
  raw?: {
    omitVersion?: boolean;
    thisUpdate?: Uint8Array;
    nextUpdate?: Uint8Array;
    /** Replace the revoked-certificates SEQUENCE entries with these raw DER entries. */
    entries?: readonly Uint8Array[];
    /** Replace the Name with these bytes (e.g. a non-SEQUENCE). */
    issuer?: Uint8Array;
    /** Wrap the signature in this tag instead of BIT STRING (0x03). */
    sigTag?: number;
    /** Replace the TBSCertList tag (0x30). */
    tbsTag?: number;
    /** Emit the outer SEQUENCE with this many trailing bytes. */
    trailing?: Uint8Array;
  };
}
export function forgeCrl(o: CrlOptions): Uint8Array {
  const sigDigest = o.sigDigest ?? 'sha256';
  const sigAlg = seq(oid(SIG_OID[sigDigest]));
  const entries = (o.raw?.entries ?? (o.revoked ?? []).map((s) => {
    const hex = s.length % 2 ? `0${s}` : s;
    return seq(integer(hexToBytes(hex)), derTime(o.thisUpdate), seq(extension('2.5.29.21', false, enumerated(1))));
  })) as Uint8Array[];
  const tbs = tlv(
    o.raw?.tbsTag ?? 0x30,
    ...(o.raw?.omitVersion ? [] : [integer(1)]),
    sigAlg,
    o.raw?.issuer ?? dn(o.issuer),
    o.raw?.thisUpdate ?? derTime(o.thisUpdate),
    ...(o.omitNextUpdate ? [] : [o.raw?.nextUpdate ?? derTime(o.nextUpdate)]),
    ...(entries.length > 0 ? [seq(...entries)] : []),
    ctx(0, seq(extension('2.5.29.20', false, integer(o.crlNumber ?? 1)), ...(o.authorityKey ? [ext.authorityKeyId(o.authorityKey)] : []))),
  );
  const sig = ecdsaSign(o.signer, sigDigest, tbs);
  const sigEl = o.raw?.sigTag !== undefined ? tlv(o.raw.sigTag, Uint8Array.of(0), sig.der) : bitString(sig.der);
  return cat(seq(tbs, sigAlg, sigEl), o.raw?.trailing ?? new Uint8Array(0));
}

/** A fixed, deterministic 20-byte positive serial for `label`. */
export function serialFor(label: string): Uint8Array {
  const s = fill(`serial/${label}`, 20);
  s[0] = s[0]! & 0x7f;
  if (s[0] === 0) s[0] = 0x11;
  return s;
}
