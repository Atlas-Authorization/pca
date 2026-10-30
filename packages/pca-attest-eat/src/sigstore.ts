/**
 * OFFLINE SIGSTORE BUNDLE VERIFICATION FOR BUILD PROVENANCE (track K9).
 *
 * Verifies a Sigstore bundle that carries an in-toto Statement with SLSA v1 provenance, against trust roots the verifier
 * pinned (a Sigstore `trusted_root.json`), with no network access, and returns the {@link BuildProvenanceFacts} that
 * `@atlasauth/pca` `provenanceGate` then checks against the verifier's signer-builder pins. Order follows the Sigstore
 * client specification (sigstore/architecture-docs `client-spec.md` section 4, fetched 2026-10-27):
 *
 *   1. signing time first (client spec 4.2): every RFC 3161 timestamp in the bundle must verify against a pinned timestamp
 *      authority (CMS SignedData over TSTInfo, messageImprint = hash of the signature bytes, chain valid at genTime); a
 *      Rekor v1 signed entry timestamp (SET) must verify when present. At least one verified time is required;
 *   2. the Rekor entry: Rekor v1 `dsse` 0.0.1 or `intoto` 0.0.2, or Rekor v2 `hashedrekord` 0.0.2 over the DSSE PAE (client
 *      spec 4.4, Rekor v2 spec 6.1.4, persisted-body variant: digest, signature and certificate are compared); the RFC 9162
 *      inclusion proof must lead to the root of a checkpoint signed by the pinned log key (Rekor v2: Ed25519 signed note
 *      under the log's name, the host of its base URL);
 *   3. the certificate path to a pinned Fulcio CA (intermediates come from the trusted root, never from the bundle), every
 *      certificate valid at EVERY verified time (hybrid model; client spec 4.3 validates once per time source), CA flags,
 *      the code-signing EKU on the leaf; the embedded SCT under a pinned CT log key when the root lists CT logs;
 *   4. the entry body names this envelope's payload (or PAE digest), signature and certificate;
 *   5. the DSSE signature over PAE(payloadType, payload) under the leaf key, exactly one signature, payload type
 *      `application/vnd.in-toto+json`;
 *   6. the Statement (`https://in-toto.io/Statement/v1`); {@link verifySigstoreBundle} then reads the SLSA v1 predicate.

 * Identity (SAN), OIDC issuer and source repository come from the Fulcio certificate extensions (sigstore/fulcio
 * `docs/oid-info.md`): `.1.1`-`.1.6` are raw UTF-8, `.1.8` onward DER UTF8String; both issuer forms must agree when present.
 * Sources: sigstore/protobuf-specs (bundle, trustroot), secure-systems-lab/dsse `protocol.md` (PAE), in-toto/attestation
 * `spec/v1/statement.md`, slsa.dev/spec/v1.0 (provenance, verifying-artifacts), RFC 9162 (inclusion), RFC 6962 section 3.2
 * (precertificate SCT), transparency-dev/formats `log/README.md` (checkpoint), rekor `pkg/verify/verify.go` (SET payload),
 * sigstore/architecture-docs 82f7d950 `rekor-v2-spec.md` (hashedrekord 0.0.2, checkpoints), RFC 3161 and RFC 5652 (timestamps),
 * C2SP signed-note (Ed25519 key hash), sigstore-go 0161b209 `pkg/verify/tlog.go` (note name = base URL host). Tested on the
 * sigstore-conformance acb38c9e bundle-verify fixtures.
 *
 * Not supported (refused, never skipped): `messageSignature` bundles, public-key (non-keyless) bundles, v0.1 bundles,
 * OtherName SANs, SLSA v0.2 predicates, Rekor v2 `dsse` entries (Rekor v2 defines only hashedrekord). Every failure is a
 * distinct `code`.
 */
import { X509Certificate, createHash, createPublicKey, verify as nodeVerify, type KeyObject } from 'node:crypto';
import { rfc9162LeafHash, verifyRfc9162Inclusion, SLSA_PROVENANCE_V1, INTOTO_STATEMENT_V1, type BuildProvenanceFacts, type SubjectDigest } from '@atlasauth/pca';

export const SIGSTORE_BUNDLE_MEDIA_TYPES = [
  'application/vnd.dev.sigstore.bundle+json;version=0.2',
  'application/vnd.dev.sigstore.bundle+json;version=0.3',
  'application/vnd.dev.sigstore.bundle.v0.3+json',
] as const;
export const INTOTO_PAYLOAD_TYPE = 'application/vnd.in-toto+json';
const OID_FULCIO = '1.3.6.1.4.1.57264.1.';
const OID_SCT_LIST = '1.3.6.1.4.1.11129.2.4.2';
const OID_SAN = '2.5.29.17';
const EKU_CODE_SIGNING = '1.3.6.1.5.5.7.3.3';

export type SigstoreCode =
  | 'malformed'
  | 'media_type'
  | 'not_keyless'
  | 'envelope'
  | 'tlog_count'
  | 'tlog_kind'
  | 'tlog_key'
  | 'no_verified_time'
  | 'tsa'
  | 'tlog_set'
  | 'tlog_checkpoint'
  | 'tlog_inclusion'
  | 'tlog_body'
  | 'cert_parse'
  | 'cert_chain'
  | 'cert_time'
  | 'cert_eku'
  | 'sct'
  | 'identity'
  | 'signature'
  | 'statement'
  | 'predicate';
export type SigstoreResult = { ok: true; facts: BuildProvenanceFacts } | { ok: false; code: SigstoreCode; detail: string };

// ------------------------------------------------------------------------------------------------ trusted root

interface Validity { start: number; end: number }
/** A pinned log. `v2` logs (Ed25519, C2SP signed-note checkpoints) carry the note name: the host of their base URL. */
export interface PinnedLog { keyId: Uint8Array; key: KeyObject; valid: Validity; v2?: { name: string } }
export interface PinnedCa { chain: X509Certificate[]; valid: Validity }
export interface PinnedRoots { tlogs: PinnedLog[]; ctlogs: PinnedLog[]; cas: PinnedCa[]; tsas: PinnedCa[] }

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const b64 = (s: unknown): Buffer => {
  if (typeof s !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4 !== 0) throw new Error('not base64');
  return Buffer.from(s, 'base64');
};
const validity = (v: unknown): Validity => {
  const s = isObj(v) && typeof v.start === 'string' ? Date.parse(v.start) : NaN;
  if (!Number.isFinite(s)) throw new Error('validFor.start missing');
  const e = isObj(v) && typeof v.end === 'string' ? Date.parse(v.end) : Infinity;
  if (Number.isNaN(e)) throw new Error('validFor.end malformed');
  return { start: s, end: e };
};
const sha256 = (...b: Uint8Array[]): Buffer => {
  const h = createHash('sha256');
  for (const x of b) h.update(x);
  return h.digest();
};

/**
 * A log key. ECDSA P-256 (Rekor v1, CT): id = SHA-256(SPKI DER), RFC 6962. RSA PKCS#1 (some CT logs): id = SHA-256 of the
 * SPKI form. Ed25519 (Rekor v2): id = SHA-256(name || 0x0A || 0x01 || key), the C2SP signed-note key hash, with `name`
 * the host of `baseUrl` (as sigstore-go's note verifier does). A root whose id disagrees with its key is malformed.
 */
function pinnedLog(t: unknown, transparency: boolean): PinnedLog | null {
  if (!isObj(t) || !isObj(t.publicKey) || !isObj(t.logId)) throw new Error('log entry malformed');
  const der = b64(t.publicKey.rawBytes);
  const keyId = b64(t.logId.keyId);
  const valid = validity(t.publicKey.validFor);
  switch (t.publicKey.keyDetails) {
    case 'PKIX_ECDSA_P256_SHA_256': {
      if (!sha256(der).equals(keyId)) throw new Error('log id is not the SHA-256 of its key');
      return { keyId, key: createPublicKey({ key: der, format: 'der', type: 'spki' }), valid };
    }
    case 'PKCS1_RSA_PKCS1V5': {
      if (transparency) return null;
      const key = createPublicKey({ key: der, format: 'der', type: 'pkcs1' });
      if (!sha256(key.export({ type: 'spki', format: 'der' })).equals(keyId)) throw new Error('log id is not the SHA-256 of its key');
      return { keyId, key, valid };
    }
    case 'PKIX_ED25519': {
      if (!transparency) return null;
      const key = createPublicKey({ key: der, format: 'der', type: 'spki' });
      const raw = der.subarray(der.length - 32);
      const name = typeof t.baseUrl === 'string' ? new URL(t.baseUrl).hostname : '';
      if (!name || !sha256(Buffer.from(`${name}\n`), Buffer.from([1]), raw).equals(keyId)) throw new Error('log id is not the signed-note key hash of its key');
      return { keyId, key, valid, v2: { name } };
    }
    default:
      return null;
  }
}

function pinnedChain(c: unknown): PinnedCa {
  if (!isObj(c) || !isObj(c.certChain) || !Array.isArray(c.certChain.certificates) || c.certChain.certificates.length === 0) throw new Error('certificate authority entry malformed');
  return { chain: c.certChain.certificates.map((x) => new X509Certificate(b64(isObj(x) ? x.rawBytes : undefined))), valid: validity(c.validFor) };
}

/**
 * Parse a Sigstore `trusted_root.json` (media type `application/vnd.dev.sigstore.trustedroot+json;version=0.1`): transparency
 * logs, CT logs, Fulcio CAs and timestamp authorities. Throws on anything malformed. A root with no CT log means its owner
 * does not require SCTs; otherwise an SCT from a pinned CT log is required.
 */
export function parseTrustedRoot(json: unknown): PinnedRoots {
  if (!isObj(json) || json.mediaType !== 'application/vnd.dev.sigstore.trustedroot+json;version=0.1') throw new Error('not a trusted root v0.1');
  const arr = (k: string): unknown[] => (Array.isArray(json[k]) ? (json[k] as unknown[]) : []);
  const tlogs = arr('tlogs').map((t) => pinnedLog(t, true)).filter((x): x is PinnedLog => x !== null);
  const ctlogs = arr('ctlogs').map((t) => pinnedLog(t, false)).filter((x): x is PinnedLog => x !== null);
  const cas = arr('certificateAuthorities').map(pinnedChain);
  const tsas = arr('timestampAuthorities').map(pinnedChain);
  if (tlogs.length === 0 || cas.length === 0) throw new Error('a trusted root needs a transparency log and a CA');
  return { tlogs, ctlogs, cas, tsas };
}

// ------------------------------------------------------------------------------------------------ DER

interface Tlv { tag: number; start: number; body: number; end: number }
function tlv(b: Uint8Array, off: number, limit = b.length): Tlv {
  if (off + 2 > limit) throw new Error('DER truncated');
  const tag = b[off]!;
  if ((tag & 0x1f) === 0x1f) throw new Error('DER multi-byte tag');
  let len = b[off + 1]!;
  let body = off + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || body + n > limit) throw new Error('DER length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[body + i]!;
    body += n;
  }
  if (body + len > limit) throw new Error('DER overrun');
  return { tag, start: off, body, end: body + len };
}
function kids(b: Uint8Array, t: Tlv): Tlv[] {
  const out: Tlv[] = [];
  for (let o = t.body; o < t.end; ) {
    const c = tlv(b, o, t.end);
    out.push(c);
    o = c.end;
  }
  return out;
}
function oidText(b: Uint8Array, t: Tlv): string {
  if (t.tag !== 0x06 || t.end <= t.body) throw new Error('not an OID');
  const parts: number[] = [];
  let v = 0;
  for (let i = t.body; i < t.end; i++) {
    v = v * 128 + (b[i]! & 0x7f);
    if (!(b[i]! & 0x80)) {
      parts.push(v);
      v = 0;
    }
  }
  const first = parts.shift()!;
  return [Math.min(2, Math.floor(first / 40)), first - Math.min(2, Math.floor(first / 40)) * 40, ...parts].join('.');
}
function enc(tag: number, content: Uint8Array): Uint8Array {
  const n = content.length;
  const len = n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : n < 0x10000 ? [0x82, n >> 8, n & 0xff] : [0x83, n >> 16, (n >> 8) & 0xff, n & 0xff];
  return Buffer.concat([Buffer.from([tag, ...len]), content]);
}

interface Ext { oid: string; value: Uint8Array; tlv: Tlv }
interface ParsedCert { der: Uint8Array; tbs: Tlv; tbsKids: Tlv[]; extsWrapper: Tlv; exts: Ext[] }
function parseCert(der: Uint8Array): ParsedCert {
  const cert = tlv(der, 0);
  if (cert.tag !== 0x30 || cert.end !== der.length) throw new Error('certificate is not one SEQUENCE');
  const [tbs] = kids(der, cert);
  if (!tbs || tbs.tag !== 0x30) throw new Error('no TBSCertificate');
  const tbsKids = kids(der, tbs);
  const extsWrapper = tbsKids.find((k) => k.tag === 0xa3);
  if (!extsWrapper) throw new Error('no extensions');
  const [seq] = kids(der, extsWrapper);
  if (!seq || seq.tag !== 0x30) throw new Error('extensions malformed');
  const exts = kids(der, seq).map((e) => {
    const parts = kids(der, e);
    const oct = parts[parts.length - 1]!;
    if (oct.tag !== 0x04) throw new Error('extension value is not an OCTET STRING');
    return { oid: oidText(der, parts[0]!), value: der.slice(oct.body, oct.end), tlv: e };
  });
  const seen = new Set<string>();
  for (const e of exts) {
    if (seen.has(e.oid)) throw new Error(`duplicate extension ${e.oid}`);
    seen.add(e.oid);
  }
  return { der, tbs, tbsKids, extsWrapper, exts };
}

const utf8Strict = (b: Uint8Array): string => new TextDecoder('utf-8', { fatal: true }).decode(b);
/** Fulcio extension `.1.n`: raw UTF-8 for n <= 6, a DER UTF8String for n >= 8 (fulcio docs/oid-info.md). */
function fulcioExt(c: ParsedCert, n: number): string | undefined {
  const e = c.exts.find((x) => x.oid === `${OID_FULCIO}${n}`);
  if (!e) return undefined;
  if (n <= 6) return utf8Strict(e.value);
  const t = tlv(e.value, 0);
  if (t.tag !== 0x0c || t.end !== e.value.length) throw new Error(`extension .1.${n} is not a DER UTF8String`);
  return utf8Strict(e.value.slice(t.body, t.end));
}
/** Exactly one SAN, a URI or an email; anything else (OtherName, several names) is refused. */
function sanIdentity(c: ParsedCert): string {
  const e = c.exts.find((x) => x.oid === OID_SAN);
  if (!e) throw new Error('no subjectAltName');
  const seq = tlv(e.value, 0);
  const names = kids(e.value, seq);
  if (seq.tag !== 0x30 || names.length !== 1) throw new Error('subjectAltName must hold exactly one name');
  const n = names[0]!;
  if (n.tag !== 0x86 && n.tag !== 0x81) throw new Error('subjectAltName must be a URI or an email');
  return utf8Strict(e.value.slice(n.body, n.end));
}

// ------------------------------------------------------------------------------------------------ SCT (RFC 6962 3.2)

function verifySct(leaf: ParsedCert, issuer: X509Certificate, roots: PinnedRoots): string | null {
  const e = leaf.exts.find((x) => x.oid === OID_SCT_LIST);
  if (!e) return 'no embedded SCT';
  const outer = tlv(e.value, 0);
  if (outer.tag !== 0x04) return 'SCT list is not an OCTET STRING';
  const list = e.value.slice(outer.body, outer.end);
  const dv = new DataView(list.buffer, list.byteOffset, list.byteLength);
  if (list.length < 2 || dv.getUint16(0) !== list.length - 2) return 'SCT list length';
  // the precertificate TBS: the leaf TBS without the SCT list extension
  const der = leaf.der;
  const extSeq = kids(der, leaf.extsWrapper)[0]!;
  const keptExts = Buffer.concat(kids(der, extSeq).filter((k) => k.start !== e.tlv.start).map((k) => der.slice(k.start, k.end)));
  const tbsBody = Buffer.concat(leaf.tbsKids.map((k) => (k === leaf.extsWrapper ? enc(0xa3, enc(0x30, keptExts)) : der.slice(k.start, k.end))));
  const tbs = enc(0x30, tbsBody);
  const issuerKeyHash = createHash('sha256').update(issuer.publicKey.export({ type: 'spki', format: 'der' })).digest();
  let why = 'no SCT from a pinned CT log';
  for (let o = 2; o < list.length; ) {
    if (o + 2 > list.length) return 'SCT truncated';
    const n = dv.getUint16(o);
    const s = list.slice(o + 2, o + 2 + n);
    o += 2 + n;
    if (s.length !== n || n < 47) return 'SCT truncated';
    const sv = new DataView(s.buffer, s.byteOffset, s.byteLength);
    if (s[0] !== 0) continue;
    const logId = s.slice(1, 33);
    const ts = sv.getBigUint64(33);
    const extLen = sv.getUint16(41);
    const ext = s.slice(43, 43 + extLen);
    let p = 43 + extLen;
    if (p + 4 > s.length) return 'SCT truncated';
    const hashAlg = s[p]!;
    const sigAlg = s[p + 1]!;
    const sigLen = sv.getUint16(p + 2);
    const sig = s.slice(p + 4, p + 4 + sigLen);
    p += 4 + sigLen;
    if (p !== s.length || sig.length !== sigLen) return 'SCT malformed';
    const log = roots.ctlogs.find((l) => Buffer.from(l.keyId).equals(logId));
    if (!log) continue;
    if (hashAlg !== 4 || (sigAlg !== 3 && sigAlg !== 1)) { why = 'SCT is not SHA-256 with ECDSA or RSA'; continue; }
    const tsMs = Number(ts);
    if (tsMs < log.valid.start || tsMs > log.valid.end) { why = 'SCT log key not valid at its timestamp'; continue; }
    const head = Buffer.alloc(12);
    head[0] = 0; // v1
    head[1] = 0; // certificate_timestamp
    head.writeBigUInt64BE(ts, 2);
    head.writeUInt16BE(1, 10); // precert_entry
    const tbsLen = Buffer.from([tbs.length >> 16, (tbs.length >> 8) & 0xff, tbs.length & 0xff]);
    const extLenB = Buffer.from([ext.length >> 8, ext.length & 0xff]);
    const signed = Buffer.concat([head, issuerKeyHash, tbsLen, tbs, extLenB, ext]);
    if (nodeVerify('sha256', signed, log.key, sig)) return null;
    why = 'SCT signature invalid';
  }
  return why;
}

// ------------------------------------------------------------------------------------------------ RFC 3161 timestamps

const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_TST_INFO = '1.2.840.113549.1.9.16.1.4';
const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3';
const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const EKU_TIME_STAMPING = '1.3.6.1.5.5.7.3.8';
const DIGEST_OIDS: Record<string, string> = { '2.16.840.1.101.3.4.2.1': 'sha256', '2.16.840.1.101.3.4.2.2': 'sha384', '2.16.840.1.101.3.4.2.3': 'sha512' };
const digestOf = (b: Uint8Array, t: Tlv): string => {
  const alg = DIGEST_OIDS[oidText(b, kids(b, t)[0]!)];
  if (!alg) throw new Error('unsupported digest algorithm');
  return alg;
};
function generalizedTime(b: Uint8Array, t: Tlv): number {
  if (t.tag !== 0x18) throw new Error('genTime is not a GeneralizedTime');
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d{1,9}))?Z$/.exec(Buffer.from(b.slice(t.body, t.end)).toString('latin1'));
  if (!m) throw new Error('genTime malformed');
  const ms = Date.UTC(+m[1]!, +m[2]! - 1, +m[3]!, +m[4]!, +m[5]!, +m[6]!);
  // an impossible date (Feb 30, hour 24) would roll over in Date.UTC: refuse it
  if (new Date(ms).toISOString().slice(0, 19) !== `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}`) throw new Error('genTime is not a real date');
  return ms + (m[7] ? Math.floor(Number(`0.${m[7]}`) * 1000) : 0);
}
const inside = (c: X509Certificate, at: number): boolean => Date.parse(c.validFrom) <= at && at <= Date.parse(c.validTo);
/** Chain `chain` (leaf first, self-signed root last): issuer links, signatures, CA flags; every certificate valid at `at`. */
function chainOk(chain: readonly X509Certificate[], at: number): boolean {
  for (let i = 0; i < chain.length; i++) {
    const c = chain[i]!;
    const up = chain[i + 1] ?? c;
    if (!c.checkIssued(up) || !c.verify(up.publicKey) || !inside(c, at)) return false;
    if (i > 0 && !c.ca) return false;
  }
  return true;
}

/**
 * Verify an RFC 3161 TimeStampResp (or bare TimeStampToken) over `data` (the raw signature bytes, client spec 4.2.1): CMS
 * SignedData (RFC 5652) with TSTInfo content, `messageImprint` equal to the hash of `data`, signed attributes carrying the
 * content type and the digest of the TSTInfo, the signature over the DER SET of signed attributes under the leaf of a pinned
 * timestamp authority whose chain (and `validFor`) is valid at `genTime`, with the timeStamping EKU. Returns `genTime` (ms).
 */
export function verifyRfc3161(token: Uint8Array, data: Uint8Array, tsas: readonly PinnedCa[]): number {
  let ci = tlv(token, 0);
  if (ci.end !== token.length || ci.tag !== 0x30) throw new Error('timestamp is not one SEQUENCE');
  let parts = kids(token, ci);
  if (parts[0]?.tag === 0x30 && parts[0].end - parts[0].body >= 3 && token[kids(token, parts[0])[0]!.start] === 0x02) {
    // TimeStampResp: status (granted 0 or grantedWithMods 1), then the token
    const st = kids(token, parts[0])[0]!;
    const status = token.slice(st.body, st.end);
    if (!(status.length === 1 && (status[0] === 0 || status[0] === 1))) throw new Error('timestamp status is not granted');
    if (!parts[1]) throw new Error('no timeStampToken');
    ci = parts[1];
    parts = kids(token, ci);
  }
  if (oidText(token, parts[0]!) !== OID_SIGNED_DATA || parts[1]?.tag !== 0xa0) throw new Error('not CMS SignedData');
  const sd = kids(token, parts[1])[0]!;
  const sdk = kids(token, sd);
  const encap = sdk.find((k, i) => i > 1 && k.tag === 0x30)!;
  const ek = kids(token, encap);
  if (oidText(token, ek[0]!) !== OID_TST_INFO || ek[1]?.tag !== 0xa0) throw new Error('content is not TSTInfo');
  const octet = kids(token, ek[1])[0]!;
  if (octet.tag !== 0x04) throw new Error('TSTInfo is not an OCTET STRING');
  const tstBytes = token.slice(octet.body, octet.end);
  const tst = tlv(tstBytes, 0);
  const tk = kids(tstBytes, tst);
  const mi = kids(tstBytes, tk[2]!);
  const miAlg = digestOf(tstBytes, mi[0]!);
  const hashed = tstBytes.slice(mi[1]!.body, mi[1]!.end);
  if (!createHash(miAlg).update(data).digest().equals(Buffer.from(hashed))) throw new Error('messageImprint is not the hash of the signature');
  const genTime = generalizedTime(tstBytes, tk[4]!);
  const signerInfos = sdk[sdk.length - 1]!;
  if (signerInfos.tag !== 0x31) throw new Error('no signerInfos');
  const sis = kids(token, signerInfos);
  if (sis.length !== 1) throw new Error('exactly one SignerInfo is required');
  const si = kids(token, sis[0]!);
  const dAlg = digestOf(token, si[2]!);
  const attrs = si[3]!;
  if (attrs.tag !== 0xa0) throw new Error('signed attributes are required');
  let ctOk = false;
  let mdOk = false;
  for (const a of kids(token, attrs)) {
    const [oid, set] = kids(token, a);
    const vals = kids(token, set!);
    const o = oidText(token, oid!);
    if (vals.length !== 1) throw new Error('an attribute must have one value');
    if (o === OID_CONTENT_TYPE) ctOk = oidText(token, vals[0]!) === OID_TST_INFO;
    if (o === OID_MESSAGE_DIGEST) mdOk = createHash(dAlg).update(tstBytes).digest().equals(Buffer.from(token.slice(vals[0]!.body, vals[0]!.end)));
  }
  if (!ctOk || !mdOk) throw new Error('signed attributes do not commit to the TSTInfo');
  const signedAttrs = Buffer.concat([Buffer.from([0x31]), Buffer.from(token.slice(attrs.start + 1, attrs.end))]);
  const sigT = si[5]!;
  if (sigT.tag !== 0x04) throw new Error('signature is not an OCTET STRING');
  const sig = token.slice(sigT.body, sigT.end);
  for (const tsa of tsas) {
    if (genTime < tsa.valid.start || genTime > tsa.valid.end) continue;
    const leaf = tsa.chain[0]!;
    if (!(leaf.keyUsage ?? []).includes(EKU_TIME_STAMPING)) continue;
    if (!nodeVerify(dAlg, signedAttrs, leaf.publicKey, sig)) continue;
    if (!chainOk(tsa.chain, genTime)) continue;
    return genTime;
  }
  throw new Error('no pinned timestamp authority signed it (valid at its time)');
}

// ------------------------------------------------------------------------------------------------ Rekor

/**
 * Signed-note checkpoint (transparency-dev formats log/README.md, C2SP tlog-checkpoint and signed-note): origin, size and
 * base64 root lines, a blank line, then `— <name> <base64(keyhint4 || sig)>` lines. Rekor v1: the key hint is the first 4
 * bytes of the log id, ECDSA over the body. Rekor v2: the line must carry the log's note name (the host of its base URL), the
 * hint is the first 4 bytes of the note key hash (= the log id), Ed25519 over the body. Witness co-signatures are ignored.
 */
function verifyCheckpoint(text: string, log: PinnedLog, size: number, root: Buffer): string | null {
  const cut = text.indexOf('\n\n');
  if (cut < 0) return 'checkpoint has no signature block';
  const body = text.slice(0, cut + 1);
  const lines = body.split('\n');
  if (lines.length < 4 || lines[0]!.length === 0) return 'checkpoint body too short or without an origin';
  if (!/^[1-9][0-9]*$/.test(lines[1]!) || Number(lines[1]) !== size) return 'checkpoint size differs from the proof';
  if (!b64(lines[2]).equals(root)) return 'checkpoint root differs from the proof';
  for (const l of text.slice(cut + 2).split('\n')) {
    const m = /^\u2014 (\S+) ([A-Za-z0-9+/=]+)$/.exec(l);
    if (!m) continue;
    const raw = b64(m[2]);
    if (raw.length < 5 || !raw.subarray(0, 4).equals(Buffer.from(log.keyId).subarray(0, 4))) continue;
    if (log.v2 && m[1] !== log.v2.name) continue;
    if (nodeVerify(log.v2 ? null : 'sha256', Buffer.from(body, 'utf8'), log.key, raw.subarray(4))) return null;
  }
  return 'no checkpoint signature by the pinned log key';
}

const decInt = (v: unknown): number => {
  if (typeof v !== 'string' || !/^(0|[1-9][0-9]{0,15})$/.test(v)) throw new Error('not a decimal integer string');
  const n = Number(v);
  if (!Number.isSafeInteger(n)) throw new Error('integer out of range');
  return n;
};

/** DSSE PAE (secure-systems-lab/dsse protocol.md). */
export function dssePae(payloadType: string, payload: Uint8Array): Buffer {
  const t = Buffer.from(payloadType, 'utf8');
  return Buffer.concat([Buffer.from(`DSSEv1 ${t.length} `), t, Buffer.from(` ${payload.length} `), Buffer.from(payload)]);
}

function leafHashAlg(k: KeyObject): string | null {
  if (k.asymmetricKeyType !== 'ec') return null;
  const c = k.asymmetricKeyDetails?.namedCurve;
  return c === 'prime256v1' ? 'sha256' : c === 'secp384r1' ? 'sha384' : null;
}

// ------------------------------------------------------------------------------------------------ the verifier

/** What a verified bundle establishes, before any SLSA reading (what the native verifiers reproduce from the shared vectors). */
export interface SigstoreCore {
  identity: string;
  oidc_issuer: string;
  source_repo?: string;
  source_ref?: string;
  source_digest?: string;
  predicate_type: string;
  subjects: SubjectDigest[];
  /** The earliest verified signing time, unix seconds (a TSA genTime or a SET-verified Rekor v1 integratedTime). */
  signed_time: number;
  rekor_log_index: number;
  /** `v1` (SET or TSA time, Rekor v1 entry) or `v2` (TSA time, Rekor v2 hashedrekord entry). */
  rekor: 'v1' | 'v2';
  timestamps: { tsa: number; set: boolean };
}
export type SigstoreCoreResult = { ok: true; core: SigstoreCore; statement: Record<string, unknown> } | { ok: false; code: SigstoreCode; detail: string };

export interface VerifySigstoreOptions {
  roots: PinnedRoots;
}

/**
 * Verify a Sigstore bundle carrying a DSSE in-toto statement. Never throws; every refusal has a code and a detail.
 * Supports Rekor v1 `dsse` 0.0.1 and `intoto` 0.0.2 entries and Rekor v2 `hashedrekord` 0.0.2 entries (the DSSE mapping of
 * client spec 4.4 / Rekor v2 spec 6.1.4, persisted-body variant), RFC 3161 timestamps and the Rekor v1 SET as time sources.
 */
export function verifySigstoreBundleCore(bundle: unknown, o: VerifySigstoreOptions): SigstoreCoreResult {
  const no = (code: SigstoreCode, detail: string): SigstoreCoreResult => ({ ok: false, code, detail });
  let stage: SigstoreCode = 'malformed';
  try {
    if (!isObj(bundle) || !isObj(bundle.verificationMaterial)) return no('malformed', 'not a bundle');
    if (!(SIGSTORE_BUNDLE_MEDIA_TYPES as readonly unknown[]).includes(bundle.mediaType)) return no('media_type', `unsupported media type ${String(bundle.mediaType)}`);
    const vm = bundle.verificationMaterial;
    const v03 = bundle.mediaType !== SIGSTORE_BUNDLE_MEDIA_TYPES[0];
    // keyless only: v0.3 carries `certificate`, v0.2 `x509CertificateChain` (the leaf first; intermediates are ignored)
    const certRaw = v03 ? (isObj(vm.certificate) ? vm.certificate.rawBytes : undefined) : isObj(vm.x509CertificateChain) && Array.isArray(vm.x509CertificateChain.certificates) && isObj(vm.x509CertificateChain.certificates[0]) ? vm.x509CertificateChain.certificates[0].rawBytes : undefined;
    if (certRaw === undefined) return no('not_keyless', 'no Fulcio certificate (public-key bundles are not supported)');
    const env = bundle.dsseEnvelope;
    if (!isObj(env) || bundle.messageSignature !== undefined) return no('envelope', 'not a DSSE bundle');
    if (env.payloadType !== INTOTO_PAYLOAD_TYPE) return no('envelope', 'payloadType is not application/vnd.in-toto+json');
    if (!Array.isArray(env.signatures) || env.signatures.length !== 1 || !isObj(env.signatures[0])) return no('envelope', 'a DSSE envelope must carry exactly one signature');
    const payload = b64(env.payload);
    const dsseSig = b64(env.signatures[0].sig);
    const pae = dssePae(INTOTO_PAYLOAD_TYPE, payload);
    stage = 'cert_parse';
    const leafDer = new Uint8Array(b64(certRaw));
    const leaf = new X509Certificate(leafDer);
    const pc = parseCert(leafDer);
    const alg = leafHashAlg(leaf.publicKey);

    // ---- the log entry and its log
    stage = 'tlog_count';
    if (!Array.isArray(vm.tlogEntries) || vm.tlogEntries.length !== 1 || !isObj(vm.tlogEntries[0])) return no('tlog_count', 'exactly one transparency log entry is required');
    const t = vm.tlogEntries[0];
    stage = 'tlog_kind';
    const kv = isObj(t.kindVersion) ? `${String(t.kindVersion.kind)}/${String(t.kindVersion.version)}` : '';
    if (!['dsse/0.0.1', 'intoto/0.0.2', 'hashedrekord/0.0.2'].includes(kv)) return no('tlog_kind', `unsupported entry ${kv}`);
    const v2 = kv === 'hashedrekord/0.0.2';
    stage = 'tlog_key';
    const keyId = b64(isObj(t.logId) ? t.logId.keyId : undefined);
    const log = o.roots.tlogs.find((l) => Buffer.from(l.keyId).equals(keyId));
    if (!log) return no('tlog_key', 'the entry names a log the verifier did not pin');
    if (v2 !== (log.v2 !== undefined)) return no('tlog_key', 'the entry type does not match the log version');
    const logIndex = decInt(t.logIndex);
    const body = b64(t.canonicalizedBody);

    // ---- time first (client spec 4.2): every RFC 3161 timestamp must verify; a Rekor v1 SET must verify when present
    stage = 'tsa';
    const times: number[] = [];
    const tvd = isObj(vm.timestampVerificationData) ? vm.timestampVerificationData : {};
    const tsList = Array.isArray(tvd.rfc3161Timestamps) ? tvd.rfc3161Timestamps : [];
    for (const ts of tsList) times.push(verifyRfc3161(new Uint8Array(b64(isObj(ts) ? ts.signedTimestamp : undefined)), dsseSig, o.roots.tsas));
    const tsaCount = times.length;
    let set = false;
    if (!v2 && isObj(t.inclusionPromise)) {
      stage = 'tlog_set';
      const integrated = decInt(t.integratedTime);
      const setMsg = `{"body":${JSON.stringify(t.canonicalizedBody)},"integratedTime":${integrated},"logID":"${keyId.toString('hex')}","logIndex":${logIndex}}`;
      if (!nodeVerify('sha256', Buffer.from(setMsg, 'utf8'), log.key, b64(t.inclusionPromise.signedEntryTimestamp))) return no('tlog_set', 'signed entry timestamp invalid');
      times.push(integrated * 1000);
      set = true;
    }
    if (times.length === 0) return no('no_verified_time', 'no verified time: no RFC 3161 timestamp and no Rekor v1 signed entry timestamp');
    for (const at of times) if (at < log.valid.start || at > log.valid.end) return no('tlog_key', 'the log key was not valid at a signing time');

    // ---- inclusion
    stage = 'tlog_inclusion';
    const ip = t.inclusionProof;
    if (!isObj(ip) || !Array.isArray(ip.hashes) || !isObj(ip.checkpoint)) return no('tlog_inclusion', 'no inclusion proof');
    const root = b64(ip.rootHash);
    const size = decInt(ip.treeSize);
    if (!verifyRfc9162Inclusion(rfc9162LeafHash(body), decInt(ip.logIndex), size, ip.hashes.map((h) => new Uint8Array(b64(h))), new Uint8Array(root))) return no('tlog_inclusion', 'the inclusion proof does not lead to the root');
    stage = 'tlog_checkpoint';
    const cpe = verifyCheckpoint(String(ip.checkpoint.envelope), log, size, root);
    if (cpe) return no('tlog_checkpoint', cpe);

    // ---- certificate path at every verified time (hybrid model), CT
    stage = 'cert_chain';
    let issuer: X509Certificate | undefined;
    for (const ca of o.roots.cas) {
      if (times.some((at) => at < ca.valid.start || at > ca.valid.end)) continue;
      const [first] = ca.chain;
      if (!first || !leaf.checkIssued(first) || !leaf.verify(first.publicKey)) continue;
      if (times.every((at) => chainOk(ca.chain, at)) && ca.chain.every((c) => c.ca)) {
        issuer = first;
        break;
      }
    }
    if (!issuer) return no('cert_chain', 'no pinned CA issued the certificate, valid at every signing time');
    if (leaf.ca) return no('cert_chain', 'the leaf is a CA certificate');
    if (!times.every((at) => inside(leaf, at))) return no('cert_time', 'the certificate was not valid at a signing time');
    if (!(leaf.keyUsage ?? []).includes(EKU_CODE_SIGNING)) return no('cert_eku', 'the certificate lacks the code-signing EKU');
    if (o.roots.ctlogs.length > 0) {
      stage = 'sct';
      const sct = verifySct(pc, issuer, o.roots);
      if (sct) return no('sct', sct);
    }

    // ---- the entry body names this envelope
    stage = 'tlog_body';
    const eb = JSON.parse(body.toString('utf8')) as Record<string, unknown>;
    const spec = isObj(eb.spec) ? eb.spec : {};
    if (`${String(eb.kind)}/${String(eb.apiVersion)}` !== kv) return no('tlog_body', 'the entry body is not the kind the bundle names');
    const sameCert = (der: Buffer) => der.equals(Buffer.from(leafDer));
    const pemDer = (pem: string): Buffer => {
      const m = /^-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+)-----END CERTIFICATE-----\n?$/.exec(pem);
      return m ? b64(m[1]!.replace(/\n/g, '')) : Buffer.alloc(0);
    };
    const payloadSha = createHash('sha256').update(payload).digest('hex');
    if (kv === 'dsse/0.0.1') {
      const ph = isObj(spec.payloadHash) ? spec.payloadHash : {};
      if (ph.algorithm !== 'sha256' || ph.value !== payloadSha) return no('tlog_body', 'the entry names another payload');
      const sigs = Array.isArray(spec.signatures) ? spec.signatures : [];
      if (sigs.length !== 1 || !isObj(sigs[0])) return no('tlog_body', 'the entry must name exactly one signature');
      if (!b64(sigs[0].signature).equals(dsseSig)) return no('tlog_body', 'the entry names another signature');
      if (!sameCert(pemDer(b64(sigs[0].verifier).toString('utf8')))) return no('tlog_body', 'the entry names another certificate');
    } else if (kv === 'intoto/0.0.2') {
      // Rekor intoto 0.0.2 stores the envelope signature and payload base64 twice, and the key as base64 PEM
      const c = isObj(spec.content) ? spec.content : {};
      const ph = isObj(c.payloadHash) ? c.payloadHash : {};
      if (ph.algorithm !== 'sha256' || ph.value !== payloadSha) return no('tlog_body', 'the entry names another payload');
      const e = isObj(c.envelope) ? c.envelope : {};
      const sigs = Array.isArray(e.signatures) ? e.signatures : [];
      if (sigs.length !== 1 || !isObj(sigs[0])) return no('tlog_body', 'the entry must name exactly one signature');
      if (!b64(b64(sigs[0].sig).toString('latin1')).equals(dsseSig)) return no('tlog_body', 'the entry names another signature');
      if (!sameCert(pemDer(b64(sigs[0].publicKey).toString('utf8')))) return no('tlog_body', 'the entry names another certificate');
    } else {
      // Rekor v2 hashedrekord over DSSE: digest = Hash(PAE), content = the envelope signature, verifier = the leaf
      const h = isObj(spec.hashedRekordV002) ? spec.hashedRekordV002 : {};
      const data = isObj(h.data) ? h.data : {};
      const hashName = data.algorithm === 'SHA2_256' ? 'sha256' : data.algorithm === 'SHA2_384' ? 'sha384' : data.algorithm === 'SHA2_512' ? 'sha512' : null;
      if (!hashName || hashName !== alg) return no('tlog_body', 'the entry digest algorithm is not the signing key\'s');
      if (!b64(data.digest).equals(createHash(hashName).update(pae).digest())) return no('tlog_body', 'the entry names another envelope');
      const sg = isObj(h.signature) ? h.signature : {};
      if (!b64(sg.content).equals(dsseSig)) return no('tlog_body', 'the entry names another signature');
      const ver = isObj(sg.verifier) && isObj(sg.verifier.x509Certificate) ? sg.verifier.x509Certificate.rawBytes : undefined;
      if (!sameCert(b64(ver))) return no('tlog_body', 'the entry names another certificate');
    }

    // ---- DSSE signature
    stage = 'signature';
    if (!alg) return no('signature', 'unsupported leaf key type');
    if (!nodeVerify(alg, pae, leaf.publicKey, dsseSig)) return no('signature', 'DSSE signature invalid');

    // ---- identity
    stage = 'identity';
    const identity = sanIdentity(pc);
    const issV2 = fulcioExt(pc, 8);
    const issV1 = fulcioExt(pc, 1);
    if (issV2 !== undefined && issV1 !== undefined && issV2 !== issV1) return no('identity', 'the two issuer extensions disagree');
    const oidcIssuer = issV2 ?? issV1;
    if (!oidcIssuer) return no('identity', 'no OIDC issuer extension');
    const sourceRepo = fulcioExt(pc, 12);
    const sourceDigest = fulcioExt(pc, 13);
    const sourceRef = fulcioExt(pc, 14);

    // ---- statement
    stage = 'statement';
    const st = JSON.parse(utf8Strict(payload)) as Record<string, unknown>;
    if (st._type !== INTOTO_STATEMENT_V1) return no('statement', 'not an in-toto Statement v1');
    if (!Array.isArray(st.subject) || st.subject.length === 0) return no('statement', 'no subject');
    const subjects: SubjectDigest[] = [];
    for (const s of st.subject) {
      const d = isObj(s) && isObj(s.digest) ? s.digest : {};
      for (const a of ['sha256', 'sha512'] as const) if (typeof d[a] === 'string') subjects.push({ alg: a, digest: d[a] as string });
    }
    if (subjects.length === 0 || subjects.length > 64) return no('statement', 'no sha256/sha512 subject digest (or more than 64)');
    if (typeof st.predicateType !== 'string') return no('statement', 'no predicateType');
    return {
      ok: true,
      statement: st,
      core: {
        identity,
        oidc_issuer: oidcIssuer,
        ...(sourceRepo !== undefined ? { source_repo: sourceRepo } : {}),
        ...(sourceRef !== undefined ? { source_ref: sourceRef } : {}),
        ...(sourceDigest !== undefined ? { source_digest: sourceDigest } : {}),
        predicate_type: st.predicateType,
        subjects,
        signed_time: Math.floor(Math.min(...times) / 1000),
        rekor_log_index: logIndex,
        rekor: v2 ? 'v2' : 'v1',
        timestamps: { tsa: tsaCount, set },
      },
    };
  } catch (e) {
    return no(stage, `fail closed: ${e instanceof Error ? e.message : 'error'}`);
  }
}

/** {@link verifySigstoreBundleCore}, then the SLSA v1 predicate: the facts `provenanceGate` checks. */
export function verifySigstoreBundle(bundle: unknown, o: VerifySigstoreOptions): SigstoreResult {
  const r = verifySigstoreBundleCore(bundle, o);
  if (!r.ok) return r;
  const st = r.statement;
  const c = r.core;
  if (st.predicateType !== SLSA_PROVENANCE_V1) return { ok: false, code: 'predicate', detail: `predicate ${String(st.predicateType)} is not SLSA provenance v1` };
  const pr = isObj(st.predicate) ? st.predicate : {};
  const bd = isObj(pr.buildDefinition) ? pr.buildDefinition : {};
  const rd = isObj(pr.runDetails) ? pr.runDetails : {};
  const builderId = isObj(rd.builder) ? rd.builder.id : undefined;
  if (typeof bd.buildType !== 'string' || typeof builderId !== 'string' || !isObj(bd.externalParameters)) return { ok: false, code: 'predicate', detail: 'buildType, externalParameters and builder.id are required (SLSA Build L1)' };
  const dep0 = Array.isArray(bd.resolvedDependencies) && isObj(bd.resolvedDependencies[0]) ? bd.resolvedDependencies[0] : undefined;
  const depCommit = dep0 && isObj(dep0.digest) && typeof dep0.digest.gitCommit === 'string' ? dep0.digest.gitCommit : undefined;
  const facts: BuildProvenanceFacts = {
    v: 1,
    predicate_type: SLSA_PROVENANCE_V1,
    build_type: bd.buildType,
    builder_id: builderId,
    subjects: c.subjects,
    identity: c.identity,
    oidc_issuer: c.oidc_issuer,
    ...(c.source_repo !== undefined ? { source_repo: c.source_repo } : {}),
    ...(c.source_ref !== undefined ? { source_ref: c.source_ref } : {}),
    ...(c.source_digest !== undefined ? { source_digest: c.source_digest } : {}),
    ...(dep0 && typeof dep0.uri === 'string' ? { provenance_source: { uri: dep0.uri, ...(depCommit !== undefined ? { git_commit: depCommit } : {}) } } : {}),
    integrated_time: c.signed_time,
    rekor_log_index: c.rekor_log_index,
  };
  return { ok: true, facts };
}
