/**
 * TEST-ONLY Sigstore bundle minter. Builds, under a private test PKI and private test logs, bundles in the real wire format
 * (Rekor v1 dsse / intoto, Rekor v2 hashedrekord, SET and RFC 3161 time, embedded SCT, inclusion proof, checkpoint) in which
 * every check passes unless a knob breaks exactly one piece. Signatures are re-made around every change, so a refusal comes
 * from the check under test and not from a stale signature. NEVER import this from production code.
 */
import { X509Certificate, createHash, generateKeyPairSync, sign as nodeSign, type KeyObject } from 'node:crypto';
import { INTOTO_STATEMENT_V1, SLSA_PROVENANCE_V1, rfc9162LeafHash } from '@atlasauth/pca';
import { cat, ctxPrim, ecdsaSign, ext, extension, forgeCert, forgeKey, generalizedTime, integer, octets, oid, readDer, seq, set, tlv, utf8, type DnAttr, type Extension, type ForgeKey } from './forge-x509';
import type { PinnedCa, PinnedLog, PinnedRoots } from '../sigstore';

export const T0 = Date.UTC(2026, 0, 15, 12, 0, 0);
export const HOUR = 3_600_000;
export const MEDIA_V03 = 'application/vnd.dev.sigstore.bundle.v0.3+json';
export const MEDIA_V03B = 'application/vnd.dev.sigstore.bundle+json;version=0.3';
export const MEDIA_V02 = 'application/vnd.dev.sigstore.bundle+json;version=0.2';
export const ISSUER_URL = 'https://token.actions.example.test';
export const IDENTITY = 'https://example.test/org/repo/.github/workflows/release.yml@refs/heads/main';
export const OID = {
  codeSigning: '1.3.6.1.5.5.7.3.3',
  timeStamping: '1.3.6.1.5.5.7.3.8',
  signedData: '1.2.840.113549.1.7.2',
  tstInfo: '1.2.840.113549.1.9.16.1.4',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',
  ecdsaSha256: '1.2.840.10045.4.3.2',
  fulcio: '1.3.6.1.4.1.57264.1.',
  sctList: '1.3.6.1.4.1.11129.2.4.2',
  san: '2.5.29.17',
  basicConstraints: '2.5.29.19',
} as const;

export const b64 = (b: Uint8Array | string): string => (typeof b === 'string' ? Buffer.from(b, 'utf8') : Buffer.from(b)).toString('base64');
const be16 = (n: number): Uint8Array => Uint8Array.of((n >> 8) & 0xff, n & 0xff);
const be64 = (n: bigint): Buffer => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(n);
  return b;
};
const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const sha = (alg: 'sha256' | 'sha384' | 'sha512', ...p: Uint8Array[]): Buffer => {
  const h = createHash(alg);
  for (const x of p) h.update(x);
  return h.digest();
};

// ------------------------------------------------------------------------------------------------ CAs
export interface Ca {
  key: ForgeKey;
  der: Uint8Array;
  x509: X509Certificate;
  name: DnAttr[];
}
export interface CaOpts {
  from?: Date;
  to?: Date;
  /** basicConstraints cA (default true). */
  isCa?: boolean;
  parent?: Ca;
  /** Issuer name written into the certificate (default: the parent's, or its own). */
  issuerName?: DnAttr[];
  /** Key that signs the certificate (default: the parent's, or its own). */
  signer?: ForgeKey;
}
export function mintCa(label: string, o: CaOpts = {}): Ca {
  const key = forgeKey(`ca/${label}`, 'P-256');
  const name: DnAttr[] = [['O', 'forge'], ['CN', label]];
  const signer = o.signer ?? o.parent?.key ?? key;
  const c = forgeCert({
    subject: name,
    issuer: o.issuerName ?? o.parent?.name ?? name,
    subjectKey: key,
    signer,
    serial: 1n,
    notBefore: o.from ?? new Date(Date.UTC(2020, 0, 1)),
    notAfter: o.to ?? new Date(Date.UTC(2040, 0, 1)),
    extensions: [ext.basicConstraints(o.isCa ?? true), ext.keyUsage(['keyCertSign', 'cRLSign'])],
  });
  return { key, der: c.der, x509: new X509Certificate(c.der), name };
}

// ------------------------------------------------------------------------------------------------ logs
export interface Log {
  priv: KeyObject;
  pub: KeyObject;
  keyId: Buffer;
  pinned: PinnedLog;
  name?: string;
}
const FAR: { start: number; end: number } = { start: Date.UTC(2020, 0, 1), end: Infinity };
export function mintLog(kind: 'ec' | 'v2', name = 'rekor.test'): Log {
  if (kind === 'ec') {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const keyId = sha('sha256', publicKey.export({ type: 'spki', format: 'der' }));
    return { priv: privateKey, pub: publicKey, keyId, pinned: { keyId, key: publicKey, valid: { ...FAR } } };
  }
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const der = publicKey.export({ type: 'spki', format: 'der' });
  const keyId = sha('sha256', enc(`${name}\n`), Uint8Array.of(1), der.subarray(der.length - 32));
  return { priv: privateKey, pub: publicKey, keyId, name, pinned: { keyId, key: publicKey, valid: { ...FAR }, v2: { name } } };
}

// ------------------------------------------------------------------------------------------------ RFC 3161
export interface TokenPieces {
  /** Children of TSTInfo, in order; `tstInfo` replaces the whole structure when set. */
  version: Uint8Array;
  policy: Uint8Array;
  imprintAlg: Uint8Array;
  imprintHash: Uint8Array;
  serial: Uint8Array;
  genTime: Uint8Array;
  tstExtra: Uint8Array[];
  tstInfo?: Uint8Array;
  sdOid: Uint8Array;
  sdTag: number;
  sdVersion: Uint8Array;
  digestAlgs: Uint8Array;
  encapOid: Uint8Array;
  encapTag: number;
  octetTag: number;
  encapSeqTag: number;
  /** Replaces the whole EncapsulatedContentInfo. */
  encap?: Uint8Array;
  /** DER of every signed attribute. */
  attrs: Uint8Array[];
  attrsTag: number;
  signerVersion: Uint8Array;
  sid: Uint8Array;
  signerDigestAlg: Uint8Array;
  sigAlg: Uint8Array;
  sigTag: number;
  /** Replaces the real signature value. */
  signature?: Uint8Array;
  signerInfosTag: number;
  signerInfoCount: number;
  /** Status INTEGER of a TimeStampResp wrapper (null: a bare token). */
  status: Uint8Array | null;
  dAlg: 'sha256' | 'sha384';
  /** The TSA key that signs the attributes. */
  signKey: ForgeKey;
}
export interface Tsa {
  root: Ca;
  leafKey: ForgeKey;
  leaf: X509Certificate;
  pinned: PinnedCa;
}
export interface TsaOpts {
  eku?: string[];
  leafFrom?: Date;
  leafTo?: Date;
  rootIsCa?: boolean;
  valid?: { start: number; end: number };
}
export function mintTsa(o: TsaOpts = {}): Tsa {
  const root = mintCa('tsa-root', { isCa: o.rootIsCa ?? true });
  const leafKey = forgeKey('tsa-leaf', 'P-256');
  const c = forgeCert({
    subject: [['O', 'forge'], ['CN', 'tsa-leaf']],
    issuer: root.name,
    subjectKey: leafKey,
    signer: root.key,
    serial: 2n,
    notBefore: o.leafFrom ?? new Date(Date.UTC(2020, 0, 1)),
    notAfter: o.leafTo ?? new Date(Date.UTC(2040, 0, 1)),
    extensions: [ext.keyUsage(['digitalSignature']), ext.extKeyUsage(o.eku ?? [OID.timeStamping], true)],
  });
  const leaf = new X509Certificate(c.der);
  return { root, leafKey, leaf, pinned: { chain: [leaf, root.x509], valid: o.valid ?? { ...FAR } } };
}
const algOid = { sha256: OID.sha256, sha384: OID.sha384, sha512: OID.sha512 } as const;
/** A TimeStampResp (or a bare token) over `data` with every piece valid; `mod` edits the pieces first. */
export function mintToken(data: Uint8Array, tsa: Tsa, o: { genTime?: Date; mod?: (p: TokenPieces) => void } = {}): Uint8Array {
  const gen = o.genTime ?? new Date(T0);
  const p: TokenPieces = {
    version: integer(1),
    policy: oid('1.2.3.4'),
    imprintAlg: seq(oid(OID.sha256)),
    imprintHash: octets(sha('sha256', data)),
    serial: integer(5),
    genTime: generalizedTime(gen),
    tstExtra: [],
    sdOid: oid(OID.signedData),
    sdTag: 0xa0,
    sdVersion: integer(3),
    digestAlgs: set(seq(oid(OID.sha256))),
    encapOid: oid(OID.tstInfo),
    encapTag: 0xa0,
    octetTag: 0x04,
    encapSeqTag: 0x30,
    attrs: [],
    attrsTag: 0xa0,
    signerVersion: integer(1),
    sid: seq(),
    signerDigestAlg: seq(oid(OID.sha256)),
    sigAlg: seq(oid(OID.ecdsaSha256)),
    sigTag: 0x04,
    signerInfosTag: 0x31,
    signerInfoCount: 1,
    status: null,
    dAlg: 'sha256',
    signKey: tsa.leafKey,
  };
  o.mod?.(p);
  const tstInfo = p.tstInfo ?? seq(p.version, p.policy, seq(p.imprintAlg, p.imprintHash), p.serial, p.genTime, ...p.tstExtra);
  const attrs =
    p.attrs.length > 0
      ? p.attrs
      : [seq(oid(OID.contentType), set(oid(OID.tstInfo))), seq(oid(OID.messageDigest), set(octets(sha(p.dAlg, tstInfo))))];
  const signedAttrs = tlv(0x31, ...attrs);
  const sig = p.signature ?? ecdsaSign(p.signKey, p.dAlg, signedAttrs).der;
  const si = seq(p.signerVersion, p.sid, p.signerDigestAlg, tlv(p.attrsTag, ...attrs), p.sigAlg, tlv(p.sigTag, sig));
  const encap = p.encap ?? tlv(p.encapSeqTag, p.encapOid, tlv(p.encapTag, tlv(p.octetTag, tstInfo)));
  const sd = seq(p.sdVersion, p.digestAlgs, encap, tlv(p.signerInfosTag, ...Array.from({ length: p.signerInfoCount }, () => si)));
  const token = seq(p.sdOid, tlv(p.sdTag, sd));
  return p.status === null ? token : seq(seq(p.status), token);
}
export const digestOidFor = (a: 'sha256' | 'sha384' | 'sha512'): string => algOid[a];

// ------------------------------------------------------------------------------------------------ leaf + SCT
export interface SctSpec {
  version?: number;
  logId?: Uint8Array;
  ts?: bigint;
  ext?: Uint8Array;
  hashAlg?: number;
  sigAlg?: number;
  sig?: Uint8Array;
  signKey?: KeyObject;
  trailing?: Uint8Array;
  /** The whole SCT body, replacing everything above. */
  raw?: Uint8Array;
}
export interface LeafOpts {
  curve?: 'P-256' | 'P-384';
  /** SubjectPublicKeyInfo to certify instead of the leaf key's (an unsupported key type). */
  spki?: Uint8Array;
  from?: Date;
  to?: Date;
  identity?: string;
  /** Raw GeneralName TLVs of the SAN (default: one URI with `identity`). */
  san?: Uint8Array[];
  noSan?: boolean;
  /** Fulcio `.1.1` (raw UTF-8) and `.1.8` (DER UTF8String) issuer; null omits. */
  issuerV1?: string | null;
  issuerV2?: string | null;
  repo?: string | null;
  digest?: string | null;
  ref?: string | null;
  /** Extended key usages (default: code signing); null omits the extension. */
  eku?: string[] | null;
  /** basicConstraints: none (default), `ca` (cA TRUE), `false` (cA FALSE written out), `empty` (the default cA FALSE), `pathlen` (a path length only) or `ber` (cA FALSE, indefinite length). */
  bc?: 'none' | 'ca' | 'false' | 'empty' | 'pathlen' | 'ber' | 'octet' | 'bool2';
  /** Final say over the extension list (before the SCT is added). */
  exts?: (base: Extension[]) => Extension[];
  scts?: SctSpec[];
  sctList?: (list: Uint8Array) => Uint8Array;
  /** The extension value around the SCT list (default: an OCTET STRING holding it). */
  sctValue?: (list: Uint8Array) => Uint8Array;
  /** Mint the leaf's SCT under this CT log (default: the bundle's). */
  ctLog?: CtLog;
}
export interface CtLog {
  priv: KeyObject;
  pinned: PinnedLog;
}
export function mintCtLog(): CtLog {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const keyId = sha('sha256', publicKey.export({ type: 'spki', format: 'der' }));
  return { priv: privateKey, pinned: { keyId, key: publicKey, valid: { ...FAR } } };
}
const fulcio = (n: number, v: string, raw: boolean): Extension => extension(`${OID.fulcio}${n}`, false, raw ? enc(v) : utf8(v));
function tbsOf(certDer: Uint8Array): Uint8Array {
  const t = readDer(certDer).children![0]!;
  return seq(certDer.subarray(t.start, t.end));
}
export function mintLeaf(ca: Ca, o: LeafOpts, ct: CtLog): { key: ForgeKey; der: Uint8Array } {
  const key = forgeKey(`leaf/${o.curve ?? 'P-256'}`, o.curve ?? 'P-256');
  const base: Extension[] = [ext.keyUsage(['digitalSignature'])];
  if (o.eku !== null) base.push(ext.extKeyUsage(o.eku ?? [OID.codeSigning], true));
  if (o.bc === 'ca') base.push(extension(OID.basicConstraints, true, seq(tlv(0x01, Uint8Array.of(0xff)))));
  if (o.bc === 'false') base.push(extension(OID.basicConstraints, true, seq(tlv(0x01, Uint8Array.of(0x00)))));
  if (o.bc === 'empty') base.push(extension(OID.basicConstraints, true, seq()));
  if (o.bc === 'pathlen') base.push(extension(OID.basicConstraints, true, seq(integer(5))));
  if (o.bc === 'octet') base.push(extension(OID.basicConstraints, true, tlv(0x04, tlv(0x01, Uint8Array.of(0xff)))));
  if (o.bc === 'bool2') base.push(extension(OID.basicConstraints, true, seq(tlv(0x01, Uint8Array.of(0xff, 0x00)))));
  if (o.bc === 'ber') base.push(extension(OID.basicConstraints, true, Uint8Array.of(0x30, 0x80, 0x01, 0x01, 0x00, 0x00, 0x00)));
  if (!o.noSan) base.push(extension(OID.san, false, seq(...(o.san ?? [ctxPrim(6, enc(o.identity ?? IDENTITY))]))));
  if (o.issuerV1 !== null) base.push(fulcio(1, o.issuerV1 ?? ISSUER_URL, true));
  if (o.issuerV2 !== null) base.push(fulcio(8, o.issuerV2 ?? ISSUER_URL, false));
  if (o.repo !== null) base.push(fulcio(12, o.repo ?? 'https://example.test/org/repo', false));
  if (o.digest !== null) base.push(fulcio(13, o.digest ?? 'd'.repeat(40), false));
  if (o.ref !== null) base.push(fulcio(14, o.ref ?? 'refs/heads/main', false));
  const exts = o.exts ? o.exts(base) : base;
  const mk = (extensions: Extension[]) =>
    forgeCert({
      subject: [['CN', 'leaf']],
      issuer: ca.name,
      subjectKey: o.spki ? { ...key, spki: o.spki } : key,
      signer: ca.key,
      serial: 7n,
      notBefore: o.from ?? new Date(T0 - 600_000),
      notAfter: o.to ?? new Date(T0 + 600_000),
      extensions,
    });
  if (!o.scts) return { key, der: mk(exts).der };
  const tbs = tbsOf(mk(exts).der);
  const issuerKeyHash = sha('sha256', ca.key.spki);
  const logKey = o.ctLog ?? ct;
  const parts = o.scts.map((s) => {
    if (s.raw) return s.raw;
    const ts = s.ts ?? BigInt(T0);
    const e = s.ext ?? new Uint8Array(0);
    const head = Buffer.alloc(12);
    head.writeBigUInt64BE(ts, 2);
    head.writeUInt16BE(1, 10);
    const signed = cat(head, issuerKeyHash, Uint8Array.of(tbs.length >> 16, (tbs.length >> 8) & 0xff, tbs.length & 0xff), tbs, be16(e.length), e);
    const sig = s.sig ?? new Uint8Array(nodeSign('sha256', signed, s.signKey ?? logKey.priv));
    return cat(Uint8Array.of(s.version ?? 0), s.logId ?? logKey.pinned.keyId, be64(ts), be16(e.length), e, Uint8Array.of(s.hashAlg ?? 4, s.sigAlg ?? 3), be16(sig.length), sig, s.trailing ?? new Uint8Array(0));
  });
  let list: Uint8Array = cat(...parts.map((p) => cat(be16(p.length), p)));
  list = cat(be16(list.length), list);
  if (o.sctList) list = o.sctList(list);
  const value = o.sctValue ? o.sctValue(list) : octets(list);
  return { key, der: mk([...exts, extension(OID.sctList, false, value)]).der };
}

// ------------------------------------------------------------------------------------------------ the bundle
export interface CheckpointParts {
  origin: string;
  size: number;
  rootB64: string;
  name: string;
  keyId: Buffer;
  sign: (body: string) => Buffer;
  /** The canonical text: body, blank line, one signature line. */
  text: string;
}
export interface MintOpts {
  rekor?: 'dsse' | 'intoto' | 'v2';
  media?: string;
  leaf?: LeafOpts;
  /** Edit the in-toto statement before it is serialised (return a value to replace it). */
  statement?: (s: Record<string, unknown>) => Record<string, unknown> | void;
  rawPayload?: string | Uint8Array;
  /** Sign the DSSE envelope with this key instead of the leaf's. */
  dsseKey?: ForgeKey;
  /** Rekor v1: include a signed entry timestamp (default true). */
  set?: boolean;
  /** Seconds added to the entry's integrated time (and so to the SET time). */
  integratedOffsetSec?: number;
  /** RFC 3161 timestamps to include, each built over the DSSE signature. */
  tsa?: { genTime?: Date; mod?: (p: TokenPieces) => void }[];
  tsaOpts?: TsaOpts;
  /** Edit the log entry body before it is encoded (the SET and proof are made over the edited body). */
  body?: (b: any) => void;
  checkpoint?: (c: CheckpointParts) => string;
  /** Pin an SCT-checking CT log (default: only when the leaf carries SCTs). */
  ctlogs?: boolean;
  roots?: (r: PinnedRoots) => PinnedRoots | void;
  /** Edit the finished bundle (nothing is re-signed). */
  bundle?: (b: any) => void;
  /** Edit the finished tlog entry (nothing is re-signed). */
  entry?: (e: any) => void;
  caOpts?: CaOpts;
  logKind?: 'ec' | 'v2';
}
export interface Minted {
  bundle: any;
  roots: PinnedRoots;
  ca: Ca;
  log: Log;
  ct: CtLog;
  tsa: Tsa;
  leafDer: Uint8Array;
  leafKey: ForgeKey;
  dsseSig: Uint8Array;
  payload: Uint8Array;
  pae: Buffer;
}
export function pae(type: string, payload: Uint8Array): Buffer {
  const t = Buffer.from(type, 'utf8');
  return Buffer.concat([Buffer.from(`DSSEv1 ${t.length} `), t, Buffer.from(` ${payload.length} `), Buffer.from(payload)]);
}
export function defaultStatement(): Record<string, unknown> {
  return {
    _type: INTOTO_STATEMENT_V1,
    subject: [{ name: 'artifact', digest: { sha256: 'ab'.repeat(32) } }],
    predicateType: SLSA_PROVENANCE_V1,
    predicate: {
      buildDefinition: {
        buildType: 'https://example.test/build/v1',
        externalParameters: {},
        resolvedDependencies: [{ uri: 'git+https://example.test/org/repo@refs/heads/main', digest: { gitCommit: 'c'.repeat(40) } }],
      },
      runDetails: { builder: { id: 'https://example.test/builder' } },
    },
  };
}
export function mint(o: MintOpts = {}): Minted {
  const rekor = o.rekor ?? 'dsse';
  const v2 = rekor === 'v2';
  const ca = mintCa('fulcio-ca', o.caOpts);
  const log = mintLog(o.logKind ?? (v2 ? 'v2' : 'ec'));
  const ct = mintCtLog();
  const tsa = mintTsa(o.tsaOpts);
  const leaf = mintLeaf(ca, o.leaf ?? {}, ct);
  const hashAlg = leaf.key.curve === 'P-384' ? 'sha384' : 'sha256';

  let st: Record<string, unknown> = defaultStatement();
  if (o.statement) {
    const edited = o.statement(st);
    if (edited) st = edited;
  }
  const payload = typeof o.rawPayload === 'string' ? enc(o.rawPayload) : (o.rawPayload ?? enc(JSON.stringify(st)));
  const type = 'application/vnd.in-toto+json';
  const p = pae(type, payload);
  const dsseSig = ecdsaSign(o.dsseKey ?? leaf.key, hashAlg, p).der;
  const pem = Buffer.from(`-----BEGIN CERTIFICATE-----\n${Buffer.from(leaf.der).toString('base64').match(/.{1,64}/g)!.join('\n')}\n-----END CERTIFICATE-----\n`);
  const payloadSha = createHash('sha256').update(payload).digest('hex');

  let body: any;
  if (rekor === 'dsse') {
    body = { apiVersion: '0.0.1', kind: 'dsse', spec: { payloadHash: { algorithm: 'sha256', value: payloadSha }, signatures: [{ signature: b64(dsseSig), verifier: b64(pem) }] } };
  } else if (rekor === 'intoto') {
    body = { apiVersion: '0.0.2', kind: 'intoto', spec: { content: { payloadHash: { algorithm: 'sha256', value: payloadSha }, envelope: { signatures: [{ sig: b64(b64(dsseSig)), publicKey: b64(pem) }] } } } };
  } else {
    body = {
      apiVersion: '0.0.2',
      kind: 'hashedrekord',
      spec: { hashedRekordV002: { data: { algorithm: hashAlg === 'sha384' ? 'SHA2_384' : 'SHA2_256', digest: b64(sha(hashAlg, p)) }, signature: { content: b64(dsseSig), verifier: { x509Certificate: { rawBytes: b64(leaf.der) } } } } },
    };
  }
  // the bundle names the kind the log really holds; a body edit must not move it
  const kindVersion = { kind: body.kind, version: body.apiVersion };
  o.body?.(body);
  const canonicalizedBody = b64(JSON.stringify(body));
  const bodyBytes = Buffer.from(canonicalizedBody, 'base64');
  const rootHash = Buffer.from(rfc9162LeafHash(bodyBytes));
  const logIndex = 12345;
  const integrated = T0 / 1000 + (o.integratedOffsetSec ?? 0);

  const origin = 'rekor.test - 1';
  const name = log.name ?? 'rekor.test';
  const sign = (b: string): Buffer => nodeSign(v2 ? null : 'sha256', Buffer.from(b, 'utf8'), log.priv);
  const cpBody = `${origin}\n1\n${rootHash.toString('base64')}\n`;
  const sigLine = `— ${name} ${b64(Buffer.concat([log.keyId.subarray(0, 4), sign(cpBody)]))}\n`;
  const cpParts: CheckpointParts = { origin, size: 1, rootB64: rootHash.toString('base64'), name, keyId: log.keyId, sign, text: `${cpBody}\n${sigLine}` };
  const envelope = o.checkpoint ? o.checkpoint(cpParts) : cpParts.text;

  const entry: any = {
    logIndex: String(logIndex),
    logId: { keyId: b64(log.keyId) },
    kindVersion,
    integratedTime: String(integrated),
    inclusionProof: { logIndex: '0', rootHash: rootHash.toString('base64'), treeSize: '1', hashes: [], checkpoint: { envelope } },
    canonicalizedBody,
  };
  if (!v2 && (o.set ?? true)) {
    const setMsg = `{"body":${JSON.stringify(canonicalizedBody)},"integratedTime":${integrated},"logID":"${log.keyId.toString('hex')}","logIndex":${logIndex}}`;
    entry.inclusionPromise = { signedEntryTimestamp: b64(nodeSign('sha256', Buffer.from(setMsg, 'utf8'), log.priv)) };
  }
  o.entry?.(entry);

  const tokens = (o.tsa ?? (v2 ? [{}] : [])).map((t) => ({ signedTimestamp: b64(mintToken(dsseSig, tsa, t)) }));
  const vm: any = { tlogEntries: [entry] };
  if (o.media === MEDIA_V02) vm.x509CertificateChain = { certificates: [{ rawBytes: b64(leaf.der) }] };
  else vm.certificate = { rawBytes: b64(leaf.der) };
  if (tokens.length > 0) vm.timestampVerificationData = { rfc3161Timestamps: tokens };
  const bundle: any = {
    mediaType: o.media ?? MEDIA_V03,
    verificationMaterial: vm,
    dsseEnvelope: { payload: b64(payload), payloadType: type, signatures: [{ sig: b64(dsseSig) }] },
  };
  o.bundle?.(bundle);

  let roots: PinnedRoots = {
    tlogs: [log.pinned],
    ctlogs: o.ctlogs || o.leaf?.scts ? [(o.leaf?.ctLog ?? ct).pinned] : [],
    cas: [{ chain: [ca.x509], valid: { start: Date.UTC(2020, 0, 1), end: Date.UTC(2040, 0, 1) } }],
    tsas: [tsa.pinned],
  };
  const edited = o.roots?.(roots);
  if (edited) roots = edited;
  return { bundle, roots, ca, log, ct, tsa, leafDer: leaf.der, leafKey: leaf.key, dsseSig, payload, pae: p };
}
