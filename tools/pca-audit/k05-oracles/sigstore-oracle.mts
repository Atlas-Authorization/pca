// k05 differential oracle: offline Sigstore bundle verification (packages/pca-attest-eat/src/sigstore.ts).
//
// Natives replay out/k05-sigstore.json.gz (format: lib.mjs). Inputs:
//   * a deterministic synthetic PKI minted HERE (seeded P-256 / P-384 / Ed25519 keys, RFC 6979 ECDSA via @noble/curves, so the
//     file is byte-identical run to run): a Fulcio-like root + intermediate, a CT log, a Rekor v1 log (ECDSA), a Rekor v2 log
//     (Ed25519 signed note), a timestamp authority. Every knob re-signs what it touches, so a case fails at exactly the
//     check it targets (SCT layout, Fulcio extensions, SAN, EKU, CA flag, AKI, validity edges +-1 ms, RFC 3161 layout and
//     attributes, genTime forms, SET, inclusion proofs on a 7-leaf tree, checkpoint text, entry bodies of all three kinds,
//     the statement and the SLSA predicate);
//   * the real bundles and trusted roots of packages/pca/conformance/sigstore-vectors.json (replayed, then structurally
//     mutated with lib.mjs variants());
//   * blind DER mutations (tag / length bytes of every TLV header, truncation at every TLV boundary) of the leaf
//     certificate and of the RFC 3161 token.
// Roots: every trusted root is a `parseTrustedRoot/<id>` case (args [rootJson], out = the summary below or $throws);
// other cases name a root as {"$root": "<id>"}: the native parses that root (the same JSON) and passes its PinnedRoots.
// (0.5: the reference is strict where the 0.4 generator flagged `@suspect` leniencies: no String() coercion, without a SET the
// reported logIndex is the inclusion proof's verified one, a CA:TRUE leaf is refused, OIDs must be minimal, validFor is RFC 3339, genTime
// fractions truncate exactly. Every case is a plain case now.)
//
//   packages/pca/node_modules/tsx/dist/cli.mjs --tsconfig tools/pca-audit/k05-oracles/tsconfig.json tools/pca-audit/k05-oracles/sigstore-oracle.mts
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { p256, p384 } from '../../../packages/pca/node_modules/@noble/curves/nist.js';
import { ed25519 } from '../../../packages/pca/node_modules/@noble/curves/ed25519.js';
import * as S from '../../../packages/pca-attest-eat/src/sigstore.ts';
import { Oracle, ROOT, seed, variants, HOSTILE, clone } from './lib.mjs';

const O = new Oracle('sigstore', 'tools/pca-audit/k05-oracles/sigstore-oracle.mts',
  'TS-reference oracle for Sigstore bundle verification (sigstore.ts): parseTrustedRoot, verifyRfc3161, dssePae, verifySigstoreBundleCore, verifySigstoreBundle.');

const H = (alg: string, ...b: Uint8Array[]) => { const h = createHash(alg); for (const x of b) h.update(x); return h.digest(); };
const sha256 = (...b: Uint8Array[]) => H('sha256', ...b);
const B = (x: Uint8Array | string) => (typeof x === 'string' ? Buffer.from(x) : Buffer.from(x));

// ---------------------------------------------------------------------------------------------------------------- DER
const len = (n: number) => (n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : n < 0x10000 ? [0x82, n >> 8, n & 0xff] : [0x83, n >> 16, (n >> 8) & 0xff, n & 0xff]);
const tlv = (tag: number, ...c: Uint8Array[]) => { const b = Buffer.concat(c); return Buffer.concat([Buffer.from([tag, ...len(b.length)]), b]); };
const seq = (...c: Uint8Array[]) => tlv(0x30, ...c);
const set = (...c: Uint8Array[]) => tlv(0x31, ...c);
const oidBytes = (s: string) => {
  const p = s.split('.').map(Number);
  const out = [40 * p[0]! + p[1]!];
  for (const v of p.slice(2)) { const st: number[] = []; let x = v; do { st.unshift(x & 0x7f); x = Math.floor(x / 128); } while (x > 0); for (let i = 0; i < st.length - 1; i++) st[i]! |= 0x80; out.push(...st); }
  return Buffer.from(out);
};
const oid = (s: string) => tlv(0x06, oidBytes(s));
const int = (n: number | Buffer) => { let b = typeof n === 'number' ? Buffer.from([n]) : n; if (b[0]! & 0x80) b = Buffer.concat([Buffer.from([0]), b]); return tlv(0x02, b); };
const octet = (b: Uint8Array) => tlv(0x04, b);
const utf8 = (s: string | Uint8Array) => tlv(0x0c, B(s));
const bool = () => tlv(0x01, Buffer.from([0xff]));
const bits = (b: Uint8Array, unused = 0) => tlv(0x03, Buffer.from([unused]), b);
const utc = (d: Date) => tlv(0x17, Buffer.from(d.toISOString().replace(/[-:T]/g, '').slice(2, 14) + 'Z'));
const genStr = (d: Date) => d.toISOString().replace(/[-:T]/g, '').slice(0, 14) + 'Z';
const name = (cn: string) => seq(set(seq(oid('2.5.4.10'), utf8('pca-synthetic'))), set(seq(oid('2.5.4.3'), utf8(cn))));
const ECDSA_SHA256 = seq(oid('1.2.840.10045.4.3.2'));
const ext = (o: string, value: Uint8Array, critical = false) => seq(oid(o), ...(critical ? [bool()] : []), octet(value));

// ---------------------------------------------------------------------------------------------------------------- keys
type Key = { kind: 'p256' | 'p384' | 'ed'; priv: Uint8Array; spki: Buffer; raw: Uint8Array };
const spkiEc = (pub: Uint8Array, curve: string) => seq(seq(oid('1.2.840.10045.2.1'), oid(curve)), bits(pub));
function key(label: string, kind: Key['kind'] = 'p256'): Key {
  const s = Buffer.concat([seed(`k05-sigstore/${label}`), seed(`k05-sigstore/${label}#2`)]);
  if (kind === 'ed') { const priv = s.subarray(0, 32); const raw = ed25519.getPublicKey(priv); return { kind, priv, raw, spki: seq(seq(oid('1.3.101.112')), bits(raw)) }; }
  const c = kind === 'p256' ? p256 : p384;
  const priv = s.subarray(0, kind === 'p256' ? 32 : 48);
  const raw = c.getPublicKey(priv, false);
  return { kind, priv, raw, spki: spkiEc(raw, kind === 'p256' ? '1.2.840.10045.3.1.7' : '1.3.132.0.34') };
}
/** Deterministic signature: Ed25519 over msg; ECDSA (RFC 6979) over H(msg), DER encoded. */
function sign(k: Key, msg: Uint8Array, hash = k.kind === 'p384' ? 'sha384' : 'sha256'): Buffer {
  if (k.kind === 'ed') return B(ed25519.sign(msg, k.priv));
  return B((k.kind === 'p256' ? p256 : p384).sign(H(hash, msg), k.priv, { prehash: false }).toDERRawBytes());
}
const ski = (k: Key) => sha256(k.spki).subarray(0, 20);

const rootK = key('root'), interK = key('inter'), ctK = key('ct'), logK = key('rekor1'), log2K = key('rekor2', 'ed'), tsaK = key('tsa');
const leafK = key('leaf'), leaf384K = key('leaf384', 'p384'), leafEdK = key('leafEd', 'ed'), otherK = key('other'), otherCaK = key('otherCa');
const T = Date.parse('2026-06-01T12:00:00Z');
const FROM = new Date('2025-01-01T00:00:00Z'), TO = new Date('2035-01-01T00:00:00Z');
const ROOT_NAME = name('pca-synthetic-root'), INTER_NAME = name('pca-synthetic-intermediate'), TSA_NAME = name('pca-synthetic-tsa');

interface CertArgs { serial: number; issuer: Buffer; subject: Buffer; key: Key; from: Date; to: Date; exts: Buffer[] | null }
const tbsOf = (a: CertArgs) => seq(tlv(0xa0, int(2)), int(a.serial), ECDSA_SHA256, a.issuer, seq(utc(a.from), utc(a.to)), a.subject, a.key.spki, ...(a.exts ? [tlv(0xa3, seq(...a.exts))] : []));
const certOf = (tbs: Buffer, signer: Key) => seq(tbs, ECDSA_SHA256, bits(sign(signer, tbs)));
const caExts = (k: Key, issuerKey: Key, o: { ca?: boolean; ku?: number } = {}) => [
  ...(o.ca === false ? [] : [ext('2.5.29.19', seq(bool()), true)]),
  ext('2.5.29.15', bits(Buffer.from([o.ku ?? 0x06]), 1), true),
  ext('2.5.29.14', octet(ski(k))),
  ext('2.5.29.35', seq(tlv(0x80, ski(issuerKey)))),
];
const rootCert = certOf(tbsOf({ serial: 1, issuer: ROOT_NAME, subject: ROOT_NAME, key: rootK, from: FROM, to: TO, exts: caExts(rootK, rootK) }), rootK);
const interOf = (o: { ca?: boolean; ku?: number; from?: Date; to?: Date; k?: Key; signer?: Key } = {}) =>
  certOf(tbsOf({ serial: 2, issuer: ROOT_NAME, subject: INTER_NAME, key: o.k ?? interK, from: o.from ?? FROM, to: o.to ?? TO, exts: caExts(o.k ?? interK, rootK, o) }), o.signer ?? rootK);
const interCert = interOf();
const tsaOf = (o: { eku?: string | null; from?: Date; to?: Date } = {}) => certOf(tbsOf({ serial: 3, issuer: ROOT_NAME, subject: TSA_NAME, key: tsaK, from: o.from ?? FROM, to: o.to ?? TO, exts: [
  ext('2.5.29.15', bits(Buffer.from([0x80]), 7), true),
  ...(o.eku === null ? [] : [ext('2.5.29.37', seq(oid(o.eku ?? '1.3.6.1.5.5.7.3.8')), true)]),
  ext('2.5.29.14', octet(ski(tsaK))),
  ext('2.5.29.35', seq(tlv(0x80, ski(rootK)))),
] }), rootK);
const tsaCert = tsaOf();
const ctLogId = sha256(ctK.spki), logId = sha256(logK.spki);
const LOG2_NAME = 'log2.synthetic.example';
const log2Id = sha256(Buffer.from(`${LOG2_NAME}\n`), Buffer.from([1]), log2K.raw);

// ---------------------------------------------------------------------------------------------------------------- trusted roots
const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');
const pk = (k: Key, details: string, validFor: object = { start: FROM.toISOString() }) => ({ rawBytes: b64(k.spki), keyDetails: details, validFor });
const BASE_ROOT = {
  mediaType: 'application/vnd.dev.sigstore.trustedroot+json;version=0.1',
  tlogs: [
    { baseUrl: 'https://synthetic.log', hashAlgorithm: 'SHA2_256', publicKey: pk(logK, 'PKIX_ECDSA_P256_SHA_256'), logId: { keyId: b64(logId) } },
    { baseUrl: `https://${LOG2_NAME}`, hashAlgorithm: 'SHA2_256', publicKey: pk(log2K, 'PKIX_ED25519'), logId: { keyId: b64(log2Id) } },
  ],
  certificateAuthorities: [{ subject: { organization: 'pca-synthetic', commonName: 'pca-synthetic-intermediate' }, uri: 'https://synthetic.ca', certChain: { certificates: [{ rawBytes: b64(interCert) }, { rawBytes: b64(rootCert) }] }, validFor: { start: FROM.toISOString() } }],
  ctlogs: [{ baseUrl: 'https://synthetic.ct', hashAlgorithm: 'SHA2_256', publicKey: pk(ctK, 'PKIX_ECDSA_P256_SHA_256'), logId: { keyId: b64(ctLogId) } }],
  timestampAuthorities: [{ subject: { organization: 'pca-synthetic', commonName: 'pca-synthetic-tsa' }, uri: 'https://synthetic.tsa', certChain: { certificates: [{ rawBytes: b64(tsaCert) }, { rawBytes: b64(rootCert) }] }, validFor: { start: FROM.toISOString() } }],
};
const ROOTS: Record<string, any> = {};
const PARSED: Record<string, S.PinnedRoots | Error> = {};
const iso = (ms: number) => new Date(ms).toISOString();
function summary(r: S.PinnedRoots) {
  const lg = (l: S.PinnedLog) => ({ keyId: b64(l.keyId), start: l.valid.start, end: Number.isFinite(l.valid.end) ? l.valid.end : null, v2: l.v2?.name ?? null });
  const ca = (c: S.PinnedCa) => ({ chain: c.chain.length, start: c.valid.start, end: Number.isFinite(c.valid.end) ? c.valid.end : null });
  return { tlogs: r.tlogs.map(lg), ctlogs: r.ctlogs.map(lg), cas: r.cas.map(ca), tsas: r.tsas.map(ca) };
}
/** Register a root (a parseTrustedRoot case) and return its {$root} reference. */
async function root(id: string, json: unknown, fn = 'parseTrustedRoot') {
  if (ROOTS[id] === undefined) {
    ROOTS[id] = JSON.parse(JSON.stringify(json));
    try { PARSED[id] = S.parseTrustedRoot(ROOTS[id]); } catch (e) { PARSED[id] = e as Error; }
    O.add(fn, id, [ROOTS[id]], PARSED[id] instanceof Error ? { $throws: (PARSED[id] as Error).message } : summary(PARSED[id] as S.PinnedRoots));
  }
  return { $root: id };
}
const rootsOf = (r: { $root: string } | null) => { const p = r && PARSED[r.$root]; if (!p || p instanceof Error) throw new Error('bad root ref'); return p; };

// ---------------------------------------------------------------------------------------------------------------- the leaf
const REPO = 'https://github.com/pca-synthetic/tool';
const SAN_URI = `${REPO}/.github/workflows/release.yml@refs/tags/v1.0.0`;
const OIDC = 'https://token.actions.githubusercontent.com';
interface SctOpt {
  ts?: bigint; claimTs?: bigint; version?: number; signer?: Key; logId?: Buffer; hashAlg?: number; sigAlg?: number; ext?: Buffer;
  sigLenDelta?: number; sctLenDelta?: number; listLenDelta?: number; outerTag?: number; before?: Buffer[]; after?: Buffer[]; trailing?: Buffer; issuerKey?: Key; sigHash?: string; raw?: Buffer;
}
interface LeafOpt {
  key?: Key; from?: number; to?: number; aki?: Buffer | null; ski?: boolean; san?: Buffer | null; sanCritical?: boolean;
  iss1?: Buffer | null; iss8?: Buffer | null; ku?: Buffer | null; src?: [Buffer | null, Buffer | null, Buffer | null]; eku?: string[] | null; ca?: boolean;
  sct?: SctOpt | null; issuer?: Buffer; signer?: Key; extra?: Buffer[]; noExts?: boolean; dup?: boolean; order?: 'sctFirst';
}
const sctBytes = (o: SctOpt, pre: Buffer): Buffer => {
  const ts = o.ts ?? BigInt(T - 30_000);
  const extB = o.ext ?? Buffer.alloc(0);
  const head = Buffer.alloc(12);
  head.writeBigUInt64BE(o.claimTs ?? ts, 2);
  head.writeUInt16BE(1, 10);
  const signed = Buffer.concat([head, sha256((o.issuerKey ?? interK).spki), Buffer.from([pre.length >> 16, (pre.length >> 8) & 0xff, pre.length & 0xff]), pre, Buffer.from([extB.length >> 8, extB.length & 0xff]), extB]);
  const sig = sign(o.signer ?? ctK, signed, o.sigHash);
  const tsB = Buffer.alloc(8);
  tsB.writeBigUInt64BE(ts);
  const sl = sig.length + (o.sigLenDelta ?? 0);
  return Buffer.concat([Buffer.from([o.version ?? 0]), o.logId ?? ctLogId, tsB, Buffer.from([extB.length >> 8, extB.length & 0xff]), extB, Buffer.from([o.hashAlg ?? 4, o.sigAlg ?? 3, (sl >> 8) & 0xff, sl & 0xff]), sig]);
};
const u16 = (n: number) => Buffer.from([(n >> 8) & 0xff, n & 0xff]);
function leafCert(o: LeafOpt = {}): Buffer {
  const k = o.key ?? leafK;
  const src = o.src ?? [utf8(REPO), utf8('a'.repeat(40)), utf8('refs/tags/v1.0.0')];
  const base: Buffer[] = o.noExts ? [] : [
    ...(o.ku === null ? [] : [ext('2.5.29.15', o.ku ?? bits(Buffer.from([0x80]), 7), true)]),
    ...(o.eku === null ? [] : [ext('2.5.29.37', seq(...(o.eku ?? ['1.3.6.1.5.5.7.3.3']).map(oid)))]),
    ...(o.ca ? [ext('2.5.29.19', seq(bool()), true)] : []),
    ...(o.ski === false ? [] : [ext('2.5.29.14', octet(ski(k)))]),
    ...(o.aki === null ? [] : [ext('2.5.29.35', seq(tlv(0x80, o.aki ?? ski(interK))))]),
    ...(o.san === null ? [] : [ext('2.5.29.17', o.san ?? seq(tlv(0x86, Buffer.from(SAN_URI))), o.sanCritical ?? true)]),
    ...(o.iss1 === undefined || o.iss1 === null ? [] : [ext('1.3.6.1.4.1.57264.1.1', o.iss1)]),
    ...(o.iss8 === null ? [] : [ext('1.3.6.1.4.1.57264.1.8', o.iss8 ?? utf8(OIDC))]),
    ...(src[0] ? [ext('1.3.6.1.4.1.57264.1.12', src[0])] : []),
    ...(src[1] ? [ext('1.3.6.1.4.1.57264.1.13', src[1])] : []),
    ...(src[2] ? [ext('1.3.6.1.4.1.57264.1.14', src[2])] : []),
    ...(o.extra ?? []),
    ...(o.dup ? [ext('2.5.29.15', bits(Buffer.from([0x80]), 7), true)] : []),
  ];
  const args = { serial: 100, issuer: o.issuer ?? INTER_NAME, subject: seq(), key: k, from: new Date(o.from ?? T - 60_000), to: new Date(o.to ?? T + 600_000) };
  let exts = base;
  if (o.sct !== null && !o.noExts) {
    const so = o.sct ?? {};
    const pre = tbsOf({ ...args, exts: base });
    let list: Buffer;
    if (so.raw) list = so.raw;
    else {
      const one = sctBytes(so, pre);
      const item = Buffer.concat([u16(one.length + (so.sctLenDelta ?? 0)), one]);
      const body = Buffer.concat([...(so.before ?? []), item, ...(so.after ?? [])]);
      list = Buffer.concat([u16(body.length + (so.listLenDelta ?? 0)), body, so.trailing ?? Buffer.alloc(0)]);
    }
    const sctExt = ext('1.3.6.1.4.1.11129.2.4.2', tlv(so.outerTag ?? 0x04, list));
    exts = o.order === 'sctFirst' ? [sctExt, ...base] : [...base, sctExt];
  }
  return certOf(tbsOf({ ...args, exts: o.noExts ? null : exts }), o.signer ?? interK);
}
/** An SCT from a log the root does not pin (skipped), to put before / after the real one. */
const foreignSct = (pre?: Buffer) => { const s = sctBytes({ signer: otherK, logId: sha256(otherK.spki) }, pre ?? Buffer.alloc(3)); return Buffer.concat([u16(s.length), s]); };

// ---------------------------------------------------------------------------------------------------------------- RFC 3161
const SHA256_ALG = seq(oid('2.16.840.1.101.3.4.2.1'));
interface TsOpt {
  status?: number | null; statusRaw?: Buffer; genTime?: string; genTag?: number; imprintAlg?: Buffer; imprintOver?: Buffer; imprint?: Buffer;
  ct?: 'ok' | 'omit' | 'wrong' | 'two'; md?: 'ok' | 'omit' | 'wrong' | 'two'; attrsTag?: number; siDigest?: string; signer?: Key; signerCount?: number;
  sigTag?: number; respNoToken?: boolean; contentOid?: string; sdOid?: string; tstTag?: number; contentTag?: number; ctxTag?: number; signerInfosTag?: number;
  noEncap?: boolean; serial?: number; extraTail?: Buffer;
}
const DIG: Record<string, string> = { sha256: '2.16.840.1.101.3.4.2.1', sha384: '2.16.840.1.101.3.4.2.2', sha512: '2.16.840.1.101.3.4.2.3' };
function tsToken(sig: Buffer, o: TsOpt = {}): Buffer {
  const miAlg = o.imprintAlg ?? SHA256_ALG;
  const miHash = o.imprint ?? sha256(o.imprintOver ?? sig);
  const tst = seq(int(1), oid('1.3.6.1.4.1.57264.99.1'), seq(miAlg, octet(miHash)), int(o.serial ?? 7), tlv(o.genTag ?? 0x18, Buffer.from(o.genTime ?? genStr(new Date(T + 30_000)), 'latin1')));
  const dAlg = o.siDigest ?? 'sha256';
  const dh = DIG[dAlg] ? dAlg : 'sha256';
  const ctA = seq(oid('1.2.840.113549.1.9.3'), set(oid(o.ct === 'wrong' ? '1.2.840.113549.1.7.1' : '1.2.840.113549.1.9.16.1.4'), ...(o.ct === 'two' ? [oid('1.2.840.113549.1.9.16.1.4')] : [])));
  const mdV = o.md === 'wrong' ? octet(H(dh, Buffer.from('x'))) : octet(H(dh, tst));
  const mdA = seq(oid('1.2.840.113549.1.9.4'), set(mdV, ...(o.md === 'two' ? [mdV] : [])));
  const attrs = [...(o.ct === 'omit' ? [] : [ctA]), ...(o.md === 'omit' ? [] : [mdA])];
  const signedAttrs = set(...attrs);
  const si = seq(int(1), seq(ROOT_NAME, int(3)), seq(oid(DIG[dAlg] ?? dAlg)), tlv(o.attrsTag ?? 0xa0, ...attrs), ECDSA_SHA256, tlv(o.sigTag ?? 0x04, sign(o.signer ?? tsaK, signedAttrs, dh)));
  const sis = Array.from({ length: o.signerCount ?? 1 }, () => si);
  const encap = seq(oid(o.contentOid ?? '1.2.840.113549.1.9.16.1.4'), tlv(o.contentTag ?? 0xa0, tlv(o.tstTag ?? 0x04, tst)));
  const sd = seq(int(3), set(SHA256_ALG), ...(o.noEncap ? [] : [encap]), tlv(o.signerInfosTag ?? 0x31, ...sis));
  const token = seq(oid(o.sdOid ?? '1.2.840.113549.1.7.2'), tlv(o.ctxTag ?? 0xa0, sd), ...(o.extraTail ? [o.extraTail] : []));
  if (o.status === null) return token;
  return seq(seq(o.statusRaw ? tlv(0x02, o.statusRaw) : int(o.status ?? 0)), ...(o.respNoToken ? [] : [token]));
}

// ---------------------------------------------------------------------------------------------------------------- RFC 9162 tree
const leafHash = (d: Uint8Array) => sha256(Buffer.from([0]), d);
const nodeH = (l: Uint8Array, r: Uint8Array) => sha256(Buffer.from([1]), l, r);
const kSplit = (n: number) => { let k = 1; while (k * 2 < n) k *= 2; return k; };
const mth = (ls: Buffer[]): Buffer => (ls.length === 1 ? ls[0]! : nodeH(mth(ls.slice(0, kSplit(ls.length))), mth(ls.slice(kSplit(ls.length)))));
const path = (m: number, ls: Buffer[]): Buffer[] => {
  if (ls.length <= 1) return [];
  const k = kSplit(ls.length);
  return m < k ? [...path(m, ls.slice(0, k)), mth(ls.slice(k))] : [...path(m - k, ls.slice(k)), mth(ls.slice(0, k))];
};

// ---------------------------------------------------------------------------------------------------------------- bundles
const PT = 'application/vnd.in-toto+json';
const STATEMENT = {
  _type: 'https://in-toto.io/Statement/v1',
  subject: [{ name: 'tool.tar', digest: { sha256: sha256(Buffer.from('pca synthetic artifact')).toString('hex') } }],
  predicateType: 'https://slsa.dev/provenance/v1',
  predicate: { buildDefinition: { buildType: 'https://actions.github.io/buildtypes/workflow/v1', externalParameters: { workflow: { ref: 'refs/tags/v1.0.0', repository: REPO, path: '.github/workflows/release.yml' } }, resolvedDependencies: [{ uri: `git+${REPO}@refs/tags/v1.0.0`, digest: { gitCommit: 'a'.repeat(40) } }] }, runDetails: { builder: { id: 'https://github.com/actions/runner/github-hosted' } } },
};
const pemOf = (der: Uint8Array) => `-----BEGIN CERTIFICATE-----\n${b64(der).match(/.{1,64}/g)!.join('\n')}\n-----END CERTIFICATE-----\n`;
interface CpOpt { origin?: string; sizeLine?: string; rootLine?: string; noBlank?: boolean; lines?: (sigLine: string, body: string) => string[]; signer?: Key; name?: string; hint?: Buffer; bodyExtra?: string; text?: string }
interface BOpt {
  kind?: 'dsse' | 'intoto' | 'hashedrekord'; log?: 'v1' | 'v2'; leaf?: LeafOpt; leafDer?: Buffer; bodyCert?: Buffer; dsseKey?: Key; dsseHash?: string;
  statement?: unknown; payload?: Buffer; bodyMut?: (b: any) => void; bodyRaw?: Buffer;
  logIndex?: unknown; integrated?: unknown; setTime?: number; set?: 'ok' | 'omit' | 'bad'; size?: number; index?: number; proofMut?: (h: string[]) => unknown; ipMut?: (ip: any) => void;
  cp?: CpOpt; ts?: TsOpt[] | null; mediaType?: string; mut?: (b: any) => void; sigOverride?: Buffer; hrAlg?: string;
}
function bundle(o: BOpt = {}): any {
  const kind = o.kind ?? 'dsse';
  const v2 = (o.log ?? (kind === 'hashedrekord' ? 'v2' : 'v1')) === 'v2';
  const lk = o.leaf?.key ?? leafK;
  const leaf = o.leafDer ?? leafCert(o.leaf);
  const payload = o.payload ?? Buffer.from(JSON.stringify(o.statement ?? STATEMENT));
  const pae = S.dssePae(PT, payload);
  const sig = o.sigOverride ?? sign(o.dsseKey ?? lk, pae, o.dsseHash);
  const certInBody = o.bodyCert ?? leaf;
  let bodyObj: any;
  if (kind === 'dsse') bodyObj = { apiVersion: '0.0.1', kind: 'dsse', spec: { envelopeHash: { algorithm: 'sha256', value: sha256(Buffer.from('envelope')).toString('hex') }, payloadHash: { algorithm: 'sha256', value: sha256(payload).toString('hex') }, signatures: [{ signature: b64(sig), verifier: b64(Buffer.from(pemOf(certInBody))) }] } };
  else if (kind === 'intoto') bodyObj = { apiVersion: '0.0.2', kind: 'intoto', spec: { content: { envelope: { payloadType: PT, signatures: [{ sig: b64(Buffer.from(b64(sig))), publicKey: b64(Buffer.from(pemOf(certInBody))) }] }, hash: { algorithm: 'sha256', value: sha256(Buffer.from('envelope')).toString('hex') }, payloadHash: { algorithm: 'sha256', value: sha256(payload).toString('hex') } } } };
  else {
    const alg = o.hrAlg ?? (lk.kind === 'p384' ? 'SHA2_384' : 'SHA2_256');
    const hn = alg === 'SHA2_384' ? 'sha384' : alg === 'SHA2_512' ? 'sha512' : 'sha256';
    bodyObj = { apiVersion: '0.0.2', kind: 'hashedrekord', spec: { hashedRekordV002: { data: { algorithm: alg, digest: b64(H(hn, pae)) }, signature: { content: b64(sig), verifier: { x509Certificate: { rawBytes: b64(certInBody) }, keyDetails: 'PKIX_ECDSA_P256_SHA_256' } } } } };
  }
  o.bodyMut?.(bodyObj);
  const body = o.bodyRaw ?? Buffer.from(JSON.stringify(bodyObj));
  const bodyB64 = b64(body);
  const size = o.size ?? 7, index = o.index ?? 5;
  const leaves = Array.from({ length: size }, (_, i) => (i === index ? leafHash(body) : leafHash(seed(`k05-sigstore/tree/${i}`))));
  const rootHash = mth(leaves);
  const hashes = path(index, leaves).map(b64);
  const lid = v2 ? log2Id : logId;
  const integrated = Math.floor(T / 1000) + 60;
  const logIndex = o.logIndex ?? String(index);
  const setMsg = `{"body":${JSON.stringify(bodyB64)},"integratedTime":${o.setTime ?? integrated},"logID":"${lid.toString('hex')}","logIndex":${typeof logIndex === 'string' && /^\d+$/.test(logIndex) ? Number(logIndex) : index}}`;
  const cp = o.cp ?? {};
  const nm = cp.name ?? (v2 ? LOG2_NAME : 'synthetic.log - 1');
  const note = `${cp.origin ?? nm}\n${cp.sizeLine ?? size}\n${cp.rootLine ?? b64(rootHash)}\n${cp.bodyExtra ?? ''}`;
  const cpSig = Buffer.concat([cp.hint ?? lid.subarray(0, 4), sign(cp.signer ?? (v2 ? log2K : logK), Buffer.from(note))]);
  const sigLine = `— ${v2 ? (cp.name ?? LOG2_NAME) : 'synthetic.log'} ${b64(cpSig)}`;
  const envelope = cp.text ?? (cp.noBlank ? `${note}${sigLine}\n` : `${note}\n${(cp.lines ? cp.lines(sigLine, note) : [sigLine]).join('\n')}\n`);
  const tlog: any = {
    logIndex, logId: { keyId: b64(lid) }, kindVersion: { kind, version: kind === 'dsse' ? '0.0.1' : '0.0.2' },
    ...(v2 ? {} : { integratedTime: o.integrated ?? String(integrated) }),
    ...(!v2 && (o.set ?? 'ok') !== 'omit' ? { inclusionPromise: { signedEntryTimestamp: b64(o.set === 'bad' ? sign(otherK, Buffer.from(setMsg)) : sign(logK, Buffer.from(setMsg))) } } : {}),
    inclusionProof: { logIndex: String(index), rootHash: b64(rootHash), treeSize: String(size), hashes: o.proofMut ? o.proofMut(hashes) : hashes, checkpoint: { envelope } },
    canonicalizedBody: bodyB64,
  };
  o.ipMut?.(tlog.inclusionProof);
  const ts = o.ts === null ? [] : (o.ts ?? (v2 ? [{}] : [{}])).map((x) => ({ signedTimestamp: b64(tsToken(sig, x)) }));
  const mt = o.mediaType ?? 'application/vnd.dev.sigstore.bundle.v0.3+json';
  const b: any = {
    mediaType: mt,
    verificationMaterial: {
      ...(mt === S.SIGSTORE_BUNDLE_MEDIA_TYPES[0] ? { x509CertificateChain: { certificates: [{ rawBytes: b64(leaf) }, { rawBytes: b64(interCert) }] } } : { certificate: { rawBytes: b64(leaf) } }),
      tlogEntries: [tlog],
      ...(ts.length || o.ts !== null ? { timestampVerificationData: { rfc3161Timestamps: ts } } : {}),
    },
    dsseEnvelope: { payload: b64(payload), payloadType: PT, signatures: [{ sig: b64(sig), keyid: '' }] },
  };
  o.mut?.(b);
  return b;
}

// ---------------------------------------------------------------------------------------------------------------- recorders
const coreOut = (r: S.SigstoreCoreResult) => (r.ok ? { ok: true, core: r.core } : { ok: false, code: r.code, detail: r.detail });
const coreRef = (b: unknown, r: { $root: string }) => coreOut(S.verifySigstoreBundleCore(b, { roots: rootsOf(r) }));
const fullRef = (b: unknown, r: { $root: string }) => S.verifySigstoreBundle(b, { roots: rootsOf(r) });
let MAIN: { $root: string };
const want: Array<[string, string | null, string | null]> = []; // [case, wanted code (null = ok), got]
async function core(name: string, b: unknown, r = MAIN, expect?: string | null, fn: string = 'verifySigstoreBundleCore') {
  if (!(await O.run(fn, name, coreRef, [b, r]))) return;
  const out = O.cases[O.cases.length - 1]!.out as any;
  if (expect !== undefined) want.push([name, expect, out.ok ? null : out.code]);
}
async function full(name: string, b: unknown, r = MAIN) { await O.run('verifySigstoreBundle', name, fullRef, [b, r]); }

// ================================================================================================================ cases
MAIN = await root('synthetic', BASE_ROOT);
const R = (f: (r: any) => void) => { const r = clone(BASE_ROOT); f(r); return r; };

// ---- trusted roots: parse outcomes (every pinnedLog / pinnedChain / validity branch)
const NO_CT = await root('synthetic-no-ct', R((r) => { r.ctlogs = []; }));
await root('no-tsa', R((r) => { r.timestampAuthorities = []; }));
await root('not-object', 'x');
await root('null', null);
await root('array', []);
await root('mediaType-wrong', R((r) => { r.mediaType = 'application/vnd.dev.sigstore.trustedroot+json;version=0.2'; }));
await root('mediaType-missing', R((r) => { delete r.mediaType; }));
await root('no-tlogs', R((r) => { r.tlogs = []; }));
await root('tlogs-not-array', R((r) => { r.tlogs = {}; }));
await root('no-cas', R((r) => { r.certificateAuthorities = []; }));
await root('cas-missing', R((r) => { delete r.certificateAuthorities; }));
await root('only-v2-log', R((r) => { r.tlogs = [r.tlogs[1]]; }));
await root('only-v1-log', R((r) => { r.tlogs = [r.tlogs[0]]; }));
for (const [i, t] of [[0, 'v1'], [1, 'v2']] as const) {
  await root(`tlog-${t}-not-object`, R((r) => { r.tlogs[i] = 'x'; }));
  await root(`tlog-${t}-no-publicKey`, R((r) => { delete r.tlogs[i].publicKey; }));
  await root(`tlog-${t}-no-logId`, R((r) => { delete r.tlogs[i].logId; }));
  await root(`tlog-${t}-logId-not-object`, R((r) => { r.tlogs[i].logId = 'x'; }));
  await root(`tlog-${t}-keyId-bad-b64`, R((r) => { r.tlogs[i].logId.keyId = 'A'; }));
  await root(`tlog-${t}-keyId-missing`, R((r) => { delete r.tlogs[i].logId.keyId; }));
  await root(`tlog-${t}-keyId-flipped`, R((r) => { const k = Buffer.from(r.tlogs[i].logId.keyId, 'base64'); k[31]! ^= 1; r.tlogs[i].logId.keyId = b64(k); }));
  await root(`tlog-${t}-rawBytes-bad-b64`, R((r) => { r.tlogs[i].publicKey.rawBytes = 'A==='; }));
  await root(`tlog-${t}-rawBytes-missing`, R((r) => { delete r.tlogs[i].publicKey.rawBytes; }));
  await root(`tlog-${t}-validFor-missing`, R((r) => { delete r.tlogs[i].publicKey.validFor; }));
  await root(`tlog-${t}-keyDetails-unknown`, R((r) => { r.tlogs[i].publicKey.keyDetails = 'PKIX_ECDSA_P384_SHA_384'; }));
  await root(`tlog-${t}-keyDetails-missing`, R((r) => { delete r.tlogs[i].publicKey.keyDetails; }));
  await root(`tlog-${t}-as-rsa`, R((r) => { r.tlogs[i].publicKey.keyDetails = 'PKCS1_RSA_PKCS1V5'; }));
}
await root('tlog-v1-as-ed25519', R((r) => { r.tlogs[0].publicKey.keyDetails = 'PKIX_ED25519'; }));
await root('tlog-v2-as-ecdsa', R((r) => { r.tlogs[1].publicKey.keyDetails = 'PKIX_ECDSA_P256_SHA_256'; }));
await root('tlog-v2-no-baseUrl', R((r) => { delete r.tlogs[1].baseUrl; }));
await root('tlog-v2-baseUrl-number', R((r) => { r.tlogs[1].baseUrl = 5; }));
await root('tlog-v2-baseUrl-other-host', R((r) => { r.tlogs[1].baseUrl = 'https://log3.synthetic.example'; }));
await root('tlog-v2-baseUrl-path-port', R((r) => { r.tlogs[1].baseUrl = `https://${LOG2_NAME}:8443/api/v2`; }));
await root('tlog-v2-baseUrl-upper', R((r) => { r.tlogs[1].baseUrl = `https://${LOG2_NAME.toUpperCase()}`; }));
await root('tlog-v2-baseUrl-not-url', R((r) => { r.tlogs[1].baseUrl = 'not a url'; }));
await root('tlog-v2-baseUrl-empty', R((r) => { r.tlogs[1].baseUrl = ''; }));
await root('ctlog-as-ed25519', R((r) => { r.ctlogs[0].publicKey.keyDetails = 'PKIX_ED25519'; }));
await root('ctlog-keyId-flipped', R((r) => { const k = Buffer.from(r.ctlogs[0].logId.keyId, 'base64'); k[0]! ^= 1; r.ctlogs[0].logId.keyId = b64(k); }));
await root('ctlog-unknown-type', R((r) => { r.ctlogs[0].publicKey.keyDetails = 'X'; }));
await root('ctlog-as-rsa-on-ec-key', R((r) => { r.ctlogs[0].publicKey.keyDetails = 'PKCS1_RSA_PKCS1V5'; }));
await root('ctlogs-not-array', R((r) => { r.ctlogs = 'x'; }));
// validity: strict RFC 3339 only (0.5); other forms Date.parse would take are refused
for (const [lbl, vf] of [
  ['start-missing', {}], ['start-number', { start: 5 }], ['start-empty', { start: '' }], ['start-garbage', { start: 'not a date' }],
  ['start-null', { start: null }], ['not-object', 'x'], ['end-garbage', { start: FROM.toISOString(), end: 'not a date' }],
  ['end-number', { start: FROM.toISOString(), end: 5 }], ['end-null', { start: FROM.toISOString(), end: null }],
  ['end-iso', { start: FROM.toISOString(), end: TO.toISOString() }], ['offset-form', { start: '2025-01-01T01:00:00+01:00', end: '2035-01-01T00:00:00.500Z' }],
  ['fraction', { start: '2025-01-01T00:00:00.123Z' }], ['end-before-start', { start: TO.toISOString(), end: FROM.toISOString() }],
  ['start-date-only', { start: '2025-01-01' }], ['start-no-zone', { start: '2025-01-01T00:00:00' }], ['start-space', { start: '2025-01-01 00:00:00Z' }],
  ['start-lowercase', { start: '2025-01-01t00:00:00z' }], ['start-rfc2822', { start: 'Wed, 01 Jan 2025 00:00:00 GMT' }], ['start-feb-30', { start: '2025-02-30T00:00:00Z' }],
  ['start-offset-no-colon', { start: '2025-01-01T00:00:00+0100' }], ['start-year-6', { start: '+002025-01-01T00:00:00Z' }], ['end-date-only', { start: FROM.toISOString(), end: '2035-01-01' }],
  ['end-feb-29-leap', { start: FROM.toISOString(), end: '2028-02-29T00:00:00Z' }], ['end-feb-29-nonleap', { start: FROM.toISOString(), end: '2027-02-29T00:00:00Z' }],
] as const) {
  await root(`tlog-validFor-${lbl}`, R((r) => { r.tlogs[0].publicKey.validFor = vf; }));
  await root(`ca-validFor-${lbl}`, R((r) => { r.certificateAuthorities[0].validFor = vf; }));
}
await root('ca-not-object', R((r) => { r.certificateAuthorities = ['x']; }));
await root('ca-no-certChain', R((r) => { delete r.certificateAuthorities[0].certChain; }));
await root('ca-certChain-not-object', R((r) => { r.certificateAuthorities[0].certChain = []; }));
await root('ca-certificates-empty', R((r) => { r.certificateAuthorities[0].certChain.certificates = []; }));
await root('ca-certificates-not-array', R((r) => { r.certificateAuthorities[0].certChain.certificates = {}; }));
await root('ca-cert-not-object', R((r) => { r.certificateAuthorities[0].certChain.certificates[0] = 'x'; }));
await root('ca-cert-rawBytes-bad', R((r) => { r.certificateAuthorities[0].certChain.certificates[0].rawBytes = 'AAAA'; }));
await root('ca-cert-rawBytes-missing', R((r) => { delete r.certificateAuthorities[0].certChain.certificates[0].rawBytes; }));
await root('tsa-no-validFor', R((r) => { delete r.timestampAuthorities[0].validFor; }));
await root('tsa-certificates-empty', R((r) => { r.timestampAuthorities[0].certChain.certificates = []; }));
await root('tsas-not-array', R((r) => { r.timestampAuthorities = 5; }));

// ---- roots used by the verification cases (time windows +-1 ms around the signing times)
const TSA_T = T + 30_000, SET_T = (Math.floor(T / 1000) + 60) * 1000;
const RW = async (id: string, f: (r: any) => void) => root(id, R(f));
const rTsaEnded = await RW('tsa-ended-before-time', (r) => { r.timestampAuthorities[0].validFor.end = iso(TSA_T - 1); });
const rTsaEndAt = await RW('tsa-ends-at-time', (r) => { r.timestampAuthorities[0].validFor.end = iso(TSA_T); });
const rTsaStartAfter = await RW('tsa-starts-after-time', (r) => { r.timestampAuthorities[0].validFor.start = iso(TSA_T + 1); });
const rTsaStartAt = await RW('tsa-starts-at-time', (r) => { r.timestampAuthorities[0].validFor.start = iso(TSA_T); });
const rTsaNoEku = await RW('tsa-cert-no-eku', (r) => { r.timestampAuthorities[0].certChain.certificates[0].rawBytes = b64(tsaOf({ eku: null })); });
const rTsaCodeEku = await RW('tsa-cert-codesigning-eku', (r) => { r.timestampAuthorities[0].certChain.certificates[0].rawBytes = b64(tsaOf({ eku: '1.3.6.1.5.5.7.3.3' })); });
const rTsaCertExpired = await RW('tsa-cert-expired', (r) => { r.timestampAuthorities[0].certChain.certificates[0].rawBytes = b64(tsaOf({ to: new Date(TSA_T - 1000) })); });
const rTsaCertNotYet = await RW('tsa-cert-not-yet', (r) => { r.timestampAuthorities[0].certChain.certificates[0].rawBytes = b64(tsaOf({ from: new Date(TSA_T + 1000) })); });
const rTsaTwo = await RW('tsa-two-first-wrong', (r) => { r.timestampAuthorities.unshift({ certChain: { certificates: [{ rawBytes: b64(interCert) }, { rawBytes: b64(rootCert) }] }, validFor: { start: FROM.toISOString() } }); });
const rTsaLeafOnly = await RW('tsa-chain-leaf-only', (r) => { r.timestampAuthorities[0].certChain.certificates = [r.timestampAuthorities[0].certChain.certificates[0]]; });
const rLogEndBefore = await RW('tlog-ends-before-set', (r) => { r.tlogs[0].publicKey.validFor.end = iso(SET_T - 1); });
const rLogEndAt = await RW('tlog-ends-at-set', (r) => { r.tlogs[0].publicKey.validFor.end = iso(SET_T); });
const rLogStartAfter = await RW('tlog-starts-after-tsa', (r) => { r.tlogs[0].publicKey.validFor.start = iso(TSA_T + 1); });
const rLogStartAt = await RW('tlog-starts-at-tsa', (r) => { r.tlogs[0].publicKey.validFor.start = iso(TSA_T); });
const rLog2EndBefore = await RW('tlog2-ends-before-tsa', (r) => { r.tlogs[1].publicKey.validFor.end = iso(TSA_T - 1); });
const rCaEndBefore = await RW('ca-ends-before-set', (r) => { r.certificateAuthorities[0].validFor.end = iso(SET_T - 1); });
const rCaEndAt = await RW('ca-ends-at-set', (r) => { r.certificateAuthorities[0].validFor.end = iso(SET_T); });
const rCaStartAfter = await RW('ca-starts-after-tsa', (r) => { r.certificateAuthorities[0].validFor.start = iso(TSA_T + 1); });
const rInterNotCa = await RW('inter-not-ca', (r) => { r.certificateAuthorities[0].certChain.certificates[0].rawBytes = b64(interOf({ ca: false })); });
const rInterNoCertSign = await RW('inter-no-keyCertSign', (r) => { r.certificateAuthorities[0].certChain.certificates[0].rawBytes = b64(interOf({ ku: 0x80 })); });
const rInterExpired = await RW('inter-expired-at-time', (r) => { r.certificateAuthorities[0].certChain.certificates[0].rawBytes = b64(interOf({ to: new Date(TSA_T - 1000) })); });
const rInterOnly = await RW('ca-chain-inter-only', (r) => { r.certificateAuthorities[0].certChain.certificates = [r.certificateAuthorities[0].certChain.certificates[0]]; });
const rInterWrongSigner = await RW('inter-signed-by-other', (r) => { r.certificateAuthorities[0].certChain.certificates[0].rawBytes = b64(interOf({ signer: otherCaK })); });
const rCaTwo = await RW('ca-two-first-other', (r) => { r.certificateAuthorities.unshift({ certChain: { certificates: [{ rawBytes: b64(interOf({ k: otherCaK })) }, { rawBytes: b64(rootCert) }] }, validFor: { start: FROM.toISOString() } }); });
const rCaTwoFirstEnded = await RW('ca-two-first-ended', (r) => { r.certificateAuthorities.unshift({ ...clone(r.certificateAuthorities[0]), validFor: { start: FROM.toISOString(), end: iso(TSA_T - 1) } }); });
const rCtEndBefore = await RW('ct-ends-before-sct', (r) => { r.ctlogs[0].publicKey.validFor.end = iso(T - 30_000 - 1); });
const rCtEndAt = await RW('ct-ends-at-sct', (r) => { r.ctlogs[0].publicKey.validFor.end = iso(T - 30_000); });
const rCtStartAfter = await RW('ct-starts-after-sct', (r) => { r.ctlogs[0].publicKey.validFor.start = iso(T - 30_000 + 1); });
const rCtTwo = await RW('ct-two-logs', (r) => { r.ctlogs.unshift({ baseUrl: 'https://other.ct', publicKey: pk(otherK, 'PKIX_ECDSA_P256_SHA_256'), logId: { keyId: b64(sha256(otherK.spki)) } }); });

// ---- the controls
for (const kind of ['dsse', 'intoto', 'hashedrekord'] as const) {
  await core(`${kind}/valid`, bundle({ kind }), MAIN, null);
  await full(`${kind}/valid`, bundle({ kind }));
  await core(`${kind}/valid no-ct root`, bundle({ kind }), NO_CT, null);
}
await core('dsse/valid set-only', bundle({ ts: null }), MAIN, null);
await core('dsse/valid set-only empty list', bundle({ ts: [] }), MAIN, null);
await core('dsse/valid tsa-only', bundle({ set: 'omit' }), MAIN, null);
await core('dsse/valid two-tsa', bundle({ ts: [{}, {}] }), MAIN, null);
await core('dsse/valid media 0.2', bundle({ mediaType: S.SIGSTORE_BUNDLE_MEDIA_TYPES[0] }), MAIN, null);
await core('dsse/valid media 0.3 legacy', bundle({ mediaType: S.SIGSTORE_BUNDLE_MEDIA_TYPES[1] }), MAIN, null);
await core('hashedrekord/valid p384 leaf', bundle({ kind: 'hashedrekord', leaf: { key: leaf384K } }), MAIN, null);
await core('dsse/valid p384 leaf', bundle({ leaf: { key: leaf384K } }), MAIN, null);

// ---- bundle shape (verifySigstoreBundleCore stage 'malformed' .. 'envelope')
const V = bundle();
const M = (f: (b: any) => void) => { const b = clone(V); f(b); return b; };
await core('shape/not object', 'x', MAIN, 'malformed');
await core('shape/null', null, MAIN, 'malformed');
await core('shape/array', [V], MAIN, 'malformed');
await core('shape/no verificationMaterial', M((b) => { delete b.verificationMaterial; }), MAIN, 'malformed');
await core('shape/verificationMaterial array', M((b) => { b.verificationMaterial = []; }), MAIN, 'malformed');
for (const mt of ['application/vnd.dev.sigstore.bundle+json;version=0.1', 'application/vnd.dev.sigstore.bundle.v0.3+json ', 'APPLICATION/VND.DEV.SIGSTORE.BUNDLE.V0.3+JSON', '', 7, null])
  await core(`shape/mediaType ${JSON.stringify(mt)}`, M((b) => { b.mediaType = mt; }), MAIN, 'media_type');
await core('shape/mediaType missing', M((b) => { delete b.mediaType; }), MAIN, 'media_type');
await core('shape/v0.3 with chain only', M((b) => { b.verificationMaterial.x509CertificateChain = { certificates: [b.verificationMaterial.certificate] }; delete b.verificationMaterial.certificate; }), MAIN, 'not_keyless');
await core('shape/v0.2 with certificate only', M((b) => { b.mediaType = S.SIGSTORE_BUNDLE_MEDIA_TYPES[0]; }), MAIN, 'not_keyless');
await core('shape/v0.2 chain empty', bundle({ mediaType: S.SIGSTORE_BUNDLE_MEDIA_TYPES[0], mut: (b) => { b.verificationMaterial.x509CertificateChain.certificates = []; } }), MAIN, 'not_keyless');
await core('shape/v0.2 chain first not object', bundle({ mediaType: S.SIGSTORE_BUNDLE_MEDIA_TYPES[0], mut: (b) => { b.verificationMaterial.x509CertificateChain.certificates[0] = 'x'; } }), MAIN, 'not_keyless');
await core('shape/v0.2 chain not array', bundle({ mediaType: S.SIGSTORE_BUNDLE_MEDIA_TYPES[0], mut: (b) => { b.verificationMaterial.x509CertificateChain.certificates = {}; } }), MAIN, 'not_keyless');
await core('shape/v0.2 chain first without rawBytes', bundle({ mediaType: S.SIGSTORE_BUNDLE_MEDIA_TYPES[0], mut: (b) => { delete b.verificationMaterial.x509CertificateChain.certificates[0].rawBytes; } }), MAIN, 'not_keyless');
await core('shape/v0.2 chain second bogus (ignored)', bundle({ mediaType: S.SIGSTORE_BUNDLE_MEDIA_TYPES[0], mut: (b) => { b.verificationMaterial.x509CertificateChain.certificates[1] = { rawBytes: 'AAAA' }; } }), MAIN, null);
await core('shape/certificate rawBytes null', M((b) => { b.verificationMaterial.certificate.rawBytes = null; }), MAIN);
await core('shape/public key bundle', M((b) => { delete b.verificationMaterial.certificate; b.verificationMaterial.publicKey = { hint: 'x' }; }), MAIN, 'not_keyless');
await core('shape/messageSignature', M((b) => { b.messageSignature = { messageDigest: {}, signature: 'AA==' }; }), MAIN, 'envelope');
await core('shape/messageSignature null', M((b) => { b.messageSignature = null; }), MAIN, 'envelope');
await core('shape/no envelope', M((b) => { delete b.dsseEnvelope; }), MAIN, 'envelope');
await core('shape/payloadType other', M((b) => { b.dsseEnvelope.payloadType = 'application/json'; }), MAIN, 'envelope');
await core('shape/no signatures', M((b) => { b.dsseEnvelope.signatures = []; }), MAIN, 'envelope');
await core('shape/two signatures', M((b) => { b.dsseEnvelope.signatures.push(b.dsseEnvelope.signatures[0]); }), MAIN, 'envelope');
await core('shape/signature not object', M((b) => { b.dsseEnvelope.signatures = ['x']; }), MAIN, 'envelope');
await core('shape/signatures object', M((b) => { b.dsseEnvelope.signatures = { sig: 'x' }; }), MAIN, 'envelope');
// base64 forms the strict decoder must refuse or accept
const b64Forms = (s: string): Array<[string, string]> => [
  ['no padding', s.replace(/=+$/, '')], ['extra pad', s + '='], ['urlsafe', s.replace(/\+/g, '-').replace(/\//g, '_')], ['newline', s.slice(0, 4) + '\n' + s.slice(4)],
  ['space', ' ' + s], ['truncated 4', s.slice(0, -4)], ['plus AAAA', s + 'AAAA'], ['length 4n+1', s + 'A'], ['empty', ''],
  ['noncanonical tail', s.endsWith('==') ? s.slice(0, -3) + String.fromCharCode(s.charCodeAt(s.length - 3) ^ 1) + '==' : s.endsWith('=') ? s.slice(0, -2) + 'B=' : s],
  ['inner pad', s.slice(0, 4) + '====' + s.slice(4)],
];
const B64_FIELDS: Array<[string, (b: any) => any, string]> = [
  ['payload', (b) => b.dsseEnvelope, 'payload'], ['dsse sig', (b) => b.dsseEnvelope.signatures[0], 'sig'], ['certificate', (b) => b.verificationMaterial.certificate, 'rawBytes'],
  ['logId', (b) => b.verificationMaterial.tlogEntries[0].logId, 'keyId'], ['body', (b) => b.verificationMaterial.tlogEntries[0], 'canonicalizedBody'],
  ['SET', (b) => b.verificationMaterial.tlogEntries[0].inclusionPromise, 'signedEntryTimestamp'], ['rootHash', (b) => b.verificationMaterial.tlogEntries[0].inclusionProof, 'rootHash'],
  ['proof hash', (b) => b.verificationMaterial.tlogEntries[0].inclusionProof.hashes, 0], ['timestamp', (b) => b.verificationMaterial.timestampVerificationData.rfc3161Timestamps[0], 'signedTimestamp'],
];
for (const [f, at, k] of B64_FIELDS) for (const [lbl, s] of b64Forms(at(V)[k])) await core(`b64/${f} ${lbl}`, M((b) => { at(b)[k] = s; }));

// ---- the log entry (count, kind, key, decimal strings)
await core('tlog/none', M((b) => { b.verificationMaterial.tlogEntries = []; }), MAIN, 'tlog_count');
await core('tlog/two', M((b) => { b.verificationMaterial.tlogEntries.push(b.verificationMaterial.tlogEntries[0]); }), MAIN, 'tlog_count');
await core('tlog/not array', M((b) => { b.verificationMaterial.tlogEntries = b.verificationMaterial.tlogEntries[0]; }), MAIN, 'tlog_count');
await core('tlog/entry not object', M((b) => { b.verificationMaterial.tlogEntries = [1]; }), MAIN, 'tlog_count');
for (const [k, v] of [['dsse', '0.0.2'], ['intoto', '0.0.1'], ['hashedrekord', '0.0.1'], ['rekord', '0.0.1'], ['DSSE', '0.0.1'], ['dsse', 1]] as const)
  await core(`tlog/kindVersion ${k}/${v}`, M((b) => { b.verificationMaterial.tlogEntries[0].kindVersion = { kind: k, version: v }; }), MAIN, 'tlog_kind');
await core('tlog/kindVersion missing', M((b) => { delete b.verificationMaterial.tlogEntries[0].kindVersion; }), MAIN, 'tlog_kind');
await core('tlog/kindVersion string', M((b) => { b.verificationMaterial.tlogEntries[0].kindVersion = 'dsse/0.0.1'; }), MAIN, 'tlog_kind');
await core('tlog/logId of other log', M((b) => { b.verificationMaterial.tlogEntries[0].logId.keyId = b64(sha256(otherK.spki)); }), MAIN, 'tlog_key');
await core('tlog/logId of the CT log', M((b) => { b.verificationMaterial.tlogEntries[0].logId.keyId = b64(ctLogId); }), MAIN, 'tlog_key');
await core('tlog/logId missing', M((b) => { delete b.verificationMaterial.tlogEntries[0].logId; }), MAIN, 'tlog_key');
await core('tlog/dsse entry on v2 log', bundle({ kind: 'dsse', log: 'v2' }), MAIN, 'tlog_key');
await core('tlog/intoto entry on v2 log', bundle({ kind: 'intoto', log: 'v2' }), MAIN, 'tlog_key');
await core('tlog/hashedrekord on v1 log', bundle({ kind: 'hashedrekord', log: 'v1' }), MAIN, 'tlog_key');
for (const li of ['0', '00', '01', '-1', '+5', '5 ', ' 5', '1e3', '5.0', '9007199254740991', '9007199254740992', '1234567890123456', '12345678901234567', '', 5, null, '٥'])
  await core(`tlog/logIndex ${JSON.stringify(li)}`, bundle({ logIndex: li }));
for (const it of ['0', '-1', '01', String(Math.floor(T / 1000) + 59), String(Math.floor(T / 1000) + 61), Math.floor(T / 1000) + 60, '', '9007199254740992'])
  await core(`tlog/integratedTime ${JSON.stringify(it)}`, bundle({ integrated: it }));
await core('tlog/integratedTime missing with SET', M((b) => { delete b.verificationMaterial.tlogEntries[0].integratedTime; }), MAIN, 'tlog_set');
await core('tlog/SET over other time', bundle({ setTime: Math.floor(T / 1000) + 61 }), MAIN, 'tlog_set');
await core('tlog/SET by other key', bundle({ set: 'bad' }), MAIN, 'tlog_set');
await core('tlog/SET not object', M((b) => { b.verificationMaterial.tlogEntries[0].inclusionPromise = 'x'; }), MAIN);
await core('tlog/SET missing value', M((b) => { b.verificationMaterial.tlogEntries[0].inclusionPromise = {}; }), MAIN, 'tlog_set');
await core('tlog/no time sources', bundle({ set: 'omit', ts: null }), MAIN, 'no_verified_time');
await core('tlog/no time sources, tvd not object', bundle({ set: 'omit', mut: (b) => { b.verificationMaterial.timestampVerificationData = 'x'; } }), MAIN, 'no_verified_time');
await core('tlog/rfc3161Timestamps not array', bundle({ set: 'omit', mut: (b) => { b.verificationMaterial.timestampVerificationData.rfc3161Timestamps = {}; } }), MAIN, 'no_verified_time');
await core('tlog/v2 SET ignored', bundle({ kind: 'hashedrekord', mut: (b) => { b.verificationMaterial.tlogEntries[0].inclusionPromise = { signedEntryTimestamp: 'AAAA' }; } }), MAIN, null);
await core('tlog/v2 no timestamp', bundle({ kind: 'hashedrekord', ts: null }), MAIN, 'no_verified_time');
// log / CA / TSA validity windows at the signing times (+-1 ms)
for (const [n, r, w] of [
  ['tsa ended 1ms before', rTsaEnded, 'tsa'], ['tsa ends at time', rTsaEndAt, null], ['tsa starts 1ms after', rTsaStartAfter, 'tsa'], ['tsa starts at time', rTsaStartAt, null],
  ['tsa cert no eku', rTsaNoEku, 'tsa'], ['tsa cert codesigning eku', rTsaCodeEku, 'tsa'], ['tsa cert expired', rTsaCertExpired, 'tsa'], ['tsa cert not yet valid', rTsaCertNotYet, 'tsa'],
  ['tsa two, first wrong', rTsaTwo, null], ['tsa chain leaf only', rTsaLeafOnly, 'tsa'],
  ['log ends 1ms before SET', rLogEndBefore, 'tlog_key'], ['log ends at SET', rLogEndAt, null], ['log starts 1ms after TSA', rLogStartAfter, 'tlog_key'], ['log starts at TSA', rLogStartAt, null],
  ['ca ends 1ms before SET', rCaEndBefore, 'cert_chain'], ['ca ends at SET', rCaEndAt, null], ['ca starts 1ms after TSA', rCaStartAfter, 'cert_chain'],
  ['inter not CA', rInterNotCa, 'cert_chain'], ['inter no keyCertSign', rInterNoCertSign, 'cert_chain'], ['inter expired', rInterExpired, 'cert_chain'], ['ca chain inter only', rInterOnly, 'cert_chain'],
  ['inter signed by other', rInterWrongSigner, 'cert_chain'], ['two CAs first other', rCaTwo, null], ['two CAs first ended', rCaTwoFirstEnded, null],
  ['ct ends 1ms before sct', rCtEndBefore, 'sct'], ['ct ends at sct', rCtEndAt, null], ['ct starts 1ms after sct', rCtStartAfter, 'sct'], ['two ct logs', rCtTwo, null],
] as const) await core(`roots/${n}`, bundle(), r, w);
await core('roots/v2 log ended before tsa', bundle({ kind: 'hashedrekord' }), rLog2EndBefore, 'tlog_key');
await core('roots/v2 log tsa-only roots ok', bundle({ kind: 'hashedrekord' }), rTsaStartAt, null);
for (const id of ['only-v1-log', 'only-v2-log', 'tlog-v2-baseUrl-other-host', 'tlog-v2-baseUrl-path-port', 'tlog-v2-baseUrl-upper', 'no-tsa', 'tlog-v2-as-rsa', 'tlog-v1-as-rsa', 'ctlog-as-ed25519', 'tlog-validFor-offset-form', 'tlog-validFor-end-before-start', 'ca-validFor-end-before-start', 'ca-validFor-fraction'])
  if (!(PARSED[id] instanceof Error)) for (const kind of ['dsse', 'hashedrekord'] as const) await core(`roots/${id} ${kind}`, bundle({ kind }), { $root: id });

// ---- inclusion proofs (RFC 9162) on trees of 1..9 leaves, every index
for (let size = 1; size <= 9; size++) for (let index = 0; index < size; index++) await core(`incl/tree ${size} index ${index}`, bundle({ size, index }), MAIN, null);
await core('incl/no proof', M((b) => { delete b.verificationMaterial.tlogEntries[0].inclusionProof; }), MAIN, 'tlog_inclusion');
await core('incl/proof not object', M((b) => { b.verificationMaterial.tlogEntries[0].inclusionProof = []; }), MAIN, 'tlog_inclusion');
await core('incl/hashes not array', bundle({ proofMut: () => ({}) }), MAIN, 'tlog_inclusion');
await core('incl/no checkpoint', bundle({ ipMut: (ip) => { delete ip.checkpoint; } }), MAIN, 'tlog_inclusion');
await core('incl/checkpoint string', bundle({ ipMut: (ip) => { ip.checkpoint = ip.checkpoint.envelope; } }), MAIN, 'tlog_inclusion');
await core('incl/hash dropped', bundle({ proofMut: (h) => h.slice(1) }), MAIN, 'tlog_inclusion');
await core('incl/hash extra', bundle({ proofMut: (h) => [...h, h[0]] }), MAIN, 'tlog_inclusion');
await core('incl/hashes reversed', bundle({ proofMut: (h) => [...h].reverse() }), MAIN, 'tlog_inclusion');
await core('incl/hash short', bundle({ proofMut: (h) => [b64(Buffer.alloc(31)), ...h.slice(1)] }), MAIN, 'tlog_inclusion');
await core('incl/65 hashes', bundle({ proofMut: (h) => Array.from({ length: 65 }, () => h[0]) }), MAIN, 'tlog_inclusion');
for (let i = 0; i < 3; i++) for (const byte of [0, 31]) await core(`incl/hash ${i} byte ${byte} flipped`, bundle({ proofMut: (h) => { const x = [...h]; const v = Buffer.from(x[i]!, 'base64'); v[byte]! ^= 0x80; x[i] = b64(v); return x; } }), MAIN, 'tlog_inclusion');
for (const [lbl, f] of [
  ['index = size', (ip: any) => { ip.logIndex = ip.treeSize; }], ['index other', (ip: any) => { ip.logIndex = '4'; }], ['size 0', (ip: any) => { ip.treeSize = '0'; }],
  ['size +1', (ip: any) => { ip.treeSize = '8'; }], ['size -1', (ip: any) => { ip.treeSize = '6'; }], ['size number', (ip: any) => { ip.treeSize = 7; }], ['index number', (ip: any) => { ip.logIndex = 5; }],
  ['index -1', (ip: any) => { ip.logIndex = '-1'; }], ['size 2^53', (ip: any) => { ip.treeSize = '9007199254740992'; }], ['size max safe', (ip: any) => { ip.treeSize = '9007199254740991'; }],
  ['rootHash flipped', (ip: any) => { const v = Buffer.from(ip.rootHash, 'base64'); v[0]! ^= 1; ip.rootHash = b64(v); }], ['rootHash 31 bytes', (ip: any) => { ip.rootHash = b64(Buffer.from(ip.rootHash, 'base64').subarray(1)); }],
] as const) await core(`incl/${lbl}`, bundle({ ipMut: f as any }));
await core('incl/entry logIndex differs from proof (not checked)', bundle({ logIndex: '4' }));

// ---- checkpoints (signed notes; v1 ECDSA and v2 Ed25519)
for (const kind of ['dsse', 'hashedrekord'] as const) {
  const C = async (n: string, cp: CpOpt, w?: string | null) => core(`cp/${kind} ${n}`, bundle({ kind, cp }), MAIN, w);
  await C('no blank line', { noBlank: true }, 'tlog_checkpoint');
  await C('empty origin', { origin: '' }, 'tlog_checkpoint');
  await C('origin other (signed)', { origin: 'other origin' });
  for (const sl of ['0', '07', '8', '6', '+7', '7 ', '1e1', '9007199254740993', ''])
    await C(`size line ${JSON.stringify(sl)}`, { sizeLine: sl });
  await C('root line other', { rootLine: b64(sha256(Buffer.from('x'))) }, 'tlog_checkpoint');
  await C('root line bad b64', { rootLine: 'A' }, 'tlog_checkpoint');
  await C('root line 31 bytes', { rootLine: b64(Buffer.alloc(31)) }, 'tlog_checkpoint');
  await C('extra body line (signed)', { bodyExtra: 'extension line\n' });
  await C('signature by other key', { signer: otherK.kind === 'p256' && kind === 'dsse' ? otherK : key('otherEd', 'ed') }, 'tlog_checkpoint');
  await C('key hint wrong', { hint: Buffer.from([0, 0, 0, 0]) }, 'tlog_checkpoint');
  await C('raw sig too short', { lines: () => [`— ${kind === 'dsse' ? 'synthetic.log' : LOG2_NAME} ${b64(Buffer.concat([kind === 'dsse' ? logId.subarray(0, 4) : log2Id.subarray(0, 4)]))}`] }, 'tlog_checkpoint');
  await C('raw sig 5 bytes', { lines: () => [`— ${kind === 'dsse' ? 'synthetic.log' : LOG2_NAME} ${b64(Buffer.concat([kind === 'dsse' ? logId.subarray(0, 4) : log2Id.subarray(0, 4), Buffer.from([1])]))}`] }, 'tlog_checkpoint');
  await C('witness lines then log', { lines: (s) => [`— witness.example ${b64(Buffer.alloc(68, 1))}`, 'not a signature line', s] }, null);
  await C('log line then garbage', { lines: (s) => [s, 'garbage'] }, null);
  await C('em dash replaced by hyphen', { lines: (s) => [s.replace('—', '-')] }, 'tlog_checkpoint');
  await C('two spaces', { lines: (s) => [s.replace(' ', '  ')] }, 'tlog_checkpoint');
  await C('trailing space', { lines: (s) => [s + ' '] }, 'tlog_checkpoint');
  await C('urlsafe sig b64', { lines: (s) => [s.replace(/\+/g, '-').replace(/\//g, '_')] });
  await C('no signature lines', { lines: () => [] }, 'tlog_checkpoint');
  await C('CRLF', { lines: (s) => [s + '\r'] }, 'tlog_checkpoint');
  await C('sig line name other', { name: 'other.name' });
  await C('whole text empty', { text: '' }, 'tlog_checkpoint');
  await C('only body, blank', { text: 'origin\n7\nAAAA\n\n' }, 'tlog_checkpoint');
  await C('three body lines only', { text: `x\n7\n\n— a b` }, 'tlog_checkpoint');
}
await core('cp/v2 signed under v1 name', bundle({ kind: 'hashedrekord', cp: { name: 'synthetic.log' } }), MAIN, 'tlog_checkpoint');
await core('cp/envelope not string', bundle({ ipMut: (ip) => { ip.checkpoint.envelope = 5; } }), MAIN, 'tlog_checkpoint');
// no String() coercion: a one-element ARRAY where a string belongs is refused (0.5)
await core('coerce/kindVersion.kind ["dsse"]', M((b) => { b.verificationMaterial.tlogEntries[0].kindVersion.kind = ['dsse']; }), MAIN, 'tlog_kind');
await core('coerce/kindVersion.version ["0.0.1"]', M((b) => { b.verificationMaterial.tlogEntries[0].kindVersion.version = ['0.0.1']; }), MAIN, 'tlog_kind');
await core('coerce/body kind ["dsse"]', bundle({ bodyMut: (b) => { b.kind = ['dsse']; } }), MAIN, 'tlog_body');
await core('coerce/body apiVersion ["0.0.1"]', bundle({ bodyMut: (b) => { b.apiVersion = ['0.0.1']; } }), MAIN, 'tlog_body');
await core('coerce/checkpoint envelope [text]', bundle({ ipMut: (ip) => { ip.checkpoint.envelope = [ip.checkpoint.envelope]; } }), MAIN, 'tlog_checkpoint');
await core('coerce/hashedrekord kindVersion.kind ["hashedrekord"]', bundle({ kind: 'hashedrekord', mut: (b) => { b.verificationMaterial.tlogEntries[0].kindVersion.kind = ['hashedrekord']; } }), MAIN, 'tlog_kind');
// Rekor v2 / TSA-only entries: without a SET the entry's own logIndex is unauthenticated, so the reported rekor_log_index is the
// inclusion proof's verified index (0.5); with a SET the log signs the entry index and that is reported
await core('unbound/v2 entry logIndex 4, proof index 5 (reports 5)', bundle({ kind: 'hashedrekord', logIndex: '4' }), MAIN, null);
await core('unbound/v1 tsa-only entry logIndex 4, proof index 5 (reports 5)', bundle({ set: 'omit', logIndex: '4' }), MAIN, null);
await core('unbound/v1 with SET entry logIndex 4, proof index 5 (the SET signs it, reports 4)', bundle({ logIndex: '4' }), MAIN, null);
await core('cp/envelope missing', bundle({ ipMut: (ip) => { delete ip.checkpoint.envelope; } }), MAIN, 'tlog_checkpoint');

// ---- the certificate: chain, CA flag, validity, EKU, AKI, parse
const L = async (n: string, leaf: LeafOpt, w?: string | null, kind: 'dsse' | 'intoto' | 'hashedrekord' = 'dsse', extra: Partial<BOpt> = {}) => core(`cert/${kind} ${n}`, bundle({ kind, leaf, ...extra }), MAIN, w);
await L('valid from = TSA time', { from: TSA_T }, null);
await L('valid from 1ms after TSA time', { from: TSA_T + 1 }, 'cert_time');
await L('valid to = SET time', { to: SET_T }, null);
await L('valid to 1ms before SET time', { to: SET_T - 1 }, 'cert_time');
await L('valid to 1s before SET (UTCTime precision)', { to: SET_T - 1000 }, 'cert_time');
await L('expired, tsa only', { to: TSA_T - 1000 }, 'cert_time', 'dsse', { set: 'omit' });
await L('hashedrekord valid to = TSA time', { to: TSA_T }, null, 'hashedrekord');
await L('hashedrekord valid to 1s before TSA', { to: TSA_T - 1000 }, 'cert_time', 'hashedrekord');
// basicConstraints cA TRUE makes the leaf a CA whatever its keyUsage (0.5; OpenSSL's X509_check_ca alone would let it pass)
await core('cert/dsse leaf CA:TRUE, keyUsage digitalSignature only', bundle({ leaf: { ca: true } }), MAIN, 'cert_chain');
await L('leaf CA:TRUE with keyCertSign', { ca: true, ku: bits(Buffer.from([0x84]), 2) }, 'cert_chain');
await L('leaf CA:TRUE without keyUsage', { ca: true, ku: null }, 'cert_chain');
await L('leaf without keyUsage', { ku: null }, null);
await L('leaf keyUsage keyCertSign only', { ku: bits(Buffer.from([0x04]), 2) }, null);
await L('no EKU', { eku: null }, 'cert_eku');
await L('EKU timestamping only', { eku: ['1.3.6.1.5.5.7.3.8'] }, 'cert_eku');
await L('EKU server auth + code signing', { eku: ['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.3'] }, null);
await L('AKI other', { aki: Buffer.alloc(20, 9) }, 'cert_chain');
await L('AKI absent', { aki: null }, null);
await L('SKI absent', { ski: false }, null);
await L('issuer name other', { issuer: name('someone-else') }, 'cert_chain');
await L('signed by other key', { signer: otherK }, 'cert_chain');
await L('signed by root directly', { signer: rootK, issuer: ROOT_NAME, aki: ski(rootK) }, 'cert_chain');
await L('no extensions', { noExts: true }, 'cert_parse');
await L('duplicate extension', { dup: true });
await L('SCT ext first', { order: 'sctFirst' }, null);
await L('extension value not octet', { extra: [seq(oid('1.2.3.4'), tlv(0x0c, Buffer.from('x')))] });
await L('extension unknown critical', { extra: [ext('1.2.3.4', Buffer.from([5, 0]), true)] });
await L('extension unknown non-critical', { extra: [ext('1.2.3.4', Buffer.from([5, 0]))] }, null);
await L('extension with trailing junk inside', { extra: [seq(oid('1.2.3.4'), octet(Buffer.from([1])), octet(Buffer.from([2])))] });
await core('cert/body names leaf, envelope cert differs (0.2 chain[0] other)', bundle({ leafDer: leafCert({ key: otherK }), dsseKey: leafK }), MAIN);
await core('cert/rawBytes random 64', M((b) => { b.verificationMaterial.certificate.rawBytes = b64(seed('k05-sigstore/junk')) + b64(seed('k05-sigstore/junk2')); }), MAIN, 'cert_parse');
await core('cert/rawBytes inter CA cert', bundle({ leafDer: interCert }), MAIN);
await core('cert/rawBytes root CA cert', bundle({ leafDer: rootCert }), MAIN);
await core('cert/rawBytes tsa cert', bundle({ leafDer: tsaCert }), MAIN);

// ---- SCT (RFC 6962 3.2)
const SC = async (n: string, sct: SctOpt | null, w?: string | null, r = MAIN) => core(`sct/${n}`, bundle({ leaf: { sct } }), r, w);
await SC('missing', null, 'sct');
await SC('missing, no-ct root', null, null, NO_CT);
await SC('outer not octet', { outerTag: 0x30 }, 'sct');
await SC('list length +1', { listLenDelta: 1 }, 'sct');
await SC('list length -1', { listLenDelta: -1 }, 'sct');
await SC('list empty', { raw: Buffer.from([0, 0]) }, 'sct');
await SC('list one byte', { raw: Buffer.from([0]) }, 'sct');
await SC('list zero bytes', { raw: Buffer.alloc(0) }, 'sct');
await SC('list trailing 1 byte after a good SCT (first verified SCT wins)', { trailing: Buffer.from([0]), listLenDelta: 1 }, null);
await SC('list trailing 1 byte after a foreign SCT', { logId: sha256(otherK.spki), signer: otherK, trailing: Buffer.from([0]), listLenDelta: 1 }, 'sct');
await SC('sct length +1', { sctLenDelta: 1, listLenDelta: 0 }, 'sct');
await SC('sct length -1', { sctLenDelta: -1 }, 'sct');
await SC('sct 46 bytes', { raw: (() => { const b = Buffer.concat([u16(46), Buffer.alloc(46)]); return Buffer.concat([u16(b.length), b]); })() }, 'sct');
await SC('sct 47 bytes v1 junk', { raw: (() => { const b = Buffer.concat([u16(47), Buffer.alloc(47)]); return Buffer.concat([u16(b.length), b]); })() }, 'sct');
await SC('sct 47 bytes v2 skipped', { raw: (() => { const s = Buffer.alloc(47); s[0] = 1; const b = Buffer.concat([u16(47), s]); return Buffer.concat([u16(b.length), b]); })() }, 'sct');
await SC('version 1 (skipped)', { version: 1 }, 'sct');
await SC('unknown log', { logId: sha256(otherK.spki), signer: otherK }, 'sct');
await SC('foreign then good', { before: [foreignSct()] }, null);
await SC('good then foreign', { after: [foreignSct()] }, null);
await SC('hashAlg 5', { hashAlg: 5 }, 'sct');
await SC('sigAlg 1 (rsa) on ec log', { sigAlg: 1 }, null);
await SC('sigAlg 2', { sigAlg: 2 }, 'sct');
await SC('sigAlg 0', { sigAlg: 0 }, 'sct');
await SC('sig over other ts', { claimTs: BigInt(T - 30_001) }, 'sct');
await SC('sig by other key', { signer: otherK }, 'sct');
await SC('issuer key hash of root', { issuerKey: rootK }, 'sct');
await SC('ext bytes', { ext: Buffer.from([1, 2, 3]) }, null);
await SC('sig length +1', { sigLenDelta: 1 }, 'sct');
await SC('sig length -1', { sigLenDelta: -1 }, 'sct');
await SC('ts 0', { ts: 0n }, 'sct');
await SC('ts at ct start', { ts: BigInt(FROM.getTime()) }, null);
await SC('ts 1ms before ct start', { ts: BigInt(FROM.getTime() - 1) }, 'sct');
// 0.5: the 64-bit SCT timestamp is read exactly; past 2^53-1 it is out of range (even under an open-ended log validity)
await SC('ts 2^63 (unbounded log)', { ts: 1n << 63n }, 'sct');
await SC('ts 2^64-1 (unbounded log)', { ts: (1n << 64n) - 1n }, 'sct');
await SC('ts 2^53+1', { ts: (1n << 53n) + 1n }, 'sct');
await SC('ts 2^53 (unbounded log)', { ts: 1n << 53n }, 'sct');
await SC('ts 2^53-1 (unbounded log)', { ts: (1n << 53n) - 1n }, null);
await SC('ts 2^63, log end set', { ts: 1n << 63n }, 'sct', rCtEndAt);
await SC('sha384 sig hash', { sigHash: 'sha384' }, 'sct');

// ---- entry bodies (the entry names this envelope)
const BM = async (n: string, kind: 'dsse' | 'intoto' | 'hashedrekord', f: (b: any) => void, w: string | null = 'tlog_body') => core(`body/${kind} ${n}`, bundle({ kind, bodyMut: f }), MAIN, w);
for (const kind of ['dsse', 'intoto', 'hashedrekord'] as const) {
  await BM('kind other', kind, (b) => { b.kind = kind === 'dsse' ? 'intoto' : 'dsse'; });
  await BM('apiVersion other', kind, (b) => { b.apiVersion = '0.0.3'; });
  await BM('apiVersion missing', kind, (b) => { delete b.apiVersion; });
  await BM('spec missing', kind, (b) => { delete b.spec; });
  await BM('spec array', kind, (b) => { b.spec = []; });
  await core(`body/${kind} not JSON`, bundle({ kind, bodyRaw: Buffer.from('not json') }), MAIN, 'tlog_body');
  await core(`body/${kind} JSON array`, bundle({ kind, bodyRaw: Buffer.from('[]') }), MAIN, 'tlog_body');
  await core(`body/${kind} JSON null`, bundle({ kind, bodyRaw: Buffer.from('null') }), MAIN);
  await core(`body/${kind} body cert other`, bundle({ kind, bodyCert: leafCert({ key: otherK }) }), MAIN, 'tlog_body');
}
const DS = (b: any) => b.spec, IT = (b: any) => b.spec.content;
for (const [kind, sp] of [['dsse', DS], ['intoto', IT]] as const) {
  await BM('payloadHash alg sha512', kind, (b) => { sp(b).payloadHash.algorithm = 'sha512'; });
  await BM('payloadHash value upper', kind, (b) => { sp(b).payloadHash.value = sp(b).payloadHash.value.toUpperCase(); });
  await BM('payloadHash missing', kind, (b) => { delete sp(b).payloadHash; });
  await BM('payloadHash string', kind, (b) => { sp(b).payloadHash = 'x'; });
}
await BM('signatures empty', 'dsse', (b) => { b.spec.signatures = []; });
await BM('signatures two', 'dsse', (b) => { b.spec.signatures.push(b.spec.signatures[0]); });
await BM('signatures not array', 'dsse', (b) => { b.spec.signatures = b.spec.signatures[0]; });
await BM('signature not object', 'dsse', (b) => { b.spec.signatures = [1]; });
await BM('signature other', 'dsse', (b) => { b.spec.signatures[0].signature = b64(sign(otherK, Buffer.from('x'))); });
await BM('signature bad b64', 'dsse', (b) => { b.spec.signatures[0].signature = 'A'; }, 'tlog_body');
await BM('verifier bad b64', 'dsse', (b) => { b.spec.signatures[0].verifier = 'A'; }, 'tlog_body');
await BM('verifier not PEM', 'dsse', (b) => { b.spec.signatures[0].verifier = b64(Buffer.from('hello')); });
await BM('verifier PEM no trailing newline', 'dsse', (b) => { b.spec.signatures[0].verifier = b64(Buffer.from(Buffer.from(b.spec.signatures[0].verifier, 'base64').toString().trimEnd())); }, null);
await BM('verifier PEM CRLF', 'dsse', (b) => { b.spec.signatures[0].verifier = b64(Buffer.from(Buffer.from(b.spec.signatures[0].verifier, 'base64').toString().replace(/\n/g, '\r\n'))); });
await BM('verifier PEM one line', 'dsse', (b) => { const t = Buffer.from(b.spec.signatures[0].verifier, 'base64').toString(); const m = /-----\n([\s\S]*)\n-----END/.exec(t)!; b.spec.signatures[0].verifier = b64(Buffer.from(`-----BEGIN CERTIFICATE-----\n${m[1]!.replace(/\n/g, '')}\n-----END CERTIFICATE-----\n`)); }, null);
await BM('verifier PEM two newlines at end', 'dsse', (b) => { b.spec.signatures[0].verifier = b64(Buffer.from(Buffer.from(b.spec.signatures[0].verifier, 'base64').toString() + '\n')); });
await BM('verifier PEM public key', 'dsse', (b) => { b.spec.signatures[0].verifier = b64(Buffer.from(`-----BEGIN PUBLIC KEY-----\n${b64(leafK.spki)}\n-----END PUBLIC KEY-----\n`)); });
await BM('envelope missing', 'intoto', (b) => { delete b.spec.content.envelope; });
await BM('envelope sigs two', 'intoto', (b) => { const e = b.spec.content.envelope; e.signatures.push(e.signatures[0]); });
await BM('envelope sigs empty', 'intoto', (b) => { b.spec.content.envelope.signatures = []; });
await BM('envelope sig single-b64', 'intoto', (b) => { const s = b.spec.content.envelope.signatures[0]; s.sig = Buffer.from(s.sig, 'base64').toString(); });
await BM('envelope sig other', 'intoto', (b) => { b.spec.content.envelope.signatures[0].sig = b64(Buffer.from(b64(Buffer.alloc(70, 1)))); });
await BM('envelope sig inner not b64', 'intoto', (b) => { b.spec.content.envelope.signatures[0].sig = b64(Buffer.from('!!!!')); });
await BM('envelope publicKey other', 'intoto', (b) => { b.spec.content.envelope.signatures[0].publicKey = b64(Buffer.from(pemOf(interCert))); });
await BM('content missing', 'intoto', (b) => { delete b.spec.content; });
const HR = (b: any) => b.spec.hashedRekordV002;
for (const alg of ['SHA2_384', 'SHA2_512', 'SHA256', 'sha256', '', null]) await core(`body/hashedrekord algorithm ${JSON.stringify(alg)}`, bundle({ kind: 'hashedrekord', hrAlg: alg as string }), MAIN, 'tlog_body');
await core('body/hashedrekord p384 leaf SHA2_256', bundle({ kind: 'hashedrekord', leaf: { key: leaf384K }, hrAlg: 'SHA2_256' }), MAIN, 'tlog_body');
await core('body/hashedrekord ed25519 leaf', bundle({ kind: 'hashedrekord', leaf: { key: leafEdK }, hrAlg: 'SHA2_256' }), MAIN, 'tlog_body');
await BM('digest of payload not PAE', 'hashedrekord', (b) => { HR(b).data.digest = b64(sha256(Buffer.from(JSON.stringify(STATEMENT)))); });
await BM('digest missing', 'hashedrekord', (b) => { delete HR(b).data.digest; });
await BM('data missing', 'hashedrekord', (b) => { delete HR(b).data; });
await BM('signature content other', 'hashedrekord', (b) => { HR(b).signature.content = b64(Buffer.alloc(70, 2)); });
await BM('signature missing', 'hashedrekord', (b) => { delete HR(b).signature; });
await BM('verifier publicKey form', 'hashedrekord', (b) => { HR(b).signature.verifier = { publicKey: { rawBytes: b64(leafK.spki) } }; });
await BM('verifier cert other', 'hashedrekord', (b) => { HR(b).signature.verifier.x509Certificate.rawBytes = b64(interCert); });
await BM('hashedRekordV002 missing', 'hashedrekord', (b) => { b.spec = { hashedRekordV001: HR(b) }; });

// ---- the DSSE signature and leaf key types
await core('sig/other key', bundle({ dsseKey: otherK }), MAIN, 'signature');
await core('sig/hashedrekord other key', bundle({ kind: 'hashedrekord', dsseKey: otherK }), MAIN, 'signature');
await core('sig/ed25519 leaf dsse', bundle({ leaf: { key: leafEdK } }), MAIN, 'signature');
await core('sig/ed25519 leaf intoto', bundle({ kind: 'intoto', leaf: { key: leafEdK } }), MAIN, 'signature');
await core('sig/p384 leaf signed with sha256', bundle({ leaf: { key: leaf384K }, dsseHash: 'sha256' }), MAIN, 'signature');
await core('sig/p256 leaf signed with sha384', bundle({ dsseHash: 'sha384' }), MAIN, 'signature');
for (const i of [0, 8, 40]) await core(`sig/byte ${i} flipped (body names it)`, bundle({ sigOverride: (() => { const s = sign(leafK, S.dssePae(PT, Buffer.from(JSON.stringify(STATEMENT)))); s[i]! ^= 1; return s; })() }), MAIN, 'signature');

// ---- identity (SAN, Fulcio issuer extensions .1.1 / .1.8, sources .1.12-.1.14)
const ID = async (n: string, leaf: LeafOpt, w?: string | null) => { await core(`id/${n}`, bundle({ leaf }), MAIN, w); await full(`id/${n}`, bundle({ leaf })); };
await ID('san email', { san: seq(tlv(0x81, Buffer.from('dev@example.com'))) }, null);
await ID('san dns', { san: seq(tlv(0x82, Buffer.from('example.com'))) }, 'identity');
await ID('san otherName', { san: seq(tlv(0xa0, oid('1.3.6.1.4.1.57264.1.7'), tlv(0xa0, utf8('x')))) }, 'identity');
await ID('san two uris', { san: seq(tlv(0x86, Buffer.from('https://a')), tlv(0x86, Buffer.from('https://b'))) }, 'identity');
await ID('san empty seq', { san: seq() }, 'identity');
await ID('san set not seq', { san: set(tlv(0x86, Buffer.from('https://a'))) }, 'cert_chain'); // OpenSSL fails to decode the SAN: checkIssued refuses first
await ID('san missing', { san: null }, 'identity');
await ID('san uri invalid utf8', { san: seq(tlv(0x86, Buffer.from([0x68, 0xff, 0x69]))) }, 'identity');
await ID('san uri with BOM', { san: seq(tlv(0x86, Buffer.from('﻿https://a'))) }, null);
await ID('san uri empty', { san: seq(tlv(0x86, Buffer.alloc(0))) }, null);
await ID('san uri non-ascii', { san: seq(tlv(0x86, Buffer.from('https://ä.example/é'))) }, null);
await ID('san uri overlong utf8', { san: seq(tlv(0x86, Buffer.from([0xc0, 0xaf]))) }, 'identity');
await ID('san uri surrogate utf8', { san: seq(tlv(0x86, Buffer.from([0xed, 0xa0, 0x80]))) }, 'identity');
await ID('san truncated', { san: Buffer.from([0x30, 0x05, 0x86, 0x10, 0x61]) }, 'cert_chain');
await ID('san non-critical', { sanCritical: false }, null);
await ID('iss8 missing, iss1 present', { iss8: null, iss1: Buffer.from(OIDC) }, null);
await ID('iss8 and iss1 agree', { iss1: Buffer.from(OIDC) }, null);
await ID('iss8 and iss1 disagree', { iss1: Buffer.from('https://accounts.google.com') }, 'identity');
await ID('iss1 differs by trailing slash', { iss1: Buffer.from(OIDC + '/') }, 'identity');
await ID('no issuer', { iss8: null }, 'identity');
await ID('iss8 empty utf8string', { iss8: utf8('') }, 'identity');
await ID('iss1 empty, no iss8', { iss8: null, iss1: Buffer.alloc(0) }, 'identity');
await ID('iss8 empty, iss1 present', { iss8: utf8(''), iss1: Buffer.from(OIDC) }, 'identity');
await ID('iss8 printable string', { iss8: tlv(0x13, Buffer.from(OIDC)) }, 'identity');
await ID('iss8 raw (not DER)', { iss8: Buffer.from(OIDC) }, 'identity');
await ID('iss8 trailing byte', { iss8: Buffer.concat([utf8(OIDC), Buffer.from([0])]) }, 'identity');
await ID('iss8 invalid utf8', { iss8: utf8(Buffer.from([0xff])) }, 'identity');
await ID('iss8 BOM', { iss8: utf8('﻿' + OIDC) }, null);
await ID('iss1 BOM, iss8 plain', { iss1: Buffer.from('﻿' + OIDC) }, null);
await ID('iss1 invalid utf8', { iss8: null, iss1: Buffer.from([0xfe]) }, 'identity');
await ID('iss8 long length form', { iss8: Buffer.concat([Buffer.from([0x0c, 0x81, OIDC.length]), Buffer.from(OIDC)]) }, null);
await ID('iss8 truncated DER', { iss8: Buffer.from([0x0c, 0x10, 0x61]) }, 'identity');
await ID('iss8 multi-byte tag', { iss8: Buffer.from([0x1f, 0x01, 0x00]) }, 'identity');
await ID('no sources', { src: [null, null, null] }, null);
await ID('source repo only', { src: [utf8(REPO), null, null] }, null);
await ID('source digest raw (not DER)', { src: [utf8(REPO), Buffer.from('a'.repeat(40)), utf8('refs/x')] }, 'identity');
await ID('source ref empty', { src: [utf8(REPO), utf8('b'.repeat(40)), utf8('')] }, null);
await ID('source repo invalid utf8', { src: [utf8(Buffer.from([0xc3])), null, null] }, 'identity');
await ID('source repo other tag', { src: [tlv(0x16, Buffer.from(REPO)), null, null] }, 'identity');
await ID('fulcio .1.6 raw ignored', { extra: [ext('1.3.6.1.4.1.57264.1.6', Buffer.from([0xff]))] }, null);
await ID('fulcio .1.9 invalid ignored', { extra: [ext('1.3.6.1.4.1.57264.1.9', Buffer.from([0xff]))] }, null);

// ---- the statement and the SLSA predicate (verifySigstoreBundleCore stage 'statement'; verifySigstoreBundle 'predicate')
const ST = async (n: string, statement: unknown, w?: string | null) => { await core(`stmt/${n}`, bundle({ statement }), MAIN, w); await full(`stmt/${n}`, bundle({ statement })); };
const st = (f: (s: any) => void) => { const s = clone(STATEMENT); f(s); return s; };
await ST('_type v0.1', st((s) => { s._type = 'https://in-toto.io/Statement/v0.1'; }), 'statement');
await ST('_type missing', st((s) => { delete s._type; }), 'statement');
await ST('subject empty', st((s) => { s.subject = []; }), 'statement');
await ST('subject missing', st((s) => { delete s.subject; }), 'statement');
await ST('subject object', st((s) => { s.subject = s.subject[0]; }), 'statement');
await ST('subject no digests', st((s) => { s.subject = [{ name: 'x', digest: { md5: 'x' } }]; }), 'statement');
await ST('subject junk items', st((s) => { s.subject = [1, null, 'x', { digest: 'x' }, s.subject[0]]; }), null);
await ST('subject sha512 + sha256', st((s) => { s.subject = [{ digest: { sha512: 'b'.repeat(128), sha256: 'c'.repeat(64) } }]; }), null);
await ST('subject digest number', st((s) => { s.subject = [{ digest: { sha256: 5 } }]; }), 'statement');
await ST('subject digest empty string', st((s) => { s.subject = [{ digest: { sha256: '' } }]; }), null);
for (const n of [63, 64, 65]) await ST(`subjects ${n}`, st((s) => { s.subject = Array.from({ length: n }, (_, i) => ({ digest: { sha256: i.toString(16).padStart(64, '0') } })); }), n > 64 ? 'statement' : null);
await ST('subjects 32 with both digests', st((s) => { s.subject = Array.from({ length: 32 }, () => ({ digest: { sha256: 'a', sha512: 'b' } })); }), null);
await ST('subjects 33 with both digests', st((s) => { s.subject = Array.from({ length: 33 }, () => ({ digest: { sha256: 'a', sha512: 'b' } })); }), 'statement');
await ST('predicateType missing', st((s) => { delete s.predicateType; }), 'statement');
await ST('predicateType number', st((s) => { s.predicateType = 1; }), 'statement');
await ST('predicateType other', st((s) => { s.predicateType = 'https://slsa.dev/provenance/v0.2'; }), null);
await ST('predicateType empty', st((s) => { s.predicateType = ''; }), null);
await ST('predicate missing', st((s) => { delete s.predicate; }), null);
await ST('buildType missing', st((s) => { delete s.predicate.buildDefinition.buildType; }), null);
await ST('externalParameters array', st((s) => { s.predicate.buildDefinition.externalParameters = []; }), null);
await ST('externalParameters empty', st((s) => { s.predicate.buildDefinition.externalParameters = {}; }), null);
await ST('builder id number', st((s) => { s.predicate.runDetails.builder.id = 1; }), null);
await ST('runDetails missing', st((s) => { delete s.predicate.runDetails; }), null);
await ST('no resolvedDependencies', st((s) => { delete s.predicate.buildDefinition.resolvedDependencies; }), null);
await ST('resolvedDependencies empty', st((s) => { s.predicate.buildDefinition.resolvedDependencies = []; }), null);
await ST('dep0 not object', st((s) => { s.predicate.buildDefinition.resolvedDependencies = ['x', { uri: 'u' }]; }), null);
await ST('dep0 no uri', st((s) => { delete s.predicate.buildDefinition.resolvedDependencies[0].uri; }), null);
await ST('dep0 uri number', st((s) => { s.predicate.buildDefinition.resolvedDependencies[0].uri = 5; }), null);
await ST('dep0 no gitCommit', st((s) => { s.predicate.buildDefinition.resolvedDependencies[0].digest = { sha1: 'x' }; }), null);
await ST('dep0 digest missing', st((s) => { delete s.predicate.buildDefinition.resolvedDependencies[0].digest; }), null);
await ST('dep0 gitCommit number', st((s) => { s.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit = 1; }), null);
await ST('statement array', [STATEMENT], 'statement');
await core('stmt/payload not JSON', bundle({ payload: Buffer.from('not json') }), MAIN, 'statement');
await core('stmt/payload invalid utf8', bundle({ payload: Buffer.concat([Buffer.from('{"a":"'), Buffer.from([0xff]), Buffer.from('"}')]) }), MAIN, 'statement');
await core('stmt/payload with BOM', bundle({ payload: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify(STATEMENT))]) }), MAIN, null);
await core('stmt/payload empty', bundle({ payload: Buffer.alloc(0) }), MAIN, 'statement');
await core('stmt/payload JSON null', bundle({ payload: Buffer.from('null') }), MAIN, 'statement');

// ---- RFC 3161 inside bundles
const TS = async (n: string, ts: TsOpt[], w?: string | null, r = MAIN) => core(`tsa/${n}`, bundle({ ts }), r, w);
await TS('bare token', [{ status: null }], null);
await TS('status 1', [{ status: 1 }], null);
await TS('status 2', [{ status: 2 }], 'tsa');
await TS('one good one bad', [{}, { signer: otherK }], 'tsa');
await TS('one bad one good', [{ signer: otherK }, {}], 'tsa');
await TS('ts entry not object', [{}], null);
await core('tsa/entry not object', M((b) => { b.verificationMaterial.timestampVerificationData.rfc3161Timestamps = ['x']; }), MAIN, 'tsa');
await core('tsa/entry missing signedTimestamp', M((b) => { b.verificationMaterial.timestampVerificationData.rfc3161Timestamps = [{}]; }), MAIN, 'tsa');
await TS('imprint over other data', [{ imprintOver: Buffer.from('other') }], 'tsa');
await TS('genTime 1s after cert end, set ok', [{ genTime: genStr(new Date(T + 601_000)) }], 'cert_time');
await TS('genTime earliest (signed_time)', [{ genTime: genStr(new Date(T - 59_000)) }], null);
await TS('genTime with millis', [{ genTime: genStr(new Date(T + 30_000)).slice(0, 14) + '.999Z' }], null);

// ---- verifyRfc3161 direct (token, data, tsas): every TSTInfo / CMS / signer-info branch, genTime forms, DER
const DATA = Buffer.from(sign(leafK, Buffer.from('k05 rfc3161 data')));
const R3 = async (n: string, token: Buffer | string, r: { $root: string } = MAIN, data: Buffer = DATA, fn = 'verifyRfc3161') =>
  O.run(fn, n, (t: string, d: string, rr: { $root: string }) => S.verifyRfc3161(new Uint8Array(Buffer.from(t, 'base64')), new Uint8Array(Buffer.from(d, 'base64')), rootsOf(rr).tsas), [typeof token === 'string' ? token : b64(token), b64(data), r]);
const tok = (o: TsOpt = {}) => tsToken(DATA, o);
await R3('valid resp', tok());
await R3('valid bare', tok({ status: null }));
await R3('valid status 1', tok({ status: 1 }));
for (const s of [2, 3, 5, 0x80]) await R3(`status ${s}`, tok({ status: s }));
await R3('status two bytes 0', tok({ statusRaw: Buffer.from([0, 0]) }));
await R3('status two bytes 00 01', tok({ statusRaw: Buffer.from([0, 1]) }));
await R3('status empty', tok({ statusRaw: Buffer.alloc(0) }));
await R3('resp without token', tok({ respNoToken: true }));
await R3('sd oid data', tok({ sdOid: '1.2.840.113549.1.7.1' }));
await R3('sd ctx tag a1', tok({ ctxTag: 0xa1 }));
await R3('content oid data', tok({ contentOid: '1.2.840.113549.1.7.1' }));
await R3('content tag a1', tok({ contentTag: 0xa1 }));
await R3('tst not octet', tok({ tstTag: 0x30 }));
await R3('no encap', tok({ noEncap: true }));
await R3('signerInfos not set', tok({ signerInfosTag: 0x30 }));
await R3('no signerInfos', tok({ signerCount: 0 }));
await R3('two signerInfos', tok({ signerCount: 2 }));
await R3('signed attrs tag a1', tok({ attrsTag: 0xa1 }));
await R3('sig not octet', tok({ sigTag: 0x03 }));
for (const a of ['omit', 'wrong', 'two'] as const) { await R3(`content-type attr ${a}`, tok({ ct: a })); await R3(`message-digest attr ${a}`, tok({ md: a })); }
await R3('si digest sha384', tok({ siDigest: 'sha384' }));
await R3('si digest sha512', tok({ siDigest: 'sha512' }));
await R3('si digest md5 oid', tok({ siDigest: '1.2.840.113549.2.5' }));
await R3('imprint sha384', tok({ imprintAlg: seq(oid(DIG.sha384!)), imprint: H('sha384', DATA) }));
await R3('imprint sha512', tok({ imprintAlg: seq(oid(DIG.sha512!)), imprint: H('sha512', DATA) }));
await R3('imprint sha1 oid', tok({ imprintAlg: seq(oid('1.3.14.3.2.26')), imprint: H('sha1', DATA) }));
await R3('imprint sha384 alg sha256 hash', tok({ imprintAlg: seq(oid(DIG.sha384!)) }));
await R3('imprint alg with NULL params', tok({ imprintAlg: seq(oid(DIG.sha256!), Buffer.from([5, 0])) }));
await R3('imprint other data', tok({ imprintOver: Buffer.from('x') }));
await R3('imprint truncated 31', tok({ imprint: sha256(DATA).subarray(0, 31) }));
await R3('signed by other key', tok({ signer: otherK }));
await R3('signed by tsa, data other', tok(), MAIN, Buffer.from('other data'));
await R3('trailing element after token (resp)', tok({ extraTail: int(1) }));
await R3('token plus trailing byte', Buffer.concat([tok(), Buffer.from([0])]));
await R3('token truncated 1', tok().subarray(0, tok().length - 1));
await R3('empty', Buffer.alloc(0));
await R3('one byte', Buffer.from([0x30]));
await R3('not a sequence', octet(Buffer.from([1, 2, 3])));
for (const [n, r] of [['tsa ended', rTsaEnded], ['tsa ends at', rTsaEndAt], ['tsa starts after', rTsaStartAfter], ['tsa starts at', rTsaStartAt], ['tsa cert no eku', rTsaNoEku], ['tsa cert expired', rTsaCertExpired], ['two tsas first wrong', rTsaTwo], ['tsa chain leaf only', rTsaLeafOnly], ['no tsas', { $root: 'no-tsa' }]] as const)
  await R3(`roots ${n}`, tok(), r);
// genTime: format, real-date, fraction and tag
const GT = ['20260601123000Z', '20260601123000.5Z', '20260601123000.05Z', '20260601123000.123456789Z', '20260601123000.1234567890Z', '20260601123000.Z', '20260601123000z',
  '202606011230Z', '20260601123000+0000', '20260601123000', '2026060112300Z', '20260230123000Z', '20260601243000Z', '20260601126000Z', '20260601123060Z', '20260631123000Z',
  '20261301123000Z', '20260001123000Z', '20280229123000Z', '20270229123000Z', '00000101000000Z', '99991231235959Z', '20260601123000.000Z', '20260601123000.999999999Z',
  ' 20260601123000Z', '2026-06-01T12:30:00Z', '２0260601123000Z', '20260601123000.1Z\u0000'];
for (const g of GT) await R3(`genTime ${JSON.stringify(g)}`, tok({ genTime: g }));
await R3('genTime UTCTime tag', tok({ genTag: 0x17, genTime: '260601123000Z' }));
await R3('genTime latin1 byte', tok({ genTime: '2026060112300¹Z' }));
// fraction parsing: exact truncation to ms (0.5). Every 1..3 digit fraction where a float floor would differ from exact truncation.
let fracSuspect = 0;
for (let d = 1; d <= 3; d++) for (let v = 0; v < 10 ** d; v++) {
  const f = String(v).padStart(d, '0');
  const exact = Number(f.padEnd(3, '0').slice(0, 3));
  const float = Math.floor(Number(`0.${f}`) * 1000);
  if (float !== exact) { fracSuspect++; await R3(`genTime fraction .${f} (float ${float} vs exact ${exact})`, tok({ genTime: `20260601123000.${f}Z` }), MAIN, DATA); }
}
for (const f of ['1', '01', '001', '0001', '9', '99', '999', '9999', '5', '25', '125', '0625', '00001']) await R3(`genTime fraction .${f}`, tok({ genTime: `20260601123000.${f}Z` }));
// OID encodings (oidText): a non-minimal arc and a dangling continuation byte are refused (0.5)
const rawOid = (b: number[]) => tlv(0x06, Buffer.from(b));
const imprintWithOid = (o: Buffer) => tok({ imprintAlg: seq(o) });
await R3('oid sha256 canonical (control)', imprintWithOid(oid(DIG.sha256!)));
await R3('oid sha256 non-minimal arc', imprintWithOid(rawOid([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x80, 0x01])));
await R3('oid sha256 dangling continuation', imprintWithOid(rawOid([...oidBytes(DIG.sha256!), 0x81])));
await R3('oid empty', imprintWithOid(rawOid([])));
await R3('oid only continuation', imprintWithOid(rawOid([0x81])));
await R3('oid first arc 2.100', imprintWithOid(oid('2.100.3')));
await R3('oid first byte 0x50 (2.0)', imprintWithOid(rawOid([0x50])));
await R3('oid first byte 0x28 (1.0)', imprintWithOid(rawOid([0x28])));
await R3('oid not tag 06', imprintWithOid(tlv(0x0d, oidBytes(DIG.sha256!))));
await R3('oid huge arc', imprintWithOid(rawOid([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f])));
// blind DER mutations of the token (tag byte, length byte +-1, truncation at each TLV start)
{
  const t = tok();
  const heads: number[] = [];
  const walk = (off: number, end: number, depth: number) => {
    while (off < end && heads.length < 400) {
      const tag = t[off]!; let l = t[off + 1]!; let body = off + 2;
      if (l & 0x80) { const n = l & 0x7f; l = 0; for (let i = 0; i < n; i++) l = l * 256 + t[body + i]!; body += n; }
      heads.push(off);
      if ((tag & 0x20) && depth < 12) walk(body, body + l, depth + 1);
      else if (tag === 0x04 && depth < 12 && t[body] === 0x30) walk(body, body + l, depth + 1);
      off = body + l;
    }
  };
  walk(0, t.length, 0);
  for (const h of heads) {
    const m = (f: (b: Buffer) => Buffer, n: string) => { const b = Buffer.from(t); return R3(`der @${h} ${n}`, f(b)); };
    await m((b) => { b[h] = b[h]! ^ 0x01; return b; }, 'tag^1');
    await m((b) => { b[h] = 0x1f; return b; }, 'tag 1f');
    await m((b) => { b[h + 1] = (b[h + 1]! + 1) & 0xff; return b; }, 'len+1');
    await m((b) => { b[h + 1] = (b[h + 1]! - 1) & 0xff; return b; }, 'len-1');
    await m((b) => { b[h + 1] = 0x80; return b; }, 'len 80');
    await m((b) => { b[h + 1] = 0x85; return b; }, 'len 85');
    await m((b) => b.subarray(0, h), 'cut');
  }
}

// ---- dssePae direct
for (const [t, p] of [[PT, '{}'], ['', ''], ['é', 'x'], [PT, '\u0000ÿ'], ['a b', ' ']] as const)
  await O.run('dssePae', `${JSON.stringify(t)} ${JSON.stringify(p)}`, (tt: string, pp: string) => S.dssePae(tt, new Uint8Array(Buffer.from(pp, 'base64'))), [t, b64(Buffer.from(p, 'latin1'))]);

// ---- blind DER mutations of the leaf certificate (inside a valid bundle)
{
  const der = leafCert();
  const heads: number[] = [];
  const walk = (off: number, end: number, depth: number) => {
    while (off < end && heads.length < 300) {
      const tag = der[off]!; let l = der[off + 1]!; let body = off + 2;
      if (l & 0x80) { const n = l & 0x7f; l = 0; for (let i = 0; i < n; i++) l = l * 256 + der[body + i]!; body += n; }
      heads.push(off);
      if ((tag & 0x20) && depth < 10) walk(body, body + l, depth + 1);
      else if (tag === 0x04 && depth < 10 && (der[body] === 0x30 || der[body] === 0x0c || der[body] === 0x04)) walk(body, body + l, depth + 1);
      off = body + l;
    }
  };
  walk(0, der.length, 0);
  for (const h of heads) for (const [n, f] of [
    ['tag^1', (b: Buffer) => { b[h] = b[h]! ^ 1; return b; }], ['len+1', (b: Buffer) => { b[h + 1] = (b[h + 1]! + 1) & 0xff; return b; }],
    ['len-1', (b: Buffer) => { b[h + 1] = (b[h + 1]! - 1) & 0xff; return b; }], ['cut', (b: Buffer) => b.subarray(0, Math.max(h, 1))],
  ] as const) await core(`der/leaf @${h} ${n}`, bundle({ leafDer: (f as any)(Buffer.from(der)) }));
}

// ---- the published vectors (real bundles + roots), replayed and structurally mutated
const VEC = JSON.parse(readFileSync(ROOT + 'packages/pca/conformance/sigstore-vectors.json', 'utf8'));
for (const [id, j] of Object.entries(VEC.roots)) await root(`vec/${id}`, j);
for (const c of VEC.cases) { await core(`vec/${c.name}`, c.bundle, { $root: `vec/${c.roots}` }, c.expect.ok ? null : c.expect.code); await full(`vec/${c.name}`, c.bundle, { $root: `vec/${c.roots}` }); }
// lib.mjs variants() over one synthetic bundle of each kind (full HOSTILE palette) and three real bundles (short palette)
const SHORT = [null, 0, -0, 1.5, '', 'x', '\ud800', [], {}, true];
const seeds: Array<[string, any, { $root: string }, unknown[]]> = [
  ['syn-dsse', bundle(), MAIN, HOSTILE], ['syn-intoto', bundle({ kind: 'intoto' }), MAIN, HOSTILE], ['syn-hashedrekord', bundle({ kind: 'hashedrekord' }), MAIN, HOSTILE],
  ...['npm/sigstore-5.0.0', 'conformance/rekor2-dsse-happy-path', 'conformance/intoto-with-custom-trust-root'].map((n) => { const c = VEC.cases.find((x: any) => x.name === n); return [`real-${n}`, c.bundle, { $root: `vec/${c.roots}` }, SHORT] as [string, any, { $root: string }, unknown[]]; }),
];
for (const [sn, sb, sr, pal] of seeds) for (const [lbl, v] of variants(sb, { hostile: pal, depth: 7 })) await core(`var/${sn} ${lbl}`, v, sr);
// variants of the synthetic root (parse only)
for (const [lbl, v] of variants(BASE_ROOT, { hostile: SHORT, depth: 5 })) await root(`var/${lbl}`, v);

// ---- self-check: every case that named its intended outcome got it (a miss is a generator bug or a reference finding)
const missed = want.filter(([, w, g]) => w !== g);
for (const [n, w, g] of missed) console.log(`  INTENT MISMATCH ${n}: wanted ${w ?? 'ok'}, reference gave ${g ?? 'ok'}`);
console.log(`intent checks: ${want.length - missed.length}/${want.length}; float-fraction cases: ${fracSuspect}`);
O.write();
