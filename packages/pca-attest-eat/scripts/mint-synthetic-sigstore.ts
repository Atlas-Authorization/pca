// Mints test-fixtures/sigstore/synthetic/: a private test trust root (a Fulcio-like root and intermediate CA, a CT log key,
// a Rekor-v1-like log key, a timestamp authority) and DSSE bundles in which EVERY check passes except exactly one:
//
//   valid.json               control: everything verifies (SET and RFC 3161 time, SCT, inclusion, checkpoint, signature)
//   bad-dsse-signature.json  the DSSE signature is made by another key; the log entry names that very signature and the
//                            leaf certificate, so only the signature check over PAE can refuse it
//   bad-sct.json             the embedded SCT is signed by the pinned CT log key over another timestamp than it states;
//                            the certificate itself is correctly signed around it, so only the SCT check can refuse it
//   aki-mismatch.json        the leaf's Authority Key Identifier is not the intermediate's Subject Key Identifier, while the
//                            issuer name and the signature are right, so only the key-identifier comparison refuses it
//
// ECDSA signatures are randomised, so this runs ONCE and its output is committed (the vector generator only reads it).
// No private key is written anywhere. Run: packages/pca/node_modules/.bin/tsx packages/pca-attest-eat/scripts/mint-synthetic-sigstore.ts
import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const OUT = join(typeof __dirname === 'string' ? __dirname : import.meta.dirname, '..', 'test-fixtures', 'sigstore', 'synthetic');
const ec = () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const spki = (k: KeyObject) => k.export({ type: 'spki', format: 'der' }) as Buffer;
const sha256 = (...b: Uint8Array[]) => { const h = createHash('sha256'); for (const x of b) h.update(x); return h.digest(); };

// ---- DER
const len = (n: number) => (n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : n < 0x10000 ? [0x82, n >> 8, n & 0xff] : [0x83, n >> 16, (n >> 8) & 0xff, n & 0xff]);
const tlv = (tag: number, ...c: Uint8Array[]) => { const b = Buffer.concat(c); return Buffer.concat([Buffer.from([tag, ...len(b.length)]), b]); };
const seq = (...c: Uint8Array[]) => tlv(0x30, ...c);
const set = (...c: Uint8Array[]) => tlv(0x31, ...c);
const oid = (s: string) => {
  const p = s.split('.').map(Number);
  const out = [40 * p[0]! + p[1]!];
  for (const v of p.slice(2)) { const st: number[] = []; let x = v; do { st.unshift(x & 0x7f); x = Math.floor(x / 128); } while (x > 0); for (let i = 0; i < st.length - 1; i++) st[i]! |= 0x80; out.push(...st); }
  return tlv(0x06, Buffer.from(out));
};
const int = (n: number | Buffer) => { let b = typeof n === 'number' ? Buffer.from([n]) : n; if (b[0]! & 0x80) b = Buffer.concat([Buffer.from([0]), b]); return tlv(0x02, b); };
const octet = (b: Uint8Array) => tlv(0x04, b);
const utf8 = (s: string) => tlv(0x0c, Buffer.from(s, 'utf8'));
const bool = () => tlv(0x01, Buffer.from([0xff]));
const bits = (b: Uint8Array, unused = 0) => tlv(0x03, Buffer.from([unused]), b);
const utc = (d: Date) => tlv(0x17, Buffer.from(d.toISOString().replace(/[-:T]/g, '').slice(2, 14) + 'Z'));
const gen = (d: Date) => tlv(0x18, Buffer.from(d.toISOString().replace(/[-:T]/g, '').slice(0, 14) + 'Z'));
const name = (cn: string) => seq(set(seq(oid('2.5.4.10'), utf8('pca-synthetic'))), set(seq(oid('2.5.4.3'), utf8(cn))));
const ECDSA_SHA256 = seq(oid('1.2.840.10045.4.3.2'));
const ext = (o: string, value: Uint8Array, critical = false) => seq(oid(o), ...(critical ? [bool()] : []), octet(value));
const ski = (k: KeyObject) => sha256(spki(k)).subarray(0, 20);

interface CertArgs { serial: number; issuer: Buffer; subject: Buffer; key: KeyObject; from: Date; to: Date; exts: Buffer[] }
const tbsOf = (a: CertArgs) => seq(tlv(0xa0, int(2)), int(a.serial), ECDSA_SHA256, a.issuer, seq(utc(a.from), utc(a.to)), a.subject, spki(a.key), tlv(0xa3, seq(...a.exts)));
const certOf = (tbs: Buffer, signer: KeyObject) => seq(tbs, ECDSA_SHA256, bits(sign('sha256', tbs, signer)));

// ---- the PKI
const T = new Date('2026-06-01T12:00:00Z');
const rootK = ec(), interK = ec(), ctK = ec(), logK = ec(), tsaK = ec();
const ROOT_NAME = name('pca-synthetic-root'), INTER_NAME = name('pca-synthetic-intermediate'), TSA_NAME = name('pca-synthetic-tsa');
const caExts = (k: KeyObject, issuerKey: KeyObject) => [
  ext('2.5.29.19', seq(bool()), true),
  ext('2.5.29.15', bits(Buffer.from([0x06]), 1), true),
  ext('2.5.29.14', octet(ski(k))),
  ext('2.5.29.35', seq(tlv(0x80, ski(issuerKey)))),
];
const FROM = new Date('2025-01-01T00:00:00Z'), TO = new Date('2035-01-01T00:00:00Z');
const root = certOf(tbsOf({ serial: 1, issuer: ROOT_NAME, subject: ROOT_NAME, key: rootK.publicKey, from: FROM, to: TO, exts: caExts(rootK.publicKey, rootK.publicKey) }), rootK.privateKey);
const inter = certOf(tbsOf({ serial: 2, issuer: ROOT_NAME, subject: INTER_NAME, key: interK.publicKey, from: FROM, to: TO, exts: caExts(interK.publicKey, rootK.publicKey) }), rootK.privateKey);
const tsa = certOf(tbsOf({ serial: 3, issuer: ROOT_NAME, subject: TSA_NAME, key: tsaK.publicKey, from: FROM, to: TO, exts: [
  ext('2.5.29.15', bits(Buffer.from([0x80]), 7), true),
  ext('2.5.29.37', seq(oid('1.3.6.1.5.5.7.3.8')), true),
  ext('2.5.29.14', octet(ski(tsaK.publicKey))),
  ext('2.5.29.35', seq(tlv(0x80, ski(rootK.publicKey)))),
] }), rootK.privateKey);
const ctLogId = sha256(spki(ctK.publicKey));
const logId = sha256(spki(logK.publicKey));

// ---- a Fulcio-like leaf with an embedded SCT over its precertificate
const REPO = 'https://github.com/pca-synthetic/tool';
function leafCert(key: KeyObject, o: { badSct?: boolean; aki?: Buffer } = {}): Buffer {
  const base = (sct?: Buffer) => [
    ext('2.5.29.15', bits(Buffer.from([0x80]), 7), true),
    ext('2.5.29.37', seq(oid('1.3.6.1.5.5.7.3.3'))),
    ext('2.5.29.14', octet(ski(key))),
    ext('2.5.29.35', seq(tlv(0x80, o.aki ?? ski(interK.publicKey)))),
    ext('2.5.29.17', seq(tlv(0x86, Buffer.from(`${REPO}/.github/workflows/release.yml@refs/tags/v1.0.0`))), true),
    ext('1.3.6.1.4.1.57264.1.8', utf8('https://token.actions.githubusercontent.com')),
    ext('1.3.6.1.4.1.57264.1.12', utf8(REPO)),
    ext('1.3.6.1.4.1.57264.1.13', utf8('a'.repeat(40))),
    ext('1.3.6.1.4.1.57264.1.14', utf8('refs/tags/v1.0.0')),
    ...(sct ? [ext('1.3.6.1.4.1.11129.2.4.2', octet(sct))] : []),
  ];
  const args = { serial: 100, issuer: INTER_NAME, subject: seq(), key, from: new Date(T.getTime() - 60_000), to: new Date(T.getTime() + 600_000) };
  const pre = tbsOf({ ...args, exts: base() });
  const ts = BigInt(T.getTime() - 30_000);
  const signed = (t: bigint) => {
    const head = Buffer.alloc(12);
    head.writeBigUInt64BE(t, 2);
    head.writeUInt16BE(1, 10);
    return Buffer.concat([head, sha256(spki(interK.publicKey)), Buffer.from([pre.length >> 16, (pre.length >> 8) & 0xff, pre.length & 0xff]), pre, Buffer.from([0, 0])]);
  };
  const sig = sign('sha256', signed(o.badSct ? ts + 1n : ts), ctK.privateKey);
  const tsB = Buffer.alloc(8);
  tsB.writeBigUInt64BE(ts);
  const sct = Buffer.concat([Buffer.from([0]), ctLogId, tsB, Buffer.from([0, 0, 4, 3, sig.length >> 8, sig.length & 0xff]), sig]);
  const list = Buffer.concat([Buffer.from([sct.length >> 8, sct.length & 0xff]), sct]);
  return certOf(tbsOf({ ...args, exts: base(Buffer.concat([Buffer.from([list.length >> 8, list.length & 0xff]), list])) }), interK.privateKey);
}

// ---- an RFC 3161 token over the signature bytes
function tsaToken(sigBytes: Buffer): Buffer {
  const SHA256 = seq(oid('2.16.840.1.101.3.4.2.1'));
  const tst = seq(int(1), oid('1.3.6.1.4.1.57264.99.1'), seq(SHA256, octet(sha256(sigBytes))), int(randomBytes(8)), gen(new Date(T.getTime() + 30_000)));
  const attrs = [seq(oid('1.2.840.113549.1.9.3'), set(oid('1.2.840.113549.1.9.16.1.4'))), seq(oid('1.2.840.113549.1.9.4'), set(octet(sha256(tst))))];
  const signedAttrs = set(...attrs);
  const si = seq(int(1), seq(ROOT_NAME, int(3)), SHA256, tlv(0xa0, ...attrs), ECDSA_SHA256, octet(sign('sha256', signedAttrs, tsaK.privateKey)));
  const sd = seq(int(3), set(SHA256), seq(oid('1.2.840.113549.1.9.16.1.4'), tlv(0xa0, octet(tst))), set(si));
  return seq(seq(int(0)), seq(oid('1.2.840.113549.1.7.2'), tlv(0xa0, sd)));
}

// ---- a DSSE bundle logged in the synthetic Rekor v1 log
const PAYLOAD = Buffer.from(JSON.stringify({
  _type: 'https://in-toto.io/Statement/v1',
  subject: [{ name: 'tool.tar', digest: { sha256: sha256(Buffer.from('pca synthetic artifact')).toString('hex') } }],
  predicateType: 'https://slsa.dev/provenance/v1',
  predicate: { buildDefinition: { buildType: 'https://actions.github.io/buildtypes/workflow/v1', externalParameters: { workflow: { ref: 'refs/tags/v1.0.0', repository: REPO, path: '.github/workflows/release.yml' } }, resolvedDependencies: [{ uri: `git+${REPO}@refs/tags/v1.0.0`, digest: { gitCommit: 'a'.repeat(40) } }] }, runDetails: { builder: { id: 'https://github.com/actions/runner/github-hosted' } } },
}));
const PT = 'application/vnd.in-toto+json';
const pae = Buffer.concat([Buffer.from(`DSSEv1 ${PT.length} ${PT} ${PAYLOAD.length} `), PAYLOAD]);
const pem = (der: Buffer) => `-----BEGIN CERTIFICATE-----\n${der.toString('base64').match(/.{1,64}/g)!.join('\n')}\n-----END CERTIFICATE-----\n`;

function bundle(leaf: Buffer, sig: Buffer) {
  const body = Buffer.from(JSON.stringify({ apiVersion: '0.0.1', kind: 'dsse', spec: { envelopeHash: { algorithm: 'sha256', value: sha256(Buffer.from('envelope')).toString('hex') }, payloadHash: { algorithm: 'sha256', value: sha256(PAYLOAD).toString('hex') }, signatures: [{ signature: sig.toString('base64'), verifier: Buffer.from(pem(leaf)).toString('base64') }] } }));
  const bodyB64 = body.toString('base64');
  const integrated = Math.floor(T.getTime() / 1000) + 60;
  const set_ = sign('sha256', Buffer.from(`{"body":${JSON.stringify(bodyB64)},"integratedTime":${integrated},"logID":"${logId.toString('hex')}","logIndex":0}`), logK.privateKey);
  const rootHash = sha256(Buffer.from([0]), body);
  const note = `synthetic.log - 1\n1\n${rootHash.toString('base64')}\n`;
  const cpSig = Buffer.concat([logId.subarray(0, 4), sign('sha256', Buffer.from(note), logK.privateKey)]);
  return {
    mediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json',
    verificationMaterial: {
      certificate: { rawBytes: leaf.toString('base64') },
      tlogEntries: [{
        logIndex: '0', logId: { keyId: logId.toString('base64') }, kindVersion: { kind: 'dsse', version: '0.0.1' }, integratedTime: String(integrated),
        inclusionPromise: { signedEntryTimestamp: set_.toString('base64') },
        inclusionProof: { logIndex: '0', rootHash: rootHash.toString('base64'), treeSize: '1', hashes: [], checkpoint: { envelope: `${note}\n— synthetic.log ${cpSig.toString('base64')}\n` } },
        canonicalizedBody: bodyB64,
      }],
      timestampVerificationData: { rfc3161Timestamps: [{ signedTimestamp: tsaToken(sig).toString('base64') }] },
    },
    dsseEnvelope: { payload: PAYLOAD.toString('base64'), payloadType: PT, signatures: [{ sig: sig.toString('base64'), keyid: '' }] },
  };
}

const leafK = ec();
const good = leafCert(leafK.publicKey);
const goodSig = sign('sha256', pae, leafK.privateKey);
const out: Record<string, unknown> = {
  'valid.json': bundle(good, goodSig),
  'bad-dsse-signature.json': bundle(good, sign('sha256', pae, ec().privateKey)),
  'bad-sct.json': bundle(leafCert(leafK.publicKey, { badSct: true }), goodSig),
  'aki-mismatch.json': bundle(leafCert(leafK.publicKey, { aki: randomBytes(20) }), goodSig),
};
const key = (k: KeyObject) => ({ rawBytes: spki(k).toString('base64'), keyDetails: 'PKIX_ECDSA_P256_SHA_256', validFor: { start: FROM.toISOString() } });
out['trusted_root.json'] = {
  mediaType: 'application/vnd.dev.sigstore.trustedroot+json;version=0.1',
  tlogs: [{ baseUrl: 'https://synthetic.log', hashAlgorithm: 'SHA2_256', publicKey: key(logK.publicKey), logId: { keyId: logId.toString('base64') } }],
  certificateAuthorities: [{ subject: { organization: 'pca-synthetic', commonName: 'pca-synthetic-intermediate' }, uri: 'https://synthetic.ca', certChain: { certificates: [{ rawBytes: inter.toString('base64') }, { rawBytes: root.toString('base64') }] }, validFor: { start: FROM.toISOString() } }],
  ctlogs: [{ baseUrl: 'https://synthetic.ct', hashAlgorithm: 'SHA2_256', publicKey: key(ctK.publicKey), logId: { keyId: ctLogId.toString('base64') } }],
  timestampAuthorities: [{ subject: { organization: 'pca-synthetic', commonName: 'pca-synthetic-tsa' }, uri: 'https://synthetic.tsa', certChain: { certificates: [{ rawBytes: tsa.toString('base64') }, { rawBytes: root.toString('base64') }] }, validFor: { start: FROM.toISOString() } }],
};
mkdirSync(OUT, { recursive: true });
for (const [f, v] of Object.entries(out)) writeFileSync(join(OUT, f), `${JSON.stringify(v, null, 1)}\n`);
console.log(`wrote ${Object.keys(out).length} files to ${OUT}`);
