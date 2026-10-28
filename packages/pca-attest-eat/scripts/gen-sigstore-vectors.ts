// packages/pca/conformance/sigstore-vectors.json: offline Sigstore bundle verification (track K9).
//
// ONE generator owns the file. Inputs are real bundles only: the committed sigstore-conformance bundle-verify fixtures
// (DSSE cases; Rekor v1 dsse/intoto, Rekor v2 hashedrekord, RFC 3161 timestamps) and the public npm provenance bundle,
// plus mutations of the passing ones. Every `expect` is computed by the TypeScript reference (verifySigstoreBundleCore)
// and asserted against the outcome the case is meant to show (`want`: the conformance suite's `_fail` suffix, or the
// mutation's intent). The native verifiers replay it: they must reproduce `ok`, and on ok the whole `core`
// (identity, issuer, source, predicate type, subjects, signed time, log index, Rekor version, time sources). `code` is
// the reference's refusal reason, informative for natives (their libraries word refusals differently).
//
//   roots: { <id>: trusted_root.json }        cases: { name, description, roots, bundle, expect }
//
//     packages/pca/node_modules/.bin/tsx packages/pca-attest-eat/scripts/gen-sigstore-vectors.ts [--check]
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseTrustedRoot, verifySigstoreBundleCore } from '../src/sigstore';

const FIX = join(__dirname, '..', 'test-fixtures', 'sigstore');
const OUT = join(__dirname, '..', '..', 'pca', 'conformance', 'sigstore-vectors.json');
const read = (p: string) => JSON.parse(readFileSync(p, 'utf8'));
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const roots: Record<string, unknown> = {};
const rootId = (json: unknown, hint: string): string => {
  const h = createHash('sha256').update(JSON.stringify(json)).digest('hex').slice(0, 8);
  const id = `${hint}-${h}`;
  roots[id] = json;
  return id;
};
const PUBLIC_GOOD = rootId(read(join(FIX, 'trusted_root.json')), 'public-good');
const cases: unknown[] = [];
function c(name: string, description: string, rid: string, bundle: unknown, want: boolean) {
  const r = verifySigstoreBundleCore(bundle, { roots: parseTrustedRoot(roots[rid]) });
  if (r.ok !== want) throw new Error(`${name}: reference ${r.ok ? 'accepts' : `refuses (${r.code}: ${r.detail})`}, wanted ${want}`);
  cases.push({ name, description, roots: rid, bundle, expect: r.ok ? { ok: true, core: r.core } : { ok: false, code: r.code } });
}
const flip = (s: string, at: number) => {
  const b = Buffer.from(s, 'base64');
  b[at] = b[at]! ^ 1;
  return b.toString('base64');
};

// ---- the sigstore-conformance DSSE cases, as published
const conf: Record<string, { rid: string; bundle: any }> = {};
for (const d of readdirSync(join(FIX, 'conformance')).sort()) {
  const dir = join(FIX, 'conformance', d);
  const rid = existsSync(join(dir, 'trusted_root.json')) ? rootId(read(join(dir, 'trusted_root.json')), d.startsWith('rekor2') ? 'staging' : 'custom') : PUBLIC_GOOD;
  const bundle = read(join(dir, 'bundle.sigstore.json'));
  conf[d] = { rid, bundle };
  c(`conformance/${d}`, `sigstore-conformance bundle-verify/${d}`, rid, bundle, !d.endsWith('_fail'));
}

// ---- the npm provenance bundle (Rekor v1 dsse, SET time, public-good root)
const npm = read(join(FIX, 'npm-sigstore-5.0.0.attestations.json')).attestations.find((a: any) => a.predicateType === 'https://slsa.dev/provenance/v1').bundle;
c('npm/sigstore-5.0.0', 'npm provenance of sigstore@5.0.0: Rekor v1 dsse entry, SET time, public-good root', PUBLIC_GOOD, npm, true);
{
  const b = clone(npm);
  delete b.verificationMaterial.tlogEntries[0].inclusionPromise;
  c('npm/no-set-no-tsa', 'no SET and no RFC 3161 timestamp: no verified time', PUBLIC_GOOD, b, false);
}
{
  const b = clone(npm);
  b.verificationMaterial.tlogEntries[0].inclusionProof.checkpoint.envelope = b.verificationMaterial.tlogEntries[0].inclusionProof.checkpoint.envelope.replace(/\n(\d+)\n/, (_m: string, n: string) => `\n${Number(n) + 1}\n`);
  c('npm/checkpoint-size', 'checkpoint size differs from the proof', PUBLIC_GOOD, b, false);
}

// ---- Rekor v2 + RFC 3161 mutations
const r2 = conf['rekor2-dsse-happy-path']!;
const env = (b: any) => b.verificationMaterial.tlogEntries[0].inclusionProof.checkpoint;
{
  const b = clone(r2.bundle);
  env(b).envelope = env(b).envelope.split('\n').filter((l: string) => !l.startsWith('— log2025-alpha3')).join('\n');
  c('rekor2/checkpoint-witness-only', 'only witness co-signatures, no signature by the log', r2.rid, b, false);
}
{
  const b = clone(r2.bundle);
  const lines = env(b).envelope.split('\n');
  const body = lines.slice(0, 3);
  const sigs = lines.slice(4).filter((l: string) => l.length > 0).reverse();
  env(b).envelope = [...body, '', ...sigs, ''].join('\n');
  c('rekor2/checkpoint-log-signature-last', 'the log signature after the witness co-signatures', r2.rid, b, true);
}
{
  const b = clone(r2.bundle);
  env(b).envelope = env(b).envelope.replace(/^[^\n]+\n/, '\n');
  c('rekor2/checkpoint-no-origin', 'an empty origin line', r2.rid, b, false);
}
{
  const b = clone(r2.bundle);
  env(b).envelope = env(b).envelope.replace(/(— log2025-alpha3\S* )(\S+)/, (_m: string, a: string, s: string) => a + flip(s, 20));
  c('rekor2/checkpoint-log-signature-flipped', 'the log signature with one bit flipped', r2.rid, b, false);
}
{
  const b = clone(r2.bundle);
  b.verificationMaterial.timestampVerificationData = { rfc3161Timestamps: [] };
  c('rekor2/no-timestamp', 'Rekor v2 has no SET: without an RFC 3161 timestamp there is no verified time', r2.rid, b, false);
}
{
  const b = clone(r2.bundle);
  const ts = b.verificationMaterial.timestampVerificationData.rfc3161Timestamps[0];
  ts.signedTimestamp = flip(ts.signedTimestamp, Buffer.from(ts.signedTimestamp, 'base64').length - 10);
  c('rekor2/timestamp-signature-flipped', 'the timestamp authority signature with one bit flipped', r2.rid, b, false);
}
{
  // the TSTInfo serial number changed: messageImprint and the TSA signature over the (unchanged) signed attributes still
  // verify, only the signed messageDigest attribute no longer matches the content
  const b = clone(r2.bundle);
  const ts = b.verificationMaterial.timestampVerificationData.rfc3161Timestamps[0];
  const tok = Buffer.from(ts.signedTimestamp, 'base64');
  const oid = Buffer.from('060b2a864886f70d0109100104', 'hex');
  let i = tok.indexOf(oid) + oid.length; // [0] { OCTET STRING { TSTInfo } }
  const skip = (at: number) => { const l = tok[at + 1]!; return at + 2 + (l & 0x80 ? l & 0x7f : 0); }; // past tag+length
  const len = (at: number) => { const l = tok[at + 1]!; if (!(l & 0x80)) return l; let n = 0; for (let k = 0; k < (l & 0x7f); k++) n = n * 256 + tok[at + 2 + k]!; return n; };
  i = skip(i); i = skip(i); i = skip(i); // [0], OCTET STRING, TSTInfo SEQUENCE: now at version
  for (let k = 0; k < 3; k++) i = skip(i) + len(i); // version, policy, messageImprint
  if (tok[i] !== 0x02) throw new Error('serial number not found');
  tok[skip(i)]! ^= 1;
  ts.signedTimestamp = tok.toString('base64');
  c('rekor2/timestamp-content-changed', 'the TSTInfo changed under unchanged signed attributes: the messageDigest attribute no longer matches', r2.rid, b, false);
}
{
  const b = clone(r2.bundle);
  const ts = b.verificationMaterial.timestampVerificationData.rfc3161Timestamps[0];
  b.verificationMaterial.timestampVerificationData.rfc3161Timestamps = [ts, ts];
  c('rekor2/two-timestamps', 'two (identical) verified timestamps', r2.rid, b, true);
}
{
  const root = clone(roots[r2.rid] as any);
  root.timestampAuthorities = [];
  c('rekor2/no-pinned-tsa', 'the trusted root pins no timestamp authority', rootId(root, 'staging-no-tsa'), r2.bundle, false);
}
{
  const root = clone(roots[r2.rid] as any);
  for (const t of root.timestampAuthorities) t.validFor = { start: t.validFor.start, end: '2025-05-01T00:00:00Z' };
  c('rekor2/tsa-pin-expired', 'the timestamp authority pin ended before the timestamp', rootId(root, 'staging-tsa-ended'), r2.bundle, false);
}
{
  const root = clone(roots[r2.rid] as any);
  root.tlogs = root.tlogs.filter((t: any) => !String(t.baseUrl).includes('alpha3'));
  c('rekor2/log-not-pinned', 'the Rekor v2 log is not in the trusted root', rootId(root, 'staging-no-alpha3'), r2.bundle, false);
}
{
  const b = clone(r2.bundle);
  b.verificationMaterial.tlogEntries[0].inclusionProof.hashes[0] = flip(b.verificationMaterial.tlogEntries[0].inclusionProof.hashes[0], 0);
  c('rekor2/inclusion-hash-flipped', 'a broken inclusion proof', r2.rid, b, false);
}
const tsaV1 = conf['intoto-with-custom-trust-root']!;
{
  const b = clone(tsaV1.bundle);
  delete b.verificationMaterial.tlogEntries[0].inclusionPromise;
  c('intoto/tsa-only', 'Rekor v1 intoto entry with only the RFC 3161 timestamp as time source', tsaV1.rid, b, true);
}
{
  const b = clone(tsaV1.bundle);
  b.verificationMaterial.timestampVerificationData = { rfc3161Timestamps: [] };
  c('intoto/set-only', 'the same entry with only the SET as time source', tsaV1.rid, b, true);
}

// ---- synthetic PKI (scripts/mint-synthetic-sigstore.ts): every check passes except exactly the one named
{
  const S = join(FIX, 'synthetic');
  const rid = rootId(read(join(S, 'trusted_root.json')), 'synthetic');
  const only = (name: string, file: string, code: string | null, description: string) => {
    c(`synthetic/${name}`, description, rid, read(join(S, file)), code === null);
    const got = (cases[cases.length - 1] as { expect: { code?: string } }).expect.code;
    if (code !== null && got !== code) throw new Error(`synthetic/${name}: refused at ${got}, meant to fail only ${code}`);
  };
  only('valid', 'valid.json', null, 'synthetic control: SET and RFC 3161 time, SCT, inclusion, checkpoint and DSSE signature all verify');
  only('bad-dsse-signature-only', 'bad-dsse-signature.json', 'signature', 'only the DSSE signature over PAE is wrong (the log entry names that signature and the right certificate)');
  only('bad-sct-only', 'bad-sct.json', 'sct', 'only the embedded SCT is wrong (signed by the pinned CT key over another timestamp; the certificate is correctly signed)');
  only('aki-mismatch-only', 'aki-mismatch.json', 'cert_chain', "only the leaf's Authority Key Identifier differs from the intermediate's Subject Key Identifier (issuer name and signature are right)");
}

const doc = { format: 'pca-sigstore-vectors', ver: 1, description: 'Generated by packages/pca-attest-eat/scripts/gen-sigstore-vectors.ts from the TypeScript reference (sigstore.ts); do not edit. Natives must reproduce expect.ok and, on ok, expect.core exactly; expect.code is the reference reason.', roots, cases };
const text = `${JSON.stringify(doc)}\n`;
if (process.argv.includes('--check')) {
  if (readFileSync(OUT, 'utf8') !== text) { console.error(`${OUT} is stale: regenerate it`); process.exit(1); }
  console.log(`${OUT} is current`);
} else {
  writeFileSync(OUT, text);
  console.log(`wrote ${OUT}: ${cases.length} cases, ${Object.keys(roots).length} roots, ${text.length} bytes`);
}
