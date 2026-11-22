// Shared helpers of the attestation-root oracles (attest-puf, attest-allowlist, attest-maa, attest-pq-software, attest-nvidia).
// Public evidence only: fixtures are read from packages/pca/fixtures, keys derive from seed(label) and never reach a corpus (the strip tool
// rewrites every `seed` / `edSecret` member to its label).
// The labels here are composed at run time (label + '/ed', 'pq-software/' + alg), so the strip tool needs the labels the run really derived:
//   PCA_SEED_LOG=<dir>/<name>.txt tsx <generator>   then   PCA_SEED_LABELS=<dir> strip-corpus-keys.py --any out/ref-<name>.json.gz
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { seed } from './lib.mjs';

export const PKG = resolve(import.meta.dirname, '../../../packages/pca');
export const fx = (...p: string[]): Buffer => readFileSync(resolve(PKG, 'fixtures', ...p));
export const fxt = (...p: string[]): string => fx(...p).toString('utf8');
export const b64u = (u: Uint8Array | Buffer): string => Buffer.from(u).toString('base64url');
export const unb = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'base64url'));
export const B = (u: Uint8Array | Buffer) => ({ $bytes: b64u(u) });
/** the 43-char base64url of seed(label): what the strip tool turns into {"$seed": label} */
export const sd = (label: string): string => b64u(seed(label));
export const hex = (u: Uint8Array | Buffer): string => Buffer.from(u).toString('hex');

/** flip one bit of a byte array at `i` (a copy) */
export const flip = (u: Uint8Array, i: number, mask = 1): Uint8Array => {
  const c = Uint8Array.from(u);
  c[i] ^= mask;
  return c;
};
/** a copy of s with the character at i replaced by a different base64url / hex character */
export const chr = (s: string, i: number): string => s.slice(0, i) + (s[i] === 'A' ? 'B' : 'A') + s.slice(i + 1);

/** The shared verifier input: the reference's own binding argument (holder / grant / epoch / nonce). */
export const EXPECTED = { holderPub: 'holder-pub-oracle', grantRef: 'grant-oracle', epoch: 7, nonce: 'nonce-oracle-1' };
export const T0 = 1_800_000_000_000;

// ---- suite keys (generation-side only; a corpus carries the public keys, signatures and, for sign cases, the label-derived seed members) ----
const PQ: any = await import('../../../packages/pca/src/pq.ts');
const { publicKeyOf }: any = await import('../../../packages/pca/src/keys.ts');
/** A suite key set derived from seed labels. `spec` is what a corpus case carries for a SIGN case: {edSecret?, seed?} (32-byte label seeds; ML-DSA only). */
export function suiteKey(label: string, alg: string) {
  const s = PQ.SIG_SUITES[alg];
  const ed = seed(label + '/ed');
  const pqSeed = seed(label + '/pq');
  const wide = (n: number) => new Uint8Array(Buffer.concat([seed(label + '/pq/a'), seed(label + '/pq/b'), seed(label + '/pq/c')]).subarray(0, n));
  const secrets: any = {};
  const pub: any = {};
  if (s.hasEd25519) { secrets.edSecret = ed; pub.edPub = b64u(publicKeyOf(ed)); }
  if (s.hasMlDsa) { secrets.mlDsa = PQ.mlDsa65Keygen(pqSeed); pub.mlDsaPub = PQ.encodeMlDsaPublicKey(secrets.mlDsa.publicKey); }
  if (s.hasMlDsa87) { secrets.mlDsa87 = PQ.mlDsa87Keygen(pqSeed); pub.mlDsa87Pub = PQ.encodeMlDsa87PublicKey(secrets.mlDsa87.publicKey); }
  if (s.hasSlhDsa) { secrets.slhDsa = PQ.slhDsa128fKeygen(wide(48)); pub.slhDsaPub = PQ.encodeSlhDsaPublicKey(secrets.slhDsa.publicKey); }
  if (s.hasSlhDsa256s) { secrets.slhDsa256s = PQ.slhDsa256sKeygen(wide(96)); pub.slhDsa256sPub = PQ.encodeSlhDsa256sPublicKey(secrets.slhDsa256s.publicKey); }
  const nativeSignable = !s.hasSlhDsa && !s.hasSlhDsa256s && !s.hasFnDsa512 && !s.hasFnDsa1024 && !(s as any).hasLessCat1;
  const spec = nativeSignable ? { alg, ...(s.hasEd25519 ? { edSecret: b64u(ed) } : {}), ...(s.hasMlDsa || s.hasMlDsa87 ? { seed: b64u(pqSeed) } : {}) } : undefined;
  return { alg, secrets, pub, spec };
}
/** The reference-side secrets of a corpus `spec` (inverse of suiteKey().spec). */
export function secretsOfSpec(spec: any): any {
  const s = PQ.SIG_SUITES[spec.alg];
  const k: any = {};
  if (spec.edSecret) k.edSecret = unb(spec.edSecret);
  if (spec.seed && s.hasMlDsa) k.mlDsa = PQ.mlDsa65Keygen(unb(spec.seed));
  if (spec.seed && s.hasMlDsa87) k.mlDsa87 = PQ.mlDsa87Keygen(unb(spec.seed));
  return k;
}

// ---- corpus writer with a blob table (the real fixtures are large: a string longer than `minLen` characters becomes {"$blob": id} in args / out) ----
import fs from 'node:fs';
import zlib from 'node:zlib';
import { createHash } from 'node:crypto';
import { ser, Ref_OUT, assertNoGeneratorBugs, clockMember } from './lib.mjs';
/** Same as lib.mjs refWrite, plus a top-level "blobs" map {id: string}: every string over minLen characters is stored once there and replaced by {"$blob": id}. */
export function refWriteBlobs(o: any, pkg: string, minLen = 400) {
  assertNoGeneratorBugs(o);
  const blobs: Record<string, string> = {};
  const walk = (v: any): any => {
    if (typeof v === 'string' && v.length > minLen) {
      const id = 'b' + createHash('sha256').update(v).digest('hex').slice(0, 20);
      blobs[id] = v;
      return { $blob: id };
    }
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === 'object') return Object.fromEntries(Object.keys(v).map((k) => [k, walk(v[k])]));
    return v;
  };
  const cases = o.cases.map((c: any) => ser({ ...c, args: walk(JSON.parse(ser(c.args))), out: walk(JSON.parse(ser(c.out))) }));
  fs.mkdirSync(Ref_OUT, { recursive: true });
  const body = '{"about":' + JSON.stringify(o.about) + ',"generator":' + JSON.stringify(String(o.generator).split('/').pop()) + ',"count":' + o.cases.length + clockMember() + ',"blobs":' + JSON.stringify(blobs) + ',"cases":[\n' + cases.join(',\n') + '\n]}\n';
  if (process.env.ORACLE_SIZES) { const by: Record<string, number> = {}; for (const [i, c] of o.cases.entries()) by[c.fn] = (by[c.fn] ?? 0) + cases[i].length; console.log(by, Object.values(blobs).reduce((a: number, b: string) => a + b.length, 0)); const big = Object.entries(blobs).map(([k, v]) => [v.length, v.slice(0, 60)] as const).sort((a, b) => b[0] - a[0]); const hist: Record<string, number> = {}; for (const [l, h] of big) hist[h.slice(0, 20) + '/' + Math.round(l / 1000)] = (hist[h.slice(0, 20) + '/' + Math.round(l / 1000)] ?? 0) + 1; console.log(hist); }
  if (Buffer.byteLength(body) > 5 * 1024 * 1024) throw new Error('oracle over 5 MB uncompressed: trim the generated space (' + Buffer.byteLength(body) + ')');
  const file = Ref_OUT + `ref-${pkg}.json.gz`;
  fs.writeFileSync(file, zlib.gzipSync(Buffer.from(body, 'utf8'), { level: 9, mtime: 0 }));
  const byFn: Record<string, number> = {};
  for (const c of o.cases) byFn[c.fn] = (byFn[c.fn] ?? 0) + 1;
  console.log(`wrote ${o.cases.length} cases (${Object.keys(blobs).length} blobs, ${Buffer.byteLength(body)} bytes) to ${file}\n  by fn: ` + Object.entries(byFn).map(([k, v]) => `${k}=${v}`).join(' '));
}
