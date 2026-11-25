// Oracle: @atlasauth/pca-scitt (SCITT Signed Statements and COSE Receipts, RFC 9943 / RFC 9942; the deterministic CBOR codec; the RFC 9162 Merkle
// tree; the in-memory and durable transparency services; the file-backed log store). Deterministic: Ed25519 signs deterministically, keys come
// from seeds. ES256 (ECDSA) is randomized, so ES256 material is VERIFY-ONLY: the vectors carry JS-signed statements/receipts (a regeneration
// produces different but equally valid bytes) and the sign-side ES256 cases compare verification outcomes, not signature bytes.
// Writes out/ref-scitt.json.gz.
//
// PORTING (fn(args) -> native entry point, comparison rule). Values are JSON; bytes are {"$bytes": b64url}; a throw only requires the native to refuse
// (an error code is compared when the case names one).
// CBOR values in the corpus ("cj"): ints/strings/bools/null as JSON, {"$bytes"} = bstr, {"$map": [[key, value], ...]} = a map (key int or text, in the
// listed order), {"$tag": n, "v": value} = a tagged value, arrays = arrays; a JSON non-integer is a float (the codec must refuse it).
//   cborEncode(cj)                         -> Cbor.encode(model) bytes
//   cborDecode(bytes)                      -> Cbor.decode(bytes) re-expressed as cj (a decoded map lists its entries in wire order)
//   emptyRoot() / leafHash(entry) / nodeHash(l, r) / treeHash(leafHashes) / inclusionPath(leafHashes, index) / rootFromInclusionPath(leaf, index, size, path)
//     / verifyInclusionPath(leaf, index, size, path, root) / consistencyPath(leafHashes, m) / verifyConsistencyPath(first, second, r1, r2, path)
//                                          -> Rfc9162.* (bytes, lists of bytes, null, booleans). A non-integer / unsafe index or size is the reference's
//                                             "invalid" answer: rootFromInclusionPath -> null, verify* -> false, inclusionPath/consistencyPath -> throw.
//   siblingSides(index, size)              -> Scitt.siblingSides
//   encodeInclusionProof(proof) / decodeInclusionProof(bytes) -> Scitt.* (proof = {index, size, path: [{side, hash}]})
//   signStatement(payload, opts)           -> Scitt.signStatement, opts.key = {alg: "EdDSA", seed}; bytes compared exactly
//   decodeCoseSign1(bytes)                 -> Scitt.decodeCoseSign1 as {protectedBytes, protectedMap: cj, unprotected: cj, payload|null, signature}
//   checkStatement(statement, pubKey[, opts]) / verifyStatement / statementPayload / statementLeaf
//                                          -> Scitt.*; pubKey = {alg: "EdDSA", pub} | {alg: "ES256", x, y}; checkStatement is {ok, reason?}
//   buildReceipt(root, proof, signer)      -> Scitt.buildReceipt, signer = {alg: "EdDSA", key: {seed}, issuer?}; bytes compared exactly
//   verifyReceipt(receipt, statement, opts) -> Scitt.verifyReceipt, opts = {treeRoot?, verificationKey?: pubKey, statementKey?: pubKey, allowHighS?}
//   verifyConsistencyProof(proof, oldRoot, newRoot) -> Scitt.verifyConsistencyProof
//   es256SignVerify(key, payload, issuer)  -> sign a statement with the ES256 private key {alg, d, x, y}; out {check, payload, lowS}
//   es256Receipt(key, n, index, edPriv, wrongPub) -> a TransparencyService signed by the ES256 key over n statements (each {i: k} signed by the Ed25519 edPriv,
//       issuer "iss"; the receipt issuer is "ts"); out = verification outcomes
//   service(spec)                          -> run spec.ops against TransparencyService ("memory") or DurableTransparencyService over MemoryScittLogStore
//       ("durable", with an optional storeFault) and compare the per-op results: [{ok: ...} | {err: code|true}]
//   fileStoreBytes(ops)                    -> append the ops through FileScittLogStore and return the file's bytes (the format is byte-identical)
//   fileStoreOpen(fileBytes)               -> open a (possibly torn / corrupt) file: {size, entries, nodes0} or a throw
//   checkScittLogStore(kind)               -> [] for the memory and file stores; kind = "memory" | "file"
//   constants()                            -> the exported numeric / string constants
import { createECDH, createHash, createPrivateKey, createPublicKey, sign as nodeSign } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as M0 from '../../../packages/pca-scitt/src/index.ts';
import * as T0 from '../../../packages/pca-scitt/src/testing.ts';
import * as R0 from '../../../packages/pca-scitt/src/rfc9162.ts';
import { Oracle, refWrite, rng, seed } from './lib.mjs';

const M: any = (M0 as any).default ?? M0;
const R: any = (R0 as any).default ?? R0;
const T: any = (T0 as any).default ?? T0;
const { MemoryScittLogStore, TransparencyService } = T;
const o = new Oracle('scitt', 'tools/pca-audit/oracles/scitt.mts', 'TS-reference oracle for SCITT receipts, the deterministic CBOR codec and the RFC 9162 tree.');
const b64u = (u: Uint8Array | Buffer) => Buffer.from(u).toString('base64url');
const bytes = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));
const B = (u: Uint8Array) => ({ $bytes: b64u(u) });
const hexb = (h: string) => new Uint8Array(Buffer.from(h.replace(/\s+/g, ''), 'hex'));
const isB = (x: any) => x && typeof x === 'object' && !Array.isArray(x) && typeof x.$bytes === 'string';
const un = (x: any) => (isB(x) ? bytes(x.$bytes) : x);

// ---- cj <-> CBOR model ----
const fromCj = (v: any): any => {
  if (v === null || typeof v !== 'object') return v;
  if (Array.isArray(v)) return v.map(fromCj);
  if (isB(v)) return bytes(v.$bytes);
  if (v.$map) return new Map(v.$map.map(([k, x]: any) => [k, fromCj(x)]));
  if ('$tag' in v) return new M.CborTag(v.$tag, fromCj(v.v));
  throw new Error('bad cj');
};
const toCj = (v: any): any => {
  if (v instanceof Uint8Array) return B(v);
  if (v instanceof Map) return { $map: [...v].map(([k, x]) => [k, toCj(x)]) };
  if (v instanceof M.CborTag) return { $tag: v.tag, v: toCj(v.value) };
  if (Array.isArray(v)) return v.map(toCj);
  return v;
};

// ---- keys ----
const N256 = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const edKey = (label: string): any => {
  const s = seed(label);
  const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(s)]), format: 'der', type: 'pkcs8' });
  const jwk: any = priv.export({ format: 'jwk' });
  return { priv: { alg: 'EdDSA', seed: b64u(s) }, pub: { alg: 'EdDSA', pub: jwk.x } };
};
const esKey = (label: string): any => {
  const d = Buffer.from(seed(label));
  d[0] &= 0x7f; // < n
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(d);
  const pt = ecdh.getPublicKey();
  const x = b64u(pt.subarray(1, 33));
  const y = b64u(pt.subarray(33, 65));
  return { priv: { alg: 'ES256', d: b64u(d), x, y }, pub: { alg: 'ES256', x, y } };
};
const toKey = (s: any, priv: boolean): any => {
  if (s.alg === 'EdDSA') {
    if (priv) return createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(s.seed, 'base64url')]), format: 'der', type: 'pkcs8' });
    return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: s.pub }, format: 'jwk' });
  }
  if (priv) return createPrivateKey({ key: { kty: 'EC', crv: 'P-256', d: s.d, x: s.x, y: s.y }, format: 'jwk' });
  return createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: s.x, y: s.y }, format: 'jwk' });
};
const ED1 = edKey('scitt/issuer');
const ED2 = edKey('scitt/ts');
const ED3 = edKey('scitt/other');
const ES1 = esKey('scitt/es-issuer');
const ES2 = esKey('scitt/es-ts');
const ES3 = esKey('scitt/es-other');
const edKey2pub = (priv: any) => (createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(priv.seed, 'base64url')]), format: 'der', type: 'pkcs8' }).export({ format: 'jwk' }) as any).x;
const ALGLABEL: any = { EdDSA: -8, ES256: -7 };

const sOpts = (spec: any) => {
  const out: any = { alg: spec.alg, key: toKey(spec.key, true), issuer: spec.issuer };
  if (spec.subject !== undefined) out.subject = spec.subject;
  if (spec.contentType !== undefined) out.contentType = spec.contentType;
  return out;
};
const rOpts = (spec: any) => {
  const out: any = { alg: spec.alg, key: toKey(spec.key, true) };
  if (spec.issuer !== undefined) out.issuer = spec.issuer;
  return out;
};
const vOpts = (op: any) => {
  const out: any = {};
  if (!op) return out;
  if (op.treeRoot !== undefined) out.treeRoot = op.treeRoot;
  if (op.verificationKey) out.verificationKey = toKey(op.verificationKey, false);
  if (op.statementKey) out.statementKey = toKey(op.statementKey, false);
  if (op.allowHighS !== undefined) out.allowHighS = op.allowHighS;
  return out;
};

// ---- the reference table ----
const REF: Record<string, (...a: any[]) => any> = {
  cborEncode: (v) => M.encode(fromCj(v)),
  cborDecode: (b) => toCj(M.decode(un(b))),
  emptyRoot: () => R.emptyRoot(),
  leafHash: (e) => R.leafHash(un(e)),
  nodeHash: (l, r) => R.nodeHash(un(l), un(r)),
  treeHash: (ls) => R.treeHash(ls.map(un)),
  inclusionPath: (ls, i) => R.inclusionPath(ls.map(un), i),
  rootFromInclusionPath: (leaf, i, n, p) => R.rootFromInclusionPath(un(leaf), i, n, p.map(un)),
  verifyInclusionPath: (leaf, i, n, p, root) => R.verifyInclusionPath(un(leaf), i, n, p.map(un), un(root)),
  consistencyPath: (ls, m) => R.consistencyPath(ls.map(un), m),
  verifyConsistencyPath: (f, s, r1, r2, p) => R.verifyConsistencyPath(f, s, un(r1), un(r2), p.map(un)),
  siblingSides: (i, n) => M.siblingSides(i, n),
  encodeInclusionProof: (p) => M.encodeInclusionProof(p),
  decodeInclusionProof: (b) => M.decodeInclusionProof(un(b)),
  signStatement: (payload, spec) => M.signStatement(payload, sOpts(spec)),
  decodeCoseSign1: (b) => {
    const c = M.decodeCoseSign1(un(b));
    return { protectedBytes: c.protectedBytes, protectedMap: toCj(c.protectedMap), unprotected: toCj(c.unprotected), payload: c.payload, signature: c.signature };
  },
  checkStatement: (st, pub, op) => M.checkStatement(un(st), toKey(pub, false), op ?? {}),
  verifyStatement: (st, pub, op) => M.verifyStatement(un(st), toKey(pub, false), op ?? {}),
  statementPayload: (st) => M.statementPayload(un(st)),
  statementLeaf: (st) => M.statementLeaf(un(st)),
  buildReceipt: (root, proof, signer) => M.buildReceipt(root, proof, rOpts(signer)),
  verifyReceipt: (r, st, op) => M.verifyReceipt(un(r), un(st), vOpts(op)),
  verifyConsistencyProof: (p, a, b) => M.verifyConsistencyProof(un(p), a, b),
  constants: () => ({
    COSE_SIGN1_TAG: M.COSE_SIGN1_TAG, HDR_ALG: M.HDR_ALG, HDR_CONTENT_TYPE: M.HDR_CONTENT_TYPE, HDR_CWT_CLAIMS: M.HDR_CWT_CLAIMS, CWT_ISS: M.CWT_ISS,
    CWT_SUB: M.CWT_SUB, HDR_VDS: M.HDR_VDS, HDR_VDS_PROOFS: M.HDR_VDS_PROOFS, VDS_RFC9162_SHA256: M.VDS_RFC9162_SHA256,
    PROOF_TYPE_INCLUSION: M.PROOF_TYPE_INCLUSION, DEFAULT_CONTENT_TYPE: M.DEFAULT_CONTENT_TYPE,
  }),
  es256SignVerify: (key, payload, issuer) => {
    const st = M.signStatement(payload, { alg: 'ES256', key: toKey(key, true), issuer });
    const c = M.decodeCoseSign1(st);
    const s = BigInt('0x' + Buffer.from(c.signature.subarray(32)).toString('hex'));
    return { check: M.checkStatement(st, toKey({ alg: 'ES256', x: key.x, y: key.y }, false)), payload: M.statementPayload(st), lowS: s <= N256 >> 1n, protectedBytes: c.protectedBytes };
  },
  es256Receipt: (key, n, index, edPriv, wrongPub) => {
    const ts = new TransparencyService({ alg: 'ES256', key: toKey(key, true), issuer: 'ts' });
    const sts: Uint8Array[] = [];
    for (let i = 0; i < n; i++) sts.push(ts.appendAndReceipt({ i }, sOpts({ alg: 'EdDSA', key: edPriv, issuer: 'iss' })).statement);
    const pub = toKey({ alg: 'ES256', x: key.x, y: key.y }, false);
    const r = ts.getReceipt(index);
    const wrong = toKey(wrongPub, false);
    return {
      key: M.verifyReceipt(r.receipt, sts[index]!, { verificationKey: pub }),
      root: M.verifyReceipt(r.receipt, sts[index]!, { treeRoot: r.root }),
      both: M.verifyReceipt(r.receipt, sts[index]!, { verificationKey: pub, treeRoot: r.root, statementKey: toKey({ alg: 'EdDSA', pub: edKey2pub(edPriv) }, false) }),
      wrongKey: M.verifyReceipt(r.receipt, sts[index]!, { verificationKey: wrong }),
      otherStatement: M.verifyReceipt(r.receipt, sts[(index + 1) % n] ?? new Uint8Array(3), { verificationKey: pub }),
      none: M.verifyReceipt(r.receipt, sts[index]!, {}),
    };
  },
};

const add = async (fn: string, name: string, args: any[]) => {
  let nm = name;
  for (let k = 1; o.names.has(`${fn}/${nm}`); k++) nm = `${name}~${k}`;
  await o.run(fn, nm, REF[fn]!, args);
};

// ======================================================================================= CBOR
const INTS = [0, 1, 10, 23, 24, 25, 100, 255, 256, 1000, 65535, 65536, 1_000_000, 4294967295, 4294967296, 4294967297, 2 ** 40, 2 ** 53 - 1, -1, -10, -24, -25, -100, -256, -257, -65536, -65537, -4294967296, -4294967297, -(2 ** 53 - 1)];
const BAD_NUMS = [1.5, -1.5, 0.1, 2 ** 53, 2 ** 53 + 2, -(2 ** 53), -(2 ** 53) - 2, 1e21, -1e21, 1e300];
const STRS = ['', 'a', 'abc', 'é', 'é', '日本語', '😀', '\u0000', 'a'.repeat(23), 'a'.repeat(24), 'a'.repeat(255), 'a'.repeat(256), 'a'.repeat(300), '﻿', '﻿x', 'x y'];
const BAD_STRS = ['\ud800', '\udc00', 'a\ud800b', '\udc00\ud800', 'x\ud83d'];
const BYTES = [new Uint8Array(0), Uint8Array.of(0), Uint8Array.of(255), new Uint8Array(23).fill(7), new Uint8Array(24).fill(8), new Uint8Array(255).fill(9), new Uint8Array(256).fill(1), new Uint8Array(300).fill(2)];
const cborValues: any[] = [];
for (const i of INTS) cborValues.push(i);
for (const s of STRS) cborValues.push(s);
for (const b of BYTES) cborValues.push(B(b));
cborValues.push(null, true, false, [], [1, 2, 3], [[]], [[[1]]], [null, true, 'x', B(Uint8Array.of(1))], Array.from({ length: 24 }, (_, i) => i), Array.from({ length: 25 }, (_, i) => i));
cborValues.push({ $map: [] });
cborValues.push({ $map: [[1, 'a']] });
cborValues.push({ $map: [[1, 'a'], [-1, 'b'], ['a', 1], ['aa', 2], ['b', 3], [100, 4], [24, 5], [256, 6], ['', 7], [-24, 8], [-25, 9], [23, 10]] });
cborValues.push({ $map: [['b', 1], ['a', 2]] }); // unsorted input is sorted on encode
cborValues.push({ $map: [[3, 1], [2, 2], [1, 3]] });
cborValues.push({ $map: [[1, { $map: [[2, { $map: [[3, [1, { $map: [['k', null]] }]]] }]] }]] });
cborValues.push({ $map: [[1, 1], [1, 2]] }); // duplicate key
cborValues.push({ $map: [[1, 1], ['1', 2]] }); // 1 vs "1" are distinct
cborValues.push({ $map: [[1.5, 1]] }, { $map: [[2 ** 53, 1]] }, { $map: [[-0, 1]] });
for (const t of [0, 1, 18, 23, 24, 255, 256, 65536, 2 ** 32, 2 ** 53 - 1]) cborValues.push({ $tag: t, v: 'x' });
cborValues.push({ $tag: 18, v: [B(Uint8Array.of(1, 2)), { $map: [] }, B(new Uint8Array(0)), B(new Uint8Array(64))] });
cborValues.push({ $tag: 18, v: { $tag: 1, v: 5 } });
cborValues.push({ $tag: -1, v: 1 }, { $tag: 1.5, v: 1 }, { $tag: 2 ** 53, v: 1 });
for (const n of BAD_NUMS) cborValues.push(n, [n], { $map: [['k', n]] });
for (const s of BAD_STRS) cborValues.push(s, [s], { $map: [[s, 1]] }, { $map: [['k', s]] });
cborValues.push(-0);
let ci = 0;
for (const v of cborValues) await add('cborEncode', `v${ci++}`, [v]);
// decode: every valid encoding, its truncations and trailing / mutated forms
const validEnc: Uint8Array[] = [];
for (const v of cborValues) {
  try {
    validEnc.push(M.encode(fromCj(v)));
  } catch {
    /* skipped: refused on encode */
  }
}
let di = 0;
for (const e of validEnc) {
  await add('cborDecode', `ok${di++}`, [B(e)]);
  if (e.length > 0 && e.length <= 70) {
    for (let k = 0; k < e.length; k++) await add('cborDecode', `trunc${di}-${k}`, [B(e.subarray(0, k))]);
  } else if (e.length > 70) {
    for (const k of [0, 1, 2, 3, 5, 9, 10, 26, 70, e.length - 1]) await add('cborDecode', `trunc${di}-${k}`, [B(e.subarray(0, k))]);
  }
  await add('cborDecode', `trail${di}`, [B(Uint8Array.from([...e, 0]))]);
}
const HEXES = [
  '', '00', '17', '1818', '1817', '1900ff', '190100', '1a0000ffff', '1a00010000', '1b00000000ffffffff', '1b0000000100000000', '1b001fffffffffffff', '1b0020000000000000',
  '1bffffffffffffffff', '1b8000000000000001', '20', '37', '3818', '3817', '3b001ffffffffffffe', '3b001fffffffffffff', '3b0020000000000000', '3bffffffffffffffff',
  '40', '4100', '58', '5801', '580100', '5817' + '00'.repeat(23), '5818' + '00'.repeat(24), '5900', '590001', '5a00000001', '5affffffff', '5b0000000000000001', '5bffffffffffffffff',
  '60', '6161', '62c3a9', '62c3', '61ff', '62c328', '63e282', '63eda080', '64f0908080', '62c080', '63efbbbf', '66efbbbf616263', '7f6161ff', '5f4101ff', '9f01ff', 'bf6161 01ff',
  '80', '8100', '820102', '83010203', '98180000', '9818' + '00'.repeat(24), '9a00000002 00', '8201', '81', '9b0000000000000001', '9bffffffffffffffff', '99ffff',
  'a0', 'a10102', 'a2 0102 0304', 'a2 0304 0102', 'a2 0101 0102', 'a1 6161 01', 'a2 6162 01 6161 02', 'a2 6161 01 6161 02', 'a1 4161 01', 'a1 f6 01', 'a1 f4 01', 'a1 8100 01', 'a1 a0 01', 'a1 c101 01',
  'a2 01 01 21 02', 'a2 21 02 01 01', 'a2 20 01 01 02', 'a2 0100 0200', 'a2 1818 01 17 02', 'a2 17 02 1818 01', 'a2 6161 01 01 02', 'a2 01 02 6161 03', 'a2 6161 01 6162 02', 'a2 6162 01 6161 02',
  'a1 1900ff 01', 'a1 1818 01', 'a1 1817 01', 'a1 a1',
  'c0 00', 'c1 00', 'd2 00', 'd8 12 00', 'd8 17 00', 'd8 18 00', 'd9 0100 00', 'da 00010000 00', 'db 0000000100000000 00', 'dbffffffffffffffff 00', 'dc', 'df', 'd2', 'd8 12', 'd8 11 00', 'd8 12 84 40 a0 40 40',
  'd2 84 40 a0 40 40', 'd2 84 41 a0 40 41', 'd2 84 40 a0 f6 40', 'd2 83 40 a0 40',
  'e0', 'f0', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8 00', 'f8 14', 'f8 20', 'f9 0000', 'fa 00000000', 'fb 0000000000000000', 'fc', 'fd', 'fe', 'ff', 'f7 f7', '1c', '1d', '1e', '1f', '3c', '3f', '5c', '5f', '7c', '7f', '9c', '9f', 'bc', 'bf', 'dc', 'df',
  '00 00', 'f6 f6', '8000', 'a000',
];
let hi = 0;
for (const h of HEXES) await add('cborDecode', `hex${hi++}`, [B(hexb(h))]);
{
  const r = rng(0x5c177);
  for (let i = 0; i < 120 && validEnc.length > 0; i++) {
    const e = Uint8Array.from(r.pick(validEnc));
    if (e.length === 0) continue;
    e[r.int(0, e.length - 1)] ^= 1 << r.int(0, 7);
    await add('cborDecode', `flip${i}`, [B(e)]);
  }
}
// ======================================================================================= RFC 9162
const entry = (i: number) => new TextEncoder().encode(`entry-${i}`);
const lh = (n: number) => Array.from({ length: n }, (_, i) => R.leafHash(entry(i)));
await add('emptyRoot', 'empty', []);
for (let i = 0; i < 6; i++) await add('leafHash', `e${i}`, [B(i === 0 ? new Uint8Array(0) : entry(i))]);
await add('leafHash', 'big', [B(new Uint8Array(1000).fill(3))]);
for (let i = 0; i < 4; i++) await add('nodeHash', `n${i}`, [B(R.leafHash(entry(i))), B(R.leafHash(entry(i + 1)))]);
await add('nodeHash', 'short', [B(Uint8Array.of(1)), B(Uint8Array.of(2))]);
const NS = [...Array.from({ length: 26 }, (_, i) => i), 31, 32, 33, 63, 64, 65, 100];
const flipB = (u: Uint8Array, k = 0) => { const c = Uint8Array.from(u); c[k] ^= 1; return c; };
for (const n of NS) {
  const L = lh(n);
  await add('treeHash', `n${n}`, [L.map(B)]);
  if (n === 0) continue;
  const root = R.treeHash(L);
  const denseIdx = n <= 12 ? Array.from({ length: n }, (_, i) => i) : [0, 1, Math.floor(n / 2), n - 1];
  for (const i of denseIdx) {
    const p = R.inclusionPath(L, i);
    const P = p.map(B);
    await add('inclusionPath', `n${n}i${i}`, [L.map(B), i]);
    await add('rootFromInclusionPath', `n${n}i${i}`, [B(L[i]!), i, n, P]);
    await add('verifyInclusionPath', `ok-n${n}i${i}`, [B(L[i]!), i, n, P, B(root)]);
    await add('verifyInclusionPath', `badroot-n${n}i${i}`, [B(L[i]!), i, n, P, B(flipB(root))]);
    await add('verifyInclusionPath', `badleaf-n${n}i${i}`, [B(flipB(L[i]!)), i, n, P, B(root)]);
    await add('verifyInclusionPath', `idx+1-n${n}i${i}`, [B(L[i]!), i + 1, n, P, B(root)]);
    await add('verifyInclusionPath', `size+1-n${n}i${i}`, [B(L[i]!), i, n + 1, P, B(root)]);
    if (n > 1) await add('verifyInclusionPath', `size-1-n${n}i${i}`, [B(L[i]!), i, n - 1, P, B(root)]);
    if (P.length > 0) {
      await add('verifyInclusionPath', `short-n${n}i${i}`, [B(L[i]!), i, n, P.slice(1), B(root)]);
      await add('verifyInclusionPath', `flipstep-n${n}i${i}`, [B(L[i]!), i, n, P.map((x: any, k: number) => (k === 0 ? B(flipB(bytes(x.$bytes))) : x)), B(root)]);
    }
    await add('verifyInclusionPath', `long-n${n}i${i}`, [B(L[i]!), i, n, [...P, B(L[0]!)], B(root)]);
  }
  for (const i of [-1, n, n + 5, 1.5]) await add('inclusionPath', `oor-n${n}i${i}`, [L.map(B), i]);
  for (const [i, sz] of [[-1, n], [0, 0], [n, n], [1.5, n], [0, 1.5], [2 ** 53, n], [0, 2 ** 53]] as any[]) {
    await add('rootFromInclusionPath', `inv-n${n}-${i}-${sz}`, [B(L[0]!), i, sz, R.inclusionPath(L, 0).map(B)]);
    await add('verifyInclusionPath', `inv-n${n}-${i}-${sz}`, [B(L[0]!), i, sz, R.inclusionPath(L, 0).map(B), B(root)]);
  }
  await add('rootFromInclusionPath', `shortleaf-n${n}`, [B(Uint8Array.of(1)), 0, n, R.inclusionPath(L, 0).map(B)]);
  await add('rootFromInclusionPath', `shortstep-n${n}`, [B(L[0]!), 0, n, n > 1 ? [B(Uint8Array.of(1))] : [B(Uint8Array.of(1))]]);
  const ms = n <= 12 ? Array.from({ length: n }, (_, i) => i + 1) : [1, 3, 8, Math.floor(n / 2), n - 1, n];
  for (const m of ms) {
    const p = R.consistencyPath(L, m).map(B);
    const r1 = R.treeHash(L.slice(0, m));
    await add('consistencyPath', `n${n}m${m}`, [L.map(B), m]);
    await add('verifyConsistencyPath', `ok-n${n}m${m}`, [m, n, B(r1), B(root), p]);
    await add('verifyConsistencyPath', `badfirst-n${n}m${m}`, [m, n, B(flipB(r1)), B(root), p]);
    await add('verifyConsistencyPath', `badsecond-n${n}m${m}`, [m, n, B(r1), B(flipB(root)), p]);
    await add('verifyConsistencyPath', `swapped-n${n}m${m}`, [n, m, B(root), B(r1), p]);
    if (p.length > 0) {
      await add('verifyConsistencyPath', `short-n${n}m${m}`, [m, n, B(r1), B(root), p.slice(0, -1)]);
      await add('verifyConsistencyPath', `drop0-n${n}m${m}`, [m, n, B(r1), B(root), p.slice(1)]);
      await add('verifyConsistencyPath', `flipstep-n${n}m${m}`, [m, n, B(r1), B(root), p.map((x: any, k: number) => (k === p.length - 1 ? B(flipB(bytes(x.$bytes))) : x))]);
    }
    await add('verifyConsistencyPath', `long-n${n}m${m}`, [m, n, B(r1), B(root), [...p, B(root)]]);
    await add('verifyConsistencyPath', `m+1-n${n}m${m}`, [m + 1, n, B(r1), B(root), p]);
  }
  for (const m of [0, -1, n + 1, 1.5]) await add('consistencyPath', `oor-n${n}m${m}`, [L.map(B), m]);
  for (const [f, s] of [[0, n], [-1, n], [1.5, n], [1, 2 ** 53], [2 ** 53, 2 ** 53]] as any[]) await add('verifyConsistencyPath', `inv-n${n}-${f}-${s}`, [f, s, B(root), B(root), []]);
  await add('verifyConsistencyPath', `shortroot-n${n}`, [1, n, B(Uint8Array.of(1)), B(root), []]);
}
// ======================================================================================= siblingSides, proof codec
for (let n = 1; n <= 40; n++) for (let i = 0; i < n; i++) await add('siblingSides', `n${n}i${i}`, [i, n]);
for (const [i, n] of [[5, 3], [-1, 4], [0, 0], [3, 3], [100, 7]] as any[]) await add('siblingSides', `odd-${i}-${n}`, [i, n]);
const pf = (n: number, i: number) => {
  const L = lh(n);
  const sides = M.siblingSides(i, n);
  return { index: i, size: n, path: R.inclusionPath(L, i).map((h: Uint8Array, k: number) => ({ side: sides[k], hash: b64u(h) })) };
};
for (const [n, i] of [[1, 0], [2, 0], [2, 1], [3, 2], [5, 4], [8, 3], [13, 7], [26, 25], [100, 63]] as any[]) {
  const p = pf(n, i);
  await add('encodeInclusionProof', `n${n}i${i}`, [p]);
  await add('decodeInclusionProof', `n${n}i${i}`, [B(M.encodeInclusionProof(p))]);
}
{
  const p = pf(9, 4);
  const hh = p.path[0].hash;
  await add('encodeInclusionProof', 'bad-hash', [{ ...p, path: [{ side: 'L', hash: 'AAAA' }] }]);
  await add('encodeInclusionProof', 'bad-hash-pad', [{ ...p, path: [{ side: 'L', hash: hh + '=' }] }]);
  await add('encodeInclusionProof', 'path-not-array', [{ ...p, path: 'x' }]);
  await add('encodeInclusionProof', 'step-null', [{ ...p, path: [null] }]);
  await add('encodeInclusionProof', 'step-no-hash', [{ ...p, path: [{ side: 'L' }] }]);
  await add('encodeInclusionProof', 'no-size', [{ index: 4, path: p.path }]);
  await add('encodeInclusionProof', 'no-index', [{ size: 9, path: p.path }]);
  await add('encodeInclusionProof', 'float-size', [{ ...p, size: 9.5 }]);
  await add('encodeInclusionProof', 'string-size', [{ ...p, size: '9' }]);
  await add('encodeInclusionProof', 'null-size', [{ ...p, size: null }]);
  await add('encodeInclusionProof', 'neg-index', [{ ...p, index: -1 }]);
  await add('encodeInclusionProof', 'big-size', [{ ...p, size: 2 ** 53 }]);
  await add('encodeInclusionProof', 'empty-path', [{ index: 0, size: 1, path: [] }]);
  const h32 = (i: number) => new Uint8Array(32).fill(i);
  const E = (v: any) => M.encode(v);
  const cases: [string, Uint8Array][] = [
    ['not-array', E(5)], ['len2', E([1, 0])], ['len4', E([1, 0, [], 0])], ['size-str', E(['1', 0, []])], ['index-str', E([1, '0', []])],
    ['size0', E([0, 0, []])], ['index-neg', E([1, -1, []])], ['index>=size', E([2, 2, [h32(1)]])], ['path-not-array', E([1, 0, 5])],
    ['path-short', E([4, 1, [h32(1)]])], ['path-long', E([1, 0, [h32(1)]])], ['entry-short', E([2, 0, [new Uint8Array(31)]])], ['entry-not-bytes', E([2, 0, ['x']])],
    ['ok2', E([2, 0, [h32(1)]])], ['ok3', E([3, 2, [h32(1)]])], ['ok5', E([5, 4, [h32(1)]])], ['trailing', Uint8Array.from([...E([2, 0, [h32(1)]]), 0])], ['garbage', Uint8Array.of(0xff)],
  ];
  for (const [nm, b] of cases) await add('decodeInclusionProof', nm, [B(b)]);
}
// ======================================================================================= Signed Statements
const PAYLOADS: any[] = [
  { action: 'pay', amount: 12, currency: 'EUR' },
  { a: [1, 2, 3], b: { c: null, d: true, e: 'é😀' } },
  {},
  [],
  'text',
  42,
  null,
  { 'kéy': 'v', z: 1, a: 2 },
  { n: 2 ** 53 - 1, m: -(2 ** 53 - 1), z: 0 },
  { deep: { a: { b: { c: { d: { e: { f: 1 } } } } } } },
  { unicode: '  ', ctl: '\u0001\n\t"\\' },
  { long: 'x'.repeat(2000) },
];
const BAD_PAYLOADS: any[] = [{ f: 1.5 }, { s: '\ud800' }, { big: 2 ** 53 + 2 }, { neg0: -0 }];
const edSpec = (k: any, extra: any = {}) => ({ alg: 'EdDSA', key: k.priv, issuer: 'https://issuer.example', ...extra });
let pi = 0;
for (const p of PAYLOADS) {
  await add('signStatement', `plain${pi}`, [p, edSpec(ED1)]);
  await add('signStatement', `subject${pi}`, [p, edSpec(ED2, { subject: 'grant:' + pi })]);
  await add('signStatement', `ctype${pi}`, [p, edSpec(ED3, { contentType: 'application/json', issuer: 'é-iss' })]);
  pi++;
}
await add('signStatement', 'empty-issuer', [{ a: 1 }, edSpec(ED1, { issuer: '' })]);
await add('signStatement', 'empty-subject', [{ a: 1 }, edSpec(ED1, { subject: '' })]);
await add('signStatement', 'empty-ctype', [{ a: 1 }, edSpec(ED1, { contentType: '' })]);
await add('signStatement', 'bad-issuer-surrogate', [{ a: 1 }, edSpec(ED1, { issuer: '\ud800' })]);
for (let i = 0; i < BAD_PAYLOADS.length; i++) await add('signStatement', `bad${i}`, [BAD_PAYLOADS[i], edSpec(ED1)]);
{
  let k = 0;
  for (const p of PAYLOADS.slice(0, 6)) await add('es256SignVerify', `p${k++}`, [ES1.priv, p, 'https://es.example']);
  for (const [n, i] of [[1, 0], [2, 1], [5, 3], [8, 7], [13, 6]] as any[]) await add('es256Receipt', `n${n}i${i}`, [ES2.priv, n, i, ED1.priv, ES3.pub]);
}
// ---- statements to check ----
const stEd = (p: any, k = ED1, extra: any = {}) => M.signStatement(p, sOpts(edSpec(k, extra)));
const stEs = (p: any, k = ES1, extra: any = {}) => M.signStatement(p, sOpts({ alg: 'ES256', key: k.priv, issuer: 'https://es.example', ...extra }));
const SMALL = stEd({ a: 1 });
const SMALL_ES = stEs({ a: 1 });
const raw = (alg: string, key: any, msg: Uint8Array, high = false) => {
  const k = toKey(key, true);
  const sig = new Uint8Array(alg === 'EdDSA' ? nodeSign(null, msg, k) : nodeSign('sha256', msg, { key: k, dsaEncoding: 'ieee-p1363' }));
  if (alg === 'ES256') {
    const s = BigInt('0x' + Buffer.from(sig.subarray(32)).toString('hex'));
    const low = s > N256 >> 1n ? N256 - s : s;
    const want = high ? N256 - low : low;
    sig.set(Buffer.from(want.toString(16).padStart(64, '0'), 'hex'), 32);
  }
  return sig;
};
const sigStruct = (prot: Uint8Array, payload: Uint8Array) => M.encode(['Signature1', prot, new Uint8Array(0), payload]);
const cose = (prot: Uint8Array, unprot: Map<any, any>, payload: Uint8Array | null, sig: Uint8Array) => M.encode(new M.CborTag(18, [prot, unprot, payload, sig]));
const mk = (hdr: [any, any][], payload: Uint8Array | null, alg: string | null, key: any, o2: any = {}) => {
  const prot = M.encode(new Map(hdr));
  const sig = alg ? raw(alg, key, sigStruct(prot, payload ?? new Uint8Array(0)), o2.high) : new Uint8Array(64);
  return cose(o2.rawProt ?? prot, o2.unprot ?? new Map(), payload, o2.sig ?? sig);
};
const P1 = new TextEncoder().encode('{"a":1}');
const crafted: [string, Uint8Array][] = [
  ['good-ed', mk([[1, -8]], P1, 'EdDSA', ED1.priv)],
  ['good-es', mk([[1, -7]], P1, 'ES256', ES1.priv)],
  ['high-s-es', mk([[1, -7]], P1, 'ES256', ES1.priv, { high: true })],
  ['missing-alg', mk([[3, 'x']], P1, 'EdDSA', ED1.priv)],
  ['alg-eddsa-wrong-label', mk([[1, -35]], P1, 'EdDSA', ED1.priv)],
  ['alg-string', mk([[1, 'EdDSA']], P1, 'EdDSA', ED1.priv)],
  ['alg-null', mk([[1, null]], P1, 'EdDSA', ED1.priv)],
  ['alg-0', mk([[1, 0]], P1, 'EdDSA', ED1.priv)],
  ['detached', mk([[1, -8]], null, 'EdDSA', ED1.priv)],
  ['empty-protected', cose(new Uint8Array(0), new Map(), P1, new Uint8Array(64))],
  ['protected-not-map', cose(M.encode(5), new Map(), P1, new Uint8Array(64))],
  ['protected-garbage', cose(Uint8Array.of(0xff), new Map(), P1, new Uint8Array(64))],
  ['empty-payload', mk([[1, -8]], new Uint8Array(0), 'EdDSA', ED1.priv)],
  ['short-sig', mk([[1, -8]], P1, 'EdDSA', ED1.priv, { sig: new Uint8Array(63) })],
  ['zero-sig', mk([[1, -8]], P1, 'EdDSA', ED1.priv, { sig: new Uint8Array(64) })],
  ['zero-sig-es', mk([[1, -7]], P1, 'ES256', ES1.priv, { sig: new Uint8Array(64) })],
  ['es-short-sig', mk([[1, -7]], P1, 'ES256', ES1.priv, { sig: new Uint8Array(63) })],
  ['es-r0', mk([[1, -7]], P1, 'ES256', ES1.priv, { sig: new Uint8Array(64).fill(1).fill(0, 0, 32) })],
  ['es-r-n', mk([[1, -7]], P1, 'ES256', ES1.priv, { sig: Uint8Array.from([...Buffer.from(N256.toString(16), 'hex'), ...new Uint8Array(31), 1]) })],
  ['unprotected-extra', mk([[1, -8]], P1, 'EdDSA', ED1.priv, { unprot: new Map([[4, new Uint8Array(1)]]) })],
  ['wrong-tag', M.encode(new M.CborTag(17, [new Uint8Array(0), new Map(), P1, new Uint8Array(64)]))],
  ['no-tag', M.encode([new Uint8Array(0), new Map(), P1, new Uint8Array(64)])],
  ['len3', M.encode(new M.CborTag(18, [new Uint8Array(0), new Map(), P1]))],
  ['unprot-not-map', M.encode(new M.CborTag(18, [new Uint8Array(0), 5, P1, new Uint8Array(64)]))],
  ['payload-str', M.encode(new M.CborTag(18, [new Uint8Array(0), new Map(), 'x', new Uint8Array(64)]))],
  ['sig-str', M.encode(new M.CborTag(18, [new Uint8Array(0), new Map(), P1, 'x']))],
  ['protected-str', M.encode(new M.CborTag(18, ['x', new Map(), P1, new Uint8Array(64)]))],
  ['trailing', Uint8Array.from([...SMALL, 0])],
  ['truncated', SMALL.subarray(0, SMALL.length - 3)],
  ['empty', new Uint8Array(0)],
  ['noncanonical-int', Uint8Array.from([0xd8, 0x12, 0x84, 0x40, 0xa0, 0x58, 0x01, 0x41, 0x40])],
];
const KEYS_TO_TRY = [ED1.pub, ED2.pub, ES1.pub, ES3.pub];
let sk = 0;
for (const [nm, st] of crafted) {
  for (const key of KEYS_TO_TRY) {
    await add('checkStatement', `${nm}-${sk++}`, [B(st), key]);
  }
  await add('checkStatement', `${nm}-high`, [B(st), ES1.pub, { allowHighS: true }]);
  await add('verifyStatement', `${nm}-ed`, [B(st), ED1.pub]);
  await add('verifyStatement', `${nm}-eshigh`, [B(st), ES1.pub, { allowHighS: true }]);
  await add('decodeCoseSign1', nm, [B(st)]);
  await add('statementPayload', nm, [B(st)]);
  await add('statementLeaf', nm, [B(st)]);
}
for (const [nm, st, key] of [['ed', SMALL, ED1.pub], ['es', SMALL_ES, ES1.pub]] as any[]) {
  for (let k = 0; k < st.length; k++) {
    const c = Uint8Array.from(st);
    c[k] ^= 0x01;
    await add('checkStatement', `flip-${nm}-${k}`, [B(c), key]);
  }
  for (const k of [0, 1, 2, 5, 10, 20, st.length - 1]) await add('checkStatement', `trunc-${nm}-${k}`, [B(st.subarray(0, k)), key]);
  await add('decodeCoseSign1', `good-${nm}`, [B(st)]);
}
pi = 0;
for (const p of PAYLOADS) {
  const a = stEd(p, ED1, pi % 2 ? { subject: 's' } : {});
  await add('checkStatement', `ed${pi}`, [B(a), ED1.pub]);
  await add('checkStatement', `ed-wrong${pi}`, [B(a), ED2.pub]);
  await add('checkStatement', `ed-as-es${pi}`, [B(a), ES1.pub]);
  await add('verifyStatement', `ed${pi}`, [B(a), ED1.pub]);
  await add('statementPayload', `ed${pi}`, [B(a)]);
  await add('statementLeaf', `ed${pi}`, [B(a)]);
  await add('decodeCoseSign1', `ed${pi}`, [B(a)]);
  if (pi < 8) {
    const e = stEs(p, ES1, pi % 2 ? { subject: 's' } : {});
    await add('checkStatement', `es${pi}`, [B(e), ES1.pub]);
    await add('checkStatement', `es-wrong${pi}`, [B(e), ES3.pub]);
    await add('checkStatement', `es-as-ed${pi}`, [B(e), ED1.pub]);
    await add('verifyStatement', `es${pi}`, [B(e), ES1.pub, { allowHighS: true }]);
    await add('decodeCoseSign1', `es${pi}`, [B(e)]);
    // high-S twin of a genuine ES256 statement
    const c = M.decodeCoseSign1(e);
    const s = BigInt('0x' + Buffer.from(c.signature.subarray(32)).toString('hex'));
    const hs = Uint8Array.from(c.signature);
    hs.set(Buffer.from((N256 - s).toString(16).padStart(64, '0'), 'hex'), 32);
    const twin = cose(c.protectedBytes, c.unprotected, c.payload, hs);
    await add('checkStatement', `es-twin${pi}`, [B(twin), ES1.pub]);
    await add('checkStatement', `es-twin-allow${pi}`, [B(twin), ES1.pub, { allowHighS: true }]);
    await add('verifyStatement', `es-twin${pi}`, [B(twin), ES1.pub]);
  }
  pi++;
}
// ======================================================================================= Receipts
const tsOf = (alg: string, key: any, issuer: string | undefined) => new TransparencyService({ alg: alg as any, key: toKey(key.priv, true), ...(issuer !== undefined ? { issuer } : {}) });
const build = (alg: string, k: any, n: number, issuer?: string) => {
  const ts = tsOf(alg, k, issuer);
  const sts: Uint8Array[] = [];
  for (let i = 0; i < n; i++) sts.push(ts.appendAndReceipt({ i, v: 'v' + i }, sOpts(edSpec(ED1))).statement);
  return { ts, sts };
};
const baseProof = (n: number, i: number) => pf(n, i);
for (const [n, i] of [[1, 0], [2, 0], [2, 1], [3, 1], [5, 4], [8, 5], [13, 12]] as any[]) {
  const L = lh(n);
  const root = b64u(R.treeHash(L));
  await add('buildReceipt', `ed-n${n}i${i}`, [root, baseProof(n, i), { alg: 'EdDSA', key: ED2.priv }]);
  await add('buildReceipt', `ed-iss-n${n}i${i}`, [root, baseProof(n, i), { alg: 'EdDSA', key: ED2.priv, issuer: 'ts.example' }]);
}
{
  const root = b64u(R.treeHash(lh(5)));
  const p = baseProof(5, 2);
  await add('buildReceipt', 'bad-root', ['AAAA', p, { alg: 'EdDSA', key: ED2.priv }]);
  await add('buildReceipt', 'bad-root-pad', [root + '=', p, { alg: 'EdDSA', key: ED2.priv }]);
  await add('buildReceipt', 'bad-proof', [root, { ...p, path: [{ side: 'L', hash: 'AA' }] }, { alg: 'EdDSA', key: ED2.priv }]);
  await add('buildReceipt', 'proof-not-matching', [root, baseProof(9, 4), { alg: 'EdDSA', key: ED2.priv }]);
  await add('buildReceipt', 'empty-issuer', [root, p, { alg: 'EdDSA', key: ED2.priv, issuer: '' }]);
}
const VK = (k: any) => k.pub;
const sets: any[] = [];
for (const n of [1, 2, 3, 5, 8, 11]) {
  const { ts, sts } = build('EdDSA', ED2, n, n % 2 ? 'ts.example' : undefined);
  for (const i of n <= 3 ? Array.from({ length: n }, (_, k) => k) : [0, n - 1, Math.floor(n / 2)]) {
    const r = ts.getReceipt(i);
    sets.push({ n, i, r, st: sts[i]!, other: sts[(i + 1) % n]! });
  }
}
for (const s of sets) {
  const t = `n${s.n}i${s.i}`;
  const R_ = B(s.r.receipt);
  const ST = B(s.st);
  await add('verifyReceipt', `key-${t}`, [R_, ST, { verificationKey: VK(ED2) }]);
  await add('verifyReceipt', `root-${t}`, [R_, ST, { treeRoot: s.r.root }]);
  await add('verifyReceipt', `both-${t}`, [R_, ST, { verificationKey: VK(ED2), treeRoot: s.r.root, statementKey: VK(ED1) }]);
  await add('verifyReceipt', `none-${t}`, [R_, ST, {}]);
  await add('verifyReceipt', `wrongkey-${t}`, [R_, ST, { verificationKey: VK(ED3) }]);
  await add('verifyReceipt', `eskey-${t}`, [R_, ST, { verificationKey: VK(ES2) }]);
  await add('verifyReceipt', `wrongroot-${t}`, [R_, ST, { treeRoot: b64u(new Uint8Array(32)) }]);
  await add('verifyReceipt', `badrootenc-${t}`, [R_, ST, { treeRoot: s.r.root + '=' }]);
  await add('verifyReceipt', `wrongstmtkey-${t}`, [R_, ST, { treeRoot: s.r.root, statementKey: VK(ED3) }]);
  await add('verifyReceipt', `otherstmt-${t}`, [R_, B(s.other), { treeRoot: s.r.root }]);
  await add('verifyReceipt', `tamper-${t}`, [R_, B(flipB(s.st, s.st.length - 1)), { verificationKey: VK(ED2) }]);
  await add('verifyReceipt', `empty-opts-key-${t}`, [R_, ST, { verificationKey: VK(ED2), allowHighS: true }]);
}
{
  const { ts, sts } = build('EdDSA', ED2, 4, 'ts');
  const r = ts.getReceipt(2);
  const E = M.decodeCoseSign1(r.receipt);
  for (let k = 0; k < r.receipt.length; k++) {
    const c = Uint8Array.from(r.receipt);
    c[k] ^= 0x01;
    await add('verifyReceipt', `flip-${k}`, [B(c), B(sts[2]!), { verificationKey: VK(ED2), treeRoot: r.root }]);
  }
  for (const k of [0, 1, 5, 20, 50, r.receipt.length - 1]) await add('verifyReceipt', `trunc-${k}`, [B(r.receipt.subarray(0, k)), B(sts[2]!), { verificationKey: VK(ED2) }]);
  await add('verifyReceipt', 'garbage-receipt', [B(Uint8Array.of(1, 2, 3)), B(sts[2]!), { verificationKey: VK(ED2) }]);
  await add('verifyReceipt', 'statement-as-receipt', [B(sts[2]!), B(sts[2]!), { verificationKey: VK(ED1) }]);
  // crafted receipts
  const rootB = bytes(r.root);
  const proofBytes = E.unprotected.get(396).get(-1)[0] as Uint8Array;
  const mkR = (protHdr: [any, any][], unprot: any, payload: Uint8Array | null, signRoot: Uint8Array = rootB, key: any = ED2.priv) => {
    const prot = M.encode(new Map(protHdr));
    return cose(prot, unprot, payload, raw('EdDSA', key, sigStruct(prot, signRoot)));
  };
  const goodUn = new Map([[396, new Map([[-1, [proofBytes]]])]]);
  const cr: [string, Uint8Array][] = [
    ['good', mkR([[1, -8], [395, 1]], goodUn, null)],
    ['embedded-payload', mkR([[1, -8], [395, 1]], goodUn, rootB)],
    ['embedded-wrong-payload', mkR([[1, -8], [395, 1]], goodUn, new Uint8Array(32))],
    ['embedded-short-payload', mkR([[1, -8], [395, 1]], goodUn, rootB.subarray(0, 31))],
    ['vds-2', mkR([[1, -8], [395, 2]], goodUn, null)],
    ['vds-missing', mkR([[1, -8]], goodUn, null)],
    ['vds-string', mkR([[1, -8], [395, '1']], goodUn, null)],
    ['alg-missing', mkR([[395, 1]], goodUn, null)],
    ['alg-bad', mkR([[1, -35], [395, 1]], goodUn, null)],
    ['no-proofs', mkR([[1, -8], [395, 1]], new Map(), null)],
    ['proofs-not-map', mkR([[1, -8], [395, 1]], new Map([[396, 5]]), null)],
    ['inclusion-missing', mkR([[1, -8], [395, 1]], new Map([[396, new Map([[-2, [proofBytes]]])]]), null)],
    ['inclusion-empty', mkR([[1, -8], [395, 1]], new Map([[396, new Map([[-1, []]])]]), null)],
    ['inclusion-not-array', mkR([[1, -8], [395, 1]], new Map([[396, new Map([[-1, proofBytes]])]]), null)],
    ['inclusion-not-bstr', mkR([[1, -8], [395, 1]], new Map([[396, new Map([[-1, ['x']]])]]), null)],
    ['inclusion-two', mkR([[1, -8], [395, 1]], new Map([[396, new Map([[-1, [proofBytes, proofBytes]]])]]), null)],
    ['inclusion-garbage', mkR([[1, -8], [395, 1]], new Map([[396, new Map([[-1, [Uint8Array.of(1)]]])]]), null)],
    ['signed-other-root', mkR([[1, -8], [395, 1]], goodUn, null, new Uint8Array(32).fill(5))],
    ['signed-by-other', mkR([[1, -8], [395, 1]], goodUn, null, rootB, ED3.priv)],
    ['alg-es-label-ed-sig', mkR([[1, -7], [395, 1]], goodUn, null)],
  ];
  for (const [nm, b] of cr) {
    await add('verifyReceipt', `cr-key-${nm}`, [B(b), B(sts[2]!), { verificationKey: VK(ED2) }]);
    await add('verifyReceipt', `cr-root-${nm}`, [B(b), B(sts[2]!), { treeRoot: r.root }]);
    await add('verifyReceipt', `cr-both-${nm}`, [B(b), B(sts[2]!), { verificationKey: VK(ED2), treeRoot: r.root, statementKey: VK(ED1) }]);
    await add('decodeCoseSign1', `cr-${nm}`, [B(b)]);
  }
}
// ES256 receipts: JS-signed (random), plus a high-S twin
{
  const { ts, sts } = build('ES256', ES2, 5, 'ts.es');
  for (const i of [0, 2, 4]) {
    const r = ts.getReceipt(i);
    const c = M.decodeCoseSign1(r.receipt);
    const s = BigInt('0x' + Buffer.from(c.signature.subarray(32)).toString('hex'));
    const hs = Uint8Array.from(c.signature);
    hs.set(Buffer.from((N256 - s).toString(16).padStart(64, '0'), 'hex'), 32);
    const twin = cose(c.protectedBytes, c.unprotected, c.payload, hs);
    for (const [nm, rb] of [['gen', r.receipt], ['twin', twin]] as any[]) {
      await add('verifyReceipt', `es-${nm}-key-${i}`, [B(rb), B(sts[i]!), { verificationKey: ES2.pub }]);
      await add('verifyReceipt', `es-${nm}-key-allow-${i}`, [B(rb), B(sts[i]!), { verificationKey: ES2.pub, allowHighS: true }]);
      await add('verifyReceipt', `es-${nm}-wrong-${i}`, [B(rb), B(sts[i]!), { verificationKey: ES3.pub }]);
      await add('verifyReceipt', `es-${nm}-ed-${i}`, [B(rb), B(sts[i]!), { verificationKey: ED2.pub }]);
      await add('verifyReceipt', `es-${nm}-root-${i}`, [B(rb), B(sts[i]!), { treeRoot: r.root }]);
    }
  }
  const stEsSigned = stEs({ v: 1 });
  const { ts: ts2 } = build('EdDSA', ED2, 1);
  const rr = ts2.register(stEsSigned);
  await add('verifyReceipt', 'es-stmt-ok', [B(rr.receipt), B(stEsSigned), { verificationKey: ED2.pub, statementKey: ES1.pub }]);
  await add('verifyReceipt', 'es-stmt-wrongkey', [B(rr.receipt), B(stEsSigned), { verificationKey: ED2.pub, statementKey: ES3.pub }]);
}
// ======================================================================================= consistency proofs
for (const [m, n] of [[1, 2], [2, 4], [3, 5], [4, 7], [5, 8], [6, 13], [1, 1], [7, 7], [1, 9], [8, 9], [3, 26]] as any[]) {
  const { ts } = build('EdDSA', ED2, n);
  const cp = ts.consistencyProof(m);
  const t = `m${m}n${n}`;
  await add('verifyConsistencyProof', `ok-${t}`, [B(cp.proof), cp.oldRoot, cp.newRoot]);
  await add('verifyConsistencyProof', `swapped-${t}`, [B(cp.proof), cp.newRoot, cp.oldRoot]);
  await add('verifyConsistencyProof', `badold-${t}`, [B(cp.proof), b64u(new Uint8Array(32)), cp.newRoot]);
  await add('verifyConsistencyProof', `badnew-${t}`, [B(cp.proof), cp.oldRoot, b64u(new Uint8Array(32))]);
  await add('verifyConsistencyProof', `rootenc-${t}`, [B(cp.proof), cp.oldRoot + '=', cp.newRoot]);
  await add('verifyConsistencyProof', `shortroot-${t}`, [B(cp.proof), 'AAAA', cp.newRoot]);
  await add('verifyConsistencyProof', `trunc-${t}`, [B(cp.proof.subarray(0, cp.proof.length - 1)), cp.oldRoot, cp.newRoot]);
  await add('verifyConsistencyProof', `trail-${t}`, [B(Uint8Array.from([...cp.proof, 0])), cp.oldRoot, cp.newRoot]);
  if (cp.proof.length < 120) for (let k = 0; k < cp.proof.length; k++) {
    const c = Uint8Array.from(cp.proof);
    c[k] ^= 0x01;
    await add('verifyConsistencyProof', `flip-${t}-${k}`, [B(c), cp.oldRoot, cp.newRoot]);
  }
}
{
  const h = (i: number) => new Uint8Array(32).fill(i);
  const E = (v: any) => M.encode(v);
  const r = b64u(h(1));
  for (const [nm, v] of [['not-array', 5], ['len2', [1, 2]], ['len4', [1, 2, [], 0]], ['size-str', ['1', 2, []]], ['newsize-str', [1, '2', []]], ['path-not-array', [1, 2, 5]], ['path-str', [1, 2, [5]]],
    ['equal-empty', [3, 3, []]], ['equal-path', [3, 3, [h(1)]]], ['zero-first', [0, 3, [h(1)]]], ['second-lt-first', [4, 3, [h(1)]]], ['empty-path', [1, 3, []]]] as any[]) {
    await add('verifyConsistencyProof', `crafted-${nm}`, [B(E(v)), r, r]);
  }
  await add('verifyConsistencyProof', 'garbage', [B(Uint8Array.of(0xff)), r, r]);
}
// ======================================================================================= services
const stmtFor = (i: number, k = ED1) => B(stEd({ i, note: 'n' + i }, k));
const baseSvc = (kind: string, extra: any = {}) => ({ kind, key: ED2.priv, stmtKey: ED1.priv, ...extra });
const opsA = (n: number) => [...Array.from({ length: n }, (_, i) => ({ op: 'append', payload: { i } })), { op: 'root' }, { op: 'size' }];
const scenarios: [string, any][] = [];
for (const kind of ['memory', 'durable']) {
  scenarios.push([`${kind}-empty`, baseSvc(kind, { ops: [{ op: 'root' }, { op: 'size' }, { op: 'receipt', i: 0 }, { op: 'consistency', m: 1 }, { op: 'consistency', m: 0 }, { op: 'entry', i: 0 }, { op: 'snapshot' }] })]);
  for (const n of [1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17]) {
    const ops: any[] = [...opsA(n)];
    for (const i of n <= 9 ? Array.from({ length: n }, (_, k) => k) : [0, 1, n - 1, Math.floor(n / 2)]) ops.push({ op: 'receipt', i }, { op: 'entry', i });
    for (const m of n <= 9 ? Array.from({ length: n }, (_, k) => k + 1) : [1, 2, n - 1, n, Math.floor(n / 2)]) ops.push({ op: 'consistency', m });
    ops.push({ op: 'receipt', i: n }, { op: 'receipt', i: -1 }, { op: 'receipt', i: 1.5 }, { op: 'consistency', m: n + 1 }, { op: 'consistency', m: 0 }, { op: 'consistency', m: 1.5 }, { op: 'entry', i: n }, { op: 'snapshot' });
    scenarios.push([`${kind}-n${n}`, baseSvc(kind, { ops, ...(n % 2 ? { issuer: 'ts.example' } : {}) })]);
  }
  scenarios.push([`${kind}-register`, baseSvc(kind, { ops: [
    { op: 'register', statement: stmtFor(1) }, { op: 'register', statement: stmtFor(2, ED3) }, { op: 'register', statement: B(Uint8Array.of(1, 2, 3)) },
    { op: 'register', statement: B(mk([[1, -8]], null, 'EdDSA', ED1.priv)) }, { op: 'register', statement: B(new Uint8Array(0)) }, { op: 'register', statement: stmtFor(3) },
    { op: 'register', statement: stmtFor(1) }, { op: 'root' }, { op: 'receipt', i: 0 }, { op: 'receipt', i: 2 }, { op: 'consistency', m: 2 }, { op: 'snapshot' }, { op: 'entry', i: 1 },
  ] })]);
  scenarios.push([`${kind}-subject`, baseSvc(kind, { ops: [{ op: 'append', payload: { a: 1 }, subject: 'grant:1' }, { op: 'append', payload: { a: 2 }, contentType: 'application/json' }, { op: 'append', payload: { f: 1.5 } }, { op: 'append', payload: { s: '\ud800' } }, { op: 'root' }] })]);
}
for (const [nm, fault] of [['drop-leaf', { dropNode: [0, 0] }], ['drop-l1', { dropNode: [1, 0] }], ['short-leaf', { shortNode: [0, 1] }], ['neg-size', { negSize: true }], ['stale', { stale: true }]] as any[]) {
  scenarios.push([`durable-fault-${nm}`, baseSvc('durable', { storeFault: fault, ops: [...opsA(3), { op: 'receipt', i: 0 }, { op: 'consistency', m: 1 }, { op: 'entry', i: 0 }] })]);
}
for (const [nm, spec] of scenarios) await add('service', nm, [spec]);
// the service reference: one scenario run, results per op
const runService = async (spec: any) => {
  const key = toKey(spec.key, true);
  const alg = spec.key.alg;
  const base: any = { alg, key, ...(spec.issuer !== undefined ? { issuer: spec.issuer } : {}) };
  let svc: any;
  if (spec.kind === 'memory') svc = new TransparencyService(base);
  else {
    const inner = new MemoryScittLogStore();
    const f = spec.storeFault;
    const store: any = f
      ? {
          size: async () => (f.negSize ? -1 : inner.size()),
          getEntry: (i: number) => inner.getEntry(i),
          getNode: async (l: number, i: number) => {
            if (f.dropNode && f.dropNode[0] === l && f.dropNode[1] === i) return undefined;
            if (f.shortNode && f.shortNode[0] === l && f.shortNode[1] === i) return new Uint8Array(31);
            return inner.getNode(l, i);
          },
          append: async (n: number, e: Uint8Array, nodes: any) => (f.stale ? false : inner.append(n, e, nodes)),
        }
      : inner;
    svc = new M.DurableTransparencyService({ store, ...base });
  }
  const stmtOpts = (op: any) => sOpts({ alg: 'EdDSA', key: spec.stmtKey, issuer: 'https://issuer.example', subject: op.subject, contentType: op.contentType });
  const res: any[] = [];
  for (const op of spec.ops) {
    try {
      let v: any;
      switch (op.op) {
        case 'append': v = await svc.appendAndReceipt(op.payload, stmtOpts(op)); break;
        case 'register': v = await svc.register(un(op.statement)); break;
        case 'receipt': v = await svc.getReceipt(op.i); break;
        case 'consistency': v = await svc.consistencyProof(op.m); break;
        case 'entry': v = await svc.getEntry(op.i); break;
        case 'snapshot': v = svc.snapshot(); break;
        case 'root': v = typeof svc.root === 'function' ? await svc.root() : svc.root; break;
        case 'size': v = typeof svc.size === 'function' ? await svc.size() : svc.size; break;
        default: throw new Error('op');
      }
      res.push({ ok: v });
    } catch (e: any) {
      res.push({ err: e && typeof e.code === 'string' ? e.code : true });
    }
  }
  return res;
};
REF.service = runService;
// (the loop above registered the scenarios before REF.service existed: re-run them now)
o.cases = o.cases.filter((c: any) => c.fn !== 'service');
o.names = new Set([...o.names].filter((n: string) => !n.startsWith('service/')));
o.seen = new Set([...o.seen].filter((n: string) => !n.startsWith('service\u0000')));
for (const [nm, spec] of scenarios) await add('service', nm, [spec]);
// ======================================================================================= file store
const tmp = mkdtempSync(join(tmpdir(), 'scitt-oracle-'));
let tmpN = 0;
const fileOps = async (ops: any[]): Promise<Uint8Array> => {
  const p = join(tmp, `f${tmpN++}.log`);
  const s = M.FileScittLogStore.open(p);
  try {
    for (const op of ops) {
      const nodes = op.nodes.map((n: any) => ({ level: n[0], index: n[1], hash: bytes(n[2]) }));
      try {
        await s.append(op.expected, un(op.entry), nodes);
      } catch {
        /* a refused / malformed append: nothing is written */
      }
    }
  } finally {
    s.close();
  }
  return new Uint8Array(readFileSync(p));
};
const fileOpen = async (fileBytes: any): Promise<any> => {
  const p = join(tmp, `o${tmpN++}.log`);
  writeFileSync(p, un(fileBytes));
  const s = M.FileScittLogStore.open(p);
  try {
    const size = await s.size();
    const entries: any[] = [];
    const nodes0: any[] = [];
    for (let i = 0; i < size; i++) {
      entries.push(await s.getEntry(i));
      nodes0.push((await s.getNode(0, i)) ?? null);
    }
    return { size, entries, nodes0, after: new Uint8Array(readFileSync(p)) };
  } finally {
    s.close();
  }
};
const checkStore = async (kind: string) => {
  if (kind === 'memory') return M.checkScittLogStore ? M.checkScittLogStore(() => new MemoryScittLogStore()) : null;
  let n = 0;
  return M.checkScittLogStore(() => M.FileScittLogStore.open(join(tmp, `c${n++}.log`)));
};
REF.fileStoreBytes = fileOps;
REF.fileStoreOpen = fileOpen;
REF.checkScittLogStore = checkStore;
const hh = (i: number) => b64u(new Uint8Array(32).fill(i));
const fileSeqs: [string, any[]][] = [
  ['one', [{ expected: 0, entry: B(Uint8Array.of(1, 2, 3)), nodes: [[0, 0, hh(1)]] }]],
  ['three', [
    { expected: 0, entry: B(Uint8Array.of(1)), nodes: [[0, 0, hh(1)]] },
    { expected: 1, entry: B(Uint8Array.of(2, 2)), nodes: [[0, 1, hh(2)], [1, 0, hh(3)]] },
    { expected: 2, entry: B(new Uint8Array(0)), nodes: [[0, 2, hh(4)]] },
  ]],
  ['stale-skipped', [
    { expected: 0, entry: B(Uint8Array.of(1)), nodes: [[0, 0, hh(1)]] },
    { expected: 0, entry: B(Uint8Array.of(9)), nodes: [[0, 0, hh(9)]] },
    { expected: 1, entry: B(Uint8Array.of(2)), nodes: [[0, 1, hh(2)]] },
  ]],
  ['malformed-skipped', [
    { expected: 0, entry: B(Uint8Array.of(1)), nodes: [[0, 0, b64u(new Uint8Array(31))]] },
    { expected: 0, entry: B(Uint8Array.of(1)), nodes: [[256, 0, hh(1)]] },
    { expected: 0, entry: B(Uint8Array.of(1)), nodes: [[0, 2 ** 32, hh(1)]] },
    { expected: 0, entry: B(Uint8Array.of(1)), nodes: [[-1, 0, hh(1)]] },
    { expected: 0, entry: B(Uint8Array.of(7)), nodes: [[255, 4294967295, hh(7)]] },
  ]],
  ['big-entry', [{ expected: 0, entry: B(new Uint8Array(300).fill(5)), nodes: [[0, 0, hh(1)]] }, { expected: 1, entry: B(Uint8Array.of(1)), nodes: [] }]],
];
const fileBlobs: Uint8Array[] = [];
for (const [nm, ops] of fileSeqs) {
  await add('fileStoreBytes', nm, [ops]);
  fileBlobs.push(await fileOps(ops));
}
for (const [bi, blob] of fileBlobs.entries()) {
  await add('fileStoreOpen', `ok${bi}`, [B(blob)]);
  const cuts = [1, 3, 4, 5, 20, 33, 36, 37, 40, blob.length - 33, blob.length - 1, blob.length - 40];
  for (const k of cuts) if (k > 0 && k < blob.length) await add('fileStoreOpen', `trunc${bi}-${k}`, [B(blob.subarray(0, k))]);
  for (const k of [0, 3, 4, 5, 10, Math.floor(blob.length / 2), blob.length - 33, blob.length - 1]) {
    if (k < 0 || k >= blob.length) continue;
    const c = Uint8Array.from(blob);
    c[k] ^= 0x01;
    await add('fileStoreOpen', `flip${bi}-${k}`, [B(c)]);
  }
  await add('fileStoreOpen', `trail${bi}`, [B(Uint8Array.from([...blob, 0, 0, 0, 9]))]);
  await add('fileStoreOpen', `junk${bi}`, [B(Uint8Array.from([...blob, ...new Uint8Array(50).fill(3)]))]);
}
await add('fileStoreOpen', 'empty', [B(new Uint8Array(0))]);
await add('fileStoreOpen', 'tiny', [B(Uint8Array.of(0, 0))]);
await add('fileStoreOpen', 'zeros', [B(new Uint8Array(100))]);
{
  // a record with a valid checksum but an inconsistent length / count
  const payload = Buffer.alloc(8);
  payload.writeUInt32BE(1, 0);
  payload[4] = 9;
  payload.writeUInt16BE(1, 5); // claims one node but carries none
  const rec = Buffer.concat([Buffer.from([0, 0, 0, payload.length]), payload, createHash('sha256').update(payload).digest()]);
  await add('fileStoreOpen', 'inconsistent-count', [B(new Uint8Array(rec))]);
}
await add('checkScittLogStore', 'memory', ['memory']);
await add('checkScittLogStore', 'file', ['file']);
await add('constants', 'all', []);
rmSync(tmp, { recursive: true, force: true });
refWrite(o, 'scitt');
