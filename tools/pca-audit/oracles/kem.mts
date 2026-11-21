// Oracle: every export of packages/pca/src/kem.ts (hybrid X25519 + ML-KEM-768 / -1024 KEM, X-Wing draft-09, ML-KEM key checks), TS reference.
// Writes out/ref-kem.json.gz. Deterministic: every key and every piece of randomness derives from a label, and the randomised entry points are
// pinned by feeding the reference a fixed random stream (the case carries the stream; the reference's draw order is asserted below).
// Case shape (as every sibling): {fn, name, args, out}; `out` is what the reference returned, or {"$throws": message}. A reference throw means the
// native refuses (message text is JS-specific and not compared).
//
// ARGUMENT FORMS (corpus -> value)
//   {"$bytes": b64url}                     literal bytes (public keys, ciphertexts, public vectors)
//   {"$bytes": {"$seed": label}}           32 bytes = sha256("atlas-pca-conformance/" + label)  (a secret, never committed as bytes)
//   rng: [part, ...]                       the random stream: the parts are concatenated; the native feeds them to its derandomised entry point in the order below
//   {"$hybridSk": {level, x, d, z, trim?, pad?, set?}}   a hybrid secret key built by the lane: x = X25519 secret (32 bytes), d and z = the ML-KEM seed halves
//                                          (32 bytes each; ML-KEM keygen seed = d || z); sk = x || expandedDecapsulationKey(level, d || z)  (2400 bytes at 768,
//                                          3168 at 1024); then trim = drop the last `trim` bytes, pad = append `pad` zero bytes, set = [[offset, byte], ...]
//   {"$mlkemDk": {level, d, z, set?, rehash?}}   an ML-KEM expanded decapsulation key from the seed d || z; set = [[offset, byte], ...] applied afterwards;
//                                          rehash = then rewrite the embedded H(ek) (dk[768k+32 .. 768k+64]) to sha3-256 of the (modified) embedded ek
//   {"$num": ...} is not used here.
// PORTING (fn(args) -> native entry point; results compared by JSON value). "rng" cases exist because the reference draws from the platform CSPRNG: the
// native needs a test-visible derandomised form taking the same bytes in the same order.
//   constants []                                         -> {NAME: value} for every exported constant (XWING_LABEL as bytes)
//   hybridKemKeygen [rng]            rng = xSecret(32) || d(32) || z(32)         -> {publicKey, secretKeySha256 (hex of sha256(secretKey)), secretKeyLen}
//   hybridKem1024Keygen [rng]        same layout, ML-KEM-1024                    -> same
//   hybridEncapsulate / hybridEncapsulate1024 [publicKey, rng]   rng = ephemeralX25519Secret(32) || m(32)   -> {ciphertext, sharedSecret}
//   hybridDecapsulate / hybridDecapsulate1024 [ciphertext, secretKey]   -> shared secret (bytes)
//   xwingKeygen [seed]                                   -> {publicKey, secretKeySha256, secretKeyLen} (the secret key IS the seed)
//   xwingEncapsulateDerand [publicKey, eseed]            -> {ciphertext, sharedSecret}  (eseed = m(32) || ephemeralX25519Secret(32); note the order differs from the hybrid)
//   xwingEncapsulate [publicKey, rng]   rng = eseed (64 bytes drawn in one call) -> {ciphertext, sharedSecret}
//   xwingDecapsulate [ciphertext, seed]                  -> shared secret (bytes)
//   encode*/decode* [value]                              -> string / bytes (b64url, no padding; decode refuses anything but canonical-alphabet input)
//   mlKemEncapsulationKeyCheck [level, ek] -> bool       mlKemDecapsulationKeyCheck [level, dk] -> bool   (never throw for a valid level; an unknown level throws)
// Not covered: the no-argument random calls (hybridKemKeygen(), xwingKeygen(), xwingEncapsulate(pk) with the platform CSPRNG): the native tests round-trip them
// (keygen -> encapsulate -> decapsulate agree; two calls differ).
import { createHash } from 'node:crypto';
import { Oracle, refWrite, seed, capture } from './lib.mjs';
import { sha3_256 } from '@noble/hashes/sha3.js';

const K0: any = await import('../../../packages/pca/src/kem.ts');
const K: any = K0.default ?? K0;
const o = new Oracle('kem', 'tools/pca-audit/oracles/kem.mts', 'TS-reference oracle for packages/pca/src/kem.ts (hybrid X25519 + ML-KEM-768/1024, X-Wing draft-09, ML-KEM FIPS 203 key checks).');

const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64url');
const B = (u: Uint8Array) => ({ $bytes: b64(u) });
const SD = (l: string) => ({ $bytes: { $seed: l } }); // secret by label
const sd = (l: string) => seed(l);
const cat = (...p: Uint8Array[]) => { const r = new Uint8Array(p.reduce((a, x) => a + x.length, 0)); let q = 0; for (const x of p) { r.set(x, q); q += x.length; } return r; };
const hex = (s: string) => new Uint8Array(Buffer.from(s, 'hex'));
const sha256hex = (u: Uint8Array) => createHash('sha256').update(u).digest('hex');
let st = 0x6b656d; // tiny deterministic filler for public non-secret garbage
const garbage = (n: number) => Uint8Array.from({ length: n }, () => { st = (Math.imul(st, 1103515245) + 12345) >>> 0; return st >>> 24; });

/** Run fn with the platform CSPRNG replaced by `bytes` (drawn in order). Returns [result, consumed]. */
function withRng(bytes: Uint8Array, fn: () => any): { r: any; used: number } {
  const c: any = globalThis.crypto;
  const orig = c.getRandomValues;
  let off = 0;
  c.getRandomValues = (a: Uint8Array) => { if (off + a.length > bytes.length) throw new Error('test rng exhausted'); a.set(bytes.subarray(off, off + a.length)); off += a.length; return a; };
  try { return { r: fn(), used: off }; } finally { c.getRandomValues = orig; }
}
/** Add a case whose `out` is the reference result with the stream pinned; fail the generator if a successful call did not use the whole stream. */
async function addRng(fn: string, name: string, jsonArgs: any[], stream: Uint8Array, call: () => any) {
  let used = -1;
  const out = await capture(() => { const x = withRng(stream, call); used = x.used; return x.r; }, []);
  if (!('$throws' in out) && used !== stream.length) throw new Error(`${fn}/${name}: reference drew ${used} of ${stream.length} stream bytes`);
  o.add(fn, name, jsonArgs, out);
}
async function addCall(fn: string, name: string, jsonArgs: any[], call: () => any) { o.add(fn, name, jsonArgs, await capture(call, [])); }

// ---- constants
const CONSTS = ['HYBRID_PUBLIC_KEY_LEN', 'HYBRID_CIPHERTEXT_LEN', 'HYBRID_SHARED_SECRET_LEN', 'HYBRID_KEM_SUITE', 'XWING_SUITE', 'XWING_SEED_LEN', 'XWING_SECRET_KEY_LEN',
  'XWING_PUBLIC_KEY_LEN', 'XWING_CIPHERTEXT_LEN', 'XWING_SHARED_SECRET_LEN', 'XWING_ESEED_LEN', 'XWING_LABEL', 'HYBRID1024_PUBLIC_KEY_LEN', 'HYBRID1024_CIPHERTEXT_LEN',
  'HYBRID1024_SHARED_SECRET_LEN', 'HYBRID1024_KEM_SUITE'];
await addCall('constants', 'all', [], () => Object.fromEntries(CONSTS.map((n) => [n, K[n]])));

// ---- suites
interface Suite { id: '768' | '1024'; keygenFn: string; encFn: string; decFn: string; keygen: () => any; enc: (pk: Uint8Array) => any; dec: (ct: Uint8Array, sk: Uint8Array) => any; pkLen: number; ctLen: number; mlPk: number; k: number; dkLen: number }
const S768: Suite = { id: '768', keygenFn: 'hybridKemKeygen', encFn: 'hybridEncapsulate', decFn: 'hybridDecapsulate', keygen: K.hybridKemKeygen, enc: K.hybridEncapsulate, dec: K.hybridDecapsulate, pkLen: 1216, ctLen: 1120, mlPk: 1184, k: 3, dkLen: 2400 };
const S1024: Suite = { id: '1024', keygenFn: 'hybridKem1024Keygen', encFn: 'hybridEncapsulate1024', decFn: 'hybridDecapsulate1024', keygen: K.hybridKem1024Keygen, enc: K.hybridEncapsulate1024, dec: K.hybridDecapsulate1024, pkLen: 1600, ctLen: 1600, mlPk: 1568, k: 4, dkLen: 3168 };

interface Key { label: string; x: Uint8Array; d: Uint8Array; z: Uint8Array; pk: Uint8Array; sk: Uint8Array }
const keyOf = (s: Suite, label: string): Key => {
  const x = sd(`kem/${s.id}/${label}/x`), d = sd(`kem/${s.id}/${label}/d`), z = sd(`kem/${s.id}/${label}/z`);
  const { r } = withRng(cat(x, d, z), () => s.keygen());
  if (r.secretKey.length !== 32 + s.dkLen) throw new Error('unexpected hybrid secret key length');
  return { label, x, d, z, pk: r.publicKey, sk: r.secretKey };
};
const skForm = (s: Suite, k: Key, extra: any = {}) => ({ $hybridSk: { level: s.id, x: SD(`kem/${s.id}/${k.label}/x`), d: SD(`kem/${s.id}/${k.label}/d`), z: SD(`kem/${s.id}/${k.label}/z`), ...extra } });
const applySet = (u: Uint8Array, set: [number, number][]) => { const r = Uint8Array.from(u); for (const [off, v] of set) r[off] = v; return r; };

// X25519 low-order points (the encapsulation / decapsulation must refuse a degenerate shared secret)
const LOW = [new Uint8Array(32), Uint8Array.from([1, ...new Uint8Array(31)]),
  hex('e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800'), hex('5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157')];

for (const s of [S768, S1024]) {
  const level = s.id;
  const A = keyOf(s, 'a'), Bk = keyOf(s, 'b');
  // keygen (rng = x || d || z)
  for (const [name, parts] of [['a', [A.x, A.d, A.z]], ['b', [Bk.x, Bk.d, Bk.z]], ['seed3', [sd(`kem/${level}/kg3/x`), sd(`kem/${level}/kg3/d`), sd(`kem/${level}/kg3/z`)]],
    ['zeros', [new Uint8Array(32), new Uint8Array(32), new Uint8Array(32)]], ['ones', [new Uint8Array(32).fill(0xff), new Uint8Array(32).fill(0xff), new Uint8Array(32).fill(0xff)]]] as [string, Uint8Array[]][]) {
    const lab = name === 'a' || name === 'b' ? name : null;
    const jsonRng = lab ? [SD(`kem/${level}/${lab}/x`), SD(`kem/${level}/${lab}/d`), SD(`kem/${level}/${lab}/z`)] : name === 'seed3' ? [SD(`kem/${level}/kg3/x`), SD(`kem/${level}/kg3/d`), SD(`kem/${level}/kg3/z`)] : parts.map(B);
    await addRng(s.keygenFn, name, [jsonRng], cat(...parts), () => { const k = s.keygen(); return { publicKey: k.publicKey, secretKeySha256: sha256hex(k.secretKey), secretKeyLen: k.secretKey.length }; });
  }

  // encapsulate (rng = eph || m)
  const encCase = async (name: string, pk: Uint8Array, eph: Uint8Array, m: Uint8Array, jsonRng: any[]) =>
    addRng(s.encFn, name, [B(pk), jsonRng], cat(eph, m), () => s.enc(pk));
  const ephA = sd(`kem/${level}/e1/eph`), mA = sd(`kem/${level}/e1/m`);
  const ephB = sd(`kem/${level}/e2/eph`), mB = sd(`kem/${level}/e2/m`);
  await encCase('a-1', A.pk, ephA, mA, [SD(`kem/${level}/e1/eph`), SD(`kem/${level}/e1/m`)]);
  await encCase('a-2', A.pk, ephB, mB, [SD(`kem/${level}/e2/eph`), SD(`kem/${level}/e2/m`)]);
  await encCase('b-1', Bk.pk, ephA, mA, [SD(`kem/${level}/e1/eph`), SD(`kem/${level}/e1/m`)]);
  await encCase('zeros', A.pk, new Uint8Array(32), new Uint8Array(32), [B(new Uint8Array(32)), B(new Uint8Array(32))]);
  await encCase('ones', A.pk, new Uint8Array(32).fill(0xff), new Uint8Array(32).fill(0xff), [B(new Uint8Array(32).fill(0xff)), B(new Uint8Array(32).fill(0xff))]);
  const g = (n: number) => garbage(n);
  // refusals: length, low-order X25519, non-reduced ML-KEM coefficient
  const rngZ = [B(new Uint8Array(32).fill(7)), B(new Uint8Array(32).fill(9))], strZ = cat(new Uint8Array(32).fill(7), new Uint8Array(32).fill(9));
  for (const [nm, pk] of [['len0', new Uint8Array()], ['len-1', A.pk.subarray(0, s.pkLen - 1)], ['len+1', cat(A.pk, Uint8Array.of(0))], ['len32', A.pk.subarray(0, 32)],
    ['other-level', keyOf(s === S768 ? S1024 : S768, 'a').pk]] as [string, Uint8Array][])
    await addRng(s.encFn, `refuse-${nm}`, [B(pk), rngZ], strZ, () => s.enc(pk));
  for (const [i, lo] of LOW.entries()) await addRng(s.encFn, `refuse-lowx-${i}`, [B(cat(lo, A.pk.subarray(32))), rngZ], strZ, () => s.enc(cat(lo, A.pk.subarray(32))));
  for (const [nm, set] of [['coef0-4095', [[32, 0xff], [33, 0x0f]]], ['coef0-3329', [[32, 0x01], [33, 0x0d]]], ['coef0-3328-ok', [[32, 0x00], [33, 0x0d]]], ['coef1-3329', [[33, 0x10], [34, 0xd0]]],
    ['coef-last-4095', [[32 + 384 * s.k - 2, 0xff], [32 + 384 * s.k - 1, 0xff]]]] as [string, [number, number][]][]) {
    const pk = applySet(A.pk, set);
    await addRng(s.encFn, `modcheck-${nm}`, [B(pk), rngZ], strZ, () => s.enc(pk));
  }
  { const pk = cat(A.pk.subarray(0, 32), new Uint8Array(s.mlPk)); await addRng(s.encFn, 'mlkem-pk-zero', [B(pk), rngZ], strZ, () => s.enc(pk)); }
  { // the rho / tail bytes are not part of the modulus check
    const pk = applySet(A.pk, [[A.pk.length - 1, A.pk[A.pk.length - 1]! ^ 0xff]]); await addRng(s.encFn, 'rho-flip', [B(pk), rngZ], strZ, () => s.enc(pk)); }
  await addCall(s.encFn, 'null-pk', [null, rngZ], () => s.enc(null as any));

  // decapsulate
  const mk = (k: Key, e: Uint8Array, m: Uint8Array, ss: Suite = s) => withRng(cat(e, m), () => ss.enc(k.pk)).r;
  const eA = mk(A, ephA, mA), eB = mk(Bk, ephB, mB);
  const dec = async (name: string, ct: Uint8Array, skJson: any, sk: Uint8Array) => addCall(s.decFn, name, [B(ct), skJson], () => s.dec(ct, sk));
  await dec('a-ok', eA.ciphertext, skForm(s, A), A.sk);
  await dec('b-ok', eB.ciphertext, skForm(s, Bk), Bk.sk);
  await dec('wrong-key', eA.ciphertext, skForm(s, Bk), Bk.sk); // implicit rejection (ML-KEM) and a different X25519 secret
  const flip = (u: Uint8Array, i: number, v = 1) => { const r = Uint8Array.from(u); r[i] = r[i]! ^ v; return r; };
  for (const [nm, i] of [['eph-0', 0], ['eph-31', 31], ['mlct-0', 32], ['mlct-mid', 32 + 500], ['mlct-last', s.ctLen - 1]] as [string, number][])
    await dec(`tamper-${nm}`, flip(eA.ciphertext, i), skForm(s, A), A.sk);
  for (const [i, lo] of LOW.entries()) await dec(`lowx-${i}`, cat(lo, eA.ciphertext.subarray(32)), skForm(s, A), A.sk);
  await dec('ct-zero', new Uint8Array(s.ctLen), skForm(s, A), A.sk);
  for (const [nm, ct] of [['len0', new Uint8Array()], ['len-1', eA.ciphertext.subarray(0, s.ctLen - 1)], ['len+1', cat(eA.ciphertext, Uint8Array.of(0))], ['other-level', mk(keyOf(s === S768 ? S1024 : S768, 'a'), ephA, mA, s === S768 ? S1024 : S768).ciphertext]] as [string, Uint8Array][])
    await dec(`refuse-ct-${nm}`, ct, skForm(s, A), A.sk);
  for (const [nm, n] of [['len0', 0], ['len1', 1], ['len32', 32]] as [string, number][]) { const sk = g(n); await addCall(s.decFn, `refuse-sk-${nm}`, [B(eA.ciphertext), B(sk)], () => s.dec(eA.ciphertext, sk)); }
  for (const [nm, ex, sk] of [['trim1', { trim: 1 }, A.sk.subarray(0, A.sk.length - 1)], ['pad1', { pad: 1 }, cat(A.sk, Uint8Array.of(0))], ['trim-mlkem', { trim: s.dkLen }, A.sk.subarray(0, 32)],
    ['only-x+1', { trim: s.dkLen - 1 }, A.sk.subarray(0, 33)]] as [string, any, Uint8Array][])
    await dec(`refuse-sk-${nm}`, eA.ciphertext, skForm(s, A, ex), sk);
  { // a decapsulation key with a damaged decryption half: the FIPS 203 algorithm re-encrypts, mismatches and answers the implicit-rejection secret
    const set: [number, number][] = [[32 + 10, A.sk[32 + 10]! ^ 0x55]];
    await dec('dkpke-damaged', eA.ciphertext, skForm(s, A, { set }), applySet(A.sk, set)); }
  { // damaged z with a tampered ciphertext: the rejection secret is J(z || c)
    const off = A.sk.length - 1; const set: [number, number][] = [[off, A.sk[off]! ^ 0xa5]]; const ct = flip(eA.ciphertext, 40);
    await dec('z-damaged-tamper', ct, skForm(s, A, { set }), applySet(A.sk, set)); }
  { const ct = flip(eA.ciphertext, 40); await dec('tamper-implicit-reject', ct, skForm(s, A), A.sk); }
  await addCall(s.decFn, 'null-ct', [null, skForm(s, A)], () => s.dec(null as any, A.sk));
  await addCall(s.decFn, 'null-sk', [B(eA.ciphertext), null], () => s.dec(eA.ciphertext, null as any));

  // key checks (ML-KEM level, this suite)
  const lv = Number(level);
  const ekOf = (k: Key) => k.pk.subarray(32);
  const ek = ekOf(A);
  const dkOf = (d: Uint8Array, z: Uint8Array) => { const { r } = withRng(cat(new Uint8Array(32), d, z), () => s.keygen()); return r.secretKey.subarray(32) as Uint8Array; };
  const dk = dkOf(A.d, A.z);
  if (dk.length !== s.dkLen) throw new Error('dk length');
  await addCall('mlKemEncapsulationKeyCheck', `${level}-valid`, [lv, B(ek)], () => K.mlKemEncapsulationKeyCheck(lv, ek));
  await addCall('mlKemEncapsulationKeyCheck', `${level}-valid-b`, [lv, B(ekOf(Bk))], () => K.mlKemEncapsulationKeyCheck(lv, ekOf(Bk)));
  await addCall('mlKemEncapsulationKeyCheck', `${level}-zero`, [lv, B(new Uint8Array(ek.length))], () => K.mlKemEncapsulationKeyCheck(lv, new Uint8Array(ek.length)));
  for (const [nm, e] of [['len0', new Uint8Array()], ['len-1', ek.subarray(0, ek.length - 1)], ['len+1', cat(ek, Uint8Array.of(0))], ['other-level', ekOf(keyOf(s === S768 ? S1024 : S768, 'a'))]] as [string, Uint8Array][])
    await addCall('mlKemEncapsulationKeyCheck', `${level}-${nm}`, [lv, B(e)], () => K.mlKemEncapsulationKeyCheck(lv, e));
  const coef = (i: number, v: number) => { // set coefficient i (0-based, 12 bits) to v, keep its pair
    const r = Uint8Array.from(ek); const o2 = Math.floor(i / 2) * 3;
    if (i % 2 === 0) { r[o2] = v & 0xff; r[o2 + 1] = (r[o2 + 1]! & 0xf0) | (v >> 8); } else { r[o2 + 1] = (r[o2 + 1]! & 0x0f) | ((v & 0xf) << 4); r[o2 + 2] = v >> 4; }
    return r;
  };
  const NC = 256 * s.k;
  for (const [nm, i, v] of [['c0-3328', 0, 3328], ['c0-3329', 0, 3329], ['c0-4095', 0, 4095], ['c1-3328', 1, 3328], ['c1-3329', 1, 3329], ['c1-4095', 1, 4095], ['clast-3329', NC - 1, 3329],
    ['clast-3328', NC - 1, 3328], ['cmid-3329', 300, 3329], ['cmid-odd-3329', 301, 3329]] as [string, number, number][]) {
    const e = coef(i, v); await addCall('mlKemEncapsulationKeyCheck', `${level}-${nm}`, [lv, B(e)], () => K.mlKemEncapsulationKeyCheck(lv, e));
  }
  { const e = Uint8Array.from(ek); e[ek.length - 1] ^= 0xff; await addCall('mlKemEncapsulationKeyCheck', `${level}-rho-flip`, [lv, B(e)], () => K.mlKemEncapsulationKeyCheck(lv, e)); }
  await addCall('mlKemEncapsulationKeyCheck', `${level}-null`, [lv, null], () => K.mlKemEncapsulationKeyCheck(lv, null));
  await addCall('mlKemEncapsulationKeyCheck', `${level}-string`, [lv, 'abc'], () => K.mlKemEncapsulationKeyCheck(lv, 'abc'));

  const dkForm = (extra: any = {}) => ({ $mlkemDk: { level: lv, d: SD(`kem/${level}/a/d`), z: SD(`kem/${level}/a/z`), ...extra } });
  const dkMod = (set: [number, number][], rehash: boolean) => {
    const r = applySet(dk, set);
    if (rehash) r.set(sha3_256(r.subarray(384 * s.k, 768 * s.k + 32)), 768 * s.k + 32);
    return r;
  };
  const dkCase = async (nm: string, jsonDk: any, bytes: Uint8Array) => addCall('mlKemDecapsulationKeyCheck', `${level}-${nm}`, [lv, jsonDk], () => K.mlKemDecapsulationKeyCheck(lv, bytes));
  await dkCase('valid', dkForm(), dk);
  await dkCase('valid-b', { $mlkemDk: { level: lv, d: SD(`kem/${level}/b/d`), z: SD(`kem/${level}/b/z`) } }, dkOf(Bk.d, Bk.z));
  const ekOff = 384 * s.k, hOff = 768 * s.k + 32;
  await dkCase('dkpke-flip', dkForm({ set: [[5, dk[5]! ^ 1]] }), dkMod([[5, dk[5]! ^ 1]], false)); // the decryption half is not covered by the check
  await dkCase('z-flip', dkForm({ set: [[dk.length - 1, dk[dk.length - 1]! ^ 1]] }), dkMod([[dk.length - 1, dk[dk.length - 1]! ^ 1]], false));
  await dkCase('h-flip', dkForm({ set: [[hOff, dk[hOff]! ^ 1]] }), dkMod([[hOff, dk[hOff]! ^ 1]], false));
  await dkCase('h-last-flip', dkForm({ set: [[hOff + 31, dk[hOff + 31]! ^ 0x80]] }), dkMod([[hOff + 31, dk[hOff + 31]! ^ 0x80]], false));
  await dkCase('ek-flip-nohash', dkForm({ set: [[ekOff + 3, dk[ekOff + 3]! ^ 1]] }), dkMod([[ekOff + 3, dk[ekOff + 3]! ^ 1]], false));
  await dkCase('ek-rho-flip-nohash', dkForm({ set: [[hOff - 1, dk[hOff - 1]! ^ 1]] }), dkMod([[hOff - 1, dk[hOff - 1]! ^ 1]], false));
  await dkCase('ek-rho-flip-rehash', dkForm({ set: [[hOff - 1, dk[hOff - 1]! ^ 1]], rehash: true }), dkMod([[hOff - 1, dk[hOff - 1]! ^ 1]], true));
  await dkCase('ek-coef-4095-rehash', dkForm({ set: [[ekOff, 0xff], [ekOff + 1, 0x0f]], rehash: true }), dkMod([[ekOff, 0xff], [ekOff + 1, 0x0f]], true));
  await dkCase('ek-coef-3329-rehash', dkForm({ set: [[ekOff, 0x01], [ekOff + 1, 0x0d]], rehash: true }), dkMod([[ekOff, 0x01], [ekOff + 1, 0x0d]], true));
  await dkCase('ek-coef-3328-rehash', dkForm({ set: [[ekOff, 0x00], [ekOff + 1, 0x0d]], rehash: true }), dkMod([[ekOff, 0x00], [ekOff + 1, 0x0d]], true));
  await dkCase('ek-coef-4095-nohash', dkForm({ set: [[ekOff, 0xff], [ekOff + 1, 0x0f]] }), dkMod([[ekOff, 0xff], [ekOff + 1, 0x0f]], false));
  for (const [nm, n] of [['len0', 0], ['len-1', dk.length - 1], ['len+1', dk.length + 1], ['len-ek', s.mlPk]] as [string, number][]) { const x = garbage(n); await addCall('mlKemDecapsulationKeyCheck', `${level}-${nm}`, [lv, B(x)], () => K.mlKemDecapsulationKeyCheck(lv, x)); }
  await addCall('mlKemDecapsulationKeyCheck', `${level}-zeros`, [lv, B(new Uint8Array(dk.length))], () => K.mlKemDecapsulationKeyCheck(lv, new Uint8Array(dk.length)));
  await addCall('mlKemDecapsulationKeyCheck', `${level}-null`, [lv, null], () => K.mlKemDecapsulationKeyCheck(lv, null));
}
// cross-level and unknown level
{
  const A7 = keyOf(S768, 'a'), A10 = keyOf(S1024, 'a');
  const ek7 = A7.pk.subarray(32), ek10 = A10.pk.subarray(32);
  await addCall('mlKemEncapsulationKeyCheck', 'x-768-key-at-1024', [1024, B(ek7)], () => K.mlKemEncapsulationKeyCheck(1024, ek7));
  await addCall('mlKemEncapsulationKeyCheck', 'x-1024-key-at-768', [768, B(ek10)], () => K.mlKemEncapsulationKeyCheck(768, ek10));
  for (const lvl of [512, 0, '768', null, 1025] as any[]) {
    await addCall('mlKemEncapsulationKeyCheck', `level-${String(lvl)}`, [lvl, B(ek7)], () => K.mlKemEncapsulationKeyCheck(lvl, ek7));
    await addCall('mlKemDecapsulationKeyCheck', `level-${String(lvl)}`, [lvl, B(new Uint8Array(2400))], () => K.mlKemDecapsulationKeyCheck(lvl, new Uint8Array(2400)));
  }
}

// ---- X-Wing
const XW = [
  { seed: '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26', eseed: '3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2', ss: 'd2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384' },
  { seed: 'badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea', eseed: '17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdefaee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32d', ss: 'f2e86241c64d60f6649fbc6c5b7d17180b780a3f34355e64a85749949c45f150' },
  { seed: 'ef58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c9', eseed: '22a96188d032675c8ac850933c7aff1533b94c834adbb69c6115bad4692d8619f90b0cdf8a7b9c264029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b', ss: '953f7f4e8c5b5049bdc771d1dffada0dd961477d1a2ae0988baa7ea6898d893f' },
];
const xw = (seedB: Uint8Array) => K.xwingKeygen(seedB);
// draft-connolly-cfrg-xwing-kem-09 Appendix C known answers: cross-check the reference here, then the corpus carries them for every lane
for (const [i, v] of XW.entries()) {
  const kp = xw(hex(v.seed)), e = K.xwingEncapsulateDerand(kp.publicKey, hex(v.eseed));
  if (Buffer.from(e.sharedSecret).toString('hex') !== v.ss) throw new Error('X-Wing KAT mismatch ' + i);
  if (Buffer.from(K.xwingDecapsulate(e.ciphertext, hex(v.seed))).toString('hex') !== v.ss) throw new Error('X-Wing KAT decapsulation mismatch ' + i);
}
const xwLabels = ['a', 'b'];
interface XKey { jsonSeed: any; seedBytes: Uint8Array; pk: Uint8Array; tag: string }
const xkeys: XKey[] = [
  ...XW.map((v, i) => ({ jsonSeed: B(hex(v.seed)), seedBytes: hex(v.seed), pk: xw(hex(v.seed)).publicKey, tag: `kat${i}` })),
  ...xwLabels.map((l) => ({ jsonSeed: SD(`kem/xwing/${l}`), seedBytes: sd(`kem/xwing/${l}`), pk: xw(sd(`kem/xwing/${l}`)).publicKey, tag: l })),
  { jsonSeed: B(new Uint8Array(32)), seedBytes: new Uint8Array(32), pk: xw(new Uint8Array(32)).publicKey, tag: 'zero' },
  { jsonSeed: B(new Uint8Array(32).fill(0xff)), seedBytes: new Uint8Array(32).fill(0xff), pk: xw(new Uint8Array(32).fill(0xff)).publicKey, tag: 'ones' },
];
for (const k of xkeys) await addCall('xwingKeygen', k.tag, [k.jsonSeed], () => { const r = K.xwingKeygen(k.seedBytes); return { publicKey: r.publicKey, secretKeySha256: sha256hex(r.secretKey), secretKeyLen: r.secretKey.length }; });
for (const n of [0, 1, 31, 33, 64]) { const s0 = garbage(n); await addCall('xwingKeygen', `refuse-len${n}`, [B(s0)], () => K.xwingKeygen(s0)); }

const eKat = XW.map((v) => hex(v.eseed));
const encPairs: [string, XKey, any, Uint8Array][] = [
  ...XW.map((v, i) => [`kat${i}`, xkeys[i]!, B(hex(v.eseed)), hex(v.eseed)] as [string, XKey, any, Uint8Array]),
  ['a-1', xkeys[3]!, [SD('kem/xwing/e1/m'), SD('kem/xwing/e1/x')], cat(sd('kem/xwing/e1/m'), sd('kem/xwing/e1/x'))],
  ['b-1', xkeys[4]!, [SD('kem/xwing/e2/m'), SD('kem/xwing/e2/x')], cat(sd('kem/xwing/e2/m'), sd('kem/xwing/e2/x'))],
  ['a-zeros', xkeys[3]!, B(new Uint8Array(64)), new Uint8Array(64)],
  ['a-ones', xkeys[3]!, B(new Uint8Array(64).fill(0xff)), new Uint8Array(64).fill(0xff)],
  ['zero-key', xkeys[5]!, [SD('kem/xwing/e1/m'), SD('kem/xwing/e1/x')], cat(sd('kem/xwing/e1/m'), sd('kem/xwing/e1/x'))],
];
void eKat;
for (const [nm, k, js, es] of encPairs) {
  await addCall('xwingEncapsulateDerand', nm, [B(k.pk), js], () => K.xwingEncapsulateDerand(k.pk, es));
  await addRng('xwingEncapsulate', nm, [B(k.pk), js], es, () => K.xwingEncapsulate(k.pk));
}
{
  const k = xkeys[3]!, es = cat(sd('kem/xwing/e1/m'), sd('kem/xwing/e1/x')), esJ = [SD('kem/xwing/e1/m'), SD('kem/xwing/e1/x')];
  for (const [nm, pk] of [['len0', new Uint8Array()], ['len-1', k.pk.subarray(0, 1215)], ['len+1', cat(k.pk, Uint8Array.of(0))], ['len32', k.pk.subarray(0, 32)]] as [string, Uint8Array][]) {
    await addCall('xwingEncapsulateDerand', `refuse-pk-${nm}`, [B(pk), esJ], () => K.xwingEncapsulateDerand(pk, es));
    await addRng('xwingEncapsulate', `refuse-pk-${nm}`, [B(pk), esJ], es, () => K.xwingEncapsulate(pk));
  }
  for (const n of [0, 1, 32, 63, 65, 96]) { const e2 = garbage(n); await addCall('xwingEncapsulateDerand', `refuse-eseed-len${n}`, [B(k.pk), B(e2)], () => K.xwingEncapsulateDerand(k.pk, e2)); }
  for (const [i, lo] of LOW.entries()) { const pk = cat(k.pk.subarray(0, 1184), lo); await addCall('xwingEncapsulateDerand', `refuse-lowx-${i}`, [B(pk), esJ], () => K.xwingEncapsulateDerand(pk, es)); }
  for (const [nm, set] of [['coef0-4095', [[0, 0xff], [1, 0x0f]]], ['coef0-3329', [[0, 0x01], [1, 0x0d]]], ['coef0-3328-ok', [[0, 0x00], [1, 0x0d]]], ['coef-last-4095', [[1150, 0xff], [1151, 0xff]]]] as [string, [number, number][]][]) {
    const pk = applySet(k.pk, set); await addCall('xwingEncapsulateDerand', `modcheck-${nm}`, [B(pk), esJ], () => K.xwingEncapsulateDerand(pk, es));
  }
  { const pk = cat(new Uint8Array(1184), k.pk.subarray(1184)); await addCall('xwingEncapsulateDerand', 'mlkem-pk-zero', [B(pk), esJ], () => K.xwingEncapsulateDerand(pk, es)); }
  await addCall('xwingEncapsulateDerand', 'null-pk', [null, esJ], () => K.xwingEncapsulateDerand(null as any, es));
  await addCall('xwingEncapsulateDerand', 'null-eseed', [B(k.pk), null], () => K.xwingEncapsulateDerand(k.pk, null as any));
}
// decapsulate
{
  const flip = (u: Uint8Array, i: number, v = 1) => { const r = Uint8Array.from(u); r[i] = r[i]! ^ v; return r; };
  const cts = encPairs.map(([nm, k, , es]) => ({ nm, k, ct: K.xwingEncapsulateDerand(k.pk, es).ciphertext as Uint8Array }));
  for (const { nm, k, ct } of cts) await addCall('xwingDecapsulate', `${nm}-ok`, [B(ct), k.jsonSeed], () => K.xwingDecapsulate(ct, k.seedBytes));
  const c0 = cts.find((c) => c.nm === 'a-1')!, kb = xkeys[4]!;
  await addCall('xwingDecapsulate', 'wrong-key', [B(c0.ct), kb.jsonSeed], () => K.xwingDecapsulate(c0.ct, kb.seedBytes));
  for (const [nm, i] of [['ctM-0', 0], ['ctM-mid', 600], ['ctM-last', 1087], ['ctX-0', 1088], ['ctX-last', 1119]] as [string, number][]) {
    const ct = flip(c0.ct, i); await addCall('xwingDecapsulate', `tamper-${nm}`, [B(ct), c0.k.jsonSeed], () => K.xwingDecapsulate(ct, c0.k.seedBytes));
  }
  for (const [i, lo] of LOW.entries()) { const ct = cat(c0.ct.subarray(0, 1088), lo); await addCall('xwingDecapsulate', `lowx-${i}`, [B(ct), c0.k.jsonSeed], () => K.xwingDecapsulate(ct, c0.k.seedBytes)); }
  await addCall('xwingDecapsulate', 'ct-zero', [B(new Uint8Array(1120)), c0.k.jsonSeed], () => K.xwingDecapsulate(new Uint8Array(1120), c0.k.seedBytes));
  for (const [nm, ct] of [['len0', new Uint8Array()], ['len-1', c0.ct.subarray(0, 1119)], ['len+1', cat(c0.ct, Uint8Array.of(0))]] as [string, Uint8Array][])
    await addCall('xwingDecapsulate', `refuse-ct-${nm}`, [B(ct), c0.k.jsonSeed], () => K.xwingDecapsulate(ct, c0.k.seedBytes));
  for (const n of [0, 1, 31, 33, 64]) { const s0 = garbage(n); await addCall('xwingDecapsulate', `refuse-seed-len${n}`, [B(c0.ct), B(s0)], () => K.xwingDecapsulate(c0.ct, s0)); }
  await addCall('xwingDecapsulate', 'refuse-both-bad', [B(new Uint8Array(3)), B(new Uint8Array(3))], () => K.xwingDecapsulate(new Uint8Array(3), new Uint8Array(3)));
  await addCall('xwingDecapsulate', 'null-ct', [null, c0.k.jsonSeed], () => K.xwingDecapsulate(null as any, c0.k.seedBytes));
  await addCall('xwingDecapsulate', 'null-seed', [B(c0.ct), null], () => K.xwingDecapsulate(c0.ct, null as any));
}

// ---- b64u convenience
{
  const A7 = keyOf(S768, 'a'), A10 = keyOf(S1024, 'a');
  const xk = xkeys[3]!;
  const ENC: [string, Uint8Array][] = [['empty', new Uint8Array()], ['one', Uint8Array.of(0xfb)], ['two', Uint8Array.of(0xff, 0xfe)], ['three', Uint8Array.of(0, 1, 2)], ['pk768', A7.pk], ['pk1024', A10.pk], ['xwpk', xk.pk], ['ct', S768 && K.xwingEncapsulateDerand(xk.pk, new Uint8Array(64)).ciphertext]];
  const DEC = ['', 'AA', 'AAA', 'AAAA', 'A', 'AAAAA', '-_', '-_8', '+/8', 'ab=', 'abc=', 'abcd====', ' abcd', 'abcd ', 'ab cd', 'ab\ncd', 'é', '\u0000', 'AB', 'AC', 'AQ', 'AR', 'ABC', 'ABD', '-_-_', '-_-', '----', 'Zm9v', 'Zm9vYg', 'Zm9vYg==', 'x'.repeat(1000), b64(A7.pk), b64(A10.pk), b64(xk.pk)];
  for (const [fn, who] of [['encodeHybridPublicKey', 'a'], ['encodeHybridCiphertext', 'a'], ['encodeXWingPublicKey', 'a'], ['encodeXWingCiphertext', 'a']] as [string, string][]) {
    void who;
    for (const [nm, v] of ENC) await addCall(fn, nm, [B(v)], () => K[fn](v));
    await addCall(fn, 'null', [null], () => K[fn](null));
  }
  for (const fn of ['decodeHybridPublicKey', 'decodeHybridCiphertext', 'decodeXWingPublicKey', 'decodeXWingCiphertext']) {
    for (const [i, s] of DEC.entries()) await addCall(fn, `s${i}`, [s], () => K[fn](s));
    await addCall(fn, 'null', [null], () => K[fn](null));
    await addCall(fn, 'number', [5], () => K[fn](5));
  }
}

// every corpus case must round-trip through the strip rule: no raw secret bytes (only labels) — enforced by strip-corpus-keys.py --any after this run
refWrite(o, 'kem');
