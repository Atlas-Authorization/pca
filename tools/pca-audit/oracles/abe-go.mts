// Oracle (go lane variant of abe.mts): master and user keys are SEED LABELS in the corpus, never raw key bytes. Keys come from fixed
// scalars, so a native test re-derives them (sha512('abe-oracle/'+label+name) mod r) and applies the recorded edits.
// Oracle: @atlasauth/pca-abe (FAME ciphertext-policy ABE on BLS12-381, AES-256-GCM, capability attributes).
// Encryption and key issuance are randomized, so they are covered three ways: (1) the scheme's group arithmetic with FIXED
// scalars (fameSetup / fameKeygen / fameEncrypt / fameDecrypt), compared byte for byte including the 576-byte GT values;
// (2) reference-made keys and ciphertexts replayed through the native decrypt (valid, unsatisfied, colluding, cross-master,
// tampered); (3) the deterministic surface (policy normalisation, ciphertext parsing, GT checks, capability attributes, the
// error paths of setup/keygen/encrypt). Scalars cross as 64-char lowercase hex, bytes as {"$bytes": b64url}.
//
// PORTING (fn(args) -> native entry point, comparison rule):
//   fame(policy, attrs, scalars)        -> setup/keygen/encrypt/decrypt with the given scalars   {h,t,mskg,k0,kp,key,ct0,rows,k,dec}
//   gtIsElement(bytes)                  -> canonical, non-identity, order-r GT element             boolean
//   gtPow(bytes, scalarHex)             -> GT exponentiation                                        bytes
//   gtMul(a, b)                         -> GT multiplication                                        bytes
//   pairingProduct([g1...], [g2...])    -> multi-pairing, one final exponentiation                 bytes; identity point -> throw
//   normalizePolicy(policy)             -> normalizePolicy                                          {ok, tree} | {ok:false, reason}
//   satisfies(tree, attrs)              -> satisfies                                                boolean
//   policyAttributes(tree)              -> policyAttributes                                         sorted list
//   parseCiphertext(x)                  -> parseCiphertext                                          ciphertext | null
//   decrypt(key, ct)                    -> decrypt                                                  bytes | null
//   decryptText(key, ct)                -> decryptText                                              string | null
//   decryptWithCapability(key, ct)      -> decryptWithCapability                                    {ok, payload} | {ok:false, reason}
//   encryptAccepts(mpk, policy)         -> encryptForPolicy succeeds (true) or throws               true | throw
//   keygenForAttributes(msk, attrs)     -> the issued key's attribute names, in order (or throw)    list | throw
//   keygenForCapability(msk, cap, extra, opts) -> {holder, attrs} of the issued key                  object | throw
//   capabilityAttributes(cap, opts)     -> capabilityAttributes (opts: chain, principal)           sorted list
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import * as PCA0 from '@atlasauth/pca';
import * as A0 from '@atlasauth/pca-abe';
import * as F0 from '../../../packages/pca-abe/src/fame.ts';
import * as BL0 from '../../../packages/pca-abe/src/bls.ts';
import { Oracle, refWrite, splitWrite, tokensIn, seed } from './lib.mjs';

const pick = (m: any) => m.default ?? m;
// the curve module instance the package itself loaded (an ESM import here would be a second, incompatible instance)
const { bls12_381 } = createRequire(new URL('../../../packages/pca-abe/src/bls.ts', import.meta.url))('@noble/curves/bls12-381');
const A: any = pick(A0);
const F: any = pick(F0);
const BL: any = pick(BL0);
const { mintRoot, attenuate, delegate, encodeKey, publicKeyOf } = pick(PCA0);

const o = new Oracle('abe-go', 'tools/pca-audit/oracles/abe-go.mts', 'TS-reference oracle for FAME CP-ABE on BLS12-381 (scheme arithmetic, decrypt, policies, capability attributes).');
const R: bigint = BL.R;
const Fp12 = bls12_381.fields.Fp12;
const J = (u: Uint8Array) => ({ $bytes: Buffer.from(u).toString('base64url') });
const by = (x: any): Uint8Array => new Uint8Array(Buffer.from(x.$bytes, 'base64url'));
const hex = (n: bigint) => n.toString(16).padStart(64, '0');
const unhex = (s: string) => BigInt('0x' + s);
/** A fixed non-zero scalar from a label. */
const sc = (label: string): bigint => {
  const v = BigInt('0x' + createHash('sha512').update('abe-oracle/' + label).digest('hex')) % R;
  return v === 0n ? 1n : v;
};

// ---- seeded keys -------------------------------------------------------------------------------------------------------
const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64url');
const RECIPES = new WeakMap<object, any>();
const reg = <T extends object>(x: T, r: any): T => (RECIPES.set(x, r), x);
/** Replace every registered key object by its recipe (what the corpus records instead of key bytes). */
const ph = (v: any): any => {
  if (v !== null && typeof v === 'object') {
    const r = RECIPES.get(v);
    if (r) return r;
    if (Array.isArray(v)) return v.map(ph);
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, ph(x)]));
  }
  return v;
};
const MSKRAW = new Map<string, any>();
const g1w = (p: any) => b64(BL.g1ToBytes(p));
const g2w = (p: any) => b64(BL.g2ToBytes(p));
const seededSetup = (label: string) => {
  const s = (n: string) => sc(label + '/' + n);
  const { mpk, msk } = F.fameSetup([s('a1'), s('a2')], [s('b1'), s('b2')], [s('d1'), s('d2'), s('d3')]);
  MSKRAW.set(label, msk);
  return {
    mpk: { v: 2, curve: 'bls12-381', h: [g2w(mpk.h1), g2w(mpk.h2)], t: [b64(BL.gtToBytes(mpk.t1)), b64(BL.gtToBytes(mpk.t2))] },
    msk: reg({ v: 2, curve: 'bls12-381', a: msk.a.map((x: bigint) => b64(BL.scalarToBytes(x))), b: msk.b.map((x: bigint) => b64(BL.scalarToBytes(x))), g: msk.g.map(g1w) }, { $abeMsk: label }),
  };
};
const seededKey = (id: string, mskObj: any, attrs: string[]) => {
  const label = RECIPES.get(mskObj).$abeMsk;
  const names = [...new Set(attrs)].filter((a) => typeof a === 'string' && a.length > 0 && !BL.isIllFormedUtf16(a));
  const key = F.fameKeygen(MSKRAW.get(label), names, [sc(id + '/r1'), sc(id + '/r2')], names.map((_, i) => sc(id + '/sg' + i)), sc(id + '/sgp'));
  const tri1 = (x: any[]) => x.map(g1w);
  return reg({
    v: 2, curve: 'bls12-381', k0: key.k0.map(g2w), kp: tri1(key.kp),
    attrs: Object.fromEntries(names.map((n) => [n, { k: tri1(key.attrs.get(n)) }])),
  }, { $abeKey: { msk: label, attrs, id } });
};
const REF = (path: any[]) => ({ $ref: path });
const at = (o: any, path: any[]) => path.reduce((x, k) => x[k], o);
/** base with edits applied; a REF value copies another position of the base, undefined deletes. */
const mut = (base: any, edits: [any[], any][]) => {
  const out = JSON.parse(JSON.stringify(base));
  for (const [path, val] of edits) {
    const v = val && typeof val === 'object' && '$ref' in val ? at(base, val.$ref) : val;
    const parent = at(out, path.slice(0, -1));
    if (v === undefined) delete parent[path[path.length - 1]];
    else parent[path[path.length - 1]] = v;
  }
  return reg(out, { $patch: RECIPES.get(base), $edits: edits.map(([path, v]) => ({ path, value: v === undefined ? { $undefined: true } : v })) });
};
/** base key plus the attribute components of the others (the collusion pool). */
const pool = (base: any, others: any[]) =>
  reg({ ...base, attrs: Object.assign({}, base.attrs, ...others.map((k) => k.attrs)) }, { $pool: [RECIPES.get(base), ...others.map((k) => RECIPES.get(k))] });
const g1x = (p: any) => J(BL.g1ToBytes(p));
const g2x = (p: any) => J(BL.g2ToBytes(p));

const refs: Record<string, (...a: any[]) => any> = {
  fame: (policy, attrs, s) => {
    const n = A.normalizePolicy(policy);
    if (!n.ok) throw new Error(n.reason);
    const { mpk, msk } = F.fameSetup(s.a.map(unhex), s.b.map(unhex), s.d.map(unhex));
    const key = F.fameKeygen(msk, attrs, s.r.map(unhex), s.sigma.map(unhex), unhex(s.sigmaPrime));
    const { ct, k } = F.fameEncrypt(mpk, n.tree, s.s.map(unhex));
    const dec = F.fameDecrypt(key, n.tree, ct);
    return {
      h: [g2x(mpk.h1), g2x(mpk.h2)],
      t: [J(BL.gtToBytes(mpk.t1)), J(BL.gtToBytes(mpk.t2))],
      mskg: msk.g.map(g1x),
      k0: key.k0.map(g2x),
      kp: key.kp.map(g1x),
      key: Object.fromEntries([...key.attrs].map(([a, v]: any) => [a, v.map(g1x)])),
      ct0: ct.ct0.map(g2x),
      rows: ct.rows.map((r: any) => r.map(g1x)),
      k: J(BL.gtToBytes(k)),
      dec: dec === null ? null : J(BL.gtToBytes(dec)),
    };
  },
  gtIsElement: (b) => BL.gtFromBytes(by(b)) !== null,
  gtPow: (b, s) => J(BL.gtToBytes(BL.gtPow(Fp12.fromBytes(by(b)), unhex(s)))),
  gtMul: (a, b) => J(BL.gtToBytes(Fp12.mul(Fp12.fromBytes(by(a)), Fp12.fromBytes(by(b))))),
  pairingProduct: (g1s, g2s) =>
    J(BL.gtToBytes(BL.pairingProduct(g1s.map((g: any, i: number) => ({ g1: bls12_381.G1.ProjectivePoint.fromHex(by(g)), g2: bls12_381.G2.ProjectivePoint.fromHex(by(g2s[i])) }))))),
  normalizePolicy: (p) => A.normalizePolicy(p),
  satisfies: (tree, attrs) => A.satisfies(tree, new Set(attrs)),
  policyAttributes: (tree) => A.policyAttributes(tree),
  parseCiphertext: (x) => A.parseCiphertext(x),
  decrypt: (key, ct) => A.decrypt(key, ct),
  decryptText: (key, ct) => A.decryptText(key, ct),
  decryptWithCapability: (key, ct) => A.decryptWithCapability(key, ct),
  encryptAccepts: (mpk, policy) => (A.encryptForPolicy(mpk, policy, 'x'), true),
  keygenForAttributes: (msk, attrs) => Object.keys(A.keygenForAttributes(msk, attrs).attrs),
  keygenForCapability: (msk, cap, extra, opts) => {
    const k = A.keygenForCapability(msk, cap, extra, opts);
    return { holder: k.holder ?? null, attrs: Object.keys(k.attrs) };
  },
  capabilityAttributes: (cap, opts) => A.capabilityAttributes(cap, opts),
};
const run = async (fn: string, name: string, args: any[], rec?: any[]) => {
  const added = await o.run(fn, name, refs[fn]!, args);
  if (added) o.cases[o.cases.length - 1].args = ph(rec ?? args);
  return added;
};

// ---- policies used throughout ----------------------------------------------------------------------------------------
const P = {
  single: { attr: 'verb:read' },
  and2: { allOf: [{ attr: 'verb:read' }, { attr: 'scope:files' }] },
  or2: { anyOf: [{ attr: 'verb:read' }, { attr: 'verb:write' }] },
  t2of3: { threshold: 2, of: [{ attr: 'a' }, { attr: 'b' }, { attr: 'c' }] },
  t3of5: { threshold: 3, of: ['p', 'q', 'r', 's', 't'].map((attr) => ({ attr })) },
  nested: { allOf: [{ attr: 'holder:H' }, { anyOf: [{ attr: 'scope:admin' }, { threshold: 2, of: [{ attr: 'x' }, { attr: 'y' }, { attr: 'z' }] }] }] },
  unicode: { anyOf: [{ attr: 'résumé:é€😀' }, { attr: 'act:["read","/a b"]' }] },
};
const deep = (n: number): any => (n === 0 ? { attr: 'leaf' } : { anyOf: [deep(n - 1), { attr: `d${n}` }] });

// ---- (1) scheme arithmetic with fixed scalars ------------------------------------------------------------------------
const scalars = (label: string, nAttrs: number) => ({
  a: [hex(sc(label + 'a1')), hex(sc(label + 'a2'))],
  b: [hex(sc(label + 'b1')), hex(sc(label + 'b2'))],
  d: [hex(sc(label + 'd1')), hex(sc(label + 'd2')), hex(sc(label + 'd3'))],
  r: [hex(sc(label + 'r1')), hex(sc(label + 'r2'))],
  sigma: Array.from({ length: nAttrs }, (_, i) => hex(sc(label + 'sg' + i))),
  sigmaPrime: hex(sc(label + 'sgp')),
  s: [hex(sc(label + 's1')), hex(sc(label + 's2'))],
});
const FAME: [string, any, string[]][] = [
  ['single', P.single, ['verb:read', 'extra']],
  ['single-miss', P.single, ['verb:write']],
  ['and2', P.and2, ['verb:read', 'scope:files']],
  ['and2-half', P.and2, ['verb:read']],
  ['or2-right', P.or2, ['verb:write']],
  ['2of3-ac', P.t2of3, ['a', 'c']],
  ['2of3-all', P.t2of3, ['c', 'b', 'a']],
  ['2of3-one', P.t2of3, ['b']],
  ['3of5', P.t3of5, ['t', 'q', 's']],
  ['nested-admin', P.nested, ['holder:H', 'scope:admin']],
  ['nested-xz', P.nested, ['holder:H', 'x', 'z']],
  ['nested-noholder', P.nested, ['scope:admin', 'x', 'y', 'z']],
  ['unicode', P.unicode, ['act:["read","/a b"]']],
  ['deep10', deep(10), ['leaf']],
];
for (const [name, policy, attrs] of FAME) await run('fame', name, [policy, attrs, scalars(name, attrs.length)], [policy, attrs, { $seed: name }]);

// ---- GT and pairing --------------------------------------------------------------------------------------------------
const G1 = bls12_381.G1.ProjectivePoint.BASE;
const G2 = bls12_381.G2.ProjectivePoint.BASE;
const egh = BL.pairing(G1, G2);
const gt = (k: bigint) => BL.gtToBytes(BL.gtPow(egh, k));
const T = [gt(1n), gt(sc('gt1')), gt(sc('gt2')), gt(R - 1n)];
for (const [i, t] of T.entries()) await run('gtIsElement', `valid${i}`, [J(t)]);
await run('gtIsElement', 'identity', [J(Fp12.toBytes(Fp12.ONE))]);
await run('gtIsElement', 'zero', [J(new Uint8Array(576))]);
await run('gtIsElement', 'short', [J(T[1]!.slice(0, 575))]);
await run('gtIsElement', 'long', [J(new Uint8Array([...T[1]!, 0]))]);
const two = new Uint8Array(576);
two[47] = 2;
await run('gtIsElement', 'not-in-subgroup-2', [J(two)]);
await run('gtIsElement', 'not-in-subgroup-pre-final-exp', [J(Fp12.toBytes(bls12_381.pairing(G1, G2, false)))]);
{
  // coordinate c + p: structurally a different encoding of the same field element
  const p = bls12_381.fields.Fp.ORDER;
  for (const off of [0, 48 * 5, 48 * 11]) {
    const b = Uint8Array.from(T[1]!);
    const c = BigInt('0x' + Buffer.from(b.subarray(off, off + 48)).toString('hex')) + p;
    b.set(Buffer.from(c.toString(16).padStart(96, '0'), 'hex'), off);
    await run('gtIsElement', `noncanonical@${off}`, [J(b)]);
  }
  const flip = Uint8Array.from(T[2]!);
  flip[300] ^= 1;
  await run('gtIsElement', 'bitflip', [J(flip)]);
}
const EXPS = [0n, 1n, 2n, R - 1n, sc('e1'), sc('e2'), (1n << 255n) - 1n - R];
for (const [i, t] of T.slice(1, 3).entries()) for (const [j, e] of EXPS.entries()) await run('gtPow', `t${i}e${j}`, [J(t), hex(e % R)]);
for (const [i, a] of T.entries()) for (const [j, b] of T.entries()) if (i <= j) await run('gtMul', `t${i}t${j}`, [J(a), J(b)]);
const P1s = [G1, G1.multiply(sc('p1a')), BL.hashToG1(new TextEncoder().encode('x'))];
const P2s = [G2, G2.multiply(sc('p2a')), G2.multiply(sc('p2b'))];
for (const [i, p] of P1s.entries()) for (const [j, q] of P2s.entries()) await run('pairingProduct', `e${i}${j}`, [[g1x(p)], [g2x(q)]]);
await run('pairingProduct', 'three', [P1s.map(g1x), P2s.map(g2x)]);
await run('pairingProduct', 'cancel', [[g1x(P1s[1]), g1x(P1s[1]!.negate())], [g2x(P2s[2]), g2x(P2s[2])]]);

// ---- policies --------------------------------------------------------------------------------------------------------
const wide = (n: number) => ({ anyOf: Array.from({ length: n }, (_, i) => ({ attr: 'w' + i })) });
const POLICIES: [string, unknown][] = [
  ...Object.entries(P),
  ['deep10', deep(10)],
  ['deep11', deep(11)],
  ['wide1023', wide(1023)],
  ['wide1024', wide(1024)],
  ['null', null],
  ['array', [{ attr: 'a' }]],
  ['string', 'verb:read'],
  ['empty-object', {}],
  ['attr-empty', { attr: '' }],
  ['attr-number', { attr: 5 }],
  ['attr-lone-surrogate', { attr: 'a\ud800' }],
  ['attr-pair-surrogate', { attr: 'a😀' }],
  ['attr-mixed', { attr: 'a', allOf: [{ attr: 'b' }] }],
  ['attr-with-of', { attr: 'a', of: [] }],
  ['allOf-empty', { allOf: [] }],
  ['allOf-not-array', { allOf: { attr: 'a' } }],
  ['anyOf-bad-child', { anyOf: [{ attr: 'a' }, 7] }],
  ['ambiguous', { allOf: [{ attr: 'a' }], anyOf: [{ attr: 'b' }] }],
  ['ambiguous-of', { allOf: [{ attr: 'a' }], of: [{ attr: 'b' }] }],
  ['of-only', { of: [{ attr: 'a' }] }],
  ['threshold-0', { threshold: 0, of: [{ attr: 'a' }] }],
  ['threshold-1.5', { threshold: 1.5, of: [{ attr: 'a' }, { attr: 'b' }] }],
  ['threshold-string', { threshold: '1', of: [{ attr: 'a' }] }],
  ['threshold-too-big', { threshold: 3, of: [{ attr: 'a' }, { attr: 'b' }] }],
  ['threshold-2^53', { threshold: 2 ** 53, of: [{ attr: 'a' }] }],
  ['threshold-no-of', { threshold: 1 }],
  ['threshold-1-dup', { threshold: 1, of: [{ attr: 'a' }, { attr: 'a' }] }],
  ['unknown-key', { not: { attr: 'a' } }],
  ['nested-error-path', { allOf: [{ attr: 'a' }, { anyOf: [{ attr: 'b' }, { threshold: 2, of: [{ attr: 'c' }, {}] }] }] }],
];
for (const [name, p] of POLICIES) await run('normalizePolicy', name, [p]);
const TREE = A.normalizePolicy(P.nested).tree;
for (const [i, s] of [[], ['holder:H'], ['holder:H', 'scope:admin'], ['holder:H', 'x'], ['holder:H', 'y', 'x'], ['x', 'y', 'z', 'scope:admin']].entries())
  await run('satisfies', `nested${i}`, [TREE, s]);
for (const [name, p] of Object.entries(P)) await run('policyAttributes', name, [A.normalizePolicy(p).tree]);
await run('policyAttributes', 'dup', [A.normalizePolicy({ threshold: 1, of: [{ attr: 'b' }, { attr: 'a' }, { attr: 'b' }] }).tree]);

// ---- reference keys and ciphertexts ----------------------------------------------------------------------------------
const M1 = seededSetup('abe-go/m1');
const M2 = seededSetup('abe-go/m2');
const ATTRS = ['verb:read', 'scope:files', 'holder:H', 'scope:admin', 'x', 'y', 'z', 'a', 'b', 'c', 'résumé:é€😀', 'leaf'];
const kAll = seededKey('abe-go/kAll', M1.msk, ATTRS);
const kRead = seededKey('abe-go/kRead', M1.msk, ['verb:read']);
const kFiles = seededKey('abe-go/kFiles', M1.msk, ['scope:files']);
const kOther = seededKey('abe-go/kOther', M2.msk, ATTRS);
const enc = (pol: any, text: string, mpk = M1.mpk) => A.encryptForPolicy(mpk, pol, text).ciphertext;
const CTS: [string, any][] = [
  ['single', enc(P.single, 'hello')],
  ['and2', enc(P.and2, 'files')],
  ['2of3', enc(P.t2of3, '')],
  ['nested', enc(P.nested, 'é€😀 payload')],
  ['unicode', enc(P.unicode, 'u')],
  ['deep10', enc(deep(10), 'deep')],
];
for (const [name, ct] of CTS) {
  await run('decrypt', `${name}/all`, [kAll, ct]);
  await run('decrypt', `${name}/read-only`, [kRead, ct]);
  await run('decrypt', `${name}/other-master`, [kOther, ct]);
  await run('decryptText', `${name}/all`, [kAll, ct]);
  await run('parseCiphertext', name, [ct]);
}
// collusion: the components of two keys that each hold half of an AND
const pooled = pool(kRead, [kFiles]);
await run('decrypt', 'and2/colluding', [pooled, CTS[1]![1]]);
await run('decrypt', 'and2/read+files-own-key', [seededKey('abe-go/kFilesRead', M1.msk, ['scope:files', 'verb:read']), CTS[1]![1]]);
// tampering: every header field and the AEAD fields
const base = CTS[3]![1];
const T1 = (over: any) => ({ ...JSON.parse(JSON.stringify(base)), ...over });
const otherCt = enc(P.nested, 'other');
const TAMPER: [string, any][] = [
  ['salt', T1({ salt: otherCt.salt })],
  ['iv', T1({ iv: otherCt.iv })],
  ['tag', T1({ tag: otherCt.tag })],
  ['ct', T1({ ct: otherCt.ct })],
  ['ct0', T1({ ct0: otherCt.ct0 })],
  ['rows-swapped', T1({ rows: [base.rows[1], base.rows[0], ...base.rows.slice(2)] })],
  ['row-from-other', T1({ rows: [otherCt.rows[0], ...base.rows.slice(1)] })],
  ['tree-attr-renamed', T1({ tree: JSON.parse(JSON.stringify(base.tree).replace('"scope:admin"', '"scope:root"')) })],
  ['tree-threshold-lowered', T1({ tree: JSON.parse(JSON.stringify(base.tree).replace('"t":2,', '"t":1,')) })],
  ['extra-top-level-key', T1({ note: 'ignored' })],
  ['v1', T1({ v: 1 })],
  ['alg', T1({ alg: 'other' })],
  ['salt-noncanonical-b64', T1({ salt: base.salt + 'A' })],
  ['iv-short', T1({ iv: 'AAAA' })],
  ['tag-padding', T1({ tag: base.tag + '=' })],
  ['rows-short', T1({ rows: base.rows.slice(1) })],
  ['row-bad-point', T1({ rows: [[base.rows[0][0], base.rows[0][1], 'AAAA'], ...base.rows.slice(1)] })],
  ['row-identity', T1({ rows: [[base.rows[0][0], base.rows[0][1], J(bls12_381.G1.ProjectivePoint.ZERO.toRawBytes(true)).$bytes], ...base.rows.slice(1)] })],
  ['ct0-two', T1({ ct0: base.ct0.slice(0, 2) })],
  ['ct0-g1-point', T1({ ct0: [base.rows[0][0], base.ct0[1], base.ct0[2]] })],
  ['leaf-extra-key', T1({ tree: { kind: 'gate', t: 1, of: [{ kind: 'leaf', attr: 'a', x: 1 }] }, rows: base.rows.slice(0, 1) })],
  ['gate-t-zero', T1({ tree: { kind: 'gate', t: 0, of: [{ kind: 'leaf', attr: 'a' }] }, rows: base.rows.slice(0, 1) })],
  ['gate-t-float', T1({ tree: { kind: 'gate', t: 1.5, of: [{ kind: 'leaf', attr: 'a' }, { kind: 'leaf', attr: 'b' }] }, rows: base.rows.slice(0, 2) })],
  ['gate-dup-attr', T1({ tree: { kind: 'gate', t: 1, of: [{ kind: 'leaf', attr: 'a' }, { kind: 'leaf', attr: 'a' }] }, rows: base.rows.slice(0, 2) })],
  ['leaf-lone-surrogate', T1({ tree: { kind: 'leaf', attr: 'a\ud800' }, rows: base.rows.slice(0, 1) })],
  ['unknown-kind', T1({ tree: { kind: 'and', of: [] } })],
  ['tree-null', T1({ tree: null })],
];
for (const [name, ct] of TAMPER) {
  await run('decrypt', `tamper/${name}`, [kAll, ct]);
  await run('parseCiphertext', `tamper/${name}`, [ct]);
}
{
  const deepTree = (n: number): any => (n === 0 ? { kind: 'leaf', attr: 'leaf' } : { kind: 'gate', t: 1, of: [deepTree(n - 1)] });
  await run('parseCiphertext', 'tree-depth-10', [T1({ tree: deepTree(10), rows: base.rows.slice(0, 1) })]);
  await run('parseCiphertext', 'tree-depth-11', [T1({ tree: deepTree(11), rows: base.rows.slice(0, 1) })]);
  const leaves = (n: number) => Array.from({ length: n }, (_, i) => ({ kind: 'leaf', attr: 'w' + i }));
  const row = base.rows[0];
  await run('parseCiphertext', 'wide-1022', [T1({ tree: { kind: 'gate', t: 1, of: leaves(1022) }, rows: Array(1022).fill(row) })]);
  await run('parseCiphertext', 'wide-1023', [T1({ tree: { kind: 'gate', t: 1, of: leaves(1023) }, rows: Array(1023).fill(row) })]);
  await run('parseCiphertext', 'wide-1024', [T1({ tree: { kind: 'gate', t: 1, of: leaves(1024) }, rows: Array(1024).fill(row) })]);
}
for (const [name, x] of [['null', null], ['array', []], ['string', 'ct'], ['empty', {}]] as [string, unknown][]) await run('parseCiphertext', name, [x]);
// malformed keys
const KEYS: [string, any][] = [
  ['k0-bad', mut(kAll, [[['k0', 2], 'AAAA']])],
  ['kp-missing', mut(kAll, [[['kp'], undefined]])],
  ['v1', mut(kAll, [[['v'], 1]])],
  ['attrs-array', mut(kAll, [[['attrs'], []]])],
  ['attr-comp-bad', mut(kAll, [[['attrs', 'holder:H'], { k: ['AAAA', 'AAAA', 'AAAA'] }]])],
  ['attr-comp-not-object', mut(kAll, [[['attrs', 'scope:admin'], 5]])],
  ['null', null],
];
for (const [name, k] of KEYS) await run('decrypt', `key/${name}`, [k, base]);
// payload layer
const tool = A.encryptToolPayload(M1.mpk, P.and2, { rows: [1, 2], note: 'é' }).ciphertext;
const notJson = enc(P.and2, '{not json');
await run('decryptWithCapability', 'ok', [kAll, tool]);
await run('decryptWithCapability', 'unsatisfied', [kRead, tool]);
await run('decryptWithCapability', 'not-json', [kAll, notJson]);
await run('decryptWithCapability', 'null-payload', [kAll, A.encryptToolPayload(M1.mpk, P.single, undefined).ciphertext]);

// ---- error paths of encrypt / keygen ---------------------------------------------------------------------------------
const mpk = M1.mpk;
const MPKS: [string, any][] = [
  ['ok', mpk],
  ['v1', { ...mpk, v: 1 }],
  ['t-identity', { ...mpk, t: [J(Fp12.toBytes(Fp12.ONE)).$bytes, mpk.t[1]] }],
  ['t-not-subgroup', { ...mpk, t: [J(two).$bytes, mpk.t[1]] }],
  ['t-short', { ...mpk, t: [mpk.t[0]] }],
  ['h-bad', { ...mpk, h: [mpk.h[0], 'AAAA'] }],
  ['h-g1', { ...mpk, h: [mpk.h[0], CTS[0]![1].rows[0][0]] }],
  ['null', null],
];
for (const [name, m] of MPKS) await run('encryptAccepts', `mpk/${name}`, [m, P.single]);
for (const [name, p] of POLICIES.slice(0, 12)) await run('encryptAccepts', `policy/${name}`, [mpk, p]);
await run('encryptAccepts', 'policy/repeated-attr', [mpk, { threshold: 1, of: [{ attr: 'a' }, { anyOf: [{ attr: 'a' }] }] }]);
const msk = M1.msk;
const MSKS: [string, any][] = [
  ['ok', msk],
  ['v1', mut(msk, [[['v'], 1]])],
  ['a-zero', mut(msk, [[['a', 0], J(new Uint8Array(32)).$bytes]])],
  ['a-r', mut(msk, [[['a', 0], J(Buffer.from(hex(R), 'hex')).$bytes]])],
  ['a-r-plus-1', mut(msk, [[['a', 0], J(Buffer.from(hex(R + 1n), 'hex')).$bytes]])],
  ['a-31-bytes', mut(msk, [[['a', 0], J(new Uint8Array(31).fill(1)).$bytes]])],
  ['b-three', mut(msk, [[['b', 2], REF(['b', 0])]])],
  ['g-bad', mut(msk, [[['g', 2], 'AAAA']])],
  ['null', null],
];
for (const [name, m] of MSKS) await run('keygenForAttributes', `msk/${name}`, [m, ['a']]);
await run('keygenForAttributes', 'names', [msk, ['b', 'a', 'b', '', 'c\udc00', 'é', 'a']]);
await run('keygenForAttributes', 'none', [msk, []]);

// ---- capability attributes -------------------------------------------------------------------------------------------
const kp = (l: string) => { const sk = seed('abe/' + l); return { sk, pk: encodeKey(publicKeyOf(sk)) }; };
const PR = kp('principal'), AG = kp('agent'), SUB = kp('sub'), OTHER = kp('other');
const RISK = { weights: { alpha: 0.25, beta: 0.2, gamma: 0.2, delta: 0.2, epsilon: 0.1, zeta: 0.05 }, theta1: 0.25, theta2: 0.6, kappa: 1, lambda: 0.0005, rho: 0.5, bMax: 1 };
const envelope = (predicates: any[]) => ({ type: 'envelope', goal_commit: 'g', predicates, caveats: [], agent_binding: {}, risk_policy: RISK });
const root1 = mintRoot({ principalSecret: PR.sk, principalPublic: PR.pk, holder: AG.pk, caveats: [envelope([{ verb: ['read', 'list'], resource: '/files/*' }]), { type: 'scope', value: 'files' }, { type: 'scopes', values: ['a', 7, 'b'] }] });
const root2 = mintRoot({ principalSecret: PR.sk, principalPublic: PR.pk, holder: AG.pk, caveats: [envelope([{ verb: 'read', resource: '/a' }, { verb: ['write'], resource: '/b' }, null, ['x']]), { type: 'scope', value: 'ops' }] });
const root3 = mintRoot({ principalSecret: PR.sk, principalPublic: PR.pk, holder: AG.pk, caveats: [{ type: 'scope', value: 'only' }] });
const root4 = mintRoot({ principalSecret: PR.sk, principalPublic: PR.pk, holder: AG.pk, caveats: [envelope([{ verb: 'say', resource: 'q"uote\\back\nline' }])] });
const child = attenuate(root1, [{ type: 'scope', value: 'admin' }, envelope([{ verb: 'delete', resource: '/*' }])], AG.sk);
const sub = delegate(child, SUB.pk, [{ type: 'scopes', values: ['root'] }], AG.sk);
const forged = delegate(root1, SUB.pk, [], OTHER.sk);
const CAPS: [string, any, any][] = [
  ['root1', root1, {}],
  ['root2-multi-predicate', root2, {}],
  ['root3-no-envelope', root3, {}],
  ['root4-escapes', root4, {}],
  ['child-no-chain', child, {}],
  ['child-chain', child, { chain: [root1, child] }],
  ['child-chain-principal', child, { chain: [root1, child], principal: PR.pk }],
  ['child-chain-wrong-principal', child, { chain: [root1, child], principal: OTHER.pk }],
  ['sub-chain', sub, { chain: [root1, child, sub] }],
  ['sub-chain-not-ending-in-cap', sub, { chain: [root1, child] }],
  ['sub-empty-chain', sub, { chain: [] }],
  ['forged-chain', forged, { chain: [root1, forged] }],
  ['no-holder', { ...root3, holder: undefined }, {}],
  ['empty-holder', { ...root3, holder: '' }, {}],
];
for (const [name, cap, opts] of CAPS) await run('capabilityAttributes', name, [cap, opts]);
await run('keygenForCapability', 'root1', [msk, root1, ['extra:1', '', 'scope:files'], {}]);
await run('keygenForCapability', 'child-chain', [msk, child, [], { chain: [root1, child] }]);
await run('keygenForCapability', 'bad-msk', [mut(msk, [[['v'], 1]]), root1, [], {}]);
await run('keygenForCapability', 'no-holder', [msk, { ...root3, holder: undefined }, ['z'], {}]);

splitWrite(o, 'abe-go', (j: string) => tokensIn(j, /"mskg?":(\[[^\]]*\]|"[^"]*")/g));
