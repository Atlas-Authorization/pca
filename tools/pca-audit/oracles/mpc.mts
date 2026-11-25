// Oracle: @atlasauth/pca-mpc, the deterministic layer (field, GF(2^128), additive sharing, Beaver, thermometer, composition,
// SPDZ authenticated shares / MAC-check / sacrifice / malicious runner in trusted-dealer mode). Everything draws from the seeded
// SplitMix64 FieldRng, so a native with the same generator reproduces every share and transcript byte for byte.
// Big integers cross the oracle as DECIMAL STRINGS (args and results; a seed is a decimal string, negatives allowed).
// PORTING (fn(args) -> native entry point; compared by JSON value; a reference throw requires the native to throw):
//   mod/fadd/fsub/fmul/fneg(a[,b]) -> Field.*        fieldRng(seed, count) -> the first `count` draws of new FieldRng(seed)
//   share(secret, n, seed) -> Sharing.share          reconstruct(shares|null..) -> Sharing.reconstruct      shareConstant(c, n)
//   sv(op, x, y?|c?) op in add/sub/neg/scale/addPublic/notBit -> Sharing.*SV
//   gf(op, a, b|i) op in add/mul/mulX/mulByXi -> Gf128.*
//   encBits(s) / makeGadget(s, seed, unsafe) / encValue(g, bits) / plainShare(x) / randomBits(m, seed) / sampleEnc(s, seed) -> Enc.*
//   genTriple(n, seed) -> {a,b,c};  beaverMul(x, y, a, b, c) -> {z, opened:[{label,value,shares}]}
//   thermometerEncode(v, M) / thermometerDecode(bits) / quantizeR(r, Q) / composeClear(vectors, Q) / assertDecisionVectors(vectors, Q)
//   composeSecure(vectors, Q, seed) -> {composed, parties, Q, multiplications, opened, sharings, heldShares0}
//   setupMac(n, seed, keys) / authShare(secret, n, seed) / authConstant / authOp(op, ...) / genAuthTriple / genTripleWithPartners -> Spdz.*
//   macSoundnessBits(keys, p) / macResiduals(p, alphaShares, opened, challenges)
//   engineRun(n, seed, values, deviations) -> {values:[opened...]} or throws (MacCheckAbort)
//   sacrifice(n, seed, count, partners, fault, deviations) -> {ok:true} or throws
//   beaverAuth(n, seed, x, y, deviations) -> {product, ...}
//   composeSecureMalicious(vectors, {Q, seed, deviations, insecureTrustedDealer: true, dealer}) -> result object or throws
import * as M0 from '@atlasauth/pca-mpc';
import * as E0 from '../../../packages/pca-mpc/src/enc';
const M: any = { ...((M0 as any).default ?? M0), ...((E0 as any).default ?? E0) }; // enc.ts is not in the package index
import { Oracle, refWrite, rng, capture } from './lib.mjs';

const o = new Oracle('mpc', 'tools/pca-audit/oracles/mpc.mts', 'TS-reference oracle for the PCA MPC package (deterministic layer).');
const r = rng(0x4d5043);
const B = (s: any) => { if (typeof s !== 'string') throw new TypeError('bigint arg'); return BigInt(s); };
const dec = (v: any): any => typeof v === 'bigint' ? v.toString() : Array.isArray(v) ? v.map(dec) : v !== null && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, dec(x)])) : v;
const D = (f: (...a: any[]) => any) => (...a: any[]) => dec(f(...a));
const BL = (xs: any) => xs.map((x: any) => (x === null ? undefined : B(x)));
const P = M.PRIME;
const big = (bits: number) => { let v = 0n; for (let i = 0; i < bits; i += 16) v = (v << 16n) | BigInt(r.int(0, 65535)); return v & ((1n << BigInt(bits)) - 1n); };
const S = (b: bigint) => b.toString();
const seeds = ['0', '1', '12345', '-1', '-99999', S(1n << 64n), S((1n << 64n) + 7n), S(big(200)), S(0x243f6a8885a308d3n)];
const edge = ['0', '1', '-1', S(P), S(P - 1n), S(P + 1n), S(-P), S(2n * P), S(1n << 62n), S(1n << 64n), S(big(130)), S(-big(130))];

// ---- field
for (const a of edge) {
  await o.run('fneg', a, D((x: string) => M.fneg(B(x))), [a]);
  await o.run('mod', a, D((x: string) => M.mod(B(x))), [a]);
  for (const b of edge) {
    await o.run('fadd', `${a}+${b}`.slice(0, 80), D((x: string, y: string) => M.fadd(B(x), B(y))), [a, b]);
    await o.run('fsub', `${a}-${b}`.slice(0, 80), D((x: string, y: string) => M.fsub(B(x), B(y))), [a, b]);
    await o.run('fmul', `${a}*${b}`.slice(0, 80), D((x: string, y: string) => M.fmul(B(x), B(y))), [a, b]);
  }
}
for (const s of seeds) await o.run('fieldRng', s, D((sd: string, n: number) => { const g = new M.FieldRng(B(sd)); return Array.from({ length: n }, () => g.next()); }), [s, 40]);
await o.run('fieldRngDefault', 'default', D((n: number) => { const g = new M.FieldRng(); return Array.from({ length: n }, () => g.next()); }), [40]);

// ---- sharing
for (const s of seeds.slice(0, 6)) for (const n of [1, 2, 3, 7]) for (const sec of ['0', '1', '-5', S(P), S(P + 3n), S(big(100))]) {
  await o.run('share', `${s}/${n}/${sec}`.slice(0, 80), D((x: string, nn: number, sd: string) => M.share(B(x), nn, new M.FieldRng(B(sd)))), [sec, n, s]);
}
for (const n of [0, -1, 1025, 1024, 1.5, 3000]) await o.run('share', `n${n}`, D((x: string, nn: number, sd: string) => M.share(B(x), nn, new M.FieldRng(B(sd)))), ['5', n, '1']);
for (const sh of [[], ['5'], ['1', '2', '3'], [S(P - 1n), '5'], ['1', null, '3'], [S(P), S(P)], [S(P), '1', '-1']]) {
  await o.run('reconstruct', JSON.stringify(sh).slice(0, 60), D((x: any) => M.reconstruct(BL(x))), [sh]);
}
for (const n of [0, 1, 2, 5, 1024, 1025]) for (const c of ['0', '9', '-9', S(P + 4n)]) await o.run('shareConstant', `${n}/${c}`, D((x: string, nn: number) => M.shareConstant(B(x), nn)), [c, n]);
const svx = [['1', '2', '3'], [S(P - 1n), '0', '5'], ['7']];
const svy = [['4', '5', '6'], [S(P - 2n), S(P - 1n), '9'], ['1']];
const svops: Record<string, (x: any, y: any) => any> = {
  add: (x, y) => M.addSV(BL(x), BL(y)), sub: (x, y) => M.subSV(BL(x), BL(y)), neg: (x) => M.negSV(BL(x)),
  scale: (x, c) => M.scaleSV(BL(x), B(c)), addPublic: (x, c) => M.addPublicSV(BL(x), B(c)), notBit: (x) => M.notBitSV(BL(x)),
};
for (const op of Object.keys(svops)) for (let i = 0; i < svx.length; i++) {
  const y: any = op === 'scale' || op === 'addPublic' ? ['0', '3', '-3', S(P), S(big(90))][i % 5] : svy[i];
  await o.run('sv', `${op}${i}`, D((oo: string, x: any, yy: any) => svops[oo]!(x, yy)), [op, svx[i], y]);
}
await o.run('sv', 'add-mismatch', D((oo: string, x: any, yy: any) => svops[oo]!(x, yy)), ['add', ['1', '2'], ['1']]);
await o.run('sv', 'sub-mismatch', D((oo: string, x: any, yy: any) => svops[oo]!(x, yy)), ['sub', ['1'], ['1', '2']]);
await o.run('sv', 'scale-empty', D((oo: string, x: any, yy: any) => svops[oo]!(x, yy)), ['scale', [], '3']);

// ---- gf128
const g128 = ['0', '1', '2', '135', S((1n << 128n) - 1n), S(1n << 127n), S(1n << 128n), S((1n << 129n) + 5n), ...Array.from({ length: 10 }, () => S(big(128)))];
for (const a of g128) {
  await o.run('gf', `mulX/${a}`.slice(0, 70), D((op: string, x: string) => M.gf128MulX(B(x))), ['mulX', a]);
  for (const i of [0, 1, 5, 127, 128, 200]) await o.run('gf', `mulByXi/${a}/${i}`.slice(0, 70), D((op: string, x: string, k: number) => M.gf128MulByXi(B(x), k)), ['mulByXi', a, i]);
}
for (let i = 0; i < g128.length; i++) for (let j = 0; j < g128.length; j += 3) {
  const a = g128[i]!, b = g128[j]!;
  await o.run('gf', `add/${i}/${j}`, D((op: string, x: string, y: string) => M.gf128Add(B(x), B(y))), ['add', a, b]);
  await o.run('gf', `mul/${i}/${j}`, D((op: string, x: string, y: string) => M.gf128Mul(B(x), B(y))), ['mul', a, b]);
}

// ---- enc
for (const s of [0, 1, 39, 40, 41, 64, 65, -1]) await o.run('encBits', `s${s}`, D((x: number) => M.encBits(x)), [s]);
for (const s of [0, 1, 39, 40, 41, 64, 65, -1]) for (const unsafe of [false, true]) for (const sd of ['1', '777']) {
  await o.run('makeGadget', `s${s}/${unsafe}/${sd}`, D((x: number, seed: string, u: boolean) => { const g = new M.FieldRng(B(seed)); return M.makeGadget(x, () => g.next(), u); }), [s, sd, unsafe]);
}
for (const x of edge) await o.run('plainShare', x, D((v: string) => M.plainShare(B(v))), [x]);
await o.run('plainGadget', 'g', D(() => M.PLAIN_GADGET), []);
for (const m of [0, 1, 59, 60, 61, 120, 253]) for (const sd of ['5', '-5']) await o.run('randomBits', `${m}/${sd}`, D((mm: number, seed: string) => M.randomBits(mm, new M.FieldRng(B(seed)))), [m, sd]);
for (const s of [0, 40, 64]) for (const sd of ['3', '31337']) {
  await o.run('sampleEnc', `s${s}/${sd}`, D((x: number, seed: string) => { const g = new M.FieldRng(B(seed)); const gad = M.makeGadget(x, () => g.next(), true); const e = M.sampleEnc(gad, g); return { gadget: gad, e }; }), [s, sd]);
}
await o.run('encValue', 'mismatch', D((g: any, bits: number[]) => M.encValue(BL(g), bits)), [['1', '2'], [1]]);
await o.run('encValue', 'ok', D((g: any, bits: number[]) => M.encValue(BL(g), bits)), [['1', '2', S(P - 1n)], [1, 0, 1]]);
await o.run('encValue', 'wrap', D((g: any, bits: number[]) => M.encValue(BL(g), bits)), [[S(P - 1n), S(P - 1n)], [1, 1]]);

// ---- beaver
for (const n of [1, 2, 3, 5]) for (const sd of ['1', '99']) await o.run('genTriple', `${n}/${sd}`, D((nn: number, seed: string) => M.genTriple(nn, new M.FieldRng(B(seed)))), [n, sd]);
const bv = (x: any, y: any, a: any, b: any, c: any) => { const op: any[] = []; const z = M.beaverMul(BL(x), BL(y), { a: BL(a), b: BL(b), c: BL(c) }, op); return { z, opened: op }; };
for (const n of [1, 2, 3, 4]) for (const sd of ['1', '2', '3']) for (const [xs, ys] of [['0', '0'], ['1', '1'], ['5', '7'], [S(P - 1n), S(P - 1n)], [S(big(60)), S(big(60))]]) {
  const rr = new M.FieldRng(B(sd)); const t = M.genTriple(n, rr);
  const x = M.share(B(xs) % P, n, rr), y = M.share(B(ys) % P, n, rr);
  await o.run('beaverMul', `${n}/${sd}/${xs}/${ys}`.slice(0, 90), D(bv), [dec(x), dec(y), dec(t.a), dec(t.b), dec(t.c)]);
}
await o.run('beaverMul', 'bad-triple', D(bv), [['1', '2'], ['3', '4'], ['1', '1'], ['1', '1'], ['1', '2']]);
await o.run('beaverMul', 'len-x-y', D(bv), [['1', '2'], ['3'], ['1', '1'], ['1', '1'], ['1', '1']]);
await o.run('beaverMul', 'len-triple', D(bv), [['1', '2'], ['3', '4'], ['1'], ['1', '1'], ['1', '1']]);

// ---- thermometer / party / compose
for (const v of [-5, -1, 0, 0.4, 0.9, 1, 1.9, 2, 2.5, 3, 4, 99, 1e9, -1e9]) for (const m of [0, 1, 3, 10]) await o.run('thermometerEncode', `${v}/${m}`, D((x: number, mm: number) => M.thermometerEncode(x, mm)), [v, m]);
for (const m of [-1, 1.5]) await o.run('thermometerEncode', `M${m}`, D((x: number, mm: number) => M.thermometerEncode(x, mm)), [2, m]);
for (const bits of [[], [1], [0], [1, 1, 0], [1, 0, 1, 1], [2, 1], ['1'], [true]]) await o.run('thermometerDecode', JSON.stringify(bits), D((b: any[]) => M.thermometerDecode(b)), [bits]);
for (const x of [0, 0.004, 0.005, 0.5, 0.505, 0.994, 0.995, 1, 1.5, -0.5, 2, 1e-12]) for (const Q of [100, 1, 7]) await o.run('quantizeR', `${x}/${Q}`, D((v: number, q: number) => M.quantizeR(v, q)), [x, Q]);
const dv = (allow: any, t: any, rQuant: any) => ({ allow, t, rQuant });
const vecs: any[] = [
  [dv(1, 1, 0)], [dv(0, 3, 5)], [dv(1, 2, 5), dv(1, 3, 1)], [dv(1, 2, 3), dv(0, 1, 4), dv(1, 3, 2)], [dv(1, 1, 0), dv(1, 1, 0), dv(1, 1, 0), dv(1, 1, 0)],
];
const hostile: any[] = [[], [dv(-1, 1, 0), dv(-1, 1, 0)], [dv(2, 1, 0)], [dv(1, 0, 0)], [dv(1, 4, 0)], [dv(1, 1, 101)], [dv(1, 1, -1)], [dv(1, 1, 1.5)], [dv(1, 1.5, 0)], [dv('1', 1, 0)], [null], [dv(1, 2, 3), 5], [dv(true, 1, 0)]];
for (const [i, v] of [...vecs, ...hostile].entries()) {
  for (const Q of [100, 10]) await o.run('composeClear', `${i}/${Q}`, D((x: any, q: number) => M.composeClear(x, q)), [v, Q]);
  await o.run('assertDecisionVectors', `${i}`, D((x: any, q: number) => { M.assertDecisionVectors(x, q); return true; }), [v, 100]);
}
const cs = (v: any, Q: any, seed: string) => {
  const res = M.composeSecure(v, { Q, seed: B(seed) });
  return { composed: res.composed, parties: res.parties, Q: res.Q, multiplications: res.multiplications, opened: res.opened, sharings: res.sharings, heldShares0: res.views[0]!.heldShares, viewsLen: res.views.length };
};
for (const [i, v] of vecs.entries()) for (const [Q, sd] of [[5, '1'], [10, '77'], [100, '4242']] as const) {
  if (Q === 100 && i > 2) continue;
  await o.run('composeSecure', `${i}/${Q}/${sd}`, D(cs), [v, Q, sd]);
}
for (const [i, v] of hostile.entries()) await o.run('composeSecure', `hostile${i}`, D(cs), [v, 10, '1']);

// ---- SPDZ (dealer)
const ctxOf = (n: number, seed: string, keys?: number) => M.setupMac(n, new M.FieldRng(B(seed)), keys);
for (const n of [1, 2, 3, 5]) for (const k of [1, 2, 3]) await o.run('setupMac', `${n}/${k}`, D((nn: number, sd: string, kk: number) => ctxOf(nn, sd, kk)), [n, '17', k]);
for (const [n, k] of [[0, 2], [-1, 2], [2, 0], [2, 17], [2, 1.5], [1.5, 2]]) await o.run('setupMac', `bad${n}/${k}`, D((nn: number, sd: string, kk: number) => ctxOf(nn, sd, kk)), [n, '17', k]);
await o.run('macSoundnessBits', 'default', D((k: number) => M.macSoundnessBits(k)), [2]);
for (const k of [1, 2, 3, 0]) await o.run('macSoundnessBits', `k${k}`, D((kk: number) => M.macSoundnessBits(kk)), [k]);
for (const [k, p] of [[1, S(1n << 61n)], [3, S(1n << 61n)], [2, S(1n << 40n)]] as const) await o.run('macSoundnessBits', `k${k}p${p}`, D((kk: number, pp: string) => M.macSoundnessBits(kk, B(pp))), [k, p]);
for (const n of [1, 2, 3]) for (const sec of ['0', '1', '-4', S(P + 9n), S(big(70))]) {
  await o.run('authShare', `${n}/${sec}`, D((nn: number, sd: string, s: string) => { const g = new M.FieldRng(B(sd)); const c = M.setupMac(nn, g); return { ctx: c, sv: M.authShare(B(s), c, g) }; }), [n, '5', sec]);
  await o.run('authConstant', `${n}/${sec}`, D((nn: number, sd: string, s: string) => { const g = new M.FieldRng(B(sd)); const c = M.setupMac(nn, g); return M.authConstant(B(s), c); }), [n, '5', sec]);
}
const AUTHOPS = ['add', 'sub', 'neg', 'scale', 'addPublic', 'notBit', 'open'];
const authOp = (op: string, n: number, sd: string, xs: string, ys: string, k: string) => {
  const g = new M.FieldRng(B(sd)); const c = M.setupMac(n, g); const x = M.authShare(B(xs), c, g), y = M.authShare(B(ys), c, g);
  const res: any = {
    add: () => M.addAuth(x, y), sub: () => M.subAuth(x, y), neg: () => M.negAuth(x), scale: () => M.scaleAuth(x, B(k)),
    addPublic: () => M.addPublicAuth(x, B(k), c), notBit: () => M.notBitAuth(x, c), open: () => M.authValue(x),
  }[op]!();
  if (op === 'open') return { val: res };
  // invariant: sum of mac shares == alpha * value (every key)
  const val = M.authValue(res);
  const okMac = [res.mac, ...res.extraMac].every((row: bigint[], l: number) => row.reduce((a, b) => M.fadd(a, b), 0n) === M.fmul(M.macKeys(c)[l]!.alpha, val));
  return { res, val, okMac };
};
for (const op of AUTHOPS) for (const n of [1, 2, 4]) for (const [x, y, k] of [['3', '9', '5'], [S(P - 1n), '0', S(P - 7n)], ['1', '1', '0'], [S(big(60)), S(big(60)), S(big(61))]]) {
  await o.run('authOp', `${op}/${n}/${x.slice(0, 10)}/${k.slice(0, 10)}`, D(authOp), [op, n, '11', x, y, k]);
}
for (const n of [1, 2, 3]) for (const sd of ['1', '2']) {
  await o.run('genAuthTriple', `${n}/${sd}`, D((nn: number, s: string) => { const g = new M.FieldRng(B(s)); const c = M.setupMac(nn, g); return M.genAuthTriple(c, g); }), [n, sd]);
  await o.run('genTripleWithPartners', `${n}/${sd}`, D((nn: number, s: string) => { const g = new M.FieldRng(B(s)); const c = M.setupMac(nn, g); return M.genTripleWithPartners(c, g); }), [n, sd]);
}
for (const [p, fault] of [[1, null], [3, null], [2, { keepCDelta: '5' }], [2, { partnerCDelta: ['1', null] }], [0, null], [9, null]] as const) {
  await o.run('genTripleWithPartners', `p${p}/${JSON.stringify(fault)}`, D((s: string, pp: number, f: any) => {
    const g = new M.FieldRng(B(s)); const c = M.setupMac(2, g);
    const ff = f ? { keepCDelta: f.keepCDelta === undefined ? undefined : B(f.keepCDelta), partnerCDelta: f.partnerCDelta?.map((x: any) => x === null ? undefined : B(x)) } : undefined;
    return M.genTripleWithPartners(c, g, pp, ff);
  }), ['3', p, fault]);
}
// MAC-check / engine: honest, value deviations, mac deviations on every key, bad key / party indexes
const dev = (d: any) => d.map((x: any) => ({ openIndex: x[0], party: x[1], valueDelta: x[2] === null ? undefined : B(x[2]), macDelta: x[3] === null ? undefined : B(x[3]), macKey: x[4] === null ? undefined : x[4] }));
const eng = (n: number, sd: string, values: string[], devs: any[], keys?: number) => {
  const g = new M.FieldRng(B(sd)); const c = M.setupMac(n, g, keys);
  const e = new M.SpdzEngine(c, dev(devs)); const outs: bigint[] = [];
  for (const [i, v] of values.entries()) outs.push(e.open(M.authShare(B(v), c, g), `v${i}`));
  e.macCheck(g);
  return { outs, count: e.openCount };
};
const E = D(eng);
await o.run('engineRun', 'honest-1', E, [2, '1', ['5'], []]);
await o.run('engineRun', 'honest-many', E, [3, '2', ['1', '2', '3', S(P - 1n), '0'], []]);
await o.run('engineRun', 'honest-none', E, [3, '2', [], []]);
await o.run('engineRun', 'single-key-refused', E, [2, '1', ['1'], [], 1]);
await o.run('engineRun', 'three-keys', E, [2, '1', ['1', '2'], [], 3]);
for (const n of [2, 3]) for (const key of [0, 1]) for (const party of [0, n - 1]) {
  await o.run('engineRun', `valdelta/${n}/${key}/${party}`, E, [n, '3', ['4', '5', '6'], [[1, party, '1', null, null]]]);
  await o.run('engineRun', `macdelta/${n}/${key}/${party}`, E, [n, '3', ['4', '5', '6'], [[2, party, null, '9', key]]]);
}
await o.run('engineRun', 'both-deltas-cancel-no', E, [2, '3', ['4'], [[0, 0, '1', '1', 0]]]);
await o.run('engineRun', 'delta-zero', E, [2, '3', ['4'], [[0, 0, '0', '0', 0]]]);
await o.run('engineRun', 'delta-p', E, [2, '3', ['4'], [[0, 0, S(P), null, null]]]);
await o.run('engineRun', 'two-cheaters', E, [3, '3', ['4', '5'], [[0, 0, '1', null, null], [1, 2, null, '3', 1]]]);
await o.run('engineRun', 'dev-beyond-opens', E, [2, '3', ['4'], [[5, 0, '1', null, null]]]);
await o.run('engineRun', 'bad-party', E, [2, '3', ['4'], [[0, 2, '1', null, null]]]);
await o.run('engineRun', 'neg-party', E, [2, '3', ['4'], [[0, -1, '1', null, null]]]);
await o.run('engineRun', 'bad-key', E, [2, '3', ['4'], [[0, 0, null, '1', 2]]]);
await o.run('engineRun', 'neg-key', E, [2, '3', ['4'], [[0, 0, null, '1', -1]]]);
// macResiduals on a tiny modulus
for (const [p, sd] of [['101', 1], ['65537', 2], [S(P), 3]] as const) {
  const q = B(p); const rr = rng(sd); const n = 3, keys = 2, m = 4;
  const alphaShares = Array.from({ length: keys }, () => Array.from({ length: n }, () => String(BigInt(rr.int(0, 100)) % q)));
  const opened = Array.from({ length: m }, () => ({ value: String(BigInt(rr.int(0, 1000)) % q), macShares: Array.from({ length: keys }, () => Array.from({ length: n }, () => String(BigInt(rr.int(0, 1000)) % q))) }));
  const challenges = Array.from({ length: keys }, () => Array.from({ length: m }, () => String(BigInt(rr.int(0, 1000)) % q)));
  await o.run('macResiduals', `${p}`, D((pp: string, a: any, op: any, ch: any) => M.macResiduals(B(pp), a.map(BL), op.map((x: any) => ({ value: B(x.value), macShares: x.macShares.map(BL) })), ch.map(BL))), [p, alphaShares, opened, challenges]);
}
// sacrifice
const sac = (n: number, sd: string, count: number, partners: number, fault: any, devs: any[]) => {
  const g = new M.FieldRng(B(sd)); const c = M.setupMac(n, g);
  const f = fault ? { keepCDelta: fault.keepCDelta === undefined ? undefined : B(fault.keepCDelta), partnerCDelta: fault.partnerCDelta?.map((x: any) => x === null ? undefined : B(x)) } : undefined;
  const batch = Array.from({ length: count }, (_, i) => M.genTripleWithPartners(c, g, partners, i === 0 ? f : undefined));
  return { certified: M.sacrificeVerify(batch, c, g, dev(devs)) };
};
for (const [n, cnt, p, f, d] of [[2, 1, 2, null, []], [3, 3, 2, null, []], [2, 2, 1, null, []], [2, 1, 2, { keepCDelta: '1' }, []], [2, 1, 2, { partnerCDelta: [null, '1'] }, []], [2, 1, 2, { partnerCDelta: ['1', '1'] }, []],
  [2, 2, 2, null, [[0, 0, '1', null, null]]], [2, 1, 2, null, [[1, 1, null, '2', 0]]], [3, 1, 2, null, [[0, 2, null, '7', 1]]]] as const) {
  await o.run('sacrifice', `${n}/${cnt}/${p}/${JSON.stringify(f)}/${JSON.stringify(d)}`.slice(0, 100), D(sac), [n, '21', cnt, p, f, d]);
}
await o.run('sacrifice', 'zero-partners', D(sac), [2, '21', 1, 0, null, []]);
// authenticated Beaver multiplication
const bauth = (n: number, sd: string, xs: string, ys: string, devs: any[]) => {
  const g = new M.FieldRng(B(sd)); const c = M.setupMac(n, g); const e = new M.SpdzEngine(c, dev(devs));
  const x = M.authShare(B(xs), c, g), y = M.authShare(B(ys), c, g); const t = M.genAuthTriple(c, g);
  const z = M.beaverMulAuth(x, y, t, c, e, 'm'); const val = M.authValue(z);
  const out = e.open(z, 'out'); e.macCheck(g);
  return { z, val, out, opens: e.openCount };
};
for (const n of [2, 3]) for (const [x, y] of [['3', '5'], ['0', '9'], [S(P - 1n), S(P - 1n)], [S(big(60)), S(big(60))]]) await o.run('beaverAuth', `${n}/${x.slice(0, 8)}`, D(bauth), [n, '9', x, y, []]);
await o.run('beaverAuth', 'cheat-d', D(bauth), [2, '9', '3', '5', [[0, 1, '1', null, null]]]);
await o.run('beaverAuth', 'cheat-e-mac', D(bauth), [3, '9', '3', '5', [[1, 0, null, '1', 1]]]);
await o.run('beaverAuth', 'cheat-out', D(bauth), [2, '9', '3', '5', [[2, 0, '1', null, null]]]);

// ---- malicious runner (trusted-dealer mode; the no-dealer default needs OT and lives in the OT oracle)
const csm = (v: any, cfg: any) => {
  const c: any = { Q: cfg.Q, seed: cfg.seed === undefined ? undefined : B(cfg.seed), deviations: cfg.deviations ? dev(cfg.deviations) : undefined, insecureTrustedDealer: cfg.insecureTrustedDealer };
  if (cfg.dealer) c.dealer = { verifyTriples: cfg.dealer.verifyTriples, partners: cfg.dealer.partners, fault: cfg.dealer.fault ? { keepCDelta: cfg.dealer.fault.keepCDelta === undefined ? undefined : B(cfg.dealer.fault.keepCDelta), partnerCDelta: cfg.dealer.fault.partnerCDelta?.map((x: any) => x === null ? undefined : B(x)) } : undefined };
  return M.composeSecureMalicious(v, c);
};
const T = { insecureTrustedDealer: true };
for (const [i, v] of vecs.entries()) for (const [Q, sd] of [[5, '1'], [12, '33']] as const) await o.run('composeSecureMalicious', `dealer/${i}/${Q}`, D(csm), [v, { ...T, Q, seed: sd }]);
await o.run('composeSecureMalicious', 'dealer/Q100', D(csm), [vecs[2], { ...T, Q: 100, seed: '5' }]);
await o.run('composeSecureMalicious', 'dealer/noverify', D(csm), [vecs[2], { ...T, Q: 5, seed: '1', dealer: { verifyTriples: false } }]);
await o.run('composeSecureMalicious', 'dealer/partners3', D(csm), [vecs[3], { ...T, Q: 5, seed: '1', dealer: { partners: 3 } }]);
await o.run('composeSecureMalicious', 'dealer/fault-keep-caught', D(csm), [vecs[2], { ...T, Q: 5, seed: '1', dealer: { fault: { keepCDelta: '1' } } }]);
await o.run('composeSecureMalicious', 'dealer/fault-partner-caught', D(csm), [vecs[2], { ...T, Q: 5, seed: '1', dealer: { fault: { partnerCDelta: ['1'] } } }]);
await o.run('composeSecureMalicious', 'dealer/fault-noverify-wrong', D(csm), [vecs[2], { ...T, Q: 5, seed: '1', dealer: { verifyTriples: false, fault: { keepCDelta: '1' } } }]);
for (const d of [[[0, 0, '1', null, null]], [[3, 1, null, '1', 0]], [[1, 0, '5', null, null]], [[2, 1, null, '5', 1]], [[40, 0, '1', null, null]]])
  await o.run('composeSecureMalicious', `dealer/dev${JSON.stringify(d)}`, D(csm), [vecs[2], { ...T, Q: 5, seed: '1', deviations: d }]);
await o.run('composeSecureMalicious', 'dealer/no-parties', D(csm), [[], { ...T, Q: 5, seed: '1' }]);
await o.run('composeSecureMalicious', 'dealer/bad-vectors', D(csm), [[dv(2, 1, 0)], { ...T, Q: 5, seed: '1' }]);
await o.run('composeSecureMalicious', 'dealer/opts-need-flag', D(csm), [vecs[2], { Q: 5, seed: '1', dealer: { verifyTriples: true } }]);

for (const c of o.cases) if (JSON.stringify(c.out).includes('is not a function') || JSON.stringify(c.out).includes('undefined')) throw new Error('generator bug in ' + c.name + ': ' + JSON.stringify(c.out).slice(0, 200));
refWrite(o, 'mpc');
