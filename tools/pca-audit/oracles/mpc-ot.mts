// Oracle: @atlasauth/pca-mpc, the oblivious-transfer stack (Ed25519 group + Schnorr, word-array kernels, base OT, IKNP/KOS extension,
// ML-KEM base OTs, hybrid base OT, MASCOT no-dealer offline phase, no-dealer malicious runner). All randomness is the seeded SplitMix64
// OtRandom / FieldRng, so a native with the same generator reproduces every point, pad, matrix and share. Big integers are DECIMAL
// STRINGS; bytes are {"$bytes": b64url}; a point is {x,y} (affine decimal strings) or, as an argument, ["X","Y","Z","T"] extended coords.
// PORTING (entry points in net.atlasauth.pca.mpc; compared by JSON value, a reference throw requires a native throw):
//   ecOp(op, a, b?) op: mulBase(k) mul(k, P) add/sub(P, Q) neg(P) compress/encode(P) decompress(bytes) -> Ec.*
//   ecValidate(P) -> {onCurve, identity, prime, inSubgroup}      schnorr(y, nonce, ctxBytes, tamper) -> {S, U, z, verifies}
//   prg(seedBytes, startBlock, nwords) / maskTail(words, nbits) / transpose32(words) / transposeCols(words, W, rows) / gfOps / kosCombine /
//   tmmo(rows, n, offset, domainBytes) / tweakDomain(bytes) / bigBytes(v, len) / bytesBig(bytes) -> Otx.*   (u32 words as JSON numbers 0..2^32-1)
//   bindingBytes(...) / kosChiWords(binding, round, u, mExt) / baseOtKdf / randomOt(choices, seed, tamper) / baseOt(messages, choices, seed, tamper) ->
//   Ot.*  channel(choices, m0, m1, seed, rounds, tamperU) -> OtChannel.extend (see args in the cases)
//   kemPad / kemBaseOt / kemBaseOtMal / kemBaseOtMalRandom / hybridBaseOt / hybridKey  -> KemOt.* / HybridOt.*
//   offline(n, seed, ...) / noDealerRun(...) -> Mascot.* / SpdzRunner.composeSecureMalicious (no-dealer default)
import * as M0 from '@atlasauth/pca-mpc';
import * as X0 from '../../../packages/pca-mpc/src/otx';
import { Oracle, refWrite, splitWrite, tokensIn, rng } from './lib.mjs';
const M: any = (M0 as any).default ?? M0;
const X: any = (X0 as any).default ?? X0;

const o = new Oracle('mpc-ot', 'tools/pca-audit/oracles/mpc-ot.mts', 'TS-reference oracle for the PCA MPC oblivious-transfer stack.');
const r = rng(0x4f54);
const dec = (v: any): any => typeof v === 'bigint' ? v.toString() : v instanceof Uint8Array ? v : v instanceof Uint32Array ? Array.from(v) : Array.isArray(v) ? v.map(dec) : v !== null && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, dec(x)])) : v;
const D = (f: (...a: any[]) => any) => (...a: any[]) => dec(f(...a));
const B = (s: any) => BigInt(s);
const bytes = (n: number) => Uint8Array.from({ length: n }, () => r.int(0, 255));
const S = (b: bigint) => b.toString();
const aff = (p: any) => { const { x, y } = M.toAffine(p); return { x: S(x), y: S(y) }; };
const P = (a: any) => ({ X: B(a[0]), Y: B(a[1]), Z: B(a[2]), T: B(a[3]) });
const ext = (p: any) => [S(p.X), S(p.Y), S(p.Z), S(p.T)];
const orng = (seed: string) => M.otRandom(M.splitMix64(B(seed)));
const mb = (n: number) => Array.from({ length: n }, () => bytes(1)[0]! & 1);
const u8 = (a: any): Uint8Array => (a instanceof Uint8Array ? a : typeof a?.$bytes === 'string' ? new Uint8Array(Buffer.from(a.$bytes, 'base64url')) : Uint8Array.from(a));

// ---- ec
const K = ['1', '2', '3', '7', '255', '1000003', S(M.L - 1n), S(M.L), S(M.L + 5n), '-1', '-12345', S(1n << 200n), S(B('123456789012345678901234567890123456789'))];
for (const [ki, k] of K.entries()) {
  await o.run('ecOp', `mulBase/${ki}`, D((op: string, a: string) => { const p = M.mulBase(B(a)); return { p: aff(p), enc: M.encodePoint(p), comp: M.compressPoint(p) }; }), ['mulBase', k]);
}
const pts = K.slice(0, 8).map((k) => M.mulBase(B(k)));
for (const [i, k] of K.entries()) for (const [j, p] of pts.entries()) {
  if ((i + j) % 3 !== 0) continue;
  await o.run('ecOp', `mul/${i}/${j}`, D((op: string, a: string, pe: any) => aff(M.mul(B(a), P(pe)))), ['mul', k, ext(p)]);
}
for (let i = 0; i < pts.length; i++) for (let j = 0; j < pts.length; j += 2) {
  await o.run('ecOp', `add/${i}/${j}`, D((op: string, a: any, b: any) => aff(M.add(P(a), P(b)))), ['add', ext(pts[i]), ext(pts[j])]);
  await o.run('ecOp', `sub/${i}/${j}`, D((op: string, a: any, b: any) => aff(M.sub(P(a), P(b)))), ['sub', ext(pts[i]), ext(pts[j])]);
}
for (let i = 0; i < pts.length; i++) await o.run('ecOp', `neg/${i}`, D((op: string, a: any) => aff(M.neg(P(a)))), ['neg', ext(pts[i])]);
await o.run('ecOp', 'add-identity', D((op: string, a: any, b: any) => aff(M.add(P(a), P(b)))), ['add', ext(M.IDENTITY), ext(pts[0])]);
await o.run('ecOp', 'double', D((op: string, a: any) => aff(M.dbl(P(a)))), ['dbl', ext(pts[1])]);
// compressed encodings: honest, identity, small order, y >= q, off curve, wrong length, non-canonical sign
const encs: string[] = ['01' + '00'.repeat(31), 'ec' + 'ff'.repeat(30) + '7f', '00'.repeat(32), '00'.repeat(31) + '80', 'ff'.repeat(31) + '7f', 'ed' + 'ff'.repeat(30) + '7f', 'ee' + 'ff'.repeat(30) + '7f',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa', '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05', '0200' + '00'.repeat(30), '01' + '00'.repeat(30) + '80'];
for (const p of pts) encs.push(Buffer.from(M.compressPoint(p)).toString('hex'));
for (const [i, h] of encs.entries()) {
  await o.run('ecOp', `decompress/${i}`, D((op: string, b: any) => { const p = M.decompressPoint(u8(b)); return { p: aff(p), onCurve: M.isOnCurve(p), identity: M.isIdentity(p), prime: M.hasPrimeOrder(p), inSub: M.isInSubgroup(p) }; }), ['decompress', { $bytes: Buffer.from(h, 'hex').toString('base64url') }]);
}
await o.run('ecOp', 'decompress/len31', D((op: string, b: any) => M.decompressPoint(u8(b))), ['decompress', { $bytes: Buffer.alloc(31).toString('base64url') }]);
// validation of crafted extended points
const q = M.Q;
const crafted: Record<string, any[]> = {
  honest: ext(pts[1]), identity: ext(M.IDENTITY), zeroZ: ['1', '2', '0', '2'], badT: ['3', '4', '1', '5'], offCurve: ['5', '7', '1', S((5n * 7n) % q)],
  order2: ['0', S(q - 1n), '1', '0'],
};
for (const [n, e] of Object.entries(crafted)) {
  await o.run('ecValidate', n, D((e: any) => { const p = P(e); return { onCurve: M.isOnCurve(p), identity: M.isIdentity(p), prime: M.hasPrimeOrder(p), inSubgroup: M.isInSubgroup(p) }; }), [e]);
  await o.run('ecAssert', n, D((e: any) => { M.assertInSubgroup(P(e), 'p'); return true; }), [e]);
}
// schnorr
const ctxs = [Buffer.from('session-one').toString('base64url'), Buffer.from('x').toString('base64url'), ''];
for (const [yi, y] of ['5', '123456789', S(M.L - 1n), '0', S(M.L + 3n)].entries()) for (const [ci, c] of ctxs.entries()) for (const nonce of ['1', '99', S(M.L), '-1']) {
  await o.run('schnorr', `${yi}/${ci}/${nonce}`.slice(0, 60), D((yy: string, n: string, cb: string) => {
    const ctx = u8({ $bytes: cb }); const Sp = M.mulBase(B(yy));
    const proof = M.schnorrProve(B(yy), Sp, () => B(n), ctx);
    const other = u8({ $bytes: Buffer.from('other-ctx').toString('base64url') });
    const forged = { U: proof.U, z: (proof.z + 1n) % M.L }; const oor = { U: proof.U, z: M.L };
    return { S: aff(Sp), U: aff(proof.U), z: proof.z, ok: M.schnorrVerify(Sp, proof, ctx), badCtx: M.schnorrVerify(Sp, proof, other), forged: M.schnorrVerify(Sp, forged, ctx), oor: M.schnorrVerify(Sp, oor, ctx), wrongS: M.schnorrVerify(M.mulBase(B(yy) + 1n), proof, ctx), identityS: M.schnorrVerify(M.IDENTITY, proof, ctx) };
  }), [y, nonce, c]);
}

// ---- otx kernels (u32 words are JSON numbers)
for (const [i, n] of [1, 2, 3, 7, 9].entries()) for (const sb of [0, 1, 17, 4096]) {
  const seed = Buffer.from(bytes(16)).toString('base64url');
  await o.run('prg', `${i}/${sb}`, D((s: string, b: number, nw: number) => X.prgColumn(u8({ $bytes: s }), b, nw)), [seed, sb, n * 5]);
}
for (const nb of [0, 1, 31, 32, 33, 64, 100, 128]) await o.run('maskTail', `${nb}`, D((w: number[], b: number) => { const a = Uint32Array.from(w); X.maskTail(a, b); return a; }), [Array.from({ length: 5 }, () => r.int(0, 2 ** 31) * 2 + 1), nb]);
for (let t = 0; t < 4; t++) await o.run('transpose32', `${t}`, D((w: number[]) => { const a = Uint32Array.from(w); X.transpose32(a); return a; }), [Array.from({ length: 32 }, () => (r.int(0, 65535) << 16 | r.int(0, 65535)) >>> 0)]);
for (const [W, rows] of [[1, 1], [1, 32], [2, 33], [3, 70], [4, 100], [5, 129]] as const) {
  await o.run('transposeCols', `${W}/${rows}`, D((w: number[], WW: number, rr: number) => X.transposeCols(Uint32Array.from(w), WW, rr)), [Array.from({ length: 128 * W }, () => (r.int(0, 65535) << 16 | r.int(0, 65535)) >>> 0), W, rows]);
}
for (let t = 0; t < 6; t++) {
  const w4 = () => Array.from({ length: 4 }, () => (r.int(0, 65535) << 16 | r.int(0, 65535)) >>> 0);
  await o.run('gfMulX', `${t}`, D((a: number[]) => { const x = Uint32Array.from(a); X.gfMulX(x); return x; }), [t === 0 ? [0, 0, 0, 0x80000000] : w4()]);
  await o.run('gfXorInto', `${t}`, D((a: number[], b: number[]) => { const x = Uint32Array.from(a); X.gfXorInto(x, Uint32Array.from(b), 0); return x; }), [w4(), w4()]);
  await o.run('gfBig', `${t}`, D((a: number[]) => ({ big: X.gfToBig(Uint32Array.from(a)), back: X.gfFromBig(X.gfToBig(Uint32Array.from(a))) })), [w4()]);
}
for (const W of [1, 2, 5]) {
  await o.run('accumColumn', `${W}`, D((c: number[], chi: number[]) => { const acc = new Uint32Array(4); X.accumColumn(Uint32Array.from(c), Uint32Array.from(chi), acc); return acc; }),
    [Array.from({ length: W }, () => (r.int(0, 65535) << 16 | r.int(0, 65535)) >>> 0), Array.from({ length: W * 32 * 4 }, () => (r.int(0, 65535) << 16 | r.int(0, 65535)) >>> 0)]);
  await o.run('kosCombine', `${W}`, D((c: number[], WW: number, chi: number[]) => X.kosCombine(Uint32Array.from(c), WW, Uint32Array.from(chi))),
    [Array.from({ length: 128 * W }, () => (r.int(0, 65535) << 16 | r.int(0, 65535)) >>> 0), W, Array.from({ length: W * 32 * 4 }, () => (r.int(0, 65535) << 16 | r.int(0, 65535)) >>> 0)]);
}
for (const n of [1, 2, 5, 33]) for (const [off, dom] of [[0, [0, 0]], [7, [1, 2]], [4294967290, [0xdeadbeef, 0xffffffff]], [2 ** 40 + 3, [5, 6]]] as const) {
  await o.run('tmmo', `${n}/${off}`, D((rows: number[], nn: number, o2: number, d: number[]) => X.tmmoCrh(Uint32Array.from(rows), nn, { offset: o2, domain: Uint32Array.from(d) })), [Array.from({ length: n * 4 }, () => (r.int(0, 65535) << 16 | r.int(0, 65535)) >>> 0), n, off, dom]);
}
const tm = D((rows: number[], nn: number, off: number, d: number[]) => X.tmmoCrh(Uint32Array.from(rows), nn, { offset: off, domain: Uint32Array.from(d) }));
await o.run('tmmo', 'noTweak', tm, [Array.from({ length: 12 }, () => (r.int(0, 65535) << 16 | r.int(0, 65535)) >>> 0), 3, 0, [0, 0]]);
await o.run('tmmo', 'bad-offset', tm, [[0, 0, 0, 0], 1, -1, [0, 0]]);
await o.run('tmmo', 'bad-domain', tm, [[0, 0, 0, 0], 1, 0, [0, 0, 0]]);
for (const l of [0, 1, 5, 16, 33]) await o.run('tweakDomain', `${l}`, D((b: string) => X.otTweakDomain(u8({ $bytes: b }))), [Buffer.from(bytes(l)).toString('base64url')]);
for (const [v, len] of [['0', 1], ['255', 1], ['256', 1], ['65535', 4], [S(1n << 127n), 16], [S((1n << 130n) + 5n), 16], ['1', 0], [S(1n << 200n), 32]] as const) {
  await o.run('bigBytes', `${v}/${len}`.slice(0, 50), D((x: string, l: number) => X.bigToBytes(B(x), l)), [v, len]);
}
for (const l of [0, 1, 2, 5, 16]) await o.run('bytesBig', `${l}`, D((b: string) => X.bytesToBig(u8({ $bytes: b }))), [Buffer.from(bytes(l)).toString('base64url')]);
await o.run('word64', 'w', D((h: number[], j: number) => X.word64(Uint32Array.from(h), j)), [[1, 2, 0xffffffff, 0x80000000], 1]);

// ---- ot: binding, kdf, base OT
const sess = Buffer.from(bytes(16)).toString('base64url');
const bindOf = (s: string, a: number, b: number, round: string) => ({ sessionId: u8({ $bytes: s }), senderIndex: a, receiverIndex: b, round });
for (const [n, s, a, b, rd] of [['ok', sess, 0, 1, 'base-ot'], ['short', Buffer.alloc(7).toString('base64url'), 0, 1, 'x'], ['long', Buffer.alloc(65).toString('base64url'), 0, 1, 'x'], ['min', Buffer.alloc(8).toString('base64url'), 0, 1, 'x'], ['max', Buffer.alloc(64).toString('base64url'), 0, 1, 'x'],
  ['same', sess, 2, 2, 'x'], ['neg', sess, -1, 1, 'x'], ['big', sess, 0, 4294967296, 'x'], ['u32max', sess, 4294967295, 0, 'x'], ['frac', sess, 0.5, 1, 'x'], ['emptyRound', sess, 0, 1, ''], ['longRound', sess, 0, 1, 'r'.repeat(65)], ['maxRound', sess, 0, 1, 'r'.repeat(64)], ['utf8Round', sess, 0, 1, 'é'.repeat(32)], ['utf8Long', sess, 0, 1, 'é'.repeat(33)]] as const) {
  await o.run('bindingBytes', n, D((ss: string, aa: number, bb: number, rr: string) => M.bindingBytes(bindOf(ss, aa, bb, rr))), [s, a, b, rd]);
}
const TAMPER: Record<string, any> = {
  none: undefined,
  S_identity: { tamperS: () => M.IDENTITY },
  S_order2: { tamperS: () => P(['0', S(q - 1n), '1', '0']) },
  S_other: { tamperS: (s: any) => M.add(s, M.BASE) },
  proof_z: { tamperProof: (p: any) => ({ U: p.U, z: (p.z + 1n) % M.L }) },
  proof_U: { tamperProof: (p: any) => ({ U: M.add(p.U, M.BASE), z: p.z }) },
  R0_identity: { tamperR: (R: any[]) => { R[0] = M.IDENTITY; } },
  R1_order2: { tamperR: (R: any[]) => { if (R.length > 1) R[1] = P(['0', S(q - 1n), '1', '0']); } },
  R_swap: { tamperR: (R: any[]) => { if (R.length > 1) [R[0], R[1]] = [R[1], R[0]]; } },
  ct_flip: { tamperCiphertext: (ct: any[]) => { ct[0][0] = ct[0][0].map((b: number) => b ^ 1); } },
  ct_flip1: { tamperCiphertext: (ct: any[]) => { ct[ct.length - 1][1] = ct[ct.length - 1][1].map((b: number) => b ^ 0x80); } },
};
const tnames = Object.keys(TAMPER);
const BSEED = '4242';
const bind0 = M.randomBinding(orng(BSEED), 'base-ot');
await o.run('baseOtKdf', 'kdf', D((i: number) => { const R = [M.mulBase(5n), M.mulBase(6n)]; const th = M.baseOtTranscriptHash(bind0, M.mulBase(3n), R); return { th, k: M.baseOtKdf(th, i, R[0], M.mulBase(9n)) }; }), [0]);
await o.run('baseOtKdf', 'kdf1', D((i: number) => { const R = [M.mulBase(5n), M.mulBase(6n)]; const th = M.baseOtTranscriptHash(bind0, M.mulBase(3n), R); return { th, k: M.baseOtKdf(th, i, R[0], M.mulBase(9n)) }; }), [7]);
const roT = (choices: number[], seed: string, tn: string) => {
  const res = M.malBaseRandomOT(choices, orng(seed), TAMPER[tn]);
  return { S: aff(res.S), U: aff(res.proof.U), z: res.proof.z, R: res.R.map(aff), senderPads: res.senderPads, recvPads: res.recvPads };
};
for (const sd of ['1', '77']) for (const choices of [[], [0], [1], [0, 1], [1, 0, 1, 1], mb(16)]) await o.run('randomOt', `${sd}/${choices.join('')}`, D(roT), [choices, sd, 'none']);
for (const tn of tnames.slice(1)) await o.run('randomOt', `tamper/${tn}`, D(roT), [[1, 0, 1], '5', tn]);
const baseT = (messages: any[], choices: number[], seed: string, tn: string) => {
  const res = M.baseOT(messages.map(([a, b]: any) => [u8(a), u8(b)]), choices, orng(seed), TAMPER[tn]);
  const t = res.transcript;
  return { received: res.received, S: aff(t.S), U: aff(t.proof.U), z: t.proof.z, R: t.R.map(aff), ct: t.ct, com: t.com };
};
const msgs = (n: number, len: number) => Array.from({ length: n }, () => [{ $bytes: Buffer.from(bytes(len)).toString('base64url') }, { $bytes: Buffer.from(bytes(len)).toString('base64url') }]);
for (const [n, len] of [[0, 16], [1, 16], [3, 16], [4, 8], [5, 1], [2, 0]] as const) await o.run('baseOt', `${n}/${len}`, D(baseT), [msgs(n, len), mb(n), '9', 'none']);
await o.run('baseOt', 'len-mismatch', D(baseT), [msgs(2, 16), [1], '9', 'none']);
await o.run('baseOt', 'too-long', D(baseT), [msgs(1, 17), [1], '9', 'none']);
await o.run('baseOt', 'unequal-pair', D(baseT), [[[{ $bytes: Buffer.alloc(4).toString('base64url') }, { $bytes: Buffer.alloc(5).toString('base64url') }]], [0], '9', 'none']);
for (const tn of tnames.slice(1)) await o.run('baseOt', `tamper/${tn}`, D(baseT), [msgs(3, 16), [1, 0, 1], '5', tn]);

// ---- IKNP + KOS channel
const chT = (choices: number[], m0: string[], m1: string[], seed: string, rounds: number, tamper: string | null) => {
  const ch = new M.OtChannel(orng(seed));
  if (tamper === 'flip00') ch.tamperU = (u: bigint[]) => { u[0] = u[0]! ^ 1n; };
  else if (tamper === 'flipLast') ch.tamperU = (u: bigint[]) => { u[127] = u[127]! ^ (1n << 5n); };
  else if (tamper === 'oversize') ch.tamperU = (u: bigint[]) => { u[3] = u[3]! | (1n << 5000n); };
  else if (tamper === 'negative') ch.tamperU = (u: bigint[]) => { u[3] = -1n; };
  else if (tamper === 'round2flip') ch.tamperU = (u: bigint[], round: number) => { if (round === 1) u[10] = u[10]! ^ 2n; };
  const outs: any[] = [];
  for (let k = 0; k < rounds; k++) outs.push(ch.extend(choices, m0.map(B), m1.map(B)));
  return { selector: ch.selector, outs, base: ch.baseTranscript ? { S: aff(ch.baseTranscript.S), R: ch.baseTranscript.R.length } : null };
};
const w64 = () => S(BigInt(r.int(0, 2 ** 31)) * 2n ** 33n + BigInt(r.int(0, 2 ** 31)));
for (const [m, rounds, sd] of [[0, 1, '3'], [1, 1, '3'], [5, 1, '11'], [40, 2, '12'], [100, 1, '13'], [200, 2, '14']] as const) {
  const ch = mb(m), m0 = Array.from({ length: m }, w64), m1 = Array.from({ length: m }, w64);
  await o.run('channel', `${m}/${rounds}`, D(chT), [ch, m0, m1, sd, rounds, null]);
}
for (const tn of ['flip00', 'flipLast', 'oversize', 'negative', 'round2flip']) await o.run('channel', `tamper/${tn}`, D(chT), [mb(20), Array.from({ length: 20 }, w64), Array.from({ length: 20 }, w64), '21', 2, tn]);
await o.run('channel', 'bad-choice', D(chT), [[0, 2], [S(1n), S(2n)], [S(3n), S(4n)], '3', 1, null]);
await o.run('channel', 'msg-negative', D(chT), [[0, 1], ['-1', '2'], ['3', '4'], '3', 1, null]);
await o.run('channel', 'msg-2pow64', D(chT), [[0, 1], [S(1n << 64n), '2'], ['3', '4'], '3', 1, null]);
await o.run('channel', 'msg-max', D(chT), [[0, 1], [S((1n << 64n) - 1n), '2'], ['3', S((1n << 64n) - 1n)], '3', 1, null]);
await o.run('channel', 'len-mismatch', D(chT), [[0, 1], ['1'], ['3', '4'], '3', 1, null]);
const kosT = (bs: string, round: number, u: string[], mExt: number) => ({ w: M.kosChiWords(u8({ $bytes: bs }), round, u.map(B), mExt), chi: M.kosChallenges(u8({ $bytes: bs }), round, u.map(B), mExt) });
for (const [mExt, round] of [[1, 0], [8, 0], [9, 3], [260, 1]] as const) await o.run('kosChi', `${mExt}/${round}`, D(kosT), [Buffer.from(bytes(20)).toString('base64url'), round, Array.from({ length: 128 }, () => S(BigInt(r.int(0, 2 ** 31)) % (1n << BigInt(Math.min(mExt, 30))))), mExt]);

// ---- KEM base OT and hybrid
const msgPairs = (a: any[]) => a.map(([x, y]: any) => [u8(x), u8(y)]);
const kemT = (fnName: string, messages: any[], choices: number[], seed: string, tn: string | null) => {
  const g = orng(seed);
  const tamper = tn === 'badKey' ? { tamperOpenedKeys: (pk: any[]) => { pk[0] = [pk[0][1], pk[0][0]]; } } : tn === 'badSid' ? { tamperReceiverSid: (s: Uint8Array) => s.map((b) => b ^ 1) } : undefined;
  if (fnName === 'kemBaseOT') return M.kemBaseOT(msgPairs(messages), choices, g);
  if (fnName === 'kemBaseOtMal') return M.kemBaseOtMal(msgPairs(messages), choices, g, tamper);
  return M.kemBaseOtMalRandom(choices, g, tamper);
};
for (const fnName of ['kemBaseOT', 'kemBaseOtMal', 'kemBaseOtMalRandom']) {
  for (const [n, len] of [[1, 16], [3, 32], [2, 5]] as const) await o.run('kemOt', `${fnName}/${n}/${len}`, D(kemT), [fnName, msgs(n, len), mb(n), '31', null]);
  if (fnName !== 'kemBaseOT') for (const tn of ['badKey', 'badSid']) await o.run('kemOt', `${fnName}/tamper/${tn}`, D(kemT), [fnName, msgs(2, 16), [0, 1], '31', tn]);
}
for (const [idx, slot, len] of [[0, 0, 0], [1, 1, 16], [2, 0, 32], [3, 1, 33], [4, 0, 100]] as const) await o.run('kemPad', `${idx}/${slot}/${len}`, D((i: number, s: number, l: number) => M.kemOtPad(i, s, bytes(32).map((_, k) => k), l)), [idx, slot, len]);
await o.run('kemPad', 'huge', D((l: number) => M.kemOtPad(0, 0, new Uint8Array(32), l)), [(1 << 20) + 1]);
const hybT = (messages: any[], choices: number[], seed: string, tn: string | null) => {
  const tamper = tn === 'ec' ? { ec: TAMPER.ct_flip } : tn === 'ecS' ? { ec: TAMPER.S_identity } : tn === 'enc' ? { tamperEncrypted: (e: any[]) => { e[0][0] = e[0][0].map((b: number) => b ^ 1); } } : tn === 'kem' ? { kem: { tamperOpenedKeys: (pk: any[]) => { pk[0] = [pk[0][1], pk[0][0]]; } } } : undefined;
  const res = M.hybridBaseOT(msgPairs(messages), choices, orng(seed), tamper);
  return { received: res.received, sid: res.transcript.sid, ecS: aff(res.transcript.ecS), kemSid: res.transcript.kemSid, encrypted: res.transcript.encrypted, commitments: res.transcript.commitments };
};
for (const [n, len] of [[1, 16], [3, 16], [2, 7]] as const) await o.run('hybridOt', `${n}/${len}`, D(hybT), [msgs(n, len), mb(n), '51', null]);
for (const tn of ['ec', 'ecS', 'enc', 'kem']) await o.run('hybridOt', `tamper/${tn}`, D(hybT), [msgs(2, 16), [1, 0], '51', tn]);
await o.run('hybridOt', 'len-mismatch', D(hybT), [msgs(2, 16), [1], '51', null]);
await o.run('hybridKey', 'k', D((len: number) => M.hybridTransferKey(new Uint8Array(32).fill(1), 3, 1, new Uint8Array(16).fill(2), new Uint8Array(32).fill(3), len)), [40]);

// ---- MASCOT no-dealer offline
const offT = (n: number, seed: string, what: string, opts: any) => {
  const off = M.makeNoDealerOffline(n, B(seed), opts ? { sacrifice: opts.sacrifice, sacrificePartners: opts.partners, macKeys: opts.keys, statSec: opts.statSec, unsafeStatSec: opts.unsafe, deviation: opts.dev ? { productMul: opts.dev[0], delta: B(opts.dev[1]) } : undefined } : undefined);
  const ctx = off.macContext;
  const base = { n: off.n, statSec: off.statSec, ctx };
  if (what === 'ctx') return base;
  if (what === 'triple') return { ...base, t: off.genAuthTriple() };
  if (what === 'input') return { ...base, v: off.authInput(B(opts.value), opts.owner) };
  if (what === 'multiply') {
    const x = Array.from({ length: n }, (_, i) => B(opts.x[i])); const y = Array.from({ length: n }, (_, i) => B(opts.y[i]));
    const z = off.otShareMultiply(x, y);
    return { ...base, z, sum: z.reduce((a: bigint, b: bigint) => M.fadd(a, b), 0n), expect: M.fmul(x.reduce((a: bigint, b: bigint) => M.fadd(a, b), 0n), y.reduce((a: bigint, b: bigint) => M.fadd(a, b), 0n)) };
  }
  if (what === 'consistency') {
    const ins = opts.values.map((v: string, i: number) => off.authInput(B(v), i % n));
    if (opts.tamper) ins[0].value[0] = M.fadd(ins[0].value[0], 1n);
    off.checkInputConsistency(ins);
    return { ...base, ok: true };
  }
  throw new Error('what');
};
await o.run('offline', 'ctx/2', D(offT), [2, '7', 'ctx', null]);
await o.run('offline', 'ctx/3', D(offT), [3, '8', 'ctx', null]);
await o.run('offline', 'bad-n', D(offT), [0, '7', 'ctx', null]);
await o.run('offline', 'bad-keys', D(offT), [2, '7', 'ctx', { keys: 0 }]);
await o.run('offline', 'bad-partners', D(offT), [2, '7', 'ctx', { partners: 9 }]);
await o.run('offline', 'weak-statSec', D(offT), [2, '7', 'ctx', { statSec: 10 }]);
await o.run('offline', 'weak-statSec-unsafe', D(offT), [2, '7', 'ctx', { statSec: 0, unsafe: true }]);
await o.run('offline', 'multiply/2', D(offT), [2, '7', 'multiply', { x: ['12345', '678'], y: ['999', '4242'] }]);
await o.run('offline', 'multiply/3', D(offT), [3, '9', 'multiply', { x: ['1', '2', S(M.PRIME - 1n)], y: ['5', S(M.PRIME - 2n), '7'] }]);
await o.run('offline', 'input/2', D(offT), [2, '7', 'input', { value: '42', owner: 1 }]);
await o.run('offline', 'input/bad-owner', D(offT), [2, '7', 'input', { value: '42', owner: 2 }]);
await o.run('offline', 'triple/2', D(offT), [2, '7', 'triple', null]);
await o.run('offline', 'triple/nosac', D(offT), [2, '7', 'triple', { sacrifice: false }]);
await o.run('offline', 'triple/1key-1partner', D(offT), [2, '7', 'triple', { keys: 1, partners: 1 }]);
await o.run('offline', 'triple/3', D(offT), [3, '10', 'triple', { partners: 1 }]);
await o.run('offline', 'triple/cheat0', D(offT), [2, '7', 'triple', { dev: [0, '1'] }]);
await o.run('offline', 'triple/cheat1', D(offT), [2, '7', 'triple', { dev: [1, '5'] }]);
await o.run('offline', 'consistency/ok', D(offT), [2, '7', 'consistency', { values: ['1', '2', '3'] }]);
await o.run('offline', 'consistency/tamper', D(offT), [2, '7', 'consistency', { values: ['1', '2'], tamper: true }]);
// the blame list of a cheating run (the message carries "names party ...")
await o.run('offlineBlame', 'cheat0', D((n: number, seed: string, dm: number, dd: string) => {
  try { M.makeNoDealerOffline(n, B(seed), { deviation: { productMul: dm, delta: B(dd) } }).genAuthTriple(); return { aborted: false }; } catch (e: any) { return { aborted: true, name: e.name, blamed: e.blamed ?? null }; }
}), [2, '7', 0, '1']);

// ---- malicious runner, no-dealer default
const nd = (v: any, cfg: any) => M.composeSecureMalicious(v, { Q: cfg.Q, seed: B(cfg.seed), deviations: cfg.deviations?.map((x: any) => ({ openIndex: x[0], party: x[1], valueDelta: x[2] === null ? undefined : B(x[2]), macDelta: x[3] === null ? undefined : B(x[3]), macKey: x[4] === null ? undefined : x[4] })) });
const dv = (allow: number, t: number, rQuant: number) => ({ allow, t, rQuant });
await o.run('noDealerRun', 'two-parties', D(nd), [[dv(1, 2, 2), dv(1, 3, 1)], { Q: 3, seed: '5' }]);
await o.run('noDealerRun', 'deny', D(nd), [[dv(1, 2, 2), dv(0, 1, 3)], { Q: 3, seed: '6' }]);
await o.run('noDealerRun', 'one-party', D(nd), [[dv(1, 3, 2)], { Q: 3, seed: '7' }]);
await o.run('noDealerRun', 'cheat-open', D(nd), [[dv(1, 2, 2), dv(1, 3, 1)], { Q: 3, seed: '5', deviations: [[0, 1, '1', null, null]] }]);
await o.run('noDealerRun', 'cheat-mac', D(nd), [[dv(1, 2, 2), dv(1, 3, 1)], { Q: 3, seed: '5', deviations: [[2, 0, null, '1', 1]] }]);
await o.run('noDealerRun', 'three-parties', D(nd), [[dv(1, 1, 1), dv(1, 2, 0), dv(1, 3, 2)], { Q: 2, seed: '8' }]);

for (const c of o.cases) if (JSON.stringify(c.out).includes('is not a function') || JSON.stringify(c.out).includes('undefined')) throw new Error('generator bug in ' + c.name + ': ' + JSON.stringify(c.out).slice(0, 200));
splitWrite(o, 'mpc-ot', (j: string) => tokensIn(j, /"recvSecrets":\[([^\]]*)\]/g));
