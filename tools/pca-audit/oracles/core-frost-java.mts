// Oracle: core FROST threshold signing (RFC 9591, FROST(Ed25519, SHA-512)) from packages/pca/src/frost.ts.
// Everything is deterministic: the dealer secret / coefficients and every nonce randomness derive from fixed seeds, so key shares, commitments,
// signature shares and the aggregate are byte-stable. The one-shot nonce registry is global state, so each signing case uses randomness no other
// case uses; double-use refusals are covered by native unit tests instead. Bytes cross as {"$bytes": b64url}; numbers are JSON numbers.
// PORTING (fn(args) -> native entry point; compared by JSON value; a reference throw requires the native to throw):
//   scalar(bytes) -> bytes                       scalarToBytes(bytesToScalar(b)): reduce 0..64 LE bytes mod L (65+ bytes throw)
//   isCanonicalScalar(bytes) -> bool
//   hash(which, msg) -> bytes                    which in H1..H5; H1/H2/H3 return scalarToBytes of the scalar, H4/H5 the 64-byte digest
//   decodeSafePoint(bytes) -> bytes              the canonical re-encoding, or a throw (non-canonical, off-curve, small order, mixed order)
//   keygen({t, n, secret?, coefficients?, identifiers?}) -> {groupPublicKey, participantShares:[{identifier, share, publicKey}], groupCommitment:[bytes]}
//   verifyingShare(share) -> bytes
//   commit(id, share, hidingRandomness, bindingRandomness) -> {hidingNonce, bindingNonce, commitment:{identifier, hiding, binding}}
//   flow({t, n, secret, coefficients, identifiers, signers:[id], message, randomness:[{hr, br}], threshold}) -> keygen result + {commitments, sigShares, aggregate}
//       (keygen, per-signer commit with the given randomness, sign with verificationShare(s) and threshold, aggregate)
//   sign(id, share, groupPublicKey, nonces{hiding, binding}, message, commitments, opts{threshold?, verificationShare?, verificationShares?}) -> {identifier, sigShare}
//   aggregate(message, commitments, sigShares, groupPublicKey, opts{threshold?, verificationShares}) -> bytes
//   verifySigShare({identifier, publicKey, commitment, sigShare, signingCommitments, groupPublicKey, message}) -> bool (never throws)
//   cosign(groupPublicKey, quorum, message, opts) -> true when the (random-nonce) aggregate verifies as strict Ed25519; refusals throw
import * as FR0 from '@atlasauth/pca/ext/frost';
import { ed25519 } from '@noble/curves/ed25519';
import { Oracle, refWrite, splitWrite, tokensIn, seed, reparse, jsonOut, ser } from './lib.mjs';

const FR: any = (FR0 as any).default ?? FR0;
const o = new Oracle('core-frost-java', 'tools/pca-audit/oracles/core-frost-java.mts', 'TS-reference oracle for core FROST threshold signing (RFC 9591, Ed25519/SHA-512).');
const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64url');
const B = (u: Uint8Array) => ({ $bytes: b64(u) });
const un = (v: any): any => {
  if (Array.isArray(v)) return v.map(un);
  if (v !== null && typeof v === 'object') {
    if (typeof v.$bytes === 'string' && Object.keys(v).length === 1) return new Uint8Array(Buffer.from(v.$bytes, 'base64url'));
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, un(x)]));
  }
  return v;
};
const J = (x: any) => JSON.parse(ser(x)); // JSON form with {$bytes}
const sd = (l: string) => seed('ref-frost/' + l);
const run = (fn: string, name: string, f: (...a: any[]) => any, args: any[]) => o.run(fn, name, f, args);
const clone = (x: any) => JSON.parse(JSON.stringify(x));
const flipB = (v: any, i = 0) => { const u = un(v); u[i] ^= 1; return B(u); };
const addL = (v: any) => { let x = 0n; const u = un(v); for (let i = 31; i >= 0; i--) x = (x << 8n) | BigInt(u[i]); x += FR.L; const out = new Uint8Array(32); for (let i = 0; i < 32; i++) { out[i] = Number(x & 0xffn); x >>= 8n; } return B(out); };

// ---- scalars and hashes
const scalar = (b: any) => FR.scalarToBytes(FR.bytesToScalar(un(b)));
for (const len of [0, 1, 31, 32, 33, 63, 64, 65]) await run('scalar', 'len' + len, scalar, [B(Uint8Array.from({ length: len }, (_, i) => sd('scalar/' + len)[i % 32]))]);
await run('scalar', 'all-ff-32', scalar, [B(new Uint8Array(32).fill(255))]);
await run('scalar', 'all-ff-64', scalar, [B(new Uint8Array(64).fill(255))]);
await run('scalar', 'zero-32', scalar, [B(new Uint8Array(32))]);
await run('scalar', 'L', scalar, [addL(B(new Uint8Array(32)))]);
await run('scalar', 'L-minus-1', scalar, [(() => { const u = un(addL(B(new Uint8Array(32)))); u[0] -= 1; return B(u); })()]);
await run('isCanonicalScalar', 'zero', (b: any) => FR.isCanonicalScalar(un(b)), [B(new Uint8Array(32))]);
await run('isCanonicalScalar', 'one', (b: any) => FR.isCanonicalScalar(un(b)), [B(Uint8Array.from({ length: 32 }, (_, i) => (i === 0 ? 1 : 0)))]);
await run('isCanonicalScalar', 'L', (b: any) => FR.isCanonicalScalar(un(b)), [addL(B(new Uint8Array(32)))]);
await run('isCanonicalScalar', 'L-1', (b: any) => FR.isCanonicalScalar(un(b)), [(() => { const u = un(addL(B(new Uint8Array(32)))); u[0] -= 1; return B(u); })()]);
await run('isCanonicalScalar', 'ff', (b: any) => FR.isCanonicalScalar(un(b)), [B(new Uint8Array(32).fill(255))]);
await run('isCanonicalScalar', 'short', (b: any) => FR.isCanonicalScalar(un(b)), [B(new Uint8Array(31))]);
await run('isCanonicalScalar', 'long', (b: any) => FR.isCanonicalScalar(un(b)), [B(new Uint8Array(33))]);
await run('isCanonicalScalar', 'null', (b: any) => FR.isCanonicalScalar(un(b)), [null]);
const hash = (which: string, m: any) => { const f = FR[which]; const r = f(un(m)); return r instanceof Uint8Array ? r : FR.scalarToBytes(r); };
for (const w of ['H1', 'H2', 'H3', 'H4', 'H5']) for (const [n, m] of [['empty', new Uint8Array()], ['abc', new TextEncoder().encode('abc')], ['seed', sd('hash')], ['long', Uint8Array.from({ length: 300 }, (_, i) => i & 255)]] as [string, Uint8Array][]) await run('hash', `${w}-${n}`, hash, [w, B(m)]);

// ---- point decoding
const dsp = (b: any) => FR.decodeSafePoint(un(b)).toRawBytes();
const hexB = (h: string) => B(Uint8Array.from(Buffer.from(h, 'hex')));
const SMALL = [
  '0100000000000000000000000000000000000000000000000000000000000000', 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', '0000000000000000000000000000000000000000000000000000000000000000',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a', '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05', '0000000000000000000000000000000000000000000000000000000000000080',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa', '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
];
for (const [i, h] of SMALL.entries()) await run('decodeSafePoint', 'small-' + i, dsp, [hexB(h)]);
const smallPts = SMALL.slice(0, 5).map((h) => { try { return ed25519.ExtendedPoint.fromHex(h); } catch { return null; } }).filter(Boolean) as any[];
const EP = ed25519.ExtendedPoint;
const pts: Uint8Array[] = [];
for (let i = 1; i <= 6; i++) pts.push(EP.BASE.multiply(BigInt(i) * 7919n + BigInt(i)).toRawBytes());
for (const [i, p] of pts.entries()) await run('decodeSafePoint', 'good-' + i, dsp, [B(p)]);
await run('decodeSafePoint', 'base', dsp, [B(EP.BASE.toRawBytes())]);
for (const [i, sp] of smallPts.entries()) await run('decodeSafePoint', 'mixed-' + i, dsp, [B(EP.BASE.add(sp).toRawBytes())]);
await run('decodeSafePoint', 'short', dsp, [B(new Uint8Array(31))]);
await run('decodeSafePoint', 'long', dsp, [B(new Uint8Array(33))]);
await run('decodeSafePoint', 'null', dsp, [null]);
await run('decodeSafePoint', 'y-eq-p', dsp, [hexB('edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f')]);
await run('decodeSafePoint', 'y-eq-p+1', dsp, [hexB('eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f')]);
await run('decodeSafePoint', 'y-top-bit-set-noncanon', dsp, [hexB('f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')]);
for (let i = 0; i < 24; i++) { const u = sd('rand-pt/' + i); await run('decodeSafePoint', 'rand-' + i, dsp, [B(u)]); }
for (let i = 0; i < 4; i++) { const u = Uint8Array.from(pts[i]); u[31] ^= 0x80; await run('decodeSafePoint', 'signflip-' + i, dsp, [B(u)]); }

// ---- keygen
const kgen = (a: any) => { const x = un(a); return FR.frostTrustedDealerKeygen(x.t, x.n, { secret: x.secret ?? undefined, coefficients: x.coefficients ?? undefined, identifiers: x.identifiers ?? undefined }); };
const kargs = (label: string, t: number, n: number, ids?: number[], extra: any = {}) => ({ t, n, secret: B(sd(label + '/s')), coefficients: Array.from({ length: t - 1 }, (_, i) => B(sd(label + '/c' + i))), ...(ids ? { identifiers: ids } : {}), ...extra });
const RFC = { t: 2, n: 3, secret: hexB('7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304'), coefficients: [hexB('178199860edd8c62f5212ee91eff1295d0d670ab4ed4506866bae57e7030b204')], identifiers: [1, 2, 3] };
await run('keygen', 'rfc-e1', kgen, [RFC]);
for (const [t, n] of [[1, 1], [1, 3], [2, 2], [2, 3], [3, 3], [2, 5], [3, 5], [4, 7], [5, 9], [10, 10]] as [number, number][]) await run('keygen', `t${t}n${n}`, kgen, [kargs(`kg-${t}-${n}`, t, n)]);
await run('keygen', 'ids-sparse', kgen, [kargs('kg-sparse', 2, 3, [5, 9, 200])]);
await run('keygen', 'ids-big', kgen, [kargs('kg-big', 2, 3, [9007199254740991, 1, 2])]);
await run('keygen', 'ids-reordered', kgen, [kargs('kg-reord', 2, 3, [3, 1, 2])]);
await run('keygen', 'secret-zero', kgen, [kargs('kg-z', 2, 3, undefined, { secret: B(new Uint8Array(32)) })]);
await run('keygen', 'secret-empty', kgen, [kargs('kg-e', 2, 3, undefined, { secret: B(new Uint8Array()) })]);
await run('keygen', 'secret-wide64', kgen, [kargs('kg-w', 2, 3, undefined, { secret: B(Uint8Array.from({ length: 64 }, (_, i) => i * 3)) })]);
await run('keygen', 'coeff-zero', kgen, [kargs('kg-cz', 3, 4, undefined, { coefficients: [B(new Uint8Array(32)), B(sd('kg-cz/x'))] })]);
await run('keygen', 'secret-L', kgen, [kargs('kg-L', 2, 3, undefined, { secret: addL(B(new Uint8Array(32))) })]);
for (const [nm, t, n, ids] of [['t0', 0, 3], ['n<t', 4, 3], ['t1.5', 1.5, 3], ['n1.5', 1, 1.5], ['neg', -1, 3], ['ids-short', 2, 3, [1, 2]], ['ids-dup', 2, 3, [1, 1, 2]], ['ids-zero', 2, 3, [0, 1, 2]], ['ids-neg', 2, 3, [-1, 1, 2]], ['ids-frac', 2, 3, [1.5, 2, 3]]] as [string, number, number, number[]?][]) {
  await run('keygen', nm, kgen, [{ ...kargs('kg-err', Math.max(1, Math.floor(Math.abs(t))), Math.max(1, Math.floor(Math.abs(n)))), t, n, ...(ids ? { identifiers: ids } : {}) }]);
}

// ---- verifyingShare + commit
const KG = (label: string, t: number, n: number, ids?: number[]) => J(kgen(kargs(label, t, n, ids)));
const KG23 = KG('vs23', 2, 3);
for (const s of KG23.participantShares) await run('verifyingShare', 'id' + s.identifier, (b: any) => FR.frostVerifyingShare(un(b)), [s.share]);
await run('verifyingShare', 'zero', (b: any) => FR.frostVerifyingShare(un(b)), [B(new Uint8Array(32))]);
await run('verifyingShare', 'wide', (b: any) => FR.frostVerifyingShare(un(b)), [B(new Uint8Array(64).fill(7))]);
const commit = (id: number, share: any, hr: any, br: any) => FR.frostCommit({ identifier: id, share: un(share), publicKey: new Uint8Array(32) }, { hidingRandomness: un(hr), bindingRandomness: un(br) });
for (const [i, s] of KG23.participantShares.entries()) await run('commit', 'id' + s.identifier, commit, [s.identifier, s.share, B(sd('cm/h' + i)), B(sd('cm/b' + i))]);
await run('commit', 'rfc-1', commit, [1, hexB('929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509'), hexB('0fd2e39e111cdc266f6c0f4d0fd45c947761f1f5d3cb583dfcb9bbaf8d4c9fec'), hexB('69cd85f631d5f7f2721ed5e40519b1366f340a87c2f6856363dbdcda348a7501')]);
await run('commit', 'hr-short', commit, [1, KG23.participantShares[0].share, B(new Uint8Array(31)), B(sd('cm/x'))]);
await run('commit', 'br-long', commit, [1, KG23.participantShares[0].share, B(sd('cm/y')), B(new Uint8Array(33))]);
await run('commit', 'same-randomness', commit, [1, KG23.participantShares[0].share, B(sd('cm/z')), B(sd('cm/z'))]);

// ---- flow (keygen + commit + sign + aggregate) over many shapes; each signer gets unique randomness
let flowN = 0;
const flowRef = (a: any) => {
  const A = un(a);
  const kg = FR.frostTrustedDealerKeygen(A.t, A.n, { secret: A.secret ?? undefined, coefficients: A.coefficients ?? undefined, identifiers: A.identifiers ?? undefined });
  const byId = new Map<number, any>(kg.participantShares.map((s: any) => [s.identifier, s]));
  const quorum = A.signers.map((id: number) => byId.get(id));
  const commits = quorum.map((p: any, i: number) => FR.frostCommit(p, { hidingRandomness: A.randomness[i].hr, bindingRandomness: A.randomness[i].br }));
  const cs = commits.map((c: any) => c.commitment);
  const vss = quorum.map((p: any) => ({ identifier: p.identifier, publicKey: p.publicKey }));
  const thr = A.threshold != null ? { threshold: A.threshold } : {};
  const shares = quorum.map((p: any, i: number) => FR.frostSign(p.identifier, p.share, kg.groupPublicKey, { hiding: commits[i].hidingNonce, binding: commits[i].bindingNonce }, A.message, cs, { ...thr, verificationShare: p.publicKey, verificationShares: vss }));
  const aggregate = FR.frostAggregate(A.message, cs, shares, kg.groupPublicKey, { ...thr, verificationShares: vss });
  return { ...kg, commitments: cs, sigShares: shares, aggregate };
};
const flowArgs = (label: string, t: number, n: number, signers: number[], msg: Uint8Array, over: any = {}) => ({
  ...kargs(label, t, n, over.identifiers), signers, message: B(msg), threshold: over.threshold === undefined ? t : over.threshold,
  randomness: signers.map((id, i) => ({ hr: B(sd(`${label}/hr/${id}/${i}/${flowN}`)), br: B(sd(`${label}/br/${id}/${i}/${flowN}`)) })),
});
const M0 = new TextEncoder().encode('test'), MEMPTY = new Uint8Array(), MBIN = Uint8Array.from({ length: 257 }, (_, i) => (i * 37) & 255), MLONG = Uint8Array.from({ length: 5000 }, (_, i) => (i * 13 + 5) & 255);
const FLOWS: [string, number, number, number[], Uint8Array, any?][] = [
  ['1of1', 1, 1, [1], M0], ['1of3-signer2', 1, 3, [2], M0], ['2of3-13', 2, 3, [1, 3], M0], ['2of3-12', 2, 3, [1, 2], M0], ['2of3-23', 2, 3, [2, 3], M0], ['2of3-all', 2, 3, [1, 2, 3], M0], ['2of3-rev', 2, 3, [3, 1], M0],
  ['2of2', 2, 2, [1, 2], M0], ['3of5-135', 3, 5, [1, 3, 5], M0], ['3of5-2345', 3, 5, [2, 3, 4, 5], M0], ['3of5-all', 3, 5, [1, 2, 3, 4, 5], M0], ['4of7', 4, 7, [2, 3, 5, 7], M0], ['5of9', 5, 9, [1, 3, 5, 7, 9], M0], ['10of10', 10, 10, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], M0],
  ['empty-msg', 2, 3, [1, 3], MEMPTY], ['bin-msg', 2, 3, [1, 3], MBIN], ['long-msg', 3, 5, [1, 2, 3], MLONG],
  ['sparse-ids', 2, 3, [200, 5], M0, { identifiers: [5, 9, 200] }], ['big-id', 2, 3, [9007199254740991, 2], M0, { identifiers: [9007199254740991, 1, 2] }], ['no-threshold', 2, 3, [1, 3], M0, { threshold: null }],
  ['threshold-below', 3, 5, [1, 2, 3, 4], M0, { threshold: 3 }], ['threshold-1', 2, 3, [1, 3], M0, { threshold: 1 }],
  ['below-threshold', 3, 5, [1, 2], M0, { threshold: 3 }], ['below-threshold-nothr-succeeds-or-not', 3, 5, [1, 2], M0, { threshold: null }], ['single-signer-2of3', 2, 3, [1], M0, { threshold: 2 }],
  ['dup-signer', 2, 3, [1, 1], M0], ['missing-signer', 2, 3, [1, 4], M0],
];
const flows: Record<string, any> = {};
for (const [nm, t, n, signers, msg, over] of FLOWS) {
  flowN++;
  const args = flowArgs('flow-' + nm, t, n, signers, msg, over ?? {});
  const a = reparse(args);
  let out: any;
  try { out = jsonOut(flowRef(a)); flows[nm] = out; } catch (e: any) { out = { $throws: e instanceof Error ? e.message : String(e), ...(e && typeof e.code === 'string' ? { code: e.code } : {}) }; }
  o.add('flow', nm, a, out);
}

// ---- aggregate: valid flows, then tampering
const aggRef = (message: any, cs: any, shares: any, group: any, opts: any) => FR.frostAggregate(un(message), un(cs), un(shares), un(group), un(opts));
const F = flows['2of3-13'], F5 = flows['3of5-135'], FA = flows['3of5-all'];
const vssOf = (f: any, ids: number[]) => ids.map((id) => ({ identifier: id, publicKey: f.participantShares.find((s: any) => s.identifier === id).publicKey }));
const MSGF = B(M0);
const goodAgg = (f: any, ids: number[], msg: any, extra: any = {}) => [msg, f.commitments, f.sigShares, f.groupPublicKey, { verificationShares: vssOf(f, ids), ...extra }];
await run('aggregate', 'ok-2of3', aggRef, goodAgg(F, [1, 3], MSGF));
await run('aggregate', 'ok-3of5', aggRef, goodAgg(F5, [1, 3, 5], MSGF));
await run('aggregate', 'ok-5of5-subset-vss', aggRef, goodAgg(FA, [1, 2, 3, 4, 5], MSGF));
await run('aggregate', 'ok-threshold', aggRef, goodAgg(F, [1, 3], MSGF, { threshold: 2 }));
await run('aggregate', 'ok-threshold-1', aggRef, goodAgg(F, [1, 3], MSGF, { threshold: 1 }));
await run('aggregate', 'ok-shares-reversed', aggRef, [MSGF, F.commitments, [...F.sigShares].reverse(), F.groupPublicKey, { verificationShares: vssOf(F, [1, 3]) }]);
await run('aggregate', 'ok-commitments-reversed', aggRef, [MSGF, [...F.commitments].reverse(), F.sigShares, F.groupPublicKey, { verificationShares: vssOf(F, [1, 3]) }]);
await run('aggregate', 'ok-vss-extra', aggRef, goodAgg(F, [1, 2, 3], MSGF));
await run('aggregate', 'ok-vss-reversed', aggRef, [MSGF, F.commitments, F.sigShares, F.groupPublicKey, { verificationShares: vssOf(F, [3, 1]) }]);
await run('aggregate', 'threshold-3', aggRef, goodAgg(F, [1, 3], MSGF, { threshold: 3 }));
await run('aggregate', 'threshold-0', aggRef, goodAgg(F, [1, 3], MSGF, { threshold: 0 }));
await run('aggregate', 'threshold-1.5', aggRef, goodAgg(F, [1, 3], MSGF, { threshold: 1.5 }));
await run('aggregate', 'wrong-message', aggRef, goodAgg(F, [1, 3], B(new TextEncoder().encode('tesT'))));
await run('aggregate', 'empty-message', aggRef, goodAgg(F, [1, 3], B(MEMPTY)));
await run('aggregate', 'other-group', aggRef, [MSGF, F.commitments, F.sigShares, F5.groupPublicKey, { verificationShares: vssOf(F, [1, 3]) }]);
await run('aggregate', 'group-small-order', aggRef, [MSGF, F.commitments, F.sigShares, hexB(SMALL[0]), { verificationShares: vssOf(F, [1, 3]) }]);
await run('aggregate', 'group-short', aggRef, [MSGF, F.commitments, F.sigShares, B(new Uint8Array(31)), { verificationShares: vssOf(F, [1, 3]) }]);
await run('aggregate', 'vss-missing', aggRef, [MSGF, F.commitments, F.sigShares, F.groupPublicKey, {}]);
await run('aggregate', 'vss-null', aggRef, [MSGF, F.commitments, F.sigShares, F.groupPublicKey, { verificationShares: null }]);
await run('aggregate', 'vss-one', aggRef, goodAgg(F, [1], MSGF));
await run('aggregate', 'vss-wrong-key', aggRef, [MSGF, F.commitments, F.sigShares, F.groupPublicKey, { verificationShares: [vssOf(F, [1])[0], { identifier: 3, publicKey: F.participantShares[1].publicKey }] }]);
await run('aggregate', 'vss-swapped', aggRef, [MSGF, F.commitments, F.sigShares, F.groupPublicKey, { verificationShares: [{ identifier: 1, publicKey: vssOf(F, [3])[0].publicKey }, { identifier: 3, publicKey: vssOf(F, [1])[0].publicKey }] }]);
await run('aggregate', 'vss-bad-point', aggRef, [MSGF, F.commitments, F.sigShares, F.groupPublicKey, { verificationShares: [vssOf(F, [1])[0], { identifier: 3, publicKey: B(new Uint8Array(32).fill(2)) }] }]);
for (let k = 0; k < 2; k++) {
  const sh = clone(F.sigShares); sh[k].sigShare = flipB(sh[k].sigShare, 0);
  await run('aggregate', 'share-flip-' + k, aggRef, [MSGF, F.commitments, sh, F.groupPublicKey, { verificationShares: vssOf(F, [1, 3]) }]);
  const sh2 = clone(F.sigShares); sh2[k].sigShare = addL(sh2[k].sigShare);
  await run('aggregate', 'share-plus-L-' + k, aggRef, [MSGF, F.commitments, sh2, F.groupPublicKey, { verificationShares: vssOf(F, [1, 3]) }]);
  const sh3 = clone(F.sigShares); sh3[k].sigShare = B(new Uint8Array(32));
  await run('aggregate', 'share-zero-' + k, aggRef, [MSGF, F.commitments, sh3, F.groupPublicKey, { verificationShares: vssOf(F, [1, 3]) }]);
  const sh4 = clone(F.sigShares); sh4[k].sigShare = B(new Uint8Array(31));
  await run('aggregate', 'share-short-' + k, aggRef, [MSGF, F.commitments, sh4, F.groupPublicKey, { verificationShares: vssOf(F, [1, 3]) }]);
  const cs = clone(F.commitments); cs[k].hiding = flipB(cs[k].hiding, 1);
  await run('aggregate', 'commit-hiding-flip-' + k, aggRef, [MSGF, cs, F.sigShares, F.groupPublicKey, { verificationShares: vssOf(F, [1, 3]) }]);
  const cs2 = clone(F.commitments); cs2[k].binding = hexB(SMALL[3]);
  await run('aggregate', 'commit-binding-small-' + k, aggRef, [MSGF, cs2, F.sigShares, F.groupPublicKey, { verificationShares: vssOf(F, [1, 3]) }]);
  const cs3 = clone(F.commitments); cs3[k].hiding = B(new Uint8Array(32).fill(1));
  await run('aggregate', 'commit-hiding-junk-' + k, aggRef, [MSGF, cs3, F.sigShares, F.groupPublicKey, { verificationShares: vssOf(F, [1, 3]) }]);
}
await run('aggregate', 'share-dropped', aggRef, [MSGF, F.commitments, [F.sigShares[0]], F.groupPublicKey, { verificationShares: vssOf(F, [1, 3]) }]);
await run('aggregate', 'share-duplicated', aggRef, [MSGF, F.commitments, [F.sigShares[0], F.sigShares[0]], F.groupPublicKey, { verificationShares: vssOf(F, [1, 3]) }]);
await run('aggregate', 'share-extra', aggRef, [MSGF, F.commitments, [...F.sigShares, F.sigShares[0]], F.groupPublicKey, { verificationShares: vssOf(F, [1, 3]) }]);
await run('aggregate', 'share-non-signer', aggRef, [MSGF, F.commitments, [F.sigShares[0], { identifier: 2, sigShare: F.sigShares[1].sigShare }], F.groupPublicKey, { verificationShares: vssOf(F, [1, 3]) }]);
await run('aggregate', 'share-id-relabelled', aggRef, [MSGF, F.commitments, [{ identifier: 3, sigShare: F.sigShares[0].sigShare }, { identifier: 1, sigShare: F.sigShares[1].sigShare }], F.groupPublicKey, { verificationShares: vssOf(F, [1, 3]) }]);
await run('aggregate', 'shares-empty', aggRef, [MSGF, F.commitments, [], F.groupPublicKey, { verificationShares: vssOf(F, [1, 3]) }]);
await run('aggregate', 'shares-null', aggRef, [MSGF, F.commitments, null, F.groupPublicKey, { verificationShares: vssOf(F, [1, 3]) }]);
await run('aggregate', 'commitments-empty', aggRef, [MSGF, [], F.sigShares, F.groupPublicKey, { verificationShares: vssOf(F, [1, 3]) }]);
await run('aggregate', 'commitments-null', aggRef, [MSGF, null, F.sigShares, F.groupPublicKey, { verificationShares: vssOf(F, [1, 3]) }]);
await run('aggregate', 'commitments-dup', aggRef, [MSGF, [F.commitments[0], F.commitments[0]], F.sigShares, F.groupPublicKey, { verificationShares: vssOf(F, [1, 3]) }]);
await run('aggregate', 'commitments-one-dropped', aggRef, [MSGF, [F.commitments[0]], F.sigShares, F.groupPublicKey, { verificationShares: vssOf(F, [1, 3]) }]);
await run('aggregate', 'commitment-id-0', aggRef, [MSGF, [{ ...F.commitments[0], identifier: 0 }, F.commitments[1]], F.sigShares, F.groupPublicKey, { verificationShares: vssOf(F, [1, 3]) }]);
await run('aggregate', 'commitment-id-frac', aggRef, [MSGF, [{ ...F.commitments[0], identifier: 1.5 }, F.commitments[1]], F.sigShares, F.groupPublicKey, { verificationShares: vssOf(F, [1, 3]) }]);
await run('aggregate', 'commitment-id-str', aggRef, [MSGF, [{ ...F.commitments[0], identifier: '1' }, F.commitments[1]], F.sigShares, F.groupPublicKey, { verificationShares: vssOf(F, [1, 3]) }]);
await run('aggregate', 'commitment-id-relabel', aggRef, [MSGF, [{ ...F.commitments[0], identifier: 2 }, F.commitments[1]], F.sigShares, F.groupPublicKey, { verificationShares: vssOf(F, [1, 2, 3]) }]);
await run('aggregate', 'sub-quorum-3of5', aggRef, [MSGF, F5.commitments.slice(0, 2), F5.sigShares.slice(0, 2), F5.groupPublicKey, { verificationShares: vssOf(F5, [1, 3]) }]);
await run('aggregate', 'sub-quorum-threshold', aggRef, [MSGF, F5.commitments.slice(0, 2), F5.sigShares.slice(0, 2), F5.groupPublicKey, { threshold: 3, verificationShares: vssOf(F5, [1, 3]) }]);
await run('aggregate', 'mixed-flows', aggRef, [MSGF, F.commitments, [F.sigShares[0], FA.sigShares[2]], F.groupPublicKey, { verificationShares: vssOf(F, [1, 3]) }]);

// ---- verifySigShare
const vsh = (p: any) => FR.frostVerifySigShare(un(p));
const vp = (f: any, i: number, ids: number[], over: any = {}) => ({ identifier: ids[i], publicKey: vssOf(f, ids)[i].publicKey, commitment: f.commitments[i], sigShare: f.sigShares[i], signingCommitments: f.commitments, groupPublicKey: f.groupPublicKey, message: MSGF, ...over });
await run('verifySigShare', 'ok-0', vsh, [vp(F, 0, [1, 3])]);
await run('verifySigShare', 'ok-1', vsh, [vp(F, 1, [1, 3])]);
for (let i = 0; i < 3; i++) await run('verifySigShare', 'ok-3of5-' + i, vsh, [vp(F5, i, [1, 3, 5])]);
await run('verifySigShare', 'wrong-key', vsh, [vp(F, 0, [1, 3], { publicKey: vssOf(F, [3])[0].publicKey })]);
await run('verifySigShare', 'wrong-message', vsh, [vp(F, 0, [1, 3], { message: B(MBIN) })]);
await run('verifySigShare', 'wrong-group', vsh, [vp(F, 0, [1, 3], { groupPublicKey: F5.groupPublicKey })]);
await run('verifySigShare', 'wrong-identifier', vsh, [vp(F, 0, [1, 3], { identifier: 3 })]);
await run('verifySigShare', 'identifier-absent', vsh, [vp(F, 0, [1, 3], { identifier: 2 })]);
await run('verifySigShare', 'wrong-commitment', vsh, [vp(F, 0, [1, 3], { commitment: F.commitments[1] })]);
await run('verifySigShare', 'share-flip', vsh, [vp(F, 0, [1, 3], { sigShare: { identifier: 1, sigShare: flipB(F.sigShares[0].sigShare) } })]);
await run('verifySigShare', 'share-plus-L', vsh, [vp(F, 0, [1, 3], { sigShare: { identifier: 1, sigShare: addL(F.sigShares[0].sigShare) } })]);
await run('verifySigShare', 'share-short', vsh, [vp(F, 0, [1, 3], { sigShare: { identifier: 1, sigShare: B(new Uint8Array(31)) } })]);
await run('verifySigShare', 'commitments-empty', vsh, [vp(F, 0, [1, 3], { signingCommitments: [] })]);
await run('verifySigShare', 'commitments-dup', vsh, [vp(F, 0, [1, 3], { signingCommitments: [F.commitments[0], F.commitments[0]] })]);
await run('verifySigShare', 'commitments-small-order', vsh, [vp(F, 0, [1, 3], { signingCommitments: [{ ...F.commitments[0], hiding: hexB(SMALL[1]) }, F.commitments[1]] })]);
await run('verifySigShare', 'pk-small-order', vsh, [vp(F, 0, [1, 3], { publicKey: hexB(SMALL[3]) })]);
await run('verifySigShare', 'pk-short', vsh, [vp(F, 0, [1, 3], { publicKey: B(new Uint8Array(31)) })]);
await run('verifySigShare', 'params-null-members', vsh, [{ identifier: 1 }]);

// ---- sign: refusals and successes with unique nonces
let sgN = 0;
const KS = flows['3of5-all'];
const freshCommit = (p: any) => { sgN++; return FR.frostCommit(p, { hidingRandomness: sd('sg/h/' + sgN), bindingRandomness: sd('sg/b/' + sgN) }); };
const SG = (id: number) => KS.participantShares.find((s: any) => s.identifier === id);
const signRef = (id: any, share: any, group: any, nonces: any, message: any, cs: any, opts: any) => FR.frostSign(id, un(share), un(group), un(nonces), un(message), un(cs), un(opts));
const sgCase = async (nm: string, ids: number[], me: number, over: any = {}) => {
  const ps = ids.map((i) => un(SG(i)));
  const cm = ps.map((p) => freshCommit(p));
  let cs = J(cm.map((c: any) => c.commitment));
  const meIdx = Math.max(0, ids.indexOf(me));
  let nonces = J({ hiding: cm[meIdx].hidingNonce, binding: cm[meIdx].bindingNonce });
  if (over.nonces === 'swap') nonces = { hiding: nonces.binding, binding: nonces.hiding };
  if (over.cs === 'small') { cs = clone(cs); cs[meIdx].hiding = hexB(SMALL[1]); }
  const a: any = { id: me, share: (SG(me) ?? SG(ids[0])).share, group: KS.groupPublicKey, nonces, message: MSGF, cs, opts: {} };
  for (const k of Object.keys(over)) if (!(k === 'nonces' && over.nonces === 'swap') && !(k === 'cs' && over.cs === 'small')) a[k] = over[k];
  await run('sign', nm, signRef, [a.id, a.share, a.group, a.nonces, a.message, a.cs, a.opts]);
};
await sgCase('ok-plain', [1, 3, 5], 3);
await sgCase('ok-threshold', [1, 3, 5], 1, { opts: { threshold: 3 } });
await sgCase('ok-vshare', [1, 3, 5], 5, { opts: { verificationShare: SG(5).publicKey } });
await sgCase('ok-vshares', [1, 3, 5], 5, { opts: { verificationShares: vssOf(KS, [1, 3, 5]) } });
await sgCase('ok-all-opts', [2, 4, 5], 4, { opts: { threshold: 3, verificationShare: SG(4).publicKey, verificationShares: vssOf(KS, [2, 4, 5]) } });
await sgCase('ok-vshares-extra', [1, 3, 5], 5, { opts: { verificationShares: vssOf(KS, [1, 2, 3, 4, 5]) } });
await sgCase('thr-too-high', [1, 3, 5], 3, { opts: { threshold: 4 } });
await sgCase('thr-0', [1, 3, 5], 3, { opts: { threshold: 0 } });
await sgCase('vshare-wrong', [1, 3, 5], 3, { opts: { verificationShare: SG(1).publicKey } });
await sgCase('vshares-missing-id', [1, 3, 5], 3, { opts: { verificationShares: vssOf(KS, [1, 3]) } });
await sgCase('vshares-wrong-key', [1, 3, 5], 3, { opts: { verificationShares: [vssOf(KS, [1])[0], vssOf(KS, [5])[0], { identifier: 3, publicKey: SG(2).publicKey }] } });
await sgCase('vshares-wrong-group', [1, 3, 5], 3, { group: flows['2of3-13'].groupPublicKey, opts: { verificationShares: vssOf(KS, [1, 3, 5]) } });
await sgCase('group-small-order', [1, 3, 5], 3, { group: hexB(SMALL[0]) });
await sgCase('group-short', [1, 3, 5], 3, { group: B(new Uint8Array(31)) });
await sgCase('id-not-in-set', [1, 3, 5], 3, { id: 2 });
await sgCase('id-0', [1, 3, 5], 3, { id: 0 });
await sgCase('id-neg', [1, 3, 5], 3, { id: -3 });
await sgCase('id-frac', [1, 3, 5], 3, { id: 3.5 });
await sgCase('id-str', [1, 3, 5], 3, { id: '3' });
await sgCase('share-wrong', [1, 3, 5], 3, { share: SG(1).share });
await sgCase('share-zero', [1, 3, 5], 3, { share: B(new Uint8Array(32)) });
await sgCase('nonces-null', [1, 3, 5], 3, { nonces: null });
await sgCase('nonces-hiding-missing', [1, 3, 5], 3, { nonces: { binding: B(sd('x')) } });
await sgCase('nonces-zero-hiding', [1, 3, 5], 3, { nonces: { hiding: B(new Uint8Array(32)), binding: B(sd('x')) } });
await sgCase('nonces-zero-binding', [1, 3, 5], 3, { nonces: { hiding: B(sd('x')), binding: B(new Uint8Array(32)) } });
await sgCase('nonces-mismatch', [1, 3, 5], 3, { nonces: { hiding: B(sd('x1')), binding: B(sd('x2')) } });
await sgCase('nonces-swapped', [1, 3, 5], 3, { nonces: 'swap' });
await sgCase('commitments-empty', [1, 3, 5], 3, { cs: [] });
await sgCase('commitments-null', [1, 3, 5], 3, { cs: null });
await sgCase('commitments-small-order', [1, 3, 5], 3, { cs: 'small' });
await sgCase('message-empty', [1, 3, 5], 3, { message: B(MEMPTY) });
await sgCase('message-long', [1, 3, 5], 3, { message: B(MLONG) });

// ---- cosign (random nonces): the aggregate verifies; refusals throw
const cosign = (group: any, quorum: any, message: any, opts: any) => { const g = un(group), m = un(message); const sig = FR.frostCosign(g, un(quorum), m, un(opts)); return ed25519.verify(sig, m, g, { zip215: false }); };
const KC = flows['3of5-all'];
const Q = (ids: number[]) => ids.map((i) => KC.participantShares.find((s: any) => s.identifier === i));
await run('cosign', 'ok-3of5', cosign, [KC.groupPublicKey, Q([1, 3, 5]), MSGF, { threshold: 3 }]);
await run('cosign', 'ok-5of5', cosign, [KC.groupPublicKey, Q([1, 2, 3, 4, 5]), MSGF, { threshold: 3 }]);
await run('cosign', 'ok-no-threshold', cosign, [KC.groupPublicKey, Q([2, 4, 5]), MSGF, {}]);
await run('cosign', 'ok-empty-message', cosign, [KC.groupPublicKey, Q([2, 4, 5]), B(MEMPTY), { threshold: 3 }]);
await run('cosign', 'below-threshold', cosign, [KC.groupPublicKey, Q([1, 3]), MSGF, { threshold: 3 }]);
await run('cosign', 'empty-quorum', cosign, [KC.groupPublicKey, [], MSGF, {}]);
await run('cosign', 'null-quorum', cosign, [KC.groupPublicKey, null, MSGF, {}]);
await run('cosign', 'dup-participant', cosign, [KC.groupPublicKey, [Q([1])[0], Q([1])[0], Q([3])[0]], MSGF, { threshold: 3 }]);
await run('cosign', 'wrong-group', cosign, [flows['2of3-13'].groupPublicKey, Q([1, 3, 5]), MSGF, { threshold: 3 }]);
await run('cosign', 'bad-share', cosign, [KC.groupPublicKey, [{ ...Q([1])[0], share: Q([2])[0].share }, Q([3])[0], Q([5])[0]], MSGF, { threshold: 3 }]);
await run('cosign', 'wrong-pk', cosign, [KC.groupPublicKey, [{ ...Q([1])[0], publicKey: Q([2])[0].publicKey }, Q([3])[0], Q([5])[0]], MSGF, { threshold: 3 }]);
await run('cosign', 'subquorum-no-threshold', cosign, [KC.groupPublicKey, Q([1, 3]), MSGF, {}]);

splitWrite(o, 'core-frost-java', (j: string) => tokensIn(j, /"(?:share|secret)":(?:\{"\$bytes":)?"([A-Za-z0-9_-]{40,})"/g));
