// Oracle: @atlasauth/pca-bbs (BBS signatures, BLS12-381-SHA-256, plus the PCA capability-credential layer).
// Deterministic: keys from fixed key material, proofGen with FIXED random scalars (the published test hook), presentations assembled
// from those proofs (presentCredential itself is randomized and is covered by round-trip unit tests, not byte comparison).
// Scalars cross the JSON boundary as lowercase hex strings; bytes as {"$bytes": b64url}.
//
// PORTING (fn(args) -> native entry point, comparison rule):
//   hashToScalar(msg, dstString)            -> Bbs.hashToScalar                 hex scalar
//   mapMessageToScalarAsHash(msg)           -> Bbs.mapMessageToScalarAsHash     hex scalar
//   createGenerators(count)                 -> Bbs.createGenerators             list of bytes (compressed); a reference throw requires a throw
//   keyGen(keyMaterial, keyInfo)            -> Bbs.keyGen                       hex scalar; throw on short material
//   skToPk(skHex)                           -> Bbs.skToPk                       bytes
//   sign(skHex, pk, header, messages)       -> Bbs.sign                         bytes (deterministic)
//   verifyDetailed(pk, sig, header, msgs)   -> Bbs.verifyDetailed               {ok, reason?}
//   proofGen(pk, sig, header, ph, msgs, disclosedIndexes, randomScalarsHex) -> Bbs.proofGen  bytes (deterministic with the fixed scalars)
//   proofVerifyDetailed(pk, proof, header, ph, disclosedMsgs, disclosedIndexes) -> Bbs.proofVerifyDetailed  {ok, reason?}
//   capabilityAttributes(cap)               -> BbsCredential.capabilityAttributes   attribute list
//   issueCapabilityCredential(cap, skHex, pk, header) -> BbsCredential.issueCapabilityCredential   credential JSON
//   verifyCredential(cred)                  -> BbsCredential.verifyCredential       boolean
//   verifyPresentation(pres, opts)          -> BbsCredential.verifyPresentation     boolean (opts: pk / disclosed / presentationHeader, each optional, pk and ph as bytes)
import * as B0 from '@atlasauth/pca-bbs';
import { Oracle, refWrite } from './lib.mjs';

const B: any = (B0 as any).default ?? B0;
const o = new Oracle('bbs', 'tools/pca-audit/oracles/bbs.mts', 'TS-reference oracle for BBS signatures (BLS12-381-SHA-256) and the capability-credential layer.');
const by = (x: any): any => (x !== null && typeof x === 'object' && !Array.isArray(x) && typeof x.$bytes === 'string' ? new Uint8Array(Buffer.from(x.$bytes, 'base64url')) : x);
const bys = (xs: any[]) => xs.map(by);
const J = (u: Uint8Array) => ({ $bytes: Buffer.from(u).toString('base64url') });
const hex = (n: bigint) => n.toString(16).padStart(64, '0');
const unhex = (s: string) => BigInt('0x' + s);
const ex = (r: any) => (r.ok ? { ok: true } : { ok: false, reason: r.reason });
const enc = (s: string) => new TextEncoder().encode(s);
const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64url');
const flip = (u: Uint8Array, i: number, m = 1) => { const c = Uint8Array.from(u); c[i] = c[i]! ^ m; return c; };

const refs: Record<string, (...a: any[]) => any> = {
  hashToScalar: (m, dst) => hex(B.hashToScalar(by(m), dst)),
  mapMessageToScalarAsHash: (m) => hex(B.mapMessageToScalarAsHash(by(m))),
  createGenerators: (n) => B.createGenerators(n).map((g: any) => J(g.toRawBytes(true))),
  keyGen: (km, ki) => hex(B.keyGen(by(km), by(ki))),
  skToPk: (sk) => J(B.skToPk(unhex(sk))),
  sign: (sk, pk, hd, ms) => J(B.sign(unhex(sk), by(pk), by(hd), bys(ms))),
  verifyDetailed: (pk, sig, hd, ms) => ex(B.verifyDetailed(by(pk), by(sig), by(hd), bys(ms))),
  proofGen: (pk, sig, hd, ph, ms, idx, rs) => J(B.proofGen(by(pk), by(sig), by(hd), by(ph), bys(ms), idx, rs.map(unhex))),
  proofVerifyDetailed: (pk, pr, hd, ph, ms, idx) => ex(B.proofVerifyDetailed(by(pk), by(pr), by(hd), by(ph), bys(ms), idx)),
  capabilityAttributes: (cap) => B.capabilityAttributes(cap),
  issueCapabilityCredential: (cap, sk, pk, hd) => B.issueCapabilityCredential(cap, { sk: unhex(sk), pk: by(pk), header: by(hd) }),
  verifyCredential: (c) => B.verifyCredential(c),
  verifyPresentation: (pres, opts) => B.verifyPresentation(pres, { pk: opts.pk === undefined ? undefined : by(opts.pk), disclosed: opts.disclosed, presentationHeader: opts.presentationHeader === undefined ? undefined : by(opts.presentationHeader) }),
};
const run = (fn: string, name: string, args: any[]) => o.run(fn, name, refs[fn]!, args);

// ---- hash / generators / keys
const MSGS = [new Uint8Array(0), enc('a'), enc('hello world'), new Uint8Array(100).fill(9), new Uint8Array(32)];
for (const [i, m] of MSGS.entries()) {
  await run('hashToScalar', `m${i}`, [J(m), 'BBS_TEST_DST_']);
  await run('mapMessageToScalarAsHash', `m${i}`, [J(m)]);
}
for (const n of [0, 1, 2, 5, 12, 1025, 1026, -1]) await run('createGenerators', `n${n}`, [n]);
const KM = [new Uint8Array(32).fill(1), new Uint8Array(40).fill(2), new Uint8Array(31).fill(3), new Uint8Array(0)];
for (const [i, k] of KM.entries()) for (const [j, info] of [new Uint8Array(0), enc('info'), new Uint8Array(70000)].entries()) await run('keyGen', `k${i}i${j}`, [J(k), J(info)]);
const SKS = [1, 2, 3].map((i) => hex(B.keyGen(new Uint8Array(32).fill(i), new Uint8Array(0))));
const PKS = SKS.map((s) => B.skToPk(unhex(s)));
for (const [i, s] of SKS.entries()) await run('skToPk', `k${i}`, [s]);

// ---- sign / verify
const HDRS = [new Uint8Array(0), enc('header')];
const MS: Uint8Array[][] = [[], [enc('one')], [enc('one'), enc('two'), enc('three')], Array.from({ length: 8 }, (_, i) => enc('msg' + i))];
const sigs: any[] = [];
for (const [pi, sk] of SKS.entries()) for (const [hi, hd] of HDRS.entries()) for (const [mi, ms] of MS.entries()) {
  if (pi > 0 && mi > 2) continue;
  const name = `k${pi}h${hi}m${mi}`;
  await run('sign', name, [sk, J(PKS[pi]!), J(hd), ms.map(J)]);
  const sig = B.sign(unhex(sk), PKS[pi]!, hd, ms);
  sigs.push({ pi, hd, ms, sig });
  await run('verifyDetailed', `${name}/ok`, [J(PKS[pi]!), J(sig), J(hd), ms.map(J)]);
  if (pi === 0 && hi === 0) {
    await run('verifyDetailed', `${name}/wrongpk`, [J(PKS[1]!), J(sig), J(hd), ms.map(J)]);
    await run('verifyDetailed', `${name}/wronghdr`, [J(PKS[pi]!), J(sig), J(enc('x')), ms.map(J)]);
    await run('verifyDetailed', `${name}/extramsg`, [J(PKS[pi]!), J(sig), J(hd), [...ms, enc('extra')].map(J)]);
    if (ms.length > 0) {
      await run('verifyDetailed', `${name}/changedmsg`, [J(PKS[pi]!), J(sig), J(hd), ms.map((m, i) => J(i === 0 ? enc('changed') : m))]);
      await run('verifyDetailed', `${name}/droppedmsg`, [J(PKS[pi]!), J(sig), J(hd), ms.slice(1).map(J)]);
    }
    for (const bi of [0, 5, 47, 48, 60, 79]) await run('verifyDetailed', `${name}/flip${bi}`, [J(PKS[pi]!), J(flip(sig, bi)), J(hd), ms.map(J)]);
    await run('verifyDetailed', `${name}/short`, [J(PKS[pi]!), J(sig.slice(1)), J(hd), ms.map(J)]);
    await run('verifyDetailed', `${name}/long`, [J(PKS[pi]!), J(new Uint8Array([...sig, 0])), J(hd), ms.map(J)]);
    await run('verifyDetailed', `${name}/eZero`, [J(PKS[pi]!), J(new Uint8Array([...sig.slice(0, 48), ...new Uint8Array(32)])), J(hd), ms.map(J)]);
    await run('verifyDetailed', `${name}/eMax`, [J(PKS[pi]!), J(new Uint8Array([...sig.slice(0, 48), ...new Uint8Array(32).fill(255)])), J(hd), ms.map(J)]);
    await run('verifyDetailed', `${name}/pkzero`, [J(new Uint8Array(96)), J(sig), J(hd), ms.map(J)]);
    await run('verifyDetailed', `${name}/pkflip`, [J(flip(PKS[pi]!, 30)), J(sig), J(hd), ms.map(J)]);
  }
}
{
  const inf = new Uint8Array(96); inf[0] = 0xc0;
  const s = sigs[2];
  await run('verifyDetailed', 'pkinf', [J(inf), J(s.sig), J(s.hd), s.ms.map(J)]);
  const infA = new Uint8Array([0xc0, ...new Uint8Array(47), ...s.sig.slice(48)]);
  await run('verifyDetailed', 'siginf', [J(PKS[s.pi]!), J(infA), J(s.hd), s.ms.map(J)]);
}

// ---- proofs (fixed randomness)
const rsFor = (n: number, seedN: number) => Array.from({ length: n }, (_, i) => hex(BigInt(seedN * 1000 + i + 1) * 0x123456789abcdef0123456789abcdefn));
const proofs: any[] = [];
const sig3 = sigs.find((s) => s.pi === 0 && s.hd.length === 0 && s.ms.length === 8)!;
const sig2 = sigs.find((s) => s.pi === 0 && s.hd.length === 6 && s.ms.length === 3)!;
const PH = enc('presentation header');
for (const [si, s] of [sig2, sig3].entries()) {
  const L = s.ms.length;
  const idxSets: number[][] = L === 3 ? [[], [0], [1, 2], [0, 1, 2]] : [[0], [3, 5], [0, 1, 2, 3, 4, 5, 6, 7], [7, 0]];
  for (const [ii, idx] of idxSets.entries()) {
    const rs = rsFor(5 + (L - new Set(idx).size), si * 10 + ii);
    const name = `s${si}i${ii}`;
    await run('proofGen', name, [J(PKS[s.pi]!), J(s.sig), J(s.hd), J(PH), s.ms.map(J), idx, rs]);
    const proof = B.proofGen(PKS[s.pi]!, s.sig, s.hd, PH, s.ms, idx, rs.map(unhex));
    proofs.push({ s, idx, proof });
    const sorted = [...idx].sort((a, b) => a - b);
    const dm = sorted.map((i) => J(s.ms[i]!));
    await run('proofVerifyDetailed', `${name}/ok`, [J(PKS[s.pi]!), J(proof), J(s.hd), J(PH), dm, sorted]);
    if (ii === 1) {
      await run('proofVerifyDetailed', `${name}/unsortedinput`, [J(PKS[s.pi]!), J(proof), J(s.hd), J(PH), [...dm].reverse(), [...sorted].reverse()]);
      await run('proofVerifyDetailed', `${name}/wrongph`, [J(PKS[s.pi]!), J(proof), J(s.hd), J(enc('other')), dm, sorted]);
      await run('proofVerifyDetailed', `${name}/wronghdr`, [J(PKS[s.pi]!), J(proof), J(enc('other')), J(PH), dm, sorted]);
      await run('proofVerifyDetailed', `${name}/wrongpk`, [J(PKS[1]!), J(proof), J(s.hd), J(PH), dm, sorted]);
      await run('proofVerifyDetailed', `${name}/changedmsg`, [J(PKS[s.pi]!), J(proof), J(s.hd), J(PH), dm.map((m, i) => (i === 0 ? J(enc('x')) : m)), sorted]);
      await run('proofVerifyDetailed', `${name}/lenmismatch`, [J(PKS[s.pi]!), J(proof), J(s.hd), J(PH), dm.slice(1), sorted]);
      await run('proofVerifyDetailed', `${name}/outofrange`, [J(PKS[s.pi]!), J(proof), J(s.hd), J(PH), dm, [sorted[0], 99]]);
      await run('proofVerifyDetailed', `${name}/negindex`, [J(PKS[s.pi]!), J(proof), J(s.hd), J(PH), dm, [-1, sorted[1]]]);
      await run('proofVerifyDetailed', `${name}/dupindex`, [J(PKS[s.pi]!), J(proof), J(s.hd), J(PH), dm, [sorted[0], sorted[0]]]);
      for (const bi of [0, 60, 100, 144, 150, 190, proof.length - 1]) await run('proofVerifyDetailed', `${name}/flip${bi}`, [J(PKS[s.pi]!), J(flip(proof, bi)), J(s.hd), J(PH), dm, sorted]);
      await run('proofVerifyDetailed', `${name}/empty`, [J(PKS[s.pi]!), J(new Uint8Array(0)), J(s.hd), J(PH), dm, sorted]);
      await run('proofVerifyDetailed', `${name}/short`, [J(PKS[s.pi]!), J(proof.slice(0, 100)), J(s.hd), J(PH), dm, sorted]);
      await run('proofVerifyDetailed', `${name}/ragged`, [J(PKS[s.pi]!), J(proof.slice(0, proof.length - 1)), J(s.hd), J(PH), dm, sorted]);
      const big = Uint8Array.from(proof); big.fill(255, 144, 176);
      await run('proofVerifyDetailed', `${name}/scalarbig`, [J(PKS[s.pi]!), J(big), J(s.hd), J(PH), dm, sorted]);
      const inf = Uint8Array.from(proof); inf.fill(0, 0, 48); inf[0] = 0xc0;
      await run('proofVerifyDetailed', `${name}/abarinf`, [J(PKS[s.pi]!), J(inf), J(s.hd), J(PH), dm, sorted]);
      await run('proofVerifyDetailed', `${name}/pkzero`, [J(new Uint8Array(96)), J(proof), J(s.hd), J(PH), dm, sorted]);
    }
  }
}
await run('proofGen', 'wrongscalarcount', [J(PKS[0]!), J(sig2.sig), J(sig2.hd), J(PH), sig2.ms.map(J), [0], rsFor(3, 1)]);
await run('proofGen', 'zeroR1', [J(PKS[0]!), J(sig2.sig), J(sig2.hd), J(PH), sig2.ms.map(J), [0], ['00'.repeat(32), ...rsFor(6, 2)]]);
await run('proofGen', 'indexOutOfRange', [J(PKS[0]!), J(sig2.sig), J(sig2.hd), J(PH), sig2.ms.map(J), [10], rsFor(7, 3)]);
await run('proofGen', 'dupIndex', [J(PKS[0]!), J(sig2.sig), J(sig2.hd), J(PH), sig2.ms.map(J), [1, 1], rsFor(6, 4)]);
await run('proofGen', 'badsig', [J(PKS[0]!), J(sig2.sig.slice(1)), J(sig2.hd), J(PH), sig2.ms.map(J), [0], rsFor(7, 5)]);

// ---- capability credentials
const CAPS: any[] = [
  { issuer: 'issuerKey', holder: 'holderKey', caveats: [] },
  { issuer: 'issuerKey', holder: 'holderKey', caveats: [{ type: 'amount', max: 10 }] },
  { issuer: 'i', holder: 'h', caveats: [{ type: 'audience', aud: 'x' }, { type: 'time', nbf: 1, exp: 2 }, { type: 'tools', allow: ['a', 'b'] }] },
  { issuer: 'i', holder: 'h' },
];
for (const [i, c] of CAPS.entries()) await run('capabilityAttributes', `c${i}`, [c]);
const creds: any[] = [];
for (const [i, c] of CAPS.slice(0, 3).entries()) {
  await run('issueCapabilityCredential', `c${i}`, [c, SKS[0], J(PKS[0]!), J(new Uint8Array(0))]);
  await run('issueCapabilityCredential', `c${i}h`, [c, SKS[0], J(PKS[0]!), J(enc('hdr'))]);
  const cred = B.issueCapabilityCredential(c, { sk: unhex(SKS[0]!), pk: PKS[0]!, header: new Uint8Array(0) });
  creds.push(cred);
  await run('verifyCredential', `c${i}/ok`, [cred]);
  await run('verifyCredential', `c${i}/tamperedvalue`, [{ ...cred, attributes: cred.attributes.map((a: any, k: number) => (k === 1 ? { ...a, value: 'evil' } : a)) }]);
  await run('verifyCredential', `c${i}/tamperedname`, [{ ...cred, attributes: cred.attributes.map((a: any, k: number) => (k === 0 ? { ...a, name: 'sub' } : a)) }]);
  await run('verifyCredential', `c${i}/badsig`, [{ ...cred, signature: b64(flip(Buffer.from(cred.signature, 'base64url'), 50)) }]);
  await run('verifyCredential', `c${i}/badb64`, [{ ...cred, signature: '!!!' }]);
  await run('verifyCredential', `c${i}/wrongheader`, [{ ...cred, header: b64(enc('x')) }]);
  await run('verifyCredential', `c${i}/nulname`, [{ ...cred, attributes: [{ ...cred.attributes[0], name: 'a\0b' }, ...cred.attributes.slice(1)] }]);
  await run('verifyCredential', `c${i}/nonstring`, [{ ...cred, attributes: [{ ...cred.attributes[0], value: 5 }, ...cred.attributes.slice(1)] }]);
}
await run('verifyCredential', 'noattrs', [{ issuerPublicKey: b64(PKS[0]!), header: '', signature: b64(new Uint8Array(80)) }]);
await run('verifyCredential', 'unpaired', [{ ...creds[0], attributes: [{ index: 0, name: 'iss', value: '\ud800' }, creds[0].attributes[1]] }]);

// presentations assembled from fixed-randomness proofs
function present(cred: any, disclose: string[], ph: Uint8Array, seedN: number) {
  const pk = Buffer.from(cred.issuerPublicKey, 'base64url');
  const hd = Buffer.from(cred.header, 'base64url');
  const sg = Buffer.from(cred.signature, 'base64url');
  const msgs = cred.attributes.map((a: any) => enc(a.name + '\0' + a.value));
  const dis = cred.attributes.filter((a: any) => disclose.includes(a.name));
  const idx = dis.map((a: any) => a.index);
  const proof = B.proofGen(new Uint8Array(pk), new Uint8Array(sg), new Uint8Array(hd), ph, msgs, idx, rsFor(5 + msgs.length - idx.length, seedN).map(unhex));
  return { issuerPublicKey: cred.issuerPublicKey, header: cred.header, presentationHeader: b64(ph), messageCount: cred.attributes.length, disclosed: dis, proof: b64(proof) };
}
const cred2 = creds[2];
const pres = present(cred2, ['iss', 'cav:1:time'], PH, 77);
const presAll = present(cred2, cred2.attributes.map((a: any) => a.name), PH, 78);
const presNone = present(cred2, [], PH, 79);
for (const [nm, p] of [['pres', pres], ['all', presAll], ['none', presNone]] as const) {
  await run('verifyPresentation', `${nm}/asis`, [p, {}]);
  await run('verifyPresentation', `${nm}/pinnedpk`, [p, { pk: J(PKS[0]!) }]);
  await run('verifyPresentation', `${nm}/wrongpk`, [p, { pk: J(PKS[1]!) }]);
  await run('verifyPresentation', `${nm}/pinnedph`, [p, { presentationHeader: J(PH) }]);
  await run('verifyPresentation', `${nm}/wrongph`, [p, { presentationHeader: J(enc('other')) }]);
  await run('verifyPresentation', `${nm}/emptyph`, [p, { presentationHeader: J(new Uint8Array(0)) }]);
  await run('verifyPresentation', `${nm}/expecteddisclosed`, [p, { disclosed: p.disclosed }]);
  await run('verifyPresentation', `${nm}/expecteddisclosedwrong`, [p, { disclosed: p.disclosed.slice(1) }]);
  await run('verifyPresentation', `${nm}/badproof`, [{ ...p, proof: b64(flip(Buffer.from(p.proof, 'base64url'), 150)) }, {}]);
  await run('verifyPresentation', `${nm}/badb64`, [{ ...p, proof: '***' }, {}]);
  await run('verifyPresentation', `${nm}/lowcount`, [{ ...p, messageCount: 1 }, {}]);
  await run('verifyPresentation', `${nm}/valuetampered`, [{ ...p, disclosed: p.disclosed.map((a: any, k: number) => (k === 0 ? { ...a, value: 'zzz' } : a)) }, {}]);
}
await run('verifyPresentation', 'reordereddisclosed', [{ ...pres, disclosed: [...pres.disclosed].reverse() }, {}]);
await run('verifyPresentation', 'negindex', [{ ...pres, disclosed: pres.disclosed.map((a: any, k: number) => (k === 0 ? { ...a, index: -1 } : a)) }, {}]);
await run('verifyPresentation', 'badph64', [{ ...pres, presentationHeader: '***' }, {}]);

refWrite(o, 'bbs');
