// Oracle: @atlasauth/pca-mpc, the endemic LWE base OT (Masny-Rindal over Kyber-768 K-PKE) and its lattice core.
// Bytes are {"$bytes": b64url}. Receiver key seeds are LABELS: the 32-byte seed is sha256("atlas-pca-conformance/" + label); the
// secret key is never in the corpus (a native derives it from the label). RANDOMNESS is the seeded SplitMix64 OtRandom (decimal-string
// seeds), consumed in the reference order, so a native reproduces every nonce, point, ciphertext and pad.
// Every protocol case calls the reference's own exported endemic functions (endemicLweReceive, endemicLweSendRandom, endemicLweRecoverRandom,
// endemicLweBaseOT) with the seeded generators, so a native replays the reference outputs byte for byte. The receiver's real key pair is the
// FIPS 203 K-PKE.KeyGen(d) (kpkeKeygenFips203), what the C library exposes as lweot_kpke_keygen_fips203. lweKeygen/lweEnc/lweDec still
// cover the library's own (pqc_kyber) K-PKE entry points; lweKeygenFips covers the FIPS 203 one.
// PORTING (net.atlasauth.pca.mpc.EndemicOt and the per-lane equivalents):
//   lweKeygenFips(label) -> {pk, skSha256}    (FIPS 203 K-PKE.KeyGen, seed sha256("atlas-pca-conformance/" + label))
//   lweKeygen(label) -> {pk, skSha256}         lweEnc(label, msg, coins) -> ct (under the label's public key)   lweDec(label, ct) -> msg
//   lweRing(op, a, b)  op add|sub -> bytes      lweHash(input) -> bytes (throws over the 4096-byte cap)
//   randomOt(choices, recvSeed, sendSeed)  (receive with the first generator, sendRandom with the second) -> {rn, points, rhos, ciphertexts, senderPads, recvPads}
//   randomOtTamper(choices, recvSeed, sendSeed) -> throws: the sender truncates ciphertext [0][0] to 1087 bytes, the receiver must abort
//   baseOt(messages, choices, seed, tamper)   ONE generator serves the receiver then the sender, as endemicLweBaseOT does -> {received, ciphertexts, encrypted, commitments} (tamper none|enc|ct)
//   sendMalformed(kind) -> throws EndemicLweOtAbort (kinds: nonce, count, point, rho)
import { createHash } from 'node:crypto';
import * as M0 from '@atlasauth/pca-mpc';
import { Oracle, refWrite, seed } from './lib.mjs';
const M: any = (M0 as any).default ?? M0;

const o = new Oracle('mpc-endemic', 'tools/pca-audit/oracles/mpc-endemic.mts', 'TS-reference oracle for the PCA MPC endemic LWE base OT.');
const sha = (...c: Uint8Array[]) => { const h = createHash('sha256'); for (const x of c) h.update(x); return new Uint8Array(h.digest()); };
const orng = (s: string) => M.otRandom(M.splitMix64(BigInt(s)));
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const u8 = (a: any): Uint8Array => (a instanceof Uint8Array ? a : typeof a?.$bytes === 'string' ? new Uint8Array(Buffer.from(a.$bytes, 'base64url')) : Uint8Array.from(a));
const fill = (n: number, k: number) => Uint8Array.from({ length: n }, (_, i) => (i * 31 + k * 7 + (i >> 3)) & 255);

const kg = (label: string) => M.kpkeKeygen(seed(label));
for (const label of ['a', 'b', 'receiver-0', 'receiver-1', 'z']) {
  await o.run('lweKeygenFips', label, (l: string) => { const k = M.kpkeKeygenFips203(seed(l)); return { pk: k.publicKey, skSha256: hex(sha(k.secretKey)) }; }, [label]);
}
for (const label of ['a', 'b', 'receiver-0', 'receiver-1', 'z']) {
  await o.run('lweKeygen', label, (l: string) => { const k = kg(l); return { pk: k.publicKey, skSha256: hex(sha(k.secretKey)) }; }, [label]);
}
for (const [li, label] of ['a', 'b', 'receiver-0'].entries()) {
  for (let t = 0; t < 4; t++) {
    const msg = fill(32, li * 4 + t), coins = fill(32, 90 + li * 4 + t);
    await o.run('lweEnc', `${label}/${t}`, (l: string, m: any, c: any) => M.kpkeEnc(kg(l).publicKey, u8(m), u8(c)), [label, msg, coins]);
    const ct = M.kpkeEnc(kg(label).publicKey, msg, coins);
    await o.run('lweDec', `${label}/${t}`, (l: string, c: any) => M.kpkeDec(kg(l).secretKey, u8(c)), [label, ct]);
    if (t === 0) await o.run('lweDec', `${label}/wrong-key`, (l: string, c: any) => M.kpkeDec(kg(l).secretKey, u8(c)), [label + '-other', ct]);
  }
}
await o.run('lweEnc', 'bad-msg-len', (l: string, m: any, c: any) => M.kpkeEnc(kg(l).publicKey, u8(m), u8(c)), ['a', fill(31, 1), fill(32, 2)]);
await o.run('lweEnc', 'bad-coins-len', (l: string, m: any, c: any) => M.kpkeEnc(kg(l).publicKey, u8(m), u8(c)), ['a', fill(32, 1), fill(33, 2)]);
await o.run('lweDec', 'bad-ct-len', (l: string, c: any) => M.kpkeDec(kg(l).secretKey, u8(c)), ['a', fill(1087, 3)]);
for (let t = 0; t < 6; t++) {
  const a = M.hashToRing(fill(10 + t, t)), b = M.hashToRing(fill(20 + t, t + 9));
  await o.run('lweRing', `add/${t}`, (op: string, x: any, y: any) => M.ringAdd(u8(x), u8(y)), ['add', a, b]);
  await o.run('lweRing', `sub/${t}`, (op: string, x: any, y: any) => M.ringSub(u8(x), u8(y)), ['sub', a, b]);
}
await o.run('lweRing', 'add/short', (op: string, x: any, y: any) => M.ringAdd(u8(x), u8(y)), ['add', fill(1151, 1), fill(1152, 2)]);
for (const n of [0, 1, 31, 32, 33, 100, 1000, 4096, 4097]) await o.run('lweHash', `len${n}`, (x: any) => M.hashToRing(u8(x)), [fill(n, n)]);

const rngSeeds = [['101', '202'], ['303', '404'], ['505', '606']];
for (const [ci, choices] of [[0], [1], [0, 1], [1, 1, 0], [0, 0, 1, 1, 0, 1]].entries()) {
  const [rs, ss] = rngSeeds[ci % 3]!;
  await o.run('randomOt', `${ci}/none`, (ch: number[], r: string, s: string) => {
    const { message, state } = M.endemicLweReceive(ch, orng(r));
    const sm = M.endemicLweSendRandom(message, orng(s));
    return { rn: message.rn, points: message.points, rhos: message.rhos, ciphertexts: sm.ciphertexts, senderPads: sm.senderPads, recvPads: M.endemicLweRecoverRandom(state, sm) };
  }, [choices, rs, ss]);
}
await o.run('randomOtTamper', 'badCt', (ch: number[], r: string, s: string) => {
  const { message, state } = M.endemicLweReceive(ch, orng(r));
  const sm = M.endemicLweSendRandom(message, orng(s), { tamperCiphertexts: (c: Uint8Array[][]) => { c[0]![0] = c[0]![0]!.slice(0, 1087); } });
  return { ciphertexts: sm.ciphertexts, recvPads: M.endemicLweRecoverRandom(state, sm) };
}, [[0, 1], '7', '8']);

/** The reference endemicLweBaseOT; the tamper hook edits the one-time-padded messages on the wire. */
function baseOt(messages: Uint8Array[][], choices: number[], seedStr: string, tamper: string) {
  const flip = (e: Uint8Array[][], slot: number) => { e[0]![slot] = e[0]![slot]!.map((b) => b ^ 1); };
  const hook = tamper === 'enc' ? { tamperCiphertexts: (e: Uint8Array[][]) => flip(e, 0) }
    : tamper === 'encChosen' ? { tamperCiphertexts: (e: Uint8Array[][]) => flip(e, choices[0]! & 1) } : undefined;
  const r = M.endemicLweBaseOT(messages, choices, orng(seedStr), hook);
  return { received: r.received, ciphertexts: r.transcript.ciphertexts, encrypted: r.transcript.encrypted, commitments: r.transcript.commitments };
}
const msgs = (n: number, len: number) => Array.from({ length: n }, (_, i) => [fill(len, 3 * i + 1), fill(len, 3 * i + 2)]);
for (const [n, len] of [[1, 16], [2, 32], [3, 5], [2, 0], [4, 65]] as const) {
  const choices = Array.from({ length: n }, (_, i) => (i * 5 + n) & 1);
  await o.run('baseOt', `${n}/${len}/none`, (m: any[][], c: number[], sd: string, t: string) => baseOt(m.map((p) => p.map(u8)), c, sd, t), [msgs(n, len), choices, String(900 + n), 'none']);
}
for (const t of ['enc', 'encChosen']) await o.run('baseOt', `tamper/${t}`, (m: any[][], c: number[], sd: string, tt: string) => baseOt(m.map((p) => p.map(u8)), c, sd, tt), [msgs(2, 16), [0, 1], '41', t]);
await o.run('baseOt', 'unequal', (m: any[][], c: number[], sd: string, t: string) => baseOt(m.map((p) => p.map(u8)), c, sd, t), [[[fill(4, 1), fill(5, 2)]], [0], '1', 'none']);

for (const kind of ['nonce', 'count', 'point', 'rho']) {
  await o.run('sendMalformed', kind, (k: string) => {
    const { message } = M.endemicLweReceive([0, 1], orng('77'));
    const m: any = { rn: message.rn, points: message.points.map((p) => [...p]), rhos: [...message.rhos] };
    if (k === 'nonce') m.rn = fill(31, 1);
    if (k === 'count') m.rhos = m.rhos.slice(1);
    if (k === 'point') m.points[1][0] = fill(1151, 1);
    if (k === 'rho') m.rhos[0] = fill(33, 1);
    return M.endemicLweSendRandom(m, orng('78')).ciphertexts.length;
  }, [kind]);
}
refWrite(o, 'mpc-endemic');
