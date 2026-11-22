// Oracle: packages/pca/src/pq-threshold.ts, the QUORUM-SET and ROTATION half of post-quantum t-of-n authorization by composition
// (a "quorum certificate": t independent per-signer PQ signatures over one domain-separated message). The sibling corpora
// ref-pq-threshold / ref-pq-threshold-java-extra cover the separate @atlasauth/pca-pq-threshold package (signed FROST group descriptor,
// hybrid threshold artifact, step-up hook); this corpus covers the in-core module, which none of them reach.
// Deterministic: Ed25519 and ML-DSA (FIPS 204 deterministic signing) from seed labels. SLH-DSA signatures appear only as DATA inside proofs
// (generated here, verify-only: no native lane signs SLH-DSA); every sign case uses ed25519 / ML-DSA-65 / ML-DSA-87 keys.
// Secrets appear ONLY as {"$seed": "<label>"} = the 32 bytes sha256("atlas-pca-conformance/" + label) (ML-DSA: its keygen seed). Bytes are {"$bytes": b64url}.
// A reference throw is {"$throws": message}: the native must throw (message not compared). Verification fns never throw and return typed verdicts.
// PORTING (fn(args) -> native entry point; compared by JSON value):
//   constants() -> {PQ_QUORUM_MAX_SIGNERS: 256, PQ_QUORUM_MAX_CHAIN: 1024}
//   buildQuorumSet(signers, t, minHashBased?) -> {ok, set: {t, minHashBased, signers: [{alg, ed?, pq}], id}} | {ok:false, reason: "bad-set"}
//       signers: [{alg, keys: {edPub?, mlDsaPub?, mlDsa87Pub?, slhDsaPub?, slhDsa256sPub?, fnDsa512Pub?, fnDsa1024Pub?}}] (b64u public keys); minHashBased absent = 0
//   loadQuorumSet(x) -> same shape (the id is RE-DERIVED and must match; wire order must already be canonical)
//   quorumMessage(setId, epoch, actionDigest) -> bytes     quorumActionDigest(bytes) -> string
//   signQuorumShare(set, index, epoch, actionDigest, keys) -> {i, sig, pq_sig?} | throws       keys: {edSecret?: {$seed}, mlDsa?: {$seed -> ML-DSA-65 keygen seed}, mlDsa87?: {$seed -> ML-DSA-87 keygen seed}}
//   assembleQuorumProof(set, shares) -> {set_id, sigs}
//   verifyQuorum({set, proof, epoch, actionDigest, expectedSetId?, requireHashBased?}) -> {ok, signers, count, hashBased} | {ok:false, reason, detail?}
//   verifyQuorumApproval(set, proof, message, epoch, opts) -> bool
//   rotationActionDigest(toSetId, toEpoch) -> string       buildRotationCert(from, fromEpoch, to, shares) -> cert     signRotationShare(from, index, fromEpoch, to, keys) -> share
//   verifyRotationChain(genesisSet, genesisEpoch, chain) -> {ok, set, epoch, length} | {ok:false, reason, at}     isRotationFork(a, b) -> bool
//   quorumProofSize(set, indices?) -> {minBytes, maxBytes, chosenBytes?, t, compact: false}
// The ed25519-only and FN-DSA / LESS suites are not generated for set building beyond refusals (FN-DSA needs the optional wasm backend).
import * as Q from '../../../packages/pca/src/pq-threshold.ts';
import * as PQ0 from '../../../packages/pca/src/pq.ts';
import * as K0 from '../../../packages/pca/src/keys.ts';
import { Oracle, refWrite, seed, ser } from './lib.mjs';

const QQ: any = (Q as any).default ?? Q;
const PQ: any = (PQ0 as any).mlDsa65Keygen ? PQ0 : (PQ0 as any).default;
const K: any = (K0 as any).publicKeyOf ? K0 : (K0 as any).default;
const o = new Oracle('pq-threshold-quorum', 'tools/pca-audit/oracles/pq-threshold-quorum.mts', 'TS-reference oracle for the in-core PQ quorum sets, quorum proofs and rotation chains.');
const uniq = (fn: string, name: string) => { let nm = name; for (let i = 2; o.names.has(`${fn}/${nm}`); i++) nm = `${name} #${i}`; return nm; };
const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64url');
const fromB64 = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));
const L = (l: string) => 'ref-pqq/' + l;
const sd = (l: string) => seed(L(l));
// resolve the corpus value forms: {$seed} -> 32 bytes, {$bytes} -> bytes; the ML-DSA key members become key pairs
const un = (v: any): any => {
  if (Array.isArray(v)) return v.map(un);
  if (v !== null && typeof v === 'object') {
    if (typeof v.$seed === 'string' && Object.keys(v).length === 1) return seed(v.$seed);
    if (typeof v.$bytes === 'string' && Object.keys(v).length === 1) return fromB64(v.$bytes);
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, un(x)]));
  }
  return v;
};
const keysOf = (k: any): any => {
  if (k === null || typeof k !== 'object' || Array.isArray(k)) return k;
  const r = un(k);
  if (r.mlDsa instanceof Uint8Array) r.mlDsa = PQ.mlDsa65Keygen(r.mlDsa);
  if (r.mlDsa87 instanceof Uint8Array) r.mlDsa87 = PQ.mlDsa87Keygen(r.mlDsa87);
  return r;
};
const run = (fn: string, name: string, f: (...a: any[]) => any, args: any[]) => {
  try { ser(args); } catch { return Promise.resolve(false); }
  return o.run(fn, uniq(fn, name), f, args);
};

// ---- key material from labels
const wide = (l: string, n: number) => new Uint8Array(Buffer.concat([sd(l + '/a'), sd(l + '/b'), sd(l + '/c')]).subarray(0, n));
interface Who { label: string; ed: string; pubs: Record<string, string>; secrets: any; slhSecret?: any }
const whoCache = new Map<string, Who>();
function who(label: string): Who {
  let w = whoCache.get(label);
  if (w) return w;
  const edSeed = sd(label + '/ed');
  const pqSeed = sd(label + '/pq');
  const ml = PQ.mlDsa65Keygen(pqSeed);
  w = { label, ed: b64(K.publicKeyOf(edSeed)), pubs: { edPub: b64(K.publicKeyOf(edSeed)), mlDsaPub: PQ.encodeMlDsaPublicKey(ml.publicKey) }, secrets: { edSecret: edSeed, mlDsa: ml } };
  whoCache.set(label, w);
  return w;
}
const memo = <T,>(f: (l: string) => T) => { const m = new Map<string, T>(); return (l: string): T => { let v = m.get(l); if (v === undefined) { v = f(l); m.set(l, v); } return v; }; };
const slhKey = memo((label: string) => { const kp = PQ.slhDsa128fKeygen(wide(label, 48)); return { kp, pub: PQ.encodeSlhDsaPublicKey(kp.publicKey) }; });
const ml87 = memo((label: string) => { const kp = PQ.mlDsa87Keygen(sd(label + '/pq87')); return { kp, pub: PQ.encodeMlDsa87PublicKey(kp.publicKey) }; });
const slh256 = memo((label: string) => { const kp = PQ.slhDsa256sKeygen(wide(label, 96)); return { kp, pub: PQ.encodeSlhDsa256sPublicKey(kp.publicKey) }; });

type Spec = { alg: string; label: string };
function inputOf(sp: Spec) {
  const w = who(sp.label);
  switch (sp.alg) {
    case 'ml-dsa-65': return { alg: sp.alg, keys: { mlDsaPub: w.pubs.mlDsaPub } };
    case 'hybrid-ed25519-ml-dsa-65': case 'hybrid-nested-ed25519-ml-dsa-65': return { alg: sp.alg, keys: { edPub: w.pubs.edPub, mlDsaPub: w.pubs.mlDsaPub } };
    case 'ml-dsa-87': return { alg: sp.alg, keys: { mlDsa87Pub: ml87(sp.label).pub } };
    case 'hybrid-ed25519-ml-dsa-87': return { alg: sp.alg, keys: { edPub: w.pubs.edPub, mlDsa87Pub: ml87(sp.label).pub } };
    case 'slh-dsa-sha2-128f': return { alg: sp.alg, keys: { slhDsaPub: slhKey(sp.label).pub } };
    case 'hybrid-ed25519-slh-dsa-sha2-128f': return { alg: sp.alg, keys: { edPub: w.pubs.edPub, slhDsaPub: slhKey(sp.label).pub } };
    case 'slh-dsa-sha2-256s': return { alg: sp.alg, keys: { slhDsa256sPub: slh256(sp.label).pub } };
    case 'hybrid-ed25519-slh-dsa-sha2-256s': return { alg: sp.alg, keys: { edPub: w.pubs.edPub, slhDsa256sPub: slh256(sp.label).pub } };
    default: throw new Error('inputOf ' + sp.alg);
  }
}
/** The corpus `keys` value (seed labels only) for a signer; null for a signer no native can sign for (SLH-DSA). */
function keysArg(sp: Spec): any {
  const base = { edSecret: { $seed: L(sp.label + '/ed') } };
  switch (sp.alg) {
    case 'ml-dsa-65': return { mlDsa: { $seed: L(sp.label + '/pq') } };
    case 'hybrid-ed25519-ml-dsa-65': case 'hybrid-nested-ed25519-ml-dsa-65': return { ...base, mlDsa: { $seed: L(sp.label + '/pq') } };
    case 'ml-dsa-87': return { mlDsa87: { $seed: L(sp.label + '/pq87') } };
    case 'hybrid-ed25519-ml-dsa-87': return { ...base, mlDsa87: { $seed: L(sp.label + '/pq87') } };
    default: return null;
  }
}
/** Real secret keys for generation (any suite, SLH included). */
function realKeys(sp: Spec): any {
  const w = who(sp.label);
  const k: any = {};
  if (sp.alg.includes('ed25519')) k.edSecret = w.secrets.edSecret;
  if (sp.alg.endsWith('ml-dsa-65')) k.mlDsa = w.secrets.mlDsa;
  if (sp.alg.endsWith('ml-dsa-87')) k.mlDsa87 = ml87(sp.label).kp;
  if (sp.alg.endsWith('slh-dsa-sha2-128f')) k.slhDsa = slhKey(sp.label).kp;
  if (sp.alg.endsWith('slh-dsa-sha2-256s')) k.slhDsa256s = slh256(sp.label).kp;
  return k;
}
const J = (x: any) => JSON.parse(ser(x));
const build = (specs: Spec[], t: number, k?: number) => { const r = k === undefined ? QQ.buildQuorumSet(specs.map(inputOf), t) : QQ.buildQuorumSet(specs.map(inputOf), t, k); if (!r.ok) throw new Error('fixture'); return J(r.set); };
const ML = (l: string): Spec => ({ alg: 'ml-dsa-65', label: l });
const HY = (l: string): Spec => ({ alg: 'hybrid-ed25519-ml-dsa-65', label: l });
const SL = (l: string): Spec => ({ alg: 'slh-dsa-sha2-128f', label: l });
const HS = (l: string): Spec => ({ alg: 'hybrid-ed25519-slh-dsa-sha2-128f', label: l });
/** Sign as the signer at its canonical index (the set sorts its signers): returns the share (deterministic, so shares can be shared across cases). */
const pqOfInput = (x: any) => x.keys.mlDsaPub ?? x.keys.mlDsa87Pub ?? x.keys.slhDsaPub ?? x.keys.slhDsa256sPub;
const specOfIndex = (set: any, specs: Spec[], i: number): Spec => {
  const e = set.signers[i];
  return specs.find((sp) => { const x = inputOf(sp); return x.alg === e.alg && pqOfInput(x) === e.pq; })!;
};
const share = (set: any, specs: Spec[], i: number, epoch: number, digest: string) => J(QQ.signQuorumShare(set, i, epoch, digest, realKeys(specOfIndex(set, specs, i))));
const DIG = 'ZGlnZXN0LW9uZQ';
const DIG2 = 'ZGlnZXN0LXR3bw';

// ---- constants
await run('constants', 'all', () => ({ PQ_QUORUM_MAX_SIGNERS: QQ.PQ_QUORUM_MAX_SIGNERS, PQ_QUORUM_MAX_CHAIN: QQ.PQ_QUORUM_MAX_CHAIN }), []);

// ---- buildQuorumSet
const bq = (name: string, signers: unknown, t: unknown, k?: unknown) => run('buildQuorumSet', name, QQ.buildQuorumSet, k === undefined ? [signers, t] : [signers, t, k]);
const A3 = [ML('a1'), ML('a2'), ML('a3')];
await bq('3 ml-dsa-65 t=2', A3.map(inputOf), 2);
await bq('t=1', A3.map(inputOf), 1);
await bq('t=n', A3.map(inputOf), 3);
await bq('1 of 1', [inputOf(ML('a1'))], 1);
await bq('input order does not matter', [A3[2]!, A3[0]!, A3[1]!].map(inputOf), 2);
await bq('hybrids', [HY('h1'), HY('h2')].map(inputOf), 2);
await bq('hybrid nested', [{ alg: 'hybrid-nested-ed25519-ml-dsa-65', label: 'h1' }, HY('h2')].map(inputOf), 1);
await bq('ml-dsa-87 and hybrid 87', [{ alg: 'ml-dsa-87', label: 'm87' }, { alg: 'hybrid-ed25519-ml-dsa-87', label: 'h87' }].map(inputOf), 2);
await bq('slh 128f x3 k=0', [SL('s1'), SL('s2'), SL('s3')].map(inputOf), 2);
await bq('slh 128f x3 k=2', [SL('s1'), SL('s2'), SL('s3')].map(inputOf), 2, 2);
await bq('slh 256s and hybrid', [{ alg: 'slh-dsa-sha2-256s', label: 'x1' }, { alg: 'hybrid-ed25519-slh-dsa-sha2-256s', label: 'x2' }].map(inputOf), 2, 2);
await bq('mixed k=1', [ML('a1'), SL('s1'), HS('hs1')].map(inputOf), 2, 1);
await bq('mixed k=2', [ML('a1'), SL('s1'), HS('hs1')].map(inputOf), 2, 2);
await bq('k=0 explicit', A3.map(inputOf), 2, 0);
await bq('k greater than t', [SL('s1'), SL('s2'), SL('s3')].map(inputOf), 2, 3);
await bq('k greater than hash-based available', [ML('a1'), SL('s1'), ML('a2')].map(inputOf), 3, 2);
await bq('k=1 with no hash-based', A3.map(inputOf), 2, 1);
for (const kk of [-1, 1.5, '1', null, true, 2 ** 53, -0]) await bq(`k ${ser(kk)}`, [SL('s1'), SL('s2')].map(inputOf), 1, kk);
for (const tt of [0, -1, 4, 1.5, '2', null, true, 2 ** 53, -0, [2], {}]) await bq(`t ${ser(tt)}`, A3.map(inputOf), tt);
for (const [nm, s] of [['empty', []], ['not array', {}], ['null', null], ['string', 'x'], ['number', 5], ['null entry', [null]], ['entry string', ['x']], ['entry array', [[]]]] as [string, any][]) await bq(`signers ${nm}`, s, 1);
{
  const a = inputOf(ML('a1'));
  await bq('duplicate signer', [a, a], 1);
  await bq('same ml key under hybrid', [a, { alg: 'hybrid-ed25519-ml-dsa-65', keys: { edPub: who('z').pubs.edPub, mlDsaPub: a.keys.mlDsaPub } }], 1);
  await bq('same ed key in two hybrids', [HY('h1'), { alg: 'hybrid-ed25519-ml-dsa-65', keys: { edPub: who('h1').pubs.edPub, mlDsaPub: who('h2').pubs.mlDsaPub } }].map((x: any) => (x.keys ? x : inputOf(x))), 1);
  await bq('hybrid ed key equals another entry ed key only', [HY('h1'), { alg: 'hybrid-ed25519-ml-dsa-65', keys: { edPub: who('h1').pubs.edPub, mlDsaPub: who('h3').pubs.mlDsaPub } }].map((x: any) => (x.keys ? x : inputOf(x))), 1);
  await bq('unknown alg', [{ alg: 'nope', keys: a.keys }], 1);
  await bq('ed25519 is not a PQ suite', [{ alg: 'ed25519', keys: { edPub: who('a1').pubs.edPub } }], 1);
  await bq('alg missing', [{ keys: a.keys }], 1);
  await bq('alg number', [{ alg: 5, keys: a.keys }], 1);
  await bq('alg case', [{ alg: 'ML-DSA-65', keys: a.keys }], 1);
  await bq('keys missing', [{ alg: 'ml-dsa-65' }], 1);
  await bq('keys null', [{ alg: 'ml-dsa-65', keys: null }], 1);
  await bq('keys array', [{ alg: 'ml-dsa-65', keys: [] }], 1);
  await bq('pq key missing', [{ alg: 'ml-dsa-65', keys: {} }], 1);
  await bq('pq key of the wrong suite', [{ alg: 'ml-dsa-65', keys: { slhDsaPub: slhKey('s1').pub } }], 1);
  await bq('pq key short', [{ alg: 'ml-dsa-65', keys: { mlDsaPub: a.keys.mlDsaPub.slice(0, -4) } }], 1);
  await bq('pq key long', [{ alg: 'ml-dsa-65', keys: { mlDsaPub: a.keys.mlDsaPub + 'AAAA' } }], 1);
  await bq('pq key padded', [{ alg: 'ml-dsa-65', keys: { mlDsaPub: a.keys.mlDsaPub + '=' } }], 1);
  await bq('pq key not canonical base64url', [{ alg: 'ml-dsa-65', keys: { mlDsaPub: a.keys.mlDsaPub.slice(0, -1) + (a.keys.mlDsaPub.endsWith('A') ? 'B' : 'A') } }], 1);
  await bq('pq key standard base64', [{ alg: 'ml-dsa-65', keys: { mlDsaPub: a.keys.mlDsaPub.replace(/-/g, '+').replace(/_/g, '/') + '' } }], 1);
  await bq('pq key number', [{ alg: 'ml-dsa-65', keys: { mlDsaPub: 5 } }], 1);
  await bq('ed key on a non-hybrid', [{ alg: 'ml-dsa-65', keys: { ...a.keys, edPub: who('a1').pubs.edPub } }], 1);
  await bq('hybrid without ed key', [{ alg: 'hybrid-ed25519-ml-dsa-65', keys: { mlDsaPub: a.keys.mlDsaPub } }], 1);
  await bq('hybrid ed key short', [{ alg: 'hybrid-ed25519-ml-dsa-65', keys: { edPub: who('a1').pubs.edPub.slice(0, -4), mlDsaPub: a.keys.mlDsaPub } }], 1);
  await bq('hybrid ed key number', [{ alg: 'hybrid-ed25519-ml-dsa-65', keys: { edPub: 5, mlDsaPub: a.keys.mlDsaPub } }], 1);
  await bq('extra key members ignored', [{ alg: 'ml-dsa-65', keys: { ...a.keys, junk: 1 } }], 1);
  await bq('extra signer members ignored', [{ ...a, junk: 1 }], 1);
  await bq('fn-dsa-512 key missing', [{ alg: 'fn-dsa-512', keys: {} }], 1);
  await bq('less-cat1 not generated', [{ alg: 'less-cat1', keys: {} }], 1);
  await bq('hybrid-less', [{ alg: 'hybrid-ed25519-less-cat1', keys: { edPub: who('a1').pubs.edPub } }], 1);
}
{
  // size bounds, with 32-byte SLH-DSA-128f keys: 256 is the maximum, 257 is refused
  const many = (n: number) => Array.from({ length: n }, (_, i) => inputOf(SL('m' + i)));
  await bq('256 signers t=1', many(256), 1);
  await bq('256 signers t=256 k=256', many(256), 256, 256);
  await bq('257 signers', many(257), 1);
  await bq('255 signers t=128', many(255), 128);
}

// ---- loadQuorumSet
const ld = (name: string, x: unknown) => run('loadQuorumSet', name, QQ.loadQuorumSet, [x]);
const SA = build(A3, 2);
const SH = build([ML('a1'), SL('s1'), HS('hs1'), HY('h1')], 3, 2);
const SS = build([SL('s1'), SL('s2'), SL('s3'), SL('s4')], 2, 1);
await ld('ok ml', SA);
await ld('ok mixed', SH);
await ld('ok slh', SS);
const mset = (base: any, f: (s: any) => void) => { const s = J(base); f(s); return s; };
for (const [nm, f] of [
  ['id wrong', (s: any) => { s.id = s.id.slice(0, -2) + (s.id.endsWith('AA') ? 'BB' : 'AA'); }], ['id missing', (s: any) => { delete s.id; }], ['id number', (s: any) => { s.id = 5; }], ['id empty', (s: any) => { s.id = ''; }],
  ['t changed (id stale)', (s: any) => { s.t = 1; }], ['t 0', (s: any) => { s.t = 0; }], ['t too big', (s: any) => { s.t = 9; }], ['t missing', (s: any) => { delete s.t; }], ['t string', (s: any) => { s.t = '2'; }], ['t fraction', (s: any) => { s.t = 1.5; }],
  ['k changed', (s: any) => { s.minHashBased = 1; }], ['k missing', (s: any) => { delete s.minHashBased; }], ['k null', (s: any) => { s.minHashBased = null; }], ['k negative', (s: any) => { s.minHashBased = -1; }], ['k above t', (s: any) => { s.minHashBased = 3; }],
  ['signers reversed', (s: any) => { s.signers.reverse(); }], ['signers swapped first two', (s: any) => { [s.signers[0], s.signers[1]] = [s.signers[1], s.signers[0]]; }], ['signers dropped one', (s: any) => { s.signers.pop(); }], ['signers emptied', (s: any) => { s.signers = []; }],
  ['signers duplicated', (s: any) => { s.signers.push(s.signers[0]); }], ['signers not array', (s: any) => { s.signers = {}; }], ['signers missing', (s: any) => { delete s.signers; }], ['signer null', (s: any) => { s.signers[0] = null; }], ['signer string', (s: any) => { s.signers[0] = 'x'; }],
  ['alg unknown', (s: any) => { s.signers[0].alg = 'nope'; }], ['alg ed25519', (s: any) => { s.signers[0].alg = 'ed25519'; }], ['alg swapped to hybrid', (s: any) => { s.signers[0].alg = 'hybrid-ed25519-ml-dsa-65'; }], ['alg missing', (s: any) => { delete s.signers[0].alg; }],
  ['pq missing', (s: any) => { delete s.signers[0].pq; }], ['pq short', (s: any) => { s.signers[0].pq = s.signers[0].pq.slice(0, -4); }], ['pq noncanonical', (s: any) => { s.signers[0].pq = s.signers[0].pq.slice(0, -1) + (s.signers[0].pq.endsWith('A') ? 'B' : 'A'); }], ['pq number', (s: any) => { s.signers[0].pq = 5; }],
  ['ed on non-hybrid', (s: any) => { s.signers[0].ed = who('a1').pubs.edPub; }], ['ed null on non-hybrid', (s: any) => { s.signers[0].ed = null; }], ['ed missing on hybrid', (s: any) => { const h = s.signers.find((e: any) => e.alg.startsWith('hybrid')); delete h.ed; }],
  ['extra member on set', (s: any) => { s.extra = 1; }], ['extra member on signer', (s: any) => { s.signers[0].extra = 1; }], ['null ed on hybrid', (s: any) => { const h = s.signers.find((e: any) => e.alg.startsWith('hybrid')); h.ed = null; }],
] as [string, (s: any) => void][]) await ld(`mut ${nm}`, mset(SH, f));
for (const [nm, v] of [['null', null], ['string', 'x'], ['array', []], ['number', 5], ['empty', {}], ['signers only', { signers: [] }], ['id only', { id: 'x' }], ['signers not array', { signers: 'x', id: 'x' }]] as [string, any][]) await ld(`not a set ${nm}`, v);
await ld('hand-built unsorted but valid keys', (() => { const s = J(SS); s.signers = [s.signers[1], s.signers[0], s.signers[2], s.signers[3]]; return s; })());
await ld('256 signers', J(build(Array.from({ length: 256 }, (_, i) => SL('m' + i)), 1)));
await ld('257 signers', (() => { const r = QQ.buildQuorumSet(Array.from({ length: 256 }, (_, i) => inputOf(SL('m' + i))), 1); const s = J(r.set); s.signers.push(J(inputOf(SL('m256')))); s.signers[256] = { alg: 'slh-dsa-sha2-128f', pq: slhKey('m256').pub }; return s; })());

// ---- quorumMessage / quorumActionDigest
const qm = (name: string, id: unknown, epoch: unknown, dg: unknown) => run('quorumMessage', name, QQ.quorumMessage, [id, epoch, dg]);
await qm('basic', SA.id, 0, DIG);
await qm('epoch 1', SA.id, 1, DIG);
await qm('epoch max safe', SA.id, 2 ** 53 - 1, DIG);
await qm('other digest', SA.id, 1, DIG2);
await qm('other set', SH.id, 1, DIG);
await qm('empty strings', '', 0, '');
await qm('unicode', 'é\u{1F600}', 3, 'ü');
await qm('long', 'a'.repeat(1000), 3, 'b'.repeat(1000));
await qm('epoch -0 (hash refuses)', SA.id, -0, DIG);
await qm('epoch 2^53 (hash refuses)', SA.id, 2 ** 53, DIG);
await qm('epoch fraction', SA.id, 1.5, DIG);
await qm('epoch negative', SA.id, -1, DIG);
await qm('epoch string', SA.id, '1', DIG);
await qm('epoch null', SA.id, null, DIG);
await qm('epoch tiny float (hash refuses)', SA.id, 1e-7, DIG);
await qm('setId number', 5, 1, DIG);
await qm('setId null', null, 1, DIG);
await qm('digest array', SA.id, 1, ['x']);
await qm('lone surrogate', '\ud800', 1, DIG);
const qd = (name: string, bytes: unknown) => run('quorumActionDigest', name, (b: any) => QQ.quorumActionDigest(un(b)), [bytes]);
for (const [nm, bytes] of [['empty', new Uint8Array(0)], ['one', new Uint8Array([0])], ['abc', new TextEncoder().encode('abc')], ['256 bytes', Uint8Array.from({ length: 256 }, (_, i) => i)], ['4096 bytes', Uint8Array.from({ length: 4096 }, (_, i) => (i * 7) & 255)]] as [string, Uint8Array][]) await qd(nm, { $bytes: b64(bytes) });
await qd('string (throws)', 'abc');
await qd('null', null);

// ---- signQuorumShare / assembleQuorumProof / the proof builders
const sqs = (name: string, set: unknown, i: unknown, epoch: unknown, dg: unknown, keys: unknown) => run('signQuorumShare', name, (s: any, ix: any, e: any, d: any, k: any) => QQ.signQuorumShare(s, ix, e, d, keysOf(k)), [set, i, epoch, dg, keys]);
{
  const SB = build([ML('a1'), HY('h1'), { alg: 'ml-dsa-87', label: 'm87' }, { alg: 'hybrid-ed25519-ml-dsa-87', label: 'h87' }], 2);
  const BSP = [ML('a1'), HY('h1'), { alg: 'ml-dsa-87', label: 'm87' }, { alg: 'hybrid-ed25519-ml-dsa-87', label: 'h87' }];
  for (const i of [0, 1, 2, 3]) {
    const sp = specOfIndex(SB, BSP, i);
    await sqs(`signer ${i} ${sp.alg}`, SB, i, 4, DIG, keysArg(sp));
  }
  const sp0 = specOfIndex(SB, BSP, 0);
  await sqs('epoch 0', SB, 0, 0, DIG, keysArg(sp0));
  await sqs('other digest', SB, 0, 7, DIG2, keysArg(sp0));
  await sqs('index out of range', SB, 4, 4, DIG, keysArg(sp0));
  await sqs('index negative', SB, -1, 4, DIG, keysArg(sp0));
  await sqs('index fraction', SB, 0.5, 4, DIG, keysArg(sp0));
  await sqs('index string', SB, '0', 4, DIG, keysArg(sp0));
  await sqs('index null', SB, null, 4, DIG, keysArg(sp0));
  await sqs('wrong key kind (ml-dsa key for a hybrid slot)', SB, 1, 4, DIG, { mlDsa: { $seed: L('h1/pq') } });
  await sqs('missing ed secret', SB, 1, 4, DIG, { mlDsa: { $seed: L('h1/pq') } });
  await sqs('keys empty', SB, 0, 4, DIG, {});
  await sqs('keys null', SB, 0, 4, DIG, null);
  await sqs('epoch -0 (hash refuses)', SB, 0, -0, DIG, keysArg(sp0));
  await sqs('epoch fraction', SB, 0, 1.5, DIG, keysArg(sp0));
  await sqs('another signers key signs (verifies as bad-signature later)', SB, 0, 4, DIG, keysArg(specOfIndex(SB, BSP, 1)));
}
await run('assembleQuorumProof', 'two shares', (s: any, sh: any) => QQ.assembleQuorumProof(s, sh), [SA, [share(SA, A3, 0, 1, DIG), share(SA, A3, 1, 1, DIG)]]);
await run('assembleQuorumProof', 'no shares', QQ.assembleQuorumProof, [SA, []]);
await run('assembleQuorumProof', 'junk shares are copied untouched', QQ.assembleQuorumProof, [SA, [{ i: 0 }, null, 5]]);
await run('assembleQuorumProof', 'shares not array', QQ.assembleQuorumProof, [SA, 'x']);
await run('assembleQuorumProof', 'set id only', QQ.assembleQuorumProof, [{ id: 'x' }, []]);

// ---- verifyQuorum
const vq = (name: string, input: unknown) => run('verifyQuorum', name, QQ.verifyQuorum, [input]);
const proofOf = (set: any, shares: any[]) => ({ set_id: set.id, sigs: shares });
const flipSig = (s: string) => s.slice(0, 20) + (s[20] === 'A' ? 'B' : 'A') + s.slice(21);
{
  const E = 5;
  const sh = (i: number, e = E, d = DIG) => share(SA, A3, i, e, d);
  const S0 = sh(0), S1 = sh(1), S2 = sh(2);
  const V = (over: any = {}) => ({ set: SA, proof: proofOf(SA, [S0, S1]), epoch: E, actionDigest: DIG, ...over });
  await vq('ok 2 of 3', V());
  await vq('ok shares in reverse order', V({ proof: proofOf(SA, [S1, S0]) }));
  await vq('ok 3 of 3', V({ proof: proofOf(SA, [S0, S1, S2]) }));
  await vq('ok other pair', V({ proof: proofOf(SA, [S0, S2]) }));
  await vq('ok expectedSetId', V({ expectedSetId: SA.id }));
  await vq('expectedSetId other', V({ expectedSetId: SH.id }));
  await vq('expectedSetId empty string', V({ expectedSetId: '' }));
  await vq('requireHashBased 0', V({ requireHashBased: 0 }));
  await vq('requireHashBased 1 unmet', V({ requireHashBased: 1 }));
  for (const rh of [-1, 1.5, '1', null, 2 ** 53, -0]) await vq(`requireHashBased ${ser(rh)}`, V({ requireHashBased: rh }));
  await vq('below threshold (1 of 2)', V({ proof: proofOf(SA, [S0]) }));
  await vq('no signatures', V({ proof: proofOf(SA, []) }));
  await vq('duplicate signer', V({ proof: proofOf(SA, [S0, S0]) }));
  await vq('duplicate signer later', V({ proof: proofOf(SA, [S0, S1, S1]) }));
  await vq('too many signatures', V({ proof: proofOf(SA, [S0, S1, S2, S0]) }));
  await vq('unknown signer index 3', V({ proof: proofOf(SA, [S0, { ...S1, i: 3 }]) }));
  await vq('unknown signer index -1', V({ proof: proofOf(SA, [S0, { ...S1, i: -1 }]) }));
  await vq('unknown signer index -0', V({ proof: proofOf(SA, [S0, { ...S1, i: -0 }]) }));
  await vq('unknown signer index 1.5', V({ proof: proofOf(SA, [S0, { ...S1, i: 1.5 }]) }));
  await vq('unknown signer index string', V({ proof: proofOf(SA, [S0, { ...S1, i: '1' }]) }));
  await vq('unknown signer index null', V({ proof: proofOf(SA, [S0, { ...S1, i: null }]) }));
  await vq('index missing', V({ proof: proofOf(SA, [S0, { sig: S1.sig }]) }));
  await vq('index 2^53', V({ proof: proofOf(SA, [S0, { ...S1, i: 2 ** 53 }]) }));
  await vq('wrong index for the signature', V({ proof: proofOf(SA, [S0, { ...S1, i: 2 }]) }));
  await vq('signature bit flipped', V({ proof: proofOf(SA, [S0, { ...S1, sig: flipSig(S1.sig) }]) }));
  await vq('signature truncated', V({ proof: proofOf(SA, [S0, { ...S1, sig: S1.sig.slice(0, -4) }]) }));
  await vq('signature empty', V({ proof: proofOf(SA, [S0, { ...S1, sig: '' }]) }));
  await vq('signature number', V({ proof: proofOf(SA, [S0, { ...S1, sig: 5 }]) }));
  await vq('signature missing', V({ proof: proofOf(SA, [S0, { i: 1 }]) }));
  await vq('signature padded', V({ proof: proofOf(SA, [S0, { ...S1, sig: S1.sig + '=' }]) }));
  await vq('pq_sig on a non-hybrid', V({ proof: proofOf(SA, [S0, { ...S1, pq_sig: S1.sig }]) }));
  await vq('wrong epoch', V({ epoch: E + 1 }));
  await vq('wrong digest', V({ actionDigest: DIG2 }));
  await vq('signed for another epoch', V({ proof: proofOf(SA, [S0, sh(1, E + 1)]) }));
  await vq('signed for another digest', V({ proof: proofOf(SA, [S0, sh(1, E, DIG2)]) }));
  await vq('proof for another set', V({ proof: { set_id: SH.id, sigs: [S0, S1] } }));
  await vq('proof set_id missing', V({ proof: { sigs: [S0, S1] } }));
  await vq('proof sigs missing', V({ proof: { set_id: SA.id } }));
  await vq('proof sigs not array', V({ proof: { set_id: SA.id, sigs: {} } }));
  await vq('proof null', V({ proof: null }));
  await vq('proof string', V({ proof: 'x' }));
  await vq('proof array', V({ proof: [] }));
  await vq('share null', V({ proof: proofOf(SA, [S0, null]) }));
  await vq('share string', V({ proof: proofOf(SA, [S0, 'x']) }));
  await vq('share array', V({ proof: proofOf(SA, [S0, []]) }));
  await vq('extra members on the proof and the share', V({ proof: { ...proofOf(SA, [S0, { ...S1, extra: 1 }]), extra: 1 } }));
  await vq('epoch -0', V({ epoch: -0 }));
  await vq('epoch fraction', V({ epoch: 1.5 }));
  await vq('epoch string', V({ epoch: '5' }));
  await vq('epoch missing', V({ epoch: undefined }));
  await vq('epoch negative', V({ epoch: -1 }));
  await vq('epoch 2^53', V({ epoch: 2 ** 53 }));
  await vq('digest number', V({ actionDigest: 5 }));
  await vq('digest missing', V({ actionDigest: undefined }));
  await vq('set tampered (id stale)', V({ set: mset(SA, (s) => { s.t = 1; }) }));
  await vq('set null', V({ set: null }));
  await vq('set missing', V({ set: undefined }));
  await vq('set with wrong id', V({ set: mset(SA, (s) => { s.id = 'x'; }) }));
  await vq('input null', null);
  await vq('input string', 'x');
  await vq('input array', []);
  await vq('input empty', {});
  // threshold 1 and 3
  const A31 = build(A3, 1), A33 = build(A3, 3);
  await vq('t=1 ok', { set: A31, proof: proofOf(A31, [share(A31, A3, 2, 0, DIG)]), epoch: 0, actionDigest: DIG });
  await vq('t=3 with 2', { set: A33, proof: proofOf(A33, [share(A33, A3, 0, 0, DIG), share(A33, A3, 1, 0, DIG)]), epoch: 0, actionDigest: DIG });
  await vq('t=3 with 3', { set: A33, proof: proofOf(A33, [0, 1, 2].map((i) => share(A33, A3, i, 0, DIG))), epoch: 0, actionDigest: DIG });
  await vq('epoch 0 and the set from another epoch', { set: A33, proof: proofOf(A33, [0, 1, 2].map((i) => share(A33, A3, i, 0, DIG))), epoch: 1, actionDigest: DIG });
}
{
  // hybrid sets: both components required
  const HP = [HY('h1'), HY('h2'), { alg: 'hybrid-nested-ed25519-ml-dsa-65', label: 'h3' }];
  const SHY = build(HP, 2);
  const hs = (i: number, e = 1, d = DIG) => share(SHY, HP, i, e, d);
  const V = (shares: any[], over: any = {}) => ({ set: SHY, proof: proofOf(SHY, shares), epoch: 1, actionDigest: DIG, ...over });
  await vq('hybrid ok', V([hs(0), hs(1)]));
  await vq('hybrid ok incl nested', V([hs(1), hs(2)]));
  await vq('hybrid missing pq_sig', V([hs(0), (({ pq_sig, ...r }) => r)(hs(1))]));
  await vq('hybrid pq_sig flipped', V([hs(0), { ...hs(1), pq_sig: flipSig(hs(1).pq_sig) }]));
  await vq('hybrid ed sig flipped', V([hs(0), { ...hs(1), sig: flipSig(hs(1).sig) }]));
  await vq('hybrid components swapped', V([hs(0), { ...hs(1), sig: hs(1).pq_sig, pq_sig: hs(1).sig }]));
  await vq('hybrid pq_sig from another signer', V([hs(0), { ...hs(1), pq_sig: hs(0).pq_sig }]));
  await vq('hybrid pq_sig number', V([hs(0), { ...hs(1), pq_sig: 5 }]));
  await vq('hybrid pq_sig null', V([hs(0), { ...hs(1), pq_sig: null }]));
  await vq('hybrid nested signed as plain', V([hs(0), { ...hs(2), pq_sig: share(build([HY('h3'), HY('h1')], 1), [HY('h3'), HY('h1')], 0, 1, DIG).pq_sig }]));
}
{
  // diversity: a hash-based signer is required
  const DP = [ML('a1'), ML('a2'), SL('s1'), HS('hs1')];
  const SD = build(DP, 3, 1);
  const ds = (i: number, e = 2, d = DIG) => share(SD, DP, i, e, d);
  const idx = (alg: string) => SD.signers.map((e: any, i: number) => (e.alg === alg ? i : -1)).filter((i: number) => i >= 0);
  const mlI = idx('ml-dsa-65'), slI = idx('slh-dsa-sha2-128f')[0]!, hsI = idx('hybrid-ed25519-slh-dsa-sha2-128f')[0]!;
  const V = (is: number[], over: any = {}) => ({ set: SD, proof: proofOf(SD, is.map((i) => ds(i))), epoch: 2, actionDigest: DIG, ...over });
  await vq('diversity ok with the slh signer', V([mlI[0]!, mlI[1]!, slI]));
  await vq('diversity ok with the hybrid slh signer', V([mlI[0]!, mlI[1]!, hsI]));
  await vq('diversity ok with both', V([mlI[0]!, slI, hsI]));
  await vq('diversity unmet: ml-dsa only quorum would be below t anyway', V([mlI[0]!, mlI[1]!]));
  {
    const DP2 = [ML('a1'), ML('a2'), ML('a3'), SL('s1')];
    const S2D = build(DP2, 3, 1);
    const ix = S2D.signers.map((e: any, i: number) => (e.alg === 'ml-dsa-65' ? i : -1)).filter((i: number) => i >= 0);
    await vq('diversity unmet: t lattice signers, set commits k=1', { set: S2D, proof: proofOf(S2D, ix.map((i: number) => share(S2D, DP2, i, 2, DIG))), epoch: 2, actionDigest: DIG });
    await vq('diversity: verifier floor does not lower the commitment', { set: S2D, proof: proofOf(S2D, ix.map((i: number) => share(S2D, DP2, i, 2, DIG))), epoch: 2, actionDigest: DIG, requireHashBased: 0 });
  }
  await vq('requireHashBased 2 met', V([mlI[0]!, slI, hsI], { requireHashBased: 2 }));
  await vq('requireHashBased 2 unmet', V([mlI[0]!, mlI[1]!, slI], { requireHashBased: 2 }));
  await vq('requireHashBased 3 unmet', V([mlI[0]!, slI, hsI], { requireHashBased: 3 }));
  const SU = build(DP, 3, 0);
  const du = (i: number) => share(SU, DP, i, 2, DIG);
  const iu = (alg: string) => SU.signers.map((e: any, i: number) => (e.alg === alg ? i : -1)).filter((i: number) => i >= 0);
  const mlU = iu('ml-dsa-65');
  await vq('no diversity commitment: lattice-only ok', { set: SU, proof: proofOf(SU, [mlU[0]!, mlU[1]!, iu('slh-dsa-sha2-128f')[0]!].map(du)), epoch: 2, actionDigest: DIG });
  await vq('verifier floor 1 with a hash-based signer', { set: SU, proof: proofOf(SU, [mlU[0]!, mlU[1]!, iu('slh-dsa-sha2-128f')[0]!].map(du)), epoch: 2, actionDigest: DIG, requireHashBased: 1 });
  await vq('verifier floor 2 with one hash-based signer', { set: SU, proof: proofOf(SU, [mlU[0]!, mlU[1]!, iu('slh-dsa-sha2-128f')[0]!].map(du)), epoch: 2, actionDigest: DIG, requireHashBased: 2 });
  const SL4 = build([SL('s1'), SL('s2'), SL('s3'), SL('s4')], 2, 2);
  await vq('all-slh set ok', { set: SL4, proof: proofOf(SL4, [0, 3].map((i) => share(SL4, [SL('s1'), SL('s2'), SL('s3'), SL('s4')], i, 0, DIG))), epoch: 0, actionDigest: DIG });
}
{
  // structural refusals that need no real signatures: 256-signer set, unknown signer and too-many-signatures bounds
  const specs = Array.from({ length: 256 }, (_, i) => SL('m' + i));
  const BIG = build(specs, 1);
  const dummy = (i: number) => ({ i, sig: 'AAAA' });
  await vq('256-signer set: bad signature at index 0', { set: BIG, proof: proofOf(BIG, [dummy(0)]), epoch: 0, actionDigest: DIG });
  await vq('256-signer set: index 255 exists', { set: BIG, proof: proofOf(BIG, [dummy(255)]), epoch: 0, actionDigest: DIG });
  await vq('256-signer set: index 256 unknown', { set: BIG, proof: proofOf(BIG, [dummy(256)]), epoch: 0, actionDigest: DIG });
  await vq('256-signer set: 257 shares', { set: BIG, proof: proofOf(BIG, Array.from({ length: 257 }, (_, i) => dummy(i % 256))), epoch: 0, actionDigest: DIG });
  await vq('256-signer set: duplicate before any signature check', { set: BIG, proof: proofOf(BIG, [dummy(3), dummy(3)]), epoch: 0, actionDigest: DIG });
  await vq('slh pq_sig on slh signer', { set: BIG, proof: proofOf(BIG, [{ i: 0, sig: 'AAAA', pq_sig: 'AAAA' }]), epoch: 0, actionDigest: DIG });
  const SSM = build([SL('s1'), SL('s2'), SL('s3')], 2);
  await vq('slh: real signatures', { set: SSM, proof: proofOf(SSM, [0, 2].map((i) => share(SSM, [SL('s1'), SL('s2'), SL('s3')], i, 9, DIG))), epoch: 9, actionDigest: DIG });
  await vq('slh: signature flipped', { set: SSM, proof: proofOf(SSM, [0, 2].map((i) => { const s = share(SSM, [SL('s1'), SL('s2'), SL('s3')], i, 9, DIG); return i === 2 ? { ...s, sig: flipSig(s.sig) } : s; })), epoch: 9, actionDigest: DIG });
}

// ---- verifyQuorumApproval
{
  const A2 = [ML('a1'), ML('a2')], S2 = build(A2, 2);
  const msg = new TextEncoder().encode('approve-this');
  const dg = QQ.quorumActionDigest(msg);
  const pr = proofOf(S2, [0, 1].map((i) => share(S2, A2, i, 3, dg)));
  const va = (name: string, set: unknown, proof: unknown, message: unknown, epoch: unknown, opts?: unknown) => run('verifyQuorumApproval', name, (s: any, p: any, m: any, e: any, ...r: any[]) => QQ.verifyQuorumApproval(s, p, un(m), e, ...r), opts === undefined ? [set, proof, message, epoch] : [set, proof, message, epoch, opts]);
  await va('ok', S2, pr, { $bytes: b64(msg) }, 3);
  await va('ok with pins', S2, pr, { $bytes: b64(msg) }, 3, { expectedSetId: S2.id, requireHashBased: 0 });
  await va('wrong message', S2, pr, { $bytes: b64(new TextEncoder().encode('approve-that')) }, 3);
  await va('wrong epoch', S2, pr, { $bytes: b64(msg) }, 4);
  await va('empty message', S2, pr, { $bytes: b64(new Uint8Array(0)) }, 3);
  await va('message is a string (refused)', S2, pr, 'approve-this', 3);
  await va('message null', S2, pr, null, 3);
  await va('message array of numbers', S2, pr, [1, 2, 3], 3);
  await va('expectedSetId mismatch', S2, pr, { $bytes: b64(msg) }, 3, { expectedSetId: 'x' });
  await va('requireHashBased unmet', S2, pr, { $bytes: b64(msg) }, 3, { requireHashBased: 1 });
  await va('opts null', S2, pr, { $bytes: b64(msg) }, 3, null);
  await va('set null', null, pr, { $bytes: b64(msg) }, 3);
  await va('proof null', S2, null, { $bytes: b64(msg) }, 3);
  await va('epoch string', S2, pr, { $bytes: b64(msg) }, '3');
}

// ---- rotation
{
  const G0 = [ML('r0a'), ML('r0b')], G1 = [ML('r1a'), ML('r1b')], G2 = [ML('r2a'), ML('r2b')], G3 = [ML('r3a'), ML('r3b')];
  const S0 = build(G0, 1), S1 = build(G1, 1), S2 = build(G2, 2), S3 = build(G3, 1);
  const rd = (name: string, id: unknown, e: unknown) => run('rotationActionDigest', name, QQ.rotationActionDigest, [id, e]);
  await rd('basic', S1.id, 1);
  await rd('epoch 0', S1.id, 0);
  await rd('other set', S2.id, 1);
  await rd('epoch max', S1.id, 2 ** 53 - 1);
  await rd('empty id', '', 1);
  await rd('epoch -0 (hash refuses)', S1.id, -0);
  await rd('epoch fraction', S1.id, 1.5);
  await rd('epoch string', S1.id, '1');
  await rd('id null', null, 1);
  const rs = (name: string, from: any, i: unknown, fe: unknown, to: any, keys: unknown) => run('signRotationShare', name, (f: any, ix: any, e: any, t: any, k: any) => QQ.signRotationShare(f, ix, e, t, keysOf(k)), [from, i, fe, to, keys]);
  await rs('signer 0', S0, 0, 0, S1, keysArg(specOfIndex(S0, G0, 0)));
  await rs('signer 1', S0, 1, 0, S1, keysArg(specOfIndex(S0, G0, 1)));
  await rs('from epoch 7', S2, 0, 7, S3, keysArg(specOfIndex(S2, G2, 0)));
  await rs('index out of range', S0, 2, 0, S1, keysArg(specOfIndex(S0, G0, 0)));
  await rs('keys missing', S0, 0, 0, S1, {});
  await rs('to is not a set', S0, 0, 0, { id: 5 }, keysArg(specOfIndex(S0, G0, 0)));
  await rs('to null', S0, 0, 0, null, keysArg(specOfIndex(S0, G0, 0)));
  await rs('from epoch fraction', S0, 0, 0.5, S1, keysArg(specOfIndex(S0, G0, 0)));
  const rsh = (from: any, specs: Spec[], i: number, fe: number, to: any) => J(QQ.signRotationShare(from, i, fe, to, realKeys(specOfIndex(from, specs, i))));
  const cert = (from: any, specs: Spec[], idxs: number[], fe: number, to: any) => J(QQ.buildRotationCert(from, fe, to, idxs.map((i) => rsh(from, specs, i, fe, to))));
  const bc = (name: string, from: unknown, fe: unknown, to: unknown, shares: unknown) => run('buildRotationCert', name, QQ.buildRotationCert, [from, fe, to, shares]);
  await bc('basic', S0, 0, S1, [rsh(S0, G0, 0, 0, S1)]);
  await bc('two shares epoch 4', S2, 4, S3, [rsh(S2, G2, 0, 4, S3), rsh(S2, G2, 1, 4, S3)]);
  await bc('no shares', S0, 0, S1, []);
  await bc('shares junk', S0, 0, S1, [null, 5, {}]);
  await bc('epoch fraction (arithmetic only)', S0, 1.5, S1, []);
  await bc('epoch string concatenates', S0, '1', S1, []);
  await bc('from null', null, 0, S1, []);
  const C01 = cert(S0, G0, [0], 0, S1), C12 = cert(S1, G1, [1], 1, S2), C23 = cert(S2, G2, [0, 1], 2, S3);
  const vc = (name: string, g: unknown, ge: unknown, chain: unknown) => run('verifyRotationChain', name, QQ.verifyRotationChain, [g, ge, chain]);
  await vc('empty chain', S0, 0, []);
  await vc('one rotation', S0, 0, [C01]);
  await vc('two rotations', S0, 0, [C01, C12]);
  await vc('three rotations (t=2 quorum last)', S0, 0, [C01, C12, C23]);
  await vc('genesis epoch 5', S0, 5, [cert(S0, G0, [0], 5, S1), cert(S1, G1, [0], 6, S2)]);
  await vc('genesis epoch mismatch', S0, 1, [C01]);
  await vc('genesis epoch -0', S0, -0, []);
  await vc('genesis epoch fraction', S0, 0.5, []);
  await vc('genesis epoch string', S0, '0', []);
  await vc('genesis epoch 2^53', S0, 2 ** 53, []);
  await vc('genesis null', null, 0, []);
  await vc('genesis tampered', mset(S0, (s) => { s.id = 'x'; }), 0, [C01]);
  await vc('genesis is not a set', {}, 0, []);
  await vc('chain not array', S0, 0, {});
  await vc('chain null', S0, 0, null);
  await vc('chain string', S0, 0, 'x');
  await vc('entry null', S0, 0, [null]);
  await vc('entry number', S0, 0, [C01, 5]);
  await vc('skips a link', S0, 0, [C12]);
  await vc('wrong order', S0, 0, [C12, C01]);
  await vc('repeated cert', S0, 0, [C01, C01]);
  await vc('quorum too small at the last link', S0, 0, [C01, C12, cert(S2, G2, [0], 2, S3)]);
  await vc('forged signature', S0, 0, [{ ...C01, proof: { ...C01.proof, sigs: [{ ...C01.proof.sigs[0], sig: flipSig(C01.proof.sigs[0].sig) }] } }]);
  await vc('signed for a different successor', S0, 0, [{ ...C01, to_set: S2 }]);
  await vc('to_epoch skips', S0, 0, [{ ...C01, to_epoch: 2 }]);
  await vc('to_epoch repeats', S0, 0, [{ ...C01, to_epoch: 0 }]);
  await vc('from_epoch wrong', S0, 0, [{ ...C01, from_epoch: 1 }]);
  await vc('from_epoch fraction', S0, 0, [{ ...C01, from_epoch: 0.5 }]);
  await vc('from_epoch string', S0, 0, [{ ...C01, from_epoch: '0' }]);
  await vc('from_epoch -0', S0, 0, [{ ...C01, from_epoch: -0 }]);
  await vc('from_set_id wrong', S0, 0, [{ ...C01, from_set_id: S1.id }]);
  await vc('from_set_id missing', S0, 0, [(({ from_set_id, ...r }) => r)(C01)]);
  await vc('to_set invalid', S0, 0, [{ ...C01, to_set: { ...S1, id: 'x' } }]);
  await vc('to_set missing', S0, 0, [(({ to_set, ...r }) => r)(C01)]);
  await vc('to_set equals from set', S0, 0, [cert(S0, G0, [0], 0, S0)]);
  await vc('proof missing', S0, 0, [(({ proof, ...r }) => r)(C01)]);
  await vc('proof for another set', S0, 0, [{ ...C01, proof: { ...C01.proof, set_id: S1.id } }]);
  await vc('proof signed at another epoch', S0, 0, [{ ...C01, proof: J(QQ.assembleQuorumProof(S0, [J(QQ.signQuorumShare(S0, 0, 1, QQ.rotationActionDigest(S1.id, 1), realKeys(specOfIndex(S0, G0, 0))))])) }]);
  await vc('proof signed over the plain action digest, not the rotation digest', S0, 0, [{ ...C01, proof: J(QQ.assembleQuorumProof(S0, [J(QQ.signQuorumShare(S0, 0, 0, DIG, realKeys(specOfIndex(S0, G0, 0))))])) }]);
  await vc('unknown signer in proof', S0, 0, [{ ...C01, proof: { ...C01.proof, sigs: [{ ...C01.proof.sigs[0], i: 5 }] } }]);
  await vc('extra members ignored', S0, 0, [{ ...C01, extra: 1 }]);
  await vc('1025 entries: too long', S0, 0, Array.from({ length: 1025 }, () => null));
  await vc('1024 junk entries: fails at the first', S0, 0, Array.from({ length: 1024 }, () => null));
  await vc('rotates to a set with a later forked successor', S0, 0, [C01, cert(S1, G1, [0], 1, S3)]);
  const fk = (name: string, a: unknown, b: unknown) => run('isRotationFork', name, QQ.isRotationFork, [a, b]);
  const C01b = cert(S0, G0, [0], 0, S2);
  await fk('same from, different to', C01, C01b);
  await fk('identical', C01, C01);
  await fk('same to, other signers', C01, cert(S0, G0, [1], 0, S1));
  await fk('different epoch', C01, cert(S0, G0, [0], 1, S2));
  await fk('different from set', C01, C12);
  await fk('first not an object', null, C01);
  await fk('second not an object', C01, 5);
  await fk('to_set missing', { from_set_id: 'a', from_epoch: 0 }, { from_set_id: 'a', from_epoch: 0, to_set: { id: 'x' } });
  await fk('to_set ids not strings', { from_set_id: 'a', from_epoch: 0, to_set: { id: 1 } }, { from_set_id: 'a', from_epoch: 0, to_set: { id: 2 } });
  await fk('minimal fork', { from_set_id: 'a', from_epoch: 0, to_set: { id: 'x' } }, { from_set_id: 'a', from_epoch: 0, to_set: { id: 'y' } });
  await fk('minimal same', { from_set_id: 'a', from_epoch: 0, to_set: { id: 'x' } }, { from_set_id: 'a', from_epoch: 0, to_set: { id: 'x' } });
  await fk('epochs differ by type', { from_set_id: 'a', from_epoch: 0, to_set: { id: 'x' } }, { from_set_id: 'a', from_epoch: '0', to_set: { id: 'y' } });
  await fk('arrays', [], []);
  await fk('to_set array', { from_set_id: 'a', from_epoch: 0, to_set: [] }, { from_set_id: 'a', from_epoch: 0, to_set: [] });
}

// ---- quorumProofSize
{
  const mixed = [ML('a1'), HY('h1'), { alg: 'ml-dsa-87', label: 'm87' }, SL('s1'), HS('hs1')];
  const SM = build(mixed, 3);
  const sz = (name: string, set: unknown, idx?: unknown) => run('quorumProofSize', name, QQ.quorumProofSize, idx === undefined ? [set] : [set, idx]);
  await sz('mixed t=3', SM);
  await sz('mixed chosen 0,1,2', SM, [0, 1, 2]);
  await sz('chosen with unknown index counts 0', SM, [0, 9]);
  await sz('chosen empty', SM, []);
  await sz('chosen duplicates counted twice', SM, [0, 0]);
  await sz('ml-dsa-65 only', SA);
  await sz('ml-dsa-65 t=1', build(A3, 1));
  await sz('all signers', build(A3, 3), [0, 1, 2]);
  await sz('slh', SS);
  await sz('hybrid slh + hybrid ml', build([HS('hs1'), HY('h1')], 2));
  await sz('256s', build([{ alg: 'slh-dsa-sha2-256s', label: 'x1' }, ML('a1')], 2));
  await sz('set with unknown alg (throws)', { t: 1, signers: [{ alg: 'nope' }] });
  await sz('set null (throws)', null);
  await sz('chosen index fraction', SM, [0.5]);
  await sz('chosen index string', SM, ['0']);
  await sz('chosen not array', SM, 'x');
}

refWrite(o, 'pq-threshold-quorum');
