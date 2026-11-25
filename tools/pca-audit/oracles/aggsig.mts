// Oracle: @atlasauth/pca-aggsig (BLS12-381 PoP aggregation, rogue-key-safe registry, BLS capability chain, witness cosignatures).
// Deterministic (BLS signatures are deterministic; secret keys derive from seed(label)). Writes out/ref-aggsig.json.gz.
// Bytes arrive/leave as {"$bytes": b64url}. Keys are given as pairs {pk, pop}; the wrapper registers them (a failed
// registration makes the case result {"registerFailed": true}).
//
// PORTING (fn(args) -> native entry point, comparison rule):
//   publicKeyOf(sk)                      -> Aggsig.publicKeyOf                        bytes
//   sign(sk, msg) / popProve(sk)         -> Aggsig.sign / popProve                    bytes; a reference throw requires a throw
//   verify(pk, msg, sig)                 -> Aggsig.verify                             boolean
//   keyValidate(pk)                      -> Aggsig.keyValidate                        boolean
//   registerKey(pk, pop)                 -> Aggsig.registerKey                        {ok} (reason compared)
//   aggregate(sigs)                      -> Aggsig.aggregate                          bytes; empty / non-canonical => throw
//   aggregateVerify(keys, msgs, agg)     -> register each {pk,pop} then Aggsig.aggregateVerify  boolean (or {registerFailed})
//   fastAggregateVerify(keys, msg, agg)  -> register each then Aggsig.fastAggregateVerify      boolean (or {registerFailed})
//   mintBlsRoot / chainDelegate          -> AggsigChain.mintBlsRoot / blsDelegate (args are secret keys + b64u ids)   cap JSON
//   capHash(cap)                         -> AggsigChain.capHash                       string
//   aggregateChainSignatures(chain)      -> AggsigChain.aggregateChainSignatures      bytes
//   verifyAggregatedChain(chain, agg, keys, root?) -> register keys into a KeyRegistry, AggsigChain.verifyAggregatedChain   {ok, reason?}
//   cosignTreeHead(sth, sk)              -> AggsigWitness.cosignTreeHead              {key,sig,suite}
//   verifyWitnessCosignature(sth, cosig) -> AggsigWitness.verifyWitnessCosignature    boolean
//   aggregateWitnessCosignatures(cosigs) -> AggsigWitness.aggregateWitnessCosignatures  bytes
//   verifyAggregatedWitnessCosignatures(sth, keys, agg) -> register keys, AggsigWitness.verifyAggregatedWitnessCosignatures  boolean
import { createHash } from 'node:crypto';
import * as A0 from '@atlasauth/pca-aggsig';
import { Oracle, refWrite, seed } from './lib.mjs';

const A: any = (A0 as any).default ?? A0;
const o = new Oracle('aggsig', 'tools/pca-audit/oracles/aggsig.mts', 'TS-reference oracle for BLS12-381 signature aggregation (PoP ciphersuite), registry, capability chain and witness cosignatures.');
const R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;
const B = (x: any): any => (x !== null && typeof x === 'object' && !Array.isArray(x) && typeof x.$bytes === 'string' ? new Uint8Array(Buffer.from(x.$bytes, 'base64url')) : x);
const Bs = (xs: any[]): any[] => xs.map(B);
const J = (u: Uint8Array) => ({ $bytes: Buffer.from(u).toString('base64url') });
function sk(label: string): Uint8Array {
  const d = createHash('sha256').update(seed(label)).digest();
  let n = (BigInt('0x' + d.toString('hex')) % (R - 1n)) + 1n;
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) { out[i] = Number(n & 0xffn); n >>= 8n; }
  return out;
}
const SK = Array.from({ length: 20 }, (_, i) => sk('aggsig-' + i));
const PK = SK.map((s) => A.publicKeyOf(s));
const POP = SK.map((s) => A.popProve(s));
const pair = (i: number) => ({ pk: J(PK[i]!), pop: J(POP[i]!) });
const msg = (s: string) => new TextEncoder().encode(s);
const flip = (u: Uint8Array, i: number, m = 1): Uint8Array => { const c = Uint8Array.from(u); c[i] = c[i]! ^ m; return c; };

function reg(keys: any[]): { r: any; bad: boolean } {
  const r = new A.KeyRegistry();
  for (const k of keys) if (!r.register(B(k.pk), B(k.pop)).ok) return { r, bad: true };
  return { r, bad: false };
}
const regKeys = (keys: any[]) => keys.map((k) => { const x = A.registerKey(B(k.pk), B(k.pop)); return x.ok ? x.key : null; });

const refs: Record<string, (...a: any[]) => any> = {
  publicKeyOf: (s) => A.publicKeyOf(B(s)),
  sign: (s, m) => A.sign(B(s), B(m)),
  popProve: (s) => A.popProve(B(s)),
  verify: (pk, m, sg) => A.verify(B(pk), B(m), B(sg)),
  keyValidate: (pk) => A.keyValidate(B(pk)),
  registerKey: (pk, pop) => { const r = A.registerKey(B(pk), B(pop)); return r.ok ? { ok: true } : { ok: false, reason: r.reason }; },
  aggregate: (sigs) => A.aggregate(Bs(sigs)),
  aggregateVerify: (keys, msgs, agg) => { const ks = regKeys(keys); return ks.includes(null) ? { registerFailed: true } : A.aggregateVerify(ks as any[], Bs(msgs), B(agg)); },
  fastAggregateVerify: (keys, m, agg) => { const ks = regKeys(keys); return ks.includes(null) ? { registerFailed: true } : A.fastAggregateVerify(ks as any[], B(m), B(agg)); },
  mintBlsRoot: (psk, ppub, holder, caveats) => A.mintBlsRoot({ principalSecret: B(psk), principalPublic: ppub, holder, caveats }),
  chainDelegate: (parent, toHolder, added, s) => A.blsDelegate(parent, toHolder, added, B(s)),
  chainAttenuate: (parent, added, s) => A.blsAttenuate(parent, added, B(s)),
  capHash: (c) => A.capHash(c),
  aggregateChainSignatures: (chain) => A.aggregateChainSignatures(chain),
  verifyAggregatedChain: (chain, agg, keys, root) => { const { r } = reg(keys); return A.verifyAggregatedChain(chain, B(agg), r, root === null ? undefined : root); },
  cosignTreeHead: (sth, s) => A.cosignTreeHead(sth, B(s)),
  verifyWitnessCosignature: (sth, c) => A.verifyWitnessCosignature(sth, c),
  aggregateWitnessCosignatures: (cs) => A.aggregateWitnessCosignatures(cs),
  verifyAggregatedWitnessCosignatures: (sth, keys, agg) => { const ks = regKeys(keys); return ks.includes(null) ? { registerFailed: true } : A.verifyAggregatedWitnessCosignatures(sth, ks as any[], B(agg)); },
};
const run = (fn: string, name: string, args: any[]) => o.run(fn, name, refs[fn]!, args);

// ---- primitives
const MSGS = [msg(''), msg('a'), msg('hello world'), new Uint8Array(32), new Uint8Array(200).fill(7)];
for (let i = 0; i < 6; i++) {
  await run('publicKeyOf', `k${i}`, [J(SK[i]!)]);
  await run('popProve', `k${i}`, [J(SK[i]!)]);
  for (const [j, m] of MSGS.entries()) await run('sign', `k${i}m${j}`, [J(SK[i]!), J(m)]);
}
for (const [bi, bad] of [new Uint8Array(0), new Uint8Array(31), new Uint8Array(33), new Uint8Array(32), Uint8Array.from(Buffer.from(R.toString(16).padStart(64, '0'), 'hex'))].entries()) await run('sign', `badsk${bi}`, [J(bad), J(msg('x'))]);
const sigs = SK.map((s, i) => A.sign(s, MSGS[i % MSGS.length]!));
for (let i = 0; i < 8; i++) {
  const m = MSGS[i % MSGS.length]!;
  await run('verify', `ok${i}`, [J(PK[i]!), J(m), J(sigs[i]!)]);
  await run('verify', `wrongmsg${i}`, [J(PK[i]!), J(msg('other')), J(sigs[i]!)]);
  await run('verify', `wrongkey${i}`, [J(PK[i + 1]!), J(m), J(sigs[i]!)]);
  await run('verify', `flipsig${i}`, [J(PK[i]!), J(m), J(flip(sigs[i]!, 40 + i))]);
  await run('verify', `uncompressed${i}`, [J(PK[i]!), J(m), J(flip(sigs[i]!, 0, 0x80))]);
  await run('verify', `shortsig${i}`, [J(PK[i]!), J(m), J(sigs[i]!.slice(1))]);
  await run('keyValidate', `ok${i}`, [J(PK[i]!)]);
  await run('keyValidate', `flip${i}`, [J(flip(PK[i]!, 20 + i))]);
  await run('keyValidate', `noflag${i}`, [J(flip(PK[i]!, 0, 0x80))]);
}
const INF1 = new Uint8Array(48); INF1[0] = 0xc0;
const INF2 = new Uint8Array(96); INF2[0] = 0xc0;
await run('keyValidate', 'inf', [J(INF1)]);
await run('keyValidate', 'short', [J(PK[0]!.slice(1))]);
await run('keyValidate', 'zeros', [J(new Uint8Array(48))]);
await run('verify', 'infsig', [J(PK[0]!), J(msg('')), J(INF2)]);
await run('verify', 'infpk', [J(INF1), J(msg('')), J(INF2)]);
for (let i = 0; i < 6; i++) {
  await run('registerKey', `ok${i}`, [J(PK[i]!), J(POP[i]!)]);
  await run('registerKey', `swappop${i}`, [J(PK[i]!), J(POP[i + 1]!)]);
  await run('registerKey', `sigAsPop${i}`, [J(PK[i]!), J(A.sign(SK[i]!, PK[i]!))]);
  await run('registerKey', `badpoplen${i}`, [J(PK[i]!), J(POP[i]!.slice(2))]);
}
await run('registerKey', 'badkey', [J(INF1), J(POP[0]!)]);

// ---- aggregation
await run('aggregate', 'empty', [[]]);
await run('aggregate', 'one', [[J(sigs[0]!)]]);
await run('aggregate', 'inf', [[J(INF2)]]);
await run('aggregate', 'bad', [[J(sigs[0]!), J(flip(sigs[1]!, 0, 0x80))]]);
for (const n of [2, 3, 5, 8]) {
  await run('aggregate', `n${n}`, [sigs.slice(0, n).map(J)]);
  await run('aggregate', `rev${n}`, [sigs.slice(0, n).reverse().map(J)]);
}
const same = msg('same message');
const sameSigs = SK.map((s) => A.sign(s, same));
for (const n of [1, 2, 3, 6]) {
  const keys = Array.from({ length: n }, (_, i) => pair(i));
  const agg = A.aggregate(sameSigs.slice(0, n));
  await run('fastAggregateVerify', `ok${n}`, [keys, J(same), J(agg)]);
  await run('fastAggregateVerify', `wrongmsg${n}`, [keys, J(msg('x')), J(agg)]);
  await run('fastAggregateVerify', `flip${n}`, [keys, J(same), J(flip(agg, 50))]);
  await run('fastAggregateVerify', `missingKey${n}`, [keys.slice(1), J(same), J(agg)]);
  await run('fastAggregateVerify', `dup${n}`, [[...keys, keys[0]], J(same), J(A.aggregate([...sameSigs.slice(0, n), sameSigs[0]!]))]);
  const dists = Array.from({ length: n }, (_, i) => msg('distinct-' + i));
  const dsigs = dists.map((m, i) => A.sign(SK[i]!, m));
  const dagg = A.aggregate(dsigs);
  await run('aggregateVerify', `ok${n}`, [keys, dists.map(J), J(dagg)]);
  await run('aggregateVerify', `flip${n}`, [keys, dists.map(J), J(flip(dagg, 60))]);
  await run('aggregateVerify', `swapmsgs${n}`, [keys, [...dists].reverse().map(J), J(dagg)]);
  await run('aggregateVerify', `lenmismatch${n}`, [keys, dists.slice(1).map(J), J(dagg)]);
  if (n > 1) await run('aggregateVerify', `repeatedmsg${n}`, [keys, dists.map(() => J(dists[0]!)), J(A.aggregate(SK.slice(0, n).map((s) => A.sign(s, dists[0]!))))]);
}
await run('fastAggregateVerify', 'empty', [[], J(same), J(sameSigs[0]!)]);
await run('aggregateVerify', 'empty', [[], [], J(INF2)]);
await run('fastAggregateVerify', 'unregistered', [[{ pk: J(PK[0]!), pop: J(POP[1]!) }], J(same), J(sameSigs[0]!)]);
// rogue key: pk_adv = a*G - pk_victim has no PoP
await run('aggregateVerify', 'rogueNoPop', [[pair(0), { pk: J(PK[1]!), pop: J(POP[2]!) }], [J(msg('a')), J(msg('b'))], J(A.aggregate([A.sign(SK[0]!, msg('a')), A.sign(SK[1]!, msg('b'))]))]);

// ---- chain
const caveatSets: any[][] = [[], [{ type: 'amount', max: 10 }], [{ type: 'amount', max: 10 }, { type: 'audience', aud: 'x' }]];
const ids = PK.map((p) => Buffer.from(p).toString('base64url'));
const chains: any[] = [];
for (const [ci, cavs] of caveatSets.entries()) {
  for (const depth of [1, 2, 3, 5]) {
    const root = A.mintBlsRoot({ principalSecret: SK[0]!, principalPublic: ids[0]!, holder: ids[1]!, caveats: cavs as any });
    const chain: any[] = [root];
    for (let d = 1; d < depth; d++) chain.push(A.blsDelegate(chain[d - 1], ids[d + 1]!, [{ type: 'step', n: d }] as any, SK[d]!));
    chains.push({ name: `c${ci}d${depth}`, chain, depth });
  }
}
const keysFor = (n: number) => Array.from({ length: n }, (_, i) => pair(i));
await run('mintBlsRoot', 'basic', [J(SK[0]!), ids[0], ids[1], [{ type: 'amount', max: 10 }]]);
await run('mintBlsRoot', 'nocav', [J(SK[0]!), ids[0], ids[1], []]);
await run('chainDelegate', 'basic', [chains[1].chain[0], ids[2], [{ type: 'x', v: 1 }], J(SK[1]!)]);
await run('chainAttenuate', 'basic', [chains[1].chain[0], [{ type: 'x', v: 1 }], J(SK[1]!)]);
for (const c of chains) {
  const agg = A.aggregateChainSignatures(c.chain);
  const keys = keysFor(c.depth);
  await run('capHash', c.name, [c.chain[c.chain.length - 1]]);
  await run('aggregateChainSignatures', c.name, [c.chain]);
  await run('verifyAggregatedChain', `${c.name}/ok`, [c.chain, J(agg), keys, null]);
  await run('verifyAggregatedChain', `${c.name}/okroot`, [c.chain, J(agg), keys, ids[0]]);
  await run('verifyAggregatedChain', `${c.name}/wrongroot`, [c.chain, J(agg), keys, ids[5]]);
  await run('verifyAggregatedChain', `${c.name}/badagg`, [c.chain, J(flip(agg, 70)), keys, null]);
  await run('verifyAggregatedChain', `${c.name}/nokeys`, [c.chain, J(agg), [], null]);
  await run('verifyAggregatedChain', `${c.name}/missingkey`, [c.chain, J(agg), keys.slice(1), null]);
  const t1 = structuredClone(c.chain); t1[0].caveats = [{ type: 'amount', max: 99 }];
  await run('verifyAggregatedChain', `${c.name}/tamperedcaveat`, [t1, J(agg), keys, null]);
  const t2 = structuredClone(c.chain); t2[0].sig = t2[0].sig.slice(0, -2) + 'AA';
  await run('verifyAggregatedChain', `${c.name}/tamperedsig`, [t2, J(agg), keys, null]);
  const t3 = structuredClone(c.chain); t3[0].parent = 'x';
  await run('verifyAggregatedChain', `${c.name}/rootparent`, [t3, J(agg), keys, null]);
  const t4 = structuredClone(c.chain); t4[0].suite = 'ed25519';
  await run('verifyAggregatedChain', `${c.name}/suite`, [t4, J(agg), keys, null]);
  const t5 = structuredClone(c.chain); t5[0].id = 'zz';
  await run('verifyAggregatedChain', `${c.name}/idmismatch`, [t5, J(agg), keys, null]);
  const t6 = structuredClone(c.chain); t6[0].caveats = [1];
  await run('verifyAggregatedChain', `${c.name}/badcaveat`, [t6, J(agg), keys, null]);
  const t7 = structuredClone(c.chain); t7[0].parent = null;
  await run('verifyAggregatedChain', `${c.name}/nullparent`, [t7, J(agg), keys, null]);
  if (c.depth > 1) {
    await run('verifyAggregatedChain', `${c.name}/reversed`, [[...c.chain].reverse(), J(agg), keys, null]);
    await run('verifyAggregatedChain', `${c.name}/droplast`, [c.chain.slice(0, -1), J(agg), keys, null]);
    await run('verifyAggregatedChain', `${c.name}/skiproot`, [c.chain.slice(1), J(agg), keys, null]);
    const t8 = structuredClone(c.chain); t8[1].parent = 'bogus';
    await run('verifyAggregatedChain', `${c.name}/brokenlink`, [t8, J(agg), keys, null]);
    const t9 = structuredClone(c.chain); t9[1].issuer = ids[9];
    await run('verifyAggregatedChain', `${c.name}/issuer`, [t9, J(agg), keys, null]);
  }
}
{ // sums agree but the signatures are over the wrong bodies: only the pairing check can refuse
  const c = structuredClone(chains[5].chain);
  c[0].sig = Buffer.from(A.sign(SK[7]!, msg('wrong'))).toString('base64url');
  await run('verifyAggregatedChain', 'wrongbody', [c, J(A.aggregateChainSignatures(c)), keysFor(c.length), null]);
}
await run('verifyAggregatedChain', 'empty', [[], J(INF2), [], null]);
await run('verifyAggregatedChain', 'notobject', [['x'], J(INF2), [], null]);
{ // drops a parent caveat / alters one: re-sign so only the structural check fires
  const root = A.mintBlsRoot({ principalSecret: SK[0]!, principalPublic: ids[0]!, holder: ids[1]!, caveats: [{ type: 'a' }, { type: 'b' }] as any });
  const kid = A.blsDelegate(root, ids[2]!, [], SK[1]!);
  const dropped: any = structuredClone(kid); dropped.caveats = [{ type: 'a' }];
  const reordered: any = structuredClone(kid); reordered.caveats = [{ type: 'b' }, { type: 'a' }];
  for (const [nm, k] of [['dropped', dropped], ['reordered', reordered]] as const) {
    const bodyDigest = (await import('@atlasauth/pca')).hashCanonical({ issuer: k.issuer, holder: k.holder, caveats: k.caveats, parent: k.parent });
    k.body_digest = bodyDigest; k.id = bodyDigest;
    await run('verifyAggregatedChain', `restructure/${nm}`, [[root, k], J(A.aggregate([A.sign(SK[0]!, msg('x'))])), keysFor(2), null]);
  }
}
{ // too long: 17 hops
  const chain: any[] = [A.mintBlsRoot({ principalSecret: SK[0]!, principalPublic: ids[0]!, holder: ids[1]!, caveats: [] })];
  for (let d = 1; d < 17; d++) chain.push(A.blsDelegate(chain[d - 1], ids[(d + 1) % 20]!, [], SK[d % 20]!));
  await run('verifyAggregatedChain', 'toolong', [chain, J(A.aggregateChainSignatures(chain)), keysFor(17).slice(0, 16), null]);
}

// ---- witnesses
const STHS: any[] = [
  { size: 10, root: 'AAAA', prev_root: 'BBBB', guardian_epoch: 1 },
  { size: 0, root: 'r', prev_root: 'p' },
  { size: 99999, root: 'root-x', prev_root: 'prev-y', guardian_epoch: 0 },
];
for (const [si, sth] of STHS.entries()) {
  const cos = SK.slice(0, 5).map((s) => A.cosignTreeHead(sth, s));
  for (let i = 0; i < 5; i++) await run('cosignTreeHead', `s${si}w${i}`, [sth, J(SK[i]!)]);
  for (let i = 0; i < 3; i++) {
    await run('verifyWitnessCosignature', `s${si}ok${i}`, [sth, cos[i]]);
    await run('verifyWitnessCosignature', `s${si}wrongsth${i}`, [{ ...sth, size: sth.size + 1 }, cos[i]]);
    await run('verifyWitnessCosignature', `s${si}suite${i}`, [sth, { ...cos[i], suite: 'ed25519' }]);
    await run('verifyWitnessCosignature', `s${si}badsig${i}`, [sth, { ...cos[i], sig: cos[i].sig.slice(0, -2) + 'AA' }]);
    await run('verifyWitnessCosignature', `s${si}swapkey${i}`, [sth, { ...cos[i], key: cos[i + 1].key }]);
  }
  for (const n of [1, 3, 5]) {
    const agg = A.aggregateWitnessCosignatures(cos.slice(0, n));
    const keys = keysFor(n);
    await run('aggregateWitnessCosignatures', `s${si}n${n}`, [cos.slice(0, n)]);
    await run('verifyAggregatedWitnessCosignatures', `s${si}n${n}ok`, [sth, keys, J(agg)]);
    await run('verifyAggregatedWitnessCosignatures', `s${si}n${n}wrongsth`, [{ ...sth, root: 'other' }, keys, J(agg)]);
    await run('verifyAggregatedWitnessCosignatures', `s${si}n${n}flip`, [sth, keys, J(flip(agg, 33))]);
    await run('verifyAggregatedWitnessCosignatures', `s${si}n${n}dup`, [sth, [...keys, keys[0]], J(agg)]);
    await run('verifyAggregatedWitnessCosignatures', `s${si}n${n}short`, [sth, keys.slice(1), J(agg)]);
  }
  await run('verifyAggregatedWitnessCosignatures', `s${si}empty`, [sth, [], J(INF2)]);
}
await run('aggregateWitnessCosignatures', 'empty', [[]]);

refWrite(o, 'aggsig');
