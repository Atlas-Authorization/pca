// Oracle: @atlasauth/pca-actions pack.ts (build side) and transparency.ts (payload). Writes out/ref-actions-pack.json.gz.
// PORTING table (the signing key is an Ed25519 seed passed as {$bytes}; everything else is plain JSON)
//   buildPack(a, {$bytes: seed})                 -> ActionPacks.buildPack(a, Keys.ed25519(Keys.edFromSeed(seed)), null, d -> false, null); a throw must throw
//   shardDefs(defs, max)                         -> ActionPacks.shardDefs(defs, max) (max null = default)
//   verifyUpgrade(prev, next, keys, prevShards, shards) -> ActionPacks.verifyUpgrade (core registry, attestation never verified)
//   packStatementPayload(pack)                   -> ActionTransparency.packStatementPayload
import * as PK0 from '../../../packages/pca-actions/src/pack.ts';
import * as TR0 from '../../../packages/pca-actions/src/transparency.ts';
import * as B0 from '../../../packages/pca-actions/src/builtin.ts';
import * as DM0 from '../../../packages/pca-actions/src/domain.ts';
import * as P0 from '../../../packages/pca/src/index.ts';
import { Oracle, refWrite, clone, seed } from './lib.mjs';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const PK = un(PK0), TR = un(TR0), BI = un(B0), DM = un(DM0);
const P: any = (P0 as any).b64u ? P0 : (P0 as any).default;
const o = new Oracle('actions-pack', 'tools/pca-audit/oracles/actions-pack.mts', 'TS-reference oracle for pca-actions pack building, upgrade verification and the transparency payload.');
const ALL: any[] = [...BI.BUILTIN_DEFS, ...DM.DOMAIN_DEFS].map((d: any) => clone(d));
const SK = seed('ref-actions-pack/registry'), SK2 = seed('ref-actions-pack/other');
const bytes = (u: Uint8Array) => ({ $bytes: P.b64u(u) });
const unb = (s: any) => Uint8Array.from(Buffer.from(s.$bytes, 'base64url'));
const KEYS = [{ kid: 'reg1', alg: 'ed25519', pk: P.b64u(P.publicKeyOf(SK)) }];
const OTHER = [{ kid: 'reg1', alg: 'ed25519', pk: P.b64u(P.publicKeyOf(SK2)) }];
const SRC = { kind: 'openapi', uri: 'https://example.com/spec', spec_digest: 'A'.repeat(43), licence: 'MIT', licence_notes: '' };
const arg = (over: any = {}) => ({ ns: 'acme', version: '1.0.0', stability: 'stable', defs: ALL.slice(0, 4), source: SRC, kid: 'reg1', ...over });
const BP = (n: string, a: any, sk = SK) => o.run('buildPack', n, (x: any, s: any) => PK.buildPack({ ...x, secret: unb(s) }), [a, bytes(sk)]);
const mut = (d: any, f: (x: any) => void) => { const c = clone(d); f(c); return c; };

await BP('inline', arg());
await BP('other key', arg(), SK2);
await BP('unsorted', arg({ defs: [...ALL.slice(0, 4)].reverse() }));
await BP('one def', arg({ defs: [ALL[0]] }));
await BP('draft', arg({ stability: 'draft', version: '0.1.0' }));
await BP('bad stability', arg({ stability: 'rc' }));
await BP('bad ns', arg({ ns: 'Bad NS' }));
await BP('bad version', arg({ version: '1.0' }));
await BP('empty', arg({ defs: [] }));
await BP('duplicate', arg({ defs: [ALL[0], ALL[0]] }));
await BP('invalid def', arg({ defs: [mut(ALL[0], (d) => (d.verb = 'Bad Verb'))] }));
await BP('bad source', arg({ source: { ...SRC, uri: '' } }));
await BP('shard true', arg({ shard: true }));
await BP('shard max2', arg({ shard: { max: 2 } }));
await BP('shard max1', arg({ shard: { max: 1 } }));
await BP('shard max0', arg({ shard: { max: 0 } }));
await BP('shard max frac', arg({ shard: { max: 1.5 } }));
await BP('shard false', arg({ shard: false }));
await BP('shard empty obj', arg({ shard: {} }));
const p1 = PK.buildPack({ ...arg(), secret: SK });
const p1s = PK.buildPack({ ...arg({ shard: { max: 2 } }), secret: SK });
const NEXTDEFS: [string, any[]][] = [
  ['same', ALL.slice(0, 4)], ['added', ALL.slice(0, 5)], ['removed', ALL.slice(1, 4)], ['swap', [...ALL.slice(1, 4), ALL[6]]],
  ['title', ALL.slice(0, 4).map((d, i) => (i === 0 ? mut(d, (x) => (x.title = 'Renamed')) : d))],
  ['blast', ALL.slice(0, 4).map((d, i) => (i === 1 ? mut(d, (x) => (x.blast = { radius: 'global', ppm: 1_000_000 })) : d))],
];
for (const [n, defs] of NEXTDEFS) {
  await BP(`chain ${n}`, arg({ version: '1.1.0', defs, prev: { pack: p1.pack } }));
  await BP(`chain sharded ${n}`, arg({ version: '1.1.0', defs, shard: { max: 2 }, prev: { pack: p1s.pack, shards: p1s.shards } }));
}
await BP('chain missing shards', arg({ version: '1.1.0', prev: { pack: p1s.pack } }));
await BP('chain other ns', arg({ ns: 'other', version: '1.1.0', prev: { pack: p1.pack } }));
await BP('chain same version', arg({ version: '1.0.0', prev: { pack: p1.pack } }));
await BP('chain lower version', arg({ version: '0.9.9', prev: { pack: p1.pack } }));
for (const [m, mx] of [[undefined, undefined], [1, 1], [2, 2], [3, 3], [100, 100], [0, 0], [-1, -1], [1.5, 1.5], [null, null]] as any[]) await o.run('shardDefs', `max ${m}`, (d: any, k: any) => PK.shardDefs(d, k === null ? undefined : k), [ALL.slice(0, 12), mx === undefined ? null : mx]);
await o.run('shardDefs', 'empty', (d: any, k: any) => PK.shardDefs(d, k), [[], 2]);
await o.run('shardDefs', 'all by 5', (d: any, k: any) => PK.shardDefs(d, k), [ALL, 5]);

const UP = (n: string, prev: any, next: any, keys: any = KEYS, ps: any = null, sh: any = null) =>
  o.run('verifyUpgrade', n, (a: any, b: any, k: any, x: any, y: any) => PK.verifyUpgrade(a, b, k, { ...(x ? { prevShards: x } : {}), ...(y ? { shards: y } : {}) }), [prev, next, keys, ps, sh]);
for (const [n, defs] of NEXTDEFS) {
  const next = PK.buildPack({ ...arg({ version: '1.1.0', defs, prev: { pack: p1.pack } }), secret: SK });
  await UP(`ok ${n}`, p1.pack, next.pack);
  await UP(`${n} wrong keys`, p1.pack, next.pack, OTHER);
  await UP(`${n} reversed`, next.pack, p1.pack);
  await UP(`${n} tampered evolution`, p1.pack, { ...next.pack, evolution: next.pack.evolution.slice(1) });
  const nexts = PK.buildPack({ ...arg({ version: '1.1.0', defs, shard: { max: 2 }, prev: { pack: p1s.pack, shards: p1s.shards } }), secret: SK });
  await UP(`sharded ${n}`, p1s.pack, nexts.pack, KEYS, p1s.shards, nexts.shards);
  await UP(`sharded ${n} no shards`, p1s.pack, nexts.pack);
}
const skip = PK.buildPack({ ...arg({ version: '1.2.0', defs: ALL.slice(0, 5) }), secret: SK });
await UP('chain gap', p1.pack, skip.pack);
const other = PK.buildPack({ ...arg({ ns: 'other', version: '1.1.0' }), secret: SK });
await UP('other namespace', p1.pack, other.pack);
await UP('not a pack', { x: 1 }, p1.pack);
for (const [n, p] of [['inline', p1.pack], ['sharded', p1s.pack], ['genesis', PK.buildPack({ ...arg({ defs: ALL.slice(0, 2) }), secret: SK }).pack]] as [string, any][]) await o.run('packStatementPayload', n, (x: any) => TR.packStatementPayload(x), [p]);
refWrite(o, 'actions-pack');
