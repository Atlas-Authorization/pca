// Oracle: @atlasauth/pca-actions transparency.ts (appendPackToLog, verifyPackLogEntry). Writes out/ref-actions-pack-log.json.gz.
// Deterministic: Ed25519 only (keys from seeds), so statements and receipts compare byte for byte. Bytes are {"$bytes": b64url}.
// PORTING
//   appendPackToLog(pack, spec) -> ActionTransparency.AppendPackToLog; spec = {regSeed, tsSeed, issuer, preload}: the registry signs with regSeed (EdDSA),
//       the log (issuer "ts") signs receipts with tsSeed, `preload` unrelated statements are registered first; out {statement, receipt, index, root}
//   verifyPackLogEntry(pack, entry, keys, treeRoot) -> ActionTransparency.VerifyPackLogEntry; entry {statement, receipt}, keys {registry, log} = Ed25519
//       public keys (b64url); treeRoot string or null; never throws, out is a boolean
import { createPrivateKey, createPublicKey } from 'node:crypto';
import * as PK0 from '../../../packages/pca-actions/src/pack.ts';
import * as TR0 from '../../../packages/pca-actions/src/transparency.ts';
import * as B0 from '../../../packages/pca-actions/src/builtin.ts';
import * as SC0 from '../../../packages/pca-scitt/src/index.ts';
import * as ST0 from '../../../packages/pca-scitt/src/testing.ts';
import { Oracle, refWrite, clone, seed } from './lib.mjs';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const PK = un(PK0), TR = un(TR0), BI = un(B0), SC = un(SC0), ST = un(ST0);
const o = new Oracle('actions-pack-log', 'tools/pca-audit/oracles/actions-pack-log.mts', 'TS-reference oracle for appending an action pack to a transparency log and verifying the entry.');
const ALL: any[] = BI.BUILTIN_DEFS.map((d: any) => clone(d));
const b64u = (u: Uint8Array) => Buffer.from(u).toString('base64url');
const unb = (s: any) => new Uint8Array(Buffer.from(s.$bytes, 'base64url'));
const B = (u: Uint8Array) => ({ $bytes: b64u(u) });
const PRE = Buffer.from('302e020100300506032b657004220420', 'hex');
const priv = (s: Uint8Array) => createPrivateKey({ key: Buffer.concat([PRE, Buffer.from(s)]), format: 'der', type: 'pkcs8' });
const pubOf = (s: Uint8Array) => (priv(s).export({ format: 'jwk' }) as any).x as string;
const pubKey = (x: string) => createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x }, format: 'jwk' });
const REG = seed('ref-actions-pack-log/registry'), TS = seed('ref-actions-pack-log/log'), OTHER = seed('ref-actions-pack-log/other');
const SRC = { kind: 'openapi', uri: 'https://example.com/spec', spec_digest: 'A'.repeat(43), licence: 'MIT', licence_notes: '' };
const mk = (over: any = {}) => PK.buildPack({ ns: 'acme', version: '1.0.0', stability: 'stable', defs: ALL.slice(0, 3), source: SRC, kid: 'reg1', secret: REG, ...over }).pack;
const PACK = mk(), PACK2 = mk({ version: '1.1.0', prev: { pack: PACK } }), PACKS = mk({ shard: { max: 1 } });

const service = (spec: any) => {
  const svc = new ST.TransparencyService({ alg: 'EdDSA', key: priv(Buffer.from(spec.tsSeed, 'base64url')), issuer: 'ts' });
  for (let i = 0; i < spec.preload; i++) svc.register(SC.signStatement({ i }, { alg: 'EdDSA', key: priv(OTHER), issuer: 'other', subject: `s${i}` }));
  return svc;
};
const append = (pack: any, spec: any) => {
  const svc = service(spec);
  const r = TR.appendPackToLog(pack, svc, { alg: 'EdDSA', key: priv(Buffer.from(spec.regSeed, 'base64url')), issuer: spec.issuer });
  return { statement: r.statement, receipt: r.receipt, index: r.index, root: r.root };
};
const SPEC = (over: any = {}) => ({ regSeed: b64u(REG), tsSeed: b64u(TS), issuer: 'registry', preload: 0, ...over });
const A = (n: string, pack: any, spec: any = SPEC()) => o.run('appendPackToLog', n, append, [pack, spec]);
await A('genesis', PACK);
await A('chained', PACK2);
await A('sharded', PACKS);
await A('index 3', PACK, SPEC({ preload: 3 }));
await A('index 7 chained', PACK2, SPEC({ preload: 7 }));
await A('other registry', PACK, SPEC({ regSeed: b64u(OTHER) }));
await A('other issuer', PACK, SPEC({ issuer: 'iss2' }));
await A('not a pack', { x: 1 });

const verify = (pack: any, e: any, k: any, root: any) =>
  !!TR.verifyPackLogEntry(pack, { statement: unb(e.statement), receipt: unb(e.receipt) }, { registry: pubKey(k.registry), log: pubKey(k.log) }, root === null ? undefined : root);
const KEYS = { registry: pubOf(REG), log: pubOf(TS) };
const flip = (b: any, i: number) => { const u = unb(b); u[i % u.length] ^= 1; return B(u); };
const V = (n: string, pack: any, e: any, k: any, root: any = null) => o.run('verifyPackLogEntry', n, verify, [pack, e, k, root]);
for (const [n, pack, pre] of [['genesis', PACK, 0], ['chained', PACK2, 0], ['sharded', PACKS, 2], ['index 5', PACK, 5]] as [string, any, number][]) {
  const e = append(pack, SPEC({ preload: pre }));
  const E = { statement: B(e.statement), receipt: B(e.receipt) };
  await V(`${n} ok`, pack, E, KEYS);
  await V(`${n} ok root`, pack, E, KEYS, e.root);
  await V(`${n} wrong root`, pack, E, KEYS, b64u(OTHER));
  await V(`${n} empty root`, pack, E, KEYS, '');
  await V(`${n} wrong registry`, pack, E, { ...KEYS, registry: pubOf(OTHER) });
  await V(`${n} wrong log`, pack, E, { ...KEYS, log: pubOf(OTHER) });
  await V(`${n} swapped keys`, pack, E, { registry: KEYS.log, log: KEYS.registry });
  await V(`${n} other pack`, pack === PACK ? PACK2 : PACK, E, KEYS);
  await V(`${n} tampered pack`, { ...pack, digest: 'x', ns: 'evil' }, E, KEYS);
  await V(`${n} swapped entry`, pack, { statement: E.receipt, receipt: E.statement }, KEYS);
  await V(`${n} empty statement`, pack, { statement: B(new Uint8Array(0)), receipt: E.receipt }, KEYS);
  await V(`${n} empty receipt`, pack, { statement: E.statement, receipt: B(new Uint8Array(0)) }, KEYS);
  await V(`${n} truncated receipt`, pack, { statement: E.statement, receipt: B(e.receipt.slice(0, e.receipt.length - 3)) }, KEYS);
  for (const i of [0, 5, 20, 40, Math.floor(e.statement.length / 2), e.statement.length - 1]) await V(`${n} flip statement ${i}`, pack, { ...E, statement: flip(E.statement, i) }, KEYS);
  for (const i of [0, 5, 20, 40, Math.floor(e.receipt.length / 2), e.receipt.length - 1]) await V(`${n} flip receipt ${i}`, pack, { ...E, receipt: flip(E.receipt, i) }, KEYS);
}
// a statement for another pack, validly logged: must not vouch for this pack
const eo = append(PACK2, SPEC());
await V('statement of another pack', PACK, { statement: B(eo.statement), receipt: B(eo.receipt) }, KEYS);
// the receipt of one entry against another's statement
const e0 = append(PACK, SPEC({ preload: 1 })), e1 = append(PACK, SPEC({ preload: 2 }));
await V('receipt of another index', PACK, { statement: B(e0.statement), receipt: B(e1.receipt) }, KEYS);
refWrite(o, 'actions-pack-log');
