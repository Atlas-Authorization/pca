// Oracle: @atlasauth/pca-actions build.ts. Writes out/ref-actions-build.json.gz.
// PORTING table (core trait registry; attestations never verified; the signing key is an Ed25519 seed passed as {$bytes})
//   buildArtifacts(defs, cfg)                -> ActionBuild.buildArtifacts(defs, cfg, CORE, null): {schema, pack, cards, ontology, mcp, types}; a throw must throw
//   generateTypes(defs)                      -> ActionBuild.generateTypes
//   toolAction(defs, tool, args)             -> ActionBuild.toolActionMapOf(defs).apply(tool, args) ({verb, resource} or null)
//   packConsistencyError(pack)               -> ActionBuild.packConsistencyError(pack, CORE)
//   signPack(pack, kid, {$bytes})            -> ActionBuild.signPack; packKeyOf(kid, {$bytes}) -> ActionBuild.packKeyOf
//   verifyPack(pack, keys)                   -> ActionBuild.verifyPack(pack, keys, CORE)
import * as BD0 from '../../../packages/pca-actions/src/build.ts';
import * as B0 from '../../../packages/pca-actions/src/builtin.ts';
import * as DM0 from '../../../packages/pca-actions/src/domain.ts';
import * as CT0 from '../../../packages/pca-actions/src/core-traits.ts';
import * as P0 from '../../../packages/pca/src/index.ts';
import { Oracle, refWrite, clone, seed } from './lib.mjs';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const BD = un(BD0), BI = un(B0), DM = un(DM0), CT = un(CT0);
const P: any = (P0 as any).b64u ? P0 : (P0 as any).default;
const CORE = CT.CORE_REGISTRY;
const o = new Oracle('actions-build', 'tools/pca-audit/oracles/actions-build.mts', 'TS-reference oracle for pca-actions build outputs and pack signing.');
const ALL: any[] = [...BI.BUILTIN_DEFS, ...DM.DOMAIN_DEFS].map((d: any) => clone(d));
const SK = seed('ref-actions-build/registry'), SK2 = seed('ref-actions-build/other');
const bytes = (u: Uint8Array) => ({ $bytes: P.b64u(u) });
const unb = (s: any) => Uint8Array.from(Buffer.from(s.$bytes, 'base64url'));
const CFG = { ns: 'acme', version: '1.0.0', stability: 'stable', site: 'https://acme.example', aud: 'acme-api' };
const mut = (d: any, f: (x: any) => void) => { const c = clone(d); f(c); return c; };
const WITHMCP = [mut(ALL[0], (d) => (d.bindings = { mcp: { tool: 'charge_tool' } })), mut(ALL[3], (d) => (d.bindings = { mcp: { tool: 'send_tool' } })), ALL[5]];

const BA = (n: string, defs: any[], cfg: any = CFG) => o.run('buildArtifacts', n, (d: any, c: any) => BD.buildArtifacts(d, c, CORE), [defs, cfg]);
await BA('three', ALL.slice(0, 3));
await BA('one', [ALL[6]]);
await BA('mcp', WITHMCP);
await BA('reversed', [...ALL.slice(0, 3)].reverse());
await BA('empty', []);
await BA('duplicate', [ALL[0], ALL[0]]);
await BA('draft', ALL.slice(2, 4), { ...CFG, stability: 'draft', version: '0.1.0' });
await BA('domain', DM.DOMAIN_DEFS.slice(0, 3).map((d: any) => clone(d)));
await BA('unit conflict', [mut(ALL[0], (d) => (d.params.amount.unit = { kind: 'money', ccy: 'USD', exp: 3 })), ALL[1]]);

const TY = (n: string, defs: any[]) => o.run('generateTypes', n, (d: any) => BD.generateTypes(d), [defs]);
await TY('all', ALL);
await TY('empty', []);
const WEIRD = mut(ALL[0], (d) => {
  d.verb = 'acme.weird_verb.do_it';
  d.params = {
    a: { type: 'string', max_len: 5 }, 'a.b': { type: 'integer', min: 0, max: 5 }, 'x.y.z': { type: 'boolean', required: false }, 'x-y': { type: 'duration' }, '9lives': { type: 'string', values: ['a', 'b"c'] },
    s: { type: 'set', values: ['p', 'q'], required: false }, s0: { type: 'set', values: [] }, arr: { type: 'array', items: 'integer', max_items: 3 }, arr2: { type: 'array', items: 'string' }, e: { type: 'string', values: [] }, d: { type: 'date' }, '.lead': { type: 'string' }, 'tail.': { type: 'string' },
  };
});
await TY('weird', [WEIRD, ALL[1]]);

const TA = (n: string, defs: any[], tool: string, args: any) => o.run('toolAction', n, (d: any, t: string, a: any) => BD.toolActionMapOf(d)(t, a), [defs, tool, args]);
await TA('charge ok', WITHMCP, 'charge_tool', { customer: 'cus_12345678', amount: 100 });
await TA('charge missing', WITHMCP, 'charge_tool', {});
await TA('send ok', WITHMCP, 'send_tool', { to: 'a@b.co', subject: 's', body: 'b' });
await TA('unknown tool', WITHMCP, 'nope', {});
await TA('no mcp', ALL.slice(0, 3), 'x', {});
await TA('nested args', WITHMCP, 'charge_tool', { customer: { a: 1 }, amount: 1 });
await TA('extra', WITHMCP, 'charge_tool', { customer: 'cus_12345678', amount: 100, zzz: 1 });

const built = BD.buildArtifacts(ALL.slice(0, 3), CFG, CORE);
const PACK = built.pack;
const PC = (n: string, p: any) => o.run('packConsistencyError', n, (x: any) => BD.packConsistencyError(x, CORE), [p]);
await PC('ok', PACK); await PC('not object', 5); await PC('null', null); await PC('array', []); await PC('wrong kind', { ...PACK, kind: 'x' }); await PC('wrong v', { ...PACK, v: 2 }); await PC('defs not list', { ...PACK, defs: 'x' });
await PC('bad root', { ...PACK, root: 'A'.repeat(43) }); await PC('bad traits digest', { ...PACK, traits_digest: 'A'.repeat(43) });
await PC('duplicate', { ...PACK, defs: [PACK.defs[0], PACK.defs[0]] }); await PC('invalid def', { ...PACK, defs: [mut(PACK.defs[0], (d) => (d.verb = 'Bad'))] }); await PC('non-object def', { ...PACK, defs: [5] });
await PC('null def', { ...PACK, defs: [null] }); await PC('empty defs', { ...PACK, defs: [] });
const SP = (n: string, p: any, sk = SK) => o.run('signPack', n, (x: any, k: string, s: any) => BD.signPack(x, k, unb(s), CORE), [p, 'reg1', bytes(sk)]);
await SP('ok', PACK); await SP('other key', PACK, SK2); await SP('bad root', { ...PACK, root: 'A'.repeat(43) }); await SP('already signed', { ...PACK, sig: { alg: 'ed25519', kid: 'x', value: 'y' } });
await o.run('packKeyOf', 'a', (k: string, s: any) => BD.packKeyOf(k, unb(s)), ['reg1', bytes(SK)]);
const SIGNED = BD.signPack(PACK, 'reg1', SK, CORE);
const KEYS = [BD.packKeyOf('reg1', SK)], OTHER = [BD.packKeyOf('reg1', SK2)];
const VP = (n: string, p: any, keys: any = KEYS) => o.run('verifyPack', n, (x: any, k: any) => BD.verifyPack(x, k, CORE), [p, keys]);
await VP('ok', SIGNED); await VP('wrong keys', SIGNED, OTHER); await VP('no keys', SIGNED, []); await VP('unsigned', PACK); await VP('tampered', { ...SIGNED, version: '9.9.9' });
await VP('bad sig', { ...SIGNED, sig: { ...SIGNED.sig, value: 'A'.repeat(86) } }); await VP('short sig', { ...SIGNED, sig: { ...SIGNED.sig, value: 'AAAA' } }); await VP('alg', { ...SIGNED, sig: { ...SIGNED.sig, alg: 'rsa' } });
await VP('sig string', { ...SIGNED, sig: 'x' }); await VP('kid number', { ...SIGNED, sig: { ...SIGNED.sig, kid: 5 } }); await VP('key alg', SIGNED, [{ ...KEYS[0], alg: 'rsa' }]); await VP('key pk', SIGNED, [{ ...KEYS[0], pk: 'zz' }]);
await VP('inconsistent', { ...SIGNED, root: 'A'.repeat(43) }); await VP('not object', 5);
refWrite(o, 'actions-build');
