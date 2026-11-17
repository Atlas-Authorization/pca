// Oracle (python lane): @atlasauth/pca-actions build.ts + sync.ts + domain.ts. Writes out/ref-actions-build-py.json.gz and the data module
// sdks/python-pca/atlas_pca/actions_builtin_data.py (the built-in and domain defs, domain verb bindings and the legacy tables, as JSON).
// PORTING table: buildArtifacts(defs, cfg, confirmed) toolActionMapOf(defs, tool, args) generateTypes(defs) packConsistencyError(pack) signPack(pack, kid, {$bytes})
//   verifyPack(pack, keys) packKeyOf(kid, {$bytes}) syncSource({current, imported, specDigest, lock?, now}, confirmed) syncText(result) domainVerbs(name) domainRoles(name)
import fs from 'node:fs';
import * as B0 from '../../../packages/pca-actions/src/builtin.ts';
import * as DM0 from '../../../packages/pca-actions/src/domain.ts';
import * as BD0 from '../../../packages/pca-actions/src/build.ts';
import * as SY0 from '../../../packages/pca-actions/src/sync.ts';
import * as CT0 from '../../../packages/pca-actions/src/core-traits.ts';
import * as P0 from '../../../packages/pca/src/index.ts';
import { Oracle, refWrite, clone, seed, ROOT } from './lib.mjs';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const BI = un(B0), DM = un(DM0), BD = un(BD0), SY = un(SY0), CT = un(CT0);
const P: any = (P0 as any).b64u ? P0 : (P0 as any).default;
const CORE = CT.CORE_REGISTRY;
const o = new Oracle('actions-build-py', 'tools/pca-audit/oracles/actions-build-py.mts', 'TS-reference oracle for pca-actions build, sync and domain bindings (python lane).');
const ALL: any[] = [...BI.BUILTIN_DEFS, ...DM.DOMAIN_DEFS].map((d: any) => clone(d));
const opt = (c: boolean) => ({ attestationVerified: () => c });
const SK = seed('ref-actions-build-py/registry'), SK2 = seed('ref-actions-build-py/other');
const bytes = (u: Uint8Array) => ({ $bytes: P.b64u(u) });
const mut = (d: any, f: (x: any) => void) => { const c = clone(d); f(c); return c; };
const CFG = { ns: 'acme', version: '1.2.3', stability: 'beta', site: 'https://acme.example', aud: 'agents' };

// ---- data module for the python lane ----
const DATA = { builtin: BI.BUILTIN_DEFS, domain: DM.DOMAIN_DEFS, domainVerbs: DM.DOMAIN_VERBS, legacyCatalog: BI.LEGACY_CATALOG, legacyOntologyEffect: BI.LEGACY_ONTOLOGY_EFFECT, resolutions: BI.RESOLUTIONS };
fs.writeFileSync(ROOT + 'sdks/python-pca/atlas_pca/actions_builtin_data.py',
  '"""The built-in connector defs, the domain-vocabulary defs and bindings and the legacy catalog tables of the TypeScript reference\n@atlasauth/pca-actions, as JSON (generated; do not edit)."""\nimport json\n\nDATA = json.loads(r\'\'\'' + JSON.stringify(DATA) + '\'\'\')\n');

// ---- buildArtifacts / generateTypes ----
const SETS: [string, any[]][] = [['empty', []], ['one', ALL.slice(0, 1)], ['six', ALL.slice(0, 6)], ['all', ALL]];
for (const [n, defs] of SETS) {
  for (const c of [true, false]) await o.run('buildArtifacts', `${n} ${c}`, (ds: any, cfg: any, cc: any) => BD.buildArtifacts(ds, cfg, CORE, opt(cc)), [defs, CFG, c]);
  await o.run('generateTypes', n, BD.generateTypes, [defs]);
}
await o.run('buildArtifacts', 'dup', (ds: any, cfg: any, cc: any) => BD.buildArtifacts(ds, cfg, CORE, opt(cc)), [[ALL[0], ALL[0]], CFG, true]);
const odd = mut(ALL[0], (x) => { x.verb = 'acme.odd_name.v2'; x.params = { 'to.iban': { type: 'string', max_len: 34 }, 'to.name': { type: 'string', max_len: 10, required: false }, 'weird key': { type: 'set', values: ['a', 'b"c'] }, n: { type: 'array', items: 'integer', min_items: 0, max_items: 3 }, e: { type: 'string', values: ['x', 'y'], max_len: 4 } }; });
await o.run('generateTypes', 'odd', BD.generateTypes, [[odd, ALL[1]]]);

// ---- toolActionMapOf ----
const withMcp = ALL.slice(0, 6).map((d, i) => mut(d, (x) => { x.bindings = { mcp: { tool: `tool_${i}` } }; }));
const sampleOf = (d: any) => { const out: any = {}; for (const [k, p] of Object.entries<any>(d.params)) out[k] = p.role?.startsWith('id.') ? 'abc12345' : p.type === 'integer' ? 5 : 'v'; return out; };
for (const [i, d] of withMcp.entries()) {
  await o.run('toolActionMapOf', `t${i} sample`, (ds: any, t: any, a: any) => BD.toolActionMapOf(ds)(t, a), [withMcp, `tool_${i}`, sampleOf(d)]);
  await o.run('toolActionMapOf', `t${i} empty`, (ds: any, t: any, a: any) => BD.toolActionMapOf(ds)(t, a), [withMcp, `tool_${i}`, {}]);
}
await o.run('toolActionMapOf', 'unknown tool', (ds: any, t: any, a: any) => BD.toolActionMapOf(ds)(t, a), [withMcp, 'nope', {}]);

// ---- pack consistency / signing ----
const PACK = BD.buildArtifacts(ALL.slice(0, 6), CFG, CORE, opt(true)).pack;
const KEYS = [BD.packKeyOf('reg1', SK)];
await o.run('packKeyOf', 'reg1', (k: any, s: any) => BD.packKeyOf(k, Uint8Array.from(Buffer.from(s.$bytes, 'base64url'))), ['reg1', bytes(SK)]);
const packs: [string, any][] = [['ok', PACK], ['root', { ...PACK, root: 'x'.repeat(43) }], ['kind', { ...PACK, kind: 'other' }], ['v2', { ...PACK, v: 2 }], ['traits', { ...PACK, traits_digest: 'y'.repeat(43) }],
  ['dup', { ...PACK, defs: [...PACK.defs, PACK.defs[0]] }], ['bad def', { ...PACK, defs: [{ ...PACK.defs[0], verb: 'BAD' }, ...PACK.defs.slice(1)] }], ['defs not array', { ...PACK, defs: 5 }], ['array', []], ['null', null], ['string', 'x']];
for (const [n, p] of packs) await o.run('packConsistencyError', n, (x: any) => BD.packConsistencyError(x, CORE), [p]);
const signed = BD.signPack(PACK, 'reg1', SK, CORE);
for (const [n, p] of packs) await o.run('signPack', n, (x: any, k: any, s: any) => BD.signPack(x, k, Uint8Array.from(Buffer.from(s.$bytes, 'base64url')), CORE), [p, 'reg1', bytes(SK)]);
const vp: [string, any, any][] = [['ok', signed, KEYS], ['other key', signed, [BD.packKeyOf('reg1', SK2)]], ['no keys', signed, []], ['unsigned', PACK, KEYS], ['tampered', { ...signed, version: '9.9.9' }, KEYS],
  ['bad sig value', { ...signed, sig: { ...signed.sig, value: 'zz' } }, KEYS], ['bad alg', { ...signed, sig: { ...signed.sig, alg: 'rsa' } }, KEYS], ['bad key pk', signed, [{ kid: 'reg1', alg: 'ed25519', pk: 'short' }]],
  ['key alg', signed, [{ kid: 'reg1', alg: 'rsa', pk: KEYS[0].pk }]], ['inconsistent', { ...signed, root: 'x'.repeat(43) }, KEYS], ['null', null, KEYS]];
for (const [n, p, k] of vp) await o.run('verifyPack', n, (x: any, kk: any) => BD.verifyPack(x, kk, CORE), [p, k]);

// ---- syncSource / syncText ----
const impl = ALL.slice(0, 5).map((d) => clone(d));
const conf = (d: any) => mut(d, (x) => { x.review = { state: 'confirmed', attestation: { x: 1 } }; });
const { defDigest } = await import('../../../packages/pca-actions/src/digest.ts').then(un);
const LK = { spec_digest: 'S'.repeat(43), ops: Object.fromEntries(impl.map((d: any) => [d.verb, defDigest(d)])), synced_at: 100 };
const cases: [string, any][] = [
  ['fresh', { current: [], imported: impl, specDigest: 'D'.repeat(43), now: 200 }],
  ['unchanged', { current: impl.map(conf), imported: impl, specDigest: 'D'.repeat(43), lock: LK, now: 200 }],
  ['unchanged nolock', { current: impl, imported: impl, specDigest: 'D'.repeat(43), now: 200 }],
  ['changed', { current: impl.map(conf), imported: impl.map((d, i) => (i === 1 ? mut(d, (x) => (x.title = 'New title')) : i === 2 ? mut(d, (x) => (x.effects = [...x.effects, 'delete'])) : d)), specDigest: 'E'.repeat(43), lock: LK, now: 300 }],
  ['removed', { current: impl, imported: impl.slice(0, 3), specDigest: 'E'.repeat(43), lock: LK, now: 300 }],
  ['imported confirmed', { current: [], imported: impl.map(conf), specDigest: 'D'.repeat(43), now: 200 }],
  ['mixed', { current: [...impl.slice(0, 2).map(conf), ALL[10]], imported: [impl[0], mut(impl[1], (x) => (x.blast = { radius: 'global', ppm: 1000000 })), ALL[11]], specDigest: 'F'.repeat(43), lock: { ...LK, ops: { ...LK.ops, 'gone.verb': 'X'.repeat(43) } }, now: 400 }],
];
for (const [n, a] of cases) for (const c of [true, false]) {
  await o.run('syncSource', `${n} ${c}`, (x: any, cc: any) => SY.syncSource({ ...x, review: opt(cc) }), [a, c]);
  await o.run('syncText', `${n} ${c}`, (x: any, cc: any) => SY.syncText(SY.syncSource({ ...x, review: opt(cc) })), [a, c]);
}

// ---- domain bindings ----
for (const d of ['payments', 'email', 'code_repos', 'data_access', 'calendar_travel']) { await o.run('domainVerbs', d, DM.domainVerbs, [d]); await o.run('domainRoles', d, DM.domainRoles, [d]); }
await o.run('domainVerbs', 'unknown', DM.domainVerbs, ['nope']);
refWrite(o, 'actions-build-py');
