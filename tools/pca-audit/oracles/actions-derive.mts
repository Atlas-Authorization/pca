// Oracle: @atlasauth/pca-actions derive.ts + explain.ts. Writes out/ref-actions-derive.json.gz.
// PORTING table: fn(args) -> native entry point (ActionDerive / ActionExplain; `confirmed` = ReviewOpts.attestationVerified constant)
//   flattenParams(params)                    -> ActionDerive.flattenParams        paramByRole(def, role) -> paramByRole (throws no_param / ambiguous_param)
//   effectClass(def)                         -> effectClass                       toSchemaVerb(def, confirmed) -> toSchemaVerb(d, CORE, d -> confirmed)
//   toSchemaDoc(defs, meta, confirmed, regDefs|null) -> toSchemaDoc(defs, reg, meta, ...), reg = null core else extendRegistry(core, regDefs)
//   operationOf(def, params)                 -> operationOf(d, callParams)        riskOf(def, confirmed, params|null, opts) -> riskOf(d, effective(d..), ...)
//   resourceMatcher(def) / predicatesOf(def, limits) / toOntology(defs, confirmed) -> same names
//   cardOf(def, confirmed)                   -> cardOf(d, effective(d, CORE, ..), CORE)    escalationOf(def, confirmed) / mcpAnnotationsOf(def, confirmed) / explainDef(def, confirmed)
//   REVERSIBILITY_SCORE()                    -> ActionDerive.REVERSIBILITY_SCORE (compare as an object)
import * as B0 from '../../../packages/pca-actions/src/builtin.ts';
import * as DM0 from '../../../packages/pca-actions/src/domain.ts';
import * as V0 from '../../../packages/pca-actions/src/validate.ts';
import * as E0 from '../../../packages/pca-actions/src/effective.ts';
import * as DR0 from '../../../packages/pca-actions/src/derive.ts';
import * as X0 from '../../../packages/pca-actions/src/explain.ts';
import * as T0 from '../../../packages/pca-actions/src/traits.ts';
import * as CT0 from '../../../packages/pca-actions/src/core-traits.ts';
import { Oracle, variants, refWrite, clone } from './lib.mjs';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const BI = un(B0), DM = un(DM0), V = un(V0), E = un(E0), DR = un(DR0), X = un(X0), T = un(T0), CT = un(CT0);
const CORE = CT.CORE_REGISTRY;
const o = new Oracle('actions-derive', 'tools/pca-audit/oracles/actions-derive.mts', 'TS-reference oracle for pca-actions derivations.');
const ALL: any[] = [...BI.BUILTIN_DEFS, ...DM.DOMAIN_DEFS].map((d: any) => clone(d));
const opt = (c: boolean) => ({ attestationVerified: () => c });
const regOf = (rd: any) => (rd == null ? CORE : T.extendRegistry(CORE, rd));
const EXTRA = [{ id: 'acme.extra', implies: ['pca.network_egress'], floor: T.profile({ risk: 2, rev: 'reversible', blast_ppm: 100000, esc: 1, caveats: ['amount_cap'], context: [], prules: [] }), card_phrase: 'does the acme thing' }];

// ---- flattenParams ----
const FL: any[] = [{}, { a: 1 }, { a: { b: 1 } }, { a: { b: { c: 1 } } }, { a: { b: { c: { d: 1 } } } }, { a: {}, b: [], c: [1, { d: 2 }], d: null }, { 'a.b': 1, a: { b: 2 } }, { a: { b: 1, c: { d: 2 } }, e: 'x' }, { a: { '1': 1, '0': 2 } }];
for (const [i, p] of FL.entries()) await o.run('flattenParams', `p${i}`, DR.flattenParams, [p]);

// ---- scalar derivations over every def ----
const sample = (d: any): any => {
  const out: any = {};
  for (const [k, p] of Object.entries<any>(d.params)) {
    out[k] = p.role?.startsWith('id.') ? 'abc1234' : p.type === 'integer' ? 7 : p.type === 'boolean' ? true : p.values ? p.values[0] : p.type === 'array' ? ['x'] : p.type === 'set' ? [] : 'val';
  }
  return out;
};
for (const d of ALL) {
  const n = d.verb;
  for (const role of [...new Set(['money.amount', 'id.x', 'nope', ...Object.values<any>(d.params).map((p) => p.role).filter(Boolean)])].slice(0, 6)) await o.run('paramByRole', `${n} ${role}`, DR.paramByRole, [d, role]);
  await o.run('effectClass', n, DR.effectClass, [d]);
  await o.run('resourceMatcher', n, DR.resourceMatcher, [d]);
  for (const c of [true, false]) {
    await o.run('toSchemaVerb', `${n} ${c}`, (x: any, cc: any) => DR.toSchemaVerb(x, CORE, opt(cc)), [d, c]);
    await o.run('cardOf', `${n} ${c}`, (x: any, cc: any) => DR.cardOf(x, E.effective(x, CORE, opt(cc)), CORE), [d, c]);
    await o.run('escalationOf', `${n} ${c}`, (x: any, cc: any) => DR.escalationOf(E.effective(x, CORE, opt(cc))), [d, c]);
    await o.run('mcpAnnotationsOf', `${n} ${c}`, (x: any, cc: any) => DR.mcpAnnotationsOf(x, E.effective(x, CORE, opt(cc))), [d, c]);
    await o.run('explainDef', `${n} ${c}`, (x: any, cc: any) => X.explainDef(x, CORE, opt(cc)), [d, c]);
  }
  const att = clone(d); att.review = { state: 'confirmed', attestation: { def_digest: 'D'.repeat(43), traits_digest: 'T'.repeat(43), facts_digest: 'F'.repeat(43), final_traits: [], dismissed: [], reviewer_kid: 'k', ts: 1, sig: 'S'.repeat(86) } };
  await o.run('toSchemaVerb', `${n} attested`, (x: any, cc: any) => DR.toSchemaVerb(x, CORE, opt(cc)), [att, true]);
  const sp = sample(d);
  await o.run('operationOf', `${n} sample`, (x: any, p: any) => DR.operationOf(x, { params: p }), [d, sp]);
  await o.run('operationOf', `${n} empty`, (x: any, p: any) => DR.operationOf(x, { params: p }), [d, {}]);
  const idp = Object.keys(d.params).find((k) => d.params[k].role?.startsWith('id.'));
  if (idp) await o.run('operationOf', `${n} bad id`, (x: any, p: any) => DR.operationOf(x, { params: p }), [d, { ...sp, [idp]: 'bad id!' }]);
  await o.run('riskOf', `${n} none`, (x: any, cc: any, p: any, op: any) => DR.riskOf(x, E.effective(x, CORE, opt(cc)), p ?? undefined, op), [d, true, null, {}]);
  for (const [lbl, p, op] of [['amount', { ...sp, amount: 50 }, { kappa: 100 }], ['amount over', { ...sp, amount: 500 }, { kappa: 100 }], ['no kappa', { ...sp, amount: 5 }, {}], ['neg', { ...sp, amount: -1 }, { kappa: 10 }], ['taint', sp, { taint: 0.5, kappa: 1 }], ['taint big', sp, { taint: 7 }], ['nested', { ...sp, amount: { x: 1 } }, { kappa: 4 }]] as any[])
    await o.run('riskOf', `${n} ${lbl}`, (x: any, cc: any, pp: any, oo: any) => DR.riskOf(x, E.effective(x, CORE, opt(cc)), pp, oo), [d, true, p, op]);
  await o.run('predicatesOf', `${n} none`, DR.predicatesOf, [d]);
  for (const m of [0, 100, 1000000, -1, 1.5, 2 ** 53]) await o.run('predicatesOf', `${n} ${m}`, DR.predicatesOf, [d, { max_amount: m }]);
}
await o.run('REVERSIBILITY_SCORE', 'all', () => DR.REVERSIBILITY_SCORE, []);

// ---- documents ----
const META = { site: 'https://acme.example', aud: 'agents', version: '1.0.0' };
const SETS: [string, any[]][] = [['empty', []], ['one', ALL.slice(0, 1)], ['six', ALL.slice(0, 6)], ['all', ALL], ['money', ALL.filter((d) => JSON.stringify(d).includes('money'))]];
for (const [n, defs] of SETS) for (const c of [true, false]) {
  await o.run('toSchemaDoc', `${n} ${c}`, (ds: any, m: any, cc: any, rd: any) => DR.toSchemaDoc(ds, regOf(rd), m, opt(cc)), [defs, META, c, null]);
  await o.run('toOntology', `${n} ${c}`, (ds: any, cc: any) => DR.toOntology(ds, CORE, opt(cc)), [defs, c]);
}
await o.run('toSchemaDoc', 'custom registry', (ds: any, m: any, cc: any, rd: any) => DR.toSchemaDoc(ds, regOf(rd), m, opt(cc)), [ALL.slice(0, 3), { ...META, pack: { ns: 'acme', version: '1.0.0', root: 'R'.repeat(43) } }, true, EXTRA]);
await o.run('toSchemaDoc', 'duplicate verb', (ds: any, m: any, cc: any, rd: any) => DR.toSchemaDoc(ds, regOf(rd), m, opt(cc)), [[ALL[0], ALL[0]], META, true, null]);
const u1 = clone(ALL.find((d) => JSON.stringify(d).includes('"ccy":"USD"'))); const u2 = clone(u1); u2.verb = u1.verb + '2'; u2.aliases = []; for (const p of Object.values<any>(u2.params)) if (p.unit?.ccy === 'USD') p.unit.exp = 3;
await o.run('toSchemaDoc', 'unit conflict', (ds: any, m: any, cc: any, rd: any) => DR.toSchemaDoc(ds, regOf(rd), m, opt(cc)), [[u1, u2], META, true, null]);
const a1 = clone(ALL[0]); const a2 = clone(ALL[1]); a2.aliases = [...(a1.aliases ?? [])].slice(0, 1).concat(a2.aliases ?? []);
await o.run('toOntology', 'alias collision', (ds: any, cc: any) => DR.toOntology(ds, CORE, opt(cc)), [[a1, a2], true]);

// ---- hostile variants of one def through the cheap derivations ----
let n = 0;
for (const [lbl, v] of variants(ALL.find((d) => JSON.stringify(d).includes('money.amount')), { maxPaths: 140, hostile: [null, 0, '', 'x', [], {}, true] })) {
  let ok = false; try { ok = V.validateDef(v) === null; } catch { ok = false; }
  if (!ok) continue;
  n++;
  await o.run('effectClass', `v ${lbl}`, DR.effectClass, [v]);
  await o.run('toSchemaVerb', `v ${lbl}`, (x: any, cc: any) => DR.toSchemaVerb(x, CORE, opt(cc)), [v, false]);
  await o.run('explainDef', `v ${lbl}`, (x: any, cc: any) => X.explainDef(x, CORE, opt(cc)), [v, true]);
}
console.log('valid variants', n);
refWrite(o, 'actions-derive');
