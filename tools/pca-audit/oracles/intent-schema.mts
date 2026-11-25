// Oracle: @atlasauth/pca-intent the outcome space from a site action schema (schema.ts): deriveOmegaFromSchema, canonValue (with the core wallet-floor helpers). Deterministic.
// PORTING (fn(args) -> native entry point, comparison rule; JSON value equality, doubles bit-exact):
//   deriveSchemaOmega(opts) -> {omega, overrides, defaults, canonOf}   IntentSchema.deriveOmegaFromSchema(opts) (omega via IntentOmega.omegaToJson; canonOf a string map)
//   canonValue(decl, x)        IntentSchema.canonValue
//   effectiveSensitivity(decl, floor?) / verbReversibility(verb) / walletFloorOverrides(verbs, floor?)   IntentSchema.* (verbs = the schema's verb list)
import * as S0 from '../../../packages/pca-intent/src/schema';
import * as INT0 from '../../../packages/pca/src/ext/intent';
import { Oracle, refWrite } from './lib.mjs';

const S: any = (S0 as any).default ?? S0;
const INT: any = (INT0 as any).default ?? INT0;
const o = new Oracle('intent-schema', 'tools/pca-audit/oracles/intent-schema.mts', 'TS-reference oracle for the schema-derived outcome space.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);
const P = 'action.params.';
const prm = (type: string, semantic: string, sensitivity: string, extra: any = {}) => ({ type, semantic, sensitivity, ...extra });
const buy = { verb: 'shop.buy', kind: 'write', reversibility: 'irreversible', params: {
  [P + 'qty']: prm('integer', 'count.items', 'material', { min: 1, max: 20 }), [P + 'amount']: prm('integer', 'money.amount', 'free'), [P + 'currency']: prm('string', 'money.currency', 'material', { values: ['usd', 'eur'] }),
  [P + 'gift']: prm('boolean', 'flag.gift', 'material'), [P + 'tags']: prm('set', 'tag.x', 'critical', { values: ['a', 'b', 'c'] }), [P + 'note']: prm('string', 'text.note', 'free'), [P + 'ids']: prm('array', 'ids.x', 'material', { items: 'integer' }),
  [P + 'day']: prm('date', 'time.day', 'material'), [P + 'tip']: prm('integer', 'money.tip', 'material', { default: 7, principal_neutral_default: true }), [P + 'size']: prm('string', 'item.size', 'material', { default: 'm', principal_neutral_default: true }),
  [P + 'coupon']: prm('string', 'item.coupon', 'material', { default: 'x', principal_neutral_default: false }) } };
const view = { verb: 'shop.view', kind: 'read', params: {} };
const send = { verb: 'mail.send', kind: 'write', reversibility: 'rate_limited', params: { [P + 'to']: prm('string', 'party.payee', 'free'), [P + 'subject']: prm('string', 'text.subject', 'free'), [P + 'body']: prm('string', 'text.message', 'free'), [P + 'cc']: prm('array', 'party.cc', 'material') } };
const del = { verb: 'files.delete', kind: 'write', params: { [P + 'hard']: prm('boolean', 'flag.hard', 'material'), [P + 'path']: prm('string', 'file.path', 'material') }, reversibility_by: { param: P + 'hard', map: { true: 'irreversible', false: 'reversible' } } };
const del2 = { verb: 'files.move', kind: 'write', params: { [P + 'mode']: prm('string', 'flag.mode', 'material', { values: ['safe', 'fast', 'raw'] }), [P + 'n']: prm('integer', 'count.n', 'material') }, reversibility_by: { param: P + 'mode', map: { safe: 'reversible', fast: 'rate_limited' }, default: 'rate_limited' } };
const del3 = { verb: 'files.copy', kind: 'write', params: { [P + 'mode']: prm('string', 'flag.mode', 'material', { values: ['safe', 'fast'] }) }, reversibility_by: { param: P + 'mode', map: { safe: 'reversible', fast: 'rate_limited' } } };
const del4 = { verb: 'files.touch', kind: 'write', params: { [P + 'x']: prm('string', 'f.x', 'material') }, reversibility_by: { param: P + 'missing', map: { a: 'reversible' } } };
const readonly = { verb: 'docs.read', kind: 'read', params: { [P + 'id']: prm('string', 'doc.id', 'material') } };
const schemaFull = { verbs: [buy, view, send, del, del2, del3, del4, readonly] };
const pol = (verb: string, where: any[]) => ({ predicates: [{ verb, resource: '*', where }], caveats: [] });
const w = (field: string, op: string, value: any) => ({ field, op, value });
const optsets: any[] = [
  { schema: { verbs: [buy] } }, { schema: { verbs: [buy, view, send] } }, { schema: schemaFull }, { schema: schemaFull, verbs: ['shop.buy', 'mail.send'] }, { schema: schemaFull, verbs: ['nope', 'shop.buy'] }, { schema: schemaFull, verbs: [] },
  { schema: { verbs: [buy] }, slots: { verbs: ['shop.buy'], constraints: [{ verb: 'shop.buy', path: P + 'qty', max: 5 }] } }, { schema: { verbs: [buy] }, slots: { verbs: ['shop.view', 'files.delete'], constraints: [] } },
  { schema: { verbs: [buy] }, policies: [pol('shop.buy', [w(P + 'qty', 'lte', 3), w(P + 'currency', 'in', ['usd', 'gbp'])])] }, { schema: { verbs: [buy] }, policies: [pol('shop.buy', [w(P + 'qty', 'lte', 3), w(P + 'size', 'prefix', 'xl')])] },
  { schema: { verbs: [buy] }, confirmed: { [P + 'qty']: [2, 40, 3.5], [P + 'currency']: ['gbp'], [P + 'gift']: [true, false], [P + 'tags']: [['b', 'a'], ['c']], [P + 'ids']: [[1, 2]], [P + 'day']: ['2026-01-02'], [P + 'tip']: [9], [P + 'note']: ['hi'] } },
  { schema: { verbs: [buy] }, domains: { [P + 'qty']: { lo: 0, hi: 50 } } }, { schema: { verbs: [buy] }, domains: { [P + 'qty']: { lo: -5, hi: 5 }, [P + 'tip']: { lo: 10, hi: 20 } }, confirmed: { [P + 'qty']: [-2, 3] } },
  { schema: { verbs: [buy, send] }, floor: { prefixes: ['party.'], exact: [] } }, { schema: { verbs: [buy, send] }, floor: { prefixes: [], exact: ['text.message'] } }, { schema: { verbs: [buy, send] }, floor: { prefixes: [] } }, { schema: { verbs: [buy, send] }, floor: {} },
  { schema: schemaFull, slots: { verbs: ['mail.send'], constraints: [{ path: P + 'to', oneOf: ['a@x.com'] }] }, policies: [pol('mail.send', [w(P + 'to', 'prefix', 'team-')])] },
  { schema: { verbs: [{ ...buy, params: { [P + 'qty']: prm('integer', 'count.items', 'material') } }] }, confirmed: { [P + 'qty']: [1000] } }, { schema: { verbs: [{ ...buy, params: { [P + 'qty']: prm('integer', 'count.items', 'material', { min: 5, max: 9 }) } }] } },
  { schema: { verbs: [{ ...buy, params: { [P + 'qty']: prm('integer', 'count.items', 'material', { min: -3, max: 3 }) } }] }, confirmed: { [P + 'qty']: [0] } }, { schema: { verbs: [] } },
];
for (const op of optsets) await run('deriveSchemaOmega', (x: any) => { const r = S.deriveOmegaFromSchema(x); return { omega: r.omega, overrides: r.overrides, defaults: r.defaults, canonOf: r.canonOf }; }, [op]);
const decls = Object.values(buy.params).concat(Object.values(send.params));
const xs: any[] = [true, false, null, 'x', 5, [1, 2], ['b', 'a'], [], ['é', 'e', 'z'], { a: 1 }, 1.5];
for (const d of decls) for (const x of (d.type === 'set' ? xs.filter((y) => Array.isArray(y) && y.every((z) => typeof z === 'string')) : xs)) await run('canonValue', S.canonValue, [d, x]);
for (const d of decls) for (const fl of [undefined, {}, { prefixes: ['party.'] }, { exact: ['count.items'] }, { prefixes: [], exact: [] }]) await run('effectiveSensitivity', INT.effectiveSensitivity, fl === undefined ? [d] : [d, fl]);
for (const v of schemaFull.verbs) await run('verbReversibility', INT.verbReversibility, [v]);
await run('verbReversibility', INT.verbReversibility, [{ verb: 'x', kind: 'write', params: {} }]);
await run('verbReversibility', INT.verbReversibility, [{ verb: 'x', kind: 'read', params: {} }]);
for (const fl of [undefined, { prefixes: ['party.'], exact: [] }, { prefixes: [] }]) await run('walletFloorOverrides', (vs: any[], f?: any) => INT.walletFloorOverrides({ verbs: vs }, f), fl === undefined ? [schemaFull.verbs] : [schemaFull.verbs, fl]);
refWrite(o, 'intent-schema');
