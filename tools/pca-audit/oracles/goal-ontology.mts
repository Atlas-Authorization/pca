// Oracle: @atlasauth/pca-goal ontology.ts (intent ontology: verb resolution, IR projection, well-formedness checker, template
// instantiation, slot typing, locale-aware amount parsing) over the five shipped ontologies plus one small hand-written ontology.
// PORTING (fn(args) -> native entry point, comparison rule; all compare by JSON value; ontologies/goals/slots are parsed-JSON maps):
//   ontologyDigest(o) -> GoalOntology.ontologyDigest
//   resolveVerb(o, word) -> GoalOntology.resolveVerb (undefined = null)
//   goalCcy(g) -> GoalOntology.goalCcy (undefined = null)
//   toIrOntology(o, opts{ccy?, rels?}) -> GoalOntology.toIrOntology(o, ccy, rels); ontologyForGoal(o, g, rels?) -> GoalOntology.ontologyForGoal
//   goalAnchors(g) -> GoalOntology.goalAnchors; checkOntology(o) -> GoalOntology.checkOntology (list of {code, where, msg})
//   instantiateTemplate(o, templateId, values, opts{principal, nl, sources?}) -> GoalOntology.instantiateTemplate (a throw requires a throw)
//   slotLits(o, slot, value) -> GoalOntology.slotLits (a list of values, or a reason string); parseHumanAmount(text, exponent, locale|null) ->
//   GoalOntology.parseHumanAmount; parseMoney(text, exponent, locale|null) -> GoalOntology.parseMoney
//   shippedOntology(name) -> GoalOntologies.ontology(name) (the embedded reference data); shippedCatalog(domain) -> GoalOntologies.selCatalog(domain)
import * as O0 from '../../../packages/pca-goal/src/ontology';
import * as OS0 from '../../../packages/pca-goal/src/ontologies/index';
import * as DSL0 from '../../../packages/pca-goal/src/ontologies/dsl';
import * as SEL0 from '../../../packages/pca-goal/src/selectors';
import { Oracle, refWrite, variants } from './lib.mjs';
const O: any = (O0 as any).default ?? O0;
const OS: any = (OS0 as any).default ?? OS0;
const D: any = (DSL0 as any).default ?? DSL0;
const SEL: any = (SEL0 as any).default ?? SEL0;
const ALL: Record<string, any> = OS.ALL_ONTOLOGIES;

const o = new Oracle('goal-ontology', 'tools/pca-audit/oracles/goal-ontology.mts', 'TS-reference oracle for pca-goal ontology.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), (x: any, ...r: any[]) => f(typeof x === 'string' && ALL[x] ? ALL[x] : x, ...r), args);
// a shipped ontology travels by name (the native test resolves it from the embedded data), the hand-written one inline
const R = (name: string, on: any): any => (name === 'mini' ? on : name);

const MINI: any = {
  id: 'mini', version: 1, domain: 'mini',
  types: [{ id: 'acct', id_prefix: 'acct_' }, { id: 'cust', id_prefix: 'cust_' }],
  units: { USD: { kind: 'money', exponent: 2 }, EUR: { kind: 'money', exponent: 2 }, count: { kind: 'count' } },
  relations: [{ id: 'accts_of', from: 'cust', to: 'acct' }],
  verbs: [
    { id: 'refund', effect: 'irreversible', resource_type: 'acct', params: { amount: { kind: 'money', ccys: ['USD', 'EUR'] }, reason: { kind: 'enum', values: ['dup', 'fraud'] } } },
    { id: 'read_acct', effect: 'read', resource_type: 'acct', params: {} },
    { id: 'send', effect: 'external_send', resource_type: 'acct', params: { to: { kind: 'text' }, n: { kind: 'count' } } },
  ],
  aliases: { reimburse: 'refund', look: 'read_acct' },
  templates: [{
    id: 'refund_small', title: 'Refund one account', phrases: ['refund', 'give back'],
    slots: [
      { name: 'acct', kind: 'id', of: 'acct', mandatory: true },
      { name: 'cap', kind: 'money', ccy: 'USD', mandatory: true, cue: ['up to'] },
      { name: 'max_refunds', kind: 'count', mandatory: false, default: { n: 3 }, max: 10 },
      { name: 'reason', kind: 'enum', values: ['dup', 'fraud'], mandatory: false, default: 'dup' },
    ],
    grants: [
      D.grant('read', 'read_acct', D.exact('acct')),
      D.grant('refund', 'refund', D.exact('acct'), D.and(D.cmp('lte', 'amount', 'cap'), D.cmp('eq', 'reason', 'reason'))),
    ],
    prohibits: D.ban('send'),
    bounds: [D.countCap('c', ['refund'], 0, 'max_refunds'), D.sumCap('s', ['refund'], 'amount', 'USD', 'cap')],
    example: { acct: 'acct_1', cap: { ccy: 'USD', minor: 5000 } },
  }, {
    id: 'many', title: 'Many accounts', phrases: ['all of'],
    slots: [{ name: 'accts', kind: 'id_list', of: 'acct', mandatory: true }, { name: 'who', kind: 'text_list', mandatory: false, default: ['a.example.com'] }],
    grants: [D.grant('rd', 'read_acct', { k: 'oneof', ids: ['$accts'] }), D.grant('sd', 'send', D.exact('accts'), D.inEnum('to', ['x']))],
    prohibits: [], bounds: [],
    example: { accts: ['acct_1', 'acct_2'] },
  }],
};
const ONTS: [string, any][] = [...Object.entries(ALL), ['mini', MINI]];

// ---- embedded data and digests
for (const [name, on] of Object.entries(ALL)) {
  await run('shippedOntology', () => ALL[name], [name]);
  await run('shippedCatalog', () => SEL.selCatalogOfDomain(name), [name]);
}
await run('shippedOntology', () => null, ['nope']);
await run('shippedCatalog', () => null, ['nope']);
for (const [name, on] of ONTS) await run('ontologyDigest', O.ontologyDigest, [R(name, on)]);

// ---- resolveVerb
for (const [name, on] of ONTS) {
  const words = [...on.verbs.map((v: any) => v.id), ...Object.keys(on.aliases), 'unknown', '', ' ', 'constructor', '__proto__', 'toString', 'REFUND'];
  for (const w of words.slice(0, 40)) for (const v of [w, ' ' + w + ' ', w.toUpperCase()]) await run('resolveVerb', (oo: any, x: string) => O.resolveVerb(oo, x) ?? null, [R(name, on), v]);
}

// ---- instantiateTemplate and the projections
const goals: any[] = [];
for (const [name, on] of ONTS) {
  for (const t of on.templates) {
    const opts = { principal: 'p1', nl: 'do ' + t.id, sources: ['src'] };
    const g: any = O.instantiateTemplate(on, t.id, t.example, opts);
    goals.push([name, on, g]);
    await run('instantiateTemplate', O.instantiateTemplate, [R(name, on), t.id, t.example, opts]);
    await run('instantiateTemplate', O.instantiateTemplate, [R(name, on), t.id, t.example, { principal: 'p1', nl: '' }]);
    await run('instantiateTemplate', O.instantiateTemplate, [R(name, on), t.id, {}, { principal: 'p1', nl: 'x' }]);
    for (const s of t.slots) {
      const without = { ...t.example }; delete without[s.name];
      await run('instantiateTemplate', O.instantiateTemplate, [R(name, on), t.id, without, { principal: 'p1', nl: 'x' }]);
      for (const bad of [null, 1, 'x', [], {}, { n: -1 }, { ccy: 'JPY', minor: 1 }, { minor: 1.5, ccy: 'USD' }, { n: 2 ** 53 }, { n: 999999 }]) {
        await run('instantiateTemplate', O.instantiateTemplate, [R(name, on), t.id, { ...t.example, [s.name]: bad }, { principal: 'p1', nl: 'x' }]);
      }
    }
  }
  await run('instantiateTemplate', O.instantiateTemplate, [R(name, on), 'nope', {}, { principal: 'p', nl: '' }]);
}
const mini1: any = O.instantiateTemplate(MINI, 'refund_small', { acct: 'acct_9', cap: { ccy: 'USD', minor: 123 }, max_refunds: { n: 2 }, reason: 'fraud' }, { principal: 'p', nl: 'n' });
goals.push(['mini', MINI, mini1]);
for (const [name, on, g] of goals) {
  await run('goalCcy', (x: any) => O.goalCcy(x) ?? null, [g]);
  await run('goalAnchors', O.goalAnchors, [g]);
  await run('toIrOntology', (oo: any, op: any) => O.toIrOntology(oo, op), [R(name, on), {}]);
  await run('ontologyForGoal', O.ontologyForGoal, [R(name, on), g]);
}
for (const [name, on] of ONTS) {
  for (const op of [{ ccy: 'EUR' }, { ccy: 'JPY' }, { ccy: 'XXX' }, { rels: [{ rel: 'r', anchor: 'a', members: ['m'] }] }, { ccy: 'EUR', rels: [] }]) await run('toIrOntology', O.toIrOntology, [R(name, on), op]);
}
{
  const g: any = { grants: [{ gid: 'g', verb: 'v', res: { k: 'all_of', parts: [{ k: 'related', rel: 'r2', anchor: 'z' }, { k: 'related', rel: 'r1', anchor: 'z' }, { k: 'related', rel: 'r1', anchor: 'a' }, { k: 'related', rel: 'r1', anchor: 'a' }] }, cond: { k: 'true' } }], prohibits: [{ pid: 'p', target: { k: 'verb', verb: 'v' }, res: { k: 'related', rel: 'r0', anchor: 'q' }, cond: { k: 'true' } }], bounds: [], escalateOn: [] };
  await run('goalAnchors', O.goalAnchors, [g]);
  const usd = { k: 'lit', v: { k: 'q', q: { u: { k: 'money', ccy: 'EUR' }, n: 5 } } };
  await run('goalCcy', (x: any) => O.goalCcy(x) ?? null, [{ grants: [{ gid: 'g', verb: 'v', res: { k: 'any', reason: 'r' }, cond: { k: 'cmp', op: 'in', l: { k: 'lit', v: { k: 's', s: 'x' } }, r: { k: 'lit', v: { k: 'set', items: [{ k: 's', s: 'a' }, usd.v] } } } }], prohibits: [], bounds: [], escalateOn: [] }]);
  await run('goalCcy', (x: any) => O.goalCcy(x) ?? null, [{ grants: [], prohibits: [], escalateOn: [{ k: 'not', c: { k: 'cmp', op: 'lte', l: usd, r: usd } }], bounds: [] }]);
  await run('goalCcy', (x: any) => O.goalCcy(x) ?? null, [{ grants: [], prohibits: [], escalateOn: [], bounds: [{ cap: { u: { k: 'money', ccy: 'GBP' }, n: 1 } }, { cap: { u: { k: 'money', ccy: 'USD' }, n: 1 } }] }]);
  await run('goalCcy', (x: any) => O.goalCcy(x) ?? null, [{ grants: [], prohibits: [], escalateOn: [], bounds: [{ cap: { u: { k: 'count' }, n: 1 } }] }]);
}

// ---- the checker: shipped, hand-written, mutated
for (const [name, on] of ONTS) await run('checkOntology', O.checkOntology, [R(name, on)]);
{
  const bad = (f: (c: any) => void) => { const c = JSON.parse(JSON.stringify(MINI)); f(c); return c; };
  const defects: any[] = [
    bad((c) => { c.types.push({ id: 'acct', id_prefix: 'zz_' }); }), bad((c) => { c.types.push({ id: 'z', id_prefix: 'acct_' }); }), bad((c) => { c.types.push({ id: 'z', id_prefix: '' }); }),
    bad((c) => { c.units.USD.exponent = 5; }), bad((c) => { c.units.USD.exponent = 1.5; }), bad((c) => { c.units.count.exponent = 2; }), bad((c) => { delete c.units.USD.exponent; }),
    bad((c) => { c.relations.push({ id: 'accts_of', from: 'cust', to: 'acct' }); }), bad((c) => { c.relations[0].from = 'nope'; }),
    bad((c) => { c.verbs.push(c.verbs[0]); }), bad((c) => { c.verbs[0].effect = 'bogus'; }), bad((c) => { c.verbs[0].resource_type = 'nope'; }),
    bad((c) => { c.verbs[0].params.amount.ccys = []; }), bad((c) => { c.verbs[0].params.amount.ccys = ['XXX']; }), bad((c) => { c.verbs[0].params.reason.values = []; }),
    bad((c) => { c.verbs[2].params.n = { kind: 'ratio' }; }), bad((c) => { c.verbs[0].params.x = { kind: 'id', of: 'nope' }; }), bad((c) => { c.verbs[0].params.x = { kind: 'id', of: 'acct' }; }),
    bad((c) => { c.aliases.Reimburse = 'refund'; }), bad((c) => { c.aliases['a​b'] = 'refund'; }), bad((c) => { c.aliases['Ａ'] = 'refund'; }), bad((c) => { c.aliases.zz = 'nope'; }),
    bad((c) => { c.aliases.zz = 'reimburse'; }), bad((c) => { c.aliases.refund = 'read_acct'; }), bad((c) => { c.aliases.read_acct = 'read_acct'; }),
    bad((c) => { c.templates.push(c.templates[0]); }), bad((c) => { c.templates[0].slots.push(c.templates[0].slots[0]); }), bad((c) => { c.templates[0].slots[0].of = 'nope'; }),
    bad((c) => { c.templates[0].slots[1].ccy = 'XXX'; }), bad((c) => { c.templates[0].slots[3].values = []; }), bad((c) => { delete c.templates[0].slots[2].default; }),
    bad((c) => { c.templates[0].slots.push({ name: 'unused', kind: 'count', mandatory: true }); }), bad((c) => { c.templates[0].grants = []; }),
    bad((c) => { c.templates[0].grants[0].verb = 'nope'; }), bad((c) => { c.templates[0].grants[0].res = { k: 'any', reason: 'x' }; }), bad((c) => { c.templates[0].grants[0].res = { k: 'exact', id: 'cust_1' }; }),
    bad((c) => { c.templates[0].grants[0].res = { k: 'oneof', ids: [] }; }), bad((c) => { c.templates[0].grants[0].res = { k: 'related', rel: 'nope', anchor: '$acct' }; }),
    bad((c) => { c.templates[0].grants[0].res = { k: 'related', rel: 'accts_of', anchor: 'acct_1' }; }), bad((c) => { c.templates[0].grants[0].res = { k: 'all_of', parts: [{ k: 'exact', id: '$acct' }] }; }),
    bad((c) => { c.templates[0].grants[1].cond = D.cmp('lte', 'nope', 'cap'); }), bad((c) => { c.templates[0].grants[1].cond = D.cmp('lte', 'reason', 'reason'); }),
    bad((c) => { c.templates[0].grants[1].cond = D.cmp('lte', 'amount', 'acct'); }), bad((c) => { c.templates[0].grants[1].cond = D.cmp('in', 'amount', 'cap'); }),
    bad((c) => { c.templates[0].grants[1].cond = D.inEnum('amount', ['a']); }), bad((c) => { c.templates[0].grants[1].cond = D.cmpEnum('eq', 'reason', 'zz'); }),
    bad((c) => { c.templates[0].grants[1].cond = { k: 'cmp', op: 'eq', l: { k: 'param', path: 'amount' }, r: { k: 'lit', v: { k: 'q', q: { u: { k: 'money', ccy: 'GBP' }, n: 1 } } } }; }),
    bad((c) => { c.templates[0].prohibits.push({ pid: 'x', target: { k: 'verb', verb: 'nope' }, res: { k: 'any', reason: 'r' }, cond: { k: 'true' } }); }),
    bad((c) => { c.templates[0].prohibits.push({ pid: 'x', target: { k: 'effect', cls: 'nope' }, res: { k: 'any', reason: 'r' }, cond: { k: 'true' } }); }),
    bad((c) => { c.templates[0].bounds[0].over = ['nope']; }), bad((c) => { c.templates[0].bounds[0].cap_slot = 'nope'; }), bad((c) => { c.templates[0].bounds[0].cap_slot = 'cap'; }),
    bad((c) => { c.templates[0].bounds[1].cap_slot = 'max_refunds'; }), bad((c) => { delete c.templates[0].bounds[1].param; }),
  ];
  for (const d of defects) await run('checkOntology', O.checkOntology, [d]);
  const small = { id: 'm', version: 1, domain: 'd', types: MINI.types, units: MINI.units, relations: MINI.relations, verbs: MINI.verbs, aliases: {}, templates: [] };
  let i = 0;
  for (const [label, v] of variants(small, { maxPaths: 40 })) if (i++ % 3 === 0) await run('checkOntology', O.checkOntology, [v]);
}

// ---- slot typing
for (const [name, on] of ONTS) {
  const slots = on.templates.flatMap((t: any) => t.slots).filter((s: any, i: number) => i < 60);
  const seen = new Set<string>();
  for (const s of slots) {
    const key = JSON.stringify(s);
    if (seen.has(key)) continue;
    seen.add(key);
    const goodByKind: any = { money: [{ ccy: s.ccy, minor: 100 }], count: [{ n: 2 }, { n: 0 }], duration: [{ ms: 5 }], instant: [{ epoch_ms: 5 }], id: [], id_list: [], enum: s.values ?? [], enum_list: s.values ? [s.values] : [], text_list: [['a.example.com'], ['é.com'], ['x​.com']] };
    const pre = on.types.find((t: any) => t.id === s.of)?.id_prefix;
    if (pre) { goodByKind.id = [pre + 'abc', pre, pre + 'a b', pre + 'é']; goodByKind.id_list = [[pre + 'a', pre + 'b'], [pre + 'a', 'zz'], []]; }
    const vals = [undefined, null, 1, 'x', [], {}, { n: -1 }, { n: 1.5 }, { n: 2 ** 53 }, { n: 11 }, { n: 100000 }, { minor: -1, ccy: s.ccy }, { minor: 1, ccy: 'JPY' }, { epoch_ms: -5 }, ...(goodByKind[s.kind] ?? [])];
    for (const v of vals) await run('slotLits', (oo: any, ss: any, vv: any) => O.slotLits(oo, ss, vv ?? undefined), [R(name, on), s, v ?? null]);
  }
}

// ---- amounts
const TEXTS = ['1', '20', '20.5', '20.50', '0.5', '1,000', '1.000', '1,000.50', '1.000,50', '1,000,000', '1.000.000', '1,00', '1.00', '1,5', '12,34', '1,2345', '1,000,00', '1.0,00', '', ' ', 'abc', '$20', '€ 20', '20 dollars', '1..0', '1,,0', '.5', ',5', '5.', '5,', '0,000', '999,999,999,999,999', '9007199254740991', '9007199254740992', '90071992547409.91', '٣', '１２３', '1 000', '١٢', '1 000,50', '123,456.78', '123.456,78', '12,345.678', '1,23,456'];
for (const t of TEXTS) for (const e of [0, 2, 3]) for (const loc of [undefined, 'en', 'de']) {
  await run('parseHumanAmount', (a: string, b: number, c: any) => O.parseHumanAmount(a, b, c ?? undefined), [t, e, loc ?? null]);
}
for (const t of TEXTS.concat(['$1,000', '£20', '€1.000,50', '$ 5', '$$5', '€€5', ' $5 ', ' 5'])) for (const e of [0, 2]) for (const loc of [null, 'en', 'de']) await run('parseMoney', O.parseMoney, [t, e, loc]);
refWrite(o, 'goal-ontology');
