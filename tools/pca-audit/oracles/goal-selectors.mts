// Oracle: @atlasauth/pca-goal selectors.ts (trait selectors and role-addressed parameters: catalog, class verbs, role resolution,
// expansion to an ordinary Goal, selector typing, role params, the selector card, the carrier form, the catalog tape).
// A hand-written catalog (CAT) and IR ontology (IRONT) carry confirmed verbs; the shipped domain catalogs (every verb unconfirmed) ride by NAME.
// PORTING (fn(args) -> native entry point, comparison rule; all compare by JSON value):
//   selCatalogDigest(cat) / selGoalDigest(sg) -> GoalSelectors.*; classVerbs/allowClassVerbs/floatClassVerbs(cat, allOf, noneOf) -> GoalSelectors.*
//   resolveRole(ont, cat, verb, role) -> GoalSelectors.resolveRole (undefined = null)
//   expandSelGoal(sg, ont, cat) / selReasons(sg, ont, cat) -> GoalSelectors.*; compileSelGoal(sg, ont, cat) -> GoalSelectors.compileSelGoal with a throwing compiler
//   (only inputs whose selector reasons are non-empty: the proved compiler is not carried natively)
//   withRoleParams(act, cat) -> GoalSelectors.withRoleParams; renderSelCard(sg, ont, cat) -> GoalSelectors.renderSelCard(..., null /*core registry*/)
//   selCarrier(sg) -> GoalSelectors.selCarrier; encodeSelCatalog(cat) -> GoalSelectors.encodeSelCatalog (a tape of [tag, value] tokens)
//   traitClosure(ids) -> GoalSelectors.traitClosure(ids, null)
//   catalogOfDomain(name) -> GoalSelectors.selCatalogOfDomain; catalogOfDefs(defs) -> GoalSelectors.selCatalogOfDefs(defs, null, null)
//   domainOnt(name) / domainCat(name): a string first argument that is a shipped domain stands for GoalOntology.toIrOntology(GoalOntologies.ontology(name), null, null) (ont position)
//   or GoalOntologies.selCatalog(name) (cat position)
import * as SEL0 from '../../../packages/pca-goal/src/selectors';
import * as OS0 from '../../../packages/pca-goal/src/ontologies/index';
import * as O0 from '../../../packages/pca-goal/src/ontology';
import * as A0 from '../../../packages/pca-actions/src/index';
import { Oracle, refWrite } from './lib.mjs';
const S: any = (SEL0 as any).default ?? SEL0;
const OS: any = (OS0 as any).default ?? OS0;
const O: any = (O0 as any).default ?? O0;
const A: any = (A0 as any).default ?? A0;
const o = new Oracle('goal-selectors', 'tools/pca-audit/oracles/goal-selectors.mts', 'TS-reference oracle for pca-goal selectors.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);
const clone = (x: any) => JSON.parse(JSON.stringify(x));

const MM = 'pca.money_moving', IRR = 'pca.irreversible', EXT = 'pca.external_communication', UNR = 'pca.unreviewed';
const CAT: any = {
  known: [EXT, IRR, MM, UNR],
  verbs: [
    { verb: 'note', traits: [EXT], roles: {} },
    { verb: 'pay', traits: [IRR, MM], roles: { 'money.amount': ['amount'] } },
    { verb: 'refund', traits: [MM], roles: { 'money.amount': ['amount'] } },
    { verb: 'shady', traits: [MM, UNR], roles: { 'money.amount': ['amt'] } },
    { verb: 'tally', traits: [EXT], roles: { 'money.amount': ['qty'] } },
    { verb: 'wire', traits: [IRR, MM], roles: { 'money.amount': ['fee', 'total'] } },
  ],
};
const USD = { k: 'q', u: { k: 'money', ccy: 'USD' } };
const IRONT: any = {
  verbs: [
    { verb: 'note', cls: 'external_send', params: [] },
    { verb: 'pay', cls: 'irreversible', params: [{ path: 'amount', ty: USD }] },
    { verb: 'refund', cls: 'irreversible', params: [{ path: 'amount', ty: USD }] },
    { verb: 'shady', cls: 'irreversible', params: [{ path: 'amt', ty: USD }] },
    { verb: 'tally', cls: 'read', params: [{ path: 'qty', ty: { k: 'q', u: { k: 'count' } } }] },
    { verb: 'wire', cls: 'irreversible', params: [{ path: 'fee', ty: USD }, { path: 'total', ty: USD }] },
  ], rels: [],
};
const DOMS = ['payments', 'email', 'calendar_travel', 'code_repos', 'data_access'];
const domOnt = (name: string) => O.toIrOntology(OS.ALL_ONTOLOGIES[name]);
const resolveOnt = (x: any) => (typeof x === 'string' && OS.ALL_ONTOLOGIES[x] ? domOnt(x) : x);
const resolveCat = (x: any) => (typeof x === 'string' && OS.ALL_ONTOLOGIES[x] ? S.selCatalogOfDomain(x) : x);

const role = (r: string) => ({ k: 'role', role: r });
const lit = (n: number, u: any = { k: 'money', ccy: 'USD' }) => ({ k: 'lit', v: { k: 'q', q: { u, n } } });
const cmpX = (op: string, l: any, r: any) => ({ k: 'cmp', op, l, r });
const roleCap = cmpX('lte', role('money.amount'), lit(100));
const base = (over: any = {}): any => ({
  v: 2, principal: 'p', ontDigest: 'o', catDigest: S.selCatalogDigest(CAT), nlDigest: 'n', sources: [],
  grants: [
    { gid: 'gA', sel: { k: 'class', all_of: [MM], none_of: [] }, res: { k: 'any', reason: 'r' }, cond: roleCap },
    { gid: 'gB', sel: { k: 'verb', verb: 'note' }, res: { k: 'exact', id: 'x' }, cond: { k: 'true' } },
  ],
  prohibits: [
    { pid: 'pT', target: { k: 'trait', all_of: [IRR], none_of: [EXT] }, res: { k: 'any', reason: 'n' }, cond: cmpX('gt', role('money.amount'), lit(5)) },
    { pid: 'pV', target: { k: 'verb', verb: 'wire' }, res: { k: 'any', reason: 'n' }, cond: { k: 'true' } },
    { pid: 'pE', target: { k: 'effect', cls: 'external_send' }, res: { k: 'exact', id: 'z' }, cond: { k: 'true' } },
  ],
  bounds: [
    { bid: 'bT', sel: { k: 'trait', all_of: [MM], none_of: [] }, agg: 'sum', value: role('money.amount'), key: '', window: { k: 'lifetime' }, scope: { k: 'session' }, cap: { u: { k: 'money', ccy: 'USD' }, n: 500 }, onExceed: 'deny' },
    { bid: 'bG', sel: { k: 'gids', gids: ['gA'] }, agg: 'count', value: lit(1, { k: 'count' }), key: '', window: { k: 'task' }, scope: { k: 'org' }, cap: { u: { k: 'count' }, n: 3 }, onExceed: 'escalate' },
    { bid: 'bE', sel: { k: 'effect', cls: 'irreversible' }, agg: 'max', value: { k: 'param', path: 'amount', ty: USD }, key: '', window: { k: 'lifetime' }, scope: { k: 'principal' }, cap: { u: { k: 'money', ccy: 'USD' }, n: 90 }, onExceed: 'deny' },
  ],
  validity: { notBefore: 0, notAfter: 100, maxIdle: 0 }, deleg: { maxDepth: 1, narrowOnly: true, mayTouch: ['gA', 'gB'] }, escalateOn: [], wildcardAck: ['gA'],
  holes: [{ hid: 'h', q: 'q', domain: [], affects: ['gA'], global: false }],
  ...over,
});
const G0 = base();
const mut = (f: (g: any) => void) => { const g = clone(G0); f(g); return g; };
const GOALS: any[] = [
  G0,
  mut((g) => { g.grants[0].sel = { k: 'class', all_of: [IRR], none_of: [] }; }),
  mut((g) => { g.grants[0].sel = { k: 'class', all_of: [EXT], none_of: [] }; g.grants[0].cond = { k: 'true' }; }),
  mut((g) => { g.grants[0].sel = { k: 'class', all_of: [UNR], none_of: [] }; }),
  mut((g) => { g.grants[0].sel = { k: 'class', all_of: ['pca.nope'], none_of: [] }; }),
  mut((g) => { g.grants[0].sel = { k: 'class', all_of: [], none_of: [] }; }),
  mut((g) => { g.grants[0].sel = { k: 'class', all_of: [MM], none_of: [IRR] }; }),
  mut((g) => { g.grants[0].sel = { k: 'class', all_of: [MM, IRR], none_of: [] }; }),
  mut((g) => { g.grants[0].sel = { k: 'class', all_of: [''], none_of: [] }; }),
  mut((g) => { g.grants[0].cond = { k: 'and', a: roleCap, b: { k: 'not', c: cmpX('gte', role('money.amount'), lit(1)) } }; }),
  mut((g) => { g.grants[0].cond = { k: 'or', a: roleCap, b: cmpX('eq', role('no.such'), lit(1)) }; }),
  mut((g) => { g.grants[0].cond = cmpX('lte', { k: 'param', path: 'amount', ty: USD }, { k: 'hist', bid: 'bT', u: { k: 'money', ccy: 'USD' } }); }),
  mut((g) => { g.grants[1].sel = { k: 'verb', verb: 'pay' }; g.grants[1].cond = roleCap; }),
  mut((g) => { g.grants[1].sel = { k: 'verb', verb: 'wire' }; g.grants[1].cond = roleCap; }),
  mut((g) => { g.prohibits[0].target = { k: 'trait', all_of: [], none_of: [] }; }),
  mut((g) => { g.prohibits[0].target = { k: 'trait', all_of: [MM], none_of: [MM] }; }),
  mut((g) => { g.prohibits[0].target = { k: 'trait', all_of: ['nope'], none_of: [] }; }),
  mut((g) => { g.prohibits[0].target = { k: 'trait', all_of: [EXT], none_of: [] }; g.prohibits[0].cond = { k: 'true' }; }),
  mut((g) => { g.prohibits[1].cond = roleCap; }),
  mut((g) => { g.prohibits[2].target = { k: 'effect', cls: 'irreversible' }; g.prohibits[2].cond = roleCap; }),
  mut((g) => { g.bounds[0].sel = { k: 'trait', all_of: [IRR], none_of: [] }; }),
  mut((g) => { g.bounds[0].sel = { k: 'trait', all_of: [EXT], none_of: [] }; }),
  mut((g) => { g.bounds[0].sel = { k: 'trait', all_of: [EXT], none_of: [] }; g.bounds[0].value = role('money.amount'); }),
  mut((g) => { g.bounds[0].sel = { k: 'trait', all_of: ['nope'], none_of: [] }; }),
  mut((g) => { g.bounds[0].sel = { k: 'effect', cls: 'irreversible' }; }),
  mut((g) => { g.bounds[0].sel = { k: 'effect', cls: 'read' }; }),
  mut((g) => { g.bounds[0].sel = { k: 'effect', cls: 'nope' }; }),
  mut((g) => { g.bounds[0].sel = { k: 'gids', gids: ['gA', 'gB'] }; }),
  mut((g) => { g.bounds[0].sel = { k: 'gids', gids: ['nope'] }; }),
  mut((g) => { g.bounds[1].sel = { k: 'gids', gids: ['gB'] }; }),
  mut((g) => { g.bounds[0].value = role('no.such'); }),
  mut((g) => { g.bounds[0].value = lit(1); }),
  mut((g) => { g.bounds[0].value = { k: 'hist', bid: 'bG', u: { k: 'count' } }; }),
  mut((g) => { g.grants[0].sel = { k: 'class', all_of: [MM], none_of: [] }; g.grants.push({ gid: 'gC', sel: { k: 'verb', verb: 'tally' }, res: { k: 'any', reason: 'r' }, cond: { k: 'true' } }); g.bounds[0].sel = { k: 'gids', gids: ['gA', 'gC'] }; }),
  mut((g) => { g.grants.push({ gid: 'gC', sel: { k: 'verb', verb: 'shady' }, res: { k: 'any', reason: 'r' }, cond: { k: 'true' } }); g.bounds[1].sel = { k: 'gids', gids: ['gC', 'gA'] }; g.bounds[1].value = role('money.amount'); g.bounds[1].agg = 'sum'; g.bounds[1].cap = { u: { k: 'money', ccy: 'USD' }, n: 7 }; }),
  mut((g) => { g.grants.push({ gid: 'gC', sel: { k: 'verb', verb: 'tally' }, res: { k: 'any', reason: 'r' }, cond: { k: 'true' } }); g.bounds[1].sel = { k: 'gids', gids: ['gC', 'gA'] }; g.bounds[1].value = role('money.amount'); }),
  mut((g) => { g.grants[0].gid = 'a.b'; }), mut((g) => { g.grants[0].gid = ''; }), mut((g) => { g.prohibits[0].pid = 'p'.repeat(65); }), mut((g) => { g.bounds[0].bid = 'b-1'; }),
  mut((g) => { g.catDigest = 'x'; }),
  mut((g) => { g.deleg.mayTouch = ['gB', 'zzz']; g.wildcardAck = ['gB']; g.holes[0].affects = ['gB', 'gA']; }),
  mut((g) => { g.grants = []; g.prohibits = []; g.bounds = []; g.holes = []; }),
];
const CATS: any[] = [CAT, { ...CAT, known: CAT.known.slice(0, 2) }, { known: CAT.known, verbs: [...CAT.verbs, { verb: 'ghost', traits: [MM], roles: {} }] }, { known: [], verbs: [] }];

for (const c of CATS) {
  await run('selCatalogDigest', S.selCatalogDigest, [c]);
  await run('encodeSelCatalog', S.encodeSelCatalog, [c]);
}
for (const d of DOMS) {
  await run('catalogOfDomain', (x: string) => S.selCatalogOfDomain(x), [d]);
  await run('selCatalogDigest', (x: any) => S.selCatalogDigest(resolveCat(x)), [d]);
  await run('encodeSelCatalog', (x: any) => S.encodeSelCatalog(resolveCat(x)), [d]);
}
const TR: [string[], string[]][] = [[[MM], []], [[IRR], [EXT]], [[], []], [[UNR], []], [[MM], [IRR]], [[EXT], [MM]], [['x'], []], [[MM, IRR], [UNR]], [[], [MM]]];
for (const [a, b] of TR) for (const fn of ['classVerbs', 'allowClassVerbs', 'floatClassVerbs']) await run(fn, (x: any, aa: string[], bb: string[]) => S[fn](resolveCat(x), aa, bb), [CAT, a, b]);
for (const d of DOMS) for (const fn of ['classVerbs', 'allowClassVerbs', 'floatClassVerbs']) await run(fn, (x: any, aa: string[], bb: string[]) => S[fn](resolveCat(x), aa, bb), [d, [MM], []]);
for (const v of ['note', 'pay', 'refund', 'shady', 'tally', 'wire', 'ghost', '']) for (const r of ['money.amount', 'no.such', 'constructor', '']) {
  await run('resolveRole', (on: any, c: any, vv: string, rr: string) => S.resolveRole(on, c, vv, rr) ?? null, [IRONT, CAT, v, r]);
}
const GOALS_NAMES = GOALS;
for (const g of GOALS_NAMES) {
  await run('selGoalDigest', S.selGoalDigest, [g]);
  await run('selReasons', (sg: any, on: any, c: any) => S.selReasons(sg, on, c), [g, IRONT, CAT]);
  await run('expandSelGoal', (sg: any, on: any, c: any) => S.expandSelGoal(sg, on, c), [g, IRONT, CAT]);
  await run('selCarrier', S.selCarrier, [g]);
  await run('renderSelCard', (sg: any, on: any, c: any) => S.renderSelCard(sg, on, c), [g, IRONT, CAT]);
  if (S.selReasons(g, IRONT, CAT).length > 0) await run('compileSelGoal', (sg: any, on: any, c: any) => S.compileSelGoal(sg, on, c), [g, IRONT, CAT]);
}
// shipped domain catalogs and ontologies: every verb unconfirmed (maximally dangerous)
for (const d of DOMS) {
  const cat = S.selCatalogOfDomain(d); const ont = domOnt(d);
  const first = cat.verbs[0].verb;
  const sg = base({ catDigest: S.selCatalogDigest(cat), grants: [{ gid: 'gA', sel: { k: 'class', all_of: [MM], none_of: [] }, res: { k: 'any', reason: 'r' }, cond: { k: 'true' } }, { gid: 'gB', sel: { k: 'verb', verb: first }, res: { k: 'any', reason: 'r' }, cond: { k: 'true' } }],
    prohibits: [{ pid: 'pT', target: { k: 'trait', all_of: [EXT], none_of: [] }, res: { k: 'any', reason: 'n' }, cond: { k: 'true' } }], bounds: [{ bid: 'bT', sel: { k: 'trait', all_of: [MM], none_of: [] }, agg: 'count', value: lit(1, { k: 'count' }), key: '', window: { k: 'lifetime' }, scope: { k: 'session' }, cap: { u: { k: 'count' }, n: 5 }, onExceed: 'deny' }], deleg: { maxDepth: 0, narrowOnly: true, mayTouch: ['gB'] }, wildcardAck: ['gB'], holes: [] });
  for (const fn of ['selReasons', 'expandSelGoal', 'renderSelCard']) await run(fn, (sgx: any, onx: any, cx: any) => S[fn](sgx, resolveOnt(onx), resolveCat(cx)), [sg, d, d]);
}
const acts = [{ verb: 'pay', res: 'r', params: { amount: { k: 'q', q: { u: { k: 'money', ccy: 'USD' }, n: 5 } } } }, { verb: 'wire', res: 'r', params: { fee: 1, total: 2 } }, { verb: 'tally', res: 'r', params: { qty: 3, '@money.amount': 9 } },
  { verb: 'ghost', res: 'r', params: { '@x': 1, y: 2 } }, { verb: 'pay', res: 'r', params: { '@money.amount': 'forged' } }, { verb: 'pay', res: 'r', params: {} }, { verb: 'note', res: 'r', params: { a: 1 } }, { verb: 'shady', res: 'r', params: { amt: 4 } }, { verb: 'pay', res: 'r', params: { amount: 1, extra: 2 }, t: 5 }];
for (const a of acts) await run('withRoleParams', S.withRoleParams, [a, CAT]);
for (const ids of [[IRR], [MM, EXT], [UNR], [], ['x'], [IRR, 'nope']]) await run('traitClosure', (x: string[]) => S.traitClosure(x), [ids]);
const DEFS = (A.CORE_PACK_DEFS as any[]).slice(0, 6).map((d) => JSON.parse(JSON.stringify(d)));
await run('catalogOfDefs', (d: any) => S.selCatalogOfDefs(d), [DEFS]);
await run('catalogOfDefs', (d: any) => S.selCatalogOfDefs(d), [DEFS.slice(0, 2)]);
await run('catalogOfDefs', (d: any) => S.selCatalogOfDefs(d), [[]]);
(o as any).constantByDesign = { compileSelGoal: 'only inputs whose selector reasons are non-empty: the proved compiler is not carried natively' };
refWrite(o, 'goal-selectors');
