// Oracle: @atlasauth/pca-goal selectors.ts (trait selectors and role-addressed parameters), over the five shipped domain catalogs.
// PORTING (fn(args) -> native entry point, compare by JSON value; the catalog and ontology of a shipped domain travel by NAME and the native
// test resolves them from the shipped data):
//   selCatalogOfDomain(domain) -> goal_selectors.sel_catalog_of_domain; selCatalogDigest(cat); selGoalDigest(sg); classVerbs / allowClassVerbs /
//   floatClassVerbs(cat, all, none); resolveRole(ontDomain, cat, verb, role) with the IR ontology of the domain (toIrOntology(shipped));
//   expandSelGoal(sg, ont, cat); selReasons(sg, ont, cat); withRoleParams(act, cat); selCarrier(sg); encodeSelCatalog(cat); renderSelCard(sg, ont, cat);
//   traitClosure(ids).
// The proved-compiler entry point compileSelGoal needs the verified core and is not ported.
import * as SEL0 from '../../../packages/pca-goal/src/selectors';
import * as O0 from '../../../packages/pca-goal/src/ontology';
import * as OS0 from '../../../packages/pca-goal/src/ontologies/index';
import { Oracle, refWrite } from './lib.mjs';
const SEL: any = (SEL0 as any).default ?? SEL0;
const O: any = (O0 as any).default ?? O0;
const OS: any = (OS0 as any).default ?? OS0;
const ALL: Record<string, any> = OS.ALL_ONTOLOGIES;
const o = new Oracle('goal-selectors-py', 'tools/pca-audit/oracles/goal-selectors-py.mts', 'TS-reference oracle for pca-goal selectors.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);

const USD = { k: 'money', ccy: 'USD' };
const lit = (v: number) => ({ k: 'lit', v: { k: 'q', q: { u: USD, n: v } } });
const cmp = (op: string, l: any, r: any) => ({ k: 'cmp', op, l, r });
const role = (r: string) => ({ k: 'role', role: r });
const names = Object.keys(ALL).sort();
for (const d of names) await run('selCatalogOfDomain', SEL.selCatalogOfDomain, [d]);
for (const d of names) {
  const cat = SEL.selCatalogOfDomain(d);
  const ont = O.toIrOntology(ALL[d]);
  const traits: string[] = [...new Set(cat.verbs.flatMap((v: any) => v.traits))] as string[];
  const roles: string[] = [...new Set(cat.verbs.flatMap((v: any) => Object.keys(v.roles)))] as string[];
  const verbs: string[] = cat.verbs.map((v: any) => v.verb);
  await run('selCatalogDigest', SEL.selCatalogDigest, [cat]);
  const picks = [[], traits.slice(0, 1), traits.slice(1, 3), traits.slice(0, 4), ['pca.unreviewed'], ['nope']];
  for (const a of picks) for (const b of [[], traits.slice(2, 3), ['pca.unreviewed']]) {
    await run('classVerbs', SEL.classVerbs, [cat, a, b]);
    await run('allowClassVerbs', SEL.allowClassVerbs, [cat, a, b]);
    await run('floatClassVerbs', SEL.floatClassVerbs, [cat, a, b]);
  }
  for (const v of verbs.slice(0, 6)) for (const r of [...roles, 'nope']) await run('resolveRole', (dom: string, c: any, vv: string, rr: string) => SEL.resolveRole(O.toIrOntology(ALL[dom]), c, vv, rr) ?? null, [d, cat, v, r]);
  const base = (over: any) => ({ v: 2, principal: 'p', ontDigest: 'o', catDigest: SEL.selCatalogDigest(cat), nlDigest: 'n', sources: [], grants: [], prohibits: [], bounds: [], validity: { notBefore: 0, notAfter: 100000, maxIdle: 0 }, deleg: { maxDepth: 1, narrowOnly: true, mayTouch: ['gc'] }, escalateOn: [], wildcardAck: ['gc'], holes: [{ hid: 'h', q: 'q', domain: [], affects: ['gc'], global: false }], ...over });
  const money = roles.find((r) => r.startsWith('money')) ?? roles[0];
  const goals: any[] = [];
  const classG = (all: string[], none: string[], cond: any = { k: 'true' }, gid = 'gc') => ({ gid, sel: { k: 'class', all_of: all, none_of: none }, res: { k: 'any', reason: 'r' }, cond });
  for (const t of traits.slice(0, 5)) {
    goals.push(base({ grants: [classG([t], [])] }));
    if (money) goals.push(base({ grants: [classG([t], [], cmp('lte', role(money), lit(500)))], prohibits: [{ pid: 'pt', target: { k: 'trait', all_of: [t], none_of: [] }, res: { k: 'any', reason: 'r' }, cond: cmp('gte', role(money), lit(1)) }], bounds: [{ bid: 'bs', sel: { k: 'gids', gids: ['gc'] }, agg: 'sum', value: role(money), key: '', window: { k: 'lifetime' }, scope: { k: 'session' }, cap: { u: USD, n: 1000 }, onExceed: 'deny' }, { bid: 'bt', sel: { k: 'trait', all_of: [t], none_of: [] }, agg: 'sum', value: role(money), key: '', window: { k: 'lifetime' }, scope: { k: 'org' }, cap: { u: USD, n: 5000 }, onExceed: 'escalate' }] }));
  }
  goals.push(base({ grants: [classG(['nope'], [])] }), base({ grants: [classG([], [])] }), base({ grants: [classG([traits[0]!], [traits[1]!])] }), base({ catDigest: 'stale' }), base({ grants: [{ gid: 'bad id!', sel: { k: 'verb', verb: verbs[0] }, res: { k: 'any', reason: 'r' }, cond: { k: 'true' } }] }));
  goals.push(base({ grants: [{ gid: 'gv', sel: { k: 'verb', verb: verbs[0] }, res: { k: 'any', reason: 'r' }, cond: { k: 'true' } }], prohibits: [{ pid: 'pv', target: { k: 'verb', verb: verbs[1] }, res: { k: 'any', reason: 'r' }, cond: { k: 'true' } }, { pid: 'pe', target: { k: 'effect', cls: 'irreversible' }, res: { k: 'any', reason: 'r' }, cond: { k: 'true' } }], bounds: [{ bid: 'be', sel: { k: 'effect', cls: 'read' }, agg: 'count', value: lit(1), key: '', window: { k: 'task' }, scope: { k: 'org' }, cap: { u: { k: 'count' }, n: 3 }, onExceed: 'deny' }, { bid: 'bg', sel: { k: 'gids', gids: ['zz'] }, agg: 'count', value: lit(1), key: '', window: { k: 'task' }, scope: { k: 'org' }, cap: { u: { k: 'count' }, n: 3 }, onExceed: 'deny' }], wildcardAck: [], holes: [] }));
  goals.push(base({ grants: [classG([traits[0]!], [], cmp('lte', role('nope.role'), lit(1)))], prohibits: [{ pid: 'pt', target: { k: 'trait', all_of: [traits[0]!], none_of: [] }, res: { k: 'any', reason: 'r' }, cond: cmp('gte', role('nope.role'), lit(1)) }], bounds: [{ bid: 'bn', sel: { k: 'gids', gids: ['gc'] }, agg: 'sum', value: role('nope.role'), key: '', window: { k: 'lifetime' }, scope: { k: 'session' }, cap: { u: USD, n: 1 }, onExceed: 'deny' }] }));
  for (const g of goals) {
    await run('selGoalDigest', SEL.selGoalDigest, [g]);
    await run('expandSelGoal', (sg: any, dom: string, c: any) => SEL.expandSelGoal(sg, O.toIrOntology(ALL[dom]), c), [g, d, cat]);
    await run('selReasons', (sg: any, dom: string, c: any) => SEL.selReasons(sg, O.toIrOntology(ALL[dom]), c), [g, d, cat]);
    await run('selCarrier', SEL.selCarrier, [g]);
    await run('renderSelCard', (sg: any, dom: string, c: any) => SEL.renderSelCard(sg, O.toIrOntology(ALL[dom]), c), [g, d, cat]);
  }
  await run('encodeSelCatalog', SEL.encodeSelCatalog, [cat]);
  const act = (verb: string, params: any) => ({ verb, res: 'r', params, t: 0, sess: 's', prin: 'p', org: 'o', agent: 'a', depth: 0 });
  const qv = { k: 'q', q: { u: USD, n: 5 } };
  for (const v of cat.verbs.slice(0, 8)) {
    const ps: any = {};
    for (const paths of Object.values(v.roles) as string[][]) for (const p of paths) ps[p] = qv;
    await run('withRoleParams', SEL.withRoleParams, [act(v.verb, ps), cat]);
    await run('withRoleParams', SEL.withRoleParams, [act(v.verb, { ...ps, '@money.amount': qv, '@forged': qv }), cat]);
  }
  await run('withRoleParams', SEL.withRoleParams, [act('nope', { a: qv, '@x': qv }), cat]);
}
for (const ids of [[], ['pca.unreviewed'], ['pca.cost_incurring', 'pca.bulk']]) await run('traitClosure', (x: string[]) => SEL.traitClosure(x), [ids]);
await run('traitClosure', (x: string[]) => SEL.traitClosure(x), [['nope']]);
refWrite(o, 'goal-selectors-py');
