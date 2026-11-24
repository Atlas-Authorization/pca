// Oracle: @atlasauth/pca-intent trajectory intent (trajectory.ts): dimension paths, augmentOmega, liftAction / liftedCell, stepTrajectory, defaultAccumulators, describeAccCell, trajectoryHarmRange. Deterministic.
// PORTING (fn(args) -> native entry point, comparison rule; JSON value equality, doubles bit-exact):
//   dimKindOf(path) / accDimPath(id) / monDimPath(id) / trajectoryHarmRange(len, hmax)   IntentTrajectory.*
//   augment(omega, psi, opts?) -> Omega JSON   IntentTrajectory.augmentOmega
//   liftScenario(omega, psi, augOpts, history, cand, schema?) -> {lifted, cell}: tilde = augmentOmega(omega, psi, augOpts); lifted = liftAction(tilde, psi, history, cand, schema); cell = liftedCell -> {verb, cell} or null
//   stepScenario(omega, psi, augOpts, history, cand, grant, schema?) -> stepTrajectory with grant in {"all","none","cell0","firstLow"} (cell0: every index 0; firstLow: cell[0] <= 1)
//   defaultAccumulators(schema, opts{spendDomainMax, questionCap?, holder?})   IntentTrajectory.defaultAccumulators
//   describeAccCell(dim, cellIndex, label, thisAction?, fmt?) with fmt in {"plain" (default), "bracket" (x => "[" + x + "]")}
import * as T0 from '../../../packages/pca-intent/src/trajectory';
import { Oracle, refWrite } from './lib.mjs';

const T: any = (T0 as any).default ?? T0;
const o = new Oracle('intent-trajectory', 'tools/pca-audit/oracles/intent-trajectory.mts', 'TS-reference oracle for trajectory intent.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);
const A = 'action.params.';
const num = (path: string, lo: number, hi: number, cuts: number[], dist = 'uniform') => ({ kind: 'num', path, lo, hi, cuts, dist });
const cat = (path: string, exacts: string[]) => ({ kind: 'cat', path, values: [...exacts.map((v) => ({ kind: 'exact', value: v })), { kind: 'other', value: '⊥' }] });
const vsp = (verb: string, reversibility: string, weight: number, dims: any[]) => ({ verb, reversibility, weight, dims });
const OM = { v: 1, approximate: ['regex'], verbs: [vsp('pay', 'irreversible', 0.4, [num(A + 'amount', 0, 500, [100]), cat('env.canon.tags', ['a']), num(accDim('old'), 0, 3, []), cat(monDim('old'), ['x'])]), vsp('tip', 'reversible', 0.3, [num(A + 'amount', 0, 100, [10])]), vsp('a', 'reversible', 0.3, [cat(A + 'to', ['x']), cat('action.resource', ['/r'])])] };
function accDim(id: string) { return 'env.acc.' + id + '.post'; }
function monDim(id: string) { return 'env.mon.' + id + '.state'; }
const HOLDER = { kind: 'site_local' };
const acc = (over: any) => ({ agg: 'count', sel: { verbs: [] }, win: { kind: 'task' }, key: null, holder: HOLDER, ...over });
const mon = (over: any) => ({ kind: 'never', p: { verb: 'a' }, ...over });
const SCHEMA = { verbs: [
  { verb: 'pay', kind: 'write', params: { [A + 'amount']: { type: 'integer', semantic: 'money.amount', sensitivity: 'material', accumulates_into: ['usd'] }, [A + 'memo']: { type: 'string', semantic: 'text.memo', sensitivity: 'free' }, [A + 'tags']: { type: 'set', semantic: 'tag.x', sensitivity: 'material', values: ['a', 'b'] } } },
  { verb: 'tip', kind: 'write', params: { [A + 'amount']: { type: 'integer', semantic: 'money.amount', sensitivity: 'material', accumulates_into: ['usd', 'tips'] } } },
  { verb: 'a', kind: 'write', params: { [A + 'to']: { type: 'string', semantic: 'party.to', sensitivity: 'material' } } },
  { verb: 'book', kind: 'write', params: { [A + 'price']: { type: 'integer', semantic: 'money.amount', sensitivity: 'material' }, [A + 'nights']: { type: 'integer', semantic: 'count.n', sensitivity: 'material' }, [A + 'seats']: { type: 'integer', semantic: 'money.amount', sensitivity: 'material', accumulates_into: [] } } },
  { verb: 'view', kind: 'read', params: {} }] };

for (const p of ['action.params.x', 'env.acc.x.post', 'env.mon.x.state', 'env.canon.x', 'env.world.x', 'env.rel.x', 'env.prov.x', 'env.class.x', 'env.hour', 'action.resource', '', 'zz.env.canon.', 'zz.env.acc.', 'ENV.acc.x']) await run('dimKindOf', T.dimKindOf, [p]);
for (const id of ['x', 'spend_1', '', 'a.b']) { await run('accDimPath', T.accDimPath, [id]); await run('monDimPath', T.monDimPath, [id]); }
for (const [l, h] of [[0, 1], [5, 2.5], [10, 0], [-1, 1], [1.5, 1], [9007199254740991, 1], [9007199254740992, 1], [1, -1], [3, 1e-9]]) await run('trajectoryHarmRange', T.trajectoryHarmRange, [l, h]);

const PSI = { accumulators: [acc({ id: 'u', agg: 'sum', sel: { accumulates_into: 'usd' }, domain_max: 1000, unit: 'usd' }), acc({ id: 'p', sel: { verbs: ['pay'] }, domain_max: 50 }), acc({ id: 'e', sel: { event: 'question' }, domain_max: 9 }), acc({ id: 'q', sel: { event: 'intent_required' }, cap: 6, holder: { kind: 'wallet' } }), acc({ id: 'big', agg: 'sum', val: A + 'amount', sel: { verbs: ['pay', 'tip'] }, domain_max: 100000 })],
  monitors: [mon({ id: 'm1', kind: 'requires_prior', p: { verb: 'a' }, q: { verb: 'pay' } }), mon({ id: 'm2', kind: 'never', p: { verb: ['tip', 'book'] } }), mon({ id: 'm3', kind: 'responds_within', p: { verb: 'a' }, q: { verb: 'pay' }, within: 2 }), mon({ id: 'm4', kind: 'always', p: { verb: '*' } })] };
const noWallet = { accumulators: PSI.accumulators.filter((a: any) => a.holder.kind !== 'wallet'), monitors: PSI.monitors };
const augCases: any[] = [[OM, { accumulators: [], monitors: [] }], [OM, PSI], [OM, PSI, { scope: 'selected', schema: SCHEMA }], [OM, PSI, { scope: 'selected' }], [OM, PSI, { scope: 'all' }],
  [OM, PSI, { cuts: { u: [50, 0, 100, 100, 7.5, -1, 1001, 10, 400], big: [1e10, 5], missing: [1] } }], [OM, { accumulators: [acc({ id: 'nodomain' })], monitors: [] }], [OM, { accumulators: [acc({ id: 'w', cap: 6, holder: { kind: 'wallet' } })], monitors: [] }],
  [OM, { accumulators: [], monitors: [mon({ id: 'a', q: { verb: ['pay'] } }), mon({ id: 'b', q: { verb: '*' } }), mon({ id: 'c' })] }, { scope: 'selected' }], [OM, { accumulators: [acc({ id: 's', agg: 'sum', sel: { accumulates_into: 'tips' }, domain_max: 9 })], monitors: [] }, { scope: 'selected', schema: SCHEMA }],
  [OM, { accumulators: [acc({ id: 's', agg: 'sum', sel: { accumulates_into: 'nope' }, domain_max: 9 })], monitors: [] }, { scope: 'selected', schema: SCHEMA }], [{ v: 1, approximate: [], verbs: [] }, PSI]];
for (const c of augCases) await run('augment', (om: any, psi: any, op?: any) => T.augmentOmega(om, psi, op), c);

const ev = (id: string, verb: string, params: any, t: number, status = 'reserved') => ({ id, verb, resource: '/r', params, t, status });
const hist: any[][] = [[], [ev('1', 'pay', { amount: 120 }, 1)], [ev('1', 'pay', { amount: 120 }, 1), ev('2', 'tip', { amount: 30 }, 2, 'committed'), ev('3', 'a', { to: 'x' }, 3)], [ev('1', 'pay', { amount: 600 }, 1, 'committed'), ev('2', 'pay', { amount: 500 }, 2)], [ev('1', 'a', { to: 'x' }, 1, 'denied'), ev('2', 'a', { to: 'y' }, 2, 'reserved')]];
const cands: any[] = [{ verb: 'pay', resource: '/r', params: { amount: 150, tags: ['b', 'a'], memo: 'hi' }, t: 5 }, { verb: 'pay', resource: '/r', params: { amount: 1.5 }, t: 5 }, { verb: 'pay', resource: '/r', params: {}, t: 5 }, { verb: 'tip', resource: '/r', params: { amount: 5 }, t: 6 },
  { verb: 'a', resource: '/r', params: { to: 'x' }, t: 7 }, { verb: 'a', resource: '/other', params: { to: 'zzz' }, t: 7 }, { verb: 'nope', resource: '/r', params: {}, t: 1 }, { verb: 'pay', resource: '/r', params: { amount: 'abc', tags: 5 }, t: 5 }, { verb: 'a', resource: '/r', params: { to: 5 }, t: 8 }];
const augOptsList: any[] = [{}, { cuts: { u: [100, 200], p: [1], big: [150] } }];
const liftScenario = (om: any, psi: any, ao: any, h: any[], cand: any, schema?: any) => { const tilde = T.augmentOmega(om, psi, ao); const lifted = T.liftAction(tilde, psi, h, cand, schema); const c = lifted ? T.liftedCell(tilde, lifted) : null; return { lifted, cell: c ? { verb: c.vs.verb, cell: c.cell } : null }; };
for (const h of hist) for (const c of cands) for (const ao of augOptsList) await run('liftScenario', liftScenario, [OM, PSI, ao, h, c, SCHEMA]);
for (const c of cands.slice(0, 4)) await run('liftScenario', liftScenario, [OM, PSI, {}, hist[2], c]);
const GRANTS: Record<string, any> = { all: () => true, none: () => false, cell0: (_v: string, c: number[]) => c.every((x) => x === 0), firstLow: (_v: string, c: number[]) => c[0] <= 1 };
const stepScenario = (om: any, psi: any, ao: any, h: any[], cand: any, grant: string, schema?: any) => { const tilde = T.augmentOmega(om, psi, ao); return T.stepTrajectory(tilde, psi, h, cand, GRANTS[grant], schema); };
for (const h of hist.slice(0, 3)) for (const c of cands.slice(0, 7)) for (const g of ['all', 'none', 'cell0', 'firstLow']) await run('stepScenario', stepScenario, [OM, PSI, augOptsList[1], h, { ...c, id: 'new1' }, g, SCHEMA]);

for (const o2 of [{ spendDomainMax: 1000 }, { spendDomainMax: 500, questionCap: 3 }, { spendDomainMax: 10, holder: { kind: 'wallet' } }, { spendDomainMax: 1, questionCap: 0 }]) {
  await run('defaultAccumulators', T.defaultAccumulators, [SCHEMA, o2]);
  await run('defaultAccumulators', T.defaultAccumulators, [{ verbs: [] }, o2]);
}
await run('defaultAccumulators', T.defaultAccumulators, [{ verbs: [{ verb: 'a-very.long/verb name with spaces and é symbols that goes on and on and on', kind: 'write', params: { [A + 'some_really_long_parameter_name_that_goes_on_and_on_and_on_to_exceed_limits']: { type: 'integer', semantic: 'money.amount', sensitivity: 'material' } } }] }, { spendDomainMax: 9 }]);
const FMT: Record<string, any> = { plain: undefined, bracket: (x: number) => '[' + x + ']' };
const dimA: any = { kind: 'num', path: 'env.acc.u.post', lo: 0, hi: 1000, cuts: [100, 200], dist: 'loguniform' };
for (const dim of [dimA, { ...dimA, cuts: [] }, { ...dimA, lo: 5, hi: 5 }]) for (let i = -1; i <= 5; i++) for (const ta of [undefined, 0, 25.5]) for (const f of ['plain', 'bracket']) {
  await run('describeAccCell', (d: any, idx: number, label: string, t: number | undefined, fmt: string) => T.describeAccCell(d, idx, label, t === null ? undefined : t, FMT[fmt]), [dim, i, 'total', ta, f]);
}
refWrite(o, 'intent-trajectory');
