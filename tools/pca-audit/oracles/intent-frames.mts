// Oracle: @atlasauth/pca-intent frame and side-effect constraints (frames.ts): stateDigest, snapshotState, writeSetOf, checkFrame, applyFrameReport. Deterministic.
// PORTING (fn(args) -> native entry point, comparison rule; JSON value equality, doubles bit-exact):
//   stateDigest(v) / snapshotState(values, keep?) / writeSetOf(spec, action)   IntentFrames.* (an undefined state value is null)
//   checkFrame(spec, action, pre, post, opts)   IntentFrames.checkFrame -> FrameReport (a TypeError-driven "error: ..." entry is compared as "error: error"; only the argument-validation message is kept)
//   applyScenario(omega, mapOpts, observations, outcome, report) -> {result: applyFrameReport(l, o, report), metrics}
import * as F0 from '../../../packages/pca-intent/src/frames';
import * as M0 from '../../../packages/pca-intent/src/map';
import * as O0 from '../../../packages/pca-intent/src/omega';
import { Oracle, refWrite } from './lib.mjs';

const F: any = (F0 as any).default ?? F0;
const M: any = (M0 as any).default ?? M0;
const O: any = (O0 as any).default ?? O0;
const o = new Oracle('intent-frames', 'tools/pca-audit/oracles/intent-frames.mts', 'TS-reference oracle for frame constraints.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);
const norm = (r: any) => ({ ...r, missing: r.missing.map((m: string) => (m.startsWith('error: ') && !m.startsWith('error: spec, action') ? 'error: error' : m)) });
const check = (spec: any, action: any, pre: any, post: any, opts: any) => norm(F.checkFrame(spec, action, pre, post, opts));

for (const v of [null, true, false, 0, 1, 1.5, -2, 'x', '', 'aé😀', [], [1, 2], ['a', { b: null }], {}, { a: 1, b: [1, 2, { c: 'x' }] }, { b: 1, a: 2 }, { n: 0.1 }, { n: 1e21 }, { n: -0 }]) await run('stateDigest', F.stateDigest, [v]);
for (const vals of [{}, { 'account.email': 'a@x.com', 'loyalty.points': 10 }, { x: null, y: [1, 2], z: { k: 1.5 } }, { '__proto__': 1, constructor: 2 }]) for (const keep of [undefined, true, false]) await run('snapshotState', F.snapshotState, keep === undefined ? [vals] : [vals, keep]);

const spec = { state: ['account.email', 'account.cards', 'loyalty.points', 'bookings.count', 'notes'], writes: { 'shop.buy': ['loyalty.points', 'bookings.count'], 'acct.update': { param: 'action.params.field', map: { email: ['account.email'], cards: ['account.cards'] }, default: ['notes'] }, 'acct.nodef': { param: 'kind', map: { a: ['notes'] } }, 'acct.num': { param: 'action.params.n', map: { '1': ['notes'], 'true': ['account.email'] } } },
  post: [{ id: 'pc1', verb: 'shop.buy', deltas: [{ path: 'bookings.count', by: 1 }] }, { id: 'pc2', verb: 'shop.buy', where: [{ field: 'env.post.loyalty.points', op: 'gte', ref: 'env.pre.loyalty.points' }] }, { id: 'pc3', verb: 'shop.buy', where: [{ field: 'env.effect.charged', op: 'lte', value: 100 }] },
    { id: 'pc4', verb: 'shop.buy', where: [{ any_of: [{ field: 'env.effect.refunded', op: 'eq', value: true }, { not: { field: 'env.post.account.email', op: 'eq', value: 'bad@x.com' } }] }] }, { id: 'pc5', verb: 'other', deltas: [{ path: 'a.b', by: 1 }] }, { id: 'pc6', verb: 'shop.buy', deltas: [{ path: 'loyalty.points', by: 5 }, { path: 'bookings.count', by: 1 }] }] };
const snap = (vals: any, keep = true) => F.snapshotState(vals, keep);
const base = { 'account.email': 'a@x.com', 'account.cards': ['visa'], 'loyalty.points': 10, 'bookings.count': 2, notes: 'n' };
const act = (verb: string, params: any = {}) => ({ verb, resource: '/shop', params });
const scen: any[] = [
  [spec, act('shop.buy'), snap(base), snap({ ...base, 'loyalty.points': 15, 'bookings.count': 3 }), {}],
  [spec, act('shop.buy'), snap(base), snap({ ...base, 'loyalty.points': 15, 'bookings.count': 3 }), { effect: { charged: 50 } }],
  [spec, act('shop.buy'), snap(base), snap({ ...base, 'loyalty.points': 15, 'bookings.count': 4 }), { effect: { charged: 50 } }],
  [spec, act('shop.buy'), snap(base), snap({ ...base, 'loyalty.points': 15, 'bookings.count': 3, 'account.email': 'bad@x.com' }), { effect: { charged: 500 } }],
  [spec, act('shop.buy'), snap(base), snap({ ...base, 'loyalty.points': 5, 'bookings.count': 3 }), { effect: { charged: 50 } }],
  [spec, act('shop.buy'), snap(base), snap({ ...base, 'loyalty.points': 15, 'bookings.count': 3, 'account.cards': [] }), { effect: { charged: 50 }, attributions: [{ var: 'account.cards', actor: 'bank' }], self: 'agent' }],
  [spec, act('shop.buy'), snap(base), snap({ ...base, 'loyalty.points': 15, 'bookings.count': 3, 'account.cards': [] }), { effect: { charged: 50 }, attributions: [{ var: 'account.cards', actor: 'agent' }], self: 'agent' }],
  [spec, act('shop.buy'), snap(base), snap({ ...base, 'loyalty.points': 15, 'bookings.count': 3, 'account.cards': [] }), { effect: { charged: 50 }, attributions: [{ var: 'account.cards', actor: 'agent' }] }],
  [spec, act('shop.buy'), snap(base), snap({ 'account.email': 'a@x.com', 'loyalty.points': 15, 'bookings.count': 3 }), {}],
  [spec, act('shop.buy'), snap(base, false), snap(base, false), {}],
  [spec, act('shop.buy'), snap(base), snap(base), { effect: { charged: 50 } }],
  [spec, act('acct.update', { field: 'email' }), snap(base), snap({ ...base, 'account.email': 'new@x.com' }), {}],
  [spec, act('acct.update', { field: 'cards' }), snap(base), snap({ ...base, 'account.email': 'new@x.com' }), {}],
  [spec, act('acct.update', { field: 'zzz' }), snap(base), snap({ ...base, notes: 'changed' }), {}],
  [spec, act('acct.update', { field: 'zzz' }), snap(base), snap({ ...base, 'account.email': 'x' }), {}],
  [spec, act('acct.update', {}), snap(base), snap({ ...base, notes: 'c' }), {}],
  [spec, act('acct.nodef', { kind: 'a' }), snap(base), snap({ ...base, notes: 'c' }), {}], [spec, act('acct.nodef', { kind: 'b' }), snap(base), snap({ ...base, notes: 'c' }), {}],
  [spec, act('acct.num', { n: 1 }), snap(base), snap({ ...base, notes: 'c' }), {}], [spec, act('acct.num', { n: true }), snap(base), snap({ ...base, 'account.email': 'q' }), {}], [spec, act('acct.num', { n: 2 }), snap(base), snap({ ...base, notes: 'c' }), {}],
  [spec, act('unknown.verb'), snap(base), snap(base), {}], [spec, act('unknown.verb'), snap(base), snap({ ...base, notes: 'x' }), {}],
  [{ state: [], writes: {} }, act('x'), snap({}), snap({}), {}], [{ state: [], writes: {}, post: [{ id: 'p', verb: 'x', where: [{ field: 'env.effect.a', op: 'eq', value: 1 }] }] }, act('x'), snap({}), snap({}), { effect: { a: 2 } }],
  [{ state: ['a', 'a', 'b'], writes: {} }, act('x'), snap({ a: 1, b: 2 }), snap({ a: 2, b: 3 }), {}],
  [{ state: ['a.b', 'a.b.c'], writes: {}, post: [{ id: 'n1', verb: 'x', deltas: [{ path: 'a.b', by: 1 }] }] }, act('x'), snap({ 'a.b': 1 }), snap({ 'a.b': 2 }), {}],
  [{ state: ['a'], writes: { x: ['a'] }, post: [{ id: 'd', verb: 'x', deltas: [{ path: 'a', by: 0.1 }] }] }, act('x'), snap({ a: 0.2 }), snap({ a: 0.30000000000000004 }), {}],
  [{ state: ['a'], writes: { x: ['a'] }, post: [{ id: 'd', verb: 'x', deltas: [{ path: 'q', by: 1 }, { path: 'a', by: 1 }] }] }, act('x'), snap({ a: 1 }), snap({ a: 3 }), {}],
  [{ state: ['a'], writes: { x: ['a'] }, post: [{ id: 'd', verb: 'x', where: [{ field: 'env.effect.k', op: 'eq', ref: 'env.effect.m' }] }, { id: 'e', verb: 'x', where: [{ all_of: [{ field: 'env.post.a', op: 'gt', value: 0 }] }] }] }, act('x'), snap({ a: 1 }), snap({ a: 0 }), { effect: { k: 1, m: 1 } }],
  [{ state: ['a'], writes: { x: ['a'] }, post: [{ id: 'd', verb: 'x', where: [{ field: 'env.effect.k', op: 'eq', ref: 'env.effect.m' }] }] }, act('x'), snap({ a: 1 }), snap({ a: 1 }), { effect: { k: null, m: null } }],
  [{ state: ['a'], writes: { x: ['a'] }, post: [{ id: 'd', verb: 'x', where: [{ field: 'action.params.q', op: 'eq', value: 1 }] }] }, act('x', { q: 2 }), snap({ a: 1 }), snap({ a: 1 }), {}],
  [{ state: ['a'], writes: { x: ['a'] }, post: [{ id: 'd', verb: 'x', where: [] }] }, act('x'), snap({ a: 1 }), snap({ a: 1 }), {}],
  [{ state: ['a'], writes: { x: ['a'] }, post: [{ id: 'd', verb: 'x' }] }, act('x'), snap({ a: 1 }), snap({ a: 1 }), {}],
  [{ state: ['a'], writes: {} }, act('x'), snap({ a: 1 }), { a: { digest: F.stateDigest(1) } }, {}], [{ state: ['a'], writes: {} }, act('x'), { a: { digest: 'd1', value: { x: 1 } } }, { a: { digest: 'd2', value: { x: 2 } } }, {}],
  // validation failures
  [null, act('x'), {}, {}, {}], [{ state: 'a' }, act('x'), {}, {}, {}], [{ state: [] }, null, {}, {}, {}], [{ state: [], writes: {} }, act('x'), null, {}, {}], [{ state: [], writes: {} }, act('x'), {}, 5, {}], [5, act('x'), {}, {}, {}],
];
for (const s of scen) await run('checkFrame', check, s);

const applyScenario = (omega: any, mo: any, obs: any[], oc: any, report: any) => { const l = M.createLearner(omega, mo); for (const x of obs) l.observe({ verb: x.verb, values: x.values }, x.y, x.source); const result = F.applyFrameReport(l, oc, report); return { result, metrics: l.metrics() }; };
const A = 'action.params.';
const OM = { v: 1, verbs: [{ verb: 'v.a', reversibility: 'reversible', weight: 1, dims: [{ kind: 'num', path: A + 'a', lo: 0, hi: 5, cuts: [1, 2, 3, 4, 5], dist: 'uniform' }] }], approximate: [] };
const vs = OM.verbs[0];
const obs = Array.from({ length: 6 }, (_, i) => ({ verb: 'v.a', values: O.cellRep(vs, [i]).values, y: 1, source: 'elicitation' }));
for (const report of [{ status: 'violated' }, { status: 'ok' }, { status: 'pending' }, null, 5, {}, { status: 'VIOLATED' }]) for (const i of [0, 3]) await run('applyScenario', applyScenario, [OM, {}, obs, O.cellRep(vs, [i]), report]);
await run('applyScenario', applyScenario, [OM, {}, obs, { verb: 'nope', values: {} }, { status: 'violated' }]);
refWrite(o, 'intent-frames');
