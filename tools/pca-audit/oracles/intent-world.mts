// Oracle: @atlasauth/pca-intent world / provenance / classifier dimensions (world.ts). Deterministic.
// PORTING (fn(args) -> native entry point, comparison rule; JSON value equality):
//   worldDim(name, o{lo,hi,cuts?,dist?}) -> IntentWorld.worldDim(name, lo, hi, cuts, dist) -> Dim JSON (IntentOmega.dimToJson)
//   excessDim(name, hi, slacks?) / optimalityCondition(name, slack?) / provenanceDim(path) / classifierDim(id, labels)
//   withDims(omega, verb, dims) -> Omega JSON;  liftOutcome(o, env, dimPaths) -> Outcome JSON
import * as W0 from '../../../packages/pca-intent/src/world';
import * as O0 from '../../../packages/pca-intent/src/omega';
import { Oracle, refWrite } from './lib.mjs';

const W: any = (W0 as any).default ?? W0;
const O: any = (O0 as any).default ?? O0;
const o = new Oracle('intent-world', 'tools/pca-audit/oracles/intent-world.mts', 'TS-reference oracle for intent world dimensions.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);

for (const spec of [{ lo: 0, hi: 100 }, { lo: 0, hi: 100, cuts: [5, 1, 5, 200, -3, 100, 0] }, { lo: -10, hi: 10, cuts: [0], dist: 'loguniform' }, { lo: 1, hi: 1, cuts: [1] }, { lo: 0, hi: 5, dist: 'uniform', cuts: [] }]) await run('worldDim', W.worldDim, ['slack', spec]);
for (const [hi, sl] of [[100, undefined], [100, []], [100, [3, 1, 3]], [50, [0, 60]], [0, [0]]] as any[]) await run('excessDim', (a: string, b: number, c: any) => W.excessDim(a, b, c), ['cost', hi, sl ?? []]);
for (const s of [undefined, 0, 5, -1, 0.5]) await run('optimalityCondition', (a: string, b: any) => (b === undefined ? W.optimalityCondition(a) : W.optimalityCondition(a, b)), s === undefined ? ['price'] : ['price', s]);
for (const p of ['recipient', 'a.b.c', '']) await run('provenanceDim', W.provenanceDim, [p]);
for (const labels of [[], ['b', 'a', 'a'], ['spam', 'ham', 'é', 'z', '😀', 'Z'], ['x']]) await run('classifierDim', W.classifierDim, ['clf', labels]);
const om = O.deriveOmega({ policies: [{ predicates: [{ verb: 'stripe.refund', where: [{ field: 'action.params.amount', op: 'lte', value: 100 }] }, { verb: 'gmail.send' }] }] });
const dimsets: any[] = [[W.worldDim('slack', { lo: 0, hi: 10, cuts: [3] })], [W.provenanceDim('recipient'), W.classifierDim('c', ['a'])], [], [W.worldDim('zz', { lo: 0, hi: 1 }), W.worldDim('aa', { lo: 0, hi: 1 })], [W.worldDim('x', { lo: 0, hi: 1 }), W.worldDim('x', { lo: 0, hi: 2 })]];
for (const verb of ['stripe.refund', 'gmail.send', 'nope.verb']) for (const ds of dimsets) await run('withDims', W.withDims, [om, verb, ds]);
await run('withDims', W.withDims, [om, 'stripe.refund', [{ kind: 'num', path: 'action.params.amount', lo: 0, hi: 1, cuts: [], dist: 'uniform' }]]);
const base = { verb: 'stripe.refund', values: { 'action.params.amount': 5 } };
const dp = ['env.world.slack', 'env.prov.recipient', 'env.prov.a.b', 'env.class.c', 'env.world.missing', 'env.other.x', 'action.params.amount'];
const envs: any[] = [{}, { world: { slack: 3 } }, { world: { slack: 'text' } }, { world: { slack: null } }, { world: { slack: true } }, { prov: { recipient: 'first_party' } }, { prov: { recipient: 5, a: { b: 'trusted' } } }, { prov: { a: { b: { c: 1 } } } }, { class: { c: 'spam' } }, { class: { c: 5 } }, { world: 5, prov: 'x', class: [] },
  { world: { slack: 3, missing: 1.5 }, prov: { recipient: 'trusted', a: { b: 'agent' } }, class: { c: 'ham' } }, { world: { slack: -0.5 } }];
for (const e of envs) await run('liftOutcome', W.liftOutcome, [base, e, dp]);
await run('liftOutcome', W.liftOutcome, [{ verb: 'v', values: {} }, envs[11], []]);
await run('liftOutcome', W.liftOutcome, [{ verb: 'v', values: { 'env.world.slack': 9 } }, { world: { slack: 'q' } }, ['env.world.slack']]);
refWrite(o, 'intent-world');
