// Oracle: @atlasauth/pca-intent verifyOutcome (effects.ts) and the Monte Carlo residual-risk estimate (metrics.ts estimateResidualRiskMC). Deterministic (seeded generator).
// PORTING (fn(args) -> native entry point, comparison rule; JSON value equality, doubles bit-exact):
//   verifyScenario(omega, mapOpts, observations, outcome, effect, pcs?) -> {result: verifyOutcome(l, o, effect, pcs) (IntentOutcome.verifyOutcome; pcs absent = defaults), metrics}
//   mcScenario(omega, mapOpts, observations, samples?, seed?) -> estimateResidualRiskMC(l, {samples, seed}) (IntentOutcome.estimateResidualRiskMC; absent = defaults 20000 / 7: not used in the corpus)
import * as E0 from '../../../packages/pca-intent/src/effects';
import * as ME0 from '../../../packages/pca-intent/src/metrics';
import * as M0 from '../../../packages/pca-intent/src/map';
import * as O0 from '../../../packages/pca-intent/src/omega';
import * as P0 from '../../../packages/pca-intent/src/policy';
import { Oracle, refWrite } from './lib.mjs';

const E: any = (E0 as any).default ?? E0;
const ME: any = (ME0 as any).default ?? ME0;
const M: any = (M0 as any).default ?? M0;
const O: any = (O0 as any).default ?? O0;
const P: any = (P0 as any).default ?? P0;
const o = new Oracle('intent-outcome', 'tools/pca-audit/oracles/intent-outcome.mts', 'TS-reference oracle for verifyOutcome and the Monte Carlo risk estimate.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);
const A = 'action.params.';
const num = (path: string, lo: number, hi: number, cuts: number[], dist = 'uniform') => ({ kind: 'num', path, lo, hi, cuts, dist });
const cat = (path: string, exacts: string[], prefixes: string[] = []) => ({ kind: 'cat', path, values: [...exacts.map((v) => ({ kind: 'exact', value: v })), ...prefixes.map((v) => ({ kind: 'prefix', value: v })), { kind: 'other', value: '⊥' }] });
const vsp = (verb: string, reversibility: string, weight: number, dims: any[]) => ({ verb, reversibility, weight, dims });
const refund = vsp('stripe.refund', 'irreversible', 0.5, [num(A + 'amount', 0, 100, [10, 50]), cat(A + 'recipient', ['bob'], ['team-'])]);
const send = vsp('gmail.send', 'rate_limited', 0.25, [cat(A + 'to', ['a', 'b'], ['p-'])]);
const cal = vsp('calendar.create_event', 'reversible', 0.25, [num('env.hour', 0, 23, [9, 17], 'uniform')]);
const OM = { v: 1, verbs: [refund, send, cal], approximate: [] };
const OA = { v: 1, verbs: [{ ...refund, weight: 1 }], approximate: [] };
const w = (field: string, op: string, value: any) => ({ field, op, value });
const POL = { predicates: [{ verb: 'stripe.refund', resource: '*', where: [w(A + 'amount', 'lte', 50), w(A + 'recipient', 'in', ['bob'])] }, { verb: 'gmail.send', resource: '*', where: [w(A + 'to', 'prefix', 'p-')] }, { verb: 'calendar.create_event', resource: '*', where: [w('env.hour', 'gte', 9)] }], caveats: [] };
const adm = P.admitter(POL);
const allCells = (vs: any): number[][] => { const t = O.verbCellCount(vs); const r: number[][] = []; for (let f = 0; f < t; f++) r.push(O.decodeCell(vs, f)); return r; };
const obsAll = (vsl: any[], every: number) => { const out: any[] = []; let i = 0; for (const vs of vsl) for (const idx of allCells(vs)) { if (i++ % every !== 0) continue; const oc = O.cellRep(vs, idx); out.push({ verb: vs.verb, values: oc.values, y: adm.admits(vs, oc) ? 1 : 0, source: 'elicitation' }); } return out; };
const mk = (omega: any, mo: any, obs: any[]) => { const l = M.createLearner(omega, mo); for (const x of obs) l.observe({ verb: x.verb, values: x.values }, x.y, x.source); return l; };

const verifyScenario = (omega: any, mo: any, obs: any[], oc: any, effect: any, pcs?: any) => { const l = mk(omega, mo, obs); const result = pcs === undefined ? E.verifyOutcome(l, oc, effect) : E.verifyOutcome(l, oc, effect, pcs); return { result, metrics: l.metrics() }; };
const refundOc = (idx: number[]) => O.cellRep(refund, idx);
const effects: any[] = [{ amount: 5, recipient: 'bob' }, { amount: 600, recipient: 'bob' }, { amount: 5, recipient: 'eve' }, { amount: 5 }, {}, { recipient: 'bob' }, { amount: -1, recipient: 'bob' }];
for (const idx of [[0, 0], [1, 0], [2, 1]]) for (const e of effects) {
  await run('verifyScenario', verifyScenario, [OA, {}, obsAll([refund], 1), refundOc(idx), e]);
}
await run('verifyScenario', verifyScenario, [OA, { eta: 0.1 }, obsAll([refund], 1), refundOc([0, 0]), { amount: 5000, recipient: 'bob' }]);
await run('verifyScenario', verifyScenario, [OM, {}, obsAll([refund, send, cal], 1), O.cellRep(send, [2]), { to: 'zzz' }]);
await run('verifyScenario', verifyScenario, [OM, {}, obsAll([refund, send, cal], 1), O.cellRep(send, [2]), { to: 'p-1' }]);
await run('verifyScenario', verifyScenario, [OM, {}, obsAll([refund, send, cal], 1), O.cellRep(cal, [1]), { hour: 12 }]);
await run('verifyScenario', verifyScenario, [OM, {}, obsAll([refund, send, cal], 1), O.cellRep(cal, [1]), { hour: 3 }]);
const customPcs = [{ id: 'c1', verb: 'stripe.refund', description: 'd', where: [{ field: 'env.effect.k', op: 'eq', value: 1 }] }];
await run('verifyScenario', verifyScenario, [OA, {}, obsAll([refund], 1), refundOc([0, 0]), { k: 2 }, customPcs]);
await run('verifyScenario', verifyScenario, [OA, {}, obsAll([refund], 1), refundOc([0, 0]), { k: 1 }, customPcs]);
await run('verifyScenario', verifyScenario, [OA, {}, obsAll([refund], 1), refundOc([0, 0]), {}, customPcs]);
await run('verifyScenario', verifyScenario, [OA, {}, obsAll([refund], 1), refundOc([0, 0]), { amount: 1 }, []]);
await run('verifyScenario', verifyScenario, [OA, {}, obsAll([refund], 1), { verb: 'nope', values: {} }, {}]);

const mcScenario = (omega: any, mo: any, obs: any[], samples: number, seed: number) => ME.estimateResidualRiskMC(mk(omega, mo, obs), { samples, seed });
for (const [om, mo, obs] of [[OA, {}, obsAll([refund], 1)], [OA, {}, obsAll([refund], 3)], [OA, { eta: 0.1 }, obsAll([refund], 2)], [OM, {}, obsAll([refund, send, cal], 1)], [OM, {}, obsAll([refund, send, cal], 4)], [OM, {}, []]] as any[]) for (const [s, sd] of [[200, 7], [1000, 1], [500, 12345]]) await run('mcScenario', mcScenario, [om, mo, obs, s, sd]);
refWrite(o, 'intent-outcome');
