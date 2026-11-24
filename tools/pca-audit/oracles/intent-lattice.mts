// Oracle: @atlasauth/pca-intent the layered lattice over a task learner (layers.ts: latticeView, decideOutcomeLayers, orgLayerFromMaps). Deterministic.
// PORTING (fn(args) -> native entry point, comparison rule; JSON value equality, doubles bit-exact):
//   latticeScenario(omega, mapOpts, observations, layers, outcomes) -> {view: latticeView(l, ceilingAdmitters(layers)), decisions: [decideOutcomeLayers(l, ceilings, o)]}
//     IntentLattice.latticeView / decideOutcomeLayers with IntentLayers.ceilingAdmitters(layers); a malformed layer throws
//   orgScenario(maps, rule) -> orgLayerFromMaps(maps, rule) (IntentLattice.orgLayerFromMaps)
import * as L0 from '../../../packages/pca-intent/src/layers';
import * as M0 from '../../../packages/pca-intent/src/map';
import * as O0 from '../../../packages/pca-intent/src/omega';
import * as P0 from '../../../packages/pca-intent/src/policy';
import { Oracle, refWrite } from './lib.mjs';

const L: any = (L0 as any).default ?? L0;
const M: any = (M0 as any).default ?? M0;
const O: any = (O0 as any).default ?? O0;
const P: any = (P0 as any).default ?? P0;
const o = new Oracle('intent-lattice', 'tools/pca-audit/oracles/intent-lattice.mts', 'TS-reference oracle for the layered lattice.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);
const A = 'action.params.';
const num = (path: string, lo: number, hi: number, cuts: number[]) => ({ kind: 'num', path, lo, hi, cuts, dist: 'uniform' });
const cat = (path: string, exacts: string[], prefixes: string[] = []) => ({ kind: 'cat', path, values: [...exacts.map((v) => ({ kind: 'exact', value: v })), ...prefixes.map((v) => ({ kind: 'prefix', value: v })), { kind: 'other', value: '⊥' }] });
const refund = { verb: 'stripe.refund', reversibility: 'irreversible', weight: 1, dims: [num(A + 'amount', 0, 100, [10, 50]), cat(A + 'recipient', ['bob'], ['team-'])] };
const OA = { v: 1, verbs: [refund], approximate: [] };
const OB = { v: 1, verbs: [{ ...refund, weight: 0.5 }, { verb: 'gmail.send', reversibility: 'rate_limited', weight: 0.5, dims: [cat(A + 'to', ['a', 'b'], ['p-'])] }], approximate: [] };
const w = (field: string, op: string, value: any) => ({ field, op, value });
const pol = (...ps: any[]) => ({ predicates: ps, caveats: [] });
const polRefund = (max: number, who?: string[]) => pol({ verb: 'stripe.refund', resource: '*', where: [w(A + 'amount', 'lte', max), ...(who ? [w(A + 'recipient', 'in', who)] : [])] });
const allCells = (vs: any): number[][] => { const t = O.verbCellCount(vs); const r: number[][] = []; for (let f = 0; f < t; f++) r.push(O.decodeCell(vs, f)); return r; };
const obsOf = (omega: any, policy: any, every: number, runtimeEvery = 0): any[] => { const adm = P.admitter(policy); const out: any[] = []; let i = 0; for (const vs of omega.verbs) for (const idx of allCells(vs)) { if (i++ % every !== 0) continue; const oc = O.cellRep(vs, idx); out.push({ verb: vs.verb, values: oc.values, y: adm.admits(vs, oc) ? 1 : 0, source: runtimeEvery && i % runtimeEvery === 0 ? 'runtime' : 'elicitation' }); } return out; };
const mk = (omega: any, mo: any, obs: any[]) => { const l = M.createLearner(omega, mo); for (const x of obs) l.observe({ verb: x.verb, values: x.values }, x.y, x.source); return l; };
const latticeScenario = (omega: any, mo: any, obs: any[], layers: any, outs: any[]) => { const l = mk(omega, mo, obs); const c = L.ceilingAdmitters(layers); return { view: L.latticeView(l, c), decisions: outs.map((x: any) => L.decideOutcomeLayers(l, c, x)) }; };
const outsOf = (omega: any) => [...omega.verbs.flatMap((vs: any) => allCells(vs).map((idx) => O.cellRep(vs, idx))), { verb: 'nope', values: {} }, { verb: 'stripe.refund', values: { [A + 'amount']: 1000, [A + 'recipient']: 'bob' } }];
const layerSets: any[] = [{}, { org: polRefund(100) }, { org: polRefund(30), site: polRefund(60, ['bob']) }, { std: polRefund(20) }, { org: polRefund(100), site: polRefund(100), std: polRefund(100, ['bob', 'team-1']) }, { org: { predicates: [], caveats: [] } }, { org: null }, { site: 'x' }, { std: [] }, { org: polRefund(50), extra: 1 }];
for (const [om, truth, every, rt] of [[OA, polRefund(50, ['bob']), 1, 0], [OA, polRefund(50, ['bob']), 3, 0], [OA, polRefund(100), 2, 4], [OB, pol(...polRefund(50).predicates, { verb: 'gmail.send', resource: '*', where: [w(A + 'to', 'prefix', 'p-')] }), 1, 0]] as any[]) {
  for (const layers of layerSets) for (const mo of [{}, { eta: 0.1 }]) await run('latticeScenario', latticeScenario, [om, mo, obsOf(om, truth, every, rt), layers, outsOf(om)]);
}
await run('latticeScenario', latticeScenario, [OA, {}, [], {}, outsOf(OA)]);
const buildMap = (omega: any, mo: any, obs: any[], ref: string) => M.emitIntentMap(mk(omega, mo, obs), ref);
const REF = (c: string) => c.repeat(43);
const mapsA = [buildMap(OA, {}, obsOf(OA, polRefund(50, ['bob']), 1), REF('a')), buildMap(OA, {}, obsOf(OA, polRefund(10), 1), REF('b')), buildMap(OA, {}, obsOf(OA, polRefund(100), 2), REF('c'))];
for (const rule of [{ kind: 'unanimity' }, { kind: 'quorum', k: 2 }, { kind: 'unanimity', vetoers: [REF('a')] }, { kind: 'weighted', weights: { [REF('a')]: 2, [REF('b')]: 1, [REF('c')]: 1 }, threshold: 3 }, { kind: 'quorum', k: 9 }]) await run('orgScenario', (maps: any[], r: any) => L.orgLayerFromMaps(maps, r), [mapsA, rule]);
await run('orgScenario', (maps: any[], r: any) => L.orgLayerFromMaps(maps, r), [mapsA.slice(0, 1), { kind: 'unanimity' }]);
await run('orgScenario', (maps: any[], r: any) => L.orgLayerFromMaps(maps, r), [[], { kind: 'unanimity' }]);
refWrite(o, 'intent-lattice');
