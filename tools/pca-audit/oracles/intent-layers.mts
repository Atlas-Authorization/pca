// Oracle: @atlasauth/pca-intent multi-principal rules + common refinement (multi.ts), layer ceilings + quorum approvals (layers.ts),
// grant measurement (metrics.ts). Deterministic: fixed seeds, no clocks. Secrets cross as b64u 32-byte seeds.
// PORTING (fn(args) -> native entry point, comparison rule; JSON value equality):
//   normalizeRule(rule, refs) -> IntentMulti.normalizeRule(...).toJson();  effectiveVetoers(rule, refs);  ruleAdmits(n, ins);  jointAcceptance(n, ps) (double)
//   commonRefinement(omegas)                       IntentMulti.commonRefinement -> Omega JSON
//   ceilingOf(layers, vs, o)                       ceilingOf(ceilingAdmitters(layers), vs, o): "org" | "site" | "std" | null
//   assertAskable(view, c)                         returns null; a throwing reference requires a throw
//   ownerRisk(omega, cells, policy)                acceptability = acceptabilityOf(policy)
//   layerCells(omega, policy) / cellKeyOf(omega, c)
//   signLayerApproval(s, seedB64u) / verifyQuorumApprovals(approvals, members, rule, expected)
//   measureGrant(omega, grant, truth, opts) / measureGrantExact(omega, grant, truth)   acceptability = acceptabilityOf(truth)
import * as MU0 from '../../../packages/pca-intent/src/multi';
import * as LA0 from '../../../packages/pca-intent/src/layers';
import * as ME0 from '../../../packages/pca-intent/src/metrics';
import * as PO0 from '../../../packages/pca-intent/src/policy';
import * as OM0 from '../../../packages/pca-intent/src/omega';
import { Oracle, refWrite, seed } from './lib.mjs';

const MU: any = (MU0 as any).default ?? MU0;
const LA: any = (LA0 as any).default ?? LA0;
const ME: any = (ME0 as any).default ?? ME0;
const O: any = (OM0 as any).default ?? OM0;
const PO: any = (PO0 as any).default ?? PO0;
const o = new Oracle('intent-layers', 'tools/pca-audit/oracles/intent-layers.mts', 'TS-reference oracle for intent multi-principal rules, layers and metrics.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);
const unseed = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));
const S = (l: string) => Buffer.from(seed('intent-layers/' + l)).toString('base64url');
const pub = (s: string) => LA.signLayerApproval({ layer: 'org', session: S('x'), seq: 1, map_digest: S('y'), prev: S('z') }, unseed(s)).signer;

// ---- rules ----
const refs3 = ['a', 'b', 'c'];
const rules: any[] = [
  { kind: 'unanimity' }, { kind: 'unanimity', vetoers: ['a'] }, { kind: 'unanimity', vetoers: ['zz'] }, { kind: 'quorum', k: 2 }, { kind: 'quorum', k: 1, vetoers: ['b', 'c'] }, { kind: 'quorum', k: 3 }, { kind: 'quorum', k: 4 }, { kind: 'quorum', k: 0 }, { kind: 'quorum', k: 1.5 }, { kind: 'quorum' },
  { kind: 'weighted', weights: { a: 3, b: 2, c: 1 }, threshold: 3 }, { kind: 'weighted', weights: { a: 3, b: 2, c: 1 }, threshold: 6 }, { kind: 'weighted', weights: { a: 3, b: 2, c: 1 }, threshold: 7 }, { kind: 'weighted', weights: { a: 3, b: 2, c: 1 }, threshold: 0 },
  { kind: 'weighted', weights: { a: 3, b: 2, c: 1 }, threshold: 5, vetoers: ['c'] }, { kind: 'weighted', weights: { a: 3, b: 2 }, threshold: 2 }, { kind: 'weighted', weights: { a: 3, b: 2, c: -1 }, threshold: 2 }, { kind: 'weighted', weights: { a: 3, b: 2, c: 1.5 }, threshold: 2 },
  { kind: 'weighted', threshold: 2 }, { kind: 'weighted', weights: { a: 0, b: 0, c: 4 }, threshold: 4 }, { kind: 'weighted', weights: { a: 1, b: 1, c: 1 }, threshold: 1.5 }, { kind: 'bogus', weights: { a: 1, b: 1, c: 1 }, threshold: 2 },
];
const normals: any[] = [];
for (const r of rules) {
  await run('normalizeRule', MU.normalizeRule, [r, refs3]);
  await run('effectiveVetoers', MU.effectiveVetoers, [r, refs3]);
  try { normals.push(MU.normalizeRule(r, refs3)); } catch {}
}
await run('normalizeRule', MU.normalizeRule, [{ kind: 'unanimity' }, []]);
await run('normalizeRule', MU.normalizeRule, [{ kind: 'quorum', k: 1 }, ['solo']]);
for (const nr of normals) {
  for (let m = 0; m < 8; m++) { const ins = [!!(m & 1), !!(m & 2), !!(m & 4)]; await run('ruleAdmits', MU.ruleAdmits, [nr, ins]); }
  for (const ps of [[0, 0, 0], [1, 1, 1], [0.5, 0.5, 0.5], [0.9, 0.2, 0.6], [0.123456789, 0.987654321, 0.5], [1, 0, 1], [0.999999, 0.000001, 0.5]]) await run('jointAcceptance', MU.jointAcceptance, [nr, ps]);
}

// ---- common refinement ----
const amt = (op: string, v: number) => ({ field: 'action.params.amount', op, value: v });
const dv = (policies: any[]) => O.deriveOmega({ policies });
const o1 = dv([{ predicates: [{ verb: 'stripe.refund', where: [amt('lte', 100), { field: 'action.params.currency', op: 'in', value: ['usd'] }] }] }]);
const o2 = dv([{ predicates: [{ verb: 'stripe.refund', where: [amt('lte', 500), { field: 'action.params.currency', op: 'in', value: ['eur', 'usd'] }, { field: 'action.params.to', op: 'prefix', value: 'x-' }] }, { verb: 'gmail.send' }] }]);
const o3 = dv([{ predicates: [{ verb: 'gmail.send', where: [{ field: 'env.hour', op: 'gte', value: 9 }] }, { verb: 'files.read' }] }]);
const oBadDom = dv([{ predicates: [{ verb: 'stripe.refund', where: [amt('lte', 5)] }] }]); oBadDom.verbs[0].dims[0].hi = 999;
const oKind = dv([{ predicates: [{ verb: 'stripe.refund', where: [{ field: 'action.params.amount', op: 'eq', value: 'cat' }] }] }]);
const oRev = dv([{ predicates: [{ verb: 'zzz.custom', where: [amt('lte', 5)] }] }]); const oRev2 = JSON.parse(JSON.stringify(oRev)); oRev2.verbs[0].reversibility = 'rate_limited';
oRev.verbs[0].reversibility = 'reversible';
const sets: any[][] = [[o1], [o1, o2], [o2, o1], [o1, o2, o3], [o3, o1], [], [oBadDom, o1], [o1, oKind], [oRev, oRev2], [oRev2, oRev], [o1, o1]];
for (const s of sets) await run('commonRefinement', MU.commonRefinement, [s]);

// ---- layers ----
const POL_A = { predicates: [{ verb: 'stripe.refund', where: [amt('lte', 100)] }] };
const POL_B = { predicates: [{ verb: 'stripe.refund', where: [amt('lte', 500)] }, { verb: 'gmail.send' }] };
const POL_C = { predicates: [{ verb: 'gmail.send', where: [{ field: 'env.hour', op: 'gte', value: 9 }] }] };
const om = dv([POL_A, POL_B, POL_C]);
const layerSets: any[] = [{}, { org: POL_A }, { site: POL_B }, { std: POL_C }, { org: POL_B, site: POL_A }, { org: POL_B, site: POL_B, std: POL_A }, { org: null }, { org: [] }, { org: 5 }, { site: 'x' }, { org: POL_A, std: null }, { org: { predicates: [] } }];
for (const ls of layerSets) {
  for (const vs of om.verbs) {
    const total = O.verbCellCount(vs);
    for (const f of [0, 1, Math.floor(total / 2), total - 1]) if (f >= 0 && f < total) await run('ceilingOf', (l: any, v: any, ov: any) => LA.ceilingOf(LA.ceilingAdmitters(l), v, ov), [ls, vs, O.cellRep(vs, O.decodeCell(vs, f))]);
  }
}
const view = { effective: [], uncertain: [{ verb: 'stripe.refund', cell: [0, 1] }, { verb: 'gmail.send', cell: [2] }], ceiling: [] };
for (const c of [{ verb: 'stripe.refund', cell: [0, 1] }, { verb: 'gmail.send', cell: [2] }, { verb: 'gmail.send', cell: [1] }, { verb: 'nope', cell: [] }, { verb: 'stripe.refund', cell: [0, 1, 2] }]) await run('assertAskable', (v: any, cc: any) => { LA.assertAskable(v, cc); return null; }, [view, c]);
const omS = dv([POL_A, POL_C]);
for (const pol of [POL_A, POL_B, POL_C, { predicates: [] }]) {
  await run('layerCells', (omg: any, pp: any) => LA.layerCells(omg, PO.admitter(pp)), [om, pol]);
  await run('layerCells', (omg: any, pp: any) => LA.layerCells(omg, PO.admitter(pp)), [omS, pol]);
}
const cellsA = LA.layerCells(om, PO.admitter(POL_A));
const cellsB = LA.layerCells(om, PO.admitter(POL_B));
for (const [cells, pol] of [[cellsA, POL_A], [cellsB, POL_A], [cellsA, POL_B], [[...cellsA, { verb: 'nope', cell: [0] }], POL_C], [[], POL_A]] as any[]) await run('ownerRisk', (omg: any, cs: any, pp: any) => LA.ownerRisk(omg, cs, ME.acceptabilityOf(pp)), [om, cells, pol]);
for (const c of [...cellsA.slice(0, 4), { verb: 'nope', cell: [3, 4] }, { verb: 'gmail.send', cell: [1] }]) await run('cellKeyOf', LA.cellKeyOf, [om, c]);

// approvals
const memSeeds = ['m1', 'm2', 'm3', 'm4'].map(S);
const members = memSeeds.map(pub);
const exp = { layer: 'org', session: S('sess'), seq: 3, map_digest: S('md'), prev: S('pv') };
const sign = (s: string, over: any = {}) => LA.signLayerApproval({ ...exp, ...over }, unseed(s));
await run('signLayerApproval', (st: any, sd: string) => LA.signLayerApproval(st, unseed(sd)), [exp, memSeeds[0]]);
await run('signLayerApproval', (st: any, sd: string) => LA.signLayerApproval(st, unseed(sd)), [{ ...exp, layer: 'task', seq: 1 }, memSeeds[1]]);
const good = memSeeds.map((s) => sign(s));
const quorums: any[] = [{ kind: 'unanimity' }, { kind: 'quorum', k: 2 }, { kind: 'quorum', k: 3, vetoers: [members[0]] }, { kind: 'weighted', weights: Object.fromEntries(members.map((m, i) => [m, i + 1])), threshold: 5 }, { kind: 'quorum', k: 9 }, { kind: 'bogus' }];
const apprSets: any[][] = [[], [good[0]], [good[0], good[1]], [good[0], good[1], good[2]], good, [good[0], good[0], good[1]], [good[1], good[2]], [sign(memSeeds[0], { seq: 4 }), good[1]], [sign(memSeeds[0], { layer: 'task' }), good[1], good[2]],
  [{ ...good[0], sig: good[1].sig }, good[1]], [{ ...good[0], sig: 'x' }, good[1]], [{ ...good[0], sig: 5 }, good[1]], [{ ...good[0], v: 2 }, good[1]], [{ ...good[0], kind: 'other' }, good[1]], [{ ...good[0], signer: S('stranger') }, good[1]],
  [null, 0, '', 'x', 5, true, [], [1], {}, good[1]], [{ ...good[0], extra: 1 }, good[1]]];
for (const q of quorums) for (const as of apprSets) await run('verifyQuorumApprovals', LA.verifyQuorumApprovals, [as, members, q, exp]);
for (const ms of [members.slice(0, 2), [...members, members[0]], [...members, 'short'], [...members, 5], 'x', null]) await run('verifyQuorumApprovals', LA.verifyQuorumApprovals, [good, ms, { kind: 'quorum', k: 1 }, exp]);
for (const bad of [null, 5, 'x', [], { layer: 'org' }]) await run('verifyQuorumApprovals', LA.verifyQuorumApprovals, [good, members, { kind: 'quorum', k: 1 }, bad]);
await run('verifyQuorumApprovals', LA.verifyQuorumApprovals, ['x', members, { kind: 'quorum', k: 1 }, exp]);

// ---- metrics ----
const TRUTH = { predicates: [{ verb: 'stripe.refund', where: [amt('lte', 200)] }, { verb: 'gmail.send' }] };
const GR = [POL_A, POL_B, { predicates: [{ verb: '*', where: [amt('lte', 10)] }] }, { predicates: [] }, TRUTH];
for (const g of GR) {
  const omm = O.deriveOmega({ policies: [g, TRUTH] });
  await run('measureGrantExact', (omg: any, gg: any, tt: any) => ME.measureGrantExact(omg, gg, ME.acceptabilityOf(tt)), [omm, g, TRUTH]);
  for (const opts of [{ samples: 400 }, { samples: 250, seed: 7 }, { samples: 120, seed: 99, hMax: 50 }]) await run('measureGrant', (omg: any, gg: any, tt: any, oo: any) => ME.measureGrant(omg, gg, ME.acceptabilityOf(tt), oo), [omm, g, TRUTH, opts]);
}
refWrite(o, 'intent-layers');
