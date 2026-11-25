// Oracle: @atlasauth/pca-intent learner feedback glue: verifyOutcome (effects.ts), applyFrameReport (frames.ts), orgLayerFromMaps (layers.ts). Deterministic.
// PORTING (fn(args) -> native entry point, comparison rule; JSON value equality, doubles compared to 1e-12 relative):
//   verifyScenario(omega, mapOpts, observations, outcome, effect, pcs|null) -> {result: verifyOutcome(l, o, effect, pcs ?? default), vetoed: l.vetoedCells(), metrics: l.metrics(), observations}
//   frameScenario(omega, mapOpts, observations, outcome, report) -> {result: applyFrameReport(l, o, report), vetoed, metrics, observations}
//   orgScenario(omega, principals[{ref, policy, observations}], rule, mapOpts) -> orgLayerFromMaps(maps, rule) = {map, policy}
import * as EF0 from '../../../packages/pca-intent/src/effects';
import * as FR0 from '../../../packages/pca-intent/src/frames';
import * as LA0 from '../../../packages/pca-intent/src/layers';
import * as M0 from '../../../packages/pca-intent/src/map';
import * as O0 from '../../../packages/pca-intent/src/omega';
import { Oracle, refWrite } from './lib.mjs';

const EF: any = (EF0 as any).default ?? EF0;
const FR: any = (FR0 as any).default ?? FR0;
const LA: any = (LA0 as any).default ?? LA0;
const M: any = (M0 as any).default ?? M0;
const O: any = (O0 as any).default ?? O0;
const o = new Oracle('intent-glue-py', 'tools/pca-audit/oracles/intent-glue-py.mts', 'TS-reference oracle for outcome verification, frame reports and org layers fed by the learner.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);

const A = 'action.params.';
const num = (path: string, lo: number, hi: number, cuts: number[], dist = 'uniform') => ({ kind: 'num', path, lo, hi, cuts, dist });
const cat = (path: string, exacts: string[], prefixes: string[] = []) => ({ kind: 'cat', path, values: [...exacts.map((v) => ({ kind: 'exact', value: v })), ...prefixes.map((v) => ({ kind: 'prefix', value: v })), { kind: 'other', value: '⊥' }] });
const vsp = (verb: string, reversibility: string, weight: number, dims: any[]) => ({ verb, reversibility, weight, dims });
const omegaOf = (...verbs: any[]) => ({ v: 1, verbs, approximate: [] });
const refund = vsp('stripe.refund', 'irreversible', 1, [num(A + 'amount', 0, 100, [10, 50]), cat(A + 'recipient', ['bob'], ['team-'])]);
const send = vsp('gmail.send', 'rate_limited', 0.5, [cat(A + 'to', ['a', 'b'], ['p-'])]);
const OA = omegaOf(refund);
const OB = omegaOf(refund, send);
const w = (field: string, op: string, value: any) => ({ field, op, value });
const pol = (...ps: any[]) => ({ predicates: ps, caveats: [] });
const polRefund = (max: number) => pol({ verb: 'stripe.refund', resource: '*', where: [w(A + 'amount', 'lte', max), w(A + 'recipient', 'in', ['bob'])] });
const allCells = (vs: any): number[][] => { const t = O.verbCellCount(vs); const r: number[][] = []; for (let f = 0; f < t; f++) r.push(O.decodeCell(vs, f)); return r; };
let st = 31;
const rnd = () => { st = (st * 1103515245 + 12345) & 0x7fffffff; return st / 0x7fffffff; };
function obsFor(omega: any, policy: any, nObs: number): any[] {
  const out: any[] = [];
  for (let i = 0; i < nObs; i++) {
    const vs = omega.verbs[Math.floor(rnd() * omega.verbs.length)];
    const cells = allCells(vs); const idx = cells[Math.floor(rnd() * cells.length)];
    const oc = O.cellRep(vs, idx);
    out.push({ verb: vs.verb, values: oc.values, y: i % 2, source: i % 4 === 3 ? 'runtime' : 'elicitation' });
  }
  return out;
}
const mk = (omega: any, mo: any, obs: any[]) => { const l = M.createLearner(omega, mo); for (const x of obs) l.observe({ verb: x.verb, values: x.values }, x.y, x.source, x.region); return l; };
const REF = (c: string) => c.repeat(43);
const tail = (l: any) => ({ vetoed: l.vetoedCells(), metrics: l.metrics(), observations: l.observations });

// ---- verifyOutcome ----
const eff = (f: string) => 'env.effect.' + f;
const customPcs = [
  { id: 'c.amount', verb: 'stripe.refund', description: 'amount in range', where: [{ all_of: [w(eff('amount'), 'lte', 10), { not: w(eff('recipient'), 'eq', 'zz') }] }] },
  { id: 'c.any', verb: 'stripe.refund', description: 'either', where: [{ any_of: [w(eff('amount'), 'gte', 0), w(eff('fee'), 'lte', 3)] }] },
  { id: 'c.other', verb: 'gmail.send', description: 'other verb', where: [w(eff('to'), 'eq', 'a')] },
];
const verifyScenario = (omega: any, mo: any, obs: any[], oc: any, effect: any, pcs: any) => {
  const l = mk(omega, mo, obs);
  const result = EF.verifyOutcome(l, oc, effect, pcs ?? undefined);
  return { result, ...tail(l) };
};
const outs = [O.cellRep(refund, [0, 0]), O.cellRep(refund, [1, 1]), O.cellRep(refund, [2, 2]), O.cellRep(refund, [3, 0]), O.cellRep(send, [1])];
const effects = [{ amount: 1, recipient: 'bob' }, { amount: 9999, recipient: 'bob' }, {}, { amount: 5 }, { recipient: 'mallory', amount: 0 }, { amount: -1, recipient: 'x' }, { amount: 0, recipient: 'team-x' }, { to: 'a' }, { to: 'z' }, { fee: 2 }, { amount: 7, fee: 9, recipient: 'bob' }];
for (const oc of outs) for (const effect of effects) {
  await run('verifyScenario', verifyScenario, [OB, {}, obsFor(OB, null, 6), oc, effect, null]);
}
for (const oc of outs.slice(0, 3)) for (const effect of effects.slice(0, 5)) {
  await run('verifyScenario', verifyScenario, [OA, { eta: 0.1 }, obsFor(OA, null, 5), oc, effect, customPcs]);
  await run('verifyScenario', verifyScenario, [OB, {}, [], oc, effect, []]);
}
await run('verifyScenario', verifyScenario, [OB, {}, obsFor(OB, null, 4), { verb: 'nope', values: {} }, {}, null]);
// the violated veto holds: a later yes does not re-admit
await run('verifyScenario', (omega: any, mo: any, obs: any[], oc: any, effect: any) => { const l = mk(omega, mo, obs); const r = EF.verifyOutcome(l, oc, effect); l.observe(oc, 1, 'elicitation'); return { r, ...tail(l), again: l.admitsOutcome(oc) }; }, [OA, {}, obsFor(OA, null, 3), outs[1], { amount: 9999, recipient: 'bob' }]);

// ---- applyFrameReport ----
const frameScenario = (omega: any, mo: any, obs: any[], oc: any, report: any) => { const l = mk(omega, mo, obs); const result = FR.applyFrameReport(l, oc, report); return { result, ...tail(l) }; };
const reports: any[] = [{ status: 'violated', outOfFrame: ['x'], missing: [], postViolated: [], attributed: [], checked: [] }, { status: 'ok' }, { status: 'pending' }, { status: 'violated' }, null, 'violated', 5, [], {}, { status: 'VIOLATED' }, { status: ['violated'] }];
for (const oc of outs.slice(0, 4)) for (const r of reports) await run('frameScenario', frameScenario, [OB, {}, obsFor(OB, null, 6), oc, r]);
await run('frameScenario', frameScenario, [OB, { eta: 0.1 }, obsFor(OB, null, 6), outs[0], reports[0]]);
await run('frameScenario', frameScenario, [OA, {}, [], { verb: 'nope', values: {} }, reports[0]]);

// ---- orgLayerFromMaps ----
const orgScenario = (omega: any, principals: any[], rule: any, mo: any) => {
  const maps = principals.map((p) => M.emitIntentMap(mk(omega, mo, p.observations), p.ref));
  return LA.orgLayerFromMaps(maps, rule);
};
const P3 = [{ ref: REF('a'), observations: obsFor(OA, null, 7) }, { ref: REF('b'), observations: obsFor(OA, null, 7) }, { ref: REF('c'), observations: obsFor(OA, null, 7) }];
for (const rule of [{ kind: 'unanimity' }, { kind: 'quorum', k: 2 }, { kind: 'quorum', k: 5 }, { kind: 'weighted', weights: { [REF('a')]: 2, [REF('b')]: 1, [REF('c')]: 1 }, threshold: 3 }, { kind: 'unanimity', vetoers: ['zzz'] }]) {
  await run('orgScenario', orgScenario, [OA, P3, rule, {}]);
  await run('orgScenario', orgScenario, [OA, P3.slice(0, 2), rule, { eta: 0.1 }]);
}
await run('orgScenario', orgScenario, [OB, P3.map((p) => ({ ...p, observations: obsFor(OB, null, 6) })), { kind: 'quorum', k: 2 }, { strategy: 'risk' }]);
await run('orgScenario', orgScenario, [OA, [], { kind: 'unanimity' }, {}]);
await run('orgScenario', orgScenario, [OA, [P3[0], { ...P3[1], ref: P3[0].ref }], { kind: 'unanimity' }, {}]);
refWrite(o, 'intent-glue-py');
