// Oracle: @atlasauth/pca-intent multi-principal aggregation over Intent Maps (multi.ts: aggregateIntentMaps, combineIntentMaps, ruleOf, verifyAggregate,
// liftIntentMap, crossOrgAggregate, verifyCrossOrgAggregate, omegaKey). Deterministic.
// PORTING (fn(args) -> native entry point, comparison rule; JSON value equality):
//   aggregateScenario(omega, principals[{ref, policy, observations}], rule, orgs, mapOpts) -> {aggregate, digest, rule: ruleOf(aggregate), verify: verifyAggregate(aggregate, maps),
//     tampered[]: verifyAggregate over fixed mutations of the aggregate, wrongInputs: verifyAggregate(aggregate, maps without the last)}
//     maps = createLearner + observe + emitIntentMap(l, ref) per principal (IntentMapKit); aggregate = IntentMultiAgg.aggregateIntentMaps(maps, rule, orgs).
//     Problem strings: "replay failed: <text>" is compared as "replay failed"; a "recompute failed: <text>" whose text is not a reference-defined
//     message (prefixes aggregateIntentMaps / ruleOf / liftIntentMap / crossOrgAggregate / commonRefinement / pca-intent / refineOmega) is compared as "recompute failed: error".
//   aggregateTwoOmegas(omegaA, omegaB, principals, rule): aggregate [map over omegaA with principal 0's observations, map over omegaB with none] (throws: different spaces)
//   aggregateOfAggregate(omega, principals, rule): aggregate of [aggregate of all maps, first map] (throws); 
//   liftOfAggregate(omega, principals, rule): liftIntentMap(aggregate of the first map only, omega) (throws)
//   crossScenario(specs[{omega, ref, policy, observations, mapOpts}], rule, orgs) -> {aggregate, lifted, omega, digest, verify: verifyCrossOrgAggregate(aggregate, maps), tampered}
//   liftScenario(omega, mapOpts, observations, ref, targetOmega) -> liftIntentMap result
//   omegaKey(omega)
import * as MU0 from '../../../packages/pca-intent/src/multi';
import * as M0 from '../../../packages/pca-intent/src/map';
import * as O0 from '../../../packages/pca-intent/src/omega';
import * as P0 from '../../../packages/pca-intent/src/policy';
import { Oracle, refWrite } from './lib.mjs';

const MU: any = (MU0 as any).default ?? MU0;
const M: any = (M0 as any).default ?? M0;
const O: any = (O0 as any).default ?? O0;
const P: any = (P0 as any).default ?? P0;
const o = new Oracle('intent-multi-agg', 'tools/pca-audit/oracles/intent-multi-agg.mts', 'TS-reference oracle for multi-principal intent aggregation.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);

const A = 'action.params.';
const num = (path: string, lo: number, hi: number, cuts: number[], dist = 'uniform') => ({ kind: 'num', path, lo, hi, cuts, dist });
const cat = (path: string, exacts: string[], prefixes: string[] = []) => ({ kind: 'cat', path, values: [...exacts.map((v) => ({ kind: 'exact', value: v })), ...prefixes.map((v) => ({ kind: 'prefix', value: v })), { kind: 'other', value: '⊥' }] });
const vsp = (verb: string, reversibility: string, weight: number, dims: any[]) => ({ verb, reversibility, weight, dims });
const omegaOf = (...verbs: any[]) => ({ v: 1, verbs, approximate: [] });
const refund = vsp('stripe.refund', 'irreversible', 1, [num(A + 'amount', 0, 100, [10, 50]), cat(A + 'recipient', ['bob'], ['team-'])]);
const refund2 = vsp('stripe.refund', 'rate_limited', 1, [num(A + 'amount', 0, 100, [20]), cat(A + 'recipient', ['alice'])]);
const refundBad = vsp('stripe.refund', 'irreversible', 1, [num(A + 'amount', 0, 200, [20]), cat(A + 'recipient', ['alice'])]);
const refundCat = vsp('stripe.refund', 'irreversible', 1, [cat(A + 'amount', ['x']), cat(A + 'recipient', ['alice'])]);
const send = vsp('gmail.send', 'rate_limited', 0.5, [cat(A + 'to', ['a', 'b'], ['p-'])]);
const note = vsp('notes.add', 'reversible', 1, [num(A + 'n', 0, 5, [2])]);
const OA = omegaOf(refund);
const w = (field: string, op: string, value: any) => ({ field, op, value });
const pol = (...ps: any[]) => ({ predicates: ps, caveats: [] });
const polRefund = (max: number, who?: string[]) => pol({ verb: 'stripe.refund', resource: '*', where: [w(A + 'amount', 'lte', max), ...(who ? [w(A + 'recipient', 'in', who)] : [])] });
const allCells = (vs: any): number[][] => { const t = O.verbCellCount(vs); const r: number[][] = []; for (let f = 0; f < t; f++) r.push(O.decodeCell(vs, f)); return r; };
let st = 99;
const rnd = () => { st = (st * 1103515245 + 12345) & 0x7fffffff; return st / 0x7fffffff; };
function obsFor(omega: any, policy: any, nObs: number): any[] {
  const adm = P.admitter(policy); const out: any[] = [];
  for (let i = 0; i < nObs; i++) {
    const vs = omega.verbs[Math.floor(rnd() * omega.verbs.length)];
    const cells = allCells(vs); const idx = cells[Math.floor(rnd() * cells.length)];
    const oc = O.cellRep(vs, idx);
    out.push({ verb: vs.verb, values: oc.values, y: adm.admits(vs, oc) ? 1 : 0, source: i % 4 === 3 ? 'runtime' : 'elicitation' });
  }
  return out;
}
const REF = (c: string) => c.repeat(43);
const buildMap = (omega: any, mapOpts: any, observations: any[], ref: string | null) => { const l = M.createLearner(omega, mapOpts); for (const x of observations) l.observe({ verb: x.verb, values: x.values }, x.y, x.source, x.region); return M.emitIntentMap(l, ref); };
const clone = (x: any) => JSON.parse(JSON.stringify(x));
const norm = (r: any) => ({ ok: r.ok, problems: r.problems.map((p: string) => {
  let q = p.replace(/replay failed: [^;]*/g, 'replay failed');
  const m = /^recompute failed: (.*)$/s.exec(q);
  if (m && !/^(aggregateIntentMaps|ruleOf|liftIntentMap|crossOrgAggregate|commonRefinement|pca-intent|refineOmega)/.test(m[1])) q = 'recompute failed: error';
  else if (!m && !/^(input |aggregate does not|recompute failed)/.test(q) && !/^replay failed/.test(q)) q = /^(aggregateIntentMaps|ruleOf|liftIntentMap|crossOrgAggregate|commonRefinement|pca-intent|refineOmega)/.test(q) ? q : 'error';
  return q;
}) });
const muts: ((m: any) => any)[] = [(m) => m, (m) => { m.metrics.residual_risk_ppm += 7; return m; }, (m) => { m.cells[0].in_grant = !m.cells[0].in_grant; return m; }, (m) => { m.aggregation = null; return m; }, (m) => { m.aggregation.rule = 'quorum'; m.aggregation.k = 1; return m; }, (m) => { m.aggregation.vetoers = []; return m; }];

function aggregateScenario(omega: any, principals: any[], rule: any, orgs: any, mapOpts: any): any {
  const maps = principals.map((p) => buildMap(omega, mapOpts, p.observations, p.ref));
  const agg = MU.aggregateIntentMaps(maps, rule, orgs ?? {});
  const tampered = muts.map((f) => norm(MU.verifyAggregate(f(clone(agg)), maps, orgs ?? {})));
  return { aggregate: agg, digest: M.intentMapDigest(agg), rule: MU.ruleOf(agg), verify: norm(MU.verifyAggregate(agg, maps, orgs ?? {})), tampered, wrongInputs: norm(MU.verifyAggregate(agg, maps.slice(0, -1), orgs ?? {})), combined: rule.kind === 'unanimity' && !rule.vetoers ? MU.combineIntentMaps(maps, orgs ?? {}) : null };
}
const P3 = [{ ref: REF('a'), policy: polRefund(50, ['bob']), observations: obsFor(OA, polRefund(50, ['bob']), 8) }, { ref: REF('b'), policy: polRefund(10), observations: obsFor(OA, polRefund(10), 8) }, { ref: REF('c'), policy: polRefund(100, ['bob']), observations: obsFor(OA, polRefund(100, ['bob']), 8) }];
const rules: any[] = [
  { kind: 'unanimity' }, { kind: 'unanimity', vetoers: [REF('a')] }, { kind: 'unanimity', vetoers: [] }, { kind: 'unanimity', vetoers: ['zzz'] },
  { kind: 'quorum', k: 1 }, { kind: 'quorum', k: 2 }, { kind: 'quorum', k: 3 }, { kind: 'quorum', k: 2, vetoers: [REF('b')] }, { kind: 'quorum', k: 0 }, { kind: 'quorum', k: 4 }, { kind: 'quorum', k: 1.5 },
  { kind: 'weighted', weights: { [REF('a')]: 2, [REF('b')]: 1, [REF('c')]: 1 }, threshold: 3 }, { kind: 'weighted', weights: { [REF('a')]: 2, [REF('b')]: 1, [REF('c')]: 1 }, threshold: 2, vetoers: [REF('c')] },
  { kind: 'weighted', weights: { [REF('a')]: 5, [REF('b')]: 0, [REF('c')]: 1 }, threshold: 5 }, { kind: 'weighted', weights: { [REF('a')]: 1, [REF('b')]: 1, [REF('c')]: 1 }, threshold: 4 }, { kind: 'weighted', weights: { [REF('a')]: 1, [REF('b')]: -1, [REF('c')]: 1 }, threshold: 1 },
  { kind: 'weighted', weights: { [REF('a')]: 1, [REF('b')]: 1.5, [REF('c')]: 1 }, threshold: 1 }, { kind: 'weighted', weights: { [REF('a')]: 1, [REF('c')]: 1 }, threshold: 1 }, { kind: 'weighted', weights: { [REF('a')]: 1, [REF('b')]: 1, [REF('c')]: 1 }, threshold: 0 },
];
for (const rule of rules) {
  await run('aggregateScenario', aggregateScenario, [OA, P3, rule, null, {}]);
  await run('aggregateScenario', aggregateScenario, [OA, P3, rule, { [REF('a')]: 'org-a', [REF('b')]: '' }, { eta: 0.1 }]);
}
await run('aggregateScenario', aggregateScenario, [OA, P3.slice(0, 1), { kind: 'unanimity' }, null, {}]);
await run('aggregateScenario', aggregateScenario, [OA, [], { kind: 'unanimity' }, null, {}]);
await run('aggregateScenario', aggregateScenario, [OA, [P3[0], { ...P3[1], ref: P3[0].ref }], { kind: 'unanimity' }, null, {}]);
await run('aggregateScenario', aggregateScenario, [OA, [P3[0], { ...P3[1], ref: null }], { kind: 'unanimity' }, null, {}]);
await run('aggregateScenario', aggregateScenario, [OA, P3, { kind: 'quorum', k: 2 }, null, { hypothesisClass: { kind: 'union', k: 2 } }]);
await run('aggregateScenario', aggregateScenario, [OA, [{ ref: REF('a'), policy: polRefund(50), observations: [] }, { ref: REF('b'), policy: polRefund(10), observations: [] }], { kind: 'unanimity' }, null, {}]);
const OB = omegaOf(refund, send);
const PB = [{ ref: REF('a'), policy: pol({ verb: 'stripe.refund', resource: '*', where: [w(A + 'amount', 'lte', 10)] }, { verb: 'gmail.send', resource: '*', where: [w(A + 'to', 'prefix', 'p-')] }), observations: [] }, { ref: REF('b'), policy: pol({ verb: 'gmail.send', resource: '*', where: [w(A + 'to', 'prefix', 'p-')] }), observations: [] }];
for (const p of PB) p.observations = obsFor(OB, p.policy, 10);
for (const rule of [{ kind: 'unanimity' }, { kind: 'quorum', k: 1 }]) await run('aggregateScenario', aggregateScenario, [OB, PB, rule, null, { strategy: 'risk' }]);
// maps over differing omega -> error; an aggregated map as an input -> error
await run('aggregateTwoOmegas', (o1: any, o2: any, ps: any[], rule: any) => MU.aggregateIntentMaps([buildMap(o1, {}, ps[0].observations, ps[0].ref), buildMap(o2, {}, [], ps[1].ref)], rule), [OA, omegaOf(refund2), P3, { kind: 'unanimity' }]);
await run('aggregateOfAggregate', (omega: any, ps: any[], rule: any) => { const maps = ps.map((p: any) => buildMap(omega, {}, p.observations, p.ref)); const agg = MU.aggregateIntentMaps(maps, rule); return MU.aggregateIntentMaps([agg, maps[0]], rule); }, [OA, P3, { kind: 'unanimity' }]);
await run('liftOfAggregate', (omega: any, ps: any[], rule: any) => { const maps = ps.map((p: any) => buildMap(omega, {}, p.observations, p.ref)); const agg = MU.aggregateIntentMaps(maps.slice(0, 1), rule); return MU.liftIntentMap(agg, omega); }, [OA, P3, { kind: 'unanimity' }]);

// ---- cross-org ----
function crossScenario(specs: any[], rule: any, orgs: any): any {
  const maps = specs.map((s) => buildMap(s.omega, s.mapOpts ?? {}, s.observations, s.ref));
  const r = MU.crossOrgAggregate(maps, rule, orgs ?? {});
  const tampered = muts.map((f) => norm(MU.verifyCrossOrgAggregate(f(clone(r.aggregate)), maps, orgs ?? {})));
  return { aggregate: r.aggregate, lifted: r.lifted, omega: r.omega, digest: M.intentMapDigest(r.aggregate), verify: norm(MU.verifyCrossOrgAggregate(r.aggregate, maps, orgs ?? {})), tampered, wrong: norm(MU.verifyCrossOrgAggregate(r.aggregate, maps.slice(1), orgs ?? {})) };
}
const OA2 = omegaOf(refund2), OC = omegaOf({ ...refund2, weight: 0.5 }, send), OD = omegaOf(note), OBad = omegaOf(refundBad), OCat = omegaOf(refundCat);
const spec = (omega: any, ref: string, policy: any, nObs: number, mapOpts: any = {}) => ({ omega, ref, policy, observations: obsFor(omega, policy, nObs), mapOpts });
const pAny = (omega: any) => pol(...omega.verbs.map((v: any) => ({ verb: v.verb, resource: '*', where: v.verb === 'stripe.refund' ? [w(A + 'amount', 'lte', 20)] : v.verb === 'gmail.send' ? [w(A + 'to', 'prefix', 'p-')] : [w(A + 'n', 'lte', 2)] })));
for (const rule of [{ kind: 'unanimity' }, { kind: 'quorum', k: 1 }, { kind: 'unanimity', vetoers: [REF('a')] }]) {
  await run('crossScenario', crossScenario, [[spec(OA, REF('a'), polRefund(50, ['bob']), 6), spec(OA2, REF('b'), polRefund(20, ['alice']), 6)], rule, { [REF('a')]: 'org1' }]);
  await run('crossScenario', crossScenario, [[spec(OA, REF('a'), polRefund(50), 5), spec(OC, REF('b'), pAny(OC), 6), spec(OD, REF('c'), pAny(OD), 4)], rule, null]);
}
await run('crossScenario', crossScenario, [[spec(OA, REF('a'), polRefund(50), 5, { eta: 0.1 }), spec(OA2, REF('b'), polRefund(20), 5, { eta: 0.1 })], { kind: 'quorum', k: 2 }, null]);
await run('crossScenario', crossScenario, [[spec(OA, REF('a'), polRefund(50), 5), spec(OBad, REF('b'), polRefund(20), 5)], { kind: 'unanimity' }, null]);
await run('crossScenario', crossScenario, [[spec(OA, REF('a'), polRefund(50), 5), spec(OCat, REF('b'), polRefund(20), 0)], { kind: 'unanimity' }, null]);
await run('crossScenario', crossScenario, [[spec(OA, REF('a'), polRefund(50), 3), spec(OA, REF('a'), polRefund(20), 3)], { kind: 'unanimity' }, null]);
await run('crossScenario', crossScenario, [[], { kind: 'unanimity' }, null]);
await run('crossScenario', (specs: any[], rule: any) => { const maps = specs.map((s) => buildMap(s.omega, {}, s.observations, s.ref)); maps[0].metrics.residual_risk_ppm += 9; return MU.crossOrgAggregate(maps, rule); }, [[spec(OA, REF('a'), polRefund(50), 4), spec(OA2, REF('b'), polRefund(20), 4)], { kind: 'unanimity' }]);

// ---- lift ----
const target = MU.commonRefinement([OA, OC, OD]);
for (const [om, pl, no] of [[OA, polRefund(50, ['bob']), 6], [OA2, polRefund(20), 6], [OC, pAny(OC), 6], [OA, polRefund(50), 0]] as any[]) {
  await run('liftScenario', (omega: any, mo: any, obs: any[], ref: string, tg: any) => MU.liftIntentMap(buildMap(omega, mo, obs, ref), tg), [om, {}, obsFor(om, pl, no), REF('x'), target]);
  await run('liftScenario', (omega: any, mo: any, obs: any[], ref: string, tg: any) => MU.liftIntentMap(buildMap(omega, mo, obs, ref), tg), [om, { eta: 0.1, nullMass: { 'stripe.refund': 0.4 } }, obsFor(om, pl, no), REF('y'), target]);
}
await run('liftScenario', (omega: any, mo: any, obs: any[], ref: string, tg: any) => MU.liftIntentMap(buildMap(omega, mo, obs, ref), tg), [OA, {}, obsFor(OA, polRefund(50), 3), REF('z'), OD]);
await run('liftScenario', (omega: any, mo: any, obs: any[], ref: string, tg: any) => MU.liftIntentMap(buildMap(omega, mo, obs, ref), tg), [OA, {}, obsFor(OA, polRefund(50), 3), REF('z'), omegaOf(refundBad)]);
// omegaKey
for (const om of [OA, OB, OC, target, { v: 1, verbs: [], approximate: [] }]) await run('omegaKey', MU.omegaKey, [om]);
refWrite(o, 'intent-multi-agg');
