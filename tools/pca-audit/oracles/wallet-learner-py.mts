// Oracle: @atlasauth/pca-wallet over an intent learner: learnerView (channel.ts) and priorAdmittedPpm with a released population prior (population.ts). Deterministic.
// PORTING (fn(args) -> native entry point, comparison rule; JSON value equality, doubles compared to 1e-12 relative):
//   viewScenario(omega, mapOpts, observations, ceiling, probes[{verb, idx}]) -> {probes: [[p, vetoed, outsideCeiling]], confirmed}
//     learner = IntentMapKit.createLearner + observe each; view = learnerView(l, ceiling == "none" ? {} : {insideCeiling}); ceiling "all" = every cell inside, "idx0" = idx[0] === 0, "never" = nothing inside
//   viewUnknownVerb(omega, verb, idx)         -> throws: learnerView over a verb the learner does not know
//   priorScenario(omega, baseOpts, observations, beta, schema, qOf) -> priorAdmittedPpm(omega, baseOpts, observations, populationPrior(release, beta)); the release holds a cell
//     key for every flat cell c of every verb with q = 0.05 + 0.04 * (c % qOf) (clamped to [0.02, 0.98])
import * as W0 from '../../../packages/pca-wallet/src/index';
import * as M0 from '../../../packages/pca-intent/src/map';
import * as O0 from '../../../packages/pca-intent/src/omega';
import * as P0 from '../../../packages/pca-intent/src/policy';
import { Oracle, refWrite } from './lib.mjs';
import { sha256 } from '@noble/hashes/sha2';

const W: any = (W0 as any).default ?? W0;
const M: any = (M0 as any).default ?? M0;
const O: any = (O0 as any).default ?? O0;
const P: any = (P0 as any).default ?? P0;
const o = new Oracle('wallet-learner-py', 'tools/pca-audit/oracles/wallet-learner-py.mts', 'TS-reference oracle for the wallet over an intent learner.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);
const dig = (x: string) => Buffer.from(sha256(new TextEncoder().encode(x))).toString('base64url');

const A = 'action.params.';
const num = (path: string, lo: number, hi: number, cuts: number[], dist = 'uniform') => ({ kind: 'num', path, lo, hi, cuts, dist });
const cat = (path: string, exacts: string[], prefixes: string[] = []) => ({ kind: 'cat', path, values: [...exacts.map((v) => ({ kind: 'exact', value: v })), ...prefixes.map((v) => ({ kind: 'prefix', value: v })), { kind: 'other', value: '⊥' }] });
const vsp = (verb: string, reversibility: string, weight: number, dims: any[]) => ({ verb, reversibility, weight, dims });
const omegaOf = (...verbs: any[]) => ({ v: 1, verbs, approximate: [] });
const refund = vsp('stripe.refund', 'irreversible', 1, [num(A + 'amount', 0, 100, [10, 50]), cat(A + 'recipient', ['bob'], ['team-'])]);
const send = vsp('gmail.send', 'rate_limited', 0.5, [cat(A + 'to', ['a', 'b'], ['p-'])]);
const OA = omegaOf(refund), OB = omegaOf(refund, send);
const w = (field: string, op: string, value: any) => ({ field, op, value });
const POLA = { predicates: [{ verb: 'stripe.refund', resource: '*', where: [w(A + 'amount', 'lte', 50), w(A + 'recipient', 'in', ['bob'])] }], caveats: [] };
let st = 5;
const rnd = () => { st = (st * 1103515245 + 12345) & 0x7fffffff; return st / 0x7fffffff; };
const allCells = (vs: any): number[][] => { const t = O.verbCellCount(vs); const r: number[][] = []; for (let f = 0; f < t; f++) r.push(O.decodeCell(vs, f)); return r; };
function obsFor(omega: any, policy: any, nObs: number, runtimeEvery = 0): any[] {
  const adm = P.admitter(policy); const out: any[] = [];
  for (let i = 0; i < nObs; i++) {
    const vs = omega.verbs[Math.floor(rnd() * omega.verbs.length)];
    const cells = allCells(vs); const idx = cells[Math.floor(rnd() * cells.length)];
    const oc = O.cellRep(vs, idx);
    out.push({ verb: vs.verb, values: oc.values, y: adm.admits(vs, oc) ? 1 : 0, source: runtimeEvery && i % runtimeEvery === runtimeEvery - 1 ? 'runtime' : 'elicitation' });
  }
  return out;
}
const mk = (omega: any, mo: any, obs: any[]) => { const l = M.createLearner(omega, mo); for (const x of obs) l.observe({ verb: x.verb, values: x.values }, x.y, x.source); return l; };
const ceilings: Record<string, any> = { all: () => true, idx0: (_v: string, idx: number[]) => idx[0] === 0, never: () => false };
const viewScenario = (omega: any, mo: any, obs: any[], ceiling: string, probes: any[]) => {
  const l = mk(omega, mo, obs);
  const view = W.learnerView(l, ceiling === 'none' ? {} : { insideCeiling: ceilings[ceiling] });
  return { probes: probes.map((p) => [view.p(p.verb, p.idx), view.vetoed(p.verb, p.idx), view.outsideCeiling(p.verb, p.idx)]), confirmed: view.confirmed() };
};
const probesOf = (omega: any) => omega.verbs.flatMap((vs: any) => allCells(vs).map((idx) => ({ verb: vs.verb, idx })));
for (const [om, mo, nObs, rt] of [[OA, {}, 6, 0], [OA, {}, 9, 3], [OB, { eta: 0.1 }, 8, 4], [OB, { tau: 0.7 }, 5, 0], [OA, {}, 0, 0]] as any[]) for (const ceiling of ['none', 'all', 'idx0', 'never'])
  await run('viewScenario', viewScenario, [om, mo, obsFor(om, om === OA ? POLA : POLA, nObs, rt), ceiling, probesOf(om)]);
await run('viewUnknownVerb', (omega: any, verb: string, idx: number[]) => W.learnerView(mk(omega, {}, [])).p(verb, idx), [OA, 'nope', [0, 0]]);

const SCHEMA = dig('schema');
const priorScenario = (omega: any, base: any, obs: any[], beta: number, schema: string, qOf: number, hi = false) => {
  const cells: any = {};
  for (const vs of omega.verbs) for (let c = 0; c < O.verbCellCount(vs); c++) cells[W.populationCellKey(schema, vs, O.decodeCell(vs, c))] = { q: Math.min(0.98, Math.max(0.02, hi ? 0.98 - 0.04 * (c % qOf) : 0.05 + 0.04 * (c % qOf))), n: 50 };
  const rel = { v: 1, kind: 'pca-intent-population-prior', schema, period: 1, epsilon: 0.9, delta: 1e-5, sigma: 1, sensitivity: 8, cells };
  return W.priorAdmittedPpm(omega, base, obs, W.populationPrior(rel, beta));
};
for (const [om, nObs] of [[OA, 3], [OA, 7], [OB, 5]] as any[]) for (const base of [{}, { tau: 0.6 }, { tau: 0.3, nullMass: 0.1 }, { tau: 0.15, nullMass: 0 }, { eta: 0.1, tau: 0.8 }, { hypothesisClass: { kind: 'union', k: 2 }, tau: 0.5 }]) for (const beta of [0, 0.5, 0.9]) for (const qOf of [3, 11]) for (const hi of [false, true])
  await run('priorScenario', priorScenario, [om, base, obsFor(om, POLA, nObs), beta, SCHEMA, qOf, hi]);
await run('priorScenario', priorScenario, [OA, {}, [], 1, SCHEMA, 3]);
await run('priorScenario', priorScenario, [OA, {}, [], 0.5, 'nope', 3]);
refWrite(o, 'wallet-learner-py');
