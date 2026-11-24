// Oracle (java extra): the wallet's default views over the intent learner (pca-wallet channel.ts learnerView, population.ts priorAdmittedPpm).
// Deterministic: omegas and observations are recorded in the args.
// PORTING (fn(args) -> native entry point, comparison rule; JSON value equality, doubles bit-exact):
//   view(omega, observations, ceiling) -> WalletLearner.learnerView(learner, insideCeiling): learner = IntentLearner(omega) after observe(outcome, y) for each
//     {verb, values, y}; ceiling null (no predicate) or k: inside iff idx[0] <= k. Output {cells: [[verb, idx, p, vetoed, outsideCeiling]] over every cell of every verb
//     in omega order, confirmed: [{verb, idx}]}; an unknown verb throws (probe: [verb, idx] -> p).
//   ppm(omega, options, observations, release, beta) -> WalletLearner.priorAdmittedPpm(omega, LearnerOptions.fromJson(options), observations, WalletPopulation.populationPrior(release, beta))
import * as L0 from '../../../packages/pca-intent/src/learner';
import * as O0 from '../../../packages/pca-intent/src/omega';
import * as W0 from '../../../packages/pca-wallet/src/index';
import { Oracle, refWrite } from './lib.mjs';

const L: any = (L0 as any).default ?? L0;
const O: any = (O0 as any).default ?? O0;
const W: any = (W0 as any).default ?? W0;
const o = new Oracle('wallet-learner-java', 'tools/pca-audit/oracles/wallet-learner-java.mts', 'TS-reference oracle for the wallet learner view.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);
const A = 'action.params.';
const num = (path: string, lo: number, hi: number, cuts: number[], dist = 'uniform') => ({ kind: 'num', path, lo, hi, cuts, dist });
const cat = (path: string, exacts: string[], prefixes: string[] = []) => ({ kind: 'cat', path, values: [...exacts.map((v) => ({ kind: 'exact', value: v })), ...prefixes.map((v) => ({ kind: 'prefix', value: v })), { kind: 'other', value: '⊥' }] });
const vsp = (verb: string, reversibility: string, weight: number, dims: any[]) => ({ verb, reversibility, weight, dims });
const omegaOf = (...verbs: any[]) => ({ v: 1, verbs, approximate: [] });
const refund = vsp('stripe.refund', 'irreversible', 1, [num(A + 'amount', 0, 100, [10, 50]), cat(A + 'recipient', ['bob'], ['team-'])]);
const send = vsp('gmail.send', 'rate_limited', 0.5, [cat(A + 'to', ['a', 'b'], ['p-'])]);
const OMS = [omegaOf(refund), omegaOf(refund, send)];
const ob = (verb: string, values: any, y: number) => ({ verb, values, y });
const R = (amount: number, recipient: string, y: number) => ob('stripe.refund', { [A + 'amount']: amount, [A + 'recipient']: recipient }, y);
const OBS: any[][] = [
  [],
  [R(5, 'bob', 1)],
  [R(5, 'bob', 1), R(30, 'bob', 1), R(80, 'team-x', 0)],
  [R(5, 'bob', 1), R(5, 'team-a', 1), R(60, 'bob', 0), R(60, 'zed', 0), R(30, 'bob', 1), R(5, 'zed', 1), R(90, 'bob', 1)],
  [R(5, 'bob', 0), R(5, 'bob', 1), R(5, 'bob', 0)],
  [R(5, 'bob', 1), ob('gmail.send', { [A + 'to']: 'a' }, 1), ob('gmail.send', { [A + 'to']: 'p-9' }, 0)],
];
const view = (omega: any, obs: any[], ceiling: number | null) => {
  const l = new L.IntentLearner(omega);
  for (const x of obs) l.observe({ verb: x.verb, values: x.values }, x.y);
  const v = W.learnerView(l, ceiling === null ? {} : { insideCeiling: (_verb: string, idx: number[]) => idx[0] <= ceiling });
  const cells: any[] = [];
  for (const vs of omega.verbs) {
    const t = O.verbCellCount(vs);
    for (let f = 0; f < t; f++) {
      const idx = O.decodeCell(vs, f);
      cells.push([vs.verb, idx, v.p(vs.verb, idx), v.vetoed(vs.verb, idx), v.outsideCeiling(vs.verb, idx)]);
    }
  }
  return { cells, confirmed: v.confirmed() };
};
for (const om of OMS) for (const obs of OBS) for (const c of [null, 0, 1]) await run('view', view, [om, obs, c]);
const probe = (omega: any, verb: string) => W.learnerView(new L.IntentLearner(omega)).p(verb, [0, 0]);
await run('probe', probe, [OMS[0], 'stripe.refund']);
await run('probe', probe, [OMS[0], 'no.such']);

// priorAdmittedPpm over a release of the stripe.refund cells
const SCHEMA = Buffer.alloc(32, 7).toString('base64url');
const rel = (qs: (c: number) => number) => {
  const vsR = refund;
  const cells: any = {};
  const t = O.verbCellCount(vsR);
  for (let c = 0; c < t; c++) cells[W.populationCellKey(SCHEMA, vsR, O.decodeCell(vsR, c))] = { q: qs(c), n: 100 };
  return { v: 1, kind: 'pca-intent-population-prior', schema: SCHEMA, period: 7, epsilon: 0.9, delta: 1e-5, sigma: 1, sensitivity: 8, cells };
};
const RELS = [rel((c) => 0.05 + 0.07 * c), rel(() => 0.9), rel((c) => (c % 2 ? 0.8 : 0.1)), { ...rel(() => 0.5), cells: {} }];
const ppm = (omega: any, options: any, observations: any[], release: any, beta: number) => {
  const base = { ...options };
  const l0 = observations.map((x) => ({ verb: x.verb, values: x.values, y: x.y, source: 'elicitation' }));
  return W.priorAdmittedPpm(omega, base, l0, W.populationPrior(release, beta));
};
for (const options of [{}, { tau: 1 }, { tau: 0.5 }, { tau: 0.8, eta: 0.1 }, { nullMass: 0.2 }]) for (const obs of OBS.slice(0, 5)) for (const r of RELS) for (const beta of [0, 0.3, 0.9]) await run('ppm', ppm, [OMS[0], options, obs, r, beta]);
await run('ppm', ppm, [OMS[0], {}, OBS[2], RELS[0], 0.95]);
refWrite(o, 'wallet-learner-java');
