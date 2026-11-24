// Oracle: @atlasauth/pca-intent cut refinement and partial answers (refine.ts). Deterministic.
// PORTING (fn(args) -> native entry point, comparison rule; JSON value equality, doubles bit-exact):
//   refineOmega(omega, refinement) -> Omega JSON (IntentRefine.refineOmega)
//   regionsOf(omega, mapOpts, observations, empty) -> [regionOfObservation(empty ? omega with no verbs : l.omega, o)] over the learner's recorded observations
//   refineScenario(omega, mapOpts, observations, refinement) -> {omega, observations, metrics, cells}: IntentMapKit.createLearner, observe each,
//     refineLearner(l, r) (no rescope), then the new learner's omega JSON / observations JSON / metrics / cells ({verb, cell, p})
//   partialScenario(omega, mapOpts, observations, q: {verb, cell}, partial) -> {omega, added, observations, metrics, synth}: answerPartial(l, question, partial)
//     with question = {verb, cell, outcome: cellRep, p: acceptance, score: 0}
//   adaptiveScenario(omega, mapOpts, policy, partials, partialEvery, opts) -> elicitAdaptive: answer(q, l) = the k-th partial answer on every partialEvery-th
//     question while partials remain and the question is about stripe.refund, else 1/0 = admitter(policy).admits(vs of l.omega, q.outcome); opts {epsRisk, epsBurden, maxQuestions, audit?, seed?, maxRefinements?}
import * as R0 from '../../../packages/pca-intent/src/refine';
import * as M0 from '../../../packages/pca-intent/src/map';
import * as O0 from '../../../packages/pca-intent/src/omega';
import * as P0 from '../../../packages/pca-intent/src/policy';
import { Oracle, refWrite } from './lib.mjs';

const R: any = (R0 as any).default ?? R0;
const M: any = (M0 as any).default ?? M0;
const O: any = (O0 as any).default ?? O0;
const P: any = (P0 as any).default ?? P0;
const o = new Oracle('intent-refine', 'tools/pca-audit/oracles/intent-refine.mts', 'TS-reference oracle for cut refinement and partial answers.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);

const A = 'action.params.';
const num = (path: string, lo: number, hi: number, cuts: number[], dist = 'uniform') => ({ kind: 'num', path, lo, hi, cuts, dist });
const cat = (path: string, exacts: string[], prefixes: string[] = []) => ({ kind: 'cat', path, values: [...exacts.map((v) => ({ kind: 'exact', value: v })), ...prefixes.map((v) => ({ kind: 'prefix', value: v })), { kind: 'other', value: '⊥' }] });
const vsp = (verb: string, reversibility: string, weight: number, dims: any[]) => ({ verb, reversibility, weight, dims });
const omegaOf = (...verbs: any[]) => ({ v: 1, verbs, approximate: [] });
const refund = vsp('stripe.refund', 'irreversible', 1, [num(A + 'amount', 0, 100, [10, 50]), cat(A + 'recipient', ['bob'], ['team-'])]);
const send = vsp('gmail.send', 'rate_limited', 0.5, [cat(A + 'to', ['a', 'b'], ['p-'])]);
const flat = vsp('v.a', 'reversible', 1, [num(A + 'a', 0, 9, [3, 6])]);
const OM: Record<string, any> = { A: omegaOf(refund), B: omegaOf(refund, send), E: omegaOf(flat) };
const w = (field: string, op: string, value: any) => ({ field, op, value });
const pol = (...ps: any[]) => ({ predicates: ps, caveats: [] });
const POL: Record<string, any> = {
  A: pol({ verb: 'stripe.refund', resource: '*', where: [w(A + 'amount', 'lte', 30), w(A + 'recipient', 'in', ['bob'])] }),
  B: pol({ verb: 'stripe.refund', resource: '*', where: [w(A + 'amount', 'lte', 10)] }, { verb: 'gmail.send', resource: '*', where: [w(A + 'to', 'prefix', 'p-')] }),
  E: pol({ verb: 'v.a', resource: '*', where: [w(A + 'a', 'lte', 4)] }),
};
const allCells = (vs: any): number[][] => { const t = O.verbCellCount(vs); const r: number[][] = []; for (let f = 0; f < t; f++) r.push(O.decodeCell(vs, f)); return r; };
let st = 4242;
const rnd = () => { st = (st * 1103515245 + 12345) & 0x7fffffff; return st / 0x7fffffff; };
function obsScript(key: string, nObs: number, regions = false): any[] {
  const omega = OM[key]; const adm = P.admitter(POL[key]); const out: any[] = [];
  for (let i = 0; i < nObs; i++) {
    const vs = omega.verbs[Math.floor(rnd() * omega.verbs.length)];
    const cells = allCells(vs); const idx = cells[Math.floor(rnd() * cells.length)];
    const oc = O.cellRep(vs, idx);
    const x: any = { verb: vs.verb, values: oc.values, y: adm.admits(vs, oc) ? 1 : 0, source: i % 5 === 4 ? 'runtime' : 'elicitation' };
    if (regions && i % 3 === 1) x.region = JSON.parse(JSON.stringify(require_regionOfCell(vs, idx)));
    out.push(x);
  }
  return out;
}
import * as RG0 from '../../../packages/pca-intent/src/region';
const RG: any = (RG0 as any).default ?? RG0;
function require_regionOfCell(vs: any, idx: number[]) { return RG.regionOfCell(vs, idx); }
const mk = (omega: any, mapOpts: any, observations: any[]) => { const l = M.createLearner(omega, mapOpts); for (const x of observations) l.observe({ verb: x.verb, values: x.values }, x.y, x.source, x.region); return l; };
const cellsOf = (l: any) => l.cells().map((c: any) => ({ verb: c.verb, cell: c.cell, p: c.p }));

// ---- refineOmega ----
const refs: any[] = [
  { verb: 'stripe.refund', path: A + 'amount', cuts: [30] }, { verb: 'stripe.refund', path: A + 'amount', cuts: [30, 30, 10, 99, 100, 101, -5, 0, 1.5] }, { verb: 'stripe.refund', path: A + 'amount' },
  { verb: 'stripe.refund', path: A + 'amount', cuts: [5], values: ['x'] }, { verb: 'stripe.refund', path: A + 'amount', cuts: [5], prefixes: ['x'] }, { verb: 'stripe.refund', path: A + 'amount', values: [] },
  { verb: 'stripe.refund', path: A + 'recipient', values: ['alice', 'bob', 'zed'] }, { verb: 'stripe.refund', path: A + 'recipient', prefixes: ['vip-', 'team-', 'team-a'] }, { verb: 'stripe.refund', path: A + 'recipient', values: ['é', 'Z', 'a'], prefixes: ['😀'] },
  { verb: 'stripe.refund', path: A + 'recipient', cuts: [3] }, { verb: 'stripe.refund', path: A + 'recipient', values: Array.from({ length: 25 }, (_, i) => 'v' + i) }, { verb: 'stripe.refund', path: A + 'recipient', cuts: [] },
  { verb: 'nope', path: A + 'amount', cuts: [1] }, { verb: 'stripe.refund', path: A + 'missing', cuts: [1] },
  { verb: 'stripe.refund', path: A + 'currency', newDim: cat(A + 'currency', ['usd', 'eur', 'usd'], ['x-']) }, { verb: 'stripe.refund', path: A + 'fee', newDim: num(A + 'fee', 0, 20, [5, 5, 30, -1, 10]) },
  { verb: 'stripe.refund', path: A + 'amount', newDim: num(A + 'amount', 0, 5, []) }, { verb: 'stripe.refund', path: A + 'aaa', newDim: num(A + 'zzz', 0, 5, []) }, { verb: 'stripe.refund', path: A + 'zzz', newDim: num(A + 'zzz', 0, 5, [2], 'loguniform') },
  { verb: 'gmail.send', path: A + 'to', values: ['c'], prefixes: ['q-'] }, { verb: 'gmail.send', path: 'action.resource', newDim: cat('action.resource', ['/a'], ['/b/']) },
];
for (const key of ['A', 'B']) for (const r of refs) await run('refineOmega', R.refineOmega, [OM[key], r]);

// ---- regionOfObservation ----
const regionsOf = (omega: any, mo: any, obs: any[], empty: boolean) => { const l = mk(omega, mo, obs); return l.observations.map((x: any) => R.regionOfObservation(empty ? { ...omega, verbs: [] } : l.omega, x)); };
for (const key of ['A', 'B', 'E']) await run('regionsOf', regionsOf, [OM[key], {}, obsScript(key, 8, true), false]);
await run('regionsOf', regionsOf, [OM.A, {}, obsScript('A', 3), true]);

// ---- refineLearner ----
for (const key of ['A', 'B']) for (const r of refs.slice(0, 16)) {
  if (r.verb !== 'stripe.refund') continue;
  await run('refineScenario', (omega: any, mo: any, obs: any[], rr: any) => { const l = mk(omega, mo, obs); const nl = R.refineLearner(l, rr); return { omega: nl.omega, observations: nl.observations, metrics: nl.metrics(), cells: cellsOf(nl) }; }, [OM[key], key === 'A' && r.cuts ? { eta: 0.1 } : {}, obsScript(key, 6, true), r]);
}
for (const r of refs.slice(14, 18)) await run('refineScenario', (omega: any, mo: any, obs: any[], rr: any) => { const l = mk(omega, mo, obs); const nl = R.refineLearner(l, rr); return { omega: nl.omega, observations: nl.observations, metrics: nl.metrics(), cells: cellsOf(nl) }; }, [OM.A, {}, obsScript('A', 6), r]);

// ---- answerPartial ----
const partials: any[] = [
  { path: A + 'amount', cuts: [30], parts: [{ lo: 0, hi: 30, y: 1 }, { lo: 31, hi: 100, y: 0 }] },
  { path: A + 'amount', cuts: [20, 30], parts: [{ lo: 0, hi: 20, y: 1 }, { lo: 21, hi: 30, y: 0 }] },
  { path: A + 'amount', cuts: [30], parts: [{ lo: 0, hi: 30, y: 1 }] },
  { path: A + 'amount', parts: [{ lo: 0, hi: 100, y: 1 }] },
  { path: A + 'recipient', values: ['alice'], parts: [{ values: ['alice'], y: 1 }, { other: true, y: 0 }] },
  { path: A + 'recipient', values: ['alice', 'carol'], parts: [{ values: ['alice', 'bob'], y: 1 }, { values: ['carol'], y: 0 }, { other: true, y: 0 }] },
  { path: A + 'recipient', parts: [{ other: true, y: 1 }] },
  { path: A + 'currency', newDim: cat(A + 'currency', ['usd', 'eur']), parts: [{ values: ['usd'], y: 1 }, { values: ['eur'], y: 0 }, { other: true, y: 0 }] },
  { path: A + 'currency', newDim: cat(A + 'currency', ['usd']), parts: [{ values: ['usd'], y: 0 }, { other: true, y: 1 }] },
  { path: A + 'fee', newDim: num(A + 'fee', 0, 20, [5, 10]), parts: [{ lo: 0, hi: 5, y: 1 }, { lo: 6, hi: 20, y: 0 }] },
  { path: A + 'fee', newDim: num(A + 'fee', 0, 20, [5, 10]), parts: [{ lo: 0, hi: 5, y: 0 }, { lo: 6, hi: 20, y: 0 }] },
  { path: A + 'fee', newDim: num(A + 'fee', 0, 20, [5, 10]), parts: [{ lo: 6, hi: 10, y: 1 }, { lo: 0, hi: 5, y: 0 }] },
  { path: A + 'nope', cuts: [1], parts: [] }, { path: A + 'amount', cuts: [30], parts: [{ values: ['x'], y: 1 }] },
];
for (const key of ['A', 'B']) {
  const vs = OM[key].verbs[0]; const cells = allCells(vs);
  for (const p of partials) for (const ci of [0, Math.floor(cells.length / 2), cells.length - 1]) {
    await run('partialScenario', (omega: any, mo: any, obs: any[], q: any, pa: any) => {
      const l = mk(omega, mo, obs); const svs = omega.verbs.find((v: any) => v.verb === q.verb); const oc = O.cellRep(svs, q.cell);
      const r = R.answerPartial(l, { verb: q.verb, cell: q.cell, outcome: oc, p: l.acceptance(oc), score: 0 }, pa);
      return { omega: r.learner.omega, added: r.added, observations: r.learner.observations, metrics: r.learner.metrics(), synth: r.learner.synthesize() };
    }, [OM[key], {}, obsScript(key, 5, true), { verb: vs.verb, cell: cells[ci] }, p]);
  }
}
await run('partialScenario', (omega: any, mo: any, obs: any[], q: any, pa: any) => { const l = mk(omega, mo, obs); return R.answerPartial(l, { verb: q.verb, cell: q.cell, outcome: { verb: q.verb, values: {} }, p: 0.5, score: 0 }, pa).added; }, [OM.A, {}, [], { verb: 'nope', cell: [] }, partials[0]]);

// ---- elicitAdaptive ----
for (const key of ['A', 'B', 'E']) {
  const vs0 = OM[key].verbs[0];
  for (const [every, plist, opts] of [[2, partials.slice(0, 2), {}], [3, [partials[4], partials[7], partials[0]], {}], [1, partials.slice(0, 6), { maxRefinements: 2 }], [2, [partials[9], partials[0]], { audit: true }], [4, [], { audit: true }], [2, [partials[4], partials[1]], { seed: [{ verb: vs0.verb, cell: allCells(vs0)[0] }, { verb: vs0.verb, cell: [9] }] }], [2, partials.slice(0, 3), { maxQuestions: 3 }]] as any[]) {
    if (key === 'E') continue;
    await run('adaptiveScenario', (omega: any, mo: any, policy: any, ps: any[], ev: number, oo: any) => {
      let k = 0; let pi = 0;
      const adm = P.admitter(policy);
      const ans = (q: any, l: any) => { k++; if (k % ev === 0 && pi < ps.length && q.verb === 'stripe.refund') return ps[pi++]; const vs = l.omega.verbs.find((v: any) => v.verb === q.verb); return adm.admits(vs, q.outcome) ? 1 : 0; };
      const l0 = M.createLearner(omega, mo);
      const r = R.elicitAdaptive(l0, ans, { epsRisk: 0.001, epsBurden: 0.01, maxQuestions: 25, ...oo });
      return { stop: r.stop, questions: r.questions, auditQuestions: r.auditQuestions, seedQuestions: r.seedQuestions, refinements: r.refinements, asked: r.asked.map((q: any) => ({ verb: q.verb, cell: q.cell, outcome: q.outcome, p: q.p, score: q.score })), omega: r.learner.omega, metrics: r.learner.metrics(), observations: r.learner.observations };
    }, [OM[key], {}, POL[key], plist, every, opts]);
  }
}
refWrite(o, 'intent-refine');
