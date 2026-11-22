// Oracle: @atlasauth/pca-intent elicitation-as-learning (learner.ts): IntentLearner posterior / metrics / questions / synthesis, elicit, auditRound,
// boxesToPredicates, hypothesisCellSets, hypothesisClassName. Deterministic: scenario scripts are recorded in the args.
// PORTING (fn(args) -> native entry point, comparison rule; JSON value equality, doubles bit-exact):
//   scenario(omega, opts, ops) -> list of per-op results. Build the learner with IntentLearner(omega, options) where options are the plain
//     data of `opts`; opts.nullMassFn == "byRev" => nullMass(vs) = 0.1 for reversible else 0.3; opts.priorMix {beta, weight} with weight
//     "size" (1 + number of contained cells) / "neg" (returns -1) / "zero" (returns 0). Throw anywhere (constructor or an op) => throw.
//     ops: observe{verb,values,y,source?,region?} -> observation JSON or null; probe{verb,values} -> [acceptance, admitsOutcome, isVetoed];
//     next -> question {verb,cell,outcome,p,score} or null; metrics; cells; unconfirmed; synth; vetoed; observations; replay (replay the
//     recorded observations onto a fresh learner and return its metrics); elicit{policy,epsRisk,epsBurden,maxQuestions,audit?,seed?,flipEvery?}
//     (answer = admitter(policy).admits(vs, outcome), flipped on every flipEvery-th question) -> result + metrics.
//   boxesToPredicates(vs, allowed) / hypothesisCellSets(vs, class, caps) / hypothesisClassName(spec)
import * as L0 from '../../../packages/pca-intent/src/learner';
import * as O0 from '../../../packages/pca-intent/src/omega';
import * as R0 from '../../../packages/pca-intent/src/region';
import * as P0 from '../../../packages/pca-intent/src/policy';
import { Oracle, refWrite } from './lib.mjs';

const L: any = (L0 as any).default ?? L0;
const O: any = (O0 as any).default ?? O0;
const R: any = (R0 as any).default ?? R0;
const P: any = (P0 as any).default ?? P0;
const o = new Oracle('intent-learner', 'tools/pca-audit/oracles/intent-learner.mts', 'TS-reference oracle for the intent learner.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);

const A = 'action.params.';
const num = (path: string, lo: number, hi: number, cuts: number[], dist = 'uniform') => ({ kind: 'num', path, lo, hi, cuts, dist });
const cat = (path: string, exacts: string[], prefixes: string[] = []) => ({ kind: 'cat', path, values: [...exacts.map((v) => ({ kind: 'exact', value: v })), ...prefixes.map((v) => ({ kind: 'prefix', value: v })), { kind: 'other', value: '⊥' }] });
const vsp = (verb: string, reversibility: string, weight: number, dims: any[]) => ({ verb, reversibility, weight, dims });
const omegaOf = (...verbs: any[]) => ({ v: 1, verbs, approximate: [] });
const refund = vsp('stripe.refund', 'irreversible', 1, [num(A + 'amount', 0, 100, [10, 50]), cat(A + 'recipient', ['bob'], ['team-'])]);
const send = vsp('gmail.send', 'rate_limited', 0.5, [cat(A + 'to', ['a', 'b'], ['p-'])]);
const cal = vsp('calendar.create', 'reversible', 1, [num('env.hour', 0, 23, [9, 17]), num(A + 'count', 0, 10, [5], 'loguniform')]);
const big = vsp('stripe.charge', 'irreversible', 2, [num(A + 'amount', 0, 200, [10, 50, 100]), cat(A + 'recipient', ['bob'], ['team-'])]);
const flat = vsp('v.a', 'reversible', 1, [num(A + 'a', 0, 2, [1, 2])]);
const OM: Record<string, any> = { A: omegaOf(refund), B: omegaOf(refund, send), C: omegaOf(cal), D: omegaOf(big), E: omegaOf(flat), F: omegaOf(cal, send) };
const pol = (...ps: any[]) => ({ predicates: ps, caveats: [] });
const w = (field: string, op: string, value: any) => ({ field, op, value });
const POL: Record<string, any> = {
  A: pol({ verb: 'stripe.refund', resource: '*', where: [w(A + 'amount', 'lte', 50), w(A + 'recipient', 'in', ['bob'])] }),
  B: pol({ verb: 'stripe.refund', resource: '*', where: [w(A + 'amount', 'lte', 10)] }, { verb: 'gmail.send', resource: '*', where: [w(A + 'to', 'prefix', 'p-')] }),
  C: pol({ verb: 'calendar.create', resource: '*', where: [w('env.hour', 'gte', 9), w('env.hour', 'lte', 17)] }),
  D: pol({ verb: 'stripe.charge', resource: '*', where: [w(A + 'amount', 'lte', 100), w(A + 'recipient', 'prefix', 'team-')] }),
  E: pol({ verb: 'v.a', resource: '*', where: [w(A + 'a', 'lte', 1)] }),
  F: pol({ verb: 'calendar.create', resource: '*', where: [w(A + 'count', 'lte', 5)] }, { verb: 'gmail.send', resource: '*', where: [w(A + 'to', 'eq', 'a')] }),
};
const cellVals = (vs: any, idx: number[]) => O.cellRep(vs, idx).values;
const allCells = (vs: any): number[][] => { const t = O.verbCellCount(vs); const r: number[][] = []; for (let f = 0; f < t; f++) r.push(O.decodeCell(vs, f)); return r; };

function mkOpts(opts: any): any {
  const x: any = { ...opts };
  if (x.nullMassFn === 'byRev') { x.nullMass = (vs: any) => (vs.reversibility === 'reversible' ? 0.1 : 0.3); delete x.nullMassFn; }
  if (x.priorMix) {
    const kind = x.priorMix.weight;
    const wt = kind === 'size' ? (_vs: any, has: (c: number) => boolean) => { let k = 1; for (let c = 0; c < 64; c++) if (has(c)) k++; return k; } : kind === 'neg' ? () => -1 : () => 0;
    x.priorMix = { beta: x.priorMix.beta, weight: wt };
  }
  return x;
}

const jq = (q: any) => (q === null ? null : { verb: q.verb, cell: q.cell, outcome: q.outcome, p: q.p, score: q.score });
function scenario(omega: any, opts: any, ops: any[]): any[] {
  const lopts = mkOpts(opts);
  const l = new L.IntentLearner(omega, lopts);
  const out: any[] = [];
  for (const op of ops) {
    switch (op.op) {
      case 'observe': out.push(l.observe({ verb: op.verb, values: op.values }, op.y, op.source ?? 'elicitation', op.region)); break;
      case 'probe': { const oc = { verb: op.verb, values: op.values }; out.push([l.acceptance(oc), l.admitsOutcome(oc), l.isVetoed(oc)]); break; }
      case 'next': out.push(jq(l.nextQuestion())); break;
      case 'metrics': out.push(l.metrics()); break;
      case 'cells': out.push(l.cells()); break;
      case 'unconfirmed': out.push(l.unconfirmedGrantCells()); break;
      case 'synth': out.push(l.synthesize()); break;
      case 'vetoed': out.push(l.vetoedCells()); break;
      case 'observations': out.push(l.observations); break;
      case 'replay': out.push(L.IntentLearner.replay(omega, lopts, l.observations).metrics()); break;
      case 'elicit': {
        const adm = P.admitter(op.policy);
        let k = 0;
        const ans = (q: any) => { const vs = omega.verbs.find((v: any) => v.verb === q.verb); const y = adm.admits(vs, q.outcome) ? 1 : 0; k++; return op.flipEvery && k % op.flipEvery === 0 ? (1 - y) : y; };
        const r = L.elicit(l, ans, { epsRisk: op.epsRisk, epsBurden: op.epsBurden, maxQuestions: op.maxQuestions, audit: op.audit, seed: op.seed });
        out.push({ stop: r.stop, questions: r.questions, auditQuestions: r.auditQuestions, seedQuestions: r.seedQuestions, asked: r.asked.map(jq), metrics: l.metrics() });
        break;
      }
      default: throw new Error('bad op');
    }
  }
  return out;
}

// scripted answer sequences: a deterministic pseudo-random walk over cells, answers from a truth policy
let st = 12345;
const rnd = () => { st = (st * 1103515245 + 12345) & 0x7fffffff; return st / 0x7fffffff; };
function script(omegaKey: string, nObs: number, extra: { noisyEvery?: number; runtimeEvery?: number; regions?: boolean } = {}): any[] {
  const omega = OM[omegaKey];
  const adm = P.admitter(POL[omegaKey]);
  const ops: any[] = [];
  for (let i = 0; i < nObs; i++) {
    const vs = omega.verbs[Math.floor(rnd() * omega.verbs.length)];
    const cells = allCells(vs);
    const idx = cells[Math.floor(rnd() * cells.length)];
    const oc = O.cellRep(vs, idx);
    let y = adm.admits(vs, oc) ? 1 : 0;
    if (extra.noisyEvery && i % extra.noisyEvery === extra.noisyEvery - 1) y = 1 - y;
    const source = extra.runtimeEvery && i % extra.runtimeEvery === extra.runtimeEvery - 1 ? 'runtime' : i % 7 === 6 ? 'witness' : 'elicitation';
    const op: any = { op: 'observe', verb: vs.verb, values: oc.values, y, source };
    if (extra.regions && i % 3 === 2) { op.region = R.regionOfCell(vs, idx); if (i % 6 === 2) for (const k of Object.keys(op.region.dims)) { const d = op.region.dims[k]; if (d.kind === 'num') op.region.dims[k] = { ...d, hi: d.hi + 7 }; } }
    ops.push(op);
    if (i % 3 === 0) ops.push({ op: 'next' });
    if (i % 4 === 1) ops.push({ op: 'metrics' });
    if (i % 5 === 2) ops.push({ op: 'probe', verb: vs.verb, values: oc.values });
  }
  ops.push({ op: 'metrics' }, { op: 'cells' }, { op: 'unconfirmed' }, { op: 'synth' }, { op: 'vetoed' }, { op: 'observations' }, { op: 'replay' }, { op: 'next' });
  return ops;
}
const tail = [{ op: 'metrics' }, { op: 'cells' }, { op: 'next' }, { op: 'unconfirmed' }, { op: 'synth' }];
const elicitOp = (key: string, extra: any = {}) => ({ op: 'elicit', policy: POL[key], epsRisk: 0.001, epsBurden: 0.01, maxQuestions: 30, ...extra });

const CLASSES: any[] = [{ kind: 'box' }, { kind: 'union', k: 2 }, { kind: 'union', k: 1 }, { kind: 'decision-list', maxRules: 1 }, { kind: 'decision-list', maxRules: 2, conditions: 'atomic' }, { kind: 'decision-list', maxRules: 2, conditions: 'atomic', decay: 0.5 }, { kind: 'decision-list', maxRules: 2 }, { kind: 'decision-list', maxRules: 3, conditions: 'atomic' }];

// ---- per class x omega: scripted observations + elicit ----
for (const hc of CLASSES) {
  for (const key of ['E', 'A', 'C', 'B']) {
    const heavy = (hc.kind === 'decision-list' && (hc.conditions ?? 'box') === 'box' && hc.maxRules >= 2) || (hc.kind === 'union' && hc.k >= 2 && key === 'B');
    if (heavy && key !== 'E') continue;
    if (hc.kind === 'decision-list' && hc.maxRules >= 3 && key !== 'E') continue;
    const opts: any = { hypothesisClass: hc, maxEnumeration: 4_000_000 };
    await run('scenario', scenario, [OM[key], opts, script(key, 8)]);
    await run('scenario', scenario, [OM[key], opts, [elicitOp(key), ...tail]]);
  }
}
// ---- options sweep on the box class ----
const optsets: any[] = [
  {}, { tau: 0.9 }, { tau: 0.5 }, { strategy: 'risk' }, { strategy: 'disagreement' }, { nullMass: 0 }, { nullMass: 1 }, { nullMass: 0.6 }, { nullMassFn: 'byRev' },
  { eta: 0.1 }, { eta: 0.1, tau: 0.8 }, { etaPos: 0.05, etaNeg: 0.2 }, { etaPos: 0, etaNeg: 0.3 }, { etaPos: 0.3, etaNeg: 0 }, { etaPos: 0.1, etaNeg: 0.1, strategy: 'risk' },
  { agnosticSlack: 0 }, { agnosticSlack: 1 }, { agnosticSlack: 2, tau: 0.7 },
  { monotone: { paths: [A + 'amount'] } }, { monotone: { paths: [A + 'amount'], offMass: 0.2 } }, { monotone: { paths: [] } }, { monotone: { paths: ['env.hour'], offMass: 0 } },
  { priorMix: { beta: 0.3, weight: 'size' } }, { priorMix: { beta: 0, weight: 'size' } }, { priorMix: { beta: 0.5, weight: 'zero' } },
  { anchor: { policy: null, lambda: 0 } }, { harm: undefined },
];
for (const key of ['A', 'C', 'B']) for (const op of optsets) {
  const o2 = { ...op };
  if (o2.anchor && o2.anchor.policy === null) o2.anchor = { policy: POL[key], lambda: 0 };
  await run('scenario', scenario, [OM[key], o2, script(key, 9, { noisyEvery: op.eta || op.etaPos || op.etaNeg ? 4 : 0, runtimeEvery: 5 })]);
  await run('scenario', scenario, [OM[key], o2, [elicitOp(key, { flipEvery: op.eta || op.etaPos || op.etaNeg || op.agnosticSlack !== undefined ? 5 : 0 }), ...tail]]);
}
// anchors, mixtures
for (const key of ['A', 'D', 'C']) {
  for (const lambda of [0.5, 2, 10]) {
    await run('scenario', scenario, [OM[key], { anchor: { policy: POL[key], lambda } }, [{ op: 'metrics' }, { op: 'next' }, ...script(key, 6)]]);
    await run('scenario', scenario, [OM[key], { anchors: [{ policy: POL[key], lambda }, { policy: POL.E, lambda: 1 }], hypothesisClass: { kind: 'union', k: 2 } }, [{ op: 'metrics' }, { op: 'cells' }, { op: 'synth' }]]);
  }
  await run('scenario', scenario, [OM[key], { anchor: { policy: POL[key], lambda: 3 }, anchors: [{ policy: POL[key], lambda: 1 }] }, [elicitOp(key), ...tail]]);
}
// regions, runtime vetoes, conflicts, outside-omega
for (const key of ['A', 'D', 'B']) {
  await run('scenario', scenario, [OM[key], {}, script(key, 12, { regions: true })]);
  await run('scenario', scenario, [OM[key], { eta: 0.05 }, script(key, 12, { regions: true, noisyEvery: 3 })]);
  await run('scenario', scenario, [OM[key], { hypothesisClass: { kind: 'union', k: 2 } }, script(key, 12, { runtimeEvery: 2, noisyEvery: 3 })]);
}
{
  const vs = OM.A.verbs[0];
  const vals = cellVals(vs, [1, 1]);
  await run('scenario', scenario, [OM.A, {}, [
    { op: 'observe', verb: 'nope', values: {}, y: 1 }, { op: 'observe', verb: vs.verb, values: { [A + 'amount']: 1000, [A + 'recipient']: 'bob' }, y: 1 }, { op: 'observe', verb: vs.verb, values: { [A + 'amount']: 'x', [A + 'recipient']: 'bob' }, y: 0 },
    { op: 'probe', verb: 'nope', values: {} }, { op: 'probe', verb: vs.verb, values: { [A + 'amount']: -1 } },
    { op: 'observe', verb: vs.verb, values: vals, y: 0, source: 'runtime' }, { op: 'observe', verb: vs.verb, values: vals, y: 1 }, { op: 'probe', verb: vs.verb, values: vals }, { op: 'next' }, { op: 'metrics' }, { op: 'vetoed' }, { op: 'observations' }]]);
  // conflict: a "no" on every cell then a "yes"
  const ops: any[] = [];
  for (const idx of allCells(vs)) ops.push({ op: 'observe', verb: vs.verb, values: cellVals(vs, idx), y: 0 });
  ops.push({ op: 'observe', verb: vs.verb, values: vals, y: 1 }, { op: 'metrics' }, { op: 'cells' }, { op: 'synth' }, { op: 'observations' });
  await run('scenario', scenario, [OM.A, {}, ops]);
  await run('scenario', scenario, [OM.A, { agnosticSlack: 1 }, ops]);
  await run('scenario', scenario, [OM.A, { eta: 0.1 }, ops]);
  await run('scenario', scenario, [OM.A, { hypothesisClass: { kind: 'union', k: 2 } }, ops]);
  // a "yes" everywhere then a "no"
  const ops2: any[] = [];
  for (const idx of allCells(vs)) ops2.push({ op: 'observe', verb: vs.verb, values: cellVals(vs, idx), y: 1 });
  ops2.push({ op: 'observe', verb: vs.verb, values: vals, y: 0, source: 'runtime' }, { op: 'metrics' }, { op: 'synth' }, { op: 'unconfirmed' });
  await run('scenario', scenario, [OM.A, {}, ops2]);
  await run('scenario', scenario, [OM.A, { etaPos: 0.1, etaNeg: 0.1 }, ops2]);
}
// elicit variants: seeds, audit, budgets
for (const key of ['A', 'D', 'B', 'C']) {
  const vs = OM[key].verbs[0];
  const seed = [[0, 0], [1, 1], [1, 0], [0, 0], [7]].map((c) => ({ verb: vs.verb, cell: c.slice(0, c.length === 1 ? 1 : vs.dims.length) }));
  for (const hc of [{ kind: 'box' }, { kind: 'union', k: 2 }]) {
    if (hc.kind === 'union' && key === 'D') continue;
    await run('scenario', scenario, [OM[key], { hypothesisClass: hc }, [elicitOp(key, { seed, audit: true, maxQuestions: 40 }), ...tail]]);
    await run('scenario', scenario, [OM[key], { hypothesisClass: hc }, [elicitOp(key, { maxQuestions: 2 }), ...tail]]);
    await run('scenario', scenario, [OM[key], { hypothesisClass: hc, strategy: 'risk' }, [elicitOp(key, { audit: true, epsRisk: 0.05, epsBurden: 0.2 }), ...tail]]);
    await run('scenario', scenario, [OM[key], { hypothesisClass: hc, eta: 0.1 }, [elicitOp(key, { audit: true, flipEvery: 4, maxQuestions: 25 }), ...tail]]);
  }
  await run('scenario', scenario, [OM[key], {}, [elicitOp(key, { epsRisk: 0, epsBurden: 0, maxQuestions: 100, audit: true, seed: [{ verb: 'nope', cell: [] }] }), ...tail]]);
  await run('scenario', scenario, [OM[key], {}, [elicitOp(key, { maxQuestions: 0, audit: true }), ...tail]]);
}
// constructor / option errors
for (const bad of [{ eta: 0.5 }, { eta: -0.1 }, { etaPos: 0.5 }, { etaNeg: -1 }, { agnosticSlack: -1 }, { agnosticSlack: 1.5 }, { agnosticSlack: 1, eta: 0.1 }, { hypothesisClass: { kind: 'union', k: 0 } }, { hypothesisClass: { kind: 'union', k: 1.5 } }, { hypothesisClass: { kind: 'decision-list', maxRules: 0 } },
  { hypothesisClass: { kind: 'decision-list', maxRules: 1, conditions: 'weird' } }, { hypothesisClass: { kind: 'decision-list', maxRules: 1, decay: 0 } }, { hypothesisClass: { kind: 'decision-list', maxRules: 1, decay: 1.5 } }, { nullMass: 2 }, { nullMass: -0.1 },
  { monotone: { paths: [A + 'amount'], offMass: 2 } }, { priorMix: { beta: 1, weight: 'size' } }, { priorMix: { beta: -0.1, weight: 'size' } }, { priorMix: { beta: 0.3, weight: 'neg' } }, { maxHypotheses: 3 }, { maxHypotheses: 30, hypothesisClass: { kind: 'union', k: 2 } },
  { maxEnumeration: 5, hypothesisClass: { kind: 'union', k: 2 } }, { maxEnumeration: 5, hypothesisClass: { kind: 'decision-list', maxRules: 2 } }, { maxEnumeration: 3, hypothesisClass: { kind: 'decision-list', maxRules: 2, conditions: 'atomic' } }]) {
  await run('scenario', scenario, [OM.A, bad, [{ op: 'metrics' }]]);
}
await run('scenario', scenario, [omegaOf(vsp('v.big', 'reversible', 1, [cat(A + 'x', Array.from({ length: 21 }, (_, i) => 'v' + i))])), {}, [{ op: 'metrics' }]]);
await run('scenario', scenario, [omegaOf(vsp('v.big', 'reversible', 1, [num(A + 'x', 0, 400, Array.from({ length: 60 }, (_, i) => i + 1)), num(A + 'y', 0, 400, Array.from({ length: 60 }, (_, i) => i + 1))])), {}, [{ op: 'metrics' }]]);
await run('scenario', scenario, [{ v: 1, verbs: [], approximate: [] }, {}, [{ op: 'metrics' }, { op: 'next' }, { op: 'synth' }, { op: 'cells' }]]);

// ---- standalone ----
for (const hc of CLASSES.slice(0, 5)) for (const key of ['E', 'A']) {
  const vs = OM[key].verbs[0];
  await run('hypothesisCellSets', (v: any, c: any) => { const r = L.hypothesisCellSets(v, c); return { sets: r.sets.map((s: any) => Array.from(s)), complexity: r.complexity }; }, [vs, hc]);
}
await run('hypothesisCellSets', (v: any, c: any, caps: any) => L.hypothesisCellSets(v, c, caps).sets.length, [OM.A.verbs[0], { kind: 'union', k: 2 }, { maxHypotheses: 10 }]);
await run('hypothesisCellSets', (v: any, c: any) => L.hypothesisCellSets(v, c).sets.length, [OM.A.verbs[0], undefined]);
for (const hc of [...CLASSES, { kind: 'decision-list', maxRules: 1, conditions: 'atomic' }, { kind: 'decision-list', maxRules: 1, conditions: 'box' }]) await run('hypothesisClassName', L.hypothesisClassName, [hc]);
// boxesToPredicates over random allowed sets
for (const key of ['A', 'D', 'B', 'C', 'F']) for (const vs of OM[key].verbs) {
  const t = O.verbCellCount(vs);
  for (let rep = 0; rep < 14; rep++) {
    const allowed = Array.from({ length: t }, (_, i) => (rep === 0 ? 1 : rep === 1 ? 0 : rnd() < (rep % 4 === 0 ? 0.8 : 0.4) ? 1 : 0));
    await run('boxesToPredicates', (v: any, a: number[]) => L.boxesToPredicates(v, Uint8Array.from(a)), [vs, allowed]);
  }
}
// categorical conditions with nested prefixes and no other cell constraints
const nested = vsp('v.n', 'reversible', 1, [{ kind: 'cat', path: A + 'p', values: [{ kind: 'exact', value: 'ab1' }, { kind: 'exact', value: 'zz' }, { kind: 'prefix', value: 'a' }, { kind: 'prefix', value: 'ab' }, { kind: 'other', value: '⊥' }] }]);
for (let m = 0; m < 32; m++) await run('boxesToPredicates', (v: any, a: number[]) => L.boxesToPredicates(v, Uint8Array.from(a)), [nested, Array.from({ length: 5 }, (_, i) => (m >> i) & 1)]);
refWrite(o, 'intent-learner');
