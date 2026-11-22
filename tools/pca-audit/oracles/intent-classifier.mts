// Oracle: @atlasauth/pca-intent classifier error folded into the residual risk (classifier.ts). Deterministic.
// PORTING (fn(args) -> native entry point, comparison rule; JSON value equality, doubles bit-exact):
//   calibrate(samples, labels, delta?) / confusionDigest(cal) / publishedErrorRate(cal) / classifierCardNote(id, cal)   IntentClassifierKit.*
//   riskArrays(op, arrays, hMax?) with op in {risk, sound, bound}: classifierRisk / labelSound / labelSoundBound
//   awareScenario(omega, mapOpts, observations, specs) -> classifierAwareResidualRisk(l, specs)   (learner via IntentMapKit.createLearner)
//   jitScenario(omega, mapOpts, observations, spec, gammaMax) -> classifierJitCells(l, spec, gammaMax)
import * as C0 from '../../../packages/pca-intent/src/classifier';
import * as M0 from '../../../packages/pca-intent/src/map';
import * as O0 from '../../../packages/pca-intent/src/omega';
import { Oracle, refWrite } from './lib.mjs';

const C: any = (C0 as any).default ?? C0;
const M: any = (M0 as any).default ?? M0;
const O: any = (O0 as any).default ?? O0;
const o = new Oracle('intent-classifier', 'tools/pca-audit/oracles/intent-classifier.mts', 'TS-reference oracle for the intent classifier risk.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);
let st = 2024;
const rnd = () => { st = (st * 1103515245 + 12345) & 0x7fffffff; return st / 0x7fffffff; };
function samplesFor(labels: string[], perRow: number, errRate: number): any[] {
  const out: any[] = [];
  for (const t of labels) for (let i = 0; i < perRow; i++) out.push({ truth: t, predicted: rnd() < errRate ? labels[Math.floor(rnd() * labels.length)] : t });
  return out;
}
const LB = ['ok', 'bad'];
const L3 = ['c', 'a', 'b', 'a'];
const cases: [any[], string[], number | undefined][] = [
  [samplesFor(LB, 20, 0.1), LB, undefined], [samplesFor(LB, 20, 0.3), LB, 0.01], [samplesFor(LB, 12, 0), LB, 0.5], [[], LB, undefined], [samplesFor(['a', 'b', 'c'], 15, 0.2), L3, undefined], [samplesFor(['a', 'b', 'c'], 8, 0.5), L3, 0.2],
  [[{ truth: 'ok', predicted: 'ok' }], LB, undefined], [[{ truth: 'ok', predicted: 'bad' }, { truth: 'ok', predicted: 'bad' }], LB, 0.05], [samplesFor(['z'], 30, 0), ['z'], undefined], [samplesFor(['é', 'e', 'z'], 10, 0.4), ['z', 'e', 'é'], undefined],
  [samplesFor(LB, 5, 0.2), [], undefined], [samplesFor(LB, 5, 0.2), LB, 0], [samplesFor(LB, 5, 0.2), LB, 1], [samplesFor(LB, 5, 0.2), LB, 2], [samplesFor(LB, 5, 0.2), LB, -0.1], [[{ truth: 'x', predicted: 'ok' }], LB, undefined], [[{ truth: 'ok', predicted: 'y' }], LB, undefined],
  [samplesFor(LB, 40, 0.05), LB, 0.000001], [samplesFor(LB, 40, 0.05), LB, 0.123456789],
];
const cals: any[] = [];
for (const [s, l, d] of cases) { await run('calibrate', (ss: any, ll: any, dd?: number) => C.calibrateConfusion(ss, ll, dd), d === undefined ? [s, l] : [s, l, d]); try { cals.push(C.calibrateConfusion(s, l, d)); } catch {} }
for (const c of cals) { await run('confusionDigest', C.confusionDigest, [c]); await run('publishedErrorRate', C.publishedErrorRate, [c]); await run('classifierCardNote', C.classifierCardNote, ['doc.kind', c]); await run('classifierCardNote', C.classifierCardNote, ['q"uote', c]); }
await run('publishedErrorRate', C.publishedErrorRate, [{ labels: [], counts: [], gamma: [], gammaBar: [], delta_ppm: 0 }]);
await run('publishedErrorRate', C.publishedErrorRate, [{ labels: ['a', 'b'], counts: [[0, 0], [0, 0]], gamma: [[0, 0], [0, 0]], gammaBar: [[1, 1], [1, 1]], delta_ppm: 1 }]);
await run('classifierCardNote', C.classifierCardNote, ['x', { labels: ['a', 'b'], counts: [[0, 0], [0, 0]], gamma: [[0, 0], [0, 0]], gammaBar: [[0.12345, 0.0005], [0.0004, 0.9995]], delta_ppm: 1 }]);
await run('classifierCardNote', C.classifierCardNote, ['x', { labels: ['a', 'b'], counts: [], gamma: [], gammaBar: [[0, 0.0449999], [0, 0]], delta_ppm: 1 }]);
await run('classifierCardNote', C.classifierCardNote, ['x', { labels: ['a', 'b'], counts: [], gamma: [], gammaBar: [[0, 0.0450001], [0, 0]], delta_ppm: 1 }]);
await run('classifierCardNote', C.classifierCardNote, ['x', { labels: ['a', 'b'], counts: [], gamma: [], gammaBar: [[0, 0.125], [0, 0]], delta_ppm: 1 }]);

// ---- explicit arrays ----
const Xn = 3, Ln = 3;
const mat = (f: () => number) => Array.from({ length: Xn }, () => Array.from({ length: Ln }, f));
function gMat(): number[][] { const g = Array.from({ length: Ln }, () => Array.from({ length: Ln }, () => 0)); for (let t = 0; t < Ln; t++) { let rest = 1; for (let p = 0; p < Ln; p++) { const x = p === Ln - 1 ? rest : Math.round(rnd() * rest * 100) / 100; g[p][t] = x; rest -= x; } } return g; }
for (let i = 0; i < 24; i++) {
  const arr = { mu: mat(() => Math.round(rnd() * 20) / 100), a: mat(() => (rnd() < 0.5 ? 1 : 0)), h: mat(() => 1 + Math.round(rnd() * 90) / 10), inG: mat(() => rnd() < 0.5) as any, g: gMat() };
  const sound = { ...arr, inG: arr.inG.map((row: boolean[], x: number) => row.map((b, p) => (arr.a[x][p] === 1 ? b : false))) };
  for (const a2 of [arr, sound]) {
    await run('riskArrays', (op: string, a: any, h?: number) => (op === 'risk' ? C.classifierRisk(a) : op === 'sound' ? C.labelSound(a) : C.labelSoundBound(a, h)), ['risk', a2]);
    await run('riskArrays', (op: string, a: any, h?: number) => (op === 'risk' ? C.classifierRisk(a) : op === 'sound' ? C.labelSound(a) : C.labelSoundBound(a, h)), ['sound', a2]);
    await run('riskArrays', (op: string, a: any, h?: number) => (op === 'risk' ? C.classifierRisk(a) : op === 'sound' ? C.labelSound(a) : C.labelSoundBound(a, h)), ['bound', a2, 10]);
  }
}
await run('riskArrays', (op: string, a: any) => C.classifierRisk(a), ['risk', { mu: [], a: [], h: [], inG: [], g: [] }]);

// ---- learner-bound ----
const A = 'action.params.';
const num = (path: string, lo: number, hi: number, cuts: number[]) => ({ kind: 'num', path, lo, hi, cuts, dist: 'uniform' });
const cat = (path: string, exacts: string[]) => ({ kind: 'cat', path, values: [...exacts.map((v) => ({ kind: 'exact', value: v })), { kind: 'other', value: '⊥' }] });
const doc = { verb: 'doc.share', reversibility: 'irreversible', weight: 0.5, dims: [num(A + 'amount', 0, 20, [10]), cat('env.class.doc', ['ok', 'bad'])] };
const note = { verb: 'note.add', reversibility: 'reversible', weight: 0.25, dims: [cat(A + 'to', ['a'])] };
const doc3 = { verb: 'doc.copy', reversibility: 'rate_limited', weight: 0.25, dims: [cat('env.class.kind', ['a', 'b', 'c'])] };
const OM = { v: 1, verbs: [doc, note, doc3], approximate: [] };
const OM2 = { v: 1, verbs: [doc, note], approximate: [] };
const allCells = (vs: any): number[][] => { const t = O.verbCellCount(vs); const r: number[][] = []; for (let f = 0; f < t; f++) r.push(O.decodeCell(vs, f)); return r; };
const mk = (omega: any, mo: any, obs: any[]) => { const l = M.createLearner(omega, mo); for (const x of obs) l.observe({ verb: x.verb, values: x.values }, x.y, x.source); return l; };
const obsFor = (vs: any, pred: (idx: number[]) => number, every = 1) => allCells(vs).filter((_, i) => i % every === 0).map((idx) => ({ verb: vs.verb, values: O.cellRep(vs, idx).values, y: pred(idx), source: 'elicitation' }));
const calOk = C.calibrateConfusion(samplesFor(LB, 20, 0.1), LB);
const cal3 = C.calibrateConfusion(samplesFor(['a', 'b', 'c'], 15, 0.2), ['a', 'b', 'c']);
const calPartial = C.calibrateConfusion(samplesFor(['ok'], 10, 0), ['ok']);
const obsDoc = obsFor(doc, (i) => (i[1] === 0 ? 1 : 0));
const obsAll = [...obsDoc, ...obsFor(note, () => 1), ...obsFor(doc3, (i) => (i[0] === 0 ? 1 : 0))];
const specDoc = { verb: 'doc.share', path: 'env.class.doc', cal: calOk };
const specKind = { verb: 'doc.copy', path: 'env.class.kind', cal: cal3 };
const aware = (omega: any, mo: any, obs: any[], specs: any[]) => C.classifierAwareResidualRisk(mk(omega, mo, obs), specs);
for (const [om, mo, obs, specs] of [[OM2, {}, obsDoc, [specDoc]], [OM, {}, obsAll, [specDoc, specKind]], [OM, {}, obsAll, [specKind]], [OM, {}, obsAll, []], [OM, { eta: 0.1 }, obsAll, [specDoc, specKind]], [OM, {}, [], [specDoc, specKind]], [OM, {}, obsFor(doc, (i) => (i[1] === 0 ? 1 : 0), 2), [specDoc]],
  [OM2, {}, obsDoc, [{ ...specDoc, cal: calPartial }]], [OM2, {}, obsDoc, [{ ...specDoc, verb: 'nope' }]], [OM2, {}, obsDoc, [{ ...specDoc, path: 'action.params.amount' }]], [OM2, {}, obsDoc, [{ ...specDoc, path: 'missing' }]]] as any[]) await run('awareScenario', aware, [om, mo, obs, specs]);
const jit = (omega: any, mo: any, obs: any[], spec: any, g: number) => C.classifierJitCells(mk(omega, mo, obs), spec, g);
for (const g of [0, 0.01, 0.05, 0.1, 0.3, 0.5, 1]) for (const [om, mo, obs, spec] of [[OM2, {}, obsDoc, specDoc], [OM, {}, obsAll, specKind], [OM, { eta: 0.1 }, obsAll, specDoc], [OM, {}, obsAll, { ...specDoc, cal: calPartial }]] as any[]) await run('jitScenario', jit, [om, mo, obs, spec, g]);
await run('jitScenario', jit, [OM2, {}, obsDoc, { ...specDoc, verb: 'nope' }, 0.1]);
refWrite(o, 'intent-classifier');
