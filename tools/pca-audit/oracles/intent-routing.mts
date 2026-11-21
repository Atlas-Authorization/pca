// NOTE: the reference verifyJudgeVerdict throws (not total) on a PQ-suite verdict that carries no pq_pk (bindSuiteFields puts undefined into the signed body); such inputs are not in the corpus, the native returns false.
// Oracle: @atlasauth/pca-intent runtime routing and conformance (runtime.ts: routeAction, intentConformanceAttestation, checkIntentConformance, verifyICAtt, recordJitDecision,
// the learner forms of judgeInputOf / jitConsentRequest) over the core bond sizing (optimistic bondAmount) and the semantic judge threshold (verifySemanticThreshold). Deterministic: judges are
// Ed25519 keys from fixed seeds; no clocks. The hardware-attestation gate is not exercised (it is an injected predicate natively).
// PORTING (fn(args) -> native entry point, comparison rule; JSON value equality, doubles bit-exact; Infinity is compared as the string "inf"):
//   bondAmount(policy, exposure)           IntentBond.bondAmount(BondPolicy.fromJson(policy), exposure)
//   quantizeScore(x)                       IntentSemantic.quantizeScore
//   verifyJudgeVerdict(v, expected, pins)  IntentSemantic.verifyJudgeVerdict(v, expected.actionDigest, expected.goalCommitment, pins)
//   conformalThreshold(cal) / empiricalFalseAllowRate(samples, cutoff)   IntentSemantic.*
//   verifySemanticThreshold(verdicts, opts)  IntentSemantic.verifySemanticThreshold(verdicts, opts, null)
//   routeScenario(omega, mapOpts, observations, outcomes, opts) -> [routeAction(l, o, opts)] (IntentRouting.routeAction with RouteOptions.fromJson(opts))
//   routeVetoScenario(omega, mapOpts, observations, outcomes, opts): as routeScenario after observing every outcome as a negative runtime observation
//   conformanceScenario(omega, mapOpts, observations, outcome, ctx, verdicts, copts) -> {input: judgeInputOf(l, o, ctx), att: intentConformanceAttestation(input, verdicts, copts), digest: icAttDigest(att),
//     verify: verifyICAtt(att, input, verdicts, copts), tampered: [verifyICAtt over fixed mutations of att, and over fewer verdicts], check: checkIntentConformance(panel returning the verdicts, input, copts)}
//   jitScenario(omega, mapOpts, observations, outcome, decision, ctx) -> {req, digest, result: recordJitDecision(l, req, decision), metrics, route: routeAction(l, o)}
import * as RT0 from '../../../packages/pca-intent/src/runtime';
import * as M0 from '../../../packages/pca-intent/src/map';
import * as O0 from '../../../packages/pca-intent/src/omega';
import * as P0 from '../../../packages/pca-intent/src/policy';
import * as OPT0 from '../../../packages/pca/src/ext/optimistic';
import * as INT0 from '../../../packages/pca/src/ext/intent';
import * as K0 from '../../../packages/pca/src/keys';
import { Oracle, refWrite, seed } from './lib.mjs';
import { sha256 } from '@noble/hashes/sha2';

const RT: any = (RT0 as any).default ?? RT0;
const M: any = (M0 as any).default ?? M0;
const O: any = (O0 as any).default ?? O0;
const P: any = (P0 as any).default ?? P0;
const OPT: any = (OPT0 as any).default ?? OPT0;
const INT: any = (INT0 as any).default ?? INT0;
const publicKeyOf: any = ((K0 as any).default ?? K0).publicKeyOf;
const o = new Oracle('intent-routing', 'tools/pca-audit/oracles/intent-routing.mts', 'TS-reference oracle for intent runtime routing and conformance.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);
const inf = (x: number) => (Number.isFinite(x) ? x : 'inf');
const dig = (x: string) => Buffer.from(sha256(new TextEncoder().encode(x))).toString('base64url');

// ---- bond sizing ----
const policies: any[] = [
  { ...OPT.DEFAULT_BOND_POLICY, maxOpenAmount: undefined }, { floor: 5, k: 2, maxOpenClaims: 3, maxOpenAmount: 100 }, { floor: 0, k: 0.5, maxOpenClaims: 1, maxOpenAmount: 1 }, { floor: 1, k: 1.5, maxOpenClaims: 1, maxOpenAmount: 1, curve: { kind: 'linear' } },
  { floor: 1, k: 1, maxOpenClaims: 1, maxOpenAmount: 1, curve: { kind: 'power', gamma: 1 } }, { floor: 1, k: 1, maxOpenClaims: 1, maxOpenAmount: 1, curve: { kind: 'power', gamma: 2 } }, { floor: 2, k: 0.1, maxOpenClaims: 1, maxOpenAmount: 1, curve: { kind: 'power', gamma: 3 } },
  { floor: 1, k: 1, maxOpenClaims: 1, maxOpenAmount: 1, curve: { kind: 'power', gamma: 0.5 } }, { floor: 1, k: 1, maxOpenClaims: 1, maxOpenAmount: 1, curve: { kind: 'power' } }, { floor: 1, k: 1, maxOpenClaims: 1, maxOpenAmount: 1, curve: { kind: 'power', gamma: 'x' } },
  { floor: 1, k: 2, maxOpenClaims: 1, maxOpenAmount: 1, curve: { kind: 'piecewise', tiers: [{ upTo: 10, marginalK: 1 }, { upTo: 100, marginalK: 2 }, { upTo: 1e9, marginalK: 5 }] } },
  { floor: 1, k: 1, maxOpenClaims: 1, maxOpenAmount: 1, curve: { kind: 'piecewise', tiers: [{ upTo: 5, marginalK: 0 }, { upTo: 50, marginalK: 3 }] } },
  { floor: 1, k: 1, maxOpenClaims: 1, maxOpenAmount: 1, curve: { kind: 'piecewise', tiers: [] } }, { floor: 1, k: 1, maxOpenClaims: 1, maxOpenAmount: 1, curve: { kind: 'piecewise' } },
  { floor: 1, k: 1, maxOpenClaims: 1, maxOpenAmount: 1, curve: { kind: 'piecewise', tiers: [{ upTo: 10, marginalK: 2 }, { upTo: 5, marginalK: 3 }] } }, { floor: 1, k: 1, maxOpenClaims: 1, maxOpenAmount: 1, curve: { kind: 'piecewise', tiers: [{ upTo: 10, marginalK: 2 }, { upTo: 20, marginalK: 1 }] } },
  { floor: 1, k: 1, maxOpenClaims: 1, maxOpenAmount: 1, curve: { kind: 'piecewise', tiers: [{ upTo: 10, marginalK: -1 }] } }, { floor: 1, k: 1, maxOpenClaims: 1, maxOpenAmount: 1, curve: { kind: 'piecewise', tiers: [{ upTo: 0, marginalK: 1 }] } },
];
for (const p of policies) for (const e of [0, -1, 0.5, 1, 2.5, 10, 11.3333333, 100, 1234.5678, 123456.789012345, 1e9, 1e10, 1e12, 3e14, 1e16]) await run('bondAmount', OPT.bondAmount, [p, e]);
for (const x of [-1, -0.0000001, 0, 0.0000004, 0.0000005, 0.123456789, 0.5, 0.5000005, 0.9999995, 1, 1.5, 2, 1e-7, 0.85, 0.1 + 0.2]) await run('quantizeScore', INT.quantizeScore, [x]);

// ---- judges ----
const J = ['j1', 'j2', 'j3', 'j4'].map((l) => seed('intent-routing/' + l));
const JK = J.map((s) => Buffer.from(publicKeyOf(s)).toString('base64url'));
const AD = dig('action'), GC = dig('goal');
const sign = (i: number, v: any) => INT.signJudgeVerdict(J[i], { actionDigest: AD, goalCommitment: GC, faithful: true, score: 0.9, judgeMeasurement: 'm', ...v });
const good = [sign(0, {}), sign(1, { score: 0.8 }), sign(2, { score: 0.95 })];
const vv: any[] = [good[0], good[1], sign(0, { faithful: false }), sign(0, { score: 0 }), sign(0, { score: 1 }), sign(0, { score: 0.1234567 }), sign(0, { judgeMeasurement: '' }), sign(0, { judgeMeasurement: 'é' }),
  { ...good[0], sig: good[1].sig }, { ...good[0], sig: 5 }, { ...good[0], sig: undefined }, { ...good[0], judge: JK[1] }, { ...good[0], judge: 'short' }, { ...good[0], judge: 5 }, { ...good[0], actionDigest: dig('x') }, { ...good[0], goalCommitment: dig('x') }, { ...good[0], actionDigest: 5 },
  { ...good[0], faithful: 'true' }, { ...good[0], score: 1.5 }, { ...good[0], score: -0.1 }, { ...good[0], score: '0.9' }, { ...good[0], score: null }, { ...good[0], judgeMeasurement: 5 }, { ...good[0], judgeMeasurement: undefined },
  { ...good[0], alg: 'ed25519' }, { ...good[0], alg: 'ml-dsa-65', pq_pk: 'AAAA' }, { ...good[0], alg: 'hybrid-ed25519-ml-dsa-65', pq_pk: 'AAAA', pq_sig: 'AAAA' }, { ...good[0], alg: 'nope' }, { ...good[0], alg: 5 }, { ...good[0], pq_pk: 'x' }, { ...good[0], extra: 1 }, null, 5, 'x', [], {}];
for (const v of vv) { await run('verifyJudgeVerdict', INT.verifyJudgeVerdict, [v, { actionDigest: AD, goalCommitment: GC }, undefined]); await run('verifyJudgeVerdict', INT.verifyJudgeVerdict, [v, { actionDigest: AD, goalCommitment: GC }, { pqPins: { [JK[0]]: 'AAAA' } }]); }
await run('verifyJudgeVerdict', INT.verifyJudgeVerdict, [good[0], { actionDigest: dig('x'), goalCommitment: GC }, undefined]);
await run('verifyJudgeVerdict', INT.verifyJudgeVerdict, [good[0], { actionDigest: AD, goalCommitment: dig('x') }, undefined]);

// ---- calibration ----
const S = (arr: [number, boolean][]) => arr.map(([score, faithful]) => ({ score, faithful }));
const cals: any[] = [{ alpha: 0.1, samples: S([[0.1, false], [0.2, false], [0.3, false], [0.4, false], [0.5, false], [0.6, false], [0.7, false], [0.8, false], [0.85, false], [0.9, false], [0.95, true], [0.99, true]]) }, { alpha: 0.5, samples: S([[0.3, false], [0.6, false], [0.2, false]]) },
  { alpha: 1, samples: S([[0.3, false], [0.6, false]]) }, { alpha: 0.05, samples: S([[0.3, false], [0.6, false]]) }, { alpha: 0, samples: S([[0.3, false]]) }, { alpha: -1, samples: S([[0.3, false]]) }, { alpha: 2, samples: S([[0.3, false], [0.1, false]]) }, { alpha: 0.1, samples: [] },
  { alpha: 0.1, samples: S([[0.9, true], [0.8, true]]) }, { alpha: 'x', samples: S([[0.3, false]]) }, { samples: S([[0.3, false]]) }, { alpha: 0.2 }, { alpha: 0.2, samples: 'x' }, { alpha: 0.2, samples: [null, 5, { score: 'x', faithful: false }, { score: 0.4, faithful: false }, { score: 0.4, faithful: 'no' }, { score: 0.2, faithful: false }] },
  { alpha: 0.3, samples: S(Array.from({ length: 20 }, (_, i) => [i / 20, i % 3 === 0] as [number, boolean])) }, null, 5, {}];
for (const c of cals) await run('conformalThreshold', (x: any) => inf(INT.conformalThreshold(x)), [c]);
for (const c of cals.slice(0, 8)) for (const cut of [0, 0.25, 0.5, 0.75, 0.99, 1]) await run('empiricalFalseAllowRate', INT.empiricalFalseAllowRate, [c?.samples ?? [], cut]);

// ---- threshold ----
const base = { judgeKeys: JK, k: 2, goalCommitment: GC, actionDigest: AD };
const sets: any[][] = [good, good.slice(0, 2), good.slice(0, 1), [], [good[0], good[0], good[1]], [good[0], sign(0, { score: 0.5 }), good[1]], [good[0], sign(0, { faithful: false }), good[1]], [good[0], good[1], sign(3, {})], [good[0], { ...good[1], sig: good[0].sig }],
  [good[0], good[1], good[2], sign(3, { score: 0.1 })], [good[0], good[1], good[2], sign(3, { faithful: false })], [sign(0, { score: 0.9 }), sign(1, { score: 0.9 }), sign(2, { score: 0.9 })], [null, 5, good[0], good[1]], [good[0], { ...good[1], actionDigest: dig('z') }], [good[0], { ...good[1], alg: 'ml-dsa-65', pq_pk: 'AAAA' }]];
const optsList: any[] = [base, { ...base, k: 1 }, { ...base, k: 3 }, { ...base, k: 4 }, { ...base, k: 0 }, { ...base, k: -1 }, { ...base, k: 1.5 }, { ...base, k: '2' }, { ...base, k: null }, { ...base, judgeKeys: JK.slice(0, 1), k: 1 }, { ...base, judgeKeys: [] }, { ...base, judgeKeys: 'x' }, { ...base, judgeKeys: ['short', JK[0], 5] },
  { ...base, actionDigest: 5 }, { ...base, goalCommitment: undefined }, { ...base, calibration: cals[0] }, { ...base, calibration: cals[1] }, { ...base, calibration: cals[2], k: 1 }, { ...base, calibration: cals[3] }, { ...base, calibration: cals[7] }, { ...base, calibration: { alpha: 0.5, samples: S([[0.5, false]]) }, k: 1 },
  { ...base, pqPins: {} }, { ...base, pqPins: { [JK[0]]: 'AAAA' } }];
for (const s of sets) for (const op of optsList) await run('verifySemanticThreshold', (vs: any, oo: any) => { const r = INT.verifySemanticThreshold(vs, oo); return { ...r, ...(r.cutoff !== undefined ? { cutoff: inf(r.cutoff) } : {}) }; }, [s, op]);

// ---- learner-bound scenarios ----
const A = 'action.params.';
const num = (path: string, lo: number, hi: number, cuts: number[], dist = 'uniform') => ({ kind: 'num', path, lo, hi, cuts, dist });
const cat = (path: string, exacts: string[], prefixes: string[] = []) => ({ kind: 'cat', path, values: [...exacts.map((v) => ({ kind: 'exact', value: v })), ...prefixes.map((v) => ({ kind: 'prefix', value: v })), { kind: 'other', value: '⊥' }] });
const vsp = (verb: string, reversibility: string, weight: number, dims: any[]) => ({ verb, reversibility, weight, dims });
const refund = vsp('stripe.refund', 'irreversible', 0.5, [num(A + 'amount', 0, 100, [10, 50]), cat(A + 'recipient', ['bob'], ['team-'])]);
const send = vsp('gmail.send', 'rate_limited', 0.25, [cat(A + 'to', ['a', 'b'], ['p-'])]);
const cal = vsp('calendar.create', 'reversible', 0.25, [num(A + 'hour', 0, 23, [9, 17]), num(A + 'count', 0, 4, [2])]);
const OM = { v: 1, verbs: [refund, send, cal], approximate: [] };
const w = (field: string, op: string, value: any) => ({ field, op, value });
const POL = { predicates: [{ verb: 'stripe.refund', resource: '*', where: [w(A + 'amount', 'lte', 50), w(A + 'recipient', 'in', ['bob'])] }, { verb: 'gmail.send', resource: '*', where: [w(A + 'to', 'prefix', 'p-')] }, { verb: 'calendar.create', resource: '*', where: [w(A + 'hour', 'gte', 9)] }], caveats: [] };
const adm = P.admitter(POL);
const allCells = (vs: any): number[][] => { const t = O.verbCellCount(vs); const r: number[][] = []; for (let f = 0; f < t; f++) r.push(O.decodeCell(vs, f)); return r; };
function obsAll(vsList: any[], every: number): any[] {
  const out: any[] = []; let i = 0;
  for (const vs of vsList) for (const idx of allCells(vs)) { if (i++ % every !== 0) continue; const oc = O.cellRep(vs, idx); out.push({ verb: vs.verb, values: oc.values, y: adm.admits(vs, oc) ? 1 : 0, source: i % 7 === 0 ? 'runtime' : 'elicitation' }); }
  return out;
}
const mk = (omega: any, mo: any, obs: any[]) => { const l = M.createLearner(omega, mo); for (const x of obs) l.observe({ verb: x.verb, values: x.values }, x.y, x.source); return l; };
const outcomes = (vsList: any[], step: number): any[] => vsList.flatMap((vs) => allCells(vs).filter((_, i) => i % step === 0).map((idx) => O.cellRep(vs, idx)));
const extra = [{ verb: 'nope', values: {} }, { verb: 'stripe.refund', values: { [A + 'amount']: 1000, [A + 'recipient']: 'bob' } }, { verb: 'stripe.refund', values: { [A + 'amount']: 5 } }];
const routeOpts: any[] = [{}, { theta2: 0.1 }, { theta2: 0.9, hMax: 100 }, { hMax: 0 }, { theta2: 0 }, { bondPolicy: { floor: 5, k: 2, maxOpenClaims: 1, maxOpenAmount: 1 } }, { bondPolicy: { floor: 1, k: 1, maxOpenClaims: 1, maxOpenAmount: 1, curve: { kind: 'power', gamma: 2 } } }, { bondPolicy: { floor: 1, k: 1, maxOpenClaims: 1, maxOpenAmount: 1, curve: { kind: 'piecewise', tiers: [] } } }];
const routeScenario = (omega: any, mo: any, obs: any[], outs: any[], ro: any) => { const l = mk(omega, mo, obs); return outs.map((x: any) => RT.routeAction(l, x, ro)); };
for (const [mo, every] of [[{}, 1], [{}, 2], [{}, 5], [{ eta: 0.1 }, 1], [{ tau: 0.9, eta: 0.1 }, 2], [{ hypothesisClass: { kind: 'union', k: 2 } }, 3]] as any[]) {
  for (const ro of routeOpts) await run('routeScenario', routeScenario, [OM, mo, obsAll([refund, send, cal], every), [...outcomes([refund, send, cal], 2), ...extra], ro]);
}
await run('routeScenario', routeScenario, [OM, {}, [], [...outcomes([refund, send, cal], 3), ...extra], {}]);
// runtime veto then route
await run('routeVetoScenario', (omega: any, mo: any, obs: any[], outs: any[], ro: any) => { const l = mk(omega, mo, obs); for (const x of outs) l.observe(x, 0, 'runtime'); return outs.map((x: any) => RT.routeAction(l, x, ro)); }, [OM, {}, obsAll([refund, send, cal], 1), outcomes([cal], 3), {}]);

// conformance
const ctx = { intentRef: dig('ref'), mapDigest: dig('map'), statementText: 'refund up to 50', slots: { verbs: ['stripe.refund'], constraints: [] }, goalCommitment: GC };
function conformance(omega: any, mo: any, obs: any[], oc: any, c: any, verdicts: any[], copts: any): Promise<any> | any {
  const l = mk(omega, mo, obs);
  const input = RT.judgeInputOf(l, oc, c);
  const att = RT.intentConformanceAttestation(input, verdicts, copts);
  const muts: ((a: any) => any)[] = [(a) => a, (a) => { a.ok = !a.ok; return a; }, (a) => { a.aggregate_score_ppm += 1; return a; }, (a) => { a.verdict_digests.pop(); return a; }, (a) => { a.k += 1; return a; }, (a) => { a.reason = 'x'; return a; }];
  const tampered = muts.map((f) => RT.verifyICAtt(f(JSON.parse(JSON.stringify(att))), input, verdicts, copts));
  tampered.push(RT.verifyICAtt(att, input, verdicts.slice(1), copts));
  return RT.checkIntentConformance({ verdicts: () => verdicts }, input, copts).then((check: any) => ({ input, att, digest: RT.icAttDigest(att), verify: RT.verifyICAtt(att, input, verdicts, copts), tampered, check }));
}
const l0 = mk(OM, {}, obsAll([refund, send, cal], 1));
const outC = [outcomes([refund], 4)[1], outcomes([send], 1)[0], outcomes([cal], 4)[2]];
for (const oc of outC) {
  const input = RT.judgeInputOf(l0, oc, ctx);
  const sg = (i: number, v: any) => INT.signJudgeVerdict(J[i], { actionDigest: input.actionDigest, goalCommitment: GC, faithful: true, score: 0.9, judgeMeasurement: 'm', ...v });
  const vs3 = [sg(0, {}), sg(1, { score: 0.8 }), sg(2, { score: 0.95 })];
  for (const [verdicts, copts] of [[vs3, { judgeKeys: JK, k: 2 }], [vs3.slice(0, 1), { judgeKeys: JK, k: 2 }], [[...vs3, sg(3, { faithful: false })], { judgeKeys: JK, k: 3 }], [vs3, { judgeKeys: JK, k: 2, calibration: cals[0] }], [vs3, { judgeKeys: JK, k: 2, calibration: cals[1] }], [vs3, { judgeKeys: JK.slice(0, 1), k: 1 }], [[], { judgeKeys: JK, k: 1 }], [vs3, { judgeKeys: JK, k: 0 }], [[{ ...vs3[0], actionDigest: dig('q') }, vs3[1]], { judgeKeys: JK, k: 1 }]] as any[]) {
    await run('conformanceScenario', conformance, [OM, {}, obsAll([refund, send, cal], 1), oc, ctx, verdicts, copts]);
  }
}
await run('conformanceScenario', conformance, [OM, {}, [], { verb: 'nope', values: {} }, ctx, [], { judgeKeys: JK, k: 1 }]);

// jit
const jitScenario = (omega: any, mo: any, obs: any[], oc: any, decision: string, c: any) => {
  const l = mk(omega, mo, obs);
  const req = RT.jitConsentRequest(l, oc, { intentRef: c.intentRef, mapDigest: c.mapDigest });
  return { req, digest: RT.jitConsentDigest(req), result: RT.recordJitDecision(l, req, decision), metrics: l.metrics(), route: RT.routeAction(l, oc, {}) };
};
for (const oc of [outcomes([refund], 2)[0], outcomes([refund], 2)[1], outcomes([refund], 1)[3]]) for (const d of ['approve', 'deny']) for (const [mo, every] of [[{}, 1], [{ eta: 0.1 }, 2]] as any[]) await run('jitScenario', jitScenario, [OM, mo, obsAll([refund, send, cal], every), oc, d, ctx]);
await run('jitScenario', jitScenario, [OM, {}, [], { verb: 'nope', values: {} }, 'approve', ctx]);
refWrite(o, 'intent-routing');
