// Oracle: @atlasauth/pca-intent Intent Map (map.ts) and its committed form (map-commit.ts). Deterministic.
// PORTING (fn(args) -> native entry point, comparison rule; JSON value equality):
//   mapScenario(omega, mapOpts, observations, intentRef, secretSeed) -> {map, digest, grantDigest, verify, tampered[], options, omegaRoundtrip, commit}
//     createLearner(omega, mapOpts) -> observe each {verb, values, y, source, region?} -> emitIntentMap(l, intentRef);
//     digest = intentMapDigest(map); verify = verifyIntentMap(map) (a "replay failed: ..." problem is compared as "replay failed");
//     tampered = verifyIntentMap over fixed mutations of the map; options = mapLearnerOptions(map); omegaRoundtrip = omegaToJSON(omegaFromJSON(map.omega));
//     commit = commitIntentMap(map, secret) with secret[i] = (secretSeed + 7 i) mod 256: {map_commit, size, leaves, disclosures} (disclose first/middle/last cell of every verb).
//   commitIntentMap(map) -> {map_commit, size, leaves} with secret[i] = (3 + 7 i) mod 256 (throws on a malformed map or a short secret: the 31-byte case passes secret length 31 to the native)
//   grantDigest(g) / intentMapDigest(m) / omegaToJSON(omega) / omegaFromJSON(j)
//   divergence(omega, mapOpts, observations, [{outcome, y}]) -> applyDivergence results
import * as M0 from '../../../packages/pca-intent/src/map';
import * as MC0 from '../../../packages/pca-intent/src/map-commit';
import * as O0 from '../../../packages/pca-intent/src/omega';
import * as P0 from '../../../packages/pca-intent/src/policy';
import { Oracle, refWrite } from './lib.mjs';

const M: any = (M0 as any).default ?? M0;
const MC: any = (MC0 as any).default ?? MC0;
const O: any = (O0 as any).default ?? O0;
const P: any = (P0 as any).default ?? P0;
const o = new Oracle('intent-map', 'tools/pca-audit/oracles/intent-map.mts', 'TS-reference oracle for the intent map and its committed form.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);

const A = 'action.params.';
const num = (path: string, lo: number, hi: number, cuts: number[], dist = 'uniform') => ({ kind: 'num', path, lo, hi, cuts, dist });
const cat = (path: string, exacts: string[], prefixes: string[] = []) => ({ kind: 'cat', path, values: [...exacts.map((v) => ({ kind: 'exact', value: v })), ...prefixes.map((v) => ({ kind: 'prefix', value: v })), { kind: 'other', value: '⊥' }] });
const vsp = (verb: string, reversibility: string, weight: number, dims: any[]) => ({ verb, reversibility, weight, dims });
const omegaOf = (...verbs: any[]) => ({ v: 1, verbs, approximate: [] });
const refund = vsp('stripe.refund', 'irreversible', 1, [num(A + 'amount', 0, 100, [10, 50]), cat(A + 'recipient', ['bob'], ['team-'])]);
const send = vsp('gmail.send', 'rate_limited', 0.5, [cat(A + 'to', ['a', 'b'], ['p-'])]);
const cal = vsp('calendar.create', 'reversible', 1, [num('action.params.hour', 0, 23, [9, 17]), num(A + 'count', 0, 10, [5], 'loguniform')]);
const flat = vsp('v.a', 'reversible', 1, [num(A + 'a', 0, 2, [1, 2])]);
const derived = O.deriveOmega({ policies: [{ predicates: [{ verb: 'files.write', resource: '/shared/*' }, { verb: 'stripe.refund', where: [{ field: A + 'amount', op: 'lte', value: 100 }] }], caveats: [] }] });
const OM: Record<string, any> = { A: omegaOf(refund), B: omegaOf(refund, send), C: omegaOf(cal), E: omegaOf(flat), F: omegaOf(send, flat), G: derived, H: { ...omegaOf(refund, send), verbs: [{ ...refund, weight: 3 }, { ...send, weight: 1 }] } };
const w = (field: string, op: string, value: any) => ({ field, op, value });
const pol = (...ps: any[]) => ({ predicates: ps, caveats: [] });
const POL: Record<string, any> = {
  A: pol({ verb: 'stripe.refund', resource: '*', where: [w(A + 'amount', 'lte', 50), w(A + 'recipient', 'in', ['bob'])] }),
  B: pol({ verb: 'stripe.refund', resource: '*', where: [w(A + 'amount', 'lte', 10)] }, { verb: 'gmail.send', resource: '*', where: [w(A + 'to', 'prefix', 'p-')] }),
  C: pol({ verb: 'calendar.create', resource: '*', where: [w(A + 'hour', 'gte', 9)] }),
  E: pol({ verb: 'v.a', resource: '*', where: [w(A + 'a', 'lte', 1)] }),
  F: pol({ verb: 'gmail.send', resource: '*', where: [w(A + 'to', 'eq', 'a')] }, { verb: 'v.a', resource: '*', where: [w(A + 'a', 'gte', 1)] }),
  G: pol({ verb: 'stripe.refund', resource: '*', where: [w(A + 'amount', 'lte', 100)] }),
  H: pol({ verb: 'stripe.refund', resource: '*', where: [w(A + 'amount', 'lte', 10)] }),
};
let st = 777;
const rnd = () => { st = (st * 1103515245 + 12345) & 0x7fffffff; return st / 0x7fffffff; };
const allCells = (vs: any): number[][] => { const t = O.verbCellCount(vs); const r: number[][] = []; for (let f = 0; f < t; f++) r.push(O.decodeCell(vs, f)); return r; };
function obsScript(key: string, nObs: number, withRuntime = false): any[] {
  const omega = OM[key]; const adm = P.admitter(POL[key]); const out: any[] = [];
  for (let i = 0; i < nObs; i++) {
    const vs = omega.verbs[Math.floor(rnd() * omega.verbs.length)];
    const cells = allCells(vs); const idx = cells[Math.floor(rnd() * cells.length)];
    const oc = O.cellRep(vs, idx);
    out.push({ verb: vs.verb, values: oc.values, y: adm.admits(vs, oc) ? 1 : 0, source: withRuntime && i % 4 === 3 ? 'runtime' : i % 5 === 4 ? 'witness' : 'elicitation' });
  }
  return out;
}
const sec = (seed: number) => Uint8Array.from({ length: 32 }, (_, i) => (seed + 7 * i) & 255);
const clone = (x: any) => JSON.parse(JSON.stringify(x));
const normProblems = (r: any) => ({ ok: r.ok, problems: r.problems.map((p: string) => (p.startsWith('replay failed') ? 'replay failed' : p)) });
function disclosures(omega: any, cm: any): any[] {
  const out: any[] = [];
  for (const vs of omega.verbs) {
    const t = O.verbCellCount(vs);
    for (const f of [0, Math.floor(t / 2), t - 1]) {
      const oc = O.cellRep(vs, O.decodeCell(vs, f));
      const params: any = {}; let resource: any;
      for (const [k, v] of Object.entries(oc.values)) { if (k === 'action.resource') resource = v; else params[k.slice('action.params.'.length)] = v; }
      out.push(cm.disclose({ verb: vs.verb, resource }, params));
    }
  }
  return out;
}
function mapScenario(omega: any, mapOpts: any, observations: any[], intentRef: string | null, secretSeed: number): any {
  const l = M.createLearner(omega, mapOpts);
  for (const x of observations) l.observe({ verb: x.verb, values: x.values }, x.y, x.source, x.region);
  const map = M.emitIntentMap(l, intentRef);
  const muts: ((m: any) => any)[] = [
    (m) => m, (m) => { m.metrics.residual_risk_ppm += 5; return m; }, (m) => { m.cells[0].p_ppm += 3; return m; }, (m) => { m.cells[0].in_grant = !m.cells[0].in_grant; return m; },
    (m) => { m.grant_digest = 'AAAA'; return m; }, (m) => { m.observations.pop(); return m; }, (m) => { m.kind = 'x'; return m; }, (m) => { m.principals = ['a', 'b']; return m; },
    (m) => { m.aggregation = { rule: 'unanimity' }; return m; }, (m) => { delete m.metrics.log2_vs_mbits; return m; }, (m) => { m.learner.eta_ppm += 100000; return m; }, (m) => { m.metrics.questions += 1; return m; },
    (m) => { m.cells.pop(); return m; }, (m) => { m.omega.verbs[0].w = 5; return m; }, (m) => { m.metrics.log2_vs_mbits = null; return m; }, (m) => { m.cells[0].p_ppm += 2; return m; }, (m) => { m.cells[0].p_ppm += 1; return m; },
  ];
  const tampered = muts.map((f) => normProblems(M.verifyIntentMap(f(clone(map)))));
  tampered.push(normProblems(M.verifyIntentMap(null)), normProblems(M.verifyIntentMap({ v: 2 })));
  let commit: any;
  try {
    const cm = MC.commitIntentMap(map, sec(secretSeed));
    commit = { map_commit: cm.map_commit, size: cm.size, leaves: cm.leaves, disclosures: disclosures(omega, cm) };
  } catch (e) { commit = { error: true }; }
  return { map, digest: M.intentMapDigest(map), grantDigest: M.grantDigest(map.grant), verify: normProblems(M.verifyIntentMap(map)), tampered, options: M.mapLearnerOptions(map), omegaRoundtrip: M.omegaToJSON(M.omegaFromJSON(map.omega)), commit };
}

const optsets: any[] = [
  {}, { eta: 0.1 }, { tau: 0.9 }, { strategy: 'risk' }, { nullMass: 0.3 }, { nullMass: { 'stripe.refund': 0.4 }, defaultNullMass: 0.1 }, { nullMass: { toString: 0.5 } },
  { hypothesisClass: { kind: 'union', k: 2, decay: 0.3333333 } }, { hypothesisClass: { kind: 'decision-list', maxRules: 1 } }, { hypothesisClass: { kind: 'decision-list', maxRules: 2, conditions: 'atomic', decay: 0.5 } },
  { agnosticSlack: 1 }, { etaPos: 0.05, etaNeg: 0.15 }, { eta: 0.0000004 }, { monotone: { paths: [A + 'amount'], offMass: 0.25 } }, { monotone: { paths: [A + 'amount'] } },
  { priorMix: { beta: 0.3, cells: [{ verb: 'stripe.refund', cell: 0, q: 0.5 }, { verb: 'stripe.refund', cell: 3, q: 0.9 }, { verb: 'gmail.send', cell: 1, q: 0.25 }, { verb: 'v.a', cell: 99, q: 0.1 }] } },
  { priorMix: { beta: 0, cells: [] } },
];
for (const key of ['A', 'B', 'C', 'E', 'F', 'G', 'H']) {
  for (const op of optsets) {
    if (key === 'G' && (op.hypothesisClass || op.monotone === undefined && false)) continue;
    const o2 = { ...op };
    await run('mapScenario', mapScenario, [OM[key], o2, obsScript(key, 7, !!op.agnosticSlack || op.eta === undefined), key === 'A' ? 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' : null, 5 + n]);
  }
  await run('mapScenario', mapScenario, [OM[key], { anchor: { policy: POL[key], lambda: 2.5 } }, obsScript(key, 5), null, 11]);
  await run('mapScenario', mapScenario, [OM[key], { anchors: [{ policy: POL[key], lambda: 1.0005 }, { policy: POL.E, lambda: 3 }], hypothesisClass: { kind: 'union', k: 2 } }, obsScript(key, 5), null, 12]);
  await run('mapScenario', mapScenario, [OM[key], { anchor: { policy: POL[key], lambda: 0.0004 }, anchors: [] }, [], 'x', 13]);
  await run('mapScenario', mapScenario, [OM[key], {}, [], null, 14]);
}
// errors
for (const bad of [{ priorMix: { beta: 0.3, cells: [{ verb: 'v.a', cell: 0, q: 2 }] } }, { priorMix: { beta: 0.3, cells: [{ verb: 'v.a', cell: -1, q: 0.5 }] } }, { priorMix: { beta: 0.3, cells: [{ verb: 'v.a', cell: 1.5, q: 0.5 }] } }, { eta: 0.7 }, { agnosticSlack: -1 }, { hypothesisClass: { kind: 'union', k: 0 } }]) {
  await run('mapScenario', mapScenario, [OM.E, bad, [], null, 1]);
}
// commit errors on malformed maps
const base = (): any => { const l = M.createLearner(OM.A, {}); for (const x of obsScript('A', 4)) l.observe({ verb: x.verb, values: x.values }, x.y, x.source); return M.emitIntentMap(l, null); };
const commitMut: ((m: any) => any)[] = [(m) => m, (m) => { m.cells.pop(); return m; }, (m) => { m.cells[0].cell = [0]; return m; }, (m) => { m.cells[0].cell = [9, 0]; return m; }, (m) => { m.cells[0].cell = [-1, 0]; return m; }, (m) => { m.cells[1].cell = [...m.cells[0].cell]; return m; },
  (m) => { m.omega.verbs.push(clone(m.omega.verbs[0])); return m; }, (m) => { m.metrics.questions = -1; return m; }, (m) => { m.metrics.log2_vs_mbits = null; return m; }, (m) => { m.cells[0].p_ppm = 2000000; return m; }, (m) => { m.omega.verbs[0].dims[0].cuts = [10, 50, 500, -3]; return m; }, (m) => { m.omega.verbs[0].dims[1].values = []; return m; }];
for (const f of commitMut) await run('commitIntentMap', (m: any) => { const cm = MC.commitIntentMap(m, sec(3)); return { map_commit: cm.map_commit, size: cm.size, leaves: cm.leaves }; }, [f(clone(base()))]);
// standalone digests
await run('grantDigest', M.grantDigest, [{ predicates: [], caveats: [] }]);
await run('grantDigest', M.grantDigest, [{ predicates: [] }]);
await run('grantDigest', M.grantDigest, [POL.A]);
await run('grantDigest', M.grantDigest, [{ predicates: [{ verb: 'x', resource: '*', where: [w(A + 'a', 'lte', 1.5)] }], caveats: [{ type: 'reversibility_max', class: 'reversible' }] }]);
await run('intentMapDigest', M.intentMapDigest, [base()]);
await run('intentMapDigest', M.intentMapDigest, [{ v: 1, kind: 'pca-intent-map' }]);
for (const k of ['A', 'B', 'H', 'G']) { await run('omegaToJSON', M.omegaToJSON, [OM[k]]); await run('omegaFromJSON', (j: any) => M.omegaFromJSON(j), [M.omegaToJSON(OM[k])]); }
await run('omegaFromJSON', (j: any) => M.omegaFromJSON(j), [{ verbs: [{ verb: 'v', reversibility: 'reversible', w: 2, dims: [{ kind: 'num', path: A + 'x', lo: 0, hi: 5 }, { kind: 'cat', path: A + 'y' }] }], approximate: ['x'] }]);
// divergence
for (const key of ['A', 'B', 'E']) {
  const vs = OM[key].verbs[0]; const cells = allCells(vs);
  const divs = [0, Math.floor(cells.length / 2), cells.length - 1].flatMap((i) => [{ outcome: O.cellRep(vs, cells[i]), y: 0 }, { outcome: O.cellRep(vs, cells[i]), y: 1 }]);
  await run('divergence', (omega: any, mo: any, obs: any[], ds: any[]) => { const l = M.createLearner(omega, mo); for (const x of obs) l.observe({ verb: x.verb, values: x.values }, x.y, x.source); return ds.map((d) => M.applyDivergence(l, d.outcome, d.y)); }, [OM[key], {}, obsScript(key, 6), divs]);
  await run('divergence', (omega: any, mo: any, obs: any[], ds: any[]) => { const l = M.createLearner(omega, mo); for (const x of obs) l.observe({ verb: x.verb, values: x.values }, x.y, x.source); return ds.map((d) => M.applyDivergence(l, d.outcome, d.y)); }, [OM[key], { eta: 0.1 }, obsScript(key, 6), divs]);
}
refWrite(o, 'intent-map');
