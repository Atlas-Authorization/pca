// Oracle: @atlasauth/pca-analyzer (static analyzability of authority: the bounded decision engine, reachability / subsumption / equivalence /
// intent conformance, quantitative exposure, residual policies and what-may-I-do, SQL and UCAST filters, narrowing, coverage, minimal-flip
// counterfactuals, schema validation and the policy test runner). Policies are plain JSON (a bare {predicates, caveats?, vetoes?, tighten?, meet?}),
// so a native takes them as parsed JSON trees. Numbers that are not finite come back as {"$num": "Infinity"}; a throw is {"$throws": message}.
// Keys are LABELS: the Ed25519 key of a label is seed("atlas-pca-conformance/" + label) (sha256) and "$key:LABEL" stands for its b64u public key.
// Deliberately NOT in the corpus (JavaScript `undefined` has no JSON form): conditions without a `value`, vetoes that are null.
// PORTING (fn(args) -> native entry point; results compared by JSON value; numbers by binary64 value):
//   analyzeCaveats(caveats)                          CaveatAnalysis.analyzeCaveats(..).toJson()
//   numericConjunctionSatisfiable(conditions)        Field.numericConjunctionSatisfiable
//   tightenInterval(iv|null, op, value)              Field.tightenInterval(iv or FULL_INTERVAL, ..).toJson()   (iv = {lo, loInclusive, hi, hiInclusive}, all finite)
//   intervalEmpty(iv|null)                           Field.intervalEmpty (null = FULL_INTERVAL)
//   fieldProbes(conditions)                          Field.fieldProbes
//   vetoesFromConstitution(constitution)             Constitution.vetoesFromConstitution
//   toModel(policy)                                  Enumerate.toModel(..).toJson()
//   collectProbes(inputs)                            Enumerate.collectProbes: {verbs, resources, revClasses, fields: [{path, values}]}, an absent value as {"$absent": true}
//   representatives(inputs)                          Enumerate.representatives(collectProbes(..)) as [{verb, resource, revClass, assignments, action: repToAction}]
//   decideAction(policy, action)                     Enumerate.decideAction(toModel(policy), action)
//   admitsConcrete(policy, action)                   Analyzer.admitsConcrete
//   vetoApplies(veto, ctx)                           Enumerate.vetoApplies
//   thresholdsOf(policy, path)                       Exposure.thresholdsOf(toModel(policy), path)
//   reachable(policy, action, opts) / alwaysDenies(policy, verb?, opts?) / alwaysAllows(policy, verb, opts?)   Analyzer.* (a missing verb argument = null)
//   subsumes / disjoint / equivalent(a, b, opts?)    Analyzer.*
//   intentConformance(policy, intent, opts?)         Analyzer.intentConformance
//   predicateNumericSatisfiable(where)               Analyzer.predicateNumericSatisfiable
//   maxExposure(policy, opts)                        Exposure.maxExposure      escalationSurface(policy, opts?)   Exposure.escalationSurface
//   delegationEnvelope(chain, opts?)                 Exposure.delegationEnvelope
//   diffPolicies(a, b, opts?)                        Exposure.diffPolicies     diffGate(diff, allow?)   Exposure.diffGate
//   findWithBackend(query, spec)                     Exposure.findWithBackend with a stub backend {name, result} (find returns result)
//   dagExposure(body)                                DagExposure.dagExposure
//   residual(policy, known, opts?) / residualPolicy(residual) / evaluateResidual(residual, ctx)   Residual.*
//   whatMayIDo(policy, verbs, known, opts?)          Residual.whatMayIDo
//   toFilter(policy, known, residualOpts, filterOpts)   Filter.toFilter(Residual.residual(..), filterOpts)
//   evalFilter(expr, row) / toUcast(expr) / evalUcast(ucast, row)    Filter.*  (evalFilter: true | false | null)
//   suggestNarrowing(policy, observed, opts?)        Narrowing.suggestNarrowing
//   signAccessRequest(request, label) / verifyAccessRequest(signed, expectedSigner?)    Narrowing.* ("$key:LABEL" in expectedSigner)
//   witnessOf(policy, action)                        Coverage.witnessOf(toModel(policy), action)
//   coverage(policy, traffic, opts?) / coverageGate(report, min?)   Coverage.*
//   minimalFlip(policy, action, opts)                Flip.minimalFlip
//   verbShapesFromActionDefs(defs) / verbShapes(src) / validatePolicyAgainstSchema(policy, src, opts?)   Validate.*
//   policyTestsDoc(policy, cases) / runPolicyTests(policy, doc, opts?) / generateBoundaryTests(policy, opts?) / decideAll(policy, doc)   TestRunner.*
//   signPolicyTests(doc, label) / verifyPolicyTests(signed, expectedSigner)   TestRunner.* ("$key:LABEL")
import * as M0 from '@atlasauth/pca-analyzer';
import * as C0 from '@atlasauth/pca';
import * as F0 from '../../../packages/pca-analyzer/src/field';
import { Oracle, refWrite, seed, reparse, jsonOut } from './lib.mjs';

const M: any = (M0 as any).default ?? M0;
const fieldProbes: any = ((F0 as any).default ?? F0).fieldProbes;
const C: any = (C0 as any).default ?? C0;
const o = new Oracle('analyzer', 'tools/pca-audit/oracles/analyzer.mts', 'TS-reference oracle for @atlasauth/pca-analyzer.');
const pub = (label: string): string => C.b64u(C.publicKeyOf(seed(label)));
const keyed = (v: any): any => {
  if (typeof v === 'string') return v.startsWith('$key:') ? pub(v.slice(5)) : v;
  if (Array.isArray(v)) return v.map(keyed);
  if (v !== null && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, keyed(x)]));
  return v;
};

/** {"$num": "Infinity"} back to the number (a diff carries infinite exposure deltas, which JSON cannot). */
const dec = (v: any): any => (Array.isArray(v) ? v.map(dec) : v !== null && typeof v === 'object' ? (Object.keys(v).length === 1 && typeof v.$num === 'string' ? Number(v.$num) : Object.fromEntries(Object.entries(v).map(([k, x]) => [k, dec(x)]))) : v);
const T0 = 1_800_000_000_000;
const AT = 1_900_000_000_000;

// ---- policy fixtures --------------------------------------------------------------------------------------------------------------
const amt = (op: string, value: any, field = 'amount') => ({ field: `action.params.${field}`, op, value });
const POL: Record<string, any> = {
  pay: {
    predicates: [
      { verb: 'pay', resource: '/vendors/*', where: [amt('lte', 1000), amt('in', ['usd', 'eur'], 'currency')] },
      { verb: ['read', 'list'], resource: '*' },
    ],
    caveats: [{ type: 'expires', at: AT }, { type: 'rate', max: 5, per_secs: 60 }],
  },
  gated: {
    predicates: [
      { verb: 'pay', where: [amt('lte', 9000)] },
      { verb: 'refund', resource: '/orders/*', where: [amt('lt', 100)] },
    ],
    caveats: [{ type: 'reversibility_max', class: 'rate_limited' }, { type: 'budget_alloc', limit: 5000 }],
    vetoes: [
      { id: 'no-huge', kind: 'deny', when: { verb: 'pay', where: [amt('gt', 5000)] } },
      { id: 'approve-mid', kind: 'approval', when: { verb: 'pay' }, over: { path: 'action.params.amount', threshold: 2000 }, unless: [{ field: 'env.approved', op: 'eq', value: true }] },
      { id: 'no-sanctioned', kind: 'deny', when: { verb: '*', where: [{ field: 'action.params.country', op: 'in', value: ['xx', 'yy'] }] }, unless: [{ field: 'subject.waiver', op: 'eq', value: true }] },
    ],
    tighten: [
      { id: 'risk', when: { field: 'subject.risk', op: 'gt', value: 7 }, signal: 'escalate' },
      { id: 'frozen', when: { field: 'env.frozen', op: 'eq', value: true }, signal: 'deny' },
    ],
  },
  groups: {
    predicates: [{
      verb: 'send',
      where: [
        { any_of: [{ field: 'action.params.channel', op: 'eq', value: 'email' }, { all_of: [{ field: 'action.params.channel', op: 'eq', value: 'sms' }, amt('lte', 160, 'len')] }] },
        { not: { field: 'action.params.to', op: 'prefix', value: '+1900' } },
      ],
    }],
  },
  regex: {
    predicates: [
      { verb: 'read', resource: 're:^/docs/[a-z]+$' },
      { verb: 'write', resource: '/tmp/*', where: [{ field: 'action.params.name', op: 'like', value: 'a%' }] },
    ],
  },
  refs: { predicates: [{ verb: 'xfer', where: [{ field: 'action.params.amount', op: 'lte', ref: 'subject.limit' }] }] },
  chain: {
    predicates: [{ verb: 'pay', where: [amt('lte', 500)] }],
    caveats: [{ type: 'delegation_depth', max: 3 }],
    meet: [{ predicates: [{ verb: 'pay', where: [amt('lte', 800)] }, { verb: 'read' }], caveats: [{ type: 'delegation_depth', max: 2 }, { type: 'expires', at: AT }] }],
  },
  unsat: { predicates: [{ verb: '*' }], caveats: [{ type: 'not_before', at: 2000 }, { type: 'expires', at: 1000 }] },
  empty: { predicates: [] },
  open: { predicates: [{ verb: '*' }] },
  intervals: {
    predicates: [
      { verb: 'buy', where: [amt('gte', 1, 'qty'), amt('lt', 10, 'qty'), amt('ne', 5, 'qty')] },
      { verb: 'buy', where: [amt('eq', 50, 'qty')] },
    ],
  },
  contradict: { predicates: [{ verb: 'x', where: [amt('gte', 100, 'n'), amt('lte', 10, 'n')] }] },
  verbcond: {
    predicates: [{ verb: '*', where: [{ field: 'action.verb', op: 'prefix', value: 'gh.' }, { field: 'action.resource', op: 'prefix', value: '/repo/' }, { field: 'action.params.n', op: 'exists', value: true }] }],
  },
  strnum: { predicates: [{ verb: 'pay', where: [amt('lte', '100')] }] },
  wide: {
    predicates: [{ verb: 'pay', where: [amt('lte', 20000)] }, { verb: 'refund', where: [amt('lte', 50)] }, { verb: 'read' }],
    caveats: [{ type: 'rate', max: 10, per_secs: 3600 }],
  },
  narrowv: {
    predicates: [{ verb: 'pay', resource: '/vendors/acme', where: [amt('lte', 300)] }],
    caveats: [{ type: 'rate', max: 2, per_secs: 60 }, { type: 'max_blast_radius', max: 0.5 }],
  },
};
const NAMES = Object.keys(POL);
const MONEY = ['pay', 'gated', 'wide', 'narrowv', 'chain'];

const CONSTITUTION = {
  invariants: [
    { id: 'cap-day', kind: 'cap', when: { verb: 'pay' }, amount: 'action.params.amount', max: 3000, window_secs: 86400 },
    { id: 'rate-pay', kind: 'rate', when: { verb: 'pay' }, max: 3, window_secs: 3600 },
    { id: 'never-bad', kind: 'never', when: { verb: 'pay', resource: '/vendors/bad' } },
    { id: 'nu', kind: 'never_unless', when: { verb: 'refund' }, unless: [{ field: 'env.approved', op: 'eq', value: true }] },
    { id: 'ap', kind: 'require_approval_over', when: { verb: 'pay' }, amount: 'action.params.amount', threshold: 700, approved: [{ field: 'env.approved', op: 'eq', value: true }] },
    { id: 'na', kind: 'never_after', after: { verb: 'a' }, forbid: { verb: 'b' } },
    { id: 'rp', kind: 'require_prior', when: { verb: 'deploy' }, prior: { verb: 'review' } },
  ],
};
const LIFETIME_CAP = { invariants: [{ id: 'cap-life', kind: 'cap', when: { verb: 'pay' }, amount: 'action.params.amount', max: 2500 }, { id: 'cap-part', kind: 'cap', when: { verb: 'pay', resource: '/x' }, amount: 'action.params.amount', max: 10 }] };

// ---- helpers -----------------------------------------------------------------------------------------------------------------------
const ra = reparse;
const run = (fn: string, name: string, ref: any, args: any[]) => o.run(fn, name, ref, args);
const model = (p: any) => M.toModel(ra(p));
/** Deterministic concrete actions of a policy: an even sample of its own representative grid. */
function poolOf(p: any, n: number): any[] {
  const m = model(p);
  const pr = M.collectProbes({ predicateSets: [M.probeSet(m)], varyReversibility: m.revCap !== undefined });
  const size = pr.verbs.length * pr.resources.length * pr.revClasses.length * pr.fields.reduce((a: number, f: any) => a * f.values.length, 1);
  if (size > 60_000) return [];
  const reps = [...M.representatives(pr)];
  const step = Math.max(1, Math.floor(reps.length / n));
  const out: any[] = [];
  for (let i = 0; i < reps.length && out.length < n; i += step) out.push(M.repToAction(reps[i]));
  return out;
}
const POOLS: Record<string, any[]> = {};
for (const k of NAMES) POOLS[k] = poolOf(POL[k], 36);
const ACT = (verb: string, resource: string, params: any = {}, extra: any = {}) => ({ verb, resource, params, ...extra });

// ---- pure engine pieces ------------------------------------------------------------------------------------------------------------
const CAV: any[][] = [
  [], [{ type: 'expires', at: AT }], [{ type: 'not_before', at: 5 }, { type: 'expires', at: 10 }], [{ type: 'not_before', at: 10 }, { type: 'expires', at: 10 }],
  [{ type: 'rate', max: 0, per_secs: 60 }], [{ type: 'rate', max: 0.5, per_secs: 60 }], [{ type: 'rate', max: 3, per_secs: 0 }], [{ type: 'rate', max: 3, per_secs: 60 }],
  [{ type: 'max_blast_radius', max: -1 }], [{ type: 'max_blast_radius', max: 0 }], [{ type: 'delegation_depth', max: -1 }], [{ type: 'delegation_depth', max: 4 }],
  [{ type: 'budget_alloc', limit: -1 }], [{ type: 'budget_alloc', limit: 0 }], [{ type: 'budget_alloc', limit: 'x' }],
  [{ type: 'reversibility_max', class: 'reversible' }, { type: 'reversibility_max', class: 'rate_limited' }], [{ type: 'reversibility_max', class: 'nope' }],
  [{ type: 'reversibility_max', class: ['irreversible'] }], [{ type: 'reversibility_max' }], [{ type: 'reversibility_max', class: null }], [{ type: 'reversibility_max', class: 5 }],
  [{ type: 'mystery' }], [{ type: 5 }], [null], ['x'], [{}], [{ type: 'expires' }], [{ type: 'expires', at: 'soon' }], [{ type: 'not_before', at: null }],
  [{ type: 'expires', at: -0 }], [{ type: 'rate', max: 1e21, per_secs: 1 }],
];
for (const [i, c] of CAV.entries()) await run('analyzeCaveats', `c${i}`, M.analyzeCaveats, [c]);
await run('analyzeCaveats', 'not-array-obj', M.analyzeCaveats, [{ type: 'expires', at: 1 }]);
await run('analyzeCaveats', 'not-array-null', M.analyzeCaveats, [null]);
await run('analyzeCaveats', 'not-array-str', M.analyzeCaveats, ['x']);

const COND_SETS: any[][] = [
  [], [amt('gte', 100), amt('lte', 10)], [amt('gt', 5), amt('lt', 5)], [amt('gte', 5), amt('lte', 5)], [amt('gt', 5), amt('lte', 5)], [amt('eq', 5), amt('eq', 6)], [amt('eq', 5), amt('gt', 5)],
  [amt('gte', 1), amt('lt', 10), amt('ne', 5)], [amt('gte', 100), amt('lte', 10, 'other')], [amt('gte', 'a'), amt('lte', 'b')], [{ field: 'x', op: 'gte', value: 1, ref: 'y' }],
  [{ all_of: [amt('gte', 100), amt('lte', 10)] }], [amt('lt', 5), amt('lt', 3), amt('gte', 4)], [amt('lte', 5), amt('lt', 5), amt('gte', 5)], [amt('gte', 5), amt('gt', 5), amt('lte', 5)],
  [amt('gt', 1e300), amt('lt', -1e300)], [{ op: 'gte', value: 1 }], [null, 5, 'x'],
];
for (const [i, c] of COND_SETS.entries()) {
  await run('numericConjunctionSatisfiable', `s${i}`, M.numericConjunctionSatisfiable, [c]);
  await run('predicateNumericSatisfiable', `s${i}`, M.predicateNumericSatisfiable, [c]);
}
await run('predicateNumericSatisfiable', 'not-array', M.predicateNumericSatisfiable, [{}]);
await run('predicateNumericSatisfiable', 'null', M.predicateNumericSatisfiable, [null]);
const IV = [null, { lo: 0, loInclusive: true, hi: 10, hiInclusive: false }, { lo: 5, loInclusive: false, hi: 5, hiInclusive: true }, { lo: 5, loInclusive: true, hi: 5, hiInclusive: true }, { lo: 3, loInclusive: false, hi: 9, hiInclusive: false }];
const OPS = ['eq', 'gte', 'gt', 'lte', 'lt', 'ne', 'in', 'prefix', 5, null];
const VALS = [0, 3, 5, 9, 10, 12, -1, 1.5, 'x', null, true, [1]];
for (const [ii, iv] of IV.entries()) for (const op of OPS) for (const v of VALS) {
  await run('tightenInterval', `i${ii}/${String(op)}/${JSON.stringify(v)}`, (a: any, b: any, c: any) => M.tightenInterval(a ?? M.FULL_INTERVAL, b, c), [iv, op, v]);
}
for (const [ii, iv] of IV.entries()) await run('intervalEmpty', `i${ii}`, (a: any) => M.intervalEmpty(a ?? M.FULL_INTERVAL), [iv]);
for (const iv of [{ lo: 9, loInclusive: true, hi: 1, hiInclusive: true }, { lo: 4, loInclusive: false, hi: 4, hiInclusive: false }, { lo: 4, loInclusive: true, hi: 4, hiInclusive: false }]) {
  await run('intervalEmpty', `x${JSON.stringify(iv)}`, (a: any) => M.intervalEmpty(a), [iv]);
}

const FP: any[][] = [
  [], [amt('lte', 10)], [amt('lte', 10), amt('gte', 2), amt('eq', 5)], [amt('in', ['a', 'b', 'a'])], [amt('in', [1, 2, 'x', null])], [amt('nin', [3])], [amt('prefix', '/a/'), amt('prefix', '/b')],
  [amt('eq', 'x'), amt('ne', 'y')], [amt('eq', null)], [amt('eq', true), amt('eq', 1)], [amt('like', 'a%'), amt('matches', '^a'), amt('is_a', 'Thing')], [amt('member_of', 'g'), amt('member_of', ['g1', 5, 'g2'])],
  [amt('exists', true)], [amt('lte', 5, 'o'), { field: 'z', op: 'lt', value: 1, ref: 'w' }], [{ all_of: [amt('lte', 5)] }], [amt('eq', [1, 2]), amt('eq', { a: 1 })], [amt('eq', 0), amt('eq', -0)],
  [amt('lte', 1.5), amt('lt', 2.5)], [amt('gt', 0.1), amt('lt', 0.3)], [amt('lte', 1e21), amt('gte', -1e21)], [amt('lte', 'x')], [amt('in', 'abc')], [null],
];
for (const [i, c] of FP.entries()) await run('fieldProbes', `f${i}`, fieldProbes, [c]);

for (const [i, c] of [CONSTITUTION, LIFETIME_CAP, { invariants: [] }, {}, null, { invariants: 'x' }, { invariants: [{ kind: 'nope', id: 'z' }] }, { invariants: [5] }, { invariants: [{ kind: 'never', id: 'a' }] }].entries()) {
  await run('vetoesFromConstitution', `c${i}`, M.vetoesFromConstitution, [c]);
}
await run('vetoesFromConstitution', 'null-inv', M.vetoesFromConstitution, [{ invariants: [null] }]);

// ---- model, probes, representatives --------------------------------------------------------------------------------------------------
for (const k of NAMES) await run('toModel', k, (p: any) => M.toModel(p), [POL[k]]);
for (const [i, p] of [null, 5, 'x', [], {}, { predicates: 'x' }, { predicates: [null, 5, { verb: 'a' }] }, { predicates: [], caveats: 5, vetoes: 5, tighten: 5, meet: 5 }, { predicates: [{ verb: 'a' }], meet: [null, { predicates: [{ verb: 'b', resource: 're:x' }], caveats: [{ type: 'reversibility_max', class: 'reversible' }] }] }].entries()) {
  await run('toModel', `odd${i}`, (x: any) => M.toModel(x), [p]);
}
const probesJson = (inp: any) => {
  const p = M.collectProbes(inp);
  return { ...p, fields: p.fields.map((f: any) => ({ path: f.path, values: f.values.map((v: any) => (typeof v === 'symbol' ? { $absent: true } : v)) })) };
};
const reps = (inp: any) => {
  const p = M.collectProbes(inp);
  const size = p.verbs.length * p.resources.length * p.revClasses.length * p.fields.reduce((a: number, f: any) => a * f.values.length, 1);
  if (size > 400) throw new Error('grid too large for the corpus');
  return [...M.representatives(p)].map((r: any) => ({ verb: r.verb, resource: r.resource, revClass: r.revClass, assignments: Object.fromEntries(r.assignments), action: M.repToAction(r) }));
};
const PIN: any[] = [
  { predicateSets: [], varyReversibility: false },
  { predicateSets: [[{ verb: 'a', where: [amt('lte', 3)] }]], varyReversibility: false },
  { predicateSets: [[{ verb: ['a', 'b', '*'], resource: '/x/*', where: [amt('in', ['p', 'q']), { field: 'subject.tier', op: 'gte', value: 2 }, { field: 'env.zone', op: 'eq', value: 'eu' }] }]], varyReversibility: true },
  { predicateSets: [[{ verb: 'a', resource: 're:^x$' }, { verb: 'b', resource: '/y' }, { verb: 'c', resource: '*' }]], varyReversibility: false },
  { predicateSets: [[{ verb: '*', where: [{ field: 'action.verb', op: 'in', value: ['v1', 'v2'] }, { field: 'action.resource', op: 'prefix', value: '/r' }, { field: 'action.resource', op: 'eq', value: '/exact' }, { field: 'action.resource', op: 'in', value: ['/m', '/n/*', 5] }] }]], varyReversibility: false },
  { predicateSets: [[{ verb: 'a', where: [{ not: amt('lte', 3) }, { any_of: [amt('eq', 'u'), amt('eq', 'w', 'k')] }, { all_of: [amt('gt', 1, 'j')] }] }]], varyReversibility: false },
  { predicateSets: [[{ verb: 'a' }], [{ verb: 'b', where: [amt('eq', 1)] }]], extraVerbs: ['zz'], extraResources: ['/e/*', 're:q', '*', '/plain'], extraFieldConditions: [{ path: 'action.params.amount', cond: amt('lte', 7) }], varyReversibility: true },
  { predicateSets: [[{ verb: 'a', where: [{ field: 'action.params', op: 'exists', value: true }, { field: 'action', op: 'exists', value: true }, { field: 'action.params.x.y', op: 'eq', value: 1 }, { field: 'action.reason', op: 'eq', value: 'r' }, { field: 'other.x', op: 'eq', value: 1 }, { field: 'action.params.', op: 'eq', value: 2 }] }]], varyReversibility: false },
  { predicateSets: [[null, 5, 'x', { verb: 3 }, { verb: ['z', 4] }]], varyReversibility: false },
];
for (const [i, inp] of PIN.entries()) {
  await run('collectProbes', `p${i}`, probesJson, [inp]);
  await run('representatives', `p${i}`, reps, [inp]);
}
await run('collectProbes', 'bad-resource', probesJson, [{ predicateSets: [[{ verb: 'a', resource: 5 }]], varyReversibility: false }]);
await run('collectProbes', 'null-resource', probesJson, [{ predicateSets: [[{ verb: 'a', resource: null }]], varyReversibility: false }]);
await run('collectProbes', 'bad-extra-resource', probesJson, [{ predicateSets: [], extraResources: [7], varyReversibility: false }]);

// ---- concrete decisions --------------------------------------------------------------------------------------------------------------
for (const k of NAMES) {
  const pool = POOLS[k] ?? [];
  for (const [i, a] of pool.entries()) {
    await run('decideAction', `${k}/${i}`, (p: any, x: any) => M.decideAction(M.toModel(p), x), [POL[k], a]);
    if (i % 2 === 0) await run('witnessOf', `${k}/${i}`, (p: any, x: any) => M.witnessOf(M.toModel(p), x), [POL[k], a]);
    if (i % 3 === 0) await run('admitsConcrete', `${k}/${i}`, M.admitsConcrete, [POL[k], a]);
  }
}
const HAND: any[] = [
  ACT('pay', '/vendors/a', { amount: 500, currency: 'usd' }), ACT('pay', '/vendors/a', { amount: 1000, currency: 'eur' }), ACT('pay', '/vendors/a', { amount: 1001, currency: 'usd' }),
  ACT('pay', '/vendors/a', { amount: 500 }), ACT('pay', '/other', { amount: 5, currency: 'usd' }), ACT('read', '/x'), ACT('list', '/'), ACT('pay', '/vendors/a', { amount: '500', currency: 'usd' }),
  ACT('pay', '/vendors/a', { amount: 2500, currency: 'usd' }, { reversibilityClass: 'irreversible' }), ACT('pay', '/vendors/a', { amount: 100 }, { reversibilityClass: 'reversible' }),
  ACT('pay', '/vendors/a', { amount: 6000 }, { reversibilityClass: 'reversible', env: { approved: true } }), ACT('pay', '/vendors/a', { amount: 3000 }, { reversibilityClass: 'reversible', env: { approved: true } }),
  ACT('pay', '/vendors/a', { amount: 100, country: 'xx' }, { reversibilityClass: 'reversible' }), ACT('pay', '/vendors/a', { amount: 100, country: 'xx' }, { reversibilityClass: 'reversible', subject: { waiver: true } }),
  ACT('pay', '/v', { amount: 100 }, { reversibilityClass: 'reversible', subject: { risk: 9 } }), ACT('pay', '/v', { amount: 100 }, { reversibilityClass: 'reversible', env: { frozen: true } }),
  ACT('refund', '/orders/9', { amount: 99 }, { reversibilityClass: 'rate_limited' }), ACT('refund', '/orders/9', { amount: 100 }, { reversibilityClass: 'rate_limited' }),
  ACT('send', '/m', { channel: 'email', to: '+1555' }), ACT('send', '/m', { channel: 'sms', len: 160, to: '+1555' }), ACT('send', '/m', { channel: 'sms', len: 161, to: '+1555' }), ACT('send', '/m', { channel: 'email', to: '+1900123' }),
  ACT('read', '/docs/abc'), ACT('read', '/docs/ABC'), ACT('write', '/tmp/f', { name: 'abc' }), ACT('xfer', '/a', { amount: 5 }, { subject: { limit: 9 } }), ACT('xfer', '/a', { amount: 12 }, { subject: { limit: 9 } }),
  ACT('buy', '/s', { qty: 5 }), ACT('buy', '/s', { qty: 4 }), ACT('buy', '/s', { qty: 50 }), ACT('buy', '/s', { qty: 10 }), ACT('gh.pr', '/repo/x', { n: 1 }), ACT('gh.pr', '/repo/x'),
  { verb: 'pay', resource: '/x' }, { verb: 'pay' }, { resource: '/x' }, { verb: 5, resource: '/x', params: {} }, ACT('pay', '/vendors/a', { amount: 500, currency: 'usd' }, { subject: 'x', env: null }),
];
for (const [i, a] of HAND.entries()) {
  for (const k of ['pay', 'gated', 'groups', 'regex', 'refs', 'chain', 'intervals', 'verbcond', 'open', 'empty', 'unsat', 'strnum']) {
    await run('decideAction', `hand${i}/${k}`, (p: any, x: any) => M.decideAction(M.toModel(p), x), [POL[k], a]);
    if (i % 4 === 0) await run('witnessOf', `hand${i}/${k}`, (p: any, x: any) => M.witnessOf(M.toModel(p), x), [POL[k], a]);
  }
}
const VETOS = [
  [{ id: 'v', kind: 'deny', when: { verb: 'pay' } }, ACT('pay', '/a', { amount: 1 })], [{ id: 'v', kind: 'deny', when: { verb: 'read' } }, ACT('pay', '/a')],
  [{ id: 'v', kind: 'approval', when: { verb: 'pay' }, over: { path: 'action.params.amount', threshold: 10 } }, ACT('pay', '/a', { amount: 11 })],
  [{ id: 'v', kind: 'approval', when: { verb: 'pay' }, over: { path: 'action.params.amount', threshold: 10 } }, ACT('pay', '/a', { amount: 10 })],
  [{ id: 'v', kind: 'approval', when: { verb: 'pay' }, over: { path: 'action.params.amount', threshold: 10 } }, ACT('pay', '/a', { amount: -1 })],
  [{ id: 'v', kind: 'approval', when: { verb: 'pay' }, over: { path: 'action.params.amount', threshold: 10 } }, ACT('pay', '/a', { amount: 'x' })],
  [{ id: 'v', kind: 'approval', when: { verb: 'pay' }, over: { path: 'action.params.amount', threshold: 10 } }, ACT('pay', '/a')],
  [{ id: 'v', kind: 'deny', when: { verb: 'pay' }, unless: [{ field: 'env.ok', op: 'eq', value: true }] }, ACT('pay', '/a', {}, { env: { ok: true } })],
  [{ id: 'v', kind: 'deny', when: { verb: 'pay' }, unless: [{ field: 'env.ok', op: 'eq', value: true }] }, ACT('pay', '/a', {}, { env: { ok: false } })],
  [{ id: 'v', kind: 'deny', when: { verb: 'pay' }, unless: [] }, ACT('pay', '/a')],
  [{ id: 'v', kind: 'approval', when: { verb: 'pay' }, unless: [{ field: 'env.ok', op: 'eq', value: true }] }, ACT('pay', '/a', {}, { env: { ok: true } })],
  [{ id: 'v', kind: 'deny', when: { verb: 'pay', where: [amt('gt', 5)] } }, ACT('pay', '/a')],
  [{ id: 'v', kind: 'deny', when: { verb: 'pay', where: [amt('gt', 5)] } }, ACT('pay', '/a', { amount: 1 })],
  [{ id: 'v', kind: 'deny', when: {} }, ACT('pay', '/a')], [{ id: 'v', kind: 'deny' }, ACT('pay', '/a')],
];
for (const [i, [v, a]] of VETOS.entries()) {
  await run('vetoApplies', `v${i}`, (veto: any, x: any) => M.vetoApplies(veto, { action: { ...x, params: x.params ?? {} }, subject: x.subject ?? {}, env: x.env ?? {} }), [v, a]);
}
await run('vetoApplies', 'unless-object', (veto: any, x: any) => M.vetoApplies(veto, { action: x, subject: {}, env: {} }), [{ id: 'v', kind: 'deny', when: { verb: 'pay' }, unless: { a: 1 } }, ACT('pay', '/a')]);

// ---- reachable / vacuity / relations / intent ------------------------------------------------------------------------------------------
const PARTIAL: any[] = [
  { verb: 'pay', resource: '/vendors/a' }, { verb: 'pay', resource: '/vendors/a', params: { amount: 5000 } }, { verb: 'pay', resource: '/vendors/a', params: { currency: 'gbp' } },
  { verb: 'read', resource: '/x' }, { verb: 'delete', resource: '/x' }, { verb: 'pay', resource: '/other' }, { verb: 'pay', resource: '/vendors/a', reversibilityClass: 'irreversible' },
  { verb: 'pay', resource: '/vendors/a', reversibilityClass: 'reversible', params: { amount: 100 } }, { verb: 'refund', resource: '/orders/1' }, { verb: 'send', resource: '/m', params: { channel: 'sms' } },
  { verb: 'xfer', resource: '/a', params: { amount: 5 } }, { verb: 'buy', resource: '/s' }, { verb: 'buy', resource: '/s', params: { qty: 7 } }, { verb: 'gh.x', resource: '/repo/q' }, { verb: 'x', resource: '/y' },
  { verb: 'read', resource: '/docs/abc' },
];
for (const k of NAMES) for (const [i, a] of PARTIAL.entries()) await run('reachable', `${k}/${i}`, M.reachable, [POL[k], a, {}]);
for (const k of ['pay', 'gated', 'groups', 'wide', 'intervals', 'regex']) {
  for (const mc of [0, 3, 40]) for (const [i, a] of PARTIAL.slice(0, 4).entries()) await run('reachable', `${k}/mc${mc}/${i}`, M.reachable, [POL[k], a, { maxCombinations: mc }]);
}
await run('reachable', 'bad-bound-nan', M.reachable, [POL.pay, PARTIAL[0], { maxCombinations: null }]);
await run('reachable', 'bad-bound-neg', M.reachable, [POL.pay, PARTIAL[0], { maxCombinations: -5 }]);
await run('reachable', 'null-action', M.reachable, [POL.pay, null, {}]);
await run('reachable', 'null-policy', M.reachable, [null, PARTIAL[0], {}]);

const VERBS = [null, 'pay', 'read', 'refund', 'send', 'buy', 'zzz', 'gh.pr', 'xfer'];
for (const k of NAMES) {
  for (const v of VERBS) {
    await run('alwaysDenies', `${k}/${v}`, (p: any, vb: any, op: any) => (vb === null ? M.alwaysDenies(p, undefined, op) : M.alwaysDenies(p, vb, op)), [POL[k], v, {}]);
    if (v !== null) await run('alwaysAllows', `${k}/${v}`, M.alwaysAllows, [POL[k], v, {}]);
  }
  for (const mc of [0, 2]) {
    await run('alwaysDenies', `${k}/mc${mc}`, (p: any, vb: any, op: any) => M.alwaysDenies(p, undefined, op), [POL[k], null, { maxCombinations: mc }]);
    await run('alwaysAllows', `${k}/mc${mc}`, M.alwaysAllows, [POL[k], 'pay', { maxCombinations: mc }]);
  }
}
for (const a of NAMES) for (const b of NAMES) {
  for (const [fn, f] of [['subsumes', M.subsumes], ['disjoint', M.disjoint], ['equivalent', M.equivalent]] as const) {
    if (fn !== 'equivalent' || a <= b) await run(fn, `${a}/${b}`, f, [POL[a], POL[b], {}]);
  }
}
for (const a of ['pay', 'wide', 'gated', 'groups']) for (const b of ['pay', 'narrowv', 'chain']) for (const mc of [0, 5]) {
  await run('subsumes', `${a}/${b}/mc${mc}`, M.subsumes, [POL[a], POL[b], { maxCombinations: mc }]);
  await run('equivalent', `${a}/${b}/mc${mc}`, M.equivalent, [POL[a], POL[b], { maxCombinations: mc }]);
}
await run('subsumes', 'bare-vs-meet', M.subsumes, [{ predicates: [{ verb: 'pay' }, { verb: 'read' }] }, { predicates: [{ verb: 'pay' }], meet: [{ predicates: [{ verb: 'pay', where: [amt('lte', 5)] }] }] }, {}]);

const INTENTS: any[] = [
  { verbs: ['pay'], resourceScopes: ['/vendors/*'], maxAmount: 1000 }, { verbs: ['*'], maxAmount: 10000, minAmount: 1 }, { verbs: ['read', 'list'] }, { verbs: ['pay', 'refund'], resourceScopes: ['/vendors/*', '/orders/*', 're:^/x$'], maxAmount: 500 },
  { verbs: ['pay'], maxAmount: 100 }, { verbs: ['pay'], resourceScopes: ['/vendors/a'], maxAmount: 1000, amountField: 'amount' }, { verbs: [], maxAmount: 5 }, { verbs: ['pay'], resourceScopes: ['*'], maxAmount: 0 },
  { verbs: ['buy'], maxAmount: 8, amountField: 'qty', minAmount: 2 }, { verbs: ['pay', 'read'], resourceScopes: ['/vendors/*', '/docs/*'] },
];
for (const k of NAMES) for (const [i, it] of INTENTS.entries()) await run('intentConformance', `${k}/${i}`, M.intentConformance, [POL[k], it, {}]);
for (const k of ['pay', 'gated', 'wide', 'groups']) for (const mc of [0, 10]) await run('intentConformance', `${k}/mc${mc}`, M.intentConformance, [POL[k], INTENTS[0], { maxCombinations: mc }]);
await run('intentConformance', 'bad-verbs', M.intentConformance, [POL.pay, { verbs: 'pay' }, {}]);
await run('intentConformance', 'bad-scope', M.intentConformance, [POL.pay, { verbs: ['pay'], resourceScopes: [5] }, {}]);

// ---- exposure -----------------------------------------------------------------------------------------------------------------------------
for (const k of NAMES) for (const p of ['action.params.amount', 'action.params.qty', 'action.params.zz']) await run('thresholdsOf', `${k}/${p}`, (pol: any, path: any) => M.thresholdsOf(M.toModel(pol), path), [POL[k], p]);
const EXPO: any[] = [
  { verb: 'pay' }, { verb: 'pay', windowSecs: 3600 }, { verb: 'pay', windowSecs: 86400, constitution: CONSTITUTION }, { verb: 'pay', constitution: LIFETIME_CAP }, { verb: 'pay', windowSecs: 100, constitution: LIFETIME_CAP },
  { verb: 'pay', integer: true }, { verb: 'pay', min: 10, max: 400 }, { verb: 'pay', integer: true, min: 0, max: 1e6 }, { verb: 'pay', resource: '/vendors/a' }, { verb: 'pay', resource: '/zzz' }, { verb: 'refund' }, { verb: 'read' },
  { verb: 'pay', budgetModel: 'dollars' }, { verb: 'pay', budgetModel: 'risk', kappa: 0.01 }, { verb: 'pay', budgetModel: 'risk', kappa: 0.01, blastRadius: 0.5, windowSecs: 60 }, { verb: 'pay', budgetModel: 'risk', kappa: 5, windowSecs: 60 },
  { verb: 'pay', maxCombinations: 0 }, { verb: 'pay', maxCombinations: 30 }, { verb: 'stripe.charge', budgetModel: 'risk', kappa: 0.1 }, { verb: 'pay', amountField: 'qty' }, { verb: 'pay', constitution: {} },
];
for (const k of NAMES) for (const [i, e] of EXPO.entries()) {
  if (!MONEY.includes(k) && i > 5) continue;
  await run('maxExposure', `${k}/${i}`, M.maxExposure, [POL[k], e]);
}
await run('maxExposure', 'policy-budget-model', M.maxExposure, [{ ...POL.gated, budgetModel: 'risk', riskPolicy: { kappa: 0.02 } }, { verb: 'pay', windowSecs: 60 }]);
await run('maxExposure', 'policy-budget-dollars', M.maxExposure, [{ ...POL.gated, budgetModel: 'dollars' }, { verb: 'pay' }]);
await run('maxExposure', 'null-policy', M.maxExposure, [null, { verb: 'pay' }]);
await run('maxExposure', 'rate-caveat-window', M.maxExposure, [POL.pay, { verb: 'pay', windowSecs: 1 }]);
for (const k of NAMES) {
  await run('escalationSurface', `${k}`, M.escalationSurface, [POL[k], {}]);
  await run('escalationSurface', `${k}/pay`, M.escalationSurface, [POL[k], { verb: 'pay', limit: 3 }]);
}
await run('escalationSurface', 'mc0', M.escalationSurface, [POL.gated, { maxCombinations: 0 }]);
await run('escalationSurface', 'limit0', M.escalationSurface, [POL.gated, { limit: 0 }]);
const CHAINS: any[] = [
  [POL.pay], [POL.wide, POL.pay], [POL.wide, POL.narrowv], [POL.wide, POL.gated, POL.pay], [POL.pay, POL.wide], [POL.chain], [POL.open, POL.chain], [{ predicates: [{ verb: 'pay' }], caveats: [{ type: 'delegation_depth', max: 1 }] }, { predicates: [{ verb: 'pay' }], caveats: [{ type: 'delegation_depth', max: 5 }] }, POL.pay],
  [], [POL.empty], [POL.unsat, POL.pay],
];
for (const [i, c] of CHAINS.entries()) {
  await run('delegationEnvelope', `c${i}`, M.delegationEnvelope, [c, {}]);
  await run('delegationEnvelope', `c${i}/mc0`, M.delegationEnvelope, [c, { maxCombinations: 0 }]);
}
const DPAIRS: [string, string][] = [['pay', 'wide'], ['wide', 'pay'], ['pay', 'pay'], ['gated', 'wide'], ['wide', 'gated'], ['narrowv', 'pay'], ['empty', 'open'], ['open', 'empty'], ['groups', 'regex'], ['refs', 'intervals'], ['unsat', 'pay'], ['chain', 'pay']];
for (const [a, b] of DPAIRS) {
  await run('diffPolicies', `${a}/${b}`, M.diffPolicies, [POL[a], POL[b], {}]);
  await run('diffPolicies', `${a}/${b}/lim1`, M.diffPolicies, [POL[a], POL[b], { limit: 1 }]);
}
for (const [a, b] of [['pay', 'wide'], ['wide', 'pay'], ['gated', 'wide'], ['narrowv', 'pay'], ['pay', 'pay'], ['wide', 'gated']] as [string, string][]) {
  await run('diffPolicies', `${a}/${b}/exp`, M.diffPolicies, [POL[a], POL[b], { exposure: { verb: 'pay' } }]);
  await run('diffPolicies', `${a}/${b}/expw`, M.diffPolicies, [POL[a], POL[b], { exposure: { verb: 'pay', windowSecs: 3600, constitution: CONSTITUTION } }]);
}
await run('diffPolicies', 'mc0', M.diffPolicies, [POL.pay, POL.wide, { maxCombinations: 0 }]);
for (const [a, b] of [['pay', 'wide'], ['wide', 'pay'], ['pay', 'pay'], ['regex', 'pay'], ['gated', 'wide']] as [string, string][]) {
  for (const exposure of [undefined, { verb: 'pay' }]) {
    const d = jsonOut(M.diffPolicies(POL[a], POL[b], exposure ? { exposure } : {}));
    for (const allow of [{}, { widen: true }, { maxExposureIncrease: 1e9 }, { widen: true, maxExposureIncrease: 100 }, undefined]) {
      await run('diffGate', `${a}/${b}/${exposure ? 'e' : 'n'}/${JSON.stringify(allow)}`, (dd: any, al: any) => (al === null ? M.diffGate(dec(dd)) : M.diffGate(dec(dd), al)), [d, allow ?? null]);
    }
  }
}
const BACKENDS: any[] = [
  [{ kind: 'reachable', a: POL.pay, verb: 'pay' }, { name: 'z3', result: { witness: ACT('pay', '/vendors/a', { amount: 5, currency: 'usd' }) } }],
  [{ kind: 'reachable', a: POL.pay, verb: 'pay' }, { name: 'z3', result: { witness: ACT('read', '/x') } }],
  [{ kind: 'reachable', a: POL.pay }, { name: 'z3', result: { witness: ACT('read', '/x') } }],
  [{ kind: 'reachable', a: POL.pay }, { name: 'cvc5', result: { witness: ACT('delete', '/x') } }],
  [{ kind: 'differs', a: POL.pay, b: POL.wide }, { name: 's', result: { witness: ACT('refund', '/r', { amount: 40 }) } }],
  [{ kind: 'differs', a: POL.pay, b: POL.pay }, { name: 's', result: { witness: ACT('read', '/x') } }],
  [{ kind: 'differs', a: POL.pay }, { name: 's', result: { witness: ACT('read', '/x') } }],
  [{ kind: 'reachable', a: POL.pay }, { name: 'z3', result: { unsat: true } }], [{ kind: 'reachable', a: POL.pay }, { name: 'z3', result: { unsat: false } }], [{ kind: 'reachable', a: POL.pay }, { name: 'z3', result: {} }],
];
for (const [i, [q, spec]] of BACKENDS.entries()) {
  await run('findWithBackend', `b${i}`, (qq: any, s: any) => M.findWithBackend({ name: s.name, find: async () => s.result }, qq), [q, spec]);
}

// ---- DAG exposure -----------------------------------------------------------------------------------------------------------------------
const step = (id: string, deps: string[] = [], over: any = {}) => ({ id, deps, cost: {}, sink: null, deny_labels: [], escalate_labels: [], ...over });
const edge = (from: string, to: string, over: any = {}) => ({ from: { step: from }, to: { step: to }, deny_labels: [], promise: null, ...over });
const BUD = (caps: any = { usd: 100 }, max_steps = 10) => ({ caps, max_steps });
const DAGS: any[] = [
  { steps: [step('a'), step('b', ['a']), step('c', ['a']), step('d', ['b', 'c'])], edges: [edge('a', 'b'), edge('a', 'c'), edge('b', 'd'), edge('c', 'd', { promise: { x: 1 } })], budget: BUD() },
  { steps: [step('a', [], { cost: { usd: 60 } }), step('b', ['a'], { cost: { usd: 60 } }), step('c', ['b'], { cost: { usd: 200 } })], edges: [edge('a', 'b')], budget: BUD({ usd: 100 }, 2) },
  { steps: [step('a'), step('s', ['a'], { sink: 'email' }), step('t', ['a'], { sink: 'http', deny_labels: ['pii'] }), step('u', ['t'], { sink: 'x', escalate_labels: ['e'] })], edges: [edge('a', 's'), edge('a', 't'), edge('t', 'u', { deny_labels: ['z'] })], budget: BUD({}, 99) },
  { steps: [step('a', [], { sink: 'k' })], edges: [], budget: BUD() }, { steps: [], edges: [], budget: BUD() },
  { steps: [step('a'), step('a')], edges: [], budget: BUD() }, { steps: [step('a', ['b']), step('b', ['a'])], edges: [], budget: BUD() }, { steps: [step('a', ['zz'])], edges: [], budget: BUD() },
  { steps: [step('a', [], { cost: { usd: 5, gpu: 1 } }), step('b', ['a'], { cost: { usd: 5 } })], edges: [], budget: BUD({ usd: 8, gpu: 0 }, 5) },
  { steps: [step('a', [], { sink: 'q' }), step('b', ['a'], { sink: 'q' })], edges: [edge('a', 'b', { promise: null }), edge('a', 'b', { promise: { p: 1 } })], budget: BUD({ usd: 1, '5': 2, b: 3 }, 1) },
  { steps: [step('a'), step('b'), step('c', ['a', 'b']), step('d', ['c']), step('e', ['c']), step('f', ['d', 'e']), step('g', ['f'])], edges: [], budget: BUD({}, 3) },
  { steps: [step('a', ['b'])], edges: [], budget: BUD() }, { steps: [step('a')], edges: [edge('a', 'zz')], budget: BUD() }, { steps: [step('a', [], { sink: 'x' })], edges: [edge('zz', 'a')], budget: BUD() },
  { steps: 'x', edges: [], budget: BUD() }, { steps: [step('a')], edges: [], budget: {} }, { steps: [step('a')], edges: 5, budget: BUD() },
];
{
  const wide = [step('r')];
  const edgesW: any[] = [];
  for (let layer = 0; layer < 22; layer++) {
    const prev = layer === 0 ? ['r'] : [`l${layer - 1}x`, `l${layer - 1}y`];
    wide.push(step(`l${layer}x`, prev), step(`l${layer}y`, prev));
  }
  DAGS.push({ steps: wide, edges: edgesW, budget: BUD({}, 100) });
}
for (const [i, d] of DAGS.entries()) await run('dagExposure', `d${i}`, M.dagExposure, [d]);

// ---- residual / what-may-I-do / filters ---------------------------------------------------------------------------------------------------
const KNOWN: any[] = [
  {}, { verb: 'pay' }, { verb: 'pay', resource: '/vendors/a' }, { verb: 'pay', resource: '/vendors/a', params: { currency: 'usd' } }, { verb: 'read', resource: '/x' }, { verb: 'nope' },
  { verb: 'pay', subject: { risk: 9 } }, { verb: 'pay', subject: { risk: 1 }, env: { approved: true, frozen: false } }, { verb: 'pay', reversibilityClass: 'irreversible' }, { verb: 'pay', reversibilityClass: 'reversible' },
  { resource: '/orders/1' }, { verb: 'send', params: { channel: 'sms' } }, { verb: 'xfer', subject: { limit: 10 } }, { verb: 'buy', params: { qty: 3 } }, { verb: 'pay', env: { frozen: true } },
];
const ROPTS: any[] = [{}, { unknown: ['action.params'] }, { unknown: ['action.params.amount'] }, { unknown: [] }, { resourceUnknown: true }, { unknown: ['subject', 'env'] }];
for (const k of NAMES) for (const [i, kn] of KNOWN.entries()) {
  await run('residual', `${k}/${i}`, M.residual, [POL[k], kn, {}]);
  if (i % 3 === 0) for (const [j, op] of ROPTS.entries()) if (j > 0) await run('residual', `${k}/${i}/o${j}`, M.residual, [POL[k], kn, op]);
}
for (const [i, kn] of [{ verb: 'pay' }, { verb: 'pay', resource: '/vendors/a' }, { verb: 'pay', subject: { risk: 1 } }].entries()) {
  for (const k of ['gated', 'chain', 'pay', 'unsat']) {
    const r = ra(M.residual(POL[k], kn, {}));
    await run('residualPolicy', `${k}/${i}`, M.residualPolicy, [r]);
    for (const [j, a] of (POOLS[k] ?? []).slice(0, 8).entries()) {
      await run('evaluateResidual', `${k}/${i}/${j}`, (rr: any, ctx: any) => M.evaluateResidual(rr, ctx), [r, { action: { verb: a.verb, resource: a.resource, params: a.params ?? {}, ...(a.reversibilityClass ? { reversibility_class: a.reversibilityClass } : {}) }, subject: a.subject ?? {}, env: a.env ?? {} }]);
    }
  }
}
const SHAPES: any[] = [
  { verb: 'pay', params: { amount: { type: 'integer', min: 0, max: 10000 }, currency: { type: 'string', values: ['usd', 'eur', 'gbp'] } } },
  { verb: 'read', params: {} }, { verb: 'refund', params: { amount: { type: 'integer' } } }, { verb: 'send', params: { channel: { type: 'string' }, len: { type: 'integer', max: 500 }, to: { type: 'string' } } },
  { verb: 'buy', params: { qty: { type: 'integer', min: 1, max: 100 } } }, { verb: 'xfer', params: { amount: { type: 'integer', min: 1 } } }, { verb: 'zzz', params: { note: { type: 'string' } } },
];
for (const k of NAMES) {
  await run('whatMayIDo', `${k}/free`, M.whatMayIDo, [POL[k], SHAPES, {}, {}]);
  await run('whatMayIDo', `${k}/risk`, M.whatMayIDo, [POL[k], SHAPES, { subject: { risk: 9 }, env: { approved: true } }, { remaining: { usd: 50 }, missingDischarges: ['kyc'] }]);
  await run('whatMayIDo', `${k}/res`, M.whatMayIDo, [POL[k], SHAPES.slice(0, 4), { resource: '/vendors/a', reversibilityClass: 'reversible' }, {}]);
}
await run('whatMayIDo', 'mc0', M.whatMayIDo, [POL.pay, SHAPES, {}, { maxCombinations: 0 }]);
await run('whatMayIDo', 'mc20', M.whatMayIDo, [POL.gated, SHAPES, {}, { maxCombinations: 20 }]);

const COLS = { 'action.resource': 'res', 'action.params.amount': 'amount', 'action.params.currency': 'cur', 'action.params.country': 't.country', 'subject.risk': 'risk', 'env.approved': 'approved', 'action.params.channel': 'ch', 'action.params.qty': 'qty' };
const FOPTS: any[] = [{ columns: COLS }, { columns: COLS, dialect: 'sqlite' }, { columns: COLS, dialect: 'mysql', include: 'admitted' }, { columns: COLS, include: 'autonomous' }, { columns: { 'action.params.amount': 'a b' } }, { columns: {} }, {}];
const FKNOWN: any[] = [{ verb: 'pay' }, { verb: 'pay', subject: { risk: 1 }, env: { approved: true } }, { verb: 'read' }, { verb: 'refund' }, { verb: 'send' }, { verb: 'buy' }, { verb: 'xfer' }, { verb: 'nope' }];
const EXPRS: any[] = [];
for (const k of NAMES) for (const [i, kn] of FKNOWN.entries()) for (const [j, fo] of FOPTS.entries()) {
  if (j > 3 && i > 1) continue;
  await run('toFilter', `${k}/${i}/${j}`, (p: any, kk: any, ro: any, f: any) => M.toFilter(M.residual(p, kk, ro), f), [POL[k], kn, {}, fo]);
  if (j <= 3) { const r = M.toFilter(M.residual(ra(POL[k]), kn, {}), fo); if (r.ok && !EXPRS.some((e) => JSON.stringify(e) === JSON.stringify(r.expr)) && EXPRS.length < 60) EXPRS.push(ra(r.expr)); }
}
const ROWS: any[] = [
  {}, { amount: 5 }, { amount: 5000, cur: 'usd' }, { amount: -1, cur: 'eur', risk: 3 }, { amount: 'x', cur: 5 }, { res: '/vendors/a', amount: 10, cur: 'usd', 't.country': 'xx', approved: true, risk: 9 },
  { res: '/orders/1', amount: 50 }, { res: '/other', cur: 'gbp' }, { ch: 'sms', qty: 3 }, { ch: 'email', qty: null }, { amount: null, cur: null }, { approved: false, risk: 8, res: '' },
];
for (const [i, e] of EXPRS.entries()) {
  await run('toUcast', `e${i}`, M.toUcast, [e]);
  const u = ra(M.toUcast(e));
  for (const [j, row] of ROWS.entries()) {
    await run('evalFilter', `e${i}/r${j}`, M.evalFilter, [e, row]);
    await run('evalUcast', `e${i}/r${j}`, M.evalUcast, [u, row]);
  }
}
for (const [i, e] of ([
  { t: 'true' }, { t: 'false' }, { t: 'cmp', col: 'a', op: 'ne', v: 1 }, { t: 'cmp', col: 'a', op: 'gte', v: 'k' }, { t: 'in', col: 'a', vs: [1, 'x', true], neg: true }, { t: 'prefix', col: 'a', prefix: 'ab_%!' },
  { t: 'null', col: 'a', isNull: false }, { t: 'coalesce', x: { t: 'cmp', col: 'a', op: 'eq', v: true }, def: true }, { t: 'not', x: { t: 'and', xs: [{ t: 'cmp', col: 'a', op: 'lt', v: 3 }, { t: 'or', xs: [] }] } },
  { t: 'and', xs: [] }, { t: 'or', xs: [{ t: 'null', col: 'b', isNull: true }, { t: 'cmp', col: 'a', op: 'eq', v: 'x' }] },
] as any[]).entries()) {
  await run('toUcast', `h${i}`, M.toUcast, [e]);
  const u = ra(M.toUcast(e));
  for (const [j, row] of ([{}, { a: 1 }, { a: 'x' }, { a: true }, { a: null }, { a: 'ab_%!c' }, { a: 5, b: null }, { a: 2, b: 1 }] as any[]).entries()) {
    await run('evalFilter', `h${i}/r${j}`, M.evalFilter, [e, row]);
    await run('evalUcast', `h${i}/r${j}`, M.evalUcast, [u, row]);
  }
}
await run('toFilter', 'veto-over-nocol', (p: any, kk: any, ro: any, f: any) => M.toFilter(M.residual(p, kk, ro), f), [POL.gated, { verb: 'pay' }, {}, { columns: { 'action.params.amount': 'amount' } }]);
await run('toFilter', 'prefix-escape', (p: any, kk: any, ro: any, f: any) => M.toFilter(M.residual(p, kk, ro), f), [{ predicates: [{ verb: 'read', resource: '/a_b%c!/*' }] }, { verb: 'read' }, {}, { columns: { 'action.resource': 'res' } }]);
await run('toFilter', 'ref', (p: any, kk: any, ro: any, f: any) => M.toFilter(M.residual(p, kk, ro), f), [POL.refs, { verb: 'xfer' }, {}, { columns: { 'action.params.amount': 'amount', 'subject.limit': 'lim' } }]);

// ---- narrowing / access requests -------------------------------------------------------------------------------------------------------
const ledger = (verb: string, resource: string, params: any, extra: any = {}) => ({ verb, resource, params, source: 'ledger', ...extra });
const OBS_PAY = [
  ...[100, 120, 150, 180, 210, 240].map((a, i) => ledger('pay', '/vendors/acme', { amount: a, currency: i % 2 ? 'usd' : 'eur' })),
  ledger('read', '/docs/a', {}), ledger('read', '/docs/b', {}), ledger('pay', '/vendors/zed', { amount: 90, currency: 'usd' }),
  { verb: 'pay', resource: '/vendors/evil', params: { amount: 999, currency: 'usd' }, source: 'agent' }, ledger('pay', '/vendors/acme', { amount: 5000, currency: 'usd' }, { outcome: 'denied' }),
  ledger('pay', '/vendors/acme', { amount: 7000, currency: 'usd' }, { outcome: 'denied' }), ledger('delete', '/x', {}, { outcome: 'denied' }),
];
const OBS: any[][] = [
  [], OBS_PAY, OBS_PAY.slice(0, 6), OBS_PAY.slice(0, 4), OBS_PAY.slice(6, 9), [ledger('pay', '/vendors/acme', { amount: 7.5, currency: 'usd' }), ...[1, 2, 3, 4, 5].map((i) => ledger('pay', '/vendors/acme', { amount: i + 0.5, currency: 'usd' }))],
  [...OBS_PAY, ledger('list', '/z', {}), ledger('pay', '/vendors/acme', { amount: 10 })],
  [{ verb: 'pay', resource: '/vendors/acme', params: { amount: 1 }, source: 'agent' }],
];
const NOPTS: any[] = [{}, { margin: 0.5 }, { minSamples: 2 }, { enumLimit: 1, minSamples: 2 }, { taskBinding: 'task-1', decay: { nowSec: 1000, expiresInSecs: 3600 } }, { minSamples: 100 }, { margin: 0 }];
for (const k of ['pay', 'wide', 'gated', 'narrowv', 'groups', 'chain', 'regex', 'empty']) for (const [i, ob] of OBS.entries()) for (const [j, no] of NOPTS.entries()) {
  if (j > 1 && i > 3) continue;
  await run('suggestNarrowing', `${k}/${i}/${j}`, M.suggestNarrowing, [POL[k], ob, no]);
}
const ARQ = ra(M.suggestNarrowing(POL.pay, OBS_PAY, {})).accessRequests;
const SIGNED: any[] = [];
for (const [i, r] of ARQ.entries()) {
  await run('signAccessRequest', `r${i}`, (req: any, label: string) => M.signAccessRequest(req, seed(label), pub(label)), [r, 'agent-1']);
  SIGNED.push(ra(M.signAccessRequest(r, seed('agent-1'), pub('agent-1'))));
}
for (const [i, s] of SIGNED.entries()) {
  for (const [name, mut] of [
    ['ok', (x: any) => x], ['bad-sig', (x: any) => ({ ...x, sig: x.sig.slice(0, -2) + 'AA' })], ['no-sig', (x: any) => ({ ...x, sig: 5 })], ['other-signer', (x: any) => ({ ...x, signer: pub('agent-2') })],
    ['changed', (x: any) => ({ ...x, request: { ...x.request, denied_count: 99 } })], ['kind', (x: any) => ({ ...x, request: { ...x.request, kind: 'other' } })], ['ver', (x: any) => ({ ...x, request: { ...x.request, v: 2 } })], ['not-obj', () => 'x'], ['no-request', (x: any) => ({ ...x, request: null })],
  ] as [string, (x: any) => any][]) {
    const sv = ra(mut(s));
    await run('verifyAccessRequest', `r${i}/${name}`, (x: any, e: any) => (e === null ? M.verifyAccessRequest(x) : M.verifyAccessRequest(x, keyed(e))), [sv, null]);
    await run('verifyAccessRequest', `r${i}/${name}/expect-ok`, (x: any, e: any) => M.verifyAccessRequest(x, keyed(e)), [sv, '$key:agent-1']);
    await run('verifyAccessRequest', `r${i}/${name}/expect-other`, (x: any, e: any) => M.verifyAccessRequest(x, keyed(e)), [sv, '$key:agent-2']);
  }
}

// ---- coverage -------------------------------------------------------------------------------------------------------------------------------
for (const k of NAMES) {
  const pool = POOLS[k] ?? [];
  await run('coverage', `${k}/pool`, M.coverage, [POL[k], pool.slice(0, 24), {}]);
  await run('coverage', `${k}/none`, M.coverage, [POL[k], [], {}]);
  await run('coverage', `${k}/hand`, M.coverage, [POL[k], HAND.filter((a) => a.verb !== undefined && typeof a.verb === 'string' && a.resource !== undefined), { epsilon: 5, maxMutants: 30 }]);
}
await run('coverage', 'pay/few-mutants', M.coverage, [POL.pay, [ACT('pay', '/vendors/a', { amount: 1000, currency: 'usd' }), ACT('pay', '/vendors/a', { amount: 1001, currency: 'usd' }), ACT('pay', '/vendors/a', { amount: 999, currency: 'usd' })], { maxMutants: 4 }]);
for (const k of ['pay', 'gated', 'wide', 'intervals', 'regex']) {
  const rep = ra(M.coverage(POL[k], (POOLS[k] ?? []).slice(0, 20), {}));
  for (const [i, mn] of [{}, { clauses: 0.5 }, { clauses: 1, boundaries: 1, mutation: 1 }, { maxSurvivors: 0 }, { maxSurvivors: 1000, mutation: 0.3, boundaries: 0.2 }].entries()) {
    await run('coverageGate', `${k}/${i}`, (r: any, m: any) => (m === null ? M.coverageGate(r) : M.coverageGate(r, m)), [rep, mn]);
  }
  await run('coverageGate', `${k}/default`, (r: any, m: any) => M.coverageGate(r), [rep, null]);
}

// ---- minimal flip ------------------------------------------------------------------------------------------------------------------------
const FSCHEMA = [
  { verb: 'pay', params: { amount: { type: 'integer', min: 0, max: 100000, sensitivity: 'critical' }, currency: { type: 'string', values: ['usd', 'eur'] } } },
  { verb: 'refund', params: { amount: { type: 'integer', min: 0 } } }, { verb: 'buy', params: { qty: { type: 'integer', min: 1, max: 200 } } },
];
const FLIPA: any[] = [
  ACT('pay', '/vendors/a', { amount: 5000, currency: 'usd' }), ACT('pay', '/vendors/a', { amount: 1500, currency: 'usd' }), ACT('pay', '/vendors/a', { amount: 500, currency: 'gbp' }), ACT('pay', '/other', { amount: 500, currency: 'usd' }),
  ACT('pay', '/other', { amount: 5000, currency: 'gbp' }), ACT('pay', '/vendors/a', { amount: 3000, currency: 'usd' }, { reversibilityClass: 'reversible' }), ACT('pay', '/vendors/a', { amount: 100, currency: 'usd' }, { reversibilityClass: 'reversible', subject: { risk: 9 } }),
  ACT('pay', '/vendors/a', { amount: 100, country: 'xx' }, { reversibilityClass: 'reversible' }), ACT('refund', '/orders/1', { amount: 150 }, { reversibilityClass: 'rate_limited' }), ACT('buy', '/s', { qty: 60 }), ACT('buy', '/s', { qty: 5 }), ACT('send', '/m', { channel: 'sms', len: 500, to: '+1900' }),
  ACT('delete', '/x', {}), ACT('pay', '/vendors/a', { amount: 5000, currency: 'usd' }, { reversibilityClass: 'irreversible' }),
];
const FOPT: any[] = [
  { holderAuthenticated: true }, { holderAuthenticated: true, schema: FSCHEMA }, { holderAuthenticated: false }, { holderAuthenticated: true, desired: 'escalate' }, { holderAuthenticated: true, redact: 'none', schema: FSCHEMA },
  { holderAuthenticated: true, redact: 'all', schema: FSCHEMA }, { holderAuthenticated: true, allowSplit: true, schema: FSCHEMA }, { holderAuthenticated: true, changeable: ['amount'] }, { holderAuthenticated: true, maxCandidates: 1 },
  { holderAuthenticated: true, probe: { limit: 2, windowSecs: 60, history: [T0 - 10_000, T0 - 5_000], now: T0 } }, { holderAuthenticated: true, probe: { limit: 3, windowSecs: 60, history: [T0 - 100_000, T0 - 5_000], now: T0 } },
  { holderAuthenticated: true, caveatContext: { now: T0, recentActionTimes: [], delegationDepth: 0, blastRadius: 0.1, reversibilityClass: 'reversible' }, schema: FSCHEMA },
];
for (const k of ['pay', 'gated', 'wide', 'narrowv', 'intervals', 'groups']) for (const [i, a] of FLIPA.entries()) for (const [j, fo] of FOPT.entries()) {
  if (j > 2 && !['pay', 'gated'].includes(k)) continue;
  if (j > 8 && i > 3) continue;
  await run('minimalFlip', `${k}/${i}/${j}`, M.minimalFlip, [POL[k], a, fo]);
}
const TIMED = { predicates: [{ verb: 'go' }], caveats: [{ type: 'not_before', at: T0 + 60_000 }, { type: 'rate', max: 2, per_secs: 60 }, { type: 'expires', at: AT }] };
for (const [i, ctx] of [{ now: T0, recentActionTimes: [] }, { now: T0 + 70_000, recentActionTimes: [T0 + 69_000, T0 + 68_000] }, { now: T0 + 70_000, recentActionTimes: [T0 + 69_000, T0 + 68_000, T0 + 67_000] }, { now: T0 + 70_000, recentActionTimes: [T0 + 69_000] }, { now: AT + 1, recentActionTimes: [] }].entries()) {
  await run('minimalFlip', `timed/${i}`, M.minimalFlip, [TIMED, ACT('go', '/x'), { holderAuthenticated: true, caveatContext: ctx }]);
}
await run('minimalFlip', 'null-action', M.minimalFlip, [POL.pay, null, { holderAuthenticated: true }]);

// ---- schema validation ------------------------------------------------------------------------------------------------------------------
const SCHEMA = {
  verbs: [
    { verb: 'pay', params: { amount: { type: 'integer', semantic: 'money.amount', unit: 'usd-minor', min: 0, max: 50000, sensitivity: 'critical', required: true }, currency: { type: 'string', values: ['usd', 'eur'] }, memo: { type: 'string' }, when: { type: 'date' }, urgent: { type: 'boolean' } } },
    { verb: 'refund', params: { amount: { type: 'integer', semantic: 'money.amount', min: 0 }, reason: { type: 'string', values: ['fraud', 'dup'] } } },
    { verb: 'read', params: { path: { type: 'string' } } }, { verb: 'ping', params: {} },
  ],
  units: { 'usd-minor': { kind: 'currency', currency: 'USD', exponent: 2 } },
};
const SHAPE_LIST = [{ verb: 'pay', params: { amount: { type: 'integer', semantic: 'money.amount', min: 0, max: 100 }, tags: { type: 'set', values: ['a'] } } }, { verb: 'read', params: {} }];
const DEFS = [
  { verb: 'pay', params: { amount: { type: 'integer', role: 'money.amount', required: true, min: 1, max: 9, sensitivity: 'material' }, when: { type: 'datetime' }, to: { type: 'object_ref' }, kind: { type: 'string', values: ['a', 'b'] }, items: { type: 'array' }, flags: { type: 'set', values: ['x'] }, ok: { type: 'boolean' }, day: { type: 'date' } } },
  { verb: 'read' }, { id: 'legacy', params: { x: { type: 'string', semantic: 'money.amount', unit: 'eur' } } },
];
for (const [i, s] of [SCHEMA, SHAPE_LIST, DEFS, [], { verbs: [] }].entries()) await run('verbShapes', `s${i}`, M.verbShapes, [s]);
await run('verbShapesFromActionDefs', 'defs', M.verbShapesFromActionDefs, [DEFS]);
await run('verbShapesFromActionDefs', 'empty', M.verbShapesFromActionDefs, [[]]);
const VPOL: any[] = [
  POL.pay, POL.gated, { predicates: [{ verb: 'pay', where: [amt('lte', 100)] }] }, { predicates: [{ verb: 'pay' }] }, { predicates: [{ verb: '*' }] }, { predicates: [{ verb: 'pay', where: [amt('lte', 'x'), amt('gte', 1, 'currency'), amt('eq', 'gbp', 'currency'), amt('in', ['usd', 'zzz'], 'currency'), amt('in', ['q'], 'currency')] }] },
  { predicates: [{ verb: ['pay', 'refund'], where: [amt('lte', 60000), amt('gte', -5), amt('gt', 50000), amt('lt', 0), amt('eq', 99999), amt('gte', 0), amt('lte', 50000)] }] }, { predicates: [{ verb: 'pay', where: [amt('eq', 1, 'nope'), amt('lte', 'when', 'memo'), amt('lte', 5, 'when')] }] },
  { predicates: [{ verb: 'ghost', where: [amt('lte', 1)] }, { verb: ['pay', 'ghost'], where: [amt('lte', 1)] }] }, { predicates: [{ verb: 'pay', where: [amt('eq', 'x', 'urgent'), amt('eq', true, 'urgent')] }, { verb: 'pay', where: [amt('lte', 10), amt('gte', 20)] }] },
  { predicates: [{ verb: 'pay', where: [{ all_of: [amt('lte', 5)] }] }, { verb: 'refund', where: [{ any_of: [amt('lte', 5)] }] }] }, { predicates: [{ verb: 'refund', where: [{ not: amt('lte', 5) }] }] },
  { predicates: [{ verb: 'pay', where: [amt('lte', 5)] }], vetoes: [{ id: 'v', kind: 'deny', when: { verb: 'ghost' } }, { id: 'w', kind: 'deny', when: { verb: 'pay', where: [amt('eq', 1, 'nope')] } }] },
];
const VOPTS: any[] = [{}, { listUngranted: true }, { units: { 'action.params.amount': { kind: 'currency', currency: 'USD', exponent: 2 } } }, { units: {} }, { units: { 'action.params.amount': { kind: 'currency', currency: 'EUR', exponent: 2 } }, listUngranted: true }, { units: { 'action.params.amount': { kind: 'currency', currency: 'USD', exponent: 2 } }, schemaUnits: { 'usd-minor': { kind: 'currency', currency: 'USD', exponent: 3 } } }];
for (const [i, p] of VPOL.entries()) for (const [j, vo] of VOPTS.entries()) {
  for (const [sn, src] of [['schema', SCHEMA], ['shapes', SHAPE_LIST], ['defs', DEFS]] as [string, any][]) {
    if (j > 1 && sn !== 'schema') continue;
    await run('validatePolicyAgainstSchema', `p${i}/${j}/${sn}`, M.validatePolicyAgainstSchema, [p, src, vo]);
  }
}

// ---- policy tests ------------------------------------------------------------------------------------------------------------------------
const TKEYS = ['pay', 'gated', 'wide', 'intervals', 'groups', 'narrowv', 'verbcond', 'chain'];
for (const k of TKEYS) {
  await run('generateBoundaryTests', k, M.generateBoundaryTests, [POL[k], {}]);
  await run('generateBoundaryTests', `${k}/eps`, M.generateBoundaryTests, [POL[k], { epsilon: 5 }]);
  const doc = ra(M.generateBoundaryTests(POL[k], {}));
  await run('decideAll', k, M.decideAll, [POL[k], doc]);
  await run('runPolicyTests', `${k}/self`, M.runPolicyTests, [POL[k], doc, {}]);
  await run('runPolicyTests', `${k}/self-digest`, M.runPolicyTests, [POL[k], doc, { requireDigest: true }]);
  for (const other of ['wide', 'narrowv', 'pay']) if (other !== k) await run('runPolicyTests', `${k}/vs-${other}`, M.runPolicyTests, [POL[other], doc, { requireDigest: true }]);
  const tweaked = { ...doc, cases: doc.cases.map((c: any, i: number) => (i % 3 === 0 ? { ...c, expect: c.expect === 'allow' ? 'deny' : 'allow' } : i % 3 === 1 ? { ...c, decidedBy: 'nobody' } : c)) };
  await run('runPolicyTests', `${k}/tweaked`, M.runPolicyTests, [POL[k], tweaked, {}]);
  const sig = ra(M.signPolicyTests(doc, seed('owner'), pub('owner')));
  for (const [name, mut] of [['ok', (x: any) => x], ['bad-sig', (x: any) => ({ ...x, sig: x.sig.slice(0, -2) + 'AA' })], ['doc-changed', (x: any) => ({ ...x, doc: { ...x.doc, policy_digest: 'x' } })], ['kind', (x: any) => ({ ...x, doc: { ...x.doc, kind: 'z' } })], ['no-sig', (x: any) => ({ ...x, sig: null })]] as [string, (x: any) => any][]) {
    await run('verifyPolicyTests', `${k}/${name}`, (s: any, e: any) => M.verifyPolicyTests(s, keyed(e)), [ra(mut(sig)), '$key:owner']);
  }
  await run('verifyPolicyTests', `${k}/other`, (s: any, e: any) => M.verifyPolicyTests(s, keyed(e)), [sig, '$key:intruder']);
  if (k === 'pay') await run('signPolicyTests', k, (d: any, label: string) => M.signPolicyTests(d, seed(label), pub(label)), [doc, 'owner']);
}
for (const k of ['pay', 'gated']) {
  await run('policyTestsDoc', k, M.policyTestsDoc, [POL[k], []]);
  await run('policyTestsDoc', `${k}/cases`, M.policyTestsDoc, [POL[k], [{ name: 'a', action: ACT('pay', '/vendors/a', { amount: 5, currency: 'usd' }), expect: 'allow' }]]);
}
await run('runPolicyTests', 'empty-doc', M.runPolicyTests, [POL.pay, { v: 1, kind: 'pca-policy-tests', policy_digest: 'x', cases: [] }, {}]);

refWrite(o, 'analyzer');
