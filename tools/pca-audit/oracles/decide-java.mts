// Oracle: the Policy VM decision `decide(input)` exported by @atlasauth/pca (releaseGuardianShare, required threshold, risk,
// budget admission, budget after). Written for the Java lane (Decide.decide); reusable by any native.
// A non-numeric budget (B: 'x') is left out: the reference computes with NaN and still releases, the native refuses it (fail closed).
// Deterministic: keys from seed(label), fixed salt, fixed clock T0. Writes out/ref-decide-java.json.gz.
//
// PORTING (fn(args) -> native entry point, comparison rule)
//   decide(input) -> the native decide over the same JSON object; result is the policy decision {releaseGuardianShare, requiredThreshold,
//                    r, admit, needStepUp, reasons, budget, k1Bound?} compared by JSON value (reasons compared in order).
//   input is DecideInput as JSON (grant, chain?, action, plan?, risk, budget, now, nodeId?, goalNodeId?, caveatContext?, rFloor?,
//   ageHorizonMs?, chainVerified?, pqPins?, trustedRoot?). Every grant and chain in the corpus is signed by the reference.
import * as PCA0 from '@atlasauth/pca';
import { Oracle, refWrite, seed } from './lib.mjs';

const P: any = (PCA0 as any).default ?? PCA0;
const { delegate, encodeKey, mintGrant, publicKeyOf, mintRoot, decide, DEFAULT_RISK_POLICY } = P;

const o = new Oracle('decide-java', 'tools/pca-audit/oracles/decide-java.mts', 'TS-reference oracle for decide (Java lane).');
const T0 = 1_800_000_000_000;
const key = (l: string) => { const sk = seed('decide/' + l); return { sk, pk: encodeKey(publicKeyOf(sk)) }; };
const PR = key('principal'), AG = key('agent'), SUB = key('sub');
const J = (x: any) => JSON.parse(JSON.stringify(x));

const preds = [{ verb: 'charge', resource: 'merchant:*', where: [{ field: 'action.params.amount', op: 'lte', value: 100 }] }, { verb: 'read', resource: '*' }];
const mk = (envCaveats: any[], rootCaveats: any[] = [], policy: any = DEFAULT_RISK_POLICY) => {
  const { grant } = mintGrant({ principalSecret: PR.sk, principalPublic: PR.pk, holder: AG.pk, goal: 'pay', salt: 'c2FsdC1zYWx0LXNhbHQ', envelope: { predicates: preds, caveats: envCaveats, agent_binding: {}, risk_policy: policy } });
  if (rootCaveats.length === 0) return J(grant);
  // a root with caveats outside the envelope: re-mint with the envelope first
  return J(mintRoot({ principalSecret: PR.sk, principalPublic: PR.pk, holder: AG.pk, caveats: [...grant.caveats, ...rootCaveats] }));
};
const G0 = mk([]);
const G1 = mk([{ type: 'expires', at: T0 + 10_000_000 }, { type: 'max_blast_radius', max: 0.8 }, { type: 'reversibility_max', class: 'rate_limited' }, { type: 'delegation_depth', max: 2 }]);
const G2 = mk([], [{ type: 'expires', at: T0 + 5 }]);
const G3 = mk([{ type: 'rate', max: 2, per_secs: 60 }]);
const GP = mk([], [], { ...DEFAULT_RISK_POLICY, theta1: 0.1, theta2: 0.3, kappa: 2, lambda: 0.01 });
const GRANTS: [string, any][] = [['g0', G0], ['g1', G1], ['g2rootcv', G2], ['g3rate', G3], ['gpol', GP]];
const GNOENV = J(mintRoot({ principalSecret: PR.sk, principalPublic: PR.pk, holder: AG.pk, caveats: [] }));
const sub = J(delegate(G0, SUB.pk, [{ type: 'expires', at: T0 + 2_000_000 }], AG.sk));
const subBad = J(delegate(G0, SUB.pk, [{ type: 'expires', at: T0 - 1 }], AG.sk));
const subDepth = J(delegate(G1, SUB.pk, [{ type: 'delegation_depth', max: 0 }], AG.sk));
const subTampered = { ...sub, sig: 'AAAA' };

const act = (verb: string, resource: string, params: any = {}, rc?: string) => ({ action: { verb, resource, params, ...(rc ? { reversibility_class: rc } : {}) } });
const ACTS: [string, any][] = [['charge10', act('charge', 'merchant:m1', { amount: 10 })], ['charge500', act('charge', 'merchant:m1', { amount: 500 })], ['read', act('read', 'doc:1')],
  ['refund', act('refund', 'merchant:m1')], ['chargeIrr', act('charge', 'merchant:m1', { amount: 10 }, 'irreversible')], ['chargeRev', act('charge', 'merchant:m1', { amount: 10 }, 'reversible')],
  ['chargeRl', act('charge', 'merchant:m1', { amount: 10 }, 'rate_limited')]];
const RISKS: [string, any][] = [['low', { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 }],
  ['mid', { semanticDistance: 0.4, reversibility: 0.5, blastRadius: 0.5, taint: 0.2, confidence: 0.6, age: 0.1 }],
  ['high', { semanticDistance: 1, reversibility: 0, blastRadius: 1, taint: 1, confidence: 0, age: 1 }], ['empty', {}], ['partial', { blastRadius: 0.2, taint: 0 }],
  ['nan', { semanticDistance: null, reversibility: 'x', blastRadius: 0.1, taint: 0, confidence: 1, age: 0 }]];
const BUDGETS: [string, any][] = [['full', { B: 1, tau: T0 }], ['empty', { B: 0, tau: T0 }], ['half', { B: 0.5, tau: T0 - 1000, asOf: T0 - 500 }], ['old', { B: 1, tau: T0 - 7_200_000 }]];
const PLAN = [{ id: 'a', verb: 'read', resource: 'x', post: ['b'] }, { id: 'b', verb: 'charge', resource: 'merchant:m1', reversibility_class: 'reversible', post: ['c'] }, { id: 'c', verb: 'read', resource: 'y' }];

let n = 0;
const add = (input: any, tag: string) => o.run('decide', `c${n++}/${tag}`, decide, [{ now: T0, ...input }]);
for (const [gn, g] of GRANTS) for (const [an, a] of ACTS) {
  await add({ grant: g, action: a, risk: RISKS[0][1], budget: BUDGETS[0][1] }, `${gn}/${an}/low`);
  await add({ grant: g, action: a, risk: RISKS[1][1], budget: BUDGETS[0][1] }, `${gn}/${an}/mid`);
}
for (const [rn, r] of RISKS) for (const [bn, b] of BUDGETS) for (const [gn, g] of GRANTS.slice(0, 1).concat(GRANTS.slice(4)))
  await add({ grant: g, action: ACTS[0][1], risk: r, budget: b }, `${gn}/${rn}/${bn}`);
for (const [rn, r] of RISKS) for (const [pn, plan] of [['plan', PLAN], ['noplan', undefined]] as any[])
  for (const nodeId of ['a', 'b', 'zz', undefined]) await add({ grant: G0, action: ACTS[0][1], risk: r, budget: BUDGETS[0][1], plan, nodeId }, `plan/${rn}/${pn}/${nodeId}`);
// caveat contexts and the reversibility class resolved from the plan node
for (const cc of [undefined, {}, { recentActionTimes: [T0 - 1000, T0 - 2000] }, { recentActionTimes: [T0 - 1000] }, { reversibilityClass: 'irreversible' }, { reversibilityClass: 'reversible' }, { blastRadius: 0.95 }, { delegationDepth: 9 }, { recentActionTimes: 'x' }])
  for (const [gn, g] of [['g1', G1], ['g3', G3], ['g0', G0]] as any[])
    await add({ grant: g, action: act('read', 'doc:1'), risk: RISKS[0][1], budget: BUDGETS[0][1], caveatContext: cc, plan: PLAN, nodeId: 'b' }, `cc/${gn}/${JSON.stringify(cc)}`);
// chains
for (const [cn, chain] of [['none', undefined], ['empty', []], ['one', [G0]], ['sub', [G0, sub]], ['subBad', [G0, subBad]], ['subTampered', [G0, subTampered]], ['notarr', 'x'], ['null', null], ['g1depth', [G1, subDepth]]] as any[])
  for (const [vn, cv] of [['unverified', undefined], ['verified', true]] as any[])
    await add({ grant: cn === 'g1depth' ? G1 : G0, chain, action: ACTS[2][1], risk: RISKS[0][1], budget: BUDGETS[0][1], chainVerified: cv }, `chain/${cn}/${vn}`);
// grants without an envelope, tampered, wrong time, floors and horizons
await add({ grant: GNOENV, action: ACTS[0][1], risk: RISKS[0][1], budget: BUDGETS[0][1] }, 'noenv');
await add({ grant: { ...G0, sig: 'AAAA' }, action: ACTS[0][1], risk: RISKS[0][1], budget: BUDGETS[0][1] }, 'badsig');
await add({ grant: null, action: ACTS[0][1], risk: RISKS[0][1], budget: BUDGETS[0][1] }, 'nullgrant');
for (const now of [null, 'x', 2 ** 53, -1, T0 + 1_000_000]) await add({ grant: G0, action: ACTS[0][1], risk: RISKS[0][1], budget: BUDGETS[0][1], now }, `now/${now}`);
for (const rf of [undefined, 0, 0.3, 0.7, 1, 2, -1, 'x', null]) await add({ grant: G0, action: ACTS[0][1], risk: RISKS[0][1], budget: BUDGETS[0][1], rFloor: rf }, `rfloor/${rf}`);
for (const h of [undefined, 1000, 7_200_000, 0, -5, 'x']) await add({ grant: G0, action: ACTS[0][1], risk: { ...RISKS[0][1], age: undefined }, budget: BUDGETS[3][1], ageHorizonMs: h }, `horizon/${h}`);
for (const [pn, pins] of [['none', undefined], ['empty', {}], ['pin', { [PR.pk]: 'AAAA' }]] as any[]) await add({ grant: G0, action: ACTS[0][1], risk: RISKS[0][1], budget: BUDGETS[0][1], pqPins: pins }, `pins/${pn}`);
await add({ grant: G0, action: { action: { verb: 'charge', resource: 'merchant:m1', params: { amount: 5 } }, subject: { id: 's' }, env: { x: 1 } }, risk: RISKS[0][1], budget: BUDGETS[0][1] }, 'subjectenv');
await add({ grant: G0, action: ACTS[0][1], risk: null, budget: BUDGETS[0][1] }, 'risknull');
console.log('cases', o.cases.length);
refWrite(o, 'decide-java');
