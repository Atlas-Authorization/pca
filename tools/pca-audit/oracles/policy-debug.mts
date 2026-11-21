// Oracle: packages/pca/src/policy-debug.ts (explainRisk, explainDecision, applyDelta, counterfactual, auditPCActn). NOTE: policy-debug's explainDecision is NOT
// @atlasauth/pca-explain's explainDecision (ref-explain): it takes the Policy VM's DecideInput and explains `decide`. Writes out/ref-policy-debug.json.gz.
// Deterministic: Ed25519 keys from seed(label), fixed clock. Every grant is signed by the reference; keys only appear as public keys.
// PORTING (fn(args) -> native entry point; results compared by JSON value; a throw = the native throws)
//   explainRisk [inputs, weights, rFloor|null]            -> RiskExplanation {inputs, weights, terms[6], rawSum, rScore, rFloor, r}   (null = argument omitted: default 0)
//   explainDecision [input]                               -> DecisionExplanation (input = DecideInput as JSON, same shape as ref-decide-java)
//   applyDelta [input, delta]                             -> DecideInput (the counterfactual edit; compare as JSON)
//   counterfactual [input, deltas]                        -> {baseline, outcomes, flipping, thresholdChanging}
//   auditPCActn [pcactn, input, opts]                     -> {verify: {allow, checks, reason?}, explanation}; opts {grant, nowEpoch?, audience? (null = explicit opt-out, absent = not given), insecureSkipPlanRootCheck?}
//   delta = {label?, risk?, budget?, rFloor?, now?, caveatContext?, humanCosign?: true|{full?: bool}}
import { Oracle, refWrite, seed } from './lib.mjs';
import { adder } from './foundation.mjs';
const P: any = await import('../../../packages/pca/src/index.ts').then((m: any) => m.default ?? m);
const PD: any = await import('../../../packages/pca/src/policy-debug.ts');
const { delegate, encodeKey, mintGrant, publicKeyOf, mintRoot, buildPCActn, paramsDigest, DEFAULT_RISK_POLICY } = P;
const o = new Oracle('policy-debug', 'tools/pca-audit/oracles/policy-debug.mts', 'TS-reference oracle for packages/pca/src/policy-debug.ts.');
const T0 = 1_800_000_000_000;
const key = (l: string) => { const sk = seed('pdbg/' + l); return { sk, pk: encodeKey(publicKeyOf(sk)) }; };
const PR = key('principal'), AG = key('agent'), SUB = key('sub');
const J = (x: any) => JSON.parse(JSON.stringify(x));
const REF: Record<string, (...a: any[]) => any> = {
  explainRisk: (i, w, f) => (f === null ? PD.explainRisk(i, w) : PD.explainRisk(i, w, f)),
  explainDecision: (i) => PD.explainDecision(i),
  applyDelta: (i, d) => PD.applyDelta(i, d),
  counterfactual: (i, ds) => PD.counterfactual(i, ds),
  auditPCActn: async (p, i, op) => { const { grant, ...rest } = op; const a = await PD.auditPCActn(p, i, { grant, ...rest, nowEpoch: op.nowEpoch }); return { verify: { allow: a.verify.allow, checks: a.verify.checks, ...(a.verify.reason !== undefined ? { reason: a.verify.reason } : {}) }, explanation: a.explanation }; },
};
const add = adder(o, REF);

const preds = [{ verb: 'charge', resource: 'merchant:*', where: [{ field: 'action.params.amount', op: 'lte', value: 100 }] }, { verb: 'read', resource: '*' }];
const mk = (envCaveats: any[], policy: any = DEFAULT_RISK_POLICY) => J(mintGrant({ principalSecret: PR.sk, principalPublic: PR.pk, holder: AG.pk, goal: 'pay', salt: 'c2FsdC1zYWx0LXNhbHQ', envelope: { predicates: preds, caveats: envCaveats, agent_binding: {}, risk_policy: policy } }).grant);
const G0 = mk([]), G1 = mk([{ type: 'expires', at: T0 + 10_000_000 }, { type: 'max_blast_radius', max: 0.8 }, { type: 'reversibility_max', class: 'rate_limited' }]);
const GP = mk([], { ...DEFAULT_RISK_POLICY, theta1: 0.1, theta2: 0.3, kappa: 2, lambda: 0.01, rho: 0.4, bMax: 3 });
const GNOENV = J(mintRoot({ principalSecret: PR.sk, principalPublic: PR.pk, holder: AG.pk, caveats: [] }));
const act = (verb: string, resource: string, params: any = {}, rc?: string) => ({ action: { verb, resource, params, ...(rc ? { reversibility_class: rc } : {}) } });
const RL = { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 }, RM = { semanticDistance: 0.4, reversibility: 0.5, blastRadius: 0.5, taint: 0.2, confidence: 0.6, age: 0.1 }, RH = { semanticDistance: 1, reversibility: 0, blastRadius: 1, taint: 1, confidence: 0, age: 1 };
const BUD = [{ B: 1, tau: T0 }, { B: 0, tau: T0 }, { B: 0.5, tau: T0 - 1000, asOf: T0 - 500 }, { B: 1, tau: T0 - 7_200_000 }];
const PLAN = [{ id: 'a', verb: 'read', resource: 'x', post: ['b'] }, { id: 'b', verb: 'charge', resource: 'merchant:m1', reversibility_class: 'reversible', post: ['c'] }, { id: 'c', verb: 'read', resource: 'y' }];
const di = (g: any, a: any, risk: any, budget: any, over: any = {}) => ({ grant: g, action: a, risk, budget, now: T0, ...over });
const W = { alpha: 0.25, beta: 0.2, gamma: 0.2, delta: 0.2, epsilon: 0.1, zeta: 0.05 };

// explainRisk
const RI: any[] = [RL, RM, RH, { semanticDistance: -0.5, reversibility: 1.5, blastRadius: 2, taint: -1, confidence: 7, age: 0.5 }, { semanticDistance: { $num: 'NaN' }, reversibility: { $num: 'NaN' }, blastRadius: { $num: 'Infinity' }, taint: { $num: '-Infinity' }, confidence: { $num: 'NaN' }, age: { $num: 'Infinity' } },
  { semanticDistance: 0.5, reversibility: 0.5, blastRadius: 0.5, taint: 0.5, confidence: 0.5, age: 0.5 }, { semanticDistance: 1e-9, reversibility: 1 - 1e-9, blastRadius: 0.1, taint: 0.2, confidence: 0.3, age: 0.4 }];
const WS: any[] = [W, { alpha: 0, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 }, { alpha: 1, beta: 1, gamma: 1, delta: 1, epsilon: 1, zeta: 1 }, { alpha: -1, beta: 2, gamma: { $num: 'NaN' }, delta: { $num: 'Infinity' }, epsilon: 0.1, zeta: { $num: '-Infinity' } }, { alpha: 0.7, beta: 0.7, gamma: 0, delta: 0, epsilon: 0, zeta: 0 }];
for (const [ii, i] of RI.entries()) for (const [wi, w] of WS.entries()) for (const f of [null, 0, 0.3, 0.9, 1, 2, -1, { $num: 'NaN' }, { $num: 'Infinity' }]) await add('explainRisk', `i${ii}w${wi}f${JSON.stringify(f)}`, [i, w, f]);

// explainDecision
let n = 0;
const ed = (tag: string, input: any) => add('explainDecision', `${tag}#${n++}`, [input]);
for (const [gn, g] of [['g0', G0], ['g1', G1], ['gp', GP]] as any[]) for (const [an, a] of [['c10', act('charge', 'merchant:m1', { amount: 10 })], ['c500', act('charge', 'merchant:m1', { amount: 500 })], ['read', act('read', 'doc:1')], ['refund', act('refund', 'merchant:m1')], ['irr', act('charge', 'merchant:m1', { amount: 10 }, 'irreversible')]] as any[]) {
  for (const [rn, r] of [['l', RL], ['m', RM], ['h', RH]] as any[]) for (const [bi, b] of BUD.entries()) { if (rn !== 'm' && bi > 1) continue; await ed(`${gn}/${an}/${rn}/b${bi}`, di(g, a, r, b)); }
}
const A0 = act('charge', 'merchant:m1', { amount: 10 });
await ed('no-envelope', di(GNOENV, A0, RL, BUD[0]));
await ed('rfloor', di(G0, A0, RL, BUD[0], { rFloor: 0.4 })); await ed('rfloor-over', di(G0, A0, RL, BUD[0], { rFloor: 5 })); await ed('rfloor-neg', di(G0, A0, RL, BUD[0], { rFloor: -1 })); await ed('rfloor-nan', di(G0, A0, RL, BUD[0], { rFloor: { $num: 'NaN' } })); await ed('rfloor-str', di(G0, A0, RL, BUD[0], { rFloor: '0.4' }));
await ed('risk-empty-worst', di(G0, A0, {}, BUD[0])); await ed('risk-partial', di(G0, A0, { blastRadius: 0.2, taint: 0 }, BUD[0])); await ed('risk-str-ignored', di(G0, A0, { semanticDistance: 'x', blastRadius: 0.1 }, BUD[0])); await ed('risk-undefined', { grant: G0, action: A0, budget: BUD[0], now: T0 });
await ed('plan-geodesic', di(G0, A0, {}, BUD[0], { plan: PLAN, nodeId: 'b' })); await ed('plan-goal', di(G0, A0, {}, BUD[0], { plan: PLAN, nodeId: 'a', goalNodeId: 'b' })); await ed('plan-no-node', di(G0, A0, {}, BUD[0], { plan: PLAN })); await ed('plan-explicit-distance', di(G0, A0, { semanticDistance: 0.1 }, BUD[0], { plan: PLAN, nodeId: 'a' })); await ed('plan-unknown-node', di(G0, A0, {}, BUD[0], { plan: PLAN, nodeId: 'zzz' }));
await ed('age-horizon', di(G0, A0, { semanticDistance: 0 }, BUD[3], { ageHorizonMs: 3_600_000 })); await ed('age-explicit', di(G0, A0, { age: 0.9 }, BUD[3]));
await ed('now-later', di(G0, A0, RM, BUD[0], { now: T0 + 1_000_000 })); await ed('now-expired-caveat', di(G1, A0, RM, BUD[0], { now: T0 + 20_000_000 }));
await ed('caveat-ctx', di(G1, A0, RM, BUD[0], { caveatContext: { blastRadius: 0.95 } }));

// applyDelta + counterfactual
const base = di(G0, A0, RM, BUD[2]);
const DELTAS: any[] = [{}, { label: 'custom' }, { risk: { taint: 0 } }, { risk: { blastRadius: 0.1, confidence: 1 } }, { budget: { B: 5 } }, { budget: { B: 0 } }, { rFloor: 0.9 }, { rFloor: 0 }, { now: T0 + 3_600_000 }, { now: T0 - 1 }, { caveatContext: { blastRadius: 0.9 } },
  { humanCosign: true }, { humanCosign: { full: true } }, { humanCosign: { full: false } }, { humanCosign: {} }, { humanCosign: false }, { humanCosign: true, risk: { taint: 1 }, budget: { B: 0 } }, { risk: { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 } },
  { risk: { taint: { $num: 'NaN' } } }, { budget: { B: 0.2 }, rFloor: 0.2, now: T0 + 1, label: '' }, { label: 'x', humanCosign: { full: true }, now: T0 + 500 }];
for (const [di_, d] of DELTAS.entries()) { await add('applyDelta', `d${di_}`, [base, d]); await add('applyDelta', `gp-d${di_}`, [di(GP, A0, RM, BUD[1]), d]); await add('applyDelta', `noenv-d${di_}`, [di(GNOENV, A0, RM, BUD[1]), d]); }
await add('counterfactual', 'all-deltas', [base, DELTAS]); await add('counterfactual', 'empty', [base, []]);
for (const [i, d] of DELTAS.entries()) await add('counterfactual', `one-${i}`, [di(GP, A0, RM, BUD[1]), [d]]);
await add('counterfactual', 'denied-base', [di(G0, act('refund', 'merchant:m1'), RH, BUD[1]), [{ humanCosign: { full: true } }, { risk: RL }, { budget: { B: 1 } }]]);
await add('counterfactual', 'no-envelope', [di(GNOENV, A0, RM, BUD[0]), [{ humanCosign: true }, { risk: { taint: 0 } }]]);
await add('counterfactual', 'flip-to-allow', [di(G0, A0, RH, BUD[0]), [{ risk: RL }, { risk: RM }, { rFloor: 0 }]]);

// auditPCActn
const plan = [{ id: 'n1', verb: 'charge', resource: 'merchant:m1', params_digest: paramsDigest({ amount: 5 }) }];
const GRT = J(mintRoot({ principalSecret: PR.sk, principalPublic: PR.pk, holder: AG.pk, caveats: [] }));
const pc = (over: any = {}) => J(buildPCActn({ grant: GRT, chain: [GRT], plan, nodeId: 'n1', params: { amount: 5 }, counter: 1, signerSecret: AG.sk, aud: 'rs', now: T0, nonce: 'n-1', ...over }));
const AP = pc();
const aud = (p: any, i: any, op: any) => add('auditPCActn', `a${n++}`, [p, i, op]);
const dinp = di(GRT, { action: { verb: 'charge', resource: 'merchant:m1', params: { amount: 5 } } }, RM, BUD[0]);
await aud(AP, dinp, { grant: GRT, nowEpoch: T0 + 1000, audience: 'rs', insecureSkipPlanRootCheck: true });
await aud(AP, dinp, { grant: GRT, nowEpoch: T0 + 1000, audience: 'other', insecureSkipPlanRootCheck: true });
await aud(AP, dinp, { grant: GRT, nowEpoch: T0 + 1000, audience: null, insecureSkipPlanRootCheck: true });
await aud(AP, dinp, { grant: GRT, nowEpoch: T0 + 1000, insecureSkipPlanRootCheck: true });
await aud(AP, dinp, { grant: GRT, nowEpoch: T0 + 1000, audience: 'rs' });
await aud({ ...AP, sig: 'AAAA' }, dinp, { grant: GRT, nowEpoch: T0 + 1000, audience: 'rs', insecureSkipPlanRootCheck: true });
await aud(AP, di(G1, A0, RM, BUD[0]), { grant: GRT, nowEpoch: T0 + 1000, audience: 'rs', insecureSkipPlanRootCheck: true });
await aud(AP, di(GNOENV, A0, RL, BUD[1]), { grant: GRT, nowEpoch: T0 + 1000, audience: 'rs', insecureSkipPlanRootCheck: true });
await aud(pc({ counter: 2, nonce: 'n-2', params: { amount: 5 } }), dinp, { grant: GRT, nowEpoch: T0 + 1000, audience: 'rs', insecureSkipPlanRootCheck: true });
refWrite(o, 'policy-debug');
