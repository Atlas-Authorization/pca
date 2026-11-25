// Oracle: deriveDecideInput (policy-vm.ts) and the pipeline derive -> decide, TS reference. The corpus ref-decide-java.json.gz already covers decide(input);
// this one covers how a verifier assembles that input from a PCActn plus its own context. Writes out/ref-decide-derive.json.gz. Deterministic: keys from
// seed(label), fixed salt, fixed clock T0; every grant and chain is signed by the reference (no secret key in the corpus).
//
// PORTING (fn(args) -> native entry point, comparison rule; results compared by JSON value, an undefined member is absent)
//   deriveDecideInput [p, ctx]   -> the DecideInput object {grant, trustedRoot, pqPins?, chain, action:{action:{verb,resource,params,reversibility_class},subject?,env?},
//                                   plan, nodeId, goalNodeId, risk, budget, now, caveatContext, ageHorizonMs}. p = the PCActn (only action.{verb,resource,
//                                   reversibility_class}, plan.node_id and cap_chain are read), ctx = {grant (REQUIRED), plan?, params?, risk, budget, chain?, now,
//                                   pqPins?, goalNodeId?, subject?, env?, caveatContext?, ageHorizonMs?}. A missing or non-object ctx.grant refuses with code
//                                   "grant_required" (an array passes: it is an object); a null / non-object p, or a null ctx, refuses as well (the message is engine specific).
//                                   Rules: grant and trustedRoot = ctx.grant; chain = ctx.chain, else p.cap_chain; params = ctx.params, else {}; subject / env only when
//                                   truthy; pqPins only when given (not undefined); nodeId = p.plan.node_id; nothing is taken from the presented chain root.
//   deriveThenDecide [p, ctx]    -> {input: DecideInput, decision: PolicyDecision} (decide run on the derived input), or the same refusal as deriveDecideInput.
import * as PCA0 from '@atlasauth/pca';
import { Oracle, refWrite, seed } from './lib.mjs';

const P: any = (PCA0 as any).default ?? PCA0;
const { delegate, encodeKey, mintGrant, publicKeyOf, decide, deriveDecideInput, DEFAULT_RISK_POLICY } = P;
const o = new Oracle('decide-derive', 'tools/pca-audit/oracles/decide-derive.mts', 'TS-reference oracle for deriveDecideInput and derive-then-decide.');
const T0 = 1_800_000_000_000;
const key = (l: string) => { const sk = seed('decide-derive/' + l); return { sk, pk: encodeKey(publicKeyOf(sk)) }; };
const PR = key('principal'), AG = key('agent'), SUB = key('sub');
const J = (x: any) => JSON.parse(JSON.stringify(x));
const preds = [{ verb: 'charge', resource: 'merchant:*', where: [{ field: 'action.params.amount', op: 'lte', value: 100 }] }, { verb: 'read', resource: '*' }];
const mk = (envCaveats: any[]) => J(mintGrant({ principalSecret: PR.sk, principalPublic: PR.pk, holder: AG.pk, goal: 'pay', salt: 'c2FsdC1zYWx0LXNhbHQ', envelope: { predicates: preds, caveats: envCaveats, agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY } }).grant);
const G0 = mk([]);
const G1 = mk([{ type: 'expires', at: T0 + 10_000_000 }, { type: 'reversibility_max', class: 'rate_limited' }, { type: 'delegation_depth', max: 2 }]);
const SUBHOP = J(delegate(G0, SUB.pk, [{ type: 'expires', at: T0 + 2_000_000 }], AG.sk));
const SUBBAD = J(delegate(G0, SUB.pk, [{ type: 'expires', at: T0 - 1 }], AG.sk));
const PLAN = [{ id: 'a', verb: 'read', resource: 'x', post: ['b'] }, { id: 'b', verb: 'charge', resource: 'merchant:m1', reversibility_class: 'reversible', post: ['c'] }, { id: 'c', verb: 'read', resource: 'y' }];
const RISK = { semanticDistance: 0.1, reversibility: 1, blastRadius: 0.1, taint: 0, confidence: 1, age: 0 };
const BUD = { B: 1, tau: T0 };
const pc = (over: any = {}) => ({ action: { verb: 'charge', resource: 'merchant:m1', reversibility_class: 'reversible' }, plan: { node_id: 'b' }, cap_chain: [G0], ...over });
const cx = (over: any = {}) => ({ grant: G0, risk: RISK, budget: BUD, now: T0, params: { amount: 10 }, plan: PLAN, ...over });
const rv = (x: any): any => Array.isArray(x) ? x.map(rv) : x && typeof x === 'object' ? (Object.keys(x).length === 1 && typeof x.$num === 'string' ? Number(x.$num) : Object.fromEntries(Object.entries(x).map(([k, v]) => [k, rv(v)]))) : x; // {"$num": "NaN"|"Infinity"|"-Infinity"} (corpus convention for a non-finite number)
const REF: Record<string, (...a: any[]) => any> = {
  deriveDecideInput: (p, c) => deriveDecideInput(rv(p), rv(c)),
  deriveThenDecide: (p, c) => { p = rv(p); c = rv(c); const input = deriveDecideInput(p, c); return { input, decision: decide(input) }; },
};
let n = 0;
const add = async (name: string, p: any, c: any) => { for (const fn of ['deriveDecideInput', 'deriveThenDecide']) await o.run(fn, `${name}#${n++}`, REF[fn], [p, c]); };

await add('base', pc(), cx());
for (const [gn, g] of [['g1', G1], ['undefined', undefined], ['null', null], ['string', 'x'], ['number', 5], ['array', []], ['empty', {}], ['bool', true]] as any[]) await add('grant/' + gn, pc(), cx({ grant: g }));
const noGrant = cx(); delete (noGrant as any).grant; await add('grant/absent', pc(), noGrant);
for (const [cn, ch] of [['none', undefined], ['p-chain', undefined], ['empty', []], ['sub', [G0, SUBHOP]], ['sub-bad', [G0, SUBBAD]], ['one', [G0]], ['str', 'x'], ['null', null]] as any[]) {
  await add('chain/ctx/' + cn, pc({ cap_chain: [G1, J(delegate(G1, SUB.pk, [], AG.sk))] }), cx({ chain: ch }));
  await add('chain/p/' + cn, pc({ cap_chain: ch }), cx());
}
await add('chain/both', pc({ cap_chain: [G0, SUBHOP] }), cx({ chain: [G0] }));
await add('chain/none', (() => { const p = pc(); delete (p as any).cap_chain; return p; })(), cx());
for (const [pn, pp] of [['absent', undefined], ['empty', {}], ['amount', { amount: 500 }], ['nested', { a: { b: [1, 2, { c: null }] } }], ['nan-like', { amount: 'x' }]] as any[]) await add('params/' + pn, pc(), cx({ params: pp }));
for (const [sn, s] of [['absent', undefined], ['obj', { id: 's1' }], ['empty', {}], ['null', null], ['zero', 0], ['str', 'x'], ['array', [1]]] as any[]) for (const [en, e] of [['absent', undefined], ['obj', { x: 1 }], ['null', null], ['empty', {}]] as any[]) await add(`subjenv/${sn}/${en}`, pc(), cx({ subject: s, env: e }));
for (const [pn, pins] of [['absent', undefined], ['empty', {}], ['pin', { [PR.pk]: 'AAAA' }], ['null', null]] as any[]) await add('pins/' + pn, pc(), cx({ pqPins: pins }));
for (const [nn, np] of [['plan-b', pc()], ['plan-zz', pc({ plan: { node_id: 'zz' } })], ['plan-absent', (() => { const p = pc(); delete (p as any).plan; return p; })()], ['plan-null', pc({ plan: null })], ['plan-empty', pc({ plan: {} })], ['plan-num', pc({ plan: { node_id: 5 } })]] as any[]) await add('node/' + nn, np, cx());
for (const [gn, g] of [['absent', undefined], ['a', 'a'], ['c', 'c'], ['zz', 'zz']] as any[]) await add('goalnode/' + gn, pc(), cx({ goalNodeId: g }));
for (const [pn, pl] of [['absent', undefined], ['empty', []], ['plan', PLAN]] as any[]) await add('plan/' + pn, pc(), cx({ plan: pl }));
for (const rc of [undefined, 'reversible', 'irreversible', 'rate_limited', 'x', null, 5]) await add('rc/' + rc, pc({ action: { verb: 'charge', resource: 'merchant:m1', reversibility_class: rc } }), cx({ grant: G1 }));
for (const [an, a] of [['no-verb', { resource: 'r' }], ['no-resource', { verb: 'v' }], ['empty', {}], ['null', null], ['absent', undefined], ['extra', { verb: 'read', resource: 'doc:1', params: { amount: 99 }, reversibility_class: 'reversible', junk: 1 }]] as any[]) await add('action/' + an, pc({ action: a }), cx());
for (const [rn, r] of [['partial', { blastRadius: 0.2 }], ['empty', {}], ['high', { semanticDistance: 1, reversibility: 0, blastRadius: 1, taint: 1, confidence: 0, age: 1 }]] as any[]) await add('risk/' + rn, pc(), cx({ risk: r }));
for (const [bn, b] of [['empty', { B: 0, tau: T0 }], ['old', { B: 1, tau: T0 - 7_200_000 }], ['asof', { B: 0.5, tau: T0 - 1000, asOf: T0 - 500 }]] as any[]) await add('budget/' + bn, pc(), cx({ budget: b }));
for (const [cn, cc] of [['absent', undefined], ['empty', {}], ['depth', { delegationDepth: 9 }], ['times', { recentActionTimes: [T0 - 1000] }], ['rc', { reversibilityClass: 'irreversible' }], ['blast', { blastRadius: 0.95 }]] as any[]) await add('cc/' + cn, pc(), cx({ caveatContext: cc, grant: G1 }));
for (const h of [undefined, 1000, 0, -5, 'x']) for (const now of [T0, T0 + 5_000_000]) await add(`horizon/${h}/${now}`, pc(), cx({ ageHorizonMs: h, now, risk: { ...RISK, age: undefined }, budget: { B: 1, tau: T0 - 1000 } }));
for (const now of [null, 'x', 2 ** 53, -1, undefined]) await add('now/' + now, pc(), cx({ now }));
for (const [pn, bad] of [['null', null], ['undefined', undefined], ['string', 'x'], ['number', 5], ['array', []]] as any[]) await add('p/' + pn, bad, cx());
await add('ctx/null', pc(), null);
await add('ctx/empty', pc(), {});
// non-finite numbers (corpus {"$num"} convention), appended last so earlier case names keep their numbers
for (const [tag, v] of [['NaN', { $num: 'NaN' }], ['Infinity', { $num: 'Infinity' }]] as any[]) { await add('now-' + tag, pc(), cx({ now: v })); await add('horizon-' + tag, pc(), cx({ ageHorizonMs: v, risk: { ...RISK, age: undefined }, budget: { B: 1, tau: T0 - 1000 } })); await add('budget-tau-' + tag, pc(), cx({ budget: { B: 1, tau: v } })); await add('risk-' + tag, pc(), cx({ risk: { ...RISK, blastRadius: v } })); }
console.log('cases', o.cases.length);
refWrite(o, 'decide-derive');
