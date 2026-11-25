// Oracle (extra, Java lane): the AuthZEN PDP paths that need a real grant, a signed PCActn, the Policy-VM decision and the analyzer's
// static admission (authzen.mts covers the refusals only). Deterministic: Ed25519 keys from seed(label), fixed clock and salt.
// PORTING: evaluate(desc, request) -> authzenPdp(config built from desc).evaluate(request); the decision is compared by JSON value.
// desc = {grant, policy?, audience? (key absent = not given, null = accept any, string), insecureSkipPlanRootCheck?, authorizedPlanRoots?,
//   authorizer? (true: an authorizer that allows), requireAuthorizer?, requireProof?, budget?, risk?, plan?}; resolve returns {grant, policy, budget?, risk?, plan?}.
// Writes out/ref-authzen-java-extra.json.gz.
import * as C0 from '@atlasauth/pca';
import { Oracle, refWrite, seed } from './lib.mjs';

const C: any = (C0 as any).default ?? C0;
const M: any = await import('../../../packages/pca-authzen/src/index.ts');
const o = new Oracle('authzen-java-extra', 'tools/pca-audit/oracles/authzen-java-extra.mts', 'TS-reference oracle for AuthZEN permit paths (Java lane).');
const T0 = 1_800_000_000_000;
const J = (x: any) => JSON.parse(JSON.stringify(x));
const pr = seed('az/principal'), ag = seed('az/agent');
const pk = (s: Uint8Array) => C.encodeKey(C.publicKeyOf(s));
const P = (verb: string, resource: string, where?: any[]) => ({ verb, resource, ...(where ? { where } : {}) });
const mint = (predicates: any[], caveats: any[] = [], risk_policy: any = C.DEFAULT_RISK_POLICY) => J(C.mintGrant({
  principalSecret: pr, principalPublic: pk(pr), holder: pk(ag), goal: 'az', salt: 'c2FsdC1zYWx0LXNhbHQ', envelope: { predicates, caveats, agent_binding: {}, risk_policy },
}).grant);
const G = mint([P('read', 'doc:*'), P('write', 'doc:*', [{ field: 'action.params.size', op: 'lte', value: 10 }])]);
const GSTEP = mint([P('read', 'doc:*')], [], { ...C.DEFAULT_RISK_POLICY, theta1: 0, theta2: 0.0001 });
const act = (grant: any, verb: string, resource: string, params: any, over: any = {}) => J(C.buildPCActn({
  grant, chain: [grant], plan: [{ id: 'n1', verb, resource, params_digest: C.paramsDigest(params) }], nodeId: 'n1', params, counter: 1, signerSecret: ag, aud: 'rs', now: T0 - 1000, ttlMs: 600_000, nonce: 'n-1', ...over,
}));
const req = (verb: string, id: string, props: any, context: any = {}) => ({ subject: { type: 'user', id: 'alice' }, action: { name: verb, ...(props.action ? { properties: props.action } : {}) }, resource: { type: 'doc', id, ...(props.resource ? { properties: props.resource } : {}) }, context });
const withProof = (r: any, p: any) => ({ ...r, context: { ...r.context, pca_action: JSON.stringify(p) } });

const cfgOf = (d: any) => ({
  resolve: () => ({ grant: d.grant, policy: d.policy ?? { predicates: [], caveats: [] }, ...(d.budget ? { budget: d.budget } : {}), ...(d.risk ? { risk: d.risk } : {}), ...(d.plan ? { plan: d.plan } : {}) }),
  now: () => T0,
  ...('audience' in d ? { audience: d.audience } : {}),
  ...(d.insecureSkipPlanRootCheck !== undefined ? { insecureSkipPlanRootCheck: d.insecureSkipPlanRootCheck } : {}),
  ...(d.authorizedPlanRoots !== undefined ? { authorizedPlanRoots: d.authorizedPlanRoots } : {}),
  ...(d.authorizer ? { authorizer: async () => ({ allow: true }) } : {}),
  ...(d.requireAuthorizer !== undefined ? { requireAuthorizer: d.requireAuthorizer } : {}),
  ...(d.requireProof !== undefined ? { requireProof: d.requireProof } : {}),
});
const evaluate = async (d: any, r: any) => M.authzenPdp(cfgOf(d)).evaluate(r);
let n = 0;
const add = (name: string, d: any, r: any) => o.run('evaluate', `${name}#${n++}`, evaluate, [d, r]);

const R1 = req('read', '1', {});
const PC1 = act(G, 'read', 'doc:1', {});
const LOW = { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 };
const base: any = { grant: G, audience: 'rs', insecureSkipPlanRootCheck: true, authorizer: true, risk: LOW };
await add('permit', base, withProof(R1, PC1));
await add('permit no risk inputs', { ...base, risk: undefined }, withProof(R1, PC1));
await add('permit audience null', { ...base, audience: null }, withProof(R1, PC1));
await add('audience omitted', (({ audience, ...rest }) => rest)(base), withProof(R1, PC1));
await add('audience wrong', { ...base, audience: 'zz' }, withProof(R1, PC1));
await add('no authorizer', { ...base, authorizer: false }, withProof(R1, PC1));
await add('no authorizer not required', { ...base, authorizer: false, requireAuthorizer: false }, withProof(R1, PC1));
await add('no plan policy', { ...base, insecureSkipPlanRootCheck: undefined }, withProof(R1, PC1));
await add('plan roots listed', { ...base, insecureSkipPlanRootCheck: undefined, authorizedPlanRoots: [PC1.plan.root] }, withProof(R1, PC1));
await add('plan roots other', { ...base, insecureSkipPlanRootCheck: undefined, authorizedPlanRoots: ['x'] }, withProof(R1, PC1));
await add('wrong verb', base, withProof(req('write', '1', {}), PC1));
await add('wrong resource', base, withProof(req('read', '2', {}), PC1));
await add('wrong params', base, withProof(req('read', '1', { resource: { a: 1 } }), PC1));
await add('tampered', base, withProof(R1, { ...PC1, counter: 9 }));
await add('expired', { ...base }, withProof(R1, act(G, 'read', 'doc:1', {}, { now: T0 - 2_000_000 })));
await add('other grant', { ...base, grant: mint([P('read', 'doc:*')]) }, withProof(R1, PC1));
await add('malformed', base, { ...R1, context: { pca_action: 'not json' } });
await add('malformed type', base, { ...R1, context: { pca_action: 5 } });
// the policy decision: params under the predicate limit, over it, a verb the grant does not allow
for (const size of [5, 10, 11, 500]) {
  const r = req('write', '1', { resource: { size } });
  await add(`write size ${size}`, base, withProof(r, act(G, 'write', 'doc:1', { size })));
}
const rOther = req('delete', '1', {});
await add('delete not granted', base, withProof(rOther, act(G, 'delete', 'doc:1', {})));
// budget and risk: a low budget, supplied risk inputs, a step-up grant
for (const [bn, b] of [['empty', { B: 0, tau: T0, asOf: T0 }], ['full', { B: 1, tau: T0, asOf: T0 }], ['half', { B: 0.5, tau: T0 - 5000, asOf: T0 - 1000 }]] as any[])
  for (const [rn, risk] of [['none', undefined], ['low', { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 }], ['high', { semanticDistance: 1, reversibility: 0, blastRadius: 1, taint: 1, confidence: 0, age: 1 }]] as any[])
    await add(`budget ${bn} risk ${rn}`, { ...base, budget: b, risk }, withProof(R1, PC1));
await add('step-up grant', { ...base, grant: GSTEP, risk: undefined }, withProof(R1, act(GSTEP, 'read', 'doc:1', {})));
// static path (no proof): admission under the declared policy
const POL = { predicates: [P('read', 'doc:*'), P('write', 'doc:*', [{ field: 'action.params.size', op: 'lte', value: 10 }])], caveats: [] };
for (const [name, r] of [['read', R1], ['write small', req('write', '1', { resource: { size: 3 } })], ['write big', req('write', '1', { resource: { size: 30 } })], ['delete', req('delete', '1', {})]] as any[]) {
  await add(`static ${name}`, { grant: G, policy: POL, requireProof: false, audience: 'rs' }, r);
  await add(`static ${name} requireProof`, { grant: G, policy: POL, audience: 'rs' }, r);
}
await add('static empty policy', { grant: G, policy: { predicates: [] }, requireProof: false }, R1);
console.log('cases', o.cases.length);
refWrite(o, 'authzen-java-extra');
