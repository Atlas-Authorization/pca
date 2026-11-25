// Oracle: @atlasauth/pca-authzen (guards, default action mapping, AARP, PDP refusal/merge paths, handler, search). Deterministic.
// PDP / search cases name a fixed config (PDP) or provider (search); the native replay keeps the same tables. Permit paths that
// need the Policy-VM, the analyzer or a signed PCActn are not covered here. Writes out/ref-authzen.json.gz.
import { Oracle, HOSTILE, variants, refWrite } from './lib.mjs';

const M: any = await import('../../../packages/pca-authzen/src/index.ts');
const { paramsDigest } = await import('../../../packages/pca/src/index.ts') as any;
const o = new Oracle('authzen', 'tools/pca-audit/oracles/authzen.mts', 'TS-reference oracle for the AuthZEN PDP, handler and search APIs.');

const NOW = 1_000_000;
const ok = async () => ({ allow: true });
const CFG: Record<string, any> = {
  none: { resolve: () => null, now: () => NOW },
  throws: { resolve: () => { throw new Error('boom'); }, now: () => NOW },
  noauth: { resolve: () => ({ grant: {}, policy: {} }), now: () => NOW },
  auth: { resolve: () => ({ grant: {}, policy: {} }), authorizer: ok, now: () => NOW },
  max2: { resolve: () => null, maxEvaluations: 2, now: () => NOW },
  toolmap: { resolve: () => null, toolCapability: (n: string) => 'cap.' + n, now: () => NOW },
  toolthrow: { resolve: () => null, toolCapability: () => { throw new Error('bad tool'); }, now: () => NOW },
};
const pdp = (n: string) => M.authzenPdp(CFG[n]);

const R = (id = '1', extra: any = {}) => ({ subject: { type: 'user', id: 'alice' }, action: { name: 'read' }, resource: { type: 'doc', id }, ...extra });
const EV = R();
const EMPTY_DIGEST = paramsDigest({});
const pc = (action: any) => JSON.stringify({ action });
const withCtx = (context: any) => R('1', { context });

// ---- guards -------------------------------------------------------------------------------------------------------
const seeds: Record<string, any> = {
  isAccessEvaluationRequest: R('1', { context: { a: 1 } }),
  isAccessEvaluationsRequest: { evaluations: [EV] },
  isCoazToolAuthorizationRequest: { subject: { type: 'user', id: 'a' }, tool: { name: 't', arguments: { x: 1 } } },
  isAuthzenSubject: { type: 'user', id: 'a' },
  isAuthzenAction: { name: 'read' },
  isAuthzenResource: { type: 'doc', id: '1' },
  isSubjectSearch: { subject: { type: 'user' }, action: { name: 'read' }, resource: { type: 'doc', id: '1' }, context: { c: 1 }, page: { token: 't', limit: 5, properties: { p: 1 } } },
  isResourceSearch: { subject: { type: 'user', id: 'a' }, action: { name: 'read' }, resource: { type: 'doc' }, page: { limit: 0 } },
  isActionSearch: { subject: { type: 'user', id: 'a' }, resource: { type: 'doc', id: '1' }, context: {} },
};
for (const [fn, seed] of Object.entries(seeds)) {
  await o.run(fn, 'seed', M[fn], [seed]);
  for (const [hi, h] of HOSTILE.entries()) await o.run(fn, 'top' + hi, M[fn], [h]);
  for (const [label, v] of variants(seed, { depth: 3, maxPaths: 40 })) await o.run(fn, label, M[fn], [v]);
}
await o.run('isActionSearch', 'has action', M.isActionSearch, [{ ...seeds.isActionSearch, action: { name: 'x' } }]);

// ---- defaultToAction ----------------------------------------------------------------------------------------------
const maps: any[] = [
  EV, R(''), R('1', { action: { name: 'read', properties: { a: 1, reversibility_class: 'reversible' } } }),
  { ...R(), resource: { type: 'doc', id: '1', properties: { a: 1, b: 2 } }, action: { name: 'w', properties: { b: 3 } } },
  R('1', { context: { reversibility_class: 'costly', k: 1 } }), R('1', { context: { pca_action: 'x', pca_approval: {}, pca_provenance: 'p' } }),
  R('1', { context: { pca_action: 'x' } }), R('1', { context: {} }), R('1', { subject: { type: 'u', id: 'a', properties: { r: 'admin' } } }),
  R('1', { subject: { type: 'u', id: 'a', properties: [] } }), R('1', { action: { name: 'r', properties: { reversibility_class: 5 }}, context: { reversibility_class: 'x' } }),
  { ...R(), resource: { type: 'doc', id: '1', properties: null } },
];
for (const [i, m] of maps.entries()) await o.run('defaultToAction', `m${i}`, M.defaultToAction, [m]);

// ---- AARP ---------------------------------------------------------------------------------------------------------
const PEND = { approval_required: true, auth_req_id: 'r1', tier: 3, required_threshold: { t: 3, proof: 'strong', optimisticAllowed: false }, goal_commit: 'g', risk: 0.5, reason: 'why', requested_at: 7 };
const resps: any[] = [
  { decision: false }, { decision: false, context: {} }, { decision: false, context: { pca_approval: PEND } }, { decision: false, context: { pca_approval: { ...PEND, approval_required: false } } },
  { decision: false, context: { pca_approval: { approval_required: true, auth_req_id: 'x' } } }, { decision: false, context: { pca_approval: { ...PEND, tier: 2, required_threshold: { t: 4 } } } },
  { decision: false, context: { pca_approval: { ...PEND, tier: 5, required_threshold: 'x', goal_commit: 1, risk: 'x', reason: 2, requested_at: null } } },
  { decision: false, context: { pca_approval: { ...PEND, auth_req_id: 5 } } }, { decision: false, context: { pca_approval: 'x' } }, { decision: false, context: { pca_approval: [PEND] } },
  { decision: false, context: null }, { decision: false, context: 'x' }, { decision: false, context: [] }, { decision: false, context: { pca_approval: { ...PEND, required_threshold: { t: 1, proof: 'p', optimisticAllowed: true } } } },
  { decision: false, context: { pca_approval: { ...PEND, required_threshold: { t: true, proof: 'p', optimisticAllowed: true } } } }, null, 'x', [],
];
for (const [i, r] of resps.entries()) { await o.run('approvalOf', `r${i}`, M.approvalOf, [r]); await o.run('isApprovalRequired', `r${i}`, M.isApprovalRequired, [r]); }
for (const [label, v] of variants({ decision: false, context: { pca_approval: PEND } }, { depth: 4, maxPaths: 60 })) await o.run('approvalOf', label, M.approvalOf, [v]);

// ---- PDP ----------------------------------------------------------------------------------------------------------
const PCS: any[] = [
  5, null, [], '', '[]', 'null', 'nope', '{}', 'x'.repeat(524_289), pc(null), pc('x'), pc({ verb: 'write', resource: 'doc:1', params_digest: 'x' }),
  pc({ verb: 'read', resource: 'doc:2', params_digest: 'x' }), pc({ verb: 'read', resource: 'doc:1', params_digest: 'x' }), pc({ verb: 'read', resource: 'doc:1' }),
  pc({ verb: 5, resource: null }), pc({ resource: 'doc:1' }), pc({ verb: 'read', resource: 'doc:1', params_digest: EMPTY_DIGEST }),
  JSON.stringify({ action: { verb: 'read', resource: 'doc:1', params_digest: EMPTY_DIGEST }, counter: 3 }), '{"action":{"verb":"read","verb":"x"}}',
];
for (const cfg of ['none', 'throws', 'noauth', 'auth']) {
  await o.run('pdp.evaluate', `${cfg}/plain`, (c: string, r: any) => pdp(c).evaluate(r), [cfg, EV]);
  for (const [i, p] of PCS.entries()) await o.run('pdp.evaluate', `${cfg}/pc${i}`, (c: string, r: any) => pdp(c).evaluate(r), [cfg, withCtx({ pca_action: p, other: 1 })]);
}
await o.run('pdp.evaluate', 'auth/params', (c: string, r: any) => pdp(c).evaluate(r), ['auth', R('1', { action: { name: 'read', properties: { q: 1 } }, context: { pca_action: pc({ verb: 'read', resource: 'doc:1', params_digest: EMPTY_DIGEST }) } })]);

const subj = { type: 'user', id: 'alice' };
const evs: Array<[string, any]> = [
  ['empty', { evaluations: [] }], ['notarray', { evaluations: 'x' }], ['defaults', { ...EV, evaluations: [{}, { resource: { type: 'doc', id: '2' } }, { action: null }] }],
  ['incomplete', { evaluations: [{}, EV] }], ['prims', { ...EV, evaluations: ['s', 5, true, []] }], ['nullitem', { ...EV, evaluations: [null] }],
  ['sem-all', { ...EV, evaluations: [{}, {}], options: { evaluations_semantic: 'execute_all' } }], ['sem-deny', { ...EV, evaluations: [{}, {}, {}], options: { evaluations_semantic: 'deny_on_first_deny' } }],
  ['sem-permit', { ...EV, evaluations: [{}, {}, {}], options: { evaluations_semantic: 'permit_on_first_permit' } }], ['sem-bad', { ...EV, evaluations: [{}], options: { evaluations_semantic: 'x' } }],
  ['sem-num', { ...EV, evaluations: [{}], options: { evaluations_semantic: 5 } }], ['sem-null', { ...EV, evaluations: [{}], options: { evaluations_semantic: null } }], ['opts-null', { ...EV, evaluations: [{}], options: null }],
  ['opts-str', { ...EV, evaluations: [{}], options: 'x' }], ['ctx-default', { ...EV, context: { pca_action: 5 }, evaluations: [{}, { context: { a: 1 } }, { context: null }] }],
  ['three', { ...EV, evaluations: [{}, {}, {}] }], ['three-sem', { ...EV, evaluations: [{}, {}, {}], options: { evaluations_semantic: 'deny_on_first_deny' } }],
];
for (const cfg of ['none', 'max2', 'throws']) for (const [n, b] of evs) await o.run('pdp.evaluations', `${cfg}/${n}`, (c: string, r: any) => pdp(c).evaluations(r), [cfg, b]);
await o.run('pdp.evaluations', 'noreq', (c: string, r: any) => pdp(c).evaluations(r), ['none', null]);

const tools: any[] = [
  { subject: subj, tool: { name: 't' } }, { subject: subj, tool: { name: 't', arguments: { a: 1 } } }, { subject: subj, tool: { name: 't', arguments: null } },
  { subject: subj, tool: { name: 't' }, context: { c: 1 } }, { subject: subj, tool: { name: 't' }, context: null }, { subject: subj, tool: { name: '' } },
];
for (const cfg of ['none', 'toolmap', 'toolthrow', 'noauth']) for (const [i, t] of tools.entries()) await o.run('pdp.evaluateTool', `${cfg}/t${i}`, (c: string, r: any) => pdp(c).evaluateTool(r), [cfg, t]);

// ---- handler ------------------------------------------------------------------------------------------------------
const H = (c: string, r: any) => M.authzenHandler(pdp(c))(r);
const hreqs: any[] = [
  { path: M.EVALUATION_PATH, body: EV }, { path: M.EVALUATION_PATH, body: {} }, { path: M.EVALUATION_PATH, body: null }, { path: M.EVALUATION_PATH },
  { path: M.EVALUATION_PATH, body: R('1', { context: 5 }) }, { path: M.EVALUATIONS_PATH, body: EV }, { path: M.EVALUATIONS_PATH, body: { ...EV, evaluations: [] } },
  { path: M.EVALUATIONS_PATH, body: { ...EV, evaluations: [{}, {}] } }, { path: M.EVALUATIONS_PATH, body: { evaluations: null } }, { path: M.EVALUATIONS_PATH, body: { subject: 1 } },
  { path: M.EVALUATIONS_PATH, body: { evaluations: [null] } }, { path: M.EVALUATIONS_PATH, body: [] }, { path: M.EVALUATIONS_PATH, body: { evaluations: 'x' } },
  { path: M.COAZ_TOOL_PATH, body: tools[1] }, { path: M.COAZ_TOOL_PATH, body: { subject: subj, tool: {} } }, { path: M.COAZ_TOOL_PATH, body: null },
  { path: '/access/v1/unknown', body: EV }, { path: '/access/v1/evaluation/', body: EV }, { path: '', body: EV }, { body: EV },
];
for (const cfg of ['none', 'throws', 'noauth']) for (const [i, r] of hreqs.entries()) await o.run('authzenHandler', `${cfg}/h${i}`, H, [cfg, r]);

// ---- search -------------------------------------------------------------------------------------------------------
const U = (id: string, extra: any = {}) => ({ type: 'user', id, ...extra });
const PROV: Record<string, any> = {
  none: {},
  full: {
    searchSubject: async () => ({ results: [U('a'), U('b'), { type: 'group', id: 'g' }, U('a'), { id: 'a', type: 'user' }], page: { next_token: '', total: 3, properties: { k: 1 } }, context: { c: 1 } }),
    searchResource: async () => ({ results: [{ type: 'doc', id: '1' }, { type: 'doc', id: '2' }, { type: 'user', id: 'x' }], page: { next_token: 'n1' } }),
    searchAction: async () => ({ results: [{ name: 'read' }, { name: 'write' }, { name: 'read' }, { name: 'read', properties: { p: 1 } }] }),
  },
  nopage: { searchSubject: async () => ({ results: [U('a'), U('b')] }), searchResource: async () => ({ results: [] }), searchAction: async () => ({ results: [] }) },
  emptyprops: { searchSubject: async () => ({ results: [U('a')], page: { next_token: 'z', properties: {} }, context: {} }) },
  bad: { searchSubject: async () => ({ results: [null] }), searchResource: async () => ({ results: [5] }), searchAction: async () => ({ results: [null, 5] }) },
  notarray: { searchSubject: async () => ({ results: 'x' }), searchResource: async () => ({}), searchAction: async () => ({ results: null }) },
  throws: { searchSubject: async () => { throw new Error('x'); }, searchResource: async () => { throw new Error('x'); }, searchAction: async () => { throw new Error('x'); } },
  echo: {
    searchSubject: async (r: any) => ({ results: [], context: { saw: r } }), searchResource: async (r: any) => ({ results: [], context: { saw: r } }),
    searchAction: async (r: any) => ({ results: [], context: { saw: r } }),
  },
  partial: { searchResource: async () => ({ results: [] }) },
};
const SH = (p: string, r: any) => M.authzenSearchHandler(PROV[p])(r);
const SBASE = { subject: { type: 'user', id: 'ignored' }, action: { name: 'read' }, resource: { type: 'doc', id: '1' } };
const bodies = (path: string): any[] => {
  const s = path === M.SEARCH_SUBJECT_PATH ? { ...SBASE } : path === M.SEARCH_RESOURCE_PATH ? { subject: { type: 'user', id: 'a' }, action: { name: 'read' }, resource: { type: 'doc', id: 'ignored' } } : { subject: { type: 'user', id: 'a' }, resource: { type: 'doc', id: '1' } };
  return [
    s, { ...s, page: { limit: 1 } }, { ...s, page: { limit: 2 } }, { ...s, page: { limit: 3 } }, { ...s, page: { limit: 0 } }, { ...s, page: { limit: 100, token: 't' } },
    { ...s, page: { limit: -1 } }, { ...s, page: { limit: 1.5 } }, { ...s, page: { token: 5 } }, { ...s, page: null }, { ...s, page: [] }, { ...s, context: { c: 1 } }, { ...s, context: null },
    { ...s, extra: 1 }, {}, null, 'x', { ...s, subject: { type: '' } },
    path === M.SEARCH_ACTION_PATH ? { ...s, action: { name: 'x' } } : { ...s, action: undefined }, { ...s, resource: null },
  ];
};
for (const path of [M.SEARCH_SUBJECT_PATH, M.SEARCH_RESOURCE_PATH, M.SEARCH_ACTION_PATH]) {
  for (const p of Object.keys(PROV)) for (const [i, b] of bodies(path).entries()) await o.run('authzenSearchHandler', `${p}${path}/b${i}`, SH, [p, { path, body: b }]);
}
for (const p of Object.keys(PROV)) await o.run('authzenSearchHandler', `${p}/other`, SH, [p, { path: '/access/v1/evaluation', body: {} }]);
for (const p of Object.keys(PROV)) for (const b of ['', '/base', 'https://pdp.example']) await o.run('searchMetadata', `${p}${b}`, (base: string, n: string) => M.searchMetadata(base, PROV[n]), [b, p]);

refWrite(o, 'authzen');
