// Oracle: @atlasauth/pca-mcp (the pure surface: the WWW-Authenticate parser and step-up planner, the RFC 9207 iss table, the v1 action-schema draft from
// an MCP tool list with its decisions and closed-world tool-call check, the tool-result proof meta, the client conformance matrix). Deterministic.
// Not covered: withPCA (needs a live agent), pcaFetch (needs a fetch and an agent), importActionDefsFromMcp (optional package).
// PORTING (fn(args) -> native entry point, comparison rule; "Mcp" = net.atlasauth.pca.mcp.Mcp, JSON by value):
//   constants()                                   {MCP_CLIENT_REVISIONS, MCP_AUTH_CLIENT_ROWS}  <-  Mcp.MCP_CLIENT_REVISIONS, Mcp.mcpAuthClientRows()
//   parseChallenges(h) / pcaNeedProblem(h)        same names; a repeated param keeps its first value; the params 'constructor' and '__proto__' are never stored
//   planStepUp(status, header, state)             same name; state {requested, attempts, maxAttempts?, pcaAware?}
//   checkAuthorizationResponseIss(a)              a {recordedIssuer, issParameterSupported, iss}; an absent iss differs from a null one
//   guardToolResult(pca, result)                  Mcp.guardToolResult(Object pca, Object result)
//   pcaHeaders(encoded)                           Mcp.pcaHeaders(encoded): {PCA-Action: base64url(utf8)}; the reference's provenance header is not produced natively
//   draftActionSchemaFromMcp(tools, site)         Mcp.draftActionSchemaFromMcp(List, Map): {schema, todo}
//   applySchemaDecisions(draft, decisions)        same name
//   verbOfTool(schema, tool) / conformToolCall(schema, tool, args)    same names; null where the reference returns undefined
import { Oracle, HOSTILE, refWrite, rng, variants } from './lib.mjs';

const M: any = await import('../../../packages/pca-mcp/src/index.ts');
const core: any = await import('../../../packages/pca/src/index.ts');
const o = new Oracle('mcp', 'tools/pca-audit/oracles/mcp.mts', 'TS-reference oracle for the MCP adapter pure surface (step-up client, action-schema draft).');

// ---- constants -----------------------------------------------------------------------------------------------------------
await o.run('constants', 'all', () => ({ MCP_CLIENT_REVISIONS: M.MCP_CLIENT_REVISIONS, MCP_AUTH_CLIENT_ROWS: M.MCP_AUTH_CLIENT_ROWS }), []);

// ---- parseChallenges / planStepUp / iss ------------------------------------------------------------------------------------------
const NEED = core.encodePcaNeed({ v: 1, kind: 'scope', verb: 'pay', resource: 'cart/1', scopes: ['pay:write'] });
const BAD_NEED = Buffer.from('{"v":2}').toString('base64url');
const heads: any[] = [
  'Bearer realm="x", error="insufficient_scope", scope="a b", resource_metadata="https://rs/.well-known/oauth-protected-resource"', `Bearer error="insufficient_scope", scope="a", pca_need="${NEED}"`, `Bearer error="insufficient_scope", pca_need="${BAD_NEED}"`,
  'Bearer error="insufficient_scope", pca_need=""', 'Bearer error="insufficient_scope", pca_need="!!!"', 'Bearer error="invalid_token"', 'Basic realm="x", Bearer error="insufficient_scope" scope="z"', 'bearer ERROR="insufficient_scope", Scope="b a c"',
  'Bearer error=insufficient_scope, scope=a', 'Bearer error = "insufficient_scope" , scope = "a b"', 'Bearer error="insufficient_scope", error="other"', 'Bearer error="insufficient_scope", constructor="x", __proto__="y", scope="s"', 'Bearer error="a\\"b\\\\c", x="\\q"',
  'Bearer error="unterminated', 'Bearer =x', '"', '=', ',,,', '', '   ', 'Bearer', 'Bearer ', 'Bearer a=b=c', 'Bearer a="b"c="d"', 'Bearer a=,b=c', 'Bearer\terror="insufficient_scope"', 'Bearer error="insufficient_scope"', `Bearer pca_need="${NEED}"`,
  `Bearer error="insufficient_scope", pca_need="${NEED}"`, `Bearer error="insufficient_scope",pca_need="${NEED}"`, `Bearer error="insufficient_scope" pca_need="${NEED}"`, `Bearer error="insufficient_scope", xpca_need="${NEED}"`, `Bearer error="insufficient_scope", pca_need=${NEED}`,
  `Bearer error="insufficient_scope", PCA_NEED="${NEED}"`, `Bearer error="insufficient_scope", pca_need="${NEED}", pca_need="${BAD_NEED}"`, `Bearer error="insufficient_scope", pca_need="a\\"b"`, 'Bearer error="insufficient_scope", scope="  a   b  "', 'Bearer error="insufficient_scope", scope="b,a"',
  'Bearer error="insufficient_scope", scope="é ü"', 'Bearer error="insufficient_scope", scope=""', 'Bearer error="insufficient_scope", scope="a a a"', 'PCA-StepUp need="x", Bearer error="insufficient_scope"', 'İ="x"', 'Bearer İ="x", ſ="y"', 'Bearer a="😀"',
  5, null, undefined, [], {}, true,
];
const frag = ['Bearer', 'Basic', 'error', 'scope', 'realm', 'pca_need', 'insufficient_scope', 'a b', '=', '"', ',', ' ', '\t', '\\', 'x', 'invalid_token', 'resource_metadata', '__proto__', 'constructor', `${NEED}`, 'é'];
const R = rng(0xc0ffee);
for (let i = 0; i < 220; i++) heads.push(Array.from({ length: R.int(1, 9) }, () => R.pick(frag)).join(R.pick(['', ' ', ', ', ','])));
for (const [i, h] of heads.entries()) {
  await o.run('parseChallenges', `h${i}`, (x: any) => M.parseChallenges(x), [h ?? null]);
  await o.run('pcaNeedProblem', `h${i}`, (x: any) => M.pcaNeedProblem(x) ?? null, [h ?? null]);
}
const states: any[] = [{ requested: [], attempts: 0 }, { requested: ['a'], attempts: 0 }, { requested: ['a', 'b'], attempts: 2 }, { requested: ['a'], attempts: 3 }, { requested: ['a'], attempts: 1, maxAttempts: 1 }, { requested: ['a'], attempts: 0, maxAttempts: 0 },
  { requested: ['z'], attempts: 0, pcaAware: true }, { requested: ['a', 'b'], attempts: 0, pcaAware: true }, { requested: ['b', 'a'], attempts: 1, pcaAware: false }, { requested: [], attempts: 0.5 }, { requested: ['a', 'a'], attempts: 0 }, { requested: ['b'], attempts: -1 },
  { requested: ['a'], attempts: 0, maxAttempts: 2.5 }, { requested: ['é'], attempts: 0 }, { requested: ['B', 'a', 'C'], attempts: 0 }];
for (const [si, st] of states.entries()) for (const [hi, h] of heads.slice(0, 40).entries()) for (const status of [403, 401, 200]) {
  if (status !== 403 && hi > 6) continue;
  await o.run('planStepUp', `s${si}h${hi}c${status}`, M.planStepUp, [status, h ?? null, st]);
}
await o.run('planStepUp', 'strstatus', M.planStepUp, ['403', heads[0], states[0]]);
await o.run('planStepUp', 'nullstatus', M.planStepUp, [null, heads[0], states[0]]);
await o.run('planStepUp', 'nohead', M.planStepUp, [403, null, states[0]]);
const issCases: any[] = [];
for (const rec of ['https://as.example', '', undefined, null, 5, 'https://AS.example']) for (const sup of [true, false, undefined, 'yes', null]) for (const iss of [undefined, 'https://as.example', 'https://as.example/', 'https://AS.example', null, '', 5, 'https://as.example ']) issCases.push({ recordedIssuer: rec, issParameterSupported: sup, iss });
for (const [i, c] of issCases.entries()) await o.run('checkAuthorizationResponseIss', `c${i}`, M.checkAuthorizationResponseIss, [c]);

// ---- guardToolResult / pcaHeaders -------------------------------------------------------------------------------------------------
const results: any[] = [{ content: [{ type: 'text', text: 'ok' }] }, { content: [], isError: true, _meta: { a: 1 } }, { content: [], _meta: null }, { content: [], _meta: 'x' }, { content: [], _meta: [1, 2] }, { content: [], _meta: { 'x-pca-action': 'old' } }, {}, 5, 'str', [], null, { _meta: 0 }, { _meta: true }];
for (const [i, r] of results.entries()) for (const [j, p] of [{ encoded: 'ENC' }, { encoded: '' }, {}, { encoded: null }, { encoded: 5 }, null, 'x', { encoded: 'é ' }].entries()) await o.run('guardToolResult', `r${i}p${j}`, M.guardToolResult, [p, r]);
for (const [i, e] of ['', 'abc', '{"a":1}', 'é', '😀', 'a'.repeat(100), '\u0000'].entries()) await o.run('pcaHeaders', `e${i}`, (x: string) => { const h = M.pcaHeaders(x); return { 'PCA-Action': h['PCA-Action'] }; }, [e]);

// ---- action schema draft ------------------------------------------------------------------------------------------------------------
const SITE = { site: 'shop.example', aud: 'https://shop.example', version: '1.0' };
const tools: any[] = [
  { name: 'search', description: 'search things', inputSchema: { type: 'object', properties: { q: { type: 'string', maxLength: 50 }, limit: { type: 'integer', minimum: 1, maximum: 100 } }, required: ['q'] }, annotations: { readOnlyHint: true } },
  { name: 'pay', description: 'x'.repeat(2000), inputSchema: { type: 'object', properties: { amount: { type: 'integer', minimum: 0, 'x-pca-semantic': 'money', 'x-pca-unit': 'cents', 'x-pca-accumulates-into': ['spend'] }, currency: { type: 'string', enum: ['USD', 'EUR'] }, express: { type: 'boolean' }, when: { type: 'string', format: 'date' } }, required: ['amount', 'currency'] }, annotations: { destructiveHint: true } },
  { name: 'tags', inputSchema: { type: 'object', properties: { tags: { type: 'array', uniqueItems: true, items: { type: 'string', enum: ['a', 'b'] }, minItems: 1, maxItems: 2 }, ids: { type: 'array', items: { type: 'integer' }, maxItems: 5 }, misc: { type: 'array' } } } },
  { name: 'refs', inputSchema: { type: 'object', properties: { a: { $ref: '#/definitions/A' }, b: { $ref: '#/definitions/B', description: 'sibling' }, c: { $ref: 'https://remote/x' }, d: { $ref: '#/definitions/missing' }, e: { $ref: '#/definitions/Loop' } }, definitions: { A: { type: 'string' }, B: { type: 'integer', exclusiveMinimum: 0, exclusiveMaximum: 10 }, Loop: { $ref: '#/definitions/Loop' } } } },
  { name: 'combo', inputSchema: { type: 'object', properties: { u: { anyOf: [{ type: 'string' }, { type: 'null' }] }, v: { oneOf: [{ const: 'a' }, { const: 'b' }, { enum: ['c', 'd'] }] }, w: { anyOf: [{ type: 'string' }, { type: 'integer' }] }, x: { allOf: [{ type: 'string', maxLength: 3 }, { description: 'merged' }] }, y: { const: 'k' }, z: { type: ['null', 'integer'] } } } },
  { name: 'bad-name', inputSchema: { type: 'object', properties: { 'a-b': { type: 'string' }, ok: { type: 'number' }, obj: { type: 'object' }, nul: { type: 'null' }, none: {} } } },
  { name: 'nested', inputSchema: { type: 'object', properties: { o: { type: 'object', properties: { p: { type: 'string' } } } }, allOf: [{ properties: { extra: { type: 'string' } }, required: ['extra'] }] } },
  { name: 'noschema' }, { name: 'emptyschema', inputSchema: {} }, { name: 'weird', description: '', inputSchema: { properties: 5, required: 'ab' } },
  { name: 'unicode_é', inputSchema: { type: 'object', properties: { 'é': { type: 'string' }, ok_1: { type: 'string', 'x-pca-semantic': 'name', 'x-pca-sensitivity': 'free' } } }, annotations: { readOnlyHint: false } },
];
const drafts: Record<string, any> = {};
for (const [i, t] of tools.entries()) await o.run('draftActionSchemaFromMcp', `t${i}`, async (tl: any, s: any) => (await M.draftActionSchemaFromMcp(tl, s)), [[t], SITE]);
await o.run('draftActionSchemaFromMcp', 'all', async (tl: any, s: any) => (await M.draftActionSchemaFromMcp(tl, s)), [tools, SITE]);
for (const [i, s] of [{ ...SITE, verbPrefix: 'shop.' }, { ...SITE, verbPrefix: '' }, { site: 's', aud: 'a', version: 'v' }, { site: 's' }, {}, { ...SITE, verbPrefix: 5 }, { ...SITE, verbPrefix: null }].entries())
  await o.run('draftActionSchemaFromMcp', `site${i}`, async (tl: any, st: any) => (await M.draftActionSchemaFromMcp(tl, st)), [tools.slice(0, 3), s]);
await o.run('draftActionSchemaFromMcp', 'empty', async (tl: any, s: any) => (await M.draftActionSchemaFromMcp(tl, s)), [[], SITE]);
const DEEP = (n: number): any => { let s: any = { type: 'string' }; for (let i = 0; i < n; i++) s = { allOf: [s] }; return s; };
for (const n of [3, 7, 8, 9, 12]) await o.run('draftActionSchemaFromMcp', `deep${n}`, async (tl: any, s: any) => (await M.draftActionSchemaFromMcp(tl, s)), [[{ name: 'd', inputSchema: { type: 'object', properties: { p: DEEP(n) } } }], SITE]);
for (const [label, v] of variants(tools[1], { depth: 5, maxPaths: 60 })) await o.run('draftActionSchemaFromMcp', `v${o.cases.length}`, async (tl: any, s: any) => (await M.draftActionSchemaFromMcp(tl, s)), [[v], SITE]);
for (const [i, h] of HOSTILE.entries()) await o.run('draftActionSchemaFromMcp', `hostile${i}`, async (tl: any, s: any) => (await M.draftActionSchemaFromMcp(tl, s)), [[{ name: 'h', inputSchema: { type: 'object', properties: { p: h, q: { type: 'string', maxLength: h, minimum: h, description: h } } } }], SITE]);

const DRAFT = (await M.draftActionSchemaFromMcp(tools.slice(0, 3), SITE)).schema;
const decisions: any[] = [
  { verbs: {} }, { verbs: { pay: { reversibility: 'rate_limited' } } }, { verbs: { pay: { params: { 'action.params.amount': { semantic: 'money', sensitivity: 'critical', unit: 'cents', max: 500 } } } } }, { verbs: { search: { reversibility: 'reversible', params: { 'action.params.q': { sensitivity: 'free' } } } } },
  { verbs: { nope: {} } }, { verbs: { pay: { params: { 'action.params.nope': {} } } } }, { verbs: { pay: { params: { 'action.params.amount': null } } } }, { verbs: { pay: { params: { 'action.params.amount': 5 } } } }, { verbs: { pay: { params: { 'action.params.amount': 'ab' } } } }, { verbs: { pay: null } }, { verbs: { pay: 5 } },
  { verbs: { pay: { reversibility: '' } } }, { verbs: { pay: { reversibility: 5 } } }, { verbs: { pay: { params: null } } }, { verbs: { pay: { params: 'ab' } } }, { verbs: { pay: { params: [] } } }, { verbs: null }, { verbs: 'ab' }, { verbs: [] }, {},
  { verbs: {}, units: { cents: { per: 'x' } } }, { verbs: {}, units: null }, { verbs: {}, units: 'ab' }, { verbs: { pay: { reversibility: 'irreversible' }, search: { reversibility: 'reversible' } } }, { verbs: { 1: {}, pay: {} } }, { verbs: { pay: { params: { 'action.params.amount': { min: -0 } } } } },
];
for (const [i, d] of decisions.entries()) await o.run('applySchemaDecisions', `d${i}`, M.applySchemaDecisions, [DRAFT, d]);
await o.run('applySchemaDecisions', 'negzero', M.applySchemaDecisions, [{ ...DRAFT, extra: -0, units: { u: 1 } }, { verbs: {}, units: { v: 2 } }]);

// ---- verbOfTool / conformToolCall ---------------------------------------------------------------------------------------------------------
const SCHEMA = { ...DRAFT, verbs: DRAFT.verbs.map((v: any) => ({ ...v, params: Object.fromEntries(Object.entries(v.params).map(([k, d]: any) => [k, { ...d, semantic: 'x' }])) })) };
const dup = { ...SCHEMA, verbs: [...SCHEMA.verbs, { ...SCHEMA.verbs[0], verb: 'other', mcp: { tool: 'search' } }] };
for (const [i, s] of [SCHEMA, dup, { verbs: [] }, { verbs: [{ verb: 'a', mcp: { tool: 't' } }, { verb: 'b' }, { mcp: null, verb: 'c' }] }, { verbs: [{ mcp: { tool: 'x' } }] }, { verbs: [{ verb: 'v', mcp: 'x' }] }, {}, null, { verbs: 'x' }, { verbs: [null] }, { verbs: [5, { verb: 'a', mcp: { tool: 'x' } }] }].entries())
  for (const [j, t] of ['search', 'pay', 'tags', 'nope', '', 't', 'x'].entries()) await o.run('verbOfTool', `s${i}t${j}`, (sc: any, tn: any) => M.verbOfTool(sc, tn) ?? null, [s, t]);
const argSets: any[] = [{ q: 'x' }, { q: 'x', limit: 5 }, { q: 'x', limit: 0 }, { q: 'x', limit: 101 }, { q: 'x', limit: 1.5 }, { q: 'x', limit: '5' }, {}, { limit: 5 }, { q: 'x', extra: 1 }, { q: 5 }, { q: 'x'.repeat(51) }, { q: '' }, null, [], 'x', 5, { q: 'x', limit: null },
  { amount: 5, currency: 'USD' }, { amount: -1, currency: 'USD' }, { amount: 5, currency: 'GBP' }, { amount: 5, currency: 'USD', express: true }, { amount: 5, currency: 'USD', express: 'yes' }, { amount: 5, currency: 'USD', when: '2026-02-30' }, { amount: 5, currency: 'USD', when: '2026-02-28' },
  { tags: ['a'] }, { tags: ['a', 'b', 'a'] }, { tags: [] }, { tags: ['c'] }, { ids: [1, 2] }, { ids: [1, 'x'] }, { ids: [] }, { misc: [] }, { misc: 'x' }, { ids: Array.from({ length: 6 }, (_, i) => i) }];
for (const [i, a] of argSets.entries()) for (const [j, t] of ['search', 'pay', 'tags', 'nope'].entries()) await o.run('conformToolCall', `a${i}t${j}`, M.conformToolCall, [SCHEMA, t, a]);
await o.run('conformToolCall', 'dup', M.conformToolCall, [dup, 'search', { q: 'x' }]);
await o.run('conformToolCall', 'noverbs', M.conformToolCall, [{ verbs: [] }, 'search', {}]);

refWrite(o, 'mcp');
