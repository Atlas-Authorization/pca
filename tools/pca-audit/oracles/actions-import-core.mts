// Oracle: @atlasauth/pca-actions import/{limits,common,openapi,mcp,jsonschema,asyncapi}.ts. Writes out/ref-actions-import-core.json.gz.
// PORTING table: fn(args) -> native entry point (net.atlasauth.pca.actions.importers), comparison rule = JSON value equality
//   Sources and options are JSON; an importer returns {defs, todo, source}; any throw in the reference needs a throw in the native.
//   importOpenApi(doc, opts) / importMcp(src, opts) / importAsyncApi(doc, opts) / importJsonSchema(schema, opts{verb,title?,description?,effects?})
//        -> OpenApiImporter.importOpenApi / McpImporter.importMcp / AsyncApiImporter.importAsyncApi / JsonSchemaImporter.importJsonSchema
//   clip(s, max) tokensOf(s) verbOf(ns, raw) aliasOf(raw, verb) humanize(s) pointer(root, ref) paramSeg(s) -> ImportCommon.<same>
//   resolveLimits(over) -> ImportLimits.resolve(over) (the six limits as an object {max_bytes, max_ops, max_json_depth, max_nodes, max_ref_nodes, max_ref_depth})
//   checkParsed(root, over) -> ImportLimits.resolve(over).checkParsed(root);  textSizeCheck(text, over) -> ImportLimits.resolve(over).textSizeCheck(text) (returns null)
import * as C0 from '../../../packages/pca-actions/src/import/common.ts';
import * as L0 from '../../../packages/pca-actions/src/import/limits.ts';
import * as O0 from '../../../packages/pca-actions/src/import/openapi.ts';
import * as M0 from '../../../packages/pca-actions/src/import/mcp.ts';
import * as J0 from '../../../packages/pca-actions/src/import/jsonschema.ts';
import * as A0 from '../../../packages/pca-actions/src/import/asyncapi.ts';
import { Oracle, variants, refWrite, clone, rng } from './lib.mjs';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const C = un(C0), L = un(L0), O = un(O0), M = un(M0), J = un(J0), A = un(A0);
const o = new Oracle('actions-import-core', 'tools/pca-audit/oracles/actions-import-core.mts', 'TS-reference oracle for the pca-actions importers (openapi, mcp, jsonschema, asyncapi) and their shared helpers.');
const R = rng(0x8a11);
const take = <T,>(xs: T[], n: number): T[] => { const k = Math.max(1, Math.floor(xs.length / n)); return xs.filter((_, i) => i % k === 0).slice(0, n); };

// ---- helpers ----
const NAMES = ['createCustomer', 'list_invoices', 'GET /v1/a/b', 'a.b.c', 'refund', 'x', '', ' ', 'HTTPServerError', 'ünïcode_Näme', 'a'.repeat(40), 'send-email-now', 'get', 'Get Thing By Id', 'a/b/c/d/e/f/g/h', 'one two three four five six seven', 'naméx', '\ud800bad', 'camelCaseXMLParser2go', 'delete_all_the_things_from_the_very_long_place', 'ß', 'İstanbul', '日本語', 'a--b__c..d', 'listAll', 'userDelete', 'v1.2.3'];
for (const n of NAMES) {
  await o.run('tokensOf', n, C.tokensOf, [n]); await o.run('humanize', n, C.humanize, [n]);
  await o.run('verbOf', n, C.verbOf, ['api', n]); await o.run('verbOf', `ns2 ${n}`, C.verbOf, ['x_y', n]);
  for (const v of ['api.x', 'api.list_invoices', '']) await o.run('aliasOf', `${n}|${v}`, C.aliasOf, [n, v]);
  await o.run('paramSeg', n, C.paramSeg, [n]);
}
await o.run('paramSeg', '___', C.paramSeg, ['___']); await o.run('paramSeg', 'long', C.paramSeg, ['_'.repeat(64) + 'abc']); await o.run('paramSeg', 'long2', C.paramSeg, ['a'.repeat(100)]);
await o.run('paramSeg', 'astral', C.paramSeg, ['a\u{1F600}b']);
const CLIPS = ['  hello \n world  ', 'a\u0000b‮c', 'x\ud800y', 'x\udc00y', 'é'.repeat(100), 'é'.repeat(50), '\u{1F600}'.repeat(30), '   padded ﻿', 'tab\there', 'a b', ''];
for (const [i, s] of CLIPS.entries()) for (const m of [0, 1, 2, 3, 5, 10, 50, 120, 280, 1024]) await o.run('clip', `${i}/${m}`, C.clip, [s, m]);
for (const x of [null, 5, true, [], {}]) await o.run('clip', `nonstr ${JSON.stringify(x)}`, C.clip, [x, 10]);

const root = { a: { b: [1, { c: 2 }], 'x/y': { z: 1 }, 'p~q': { w: 1 }, 'sp ace': { v: 1 } }, arr: [[1], { k: 1 }] };
for (const ref of ['#/a', '#/a/b', '#/a/b/0', '#/a/b/1', '#/a/b/1/c', '#/a/b/2', '#/a/x~1y', '#/a/x~1y/z', '#/a/p~0q', '#/a/sp%20ace', '#/a/sp%2', '#/a/%E0%A4%A', '#/a/%C3%A9', '#', '#/', 'other', '', '#/arr/0', '#/arr/1', '#/arr/length', '#/arr/01', '#/a/b/-1', '#/__proto__', '#/a/constructor', 5, null])
  await o.run('pointer', String(ref), C.pointer, [root, ref]);
await o.run('pointer', 'root str', C.pointer, ['abc', '#/a']); await o.run('pointer', 'root null', C.pointer, [null, '#/a']);

for (const over of [undefined, {}, { max_bytes: 10 }, { max_ops: 1e9 }, { max_json_depth: 0 }, { max_nodes: -1 }, { max_ref_depth: 1.5 }, { max_ref_nodes: null }, { max_bytes: 5, max_ops: 3, max_json_depth: 2, max_nodes: 4, max_ref_nodes: 9, max_ref_depth: 2 }, 'x', [], { max_bytes: '5' }, { max_bytes: 2 ** 53 }])
  await o.run('resolveLimits', JSON.stringify(over) ?? 'undef', L.resolveLimits, over === undefined ? [] : [over]);
const rl = (over: any) => { const l = L.resolveLimits(over); return [l.max_bytes, l.max_ops, l.max_json_depth, l.max_nodes, l.max_ref_nodes, l.max_ref_depth]; };
for (const [i, over] of [undefined, { max_bytes: 10 }, { max_json_depth: 2 }, { max_nodes: 3 }].entries()) {
  for (const [j, r] of [{ a: 1 }, [1, [2, [3, [4]]]], 'str', { a: { b: { c: { d: 1 } } } }, [[], {}], null, 5, { a: 'x'.repeat(20) }, { a: [1, 2, 3, 4, 5, 6] }].entries()) await o.run('checkParsed', `${i}/${j}`, (x: any, ov: any) => L.checkParsed(x, L.resolveLimits(ov)), [r, over ?? {}]);
  for (const [j, t] of ['abc', 'é'.repeat(8), '', 'x'.repeat(11)].entries()) await o.run('textSizeCheck', `${i}/${j}`, (x: any, ov: any) => L.textSizeCheck(x, L.resolveLimits(ov)), [t, over ?? {}]);
}
void rl;

// ---- OpenAPI ----
const OA: any = {
  openapi: '3.0.3', info: { title: 't', version: '1' },
  paths: {
    '/v1/customers': {
      get: { operationId: 'listCustomers', summary: 'List customers', parameters: [{ name: 'limit', in: 'query', schema: { type: 'integer', minimum: 1, maximum: 100 } }, { name: 'Idempotency-Key', in: 'header', schema: { type: 'string' } }, { name: 'X-Trace', in: 'header', schema: { type: 'string' } }, { $ref: '#/components/parameters/Page' }], security: [{ oauth: ['read', 'write'] }] },
      post: { operationId: 'createCustomer', description: 'Create one.', requestBody: { content: { 'application/json': { schema: { $ref: '#/components/schemas/Cust' } } } }, 'x-internal': true },
    },
    '/v1/customers/{id}': {
      parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }],
      get: { summary: 'Get one' }, delete: { deprecated: true, operationId: 'deleteCustomer', parameters: [{ name: 'force', in: 'query', required: true, schema: { type: 'boolean' }, description: 'Force it.' }] },
      patch: { operationId: 'patchCustomer', requestBody: { content: { 'application/x-www-form-urlencoded': { schema: { type: 'object', properties: { name: { type: 'string' }, id: { type: 'string' } } } } } } },
    },
    '/pay': { post: { 'x-pca-verb': 'api.pay.send', requestBody: { content: { 'application/vnd.api+json': { schema: { type: 'object', required: ['amount'], properties: { amount: { type: 'integer', 'x-pca-role': 'money.amount', exclusiveMinimum: 0, maximum: 5000 }, currency: { type: 'string', enum: ['USD', 'EUR'] }, note: { type: 'string', 'x-pca-role': 'bogus role' } } } } } } } },
    '/files': { put: { operationId: 'putFile', requestBody: { content: { 'text/plain': { schema: { type: 'string' } } } } }, get: { operationId: 'listFiles' } },
    '/e/{a}/{b}': { head: {}, options: {}, trace: {} },
  },
  components: {
    parameters: { Page: { name: 'page', in: 'query', schema: { type: 'integer', exclusiveMinimum: 0, exclusiveMaximum: 50 } } },
    schemas: { Cust: { type: 'object', required: ['name'], properties: { name: { type: 'string', maxLength: 50, description: '  The  name ' }, email: { type: 'string', format: 'email' }, tags: { type: 'array', items: { type: 'string', enum: ['a', 'b'] }, uniqueItems: true, maxItems: 3 }, address: { type: 'object', properties: { street: { type: 'string' }, geo: { type: 'object', properties: { lat: { type: 'number' }, deep: { type: 'object', properties: { z: { type: 'integer' } } } } } } }, kind: { anyOf: [{ const: 'a' }, { const: 'b' }] }, parent: { $ref: '#/components/schemas/Cust' }, id: { type: 'string', readOnly: true }, when: { type: 'string', format: 'date-time' }, day: { type: 'string', format: 'date' }, n: { type: 'integer', format: 'int64' }, scores: { type: 'array', items: { type: 'integer' }, minItems: 1 }, misc: { type: 'array', items: { type: 'object' } }, 'weird name!': { type: 'string' }, opt: { oneOf: [{ type: 'null' }, { type: 'string' }] }, un: { oneOf: [{ type: 'string' }, { type: 'integer' }] }, all: { allOf: [{ $ref: '#/components/schemas/Base' }, { properties: { extra: { type: 'string' } } }] } } }, Base: { type: 'object', required: ['base'], properties: { base: { type: 'string' } } } },
  },
};
const SW: any = {
  swagger: '2.0', info: { title: 't', version: '1' },
  paths: {
    '/pets': { get: { operationId: 'findPets', parameters: [{ name: 'tags', in: 'query', type: 'array', items: { type: 'string' } }, { name: 'limit', in: 'query', type: 'integer', format: 'int32', maximum: 10 }] }, post: { operationId: 'addPet', parameters: [{ name: 'pet', in: 'body', required: true, schema: { $ref: '#/definitions/Pet' } }] } },
    '/pets/{id}': { get: { parameters: [{ name: 'id', in: 'path', required: true, type: 'integer' }] }, delete: { parameters: [{ name: 'id', in: 'path', required: true, type: 'integer' }, { name: 'api_key', in: 'header', type: 'string' }, { name: 'file', in: 'formData', type: 'string' }] } },
  },
  definitions: { Pet: { type: 'object', required: ['name'], properties: { name: { type: 'string' }, age: { type: 'integer', minimum: 0 }, status: { type: 'string', enum: ['available', 'sold'] } } } },
};
const OPT = { ns: 'api' };
const OAV = [
  ['base', OPT], ['ext', { ns: 'api', allowExtensions: ['x-pca-verb', 'x-pca-role', 'x-internal'] }], ['noext', { ns: 'api', allowExtensions: [] }],
  ['meta', { ns: 'shop', uri: 'https://example.com/openapi.json', licence: 'MIT', now: 1_800_000_000 }], ['badns', { ns: 'Bad-NS' }], ['nons', {}], ['now-neg', { ns: 'api', now: -1 }], ['now-frac', { ns: 'api', now: 1.5 }],
  ['lim-ops', { ns: 'api', limits: { max_ops: 3 } }], ['lim-ref', { ns: 'api', limits: { max_ref_nodes: 5, max_ref_depth: 1 } }], ['lim-bad', { ns: 'api', limits: { max_ops: 0 } }], ['lim-bytes', { ns: 'api', limits: { max_bytes: 100 } }],
];
for (const [n, opts] of OAV) { await o.run('importOpenApi', `oa ${n}`, O.importOpenApi, [OA, opts]); await o.run('importOpenApi', `sw ${n}`, O.importOpenApi, [SW, opts]); }
for (const [n, opts] of OAV.slice(0, 1)) {
  for (const [lab, v] of take([...variants(OA, { maxPaths: 700 })] as [string, any][], 160)) await o.run('importOpenApi', `oa ${n} ${lab}`, O.importOpenApi, [v, opts]);
  for (const [lab, v] of take([...variants(SW, { maxPaths: 300 })] as [string, any][], 70)) await o.run('importOpenApi', `sw ${n} ${lab}`, O.importOpenApi, [v, opts]);
}
// hostile documents
const bad: [string, any][] = [
  ['array', []], ['string', 'openapi: 3'], ['null', null], ['v2 wrong', { swagger: '3.0' }], ['v3.x', { openapi: '3.1.0', paths: {} }], ['v4', { openapi: '4.0' }],
  ['paths str', { openapi: '3.0.0', paths: 'x' }],
  ['cyc ref', { openapi: '3.0.0', paths: { '/a': { $ref: '#/paths/~1b' }, '/b': { $ref: '#/paths/~1a' } } }],
  ['unres ref', { openapi: '3.0.0', paths: { '/a': { $ref: '#/nope' }, '/b': { get: { parameters: [{ $ref: '#/nope' }], requestBody: { $ref: 'http://x/y' } } } } }],
  ['path ref', { openapi: '3.0.0', paths: { '/a': { $ref: '#/x/p' } }, x: { p: { get: { operationId: 'viaRef' } } } }],
  ['array ref', { openapi: '3.0.0', paths: { '/a': { $ref: '#/x/p' } }, x: { p: [1] } }],
  ['dup ids', { openapi: '3.0.0', paths: { '/a': { get: { operationId: 'same' }, post: { operationId: 'same' } }, '/b': { get: { operationId: 'same' } } } }],
  ['nobody', { openapi: '3.0.0', paths: { '/a': { post: { requestBody: { content: { 'text/csv': {}, 'application/xml': {} } } } } } }],
  ['body null', { openapi: '3.0.0', paths: { '/a': { post: { requestBody: { content: { 'application/json': { schema: null } } } } } } }],
  ['body nonobj', { openapi: '3.0.0', paths: { '/a': { post: { requestBody: { content: { 'application/json': { schema: { type: 'string' } } } } } } } }],
  ['ct case', { openapi: '3.0.0', paths: { '/a': { post: { requestBody: { content: { 'Application/JSON; charset=utf-8': { schema: { type: 'object', properties: { a: { type: 'string' } } } } } } } } } }],
  ['sec', { openapi: '3.0.0', security: [{ a: ['z', 'y'] }], paths: { '/a': { get: { security: [] }, post: {} } } }],
  ['many params', { openapi: '3.0.0', paths: { '/a': { get: { parameters: Array.from({ length: 70 }, (_, i) => ({ name: `p${i}`, in: 'query', schema: { type: 'string' } })) } } } }],
  ['many props', { openapi: '3.0.0', paths: { '/a': { post: { requestBody: { content: { 'application/json': { schema: { type: 'object', properties: Object.fromEntries(Array.from({ length: 70 }, (_, i) => [`f${i}`, { type: 'string' }])) } } } } } } } }],
  ['param kinds', { openapi: '3.0.0', paths: { '/a': { get: { parameters: [{ name: 'c', in: 'cookie' }, { name: 'h', in: 'header', schema: { type: 'string' } }, { name: 'q1', in: 'query', description: 'D', schema: { type: 'string' } }, { name: 'q2', in: 'query', description: 'D', schema: { type: 'string', description: 'own' } }, { name: 'q3', in: 'query', schema: 'abc', description: 5 }, { name: 'sp ace', in: 'query' }] } } } }],
  ['unicode', { openapi: '3.0.0', paths: { '/ünï/{x}': { get: { operationId: 'ünï', summary: 'Ü\u0000‮ x' } }, '/a b/{c}/': { get: {} } } }],
  ['versions', { openapi: '3.0.0', paths: { '/v1/api/REST/users/{id}': { get: {} }, '/V2.1/Public/orders': { get: {} }, '/{a}': { get: {} }, '/{}': { get: {} } } }],
  ['allof bad', { openapi: '3.0.0', paths: { '/a': { post: { requestBody: { content: { 'application/json': { schema: { allOf: [{ required: 'abc' }, { required: 5 }] } } } } } } } }],
  ['allof str', { openapi: '3.0.0', paths: { '/a': { post: { requestBody: { content: { 'application/json': { schema: { type: 'object', allOf: [{ properties: 'ab', required: 'xy' }, { properties: ['q'] }] } } } } } } } }],
  ['long id', { openapi: '3.0.0', paths: { '/a': { get: { operationId: 'x'.repeat(201) }, post: { operationId: 'y'.repeat(200) } } } }],
  ['verb ext', { openapi: '3.0.0', paths: { '/a': { get: { 'x-pca-verb': 'api.ok.fine', operationId: 'aa' }, post: { 'x-pca-verb': 'other.nope', operationId: 'bb' }, put: { 'x-pca-verb': 5 } } } }],
];
for (const [n, d] of bad) for (const [on, opts] of [OAV[0], OAV[1]] as [string, any][]) await o.run('importOpenApi', `bad ${n} ${on}`, O.importOpenApi, [d, opts]);

// ---- MCP ----
const MC: any = { tools: [
  { name: 'search_docs', description: 'Search.', inputSchema: { type: 'object', properties: { q: { type: 'string' }, limit: { type: 'integer', maximum: 50 } }, required: ['q'] }, annotations: { readOnlyHint: true, idempotentHint: true } },
  { name: 'delete_repo', title: 'Delete a repo', inputSchema: { type: 'object', properties: { repo: { type: 'string' }, opts: { type: 'object', properties: { force: { type: 'boolean' } } } } }, annotations: { destructiveHint: true, openWorldHint: true, title: 'Annotated title' } },
  { name: 'both', annotations: { readOnlyHint: true, destructiveHint: true } }, { name: 'search_docs' }, { name: '' }, { title: 'noname' }, 7,
  { name: 'refs', inputSchema: { $defs: { X: { type: 'string', enum: ['p', 'q'] } }, type: 'object', properties: { a: { $ref: '#/$defs/X' } } } },
  { name: 'refs2', inputSchema: { type: 'object', properties: { a: { $ref: '#/properties/b' }, b: { $ref: '#/properties/a' }, c: { oneOf: [{ type: 'string' }, { type: 'integer' }] } } } },
  { name: 'x'.repeat(257) }, { name: 'with space/and.dots:colons' },
] };
for (const [n, opts] of OAV) await o.run('importMcp', n, M.importMcp, [MC, opts]);
await o.run('importMcp', 'array', M.importMcp, [MC.tools, OPT]);
for (const x of [null, 'x', 5, {}, { tools: 'x' }, { tools: [] }, []]) await o.run('importMcp', `bad ${JSON.stringify(x)}`, M.importMcp, [x, OPT]);
for (const [lab, v] of take([...variants(MC, { maxPaths: 400 })] as [string, any][], 140)) await o.run('importMcp', lab, M.importMcp, [v, OPT]);

// ---- JSON Schema ----
const JS: any = { type: 'object', title: 'Make a thing', description: 'Makes things.', required: ['name', 'n'], properties: { name: { type: 'string', maxLength: 10 }, n: { type: 'integer', exclusiveMinimum: 1 }, flag: { type: 'boolean' }, nested: { type: 'object', properties: { a: { type: 'string' }, b: { type: 'object', properties: { c: { type: 'object', properties: { d: { type: 'string' } } } } } } }, list: { type: 'array', items: { type: 'string' } }, e: { enum: ['x', 'y'] }, k: { const: 'only' }, f: { type: 'number' }, tup: { type: 'array', items: [{ type: 'string' }] }, u: { type: ['string', 'null'] }, r: { $ref: '#/$defs/R' } }, $defs: { R: { type: 'string', format: 'uuid' } } };
const JOPT = [{ ns: 'api', verb: 'api.thing.make' }, { ns: 'api', verb: 'api.thing.make', effects: ['create', 'send'], title: 'T', description: 'D' }, { ns: 'api', verb: 'api.thing' }, { ns: 'api', verb: 'api.thing.make', effects: [] }, { ns: 'api', verb: 'api.thing.make', effects: ['bogus'] }, { ns: 'api', verb: 'other.thing.make' }, { ns: 'api' }, { ns: 'api', verb: 'api.thing.make', effects: ['read'], now: 5, uri: 'u', licence: 'MIT' }, { ns: 'api', verb: 'api.thing.make', allowExtensions: ['x-pca-role'] }, { ns: 'api', verb: 'api.thing.make', title: null, description: null }];
for (const [i, op] of JOPT.entries()) await o.run('importJsonSchema', `opts ${i}`, J.importJsonSchema, [JS, op]);
for (const [i, s] of [[], 'x', null, {}, { type: 'string' }, { type: 'object' }, { anyOf: [{ type: 'object', properties: { a: { type: 'string' } } }] }, { $ref: '#/nope' }, { allOf: [{ properties: { a: { type: 'string' } } }, { properties: { b: { type: 'integer' } }, required: ['b'] }] }, { properties: { 'x-pca-role-p': { type: 'integer', 'x-pca-role': 'money.amount' }, q: { type: 'string', 'x-pca-role': 'id.thing' }, w: { type: 'string', 'x-pca-role': 'x.vendor.field' }, z: { type: 'string', 'x-pca-role': 'money.amount' } } }].entries())
  for (const [k, op] of [JOPT[0], JOPT[8]].entries()) await o.run('importJsonSchema', `schema ${i}/${k}`, J.importJsonSchema, [s, op]);
for (const [lab, v] of take([...variants(JS, { maxPaths: 400 })] as [string, any][], 140)) await o.run('importJsonSchema', lab, J.importJsonSchema, [v, JOPT[0]]);

// ---- AsyncAPI ----
const A2: any = { asyncapi: '2.6.0', info: { title: 't', version: '1' }, channels: {
  'user/signedup': { parameters: { userId: { schema: { type: 'string' } } }, publish: { operationId: 'onSignup', summary: 'Signed up', message: { payload: { type: 'object', properties: { email: { type: 'string', format: 'email' } } } } }, subscribe: { message: { oneOf: [{ payload: { type: 'object', properties: { id: { type: 'string' } } } }, { $ref: '#/components/messages/M' }] } } },
  'internal/jobs': { 'x-pca-internal': true, publish: { message: { payload: { type: 'object', properties: { job: { type: 'string' } } } } } },
  'ref/ch': { $ref: '#/channels/user~1signedup' }, 'bad/payload': { publish: { message: { payload: { type: 'string' } } }, subscribe: { message: { payload: null } } },
}, components: { messages: { M: { payload: { type: 'object', properties: { m: { type: 'integer' } } } } } } };
const A3: any = { asyncapi: '3.0.0', info: { title: 't', version: '1' }, channels: { userSignedUp: { address: 'user/signedup', messages: { b: { payload: { type: 'object', properties: { b: { type: 'string' } } } }, a: { payload: { type: 'object', properties: { a: { type: 'string' } } } } } }, jobs: { 'x-pca-internal': true, messages: {} } }, operations: { sendSignup: { action: 'send', channel: { $ref: '#/channels/userSignedUp' }, summary: 'S', description: 'D' }, recvSignup: { action: 'receive', channel: { $ref: '#/channels/userSignedUp' }, messages: [{ payload: { type: 'object', properties: { x: { type: 'integer' } } } }] }, runJob: { action: 'send', channel: { $ref: '#/channels/jobs' } }, bad: { action: 'other', channel: { $ref: '#/channels/jobs' } }, nochan: { action: 'send', channel: { $ref: '#/channels/none' } }, inline: { action: 'send', channel: { address: 'inline/addr', messages: { z: { payload: { type: 'object', properties: { z: { type: 'string' } } } } } } } } };
for (const [n, opts] of OAV) { await o.run('importAsyncApi', `v2 ${n}`, A.importAsyncApi, [A2, opts]); await o.run('importAsyncApi', `v3 ${n}`, A.importAsyncApi, [A3, opts]); }
for (const x of [null, 'x', {}, { asyncapi: 2 }, { asyncapi: '1.0' }, { asyncapi: '2.0.0' }, { asyncapi: '3.0.0' }]) await o.run('importAsyncApi', `bad ${JSON.stringify(x)}`, A.importAsyncApi, [x, OPT]);
for (const [lab, v] of take([...variants(A2, { maxPaths: 500 })] as [string, any][], 90)) await o.run('importAsyncApi', `v2 ${lab}`, A.importAsyncApi, [v, OPT]);
for (const [lab, v] of take([...variants(A3, { maxPaths: 500 })] as [string, any][], 90)) await o.run('importAsyncApi', `v3 ${lab}`, A.importAsyncApi, [v, OPT]);
void R; void clone;
refWrite(o, 'actions-import-core');
