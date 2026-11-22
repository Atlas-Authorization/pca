// Oracle: packages/pca/src/action-schema.ts drafting and verb helpers. Writes out/ref-action-schema-draft.json.gz.
// PORTING (fn(args) -> native entry point; comparison = JSON value equality; a reference throw needs a native error):
//   draftSchemaFromOpenApi(doc, site)   {schema, todo}      draft of the action schema from an OpenAPI document
//   reversibilityFromMcpHints(annotations)  {kind, atLeast}
//   reversibilityOf(verbDecl, params)       class name
//   schemaVerb(doc, verb)                   the verb declaration or null
import * as S0 from '../../../packages/pca/src/action-schema.ts';
import { Oracle, refWrite } from './lib.mjs';

const S: any = (S0 as any).default ?? S0;
const o = new Oracle('action-schema-draft', 'tools/pca-audit/oracles/action-schema-draft.mts', 'TS-reference oracle for the action schema drafting helpers.');
const site = { site: 'shop.example', aud: 'https://shop.example', version: '1.0.0' };
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);

const base: any = {
  paths: {
    '/orders/{orderId}': {
      parameters: [{ name: 'orderId', in: 'path', required: true, schema: { type: 'string', maxLength: 36 } }],
      get: { operationId: 'getOrder', description: 'Fetch one order', parameters: [{ name: 'expand', in: 'query', schema: { type: 'string', enum: ['items', 'customer'] } }] },
      delete: { operationId: 'cancelOrder', 'x-pca-reversibility': 'rate_limited', parameters: [{ name: 'reason', in: 'query', required: true, schema: { type: 'string' } }] },
    },
    '/orders': {
      get: { operationId: 'listOrders', parameters: [{ name: 'limit', in: 'query', schema: { type: 'integer', minimum: 1, maximum: 100 } }, { name: 'X-Trace', in: 'header', schema: { type: 'string' } }] },
      post: {
        operationId: 'createOrder', description: 'Place an order',
        requestBody: { content: { 'application/json': { schema: { type: 'object', required: ['sku', 'qty'], properties: { sku: { type: 'string', 'x-pca-semantic': 'sku' }, qty: { type: 'integer', minimum: 1, maximum: 10, 'x-pca-unit': 'items' }, note: { type: 'string', description: 'free text' }, gift: { type: 'boolean' }, tags: { type: 'array', uniqueItems: true, items: { type: 'string', enum: ['a', 'b'] } }, due: { type: 'string', format: 'date' } } } } } },
      },
    },
    '/pay': { post: { operationId: 'payInvoice', 'x-pca-verb': 'billing.pay', 'x-pca-kind': 'write', requestBody: { content: { 'application/vnd.api+json': { schema: { type: 'object', properties: { amount: { type: 'integer', exclusiveMinimum: 0, exclusiveMaximum: 1000001, 'x-pca-accumulates-into': 'spend.usd_cents' } } } } } } } },
    '/health': { get: { operationId: 'health' }, head: { description: 'no id: skipped' } },
  },
};
const docs: [string, any][] = [
  ['base', base],
  ['empty', {}],
  ['paths null', { paths: null }],
  ['no ids', { paths: { '/a': { get: { description: 'x' } } } }],
  ['dup verb', { paths: { '/a': { get: { operationId: 'x' } }, '/b': { get: { operationId: 'x' } } } }],
  ['clash body/query', { paths: { '/c': { post: { operationId: 'clash', parameters: [{ name: 'sku', in: 'query', schema: { type: 'integer' } }], requestBody: { content: { 'application/json': { schema: { properties: { sku: { type: 'string' } } } } } } } } } }],
  ['bad names', { paths: { '/d': { post: { operationId: 'bad', parameters: [{ name: 'a-b', in: 'query' }, { name: 'ok_name', in: 'cookie' }], requestBody: { content: { 'application/json': { schema: { properties: { 'x y': { type: 'string' }, [`${'z'.repeat(70)}`]: { type: 'string' } } } } } } } } } }],
  ['refs', {
    components: { schemas: { Item: { type: 'object', properties: { sku: { type: 'string' }, n: { type: 'integer' } }, required: ['sku'] }, Id: { type: 'string', maxLength: 12 } }, parameters: { Lim: { name: 'limit', in: 'query', schema: { type: 'integer' } } }, requestBodies: { Body: { content: { 'application/json': { schema: { $ref: '#/components/schemas/Item' } } } } } },
    paths: { '/e': { post: { operationId: 'viaRefs', parameters: [{ $ref: '#/components/parameters/Lim' }, { $ref: '#/components/parameters/Missing' }, { name: 'id', in: 'path', schema: { $ref: '#/components/schemas/Id' } }], requestBody: { $ref: '#/components/requestBodies/Body' } } } },
  }],
  ['allOf/anyOf', { paths: { '/f': { post: { operationId: 'combos', requestBody: { content: { 'application/json': { schema: { allOf: [{ properties: { a: { type: 'string' } }, required: ['a'] }, { properties: { b: { anyOf: [{ type: 'string' }, { type: 'null' }] }, c: { oneOf: [{ const: 'x' }, { enum: ['y', 'z'] }] }, d: { anyOf: [{ type: 'string' }, { type: 'integer' }] }, e: { type: 'number' }, f: { type: 'object' } } }] } } } } } } } }],
  ['kind override', { paths: { '/g': { post: { operationId: 'readByPost', 'x-pca-kind': 'read' }, get: { operationId: 'writeByGet', 'x-pca-kind': 'write' }, put: { operationId: 'putIt', 'x-pca-reversibility': 'reversible' } } } }],
  ['array items', { paths: { '/h': { post: { operationId: 'arrs', requestBody: { content: { 'application/json': { schema: { properties: { ids: { type: 'array', items: { type: 'integer' }, minItems: 1, maxItems: 5 }, names: { type: 'array', items: { type: 'string' } }, loose: { type: 'array' } } } } } } } } } }],
  ['long description', { paths: { '/i': { get: { operationId: 'long', description: 'd'.repeat(2000) } } } }],
  ['path item params override', { paths: { '/j/{id}': { parameters: [{ name: 'id', in: 'path', schema: { type: 'string' } }, { name: 'q', in: 'query', schema: { type: 'string' } }], get: { operationId: 'ovr', parameters: [{ name: 'q', in: 'query', required: true, schema: { type: 'integer' } }] } } } }],
  ['param description', { paths: { '/k': { get: { operationId: 'pd', parameters: [{ name: 'a', in: 'query', description: 'from the parameter', schema: {} }, { name: 'b', in: 'query', description: 'ignored', schema: { description: 'schema wins' } }] } } } }],
  ['non object op', { paths: { '/l': { get: [1], post: null, put: 'x', delete: { operationId: 'ok' } } } }],
];
for (const [name, doc] of docs) await run('draftSchemaFromOpenApi', S.draftSchemaFromOpenApi, [doc, site]);
await run('draftSchemaFromOpenApi', S.draftSchemaFromOpenApi, [base, { site: 's', aud: 'a', version: 'v' }]);

for (const a of [undefined, null, {}, { readOnlyHint: true }, { destructiveHint: true }, { readOnlyHint: true, destructiveHint: true }, { readOnlyHint: false, destructiveHint: true }, { readOnlyHint: 'true' }, { idempotentHint: true }, []]) {
  await run('reversibilityFromMcpHints', S.reversibilityFromMcpHints, [a]);
}

const revBy = (def?: string) => ({ verb: 'v', kind: 'write', params: {}, reversibility_by: { param: 'action.params.mode', map: { dry: 'reversible', live: 'irreversible', true: 'rate_limited', '3': 'reversible' }, ...(def ? { default: def } : {}) } });
const verbs: any[] = [revBy(), revBy('rate_limited'), { verb: 'r', kind: 'read', params: {} }, { verb: 'w', kind: 'write', params: {} }, { verb: 'x', kind: 'write', reversibility: 'rate_limited', params: {} }, { verb: 'y', kind: 'read', reversibility: 'irreversible', params: {} }];
const plist: any[] = [{}, { mode: 'dry' }, { mode: 'live' }, { mode: 'other' }, { mode: true }, { mode: false }, { mode: 3 }, { mode: 4 }, { mode: 1.5 }, { mode: null }, { mode: ['dry'] }, { other: 'dry' }];
for (const v of verbs) for (const p of plist) await run('reversibilityOf', S.reversibilityOf, [v, p]);

const doc2 = { v: 1, kind: 'pca-action-schema', site: 's', aud: 'a', version: '1', verbs: [{ verb: 'a.b', kind: 'read', params: {} }, { verb: 'c.d', kind: 'write', params: {} }] };
for (const [d, v] of [[doc2, 'a.b'], [doc2, 'c.d'], [doc2, 'nope'], [{}, 'a.b'], [null, 'a.b'], [{ verbs: 'x' }, 'a'], [{ verbs: [{ verb: 'a' }] }, 'a']] as [any, string][]) await run('schemaVerb', (x: any, y: string) => S.schemaVerb(x, y) ?? null, [d, v]);
refWrite(o, 'action-schema-draft');
