// Importers: exact outcomes for each source kind, and the invariants every importer shares.
import { describe, expect, it } from 'vitest';
import {
  ActionKitError, CORE_REGISTRY, defDigest, defsToJsonl, effective, importActions, importAsyncApi, importGraphql, importGrpc, importJsonSchema, importMcp, importOpenApi,
  IMPORTERS, defsToYaml, loadActionsText, jsonlToDefs, parseDescriptorSet, parseGraphqlSdl, parseProto, traitsOf, hintTraits, validateDef, verbOf, tokensOf, fromIntrospection,
  type ActionDef, type ImportReport,
} from '../src';
import { descriptorSet } from './pb';

const O = { ns: 'acme' };

const stripe = {
  openapi: '3.0.3',
  components: {
    schemas: {
      Address: { type: 'object', required: ['line1'], properties: { line1: { type: 'string', maxLength: 100 }, zip: { type: 'string' } } },
      Reason: { type: 'string', enum: ['duplicate', 'fraudulent'] },
    },
  },
  security: [{ oauth: ['read', 'write'] }],
  paths: {
    '/v1/customers/{id}': {
      parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
      get: { operationId: 'getCustomer', summary: 'Get a customer' },
      delete: { operationId: 'deleteCustomer', deprecated: true },
    },
    '/v1/refunds': {
      post: {
        operationId: 'createRefund',
        summary: 'Refund a charge',
        parameters: [{ name: 'Idempotency-Key', in: 'header', schema: { type: 'string' } }, { name: 'X-Trace', in: 'header', schema: { type: 'string' } }],
        requestBody: {
          content: {
            'application/json': {
              schema: {
                type: 'object', required: ['amount', 'currency'],
                properties: {
                  amount: { type: 'integer', minimum: 1, maximum: 1000000 }, currency: { type: 'string' }, reason: { $ref: '#/components/schemas/Reason' },
                  address: { $ref: '#/components/schemas/Address' }, 'meta-data': { type: 'string' }, created: { type: 'string', format: 'date-time', readOnly: true },
                },
              },
            },
          },
        },
      },
    },
  },
};

const only = (r: ImportReport, verb: string): ActionDef => {
  const d = r.defs.find((x) => x.verb === verb);
  if (!d) throw new Error(`no def ${verb}; have ${r.defs.map((x) => x.verb).join(', ')}`);
  return d;
};

describe('invariants every importer shares', () => {
  const results: [string, ImportReport][] = [
    ['openapi', importOpenApi(stripe, O)],
    ['mcp', importMcp([{ name: 'read_file', inputSchema: { type: 'object', properties: { path: { type: 'string' } } }, annotations: { readOnlyHint: true } }, { name: 'rm', annotations: { destructiveHint: true } }], O)],
    ['graphql', importGraphql('type Query { a(x: Int): String } type Mutation { b(y: String!): String }', O)],
    ['grpc', importGrpc('syntax="proto3"; package p; message R { string n = 1; } service S { rpc Do(R) returns (R); }', O)],
    ['asyncapi', importAsyncApi({ asyncapi: '2.6.0', channels: { 'a/b': { publish: { message: { payload: { type: 'object', properties: { m: { type: 'string' } } } } } } } }, O)],
    ['jsonschema', importJsonSchema({ type: 'object', properties: { q: { type: 'string' } } }, { ns: 'acme', verb: 'acme.search.run' })],
  ];
  for (const [kind, r] of results) {
    it(`${kind}: every def is well formed and unreviewed, with its source recorded`, () => {
      expect(r.defs.length).toBeGreaterThan(0);
      for (const d of r.defs) {
        expect(validateDef(d), d.verb).toBeNull();
        expect(d.review).toEqual({ state: 'unreviewed' });
        expect(d.source?.kind).toBe(kind);
        expect(d.source?.spec_digest).toBe(r.source.spec_digest);
        expect(traitsOf(d, CORE_REGISTRY)).toContain('pca.unreviewed');
      }
    });
    it(`${kind}: an unreviewed def is held at the most restrictive floor`, () => {
      for (const d of r.defs) {
        const e = effective(d, CORE_REGISTRY);
        expect(e.eff.rev).toBe('irreversible');
        expect(e.eff.blast_ppm).toBe(1_000_000);
        expect(e.eff.esc).toBeGreaterThanOrEqual(2);
        expect(e.eff.caveats).toContain('approval_ref');
      }
    });
  }
  it('imports are deterministic and the spec digest follows the source', () => {
    expect(JSON.stringify(importOpenApi(stripe, O))).toBe(JSON.stringify(importOpenApi(JSON.parse(JSON.stringify(stripe)), O)));
    const other = JSON.parse(JSON.stringify(stripe));
    other.paths['/v1/refunds'].post.summary = 'Something else';
    expect(importOpenApi(other, O).source.spec_digest).not.toBe(importOpenApi(stripe, O).source.spec_digest);
    expect(importOpenApi(stripe, { ...O, now: 77, uri: 'https://example.test/spec.json', licence: 'MIT' }).defs[0]!.source).toMatchObject({ imported_at: 77, uri: 'https://example.test/spec.json', licence: 'MIT' });
  });
  it('jsonl round trips and rejects an invalid line by number', () => {
    const r = importOpenApi(stripe, O);
    const text = defsToJsonl(r.defs);
    expect(jsonlToDefs(text).map(defDigest)).toEqual(r.defs.slice().sort((a, b) => (a.verb < b.verb ? -1 : 1)).map(defDigest));
    expect(() => jsonlToDefs(text + '{"v":1}\n')).toThrow(/line \d+/);
  });
  it('importActions dispatches by kind and refuses an unknown one', () => {
    expect(importActions('openapi', stripe, O).defs.length).toBe(3);
    expect(() => importActions('wsdl' as never, {}, O)).toThrow(/unknown import kind/);
  });
  it('refuses a bad namespace', () => {
    expect(() => importOpenApi(stripe, { ns: 'Acme' })).toThrow(ActionKitError);
    expect(() => importOpenApi(stripe, { ns: 'a.b' })).toThrow(/ns must match/);
  });
});

describe('verb naming', () => {
  it('turns operation names into <ns>.<noun>.<action>', () => {
    expect(verbOf('a', 'createCustomer')).toBe('a.customer.create');
    expect(verbOf('a', 'customer_create')).toBe('a.customer.create');
    expect(verbOf('a', 'Users_List')).toBe('a.users.list');
    expect(verbOf('a', 'repos/create-fork')).toBe('a.repos.create_fork');
    expect(verbOf('a', 'customers.cards.delete')).toBe('a.customers.cards.delete');
    expect(verbOf('a', 'weather')).toBe('a.weather');
    expect(verbOf('a', '!!!')).toBe('a.op');
    expect(tokensOf('XMLHttpRequestV2')).toEqual(['xml', 'http', 'request', 'v2']);
  });
  it('keeps every segment within 32 characters and 6 segments, deterministically', () => {
    const v = verbOf('a', 'x'.repeat(100) + '.' + 'y'.repeat(100));
    expect(v.split('.').every((s) => s.length <= 32)).toBe(true);
    expect(verbOf('a', 'x'.repeat(100) + '.' + 'y'.repeat(100))).toBe(v);
    expect(verbOf('a', 'a.b.c.d.e.f.g.h.i').split('.').length).toBeLessThanOrEqual(6);
  });
});

describe('OpenAPI', () => {
  const r = importOpenApi(stripe, O);
  it('maps the method to effects and the path to scope', () => {
    expect(only(r, 'acme.customer.get')).toMatchObject({ effects: ['read'], idempotency: { mode: 'natural' }, resource: { scope: 'one', type: 'acme.customer' } });
    expect(only(r, 'acme.customer.delete').effects).toEqual(['delete']);
    expect(only(r, 'acme.refund.create')).toMatchObject({ effects: ['create'], resource: { scope: 'one' } });
  });
  it('flattens the body with refs, enums, nested objects and the required set', () => {
    const d = only(r, 'acme.refund.create');
    expect(d.params['amount']).toEqual({ type: 'integer', min: 1, max: 1000000 });
    expect(d.params['currency']).toEqual({ type: 'string' });
    expect(d.params['reason']).toEqual({ type: 'string', required: false, values: ['duplicate', 'fraudulent'] });
    expect(d.params['address.line1']).toEqual({ type: 'string', required: false, max_len: 100 });
    expect(d.params['address.zip']).toEqual({ type: 'string', required: false });
    // a response-only property is not an input; an unsafe name is renamed and noted
    expect(Object.keys(d.params).includes('created')).toBe(false);
    expect(d.params['meta_data']).toEqual({ type: 'string', required: false });
    expect(r.todo.some((t) => t.code === 'renamed_param' && /meta-data/.test(t.message))).toBe(true);
  });
  it('turns Idempotency-Key into a key param and notes other headers, scopes and deprecation', () => {
    const d = only(r, 'acme.refund.create');
    expect(d.idempotency).toEqual({ mode: 'key_param', param: 'idempotency_key' });
    expect(d.params['idempotency_key']).toEqual({ type: 'string', required: false, max_len: 255 });
    expect(r.todo.some((t) => t.code === 'param_location' && /X-Trace/.test(t.message))).toBe(true);
    expect(r.todo.some((t) => t.code === 'required_scope' && /read, write/.test(t.message))).toBe(true);
    expect(r.todo.some((t) => t.code === 'deprecated')).toBe(true);
  });
  it('binds the operation and keeps the summary as the title', () => {
    expect(only(r, 'acme.refund.create').bindings).toEqual({ openapi: { operationId: 'createRefund', method: 'POST', path: '/v1/refunds' } });
    expect(only(r, 'acme.refund.create').title).toBe('Refund a charge');
    expect(only(r, 'acme.refund.create').aliases).toEqual(['create_refund']);
  });
  it('path item parameters apply to every operation and the operation wins a clash', () => {
    const d = importOpenApi({ openapi: '3.0.0', paths: { '/a/{id}': { parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }, { name: 'q', in: 'query', schema: { type: 'string' } }], get: { operationId: 'a1', parameters: [{ name: 'q', in: 'query', schema: { type: 'integer' } }] } } } }, O).defs[0]!;
    expect(d.params['id']).toEqual({ type: 'string' });
    expect(d.params['q']).toEqual({ type: 'integer', required: false });
  });
  it('names an operation without an operationId from its method and path', () => {
    const d = importOpenApi({ openapi: '3.1.0', paths: { '/v1/customers/{id}/cards': { get: {} }, '/v1/customers': { get: {}, post: {} } } }, O);
    expect(d.defs.map((x) => x.verb).sort()).toEqual(['acme.customers.cards.list', 'acme.customers.list', 'acme.customers.post']);
    expect(d.defs.every((x) => x.aliases === undefined)).toBe(true);
    expect(d.defs[0]!.bindings?.openapi?.operationId).toMatch(/^(get|post)_/);
  });
  it('ignores x- extensions unless allow-listed', () => {
    const doc = { openapi: '3.0.0', paths: { '/a': { post: { operationId: 'op1', 'x-pca-verb': 'acme.thing.do', 'x-other': 1, requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { amount: { type: 'integer', 'x-pca-role': 'money.amount' } } } } } } } } } };
    const on = importOpenApi(doc, O);
    expect(on.defs[0]!.verb).toBe('acme.thing.do');
    expect(on.defs[0]!.params['amount']!.role).toBe('money.amount');
    expect(on.todo.some((t) => t.code === 'extension_ignored' && /x-other/.test(t.message))).toBe(true);
    const off = importOpenApi(doc, { ...O, allowExtensions: [] });
    expect(off.defs[0]!.verb).toBe('acme.op1');
    expect(off.defs[0]!.params['amount']!.role).toBeUndefined();
    // a role the type cannot carry is refused, noted
    const bad = importOpenApi({ ...doc, paths: { '/a': { post: { operationId: 'op1', requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { s: { type: 'string', 'x-pca-role': 'money.amount' } } } } } } } } } }, O);
    expect(bad.defs[0]!.params['s']!.role).toBeUndefined();
    expect(bad.todo.some((t) => t.code === 'role_ignored')).toBe(true);
  });
  it('gives colliding verbs distinct names and says so', () => {
    const d = importOpenApi({ openapi: '3.0.0', paths: { '/a': { get: { operationId: 'getThing' } }, '/b': { get: { operationId: 'get_thing' } } } }, O);
    expect(d.defs.map((x) => x.verb)).toEqual(['acme.thing.get', 'acme.thing.get_2']);
    expect(d.todo.some((t) => t.code === 'duplicate_verb')).toBe(true);
  });
  it('declares what it cannot represent as a string placeholder and notes it', () => {
    const d = importOpenApi({ openapi: '3.0.0', paths: { '/a': { post: { operationId: 'op', requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { f: { type: 'number' }, u: { oneOf: [{ type: 'string' }, { type: 'integer' }] }, o: { type: 'object' }, r: { $ref: 'https://x.test/s.json' } } } } } } } } } }, O);
    for (const p of ['f', 'u', 'o', 'r']) expect(d.defs[0]!.params[p]).toMatchObject({ type: 'string', required: false });
    expect(new Set(d.todo.map((t) => t.code))).toEqual(new Set(['unsupported_type', 'union', 'object_leaf', 'unresolved_ref']));
  });
  it('reads form bodies and Swagger 2 documents', () => {
    const f = importOpenApi({ openapi: '3.0.0', paths: { '/a': { post: { operationId: 'op', requestBody: { content: { 'application/x-www-form-urlencoded': { schema: { type: 'object', properties: { n: { type: 'integer' } } } } } } } } } }, O);
    expect(f.defs[0]!.params['n']).toEqual({ type: 'integer', required: false });
    const sw = importOpenApi({
      swagger: '2.0', definitions: { Pet: { type: 'object', required: ['name'], properties: { name: { type: 'string' }, tag: { type: 'string', enum: ['a', 'b'] } } } },
      paths: { '/pets/{id}': { put: { operationId: 'putPet', parameters: [{ name: 'id', in: 'path', required: true, type: 'string' }, { name: 'body', in: 'body', schema: { $ref: '#/definitions/Pet' } }, { name: 'dry', in: 'query', type: 'boolean' }] } } },
    }, O);
    expect(sw.defs[0]!.effects).toEqual(['update']);
    expect(sw.defs[0]!.params).toEqual({ id: { type: 'string' }, name: { type: 'string' }, tag: { type: 'string', required: false, values: ['a', 'b'] }, dry: { type: 'boolean', required: false } });
  });
  it('refuses something that is not an OpenAPI document', () => {
    expect(() => importOpenApi({ paths: {} }, O)).toThrow(/not an OpenAPI/);
    expect(() => importOpenApi('openapi: 3.0.0', O)).toThrow(/must be an object/);
  });
});

describe('MCP', () => {
  const tools = [
    { name: 'read_file', description: 'Read a file', inputSchema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] }, annotations: { readOnlyHint: true } },
    { name: 'delete_file', annotations: { destructiveHint: true, idempotentHint: true } },
    { name: 'fetch', annotations: { openWorldHint: true, title: 'Fetch it' } },
    { name: 'liar', annotations: { readOnlyHint: true, destructiveHint: true } },
    { name: 'plain' },
  ];
  const r = importMcp({ tools }, { ns: 'fs' });
  it('treats hints as untrusted lower bounds', () => {
    expect(only(r, 'fs.file.read')).toMatchObject({ effects: ['read'], bindings: { mcp: { tool: 'read_file' } }, aliases: ['read_file'], params: { path: { type: 'string' } } });
    expect(only(r, 'fs.file.delete')).toMatchObject({ effects: ['delete', 'update'], idempotency: { mode: 'natural' } });
    expect(only(r, 'fs.fetch').traits).toEqual(['pca.network_egress']);
    expect(only(r, 'fs.fetch').title).toBe('Fetch it');
    // read-only AND destructive: the safe claim is not honoured
    expect(only(r, 'fs.liar').effects).toEqual(['delete', 'update']);
    expect(only(r, 'fs.plain').effects).toEqual(['update']);
  });
  it('accepts a bare array and rejects other shapes; a nameless tool and a duplicate are noted', () => {
    expect(importMcp(tools, { ns: 'fs' }).defs.length).toBe(5);
    expect(() => importMcp({ nope: 1 }, { ns: 'fs' })).toThrow(/tool array/);
    const d = importMcp([{ name: 'a' }, { name: 'a' }, { description: 'x' }], { ns: 'fs' });
    expect(d.defs.length).toBe(1);
    expect(d.todo.map((t) => t.code).sort()).toEqual(['duplicate_tool', 'skipped_op']);
  });
  it('resolves refs inside the tool schema and flattens nested objects to dotted names', () => {
    const d = importMcp([{ name: 'send', inputSchema: { type: 'object', properties: { to: { $ref: '#/$defs/Person' } }, required: ['to'], $defs: { Person: { type: 'object', required: ['email'], properties: { email: { type: 'string', format: 'email' }, name: { type: 'string' } } } } } }], { ns: 'm' }).defs[0]!;
    expect(d.params).toEqual({ 'to.email': { type: 'string', format: 'email' }, 'to.name': { type: 'string', required: false } });
  });
});

describe('GraphQL', () => {
  const sdl = `
    "the schema"
    schema { query: Q mutation: M }
    scalar DateTime
    enum Kind { A B }
    input Addr { zip: String! city: String }
    input NewUser { email: String! age: Int kind: Kind addr: Addr tags: [String!] }
    type User { id: ID! }
    type Q { """Get a user""" user(id: ID!): User  old(x: Int): User @deprecated(reason: "no") }
    type M { createUser(input: NewUser!, at: DateTime): User deleteUser(id: ID!): Boolean }
    type Subscription { userChanged(id: ID!): User }
  `;
  const r = importGraphql(sdl, { ns: 'g' });
  it('maps query fields to reads and mutation fields to writes', () => {
    expect(only(r, 'g.user').effects).toEqual(['read']);
    expect(only(r, 'g.user.create').effects).toEqual(['update']);
    expect(only(r, 'g.user.delete')).toMatchObject({ effects: ['update'], bindings: { graphql: { op: 'mutation', field: 'deleteUser' } } });
    expect(only(r, 'g.user').title).toBe('Get a user');
    expect(r.todo.some((t) => t.code === 'deprecated' && /old/.test(t.where))).toBe(true);
  });
  it('flattens input objects to dotted params with required propagation, enums and lists', () => {
    const d = only(r, 'g.user.create');
    expect(d.params['input.email']).toEqual({ type: 'string' });
    expect(d.params['input.age']).toEqual({ type: 'integer', required: false });
    expect(d.params['input.kind']).toEqual({ type: 'string', required: false, values: ['A', 'B'] });
    expect(d.params['input.addr.zip']).toEqual({ type: 'string', required: false });
    expect(d.params['input.tags']).toEqual({ type: 'array', required: false, items: 'string' });
    expect(d.params['at']).toEqual({ type: 'datetime', required: false });
  });
  it('treats a subscription as a streaming read', () => {
    expect(only(r, 'g.user_changed')).toMatchObject({ effects: ['read'], traits: ['pca.bulk'], bindings: { graphql: { op: 'subscription' } } });
  });
  it('an introspection result gives the same defs as the SDL', () => {
    const intro = {
      data: { __schema: {
        queryType: { name: 'Query' }, mutationType: { name: 'Mutation' }, subscriptionType: null,
        types: [
          { kind: 'OBJECT', name: 'Query', fields: [{ name: 'user', description: 'Get a user', args: [{ name: 'id', type: { kind: 'NON_NULL', ofType: { kind: 'SCALAR', name: 'ID' } } }], type: { kind: 'OBJECT', name: 'User' }, isDeprecated: false }] },
          { kind: 'OBJECT', name: 'Mutation', fields: [{ name: 'createUser', args: [{ name: 'input', type: { kind: 'NON_NULL', ofType: { kind: 'INPUT_OBJECT', name: 'NewUser' } } }], type: { kind: 'OBJECT', name: 'User' }, isDeprecated: false }] },
          { kind: 'INPUT_OBJECT', name: 'NewUser', inputFields: [{ name: 'email', type: { kind: 'NON_NULL', ofType: { kind: 'SCALAR', name: 'String' } } }, { name: 'age', type: { kind: 'SCALAR', name: 'Int' } }] },
          { kind: 'OBJECT', name: 'User', fields: [] }, { kind: 'OBJECT', name: '__Type', fields: [] },
        ],
      } },
    };
    const sdl2 = 'type Query { """Get a user""" user(id: ID!): User } type Mutation { createUser(input: NewUser!): User } input NewUser { email: String! age: Int } type User { id: ID }';
    const a = importGraphql(intro, { ns: 'g' }), b = importGraphql(sdl2, { ns: 'g' });
    expect(a.defs.map((d) => [d.verb, d.params, d.effects])).toEqual(b.defs.map((d) => [d.verb, d.params, d.effects]));
    expect(fromIntrospection(intro).types.has('__Type')).toBe(false);
  });
  it('parses extensions, interfaces, unions, directives and comments', () => {
    const s = parseGraphqlSdl('# c\nextend type Query { a: Int }\ntype Query { b: Int }\ninterface I { x: Int }\ntype T implements I & J @d(a: [1, {b: "c"}]) { x: Int }\nunion U = A | B\ndirective @d(a: Int) repeatable on FIELD | OBJECT');
    expect(s.types.get('Query')!.fields.map((f) => f.name)).toEqual(['a', 'b']);
    expect(s.types.get('U')!.kind).toBe('union');
  });
  it('rejects an executable document and a syntax error', () => {
    expect(() => importGraphql('query Q { a }', { ns: 'g' })).toThrow(/unsupported definition/);
    expect(() => importGraphql('type Q { a(x: Int }', { ns: 'g' })).toThrow(ActionKitError);
    expect(() => importGraphql('type Q { a: "unterminated }', { ns: 'g' })).toThrow(/unterminated/);
  });
});

describe('gRPC', () => {
  const proto = `
    syntax = "proto3";
    package pay.v1;
    import "google/api/annotations.proto";
    enum Reason { REASON_UNSPECIFIED = 0; FRAUD = 1; DUP = 2; }
    message Money { int64 units = 1; string currency = 2 [(google.api.field_behavior) = REQUIRED]; }
    message RefundRequest {
      string payment_id = 1 [(google.api.field_behavior) = REQUIRED];
      Money money = 2;
      Reason reason = 3;
      repeated string notes = 4;
      string audit = 5 [(google.api.field_behavior) = OUTPUT_ONLY];
      map<string, string> labels = 6;
      oneof target { string account = 7; string card = 8; }
      google.protobuf.Timestamp when = 9;
    }
    message Empty {}
    service Payments {
      rpc Refund(RefundRequest) returns (Empty) { option (google.api.http) = { post: "/v1/refunds" body: "*" }; }
      rpc GetBalance(Empty) returns (Empty) { option idempotency_level = NO_SIDE_EFFECTS; }
      rpc Watch(stream Empty) returns (stream Empty);
      rpc Drop(Empty) returns (Empty) { option (google.api.http) = { delete: "/v1/x/{id}" }; }
    }`;
  const r = importGrpc(proto, { ns: 'pay' });
  it('maps rpc names, http annotations and idempotency levels', () => {
    expect(only(r, 'pay.payments.refund')).toMatchObject({ effects: ['create'], bindings: { grpc: { service: 'pay.v1.Payments', method: 'Refund' }, http: { method: 'POST', path: '/v1/refunds' } } });
    expect(only(r, 'pay.payments.get_balance')).toMatchObject({ effects: ['read'], idempotency: { mode: 'natural' } });
    expect(only(r, 'pay.payments.drop').effects).toEqual(['delete']);
  });
  it('flattens the request message with field behavior, enums, repeated and well-known types', () => {
    const p = only(r, 'pay.payments.refund').params;
    expect(p['payment_id']).toEqual({ type: 'string' });
    expect(p['money.units']).toEqual({ type: 'integer', required: false });
    expect(p['money.currency']).toEqual({ type: 'string', required: false });
    expect(p['reason']).toEqual({ type: 'string', required: false, values: ['REASON_UNSPECIFIED', 'FRAUD', 'DUP'] });
    expect(p['notes']).toEqual({ type: 'array', required: false, items: 'string' });
    expect(p['when']).toEqual({ type: 'datetime', required: false });
    expect(p['account']).toEqual({ type: 'string', required: false });
    expect('audit' in p).toBe(false);
    expect(p['labels']).toMatchObject({ type: 'string' });
  });
  it('gives streaming methods pca.bulk', () => {
    expect(only(r, 'pay.payments.watch').traits).toEqual(['pca.bulk']);
    expect(r.todo.some((t) => t.code === 'streaming')).toBe(true);
  });
  it('a binary descriptor set gives the same defs as the proto text', () => {
    const bin = descriptorSet({
      pkg: 'pay.v1',
      messages: [
        { name: 'Money', fields: [{ name: 'units', num: 1, type: 3 }, { name: 'currency', num: 2, type: 9, behavior: [2] }] },
        { name: 'RefundRequest', fields: [{ name: 'payment_id', num: 1, type: 9, behavior: [2] }, { name: 'money', num: 2, type: 11, typeName: '.pay.v1.Money' }, { name: 'notes', num: 4, type: 9, label: 3 }] },
        { name: 'Empty', fields: [] },
      ],
      services: [{ name: 'Payments', methods: [
        { name: 'Refund', input: '.pay.v1.RefundRequest', output: '.pay.v1.Empty', http: { method: 'post', path: '/v1/refunds' } },
        { name: 'GetBalance', input: '.pay.v1.Empty', output: '.pay.v1.Empty', idem: 1 },
        { name: 'Watch', input: '.pay.v1.Empty', output: '.pay.v1.Empty', cs: true, ss: true },
      ] }],
    });
    const b = importGrpc(bin, { ns: 'pay' });
    const text = importGrpc(`syntax="proto3"; package pay.v1;
      message Money { int64 units = 1; string currency = 2 [(google.api.field_behavior) = REQUIRED]; }
      message RefundRequest { string payment_id = 1 [(google.api.field_behavior) = REQUIRED]; Money money = 2; repeated string notes = 4; }
      message Empty {}
      service Payments { rpc Refund(RefundRequest) returns (Empty) { option (google.api.http) = { post: "/v1/refunds" }; } rpc GetBalance(Empty) returns (Empty) { option idempotency_level = NO_SIDE_EFFECTS; } rpc Watch(stream Empty) returns (stream Empty); }`, { ns: 'pay' });
    expect(b.defs.map((d) => [d.verb, d.effects, d.params, d.traits, d.bindings])).toEqual(text.defs.map((d) => [d.verb, d.effects, d.params, d.traits, d.bindings]));
    expect(parseDescriptorSet(bin).services[0]!.methods.length).toBe(3);
    expect(parseProto('syntax="proto3"; message A { message B { int32 x = 1; } B b = 1; }').messages.has('A.B')).toBe(true);
  });
  it('rejects garbage', () => {
    expect(() => importGrpc('service S { rpc X(', { ns: 'p' })).toThrow(ActionKitError);
    expect(() => importGrpc(new Uint8Array([0x0a, 0xff, 0xff, 0xff, 0xff, 0x0f, 1]), { ns: 'p' })).toThrow(ActionKitError);
    expect(() => importGrpc(42, { ns: 'p' })).toThrow(/proto text/);
  });
});

describe('AsyncAPI', () => {
  it('2.x: publish is a send, subscribe is a read; the payload and channel parameters become params', () => {
    const r = importAsyncApi({
      asyncapi: '2.6.0',
      components: { messages: { Signup: { payload: { type: 'object', required: ['email'], properties: { email: { type: 'string' }, plan: { type: 'string', enum: ['free', 'pro'] } } } } } },
      channels: {
        'user/{userId}/signedup': { parameters: { userId: { schema: { type: 'string' } } }, publish: { operationId: 'announceSignup', summary: 'Announce a signup', message: { $ref: '#/components/messages/Signup' } }, subscribe: { operationId: 'onSignup', message: { payload: { type: 'object', properties: { id: { type: 'string' } } } } } },
        'internal/jobs': { 'x-pca-internal': true, publish: { operationId: 'enqueue', message: { payload: { type: 'object', properties: { j: { type: 'string' } } } } } },
      },
    }, { ns: 'ev' });
    expect(only(r, 'ev.announce_signup')).toMatchObject({ effects: ['send'], params: { userId: { type: 'string' }, email: { type: 'string' }, plan: { type: 'string', values: ['free', 'pro'], required: false } }, bindings: { asyncapi: { channel: 'user/{userId}/signedup', op: 'send' } } });
    expect(only(r, 'ev.on_signup')).toMatchObject({ effects: ['read'], bindings: { asyncapi: { op: 'receive' } } });
    expect(only(r, 'ev.enqueue').effects).toEqual(['create']);
    expect(hintTraits(only(r, 'ev.announce_signup'))).toContain('pca.external_communication');
    expect(hintTraits(only(r, 'ev.enqueue'))).not.toContain('pca.external_communication');
  });
  it('3.x: operations with an action and a channel reference', () => {
    const r = importAsyncApi({
      asyncapi: '3.0.0',
      channels: { orders: { address: 'orders.placed', messages: { placed: { payload: { type: 'object', properties: { id: { type: 'string' } } } } } } },
      operations: { sendOrder: { action: 'send', channel: { $ref: '#/channels/orders' } }, getOrder: { action: 'receive', channel: { $ref: '#/channels/orders' }, messages: [{ $ref: '#/channels/orders/messages/placed' }] }, bad: { action: 'x' } },
    }, { ns: 'ev' });
    expect(r.defs.map((d) => [d.verb, d.effects[0]])).toEqual([['ev.order.get', 'read'], ['ev.order.send', 'send']]);
    expect(r.defs[0]!.bindings?.asyncapi).toEqual({ channel: 'orders.placed', op: 'receive' });
    expect(r.todo.some((t) => t.code === 'skipped_op')).toBe(true);
  });
  it('refuses a non-AsyncAPI document', () => {
    expect(() => importAsyncApi({ openapi: '3.0.0' }, { ns: 'e' })).toThrow(/not an AsyncAPI/);
  });
});

describe('JSON Schema', () => {
  it('gives one def with the caller verb and the schema as params', () => {
    const r = importJsonSchema({ title: 'Search', description: 'Find things', type: 'object', required: ['q'], properties: { q: { type: 'string', maxLength: 50 }, n: { type: 'integer', minimum: 1, exclusiveMaximum: 11 } } }, { ns: 'fn', verb: 'fn.search.run', effects: ['read'] });
    expect(r.defs).toHaveLength(1);
    expect(r.defs[0]).toMatchObject({ verb: 'fn.search.run', title: 'Search', description: 'Find things', effects: ['read'], params: { q: { type: 'string', max_len: 50 }, n: { type: 'integer', required: false, min: 1, max: 10 } } });
  });
  it('refuses a verb outside the namespace and bad effects; notes a non-object schema', () => {
    expect(() => importJsonSchema({}, { ns: 'fn', verb: 'other.x.y' })).toThrow(/verb/);
    expect(() => importJsonSchema({}, { ns: 'fn', verb: 'fn.x.y', effects: ['fly' as never] })).toThrow(/effects/);
    expect(importJsonSchema({ type: 'string' }, { ns: 'fn', verb: 'fn.x.y' }).todo.some((t) => t.code === 'not_object')).toBe(true);
  });
});

describe('the CLI importer registry', () => {
  const doc = { tools: [{ name: 'send_mail', inputSchema: { type: 'object', properties: { to: { type: 'string' } } } }] };
  it('covers every source kind, returns string todos, and its defs are unreviewed', () => {
    expect(Object.keys(IMPORTERS).sort()).toEqual(['asyncapi', 'graphql', 'grpc', 'jsonschema', 'mcp', 'openapi']);
    const r = IMPORTERS['mcp']!(doc, { ns: 'x' });
    expect(r.defs[0]!.review).toEqual({ state: 'unreviewed' });
    expect(typeof r.todo.length).toBe('number');
    expect(IMPORTERS['graphql']!('type Query { a: Int }', { ns: 'x' }).defs).toHaveLength(1);
    expect(IMPORTERS['grpc']!('syntax="proto3"; message M {} service S { rpc R(M) returns (M); }', { ns: 'x' }).defs).toHaveLength(1);
    expect(() => IMPORTERS['jsonschema']!({}, { ns: 'x' })).toThrow(/--verb/);
    expect(IMPORTERS['jsonschema']!({ type: 'object' }, { ns: 'x', verb: 'x.a.b' }).defs[0]!.verb).toBe('x.a.b');
  });
  it('defsToYaml round-trips through the authoring loader to the same digests', () => {
    const r = IMPORTERS['openapi']!(stripe, { ns: 'acme' });
    const l = loadActionsText(defsToYaml('acme', r.defs));
    expect(l.errors).toEqual([]);
    expect(l.defs.map(defDigest)).toEqual(r.defs.map(defDigest));
    expect(l.defs.every((d) => d.review.state === 'unreviewed')).toBe(true);
  });
});
