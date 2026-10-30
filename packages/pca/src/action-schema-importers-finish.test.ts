/**
 * Importers (rule 14, MCP / OpenAPI -> draft schema): the parts a first version left as placeholders. OpenAPI path and query
 * parameters, local `$ref`s, `allOf` / `anyOf` / `oneOf` / nullable, `+json` bodies, exclusive bounds and duplicate verbs.
 * Every draft is checked by the schema's own shape check, and every unrepresentable input is flagged in `todo` (never dropped).
 */
import { describe, expect, it } from 'vitest';
import { actionSchemaShapeError, conformAction, draftSchemaFromMcpTools, draftSchemaFromOpenApi, type OpenApiLike, type McpToolLike, type ActionSchema } from './action-schema';

const SITE = { site: 'https://s.example', aud: 's.example', version: '1' };
const SIG = { alg: 'ed25519', kid: 'k', value: 'x' } as const;
const asDoc = (d: { schema: Omit<ActionSchema, 'sig'> }): ActionSchema => ({ ...d.schema, sig: SIG }) as ActionSchema;

describe('OpenAPI importer: path and query parameters', () => {
  const doc: OpenApiLike = {
    paths: {
      '/trips/{trip_id}': {
        parameters: [{ name: 'trip_id', in: 'path', schema: { type: 'string', maxLength: 40 } }, { name: 'verbose', in: 'query', schema: { type: 'boolean' } }],
        get: { operationId: 'getTrip', parameters: [{ name: 'verbose', in: 'query', required: true, schema: { type: 'boolean' } }, { name: 'X-Trace', in: 'header', schema: { type: 'string' } }, { name: 'limit', in: 'query', description: 'page size', schema: { type: 'integer', minimum: 1, maximum: 50 } }] },
      },
    },
  };
  const d = draftSchemaFromOpenApi(doc, SITE);
  it('imports path and query parameters; a path parameter is always required; the operation overrides the path item', () => {
    expect(d.schema.verbs).toEqual([
      {
        verb: 'getTrip',
        kind: 'read',
        reversibility: 'reversible',
        openapi: { operationId: 'getTrip' },
        params: {
          'action.params.limit': { type: 'integer', semantic: 'unknown', sensitivity: 'material', required: false, description: 'page size', min: 1, max: 50 },
          'action.params.trip_id': { type: 'string', semantic: 'unknown', sensitivity: 'material', max_len: 40 },
          'action.params.verbose': { type: 'boolean', semantic: 'unknown', sensitivity: 'material' },
        },
      },
    ]);
  });
  it('flags a header parameter and the semantic of every imported one; never silently drops', () => {
    expect(d.todo).toEqual([
      'getTrip: header parameter \'X-Trace\' is not an action parameter (the schema sees path, query and body parameters only)',
      'action.params.trip_id: semantic type',
      'action.params.limit: semantic type',
      'action.params.verbose: semantic type',
    ]);
  });
  it('the draft is closed-world: an undeclared query parameter is rejected, a declared one conforms', () => {
    const s = asDoc(d);
    expect(actionSchemaShapeError(d.schema, { signed: false })).toBeNull();
    expect(conformAction(s, 'getTrip', { trip_id: 't1', verbose: true, limit: 5 }).ok).toBe(true);
    expect(conformAction(s, 'getTrip', { trip_id: 't1', verbose: true, extra: 1 }).ok).toBe(false);
    expect(conformAction(s, 'getTrip', { verbose: true }).ok).toBe(false);
  });
  it('a body property and a query parameter with the same name: the body declaration is kept and the clash flagged', () => {
    const r = draftSchemaFromOpenApi({ paths: { '/a': { post: { operationId: 'a', parameters: [{ name: 'x', in: 'query', schema: { type: 'string' } }], requestBody: { content: { 'application/json': { schema: { properties: { x: { type: 'integer' } } } } } } } } } }, SITE);
    expect(r.schema.verbs[0]!.params['action.params.x']!.type).toBe('integer');
    expect(r.todo).toContain("a: 'x' is declared by both the query parameters and another source; kept the first");
  });
});

describe('OpenAPI importer: references, composition, media types', () => {
  const doc: OpenApiLike = {
    components: {
      schemas: {
        Seat: { type: 'string', enum: ['aisle', 'window'] },
        Pax: { type: 'integer', exclusiveMinimum: 0, exclusiveMaximum: 10 },
        Booking: { type: 'object', required: ['pax'], properties: { pax: { $ref: '#/components/schemas/Pax' }, seat: { oneOf: [{ $ref: '#/components/schemas/Seat' }, { type: 'null' }] } } },
        Meta: { type: 'object', properties: { note: { type: 'string' } } },
        Loop: { $ref: '#/components/schemas/Loop' },
      },
      requestBodies: { B: { content: { 'application/vnd.s+json; charset=utf-8': { schema: { allOf: [{ $ref: '#/components/schemas/Booking' }, { $ref: '#/components/schemas/Meta' }] } } } } },
    },
    paths: {
      '/b': { post: { operationId: 'book', requestBody: { $ref: '#/components/requestBodies/B' } } },
      '/c': { post: { operationId: 'cyc', requestBody: { content: { 'application/json': { schema: { properties: { l: { $ref: '#/components/schemas/Loop' }, r: { $ref: 'https://x.example/s.json' }, u: { anyOf: [{ type: 'string' }, { type: 'integer' }] } } } } } } } },
    },
  };
  const d = draftSchemaFromOpenApi(doc, SITE);
  const byVerb = (v: string) => d.schema.verbs.find((x) => x.verb === v)!;
  it('follows local references, merges allOf, collapses a nullable oneOf, accepts a +json media type and exclusive integer bounds', () => {
    expect(byVerb('book').params).toEqual({
      'action.params.note': { type: 'string', semantic: 'unknown', sensitivity: 'material', required: false },
      'action.params.pax': { type: 'integer', semantic: 'unknown', sensitivity: 'material', min: 1, max: 9 },
      'action.params.seat': { type: 'string', semantic: 'unknown', sensitivity: 'material', required: false, values: ['aisle', 'window'] },
    });
  });
  it('a cyclic, remote or union schema becomes a flagged string placeholder (fail closed), never a silent pass', () => {
    expect(Object.values(byVerb('cyc').params).map((p) => p.type)).toEqual(['string', 'string', 'string']);
    expect(d.todo.filter((t) => t.startsWith('action.params.l'))[0]).toBe('action.params.l: schema nesting or reference chain deeper than 8 (declared string; refine or drop)');
    expect(d.todo).toContain("action.params.r: reference 'https://x.example/s.json' is not a local reference that resolves (declared string; refine or drop)");
    expect(d.todo).toContain('action.params.u: a union of 2 schemas has no schema representation (declared string; refine or drop)');
  });
  it('an unresolvable requestBody reference is flagged and imports no parameters', () => {
    const r = draftSchemaFromOpenApi({ paths: { '/z': { post: { operationId: 'z', requestBody: { $ref: '#/components/requestBodies/Missing' } } } } }, SITE);
    expect(r.schema.verbs[0]!.params).toEqual({});
    expect(r.todo).toContain("reference '#/components/requestBodies/Missing' is not a local reference that resolves");
  });
  it('two operations with one verb name are flagged', () => {
    const r = draftSchemaFromOpenApi({ paths: { '/a': { get: { operationId: 'same' } }, '/b': { get: { operationId: 'same' } } } }, SITE);
    expect(r.todo).toEqual(['same: declared by more than one operation; give each a distinct x-pca-verb']);
  });
  it('all-string alternatives merge into one closed value set', () => {
    const r = draftSchemaFromOpenApi({ paths: { '/a': { get: { operationId: 'a', parameters: [{ name: 'k', in: 'query', schema: { anyOf: [{ const: 'x' }, { enum: ['y', 'x'] }] } }] } } } }, SITE);
    expect(r.schema.verbs[0]!.params['action.params.k']).toEqual({ type: 'string', semantic: 'unknown', sensitivity: 'material', required: false, values: ['x', 'y'] });
  });
});

describe('MCP importer: references and composition inside inputSchema', () => {
  const tool: McpToolLike = {
    name: 'find',
    inputSchema: {
      $ref: '#/$defs/In',
      ...({ $defs: { In: { type: 'object', required: ['q'], properties: { q: { type: ['string', 'null'] }, n: { $ref: '#/$defs/N' } } }, N: { type: 'integer', exclusiveMinimum: -1, maximum: 5 } } } as object),
    } as McpToolLike['inputSchema'],
  };
  const d = draftSchemaFromMcpTools([tool], SITE);
  it('resolves a referenced inputSchema and its properties', () => {
    expect(d.schema.verbs[0]!.params).toEqual({
      'action.params.n': { type: 'integer', semantic: 'unknown', sensitivity: 'material', required: false, min: 0, max: 5 },
      'action.params.q': { type: 'string', semantic: 'unknown', sensitivity: 'material' },
    });
  });
});

describe('reserved schema members', () => {
  it('harm / world / effects / returns are signed containers that no check reads: conformance is identical with and without them', () => {
    const base = { v: 1, kind: 'pca-action-schema', site: 's', aud: 'a', version: '1', verbs: [{ verb: 'v', kind: 'write', reversibility: 'irreversible', params: { 'action.params.n': { type: 'integer', semantic: 's', sensitivity: 'free', min: 0, max: 3 } } }] };
    const withRes = { ...base, state: [{ x: 1 }], verbs: [{ ...base.verbs[0], harm: { max: 0 }, world: [{ k: 'v' }], effects: { e: 1 }, returns: { r: 1 } }] };
    const view = (r: ReturnType<typeof conformAction>) => (r.ok ? { ok: true } : { ok: false, code: r.code, reason: r.reason });
    for (const params of [{ n: 2 }, { n: 4 }, {}, { n: 1, z: 1 }]) expect(view(conformAction(withRes as never, 'v', params))).toEqual(view(conformAction(base as never, 'v', params)));
    expect(actionSchemaShapeError(withRes, { signed: false })).toBeNull();
    expect(actionSchemaShapeError({ ...withRes, verbs: [{ ...withRes.verbs[0], harm: 'x' }] }, { signed: false })).toBe("verb 'v': harm must be an object");
  });
});
