/**
 * The draft importers (MCP tools and OpenAPI operations): local reference resolution, schema flattening (allOf, anyOf / oneOf,
 * const, depth and node bounds), JSON request-body selection and parameter references. Every unrepresentable input is flagged
 * in `todo` with the exact location and never dropped.
 */
import { describe, expect, it } from 'vitest';
import { draftSchemaFromMcpTools, draftSchemaFromOpenApi, type McpToolLike, type OpenApiLike } from './action-schema';

const SITE = { site: 'https://s.example', aud: 's.example', version: '1' };
const BASE = { semantic: 'unknown', sensitivity: 'material', required: false };
const mcp = (inputSchema: unknown, name = 't1'): McpToolLike => ({ name, inputSchema: inputSchema as McpToolLike['inputSchema'] });
const REF_MSG = (ref: string) => `reference '${ref}' is not a local reference that resolves (declared string; refine or drop)`;
const NOREP = "action.params.x: type 'undefined' has no schema representation (declared string; refine or drop)";

/** One property `x` under a tool whose root (the reference target) is the whole input schema. */
function one(x: unknown, definitions: Record<string, unknown> = {}, required = false) {
  const d = draftSchemaFromMcpTools([mcp({ type: 'object', properties: { x }, ...(required ? { required: ['x'] } : {}), definitions })], SITE);
  return { decl: d.schema.verbs[0]!.params['action.params.x']!, todo: d.todo };
}

describe('local references', () => {
  it('follows #/a/b pointers, decoding ~1 as / and ~0 as ~', () => {
    const d = draftSchemaFromMcpTools(
      [mcp({
        type: 'object',
        properties: { a: { $ref: '#/definitions/A' }, b: { $ref: '#/definitions/a~1b' }, c: { $ref: '#/definitions/a~0b' }, d: { $ref: '#/definitions/Deep/inner/leaf' }, e: { $ref: '#/definitions/List/0' } },
        definitions: { A: { type: 'integer' }, 'a/b': { type: 'boolean' }, 'a~b': { type: 'integer', minimum: 3 }, Deep: { inner: { leaf: { type: 'integer', maximum: 9 } } }, List: [{ type: 'boolean' }] },
      })],
      SITE,
    );
    const p = d.schema.verbs[0]!.params;
    expect(p['action.params.a']).toEqual({ type: 'integer', ...BASE });
    expect(p['action.params.b']).toEqual({ type: 'boolean', ...BASE });
    expect(p['action.params.c']).toEqual({ type: 'integer', min: 3, ...BASE });
    expect(p['action.params.d']).toEqual({ type: 'integer', max: 9, ...BASE });
    expect(p['action.params.e']).toEqual({ type: 'boolean', ...BASE });
    expect(d.todo.filter((m) => m.includes('reference'))).toEqual([]);
  });
  it('a reference that does not resolve is flagged with its location and declared string', () => {
    for (const ref of ['#/definitions/Missing', 'definitions/A', '#', 'http://x/y', '#definitions/A', '#/definitions/A/nope', '#/definitions/Str', '#/definitions/Str/length', '#/definitions/Nil', '#/definitions/Nil/x', '#/definitions/Num', '#/definitions/toString', '#/definitions/Arr/5', 'xxdefinitions/A', '#xdefinitions/A', '/definitions/A']) {
      const { decl, todo } = one({ $ref: ref }, { A: { type: 'integer' }, Str: 'text', Nil: null, Num: 5, Arr: [] });
      expect(decl, ref).toEqual({ type: 'string', ...BASE });
      expect(todo, ref).toContain(`action.params.x: ${REF_MSG(ref)}`);
    }
  });
  it('a reference longer than 120 characters is cut at 120 in the flag', () => {
    const ref = `#/definitions/${'x'.repeat(200)}`;
    const { todo } = one({ $ref: ref });
    expect(todo).toContain(`action.params.x: ${REF_MSG(ref.slice(0, 120))}`);
  });
  it('sibling members of a $ref win over the target', () => {
    const { decl } = one({ $ref: '#/definitions/A', maximum: 4 }, { A: { type: 'integer', minimum: 1, maximum: 9 } });
    expect(decl).toEqual({ type: 'integer', min: 1, max: 4, ...BASE });
  });
  it('the input schema itself may be a reference that does not resolve', () => {
    const d = draftSchemaFromMcpTools([mcp({ $ref: '#/nope' })], SITE);
    expect(d.todo).toContain(`t1: inputSchema: ${REF_MSG('#/nope')}`);
    expect(d.schema.verbs[0]!.params).toEqual({});
  });
  it('an array item reference that does not resolve is located at the item', () => {
    const { todo } = one({ type: 'array', items: { $ref: '#/nope' } });
    expect(todo).toContain(`action.params.x[]: ${REF_MSG('#/nope')}`);
  });
});

describe('reference and nesting bounds', () => {
  const chain = (n: number) => {
    const defs: Record<string, unknown> = {};
    for (let i = 0; i < n; i++) defs[`D${i}`] = i === n - 1 ? { type: 'integer' } : { $ref: `#/definitions/D${i + 1}` };
    return defs;
  };
  const DEEP = 'action.params.x: schema nesting or reference chain deeper than 8 (declared string; refine or drop)';
  it('a chain of 8 references resolves; a chain of 9 is cut and flagged', () => {
    const ok = one({ $ref: '#/definitions/D0' }, chain(8));
    expect(ok.decl).toEqual({ type: 'integer', ...BASE });
    expect(ok.todo).not.toContain(DEEP);
    const cut = one({ $ref: '#/definitions/D0' }, chain(9));
    expect(cut.decl).toEqual({ type: 'string', ...BASE });
    expect(cut.todo).toContain(DEEP);
    expect(cut.todo).toContain(NOREP);
  });
  it('a reference cycle ends at the depth bound', () => {
    const { decl, todo } = one({ $ref: '#/definitions/C' }, { C: { $ref: '#/definitions/C' } });
    expect(decl).toEqual({ type: 'string', ...BASE });
    expect(todo).toContain(DEEP);
  });
  it('nested anyOf wrappers count toward the depth: 8 are followed, 9 are cut', () => {
    const nest = (n: number) => {
      let s: unknown = { type: 'integer' };
      for (let i = 0; i < n; i++) s = { anyOf: [s, { type: 'null' }] };
      return s;
    };
    const ok = one(nest(8));
    expect(ok.decl).toEqual({ type: 'integer', ...BASE });
    expect(ok.todo).not.toContain(DEEP);
    const cut = one(nest(9));
    expect(cut.decl).toEqual({ type: 'string', ...BASE });
    expect(cut.todo).toContain(DEEP);
  });
  const names = (n: number) => Array.from({ length: n }, (_, i) => `p${String(i).padStart(5, '0')}`);
  it('an operation may expand at most 20000 schema nodes; the first one past the bound is flagged once', () => {
    const properties: Record<string, unknown> = {};
    for (const n of names(20_001)) properties[n] = { type: 'string' };
    const d = draftSchemaFromMcpTools([mcp({ type: 'object', properties })], SITE);
    expect(d.todo.filter((m) => m.includes('expansion stopped'))).toEqual(['action.params.p19999: schema expansion stopped after 20000 nodes (declared string; refine or drop)']);
    expect(d.todo.filter((m) => m.includes('has no schema representation'))).toEqual([
      "action.params.p19999: type 'undefined' has no schema representation (declared string; refine or drop)",
      "action.params.p20000: type 'undefined' has no schema representation (declared string; refine or drop)",
    ]);
    expect(Object.keys(d.schema.verbs[0]!.params).length).toBe(20_001);
  });
  it('a property that is not a schema object costs nothing against the bound', () => {
    const properties: Record<string, unknown> = {};
    for (const n of names(20_001)) properties[n] = true;
    const d = draftSchemaFromMcpTools([mcp({ type: 'object', properties })], SITE);
    expect(d.todo.filter((m) => m.includes('expansion stopped'))).toEqual([]);
  });
});

describe('properties that are not schemas', () => {
  it('null, undefined and primitives are declared string placeholders and flagged', () => {
    const d = draftSchemaFromMcpTools([mcp({ type: 'object', properties: { n: null, u: undefined, s: 'str', k: 5, t: true } })], SITE);
    for (const name of ['n', 'u', 's', 'k', 't']) {
      expect(d.schema.verbs[0]!.params[`action.params.${name}`], name).toEqual({ type: 'string', ...BASE });
      expect(d.todo, name).toContain(`action.params.${name}: type 'undefined' has no schema representation (declared string; refine or drop)`);
    }
  });
});

describe('allOf', () => {
  it('merges its members; properties and required lists accumulate', () => {
    const { decl } = one({ allOf: [{ type: 'integer', minimum: 1 }, { maximum: 5, description: 'd' }] });
    expect(decl).toEqual({ type: 'integer', min: 1, max: 5, description: 'd', ...BASE });
    const d = draftSchemaFromMcpTools([mcp({ allOf: [{ properties: { a: { type: 'integer' } }, required: ['a'] }, { properties: { b: { type: 'boolean' } } }] })], SITE);
    expect(d.schema.verbs[0]!.params).toEqual({
      'action.params.a': { type: 'integer', semantic: 'unknown', sensitivity: 'material' },
      'action.params.b': { type: 'boolean', ...BASE },
    });
  });
});

describe('anyOf / oneOf', () => {
  const union = (n: number) => `action.params.x: a union of ${n} schemas has no schema representation (declared string; refine or drop)`;
  it('a nullable single variant collapses to that variant, null in either order or spelling', () => {
    expect(one({ anyOf: [{ type: 'integer' }, { type: 'null' }] }).decl).toEqual({ type: 'integer', ...BASE });
    expect(one({ anyOf: [{ type: 'null' }, { type: 'integer' }] }).decl).toEqual({ type: 'integer', ...BASE });
    expect(one({ oneOf: [{ type: 'integer' }, { type: ['null'] }] }).decl).toEqual({ type: 'integer', ...BASE });
    expect(one({ oneOf: [{ type: ['null', 'null'] }, { type: 'boolean' }] }).decl).toEqual({ type: 'boolean', ...BASE });
    const r = one({ anyOf: [{ type: 'integer' }, { type: 'null' }] });
    expect(r.todo.filter((m) => m.includes('union'))).toEqual([]);
  });
  it('a type list that merely contains null is a live variant', () => {
    expect(one({ anyOf: [{ type: ['string', 'null'] }, { type: ['null'] }] }).decl).toEqual({ type: 'string', ...BASE });
    const r = one({ anyOf: [{ type: ['string', 'null'] }, { type: 'integer' }] });
    expect(r.decl).toEqual({ type: 'string', ...BASE });
    expect(r.todo).toContain(union(2));
  });
  it('members of the wrapper survive the collapse', () => {
    const { decl } = one({ anyOf: [{ type: 'integer' }, { type: 'null' }], description: 'dd', minimum: 1 });
    expect(decl).toEqual({ type: 'integer', min: 1, description: 'dd', ...BASE });
  });
  it('string constants and enums unite into one closed value set, distinct and in order', () => {
    const a = one({ anyOf: [{ const: 'a' }, { const: 'b' }] });
    expect(a.decl).toEqual({ type: 'string', values: ['a', 'b'], ...BASE });
    expect(a.todo.filter((m) => m.includes('union'))).toEqual([]);
    expect(one({ oneOf: [{ enum: ['a', 'b'] }, { const: 'b' }, { enum: ['c'] }] }).decl).toEqual({ type: 'string', values: ['a', 'b', 'c'], ...BASE });
    expect(one({ oneOf: [{ const: 'a', enum: ['a', 'b'] }, { const: 'c' }] }).decl).toEqual({ type: 'string', values: ['a', 'c'], ...BASE }); // a const wins over a sibling enum
    expect(one({ anyOf: [{ const: 'a' }, { const: 'b' }, { type: 'null' }], maxLength: 7 }).decl).toEqual({ type: 'string', values: ['a', 'b'], max_len: 7, ...BASE });
  });
  it('a union with a member that is not a string constant set has no representation', () => {
    for (const alts of [[{ const: 'a' }, { type: 'integer' }], [{ enum: ['a', 5] }, { const: 'b' }], [{ type: 'integer' }, { type: 'boolean' }], [{ const: 5 }, { const: 'b' }], [{ enum: 'ab' }, { const: 'b' }]]) {
      const r = one({ anyOf: alts });
      expect(r.decl, JSON.stringify(alts)).toEqual({ type: 'string', ...BASE });
      expect(r.todo, JSON.stringify(alts)).toContain(union(2));
      expect(r.todo, JSON.stringify(alts)).toContain(NOREP);
    }
  });
  it('a union of only nulls has no representation and is not an empty enum', () => {
    const r = one({ anyOf: [{ type: 'null' }] });
    expect(r.decl).toEqual({ type: 'string', ...BASE });
    expect(r.todo).toContain(union(0));
    const r2 = one({ anyOf: [{ type: 'null' }, { type: ['null'] }] });
    expect(r2.todo).toContain(union(0));
  });
});

describe('const', () => {
  it('a string const becomes a one-value enum unless an enum is given', () => {
    expect(one({ type: 'string', const: 'only' }).decl).toEqual({ type: 'string', values: ['only'], ...BASE });
    expect(one({ type: 'string', const: 'a', enum: ['a', 'b'] }).decl).toEqual({ type: 'string', values: ['a', 'b'], ...BASE });
    expect(one({ type: 'string', enum: ['a', 'b'] }).decl).toEqual({ type: 'string', values: ['a', 'b'], ...BASE });
    expect(one({ type: 'string' }).decl).toEqual({ type: 'string', ...BASE });
    expect(one({ type: 'string', const: 5 }).decl).toEqual({ type: 'string', ...BASE });
  });
});

describe('OpenAPI: the JSON request body', () => {
  const A = { type: 'object', properties: { fromA: { type: 'integer' } } };
  const B = { type: 'object', properties: { fromB: { type: 'integer' } } };
  const T = { type: 'object', properties: { fromT: { type: 'integer' } } };
  const names = (requestBody: unknown, extra: Record<string, unknown> = {}, components?: Record<string, unknown>) => {
    const doc = { paths: { '/x': { post: { operationId: 'op', requestBody, ...extra } } }, ...(components ? { components } : {}) } as OpenApiLike;
    const d = draftSchemaFromOpenApi(doc, SITE);
    return { keys: Object.keys(d.schema.verbs[0]!.params), todo: d.todo, params: d.schema.verbs[0]!.params };
  };
  it('application/json wins over other media types, whatever the case', () => {
    expect(names({ content: { 'a/b': { schema: A }, 'application/json': { schema: B } } }).keys).toEqual(['action.params.fromB']);
    expect(names({ content: { 'Application/JSON': { schema: B } } }).keys).toEqual(['action.params.fromB']);
    expect(names({ content: { 'application/vnd.x+json': { schema: T }, 'application/json': { schema: B } } }).keys).toEqual(['action.params.fromB']);
    expect(names({ content: { 'text/plain': { schema: T } } }).keys).toEqual([]);
  });
  it('among case variants of application/json the first in byte order is taken', () => {
    expect(names({ content: { 'application/json': { schema: A }, 'Application/JSON': { schema: B } } }).keys).toEqual(['action.params.fromB']);
  });
  it('else an application/*+json media type is taken, with or without parameters', () => {
    expect(names({ content: { 'text/plain': { schema: T }, 'application/vnd.api+json': { schema: B } } }).keys).toEqual(['action.params.fromB']);
    expect(names({ content: { 'application/vnd.api+json; charset=utf-8': { schema: B } } }).keys).toEqual(['action.params.fromB']);
    expect(names({ content: { 'APPLICATION/VND+JSON': { schema: B } } }).keys).toEqual(['action.params.fromB']);
    expect(names({ content: { 'application/+json': { schema: B } } }).keys).toEqual(['action.params.fromB']);
    expect(names({ content: { 'application/z+json': { schema: A }, 'application/a+json': { schema: B } } }).keys).toEqual(['action.params.fromB']);
    for (const k of ['application/vnd.api+jsonx', 'x-application/vnd+json', 'application/a;b+json', 'application/json5', 'application/vnd+json2', 'text/vnd+json']) expect(names({ content: { [k]: { schema: B } } }).keys, k).toEqual([]);
  });
  it('a missing, null or odd content map or entry yields no body parameters and no failure', () => {
    expect(names(undefined).keys).toEqual([]);
    expect(names(null).keys).toEqual([]);
    expect(names('text').keys).toEqual([]);
    expect(names({}).keys).toEqual([]);
    expect(names({ content: null }).keys).toEqual([]);
    expect(names({ content: 'application/json' }).keys).toEqual([]);
    expect(names({ content: 5 }).keys).toEqual([]);
    expect(names({ content: { 'application/json': null } }).keys).toEqual([]);
    expect(names({ content: { 'application/json': {} } }).keys).toEqual([]);
    expect(names({ content: { undefined: { schema: B } } }).keys).toEqual([]);
  });
  it('a request body may be a local reference; one that does not resolve is flagged', () => {
    const ok = names({ $ref: '#/components/requestBodies/R' }, {}, { requestBodies: { R: { content: { 'application/json': { schema: B } } } } });
    expect(ok.keys).toEqual(['action.params.fromB']);
    expect(ok.todo.filter((m) => m.includes('reference'))).toEqual([]);
    const ref = `#/components/requestBodies/${'x'.repeat(200)}`;
    const bad = names({ $ref: ref });
    expect(bad.keys).toEqual([]);
    expect(bad.todo).toContain(`reference '${ref.slice(0, 120)}' is not a local reference that resolves`);
  });
  it('a body schema that does not resolve is flagged at the request body', () => {
    const r = names({ content: { 'application/json': { schema: { $ref: '#/nope' } } } });
    expect(r.todo).toContain(`op: request body: ${REF_MSG('#/nope')}`);
  });
  it('required names and the body winning a name clash with a query parameter', () => {
    const body = { content: { 'application/json': { schema: { type: 'object', properties: { id: { type: 'integer' }, note: { type: 'string' } }, required: ['id'] } } } };
    const r = names(body, { parameters: [{ name: 'id', in: 'query', schema: { type: 'string' } }] });
    expect(r.params['action.params.id']).toEqual({ type: 'integer', semantic: 'unknown', sensitivity: 'material' });
    expect(r.params['action.params.note']).toEqual({ type: 'string', ...BASE });
    expect(r.todo).toContain("op: 'id' is declared by both the query parameters and another source; kept the first");
  });
});

describe('OpenAPI: parameters and operations', () => {
  const run = (op: Record<string, unknown>, pathItem: Record<string, unknown> = {}, components?: Record<string, unknown>) => {
    const doc = { paths: { '/x': { ...pathItem, get: { operationId: 'op', ...op } } }, ...(components ? { components } : {}) } as OpenApiLike;
    const d = draftSchemaFromOpenApi(doc, SITE);
    return { params: d.schema.verbs[0]!.params, todo: d.todo };
  };
  it('a parameter may be a local reference; an unresolved one is flagged and skipped', () => {
    const ok = run({ parameters: [{ $ref: '#/components/parameters/P' }] }, {}, { parameters: { P: { name: 'limit', in: 'query', schema: { type: 'integer' } } } });
    expect(Object.keys(ok.params)).toEqual(['action.params.limit']);
    expect(ok.todo.filter((m) => m.includes('reference'))).toEqual([]);
    const bad = run({ parameters: [{ $ref: '#/nope' }, { name: 'a', in: 'query', schema: { type: 'integer' } }] });
    expect(Object.keys(bad.params)).toEqual(['action.params.a']);
    expect(bad.todo).toContain("reference '#/nope' is not a local reference that resolves");
  });
  it('entries that are not parameter objects with a name and a location are skipped silently', () => {
    const r = run({ parameters: [null, 'str', 5, { name: 5, in: 'query' }, { name: 'a' }, { in: 'query' }, { name: 'ok', in: 'query', schema: { type: 'boolean' } }] }, { parameters: [null, 'x'] });
    expect(Object.keys(r.params)).toEqual(['action.params.ok']);
    expect(r.todo.filter((m) => m.includes('not an action parameter'))).toEqual([]);
  });
  it('operations that are not objects with an operationId are skipped', () => {
    const doc = { paths: { '/x': { get: null, post: 'x', put: [], delete: { description: 'no id' }, patch: { operationId: '' }, head: { operationId: 'h' }, parameters: [] } } } as OpenApiLike;
    const d = draftSchemaFromOpenApi(doc, SITE);
    expect(d.schema.verbs.map((v) => v.verb)).toEqual(['h']);
  });
});
