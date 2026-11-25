// Exact outcomes of the OpenAPI importer (references, media types, parameters, security notes, titles, idempotency, scope) and
// of the import pipeline (kind dispatch, suggest wiring, JSON Lines).
import { describe, expect, it } from 'vitest';
import { ActionKitError, DEFAULT_RULES, DEFAULT_RULES_SEALED, defsToJsonl, importActions, importAndSuggest, importOpenApi, jsonlToDefs, rulesDigest, suggestDefs, type ImportReport, type ModelAdapter } from '../src';

const N = { ns: 't' };
const oa = (paths: Record<string, unknown>, extra: Record<string, unknown> = {}, opts: Parameters<typeof importOpenApi>[1] = N): ImportReport => importOpenApi({ openapi: '3.0.0', ...extra, paths }, opts);
const sw = (paths: Record<string, unknown>): ImportReport => importOpenApi({ swagger: '2.0', paths }, N);
const thrown = (f: () => unknown): ActionKitError => {
  try { f(); } catch (e) { return e as ActionKitError; }
  throw new Error('expected a throw');
};
const obj = (...names: string[]) => ({ type: 'object', properties: Object.fromEntries(names.map((n) => [n, { type: 'string' }])) });
const post = (op: Record<string, unknown>) => oa({ '/a': { post: { operationId: 'op', ...op } } });
const keysOf = (r: ImportReport) => Object.keys(r.defs[0]!.params);
const str = { type: 'string' };

describe('reference resolution', () => {
  const chain = (n: number) => {
    const x: Record<string, unknown> = {};
    for (let i = 0; i < n; i++) x[`r${i}`] = { $ref: `#/x/r${i + 1}` };
    x[`r${n}`] = { content: { 'application/json': { schema: obj('a') } } };
    return oa({ '/a': { post: { operationId: 'op', requestBody: { $ref: '#/x/r0' } } } }, { x });
  };

  it('follows a chain of 9 references and stops at 10', () => {
    const ok = chain(8);
    expect(ok.todo).toEqual([]);
    expect(keysOf(ok)).toEqual(['a']);
    const deep = chain(9);
    expect(deep.todo).toEqual([{ where: 'POST /a', code: 'cyclic_ref', message: 'a reference chain is cyclic or too deep' }]);
    expect(keysOf(deep)).toEqual([]);
  });

  it('notes a reference cycle', () => {
    const r = oa({ '/a': { post: { operationId: 'op', requestBody: { $ref: '#/x/a' } } } }, { x: { a: { $ref: '#/x/b' }, b: { $ref: '#/x/a' } } });
    expect(r.todo).toEqual([{ where: 'POST /a', code: 'cyclic_ref', message: 'a reference chain is cyclic or too deep' }]);
  });

  it('notes an unresolvable reference and carries on without the target', () => {
    const r = oa({ '/a': { post: { operationId: 'op', requestBody: { $ref: '#/nope' } } } });
    expect(r.todo).toEqual([{ where: 'POST /a', code: 'unresolved_ref', message: "reference '#/nope' does not resolve locally" }]);
    expect(r.defs).toHaveLength(1);
  });

  it('skips a path item whose reference does not resolve, naming the path', () => {
    const r = oa({ '/p': { $ref: '#/nope' } });
    expect(r.defs).toEqual([]);
    expect(r.todo).toEqual([{ where: '/p', code: 'unresolved_ref', message: "reference '#/nope' does not resolve locally" }]);
  });

  it('resolves a path item and a parameter by reference', () => {
    const r = oa({ '/a': { $ref: '#/x/item' } }, { x: { item: { get: { operationId: 'getA', parameters: [{ $ref: '#/x/p' }] } }, p: { name: 'q', in: 'query', schema: { type: 'integer' } } } });
    expect(r.todo).toEqual([]);
    expect(r.defs[0]!.params).toEqual({ q: { type: 'integer', required: false } });
  });
});

describe('document recognition and ordering', () => {
  const msg = "not an OpenAPI 3.x or Swagger 2 document (missing 'openapi: 3.x' or 'swagger: 2.0')";
  it('refuses a non-object with the exact error', () => {
    const e = thrown(() => importOpenApi('nope', N));
    expect(e).toBeInstanceOf(ActionKitError);
    expect(e.code).toBe('bad_source');
    expect(e.message).toBe('an OpenAPI document must be an object');
  });
  it('refuses documents that are neither OpenAPI 3.x nor Swagger 2', () => {
    for (const doc of [{ swagger: '1.2' }, { openapi: 3.1 }, { openapi: '13.0.0' }, { openapi: '2.0.0' }, {}]) {
      const e = thrown(() => importOpenApi(doc, N));
      expect(e.code).toBe('bad_source');
      expect(e.message).toBe(msg);
    }
  });
  it('visits paths in UTF-8 order', () => {
    const r = oa({ '/b': { get: { operationId: 'getB' } }, '/a': { get: { operationId: 'getA' } } });
    expect(r.defs.map((d) => d.bindings!.openapi!.path)).toEqual(['/a', '/b']);
  });
});

describe('Swagger 2 parameters', () => {
  it('a body parameter without a schema declares nothing and raises no note', () => {
    const r = sw({ '/a': { post: { operationId: 'op', parameters: [{ name: 'b', in: 'body' }] } } });
    expect(r.todo).toEqual([]);
    expect(r.defs[0]!.params).toEqual({});
  });
  it('a body parameter with a schema is flattened and not reported as a location', () => {
    const r = sw({ '/a': { post: { operationId: 'op', parameters: [{ name: 'payload', in: 'body', schema: { type: 'object', required: ['a'], properties: { a: str } } }] } } });
    expect(r.todo).toEqual([]);
    expect(r.defs[0]!.params).toEqual({ a: { type: 'string' } });
  });
  it('a query parameter that already carries a schema keeps it', () => {
    const r = sw({ '/a': { get: { operationId: 'op', parameters: [{ name: 'n', in: 'query', schema: { type: 'integer' } }] } } });
    expect(r.defs[0]!.params).toEqual({ n: { type: 'integer', required: false } });
  });
  it('a formData parameter is accepted with its description', () => {
    const r = sw({ '/a': { post: { operationId: 'op', parameters: [{ name: 'f', in: 'formData', type: 'string', required: true, description: 'F' }] } } });
    expect(r.todo).toEqual([]);
    expect(r.defs[0]!.params).toEqual({ f: { type: 'string', description: 'F' } });
  });
});

describe('request body media types', () => {
  const body = (content: Record<string, unknown>) => post({ requestBody: { content } });
  const wrap = (s: unknown) => ({ schema: s });

  it('picks among equal media types in UTF-8 order', () => {
    expect(keysOf(body({ 'application/json': wrap(obj('a')), 'Application/JSON': wrap(obj('b')) }))).toEqual(['b']);
  });
  it('prefers JSON over form over multipart, and form or multipart over anything else', () => {
    expect(keysOf(body({ 'application/atom+xml': wrap(obj('a')), 'multipart/form-data': wrap(obj('b')) }))).toEqual(['b']);
    expect(keysOf(body({ 'application/json': wrap(obj('a')), 'multipart/form-data': wrap(obj('b')) }))).toEqual(['a']);
  });
  it('ignores parameters and padding around the media type', () => {
    expect(keysOf(body({ 'application/json ; charset=utf-8': wrap(obj('a')) }))).toEqual(['a']);
  });
  it('accepts a +json type, with or without parameters, but only as an application type', () => {
    expect(keysOf(body({ 'application/vnd.api+json': wrap(obj('a')) }))).toEqual(['a']);
    expect(keysOf(body({ 'application/vnd.api+json; charset=utf-8': wrap(obj('a')) }))).toEqual(['a']);
    const r = body({ 'text/application/x+json': wrap(obj('a')) });
    expect(r.todo).toEqual([{ where: 'POST /a', code: 'body_type', message: 'request body media types (text/application/x+json) are not form or JSON; the body is not declared' }]);
    expect(keysOf(r)).toEqual([]);
  });
  it('names at most 3 unsupported media types, in order', () => {
    const r = body({ 'text/plain': wrap(obj('a')), 'text/html': wrap(obj('a')), 'text/csv': wrap(obj('a')), 'application/xml': wrap(obj('a')) });
    expect(r.todo).toEqual([{ where: 'POST /a', code: 'body_type', message: 'request body media types (application/xml, text/csv, text/html) are not form or JSON; the body is not declared' }]);
  });
  it('an empty content map raises no note; a null entry has no schema', () => {
    expect(body({}).todo).toEqual([]);
    const r = body({ 'application/json': null });
    expect(r.todo).toEqual([]);
    expect(keysOf(r)).toEqual([]);
  });
});

describe('request body shape', () => {
  const json = (schema: unknown) => post({ requestBody: { content: { 'application/json': { schema } } } });
  const shape = { where: 'POST /a', code: 'body_shape', message: 'the request body is not an object schema; it is not declared' };
  it('a non-object schema is noted', () => {
    const r = json({ type: 'string' });
    expect(r.todo).toEqual([shape]);
    expect(keysOf(r)).toEqual([]);
  });
  it('an object schema without properties declares nothing and raises no note', () => {
    const r = json({ type: 'object' });
    expect(r.todo).toEqual([]);
    expect(keysOf(r)).toEqual([]);
  });
  it('a properties-only schema is an object', () => {
    const r = json({ properties: { a: str } });
    expect(r.todo).toEqual([]);
    expect(keysOf(r)).toEqual(['a']);
  });
  it('an operation without a body raises no note', () => {
    expect(oa({ '/a': { get: { operationId: 'op' } } }).todo).toEqual([]);
  });
  it('an unresolvable body schema names the body and then the shape', () => {
    expect(json({ $ref: '#/nope' }).todo).toEqual([
      { where: 'POST /a: request body', code: 'unresolved_ref', message: "reference '#/nope' is not a local reference that resolves (declared string; refine or drop)" },
      shape,
    ]);
  });
});

describe('verbs and names', () => {
  const get = (op: Record<string, unknown>, opts = N, path = '/widgets') => oa({ [path]: { get: op } }, {}, opts).defs[0]!;
  it('an x-pca-verb in the namespace and the verb grammar is used; anything else is ignored', () => {
    expect(get({ 'x-pca-verb': 't.custom.thing' }).verb).toBe('t.custom.thing');
    for (const bad of ['not a verb', 't.Foo.bar', 't.foo.bar!', 'tx.foo.bar', ['t.foo.bar'], 5]) expect(get({ 'x-pca-verb': bad }).verb).toBe('t.widgets.list');
  });
  it('an x-pca-verb that is not allow-listed is ignored and noted', () => {
    const r = oa({ '/widgets': { get: { 'x-pca-verb': 't.custom.thing' } } }, {}, { ns: 't', allowExtensions: [] });
    expect(r.defs[0]!.verb).toBe('t.widgets.list');
    expect(r.todo).toEqual([{ where: 'GET /widgets', code: 'extension_ignored', message: "extension 'x-pca-verb' is ignored (not allow-listed)" }]);
  });
  it('the verb of an unnamed operation uses the last two path nouns and list/get by the path end', () => {
    expect(get({}, N, '/a/b/c').verb).toBe('t.b.c.list');
    expect(get({}, N, '/a/b/c/{id}').verb).toBe('t.b.c.get');
  });
  it('an operationId is used only when 1..200 characters long', () => {
    const id = (v: unknown) => get({ operationId: v }, N, '/a').bindings!.openapi!.operationId;
    expect(id('x'.repeat(200))).toBe('x'.repeat(200));
    expect(id('x'.repeat(201))).toBe('get_/a');
    expect(id('')).toBe('get_/a');
    expect(id(123)).toBe('get_/a');
    expect(get({ operationId: '' }).verb).toBe('t.widgets.list');
    expect(get({ operationId: 123 }).verb).toBe('t.widgets.list');
  });
  it('an unnamed operation is named after its method and path, with no alias', () => {
    const d = get({}, N, '/a');
    expect(d.title).toBe('Get a');
    expect(d.aliases).toBeUndefined();
    expect(d.bindings).toEqual({ openapi: { operationId: 'get_/a', method: 'GET', path: '/a' } });
    expect(d.verb).toBe('t.a.list');
  });
  it('a named operation has an alias and exact bindings', () => {
    const d = oa({ '/widgets': { post: { operationId: 'createWidget' } } }).defs[0]!;
    expect(d.verb).toBe('t.widget.create');
    expect(d.aliases).toEqual(['create_widget']);
    expect(d.bindings).toEqual({ openapi: { operationId: 'createWidget', method: 'POST', path: '/widgets' } });
  });
});

describe('titles and descriptions', () => {
  const pick = (op: Record<string, unknown>) => { const d = oa({ '/a': { post: op } }).defs[0]!; return { title: d.title, description: d.description }; };
  it.each([
    [{ operationId: 'createWidget', summary: 'Make one', description: 'Long' }, { title: 'Make one', description: 'Long' }],
    [{ operationId: 'createWidget' }, { title: 'createWidget', description: undefined }],
    [{ operationId: 'createWidget', summary: '' }, { title: 'createWidget', description: undefined }],
    [{ operationId: 'createWidget', summary: 'Sum' }, { title: 'Sum', description: 'Sum' }],
    [{ operationId: 'createWidget', summary: 'Sum', description: 5 }, { title: 'Sum', description: 'Sum' }],
    [{ operationId: 'createWidget', summary: 'Sum', description: '' }, { title: 'Sum', description: undefined }],
    [{ summary: 'Sum' }, { title: 'Sum', description: 'Sum' }],
  ])('%j', (op, want) => { expect(pick(op)).toEqual(want); });
});

describe('parameters', () => {
  const get = (parameters: unknown[], path = '/a') => oa({ [path]: { get: { operationId: 'op', parameters } } });
  const p = (name: string, loc: string, extra: Record<string, unknown> = {}) => ({ name, in: loc, schema: str, ...extra });

  it('are declared in order of location then name, whatever the document order', () => {
    expect(keysOf(get([p('a', 'path'), p('b', 'query'), p('c', 'query')], '/x/{a}'))).toEqual(['a', 'b', 'c']);
    expect(keysOf(get([p('c', 'query'), p('b', 'query'), p('a', 'path')], '/x/{a}'))).toEqual(['a', 'b', 'c']);
  });
  it('the operation overrides a path-level parameter of the same location and name', () => {
    const r = oa({ '/a': { parameters: [p('p', 'query')], get: { operationId: 'op', parameters: [p('p', 'query', { schema: { type: 'integer' } })] } } });
    expect(r.defs[0]!.params).toEqual({ p: { type: 'integer', required: false } });
  });
  it('path parameters are required, query ones only when declared so', () => {
    const r = get([{ name: 'id', in: 'path', schema: str }, p('q', 'query', { required: true }), p('r', 'query', { required: false }), p('s', 'query')], '/a/{id}');
    expect(r.defs[0]!.params).toEqual({ id: { type: 'string' }, q: { type: 'string' }, r: { type: 'string', required: false }, s: { type: 'string', required: false } });
  });
  it('a declaration without a name or a location is skipped silently', () => {
    const r = get([{ in: 'query' }, { name: 'x' }, 5, null, 'str', p('ok', 'query')]);
    expect(r.todo).toEqual([]);
    expect(keysOf(r)).toEqual(['ok']);
  });
  it('the parameter description is used unless the schema has its own', () => {
    const r = get([p('a', 'query', { description: 'Alpha' }), p('b', 'query', { description: 'Param', schema: { type: 'string', description: 'Schema' } }), p('c', 'query')]);
    expect(r.defs[0]!.params).toEqual({
      a: { type: 'string', required: false, description: 'Alpha' },
      b: { type: 'string', required: false, description: 'Schema' },
      c: { type: 'string', required: false },
    });
  });
  it('cookie and other headers are not action parameters; path, query and formData are', () => {
    const r = get([p('sid', 'cookie'), p('X-Trace', 'header'), p('q', 'query')]);
    expect(r.todo).toEqual([
      { where: 'GET /a', code: 'param_location', message: "cookie parameter 'sid' is not an action parameter (path, query and body only)" },
      { where: 'GET /a', code: 'param_location', message: "header parameter 'X-Trace' is not an action parameter (path, query and body only)" },
    ]);
    expect(keysOf(r)).toEqual(['q']);
  });
  it('a renamed parameter is noted with its original name', () => {
    const r = get([p('user-id', 'query')]);
    expect(r.todo).toEqual([{ where: 'GET /a: user-id', code: 'renamed_param', message: "parameter 'user-id' is declared as 'user_id'" }]);
    expect(keysOf(r)).toEqual(['user_id']);
  });
  it('a schema problem is noted against the parameter', () => {
    expect(get([p('x', 'query', { schema: { $ref: '#/nope' } })]).todo).toEqual([
      { where: 'GET /a: x', code: 'unresolved_ref', message: "reference '#/nope' is not a local reference that resolves (declared string; refine or drop)" },
      { where: 'GET /a: x', code: 'unsupported_type', message: "type 'none' has no representation (declared string; refine or drop)" },
    ]);
    expect(get([p('ratio', 'query', { schema: { type: 'number' } })]).todo).toEqual([
      { where: 'GET /a: ratio', code: 'unsupported_type', message: "type 'number' (fractions) has no ActionDef representation (declared string; use an integer unit, or refine)" },
    ]);
  });

  describe('clashing with the body', () => {
    const withBody = (props: Record<string, unknown>, query: string) => post({ requestBody: { content: { 'application/json': { schema: { type: 'object', properties: props } } } }, parameters: [p(query, 'query', { schema: { type: 'integer' } })] });
    it('a query parameter named like a body field is dropped', () => {
      const r = withBody({ id: str }, 'id');
      expect(r.todo).toEqual([{ where: 'POST /a: id', code: 'skipped_param', message: "'id' is declared by the body and by a query parameter; kept the body's" }]);
      expect(r.defs[0]!.params).toEqual({ id: { type: 'string', required: false } });
    });
    it('a query parameter named like the parent of a flattened body field is dropped', () => {
      const r = withBody({ user: obj('name') }, 'user');
      expect(r.todo).toEqual([{ where: 'POST /a: user', code: 'skipped_param', message: "'user' is declared by the body and by a query parameter; kept the body's" }]);
      expect(keysOf(r)).toEqual(['user.name']);
    });
    it('a query parameter that merely shares a prefix is kept', () => {
      const r = withBody({ user: obj('name') }, 'use');
      expect(r.todo).toEqual([]);
      expect(keysOf(r)).toEqual(['user.name', 'use']);
    });
  });

  describe('the 64 parameter limit', () => {
    const many = (n: number) => get(Array.from({ length: n }, (_, i) => p(`q${String(i).padStart(2, '0')}`, 'query')));
    it('64 parameters are declared without a note', () => {
      const r = many(64);
      expect(r.todo).toEqual([]);
      expect(keysOf(r)).toHaveLength(64);
    });
    it('the 65th is dropped with a note', () => {
      const r = many(65);
      expect(r.todo).toEqual([{ where: 'GET /a', code: 'too_many_params', message: 'more than 64 parameters; the rest are dropped' }]);
      expect(keysOf(r)).toHaveLength(64);
      expect(keysOf(r)).not.toContain('q64');
    });
  });

  it('paths ending in a parameter, however written, decide list/get and scope', () => {
    const d = (path: string) => oa({ [path]: { get: {} } }).defs[0]!;
    expect([d('/a/{id}/').verb, d('/a/{id}/').resource.scope]).toEqual(['t.a.get', 'one']);
    expect([d('/a/x{id}').verb, d('/a/x{id}').resource.scope]).toEqual(['t.a.list', 'set']);
    expect([d('/a/{id}x').verb, d('/a/{id}x').resource.scope]).toEqual(['t.a.list', 'set']);
    expect([d('/a/{id}').verb, d('/a/{id}').resource.scope]).toEqual(['t.a.get', 'one']);
  });
});

describe('idempotency', () => {
  const withHeaders = (headers: string[], extra: Record<string, unknown> = {}) => post({ parameters: headers.map((name) => ({ name, in: 'header', schema: str })), ...extra });
  it('an Idempotency-Key header becomes an optional key parameter', () => {
    const r = withHeaders(['Idempotency-Key']);
    expect(r.todo).toEqual([]);
    expect(r.defs[0]!.params).toEqual({ idempotency_key: { type: 'string', required: false, max_len: 255 } });
    expect(r.defs[0]!.idempotency).toEqual({ mode: 'key_param', param: 'idempotency_key' });
  });
  it.each(['X-Idempotency-Key', 'Idempotency-Key-2', 'X-Trace'])('the header %s is not the idempotency key', (h) => {
    const r = withHeaders([h]);
    expect(r.todo).toEqual([{ where: 'POST /a', code: 'param_location', message: `header parameter '${h}' is not an action parameter (path, query and body only)` }]);
    expect(r.defs[0]!.params).toEqual({});
    expect(r.defs[0]!.idempotency).toBeUndefined();
  });
  it('a query parameter named idempotency-key is an ordinary renamed parameter', () => {
    const r = post({ parameters: [{ name: 'idempotency-key', in: 'query', schema: str }] });
    expect(r.todo).toEqual([{ where: 'POST /a: idempotency-key', code: 'renamed_param', message: "parameter 'idempotency-key' is declared as 'idempotency_key'" }]);
    expect(r.defs[0]!.params).toEqual({ idempotency_key: { type: 'string', required: false } });
    expect(r.defs[0]!.idempotency).toBeUndefined();
  });
  it('a body field of the same name wins and no key parameter is declared', () => {
    const r = withHeaders(['Idempotency-Key'], { requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { idempotency_key: { type: 'string', maxLength: 10 } } } } } } });
    expect(r.defs[0]!.params).toEqual({ idempotency_key: { type: 'string', required: false, max_len: 10 } });
    expect(r.defs[0]!.idempotency).toBeUndefined();
  });
  it.each([
    ['get', ['read'], { mode: 'natural' }],
    ['head', ['read'], { mode: 'natural' }],
    ['put', ['update'], { mode: 'natural' }],
    ['delete', ['delete'], { mode: 'natural' }],
    ['post', ['create'], undefined],
    ['patch', ['update'], undefined],
  ])('%s: effects and natural idempotency', (method, effects, idem) => {
    const d = oa({ '/a': { [method]: { operationId: 'op' } } }).defs[0]!;
    expect(d.effects).toEqual(effects);
    expect(d.idempotency).toEqual(idem);
  });
});

describe('scope of the resource', () => {
  it.each([
    ['get', '/a', 'set'],
    ['get', '/a/{id}', 'one'],
    ['post', '/a', 'one'],
    ['post', '/a/{id}', 'one'],
    ['put', '/a', 'set'],
    ['patch', '/a', 'set'],
    ['delete', '/a/{id}', 'one'],
  ])('%s %s is %s', (method, path, scope) => {
    expect(oa({ [path]: { [method]: { operationId: 'op' } } }).defs[0]!.resource.scope).toBe(scope);
  });
});

describe('security scopes and deprecation notes', () => {
  it('lists the distinct string scopes, sorted, ignoring anything that is not a scope list', () => {
    const r = post({ security: [{ oauth: ['b:write', 'a:read'], k: [] }, { oauth: ['a:read', 'c', 5, null] }, 'str', { z: 'notarray' }] });
    expect(r.todo).toEqual([{ where: 'POST /a', code: 'required_scope', message: 'requires scope: a:read, b:write, c' }]);
  });
  it('names at most 12 scopes', () => {
    const scopes = Array.from({ length: 13 }, (_, i) => `s${String(i + 1).padStart(2, '0')}`);
    const r = post({ security: [{ o: scopes }] });
    expect(r.todo).toEqual([{ where: 'POST /a', code: 'required_scope', message: `requires scope: ${scopes.slice(0, 12).join(', ')}` }]);
  });
  it('an operation without security uses the document default; an empty list overrides it', () => {
    const r = oa({ '/a': { get: { operationId: 'ga' } }, '/b': { get: { operationId: 'gb', security: [] } } }, { security: [{ o: ['g'] }] });
    expect(r.todo).toEqual([{ where: 'GET /a', code: 'required_scope', message: 'requires scope: g' }]);
  });
  it('notes a deprecated operation, and only a true one', () => {
    expect(oa({ '/a': { get: { deprecated: true } } }).todo).toEqual([{ where: 'GET /a', code: 'deprecated', message: 'the operation is marked deprecated' }]);
    expect(oa({ '/a': { get: { deprecated: false } } }).todo).toEqual([]);
  });
});

describe('pipeline', () => {
  const KINDS: [Parameters<typeof importActions>[0], unknown, Parameters<typeof importActions>[2]][] = [
    ['openapi', { openapi: '3.0.0', paths: { '/a': { get: { operationId: 'op' } } } }, { ns: 'acme' }],
    ['mcp', [{ name: 'read_file', inputSchema: { type: 'object', properties: { path: str } } }], { ns: 'acme' }],
    ['graphql', 'type Query { a(x: Int): String }', { ns: 'acme' }],
    ['grpc', 'syntax="proto3"; package p; message R { string n = 1; } service S { rpc Do(R) returns (R); }', { ns: 'acme' }],
    ['asyncapi', { asyncapi: '2.6.0', channels: { 'a/b': { publish: { message: { payload: obj('m') } } } } }, { ns: 'acme' }],
    ['jsonschema', obj('q'), { ns: 'acme', verb: 'acme.search.run' }],
  ];
  it.each(KINDS)('importActions routes %s to its importer', (kind, source, opts) => {
    const r = importActions(kind, source, opts);
    expect(r.source.kind).toBe(kind);
    expect(r.defs).toHaveLength(1);
  });
  it('importActions refuses an unknown kind with the exact error', () => {
    const e = thrown(() => importActions('nope' as never, {}, N));
    expect(e.code).toBe('bad_kind');
    expect(e.message).toBe("unknown import kind 'nope' (one of openapi, mcp, graphql, grpc, asyncapi, jsonschema)");
  });

  const doc = { openapi: '3.0.0', paths: { '/a': { post: { operationId: 'sendEmail', deprecated: true } } } };
  it('importAndSuggest imports, suggests and reports', async () => {
    const r = await importAndSuggest('openapi', doc, N);
    expect(r.source.kind).toBe('openapi');
    expect(r.todo.map((x) => x.code)).toEqual(['deprecated']);
    expect(r.suggestErrors).toEqual([]);
    expect(r.defs).toHaveLength(1);
    expect(r.defs[0]!.review.state).toBe('suggested');
  });
  it('importAndSuggest with suggest mode none leaves the defs as imported', async () => {
    const r = await importAndSuggest('openapi', doc, { ...N, suggest: { mode: 'none' } });
    expect(r.defs[0]!.review.state).toBe('unreviewed');
    expect(r.suggestErrors).toEqual([]);
  });
  it('model mode without adapters records no errors', async () => {
    const imported = importOpenApi(doc, N);
    const s = await suggestDefs(imported.defs, { mode: 'model' });
    expect(s.errors).toEqual([]);
    expect(s.defs).toHaveLength(1);
  });

  it('suggestDefs records the digest of the rules it ran: the sealed one for the built-in rules, the computed one for any other set', async () => {
    const defs = importOpenApi(doc, N).defs;
    const rulesOf = (d: { review: { suggested_by?: unknown } }) => (d.review.suggested_by as { rules?: unknown }).rules;
    const builtin = await suggestDefs(defs);
    expect(rulesOf(builtin.defs[0]!)).toMatchObject({ digest: DEFAULT_RULES_SEALED.digest });
    const own = { ...DEFAULT_RULES, version: '9.9.9' };
    expect(rulesDigest(own)).not.toBe(DEFAULT_RULES_SEALED.digest);
    const custom = await suggestDefs(defs, { rules: own });
    expect(rulesOf(custom.defs[0]!)).toEqual({ version: '9.9.9', digest: rulesDigest(own), fired: expect.any(Array) });
  });
  it('suggestDefs asks the model adapters only in model mode', async () => {
    const defs = importOpenApi(doc, N).defs;
    let calls = 0;
    const adapter: ModelAdapter = { id: 'm1', complete: () => { calls++; return '[]'; } };
    await suggestDefs(defs, { mode: 'rules', models: [adapter] });
    expect(calls).toBe(0);
    await suggestDefs(defs, { mode: 'model', models: [adapter] });
    expect(calls).toBe(1);
  });
  it('defsToJsonl keeps defs that share a verb in the order given', () => {
    const [d] = importOpenApi(doc, N).defs;
    const first = { ...d!, title: 'first' };
    const second = { ...d!, title: 'second' };
    expect(defsToJsonl([first, second]).split('\n').map((l) => (l ? (JSON.parse(l) as { title: string }).title : l))).toEqual(['first', 'second', '']);
    expect(defsToJsonl([second, first]).split('\n').map((l) => (l ? (JSON.parse(l) as { title: string }).title : l))).toEqual(['second', 'first', '']);
  });
  it('jsonlToDefs trims each line, so blank and padded lines read as what they hold', () => {
    const defs = importOpenApi(doc, N).defs;
    const text = defsToJsonl(defs);
    expect(jsonlToDefs(`   \n\t${text.trimEnd()}  \r\n \n`)).toEqual(defs);
  });
  it('jsonlToDefs names the line of a def that does not validate, with the reason', () => {
    const text = defsToJsonl(importOpenApi(doc, N).defs);
    const e = thrown(() => jsonlToDefs(`${text}{"v":2}\n`));
    expect(e).toBeInstanceOf(ActionKitError);
    expect(e.code).toBe('bad_defs');
    expect(e.message).toMatch(/^line 2: .+/);
    expect(e.message).not.toMatch(/not JSON/);
  });
  it('defsToJsonl is empty for no defs and newline-terminated otherwise', () => {
    expect(defsToJsonl([])).toBe('');
    const defs = importOpenApi(doc, N).defs;
    const text = defsToJsonl(defs);
    expect(text.endsWith('\n')).toBe(true);
    expect(text.split('\n')).toHaveLength(2);
    expect(jsonlToDefs(text)).toEqual(defs);
  });
  it('jsonlToDefs names the line that is not JSON', () => {
    const text = defsToJsonl(importOpenApi(doc, N).defs);
    for (const [input, line] of [[`${text}not json\n`, 2], [`\n\n{bad`, 3]] as const) {
      const e = thrown(() => jsonlToDefs(input));
      expect(e).toBeInstanceOf(ActionKitError);
      expect(e.code).toBe('bad_defs');
      expect(e.message).toBe(`line ${line}: not JSON`);
    }
  });
});
