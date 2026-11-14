import { describe, expect, it, vi } from 'vitest';
import { draftSchemaFromMcpTools, draftSchemaFromOpenApi } from './action-schema';

const site = { site: 's', aud: 'a', version: '1' };
const str = { type: 'string', 'x-pca-semantic': 'text' };

describe('id: formats', () => {
  // the id grammar is a module-level regex: re-evaluate the module so the check runs inside the test
  it('accept dotted segments of any length up to three dots and nothing longer', async () => {
    vi.resetModules();
    const { formatCheck } = await import('./action-schema');
    for (const f of ['id:a', 'id:user', 'id:a.bc', 'id:user.account_x', 'id:a.b.c.d']) expect(formatCheck(f), f).not.toBeNull();
    for (const f of ['id:', 'id:A', 'id:a.', 'id:a.b.c.d.e', 'id:a-b']) expect(formatCheck(f), f).toBeNull();
  });
});

describe('draft schema from an MCP tool: allOf nesting', () => {
  it('stops following nested allOf past the depth bound and says so', () => {
    let s: unknown = { type: 'object', properties: {} };
    for (let i = 0; i < 10; i++) s = { allOf: [s] };
    const { todo } = draftSchemaFromMcpTools([{ name: 't', inputSchema: s as never }], site);
    expect(todo.some((m) => m.includes('deeper than 8'))).toBe(true);
    let ok: unknown = { type: 'object', properties: {} };
    for (let i = 0; i < 3; i++) ok = { allOf: [ok] };
    expect(draftSchemaFromMcpTools([{ name: 't', inputSchema: ok as never }], site).todo.some((m) => m.includes('deeper than'))).toBe(false);
  });
});

describe('draft schema from OpenAPI: parameters', () => {
  const doc = {
    paths: {
      '/x/{id}': {
        get: {
          operationId: 'getX',
          parameters: [
            { name: 'q', in: 'query', required: true, schema: str },
            { name: 'id', in: 'path', schema: str },
            { name: 'opt', in: 'query', schema: str },
            { name: 'req2', in: 'query', required: false, schema: str },
            { name: 'h', in: 'header', schema: str },
            { name: 'ck', in: 'cookie', schema: str },
            { name: 'd1', in: 'query', description: 'Q desc', schema: str },
            { name: 'd2', in: 'query', description: 'Q', schema: { ...str, description: 'S' } },
            { name: 'd3', in: 'query', schema: { ...str, description: 'S3' } },
          ],
        },
      },
    },
  };
  const draft = () => {
    const out = draftSchemaFromOpenApi(doc as never, site);
    return { out, params: out.schema.verbs[0]!.params };
  };

  it('keeps path and query parameters under distinct keys, in sorted key order', () => {
    const { params } = draft();
    expect(Object.keys(params)).toEqual(['action.params.id', 'action.params.d1', 'action.params.d2', 'action.params.d3', 'action.params.opt', 'action.params.q', 'action.params.req2']);
  });
  it('flags header and cookie parameters and does not declare them', () => {
    const { out, params } = draft();
    expect(out.todo).toContain("getX: header parameter 'h' is not an action parameter (the schema sees path, query and body parameters only)");
    expect(out.todo).toContain("getX: cookie parameter 'ck' is not an action parameter (the schema sees path, query and body parameters only)");
    expect(params['action.params.h']).toBeUndefined();
    expect(params['action.params.ck']).toBeUndefined();
  });
  it('a path parameter is always required; a query parameter only when it says so', () => {
    const { params } = draft();
    expect(params['action.params.id']).not.toHaveProperty('required');
    expect(params['action.params.q']).not.toHaveProperty('required');
    expect(params['action.params.opt']).toHaveProperty('required', false);
    expect(params['action.params.req2']).toHaveProperty('required', false);
  });
  it('the parameter description fills in only when the schema has none', () => {
    const { params } = draft();
    expect(params['action.params.d1']).toHaveProperty('description', 'Q desc');
    expect(params['action.params.d2']).toHaveProperty('description', 'S');
    expect(params['action.params.d3']).toHaveProperty('description', 'S3');
    expect(params['action.params.opt']).not.toHaveProperty('description');
  });
});
