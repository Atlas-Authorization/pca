import { describe, expect, it } from 'vitest';
import { SEARCH_ACTION_PATH, SEARCH_RESOURCE_PATH, SEARCH_SUBJECT_PATH, authzenSearchHandler, isActionSearch, isResourceSearch, isSubjectSearch, type AuthzenSearchProvider } from './search';

const subj = { type: 'agent', id: 'a1' };
const subjectBody = { subject: { type: 'user' }, action: { name: 'read' }, resource: { type: 'doc', id: 'a' } };
const resourceBody = { subject: subj, action: { name: 'read' }, resource: { type: 'doc' } };
const actionBody = { subject: subj, resource: { type: 'doc', id: 'a' } };

describe('request validation (member table, entities, page)', () => {
  it('entity and action names must be non-empty strings', () => {
    expect(isSubjectSearch({ ...subjectBody, subject: { type: '' } })).toBe(false);
    expect(isSubjectSearch({ ...subjectBody, resource: { type: 'doc', id: '' } })).toBe(false);
    expect(isSubjectSearch({ ...subjectBody, action: { name: '' } })).toBe(false);
    expect(isResourceSearch({ ...resourceBody, resource: { type: '' } })).toBe(false);
    expect(isResourceSearch({ ...resourceBody, subject: { type: 'agent', id: '' } })).toBe(false);
    expect(isSubjectSearch(subjectBody)).toBe(true);
  });
  it('properties, when present, must be records', () => {
    for (const bad of ['x', 5, [], null]) {
      expect(isSubjectSearch({ ...subjectBody, subject: { type: 'user', properties: bad } })).toBe(false);
      expect(isSubjectSearch({ ...subjectBody, resource: { type: 'doc', id: 'a', properties: bad } })).toBe(false);
      expect(isSubjectSearch({ ...subjectBody, action: { name: 'read', properties: bad } })).toBe(false);
    }
    expect(isSubjectSearch({ ...subjectBody, subject: { type: 'user', properties: { a: 1 } }, action: { name: 'read', properties: {} } })).toBe(true);
  });
  it('subject search needs an id on the resource; action search needs ids on both entities and no action', () => {
    expect(isSubjectSearch({ ...subjectBody, resource: { type: 'doc' } })).toBe(false);
    expect(isActionSearch({ ...actionBody, subject: { type: 'agent' } })).toBe(false);
    expect(isActionSearch({ ...actionBody, resource: { type: 'doc' } })).toBe(false);
    expect(isActionSearch(actionBody)).toBe(true);
    expect(isActionSearch({ ...actionBody, action: { name: 'read' } })).toBe(false);
  });
  it('a bad context or page invalidates every search type', () => {
    for (const [check, body] of [[isSubjectSearch, subjectBody], [isResourceSearch, resourceBody], [isActionSearch, actionBody]] as const) {
      expect(check(body)).toBe(true);
      expect(check({ ...body, context: [] })).toBe(false);
      expect(check({ ...body, context: 'x' })).toBe(false);
      expect(check({ ...body, context: { a: 1 } })).toBe(true);
      for (const page of ['x', 5, [], null, { token: 5 }, { limit: '5' }, { limit: -1 }, { limit: 1.5 }, { limit: Number.NaN }, { limit: -0 }, { properties: 'x' }, { properties: [] }]) {
        expect(check({ ...body, page })).toBe(false);
      }
      for (const page of [{}, { token: '' }, { token: 'abc' }, { limit: 0 }, { limit: 1 }, { limit: 1000 }, { token: 't', limit: 5, properties: { a: 1 } }]) {
        expect(check({ ...body, page })).toBe(true);
      }
    }
  });
});

describe('handler responses', () => {
  it('an unsupported search is a 404 with its own message, for each search type', async () => {
    const none = authzenSearchHandler({});
    expect(await none({ path: SEARCH_SUBJECT_PATH, body: subjectBody })).toStrictEqual({ status: 404, body: { error: 'subject search is not supported' } });
    expect(await none({ path: SEARCH_RESOURCE_PATH, body: resourceBody })).toStrictEqual({ status: 404, body: { error: 'resource search is not supported' } });
    expect(await none({ path: SEARCH_ACTION_PATH, body: actionBody })).toStrictEqual({ status: 404, body: { error: 'action search is not supported' } });
  });
  it('an invalid body is a 400 with the message for its search type', async () => {
    const all = authzenSearchHandler({ searchSubject: async () => ({ results: [] }), searchResource: async () => ({ results: [] }), searchAction: async () => ({ results: [] }) });
    expect(await all({ path: SEARCH_SUBJECT_PATH, body: {} })).toStrictEqual({ status: 400, body: { error: 'invalid AuthZEN subject search request' } });
    expect(await all({ path: SEARCH_RESOURCE_PATH, body: {} })).toStrictEqual({ status: 400, body: { error: 'invalid AuthZEN resource search request' } });
    expect(await all({ path: SEARCH_ACTION_PATH, body: {} })).toStrictEqual({ status: 400, body: { error: 'invalid AuthZEN action search request' } });
  });
  it('a failing provider is a generic 500, and a non-search path is not handled', async () => {
    const boom = authzenSearchHandler({ searchResource: async () => { throw new Error('secret'); } });
    expect(await boom({ path: SEARCH_RESOURCE_PATH, body: resourceBody })).toStrictEqual({ status: 500, body: { error: 'internal error' } });
    expect(await boom({ path: '/access/v1/evaluation', body: {} })).toBeUndefined();
  });
  it('subject search strips the queried id and filters by type; no page is not an error', async () => {
    const seen: unknown[] = [];
    const h = authzenSearchHandler({
      async searchSubject(req) {
        seen.push(req);
        return { results: [{ type: 'user', id: 'u1' }, { type: 'device', id: 'd1' }, { type: 'user', id: 'u1' }] };
      },
    });
    const r = await h({ path: SEARCH_SUBJECT_PATH, body: { ...subjectBody, subject: { type: 'user', id: 'steer' } } });
    expect(r).toStrictEqual({ status: 200, body: { results: [{ type: 'user', id: 'u1' }] } });
    expect(seen[0]).toEqual({ ...subjectBody, subject: { type: 'user' } });
  });
  it('resource search without a page succeeds and keeps only the searched type', async () => {
    const h = authzenSearchHandler({ searchResource: async () => ({ results: [{ type: 'doc', id: 'a' }, { type: 'folder', id: 'f' }] }) });
    expect(await h({ path: SEARCH_RESOURCE_PATH, body: resourceBody })).toStrictEqual({ status: 200, body: { results: [{ type: 'doc', id: 'a' }] } });
  });
  it('page and context from the provider are passed through; total is omitted when absent', async () => {
    const h = authzenSearchHandler({
      searchResource: async () => ({ results: [{ type: 'doc', id: 'a' }], page: { next_token: 'n', properties: { p: 1 } }, context: { c: 1 } }),
      searchAction: async () => ({ results: [{ name: 'read' }], page: { next_token: '' } }),
    });
    expect(await h({ path: SEARCH_RESOURCE_PATH, body: resourceBody })).toStrictEqual({
      status: 200,
      body: { page: { next_token: 'n', count: 1, properties: { p: 1 } }, context: { c: 1 }, results: [{ type: 'doc', id: 'a' }] },
    });
    expect(await h({ path: SEARCH_ACTION_PATH, body: actionBody })).toStrictEqual({ status: 200, body: { page: { next_token: '', count: 1 }, results: [{ name: 'read' }] } });
  });
  it('a limit of 0 means no limit; a positive limit caps and a provider that overshoots fails closed', async () => {
    const three: AuthzenSearchProvider = { searchAction: async () => ({ results: [{ name: 'a' }, { name: 'b' }, { name: 'c' }] }) };
    const h = authzenSearchHandler(three);
    const withLimit = (limit: number) => h({ path: SEARCH_ACTION_PATH, body: { ...actionBody, page: { limit } } });
    expect(await withLimit(0)).toMatchObject({ status: 200, body: { results: [{ name: 'a' }, { name: 'b' }, { name: 'c' }] } });
    expect(await withLimit(3)).toMatchObject({ status: 200, body: { results: [{ name: 'a' }, { name: 'b' }, { name: 'c' }] } });
    expect(await withLimit(2)).toStrictEqual({ status: 500, body: { error: 'internal error' } });
  });
  it('action search results are not filtered by type', async () => {
    const h = authzenSearchHandler({ searchAction: async () => ({ results: [{ name: 'read' }, { name: 'write' }] }) });
    expect(((await h({ path: SEARCH_ACTION_PATH, body: actionBody }))!.body as { results: unknown[] }).results).toHaveLength(2);
  });
});
