import { describe, expect, it } from 'vitest';
import { SEARCH_ACTION_PATH, SEARCH_RESOURCE_PATH, SEARCH_SUBJECT_PATH, authzenSearchHandler, searchMetadata, type AuthzenSearchProvider, type ResourceSearchRequest } from './search';

const DOCS = ['a', 'b', 'c', 'd', 'e'].map((id) => ({ type: 'doc', id }));
const seen: ResourceSearchRequest[] = [];
const provider: AuthzenSearchProvider = {
  async searchResource(req) {
    seen.push(req);
    const start = req.page?.token ? Number(req.page.token) : 0;
    const limit = req.page?.limit ?? 2;
    const results = DOCS.slice(start, start + limit);
    return { results, page: { next_token: start + limit < DOCS.length ? String(start + limit) : '', total: DOCS.length } };
  },
  async searchAction() {
    return { results: [{ name: 'read' }, { name: 'write' }, { name: 'read' }] };
  },
  async searchSubject(req) {
    return { results: [{ type: req.subject.type, id: 'u1' }, { type: 'device', id: 'd1' }] };
  },
};
const h = authzenSearchHandler(provider);
const subj = { type: 'agent', id: 'a1' };

describe('AuthZEN search', () => {
  it('resource search pages to the end with count/total and the empty-string end marker', async () => {
    const body = { subject: subj, action: { name: 'read' }, resource: { type: 'doc' }, page: { limit: 2 } };
    const p1 = await h({ path: SEARCH_RESOURCE_PATH, body });
    expect(p1).toEqual({ status: 200, body: { page: { next_token: '2', count: 2, total: 5 }, results: DOCS.slice(0, 2) } });
    const p3 = await h({ path: SEARCH_RESOURCE_PATH, body: { ...body, page: { limit: 2, token: '4' } } });
    expect(p3).toEqual({ status: 200, body: { page: { next_token: '', count: 1, total: 5 }, results: DOCS.slice(4) } });
  });
  it('the queried entity id is ignored (stripped before the provider sees it)', async () => {
    seen.length = 0;
    await h({ path: SEARCH_RESOURCE_PATH, body: { subject: subj, action: { name: 'read' }, resource: { type: 'doc', id: 'steer' } } });
    expect(seen[0]!.resource).toEqual({ type: 'doc' });
  });
  it('results are only entities of the searched type, de-duplicated', async () => {
    const r = await h({ path: SEARCH_SUBJECT_PATH, body: { subject: { type: 'user' }, action: { name: 'read' }, resource: { type: 'doc', id: 'a' } } });
    expect(r!.body).toEqual({ results: [{ type: 'user', id: 'u1' }] });
    const a = await h({ path: SEARCH_ACTION_PATH, body: { subject: subj, resource: { type: 'doc', id: 'a' } } });
    expect(a!.body).toEqual({ results: [{ name: 'read' }, { name: 'write' }] });
  });
  it('the member table per search type is enforced (400)', async () => {
    const bad: Array<[string, unknown]> = [
      [SEARCH_RESOURCE_PATH, { subject: subj, action: { name: 'read' } }],
      [SEARCH_RESOURCE_PATH, { subject: { type: 'agent' }, action: { name: 'read' }, resource: { type: 'doc' } }],
      [SEARCH_RESOURCE_PATH, { subject: subj, action: { name: 'read' }, resource: { type: 'doc' }, page: { limit: -1 } }],
      [SEARCH_RESOURCE_PATH, { subject: subj, action: { name: 'read' }, resource: { type: 'doc' }, page: { limit: 1.5 } }],
      [SEARCH_RESOURCE_PATH, { subject: subj, action: { name: 'read' }, resource: { type: 'doc' }, context: [] }],
      [SEARCH_ACTION_PATH, { subject: subj, action: { name: 'read' }, resource: { type: 'doc', id: 'a' } }],
      [SEARCH_ACTION_PATH, { subject: subj, resource: { type: 'doc' } }],
      [SEARCH_SUBJECT_PATH, { subject: { type: 'user' }, resource: { type: 'doc', id: 'a' } }],
      [SEARCH_SUBJECT_PATH, null],
    ];
    for (const [path, body] of bad) expect(await h({ path, body })).toMatchObject({ status: 400 });
  });
  it('an unsupported search is 404, a non-search path falls through, a provider that ignores the limit fails closed', async () => {
    const only = authzenSearchHandler({ searchAction: provider.searchAction! });
    expect(await only({ path: SEARCH_RESOURCE_PATH, body: {} })).toMatchObject({ status: 404 });
    expect(await h({ path: '/access/v1/evaluation', body: {} })).toBeUndefined();
    const greedy = authzenSearchHandler({ searchResource: async () => ({ results: DOCS, page: { next_token: '' } }) });
    expect(await greedy({ path: SEARCH_RESOURCE_PATH, body: { subject: subj, action: { name: 'read' }, resource: { type: 'doc' }, page: { limit: 2 } } })).toMatchObject({ status: 500 });
  });
  it('metadata advertises exactly the supported searches', () => {
    expect(searchMetadata('https://pdp.example', provider)).toEqual({
      search_subject_endpoint: 'https://pdp.example/access/v1/search/subject',
      search_resource_endpoint: 'https://pdp.example/access/v1/search/resource',
      search_action_endpoint: 'https://pdp.example/access/v1/search/action',
    });
    expect(searchMetadata('https://pdp.example', { searchAction: provider.searchAction! })).toEqual({ search_action_endpoint: 'https://pdp.example/access/v1/search/action' });
  });
});
