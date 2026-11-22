import { describe, expect, it } from 'vitest';
import { GrantError } from './grant-resource';
import { grantResourceHandler, type GrantCaller, type GrantHttpRequest } from './http';

function setup(caller: GrantCaller | null = { principal: 'p1' }) {
  const calls: Array<[string, ...unknown[]]> = [];
  const svc = {
    inspect: async (id: string) => (calls.push(['inspect', id]), { id, principal: id === 'other' ? 'p2' : 'p1' }),
    list: async (q: unknown) => (calls.push(['list', q]), { grants: [] }),
    revoke: async (...a: unknown[]) => (calls.push(['revoke', ...a]), { revoked: true }),
    amend: async (...a: unknown[]) => (calls.push(['amend', ...a]), { created: false, grant: { id: 'g' } }),
    requestNeeds: async (...a: unknown[]) => (calls.push(['requestNeeds', ...a]), { ok: true }),
    needGrantId: async (n: string) => (calls.push(['needGrantId', n]), 'g1'),
    approveNeeds: async (...a: unknown[]) => (calls.push(['approveNeeds', ...a]), { grant: { id: 'g2' } }),
    denyNeeds: async (...a: unknown[]) => (calls.push(['denyNeeds', ...a]), undefined),
  };
  const h = grantResourceHandler(svc as never, { authenticate: () => caller });
  const go = (method: string, path: string, extra: Partial<GrantHttpRequest> = {}) => h({ method, path, ...extra });
  return { calls, go };
}
const mutating = (calls: Array<[string, ...unknown[]]>) => calls.filter(([n]) => !['inspect', 'needGrantId'].includes(n));

describe('grant list query', () => {
  it('accepts exactly the three statuses and names a bad one', async () => {
    const { go, calls } = setup();
    for (const status of ['active', 'revoked', 'superseded']) expect((await go('GET', '/pca/grants', { query: { status } })).status).toBe(200);
    expect(calls.filter(([n]) => n === 'list')).toHaveLength(3);
    expect(await go('GET', '/pca/grants', { query: { status: 'nope' } })).toStrictEqual({ status: 400, body: { error: 'bad_request', message: 'bad status' } });
  });
  it('passes only the filters that were given, and scopes a principal caller to itself', async () => {
    const { go, calls } = setup({ principal: 'p1' });
    await go('GET', '/pca/grants', { query: { principal: 'victim', agent: 'a1', status: 'active', limit: '5', cursor: 'c1' } });
    await go('GET', '/pca/grants', { query: { limit: 'x' } });
    await go('GET', '/pca/grants', { query: { limit: '0' } });
    expect(calls.filter(([n]) => n === 'list').map((c) => c[1])).toStrictEqual([
      { principal: 'p1', agent: 'a1', status: 'active', limit: 5, cursor: 'c1' },
      { principal: 'p1' },
      { principal: 'p1', limit: 0 },
    ]);
    const admin = setup({ admin: true });
    await admin.go('GET', '/pca/grants');
    await admin.go('GET', '/pca/grants', { query: { principal: 'p9' } });
    expect(admin.calls.map((c) => c[1])).toStrictEqual([{}, { principal: 'p9' }]);
  });
});

describe('grant routes need the exact method and shape', () => {
  it('only DELETE on a 3-segment path revokes', async () => {
    const { go, calls } = setup();
    expect((await go('DELETE', '/pca/grants/g1/amend')).status).toBe(404);
    expect((await go('DELETE', '/pca/grants/g1/a/b')).status).toBe(404);
    expect((await go('PUT', '/pca/grants/g1')).status).toBe(404);
    expect(mutating(calls)).toHaveLength(0);
  });
  it('revoke passes the scope and the signature; a principal caller without one still signs with an empty string', async () => {
    const { go, calls } = setup();
    await go('DELETE', '/pca/grants/g1', { body: { sig: 's' }, query: { scope: 'agent' } });
    await go('DELETE', '/pca/grants/g1', { body: { sig: 5 } });
    expect(mutating(calls)).toStrictEqual([['revoke', 'g1', 'agent', { sig: 's' }], ['revoke', 'g1', 'grant', { sig: '' }]]);
    const admin = setup({ admin: true });
    await admin.go('DELETE', '/pca/grants/g1', { body: { sig: 5 } });
    await admin.go('DELETE', '/pca/grants/g1', { body: { sig: 's' } });
    expect(mutating(admin.calls)).toStrictEqual([['revoke', 'g1', 'grant', { admin: true }], ['revoke', 'g1', 'grant', { sig: 's' }]]);
  });
  it('amend and needs require POST on exactly 4 segments', async () => {
    const { go, calls } = setup();
    for (const verb of ['amend', 'needs']) {
      expect((await go('GET', `/pca/grants/g1/${verb}`)).status).toBe(404);
      expect((await go('PUT', `/pca/grants/g1/${verb}`)).status).toBe(404);
      expect((await go('POST', `/pca/grants/g1/${verb}/extra`)).status).toBe(404);
    }
    expect((await go('POST', '/pca/grants/g1/other')).status).toBe(404);
    expect(mutating(calls)).toHaveLength(0);
    expect((await go('POST', '/pca/grants/g1/amend', { body: { a: 1 } })).status).toBe(200);
    expect((await go('POST', '/pca/grants/g1/needs', { body: { needs: [1] } })).status).toBe(201);
    expect(mutating(calls)).toStrictEqual([['amend', 'g1', { a: 1 }], ['requestNeeds', 'g1', [1]]]);
  });
});

describe('need routes', () => {
  it('approve and deny live only under /pca/needs/<id>/<verb> with POST', async () => {
    const { go, calls } = setup();
    for (const verb of ['approve', 'deny']) {
      expect((await go('POST', `/pca/grants/g1/${verb}`, { body: { sig: 's', approved: [] } })).status).toBe(404);
      expect((await go('POST', `/pca/other/n1/${verb}`, { body: { sig: 's', approved: [] } })).status).toBe(404);
      expect((await go('GET', `/pca/needs/n1/${verb}`)).status).toBe(404);
    }
    expect((await go('POST', '/pca/needs/n1/zzz')).status).toBe(404);
    expect((await go('POST', '/pca/needs/n1')).status).toBe(404);
    expect(mutating(calls)).toHaveLength(0);
  });
  it('approve needs sig and approved, forwards the optional step-up ref only when a string', async () => {
    const { go, calls } = setup();
    expect(await go('POST', '/pca/needs/n1/approve', { body: { sig: 's' } })).toStrictEqual({ status: 400, body: { error: 'bad_request', message: 'sig and approved are required' } });
    expect((await go('POST', '/pca/needs/n1/approve', { body: { sig: 's', approved: [1], step_up_ref: 'r' } })).status).toBe(201);
    await go('POST', '/pca/needs/n1/approve', { body: { sig: 's', approved: [1], step_up_ref: 5 } });
    expect(mutating(calls)).toStrictEqual([['approveNeeds', 'n1', [1], 's', 'r'], ['approveNeeds', 'n1', [1], 's', undefined]]);
  });
  it('deny answers denied after the owner check', async () => {
    const { go, calls } = setup();
    expect(await go('POST', '/pca/needs/n1/deny')).toStrictEqual({ status: 200, body: { status: 'denied' } });
    expect(mutating(calls)).toStrictEqual([['denyNeeds', 'n1']]);
  });
});
