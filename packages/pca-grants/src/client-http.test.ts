import { describe, expect, it } from 'vitest';
import { generateKeyPair } from '@atlasauth/pca';
import {
  GRANT_AMEND_DOMAIN, GRANT_REVOKE_DOMAIN, GRANT_STEPUP_DOMAIN, NEED_APPROVE_DOMAIN, NEED_REQUEST_DOMAIN, GrantService, MemoryGrantStore, amendMessage, grantRevokeMessage,
  needApproveMessage, type Authority, type Need,
} from './grant-resource';
import { GrantApiError, createGrantClient } from './client';
import { GRANTS_PATH, NEEDS_PATH, grantManagementMetadata, grantResourceHandler, type GrantCaller, type GrantHttpRequest } from './http';
import { signBody, signerOf } from './sig';

const principal = generateKeyPair();
const agent = generateKeyPair();
const P = signerOf(principal.secretKey);
const A = signerOf(agent.secretKey);
const Q = signerOf(generateKeyPair().secretKey);
const AUTH: Authority = { verbs: ['read', 'pay'], resources: ['acct/1/*'], limits: { 'money.usd': 100 }, expires_at: 10_000 };
const need: Need = { verb: 'pay', resource: 'acct/9/*', limits: { 'money.usd': 400 }, adjustable: true };

async function setup() {
  let n = 0;
  const svc = new GrantService({ store: new MemoryGrantStore(), now: () => 1000, newId: (k) => `${k[0]}_${++n}`, verifyStepUp: (r) => r === 'ok' });
  await svc.register({ id: 'g_0', principal: P, agent: A, authority: AUTH, chain_digest: 'cd' });
  await svc.register({ id: 'g_q', principal: Q, agent: A, authority: AUTH, chain_digest: 'cd' });
  return svc;
}
const who = (r: GrantHttpRequest): GrantCaller | null => (r.query?.as === 'admin' ? { admin: true } : r.query?.as === 'p' ? { principal: P } : r.query?.as === 'none' ? {} : null);

describe('grant HTTP binding: authentication and routing fail closed', () => {
  it('pins the mount paths and the discovery fragment', () => {
    expect(GRANTS_PATH).toBe('/pca/grants');
    expect(NEEDS_PATH).toBe('/pca/needs');
    expect(grantManagementMetadata('https://as.example')).toEqual({
      grant_management: { grants_endpoint: 'https://as.example/pca/grants', needs_endpoint: 'https://as.example/pca/needs', amend_actions: ['narrow', 'merge', 'replace'], revoke_scopes: ['grant', 'agent', 'subtree'], widening: 'new_grant_id_with_supersedes' },
    });
  });
  it('no caller, or a caller with neither principal nor admin, is 401; an authenticator that throws is 500 without detail', async () => {
    const h = grantResourceHandler(await setup(), { authenticate: who });
    expect(await h({ method: 'GET', path: '/pca/grants' })).toEqual({ status: 401, body: { error: 'unauthenticated' } });
    expect(await h({ method: 'GET', path: '/pca/grants', query: { as: 'none' } })).toEqual({ status: 401, body: { error: 'unauthenticated' } });
    const boom = grantResourceHandler(await setup(), { authenticate: () => { throw new Error('secret db password'); } });
    expect(await boom({ method: 'GET', path: '/pca/grants', query: { as: 'admin' } })).toEqual({ status: 500, body: { error: 'server_error' } });
  });
  it('unknown paths, methods and missing ids are 404', async () => {
    const h = grantResourceHandler(await setup(), { authenticate: who });
    for (const [method, path] of [['GET', '/other/grants'], ['GET', '/pca/nope'], ['POST', '/pca/grants'], ['PATCH', '/pca/grants/g_0'], ['GET', '/pca/grants/g_0/zzz'], ['GET', '/pca/needs/x/approve'], ['GET', '/pca/needs/x/deny']] as const) {
      expect(await h({ method, path, query: { as: 'admin' } })).toEqual({ status: 404, body: { error: 'not_found' } });
    }
  });
  it('a principal-scoped caller cannot learn that another principal grant exists (404 with the same message as a missing one)', async () => {
    const h = grantResourceHandler(await setup(), { authenticate: who });
    const other = await h({ method: 'GET', path: '/pca/grants/g_q', query: { as: 'p' } });
    const missing = await h({ method: 'GET', path: '/pca/grants/g_zz', query: { as: 'p' } });
    expect(other).toEqual({ status: 404, body: { error: 'not_found', message: 'no such grant' } });
    expect(other).toEqual(missing);
    for (const method of ['DELETE', 'POST'] as const) expect((await h({ method, path: '/pca/grants/g_q/amend', query: { as: 'p' }, body: {} })).status).toBe(404);
    expect((await h({ method: 'DELETE', path: '/pca/grants/g_q', query: { as: 'p' } })).status).toBe(404);
    expect((await h({ method: 'POST', path: '/pca/grants/g_q/needs', query: { as: 'p' }, body: { needs: [need] } })).status).toBe(404);
  });
  it('a principal list is forced to its own grants even when it asks for another principal; an admin may filter', async () => {
    const h = grantResourceHandler(await setup(), { authenticate: who });
    const ids = async (query: Record<string, string>) => ((await h({ method: 'GET', path: '/pca/grants', query })).body as { grants: { id: string }[] }).grants.map((g) => g.id);
    expect(await ids({ as: 'p', principal: Q })).toEqual(['g_0']);
    expect(await ids({ as: 'admin', principal: Q })).toEqual(['g_q']);
    expect(await ids({ as: 'admin', agent: A, status: 'active', limit: '1' })).toEqual(['g_0']);
    expect(await ids({ as: 'admin', limit: 'abc' })).toEqual(['g_0', 'g_q']); // a non-numeric limit is dropped, not honoured
  });
  it('revoke: a principal must sign; an admin without a signature may revoke; a present bad signature is 401 even for an admin; a bad scope is 400', async () => {
    const svc = await setup();
    const h = grantResourceHandler(svc, { authenticate: who });
    expect(await h({ method: 'DELETE', path: '/pca/grants/g_0', query: { as: 'p' } })).toEqual({ status: 401, body: { error: 'bad_signature', message: 'the signature does not verify for this grant revision' } });
    expect((await h({ method: 'DELETE', path: '/pca/grants/g_0', query: { as: 'admin' }, body: { sig: 'AAAA' } })).status).toBe(401);
    expect((await h({ method: 'DELETE', path: '/pca/grants/g_0', query: { as: 'admin', scope: 'bogus' } })).status).toBe(400);
    const sig = signBody(GRANT_REVOKE_DOMAIN, grantRevokeMessage('g_0', 'grant'), principal.secretKey);
    expect(await h({ method: 'DELETE', path: '/pca/grants/g_0', query: { as: 'p' }, body: { sig } })).toEqual({ status: 200, body: { revoked: ['g_0'] } });
    expect(await h({ method: 'DELETE', path: '/pca/grants/g_0', query: { as: 'p' }, body: { sig } })).toEqual({ status: 200, body: { revoked: [] } });
  });
  it('amend: 200 in place when narrowing, 201 with a new grant when widening, 400 for a missing body, 409 for a revoked grant', async () => {
    const svc = await setup();
    const h = grantResourceHandler(svc, { authenticate: who });
    const less: Authority = { ...AUTH, verbs: ['read'] };
    const sig = signBody(GRANT_AMEND_DOMAIN, amendMessage({ id: 'g_0', rev: 1 }, 'narrow', less), principal.secretKey);
    const r = await h({ method: 'POST', path: '/pca/grants/g_0/amend', query: { as: 'p' }, body: { action: 'narrow', authority: less, sig, signed_by: 'principal' } });
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ id: 'g_0', rev: 2, authority: less });
    const wider: Authority = { ...AUTH, verbs: ['read', 'pay', 'delete'] };
    const wsig = signBody(GRANT_AMEND_DOMAIN, amendMessage({ id: 'g_0', rev: 2 }, 'replace', wider), principal.secretKey);
    const w = await h({ method: 'POST', path: '/pca/grants/g_0/amend', query: { as: 'p' }, body: { action: 'replace', authority: wider, sig: wsig, signed_by: 'principal' } });
    expect(w).toEqual({ status: 403, body: { error: 'step_up_required', message: 'widening needs a satisfied step-up' } });
    const ok = await h({ method: 'POST', path: '/pca/grants/g_0/amend', query: { as: 'p' }, body: { action: 'replace', authority: wider, sig: wsig, signed_by: 'principal', step_up_ref: 'ok' } });
    expect(ok.status).toBe(201);
    expect(ok.body).toMatchObject({ supersedes: 'g_0', rev: 1 });
    expect((await h({ method: 'POST', path: '/pca/grants/g_0/amend', query: { as: 'p' }, body: { action: 'narrow', authority: less } })).status).toBe(409); // g_0 is superseded: not_active
    expect(await h({ method: 'POST', path: '/pca/grants/g_q/amend', query: { as: 'admin' } })).toEqual({ status: 400, body: { error: 'bad_request', message: 'malformed request' } });
  });
  it('needs: file, approve (principal only, with a signature and an array), deny; another principal cannot touch the need request', async () => {
    const svc = await setup();
    const h = grantResourceHandler(svc, { authenticate: (r) => (r.query?.as === 'q' ? { principal: Q } : who(r)) });
    expect(await h({ method: 'POST', path: '/pca/grants/g_0/needs', query: { as: 'p' }, body: {} })).toEqual({ status: 400, body: { error: 'bad_request', message: '1..32 needs' } });
    const filed = await h({ method: 'POST', path: '/pca/grants/g_0/needs', query: { as: 'p' }, body: { needs: [need] } });
    expect(filed.status).toBe(201);
    const nid = (filed.body as { id: string }).id;
    // another principal sees neither approve nor deny: 404, and the request stays pending
    expect((await h({ method: 'POST', path: `/pca/needs/${nid}/deny`, query: { as: 'q' } })).status).toBe(404);
    expect((await h({ method: 'POST', path: `/pca/needs/${nid}/approve`, query: { as: 'q' }, body: { sig: 'x', approved: [need] } })).status).toBe(404);
    expect((await svc.inspect('g_0')).pending_needs).toEqual([nid]);
    expect((await h({ method: 'POST', path: '/pca/needs/missing/deny', query: { as: 'admin' } })).status).toBe(404);
    expect(await h({ method: 'POST', path: `/pca/needs/${nid}/approve`, query: { as: 'p' }, body: { approved: [need] } })).toEqual({ status: 400, body: { error: 'bad_request', message: 'sig and approved are required' } });
    expect((await h({ method: 'POST', path: `/pca/needs/${nid}/approve`, query: { as: 'p' }, body: { sig: 'x', approved: 'no' } })).status).toBe(400);
    const sig = signBody(NEED_APPROVE_DOMAIN, needApproveMessage({ id: nid, grant_id: 'g_0' }, 1, [need]), principal.secretKey);
    const a = await h({ method: 'POST', path: `/pca/needs/${nid}/approve`, query: { as: 'p' }, body: { sig, approved: [need], step_up_ref: 'ok' } });
    expect(a.status).toBe(201);
    expect(a.body).toMatchObject({ supersedes: 'g_0' });
    expect((await h({ method: 'POST', path: `/pca/needs/${nid}/deny`, query: { as: 'p' } })).status).toBe(409);
    const filed2 = await h({ method: 'POST', path: '/pca/grants/g_q/needs', query: { as: 'q' }, body: { needs: [need] } });
    expect(await h({ method: 'POST', path: `/pca/needs/${(filed2.body as { id: string }).id}/deny`, query: { as: 'q' } })).toEqual({ status: 200, body: { status: 'denied' } });
  });
});

describe('grant client', () => {
  const FRESH = { revocation_epoch: 2, ledger_tree_size: 5, budget_version: 1, policy_revision: 1 };
  type Call = { url: string; init: RequestInit };
  const mk = (reply: (c: Call) => { status?: number; body?: unknown; token?: string; badJson?: boolean }) => {
    const calls: Call[] = [];
    const fetch = (async (url: string, init: RequestInit) => {
      const c = { url, init };
      calls.push(c);
      const r = reply(c);
      const status = r.status ?? 200;
      return { ok: status < 400, status, statusText: 'Boom', headers: { get: (k: string) => (k === 'pca-fresh-at' ? r.token ?? null : null) }, json: async () => { if (r.badJson) throw new Error('not json'); return r.body ?? {}; } } as unknown as Response;
    }) as unknown as typeof globalThis.fetch;
    return { calls, fetch };
  };
  it('builds exact requests: trailing slash trimmed, encoded ids, query without undefined, revoke default scope, bodies only when present', async () => {
    const { calls, fetch } = mk(() => ({ body: { grants: [] } }));
    const c = createGrantClient({ baseUrl: 'https://as.example/', fetch, headers: async () => ({ authorization: 'Bearer t' }) });
    await c.list({ principal: P, status: undefined, limit: 5 });
    await c.list();
    await c.inspect('a/b c');
    await c.revoke('g_0');
    await c.revoke('g_0', 'subtree', 'SIG');
    await c.amend('g_0', { action: 'narrow', authority: AUTH });
    await c.requestNeeds('g_0', [need]);
    await c.approveNeeds('n_1', [need], 'SIG');
    await c.approveNeeds('n_1', [need], 'SIG', 'ref');
    await c.denyNeeds('n_1');
    expect(calls.map((x) => `${x.init.method} ${x.url}`)).toEqual([
      `GET https://as.example/pca/grants?principal=${encodeURIComponent(P)}&limit=5`,
      'GET https://as.example/pca/grants',
      'GET https://as.example/pca/grants/a%2Fb%20c',
      'DELETE https://as.example/pca/grants/g_0?scope=grant',
      'DELETE https://as.example/pca/grants/g_0?scope=subtree',
      'POST https://as.example/pca/grants/g_0/amend',
      'POST https://as.example/pca/grants/g_0/needs',
      'POST https://as.example/pca/needs/n_1/approve',
      'POST https://as.example/pca/needs/n_1/approve',
      'POST https://as.example/pca/needs/n_1/deny',
    ]);
    expect(calls[0]!.init.headers).toEqual({ 'content-type': 'application/json', authorization: 'Bearer t' });
    expect(calls[0]!.init.body).toBeUndefined();
    expect(calls[3]!.init.body).toBeUndefined();
    expect(calls[4]!.init.body).toBe('{"sig":"SIG"}');
    expect(JSON.parse(String(calls[6]!.init.body))).toEqual({ needs: [need] });
    expect(JSON.parse(String(calls[7]!.init.body))).toEqual({ approved: [need], sig: 'SIG' });
    expect(JSON.parse(String(calls[8]!.init.body))).toEqual({ approved: [need], sig: 'SIG', step_up_ref: 'ref' });
  });
  it('sends the newest consistency token on later requests; an older or incomparable token never replaces it; a malformed header is ignored', async () => {
    const replies = [{ token: JSON.stringify(FRESH) }, { token: JSON.stringify({ ...FRESH, revocation_epoch: 1 }) }, { token: JSON.stringify({ ...FRESH, revocation_epoch: 3, ledger_tree_size: 4 }) }, { token: 'not json' }, { token: JSON.stringify({ ...FRESH, revocation_epoch: 3, ledger_tree_size: 9 }) }];
    let i = 0;
    const { calls, fetch } = mk(() => replies[i++] ?? {});
    const c = createGrantClient({ baseUrl: 'https://as.example', fetch });
    expect(c.freshAt).toBeUndefined();
    await c.inspect('a');
    expect(c.freshAt).toEqual(FRESH);
    await c.inspect('a');
    expect(c.freshAt).toEqual(FRESH);
    await c.inspect('a');
    expect(c.freshAt).toEqual(FRESH); // epoch up but tree size down: incomparable, kept
    await c.inspect('a');
    expect(c.freshAt).toEqual(FRESH);
    await c.inspect('a');
    expect(c.freshAt).toEqual({ ...FRESH, revocation_epoch: 3, ledger_tree_size: 9 });
    expect((calls[0]!.init.headers as Record<string, string>)['pca-fresh-at']).toBeUndefined();
    expect(JSON.parse((calls[1]!.init.headers as Record<string, string>)['pca-fresh-at']!)).toEqual(FRESH);
  });
  it('with a pinned signer, an unsigned or forged token is ignored', async () => {
    const { fetch } = mk(() => ({ token: JSON.stringify(FRESH) }));
    const c = createGrantClient({ baseUrl: 'https://as.example', fetch, freshSigner: Q });
    await c.inspect('a');
    expect(c.freshAt).toBeUndefined();
    expect(c.foldFreshAt({} as never)).toBeUndefined();
  });
  it('an error response becomes a typed GrantApiError; an unparseable error body falls back to the status text', async () => {
    const e1 = mk(() => ({ status: 404, body: { error: 'not_found', message: 'no such grant' } }));
    const err = await createGrantClient({ baseUrl: 'https://as.example', fetch: e1.fetch }).inspect('x').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(GrantApiError);
    expect(err).toMatchObject({ status: 404, code: 'not_found', message: 'no such grant', name: 'GrantApiError' });
    const e2 = mk(() => ({ status: 502, badJson: true }));
    await expect(createGrantClient({ baseUrl: 'https://as.example', fetch: e2.fetch }).inspect('x')).rejects.toMatchObject({ status: 502, code: 'error', message: 'Boom' });
  });
  it('pins the remaining signature domains', () => {
    expect(GRANT_AMEND_DOMAIN).toBe('atlas-pca/grant-amend/v1\0');
    expect(GRANT_REVOKE_DOMAIN).toBe('atlas-pca/grant-revoke/v1\0');
    expect(NEED_APPROVE_DOMAIN).toBe('atlas-pca/need-approve/v1\0');
    expect(NEED_REQUEST_DOMAIN).toBe('atlas-pca/need-request/v1\0');
    expect(GRANT_STEPUP_DOMAIN).toBe('atlas-pca/grant-stepup/v1\0');
  });
});
