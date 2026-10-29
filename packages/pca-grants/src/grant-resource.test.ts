import { beforeEach, describe, expect, it } from 'vitest';
import { generateKeyPair } from '@atlasauth/pca';
import {
  GRANT_AMEND_DOMAIN, GRANT_REVOKE_DOMAIN, GrantError, GrantService, MemoryGrantStore, NEED_APPROVE_DOMAIN, amendMessage, authorityDigest, compareAuthority,
  grantRevokeMessage, needApproveMessage, type Authority, type GrantRecord, type Need,
} from './grant-resource';
import { createGrantClient } from './client';
import { grantManagementMetadata, grantResourceHandler } from './http';
import { signBody, signerOf } from './sig';

const principal = generateKeyPair();
const agent = generateKeyPair();
const stranger = generateKeyPair();
const P = signerOf(principal.secretKey);
const A = signerOf(agent.secretKey);

const AUTH: Authority = { verbs: ['read', 'pay'], resources: ['acct/1/*'], limits: { 'money.usd': 100 }, expires_at: 10_000 };

function make() {
  let n = 0;
  const events: string[] = [];
  const steps = new Set(['stepup-ok']);
  const svc = new GrantService({
    store: new MemoryGrantStore(), now: () => 1000, newId: (k) => `${k[0]}_${++n}`,
    verifyStepUp: (ref) => steps.has(ref),
    onRevoke: (ids, scope) => { events.push(`revoke:${scope}:${ids.join(',')}`); },
    onChange: (kind) => { events.push(kind); },
    providers: { usage: () => ({ spent: 12 }), remainingBudget: () => ({ 'money.usd': 88 }) },
  });
  return { svc, events };
}
const reg = (svc: GrantService, over: Partial<GrantRecord> = {}) =>
  svc.register({ id: 'g_0', principal: P, agent: A, authority: AUTH, chain_digest: 'cd', ...over });
const amendSig = (g: { id: string; rev: number }, action: 'narrow' | 'merge' | 'replace', a: Authority, k = principal) =>
  signBody(GRANT_AMEND_DOMAIN, amendMessage(g, action, a), k.secretKey);

describe('compareAuthority', () => {
  it('orders verbs, resources, ceilings and expiry; incomparable and unbounded-to-bounded are classified', () => {
    expect(compareAuthority(AUTH, AUTH)).toBe('equal');
    expect(compareAuthority(AUTH, { ...AUTH, verbs: ['read'] })).toBe('narrower');
    expect(compareAuthority(AUTH, { ...AUTH, verbs: ['read', 'pay', 'delete'] })).toBe('wider');
    expect(compareAuthority(AUTH, { ...AUTH, limits: { 'money.usd': 50 } })).toBe('narrower');
    expect(compareAuthority(AUTH, { ...AUTH, limits: { 'money.usd': 500 } })).toBe('wider');
    expect(compareAuthority(AUTH, { ...AUTH, limits: {} })).toBe('wider');
    expect(compareAuthority(AUTH, { ...AUTH, expires_at: undefined })).toBe('wider');
    expect(compareAuthority(AUTH, { ...AUTH, resources: ['acct/1/x'] })).toBe('narrower');
    expect(compareAuthority(AUTH, { ...AUTH, resources: ['acct/*'] })).toBe('wider');
    expect(compareAuthority(AUTH, { ...AUTH, verbs: ['read', 'x'], limits: { 'money.usd': 1 } })).toBe('incomparable');
    expect(authorityDigest({ ...AUTH, verbs: ['pay', 'read'] })).toBe(authorityDigest(AUTH));
  });
});

describe('GrantService', () => {
  let svc: GrantService;
  let events: string[];
  beforeEach(async () => {
    ({ svc, events } = make());
    await reg(svc);
  });

  it('lists with filters and pages, inspects with usage and budget', async () => {
    await reg(svc, { id: 'g_1', agent: signerOf(stranger.secretKey) });
    expect((await svc.list({ agent: A })).grants.map((g) => g.id)).toEqual(['g_0']);
    expect((await svc.list({ principal: P })).grants.map((g) => g.id)).toEqual(['g_0', 'g_1']);
    const p1 = await svc.list({ limit: 1 });
    expect(p1.grants.map((g) => g.id)).toEqual(['g_0']);
    expect((await svc.list({ limit: 1, cursor: p1.next_cursor! })).grants.map((g) => g.id)).toEqual(['g_1']);
    const v = await svc.inspect('g_0');
    expect(v).toMatchObject({ id: 'g_0', status: 'active', rev: 1, usage: { spent: 12 }, remaining_budget: { 'money.usd': 88 }, pending_needs: [], authority_digest: authorityDigest(AUTH) });
    await expect(svc.inspect('nope')).rejects.toMatchObject({ code: 'not_found' });
  });

  it('narrow by the HOLDER revises in place; the same signature cannot be replayed on the next revision', async () => {
    const less: Authority = { ...AUTH, verbs: ['read'] };
    const sig = amendSig({ id: 'g_0', rev: 1 }, 'narrow', less, agent);
    const r = await svc.amend('g_0', { action: 'narrow', authority: less, sig, signed_by: 'holder' });
    expect(r.created).toBe(false);
    expect(r.grant).toMatchObject({ id: 'g_0', rev: 2, authority: less });
    await expect(svc.amend('g_0', { action: 'narrow', authority: { ...less, verbs: [] }, sig, signed_by: 'holder' })).rejects.toMatchObject({ code: 'bad_signature' });
  });

  it('a narrow that widens, or changes nothing, is refused; an unsigned or wrongly signed amendment is refused', async () => {
    const wider: Authority = { ...AUTH, verbs: ['read', 'pay', 'delete'] };
    await expect(svc.amend('g_0', { action: 'narrow', authority: wider, sig: amendSig({ id: 'g_0', rev: 1 }, 'narrow', wider), signed_by: 'principal' })).rejects.toMatchObject({ code: 'not_narrower' });
    await expect(svc.amend('g_0', { action: 'narrow', authority: AUTH, sig: amendSig({ id: 'g_0', rev: 1 }, 'narrow', AUTH, agent), signed_by: 'holder' })).rejects.toMatchObject({ code: 'not_narrower' });
    const less: Authority = { ...AUTH, verbs: ['read'] };
    await expect(svc.amend('g_0', { action: 'narrow', authority: less })).rejects.toMatchObject({ code: 'signature_required' });
    await expect(svc.amend('g_0', { action: 'narrow', authority: less, sig: amendSig({ id: 'g_0', rev: 1 }, 'narrow', less, stranger), signed_by: 'holder' })).rejects.toMatchObject({ code: 'bad_signature' });
  });

  it('widening needs the PRINCIPAL signature AND a step-up, and makes a new grant id with supersedes (nothing widens in place)', async () => {
    const wider: Authority = { ...AUTH, verbs: ['read', 'pay', 'delete'] };
    const holderSig = amendSig({ id: 'g_0', rev: 1 }, 'replace', wider, agent);
    await expect(svc.amend('g_0', { action: 'replace', authority: wider, sig: holderSig, signed_by: 'holder', step_up_ref: 'stepup-ok' })).rejects.toMatchObject({ code: 'signature_required' });
    const sig = amendSig({ id: 'g_0', rev: 1 }, 'replace', wider);
    await expect(svc.amend('g_0', { action: 'replace', authority: wider, sig, signed_by: 'principal' })).rejects.toMatchObject({ code: 'step_up_required' });
    await expect(svc.amend('g_0', { action: 'replace', authority: wider, sig, signed_by: 'principal', step_up_ref: 'bogus' })).rejects.toMatchObject({ code: 'step_up_required' });
    const r = await svc.amend('g_0', { action: 'replace', authority: wider, sig, signed_by: 'principal', step_up_ref: 'stepup-ok' });
    expect(r.created).toBe(true);
    expect(r.grant).toMatchObject({ id: 'g_1', supersedes: 'g_0', rev: 1, authority: wider });
    expect(await svc.inspect('g_0')).toMatchObject({ status: 'superseded', superseded_by: 'g_1', authority: AUTH });
    await expect(svc.amend('g_0', { action: 'narrow', authority: { ...AUTH, verbs: ['read'] }, sig: amendSig({ id: 'g_0', rev: 1 }, 'narrow', { ...AUTH, verbs: ['read'] }), signed_by: 'principal' })).rejects.toMatchObject({ code: 'not_active' });
  });

  it('merge unions authority and keeps old ceilings the delta omits; without a verifier the widening fails closed', async () => {
    const delta: Authority = { verbs: ['delete'], resources: ['acct/2/*'], limits: { 'money.usd': 300 }, expires_at: 20_000 };
    const sig = amendSig({ id: 'g_0', rev: 1 }, 'merge', delta);
    const r = await svc.amend('g_0', { action: 'merge', authority: delta, sig, signed_by: 'principal', step_up_ref: 'stepup-ok' });
    expect(r.grant.authority).toEqual({ verbs: ['read', 'pay', 'delete'], resources: ['acct/1/*', 'acct/2/*'], limits: { 'money.usd': 300 }, expires_at: 20_000 });
    const noStep = new GrantService({ store: new MemoryGrantStore(), now: () => 1, newId: () => 'x' });
    await noStep.register({ id: 'g_0', principal: P, agent: A, authority: AUTH, chain_digest: 'cd' });
    await expect(noStep.amend('g_0', { action: 'merge', authority: delta, sig, signed_by: 'principal', step_up_ref: 'stepup-ok' })).rejects.toMatchObject({ code: 'step_up_required' });
  });

  it('revoke: signed by the principal or admin; agent and subtree scopes reach the right grants; the host hook fires', async () => {
    await reg(svc, { id: 'g_c', parent: 'g_0' });
    await reg(svc, { id: 'g_cc', parent: 'g_c' });
    await reg(svc, { id: 'g_other', agent: signerOf(stranger.secretKey) });
    await expect(svc.revoke('g_0', 'grant', { sig: signBody(GRANT_REVOKE_DOMAIN, grantRevokeMessage('g_0', 'grant'), stranger.secretKey) })).rejects.toMatchObject({ code: 'bad_signature' });
    // a signature for scope=grant does not authorise scope=subtree
    await expect(svc.revoke('g_0', 'subtree', { sig: signBody(GRANT_REVOKE_DOMAIN, grantRevokeMessage('g_0', 'grant'), principal.secretKey) })).rejects.toMatchObject({ code: 'bad_signature' });
    const r = await svc.revoke('g_0', 'subtree', { sig: signBody(GRANT_REVOKE_DOMAIN, grantRevokeMessage('g_0', 'subtree'), principal.secretKey) });
    expect(r.revoked).toEqual(['g_0', 'g_c', 'g_cc']);
    expect(events).toContain('revoke:subtree:g_0,g_c,g_cc');
    expect((await svc.inspect('g_other')).status).toBe('active');
    expect((await svc.revoke('g_other', 'grant', { admin: true })).revoked).toEqual(['g_other']);
    expect((await svc.revoke('g_other', 'grant', { admin: true })).revoked).toEqual([]);
    await reg(svc, { id: 'g_a1' });
    await reg(svc, { id: 'g_a2' });
    expect((await svc.revoke('g_a1', 'agent', { admin: true })).revoked).toEqual(['g_a1', 'g_a2']);
    await expect(svc.revoke('g_a1', 'bogus' as never, { admin: true })).rejects.toMatchObject({ code: 'bad_request' });
  });

  describe('incremental authorization', () => {
    const need: Need = { verb: 'pay', resource: 'acct/9/*', limits: { 'money.usd': 400 }, adjustable: true };
    const approve = (id: string, rev: number, approved: Need[], k = principal) => signBody(NEED_APPROVE_DOMAIN, needApproveMessage({ id, grant_id: 'g_0' }, rev, approved), k.secretKey);

    it('the agent files typed needs; the principal approves a LOWERED amount of an adjustable need and gets a new grant', async () => {
      const nr = await svc.requestNeeds('g_0', [need]);
      expect(nr).toMatchObject({ status: 'pending', grant_id: 'g_0' });
      expect((await svc.inspect('g_0')).pending_needs).toEqual([nr.id]);
      const lowered: Need[] = [{ ...need, limits: { 'money.usd': 250 } }];
      const r = await svc.approveNeeds(nr.id, lowered, approve(nr.id, 1, lowered), 'stepup-ok');
      expect(r.grant.authority).toEqual({ verbs: ['read', 'pay'], resources: ['acct/1/*', 'acct/9/*'], limits: { 'money.usd': 250 }, expires_at: 10_000 });
      expect(r.grant.supersedes).toBe('g_0');
      await expect(svc.approveNeeds(nr.id, lowered, approve(nr.id, 1, lowered), 'stepup-ok')).rejects.toMatchObject({ code: 'conflict' });
    });
    it('an approval cannot raise an amount, change the target, lower a non-adjustable need, or come from anyone but the principal', async () => {
      const nr = await svc.requestNeeds('g_0', [need]);
      const raise: Need[] = [{ ...need, limits: { 'money.usd': 401 } }];
      await expect(svc.approveNeeds(nr.id, raise, approve(nr.id, 1, raise), 'stepup-ok')).rejects.toMatchObject({ code: 'need_not_lowered_only' });
      const other: Need[] = [{ ...need, resource: 'acct/*' }];
      await expect(svc.approveNeeds(nr.id, other, approve(nr.id, 1, other), 'stepup-ok')).rejects.toMatchObject({ code: 'need_not_lowered_only' });
      await expect(svc.approveNeeds(nr.id, [need], approve(nr.id, 1, [need], stranger), 'stepup-ok')).rejects.toMatchObject({ code: 'bad_signature' });
      await expect(svc.approveNeeds(nr.id, [need], approve(nr.id, 1, [need]))).rejects.toMatchObject({ code: 'step_up_required' });
      const fixed: Need = { ...need, adjustable: false };
      const nr2 = await svc.requestNeeds('g_0', [fixed]);
      const lower: Need[] = [{ ...fixed, limits: { 'money.usd': 1 } }];
      await expect(svc.approveNeeds(nr2.id, lower, approve(nr2.id, 1, lower), 'stepup-ok')).rejects.toMatchObject({ code: 'need_not_adjustable' });
    });
    it('malformed needs and denied needs', async () => {
      await expect(svc.requestNeeds('g_0', [])).rejects.toMatchObject({ code: 'bad_request' });
      await expect(svc.requestNeeds('g_0', [{ verb: '', resource: 'x' }])).rejects.toMatchObject({ code: 'bad_request' });
      await expect(svc.requestNeeds('g_0', [{ verb: 'v', resource: 'x', limits: { a: -1 } }])).rejects.toMatchObject({ code: 'bad_request' });
      const nr = await svc.requestNeeds('g_0', [need]);
      await svc.denyNeeds(nr.id);
      await expect(svc.denyNeeds(nr.id)).rejects.toMatchObject({ code: 'conflict' });
      expect((await svc.inspect('g_0')).pending_needs).toEqual([]);
    });
  });

  it('GrantError carries its code', () => {
    expect(new GrantError('forbidden', 'x')).toMatchObject({ code: 'forbidden', name: 'GrantError' });
  });
});

describe('HTTP binding + client', () => {
  it('a principal only sees its own grants; an admin sees all; routes map to statuses', async () => {
    const { svc } = make();
    await reg(svc);
    await reg(svc, { id: 'g_x', principal: signerOf(stranger.secretKey) });
    const h = grantResourceHandler(svc, {
      authenticate: (r) => (r.query?.as === 'admin' ? { admin: true } : r.query?.as === 'p' ? { principal: P } : null),
    });
    expect((await h({ method: 'GET', path: '/pca/grants' })).status).toBe(401);
    const mine = await h({ method: 'GET', path: '/pca/grants', query: { as: 'p' } });
    expect((mine.body as { grants: { id: string }[] }).grants.map((g) => g.id)).toEqual(['g_0']);
    const all = await h({ method: 'GET', path: '/pca/grants', query: { as: 'admin' } });
    expect((all.body as { grants: unknown[] }).grants).toHaveLength(2);
    expect((await h({ method: 'GET', path: '/pca/grants/g_x', query: { as: 'p' } })).status).toBe(404);
    expect((await h({ method: 'GET', path: '/pca/grants/g_0', query: { as: 'p' } })).status).toBe(200);
    expect((await h({ method: 'DELETE', path: '/pca/grants/g_0', query: { as: 'p' } })).status).toBe(401);
    expect((await h({ method: 'DELETE', path: '/pca/grants/g_0', query: { as: 'admin', scope: 'grant' } })).body).toEqual({ revoked: ['g_0'] });
    expect((await h({ method: 'GET', path: '/pca/nope', query: { as: 'p' } })).status).toBe(404);
    expect((await h({ method: 'GET', path: '/pca/grants', query: { as: 'p', status: 'weird' } })).status).toBe(400);
    expect(grantManagementMetadata('https://as.example').grant_management.grants_endpoint).toBe('https://as.example/pca/grants');
  });

  it('the client round-trips, surfaces errors, and keeps only the freshest consistency token', async () => {
    const { svc } = make();
    await reg(svc);
    const h = grantResourceHandler(svc, { authenticate: () => ({ principal: P }) });
    const tokens = [
      { revocation_epoch: 2, ledger_tree_size: 5, budget_version: 1, policy_revision: 1 },
      { revocation_epoch: 1, ledger_tree_size: 9, budget_version: 1, policy_revision: 1 },
    ];
    let i = 0;
    const fakeFetch = (async (url: string, init: RequestInit) => {
      const u = new URL(url);
      const r = await h({ method: init.method ?? 'GET', path: u.pathname, query: Object.fromEntries(u.searchParams), body: init.body ? JSON.parse(String(init.body)) : undefined });
      return { ok: r.status < 400, status: r.status, statusText: 'x', headers: { get: (k: string) => (k === 'pca-fresh-at' && i < tokens.length ? JSON.stringify(tokens[i++]) : null) }, json: async () => r.body } as unknown as Response;
    }) as unknown as typeof fetch;
    const c = createGrantClient({ baseUrl: 'https://as.example/', fetch: fakeFetch });
    expect((await c.list({ status: 'active' })).grants[0]!.id).toBe('g_0');
    expect(c.freshAt?.revocation_epoch).toBe(2);
    await c.inspect('g_0');
    // the second token has an older revocation epoch: it must NOT replace the fresher one
    expect(c.freshAt?.revocation_epoch).toBe(2);
    await expect(c.inspect('missing')).rejects.toMatchObject({ status: 404, code: 'not_found', name: 'GrantApiError' });
  });
});
