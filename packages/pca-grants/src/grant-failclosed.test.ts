import { describe, expect, it } from 'vitest';
import { generateKeyPair } from '@atlasauth/pca';
import {
  GRANT_AMEND_DOMAIN, GrantService, MemoryGrantStore, amendMessage, authorityDigest, compareAuthority, verifyAmendment, verifyNeedApproval, verifyRevokeSignature,
  type Authority, type GrantFacts, type GrantRecord, type GrantStore, type Need, type NeedRequest,
} from './grant-resource';
import { signBody, signerOf } from './sig';

const principal = generateKeyPair();
const agent = generateKeyPair();
const P = signerOf(principal.secretKey);
const A = signerOf(agent.secretKey);
const AUTH: Authority = { verbs: ['read', 'pay'], resources: ['acct/1/*'], limits: { 'money.usd': 100 }, expires_at: 10_000 };

const svcOf = (over: Partial<ConstructorParameters<typeof GrantService>[0]> = {}) => {
  let n = 0;
  return new GrantService({ store: new MemoryGrantStore(), now: () => 1000, newId: (k) => `${k[0]}_${++n}`, ...over });
};
const reg = (s: GrantService, over: Partial<GrantRecord> = {}) => s.register({ id: 'g_0', principal: P, agent: A, authority: AUTH, chain_digest: 'cd', ...over });
const facts: GrantFacts = { id: 'g_0', rev: 1, principal: P, agent: A, status: 'active', authority: AUTH };
const sigFor = (action: 'narrow' | 'merge' | 'replace', a: Authority, k = principal, rev = 1) => signBody(GRANT_AMEND_DOMAIN, amendMessage({ id: 'g_0', rev }, action, a), k.secretKey);

describe('grant service: missing X gives exact result Y', () => {
  it('register refuses a malformed authority and a duplicate id', async () => {
    const s = svcOf();
    const bad: unknown[] = [
      { verbs: 'read', resources: [] }, { verbs: [], resources: 'x' }, { verbs: [''], resources: [] }, { verbs: [], resources: [1] }, { verbs: [], resources: [], limits: { a: -1 } },
      { verbs: [], resources: [], limits: { a: NaN } }, { verbs: [], resources: [], expires_at: 1.5 }, { verbs: [], resources: [], expires_at: -1 }, { verbs: Array(257).fill('v'), resources: [] },
      { verbs: [], resources: Array(1025).fill('r') }, { verbs: ['v'.repeat(129)], resources: [] }, null, [],
    ];
    for (const a of bad) await expect(reg(s, { authority: a as Authority })).rejects.toMatchObject({ code: 'bad_request', message: 'malformed authority' });
    await reg(s);
    await expect(reg(s)).rejects.toMatchObject({ code: 'conflict', message: 'grant id exists' });
  });
  it('unknown grants, needs and requests are not_found', async () => {
    const s = svcOf();
    await expect(s.inspect('x')).rejects.toMatchObject({ code: 'not_found', message: 'no such grant' });
    await expect(s.revoke('x', 'grant', { admin: true })).rejects.toMatchObject({ code: 'not_found' });
    await expect(s.amend('x', { action: 'narrow', authority: AUTH })).rejects.toMatchObject({ code: 'not_found' });
    await expect(s.requestNeeds('x', [])).rejects.toMatchObject({ code: 'not_found' });
    await expect(s.approveNeeds('n', [], 'sig')).rejects.toMatchObject({ code: 'not_found', message: 'no such need request' });
    await expect(s.denyNeeds('n')).rejects.toMatchObject({ code: 'not_found', message: 'no such need request' });
    await expect(s.needGrantId('n')).rejects.toMatchObject({ code: 'not_found' });
  });
  it('revoke needs a real authority: a missing or false admin flag is forbidden, a missing signature is bad_signature', async () => {
    const s = svcOf();
    await reg(s);
    await expect(s.revoke('g_0', 'grant', { admin: false } as never)).rejects.toMatchObject({ code: 'forbidden', message: 'not authorised' });
    await expect(s.revoke('g_0', 'grant', {} as never)).rejects.toMatchObject({ code: 'forbidden' });
    await expect(s.revoke('g_0', 'grant', { sig: '' })).rejects.toMatchObject({ code: 'bad_signature' });
    expect((await s.inspect('g_0')).status).toBe('active');
  });
  it('revoke reports an empty set to the host hook too, so a host registry is never left out of step', async () => {
    const seen: Array<[string[], string]> = [];
    const s = svcOf({ onRevoke: (ids, scope) => { seen.push([ids, scope]); } });
    await reg(s);
    await s.revoke('g_0', 'grant', { admin: true });
    await s.revoke('g_0', 'grant', { admin: true });
    expect(seen).toEqual([[['g_0'], 'grant'], [[], 'grant']]);
  });
  it('a revoked or superseded grant refuses amendments and new needs with not_active', async () => {
    const s = svcOf();
    await reg(s);
    await s.revoke('g_0', 'grant', { admin: true });
    const less: Authority = { ...AUTH, verbs: ['read'] };
    await expect(s.amend('g_0', { action: 'narrow', authority: less, sig: sigFor('narrow', less), signed_by: 'principal' })).rejects.toMatchObject({ code: 'not_active', message: 'grant is not active' });
    await expect(s.requestNeeds('g_0', [{ verb: 'v', resource: 'r' }])).rejects.toMatchObject({ code: 'not_active', message: 'grant is revoked' });
  });
  it('an incomparable change is treated as wider: it needs the principal and a step-up, and the holder alone cannot make it', async () => {
    const s = svcOf({ verifyStepUp: (r) => r === 'ok' });
    await reg(s);
    const sideways: Authority = { ...AUTH, verbs: ['read', 'x'] };
    expect(compareAuthority(AUTH, sideways)).toBe('incomparable');
    await expect(s.amend('g_0', { action: 'replace', authority: sideways, sig: sigFor('replace', sideways, agent), signed_by: 'holder', step_up_ref: 'ok' })).rejects.toMatchObject({ code: 'signature_required' });
    await expect(s.amend('g_0', { action: 'replace', authority: sideways, sig: sigFor('replace', sideways), signed_by: 'principal' })).rejects.toMatchObject({ code: 'step_up_required' });
    expect((await s.amend('g_0', { action: 'replace', authority: sideways, sig: sigFor('replace', sideways), signed_by: 'principal', step_up_ref: 'ok' })).created).toBe(true);
  });
  it('a step-up check that throws, or says no, leaves the grant untouched', async () => {
    const wider: Authority = { ...AUTH, verbs: ['read', 'pay', 'delete'] };
    const throwing = svcOf({ verifyStepUp: () => { throw new Error('idp down'); } });
    await reg(throwing);
    await expect(throwing.amend('g_0', { action: 'replace', authority: wider, sig: sigFor('replace', wider), signed_by: 'principal', step_up_ref: 'r' })).rejects.toThrow('idp down');
    const no = svcOf({ verifyStepUp: () => false });
    await reg(no);
    await expect(no.amend('g_0', { action: 'replace', authority: wider, sig: sigFor('replace', wider), signed_by: 'principal', step_up_ref: 'r' })).rejects.toMatchObject({ code: 'step_up_required' });
    expect(await no.inspect('g_0')).toMatchObject({ status: 'active', rev: 1, authority: AUTH });
    expect((await no.list()).grants).toHaveLength(1);
  });
  it('a store that fails mid-write surfaces the failure (nothing is reported as granted)', async () => {
    const inner = new MemoryGrantStore();
    let fail = false;
    const store: GrantStore = {
      get: (id) => inner.get(id), list: () => inner.list(), getNeed: (id) => inner.getNeed(id), putNeed: (n: NeedRequest) => inner.putNeed(n), listNeeds: (g) => inner.listNeeds(g),
      put: async (g: GrantRecord) => { if (fail) throw new Error('disk full'); await inner.put(g); },
    };
    const s = svcOf({ store });
    await reg(s);
    fail = true;
    const less: Authority = { ...AUTH, verbs: ['read'] };
    await expect(s.amend('g_0', { action: 'narrow', authority: less, sig: sigFor('narrow', less), signed_by: 'principal' })).rejects.toThrow('disk full');
    expect((await inner.get('g_0'))!.authority).toEqual(AUTH);
  });
  it('list clamps the page size to 1..200, orders by id and pages by cursor', async () => {
    const s = svcOf();
    for (const id of ['g_b', 'g_a', 'g_c']) await reg(s, { id });
    expect((await s.list({ limit: 0 })).grants.map((g) => g.id)).toEqual(['g_a']);
    expect((await s.list({ limit: -5 })).grants.map((g) => g.id)).toEqual(['g_a']);
    expect(await s.list({ limit: 2 })).toMatchObject({ next_cursor: 'g_b' });
    expect((await s.list({ limit: 2, cursor: 'g_b' })).grants.map((g) => g.id)).toEqual(['g_c']);
    expect((await s.list({ limit: 2, cursor: 'g_b' })).next_cursor).toBeUndefined();
    expect((await s.list({ status: 'revoked' })).grants).toEqual([]);
  });
  it('without providers an inspect carries no usage, budget, card or residual member', async () => {
    const s = svcOf();
    await reg(s);
    const v = await s.inspect('g_0');
    for (const k of ['usage', 'remaining_budget', 'policy_card', 'residual', 'history']) expect(k in v).toBe(false);
    expect(v.authority_digest).toBe(authorityDigest(AUTH));
  });
  it('needs: 0 or 33 needs, a non-object need, an over-long verb and a host validator refusal are bad_request', async () => {
    const s = svcOf({ validateNeed: (n) => (n.verb === 'forbidden' ? 'verb not in the action schema' : null) });
    await reg(s);
    const ok: Need = { verb: 'v', resource: 'r' };
    await expect(s.requestNeeds('g_0', Array(33).fill(ok))).rejects.toMatchObject({ code: 'bad_request', message: '1..32 needs' });
    await expect(s.requestNeeds('g_0', ['x'] as never)).rejects.toMatchObject({ code: 'bad_request', message: 'malformed need' });
    await expect(s.requestNeeds('g_0', [{ verb: 'v'.repeat(129), resource: 'r' }])).rejects.toMatchObject({ code: 'bad_request', message: 'malformed need' });
    await expect(s.requestNeeds('g_0', [{ verb: 'forbidden', resource: 'r' }])).rejects.toMatchObject({ code: 'bad_request', message: 'verb not in the action schema' });
    expect((await s.requestNeeds('g_0', Array(32).fill(ok))).needs).toHaveLength(32);
  });
});

describe('pure verifiers: the normative check order and exact codes', () => {
  const less: Authority = { ...AUTH, verbs: ['read'] };
  it('verifyAmendment: shape, authority, status, classification, signature, then step-up', () => {
    expect(verifyAmendment(facts, null, true)).toEqual({ ok: false, code: 'bad_request' });
    expect(verifyAmendment(facts, { action: 'delete', authority: less }, true)).toEqual({ ok: false, code: 'bad_request' });
    expect(verifyAmendment(facts, { action: 'narrow', authority: { verbs: 1, resources: [] } }, true)).toEqual({ ok: false, code: 'bad_request' });
    expect(verifyAmendment({ ...facts, status: 'revoked' }, { action: 'narrow', authority: less }, true)).toEqual({ ok: false, code: 'not_active' });
    expect(verifyAmendment({ ...facts, status: 'superseded' }, { action: 'narrow', authority: less }, true)).toEqual({ ok: false, code: 'not_active' });
    expect(verifyAmendment(facts, { action: 'narrow', authority: AUTH }, true)).toEqual({ ok: false, code: 'not_narrower' }); // equal, before the signature is looked at
    expect(verifyAmendment(facts, { action: 'narrow', authority: less }, true)).toEqual({ ok: false, code: 'signature_required' });
    expect(verifyAmendment(facts, { action: 'narrow', authority: less, sig: 'x', signed_by: 'stranger' }, true)).toEqual({ ok: false, code: 'signature_required' });
    expect(verifyAmendment(facts, { action: 'narrow', authority: less, sig: 'x', signed_by: 'holder' }, true)).toEqual({ ok: false, code: 'bad_signature' });
    expect(verifyAmendment(facts, { action: 'narrow', authority: less, sig: sigFor('narrow', less, agent), signed_by: 'holder' }, false)).toEqual({ ok: true, widens: false, next: less });
    // a holder signature stands for the holder only: the principal's key does not verify as the holder
    expect(verifyAmendment(facts, { action: 'narrow', authority: less, sig: sigFor('narrow', less), signed_by: 'holder' }, false)).toEqual({ ok: false, code: 'bad_signature' });
    // a signature for another revision or another action does not carry over
    expect(verifyAmendment(facts, { action: 'narrow', authority: less, sig: sigFor('narrow', less, principal, 2), signed_by: 'principal' }, false)).toEqual({ ok: false, code: 'bad_signature' });
    expect(verifyAmendment(facts, { action: 'merge', authority: less, sig: sigFor('narrow', less), signed_by: 'principal' }, false)).toEqual({ ok: false, code: 'bad_signature' });
  });
  it('verifyAmendment: a widening is refused without a step-up even with a valid principal signature', () => {
    const wider: Authority = { ...AUTH, verbs: ['read', 'pay', 'delete'] };
    const req = { action: 'replace', authority: wider, sig: sigFor('replace', wider), signed_by: 'principal' };
    expect(verifyAmendment(facts, req, false)).toEqual({ ok: false, code: 'step_up_required' });
    expect(verifyAmendment(facts, req, true)).toEqual({ ok: true, widens: true, next: wider });
    expect(verifyAmendment(facts, { ...req, action: 'narrow', sig: sigFor('narrow', wider) }, true)).toEqual({ ok: false, code: 'not_narrower' });
  });
  it('verifyRevokeSignature: an unknown scope is bad_request, a signature for another scope or grant is bad_signature', () => {
    expect(verifyRevokeSignature(facts, 'everything', 'x')).toEqual({ ok: false, code: 'bad_request' });
    expect(verifyRevokeSignature(facts, undefined, 'x')).toEqual({ ok: false, code: 'bad_request' });
    expect(verifyRevokeSignature(facts, 'grant', undefined)).toEqual({ ok: false, code: 'bad_signature' });
  });
  it('verifyNeedApproval: a settled request is a conflict; approvals must match the needs one for one', () => {
    const need: Need = { verb: 'pay', resource: 'r/*', limits: { usd: 10 }, adjustable: false };
    const nr = { id: 'n_1', grant_id: 'g_0', needs: [need], status: 'pending' as const };
    expect(verifyNeedApproval({ ...nr, status: 'approved' }, facts, [need], 'x', true)).toEqual({ ok: false, code: 'conflict' });
    expect(verifyNeedApproval({ ...nr, status: 'denied' }, facts, [need], 'x', true)).toEqual({ ok: false, code: 'conflict' });
    expect(verifyNeedApproval(nr, facts, [need], 'x', true)).toEqual({ ok: false, code: 'bad_signature' });
  });
});
