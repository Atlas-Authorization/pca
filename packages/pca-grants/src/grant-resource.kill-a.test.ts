import { describe, expect, it } from 'vitest';
import { generateKeyPair } from '@atlasauth/pca';
import {
  GRANT_AMEND_DOMAIN, GRANT_REVOKE_DOMAIN, NEED_APPROVE_DOMAIN, GrantError, GrantService, MemoryGrantStore, amendMessage, authorityDigest, compareAuthority,
  grantRevokeMessage, needApproveMessage, needRequestMessage, stepUpMessage, verifyAmendment, verifyNeedApproval, verifyRevokeSignature,
  type Authority, type GrantFacts, type GrantRecord, type GrantServiceOptions, type GrantStore, type Need, type NeedRequest,
} from './grant-resource';
import { signBody, signerOf } from './sig';

const pk = generateKeyPair();
const ak = generateKeyPair();
const P = signerOf(pk.secretKey);
const A = signerOf(ak.secretKey);
const B = signerOf(generateKeyPair().secretKey);
const AUTH: Authority = { verbs: ['read'], resources: ['acct/1'], limits: { usd: 100 }, expires_at: 10_000 };

const err = async (p: Promise<unknown>): Promise<GrantError> => {
  try {
    await p;
  } catch (e) {
    return e as GrantError;
  }
  throw new Error('no throw');
};

interface Calls { change: Array<[string, GrantRecord]>; revoke: Array<[string[], string]>; ids: string[]; stepUp: number }
function mk(over: Partial<GrantServiceOptions> = {}) {
  const calls: Calls = { change: [], revoke: [], ids: [], stepUp: 0 };
  let n = 0;
  const store = new MemoryGrantStore();
  const svc = new GrantService({
    store,
    now: () => 1000,
    newId: (k) => {
      calls.ids.push(k);
      return `${k[0]}_${++n}`;
    },
    onChange: (kind, g) => {
      calls.change.push([kind, structuredClone(g)]);
    },
    onRevoke: (ids, scope) => {
      calls.revoke.push([ids, scope]);
    },
    ...over,
  });
  return { svc, store, calls };
}
const reg = (svc: GrantService, id: string, extra: Record<string, unknown> = {}) =>
  svc.register({ id, principal: P, agent: A, authority: structuredClone(AUTH), chain_digest: 'cd', ...extra } as never);

describe('compareAuthority: resources and limits', () => {
  const c = (o: Partial<Authority>, n: Partial<Authority>) => compareAuthority({ verbs: ['v'], resources: ['x'], ...o }, { verbs: ['v'], resources: ['x'], ...n });
  it('an exact resource covers only itself', () => {
    expect(c({ resources: ['acct/1'] }, { resources: ['acct/12'] })).toBe('incomparable');
    expect(c({ resources: ['acct/1'] }, { resources: ['acct/1'] })).toBe('equal');
    expect(c({ resources: ['acct/1'] }, { resources: ['acct/2'] })).toBe('incomparable');
  });
  it('every small resource must be covered, and any one big resource may cover it', () => {
    expect(c({ resources: ['a/1'] }, { resources: ['a/1', 'b/1'] })).toBe('wider');
    expect(c({ resources: ['a/1', 'b/1'] }, { resources: ['a/1'] })).toBe('narrower');
    expect(c({ resources: ['a/1', 'b/1'] }, { resources: ['a/1', 'b/*'] })).toBe('wider');
  });
  it('a pattern is covered by a wider pattern but not by an exact id', () => {
    expect(c({ resources: ['a/*'] }, { resources: ['a/b*'] })).toBe('narrower');
    expect(c({ resources: ['a/b*'] }, { resources: ['a/*'] })).toBe('wider');
    expect(c({ resources: ['a/*'] }, { resources: ['a/1'] })).toBe('narrower');
    expect(c({ resources: ['a/1'] }, { resources: ['a/*'] })).toBe('wider');
  });
  it('limits present on only one side are handled without throwing', () => {
    expect(c({ limits: { usd: 1 } }, {})).toBe('wider');
    expect(c({}, { limits: { usd: 1 } })).toBe('narrower');
  });
});

describe('authorityDigest', () => {
  it('ignores the order of resources and verbs', () => {
    const a = authorityDigest({ verbs: ['b', 'a'], resources: ['y', 'x'] });
    expect(authorityDigest({ verbs: ['a', 'b'], resources: ['x', 'y'] })).toBe(a);
  });
});

describe('MemoryGrantStore needs', () => {
  it('returns copies, and lists only the needs of one grant', async () => {
    const s = new MemoryGrantStore();
    const nr = (id: string, grant_id: string): NeedRequest => ({ id, grant_id, needs: [], status: 'pending', created_at: 1 });
    await s.putNeed(nr('n1', 'g1'));
    await s.putNeed(nr('n2', 'g2'));
    const got = (await s.getNeed('n1'))!;
    got.status = 'denied';
    expect((await s.getNeed('n1'))!.status).toBe('pending');
    expect((await s.listNeeds('g1')).map((x) => x.id)).toEqual(['n1']);
    expect(await s.getNeed('nope')).toBeUndefined();
  });
});

describe('authority shape validation', () => {
  const bad = async (a: unknown) => (await err(mk().svc.register({ id: 'g', principal: P, agent: A, authority: a as never, chain_digest: 'c' }))).code;
  const good = async (a: unknown) => {
    const r = await mk().svc.register({ id: 'g', principal: P, agent: A, authority: a as never, chain_digest: 'c' });
    return r.id;
  };
  it('accepts the documented bounds', async () => {
    expect(await good({ verbs: Array.from({ length: 256 }, (_, i) => `v${i}`), resources: ['r'] })).toBe('g');
    expect(await good({ verbs: ['v'], resources: Array.from({ length: 1024 }, (_, i) => `r${i}`) })).toBe('g');
    expect(await good({ verbs: ['v'], resources: ['r'], limits: { usd: 0 } })).toBe('g');
    expect(await good({ verbs: ['v'], resources: ['r'] })).toBe('g');
  });
  it('refuses anything outside them', async () => {
    expect(await bad({ verbs: Array.from({ length: 257 }, (_, i) => `v${i}`), resources: ['r'] })).toBe('bad_request');
    expect(await bad({ verbs: ['v'], resources: Array.from({ length: 1025 }, (_, i) => `r${i}`) })).toBe('bad_request');
    expect(await bad({ verbs: ['v'], resources: ['r', ''] })).toBe('bad_request');
    expect(await bad({ verbs: ['v'], resources: ['r'], limits: { a: 1, b: 'x' } })).toBe('bad_request');
    expect(await bad({ verbs: ['v'], resources: ['r'], limits: { a: Infinity } })).toBe('bad_request');
    expect(await bad({ verbs: ['v'], resources: ['r'], limits: { a: -1 } })).toBe('bad_request');
    expect(await bad({ verbs: ['v'], resources: ['r'], limits: { a: Number.NaN } })).toBe('bad_request');
    expect(await bad({ verbs: ['v'], resources: ['r'], expires_at: 1.5 })).toBe('bad_request');
  });
});

describe('verifyAmendment', () => {
  const facts = (over: Partial<GrantFacts> = {}): GrantFacts => ({ id: 'g1', rev: 1, principal: P, agent: A, status: 'active', authority: structuredClone(AUTH), ...over });
  const signed = (cur: GrantFacts, action: 'narrow' | 'merge' | 'replace', authority: Authority, by: 'holder' | 'principal') => ({
    action,
    authority,
    signed_by: by,
    sig: signBody(GRANT_AMEND_DOMAIN, amendMessage(cur, action, authority), by === 'principal' ? pk.secretKey : ak.secretKey),
  });
  it('a missing signature is signature_required, not bad_signature', () => {
    const cur = facts();
    expect(verifyAmendment(cur, { action: 'narrow', authority: { ...AUTH, limits: { usd: 5 } }, signed_by: 'holder' }, false)).toEqual({ ok: false, code: 'signature_required' });
  });
  it('merging a delta without limits or expiry keeps both and adds nothing spurious', () => {
    const cur = facts();
    const delta: Authority = { verbs: ['write'], resources: ['acct/2'] };
    const v = verifyAmendment(cur, signed(cur, 'merge', delta, 'principal'), true);
    expect(v).toMatchObject({ ok: true, widens: true });
    if (!v.ok) throw new Error('unreachable');
    expect(v.next).toEqual({ verbs: ['read', 'write'], resources: ['acct/1', 'acct/2'], limits: { usd: 100 }, expires_at: 10_000 });
  });
  it('merging into an authority that has no expiry or limits does not invent them', () => {
    const base: Authority = { verbs: ['read'], resources: ['acct/1'] };
    const cur = facts({ authority: base });
    const delta: Authority = { verbs: ['write'], resources: ['acct/1'] };
    const v = verifyAmendment(cur, signed(cur, 'merge', delta, 'principal'), true);
    if (!v.ok) throw new Error(v.code);
    expect('expires_at' in v.next).toBe(false);
    expect('limits' in v.next).toBe(false);
  });
  it('a custom comparator is honoured by the service and the default is used otherwise', async () => {
    const { svc } = mk({ compare: () => 'wider' });
    await reg(svc, 'g1');
    const narrower: Authority = { ...AUTH, limits: { usd: 5 } };
    const sig = signBody(GRANT_AMEND_DOMAIN, amendMessage({ id: 'g1', rev: 1 }, 'narrow', narrower), ak.secretKey);
    expect((await err(svc.amend('g1', { action: 'narrow', authority: narrower, signed_by: 'holder', sig }))).code).toBe('not_narrower');
    const plain = mk().svc;
    await reg(plain, 'g1');
    expect((await plain.amend('g1', { action: 'narrow', authority: narrower, signed_by: 'holder', sig })).created).toBe(false);
  });
});

describe('verifyRevokeSignature', () => {
  it('accepts a principal signature for each scope including agent', () => {
    for (const scope of ['grant', 'agent', 'subtree'] as const) {
      const sig = signBody(GRANT_REVOKE_DOMAIN, grantRevokeMessage('g1', scope), pk.secretKey);
      expect(verifyRevokeSignature({ id: 'g1', principal: P }, scope, sig)).toEqual({ ok: true, scope });
    }
    expect(verifyRevokeSignature({ id: 'g1', principal: P }, 'other', 'x')).toEqual({ ok: false, code: 'bad_request' });
  });
});

describe('verifyNeedApproval', () => {
  const want: Need = { verb: 'pay', resource: 'acct/9', limits: { usd: 400 }, adjustable: false };
  const nr = (needs: Need[] = [want]): NeedRequest => ({ id: 'n1', grant_id: 'g1', needs, status: 'pending', created_at: 1 });
  const g: GrantFacts = { id: 'g1', rev: 1, principal: P, agent: A, status: 'active', authority: { verbs: ['read'], resources: ['acct/1'], limits: { usd: 100 } } };
  const sigOf = (n: NeedRequest, approved: Need[]) => signBody(NEED_APPROVE_DOMAIN, needApproveMessage(n, g.rev, approved), pk.secretKey);
  const run = (needs: Need[], approved: Need[], stepUp = true) => verifyNeedApproval(nr(needs), g, approved, sigOf(nr(needs), approved), stepUp);
  it('an approved need with a different verb is refused', () => {
    expect(run([want], [{ ...want, verb: 'refund' }])).toEqual({ ok: false, code: 'need_not_lowered_only' });
  });
  it('an approved limit on a need that names none is refused without throwing', () => {
    const noLimits: Need = { verb: 'pay', resource: 'acct/9' };
    expect(run([noLimits], [{ ...noLimits, limits: { usd: 1 } }])).toEqual({ ok: false, code: 'need_not_lowered_only' });
  });
  it('the exact requested amount is accepted even when the need is not adjustable; lower is not', () => {
    expect(run([want], [{ ...want }]).ok).toBe(true);
    expect(run([want], [{ ...want, limits: { usd: 399 } }])).toEqual({ ok: false, code: 'need_not_adjustable' });
    expect(run([{ ...want, adjustable: true }], [{ ...want, limits: { usd: 399 } }]).ok).toBe(true);
  });
  it('the merged authority gains the approved verb, resource and limit', () => {
    const v = run([want], [{ ...want }]);
    if (!v.ok) throw new Error(v.code);
    expect(v.authority).toEqual({ verbs: ['read', 'pay'], resources: ['acct/1', 'acct/9'], limits: { usd: 400 } });
  });
  it('a need without limits yields no limit entry and still needs a step-up', () => {
    const plain: Need = { verb: 'pay', resource: 'acct/9' };
    const v = run([plain], [plain]);
    if (!v.ok) throw new Error(v.code);
    expect(v.authority).toEqual({ verbs: ['read', 'pay'], resources: ['acct/1', 'acct/9'], limits: { usd: 100 } });
    expect(run([plain], [plain], false)).toEqual({ ok: false, code: 'step_up_required' });
  });
});

describe('message builders', () => {
  it('have exactly the signed shape', () => {
    const needs: Need[] = [{ verb: 'v', resource: 'r' }];
    expect(needRequestMessage('g1', 3, needs)).toEqual({ grant: 'g1', rev: 3, needs });
    expect(stepUpMessage('g1', 'c1', 'n0')).toEqual({ grant: 'g1', challenge: 'c1', nonce: 'n0' });
  });
});

describe('GrantService.list', () => {
  it('lists plain views, pages exactly at the limit, and orders by id', async () => {
    const { svc } = mk({ providers: { usage: () => 'u', policyCard: () => 'pc', residual: () => 'rs', remainingBudget: () => 'rb' } });
    for (const id of ['g3', 'g1', 'g2']) await reg(svc, id);
    const all = await svc.list({ limit: 3 });
    expect(all.grants.map((x) => x.id)).toEqual(['g1', 'g2', 'g3']);
    expect('next_cursor' in all).toBe(false);
    for (const v of all.grants) for (const k of ['usage', 'remaining_budget', 'policy_card', 'residual']) expect(k in v).toBe(false);
    expect((await svc.list({ limit: 2 })).next_cursor).toBe('g2');
  });
  it('inspect fills every provider', async () => {
    const { svc } = mk({ providers: { usage: () => 'u', policyCard: () => 'pc', residual: () => 'rs', remainingBudget: () => 'rb' } });
    await reg(svc, 'g1');
    expect(await svc.inspect('g1')).toMatchObject({ usage: 'u', remaining_budget: 'rb', policy_card: 'pc', residual: 'rs' });
  });
});

describe('GrantService.register', () => {
  it('records the creation in the history and stores the same record', async () => {
    const { svc, store } = mk();
    const rec = await reg(svc, 'g1');
    expect(rec.history).toEqual([{ rev: 1, authority_digest: authorityDigest(AUTH), at: 1000, action: 'create' }]);
    expect((await store.get('g1'))!.history).toEqual(rec.history);
  });
});

describe('GrantService.amend records', () => {
  const providers = { usage: () => 'u' };
  it('a narrowing revises in place, records history, notifies and returns a rich view', async () => {
    const { svc, store, calls } = mk({ providers });
    await reg(svc, 'g1');
    const narrower: Authority = { ...AUTH, limits: { usd: 5 } };
    const sig = signBody(GRANT_AMEND_DOMAIN, amendMessage({ id: 'g1', rev: 1 }, 'narrow', narrower), ak.secretKey);
    const out = await svc.amend('g1', { action: 'narrow', authority: narrower, signed_by: 'holder', sig });
    expect(out.created).toBe(false);
    expect((out.grant as { usage?: unknown }).usage).toBe('u');
    const rec = (await store.get('g1'))!;
    expect(rec.rev).toBe(2);
    expect(rec.history[1]).toEqual({ rev: 2, authority_digest: authorityDigest(narrower), at: 1000, action: 'narrow' });
    expect(calls.change.map((c) => c[0])).toEqual(['amend']);
  });
  it('a widening creates a new active grant that supersedes the old one', async () => {
    const { svc, store, calls } = mk({ providers, verifyStepUp: () => true });
    await reg(svc, 'g1');
    const wider: Authority = { ...AUTH, limits: { usd: 500 } };
    const sig = signBody(GRANT_AMEND_DOMAIN, amendMessage({ id: 'g1', rev: 1 }, 'replace', wider), pk.secretKey);
    const out = await svc.amend('g1', { action: 'replace', authority: wider, signed_by: 'principal', sig, step_up_ref: 'ok' });
    expect(out.created).toBe(true);
    expect((out.grant as { usage?: unknown }).usage).toBe('u');
    const fresh = (await store.get('g_1'))!;
    expect(fresh.status).toBe('active');
    expect(fresh.supersedes).toBe('g1');
    expect(fresh.history).toEqual([{ rev: 1, authority_digest: authorityDigest(wider), at: 1000, action: 'supersedes:g1' }]);
    expect((await store.get('g1'))!.status).toBe('superseded');
    expect(calls.change.map((c) => c[0])).toEqual(['supersede']);
  });
});

describe('GrantService.revoke', () => {
  const sigFor = (id: string, scope: 'grant' | 'agent' | 'subtree') => ({ sig: signBody(GRANT_REVOKE_DOMAIN, grantRevokeMessage(id, scope), pk.secretKey) });
  async function tree() {
    const t = mk();
    // grandchild is registered before its parent so one pass over the list cannot find it
    await reg(t.svc, 'root');
    await reg(t.svc, 'grand', { parent: 'child' });
    await reg(t.svc, 'child', { parent: 'root' });
    await reg(t.svc, 'other-agent', { agent: B });
    await reg(t.svc, 'other-principal', { principal: B });
    await reg(t.svc, 'orphan', { parent: 'nobody' });
    await reg(t.svc, 'sibling');
    return t;
  }
  it('an unknown scope is a bad_request with its message', async () => {
    const e = await err(mk().svc.revoke('g', 'bogus' as never, { admin: true }));
    expect([e.code, e.message]).toEqual(['bad_request', 'unknown scope']);
  });
  it('scope grant revokes only the named grant, with a history entry and notifications', async () => {
    const { svc, store, calls } = await tree();
    expect(await svc.revoke('root', 'grant', sigFor('root', 'grant'))).toEqual({ revoked: ['root'] });
    expect((await store.get('child'))!.status).toBe('active');
    expect((await store.get('root'))!.history.at(-1)).toEqual({ rev: 1, authority_digest: authorityDigest(AUTH), at: 1000, action: 'revoke:grant' });
    expect(calls.revoke).toEqual([[['root'], 'grant']]);
    expect(calls.change.map((c) => c[0])).toEqual(['revoke']);
  });
  it('scope agent revokes the same agent and principal only', async () => {
    const { svc } = await tree();
    expect((await svc.revoke('root', 'agent', { admin: true })).revoked.sort()).toEqual(['child', 'grand', 'orphan', 'root', 'sibling']);
  });
  it('scope subtree follows parents transitively and nothing else', async () => {
    const { svc } = await tree();
    expect((await svc.revoke('root', 'subtree', sigFor('root', 'subtree'))).revoked.sort()).toEqual(['child', 'grand', 'root']);
  });
  it('already revoked grants are skipped and a non-admin object is forbidden', async () => {
    const { svc } = await tree();
    await svc.revoke('root', 'grant', { admin: true });
    expect((await svc.revoke('root', 'subtree', { admin: true })).revoked.sort()).toEqual(['child', 'grand']);
    expect((await err(svc.revoke('root', 'grant', { admin: false } as never))).code).toBe('forbidden');
  });
});

describe('GrantService needs', () => {
  const need: Need = { verb: 'pay', resource: 'acct/9', limits: { usd: 400 }, adjustable: true };
  async function filed(over: Partial<GrantServiceOptions> = {}) {
    const t = mk(over);
    await reg(t.svc, 'g1');
    const nr = await t.svc.requestNeeds('g1', [need]);
    return { ...t, nr };
  }
  const approveSig = (nr: NeedRequest, approved: Need[]) => signBody(NEED_APPROVE_DOMAIN, needApproveMessage(nr, 1, approved), pk.secretKey);
  it('requestNeeds validates limits and records ids and notifications by kind', async () => {
    const { svc } = mk();
    await reg(svc, 'g1');
    for (const limits of [{ a: 1, b: 'x' }, { a: Infinity }, { a: -1 }]) {
      expect((await err(svc.requestNeeds('g1', [{ verb: 'v', resource: 'r', limits } as never]))).message).toBe('malformed need');
    }
    expect((await svc.requestNeeds('g1', [{ verb: 'v', resource: 'r', limits: { a: 0 } }])).status).toBe('pending');
    const t = await filed();
    expect(t.calls.ids).toEqual(['need']);
    expect(t.calls.change.map((c) => c[0])).toEqual(['need']);
  });
  it('approval needs a step-up that is actually checked, and only when the failure is the step-up', async () => {
    let seen: Array<string | undefined> = [];
    const verifyStepUp = (r: string) => (seen.push(r), r === 'ok');
    const a = await filed({ verifyStepUp });
    const sig = approveSig(a.nr, [need]);
    expect((await err(a.svc.approveNeeds(a.nr.id, [need], sig))).code).toBe('step_up_required');
    expect(seen).toEqual([]);
    expect((await err(a.svc.approveNeeds(a.nr.id, [need], sig, 'no'))).code).toBe('step_up_required');
    seen = [];
    expect((await err(a.svc.approveNeeds(a.nr.id, [need], 'A'.repeat(86), 'ok'))).code).toBe('bad_signature');
    expect(seen).toEqual([]);
    const none = await filed();
    expect((await err(none.svc.approveNeeds(none.nr.id, [need], approveSig(none.nr, [need]), 'ok'))).code).toBe('step_up_required');
  });
  it('a successful approval records everything and is single use', async () => {
    const t = await filed({ verifyStepUp: () => true, providers: { usage: () => 'u' } });
    const out = await t.svc.approveNeeds(t.nr.id, [need], approveSig(t.nr, [need]), 'ok');
    expect(out.created).toBe(true);
    expect((out.grant as { usage?: unknown }).usage).toBe('u');
    expect(t.calls.ids).toEqual(['need', 'grant']);
    const fresh = (await t.store.get('g_2'))!;
    expect(fresh.status).toBe('active');
    expect(fresh.history).toEqual([{ rev: 1, authority_digest: authorityDigest(fresh.authority), at: 1000, action: `needs:${t.nr.id}` }]);
    expect((await t.store.get('g1'))!.status).toBe('superseded');
    const stored = (await t.store.getNeed(t.nr.id))!;
    expect([stored.status, stored.result_grant_id]).toEqual(['approved', 'g_2']);
    expect(t.calls.change.map((c) => c[0])).toEqual(['need', 'supersede']);
    const again = await err(t.svc.approveNeeds(t.nr.id, [need], approveSig(t.nr, [need]), 'ok'));
    expect([again.code, again.message]).toEqual(['conflict', 'need request is approved']);
  });
  it('needGrantId and denyNeeds report missing and settled requests precisely', async () => {
    const t = await filed();
    expect(await t.svc.needGrantId(t.nr.id)).toBe('g1');
    expect((await err(t.svc.needGrantId('nope'))).message).toBe('no such need request');
    await t.svc.denyNeeds(t.nr.id);
    expect((await t.store.getNeed(t.nr.id))!.status).toBe('denied');
    const e = await err(t.svc.denyNeeds(t.nr.id));
    expect([e.code, e.message]).toEqual(['conflict', 'need request is denied']);
  });
});

// a store whose list order differs from id order, to exercise the sort
describe('list ordering', () => {
  it('sorts ascending by id regardless of store order', async () => {
    const recs = ['b', 'c', 'a'].map((id) => ({ id, principal: P, agent: A, status: 'active', authority: AUTH, rev: 1, chain_digest: 'c', created_at: 1, history: [] }) as GrantRecord);
    const store: GrantStore = {
      get: async () => undefined, put: async () => {}, list: async () => recs, getNeed: async () => undefined, putNeed: async () => {}, listNeeds: async () => [],
    };
    const svc = new GrantService({ store, now: () => 1, newId: () => 'x' });
    expect((await svc.list()).grants.map((g) => g.id)).toEqual(['a', 'b', 'c']);
  });
});
