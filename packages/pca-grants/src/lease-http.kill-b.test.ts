import { describe, expect, it } from 'vitest';
import { memoryLeaseKv } from './lease';
import { LeaseRegistry, leaseResourceHandler, signLease, type NewLease } from './index';
import { LEASE_AUTH } from './test-support/lease-vectors';

const SK = new Uint8Array(32).fill(31);
const T0 = 1_800_000_000_000;
const base: NewLease = { lease_id: 'L1', path: 'a/b', grant_ref: 'g', holder: 'agent', requester: 'alice', approvers: ['bob'], justification_digest: 'j1', seq: 1, issued_at: T0, renewed_at: T0, expires_at: T0 + 1000, max_ttl: 5000 };
const lease = signLease(SK, base);
const NF = { status: 404, body: { error: 'not_found' } };
const admin = { as: 'admin' };

function mk(now?: () => number) {
  const reg = new LeaseRegistry({ authorities: [LEASE_AUTH] }, memoryLeaseKv());
  const h = leaseResourceHandler(reg, {
    authenticate: (r) => (r.query?.as === 'admin' ? { admin: true } : r.query?.as === 'agent' ? { principal: 'agent' } : r.query?.as === 'other' ? { principal: 'other' } : null),
    ...(now ? { now } : {}),
  });
  return { reg, h };
}
/** A registry double that records the calls the handler makes. */
function spy() {
  const calls: Array<[string, ...unknown[]]> = [];
  const reg = {
    accept: async (...a: unknown[]) => (calls.push(['accept', ...a]), { ok: true, replaced: false }),
    revoke: async (...a: unknown[]) => (calls.push(['revoke', ...a]), { ok: true }),
    get: async (id: string) => (calls.push(['get', id]), undefined),
    history: async () => [],
  };
  return { calls, h: leaseResourceHandler(reg as never, { authenticate: () => ({ admin: true }) }) };
}

describe('lease routes: path and shape', () => {
  it('only /pca/leases is routed', async () => {
    const { calls, h } = spy();
    for (const path of ['/other/leases', '/pca/other', '/x/y']) expect(await h({ method: 'POST', path, body: { lease } })).toStrictEqual(NF);
    expect(calls).toHaveLength(0);
  });
  it('the issue chain is the body chain only when it is an array of strings', async () => {
    const { calls, h } = spy();
    await h({ method: 'POST', path: '/pca/leases', body: { lease, chain: ['bob'] } });
    await h({ method: 'POST', path: '/pca/leases', body: { lease, chain: ['bob', 1] } });
    await h({ method: 'POST', path: '/pca/leases', body: { lease, chain: 'bob' } });
    await h({ method: 'POST', path: '/pca/leases', body: { lease } });
    expect(calls).toStrictEqual([['accept', lease, ['bob']], ['accept', lease, []], ['accept', lease, []], ['accept', lease, []]]);
  });
  it('revoke is POST /pca/leases/revoke exactly', async () => {
    const { calls, h } = spy();
    expect(await h({ method: 'POST', path: '/pca/leases/L1', body: {} })).toStrictEqual(NF);
    expect(await h({ method: 'POST', path: '/pca/leases/revoke/x', body: {} })).toStrictEqual(NF);
    expect(await h({ method: 'POST', path: '/pca/leases/L1/revoke', body: {} })).toStrictEqual(NF);
    expect(calls.filter(([n]) => n === 'revoke')).toHaveLength(0);
  });
});

describe('lease read and check routes', () => {
  const issued = async (now?: () => number) => {
    const m = mk(now);
    expect((await m.h({ method: 'POST', path: '/pca/leases', query: admin, body: { lease } })).status).toBe(201);
    return m;
  };
  it('read and check need the exact method and segment count', async () => {
    const { h } = await issued();
    expect(await h({ method: 'GET', path: '/pca/leases/L1/zzz', query: admin })).toStrictEqual(NF);
    expect(await h({ method: 'GET', path: '/pca/leases/L1/check', query: admin })).toStrictEqual(NF);
    expect(await h({ method: 'POST', path: '/pca/leases/L1/zzz', query: admin, body: { lease } })).toStrictEqual(NF);
    expect(await h({ method: 'POST', path: '/pca/leases/L1/check/x', query: admin, body: { lease } })).toStrictEqual(NF);
    expect(await h({ method: 'PUT', path: '/pca/leases/L1/check', query: admin, body: { lease } })).toStrictEqual(NF);
    expect(await h({ method: 'POST', path: '/pca/leases/L1', query: admin, body: { lease } })).toStrictEqual(NF);
  });
  it('a lease the caller does not hold, or that does not exist, looks like not_found on read and check', async () => {
    const { h } = await issued();
    for (const [method, path] of [['GET', '/pca/leases/L1'], ['POST', '/pca/leases/L1/check']] as const) {
      expect(await h({ method, path, query: { as: 'other' }, body: { lease } })).toStrictEqual(NF);
      expect(await h({ method, path: path.replace('L1', 'nope'), query: admin, body: { lease } })).toStrictEqual(NF);
    }
    expect((await h({ method: 'GET', path: '/pca/leases/L1', query: { as: 'agent' } })).status).toBe(200);
  });
  it('the default clock is the wall clock', async () => {
    const now = Date.now();
    const live = signLease(SK, { ...base, issued_at: now, renewed_at: now, expires_at: now + 3_600_000, max_ttl: 7_200_000 });
    const m = mk();
    expect((await m.h({ method: 'POST', path: '/pca/leases', query: admin, body: { lease: live } })).status).toBe(201);
    const r = await m.h({ method: 'POST', path: '/pca/leases/L1/check', query: admin, body: { lease: live } });
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ decision: 'allow' });
  });
});
