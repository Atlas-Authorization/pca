import { describe, expect, it } from 'vitest';
import { memoryLeaseKv } from './lease';
import { LEASES_PATH, LeaseRegistry, leaseManagementMetadata, leaseResourceHandler, signLease, signLeaseRevocation, type NewLease } from './index';
import { LEASE_AUTH } from './test-support/lease-vectors';

const SK = new Uint8Array(32).fill(31);
const ROGUE = new Uint8Array(32).fill(32);
const T0 = 1_800_000_000_000;
const base: NewLease = { lease_id: 'L1', path: 'a/b', grant_ref: 'g', holder: 'agent', requester: 'alice', approvers: ['bob'], justification_digest: 'j1', seq: 1, issued_at: T0, renewed_at: T0, expires_at: T0 + 1000, max_ttl: 5000 };
const lease = signLease(SK, base);
const down = { get: async () => { throw new Error('down'); }, update: async () => { throw new Error('down'); } };

const mk = (kv?: typeof down, now = T0 + 10) => {
  const reg = new LeaseRegistry({ authorities: [LEASE_AUTH] }, kv ?? memoryLeaseKv());
  const h = leaseResourceHandler(reg, { authenticate: (r) => (r.query?.as === 'admin' ? { admin: true } : r.query?.as === 'agent' ? { principal: 'agent' } : r.query?.as === 'none' ? {} : null), now: () => now });
  return { reg, h };
};
const admin = { as: 'admin' };

describe('lease routes: fail closed', () => {
  it('pins the mount path and discovery fragment', () => {
    expect(LEASES_PATH).toBe('/pca/leases');
    expect(leaseManagementMetadata('https://as.example')).toEqual({ leases: { leases_endpoint: 'https://as.example/pca/leases', revoke_targets: ['lease', 'prefix', 'grant'] } });
  });
  it('no caller, a caller without principal or admin, and a throwing authenticator are 401 / 401 / 500', async () => {
    const { h } = mk();
    expect(await h({ method: 'GET', path: '/pca/leases/L1' })).toEqual({ status: 401, body: { error: 'unauthenticated' } });
    expect(await h({ method: 'GET', path: '/pca/leases/L1', query: { as: 'none' } })).toEqual({ status: 401, body: { error: 'unauthenticated' } });
    const boom = leaseResourceHandler(new LeaseRegistry({ authorities: [LEASE_AUTH] }, memoryLeaseKv()), { authenticate: () => { throw new Error('secret'); } });
    expect(await boom({ method: 'GET', path: '/pca/leases/L1' })).toEqual({ status: 500, body: { error: 'server_error' } });
  });
  it('unknown paths and methods are 404; a non-admin may not issue or revoke (403)', async () => {
    const { h } = mk();
    for (const [method, path] of [['GET', '/other/leases'], ['GET', '/pca/other'], ['GET', '/pca/leases'], ['PUT', '/pca/leases/L1'], ['GET', '/pca/leases/L1/check'], ['POST', '/pca/leases/L1/zzz'], ['GET', '/pca/leases/revoke']] as const) {
      expect(await h({ method, path, query: admin })).toEqual({ status: 404, body: { error: 'not_found' } });
    }
    expect(await h({ method: 'POST', path: '/pca/leases', query: { as: 'agent' }, body: { lease } })).toEqual({ status: 403, body: { error: 'forbidden' } });
    expect(await h({ method: 'POST', path: '/pca/leases/revoke', query: { as: 'agent' }, body: {} })).toEqual({ status: 403, body: { error: 'forbidden' } });
  });
  it('issue refuses a malformed record, a foreign authority and a separation-of-duties breach with the exact code', async () => {
    const { h, reg } = mk();
    expect(await h({ method: 'POST', path: '/pca/leases', query: admin, body: 'nope' })).toEqual({ status: 400, body: { error: 'bad_record' } });
    expect(await h({ method: 'POST', path: '/pca/leases', query: admin, body: { lease: { ...lease, expires_at: lease.expires_at + 1 } } })).toEqual({ status: 400, body: { error: 'bad_record' } });
    expect(await h({ method: 'POST', path: '/pca/leases', query: admin, body: { lease: signLease(ROGUE, base) } })).toEqual({ status: 403, body: { error: 'unknown_authority' } });
    expect(await h({ method: 'POST', path: '/pca/leases', query: admin, body: { lease: signLease(SK, { ...base, approvers: ['alice'] }) } })).toEqual({
      status: 403, body: { error: 'sod', message: 'the requester may not approve their own request' },
    });
    // a delegation chain naming an approver is honoured; a non-string chain is ignored (treated as empty)
    expect((await h({ method: 'POST', path: '/pca/leases', query: admin, body: { lease, chain: ['bob'] } })).status).toBe(403);
    expect((await h({ method: 'POST', path: '/pca/leases', query: admin, body: { lease, chain: [1] } })).status).toBe(201);
    expect(await reg.get('L1')).toEqual(lease);
  });
  it('a renewal that does not extend, replays the reason or skips a seq is 422 / 422 / 409', async () => {
    const { h } = mk();
    await h({ method: 'POST', path: '/pca/leases', query: admin, body: { lease } });
    const renew = (over: Partial<NewLease>) => signLease(SK, { ...base, seq: 2, renewed_at: T0 + 500, expires_at: T0 + 2000, justification_digest: 'j2', ...over });
    expect((await h({ method: 'POST', path: '/pca/leases', query: admin, body: { lease: renew({ justification_digest: 'j1' }) } })).body).toEqual({ error: 'stale_justification' });
    expect((await h({ method: 'POST', path: '/pca/leases', query: admin, body: { lease: renew({ expires_at: T0 + 1000 }) } })).body).toEqual({ error: 'not_extending' });
    expect((await h({ method: 'POST', path: '/pca/leases', query: admin, body: { lease: renew({}) } })).status).toBe(201);
    expect((await h({ method: 'POST', path: '/pca/leases', query: admin, body: { lease: renew({ seq: 4 }) } })).status).toBe(409);
    expect((await h({ method: 'POST', path: '/pca/leases', query: admin, body: { lease: renew({ expires_at: T0 + 2500 }) } })).status).toBe(409); // same seq 2, different record: a fork
  });
  it('revoke refuses a malformed or foreign revocation; a covering revocation blocks a later issue', async () => {
    const { h } = mk();
    expect(await h({ method: 'POST', path: '/pca/leases/revoke', query: admin, body: {} })).toEqual({ status: 400, body: { error: 'bad_record' } });
    const foreign = signLeaseRevocation(ROGUE, { target: 'lease', value: 'L1', revoked_at: T0 + 5 });
    expect(await h({ method: 'POST', path: '/pca/leases/revoke', query: admin, body: { revocation: foreign } })).toEqual({ status: 403, body: { error: 'unknown_authority' } });
    const good = signLeaseRevocation(SK, { target: 'grant', value: 'g', revoked_at: T0 + 5 });
    expect(await h({ method: 'POST', path: '/pca/leases/revoke', query: admin, body: { revocation: good } })).toEqual({ status: 200, body: { ok: true, revoked: 0 } });
    expect(await h({ method: 'POST', path: '/pca/leases', query: admin, body: { lease } })).toEqual({ status: 409, body: { error: 'revoked' } });
  });
  it('read and check: only the holder or an admin; unknown, foreign, malformed and expired are refused with the decision code', async () => {
    const { h } = mk(undefined, T0 + 2000); // inside the cap (5000), past expiry (1000)
    await h({ method: 'POST', path: '/pca/leases', query: admin, body: { lease } });
    expect((await h({ method: 'GET', path: '/pca/leases/L1', query: admin })).body).toMatchObject({ lease, history: [{ seq: 1, renewed_at: T0, expires_at: T0 + 1000, justification_digest: 'j1' }] });
    expect((await h({ method: 'GET', path: '/pca/leases/L1', query: { as: 'agent' } })).status).toBe(200);
    expect(await h({ method: 'GET', path: '/pca/leases/NOPE', query: admin })).toEqual({ status: 404, body: { error: 'not_found' } });
    expect((await h({ method: 'POST', path: '/pca/leases/NOPE/check', query: admin, body: { lease } })).status).toBe(404);
    expect((await h({ method: 'POST', path: '/pca/leases/L1/check', query: { as: 'agent' }, body: { lease } })).body).toEqual({ decision: 'deny', code: 'expired', lease_id: 'L1' });
    expect(await h({ method: 'POST', path: '/pca/leases/L1/check', query: admin, body: {} })).toEqual({ status: 403, body: { decision: 'deny', code: 'bad_record' } });
  });
  it('check allows inside the window with the exact decision and uses the injected clock', async () => {
    const { h } = mk(undefined, T0 + 10);
    await h({ method: 'POST', path: '/pca/leases', query: admin, body: { lease } });
    expect(await h({ method: 'POST', path: '/pca/leases/L1/check', query: admin, body: { lease } })).toEqual({ status: 200, body: { decision: 'allow', lease_id: 'L1', expires_at: T0 + 1000 } });
  });
  it('an unreachable store is 503 on issue and revoke, 500 on read, and never an allow', async () => {
    const { h } = mk(down);
    expect(await h({ method: 'POST', path: '/pca/leases', query: admin, body: { lease } })).toEqual({ status: 503, body: { error: 'store_unreachable' } });
    expect(await h({ method: 'POST', path: '/pca/leases/revoke', query: admin, body: { revocation: signLeaseRevocation(SK, { target: 'lease', value: 'L1', revoked_at: T0 }) } })).toEqual({ status: 503, body: { error: 'store_unreachable' } });
    expect(await h({ method: 'GET', path: '/pca/leases/L1', query: admin })).toEqual({ status: 500, body: { error: 'server_error' } });
    expect((await h({ method: 'POST', path: '/pca/leases/L1/check', query: admin, body: { lease } })).status).toBe(500);
  });
});
