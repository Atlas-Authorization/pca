import { describe, expect, it } from 'vitest';
import { b64u, publicKeyOf } from '@atlasauth/pca';
import { LeaseRegistry, checkLease, leaseResourceHandler, renewLease, signLease, signLeaseRevocation, sodError, pathUnder, type NewLease } from './index';
import { buildLeaseVectors, LEASE_AUTH } from './test-support/lease-vectors';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const SK = new Uint8Array(32).fill(31);
const T0 = 1_800_000_000_000;
const base: NewLease = { lease_id: 'L1', path: 'a/b', grant_ref: 'g', holder: 'agent', requester: 'alice', approvers: ['bob'], justification_digest: 'j1', seq: 1, issued_at: T0, renewed_at: T0, expires_at: T0 + 1000, max_ttl: 5000 };

describe('lease vectors', () => {
  it('the checked-in vectors are current and the reference agrees with every hand-written expectation', async () => {
    const want = `${JSON.stringify(await buildLeaseVectors(), null, 2)}\n`;
    expect(readFileSync(join(__dirname, '..', '..', 'pca', 'conformance', 'lease-vectors.json'), 'utf8')).toBe(want);
    expect(LEASE_AUTH).toBe(b64u(publicKeyOf(SK)));
  });
});

describe('lease helpers', () => {
  it('signLease refuses a lease past its cap', () => {
    expect(() => signLease(SK, { ...base, expires_at: T0 + 5001 })).toThrow();
    expect(signLease(SK, { ...base, expires_at: T0 + 5000 }).expires_at).toBe(T0 + 5000);
  });
  it('pathUnder is segment bounded', () => {
    expect(pathUnder('db/prod/ro', 'db/prod')).toBe(true);
    expect(pathUnder('db/prod', 'db/prod')).toBe(true);
    expect(pathUnder('db/production', 'db/prod')).toBe(false);
  });
  it('sodError returns the exact reason', () => {
    expect(sodError({ requester: 'a', holder: 'h', approvers: ['a'] })).toBe('the requester may not approve their own request');
    expect(sodError({ requester: 'a', holder: 'h', approvers: ['h'] })).toBe('the holder may not approve its own lease');
    expect(sodError({ requester: 'a', holder: 'h', approvers: [] }, { minApprovals: 2 })).toBe('0 approver(s), need 2');
    expect(sodError({ requester: 'a', holder: 'h', approvers: ['x'] }, { minApprovals: 0 })).toBe('minApprovals must be a positive integer');
  });
  it('renewLease extends from now, caps at max_ttl, and a veto stops it (signals never lengthen)', async () => {
    const reg = new LeaseRegistry({ authorities: [LEASE_AUTH] }, memoryLeaseKv());
    await reg.accept(signLease(SK, base));
    const v = await renewLease(SK, reg, 'L1', { now: T0 + 500, increment: 1000, justification_digest: 'j2', veto: () => true });
    expect(v).toEqual({ ok: false, code: 'vetoed' });
    const r = await renewLease(SK, reg, 'L1', { now: T0 + 500, increment: 100_000, justification_digest: 'j2' });
    expect(r.ok && r.record.expires_at).toBe(T0 + 5000);
    expect((await reg.history('L1')).map((h) => h.seq)).toEqual([1, 2]);
    expect(await renewLease(SK, reg, 'L1', { now: T0 + 600, increment: 100_000, justification_digest: 'j3' })).toEqual({ ok: false, code: 'not_extending' });
    expect(await renewLease(SK, reg, 'nope', { now: T0, increment: 1, justification_digest: 'x' })).toEqual({ ok: false, code: 'unknown_lease' });
  });
  it('a throwing store fails closed', async () => {
    const kv = { get: async () => { throw new Error('down'); }, update: async () => { throw new Error('down'); } };
    const reg = new LeaseRegistry({ authorities: [LEASE_AUTH] }, kv);
    expect(await reg.accept(signLease(SK, base))).toEqual({ ok: false, code: 'store_unreachable' });
    expect(await checkLease(signLease(SK, base), reg, T0 + 1)).toEqual({ decision: 'deny', code: 'store_unreachable', lease_id: 'L1' });
  });
});

describe('hosted lease routes', () => {
  const mk = () => {
    const reg = new LeaseRegistry({ authorities: [LEASE_AUTH] }, memoryLeaseKv());
    let now = T0 + 10;
    const h = leaseResourceHandler(reg, { authenticate: (r) => (r.query?.as === 'admin' ? { admin: true } : r.query?.as === 'agent' ? { principal: 'agent' } : r.query?.as === 'eve' ? { principal: 'eve' } : null), now: () => now });
    return { h, setNow: (n: number) => { now = n; } };
  };
  it('issue, read, check, revoke', async () => {
    const { h } = mk();
    const lease = signLease(SK, base);
    expect((await h({ method: 'POST', path: '/pca/leases', body: { lease } })).status).toBe(401);
    expect((await h({ method: 'POST', path: '/pca/leases', query: { as: 'agent' }, body: { lease } })).status).toBe(403);
    expect((await h({ method: 'POST', path: '/pca/leases', query: { as: 'admin' }, body: { lease } })).status).toBe(201);
    expect((await h({ method: 'POST', path: '/pca/leases', query: { as: 'admin' }, body: { lease } })).status).toBe(200);
    expect((await h({ method: 'POST', path: '/pca/leases', query: { as: 'admin' }, body: { lease: { ...lease, holder: 'x' } } })).status).toBe(400);
    expect((await h({ method: 'GET', path: '/pca/leases/L1', query: { as: 'agent' } })).status).toBe(200);
    expect((await h({ method: 'GET', path: '/pca/leases/L1', query: { as: 'eve' } })).status).toBe(404);
    expect((await h({ method: 'POST', path: '/pca/leases/L1/check', query: { as: 'agent' }, body: { lease } })).status).toBe(200);
    const revocation = signLeaseRevocation(SK, { target: 'prefix', value: 'a', revoked_at: T0 + 20 });
    expect((await h({ method: 'POST', path: '/pca/leases/revoke', query: { as: 'agent' }, body: { revocation } })).status).toBe(403);
    expect((await h({ method: 'POST', path: '/pca/leases/revoke', query: { as: 'admin' }, body: { revocation } })).body).toEqual({ ok: true, revoked: 1 });
    expect((await h({ method: 'POST', path: '/pca/leases/L1/check', query: { as: 'agent' }, body: { lease } })).status).toBe(403);
    expect((await h({ method: 'GET', path: '/nope', query: { as: 'admin' } })).status).toBe(404);
  });
});

import { runLeaseStoreConformance, memoryLeaseKv, shardOf, DEFAULT_LEASE_SHARDS } from './index';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

describe('lease storage conformance kit', () => {
  it('the in-memory store passes', async () => {
    const passed = await runLeaseStoreConformance({ open: () => memoryLeaseKv(), reopen: (kv) => kv });
    expect(passed).toEqual(['spread', 'atomic update', 'independent leases', 'revocation placement', 'shard count is pinned', 'state survives a restart', 'pruning bounds revocations']);
  });
  it('the crash-safe durable state passes', async () => {
    const { openDurableState } = await import('@atlasauth/pca/durable-state');
    const dirs: string[] = [];
    const dirOf = new Map<object, string>();
    const opened: { close?: () => void }[] = [];
    try {
      const passed = await runLeaseStoreConformance({
        open: async () => { const dir = mkdtempSync(`${tmpdir()}/lease-kit-`); dirs.push(dir); const s = await openDurableState({ dir }); opened.push(s as never); dirOf.set(s, dir); return s; },
        // a restarted process: a second handle on the same directory
        reopen: async (kv) => { const s = await openDurableState({ dir: dirOf.get(kv)! }); opened.push(s as never); return s; },
      });
      expect(passed).toHaveLength(7);
    } finally { for (const o of opened) o.close?.(); for (const d of dirs) rmSync(d, { recursive: true, force: true }); }
  }, 120_000);
  it('shardOf is stable and bounded', () => {
    expect(shardOf('lease-1', 16)).toBe(shardOf('lease-1', 16));
    for (let i = 0; i < 200; i++) expect(shardOf(`x${i}`, 7)).toBeLessThan(7);
    expect(DEFAULT_LEASE_SHARDS).toBe(16);
  });
  it('bad shard counts and ceilings are refused at construction', () => {
    for (const shards of [0, -1, 1.5, 4097]) expect(() => new LeaseRegistry({ authorities: [] }, memoryLeaseKv(), { shards })).toThrow('shards must be an integer from 1 to 4096');
    expect(() => new LeaseRegistry({ authorities: [], maxTtlCeiling: 0 }, memoryLeaseKv())).toThrow('maxTtlCeiling must be a positive integer');
  });
});
