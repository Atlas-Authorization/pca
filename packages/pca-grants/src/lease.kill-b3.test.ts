import { describe, expect, it } from 'vitest';
import {
  LeaseRegistry,
  checkLease,
  memoryLeaseKv,
  renewLease,
  shardOf,
  signLease,
  signLeaseRevocation,
  signLeaseUnsafeOverCap,
  sodError,
  type LeaseKv,
  type NewLease,
} from './lease';
import { signerOf } from './sig';

const SK = new Uint8Array(32).fill(61);
const AUTH = signerOf(SK);
const T0 = 1_800_000_000_000;
const base: NewLease = { lease_id: 'L1', path: 'a/b', grant_ref: 'g', holder: 'agent', requester: 'alice', approvers: ['bob'], justification_digest: 'j1', seq: 1, issued_at: T0, renewed_at: T0, expires_at: T0 + 1000, max_ttl: 5000 };
const policy = { authorities: [AUTH] };

describe('lease records', () => {
  it('signing refusals carry their exact messages', () => {
    expect(() => signLease(SK, { ...base, expires_at: T0 + 5001 })).toThrow(new RangeError('signLease: a malformed lease, or one past issued_at + max_ttl'));
    expect(() => signLeaseUnsafeOverCap(SK, { ...base, lease_id: '' })).toThrow(new RangeError('signLeaseUnsafeOverCap: malformed'));
    expect(signLeaseUnsafeOverCap(SK, { ...base, expires_at: T0 + 9000 }).expires_at).toBe(T0 + 9000);
  });
  it('max_ttl of 1 is the smallest allowed, 0 is not; a renewal cannot predate the issue', () => {
    expect(signLease(SK, { ...base, max_ttl: 1, expires_at: T0 + 1 }).max_ttl).toBe(1);
    expect(() => signLease(SK, { ...base, max_ttl: 0, expires_at: T0 + 1 })).toThrow(RangeError);
    expect(() => signLease(SK, { ...base, seq: 2, renewed_at: T0 - 1, expires_at: T0 + 10 })).toThrow(RangeError);
    expect(signLease(SK, { ...base, seq: 2, renewed_at: T0, expires_at: T0 + 10 }).seq).toBe(2);
  });
  it('sodError has no implicit chain', () => {
    expect(sodError({ requester: 'a', holder: 'h', approvers: ['Stryker was here'] })).toBeNull();
  });
});

describe('LeaseRegistry construction', () => {
  const msg = 'LeaseRegistry: a durable key-value store is required (memoryLeaseKv() is for tests and single-process use)';
  it('needs a store with get and update', () => {
    const kv = memoryLeaseKv();
    expect(() => new LeaseRegistry(policy, undefined as never)).toThrow(new TypeError(msg));
    expect(() => new LeaseRegistry(policy, { update: kv.update } as never)).toThrow(new TypeError(msg));
    expect(() => new LeaseRegistry(policy, { get: kv.get } as never)).toThrow(new TypeError(msg));
  });
  it('shard count bounds are 1 and 4096 inclusive', () => {
    const shardsMsg = 'LeaseRegistry: shards must be an integer from 1 to 4096';
    expect(new LeaseRegistry(policy, memoryLeaseKv(), { shards: 1 }).shardCount).toBe(1);
    expect(new LeaseRegistry(policy, memoryLeaseKv(), { shards: 4096 }).shardCount).toBe(4096);
    for (const shards of [0, 4097, 1.5]) expect(() => new LeaseRegistry(policy, memoryLeaseKv(), { shards })).toThrow(new RangeError(shardsMsg));
  });
  it('the ttl ceiling must be a positive integer, 1 included', () => {
    expect(() => new LeaseRegistry({ ...policy, maxTtlCeiling: 1 }, memoryLeaseKv())).not.toThrow();
    for (const maxTtlCeiling of [0, 1.5]) {
      expect(() => new LeaseRegistry({ ...policy, maxTtlCeiling }, memoryLeaseKv())).toThrow(new RangeError('LeaseRegistry: maxTtlCeiling must be a positive integer'));
    }
  });
});

describe('LeaseRegistry.accept', () => {
  it('an approver named like the old placeholder is not rejected for a chain it is not in', async () => {
    const reg = new LeaseRegistry(policy, memoryLeaseKv());
    expect(await reg.accept(signLease(SK, { ...base, approvers: ['Stryker was here'] }))).toEqual({ ok: true, replaced: true, seq: 1 });
  });
  it('the ttl ceiling admits max_ttl up to and including itself and refuses above', async () => {
    const reg = new LeaseRegistry({ ...policy, maxTtlCeiling: 5000 }, memoryLeaseKv());
    expect(await reg.accept(signLease(SK, base))).toEqual({ ok: true, replaced: true, seq: 1 });
    expect(await reg.accept(signLease(SK, { ...base, lease_id: 'L2', max_ttl: 4000, expires_at: T0 + 1000 }))).toMatchObject({ ok: true });
    expect(await reg.accept(signLease(SK, { ...base, lease_id: 'L3', max_ttl: 5001 }))).toEqual({ ok: false, code: 'ttl_ceiling' });
  });
  it('a new lease must start at seq 1, with the reason', async () => {
    const reg = new LeaseRegistry(policy, memoryLeaseKv());
    expect(await reg.accept(signLease(SK, { ...base, seq: 2, renewed_at: T0 + 1, expires_at: T0 + 1000 }))).toEqual({ ok: false, code: 'bad_seq', reason: 'a new lease starts at seq 1' });
  });
  it('a renewal at the same instant as the previous record is accepted if it extends the expiry', async () => {
    const reg = new LeaseRegistry(policy, memoryLeaseKv());
    await reg.accept(signLease(SK, base));
    const same = signLease(SK, { ...base, seq: 2, renewed_at: T0, expires_at: T0 + 2000, justification_digest: 'j2' });
    expect(await reg.accept(same)).toEqual({ ok: true, replaced: true, seq: 2 });
  });
  it('an error after the update ran is still reported as store_unreachable', async () => {
    const inner = memoryLeaseKv();
    const kv: LeaseKv = {
      get: (k) => inner.get(k),
      async update(k, fn) {
        const r = await inner.update(k, fn);
        if (k !== 'lease/meta') throw new Error('late failure');
        return r;
      },
    };
    expect(await new LeaseRegistry(policy, kv).accept(signLease(SK, base))).toEqual({ ok: false, code: 'store_unreachable' });
  });
  it('a store pinned to another shard count refuses every operation', async () => {
    const kv = memoryLeaseKv();
    await new LeaseRegistry(policy, kv, { shards: 4 }).accept(signLease(SK, base));
    const other = new LeaseRegistry(policy, kv, { shards: 8 });
    expect(await other.accept(signLease(SK, { ...base, lease_id: 'L9' }))).toEqual({ ok: false, code: 'store_unreachable' });
    expect(await other.revoke(signLeaseRevocation(SK, { target: 'prefix', value: 'a', revoked_at: T0 }))).toEqual({ ok: false, code: 'store_unreachable' });
    await expect(other.get('L1')).rejects.toThrow(new Error('shard count mismatch'));
    expect(await checkLease(signLease(SK, base), other, T0 + 1)).toEqual({ decision: 'deny', code: 'store_unreachable', lease_id: 'L1' });
  });
});

describe('revocation coverage and pruning', () => {
  it('a revocation at the exact issue time covers the lease', async () => {
    const reg = new LeaseRegistry(policy, memoryLeaseKv());
    await reg.accept(signLease(SK, base));
    expect(await reg.revoke(signLeaseRevocation(SK, { target: 'prefix', value: 'a', revoked_at: T0 }))).toEqual({ ok: true, revoked: 1 });
    expect(await reg.revoke(signLeaseRevocation(SK, { target: 'prefix', value: 'a', revoked_at: T0 - 1 }))).toMatchObject({ revoked: 0 });
  });
  it('with a ceiling, a revocation is kept through revoked_at + ceiling and dropped after it', async () => {
    const clock = { t: 10_000 };
    const reg = new LeaseRegistry({ ...policy, maxTtlCeiling: 100 }, memoryLeaseKv(), { shards: 1, clock: () => clock.t });
    await reg.revoke(signLeaseRevocation(SK, { target: 'prefix', value: 'zz', revoked_at: 10_000 }));
    expect(await reg.shardRevocations(0)).toHaveLength(1);
    clock.t = 10_100;
    await reg.revoke(signLeaseRevocation(SK, { target: 'prefix', value: 'yy', revoked_at: 10_100 }));
    expect(await reg.shardRevocations(0)).toHaveLength(2);
    clock.t = 10_201;
    await reg.accept(signLease(SK, { ...base, lease_id: 'P1', max_ttl: 100, issued_at: 20_000, renewed_at: 20_000, expires_at: 20_050 }));
    expect(await reg.shardRevocations(0)).toEqual([]);
  });
  it('the exact boundary instant keeps the revocation', async () => {
    const clock = { t: 10_100 };
    const reg = new LeaseRegistry({ ...policy, maxTtlCeiling: 100 }, memoryLeaseKv(), { shards: 1, clock: () => clock.t });
    await reg.revoke(signLeaseRevocation(SK, { target: 'prefix', value: 'zz', revoked_at: 10_000 }));
    expect(await reg.shardRevocations(0)).toHaveLength(1);
  });
  it('the default clock is the wall clock', async () => {
    const reg = new LeaseRegistry({ ...policy, maxTtlCeiling: 10_000 }, memoryLeaseKv(), { shards: 1 });
    const issued = 1000;
    await reg.accept(signLease(SK, { ...base, issued_at: issued, renewed_at: issued, expires_at: issued + 500, max_ttl: 5000 }));
    await reg.revoke(signLeaseRevocation(SK, { target: 'lease', value: 'L1', revoked_at: Date.now() }));
    expect(await reg.shardRevocations(0)).toHaveLength(1);
    expect((await reg.lookup('L1'))?.revoked).toBe(true);
  });
});

describe('history and renewal', () => {
  it('the history of an unknown lease is empty', async () => {
    expect(await new LeaseRegistry(policy, memoryLeaseKv()).history('nope')).toEqual([]);
  });
  it('renewal rejects inputs that are not safe integers or increments below one', async () => {
    const reg = new LeaseRegistry(policy, memoryLeaseKv());
    await reg.accept(signLease(SK, base));
    const o = { now: T0 + 10, increment: 100, justification_digest: 'j2' };
    for (const bad of [{ now: 1.5 }, { increment: 1.5 }, { increment: 0 }, { now: Number.NaN }]) {
      expect(await renewLease(SK, reg, 'L1', { ...o, ...bad }), JSON.stringify(bad)).toEqual({ ok: false, code: 'bad_input' });
    }
  });
  it('a renewal that cannot be signed is expired_lease at or past the cap and bad_input before the issue time', async () => {
    const reg = new LeaseRegistry(policy, memoryLeaseKv());
    await reg.accept(signLease(SK, base));
    const cap = T0 + 5000;
    expect(await renewLease(SK, reg, 'L1', { now: cap, increment: 100, justification_digest: 'j2' })).toEqual({ ok: false, code: 'expired_lease' });
    expect(await renewLease(SK, reg, 'L1', { now: cap + 10, increment: 100, justification_digest: 'j2' })).toEqual({ ok: false, code: 'expired_lease' });
    expect(await renewLease(SK, reg, 'L1', { now: T0 - 5, increment: 100, justification_digest: 'j2' })).toEqual({ ok: false, code: 'bad_input' });
  });
});
