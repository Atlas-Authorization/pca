/**
 * Mutation kills for the 0.5.0 flagship gate survivors in ha.ts: the liveGuardians / quorumStatus / selectSigners input
 * guards (non-finite stale window, zero window, null or primitive guardians, a null set, quorum 1 and negative or
 * fractional quorums), validateGuardianSet's exact messages, the lease record checks (eqLease field by field, validRecord
 * on every malformed shape), leaseOpts bounds (holder length 256, ttl 2 and MAX_LEASE_TTL_MS, skew 0 and the default),
 * every lease call's lost-race / store-error / 'unknown' detail branch, the stale checks of renew / release / assertFence,
 * FenceError's message and name, the fenced signer's no-lease refusal, the fence guard's initial value and epoch floor,
 * and KvLeaseStore refusing a corrupt stored record. All clocks are injected; nothing waits on real time.
 */
import { describe, expect, it } from 'vitest';
import { createMemoryDurableKv } from './durable-state';
import {
  FenceError,
  KvLeaseStore,
  MAX_LEASE_TTL_MS,
  acquireLease,
  assertFence,
  createFenceGuard,
  fencedSigner,
  liveGuardians,
  quorumStatus,
  releaseLease,
  renewLease,
  selectSigners,
  validateGuardianSet,
  type GuardianHealth,
  type LeaseRecord,
  type LeaseStore,
} from './ha';

const NOW = 1_000_000;
const G = (id: string, lastSeen = NOW): GuardianHealth => ({ id, healthy: true, lastSeen });
const O = { ttlMs: 10_000, skewMs: 1_000 };

/** A store with a fixed record and clock; cas answers `casResult` (or throws `throwOn`). */
function fixed(cur: unknown, opts: { now?: number; cas?: boolean; throwOn?: unknown } = {}): LeaseStore & { writes: LeaseRecord[] } {
  const writes: LeaseRecord[] = [];
  return {
    writes,
    async read() {
      if (opts.throwOn !== undefined) throw opts.throwOn;
      return cur as LeaseRecord | undefined;
    },
    async cas(_e, next) {
      writes.push(next);
      return opts.cas ?? true;
    },
    async now() {
      return opts.now ?? NOW;
    },
  };
}
const kvStore = (t = NOW) => {
  const kv = createMemoryDurableKv();
  return { kv, store: new KvLeaseStore(kv, { now: () => t }) };
};

describe('liveGuardians / quorumStatus / selectSigners guards', () => {
  it('an infinite stale window is refused (no guardian is live)', () => {
    expect(liveGuardians({ guardians: [G('a')], quorum: 1 }, NOW, { staleMs: Infinity })).toEqual([]);
  });
  it('a zero stale window keeps a heartbeat taken exactly now', () => {
    expect(liveGuardians({ guardians: [G('a'), G('b', NOW - 1)], quorum: 1 }, NOW, { staleMs: 0 }).map((g) => g.id)).toEqual(['a']);
  });
  it('a null or primitive guardian voids the whole set', () => {
    expect(liveGuardians({ guardians: [G('a'), null as never], quorum: 1 }, NOW)).toEqual([]);
    expect(liveGuardians({ guardians: [G('a'), 5 as never], quorum: 1 }, NOW)).toEqual([]);
    expect(liveGuardians({ guardians: [5 as never, G('a')], quorum: 1 }, NOW)).toEqual([]);
  });
  it('a null set is empty, never a throw', () => {
    expect(liveGuardians(null as never, NOW)).toEqual([]);
    expect(quorumStatus(null as never, NOW)).toEqual({ total: 0, live: 0, quorum: undefined, available: false, degraded: false });
  });
  it('quorum 1 with one live guardian is available', () => {
    expect(quorumStatus({ guardians: [G('a')], quorum: 1 }, NOW)).toEqual({ total: 1, live: 1, quorum: 1, available: true, degraded: false });
  });
  it('selectSigners: quorum 1 picks one; negative and fractional quorums pick none', () => {
    const guardians = [G('a'), G('b')];
    expect(selectSigners({ guardians, quorum: 1 }, NOW)).toEqual(['a']);
    expect(selectSigners({ guardians, quorum: -1 }, NOW)).toEqual([]);
    expect(selectSigners({ guardians, quorum: 1.5 }, NOW)).toEqual([]);
  });
});

describe('validateGuardianSet messages', () => {
  it('null and a non-object set', () => {
    expect(validateGuardianSet(null as never)).toBe('guardian set is not an object');
    expect(validateGuardianSet('x' as never)).toBe('guardian set is not an object');
  });
  const ID = 'guardian id must be a non-empty string';
  it.each([
    ['null', null],
    ['a number', 5],
    ['a numeric id', { id: 7 }],
    ['an array id', { id: ['x'] }],
    ['an empty id', { id: '' }],
    ['a function with a string id', Object.assign(() => undefined, { id: 'b' })],
  ])('a guardian that is %s', (_n, x) => {
    expect(validateGuardianSet({ guardians: [G('a'), x as never], quorum: 1 })).toBe(ID);
  });
});

describe('KvLeaseStore compare-and-swap and corrupt state', () => {
  const rec: LeaseRecord = { holder: 'a', epoch: 1, expiresAt: 100 };
  it('an expected record against an empty key does not match', async () => {
    const { store } = kvStore();
    expect(await store.cas(rec, { holder: 'a', epoch: 1, expiresAt: 200 })).toBe(false);
    expect(await store.read()).toBeUndefined();
  });
  it.each([
    ['holder', { holder: 'b', epoch: 1, expiresAt: 100 }],
    ['epoch', { holder: 'a', epoch: 2, expiresAt: 100 }],
    ['expiresAt', { holder: 'a', epoch: 1, expiresAt: 101 }],
  ])('an expected record differing only in %s does not match', async (_n, expected) => {
    const { kv, store } = kvStore();
    await kv.set('ha/lease', rec);
    expect(await store.cas(expected, { holder: 'a', epoch: 2, expiresAt: 300 })).toBe(false);
    expect(await store.read()).toEqual(rec);
    expect(await store.cas(rec, { holder: 'a', epoch: 2, expiresAt: 300 })).toBe(true);
  });
  it('a corrupt stored record is never overwritten, even when expected names it', async () => {
    const { kv, store } = kvStore();
    const bad = { holder: 'a', epoch: 0, expiresAt: 5 };
    await kv.set('ha/lease', bad);
    expect(await store.cas(bad as never, { holder: 'a', epoch: 1, expiresAt: 10 })).toBe(false);
    expect(await kv.get('ha/lease')).toEqual(bad);
    await expect(store.read()).rejects.toThrow(/^corrupt lease state$/);
  });
});

describe('validRecord: every malformed lease is invalid', () => {
  it.each([
    ['null', null],
    ['a function carrying the fields', Object.assign(() => undefined, { holder: 'a', epoch: 1, expiresAt: 5 })],
    ['a numeric holder', { holder: 5, epoch: 1, expiresAt: 5 }],
    ['epoch 0', { holder: 'a', epoch: 0, expiresAt: 5 }],
    ['a fractional epoch', { holder: 'a', epoch: 1.5, expiresAt: 5 }],
    ['a NaN expiry', { holder: 'a', epoch: 1, expiresAt: NaN }],
    ['a negative expiry', { holder: 'a', epoch: 1, expiresAt: -1 }],
  ])('releaseLease and renewLease refuse %s', async (_n, lease) => {
    const s = fixed({ holder: 'a', epoch: 1, expiresAt: NOW + 50_000 });
    expect(await releaseLease(s, lease as never)).toEqual({ ok: false, reason: 'invalid' });
    expect(await renewLease(s, lease as never, O)).toEqual({ ok: false, reason: 'invalid' });
    expect(s.writes).toEqual([]);
  });
});

describe('leaseOpts bounds', () => {
  const ok = (holder: string, o: unknown) => acquireLease(kvStore().store, holder, o as never);
  it('holder length 256 is allowed, 257 is not; a non-string or null holder is invalid', async () => {
    expect((await ok('h'.repeat(256), O)).ok).toBe(true);
    expect(await ok('h'.repeat(257), O)).toEqual({ ok: false, reason: 'invalid' });
    expect(await ok(5 as never, O)).toEqual({ ok: false, reason: 'invalid' });
    expect(await ok(null as never, O)).toEqual({ ok: false, reason: 'invalid' });
  });
  it('missing options are invalid, not a throw', async () => {
    expect(await ok('a', undefined)).toEqual({ ok: false, reason: 'invalid' });
    expect(await ok('a', null)).toEqual({ ok: false, reason: 'invalid' });
  });
  it('ttl 2 with skew 0 is the smallest lease; ttl 1 is invalid', async () => {
    expect(await ok('a', { ttlMs: 2, skewMs: 0 })).toEqual({ ok: true, lease: { holder: 'a', epoch: 1, expiresAt: NOW + 2 } });
    expect(await ok('a', { ttlMs: 1, skewMs: 0 })).toEqual({ ok: false, reason: 'invalid' });
  });
  it('ttl MAX_LEASE_TTL_MS is allowed', async () => {
    expect(await ok('a', { ttlMs: MAX_LEASE_TTL_MS })).toEqual({ ok: true, lease: { holder: 'a', epoch: 1, expiresAt: NOW + MAX_LEASE_TTL_MS } });
  });
  it('skew defaults to 1000 ms', async () => {
    const { store } = kvStore();
    const r = await acquireLease(store, 'a', { ttlMs: 10_000 });
    expect(r).toEqual({ ok: true, lease: { holder: 'a', epoch: 1, expiresAt: NOW + 10_000 } });
    // renewal is refused once expiry minus the default 1000 ms skew has passed
    const late = new KvLeaseStore(createMemoryDurableKv(), { now: () => NOW + 9_000 });
    await late.cas(undefined, (r as { lease: LeaseRecord }).lease);
    expect(await renewLease(late, (r as { lease: LeaseRecord }).lease, { ttlMs: 10_000 })).toEqual({ ok: false, reason: 'expired' });
  });
});

describe('acquireLease', () => {
  it('a released lease is free even while the store clock is below the skew', async () => {
    const { store } = kvStore(500);
    const a = await acquireLease(store, 'a', O);
    expect(a).toEqual({ ok: true, lease: { holder: 'a', epoch: 1, expiresAt: 10_500 } });
    expect((await releaseLease(store, (a as { lease: LeaseRecord }).lease)).ok).toBe(true);
    expect(await acquireLease(store, 'b', O)).toEqual({ ok: true, lease: { holder: 'b', epoch: 2, expiresAt: 10_500 } });
  });
  it('a corrupt record or clock is a store error naming it', async () => {
    const corrupt = { ok: false, reason: 'store-error', detail: 'corrupt lease state' };
    expect(await acquireLease(fixed({ holder: 'a', epoch: 0, expiresAt: 1 }), 'b', O)).toEqual(corrupt);
    expect(await acquireLease(fixed(undefined, { now: NaN }), 'b', O)).toEqual(corrupt);
  });
  it('a non-Error throw has detail unknown', async () => {
    expect(await acquireLease(fixed(undefined, { throwOn: 'x' }), 'a', O)).toEqual({ ok: false, reason: 'store-error', detail: 'unknown' });
  });
});

describe('renewLease', () => {
  const mine: LeaseRecord = { holder: 'a', epoch: 1, expiresAt: NOW + 5_000 };
  it('no stored lease is stale', async () => {
    expect(await renewLease(kvStore().store, mine, O)).toEqual({ ok: false, reason: 'stale' });
  });
  it('another holder at the same epoch is stale', async () => {
    const s = fixed({ holder: 'b', epoch: 1, expiresAt: NOW + 5_000 });
    expect(await renewLease(s, mine, O)).toEqual({ ok: false, reason: 'stale' });
    expect(s.writes).toEqual([]);
  });
  it('a refused cas is lost-race', async () => {
    expect(await renewLease(fixed(mine, { cas: false }), mine, O)).toEqual({ ok: false, reason: 'lost-race' });
  });
  it('store errors carry the message, or unknown', async () => {
    expect(await renewLease(fixed(mine, { throwOn: new Error('boom') }), mine, O)).toEqual({ ok: false, reason: 'store-error', detail: 'boom' });
    expect(await renewLease(fixed(mine, { throwOn: 7 }), mine, O)).toEqual({ ok: false, reason: 'store-error', detail: 'unknown' });
  });
});

describe('releaseLease', () => {
  const mine: LeaseRecord = { holder: 'a', epoch: 1, expiresAt: NOW + 5_000 };
  it('no stored lease is stale', async () => {
    expect(await releaseLease(kvStore().store, mine)).toEqual({ ok: false, reason: 'stale' });
  });
  it.each([
    ['another holder at the same epoch', { holder: 'b', epoch: 1, expiresAt: NOW + 5_000 }],
    ['the same holder at a later epoch', { holder: 'a', epoch: 2, expiresAt: NOW + 5_000 }],
  ])('%s is stale', async (_n, cur) => {
    const s = fixed(cur);
    expect(await releaseLease(s, mine)).toEqual({ ok: false, reason: 'stale' });
    expect(s.writes).toEqual([]);
  });
  it('releasing twice: the second is stale', async () => {
    const { store } = kvStore();
    const a = (await acquireLease(store, 'a', O)) as { lease: LeaseRecord };
    expect(await releaseLease(store, a.lease)).toEqual({ ok: true, lease: { holder: 'a', epoch: 1, expiresAt: 0 } });
    expect(await releaseLease(store, a.lease)).toEqual({ ok: false, reason: 'stale' });
  });
  it('a refused cas is lost-race', async () => {
    expect(await releaseLease(fixed(mine, { cas: false }), mine)).toEqual({ ok: false, reason: 'lost-race' });
  });
  it('store errors carry the message, or unknown', async () => {
    expect(await releaseLease(fixed(mine, { throwOn: new Error('boom') }), mine)).toEqual({ ok: false, reason: 'store-error', detail: 'boom' });
    expect(await releaseLease(fixed(mine, { throwOn: 7 }), mine)).toEqual({ ok: false, reason: 'store-error', detail: 'unknown' });
  });
});

describe('assertFence', () => {
  const cur: LeaseRecord = { holder: 'a', epoch: 1, expiresAt: NOW + 5_000 };
  it('skew 0 is allowed; a negative or NaN skew is stale', async () => {
    expect(await assertFence(fixed(cur), cur, 0)).toEqual({ ok: true });
    expect(await assertFence(fixed(cur), cur, -1)).toEqual({ ok: false, reason: 'stale' });
    expect(await assertFence(fixed(cur), cur, NaN)).toEqual({ ok: false, reason: 'stale' });
  });
  it('a missing token is stale, not a store error', async () => {
    expect(await assertFence(fixed(cur), null as never)).toEqual({ ok: false, reason: 'stale' });
  });
  it('another holder at the same epoch, or the same holder at another epoch, is stale', async () => {
    expect(await assertFence(fixed({ ...cur, holder: 'b' }), cur)).toEqual({ ok: false, reason: 'stale' });
    expect(await assertFence(fixed({ ...cur, epoch: 2 }), cur)).toEqual({ ok: false, reason: 'stale' });
  });
});

describe('FenceError and fencedSigner', () => {
  it('message and name', () => {
    const e = new FenceError('stale');
    expect(e.message).toBe('fenced: stale');
    expect(e.name).toBe('FenceError');
    expect(e.reason).toBe('stale');
  });
  it('no lease refuses with no-lease before touching the store', async () => {
    const s = fixed({ holder: 'a', epoch: 1, expiresAt: NOW + 5_000 });
    let signed = 0;
    const f = fencedSigner(s, () => undefined, async () => ++signed);
    const err = await f().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(FenceError);
    expect((err as FenceError).reason).toBe('no-lease');
    expect((err as FenceError).message).toBe('fenced: no-lease');
    expect(signed).toBe(0);
  });
});

describe('createFenceGuard', () => {
  it('starts at a valid initial epoch and refuses below it', () => {
    const g = createFenceGuard(5);
    expect(g.highest()).toBe(5);
    expect(g.admit(4)).toBe(false);
  });
  it('a negative, fractional or -0 initial starts at 0', () => {
    expect(createFenceGuard(-3).highest()).toBe(0);
    expect(createFenceGuard(1.5).highest()).toBe(0);
    expect(createFenceGuard(-0).highest()).toBe(0);
    expect(createFenceGuard(0).highest()).toBe(0);
  });
  it('epoch 0 is never admitted, even by a fresh guard', () => {
    const g = createFenceGuard();
    expect(g.admit(0)).toBe(false);
    expect(g.highest()).toBe(0);
    expect(g.admit(1)).toBe(true);
  });
});
