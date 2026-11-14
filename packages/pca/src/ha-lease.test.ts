import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { createMemoryDurableKv, openDurableState } from './durable-state';
import {
  FenceError,
  KvLeaseStore,
  acquireLease,
  assertFence,
  createFenceGuard,
  fencedSigner,
  liveGuardians,
  quorumStatus,
  releaseLease,
  renewLease,
  selectSigners,
  type LeaseRecord,
  type LeaseStore,
} from './ha';

const O = { ttlMs: 10_000, skewMs: 1_000 };
function mk(): { store: KvLeaseStore; clock: { t: number } } {
  const clock = { t: 1_000_000 };
  return { store: new KvLeaseStore(createMemoryDurableKv(), { now: () => clock.t }), clock };
}
const okLease = (r: Awaited<ReturnType<typeof acquireLease>>): LeaseRecord => {
  if (!r.ok) throw new Error('expected ok, got ' + r.reason);
  return r.lease;
};

describe('lease: missing X gives Y', () => {
  it('no lease yet: first acquire gets epoch 1 with store-clock expiry', async () => {
    const { store } = mk();
    expect(await acquireLease(store, 'a', O)).toEqual({ ok: true, lease: { holder: 'a', epoch: 1, expiresAt: 1_010_000 } });
  });
  it.each([
    ['empty holder', '', O],
    ['ttl 0', 'a', { ttlMs: 0 }],
    ['ttl non-integer', 'a', { ttlMs: 1.5 }],
    ['ttl too large', 'a', { ttlMs: 3_600_001 }],
    ['skew >= ttl', 'a', { ttlMs: 5, skewMs: 5 }],
    ['negative skew', 'a', { ttlMs: 50, skewMs: -1 }],
    ['NaN ttl', 'a', { ttlMs: NaN }],
  ])('invalid input (%s) is refused as invalid', async (_n, holder, o) => {
    const { store } = mk();
    expect(await acquireLease(store, holder, o as never)).toEqual({ ok: false, reason: 'invalid' });
    expect(await store.read()).toBeUndefined();
  });
  it('live lease held by another: held, nothing written', async () => {
    const { store } = mk();
    await acquireLease(store, 'a', O);
    expect(await acquireLease(store, 'b', O)).toEqual({ ok: false, reason: 'held' });
    expect((await store.read())?.holder).toBe('a');
  });
  it('expired but inside the skew window is still held; past it the takeover bumps the epoch', async () => {
    const { store, clock } = mk();
    await acquireLease(store, 'a', O);
    clock.t = 1_010_000 + 999;
    expect(await acquireLease(store, 'b', O)).toEqual({ ok: false, reason: 'held' });
    clock.t = 1_010_000 + 1_000;
    expect(await acquireLease(store, 'b', O)).toEqual({ ok: true, lease: { holder: 'b', epoch: 2, expiresAt: clock.t + 10_000 } });
  });
  it('released lease is free at once and keeps its epoch', async () => {
    const { store } = mk();
    const l = okLease(await acquireLease(store, 'a', O));
    expect(await releaseLease(store, l)).toEqual({ ok: true, lease: { holder: 'a', epoch: 1, expiresAt: 0 } });
    expect(okLease(await acquireLease(store, 'b', O)).epoch).toBe(2);
  });
  it('release by a stale holder is refused', async () => {
    const { store, clock } = mk();
    const a = okLease(await acquireLease(store, 'a', O));
    clock.t += 20_000;
    await acquireLease(store, 'b', O);
    expect(await releaseLease(store, a)).toEqual({ ok: false, reason: 'stale' });
  });
});

describe('lease: renew and the store clock', () => {
  it('renew extends from the STORE clock, never beyond now + ttl', async () => {
    const { store, clock } = mk();
    const l = okLease(await acquireLease(store, 'a', O));
    clock.t += 5_000;
    expect(await renewLease(store, l, O)).toEqual({ ok: true, lease: { holder: 'a', epoch: 1, expiresAt: clock.t + 10_000 } });
  });
  it('renew inside the holder safe window edge (expiry - skew) is expired', async () => {
    const { store, clock } = mk();
    const l = okLease(await acquireLease(store, 'a', O));
    clock.t = l.expiresAt - 1_000;
    expect(await renewLease(store, l, O)).toEqual({ ok: false, reason: 'expired' });
    clock.t = l.expiresAt - 1_001;
    expect((await renewLease(store, l, O)).ok).toBe(true);
  });
  it('renew after a takeover is stale', async () => {
    const { store, clock } = mk();
    const a = okLease(await acquireLease(store, 'a', O));
    clock.t += 20_000;
    await acquireLease(store, 'b', O);
    expect(await renewLease(store, a, O)).toEqual({ ok: false, reason: 'stale' });
  });
  it('renew with a forged record (wrong epoch) is stale; a malformed one is invalid', async () => {
    const { store } = mk();
    const a = okLease(await acquireLease(store, 'a', O));
    expect(await renewLease(store, { ...a, epoch: 9 }, O)).toEqual({ ok: false, reason: 'stale' });
    expect(await renewLease(store, { ...a, epoch: 0 }, O)).toEqual({ ok: false, reason: 'invalid' });
  });
});

describe('lease: two contenders race', () => {
  it('exactly one of many concurrent acquirers wins, at epoch 1', async () => {
    const { store } = mk();
    const rs = await Promise.all(['a', 'b', 'c', 'd', 'e'].map((h) => acquireLease(store, h, O)));
    expect(rs.filter((r) => r.ok)).toHaveLength(1);
    expect(rs.filter((r) => !r.ok).every((r) => !r.ok && (r.reason === 'held' || r.reason === 'lost-race'))).toBe(true);
    expect((await store.read())?.epoch).toBe(1);
  });
  it('epochs are strictly monotone over repeated takeovers', async () => {
    const { store, clock } = mk();
    const seen: number[] = [];
    for (const h of ['a', 'b', 'a', 'c']) {
      clock.t += 20_000;
      seen.push(okLease(await acquireLease(store, h, O)).epoch);
    }
    expect(seen).toEqual([1, 2, 3, 4]);
  });
  it('cas refuses to lower the epoch even with a matching expected record, and rejects a malformed record', async () => {
    const { store, clock } = mk();
    await acquireLease(store, 'a', O);
    clock.t += 20_000;
    const b = okLease(await acquireLease(store, 'b', O));
    expect(await store.cas(b, { holder: 'z', epoch: 1, expiresAt: 5 })).toBe(false);
    expect(await store.read()).toEqual(b);
    await expect(store.cas(b, { holder: 'z', epoch: 0, expiresAt: 5 })).rejects.toThrow('invalid lease record');
  });
});

describe('fencing', () => {
  it('assertFence: current leader ok; stale epoch, expired window and no lease are refused', async () => {
    const { store, clock } = mk();
    expect(await assertFence(store, { holder: 'a', epoch: 1 })).toEqual({ ok: false, reason: 'stale' });
    const a = okLease(await acquireLease(store, 'a', O));
    expect(await assertFence(store, a)).toEqual({ ok: true });
    clock.t = a.expiresAt - 1_000;
    expect(await assertFence(store, a)).toEqual({ ok: false, reason: 'expired' });
    clock.t = a.expiresAt + 1_000;
    const b = okLease(await acquireLease(store, 'b', O));
    expect(await assertFence(store, a)).toEqual({ ok: false, reason: 'stale' });
    expect(await assertFence(store, b)).toEqual({ ok: true });
  });
  it('FencedSigner signs for the leader and refuses a stale ex-leader without running sign', async () => {
    const { store, clock } = mk();
    let held: LeaseRecord | undefined = okLease(await acquireLease(store, 'a', O));
    let calls = 0;
    const sign = fencedSigner(store, () => held, (m: string) => (calls++, `sig(${m})`));
    expect(await sign('x')).toEqual({ result: 'sig(x)', epoch: 1 });
    clock.t += 20_000;
    await acquireLease(store, 'b', O);
    await expect(sign('y')).rejects.toMatchObject({ reason: 'stale' });
    expect(calls).toBe(1);
    held = undefined;
    await expect(sign('z')).rejects.toBeInstanceOf(FenceError);
  });
  it('a lease lost DURING the signature discards the result', async () => {
    const { store, clock } = mk();
    const a = okLease(await acquireLease(store, 'a', O));
    const sign = fencedSigner(store, () => a, async () => {
      clock.t += 20_000;
      await acquireLease(store, 'b', O);
      return 'late';
    });
    await expect(sign()).rejects.toMatchObject({ reason: 'stale' });
  });
  it('FenceGuard admits equal-or-higher epochs and refuses lower or malformed ones', () => {
    const g = createFenceGuard();
    expect([g.admit(1), g.admit(2), g.admit(2), g.admit(1), g.admit(0), g.admit(NaN), g.admit(3)]).toEqual([true, true, true, false, false, false, true]);
    expect(g.highest()).toBe(3);
  });
});

describe('fail closed on store errors', () => {
  const broken = (what: 'read' | 'cas' | 'now' | 'corrupt'): LeaseStore => ({
    read: async () => {
      if (what === 'read') throw new Error('down');
      return what === 'corrupt' ? ({ holder: 'a', epoch: -1, expiresAt: 1 } as LeaseRecord) : undefined;
    },
    cas: async () => {
      if (what === 'cas') throw new Error('down');
      return true;
    },
    now: async () => {
      if (what === 'now') throw new Error('down');
      return 5;
    },
  });
  it.each(['read', 'cas', 'now', 'corrupt'] as const)('%s failure: acquire is store-error, fence is store-error (no leader)', async (w) => {
    expect(await acquireLease(broken(w), 'a', O)).toMatchObject({ ok: false, reason: 'store-error' });
    if (w !== 'cas') expect(await assertFence(broken(w), { holder: 'a', epoch: 1 })).toEqual({ ok: false, reason: 'store-error' });
  });
});

describe('durable: the lease survives a restart', () => {
  it('file-backed state keeps holder and epoch; the epoch keeps rising after the restart', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pca-ha-'));
    const clock = { t: 5_000_000 };
    const open = async (): Promise<KvLeaseStore> => new KvLeaseStore(await openDurableState({ dir, lockTimeoutMs: 30_000 }), { now: () => clock.t });
    const a = okLease(await acquireLease(await open(), 'a', O));
    const again = await open();
    expect(await again.read()).toEqual(a);
    expect(await acquireLease(again, 'b', O)).toEqual({ ok: false, reason: 'held' });
    clock.t += 20_000;
    expect(okLease(await acquireLease(await open(), 'b', O)).epoch).toBe(2);
  }, 60_000);
});

describe('quorum sharp edges fail closed', () => {
  const g = (lastSeen: number, healthy: unknown = true, id = 'g') => ({ id, healthy: healthy as boolean, lastSeen });
  it('future-dated, NaN and non-boolean heartbeats count as down', () => {
    const set = { quorum: 1, guardians: [g(2000, true, 'future'), g(NaN, true, 'nan'), g(1000, 'yes', 'str'), g(1000, true, 'ok')] };
    expect(liveGuardians(set, 1000).map((x) => x.id)).toEqual(['ok']);
  });
  it('non-finite now or a malformed set means no live guardians and no quorum', () => {
    const set = { quorum: 1, guardians: [g(1000)] };
    expect(liveGuardians(set, NaN)).toEqual([]);
    expect(liveGuardians({ quorum: 1, guardians: null } as never, 1000)).toEqual([]);
    expect(quorumStatus({ quorum: 0, guardians: [g(1000)] }, 1000).available).toBe(false);
    expect(selectSigners({ quorum: 0.5, guardians: [g(1000)] }, 1000)).toEqual([]);
  });
});
