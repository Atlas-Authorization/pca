import { describe, expect, it } from 'vitest';
import { checkHistory } from './check';
import {
  closeClients,
  driveWindowed,
  openClients,
  perform,
  prng,
  randomNamespace,
  runBurst,
  runConcurrent,
  runDurability,
  runRetention,
  settle,
} from './harness';
import { MemoryRecorder, clock } from './recorder';
import { inMemoryAdapter } from './reference';
import type { StoreAdapter, StoreClient } from './types';

describe('prng', () => {
  it('is deterministic per seed, in range, and spreads', () => {
    const a = prng(42);
    const b = prng(42);
    const xs = Array.from({ length: 200 }, () => a(10));
    expect(Array.from({ length: 200 }, () => b(10))).toEqual(xs);
    expect(xs.every((x) => Number.isInteger(x) && x >= 0 && x < 10)).toBe(true);
    expect(new Set(xs).size).toBe(10);
    expect(prng(1)(1000)).not.toBe(prng(2)(1000));
    expect(prng(7)(1_000_000)).toBe(prng(7)(1_000_000));
  });
  it('matches the reference mulberry32 sequence', () => {
    const r = prng(1);
    expect([r(2 ** 32), r(2 ** 32), r(2 ** 32)]).toEqual([2693262067, 11749833, 2265367787]);
  });
});

describe('randomNamespace', () => {
  it('is unique and prefixed', () => {
    const a = randomNamespace();
    expect(a).toMatch(/^pcasc-[0-9a-z]+-[0-9a-z]{1,6}$/);
    expect(randomNamespace()).not.toBe(a);
  });
});

describe('settle', () => {
  it('passes booleans through and maps rejections, throws, timeouts and non-booleans to unknown', async () => {
    expect(await settle(async () => true, 1000)).toBe(true);
    expect(await settle(async () => false, 1000)).toBe(false);
    expect(await settle(async () => Promise.reject(new Error('x')), 1000)).toBe('unknown');
    expect(
      await settle(() => {
        throw new Error('sync');
      }, 1000),
    ).toBe('unknown');
    expect(await settle(async () => 1, 1000)).toBe('unknown');
    expect(await settle(async () => 'true', 1000)).toBe('unknown');
    const t0 = Date.now();
    expect(await settle(() => new Promise(() => undefined), 30)).toBe('unknown');
    expect(Date.now() - t0).toBeLessThan(1000);
  });
  it('does not leave its timer behind', async () => {
    const t0 = Date.now();
    await settle(async () => true, 60_000);
    expect(Date.now() - t0).toBeLessThan(1000);
  });
});

describe('perform', () => {
  it('consume: lo = now, w = now + retention, and the store sees (key, retainUntil, now)', async () => {
    const calls: unknown[][] = [];
    const c: StoreClient = { consumeOnce: async (...a) => (calls.push(a), true) };
    const rec = new MemoryRecorder();
    const before = Date.now();
    expect(await perform(c, 'c0', 'consume', 'k', 99, { rec, retentionMs: 1000, opTimeoutMs: 1000 })).toBe(true);
    const [op] = rec.ops;
    expect(op!.lo).toBeGreaterThanOrEqual(before);
    expect(op!.w).toBe(op!.lo + 1000);
    expect(calls).toEqual([['k', op!.w, op!.lo]]);
    expect(op).toMatchObject({ client: 'c0', kind: 'consume', key: 'k', res: 'true' });
  });
  it('advance: lo = w = the value, and the store sees (key, value)', async () => {
    const calls: unknown[][] = [];
    const c: StoreClient = { advance: async (...a) => (calls.push(a), false) };
    const rec = new MemoryRecorder();
    expect(await perform(c, 'c1', 'advance', 's', 7, { rec, retentionMs: 1000, opTimeoutMs: 1000 })).toBe(false);
    expect(rec.ops[0]).toMatchObject({ lo: 7, w: 7, res: 'false', kind: 'advance', key: 's' });
    expect(calls).toEqual([['s', 7]]);
  });
  it('a failing call is recorded unknown (open-ended)', async () => {
    const rec = new MemoryRecorder();
    expect(await perform({}, 'c', 'advance', 's', 1, { rec, retentionMs: 1, opTimeoutMs: 100 })).toBe('unknown');
    expect(rec.ops[0]).toMatchObject({ res: 'unknown', ret: Infinity });
  });
});

describe('openClients / closeClients', () => {
  it('opens n clients and closes those that can be closed', async () => {
    let opened = 0;
    let closed = 0;
    const a: StoreAdapter = { name: 'x', open: async () => (opened++ % 2 ? {} : { close: async () => void closed++ }) };
    const cs = await openClients(a, 5);
    expect(cs).toHaveLength(5);
    expect(opened).toBe(5);
    await closeClients(cs);
    expect(closed).toBe(3);
  });
});

describe('driveWindowed', () => {
  it('targets <spread> keys of the current window, named namespace:kind:window:index, until the deadline', async () => {
    const rec = new MemoryRecorder();
    const store = inMemoryAdapter();
    const c = await store.open();
    const origin = clock();
    await driveWindowed(c, 'c0', 'advance', { rec, retentionMs: 1, opTimeoutMs: 1000 }, { namespace: 'ns', windowMs: 1000, spread: 2, values: 5, origin, deadline: origin + 30, rand: prng(3) });
    expect(rec.ops.length).toBeGreaterThan(5);
    expect(new Set(rec.ops.map((o) => o.key))).toEqual(new Set(['ns:advance:0:0', 'ns:advance:0:1']));
    expect(rec.ops.every((o) => o.lo >= 0 && o.lo < 5)).toBe(true);
    // the deadline is checked BEFORE an operation is stamped, so only the last one may be stamped just past it (a slow
    // runner can tick between the check and the stamp); every earlier one was stamped before a later check that passed
    expect(rec.ops.slice(0, -1).every((o) => o.call < origin + 30)).toBe(true);
    // a deadline in the past runs nothing
    const rec2 = new MemoryRecorder();
    await driveWindowed(c, 'c0', 'advance', { rec: rec2, retentionMs: 1, opTimeoutMs: 1000 }, { namespace: 'ns', windowMs: 1, spread: 1, values: 1, origin, deadline: origin - 1, rand: prng(3) });
    expect(rec2.ops).toHaveLength(0);
  });
  it('moves to the next window as time passes', async () => {
    const rec = new MemoryRecorder();
    const c = await inMemoryAdapter().open();
    // a virtual clock (not the wall clock: a slow CI runner once saw only 3 windows in 25 real ms) that advances 0.5 ms per
    // read; the loop reads it twice per operation (deadline check, then window), so operation i runs at t = 1 + i
    let t = 0;
    const now = () => (t += 0.5);
    await driveWindowed(c, 'c0', 'consume', { rec, retentionMs: 1000, opTimeoutMs: 1000 }, { namespace: 'w', windowMs: 2, spread: 1, values: 1, origin: 0, deadline: 25, rand: prng(1), now });
    // 25 operations (checks at 0.5 .. 24.5 pass, 25.5 stops), window floor((1 + i) / 2): every window 0..12 in order
    expect(rec.ops).toHaveLength(25);
    expect(rec.ops.map((o) => o.key)).toEqual(Array.from({ length: 25 }, (_, i) => `w:consume:${Math.floor((1 + i) / 2)}:0`));
    expect(new Set(rec.ops.map((o) => o.key)).size).toBe(13);
  });
});

describe('workloads against the in-memory reference', () => {
  it('runBurst: every client hits the same fresh key per round; exactly one TRUE per round', async () => {
    const r = await runBurst(inMemoryAdapter(), 'consume', { clients: 8, rounds: 5, namespace: 'b' });
    expect(r.ops).toHaveLength(40);
    expect(r.errors).toBe(0);
    expect(new Set(r.ops.map((o) => o.key)).size).toBe(5);
    expect(r.ops.filter((o) => o.res === 'true')).toHaveLength(5);
    expect(r.ops[0]!.key).toBe('b:consume:burst:0');
    expect(checkHistory(r.ops).ok).toBe(true);
  });
  it('runBurst on counters draws values from [0, values)', async () => {
    const r = await runBurst(inMemoryAdapter(), 'advance', { clients: 6, rounds: 4, values: 3, seed: 5 });
    expect(r.ops).toHaveLength(24);
    expect(r.ops.every((o) => o.lo < 3)).toBe(true);
    expect(checkHistory(r.ops).ok).toBe(true);
  });
  it('runConcurrent: many clients, windowed keys, all linearizable', async () => {
    const r = await runConcurrent(inMemoryAdapter(), 'advance', { clients: 6, durationMs: 60, windowMs: 2, spread: 2, values: 6 });
    expect(r.ops.length).toBeGreaterThan(50);
    expect(new Set(r.ops.map((o) => o.client)).size).toBe(6);
    const h = checkHistory(r.ops);
    expect(h.ok).toBe(true);
    expect(h.keys).toBeGreaterThan(3);
  });
  it('runRetention: writes then revisits every key; revisits answer false', async () => {
    const r = await runRetention(inMemoryAdapter(), 'consume', { clients: 4, revisitKeys: 10, namespace: 'r' });
    expect(r.ops).toHaveLength(20);
    expect(r.ops.slice(0, 10).every((o) => o.res === 'true' && o.client.startsWith('write-'))).toBe(true);
    expect(r.ops.slice(10).every((o) => o.res === 'false' && o.client.startsWith('revisit-'))).toBe(true);
    expect(new Set(r.ops.map((o) => o.key)).size).toBe(10);
    expect(r.ops[9]!.key).toBe('r:consume:keep:9');
  });
  it('runDurability: write, close, restart, read back', async () => {
    let restarts = 0;
    let closes = 0;
    const base = inMemoryAdapter();
    const a: StoreAdapter = {
      ...base,
      open: async () => ({ ...(await base.open()), close: async () => void closes++ }),
      restart: async () => void restarts++,
    };
    const r = await runDurability(a, 'advance', { namespace: 'd' });
    expect(restarts).toBe(1);
    expect(closes).toBe(2);
    expect(r.ops.map((o) => [o.client, o.lo, o.res])).toEqual([
      ['before-restart', 7, 'true'],
      ['after-restart', 7, 'false'],
      ['after-restart', 8, 'true'],
    ]);
    expect(r.note).toBe('backend restarted between write and read');
    const c = await runDurability(inMemoryAdapter(), 'consume', {});
    expect(c.ops.map((o) => o.res)).toEqual(['true', 'false']);
    expect(c.note).toMatch(/no restart\(\) hook/);
  });
  it('workloads close their clients even when an operation throws synchronously out of the harness', async () => {
    let closed = 0;
    const a: StoreAdapter = { name: 'x', open: async () => ({ close: async () => void closed++ }) };
    const r = await runBurst(a, 'consume', { clients: 2, rounds: 1 });
    expect(r.errors).toBe(2);
    expect(closed).toBe(2);
  });
});
