import { afterEach, describe, expect, it, vi } from 'vitest';
import { driveWindowed, prng, runBurst, runConcurrent, runDurability, runRetention, settle } from './harness';
import { MemoryRecorder } from './recorder';
import type { StoreAdapter, StoreClient } from './types';

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** An adapter whose clients always answer true, optionally after a delay, and count opens and closes. */
function counting(delayMs = 0) {
  const seen = { opened: 0, closed: 0, keys: [] as string[] };
  const adapter: StoreAdapter = {
    name: 'counting',
    capabilities: { durable: true },
    open: async () => {
      seen.opened++;
      const c: StoreClient = {
        consumeOnce: async (k) => {
          seen.keys.push(k);
          await sleep(delayMs);
          return true;
        },
        advance: async (k) => {
          seen.keys.push(k);
          await sleep(delayMs);
          return true;
        },
        close: async () => void seen.closed++,
      };
      return c;
    },
  };
  return { adapter, seen };
}

afterEach(() => {
  vi.useRealTimers();
});

describe('settle leaves no timer behind', () => {
  it('after success and after failure', async () => {
    vi.useFakeTimers();
    await settle(async () => true, 60_000);
    expect(vi.getTimerCount()).toBe(0);
    await settle(async () => Promise.reject(new Error('x')), 60_000);
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe('workload defaults', () => {
  it('keys use 5 ms windows and 3 spread slots', async () => {
    const { adapter, seen } = counting(1);
    await runConcurrent(adapter, 'consume', { clients: 2, durationMs: 40, namespace: 'ns' });
    expect(seen.keys.length).toBeGreaterThan(0);
    for (const k of seen.keys) expect(k).toMatch(/^ns:consume:\d+:[012]$/);
  });

  it('an operation slower than a millisecond still settles under the default timeout', async () => {
    const { adapter } = counting(30);
    const r = await runBurst(adapter, 'consume', { clients: 1, rounds: 1 });
    expect(r.ops.map((o) => o.res)).toEqual(['true']);
    expect(r.errors).toBe(0);
  });

  it('the default seed is random per run', async () => {
    const a = await runBurst(counting().adapter, 'advance', { clients: 1, rounds: 20, namespace: 'ns' });
    const b = await runBurst(counting().adapter, 'advance', { clients: 1, rounds: 20, namespace: 'ns' });
    expect(a.ops.map((o) => o.lo)).not.toEqual(b.ops.map((o) => o.lo));
  });

  it('bursts name their clients c0, c1, ...', async () => {
    const r = await runBurst(counting().adapter, 'consume', { clients: 3, rounds: 1 });
    expect(r.ops.map((o) => o.client).sort()).toEqual(['c0', 'c1', 'c2']);
  });
});

describe('concurrent run seeds each client apart', () => {
  it('client i draws from the generator seeded with seed + i', async () => {
    const { adapter } = counting(1);
    const r = await runConcurrent(adapter, 'advance', { clients: 2, durationMs: 80, seed: 100, namespace: 'ns' });
    const expected = (seed: number): number[] => {
      const rand = prng(seed);
      return Array.from({ length: 5 }, () => {
        rand(3);
        return rand(20);
      });
    };
    for (const i of [0, 1]) {
      const mine = r.ops.filter((o) => o.client === `c${i}`).map((o) => o.lo);
      expect(mine.length).toBeGreaterThanOrEqual(5);
      expect(mine.slice(0, 5)).toEqual(expected(100 + i));
    }
  });
});

describe('driveWindowed', () => {
  it('stops as soon as the clock reaches the deadline', async () => {
    let t = 0;
    let calls = 0;
    const c: StoreClient = {
      consumeOnce: async () => {
        t = ++calls;
        return true;
      },
    };
    const ctx = { rec: new MemoryRecorder(), retentionMs: 1000, opTimeoutMs: 1000 };
    await driveWindowed(c, 'c', 'consume', ctx, { namespace: 'n', windowMs: 5, spread: 1, values: 1, origin: 0, deadline: 3, rand: () => 0, now: () => t });
    expect(calls).toBe(3);
  });
});

describe('every workload closes the clients it opened', () => {
  it('concurrent, retention and durability', async () => {
    const a = counting();
    await runConcurrent(a.adapter, 'consume', { clients: 3, durationMs: 10 });
    expect(a.seen).toMatchObject({ opened: 3, closed: 3 });
    const b = counting();
    await runRetention(b.adapter, 'consume', { clients: 3, revisitKeys: 4 });
    expect(b.seen).toMatchObject({ opened: 3, closed: 3 });
    const c = counting();
    await runDurability(c.adapter, 'consume');
    expect(c.seen).toMatchObject({ opened: 2, closed: 2 });
  });
});
