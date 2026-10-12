/** Kills the InMemoryReplayStore.consumeOnce pruning-side-effect mutants: pruning happens ONLY when the store is full and the key is new. */
import { describe, expect, it } from 'vitest';
import { InMemoryReplayStore } from './replay';

describe('InMemoryReplayStore pruning is lazy', () => {
  it('a new key below the cap does not prune expired entries', async () => {
    const s = new InMemoryReplayStore({ maxEntries: 10 });
    await s.consumeOnce('old', 100, 50);
    await s.consumeOnce('new', 1000, 500); // 'old' is expired at now=500 but the store is not full
    expect(s.size).toBe(2);
  });
  it('re-consuming an expired key in a full store does not prune others and succeeds', async () => {
    const s = new InMemoryReplayStore({ maxEntries: 2 });
    await s.consumeOnce('a', 100, 50);
    await s.consumeOnce('b', 120, 50);
    expect(await s.consumeOnce('a', 1000, 500)).toBe(true); // existing key: overwrite, no prune
    expect(s.size).toBe(2);
  });
  it('a new key in a full store prunes expired entries then inserts; with only live entries it rejects', async () => {
    const s = new InMemoryReplayStore({ maxEntries: 2 });
    await s.consumeOnce('a', 100, 50);
    await s.consumeOnce('b', 1000, 50);
    expect(await s.consumeOnce('c', 2000, 500)).toBe(true);
    expect(s.size).toBe(2);
    await expect(s.consumeOnce('d', 3000, 500)).rejects.toThrow(/full of live/);
  });
  it('a live duplicate is refused (false), an entry exactly at its horizon is still live', async () => {
    const s = new InMemoryReplayStore();
    await s.consumeOnce('k', 100, 50);
    expect(await s.consumeOnce('k', 200, 100)).toBe(false);
    expect(await s.consumeOnce('k', 200, 101)).toBe(true);
  });
});
