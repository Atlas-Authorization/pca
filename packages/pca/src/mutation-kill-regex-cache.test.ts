/**
 * Mutation-kill tests for regex-cache.ts. Each test imports a FRESH module instance (vi.resetModules), so the global
 * cache starts empty and occupancy / weight / ownership can be asserted exactly.
 */
import { describe, expect, it, vi } from 'vitest';

type Mod = typeof import('./regex-cache');
async function fresh(): Promise<Mod> {
  vi.resetModules();
  return import('./regex-cache');
}
const HEAVY = 131_072 / 16; // REGEX_CACHE_MAX_WEIGHT / 16: the heaviest cacheable program

describe('regex cache: weights', () => {
  it('weight is ceil(weigh) (min 1) and is summed exactly', async () => {
    const m = await fresh();
    m.regexCacheGet('a', () => 1, () => 100);
    m.regexCacheGet('b', () => 2, () => 2.5);
    m.regexCacheGet('c', () => 3, () => 0);
    m.regexCacheGet('d', () => 4, () => Number.NaN);
    const s = m.regexCacheStats();
    expect(s.weight).toBe(100 + 3 + 1 + 1);
    expect(s.entries).toBe(4);
    expect(s.maxWeight).toBe(131_072);
    expect(s.keys).toHaveLength(4);
    expect(s.bySource).toEqual({ '': 4 });
  });
  it('a program of exactly 1/16 of the cap is cached; one unit heavier is returned but never cached', async () => {
    const m = await fresh();
    expect(m.regexCacheGet('edge', () => 'v', () => HEAVY)).toBe('v');
    expect(m.regexCacheHas('edge')).toBe(true);
    expect(m.regexCacheGet('over', () => 'w', () => HEAVY + 1)).toBe('w');
    expect(m.regexCacheHas('over')).toBe(false);
    expect(m.regexCacheStats().weight).toBe(HEAVY);
  });
  it('the weight cap is inclusive and evicts the least-recently-used entry; a hit refreshes recency', async () => {
    const m = await fresh();
    for (let i = 0; i < 16; i++) m.regexCacheGet(`x${i}`, () => i, () => HEAVY);
    // exactly at the cap: nothing evicted
    expect(m.regexCacheStats().weight).toBe(16 * HEAVY);
    for (let i = 0; i < 16; i++) expect(m.regexCacheHas(`x${i}`)).toBe(true);
    // touch x0 (hit: returns the cached value, not a recompute)
    expect(m.regexCacheGet('x0', () => 'recomputed', () => HEAVY)).toBe(0);
    m.regexCacheGet('x16', () => 16, () => HEAVY);
    expect(m.regexCacheHas('x0')).toBe(true);
    expect(m.regexCacheHas('x1')).toBe(false);
    expect(m.regexCacheStats().weight).toBe(16 * HEAVY);
    expect(m.regexCacheStats().entries).toBe(16);
  });
});

describe('regex cache: sources', () => {
  it('a provider returning null or throwing means the anonymous source ""', async () => {
    const m = await fresh();
    m.setRegexCacheSourceProvider(() => null);
    m.regexCacheGet('n', () => 1, () => 1);
    m.setRegexCacheSourceProvider(() => {
      throw new Error('boom');
    });
    m.regexCacheGet('t', () => 1, () => 1);
    m.setRegexCacheSourceProvider(() => 'src-a');
    m.regexCacheGet('s', () => 1, () => 1);
    expect(m.regexCacheStats().bySource).toEqual({ '': 2, 'src-a': 1 });
  });
  it('a source whose last entry is evicted disappears from the per-source table', async () => {
    const m = await fresh();
    m.setRegexCacheSourceProvider(() => 'a');
    m.regexCacheGet('a0', () => 1, () => 1);
    m.setRegexCacheSourceProvider(() => 'b');
    for (let i = 0; i < 16; i++) m.regexCacheGet(`b${i}`, () => i, () => HEAVY);
    expect(m.regexCacheHas('a0')).toBe(false);
    expect(m.regexCacheStats().bySource).toEqual({ b: 16 });
  });
});
