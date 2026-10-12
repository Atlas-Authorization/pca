/**
 * R5-API-05/06 (still open in round 6): the compiled-regex caches were global 512-entry Maps CLEARED WHOLESALE when full, so
 * any request that evaluated 512 distinct patterns flushed every other tenant's compiled programs (and 511 retained programs
 * held 134 MB). Now: ONE bounded LRU keyed by the SHA-256 of the pattern, a per-source admission cap (one source can only
 * evict its own entries once it holds its share), a total-instruction weight cap, and no clear on any request path.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { RegexBudget, chargeRegex, safeRegexFullMatch } from './index';
import { REGEX_CACHE_MAX_ENTRIES, REGEX_CACHE_MAX_PER_SOURCE, regexCacheHas, regexCacheStats } from './regex-cache';

const asSource = <T>(source: string, fn: () => T): T => RegexBudget.request(source).run(fn);
let uniq = 0;
const fresh = () => `abc${uniq++}x[0-9]+`;

describe('R5-API-05/06: bounded regex cache with per-source admission', () => {
  it('a flood of distinct patterns from ONE source never evicts another source\'s hot pattern', () => {
    const hot = 'victim-[a-z]{1,8}';
    expect(asSource('10.0.0.1', () => safeRegexFullMatch(hot, 'victim-abc'))).toBe(true);
    for (let i = 0; i < 5_000; i++) asSource('6.6.6.6', () => safeRegexFullMatch(fresh(), 'abc'));
    expect(regexCacheHas(hot)).toBe(true);
    // the flooding source holds at most its share
    expect(regexCacheStats().bySource['6.6.6.6'] ?? 0).toBeLessThanOrEqual(REGEX_CACHE_MAX_PER_SOURCE);
  });

  it('the cache is never cleared wholesale: past capacity it stays full (LRU), it does not drop to ~0', () => {
    for (let s = 0; s < 40; s++) for (let i = 0; i < REGEX_CACHE_MAX_PER_SOURCE; i++) asSource(`198.51.100.${s}`, () => safeRegexFullMatch(fresh(), 'x'));
    const st = regexCacheStats();
    expect(st.entries).toBeGreaterThan(REGEX_CACHE_MAX_ENTRIES / 2);
    expect(st.entries).toBeLessThanOrEqual(REGEX_CACHE_MAX_ENTRIES);
    // a recently used pattern survives the churn (LRU, not FIFO-then-clear)
    const keep = 'keep-me-[0-9]';
    asSource('203.0.113.1', () => safeRegexFullMatch(keep, 'keep-me-1'));
    for (let i = 0; i < 100; i++) {
      asSource(`192.0.2.${i}`, () => safeRegexFullMatch(fresh(), 'x'));
      asSource('203.0.113.1', () => safeRegexFullMatch(keep, 'keep-me-2'));
    }
    expect(regexCacheHas(keep)).toBe(true);
  });

  it('keys are pattern hashes (the raw source is not retained as a key), and the total compiled weight is bounded', () => {
    const st = regexCacheStats();
    for (const k of st.keys) expect(k).toMatch(/^[0-9a-f]{64}$/);
    expect(st.weight).toBeLessThanOrEqual(st.maxWeight);
  });

  it('the budget\'s program-length lookup uses the same bounded cache (no second clear-on-full map) and still charges', () => {
    expect(asSource('10.9.9.9', () => chargeRegex('budget-[a-z]+', 10))).toBe(true);
    expect(regexCacheHas('budget-[a-z]+')).toBe(true);
    const src = ['safe-regex.ts', 'regex-budget.ts', 'regex-cache.ts'].map((f) => readFileSync(join(__dirname, f), 'utf8')).join('\n');
    expect(src).not.toMatch(/\.clear\(\)/);
  });

  it('outside any request (library use) patterns are cached too, under the anonymous source', () => {
    const p = 'lib-[0-9]{2}';
    expect(safeRegexFullMatch(p, 'lib-42')).toBe(true);
    expect(regexCacheHas(p)).toBe(true);
    expect(safeRegexFullMatch('(a', 'a')).toBeNull(); // an unsupported pattern still fails closed
  });
});
