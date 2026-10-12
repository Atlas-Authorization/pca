/** safe-regex.ts compiledWeight: the cache weight of a compiled program is its instruction count plus its class ranges (1 for a refused pattern). */
import { describe, expect, it } from 'vitest';
import { compileSafeRegex, compileSafeRegexCached } from './safe-regex';
import { regexCacheHas, regexCacheStats } from './regex-cache';

describe('compiledWeight', () => {
  it('a program with character classes weighs instructions + ranges', () => {
    const src = '[a-cx-z]q[0-4]mk-sr2';
    const prog = compileSafeRegex(src)!.program;
    const ranges = prog.reduce((n, ins) => n + ((ins as { set?: { ranges: unknown[] } }).set?.ranges.length ?? 0), 0);
    expect(ranges).toBeGreaterThan(1);
    expect(regexCacheHas(src)).toBe(false);
    const before = regexCacheStats().weight;
    expect(compileSafeRegexCached(src)).not.toBeNull();
    expect(regexCacheStats().weight - before).toBe(prog.length + ranges);
  });
  it('a refused pattern is cached with weight 1', () => {
    const src = '(mk-sr2';
    expect(compileSafeRegex(src)).toBeNull();
    const before = regexCacheStats().weight;
    expect(compileSafeRegexCached(src)).toBeNull();
    expect(regexCacheHas(src)).toBe(true);
    expect(regexCacheStats().weight - before).toBe(1);
  });
});
