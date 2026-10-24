/**
 * r13 mutation kills for hash.ts module-level constants (static mutants: each test re-evaluates the module):
 * DEFAULT_HASH_SUITE, HASH_LEN and the LONE_SURROGATE pattern behind hasLoneSurrogate.
 */
import { describe, expect, it, vi } from 'vitest';

async function fresh() {
  vi.resetModules();
  return import('./hash');
}

describe('hash.ts constants (fresh module)', () => {
  it('default suite and digest lengths', async () => {
    const h = await fresh();
    expect(h.DEFAULT_HASH_SUITE).toBe('sha256');
    expect(h.HASH_LEN).toEqual({ sha256: 32, sha384: 48 });
  });
  it('hasLoneSurrogate finds exactly the unpaired surrogates', async () => {
    const h = await fresh();
    const cases: [string, boolean][] = [
      ['', false],
      ['abc', false],
      ['😀', false],
      ['a😀b', false],
      ['\uD800', true],
      ['\uDC00', true],
      ['\uD800a', true],
      ['a\uDC00', true],
      ['\uDC00\uD800', true],
      ['😀\uDC00', true],
      ['\uD800😀', true],
      ['ab', false],
    ];
    for (const [s, want] of cases) expect([s, h.hasLoneSurrogate(s)]).toEqual([s, want]);
  });
});
