import { describe, expect, it } from 'vitest';
import { checkRevocationAge } from './revocation';
import { InMemoryReplayStore } from './replay';

describe('an infinite clock never ages out live state', () => {
  // `until < +Infinity` is true for every entry, so an infinite clock used to free every live replay key
  it('prune ignores a non-finite clock', async () => {
    const s = new InMemoryReplayStore();
    await s.consumeOnce('k', 2000, 1000);
    for (const bad of [Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, Number.NaN]) expect(s.prune(bad)).toBe(0);
    expect(s.size).toBe(1);
    await expect(s.consumeOnce('k', 2000, 1000)).resolves.toBe(false);
  });
  // with an unbounded max age and a +Infinity clock, `now - issuedAt <= maxAge` was Infinity <= Infinity
  it('checkRevocationAge refuses a non-finite clock', () => {
    for (const bad of [Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, Number.NaN]) {
      expect(checkRevocationAge(1000, bad, Number.POSITIVE_INFINITY).ok).toBe(false);
    }
  });
});
