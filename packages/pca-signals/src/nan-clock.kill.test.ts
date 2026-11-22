import { describe, expect, it } from 'vitest';
import { createInMemorySetReplayStore } from './index';

describe('non-finite clock fails closed', () => {
  it.each([Number.NaN, Number.NEGATIVE_INFINITY])('a SET replay store holding a live jti still refuses it when now is %s', async (bad) => {
    const store = createInMemorySetReplayStore();
    expect(await store.addIfAbsent('j', 100, 10)).toBe(true);
    expect(await store.addIfAbsent('j', 100, bad)).toBe(false);
  });
  // old code: a +Infinity clock expired every held entry (`Infinity >= held`), reopening the replay window
  it('a replay store holding a live jti refuses it when now is +Infinity', async () => {
    const store = createInMemorySetReplayStore();
    expect(await store.addIfAbsent('j', 100, 10)).toBe(true);
    expect(await store.addIfAbsent('j', 100, Number.POSITIVE_INFINITY)).toBe(false);
  });
  // old code: a -Infinity expiry was dropped at once, so the same jti was accepted again
  it.each([Number.NEGATIVE_INFINITY, Number.POSITIVE_INFINITY, Number.NaN])('a replay store refuses an expiry of %s', async (exp) => {
    const store = createInMemorySetReplayStore();
    expect(await store.addIfAbsent('j', exp, 10)).toBe(false);
  });
});
