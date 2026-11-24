import { describe, expect, it } from 'vitest';
import { createInMemorySetReplayStore } from './index';

describe('non-finite clock fails closed', () => {
  it.each([Number.NaN, Number.NEGATIVE_INFINITY])('a SET replay store holding a live jti still refuses it when now is %s', async (bad) => {
    const store = createInMemorySetReplayStore();
    expect(await store.addIfAbsent('j', 100, 10)).toBe(true);
    expect(await store.addIfAbsent('j', 100, bad)).toBe(false);
  });
});
