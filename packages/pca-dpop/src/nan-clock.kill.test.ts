import { describe, expect, it } from 'vitest';
import { createInMemoryDpopReplayStore } from './index';

// A clock that is not a finite number must never admit: NaN compares false, so "now < held" used to read as "not held".
describe('non-finite clock fails closed', () => {
  it('a replay store holding a live entry still refuses the key when now is NaN', async () => {
    const store = createInMemoryDpopReplayStore();
    expect(await store.addIfAbsent('k', 100, 10)).toBe(true);
    for (const bad of [NaN, -Infinity]) expect(await store.addIfAbsent('k', 100, bad)).toBe(false);
  });
});
