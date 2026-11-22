import { describe, expect, it } from 'vitest';
import { memoryReplayGuard } from './index';

describe('memoryReplayGuard refuses a clock or expiry that is not finite', () => {
  const bad = [Number.NaN, Infinity, -Infinity];

  it('a non-finite clock never lets a held claim be claimed again', () => {
    for (const t of bad) {
      const g = memoryReplayGuard();
      expect(g.claim('k', 1000, 0)).toBe(true);
      // the old `existing >= t` was false for NaN and +Infinity, so the replay was admitted
      expect(() => g.claim('k', 1000, t)).toThrow(/finite/);
    }
  });

  it('a non-finite expiry is never stored', () => {
    for (const exp of bad) {
      const g = memoryReplayGuard();
      expect(() => g.claim('k', exp, 0)).toThrow(/finite/);
      expect(g.claim('k', 1000, 0)).toBe(true);
    }
  });

  it('a non-finite injected clock is refused too', () => {
    for (const t of bad) expect(() => memoryReplayGuard(10, () => t).claim('k', 1000)).toThrow(/finite/);
  });
});
