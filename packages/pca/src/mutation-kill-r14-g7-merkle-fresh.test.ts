/** r14 static-mutant kill for merkle.ts: DEFAULT_REVERSIBILITY_CLASS, re-evaluated in a fresh module. */
import { describe, expect, it, vi } from 'vitest';

describe('merkle.ts constants (fresh module)', () => {
  it('DEFAULT_REVERSIBILITY_CLASS', async () => {
    vi.resetModules();
    const m = await import('./merkle');
    expect(m.DEFAULT_REVERSIBILITY_CLASS).toBe('reversible');
  });
});
