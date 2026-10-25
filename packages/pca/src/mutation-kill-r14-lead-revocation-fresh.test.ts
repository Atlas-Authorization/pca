/**
 * r14 static-mutant kill for revocation.ts: the published epoch timing constants, read from a freshly evaluated module (a
 * module-level mutant is only visible to a test that re-imports the module). The validity window must stay longer than the
 * refresh period, so a refresh always lands before the previous epoch expires.
 */
import { describe, expect, it, vi } from 'vitest';

describe('revocation epoch timing constants (fresh module)', () => {
  it('refresh is 60 s, validity is 5 min, and validity exceeds the refresh period', async () => {
    vi.resetModules();
    const m = await import('./revocation');
    expect(m.REVOCATION_EPOCH_REFRESH_MS).toBe(60_000);
    expect(m.REVOCATION_EPOCH_VALIDITY_MS).toBe(300_000);
    expect(m.REVOCATION_EPOCH_VALIDITY_MS > m.REVOCATION_EPOCH_REFRESH_MS).toBe(true);
  });
});
