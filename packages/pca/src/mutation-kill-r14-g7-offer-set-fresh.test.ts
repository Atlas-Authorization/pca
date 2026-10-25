/** r14 static-mutant kills for offer-set.ts: the signature and reference domains, re-evaluated in a fresh module. */
import { describe, expect, it, vi } from 'vitest';

describe('offer-set.ts constants (fresh module)', () => {
  it('domains', async () => {
    vi.resetModules();
    const m = await import('./offer-set');
    expect([m.OFFER_SET_DOMAIN, m.OFFER_SET_REF_DOMAIN]).toEqual(['atlas-pca/offer-set/v1\0', 'atlas-pca/offer-set-ref/v1']);
  });
});
