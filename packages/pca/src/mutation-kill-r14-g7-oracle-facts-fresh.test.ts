/** r14 static-mutant kills for oracle-facts.ts: the fact signature and reference domains, re-evaluated in a fresh module. */
import { describe, expect, it, vi } from 'vitest';

describe('oracle-facts.ts constants (fresh module)', () => {
  it('domains', async () => {
    vi.resetModules();
    const m = await import('./oracle-facts');
    expect([m.FACT_DOMAIN, m.FACT_REF_DOMAIN]).toEqual(['atlas-pca/fact/v1\0', 'atlas-pca/fact-ref/v1']);
  });
});
