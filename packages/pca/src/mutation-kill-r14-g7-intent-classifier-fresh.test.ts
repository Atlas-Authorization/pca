/** r14 static-mutant kills for intent-classifier.ts: the verdict signature and reference domains, re-evaluated in a fresh module. */
import { describe, expect, it, vi } from 'vitest';

describe('intent-classifier.ts constants (fresh module)', () => {
  it('domains', async () => {
    vi.resetModules();
    const m = await import('./intent-classifier');
    expect([m.INTENT_CLASSIFIER_DOMAIN, m.INTENT_CLASSIFIER_REF_DOMAIN]).toEqual(['atlas-pca/intent-classifier/v1\0', 'atlas-pca/intent-classifier-ref/v1']);
  });
});
