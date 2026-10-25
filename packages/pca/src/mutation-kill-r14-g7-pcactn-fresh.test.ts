/**
 * r14 static-mutant kills for pcactn.ts (fresh module): the leaf signature domain (thresholdMessage pinned against an
 * independent utf8(domain) || sha256(strict canonical body)), ARTIFACT_SIZE_REASON and the notEnforced hook.
 */
import { describe, expect, it, vi } from 'vitest';
import { canonicalBytesStrict, sha256, utf8 } from './hash';

describe('pcactn.ts constants (fresh module)', () => {
  it('thresholdMessage = utf8("atlas-pca/actn/v2\\0") || sha256(canonical(body without sig / threshold / pq_sig))', async () => {
    vi.resetModules();
    const m = await import('./pcactn');
    const body = { ver: 2, aud: 'rs', counter: 1 };
    const d = utf8('atlas-pca/actn/v2\0');
    const h = sha256(canonicalBytesStrict(body));
    const want = new Uint8Array(d.length + h.length);
    want.set(d);
    want.set(h, d.length);
    expect(Array.from(m.thresholdMessage({ ...body, sig: 's', threshold: { shares: [] }, pq_sig: 'q' } as never))).toEqual(Array.from(want));
  });
  it('ARTIFACT_SIZE_REASON and notEnforced', async () => {
    vi.resetModules();
    const m = await import('./pcactn');
    expect(m.ARTIFACT_SIZE_REASON).toBe('artifact exceeds size limit (max 524288 bytes)');
    expect(m.notEnforced({} as never)).toEqual({ enforced: false });
  });
});
