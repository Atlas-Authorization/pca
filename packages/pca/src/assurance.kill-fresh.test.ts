/**
 * assurance.ts builds its known-requirement sets (the requirement keys, the threshold schemes) at module load. Other tests
 * re-evaluate the module inside a test body (vi.resetModules), so a static import would not be the evaluation a mutant of those
 * sets lands in. These tests re-evaluate the module themselves and pin that every known key and scheme is accepted.
 */
import { describe, expect, it, vi } from 'vitest';
import type { AssuranceReport, AssuranceRequirement } from './assurance';

async function unmet(req: Record<string, unknown>) {
  vi.resetModules();
  const { unmetAssurance } = await import('./assurance');
  return unmetAssurance({} as AssuranceReport, req as unknown as AssuranceRequirement);
}

describe('unmetAssurance (fresh module): every known requirement key and threshold scheme is accepted', () => {
  it('signature is a known key', async () => {
    expect(await unmet({ signature: 'pq' })).toBe('assurance: post-quantum signatures required but there is no leaf_signature evidence');
  });
  it('threshold is a known key and each scheme alone is known', async () => {
    for (const scheme of ['multisig', 'frost', 'frost_dkg', 'mpc']) {
      const why = await unmet({ threshold: [scheme] });
      expect(why, scheme).toMatch(/^assurance: /);
      expect(why, scheme).not.toMatch(/unknown/);
    }
  });
  it('the allow flags are known keys', async () => {
    expect(await unmet({ allowAwaitingAudit: true })).toBeUndefined();
    expect(await unmet({ allowPreview: true })).toBeUndefined();
  });
  it('an empty string is not a known key or scheme', async () => {
    expect(await unmet({ '': true })).toBe('assurance: unknown requirement  (fail closed)');
    expect(await unmet({ threshold: [''] })).toBe('assurance: unknown threshold requirement [""] (fail closed)');
  });
});
