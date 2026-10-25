/** r14 static-mutant kills for label-receipts.ts (fresh module): the domains, PUBLIC_CLASS, isLabelKey and classCovered. */
import { describe, expect, it, vi } from 'vitest';
import { b64u, sha256, utf8 } from './hash';

const settle = <T>(f: () => T) => {
  try {
    return { ok: true as const, value: f() };
  } catch (e) {
    return { ok: false as const, error: { name: (e as Error)?.name, message: (e as Error)?.message } };
  }
};
const PK = b64u(sha256(utf8('r14-g7-labels/pk')));

describe('label-receipts.ts (fresh module)', () => {
  it('constants', async () => {
    vi.resetModules();
    const m = await import('./label-receipts');
    expect([m.LABELS_DOMAIN, m.LABELS_REF_DOMAIN, m.PUBLIC_CLASS]).toEqual(['atlas-pca/labels/v1\0', 'atlas-pca/labels-ref/v1', 'public']);
  });
  it('isLabelKey', async () => {
    vi.resetModules();
    const m = await import('./label-receipts');
    expect(settle(() => [m.isLabelKey({ site: 's', kid: 'k', pk: PK }), m.isLabelKey({ site: 's', kid: 'k', pk: 'x' })])).toEqual({ ok: true, value: [true, false] });
  });
  it('classCovered (exact, prefix, *, public)', async () => {
    vi.resetModules();
    const m = await import('./label-receipts');
    const f = [{ path: 'a', class: 'pii.x' }, { path: 'b', class: 'pay' }, { path: 'c', class: 'public' }];
    expect(settle(() => m.decideReadPurpose(f, 'p', { p: ['pii.*', 'pay'] }))).toEqual({ ok: true, value: { outcome: 'allow', minimise: [], uncovered: [] } });
    expect(settle(() => m.decideReadPurpose(f, 'p', { p: ['*'] }))).toEqual({ ok: true, value: { outcome: 'allow', minimise: [], uncovered: [] } });
    expect(settle(() => m.decideReadPurpose(f, 'p', { p: [] }))).toEqual({ ok: true, value: { outcome: 'question', minimise: [], uncovered: ['a', 'b'] } });
  });
});
