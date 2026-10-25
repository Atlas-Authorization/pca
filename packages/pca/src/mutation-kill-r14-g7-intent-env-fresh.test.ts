/** r14 static-mutant kills for intent-env.ts: the obj / mem helpers behind intentProvenanceActive and intentWBActive (fresh module). */
import { describe, expect, it, vi } from 'vitest';

const settle = <T>(f: () => T) => {
  try {
    return { ok: true as const, value: f() };
  } catch (e) {
    return { ok: false as const, error: { name: (e as Error)?.name, message: (e as Error)?.message } };
  }
};

describe('intent-env.ts helpers (fresh module)', () => {
  it('own members of plain objects are read; others are absent', async () => {
    vi.resetModules();
    const m = await import('./intent-env');
    expect(settle(() => [m.intentProvenanceActive({ prov: {} }), m.intentProvenanceActive({}), m.intentProvenanceActive(null as never)])).toEqual({ ok: true, value: [true, false, false] });
    expect(settle(() => m.intentWBActive({ intent_session: { prov: {} } }))).toEqual({ ok: true, value: { facts: false, provenance: true, classes: false } });
    expect(settle(() => m.intentWBActive({ intent_session: { labels: ['x'] } }))).toEqual({ ok: true, value: { facts: false, provenance: true, classes: false } });
    expect(settle(() => m.intentWBActive({ intent_session: {}, policy: { provenance: {} } }))).toEqual({ ok: true, value: { facts: false, provenance: true, classes: false } });
    expect(settle(() => m.intentWBActive({ intent_session: 5 }))).toEqual({ ok: true, value: { facts: false, provenance: false, classes: false } });
  });
});
