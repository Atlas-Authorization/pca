/** r14 static-mutant kills for intent-required.ts (fresh module): suiteErr (unsupported sig.alg reason) and BODY_KEYS ('sig' allowed). */
import { describe, expect, it, vi } from 'vitest';
import { b64u, sha256, utf8 } from './hash';

const settle = <T>(f: () => T) => {
  try {
    return { ok: true as const, value: f() };
  } catch (e) {
    return { ok: false as const, error: { name: (e as Error)?.name, message: (e as Error)?.message } };
  }
};
const D32 = (l: string) => b64u(sha256(utf8(`r14-g7-ir/${l}`)));
const SK = sha256(utf8('r14-g7-ir/site'));
const BODY = () => ({
  v: 1, kind: 'pca-intent-required', session: D32('session'), map_digest: D32('map'), schema: D32('schema'), pcactn_digest: D32('pcactn'),
  action_digest: D32('action'), cell: { verb: 'air.book', coords: { 'env.acc.spend.post': [2, 3] } }, reason: 'uncertain', question_id: 'q_1',
  friction: 'typed', delivered_to: 'wallet', expires_at: 2_000_000_000_000,
});

describe('intent-required.ts helpers (fresh module)', () => {
  it('a signed body (with sig) is well-formed; an unsupported sig.alg is named', async () => {
    vi.resetModules();
    const m = await import('./intent-required');
    const s = m.signIntentRequired(BODY() as never, 'k1', SK);
    expect(settle(() => m.intentRequiredShapeError(s))).toEqual({ ok: true, value: null });
    const bad = { ...s, sig: { ...s.sig, alg: 'no-such-suite' } };
    const r = settle(() => m.intentRequiredShapeError(bad));
    expect(r.ok).toBe(true);
    expect(String((r as { value: unknown }).value)).toMatch(/^sig\.alg: .*unsupported_suite/);
  });
});
