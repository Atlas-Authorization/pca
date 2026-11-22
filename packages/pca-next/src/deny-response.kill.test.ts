/** pca-next: the deny response is built from the guard result exactly, with the guard result controlled. */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { withPCA } from './index';

const st = vi.hoisted(() => ({ result: undefined as unknown }));
vi.mock('@atlasauth/pca', async (orig) => {
  const actual = await orig<typeof import('@atlasauth/pca')>();
  return { ...actual, requirePCA: () => async () => st.result };
});

const mk = () => new Request('https://rs.example/x', { method: 'POST' });
const run = (onDeny?: never) => withPCA({ audience: 'a', resolveGrant: async () => null, ...(onDeny ? { onDeny } : {}) } as never, () => new Response('ok'))(mk());

describe('withPCA deny response', () => {
  beforeEach(() => { st.result = undefined; });

  it('falls back to forbidden / deny with no reasons, no decision, no challenge, no escalation', async () => {
    st.result = { ok: false, status: 403, verdict: { ok: false } };
    const res = await run();
    expect(res.status).toBe(403);
    expect(res.headers.get('content-type')).toBe('application/json');
    expect(res.headers.get('WWW-Authenticate')).toBeNull();
    expect(await res.json()).toEqual({ error: 'forbidden', verdict: { ok: false }, decision: 'deny' });
  });

  it('uses the first reason, the guard decision, the challenge and the escalation when present', async () => {
    st.result = { ok: false, status: 401, verdict: { ok: false, reasons: ['r1', 'r2'] }, decision: 'escalate', escalation: { to: 'human' }, wwwAuthenticate: 'PCA realm="x"' };
    const res = await run();
    expect(res.status).toBe(401);
    expect(res.headers.get('WWW-Authenticate')).toBe('PCA realm="x"');
    expect(await res.json()).toEqual({ error: 'r1', verdict: { ok: false, reasons: ['r1', 'r2'] }, decision: 'escalate', escalation: { to: 'human' } });
  });

  it('defers to onDeny when supplied', async () => {
    st.result = { ok: false, status: 403, verdict: { ok: false } };
    const seen: unknown[] = [];
    const onDeny = ((r: unknown, q: Request) => { seen.push(r, q.method); return new Response('custom', { status: 418 }); }) as never;
    const res = await run(onDeny);
    expect(res.status).toBe(418);
    expect(await res.text()).toBe('custom');
    expect(seen).toEqual([st.result, 'POST']);
  });
});
