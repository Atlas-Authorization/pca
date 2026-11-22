import { describe, expect, it, vi } from 'vitest';

const h = vi.hoisted(() => ({ result: undefined as unknown }));
vi.mock('@atlasauth/pca', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@atlasauth/pca')>();
  return { ...actual, requirePCA: () => async () => h.result };
});

import { pcaHono } from './index';

function ctx() {
  const last: { body?: unknown; status?: number; headers?: Record<string, string> | undefined } = {};
  const c = {
    last,
    req: { header: () => undefined, json: async () => undefined as unknown },
    set: () => {},
    json: (body: unknown, status?: number, headers?: Record<string, string>): Response => {
      last.body = body; last.status = status; last.headers = headers;
      return new Response('x');
    },
  };
  return c;
}

const mw = () => pcaHono({ audience: 'a', resolveGrant: async () => null, insecureAllowUnenforced: true });

describe('pcaHono deny response shape', () => {
  it('falls back to forbidden / deny when the result names neither reason nor decision', async () => {
    h.result = { ok: false, status: 403, verdict: { ok: false, checks: {} } };
    const c = ctx();
    await mw()(c as never, async () => {});
    expect(c.last.body).toEqual({ error: 'forbidden', verdict: { ok: false, checks: {} }, decision: 'deny' });
    expect(c.last.status).toBe(403);
    expect(c.last.headers).toBeUndefined();
  });

  it('uses the first reason, the given decision, the escalation and the challenge', async () => {
    const escalation = { id: 'e1' };
    h.result = { ok: false, status: 401, verdict: { ok: false, reasons: ['first', 'second'] }, decision: 'escalate', escalation, wwwAuthenticate: 'PCA realm="x"' };
    const c = ctx();
    await mw()(c as never, async () => {});
    expect(c.last.body).toEqual({ error: 'first', verdict: { ok: false, reasons: ['first', 'second'] }, decision: 'escalate', escalation });
    expect(c.last.status).toBe(401);
    expect(c.last.headers).toEqual({ 'WWW-Authenticate': 'PCA realm="x"' });
  });

  it('hands the denial to onDeny and returns its response untouched', async () => {
    h.result = { ok: false, status: 403, verdict: { ok: false, reasons: ['r'] } };
    const c = ctx();
    const custom = new Response('custom');
    const seen: unknown[] = [];
    const out = await pcaHono({ audience: 'a', resolveGrant: async () => null, insecureAllowUnenforced: true, onDeny: (r, cc) => { seen.push(r, cc); return custom; } })(c as never, async () => {});
    expect(out).toBe(custom);
    expect(seen[0]).toBe(h.result);
    expect(seen[1]).toBe(c);
    expect(c.last.body).toBeUndefined();
  });
});
