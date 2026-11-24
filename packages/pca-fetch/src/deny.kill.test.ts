import { describe, expect, it, vi } from 'vitest';

type Res = Record<string, unknown>;
let next: Res = {};

vi.mock('@atlasauth/pca', async (importOriginal) => {
  const orig = await importOriginal<typeof import('@atlasauth/pca')>();
  return { ...orig, requirePCA: () => async () => next };
});

import { withPCA } from './index';

const run = async (result: Res, denyBody?: (r: never) => unknown) => {
  next = result;
  const res = await withPCA({ audience: 'a', resolveGrant: async () => null, insecureAllowUnboundOperation: true, ...(denyBody ? { denyBody } : {}) } as never, async () => new Response('ok'))(new Request('https://rs.example/x', { method: 'POST' }));
  return { res, body: await res.json() as Res };
};

describe('pca-fetch deny response', () => {
  it('uses the first reason, the decision, the escalation and the challenge header', async () => {
    const verdict = { reasons: ['r1', 'r2'] };
    const escalation = { id: 'esc1' };
    const { res, body } = await run({ ok: false, status: 403, verdict, decision: 'escalate', escalation, wwwAuthenticate: 'PCA realm="x"' });
    expect(res.status).toBe(403);
    expect(res.headers.get('content-type')).toBe('application/json');
    expect(res.headers.get('WWW-Authenticate')).toBe('PCA realm="x"');
    expect(body).toEqual({ error: 'r1', verdict, decision: 'escalate', escalation });
  });

  it('defaults error to forbidden and decision to deny, omits escalation and the challenge header', async () => {
    const verdict = {};
    const { res, body } = await run({ ok: false, status: 401, verdict });
    expect(body).toEqual({ error: 'forbidden', verdict, decision: 'deny' });
    expect(res.headers.get('WWW-Authenticate')).toBeNull();
    const second = await run({ ok: false, status: 401, verdict: { reasons: [] } });
    expect(second.body.error).toBe('forbidden');
  });

  it('prefers a custom denyBody', async () => {
    const { body } = await run({ ok: false, status: 403, verdict: {} }, () => ({ custom: true }));
    expect(body).toEqual({ custom: true });
  });
});
