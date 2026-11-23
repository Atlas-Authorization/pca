import { describe, expect, it, vi } from 'vitest';

const guardResult: { current: unknown } = { current: undefined };
vi.mock('@atlasauth/pca', async (orig) => {
  const real = await orig<typeof import('@atlasauth/pca')>();
  return {
    ...real,
    requirePCA: () => async () => {
      if (guardResult.current instanceof Error) throw guardResult.current;
      return guardResult.current;
    },
  };
});

import { pcaExpress } from './index';

function fakeRes() {
  const sets: Array<[string, string]> = [];
  const r = {
    code: undefined as number | undefined,
    sets,
    body: undefined as unknown,
    status(c: number) { r.code = c; return r; },
    set(k: string, v: string) { sets.push([k, v]); return r; },
    json(b: unknown) { r.body = b; return b; },
  };
  return r;
}
const opts = { audience: 'a', resolveGrant: async () => null, insecureAllowUnboundOperation: true } as never;

describe('pcaExpress guard glue', () => {
  it('forwards a guard exception to next(err) and does not answer', async () => {
    const boom = new Error('boom');
    guardResult.current = boom;
    const res = fakeRes();
    const nexts: unknown[] = [];
    await pcaExpress(opts)({ headers: {} } as never, res as never, (e) => { nexts.push(e); });
    expect(nexts).toEqual([boom]);
    expect(res.code).toBeUndefined();
    expect(res.body).toBeUndefined();
  });

  it('with no reasons, no challenge, no decision: forbidden/deny, no header, no escalation', async () => {
    guardResult.current = { ok: false, status: 403, verdict: {} };
    const res = fakeRes();
    await pcaExpress(opts)({ headers: {} } as never, res as never, () => { throw new Error('next'); });
    expect(res.code).toBe(403);
    expect(res.sets).toEqual([]);
    expect(res.body).toEqual({ error: 'forbidden', verdict: {}, decision: 'deny' });
  });

  it('uses the first reason, the challenge header, the decision and the escalation', async () => {
    const verdict = { reasons: ['r1', 'r2'] };
    guardResult.current = { ok: false, status: 401, verdict, wwwAuthenticate: 'PCA realm="x"', decision: 'escalate', escalation: { to: 'human' } };
    const res = fakeRes();
    await pcaExpress(opts)({ headers: {} } as never, res as never, () => {});
    expect(res.sets).toEqual([['WWW-Authenticate', 'PCA realm="x"']]);
    expect(res.body).toEqual({ error: 'r1', verdict, decision: 'escalate', escalation: { to: 'human' } });
  });
});
