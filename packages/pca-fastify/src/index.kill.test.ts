import { describe, expect, it, vi } from 'vitest';

const guardResult: { current: unknown } = { current: null };
vi.mock('@atlasauth/pca', async (orig) => {
  const real = await orig<typeof import('@atlasauth/pca')>();
  return { ...real, requirePCA: () => async () => guardResult.current };
});

import { pcaFastify } from './index';

function fakeReply() {
  const r = {
    statusCode: undefined as number | undefined,
    headers: {} as Record<string, string>,
    body: undefined as unknown,
    code(c: number) { this.statusCode = c; return this; },
    header(k: string, v: string) { this.headers[k] = v; return this; },
    send(b: unknown) { this.body = b; return b; },
  };
  return r;
}

async function run(result: unknown) {
  guardResult.current = result;
  const mw = pcaFastify({ audience: 'a', resolveGrant: async () => null, insecureAllowUnboundOperation: true });
  const reply = fakeReply();
  await mw({ headers: {} } as never, reply as never);
  return reply;
}

describe('pcaFastify denial body', () => {
  it('sends no WWW-Authenticate header when the result has none', async () => {
    const reply = await run({ ok: false, status: 403, verdict: { reasons: ['r1'] } });
    expect(reply.headers).toEqual({});
    expect(reply.statusCode).toBe(403);
  });
  it('sends the challenge, first reason, decision and escalation when present', async () => {
    const verdict = { reasons: ['first', 'second'] };
    const reply = await run({ ok: false, status: 401, wwwAuthenticate: 'PCA realm="x"', verdict, decision: 'escalate', escalation: { id: 'e1' } });
    expect(reply.headers).toEqual({ 'WWW-Authenticate': 'PCA realm="x"' });
    expect(reply.body).toEqual({ error: 'first', verdict, decision: 'escalate', escalation: { id: 'e1' } });
  });
  it("defaults error to 'forbidden' and decision to 'deny', and omits escalation", async () => {
    const verdict = { reasons: [] as string[] };
    const reply = await run({ ok: false, status: 403, verdict });
    expect(reply.body).toEqual({ error: 'forbidden', verdict, decision: 'deny' });
    expect('escalation' in (reply.body as object)).toBe(false);
  });
  it("defaults error to 'forbidden' when the verdict has no reasons array", async () => {
    const reply = await run({ ok: false, status: 403, verdict: {} });
    expect((reply.body as { error: string }).error).toBe('forbidden');
  });
});
