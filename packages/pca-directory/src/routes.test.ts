import { describe, expect, it } from 'vitest';
import { directoryRoutes, httpLogClient, passportDigest, subjectRef, signPop, type RouteRequest } from './index';
import { makeAgent, makeWorld } from './test-util';

const call = (h: ReturnType<typeof directoryRoutes>, method: string, path: string, query: Record<string, string> = {}, body?: unknown) => h({ method, path, query, body, submitter: 't' } as RouteRequest);

describe('the log routes', () => {
  it('serve what an HTTP client expects, end to end', async () => {
    const w = makeWorld(1, 1);
    const log = w.logs[0]!;
    const h = directoryRoutes(log);
    const agent = makeAgent(w.issuer);
    const post = await call(h, 'POST', '/entries', {}, { passport: agent.sp, pop: signPop(agent.kp.secretKey, log.id, agent.sp) });
    expect(post.status).toBe(201);
    expect((await call(h, 'POST', '/entries', {}, { passport: agent.sp, pop: signPop(agent.kp.secretKey, log.id, agent.sp) })).status).toBe(200);

    // an HTTP client over these routes (fetch is a function call here)
    const fetchLike = async (url: string) => {
      const u = new URL(url);
      const out = await call(h, 'GET', u.pathname.replace('/dir', ''), Object.fromEntries(u.searchParams));
      return { ok: out.status < 400, status: out.status, json: async () => out.body };
    };
    const c = httpLogClient('https://x.example/dir', { fetch: fetchLike });
    expect((await c.sth()).size).toBe(1);
    const p = (await c.inclusion(passportDigest(agent.sp)))!;
    expect(p.entry.index).toBe(0);
    expect((await c.status(subjectRef(agent.sp.sub, 'public'))).entries).toHaveLength(1);
    expect(await c.inclusion('nope')).toBeNull();
    expect((await c.entries(0, 10))).toHaveLength(1);
  });

  it('refuse junk with the right status', async () => {
    const w = makeWorld(1, 1);
    const h = directoryRoutes(w.logs[0]!);
    expect((await call(h, 'GET', '/consistency', { from: 'x' })).status).toBe(400);
    expect((await call(h, 'GET', '/entries', { from: '-1' })).status).toBe(400);
    expect((await call(h, 'GET', '/entries/9')).status).toBe(404);
    expect((await call(h, 'GET', '/proof')).status).toBe(400);
    expect((await call(h, 'POST', '/entries', {}, { passport: 1, nope: true })).status).toBe(400);
    expect((await call(h, 'POST', '/entries', {}, [])).status).toBe(400);
    expect((await call(h, 'POST', '/cosignatures', {}, { size: 'x' })).status).toBe(400);
    expect((await call(h, 'DELETE', '/entries')).status).toBe(404);
  });
});
