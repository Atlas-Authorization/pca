import { describe, expect, it } from 'vitest';
import { McpHttpServer, type HttpReq } from './mcp-http';
import { FakeUpstream, cfgFor, createIssue, deleteRepo, readIssue, rules, secretTool } from './test-support/fakes';

const ENV = { TOK_A: 'alice-token-0123456789', TOK_B: 'bob-token-0123456789ab' };
const listen = (over: Record<string, unknown> = {}) => ({
  host: '127.0.0.1',
  clients: { alice: { tokenEnv: 'TOK_A' }, bob: { tokenEnv: 'TOK_B' } },
  allowedOrigins: ['https://app.example'],
  ...over,
});

async function boot(over: Record<string, unknown> = {}, lst: Record<string, unknown> = {}) {
  const ups: FakeUpstream[] = [];
  const cfg = cfgFor({ approvals: { waitSeconds: 1 }, ...over }, rules(), { listen: listen(lst) });
  const server = await McpHttpServer.create({
    cfg,
    env: ENV,
    makeUpstream: () => {
      const u = new FakeUpstream([readIssue, createIssue, deleteRepo, secretTool]);
      ups.push(u);
      return u;
    },
  });
  let n = 0;
  const post = (body: unknown, h: Record<string, string> = {}, token: string | null = ENV.TOK_A) =>
    server.handle({
      method: 'POST',
      url: '/mcp',
      headers: { host: 'localhost:8789', 'content-type': 'application/json', ...(token !== null ? { authorization: `Bearer ${token}` } : {}), ...h },
      body: Buffer.from(typeof body === 'string' ? body : JSON.stringify(body)),
    } as HttpReq);
  const rpc = (method: string, params?: unknown, h: Record<string, string> = {}, token?: string | null) => post({ jsonrpc: '2.0', id: ++n, method, ...(params !== undefined ? { params } : {}) }, h, token);
  const open = async (token = ENV.TOK_A): Promise<string> => {
    const r = await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } }, {}, token);
    expect(r.status).toBe(200);
    return r.headers['mcp-session-id']!;
  };
  const call = async (sid: string, name: string, args: unknown, token = ENV.TOK_A) => {
    const r = await rpc('tools/call', { name, arguments: args }, { 'mcp-session-id': sid }, token);
    const body = JSON.parse(r.body.toString() || '{}') as { result?: { isError?: boolean; content?: Array<{ text: string }> } };
    return { status: r.status, error: body.result?.isError === true ? (body.result.content?.[0]?.text ?? '') : '' };
  };
  return { server, ups, post, rpc, open, call };
}

describe('authentication and the browser rules', () => {
  it('refuses a request with no token or a wrong one', async () => {
    const t = await boot();
    expect((await t.rpc('initialize', {}, {}, null)).status).toBe(401);
    expect((await t.rpc('initialize', {}, {}, 'not-the-token-0123456789')).status).toBe(401);
    expect((await t.rpc('initialize', {}, { authorization: 'Basic abc' }, null)).status).toBe(401);
    expect(t.ups).toHaveLength(1); // only the bootstrap probe ever ran
  });

  it('refuses a foreign Origin and a foreign Host, allows a listed Origin and none', async () => {
    const t = await boot();
    expect((await t.rpc('initialize', {}, { origin: 'https://evil.example' })).status).toBe(403);
    expect((await t.rpc('initialize', {}, { host: 'evil.example' })).status).toBe(403);
    expect((await t.rpc('initialize', {}, { origin: 'https://app.example' })).status).toBe(200);
    expect((await t.rpc('initialize', {})).status).toBe(200);
  });

  it('serves nothing but POST and DELETE on its path', async () => {
    const t = await boot();
    const get = await t.server.handle({ method: 'GET', url: '/mcp', headers: { host: 'localhost', authorization: `Bearer ${ENV.TOK_A}` }, body: Buffer.alloc(0) });
    expect(get.status).toBe(405);
    const other = await t.server.handle({ method: 'POST', url: '/other', headers: { host: 'localhost', authorization: `Bearer ${ENV.TOK_A}` }, body: Buffer.alloc(0) });
    expect(other.status).toBe(404);
  });

  it('refuses a batch, a non-JSON body, another content type and an oversized message', async () => {
    const t = await boot({ limits: { maxRequestBytes: 1024 } });
    expect((await t.post('[{"jsonrpc":"2.0","id":1,"method":"ping"}]')).status).toBe(400);
    expect((await t.post('{nope')).status).toBe(400);
    expect((await t.post('{}', { 'content-type': 'text/plain' })).status).toBe(415);
    expect((await t.post(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping', params: { x: 'a'.repeat(6000) } }))).status).toBe(413);
  });

  it('no token is ever needed only when the operator says so, on loopback', async () => {
    const t = await boot({}, { clients: undefined, insecureNoAuth: true });
    expect((await t.rpc('initialize', {}, {}, undefined)).status).toBe(200);
  });
});

describe('sessions', () => {
  it('needs a session id after initialize, and rejects an unknown one', async () => {
    const t = await boot();
    expect((await t.rpc('tools/list')).status).toBe(400);
    expect((await t.rpc('tools/list', undefined, { 'mcp-session-id': 'nope' })).status).toBe(404);
    const sid = await t.open();
    expect((await t.rpc('initialize', {}, { 'mcp-session-id': sid })).status).toBe(400);
    const r = await t.rpc('tools/list', undefined, { 'mcp-session-id': sid });
    expect((JSON.parse(r.body.toString()) as { result: { tools: Array<{ name: string }> } }).result.tools.map((x) => x.name)).toEqual(['read_issue', 'create_issue']);
  });

  it('a session belongs to the client that opened it: another client gets a 404', async () => {
    const t = await boot();
    const sid = await t.open(ENV.TOK_A);
    expect((await t.rpc('tools/list', undefined, { 'mcp-session-id': sid }, ENV.TOK_B)).status).toBe(404);
    expect((await t.server.handle({ method: 'DELETE', url: '/mcp', headers: { host: 'localhost', authorization: `Bearer ${ENV.TOK_B}`, 'mcp-session-id': sid }, body: Buffer.alloc(0) })).status).toBe(404);
    expect((await t.rpc('tools/list', undefined, { 'mcp-session-id': sid }, ENV.TOK_A)).status).toBe(200);
  });

  it('each session has its own upstream, and DELETE closes it', async () => {
    const t = await boot();
    const a = await t.open();
    const b = await t.open();
    expect(a).not.toBe(b);
    expect(t.server.sessionCount).toBe(2);
    const del = await t.server.handle({ method: 'DELETE', url: '/mcp', headers: { host: 'localhost', authorization: `Bearer ${ENV.TOK_A}`, 'mcp-session-id': a }, body: Buffer.alloc(0) });
    expect(del.status).toBe(204);
    expect(t.ups.filter((u) => u.closed).length).toBeGreaterThanOrEqual(2); // the probe and session a
    expect((await t.rpc('tools/list', undefined, { 'mcp-session-id': a })).status).toBe(404);
    expect((await t.rpc('tools/list', undefined, { 'mcp-session-id': b })).status).toBe(200);
  });

  it('caps the sessions and sweeps the idle ones', async () => {
    let now = 1_000_000;
    const ups: FakeUpstream[] = [];
    const cfg = cfgFor({}, rules(), { listen: listen({ maxSessions: 2, idleSeconds: 60 }) });
    const server = await McpHttpServer.create({ cfg, env: ENV, now: () => now, makeUpstream: () => { const u = new FakeUpstream([readIssue]); ups.push(u); return u; } });
    const init = (token = ENV.TOK_A) => server.handle({ method: 'POST', url: '/mcp', headers: { host: 'localhost', 'content-type': 'application/json', authorization: `Bearer ${token}` }, body: Buffer.from('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}') });
    expect((await init()).status).toBe(200);
    expect((await init()).status).toBe(200);
    expect((await init()).status).toBe(503);
    now += 61_000;
    expect(await server.sweep()).toBe(2);
    expect((await init()).status).toBe(200);
  });
});

describe('isolation between sessions and clients', () => {
  it('untrusted content in one client does not taint another client', async () => {
    const t = await boot();
    const a = await t.open(ENV.TOK_A);
    const b = await t.open(ENV.TOK_B);
    expect((await t.call(a, 'read_issue', { id: 1 })).error).toBe('');
    // alice's write is now held (nobody approves it); bob, who has seen nothing untrusted, is not held
    expect((await t.call(a, 'create_issue', { title: 'a' })).error).toMatch(/approval_timeout/);
    expect((await t.call(b, 'create_issue', { title: 'b' })).error).toBe('');
  });

  it('a client that saw untrusted content starts its next session tainted', async () => {
    const t = await boot();
    const a1 = await t.open(ENV.TOK_A);
    await t.call(a1, 'read_issue', { id: 1 });
    const a2 = await t.open(ENV.TOK_A);
    expect((await t.call(a2, 'create_issue', { title: 'fresh session, same client' })).error).toMatch(/approval_timeout/);
  });

  it('what one session lists and what it calls come from its own upstream', async () => {
    const t = await boot();
    const a = await t.open(ENV.TOK_A);
    const b = await t.open(ENV.TOK_B);
    await t.call(a, 'read_issue', { id: 1 });
    const mine = t.ups.slice(1);
    expect(mine[0]!.calls).toHaveLength(1);
    expect(mine[1]!.calls).toHaveLength(0);
    void b;
  });

  it('one budget, one audit chain across sessions', async () => {
    const t = await boot({ budget: { max: 0.1 } });
    const a = await t.open(ENV.TOK_A);
    const b = await t.open(ENV.TOK_B);
    expect((await t.call(a, 'read_issue', { id: 1 })).error).toBe('');
    expect((await t.call(b, 'read_issue', { id: 2 })).error).toBe('');
    expect((await t.call(a, 'read_issue', { id: 3 })).error).toMatch(/verify_denied/);
  });

  it('tool refusals and default deny hold over HTTP', async () => {
    const t = await boot();
    const a = await t.open();
    expect((await t.call(a, 'dump_secrets', {})).error).toMatch(/unmapped/);
    expect((await t.call(a, 'read_issue', { id: 'x' })).error).toMatch(/bad_args/);
  });
});
