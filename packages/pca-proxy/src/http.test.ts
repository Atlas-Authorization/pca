import { agent, generateKeyPair, pcaHeaders } from '@atlasauth/pca';
import { bindParams, requestBinding } from '@atlasauth/pca-gateway';
import { beforeAll, describe, expect, it } from 'vitest';
import { parseConfig, type ProxyConfig } from './config';
import { HttpProxy, type HttpRequestLike } from './http';

const SPEC = `openapi: 3.0.3
info: { title: pets, version: '1' }
paths:
  /pets:
    get:
      operationId: listPets
      parameters:
        - { name: limit, in: query, schema: { type: integer, minimum: 1, maximum: 50 } }
        - { name: tag, in: query, schema: { type: array, items: { type: string } } }
      responses: { '200': { description: ok } }
    post:
      operationId: createPet
      requestBody:
        required: true
        content:
          application/json:
            schema: { type: object, required: [name], properties: { name: { type: string, maxLength: 40 } } }
      responses: { '201': { description: created } }
  /pets/{id}:
    get:
      operationId: getPet
      parameters:
        - { name: id, in: path, required: true, schema: { type: integer } }
      responses: { '200': { description: ok } }
    delete:
      operationId: deletePet
      parameters:
        - { name: id, in: path, required: true, schema: { type: integer } }
      responses: { '204': { description: gone } }
`;

const baseRules = {
  listPets: { policy: 'allow', effect: 'read' },
  getPet: { policy: 'allow', effect: 'read' },
  createPet: { policy: 'allow', effect: 'write' },
  deletePet: { policy: 'deny', effect: 'write' },
};

function cfgOf(http: Record<string, unknown> = {}, top: Record<string, unknown> = {}): ProxyConfig {
  return parseConfig({ http: { upstream: 'http://api.internal:9000/v1', openapi: 'spec.yaml', actions: baseRules, upstreamHeaders: { Authorization: 'Bearer ${UP_TOKEN}' }, ...http }, state: { backend: 'memory' }, approvals: { waitSeconds: 1 }, ...top });
}

interface Seen { url: string; init: RequestInit }
async function setup(http: Record<string, unknown> = {}, top: Record<string, unknown> = {}, files: Record<string, string> = {}) {
  const seen: Seen[] = [];
  let respond: () => Response | Promise<Response> = () => new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'content-type': 'application/json' } });
  const fetchImpl = (async (url: unknown, init: RequestInit) => {
    seen.push({ url: String(url), init });
    return respond();
  }) as typeof fetch;
  const proxy = await HttpProxy.create({ cfg: cfgOf(http, top), fetchImpl, env: { UP_TOKEN: 's3cret-token' }, readFile: (p) => files[p] ?? (p === 'spec.yaml' ? SPEC : (() => { throw new Error(`no file ${p}`); })()) });
  const req = (method: string, url: string, o: { headers?: HttpRequestLike['headers']; body?: string } = {}) =>
    proxy.handle({ method, url, headers: { 'content-type': 'application/json', ...(o.headers ?? {}) }, body: Buffer.from(o.body ?? '') });
  return { proxy, seen, req, set: (f: typeof respond) => (respond = f) };
}
const err = (r: { body: Buffer }): string => JSON.stringify(JSON.parse(r.body.toString()).error);

describe('sidecar mode', () => {
  it('forwards a mapped call with the upstream credential added and nothing the client injected', async () => {
    const t = await setup();
    const r = await t.req('GET', '/pets/7', { headers: { cookie: 'a=b', 'x-forwarded-host': 'evil', 'x-pca-verb': 'admin.all', 'pca-action': 'forged', 'x-http-method-override': 'DELETE', accept: 'application/json' } });
    expect(r.status).toBe(200);
    expect(t.seen[0]!.url).toBe('http://api.internal:9000/v1/pets/7');
    expect(t.seen[0]!.init.headers).toEqual({ accept: 'application/json', 'content-type': 'application/json', authorization: 'Bearer s3cret-token' });
    expect(t.seen[0]!.init.redirect).toBe('manual');
  });

  it('refuses an unmapped route, a denied operation and a method that is not mapped', async () => {
    const t = await setup();
    expect((await t.req('GET', '/admin')).status).toBe(403);
    expect((await t.req('DELETE', '/pets/1')).status).toBe(403);
    expect(err(await t.req('PATCH', '/pets/1'))).toMatch(/unmapped/);
    expect(t.seen).toHaveLength(0);
  });

  it.each(['/pets/../admin', '/pets//1', '/pets/%2e%2e/admin', '/pets/1;x=1', '/pets/%2F1', '/pets/*', '/pets/1\\x', '/pets/%00'])('refuses the ambiguous path %s', async (p) => {
    const t = await setup();
    expect((await t.req('GET', p)).status).toBe(400);
    expect(t.seen).toHaveLength(0);
  });

  it('refuses header smuggling', async () => {
    const t = await setup();
    expect((await t.req('GET', '/pets/1', { headers: { 'transfer-encoding': 'chunked', 'content-length': '5' } })).status).toBe(400);
    expect((await t.req('POST', '/pets', { headers: { 'content-type': ['application/json', 'text/plain'] }, body: '{"name":"a"}' })).status).toBe(400);
    const s = await setup({ sessionHeader: 'x-pca-session' });
    expect((await s.req('GET', '/pets/1', { headers: { 'x-pca-session': ['a', 'b'] } })).status).toBe(400);
    expect((await s.req('GET', '/pets/1', { headers: { 'x-pca-session': 'a b c' } })).status).toBe(400);
    expect(t.seen).toHaveLength(0);
  });

  it('rebuilds the body from what was checked', async () => {
    const t = await setup();
    const r = await t.req('POST', '/pets', { body: '{ "name" :  "rex" }' });
    expect(r.status).toBe(200);
    expect(Buffer.from(t.seen[0]!.init.body as Uint8Array).toString()).toBe('{"name":"rex"}');
  });

  it.each([
    ['an undeclared field', '{"name":"a","admin":true}', 422],
    ['a missing field', '{}', 422],
    ['a field over its bound', `{"name":"${'a'.repeat(50)}"}`, 422],
    ['duplicate keys', '{"name":"a","name":"b"}', 400],
    ['an array body', '[1]', 400],
    ['text that is not JSON', 'name=a', 400],
  ])('refuses %s', async (_n, body, status) => {
    const t = await setup();
    expect((await t.req('POST', '/pets', { body })).status).toBe(status);
    expect(t.seen).toHaveLength(0);
  });

  it('refuses a body on a GET, a non-JSON content type and an oversized body', async () => {
    const t = await setup({}, { limits: { maxRequestBytes: 1024 } });
    expect((await t.req('GET', '/pets/1', { body: '{"a":1}' })).status).toBe(400);
    expect((await t.req('POST', '/pets', { headers: { 'content-type': 'text/plain' }, body: '{"name":"a"}' })).status).toBe(415);
    expect((await t.req('POST', '/pets', { body: JSON.stringify({ name: 'a', pad: 'x'.repeat(2000) }) })).status).toBe(413);
  });

  it('refuses a parameter that appears twice (query and body, or repeated)', async () => {
    const t = await setup();
    expect(err(await t.req('POST', '/pets?name=x', { body: '{"name":"y"}' }))).toMatch(/more than once/);
    expect((await t.req('GET', '/pets?limit=1&limit=2')).status).toBe(400);
  });

  it('checks the query against the definition', async () => {
    const t = await setup();
    expect((await t.req('GET', '/pets?limit=10')).status).toBe(200);
    expect((await t.req('GET', '/pets?limit=999')).status).toBe(422);
    expect((await t.req('GET', '/pets?limit=abc')).status).toBe(422);
    expect((await t.req('GET', '/pets?evil=1')).status).toBe(422);
    expect((await t.req('GET', '/pets?tag=a&tag=b')).status).toBe(200);
  });

  it('treats the upstream failing as a refusal and relays nothing it said', async () => {
    const t = await setup();
    t.set(() => new Response('internal stack trace password=hunter2', { status: 500 }));
    const a = await t.req('GET', '/pets/1');
    expect(a.status).toBe(502);
    expect(a.body.toString()).not.toMatch(/hunter2/);
    t.set(() => new Response(null, { status: 302, headers: { location: 'http://evil' } }));
    expect((await t.req('GET', '/pets/1')).status).toBe(502);
    t.set(() => {
      throw new Error('ECONNRESET');
    });
    expect((await t.req('GET', '/pets/1')).status).toBe(502);
  });

  it('refuses an oversized upstream response', async () => {
    const t = await setup({}, { limits: { maxResponseBytes: 2048 } });
    t.set(() => new Response('x'.repeat(5000), { status: 200 }));
    expect(err(await t.req('GET', '/pets/1'))).toMatch(/response_too_large/);
  });

  it('holds a write once the session has relayed an upstream response', async () => {
    const t = await setup();
    expect((await t.req('POST', '/pets', { body: '{"name":"first"}' })).status).toBe(200); // clean session
    const r = await t.req('POST', '/pets', { body: '{"name":"second"}' });
    expect(r.status).toBe(403);
    expect(err(r)).toMatch(/approval_timeout/);
    expect(t.seen).toHaveLength(1);
  });

  it('keeps sessions apart only when a trusted layer names them', async () => {
    const t = await setup({ sessionHeader: 'x-pca-session' });
    await t.req('GET', '/pets/1', { headers: { 'x-pca-session': 'a' } });
    expect((await t.req('POST', '/pets', { headers: { 'x-pca-session': 'b' }, body: '{"name":"x"}' })).status).toBe(200);
  });

  it('does not let the caller pick a clean session when none is configured', async () => {
    const t = await setup();
    await t.req('GET', '/pets/1', { headers: { 'x-pca-session': 'a' } });
    const r = await t.req('POST', '/pets', { headers: { 'x-pca-session': 'fresh' }, body: '{"name":"x"}' });
    expect(err(r)).toMatch(/approval_timeout/);
  });

  it('can send the minted proof upstream', async () => {
    const t = await setup({ attachProof: true });
    await t.req('GET', '/pets/1');
    expect(String((t.seen[0]!.init.headers as Record<string, string>)['pca-action']).length).toBeGreaterThan(100);
  });

  it('observe mode forwards what enforce mode would refuse and records it', async () => {
    const t = await setup({}, { mode: 'observe' });
    expect((await t.req('GET', '/admin')).status).toBe(200);
    expect((await t.req('DELETE', '/pets/1')).status).toBe(200);
    expect(t.seen).toHaveLength(2);
    const last = t.proxy.engine.audit.tail.at(-1)!;
    expect(last.checks?.allowed).toBe('false');
  });

  it('writes a hash-chained receipt per decision', async () => {
    const t = await setup();
    await t.req('GET', '/pets/1');
    await t.req('GET', '/admin');
    expect(t.proxy.engine.audit.tail.length).toBe(2);
    expect(t.proxy.engine.audit.tail[1]!.prev).toBe(t.proxy.engine.audit.tail[0]!.hash);
  });
});

describe('the rules file form', () => {
  it('maps hand-written routes and denies everything else', async () => {
    const t = await setup({ openapi: undefined, actions: {}, routes: [{ method: 'GET', path: '/health', policy: 'allow', effect: 'read' }, { method: 'POST', path: '/orders/{id}/cancel', policy: 'deny', effect: 'write' }] });
    expect((await t.req('GET', '/health')).status).toBe(200);
    expect(err(await t.req('POST', '/orders/9/cancel'))).toMatch(/policy_deny/);
    expect((await t.req('GET', '/other')).status).toBe(403);
  });
});

describe('verify mode', () => {
  const principal = generateKeyPair();
  let verb = '';
  beforeAll(async () => {
    const probe = await HttpProxy.create({ cfg: cfgOf(), readFile: () => SPEC, env: { UP_TOKEN: 'x' } });
    verb = probe.routes.find((e) => e.id === 'GET /pets/{id}')!.verb;
  });
  const mk = (aud = 'ins_test') => agent({ principal, goal: 'read pets', permissions: { [verb.split('.')[0]!]: [verb.split('.').slice(1).join('.')] }, aud, riskPolicy: { theta1: 1, theta2: 1 } });
  const grant = (a: ReturnType<typeof mk>): string => JSON.stringify(a.grant);
  const proofFor = (a: ReturnType<typeof mk>, path: string, args: Record<string, unknown>): string => {
    const binding = requestBinding({ method: 'GET', path, query: '', headers: {} }, { body: false });
    return pcaHeaders(a.act(verb, 'pet', bindParams(args, binding)).encoded)['PCA-Action']!;
  };
  const verifyProxy = (a: ReturnType<typeof mk>) => setup({ mode: 'verify', grants: ['g.json'] }, { audience: 'ins_test' }, { 'g.json': grant(a) });

  it('refuses a call with no proof, forwards one with a valid proof, and refuses its replay', async () => {
    const a = mk();
    const t = await verifyProxy(a);
    expect((await t.req('GET', '/pets/1')).status).toBe(401);
    const h = proofFor(a, '/pets/1', { id: 1 });
    expect((await t.req('GET', '/pets/1', { headers: { 'pca-action': h } })).status).toBe(200);
    const again = await t.req('GET', '/pets/1', { headers: { 'pca-action': h } });
    expect(again.status).toBe(403);
    expect(t.seen).toHaveLength(1);
  });

  it('refuses a proof presented on another path, another argument set or another audience', async () => {
    const a = mk();
    const t = await verifyProxy(a);
    expect((await t.req('GET', '/pets/2', { headers: { 'pca-action': proofFor(a, '/pets/1', { id: 1 }) } })).status).toBe(403);
    expect((await t.req('GET', '/pets/1', { headers: { 'pca-action': proofFor(a, '/pets/1', { id: 9 }) } })).status).toBe(403);
    const other = mk('ins_other');
    const t2 = await setup({ mode: 'verify', grants: ['g.json'] }, { audience: 'ins_test' }, { 'g.json': grant(other) });
    expect((await t2.req('GET', '/pets/1', { headers: { 'pca-action': proofFor(other, '/pets/1', { id: 1 }) } })).status).toBe(403);
    expect(t.seen).toHaveLength(0);
  });

  it('refuses two proof headers and a proof that does not decode', async () => {
    const a = mk();
    const t = await verifyProxy(a);
    const h = proofFor(a, '/pets/1', { id: 1 });
    expect((await t.req('GET', '/pets/1', { headers: { 'pca-action': [h, h] } })).status).toBe(400);
    expect([401, 403]).toContain((await t.req('GET', '/pets/1', { headers: { 'pca-action': 'not-a-proof' } })).status);
  });
});
