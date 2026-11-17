import * as nodeCrypto from 'node:crypto';
import * as nodeFs from 'node:fs';
import * as nodePath from 'node:path';
import { existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { matchRoute, templateOf } from '@atlasauth/pca-proxy';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { applyPlan } from './apply';
import { runInit } from './cli';
import { makePlan } from './plan';
import { FIXTURES, fakeDeps, materialize } from './test-support/fixtures';
import type { InitOptions } from './types';

const dirs: string[] = [];
const mk = (name: string, extra: Record<string, string> = {}): string => {
  const d = materialize({ ...FIXTURES[name]!, ...extra });
  dirs.push(d);
  return d;
};
afterEach(() => {
  vi.useRealTimers();
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
const opts = (cwd: string, o: Partial<InitOptions> = {}): InitOptions => ({ cwd, proxy: false, yes: true, dryRun: false, force: false, check: false, noImport: false, ...o });
const rd = (root: string, rel: string): string => readFileSync(join(root, rel), 'utf8');
const TOKEN = 'setup_0123456789abcdefghij';

describe('verbs come from the imported actions', () => {
  it('pca.routes.json carries the verb of every imported HTTP action, and the actions file uses the same verbs', async () => {
    const root = mk('express-ts');
    const plan = await makePlan(opts(root), fakeDeps({ repo: false }));
    const routes = JSON.parse(plan.changes.find((c) => c.path === 'pca.routes.json')!.after) as { method: string; template: string; verb: string }[];
    expect(routes.map((r) => `${r.method} ${r.template}`)).toEqual(['GET /orders', 'POST /orders/{id}/refund']);
    const yaml = plan.changes.find((c) => c.path === 'actions/routes.yaml')!.after;
    for (const r of routes) {
      expect(r.verb).toMatch(/^shop_api\./);
      expect(yaml).toContain(r.verb.slice('shop_api.'.length));
    }
  });

  it('a project with no imported routes keeps the <ns>.<method> fallback and denies nothing as unmapped', async () => {
    const plan = await makePlan(opts(mk('express-ts'), { noImport: true }), fakeDeps({ repo: false }));
    const w = plan.changes.find((c) => c.path === 'src/pca.setup.ts')!.after;
    expect(w).not.toContain('@atlasauth/pca-proxy');
    expect(w).toContain('const routeEntries: any[] = [];');
    expect(plan.changes.find((c) => c.path === 'pca.routes.json')).toBeUndefined();
  });

  /** Run the generated CommonJS wiring against stubs and a fake Fastify app. */
  const load = (root: string, env: Record<string, string>, extra: Record<string, unknown> = {}) => {
    const code = rd(root, 'pca.setup.js');
    const hooks: Record<string, ((...a: never[]) => unknown)[]> = {};
    const stubs: Record<string, unknown> = {
      'node:fs': nodeFs,
      'node:path': nodePath,
      'node:crypto': nodeCrypto,
      '@atlasauth/pca': { protect: () => ({ options: { stub: true } }), unb64u: (s: string) => new TextEncoder().encode(s) },
      '@atlasauth/pca-fastify': { pcaFastify: () => async () => undefined },
      '@atlasauth/pca-proxy': { matchRoute, templateOf },
      ...extra,
    };
    const mod = { exports: {} as { registerPca: (app: unknown) => void } };
    const req = (n: string): unknown => {
      if (!(n in stubs)) throw new Error(`unexpected require ${n}`);
      return stubs[n];
    };
    const g = extra.__fetch as typeof fetch | undefined;
    new Function('require', 'module', 'process', 'fetch', code)(req, mod, { env: { PCA_DIR: root, ...env }, cwd: () => root }, g);
    mod.exports.registerPca({ addHook: (name: string, fn: never) => (hooks[name] ??= []).push(fn) });
    return hooks;
  };
  const reply = () => {
    const r = { code: 0, sent: undefined as unknown, statusCode: 200, codeFn(n: number) { r.code = n; return r; }, send(b: unknown) { r.sent = b; return r; } };
    return { code: (n: number) => r.codeFn(n), send: (b: unknown) => r.send(b), statusCode: 200, r };
  };

  it("resolves with the proxy's matcher: a literal beats a parameter, segments are exact, other methods are unmapped", async () => {
    const root = mk('fastify-js', { 'index.js': `const fastify = require('fastify');\nconst app = fastify();\napp.get('/accounts/:id', h);\napp.get('/accounts/me', h);\n` });
    const deps = fakeDeps({ repo: false });
    applyPlan(await makePlan(opts(root), deps), deps, { force: false });
    const routes = JSON.parse(rd(root, 'pca.routes.json')) as { template: string; verb: string }[];
    const me = routes.find((r) => r.template === '/accounts/me')!.verb;
    const id = routes.find((r) => r.template === '/accounts/{id}')!.verb;
    expect(me).not.toBe(id);
    const hook = load(root, { PCA_MODE: 'observe' }).onResponse![0] as unknown as (req: unknown, reply: unknown) => Promise<void>;
    for (const [m, u] of [['GET', '/accounts/me'], ['GET', '/accounts/42'], ['POST', '/accounts/42'], ['GET', '/accounts/42/extra'], ['GET', '/accounts']]) await hook({ method: m, url: u }, { statusCode: 200 });
    const lines = rd(root, '.pca/observed.jsonl').trim().split('\n').map((l) => JSON.parse(l) as { verb: string; unmapped?: boolean });
    expect(lines.map((l) => l.verb)).toEqual([me, id, 'fast_js.post', 'fast_js.get', 'fast_js.get']);
    expect(lines.map((l) => l.unmapped === true)).toEqual([false, false, true, true, true]);
  });

  it('observe: a mapped route is logged under its action verb; an unmapped one is logged as unmapped', async () => {
    const root = mk('fastify-js');
    const deps = fakeDeps({ repo: false });
    applyPlan(await makePlan(opts(root), deps), deps, { force: false });
    const hooks = load(root, { PCA_MODE: 'observe' });
    const hook = hooks.onResponse![0] as unknown as (req: unknown, reply: unknown) => Promise<void>;
    await hook({ method: 'GET', url: '/ping?x=1', body: {} }, { statusCode: 200 });
    await hook({ method: 'DELETE', url: '/other', body: { amount: 3, note: 'secret text' } }, { statusCode: 200 });
    await hook({ method: 'GET', url: '/ping', body: {} }, { statusCode: 500 });
    const routes = JSON.parse(rd(root, 'pca.routes.json')) as { verb: string }[];
    const lines = rd(root, '.pca/observed.jsonl').trim().split('\n').map((l) => JSON.parse(l) as Record<string, unknown>);
    expect(lines).toHaveLength(2);
    expect(lines[0]).toMatchObject({ verb: routes[0]!.verb, resource: '/ping', outcome: 'allow' });
    expect(lines[0]!.unmapped).toBeUndefined();
    expect(lines[1]).toMatchObject({ verb: 'fast_js.delete', resource: '/other', unmapped: true, params: { amount: 3 } });
    expect(JSON.stringify(lines)).not.toContain('secret text');
  });

  it('enforce: an unmapped route is denied before the guard, a mapped one is passed on', async () => {
    const root = mk('fastify-js');
    const deps = fakeDeps({ repo: false });
    applyPlan(await makePlan(opts(root), deps), deps, { force: false });
    writeFileSync(join(root, 'autopilot.grant.json'), '{"id":"g"}');
    const hooks = load(root, { PCA_MODE: 'enforce' });
    const deny = hooks.preHandler![0] as unknown as (req: unknown, reply: unknown) => Promise<unknown>;
    const r1 = reply();
    await deny({ method: 'GET', url: '/nope' }, r1);
    expect(r1.r.code).toBe(403);
    expect(JSON.stringify(r1.r.sent)).toContain('unmapped route');
    const r2 = reply();
    expect(await deny({ method: 'GET', url: '/ping' }, r2)).toBeUndefined();
    expect(r2.r.code).toBe(0);
    expect(hooks.preHandler).toHaveLength(2);
  });

  it('enforce without the grant fails closed at startup', async () => {
    const root = mk('fastify-js');
    const deps = fakeDeps({ repo: false });
    applyPlan(await makePlan(opts(root), deps), deps, { force: false });
    expect(() => load(root, { PCA_MODE: 'enforce' })).toThrow(/needs autopilot\.grant\.json/);
  });
});

describe('--connect', () => {
  const okFetch = () => vi.fn(async () => new Response(JSON.stringify({ source: 'ignored-by-test', ingest_key: 'sk_test_ingest' }), { status: 201 }));

  it('plans a second keypair, the reporter wiring and the dependency, and never prints the token', async () => {
    const root = mk('express-ts');
    const plan = await makePlan(opts(root, { connect: TOKEN }), fakeDeps({ repo: false }));
    expect(plan.changes.filter((c) => c.generated).map((c) => `${c.path}:${c.group ?? 'dev'}`)).toEqual(['.pca/dev.key:dev', '.pca/dev.key.pub:dev', '.pca/source.key:source', '.pca/source.key.pub:source']);
    const w = plan.changes.find((c) => c.path === 'src/pca.setup.ts')!.after;
    expect(w).toContain("import { signIngest } from '@atlasauth/pca-control-plane';");
    expect(w).toContain('/v1/pca/control/events');
    expect(w).toContain('report(op, via, body);');
    expect(JSON.parse(plan.changes.find((c) => c.path === 'package.json')!.after).dependencies['@atlasauth/pca-control-plane']).toBe('^0.5.0');
    expect(JSON.parse(plan.changes.find((c) => c.path === 'pca.init.json')!.after).connect).toBe(true);
    expect(plan.changes.find((c) => c.path === '.gitignore')!.after).toContain('.pca/connect.json');
    const dry = await runInit(['--connect', TOKEN], { cwd: root, deps: fakeDeps({ repo: false }) });
    expect(dry.text).not.toContain(TOKEN);
    expect(existsSync(join(root, '.pca/source.key'))).toBe(false);
  });

  it('registers the public half only, stores the ingest key at 0600, and never writes the token', async () => {
    const root = mk('express-ts');
    const f = okFetch();
    const r = await runInit(['--yes', '--connect', TOKEN, '--connect-url', 'https://cp.example.com/'], { cwd: root, deps: fakeDeps({ repo: false }, f as never) });
    expect(r.ok).toBe(true);
    expect(f).toHaveBeenCalledTimes(1);
    const [url, init] = f.mock.calls[0] as unknown as [string, { method: string; body: string; headers: Record<string, string> }];
    expect(url).toBe('https://cp.example.com/v1/pca/control/connect');
    const sent = JSON.parse(init.body) as Record<string, string>;
    expect(sent.token).toBe(TOKEN);
    expect(sent.public_key).toBe(rd(root, '.pca/source.key.pub').trim());
    expect(sent.public_key).not.toBe(rd(root, '.pca/dev.key.pub').trim());
    expect(init.body).not.toContain(rd(root, '.pca/source.key').trim());
    expect(init.headers.authorization).toBeUndefined();
    const conn = JSON.parse(rd(root, '.pca/connect.json')) as Record<string, string>;
    expect(conn).toMatchObject({ url: 'https://cp.example.com', ingestKey: 'sk_test_ingest' });
    if (process.platform !== 'win32') expect(statSync(join(root, '.pca/connect.json')).mode & 0o777).toBe(0o600);
    expect(JSON.stringify(readAll(root))).not.toContain(TOKEN);
    expect(r.text).not.toContain(TOKEN);
    // a second run is idempotent and does not spend another token
    const again = await runInit(['--yes', '--connect', TOKEN, '--connect-url', 'https://cp.example.com'], { cwd: root, deps: fakeDeps({ repo: false }, f as never) });
    expect(again.text).toContain('Already connected');
    expect(f).toHaveBeenCalledTimes(1);
  });

  it('a refused token is a failure that does not echo the token, and leaves no connect file', async () => {
    const root = mk('express-ts');
    const f = vi.fn(async () => new Response(`token ${TOKEN} already used`, { status: 410 }));
    const r = await runInit(['--yes', '--connect', TOKEN], { cwd: root, deps: fakeDeps({ repo: false }, f as never) });
    expect(r.ok).toBe(false);
    expect(r.text).toContain('(410)');
    expect(r.text).not.toContain(TOKEN);
    expect(existsSync(join(root, '.pca/connect.json'))).toBe(false);
  });

  it('refuses plain http to a remote host, a malformed token, the proxy and non-JavaScript projects', async () => {
    const root = mk('express-ts');
    const f = okFetch();
    expect((await runInit(['--yes', '--connect', TOKEN, '--connect-url', 'http://evil.example.com'], { cwd: root, deps: fakeDeps({ repo: false }, f as never) })).text).toContain('must be https');
    expect(f).not.toHaveBeenCalled();
    expect((await runInit(['--connect', 'short'], { cwd: mk('express-ts'), deps: fakeDeps({ repo: false }) })).text).toContain('does not look like a setup token');
    expect((await runInit(['--proxy', '--connect', TOKEN], { cwd: mk('mcp-only'), deps: fakeDeps({ repo: false }) })).text).toContain('--connect reports from the generated wiring');
    expect((await runInit(['--connect', TOKEN], { cwd: mk('fastapi'), deps: fakeDeps({ repo: false }) })).text).toContain('needs the JavaScript/TypeScript wiring');
  });

  it('refuses when the source key path is tracked', async () => {
    const plan = await makePlan(opts(mk('express-ts'), { connect: TOKEN }), fakeDeps({ tracked: ['.pca/source.key'] }));
    expect(plan.blockers.join('\n')).toContain('.pca/source.key is tracked');
  });

  it('the generated reporter signs a batch of redacted events with the source key and posts it', async () => {
    vi.useFakeTimers();
    const root = mk('fastify-js');
    const deps = fakeDeps({ repo: false });
    applyPlan(await makePlan(opts(root, { connect: TOKEN }), deps), deps, { force: false });
    mkdirSync(join(root, '.pca'), { recursive: true });
    writeFileSync(join(root, '.pca/connect.json'), JSON.stringify({ url: 'https://cp.example.com', source: 'src-1', ingestKey: 'sk_x' }));
    const posts: { url: string; init: { headers: Record<string, string>; body: string } }[] = [];
    const signed: unknown[] = [];
    const g = (async (url: string, init: never) => (posts.push({ url, init }), { status: 202 })) as unknown as typeof fetch;
    const hooks = (() => {
      const code = rd(root, 'pca.setup.js');
      const h: Record<string, ((...a: never[]) => unknown)[]> = {};
      const stubs: Record<string, unknown> = {
        'node:fs': nodeFs, 'node:path': nodePath, 'node:crypto': nodeCrypto,
        '@atlasauth/pca': { protect: () => ({ options: {} }), unb64u: (s: string) => ({ secret: s }) },
        '@atlasauth/pca-fastify': { pcaFastify: () => undefined },
        '@atlasauth/pca-proxy': { matchRoute, templateOf },
        '@atlasauth/pca-control-plane': { signIngest: (secret: unknown, claim: unknown) => (signed.push({ secret, claim }), { v: 1, ...(claim as object), sig: 'S' }) },
      };
      const mod = { exports: {} as { registerPca: (a: unknown) => void } };
      new Function('require', 'module', 'process', 'fetch', code)((n: string) => stubs[n], mod, { env: { PCA_DIR: root, PCA_MODE: 'observe' }, cwd: () => root }, g);
      mod.exports.registerPca({ addHook: (n: string, fn: never) => (h[n] ??= []).push(fn) });
      return h;
    })();
    await (hooks.onResponse![0] as unknown as (a: unknown, b: unknown) => Promise<void>)({ method: 'GET', url: '/ping', body: { amount: 9, note: 'private' } }, { statusCode: 200 });
    await vi.advanceTimersByTimeAsync(5000);
    expect(posts).toHaveLength(1);
    expect(posts[0]!.url).toBe('https://cp.example.com/v1/pca/control/events');
    expect(posts[0]!.init.headers.authorization).toBe('Bearer sk_x');
    const claim = (signed[0] as { claim: { source: string; events: Record<string, unknown>[] } }).claim;
    expect(claim.source).toBe('src-1');
    expect(claim.events).toHaveLength(1);
    expect(claim.events[0]).toMatchObject({ resource: '/ping', outcome: 'auto', mode: 'observe', agent: 'fast_js' });
    expect(JSON.stringify(claim)).not.toMatch(/private|amount/);
  });
});

function readAll(root: string): string[] {
  return ['pca.init.json', '.gitignore', '.pca/connect.json', 'src/pca.setup.ts', 'package.json'].filter((f) => existsSync(join(root, f))).map((f) => rd(root, f));
}
