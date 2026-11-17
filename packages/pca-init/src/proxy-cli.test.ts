import { chmodSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse } from 'yaml';
import { afterEach, describe, expect, it } from 'vitest';
import { parseConfigText } from '@atlasauth/pca-proxy';
import { checkInit } from './check';
import { INIT_USAGE, parseInitArgs, runInit } from './cli';
import { routesOf, routesToOpenApi } from './imports';
import { detectDir } from './detect';
import { FIXTURES, fakeDeps, materialize } from './test-support/fixtures';

const dirs: string[] = [];
const mk = (name: string, extra: Record<string, string> = {}): string => {
  const d = materialize({ ...FIXTURES[name]!, ...extra });
  dirs.push(d);
  return d;
};
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
const rd = (root: string, rel: string): string => readFileSync(join(root, rel), 'utf8');
const deps = fakeDeps({ repo: false });

describe('pca init --proxy', () => {
  it('writes one pca-proxy config per MCP server, valid for the proxy, in observe mode', async () => {
    const root = mk('mcp-only');
    const r = await runInit(['--proxy', '--yes'], { cwd: root, deps });
    expect(r.ok).toBe(true);
    for (const f of ['pca-proxy.github.yaml', 'pca-proxy.docs.yaml']) {
      const cfg = parseConfigText(rd(root, f), 'yaml');
      expect(cfg.mode).toBe('observe');
      expect(cfg.state.dir).toBe('.pca/proxy-state');
    }
    expect(parse(rd(root, 'pca-proxy.github.yaml')).mcp.upstream).toEqual({ command: 'npx', args: ['-y', '@modelcontextprotocol/server-github'] });
    expect(parse(rd(root, 'pca-proxy.docs.yaml')).mcp.upstream).toEqual({ url: 'https://mcp.example.com/mcp' });
    // an environment value is never copied into a file
    expect(rd(root, 'pca-proxy.github.yaml')).not.toContain('placeholder');
    expect(r.text).toContain('GITHUB_TOKEN');
    expect(r.text).toContain('PCA_PRINCIPAL_KEY="$(cat .pca/dev.key)" npx @atlasauth/pca-proxy mcp --config pca-proxy.github.yaml');
    expect(r.text).toContain('npx @atlasauth/pca-cli autopilot observe .pca/proxy-audit.jsonl');
    // no application code is touched
    expect(rd(root, 'package.json')).toBe(FIXTURES['mcp-only']!['package.json']);
    expect(rd(root, '.gitignore')).toContain('.pca/proxy-state/');
  });

  it('--server picks one; an unknown name is refused', async () => {
    const root = mk('mcp-only');
    const r = await runInit(['--proxy', '--server=github', '--yes'], { cwd: root, deps });
    expect(r.ok).toBe(true);
    expect(rd(root, 'pca-proxy.yaml')).toContain('server-github');
    const bad = await runInit(['--proxy', '--server', 'nope'], { cwd: mk('mcp-only'), deps });
    expect(bad).toMatchObject({ ok: false });
    expect(bad.text).toContain('found: github, docs');
  });

  it('puts an HTTP service behind the proxy from its OpenAPI file', async () => {
    const root = mk('openapi-express');
    const r = await runInit(['--proxy', '--yes'], { cwd: root, deps });
    expect(r.ok).toBe(true);
    const cfg = parseConfigText(rd(root, 'pca-proxy.yaml'), 'yaml');
    expect(cfg.http).toMatchObject({ upstream: 'http://127.0.0.1:3000', mode: 'sidecar', openapi: 'openapi.json' });
    expect(r.text).toContain('npx @atlasauth/pca-proxy http --config pca-proxy.yaml');
  });

  it('puts an HTTP service behind the proxy from routes, every route starting as approve', async () => {
    const root = mk('express-ts');
    expect((await runInit(['--proxy', '--yes'], { cwd: root, deps })).ok).toBe(true);
    const cfg = parseConfigText(rd(root, 'pca-proxy.yaml'), 'yaml');
    expect(cfg.http!.routes.map((x) => [x.method, x.path, x.policy, x.effect])).toEqual([['GET', '/orders', 'approve', 'read'], ['POST', '/orders/{id}/refund', 'approve', 'write']]);
  });

  it('refuses when there is nothing to put the proxy in front of', async () => {
    const r = await runInit(['--proxy'], { cwd: mk('fastify-js', { 'index.js': 'const fastify = require("fastify"); fastify();\n' }), deps });
    expect(r.ok).toBe(false);
    expect(r.text).toContain('no MCP server definition');
  });
});

describe('arguments and dry run', () => {
  it('without --yes it is a dry run and writes nothing', async () => {
    const root = mk('express-ts');
    const r = await runInit([], { cwd: root, deps });
    expect(r.ok).toBe(true);
    expect(r.text).toContain('Dry run: nothing was written');
    expect(r.text).toContain('+++ src/pca.setup.ts');
    expect(r.text).toContain('--- src/server.ts');
    expect(r.text).toContain('+ registerPca(app);');
    expect(() => rd(root, 'pca.init.json')).toThrow();
    // --dry-run wins over --yes
    expect((await runInit(['--yes', '--dry-run'], { cwd: root, deps })).text).toContain('Dry run');
    expect(() => rd(root, 'pca.init.json')).toThrow();
  });

  it('a dry run reports a tracked key as a failure', async () => {
    const r = await runInit([], { cwd: mk('express-ts'), deps: fakeDeps({ tracked: ['.pca/dev.key'] }) });
    expect(r.ok).toBe(false);
    expect(r.text).toContain('Cannot be applied');
  });

  it('prints a numbered what-next with the commands for this project', async () => {
    const r = await runInit(['--yes'], { cwd: mk('express-ts'), deps });
    expect(r.text).toMatch(/What next:\n {2}1\. Install, then run your app: npm run dev/);
    expect(r.text).toContain('npx @atlasauth/pca-cli autopilot observe .pca/observed.jsonl');
    expect(r.text).toContain('autopilot propose autopilot.traces.json');
    expect(r.text).toContain('autopilot review autopilot.proposal.json autopilot.report.json --reviewer-key=@.pca/dev.key');
    expect(r.text).toContain('init --mode enforce');
  });

  it('parses flags', () => {
    expect(parseInitArgs(['--yes', '--app=services/api', '--mode', 'enforce', '--no-import'], '/x')).toMatchObject({ yes: true, app: 'services/api', mode: 'enforce', noImport: true });
    expect(parseInitArgs(['--mode', 'loud'], '/x')).toBe('--mode must be observe or enforce');
    expect(parseInitArgs(['--wat'], '/x')).toBe("unknown option '--wat'");
    expect(parseInitArgs(['--app'], '/x')).toBe('--app needs a value');
    expect(parseInitArgs(['--yes=1'], '/x')).toBe('--yes takes no value');
    expect(parseInitArgs(['--help'], '/x')).toBe(INIT_USAGE);
  });
});

describe('pca init --check', () => {
  it('fails before init, and passes (with an observe warning) after', async () => {
    const root = mk('express-ts');
    const before = await checkInit({ cwd: root, proxy: false, yes: false, dryRun: false, force: false, check: true, noImport: false }, deps);
    expect(before.ok).toBe(false);
    expect(before.text).toContain('not found: PCA has not been initialized');
    await runInit(['--yes'], { cwd: root, deps });
    const after = await runInit(['--check'], { cwd: root, deps });
    expect(after.ok).toBe(true);
    expect(after.text).toContain('[pass] package');
    expect(after.text).toContain('[pass] registered');
    expect(after.text).toContain('[warn] mode');
    expect(after.text).toContain('[pass] keys.tracked');
  });

  it('fails when the registration is removed, the dependency is dropped, or the key is tracked', async () => {
    const root = mk('express-ts');
    await runInit(['--yes'], { cwd: root, deps });
    const src = rd(root, 'src/server.ts');
    writeFileSync(join(root, 'src/server.ts'), src.replace('registerPca(app);\n', ''));
    expect((await runInit(['--check'], { cwd: root, deps })).text).toContain('[fail] registered');
    writeFileSync(join(root, 'src/server.ts'), src);
    const pkg = JSON.parse(rd(root, 'package.json'));
    delete pkg.dependencies['@atlasauth/pca-express'];
    writeFileSync(join(root, 'package.json'), JSON.stringify(pkg));
    expect((await runInit(['--check'], { cwd: root, deps })).text).toContain('[fail] package: @atlasauth/pca-express missing');
    const tracked = await runInit(['--check'], { cwd: root, deps: fakeDeps({ tracked: ['.pca/dev.key'] }) });
    expect(tracked.ok).toBe(false);
    expect(tracked.text).toContain('[fail] keys.tracked');
  });

  it('warns about a key readable by other users and fails on enforce without a grant', async () => {
    const root = mk('express-ts');
    await runInit(['--yes'], { cwd: root, deps });
    if (process.platform !== 'win32') {
      chmodSync(join(root, '.pca/dev.key'), 0o644);
      expect((await runInit(['--check'], { cwd: root, deps })).text).toContain('[warn] keys.permissions');
    }
    writeFileSync(join(root, 'pca.init.json'), rd(root, 'pca.init.json').replace('"observe"', '"enforce"'));
    const r = await runInit(['--check'], { cwd: root, deps });
    expect(r.ok).toBe(false);
    expect(r.text).toContain('[fail] grant: autopilot.grant.json is missing');
  });

  it('checks the proxy configs of a proxy setup', async () => {
    const root = mk('mcp-only');
    await runInit(['--proxy', '--yes'], { cwd: root, deps });
    expect((await runInit(['--check'], { cwd: root, deps })).text).toContain('[pass] proxy.pca-proxy.github.yaml');
    writeFileSync(join(root, 'pca-proxy.github.yaml'), 'mode: nope\n');
    const r = await runInit(['--check'], { cwd: root, deps });
    expect(r.ok).toBe(false);
    expect(r.text).toContain('[fail] proxy.pca-proxy.github.yaml');
  });

  it('checks a non-JavaScript project for the package and the guard', async () => {
    const root = mk('fastapi');
    await runInit(['--yes', '--no-import'], { cwd: root, deps });
    expect((await runInit(['--check'], { cwd: root, deps })).text).toContain('[fail] package');
    writeFileSync(join(root, 'pyproject.toml'), rd(root, 'pyproject.toml') + 'x = ["atlas-pca"]\n');
    writeFileSync(join(root, 'main.py'), 'from atlas_pca import protect\n' + rd(root, 'main.py'));
    const r = await runInit(['--check'], { cwd: root, deps });
    expect(r.text).toContain('[pass] package');
    expect(r.text).toContain('[pass] registered');
  });
});

describe('route tables', () => {
  const d = (name: string) => {
    const root = mk(name);
    return detectDir(root)!;
  };
  it('reads express, FastAPI, Flask, gin, Sinatra and Next route files', () => {
    expect(routesOf(d('express-ts')).map((r) => `${r.method} ${r.path}`)).toEqual(['get /orders', 'post /orders/{id}/refund']);
    expect(routesOf(d('fastapi')).map((r) => `${r.method} ${r.path}`)).toEqual(['get /items/{item_id}', 'post /items']);
    expect(routesOf(d('flask')).map((r) => `${r.method} ${r.path}`)).toEqual(['get /hello', 'post /hello']);
    expect(routesOf(d('go-gin')).map((r) => `${r.method} ${r.path}`)).toEqual(['get /orders/{id}']);
    expect(routesOf(d('sinatra')).map((r) => `${r.method} ${r.path}`)).toEqual(['get /ping']);
    expect(routesOf(d('next-ts')).map((r) => `${r.method} ${r.path}`).sort()).toEqual(['delete /api/orders/{id}', 'get /api/orders/{id}']);
  });
  it('skips wildcard and regex routes, and builds a document with an operationId per route', () => {
    const doc = routesToOpenApi('shop', [{ method: 'get', path: '/a/{id}' }]) as { paths: Record<string, Record<string, { operationId: string; parameters: unknown[] }>> };
    expect(doc.paths['/a/{id}']!.get).toMatchObject({ operationId: 'get_a_id', parameters: [{ name: 'id', in: 'path', required: true }] });
    const root = mk('express-ts', { 'src/server.ts': `const app = express();\napp.get('/files/*', h);\napp.get(/^\\/x/, h);\napp.get('/ok', h);\n` });
    expect(routesOf(detectDir(root)!).map((r) => r.path)).toEqual(['/ok']);
  });
});
