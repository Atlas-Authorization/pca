import { chmodSync, existsSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { applyPlan, renderPlan } from './apply';
import { InitError, makePlan, parseInitConfig } from './plan';
import { FIXTURES, fakeDeps, materialize } from './test-support/fixtures';
import type { InitOptions } from './types';

const dirs: string[] = [];
const mk = (name: string): string => {
  const d = materialize(FIXTURES[name]!);
  dirs.push(d);
  return d;
};
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
const opts = (cwd: string, o: Partial<InitOptions> = {}): InitOptions => ({ cwd, proxy: false, yes: true, dryRun: false, force: false, check: false, noImport: false, ...o });
const rd = (root: string, rel: string): string => readFileSync(join(root, rel), 'utf8');

describe('plan and apply: JavaScript and TypeScript', () => {
  it('express + TypeScript: wiring file, one import, one registration, dependency, observe config, gitignored key', async () => {
    const root = mk('express-ts');
    const deps = fakeDeps({ repo: false });
    const plan = await makePlan(opts(root), deps);
    expect(plan.detection).toMatchObject({ language: 'js', framework: 'express', typescript: true });
    expect(plan.mode).toBe('observe');
    expect(plan.changes.map((c) => c.path).sort()).toEqual(
      ['.gitignore', '.pca/dev.key', '.pca/dev.key.pub', 'actions/routes.yaml', 'package.json', 'pca.config.json', 'pca.init.json', 'pca.routes.json', 'src/pca.setup.ts', 'src/server.ts'].sort(),
    );
    expect(plan.install).toEqual(['npm install']);
    // a dry run touches nothing
    expect(existsSync(join(root, 'pca.init.json'))).toBe(false);

    expect(applyPlan(plan, deps, { force: false }).ok).toBe(true);
    const entry = rd(root, 'src/server.ts');
    expect(entry).toContain("import { registerPca } from './pca.setup';");
    expect(entry.match(/registerPca\(app\);/g)).toHaveLength(1);
    expect(entry.split('\n').length).toBe(FIXTURES['express-ts']!['src/server.ts']!.split('\n').length + 2);
    const pkg = JSON.parse(rd(root, 'package.json')) as { dependencies: Record<string, string> };
    expect(pkg.dependencies['@atlasauth/pca']).toBe('^0.5.0');
    expect(pkg.dependencies['@atlasauth/pca-express']).toBe('^0.5.0');
    expect(pkg.dependencies['@atlasauth/pca-proxy']).toBe('^0.5.0');
    expect(pkg.dependencies.express).toBe('^4.19.0');
    const init = parseInitConfig(rd(root, 'pca.init.json'));
    expect(init).toMatchObject({ mode: 'observe', via: 'sdk', ns: 'shop_api', wiring: 'src/pca.setup.ts' });
    const gi = rd(root, '.gitignore');
    expect(gi).toContain('.pca/dev.key\n');
    expect(gi).toContain('.pca/observed.jsonl');
    const wiring = rd(root, 'src/pca.setup.ts');
    expect(wiring).toContain("pcaExpress(options().options)");
    expect(wiring).toContain('if (status >= 400) return;');
    // the generated TypeScript parses
    expect(wiring).toContain('export function registerPca(app: any): void');
  });

  it('writes the key with mode 0600, never prints it, and never overwrites it', async () => {
    const root = mk('express-ts');
    const deps = fakeDeps({ repo: false });
    const plan = await makePlan(opts(root), deps);
    expect(renderPlan(plan)).not.toContain('c2VjcmV0');
    applyPlan(plan, deps, { force: false });
    const key = join(root, '.pca/dev.key');
    expect(rd(root, '.pca/dev.key').trim()).toBe('c2VjcmV0LXNlZWQtMzItYnl0ZXMtbG9uZy1leGFjdGx5');
    if (process.platform !== 'win32') expect(statSync(key).mode & 0o777).toBe(0o600);
    writeFileSync(key, 'mine\n');
    chmodSync(key, 0o600);
    const again = await makePlan(opts(root), deps);
    expect(again.changes.find((c) => c.path === '.pca/dev.key')).toBeUndefined();
    applyPlan(again, deps, { force: false });
    expect(rd(root, '.pca/dev.key')).toBe('mine\n');
  });

  it('is idempotent: a second run plans nothing and changes no file', async () => {
    const root = mk('express-ts');
    const deps = fakeDeps({ repo: false });
    applyPlan(await makePlan(opts(root), deps), deps, { force: false });
    const before = ['src/server.ts', 'src/pca.setup.ts', 'package.json', 'pca.init.json', '.gitignore'].map((f) => rd(root, f));
    const second = await makePlan(opts(root), deps);
    expect(second.changes).toEqual([]);
    expect(renderPlan(second)).toContain('Nothing to change');
    expect(['src/server.ts', 'src/pca.setup.ts', 'package.json', 'pca.init.json', '.gitignore'].map((f) => rd(root, f))).toEqual(before);
  });

  it('CommonJS fastify gets a require and a .js wiring file', async () => {
    const root = mk('fastify-js');
    const deps = fakeDeps({ repo: false });
    applyPlan(await makePlan(opts(root), deps), deps, { force: false });
    expect(rd(root, 'index.js')).toContain("const { registerPca } = require('./pca.setup');\nconst app = fastify();\nregisterPca(app);");
    const w = rd(root, 'pca.setup.js');
    expect(w).toContain("require('@atlasauth/pca-fastify')");
    expect(w).toContain('module.exports = { registerPca };');
    expect(w).not.toMatch(/^export /m);
  });

  it('hono in an ESM package imports with the .js extension', async () => {
    const root = mk('hono-esm');
    const deps = fakeDeps({ repo: false });
    applyPlan(await makePlan(opts(root), deps), deps, { force: false });
    expect(rd(root, 'server.js')).toContain("import { registerPca } from './pca.setup.js';");
    expect(rd(root, 'pca.setup.js')).toContain("import { pcaHono } from '@atlasauth/pca-hono';");
  });

  it('NestJS registers a global guard', async () => {
    const root = mk('nest-ts');
    const deps = fakeDeps({ repo: false });
    applyPlan(await makePlan(opts(root), deps), deps, { force: false });
    expect(rd(root, 'src/main.ts')).toContain('  app.useGlobalGuards(new PcaGuard());');
    expect(rd(root, 'src/pca.setup.ts')).toContain('export class PcaGuard');
  });

  it('Next.js prints the per-route wrapper instead of editing a route', async () => {
    const root = mk('next-ts');
    const plan = await makePlan(opts(root), fakeDeps({ repo: false }));
    expect(plan.changes.find((c) => c.path.endsWith('route.ts'))).toBeUndefined();
    expect(plan.snippets[0]!.code).toContain('withPca(');
    expect(plan.snippets[0]!.where).toContain('route.ts');
    expect(plan.changes.find((c) => c.path === 'actions/routes.yaml')!.after).toContain('/api/orders/{id}');
  });

  it('imports actions from an OpenAPI file and records the source', async () => {
    const root = mk('openapi-express');
    const plan = await makePlan(opts(root), fakeDeps({ repo: false }));
    const yaml = plan.changes.find((c) => c.path === 'actions/openapi.yaml')!;
    expect(yaml.after).toMatch(/invoices/i);
    const cfg = JSON.parse(plan.changes.find((c) => c.path === 'pca.config.json')!.after) as Record<string, unknown>;
    expect(cfg).toMatchObject({ ns: 'billing', stability: 'draft', sources: [{ name: 'openapi', from: 'openapi', file: 'openapi.json' }] });
  });

  it('does not overwrite an action file a reviewer may have confirmed', async () => {
    const root = mk('openapi-express');
    writeFileSync(join(root, 'pca.config.json'), '{"ns":"billing"}');
    const files = { ...FIXTURES['openapi-express']!, 'actions/openapi.yaml': 'confirmed: true\n' };
    const dir = materialize(files);
    dirs.push(dir);
    const plan = await makePlan(opts(dir), fakeDeps({ repo: false }));
    expect(plan.changes.find((c) => c.path === 'actions/openapi.yaml')).toBeUndefined();
    expect(plan.notes.join('\n')).toContain('already exists and was kept');
  });

  it('--no-import skips the action import', async () => {
    const plan = await makePlan(opts(mk('express-ts'), { noImport: true }), fakeDeps({ repo: false }));
    expect(plan.changes.find((c) => c.path.startsWith('actions/'))).toBeUndefined();
  });
});

describe('other languages print the snippet and the place', () => {
  const cases: [string, string, string, string][] = [
    ['fastapi', 'main.py:3', 'RequirePCA', 'pip install'],
    ['flask', 'app.py:2', 'PCAFlask', 'pip install'],
    ['django', 'config/settings.py:1', 'atlas_pca.django.PCAMiddleware', 'pip install'],
    ['rails', 'config/application.rb:2', 'config.middleware.use AtlasPca::RackMiddleware', 'bundle add atlas-pca'],
    ['sinatra', 'app.rb:1', 'use AtlasPca::RackMiddleware', 'bundle add atlas-pca'],
    ['go-http', 'main.go:6', 'p.Middleware()(next)', 'go get github.com/Atlas-Authorization/pca-go'],
    ['aspnet', 'Program.cs:2', 'app.UsePcaProtect(pca)', 'dotnet add package AtlasPca.AspNetCore'],
    ['laravel', 'routes/api.php:2', "Route::middleware(", 'composer require atlas-auth/atlas-pca'],
    ['axum', 'src/main.rs:2', 'p.layer()', 'cargo add atlas-pca --features axum'],
    ['vapor', 'Sources/App/configure.swift:1', 'app.middleware.use(try p.middleware())', 'AtlasPCAVapor'],
  ];
  it.each(cases)('%s', async (name, at, code, install) => {
    const root = mk(name);
    const deps = fakeDeps({ repo: false });
    const plan = await makePlan(opts(root, { noImport: true }), deps);
    expect(plan.snippets).toHaveLength(1);
    expect(plan.snippets[0]!.where).toContain(at);
    expect(plan.snippets[0]!.code).toContain(code);
    expect(plan.snippets[0]!.code).toContain('PCA_MODE');
    expect(plan.install.join('\n')).toContain(install);
    // no source file is edited
    const sources = plan.changes.map((c) => c.path).filter((p) => !['.gitignore', '.pca/dev.key', '.pca/dev.key.pub', 'pca.init.json'].includes(p));
    expect(sources).toEqual([]);
    expect(applyPlan(plan, deps, { force: false }).ok).toBe(true);
    expect(rd(root, FIXTURES[name] && Object.keys(FIXTURES[name]!)[0]!)).toBe(FIXTURES[name]![Object.keys(FIXTURES[name]!)[0]!]);
  });
});

describe('adversarial', () => {
  it('a monorepo asks which app, and --app scopes every path to it', async () => {
    const root = mk('monorepo');
    await expect(makePlan(opts(root), fakeDeps({ repo: false }))).rejects.toThrow(InitError);
    await expect(makePlan(opts(root), fakeDeps({ repo: false }))).rejects.toThrow(/--app services\/api/);
    const deps = fakeDeps({ repo: false });
    const plan = await makePlan(opts(root, { app: 'services/api' }), deps);
    expect(applyPlan(plan, deps, { force: false }).ok).toBe(true);
    expect(existsSync(join(root, 'services/api/pca.init.json'))).toBe(true);
    expect(existsSync(join(root, 'services/api/.pca/dev.key'))).toBe(true);
    expect(existsSync(join(root, 'pca.init.json'))).toBe(false);
    expect(existsSync(join(root, 'services/web/pca.init.json'))).toBe(false);
  });

  it('a dirty git tree is refused without --force, and nothing is written', async () => {
    const root = mk('express-ts');
    const deps = fakeDeps({ status: ' M src/server.ts\n' });
    const plan = await makePlan(opts(root), deps);
    expect(plan.dirty).toBe(true);
    const r = applyPlan(plan, deps, { force: false });
    expect(r.ok).toBe(false);
    expect(r.text).toContain('uncommitted changes');
    expect(existsSync(join(root, 'pca.init.json'))).toBe(false);
    expect(existsSync(join(root, '.pca/dev.key'))).toBe(false);
    expect(applyPlan(plan, deps, { force: true }).ok).toBe(true);
  });

  it('a tracked key path is refused even with --force, and no key is written', async () => {
    const root = mk('express-ts');
    const deps = fakeDeps({ tracked: ['.pca/dev.key'] });
    const plan = await makePlan(opts(root), deps);
    expect(plan.blockers.join('\n')).toContain('tracked by git');
    const r = applyPlan(plan, deps, { force: true });
    expect(r.ok).toBe(false);
    expect(existsSync(join(root, '.pca/dev.key'))).toBe(false);
    expect(existsSync(join(root, 'src/pca.setup.ts'))).toBe(false);
  });

  it('refuses to write the key when a .gitignore rule re-includes it', async () => {
    const root = mk('express-ts');
    const deps = fakeDeps({ ignores: false });
    const r = applyPlan(await makePlan(opts(root), deps), deps, { force: false });
    expect(r.ok).toBe(false);
    expect(r.text).toContain('does not ignore');
    expect(existsSync(join(root, '.pca/dev.key'))).toBe(false);
  });

  it('two apps in one project, or an entry that does not parse, fall back to the snippet', async () => {
    const two = materialize({ ...FIXTURES['express-ts']!, 'src/other.ts': `import express from 'express';\nconst second = express();\n` });
    dirs.push(two);
    const p1 = await makePlan(opts(two), fakeDeps({ repo: false }));
    expect(p1.changes.find((c) => c.path === 'src/server.ts')!.after).toContain('registerPca(app);');
    const same = materialize({ ...FIXTURES['express-ts']!, 'src/server.ts': `import express from 'express';\nconst a = express();\nconst b = express();\n` });
    dirs.push(same);
    const p2 = await makePlan(opts(same), fakeDeps({ repo: false }));
    expect(p2.changes.find((c) => c.path === 'src/server.ts')).toBeUndefined();
    expect(p2.snippets[0]!.title).toContain('more than one app');
    const bad = materialize({ ...FIXTURES['express-ts']!, 'src/server.ts': `import express from 'express'\nconst app = express(;\n` });
    dirs.push(bad);
    const p3 = await makePlan(opts(bad), fakeDeps({ repo: false }));
    expect(p3.changes.find((c) => c.path === 'src/server.ts')).toBeUndefined();
  });

  it('keeps a wiring file the user edited', async () => {
    const root = materialize({ ...FIXTURES['express-ts']!, 'src/pca.setup.ts': '// mine\nexport function registerPca(app: any) {}\n' });
    dirs.push(root);
    const plan = await makePlan(opts(root), fakeDeps({ repo: false }));
    expect(plan.changes.find((c) => c.path === 'src/pca.setup.ts')).toBeUndefined();
    expect(plan.notes.join('\n')).toContain('src/pca.setup.ts already exists and was kept');
  });

  it('enforce needs the signed grant; with it the mode switches and nothing else changes', async () => {
    const root = mk('express-ts');
    const deps = fakeDeps({ repo: false });
    applyPlan(await makePlan(opts(root), deps), deps, { force: false });
    const no = await makePlan(opts(root, { mode: 'enforce' }), deps);
    expect(no.blockers.join('\n')).toContain('autopilot.grant.json');
    expect(applyPlan(no, deps, { force: false }).ok).toBe(false);
    writeFileSync(join(root, 'autopilot.grant.json'), '{}');
    const yes = await makePlan(opts(root, { mode: 'enforce' }), deps);
    expect(yes.changes.map((c) => c.path)).toEqual(['pca.init.json']);
    applyPlan(yes, deps, { force: false });
    expect(parseInitConfig(rd(root, 'pca.init.json'))).toMatchObject({ mode: 'enforce' });
    // a later plain run keeps enforce
    expect((await makePlan(opts(root), deps)).mode).toBe('enforce');
  });

  it('refuses an invalid pca.init.json instead of overwriting it', async () => {
    const root = materialize({ ...FIXTURES['express-ts']!, 'pca.init.json': '{"version":2}' });
    dirs.push(root);
    await expect(makePlan(opts(root), fakeDeps({ repo: false }))).rejects.toThrow(/version must be 1/);
  });

  it('rejects a bad namespace and path-escaping config members', async () => {
    await expect(makePlan(opts(mk('express-ts'), { ns: 'Bad-Name' }), fakeDeps({ repo: false }))).rejects.toThrow(/--ns/);
    expect(parseInitConfig(JSON.stringify({ version: 1, mode: 'observe', via: 'sdk', ns: 'a', aud: 'a', language: 'js', framework: null, wiring: null, keyFile: '../../etc/key', observedLog: 'x', grantFile: 'y' }))).toContain('inside the project');
  });
});
