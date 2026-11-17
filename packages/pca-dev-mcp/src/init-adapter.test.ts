import { describe, expect, it } from 'vitest';
import { fromInitDetection, initInspector } from './init-adapter';
import { fromInitPlan } from './plan';
import { fsInspector, recommend } from './detect';
import { EXPRESS_OPENAPI, MCP_TS, project } from './test-support/fixture';
import type { Plan as InitPlan } from '@atlasauth/pca-init';

const base = (root: string) => fsInspector.detect(root);

describe('initInspector: detection comes from pca init', () => {
  it('golden: an Express API with OpenAPI', async () => {
    const d = await initInspector.detect(project(EXPRESS_OPENAPI));
    expect(d).toMatchObject({ primaryLanguage: 'javascript', httpFrameworks: ['express'], openapi: ['openapi.yaml'], name: 'orders', recommendation: { integration: 'proxy-http' } });
  });
  it('golden: an MCP server', async () => {
    const d = await initInspector.detect(project(MCP_TS));
    expect(d).toMatchObject({ primaryLanguage: 'typescript', mcpServer: true, recommendation: { integration: 'proxy-mcp' } });
  });
  it('a monorepo is reported as ambiguous, not guessed', async () => {
    const d = await initInspector.detect(project({ 'a/package.json': JSON.stringify({ name: 'a', dependencies: { express: '1' } }), 'b/package.json': JSON.stringify({ name: 'b', dependencies: { hono: '1' } }) }));
    expect(d.ambiguous).toMatch(/more than one app/);
  });
  it('no supported project falls back to the file inspector (the proxy needs no code)', async () => {
    const d = await initInspector.detect(project({ 'README.md': 'x' }));
    expect(d.ambiguous).toBeUndefined();
    expect(d.recommendation.integration).toBe('proxy-http');
  });
  it('the recommendation is one function for every inspector', async () => {
    const b = (await base(project(EXPRESS_OPENAPI))) as never;
    const d = fromInitDetection(b, { dir: '/x', language: 'js', framework: null, packageManager: null, typescript: true, esm: false, agents: ['LangChain'], mcpServers: [], mcpTools: null, openapi: null, ns: 'x', port: 3000 });
    expect(d.recommendation).toEqual(recommend(d));
    expect(d.recommendation.integration).toBe('agent-side');
    expect(d.primaryLanguage).toBe('typescript');
  });
});

describe('fromInitPlan', () => {
  const plan: InitPlan = {
    detection: {} as never, proxy: true, mode: 'observe',
    changes: [
      { path: '.pca/dev.key', before: null, after: '', generated: 'secret', mode: 0o600, why: 'a local dev key' },
      { path: '.gitignore', before: 'node_modules\n', after: 'node_modules\n.pca/dev.key\n', why: 'keep keys out of git' },
      { path: 'pca-proxy.yaml', before: null, after: 'mode: observe\n', why: 'a proxy config' },
    ],
    install: ['npm install'], snippets: [{ title: 'Register', where: 'src/app.ts', code: 'registerPca(app);' }], notes: ['n1'], keyPath: '.pca/dev.key', blockers: [], dirty: false,
    nextSteps: ['Run the proxy:\n       npx @atlasauth/pca-proxy http --config pca-proxy.yaml', 'Review it and sign once: npx @atlasauth/pca-cli autopilot review ...'],
  };
  it('golden: every part of the init plan appears, in order, with the right kinds', () => {
    const r = fromInitPlan(plan, 'proxy-http', 'javascript');
    expect(r.steps.map((s) => `${s.id}|${s.kind}`)).toEqual(['apply|command', 'change:.pca/dev.key|create', 'change:.gitignore|edit', 'change:pca-proxy.yaml|create', 'install:0|command', 'snippet:0|edit', 'next:1|decision', 'next:2|decision']);
    expect(r.steps[0]?.command).toBe('npx @atlasauth/pca-cli init --proxy --yes');
    expect(r.notes).toEqual(['n1']);
  });
  it('the secret key has no content; an edit carries the digest of the file it was planned against; a create has none', () => {
    const r = fromInitPlan(plan, 'proxy-http', null);
    const by = (id: string) => r.steps.find((s) => s.id === id)!;
    expect(by('change:.pca/dev.key').content).toBeUndefined();
    expect(by('change:.gitignore').beforeDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(by('change:pca-proxy.yaml').beforeDigest).toBeUndefined();
  });
  it('signing and review steps are for the human', () => {
    const r = fromInitPlan(plan, 'proxy-http', null);
    expect(r.steps.find((s) => s.id === 'next:2')?.human).toBe(true);
    expect(r.steps.find((s) => s.id === 'next:1')?.human).toBeUndefined();
  });
  it('blockers, dirtiness and enforce mode pass through', () => {
    const r = fromInitPlan({ ...plan, blockers: ['b'], dirty: true, mode: 'enforce', proxy: false }, 'sdk-guard', null);
    expect(r).toMatchObject({ blockers: ['b'], dirty: true, mode: 'enforce' });
    expect(r.steps[0]?.command).toBe('npx @atlasauth/pca-cli init --mode enforce --yes');
  });
});
