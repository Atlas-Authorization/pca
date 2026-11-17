import { describe, expect, it } from 'vitest';
import { fsInspector } from './detect';
import { AGENT_ONLY, EXPRESS_OPENAPI, FASTAPI, GIN, MCP_TS, WITH_PCA, project } from './test-support/fixture';

const d = (files: Record<string, string>) => fsInspector.detect(project(files)) as ReturnType<typeof fsInspector.detect>;

describe('fsInspector.detect', () => {
  it('an MCP server in TypeScript gets the no-code MCP proxy', async () => {
    const r = await d(MCP_TS);
    expect(r).toMatchObject({ primaryLanguage: 'typescript', mcpServer: true, packageManager: 'pnpm', pcaPresent: false });
    expect(r.recommendation.integration).toBe('proxy-mcp');
  });
  it('an Express API with an OpenAPI document gets the HTTP proxy and finds the document', async () => {
    const r = await d(EXPRESS_OPENAPI);
    expect(r).toMatchObject({ httpFrameworks: ['express'], openapi: ['openapi.yaml'], packageManager: 'npm' });
    expect(r.recommendation.integration).toBe('proxy-http');
  });
  it('an HTTP framework without OpenAPI gets the in-process guard (FastAPI, Gin)', async () => {
    expect(await d(FASTAPI)).toMatchObject({ primaryLanguage: 'python', httpFrameworks: ['fastapi'], recommendation: { integration: 'sdk-guard' } });
    expect(await d(GIN)).toMatchObject({ primaryLanguage: 'go', httpFrameworks: ['gin'], recommendation: { integration: 'sdk-guard' } });
  });
  it('agent code without a server is the agent side', async () => {
    expect((await d(AGENT_ONLY)).recommendation.integration).toBe('agent-side');
  });
  it('recognises PCA already present and the harnesses configured', async () => {
    const r = await d({ ...WITH_PCA, '.cursor/rules/x.mdc': '', 'CLAUDE.md': '# hi' });
    expect(r.pcaPresent).toBe(true);
    expect(r.pcaFiles).toEqual(['package.json']);
    expect(r.harnesses.sort()).toEqual(['claude', 'cursor']);
  });
  it('an empty directory falls back to the proxy and does not throw; a missing one does', async () => {
    expect((await d({ 'README.md': 'x' })).recommendation.integration).toBe('proxy-http');
    await expect(Promise.resolve().then(() => fsInspector.detect('/definitely/not/here'))).rejects.toThrow(/not a directory/);
  });
  it('does not look inside node_modules for OpenAPI documents', async () => {
    expect((await d({ 'node_modules/x/openapi.json': '{}', 'docs/api/openapi.json': '{}' })).openapi).toEqual(['docs/api/openapi.json']);
  });
});
