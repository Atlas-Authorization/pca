import { rmSync } from 'node:fs';
import { afterEach, describe, expect, it } from 'vitest';
import { AppChoiceError, detectDir, findApp } from './detect';
import { FIXTURES, materialize } from './test-support/fixtures';

const dirs: string[] = [];
const mk = (name: string): string => {
  const d = materialize(FIXTURES[name]!);
  dirs.push(d);
  return d;
};
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe('detection per framework', () => {
  const table: [string, string, string | null][] = [
    ['express-ts', 'js', 'express'],
    ['fastify-js', 'js', 'fastify'],
    ['hono-esm', 'js', 'hono'],
    ['next-ts', 'js', 'next'],
    ['nest-ts', 'js', 'nest'],
    ['fastapi', 'python', 'fastapi'],
    ['flask', 'python', 'flask'],
    ['django', 'python', 'django'],
    ['rails', 'ruby', 'rails'],
    ['sinatra', 'ruby', 'sinatra'],
    ['go-gin', 'go', 'gin'],
    ['go-http', 'go', 'net/http'],
    ['spring', 'java', 'spring-boot'],
    ['aspnet', 'dotnet', 'aspnetcore'],
    ['laravel', 'php', 'laravel'],
    ['symfony', 'php', 'symfony'],
    ['axum', 'rust', 'axum'],
    ['vapor', 'swift', 'vapor'],
  ];
  it.each(table)('%s is %s/%s', (name, language, framework) => {
    const d = detectDir(mk(name))!;
    expect(d.language).toBe(language);
    expect(d.framework).toBe(framework);
  });

  it('reads TypeScript, ESM, package manager and the namespace', () => {
    const d = detectDir(mk('express-ts'))!;
    expect([d.typescript, d.esm, d.packageManager, d.ns]).toEqual([true, false, 'npm', 'shop_api']);
    expect(detectDir(mk('hono-esm'))!.esm).toBe(true);
  });

  it('finds agent frameworks and MCP SDKs', () => {
    expect(detectDir(mk('express-ts'))!.agents).toEqual(['Anthropic SDK']);
    expect(detectDir(mk('fastify-js'))!.agents).toEqual(['LangChain']);
    expect(detectDir(mk('hono-esm'))!.agents).toEqual(['Vercel AI SDK']);
    expect(detectDir(mk('next-ts'))!.agents).toEqual(['MCP SDK']);
    expect(detectDir(mk('fastapi'))!.agents).toEqual(['LangChain']);
  });

  it('reads MCP server definitions without copying environment values', () => {
    const d = detectDir(mk('mcp-only'))!;
    expect(d.framework).toBeNull();
    expect(d.mcpServers.map((s) => s.name)).toEqual(['github', 'docs']);
    expect(d.mcpServers[0]).toMatchObject({ command: 'npx', envNames: ['GITHUB_TOKEN'] });
    expect(JSON.stringify(d.mcpServers)).not.toContain('placeholder');
    expect(d.mcpServers[1]).toMatchObject({ url: 'https://mcp.example.com/mcp' });
  });

  it('finds an OpenAPI file', () => {
    expect(detectDir(mk('openapi-express'))!.openapi).toBe('openapi.json');
  });

  it('is null where there is no manifest', () => {
    expect(detectDir(materialize({ 'README.md': 'x' }))).toBeNull();
  });
});

describe('choosing the app', () => {
  it('a monorepo with several apps asks which one', () => {
    const root = mk('monorepo');
    expect(() => findApp(root)).toThrow(AppChoiceError);
    expect(() => findApp(root)).toThrow(/--app services\/api[\s\S]*--app services\/web/);
  });
  it('--app picks one, and a bad --app is refused', () => {
    const root = mk('monorepo');
    expect(findApp(root, 'services/api').framework).toBe('express');
    expect(() => findApp(root, 'apps/nope')).toThrow(/no supported project/);
  });
  it('a single app anywhere below the root is found', () => {
    const root = materialize({ 'services/billing/package.json': '{"name":"b","dependencies":{"express":"4"}}', 'services/billing/index.js': 'x' });
    dirs.push(root);
    expect(findApp(root).dir).toMatch(/services\/billing$/);
  });
  it('a folder with nothing supported says what it looked for', () => {
    const root = materialize({ 'notes.txt': 'x' });
    dirs.push(root);
    expect(() => findApp(root)).toThrow(/no supported project/);
  });
});
