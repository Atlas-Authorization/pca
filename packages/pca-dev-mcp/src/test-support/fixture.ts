/** Test support: build a throwaway project directory from a { path: content } map. */
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

export function project(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'pca-dev-mcp-'));
  for (const [p, c] of Object.entries(files)) {
    mkdirSync(dirname(join(root, p)), { recursive: true });
    writeFileSync(join(root, p), c);
  }
  return root;
}

export const MCP_TS = { 'package.json': JSON.stringify({ name: 'weather-mcp', dependencies: { '@modelcontextprotocol/sdk': '^1.0.0' }, devDependencies: { typescript: '^5' } }), 'tsconfig.json': '{}', 'pnpm-lock.yaml': '', '.mcp.json': JSON.stringify({ mcpServers: { notes: { command: 'node', args: ['server.js'] } } }) };
export const EXPRESS_OPENAPI = { 'package.json': JSON.stringify({ name: 'orders', dependencies: { express: '^5' } }), 'openapi.yaml': 'openapi: 3.0.3\ninfo: { title: orders, version: "1" }\npaths: {}\n' };
export const FASTAPI = { 'requirements.txt': 'fastapi==0.115\nuvicorn\n' };
export const GIN = { 'go.mod': 'module example.com/svc\n\nrequire github.com/gin-gonic/gin v1.10.0\n' };
export const AGENT_ONLY = { 'package.json': JSON.stringify({ name: 'bot', dependencies: { '@anthropic-ai/sdk': '^0.30' } }) };
export const WITH_PCA = { 'package.json': JSON.stringify({ name: 'x', dependencies: { express: '^5', '@atlasauth/pca': '^0.5.0' } }) };

/** pca-init's dependencies without git or real key generation: a repository is not assumed, and the key is a fixed test value. */
export const fakeInitDeps = { git: () => ({ code: 1, out: '' }), newKey: () => ({ secret: 'c2VjcmV0LXNlZWQtMzItYnl0ZXMtbG9uZy1leGFjdGx5', publicKey: 'cHVibGljLWtleS1mb3ItdGVzdHM' }) };
