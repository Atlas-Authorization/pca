import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

/**
 * The `mcp` template authorizes every tool call with `authorizeToolCall` (admission + binding to the exact call + the
 * full verifier, tested in @atlasauth/pca-mcp-rs) and its agent builds per-call proofs with `pcaFetch` (tested in
 * @atlasauth/pca-mcp). The template's `npm run demo` runs the whole loop and exits nonzero on an unexpected outcome.
 */
const src = (f: string) =>
  readFileSync(new URL(`../templates/mcp/src/${f}`, import.meta.url), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '');

describe('create-pca-app mcp template', () => {
  it('the server authorizes with authorizeToolCall against its own grant store, never the low-level checks', () => {
    const server = src('server.ts');
    expect(server).toMatch(/authorizeToolCall\(/);
    expect(server).toMatch(/resolveGrant: \(ref\) => grants\.get\(ref\)/);
    expect(server).toMatch(/isRevoked:/);
    expect(server).toMatch(/toolAction,/);
    expect(server).not.toMatch(/authorizeRequest|verifyPCActnCore|cap_chain\[0\]/);
  });

  it('the agent builds per-call proofs with pcaFetch and the shared toolAction mapping', () => {
    const agent = src('agent.ts');
    expect(agent).toMatch(/pcaFetch\(a, toolAction\)/);
    expect(agent).toMatch(/expect: 'allowed'[\s\S]*expect: 'allowed'/); // two allowed calls: the budget is not drained by the first
  });

  it('declares the packages it imports', () => {
    const pkg = JSON.parse(readFileSync(new URL('../templates/mcp/package.json', import.meta.url), 'utf8')) as { dependencies: Record<string, string> };
    for (const d of ['@atlasauth/pca', '@atlasauth/pca-mcp', '@atlasauth/pca-mcp-rs', '@modelcontextprotocol/sdk', 'express', 'zod']) expect(pkg.dependencies[d], d).toBeTruthy();
  });
});
