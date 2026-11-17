import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { cmdAgentKit } from './agent-kit';

const repo = (files: Record<string, string>): string => {
  const root = mkdtempSync(join(tmpdir(), 'pca-agent-kit-'));
  for (const [p, c] of Object.entries(files)) {
    mkdirSync(join(root, p, '..'), { recursive: true });
    writeFileSync(join(root, p), c);
  }
  return root;
};

describe('pca agent-kit install', () => {
  it('writes the files for the detected harnesses and prints their MCP config', () => {
    const root = repo({ '.cursor/mcp.json': '{}', 'CLAUDE.md': '#' });
    const r = cmdAgentKit('install', { root });
    expect(r.ok).toBe(true);
    expect(existsSync(join(root, '.claude/skills/pca/SKILL.md'))).toBe(true);
    expect(existsSync(join(root, '.cursor/rules/pca.mdc'))).toBe(true);
    expect(r.text).toContain('claude mcp add pca -- npx -y @atlasauth/pca-dev-mcp');
    expect(r.text).toContain('.cursor/mcp.json');
  });
  it('--harness and --all choose agents; --dry-run writes nothing', () => {
    const root = repo({});
    cmdAgentKit('install', { root, harness: 'windsurf,cline' });
    expect(existsSync(join(root, '.windsurf/rules/pca.md'))).toBe(true);
    expect(existsSync(join(root, '.clinerules/pca.md'))).toBe(true);
    expect(existsSync(join(root, 'GEMINI.md'))).toBe(false);
    const dry = repo({});
    const r = cmdAgentKit('install', { root: dry, all: true, dryRun: true });
    expect(r.text).toContain('dry run');
    expect(existsSync(join(dry, 'AGENTS.md'))).toBe(false);
  });
  it('a bad harness or sub-command fails, and a user-written rule file is not overwritten', () => {
    expect(cmdAgentKit('install', { root: repo({}), harness: 'vim' })).toMatchObject({ ok: false });
    expect(cmdAgentKit('remove', { root: repo({}) })).toMatchObject({ ok: false });
    const root = repo({ '.cursor/rules/pca.mdc': 'mine' });
    expect(cmdAgentKit('install', { root, harness: 'cursor' }).ok).toBe(false);
    expect(readFileSync(join(root, '.cursor/rules/pca.mdc'), 'utf8')).toBe('mine');
  });
});
