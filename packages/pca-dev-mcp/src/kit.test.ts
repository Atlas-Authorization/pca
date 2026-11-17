import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { project } from './test-support/fixture';
import { MARKER, formatInstall, installKit, mcpSnippets, recipe } from './kit';

const read = (root: string, p: string): string => readFileSync(join(root, p), 'utf8');

describe('installKit', () => {
  it('writes the file for each harness it detects, and only those', () => {
    const root = project({ '.cursor/mcp.json': '{}', 'CLAUDE.md': '# x' });
    const r = installKit(root);
    expect(r.detected.sort()).toEqual(['claude', 'cursor']);
    expect(r.files.map((f) => `${f.action} ${f.path}`).sort()).toEqual(['created .claude/skills/pca/SKILL.md', 'created .cursor/rules/pca.mdc']);
    expect(existsSync(join(root, 'AGENTS.md'))).toBe(false);
  });
  it('the Claude Code skill has a name, trigger phrasing and the recipe', () => {
    const root = project({ '.claude/settings.json': '{}' });
    installKit(root);
    const t = read(root, '.claude/skills/pca/SKILL.md');
    expect(t.startsWith('---\nname: pca\ndescription: ')).toBe(true);
    for (const phrase of ['add PCA', 'agent authorization', 'protect this MCP server']) expect(t.split('---')[1]).toContain(phrase);
    expect(t).toContain('Default deny');
    expect(t).toContain(MARKER);
  });
  it('--all writes every harness format with the right frontmatter', () => {
    const root = project({});
    const r = installKit(root, { all: true });
    expect(r.files).toHaveLength(6);
    expect(read(root, '.cursor/rules/pca.mdc')).toMatch(/^---\ndescription: .*\nglobs:\nalwaysApply: false\n---\n/);
    expect(read(root, '.windsurf/rules/pca.md')).toMatch(/^---\ntrigger: model_decision\ndescription: /);
    expect(read(root, '.clinerules/pca.md').startsWith(MARKER)).toBe(true);
    expect(read(root, 'AGENTS.md')).toContain('<!-- pca-agent-kit:start -->');
    expect(read(root, 'GEMINI.md')).toContain('<!-- pca-agent-kit:end -->');
  });
  it('with nothing detected it writes AGENTS.md, which most agents read', () => {
    const root = project({ 'package.json': '{}' });
    const r = installKit(root);
    expect(r.harnesses).toEqual(['codex']);
    expect(read(root, 'AGENTS.md')).toContain('Adding PCA');
    expect(formatInstall(r)).toContain('no coding-agent configuration detected');
  });
  it('keeps what is already in AGENTS.md, and a second run changes nothing', () => {
    const root = project({ 'AGENTS.md': '# Our rules\n\nUse tabs.\n' });
    installKit(root);
    const once = read(root, 'AGENTS.md');
    expect(once.startsWith('# Our rules\n\nUse tabs.\n')).toBe(true);
    expect(once).toContain('Adding PCA');
    const r2 = installKit(root);
    expect(r2.files[0]!.action).toBe('unchanged');
    expect(read(root, 'AGENTS.md')).toBe(once);
  });
  it('replaces only its own block when the recipe changes', () => {
    const root = project({ 'AGENTS.md': 'before\n\n<!-- pca-agent-kit:start -->\nOLD\n<!-- pca-agent-kit:end -->\n\nafter\n' });
    const r = installKit(root);
    expect(r.files[0]!.action).toBe('updated');
    const t = read(root, 'AGENTS.md');
    expect(t).not.toContain('OLD');
    expect(t.startsWith('before\n\n')).toBe(true);
    expect(t.endsWith('\n\nafter\n')).toBe(true);
  });
  it('never overwrites a rule file it did not write', () => {
    const root = project({ '.cursor/rules/pca.mdc': 'my own rule' });
    const r = installKit(root, { harnesses: ['cursor'] });
    expect(r.files[0]).toMatchObject({ action: 'skipped' });
    expect(read(root, '.cursor/rules/pca.mdc')).toBe('my own rule');
  });
  it('dry run writes nothing; an unknown harness is an error', () => {
    const root = project({});
    expect(installKit(root, { all: true, dryRun: true }).files.every((f) => f.action === 'created')).toBe(true);
    expect(existsSync(join(root, 'AGENTS.md'))).toBe(false);
    expect(() => installKit(root, { harnesses: ['vim' as never] })).toThrow(/unknown harness/);
  });
  it('prints an MCP config snippet for each chosen harness', () => {
    const r = installKit(project({}), { harnesses: ['claude', 'codex'], dryRun: true });
    expect(r.snippets.map((s) => s.harness)).toEqual(['claude', 'codex']);
    expect(formatInstall(r)).toContain('claude mcp add pca -- npx -y @atlasauth/pca-dev-mcp');
    expect(formatInstall(r)).toContain('[mcp_servers.pca]');
    expect(mcpSnippets().every((s) => s.text.includes('@atlasauth/pca-dev-mcp'))).toBe(true);
  });
});

describe('the recipe', () => {
  it('states the security rules and no secrets', () => {
    const t = recipe();
    for (const s of ['Default deny', 'Observe first', 'Never disable', 'Keys are never committed']) expect(t).toContain(s);
    expect(t).not.toMatch(/BEGIN [A-Z ]*PRIVATE KEY|sk_live|ghp_/);
  });
});
