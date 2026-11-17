/**
 * The coding-agent kit: one recipe (kit/recipe.md), written in each harness's own format, plus the MCP config snippet for each.
 * `installKit` writes only files that are new, or that it wrote itself (they carry the marker), or its marked block inside a
 * shared file (AGENTS.md, GEMINI.md). It never overwrites a file it did not write.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { detectHarnesses, type Harness } from './detect';

export const HARNESSES: readonly Harness[] = ['claude', 'cursor', 'codex', 'windsurf', 'cline', 'gemini'];
export const MARKER = '<!-- pca-agent-kit -->';
const START = '<!-- pca-agent-kit:start -->';
const END = '<!-- pca-agent-kit:end -->';

const DESCRIPTION = 'Add PCA (Proof-Carrying Authority) agent authorization to a project, protect an MCP server or an API from AI agents, add per-action proofs, observe then enforce, explain a PCA refusal. Use when the user says "add PCA", "agent authorization", "protect this MCP server", "protect this API from agents", "PCA proxy", "pca-proxy", or pastes a PCA refusal.';

export function recipe(): string {
  return readFileSync(resolve(__dirname, '../kit/recipe.md'), 'utf8');
}

interface Target { path: string; render(body: string): string; shared?: boolean }
const TARGETS: Record<Harness, Target> = {
  // Claude Code skill: .claude/skills/<name>/SKILL.md
  claude: { path: '.claude/skills/pca/SKILL.md', render: (b) => `---\nname: pca\ndescription: ${DESCRIPTION}\n---\n${MARKER}\n\n${b}` },
  // Cursor project rule (.mdc): the model attaches it by description
  cursor: { path: '.cursor/rules/pca.mdc', render: (b) => `---\ndescription: ${DESCRIPTION}\nglobs:\nalwaysApply: false\n---\n${MARKER}\n\n${b}` },
  // Codex (and any AGENTS.md reader): a marked block in AGENTS.md
  codex: { path: 'AGENTS.md', shared: true, render: (b) => b },
  // Windsurf workspace rule: model-decision trigger
  windsurf: { path: '.windsurf/rules/pca.md', render: (b) => `---\ntrigger: model_decision\ndescription: ${DESCRIPTION}\n---\n${MARKER}\n\n${b}` },
  // Cline: .clinerules/ directory of markdown rules
  cline: { path: '.clinerules/pca.md', render: (b) => `${MARKER}\n\n${b}` },
  // Gemini CLI: a marked block in GEMINI.md
  gemini: { path: 'GEMINI.md', shared: true, render: (b) => b },
};

export interface McpSnippet { harness: Harness; where: string; text: string }
const SERVER = { command: 'npx', args: ['-y', '@atlasauth/pca-dev-mcp'] };
const json = (v: unknown): string => JSON.stringify(v, null, 2);

export function mcpSnippets(): McpSnippet[] {
  return [
    { harness: 'claude', where: 'run once in the project (or put the JSON in .mcp.json)', text: `claude mcp add pca -- npx -y @atlasauth/pca-dev-mcp\n\n.mcp.json:\n${json({ mcpServers: { pca: SERVER } })}` },
    { harness: 'cursor', where: '.cursor/mcp.json (or ~/.cursor/mcp.json)', text: json({ mcpServers: { pca: SERVER } }) },
    { harness: 'codex', where: '~/.codex/config.toml', text: '[mcp_servers.pca]\ncommand = "npx"\nargs = ["-y", "@atlasauth/pca-dev-mcp"]' },
    { harness: 'windsurf', where: '~/.codeium/windsurf/mcp_config.json', text: json({ mcpServers: { pca: SERVER } }) },
    { harness: 'cline', where: "Cline's MCP settings (cline_mcp_settings.json)", text: json({ mcpServers: { pca: { ...SERVER, disabled: false } } }) },
    { harness: 'gemini', where: '.gemini/settings.json (or ~/.gemini/settings.json)', text: json({ mcpServers: { pca: SERVER } }) },
  ];
}

export interface InstallResult {
  detected: Harness[];
  /** The harnesses written for. */
  harnesses: Harness[];
  files: Array<{ harness: Harness; path: string; action: 'created' | 'updated' | 'unchanged' | 'skipped'; note?: string }>;
  snippets: McpSnippet[];
}

export interface InstallOptions { harnesses?: readonly Harness[]; all?: boolean; dryRun?: boolean }

function block(body: string): string { return `${START}\n${MARKER}\n\n${body.trimEnd()}\n${END}\n`; }

export function installKit(root: string, o: InstallOptions = {}): InstallResult {
  const detected = detectHarnesses(root);
  const bad = (o.harnesses ?? []).filter((h) => !HARNESSES.includes(h));
  if (bad.length) throw new Error(`unknown harness ${bad.join(', ')} (${HARNESSES.join(', ')})`);
  // none detected: AGENTS.md is the one file most coding agents read
  const chosen: Harness[] = o.harnesses?.length ? [...o.harnesses] : o.all ? [...HARNESSES] : detected.length ? detected : ['codex'];
  const body = recipe();
  const files: InstallResult['files'] = [];
  for (const h of chosen) {
    const t = TARGETS[h];
    const abs = join(root, t.path);
    const had = existsSync(abs) ? readFileSync(abs, 'utf8') : undefined;
    let next: string;
    let action: 'created' | 'updated' | 'unchanged' | 'skipped' = 'created';
    let note: string | undefined;
    if (t.shared) {
      const blk = block(t.render(body));
      if (had === undefined) next = blk;
      else if (had.includes(START) && had.includes(END)) {
        const a = had.indexOf(START), b = had.indexOf(END) + END.length;
        next = had.slice(0, a) + blk.trimEnd() + had.slice(b);
        action = next === had ? 'unchanged' : 'updated';
      } else { next = had.replace(/\n*$/, '\n\n') + blk; action = 'updated'; }
    } else {
      next = t.render(body);
      if (had !== undefined) {
        if (!had.includes(MARKER)) { action = 'skipped'; note = 'a file you wrote is already there; not overwritten'; }
        else action = had === next ? 'unchanged' : 'updated';
      }
    }
    if ((action === 'created' || action === 'updated') && !o.dryRun) {
      mkdirSync(dirname(abs), { recursive: true });
      writeFileSync(abs, next!);
    }
    files.push({ harness: h, path: t.path, action, ...(note ? { note } : {}) });
  }
  return { detected, harnesses: chosen, files, snippets: mcpSnippets().filter((s) => chosen.includes(s.harness)) };
}

export function formatInstall(r: InstallResult): string {
  const out: string[] = [];
  out.push(r.detected.length ? `detected: ${r.detected.join(', ')}` : 'no coding-agent configuration detected; wrote AGENTS.md (most agents read it). Use --harness or --all for others.');
  for (const f of r.files) out.push(`  ${f.action.padEnd(9)} ${f.path}${f.note ? `  (${f.note})` : ''}`);
  out.push('', 'Add the MCP server so the agent can call the tools (the files above only teach it when to use them):');
  for (const s of r.snippets) out.push('', `[${s.harness}] ${s.where}`, ...s.text.split('\n').map((l) => `  ${l}`));
  return out.join('\n');
}
