/**
 * `pca agent-kit install`: write the rule or skill file for each coding agent found in the repo (Claude Code, Cursor, Codex,
 * Windsurf, Cline, Gemini CLI) and print the MCP server config for each. The content lives in @atlasauth/pca-dev-mcp.
 */
import { HARNESSES, formatInstall, installKit, type Harness } from '@atlasauth/pca-dev-mcp';

export function cmdAgentKit(sub: string | undefined, o: { root: string; harness?: string; all?: boolean; dryRun?: boolean }): { ok: boolean; text: string } {
  if (sub !== 'install') return { ok: false, text: `agent-kit: unknown sub-command '${String(sub)}' (install)` };
  const harnesses = o.harness ? o.harness.split(',').map((h) => h.trim()).filter(Boolean) : [];
  const bad = harnesses.filter((h) => !(HARNESSES as readonly string[]).includes(h));
  if (bad.length) return { ok: false, text: `agent-kit install: unknown harness ${bad.join(', ')} (${HARNESSES.join(', ')})` };
  const r = installKit(o.root, { harnesses: harnesses as Harness[], ...(o.all ? { all: true } : {}), ...(o.dryRun ? { dryRun: true } : {}) });
  return { ok: !r.files.some((f) => f.action === 'skipped' && harnesses.includes(f.harness)), text: formatInstall(r) + (o.dryRun ? '\n\n(dry run: nothing was written)' : '') };
}
