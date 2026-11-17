#!/usr/bin/env node
/** pca-dev-mcp: an MCP server on stdio for coding agents. Read-only unless started with --allow-write. */
import { resolve } from 'node:path';
import { createServer } from './server';

const USAGE = `pca-dev-mcp [--root DIR] [--allow-write]

  Serves MCP on stdio. Tools: pca_detect, pca_plan_integration, pca_explain, pca_lint_policy, pca_simulate,
  pca_actions_import, pca_doctor, pca_docs_search. They inspect, plan and explain; your coding agent makes the edits.

  --root DIR      the project the tools default to (default: the current directory)
  --allow-write   also expose pca_apply_step (creates pca-proxy.yaml, appends to .gitignore). Never runs a command.
`;

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  if (argv.includes('--help') || argv.includes('-h')) { process.stdout.write(USAGE); return; }
  let root = process.cwd();
  let allowWrite = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--allow-write') allowWrite = true;
    else if (a === '--root') { const v = argv[++i]; if (!v) throw new Error('--root needs a directory'); root = resolve(v); }
    else throw new Error(`unknown option ${a}\n\n${USAGE}`);
  }
  await createServer({ root, allowWrite }).serve(process.stdin, (line) => process.stdout.write(line + '\n'));
}

main().catch((e: unknown) => {
  process.stderr.write(`pca-dev-mcp: ${e instanceof Error ? e.message : String(e)}\n`);
  process.exitCode = 1;
});
