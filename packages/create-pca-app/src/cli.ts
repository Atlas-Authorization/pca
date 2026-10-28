#!/usr/bin/env node
/**
 * create-pca-app — scaffold a runnable Proof-Carrying Authority starter.
 *
 *   npm create pca-app@latest my-app
 *   create-pca-app my-app --template express-rs
 *   create-pca-app my-app --yes            # non-interactive, default template
 *
 * Thin wrapper over `scaffold()` in ./index: it reads the target dir + template from flags (or
 * prompts for them with node:readline), copies the chosen template, and prints the next steps. The
 * generated project is the real authF loop — mint a capability, sign a proof-carrying action, verify
 * it offline — so `npm i && npm start` gets you from zero to a passing + a failing verification.
 */

import { createInterface, type Interface } from 'node:readline';
import {
  DEFAULT_TEMPLATE,
  TEMPLATES,
  TEMPLATE_DESCRIPTIONS,
  type TemplateName,
  isTemplateName,
  scaffold,
} from './index';

interface ParsedArgs {
  dir?: string;
  template?: string;
  yes: boolean;
  help: boolean;
}

export function parseArgs(argv: string[]): ParsedArgs {
  const out: ParsedArgs = { yes: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === undefined) continue;
    if (arg === '--yes' || arg === '-y') out.yes = true;
    else if (arg === '--help' || arg === '-h') out.help = true;
    else if (arg === '--template' || arg === '-t') {
      const next = argv[i + 1];
      if (next === undefined) throw new Error('--template needs a value');
      out.template = next;
      i++;
    } else if (arg.startsWith('--template=')) out.template = arg.slice('--template='.length);
    else if (!arg.startsWith('-') && out.dir === undefined) out.dir = arg;
  }
  return out;
}

function helpText(): string {
  const templates = TEMPLATES.map((t) => `    ${t.padEnd(16)} ${TEMPLATE_DESCRIPTIONS[t]}`).join('\n');
  return [
    'Usage: create-pca-app [directory] [--template <name>] [--yes]',
    '',
    'Scaffold a runnable Proof-Carrying Authority starter.',
    '',
    '  directory            where to create the project (prompted if omitted)',
    '  -t, --template <t>   starter template (default: ' + DEFAULT_TEMPLATE + ')',
    '  -y, --yes            accept defaults; do not prompt',
    '  -h, --help           show this help',
    '',
    '  Templates:',
    templates,
    '',
  ].join('\n');
}

function ask(rl: Interface, question: string): Promise<string> {
  return new Promise((res) => rl.question(question, (answer) => res(answer)));
}

async function resolveInputs(
  parsed: ParsedArgs,
): Promise<{ dir: string; template: TemplateName }> {
  const interactive = !parsed.yes && process.stdin.isTTY === true;
  let dir = parsed.dir;
  let template = parsed.template;

  if (interactive && (dir === undefined || template === undefined)) {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    try {
      if (dir === undefined) {
        const answer = (await ask(rl, 'Project directory (e.g. my-pca-app): ')).trim();
        dir = answer.length > 0 ? answer : 'my-pca-app';
      }
      if (template === undefined) {
        process.stdout.write('\nTemplates:\n');
        for (const t of TEMPLATES) process.stdout.write(`  - ${t}: ${TEMPLATE_DESCRIPTIONS[t]}\n`);
        const answer = (await ask(rl, `\nTemplate [${DEFAULT_TEMPLATE}]: `)).trim();
        template = answer.length > 0 ? answer : DEFAULT_TEMPLATE;
      }
    } finally {
      rl.close();
    }
  }

  const finalDir = dir ?? 'my-pca-app';
  const finalTemplate = template ?? DEFAULT_TEMPLATE;
  if (!isTemplateName(finalTemplate)) {
    throw new Error(`unknown template '${finalTemplate}' (choose one of: ${TEMPLATES.join(', ')})`);
  }
  return { dir: finalDir, template: finalTemplate };
}

export async function run(argv: string[]): Promise<number> {
  const parsed = parseArgs(argv);
  if (parsed.help) {
    process.stdout.write(helpText());
    return 0;
  }

  const { dir, template } = await resolveInputs(parsed);
  const result = scaffold({ dir, template });

  process.stdout.write(`\nScaffolded "${result.name}" (${result.template}) — ${result.files.length} files:\n`);
  for (const f of result.files) process.stdout.write(`  ${f}\n`);
  process.stdout.write('\nNext:\n');
  process.stdout.write(`  cd ${dir}\n`);
  process.stdout.write('  npm install\n');
  if (result.template === 'mcp') {
    process.stdout.write('  npm run demo\n\n');
    process.stdout.write('That starts the MCP server and runs the agent: each tool call carries a proof the server verifies, then allows or denies.\n');
    process.stdout.write('To run the two sides separately: `npm start` in one terminal, `npm run agent` in another.\n');
  } else if (result.template === 'actions') {
    process.stdout.write('  npm run lint && npm test && npm run build\n\n');
    process.stdout.write('That lints the actions in actions/acme.yaml, runs their examples, and builds the schema and pack into .pca/.\n');
  } else if (result.template === 'attacks') {
    process.stdout.write('  npm start\n\n');
    process.stdout.write('That runs seven attacks against OAuth scopes, OAuth RAR, macaroons/Biscuit, UCAN and PCA, and prints which approaches stop each one and why.\n');
  } else {
    process.stdout.write('  npm start\n\n');
    process.stdout.write('That runs the PCA loop: each action carries a proof the server verifies, then allows or denies.\n');
  }
  return 0;
}

// Run only when invoked as the bin (not when imported, e.g. by a test of parseArgs/run).
if (require.main === module) {
  run(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (err: unknown) => {
      process.stderr.write(`\ncreate-pca-app: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exit(1);
    },
  );
}
