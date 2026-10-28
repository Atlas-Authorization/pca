/**
 * create-pca-app — the programmatic scaffolder behind the `create-pca-app` CLI.
 *
 *   npm create pca-app@latest my-app
 *
 * `scaffold()` copies one of the on-disk starter templates (see `../templates`) into a target
 * directory and rewrites the project name. Every template is a tiny, REAL project that depends on
 * `@atlasauth/pca`: it mints a capability, builds + signs a proof-carrying action, and verifies it
 * offline — a valid action passes, a tampered or out-of-scope one fails. Nothing here authorises anything;
 * the generated code's full server verifier (`verifyPCActn` / `requirePCA`) decides. This module uses Node built-ins only, and
 * the CLI (`./cli.ts`) is a thin wrapper around it so the behaviour is testable without a process.
 */

import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';

/** The starter templates shipped on disk under `templates/<name>`. */
export const TEMPLATES = ['pca-demo', 'pca-quickstart', 'node-quickstart', 'express-rs', 'mcp', 'attacks', 'actions', 'payments', 'delegation', 'goal'] as const;
export type TemplateName = (typeof TEMPLATES)[number];

/**
 * The default template when the caller names none: the end-to-end demo — a local resource server, a
 * FROST t-of-n guardian and an agent play nine scripted outcomes (allow, deny, step-up, replay, tamper,
 * budget, attenuation, offline receipt) and `npm start` exits nonzero if any deviates.
 */
export const DEFAULT_TEMPLATE: TemplateName = 'pca-demo';

/** One-line descriptions, surfaced by the CLI prompt + `--help`. */
export const TEMPLATE_DESCRIPTIONS: Record<TemplateName, string> = {
  'pca-demo':
    'The nine-outcome story: real resource server + FROST 3-of-5 guardian + agent. Allow, off-plan deny, t=3 step-up, replay, tamper, budget, sub-agent attenuation, offline receipt. `npm start` exits nonzero if any outcome deviates.',
  'pca-quickstart':
    'The whole loop: an agent (facade `agent({...})`) proves each action and an Express server guards a route with `requirePCA()`. `npm start` prints ALLOWED (legit) / DENIED (over-budget).',
  'node-quickstart':
    'One file: mint a capability, sign a proof-carrying action, verify it offline with the full verifier (ALLOW), then watch a tampered copy, an out-of-scope action and a forged root DENY.',
  'express-rs':
    'A minimal Express resource server that authorizes the PCA-Action header per request with the full verifier (grant from its own store, scope, plan, replay, budget), plus a client that calls it with a valid, a tampered and an out-of-scope proof.',
  mcp:
    'An MCP server (Streamable HTTP) whose tools each require a proof-carrying action (`authorizeToolCall`), and an MCP agent that sends one per tool call (`pcaFetch`). `npm run demo` shows two allowed refunds and three refusals (out-of-scope tool, over-limit amount, no proof), each with its reason.',
  actions:
    'Define actions once in YAML (or the TypeScript builder): lint them with 24 rules, run their examples, explain their risk, and build a signed schema and pack. `npm test` exits nonzero if an example deviates.',
  payments:
    'An agent that pays under $200 a day on its own, must ask a person for a charge over $50, and is refused the rest (wrong merchant, wrong currency, over the ceiling). `npm start` exits nonzero if an outcome deviates.',
  delegation:
    'Delegate to a sub-agent that can only be narrower than its parent, guard the server with `protect()`, revoke the grant, and read refusals with `explainRefusal()`. `npm start` exits nonzero if an outcome deviates.',
  goal:
    'Goal to enforced policy: a model drafts, a person reviews and signs, only the signed draft becomes an agent, and a server decides every action. An edited draft and an unpinned reviewer are refused.',
  attacks:
    'Seven agent-authorization attacks (confused deputy, poisoned approval, stolen credential, replay, over-broad delegation, swapped params, cumulative overspend) run against OAuth scopes, OAuth RAR, macaroons/Biscuit, UCAN and PCA. `npm start` prints who stops what, with each server\'s reason, and the matrix.',
};

/** The token every template uses where the project name belongs; `scaffold` substitutes it. */
export const NAME_TOKEN = '__PCA_APP_NAME__';

export function isTemplateName(t: string): t is TemplateName {
  return (TEMPLATES as readonly string[]).includes(t);
}

export interface ScaffoldOptions {
  /** Target directory to create the project in (created if missing; must be empty if it exists). */
  dir: string;
  /** Which starter to copy; defaults to {@link DEFAULT_TEMPLATE}. Any non-{@link TEMPLATES} value is
   *  rejected at runtime (kept as `string` so callers can pass unvalidated input, e.g. a CLI flag). */
  template?: TemplateName | string;
  /** Project name written into the generated package.json (defaults to the target dir's basename). */
  name?: string;
  /** Override where templates are read from (defaults to the package's `templates/`). Mainly for tests. */
  templatesDir?: string;
}

export interface ScaffoldResult {
  /** Absolute path the project was written to. */
  dir: string;
  /** The template that was used. */
  template: TemplateName;
  /** The project name written into package.json. */
  name: string;
  /** Project-relative paths of every file written (sorted). */
  files: string[];
}

/** The package's bundled templates directory. Resolves from this module whether run from `dist/` or `src/`. */
export function defaultTemplatesDir(): string {
  return join(__dirname, '..', 'templates');
}

/** Recursively list a directory's files as paths relative to `root` (POSIX-style separators). */
function listFilesRel(root: string, prefix = ''): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(join(root, prefix), { withFileTypes: true })) {
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) out.push(...listFilesRel(root, rel));
    else if (entry.isFile()) out.push(rel);
  }
  return out;
}

/**
 * npm strips a file literally named `.gitignore` from a published package, so templates ship it as
 * `gitignore` and we restore the leading dot on write. Applies to the basename at any depth.
 */
function outputRel(rel: string): string {
  const dir = dirname(rel);
  const base = basename(rel);
  const renamed = base === 'gitignore' ? '.gitignore' : base;
  return dir === '.' ? renamed : `${dir}/${renamed}`;
}

/** True when a directory does not exist or exists but holds no entries. */
export function dirIsEmpty(dir: string): boolean {
  if (!existsSync(dir)) return true;
  return readdirSync(dir).length === 0;
}

/**
 * Copy a starter template into `dir`, substituting the project name. Throws if the template is
 * unknown, its directory is missing, or the target directory exists and is non-empty.
 */
export function scaffold(opts: ScaffoldOptions): ScaffoldResult {
  const template = opts.template ?? DEFAULT_TEMPLATE;
  if (!isTemplateName(template)) {
    throw new Error(`unknown template '${template}' (choose one of: ${TEMPLATES.join(', ')})`);
  }
  const templatesDir = opts.templatesDir ?? defaultTemplatesDir();
  const srcDir = join(templatesDir, template);
  if (!existsSync(srcDir)) throw new Error(`template directory not found: ${srcDir}`);

  const dir = resolve(opts.dir);
  const name = opts.name ?? (basename(dir) || template);
  if (!dirIsEmpty(dir)) throw new Error(`refusing to scaffold into a non-empty directory: ${dir}`);

  const written: string[] = [];
  for (const rel of listFilesRel(srcDir)) {
    const contents = readFileSync(join(srcDir, rel), 'utf8').split(NAME_TOKEN).join(name);
    const dest = join(dir, outputRel(rel));
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, contents, 'utf8');
    written.push(outputRel(rel));
  }
  return { dir, template, name, files: written.sort() };
}
