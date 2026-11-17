export type Language = 'js' | 'python' | 'ruby' | 'go' | 'java' | 'dotnet' | 'php' | 'rust' | 'swift';

export interface McpServerDef {
  name: string;
  command?: string;
  args?: string[];
  url?: string;
  /** Names only. A value in an MCP definition is often a secret, so it is never copied. */
  envNames: string[];
  source: string;
}

export interface Detection {
  /** Absolute project directory. */
  dir: string;
  language: Language;
  /** `express`, `fastapi`, `net/http`, ... or null when only agents or MCP servers were found. */
  framework: string | null;
  packageManager: 'npm' | 'pnpm' | 'yarn' | 'bun' | null;
  typescript: boolean;
  /** JS only: `type: module` in package.json. */
  esm: boolean;
  /** Agent frameworks and MCP SDKs the project depends on. */
  agents: string[];
  mcpServers: McpServerDef[];
  /** Relative paths of an MCP tool list document and an OpenAPI document, when present. */
  mcpTools: string | null;
  openapi: string | null;
  /** Identifier used as the action namespace. */
  ns: string;
  /** The port the app listens on by default, for the proxy upstream. */
  port: number;
}

export interface FileChange {
  /** Path relative to the project directory. */
  path: string;
  before: string | null;
  after: string;
  /** Key material is generated when the plan is applied: the secret half is never printed, never overwritten. */
  generated?: 'secret' | 'public';
  /** Which keypair a generated file belongs to (default `dev`). The secret and public halves of one group come from one key. */
  group?: 'dev' | 'source';
  mode?: number;
  why: string;
}

export interface Snippet {
  title: string;
  /** Where to paste it, e.g. `src/server.py (after the line that creates the app, line 12)`. */
  where: string;
  code: string;
}

export interface Plan {
  detection: Detection;
  proxy: boolean;
  ns: string;
  mode: 'observe' | 'enforce';
  changes: FileChange[];
  /** Commands to run after applying (installing the dependency). */
  install: string[];
  snippets: Snippet[];
  notes: string[];
  /** The project-relative key path. */
  keyPath: string;
  /** Reasons the plan can never be applied (not even with --force), e.g. the key path is tracked by git. */
  blockers: string[];
  /** The working tree has uncommitted changes (apply needs --force). */
  dirty: boolean;
  /** Printed after a successful apply. */
  nextSteps: string[];
}

export interface Git {
  (cwd: string, args: string[]): { code: number; out: string };
}

export interface InitDeps {
  git: Git;
  /** The HTTP client for `--connect`. */
  fetch?: typeof fetch;
  /** A fresh 32-byte Ed25519 secret as base64url, and its public key. */
  newKey: () => { secret: string; publicKey: string };
}

export interface InitOptions {
  cwd: string;
  app?: string;
  proxy: boolean;
  yes: boolean;
  dryRun: boolean;
  force: boolean;
  check: boolean;
  mode?: 'observe' | 'enforce';
  ns?: string;
  server?: string;
  upstream?: string;
  url?: string;
  noImport: boolean;
  /** A single-use setup token: register a locally generated source key with the control plane and report observed events. */
  connect?: string;
  /** The control plane's API origin for `--connect`. */
  connectUrl?: string;
  /** `--grant FILE`: the human-signed grant to enforce (with mode enforce). */
  grant?: string;
  /** `--signer KEY`: the guardian public key that signs grants, when it was not saved at connect. */
  signer?: string;
  /** `--include-params a,b`: parameters whose safe-integer and boolean values may be reported, so proposals can carry amount caps. */
  includeParams?: string[];
}

export interface InitResult {
  ok: boolean;
  text: string;
}
