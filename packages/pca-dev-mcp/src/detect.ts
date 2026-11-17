/**
 * What is this project, and which PCA integration fits it. Pure file inspection, read-only.
 *
 * `ProjectInspector` is the seam: `fsInspector` below reads manifests and supplies the facts `pca init` does not compute;
 * the tools use `initInspector` (init-adapter.ts), which takes the project, language and framework from `pca init`'s detector.
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

export type Language = 'typescript' | 'javascript' | 'python' | 'go' | 'rust' | 'ruby' | 'php' | 'java' | 'kotlin' | 'dotnet' | 'swift';
/** How PCA fits: a proxy in front of an MCP server or an HTTP API (no code change), a guard in the server's own code, or the agent side. */
export type Integration = 'proxy-mcp' | 'proxy-http' | 'sdk-guard' | 'agent-side';
export type Harness = 'claude' | 'cursor' | 'codex' | 'windsurf' | 'cline' | 'gemini';

export interface Detection {
  root: string;
  /** The project's name (package.json name, else the directory name). */
  name: string;
  languages: Language[];
  primaryLanguage: Language | null;
  frameworks: string[];
  /** The project is (or contains) an MCP server. */
  mcpServer: boolean;
  /** The project calls models or tools as an agent (an agent framework or model SDK is in use). */
  agentCode: boolean;
  /** HTTP API frameworks found (the things a guard attaches to). */
  httpFrameworks: string[];
  /** OpenAPI / Swagger documents, relative to the root. */
  openapi: string[];
  /** PCA is already present (a dependency, or a pca-proxy config). */
  pcaPresent: boolean;
  pcaFiles: string[];
  packageManager: 'npm' | 'pnpm' | 'yarn' | 'bun' | null;
  harnesses: Harness[];
  recommendation: { integration: Integration; reasons: string[] };
  /** Several apps were found (a monorepo): the message names them; point `path` at one. */
  ambiguous?: string;
}

export interface ProjectInspector {
  detect(root: string): Promise<Detection> | Detection;
}

// manifest text -> [needle, framework name, kind]
type Kind = 'http' | 'mcp' | 'agent';
const NEEDLES: Record<string, ReadonlyArray<readonly [string, string, Kind]>> = {
  'package.json': [
    ['"express"', 'express', 'http'], ['"fastify"', 'fastify', 'http'], ['"hono"', 'hono', 'http'], ['"next"', 'next', 'http'], ['"koa"', 'koa', 'http'], ['"@nestjs/core"', 'nestjs', 'http'],
    ['"@modelcontextprotocol/sdk"', 'mcp-sdk', 'mcp'], ['"fastmcp"', 'fastmcp', 'mcp'],
    ['"@anthropic-ai/sdk"', 'anthropic-sdk', 'agent'], ['"openai"', 'openai-sdk', 'agent'], ['"ai"', 'vercel-ai', 'agent'], ['"langchain"', 'langchain', 'agent'], ['"@langchain/', 'langchain', 'agent'],
    ['"@openai/agents"', 'openai-agents', 'agent'], ['"@mastra/core"', 'mastra', 'agent'], ['"llamaindex"', 'llamaindex', 'agent'],
  ],
  'pyproject.toml': [], 'requirements.txt': [],
  'go.mod': [
    ['gin-gonic/gin', 'gin', 'http'], ['labstack/echo', 'echo', 'http'], ['go-chi/chi', 'chi', 'http'], ['mark3labs/mcp-go', 'mcp-go', 'mcp'], ['modelcontextprotocol/go-sdk', 'mcp-go', 'mcp'],
  ],
  'Cargo.toml': [['axum', 'axum', 'http'], ['actix-web', 'actix-web', 'http'], ['rmcp', 'rmcp', 'mcp']],
  Gemfile: [['rails', 'rails', 'http'], ['sinatra', 'sinatra', 'http']],
  'composer.json': [['laravel/framework', 'laravel', 'http'], ['symfony/', 'symfony', 'http']],
  'pom.xml': [['spring-boot', 'spring', 'http']],
  'build.gradle': [['spring-boot', 'spring', 'http'], ['ktor', 'ktor', 'http']],
  'build.gradle.kts': [['spring-boot', 'spring', 'http'], ['ktor', 'ktor', 'http']],
  'Package.swift': [['vapor', 'vapor', 'http'], ['hummingbird', 'hummingbird', 'http']],
};
const PY: ReadonlyArray<readonly [RegExp, string, Kind]> = [
  [/(^|[\s"'=<>~!])fastapi\b/im, 'fastapi', 'http'], [/(^|[\s"'])flask\b/im, 'flask', 'http'], [/(^|[\s"'])django\b/im, 'django', 'http'],
  [/(^|[\s"'])fastmcp\b/im, 'fastmcp', 'mcp'], [/(^|[\s"'])mcp\b/im, 'mcp-sdk', 'mcp'],
  [/(^|[\s"'])anthropic\b/im, 'anthropic-sdk', 'agent'], [/(^|[\s"'])openai\b/im, 'openai-sdk', 'agent'], [/(^|[\s"'])langchain/im, 'langchain', 'agent'], [/(^|[\s"'])llama[-_]index/im, 'llamaindex', 'agent'],
];
const PCA_DEP = [/@atlasauth\/pca/, /\batlas[-_]pca\b/, /Atlas-Authorization\/pca/, /atlas-auth\/atlas-pca/];
const OPENAPI_NAMES = /^(openapi|swagger)\.(json|ya?ml)$/i;
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'target', 'vendor', '.venv', 'venv', '__pycache__', '.next']);

const read = (p: string): string | undefined => { try { return readFileSync(p, 'utf8'); } catch { return undefined; } };
const isDir = (p: string): boolean => { try { return statSync(p).isDirectory(); } catch { return false; } };

function findOpenApi(root: string, dir = '', depth = 0): string[] {
  const out: string[] = [];
  let names: string[];
  try { names = readdirSync(join(root, dir)); } catch { return out; }
  for (const n of names.sort()) {
    const rel = dir ? `${dir}/${n}` : n;
    if (OPENAPI_NAMES.test(n)) out.push(rel);
    else if (depth < 2 && !SKIP_DIRS.has(n) && !n.startsWith('.') && isDir(join(root, rel))) out.push(...findOpenApi(root, rel, depth + 1));
  }
  return out;
}

function hasCsprojWeb(root: string): boolean {
  try { return readdirSync(root).some((n) => n.endsWith('.csproj') && /Microsoft\.NET\.Sdk\.Web/.test(read(join(root, n)) ?? '')); } catch { return false; }
}

export const HARNESS_MARKERS: Record<Harness, readonly string[]> = {
  claude: ['.claude', 'CLAUDE.md', '.mcp.json'],
  cursor: ['.cursor', '.cursorrules'],
  codex: ['AGENTS.md', '.codex'],
  windsurf: ['.windsurf', '.windsurfrules'],
  cline: ['.clinerules', '.cline'],
  gemini: ['GEMINI.md', '.gemini'],
};

export function detectHarnesses(root: string): Harness[] {
  return (Object.keys(HARNESS_MARKERS) as Harness[]).filter((h) => HARNESS_MARKERS[h].some((m) => existsSync(join(root, m))));
}

type Facts = Pick<Detection, 'mcpServer' | 'agentCode' | 'httpFrameworks' | 'openapi' | 'pcaPresent' | 'pcaFiles' | 'primaryLanguage'>;

/** Which integration fits, and why. Shared by every inspector so the answer does not depend on who detected the project. */
export function recommend(f: Facts): Detection['recommendation'] {
  const reasons: string[] = [];
  let integration: Integration;
  if (f.mcpServer) {
    integration = 'proxy-mcp';
    reasons.push('MCP server code or configuration found: put pca-proxy in front of it; no code change, observe mode first.');
  } else if (f.httpFrameworks.length > 0 || f.openapi.length > 0) {
    if (f.openapi.length > 0) {
      integration = 'proxy-http';
      reasons.push(`An OpenAPI document (${f.openapi[0]}) maps every route to an action: put pca-proxy in front of the API as a sidecar, observe mode first.`);
      if (f.httpFrameworks.length > 0) reasons.push(`Prefer an in-process guard (sdk-guard, ${f.httpFrameworks.join(', ')}) when the API must verify proofs itself, for example across several hops.`);
    } else {
      integration = 'sdk-guard';
      reasons.push(`HTTP framework found (${f.httpFrameworks.join(', ')}) and no OpenAPI document: add the guard to the routes that act. (An OpenAPI document would also allow the no-code proxy.)`);
    }
  } else if (f.agentCode) {
    integration = 'agent-side';
    reasons.push('Agent code found and no server: protect the tools the agent calls with a proxy, or build proofs on the agent side with the facade.');
  } else {
    integration = 'proxy-http';
    reasons.push('No server or agent framework recognised. The proxy needs no code in your project: start with it in observe mode in front of the service you want to protect.');
  }
  if (f.pcaPresent) reasons.push(`PCA is already present (${f.pcaFiles.join(', ')}): the plan only adds what is missing.`);
  return { integration, reasons };
}

export const fsInspector: ProjectInspector = {
  detect(root: string): Detection {
    if (!isDir(root)) throw new Error(`not a directory: ${root}`);
    const languages: Language[] = [];
    const add = (l: Language): void => { if (!languages.includes(l)) languages.push(l); };
    const frameworks = new Set<string>();
    const kinds: Record<Kind, Set<string>> = { http: new Set(), mcp: new Set(), agent: new Set() };
    let pcaPresent = false;
    const pcaFiles: string[] = [];
    const hit = (name: string, kind: Kind): void => { frameworks.add(name); kinds[kind].add(name); };

    for (const [file, needles] of Object.entries(NEEDLES)) {
      const text = read(join(root, file));
      if (text === undefined) continue;
      for (const [needle, name, kind] of needles) if (text.includes(needle)) hit(name, kind);
      if (PCA_DEP.some((r) => r.test(text))) { pcaPresent = true; pcaFiles.push(file); }
    }
    const pkg = read(join(root, 'package.json'));
    if (pkg !== undefined) add(existsSync(join(root, 'tsconfig.json')) || /"typescript"/.test(pkg) ? 'typescript' : 'javascript');
    for (const f of ['pyproject.toml', 'requirements.txt']) {
      const text = read(join(root, f));
      if (text === undefined) continue;
      add('python');
      for (const [re, name, kind] of PY) if (re.test(text)) hit(name, kind);
      if (PCA_DEP.some((r) => r.test(text))) { pcaPresent = true; pcaFiles.push(f); }
    }
    if (existsSync(join(root, 'go.mod'))) add('go');
    if (existsSync(join(root, 'Cargo.toml'))) add('rust');
    if (existsSync(join(root, 'Gemfile'))) add('ruby');
    if (existsSync(join(root, 'composer.json'))) add('php');
    if (existsSync(join(root, 'pom.xml'))) add('java');
    for (const g of ['build.gradle', 'build.gradle.kts']) {
      const t = read(join(root, g));
      if (t !== undefined) add(/kotlin/i.test(t) ? 'kotlin' : 'java');
    }
    if (existsSync(join(root, 'Package.swift'))) add('swift');
    if (hasCsprojWeb(root) || (() => { try { return readdirSync(root).some((n) => n.endsWith('.csproj')); } catch { return false; } })()) {
      add('dotnet');
      if (hasCsprojWeb(root)) hit('aspnet', 'http');
    }
    for (const f of ['pca-proxy.yaml', 'pca-proxy.yml', 'pca.config.json']) if (existsSync(join(root, f))) { pcaPresent = true; pcaFiles.push(f); }
    if (isDir(join(root, 'actions')) && existsSync(join(root, 'actions', 'pca.config.json'))) { pcaPresent = true; pcaFiles.push('actions/pca.config.json'); }

    const openapi = findOpenApi(root);
    const mcpServer = kinds.mcp.size > 0;
    const agentCode = kinds.agent.size > 0;
    const httpFrameworks = [...kinds.http].sort();
    const packageManager = existsSync(join(root, 'pnpm-lock.yaml')) ? 'pnpm' : existsSync(join(root, 'yarn.lock')) ? 'yarn' : existsSync(join(root, 'bun.lockb')) || existsSync(join(root, 'bun.lock')) ? 'bun' : pkg !== undefined ? 'npm' : null;

    const recommendation = recommend({ mcpServer, agentCode, httpFrameworks, openapi, pcaPresent, pcaFiles: [...new Set(pcaFiles)], primaryLanguage: languages[0] ?? null });
    let name = root.split(/[\\/]/).filter(Boolean).pop() ?? 'app';
    try { const n = (JSON.parse(pkg ?? '{}') as { name?: unknown }).name; if (typeof n === 'string' && n) name = n; } catch { /* keep the directory name */ }

    return {
      root,
      name,
      languages,
      primaryLanguage: languages[0] ?? null,
      frameworks: [...frameworks].sort(),
      mcpServer,
      agentCode,
      httpFrameworks,
      openapi,
      pcaPresent,
      pcaFiles: [...new Set(pcaFiles)],
      packageManager,
      harnesses: detectHarnesses(root),
      recommendation,
    };
  },
};
