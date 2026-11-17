/** Project detection from manifest files. Pure reads; nothing is executed and no dependency is installed. */
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { basename, join, relative } from 'node:path';
import type { Detection, Language, McpServerDef } from './types';

const SKIP = new Set(['node_modules', '.git', 'dist', 'build', 'target', 'vendor', '.venv', 'venv', '__pycache__', '.next', '.pca', 'bin', 'obj']);
const MAX_FILE = 1_000_000;

export const read = (p: string): string | null => {
  try {
    return statSync(p).size > MAX_FILE ? null : readFileSync(p, 'utf8');
  } catch {
    return null;
  }
};

/** Source files under `dir` (depth-limited, skipping dependency and build directories). */
export function listFiles(dir: string, exts: readonly string[], opts: { depth?: number; limit?: number } = {}): string[] {
  const out: string[] = [];
  const limit = opts.limit ?? 400;
  const walk = (d: string, depth: number): void => {
    let names: string[];
    try {
      names = readdirSync(d).sort();
    } catch {
      return;
    }
    for (const n of names) {
      if (out.length >= limit) return;
      if (n.startsWith('.') && n !== '.mcp.json') continue;
      const p = join(d, n);
      let st;
      try {
        st = statSync(p);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        if (!SKIP.has(n) && depth < (opts.depth ?? 6)) walk(p, depth + 1);
      } else if (exts.some((e) => n.endsWith(e)) && !/\.(test|spec)\./.test(n)) out.push(p);
    }
  };
  walk(dir, 0);
  return out;
}

const has = (text: string, name: string): boolean => new RegExp(`(^|[\\s"'\\[,(=/])${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([\\s=<>~!\\[;"',)\\]/]|$)`, 'im').test(text);

const nsOf = (name: string): string => {
  const n = name.replace(/^@[^/]+\//, '').toLowerCase().replace(/[^a-z0-9_]+/g, '_').replace(/^_+|_+$/g, '').replace(/^[0-9]+/, '');
  return (n.length > 0 ? n : 'app').slice(0, 32);
};

interface Hit {
  language: Language;
  framework: string | null;
  agents: string[];
  name: string;
  port: number;
  extra?: Partial<Pick<Detection, 'packageManager' | 'typescript' | 'esm'>>;
}

function detectJs(dir: string, text: string): Hit | null {
  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(text) as Record<string, unknown>;
  } catch {
    return null;
  }
  if (pkg.workspaces !== undefined) return null; // a workspace root is not an app; its members are
  const deps = { ...(pkg.dependencies as object), ...(pkg.devDependencies as object) } as Record<string, string>;
  const d = (n: string): boolean => Object.prototype.hasOwnProperty.call(deps, n);
  const framework = d('next') ? 'next' : d('@nestjs/core') ? 'nest' : d('fastify') ? 'fastify' : d('hono') ? 'hono' : d('express') ? 'express' : null;
  const agents: string[] = [];
  if (Object.keys(deps).some((k) => k === 'langchain' || k.startsWith('@langchain/'))) agents.push('LangChain');
  if (d('@openai/agents')) agents.push('OpenAI Agents');
  if (d('@anthropic-ai/sdk')) agents.push('Anthropic SDK');
  if (d('ai') || d('@ai-sdk/openai') || d('@ai-sdk/anthropic')) agents.push('Vercel AI SDK');
  if (d('llamaindex')) agents.push('LlamaIndex');
  if (d('@modelcontextprotocol/sdk') || d('fastmcp') || d('mcp-framework')) agents.push('MCP SDK');
  const pm = existsSync(join(dir, 'pnpm-lock.yaml')) ? 'pnpm' : existsSync(join(dir, 'yarn.lock')) ? 'yarn' : existsSync(join(dir, 'bun.lockb')) || existsSync(join(dir, 'bun.lock')) ? 'bun' : 'npm';
  return {
    language: 'js',
    framework,
    agents,
    name: typeof pkg.name === 'string' ? pkg.name : basename(dir),
    port: 3000,
    extra: { packageManager: pm, typescript: d('typescript') || existsSync(join(dir, 'tsconfig.json')), esm: pkg.type === 'module' },
  };
}

function detectPython(dir: string): Hit | null {
  const text = ['pyproject.toml', 'requirements.txt', 'requirements/base.txt', 'Pipfile'].map((f) => read(join(dir, f)) ?? '').join('\n');
  if (text.trim() === '') return null;
  const framework = has(text, 'fastapi') ? 'fastapi' : has(text, 'flask') ? 'flask' : has(text, 'django') ? 'django' : null;
  const agents: string[] = [];
  if (has(text, 'langchain') || has(text, 'langchain-core') || has(text, 'langgraph')) agents.push('LangChain');
  if (has(text, 'openai-agents')) agents.push('OpenAI Agents');
  if (has(text, 'anthropic')) agents.push('Anthropic SDK');
  if (has(text, 'llama-index') || has(text, 'llama_index')) agents.push('LlamaIndex');
  if (has(text, 'mcp') || has(text, 'fastmcp')) agents.push('MCP SDK');
  return { language: 'python', framework, agents, name: basename(dir), port: framework === 'flask' ? 5000 : 8000 };
}

function detectRuby(dir: string): Hit | null {
  const t = read(join(dir, 'Gemfile'));
  if (t === null) return null;
  const framework = /gem\s+['"]rails['"]/.test(t) ? 'rails' : /gem\s+['"]sinatra['"]/.test(t) ? 'sinatra' : null;
  return { language: 'ruby', framework, agents: [], name: basename(dir), port: framework === 'sinatra' ? 4567 : 3000 };
}

function detectGo(dir: string): Hit | null {
  const t = read(join(dir, 'go.mod'));
  if (t === null) return null;
  const framework = t.includes('gin-gonic/gin') ? 'gin' : t.includes('labstack/echo') ? 'echo' : t.includes('go-chi/chi') ? 'chi' : 'net/http';
  const agents: string[] = [];
  if (t.includes('tmc/langchaingo')) agents.push('LangChain');
  if (t.includes('anthropics/anthropic-sdk-go')) agents.push('Anthropic SDK');
  if (t.includes('mark3labs/mcp-go') || t.includes('modelcontextprotocol/go-sdk')) agents.push('MCP SDK');
  return { language: 'go', framework, agents, name: /^module\s+(\S+)/m.exec(t)?.[1]?.split('/').pop() ?? basename(dir), port: 8080 };
}

function detectJava(dir: string): Hit | null {
  const t = ['pom.xml', 'build.gradle', 'build.gradle.kts'].map((f) => read(join(dir, f))).find((x) => x !== null) ?? null;
  if (t === null) return null;
  const agents: string[] = [];
  if (/langchain4j/.test(t)) agents.push('LangChain');
  if (/anthropic/.test(t)) agents.push('Anthropic SDK');
  if (/modelcontextprotocol|spring-ai-mcp/.test(t)) agents.push('MCP SDK');
  return { language: 'java', framework: /spring-boot/.test(t) ? 'spring-boot' : null, agents, name: basename(dir), port: 8080 };
}

function detectDotnet(dir: string): Hit | null {
  let proj: string | undefined;
  try {
    proj = readdirSync(dir).find((n) => n.endsWith('.csproj'));
  } catch {
    return null;
  }
  if (proj === undefined) return null;
  const t = read(join(dir, proj)) ?? '';
  return { language: 'dotnet', framework: /Microsoft\.NET\.Sdk\.Web|Microsoft\.AspNetCore/.test(t) ? 'aspnetcore' : null, agents: [], name: proj.replace(/\.csproj$/, ''), port: 5000 };
}

function detectPhp(dir: string): Hit | null {
  const t = read(join(dir, 'composer.json'));
  if (t === null) return null;
  const framework = t.includes('laravel/framework') ? 'laravel' : /symfony\/(framework-bundle|symfony)/.test(t) ? 'symfony' : null;
  return { language: 'php', framework, agents: [], name: basename(dir), port: 8000 };
}

function detectRust(dir: string): Hit | null {
  const t = read(join(dir, 'Cargo.toml'));
  if (t === null) return null;
  const framework = /^\s*axum\s*=|^\s*axum\.|\[dependencies\.axum\]/m.test(t) ? 'axum' : /^\s*actix-web\s*=|\[dependencies\.actix-web\]/m.test(t) ? 'actix' : null;
  const agents = /^\s*rmcp\s*=/m.test(t) ? ['MCP SDK'] : [];
  return { language: 'rust', framework, agents, name: /^name\s*=\s*"([^"]+)"/m.exec(t)?.[1] ?? basename(dir), port: 3000 };
}

function detectSwift(dir: string): Hit | null {
  const t = read(join(dir, 'Package.swift'));
  if (t === null) return null;
  return { language: 'swift', framework: /vapor\/vapor/i.test(t) ? 'vapor' : null, agents: [], name: basename(dir), port: 8080 };
}

/** MCP server definitions from `.mcp.json`, `mcp.json`, `.cursor/mcp.json` and `.vscode/mcp.json`. */
export function findMcpServers(dir: string): McpServerDef[] {
  const out: McpServerDef[] = [];
  for (const rel of ['.mcp.json', 'mcp.json', '.cursor/mcp.json', '.vscode/mcp.json']) {
    const t = read(join(dir, rel));
    if (t === null) continue;
    let doc: unknown;
    try {
      doc = JSON.parse(t);
    } catch {
      continue;
    }
    const o = doc as { mcpServers?: unknown; servers?: unknown };
    const map = (o.mcpServers ?? o.servers) as Record<string, Record<string, unknown>> | undefined;
    if (map === null || typeof map !== 'object' || Array.isArray(map)) continue;
    for (const [name, s] of Object.entries(map)) {
      if (s === null || typeof s !== 'object' || !/^[A-Za-z0-9._-]{1,64}$/.test(name)) continue;
      const env = s.env !== null && typeof s.env === 'object' ? Object.keys(s.env as object) : [];
      if (typeof s.command === 'string') {
        out.push({ name, command: s.command, args: Array.isArray(s.args) ? s.args.filter((a): a is string => typeof a === 'string') : [], envNames: env, source: rel });
      } else if (typeof s.url === 'string') out.push({ name, url: s.url, envNames: env, source: rel });
    }
  }
  return out;
}

const firstExisting = (dir: string, rels: string[]): string | null => rels.find((r) => existsSync(join(dir, r))) ?? null;

/** Detect the project in `dir`, or null when it has no manifest we understand (or nothing PCA can protect). */
export function detectDir(dir: string): Detection | null {
  const pj = read(join(dir, 'package.json'));
  const hit = (pj !== null ? detectJs(dir, pj) : null) ?? detectPython(dir) ?? detectRuby(dir) ?? detectGo(dir) ?? detectJava(dir) ?? detectDotnet(dir) ?? detectPhp(dir) ?? detectRust(dir) ?? detectSwift(dir);
  if (hit === null) return null;
  const mcpServers = findMcpServers(dir);
  const openapi = firstExisting(dir, ['openapi.json', 'openapi.yaml', 'openapi.yml', 'swagger.json', 'docs/openapi.json', 'docs/openapi.yaml', 'api/openapi.json', 'api/openapi.yaml', 'spec/openapi.json', 'spec/openapi.yaml']);
  return {
    dir,
    language: hit.language,
    framework: hit.framework,
    packageManager: hit.extra?.packageManager ?? null,
    typescript: hit.extra?.typescript ?? false,
    esm: hit.extra?.esm ?? false,
    agents: hit.agents,
    mcpServers,
    mcpTools: firstExisting(dir, ['mcp-tools.json', 'tools-list.json']),
    openapi,
    ns: nsOf(hit.name),
    port: hit.port,
  };
}

export class AppChoiceError extends Error {}

/**
 * The app to initialize. A directory with a framework (or agents, or MCP servers) is a candidate; a monorepo has several, and
 * then the user must name one with `--app`.
 */
export function findApp(root: string, app?: string): Detection {
  if (app !== undefined) {
    const d = detectDir(join(root, app));
    if (d === null) throw new AppChoiceError(`--app ${app}: no supported project (package.json, pyproject.toml, Gemfile, go.mod, pom.xml, *.csproj, composer.json, Cargo.toml or Package.swift) in that directory`);
    return d;
  }
  const found: Detection[] = [];
  const visit = (d: string, depth: number): void => {
    const det = detectDir(d);
    if (det !== null && (det.framework !== null || det.agents.length > 0 || det.mcpServers.length > 0)) found.push(det);
    if (depth >= 3) return;
    let names: string[] = [];
    try {
      names = readdirSync(d).sort();
    } catch {
      return;
    }
    for (const n of names) {
      if (n.startsWith('.') || SKIP.has(n)) continue;
      const p = join(d, n);
      try {
        if (statSync(p).isDirectory()) visit(p, depth + 1);
      } catch {
        /* unreadable entry */
      }
    }
  };
  visit(root, 0);
  if (found.length === 1) return found[0]!;
  if (found.length === 0) {
    const d = detectDir(root);
    if (d !== null) return d;
    throw new AppChoiceError('no supported project found here (looked for package.json, pyproject.toml, requirements.txt, Gemfile, go.mod, pom.xml, build.gradle, *.csproj, composer.json, Cargo.toml, Package.swift). Run it from your app, or pass --app DIR.');
  }
  throw new AppChoiceError(`more than one app here; choose one with --app DIR:\n${found.map((d) => `  --app ${relative(root, d.dir) || '.'}   (${d.framework ?? 'agent/MCP only'}, ${d.language})`).join('\n')}`);
}
