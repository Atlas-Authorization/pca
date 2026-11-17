/**
 * Action definitions from what the project already has: an OpenAPI file, an MCP tool list, or the route table read from the source.
 * Every imported action is a DRAFT, unconfirmed and treated as the most dangerous kind until a pinned reviewer signs it. An action file
 * or config that already exists is never overwritten (a reviewer may have confirmed it).
 */
import { existsSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { parse as parseYaml } from 'yaml';
import {
  CORE_REGISTRY, DEFAULT_RULES, applySuggestion, defsToYaml, importMcp, importOpenApi, rulesDigest, suggestWithRules,
  type ImportReport,
} from '@atlasauth/pca-actions';
import { listFiles, read } from './detect';
import type { Detection, FileChange } from './types';
import { ROUTES_FILE } from './wiring';

export interface RouteVerb {
  method: string;
  template: string;
  verb: string;
}

export interface ImportResult {
  changes: FileChange[];
  notes: string[];
  /** The route binding of every imported HTTP action: what the generated wiring resolves a request's verb through. */
  routes: RouteVerb[];
}

const METHODS = ['get', 'post', 'put', 'patch', 'delete'] as const;
const MAX_ROUTES = 300;

function normalizePath(p: string): string | null {
  if (/[*()?+^$]/.test(p)) return null; // a regex or wildcard route is not a literal operation
  const out = p
    .replace(/<(?:[a-z]+:)?([A-Za-z_]\w*)>/g, '{$1}') // flask <int:id>
    .replace(/\[\.{0,3}([A-Za-z_]\w*)\]/g, '{$1}') // next [id]
    .replace(/:([A-Za-z_]\w*)/g, '{$1}'); // express :id
  return out.length <= 256 && out.startsWith('/') ? out : null;
}

type Route = { method: string; path: string };

/** The routes found in the source: `app.get('/x')`, `@app.get("/x")`, `router.GET("/x")`, `get '/x'` and Next.js route files. */
export function routesOf(d: Detection): Route[] {
  const seen = new Map<string, Route>();
  const add = (m: string, p: string): void => {
    const path = normalizePath(p);
    const method = m.toLowerCase();
    if (path !== null && (METHODS as readonly string[]).includes(method) && seen.size < MAX_ROUTES) seen.set(`${method} ${path}`, { method, path });
  };
  const exts = d.language === 'js' ? ['.ts', '.js', '.mjs', '.cjs', '.mts'] : d.language === 'python' ? ['.py'] : d.language === 'go' ? ['.go'] : d.language === 'ruby' ? ['.rb'] : [];
  for (const f of listFiles(d.dir, exts)) {
    const t = read(f);
    if (t === null) continue;
    if (d.language === 'js') {
      for (const m of t.matchAll(/\b[A-Za-z_$][\w$]*\s*\.\s*(get|post|put|patch|delete)\s*\(\s*(['"`])(\/[^'"`$]*)\2/g)) add(m[1]!, m[3]!);
      if (d.framework === 'next' && /(^|[\\/])route\.(ts|js|mjs)$/.test(f)) {
        const rel = relative(d.dir, f).split(sep).join('/');
        const route = /(?:^|\/)app\/(.*)\/?route\.\w+$/.exec(rel)?.[1];
        if (route !== undefined) for (const m of t.matchAll(/export\s+(?:async\s+)?(?:function|const)\s+(GET|POST|PUT|PATCH|DELETE)\b/g)) add(m[1]!, `/${route.replace(/\([^/)]*\)\/?/g, '').replace(/\/$/, '')}`);
      }
    } else if (d.language === 'python') {
      for (const m of t.matchAll(/@\w+(?:\.\w+)*\.(get|post|put|patch|delete)\(\s*["'](\/[^"']*)["']/g)) add(m[1]!, m[2]!);
      for (const m of t.matchAll(/@\w+\.route\(\s*["'](\/[^"']*)["']([^)]*)\)/g)) {
        const ms = /methods\s*=\s*\[([^\]]*)\]/.exec(m[2]!)?.[1];
        for (const x of ms ? ms.match(/[A-Za-z]+/g) ?? [] : ['get']) add(x, m[1]!);
      }
    } else if (d.language === 'go') {
      for (const m of t.matchAll(/\.\s*(GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Patch|Delete)\(\s*"(\/[^"]*)"/g)) add(m[1]!, m[2]!);
    } else if (d.language === 'ruby') {
      for (const m of t.matchAll(/^\s*(get|post|put|patch|delete)\s+['"](\/[^'"]*)['"]/gm)) add(m[1]!, m[2]!);
    }
  }
  return [...seen.values()];
}

const slug = (s: string): string => s.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '') || 'root';

/** An OpenAPI 3 document describing exactly the routes found (no schemas: bodies are not guessed from source). */
export function routesToOpenApi(ns: string, routes: Route[]): unknown {
  const paths: Record<string, Record<string, unknown>> = {};
  for (const r of routes) {
    const params = [...r.path.matchAll(/\{(\w+)\}/g)].map((m) => ({ name: m[1], in: 'path', required: true, schema: { type: 'string' } }));
    (paths[r.path] ??= {})[r.method] = { operationId: `${r.method}_${slug(r.path)}`, ...(params.length ? { parameters: params } : {}), responses: { '200': { description: 'ok' } } };
  }
  return { openapi: '3.0.3', info: { title: ns, version: '0.0.0' }, paths };
}

function suggested(r: ImportReport): ImportReport {
  r.defs = r.defs.map((d) => {
    const sg = suggestWithRules(d, DEFAULT_RULES, CORE_REGISTRY);
    return applySuggestion(d, sg, { rules: { version: DEFAULT_RULES.version, digest: rulesDigest(DEFAULT_RULES), fired: sg.fired } });
  });
  return r;
}

const parseDoc = (text: string, path: string): unknown => (path.endsWith('.json') ? JSON.parse(text) : parseYaml(text));

export function importActions(d: Detection, o: { aud: string; ns: string }): ImportResult {
  const changes: FileChange[] = [];
  const notes: string[] = [];
  const sources: { name: string; from: 'openapi' | 'mcp'; file: string }[] = [];
  const routes: RouteVerb[] = [];
  const emit = (name: string, report: ImportReport, why: string): void => {
    const path = join('actions', `${name}.yaml`);
    if (existsSync(join(d.dir, path))) {
      notes.push(`${path} already exists and was kept (it may carry a reviewer's confirmation)`);
      return;
    }
    if (report.defs.length === 0) {
      notes.push(`${why}: no actions found`);
      return;
    }
    changes.push({ path, before: null, after: defsToYaml(o.ns, report.defs), why: `${report.defs.length} draft action${report.defs.length === 1 ? '' : 's'} from ${why} (unreviewed: every one escalates until confirmed)` });
    for (const t of report.todo.slice(0, 5)) notes.push(`import: ${path}: ${typeof t === 'string' ? t : JSON.stringify(t)}`);
  };

  const attempt = (label: string, run: () => ImportReport, name: string, src?: { from: 'openapi' | 'mcp'; file: string }, http = false): boolean => {
    try {
      const rep = suggested(run());
      if (http) {
        for (const def of rep.defs) {
          const b = def.bindings?.openapi;
          if (b?.method !== undefined && b.path !== undefined) routes.push({ method: b.method.toUpperCase(), template: b.path, verb: def.verb });
        }
      }
      emit(name, rep, label);
      if (src !== undefined && rep.defs.length > 0) sources.push({ name, ...src });
      return rep.defs.length > 0;
    } catch (e) {
      notes.push(`could not import ${label}: ${e instanceof Error ? e.message : String(e)}`);
      return false;
    }
  };

  let any = false;
  if (d.openapi !== null) {
    const f = d.openapi;
    any = attempt(`the OpenAPI file ${f}`, () => importOpenApi(parseDoc(read(join(d.dir, f)) ?? '', f), { ns: o.ns }), 'openapi', f.endsWith('.json') ? { from: 'openapi', file: f } : undefined, true) || any;
  }
  if (d.mcpTools !== null) {
    const f = d.mcpTools;
    any = attempt(`the MCP tool list ${f}`, () => importMcp(JSON.parse(read(join(d.dir, f)) ?? 'null'), { ns: o.ns }), 'mcp', { from: 'mcp', file: f }) || any;
  }
  if (d.openapi === null) {
    const routes = routesOf(d);
    if (routes.length > 0) any = attempt(`the ${routes.length} route${routes.length === 1 ? '' : 's'} found in the source`, () => importOpenApi(routesToOpenApi(o.ns, routes), { ns: o.ns }), 'routes', undefined, true) || any;
  }
  if (!any && changes.length === 0) notes.push('no OpenAPI file, MCP tool list or routes found to import; add actions later with `pca actions import`');

  if (changes.length > 0 && !existsSync(join(d.dir, 'pca.config.json'))) {
    const cfg = { ns: o.ns, version: '0.1.0', stability: 'draft', site: `http://localhost:${d.port}`, aud: o.aud, ...(sources.length > 0 ? { sources } : {}) };
    changes.push({ path: 'pca.config.json', before: null, after: JSON.stringify(cfg, null, 2) + '\n', why: 'the action project config (set `site` to the real origin before publishing)' });
  }
  routes.sort((a, z) => `${a.method} ${a.template}`.localeCompare(`${z.method} ${z.template}`));
  if (routes.length > 0 && !existsSync(join(d.dir, ROUTES_FILE))) {
    changes.push({ path: ROUTES_FILE, before: null, after: JSON.stringify(routes, null, 2) + '\n', why: 'the route to action-verb map the wiring resolves requests through (the verbs of the imported actions)' });
  }
  return { changes, notes, routes };
}
