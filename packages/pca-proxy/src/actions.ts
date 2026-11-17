/**
 * Tools and routes become PCA actions.
 *
 * MCP: the upstream's `tools/list` is imported with the action-kit importer (`importMcp` of `@atlasauth/pca-actions`, the one `@atlasauth/pca-mcp` wraps),
 * so every tool has a typed definition with its parameters. HTTP: an OpenAPI document (or the small rules form, synthesized into
 * one) is imported with `importOpenApi`. In both cases the imported definition is `unreviewed`; what the proxy does with it is
 * decided only by the operator's rule in the configuration (policy, effect, pin). The importers' own annotations and hints never
 * lower anything.
 */

import { createHash } from 'node:crypto';
import type { AgentOptions } from '@atlasauth/pca';
import { hashCanonicalLenient } from '@atlasauth/pca';
import { importMcp, importOpenApi, type ActionDef, type ParamDef } from '@atlasauth/pca-actions';
import type { ActionRule, HttpConfig, McpConfig, Reversibility } from './config';

export type Catalog = NonNullable<AgentOptions['catalog']>;

/** One action as the engine sees it. */
export interface ActionEntry {
  /** The tool name, or `METHOD /template` for a route. */
  id: string;
  verb: string;
  resource: string;
  def: ActionDef;
  rule: ActionRule;
  /** MCP: the digest of the tool definition as the upstream lists it now. */
  digest?: string;
  route?: RouteEntry;
}

export interface RouteEntry {
  method: string;
  template: string;
  /** Segment matchers in order: a literal, or a `{name}` parameter. */
  segments: Array<{ literal: string } | { param: string }>;
}

export interface McpToolDef {
  name: string;
  title?: string;
  description?: string;
  inputSchema?: unknown;
  annotations?: Record<string, unknown>;
  [k: string]: unknown;
}

/** The digest the operator pins: the whole definition the model would be shown (name, descriptions, schema, annotations). */
export function toolDigest(t: McpToolDef): string {
  return hashCanonicalLenient({ d: 'pca-proxy/tool/v1', name: t.name, title: t.title ?? null, description: t.description ?? null, inputSchema: t.inputSchema ?? null, annotations: t.annotations ?? null });
}

/** One thing the upstream lists (a tool, a resource, a resource template, a prompt) as the registry sees it. */
export interface RegItem {
  /** The key the operator's rule uses: the tool or prompt name, the resource uri or uriTemplate. */
  key: string;
  /** The same thing as an MCP tool, so the action-kit importer can type its parameters. */
  tool: McpToolDef;
  /** The digest the operator pins. */
  digest: string;
}

export interface Registry {
  /** Reviewed, unchanged: the only ones forwarded in enforce mode. */
  entries: Map<string, ActionEntry>;
  /** Every item with a rule and an imported definition, valid or not: the grant is compiled over these once, at start. */
  candidates: ActionEntry[];
  /** Listed by the upstream and not forwarded, with why (unmapped, no pin, changed after review). */
  held: Map<string, string>;
}

export interface ToolRegistry extends Registry {
  /** The upstream definitions by name (for `tools/list`). */
  tools: Map<string, McpToolDef>;
}

/**
 * Build a registry from what the upstream lists and the operator's rules. An item with no rule is unmapped; one whose rule has no
 * pin, or whose pin differs from the digest the upstream lists now (a rug pull, or an honest update) is held until the operator
 * reviews it again. Nothing here ever raises authority: a missing or stale pin only removes the item.
 */
export function buildRegistry(items: readonly RegItem[], rules: Readonly<Record<string, ActionRule>>, ns: string, kind: string): Registry {
  const entries = new Map<string, ActionEntry>();
  const candidates: ActionEntry[] = [];
  const held = new Map<string, string>();
  const defs = new Map<string, ActionDef>();
  const imp = importMcp({ tools: items.map((i) => i.tool) }, { ns });
  for (const d of imp.defs) {
    const t = d.bindings?.mcp?.tool;
    if (typeof t === 'string' && d.verb.startsWith(`${ns}.`)) defs.set(t, d);
  }
  const seen = new Set<string>();
  for (const it of items) {
    if (seen.has(it.key)) {
      held.set(it.key, `the upstream lists this ${kind} twice`);
      continue;
    }
    seen.add(it.key);
    const rule = Object.prototype.hasOwnProperty.call(rules, it.key) ? rules[it.key] : undefined;
    const def = defs.get(it.tool.name);
    const resource = `${ns}:${kind}:${it.key}`.slice(0, 200);
    if (rule !== undefined && def !== undefined) candidates.push({ id: it.key, verb: def.verb, resource, def, rule });
    if (rule === undefined) held.set(it.key, `unmapped: no rule for this ${kind} (default deny)`);
    else if (def === undefined) held.set(it.key, `the ${kind} could not be imported as an action (name or schema outside the importer limits)`);
    else if (rule.pin === undefined) held.set(it.key, `no pin: review the ${kind} and record its digest (pca-proxy review)`);
    else if (rule.pin !== it.digest) held.set(it.key, `the ${kind} definition changed since it was reviewed (re-review required)`);
    else entries.set(it.key, { id: it.key, verb: def.verb, resource, def, rule, digest: rule.pin });
  }
  return { entries, candidates, held };
}

export function buildToolRegistry(tools: readonly McpToolDef[], cfg: McpConfig): ToolRegistry {
  const byName = new Map<string, McpToolDef>();
  const items: RegItem[] = [];
  for (const t of tools) {
    if (typeof t?.name !== 'string') continue;
    if (!byName.has(t.name)) byName.set(t.name, t);
    items.push({ key: t.name, tool: t, digest: toolDigest(t) });
  }
  return { ...buildRegistry(items, cfg.tools, cfg.ns, 'tool'), tools: byName };
}

// ---- resources and prompts --------------------------------------------------------------------------------------------

/** The verb namespaces of the resource and prompt actions (kept apart from the tools' so a name can never collide). */
export const resNs = (ns: string): string => `${ns.slice(0, 26)}_res`;
export const prmNs = (ns: string): string => `${ns.slice(0, 26)}_prm`;

const hex6 = (s: string): string => createHash('sha256').update(s).digest('hex').slice(0, 6);
const slug = (s: string): string => s.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 20) || 'x';
const pseudo = (kind: string, key: string): string => `${kind}_${slug(key)}_${hex6(key)}`;

export interface ListedResource { uri: string; name?: string; title?: string; description?: string; mimeType?: string; annotations?: unknown; [k: string]: unknown }
export interface ListedTemplate { uriTemplate: string; name?: string; title?: string; description?: string; mimeType?: string; annotations?: unknown; [k: string]: unknown }
export interface ListedPrompt { name: string; title?: string; description?: string; arguments?: Array<{ name: string; description?: string; required?: boolean }>; [k: string]: unknown }

export const resourceDigest = (r: ListedResource): string => hashCanonicalLenient({ d: 'pca-proxy/resource/v1', uri: r.uri, name: r.name ?? null, title: r.title ?? null, description: r.description ?? null, mimeType: r.mimeType ?? null, annotations: r.annotations ?? null });
export const templateDigest = (r: ListedTemplate): string => hashCanonicalLenient({ d: 'pca-proxy/template/v1', uriTemplate: r.uriTemplate, name: r.name ?? null, title: r.title ?? null, description: r.description ?? null, mimeType: r.mimeType ?? null, annotations: r.annotations ?? null });
export const promptDigest = (p: ListedPrompt): string => hashCanonicalLenient({ d: 'pca-proxy/prompt/v1', name: p.name, title: p.title ?? null, description: p.description ?? null, arguments: p.arguments ?? null });

/** A uriTemplate as a matcher. Only `{name}` and `{+name}` are understood; anything else (query, fragment, label forms) is not mappable. */
export function compileTemplate(t: string): { re: RegExp; vars: string[] } | undefined {
  const vars: string[] = [];
  let src = '';
  let last = 0;
  for (const m of t.matchAll(/\{([^{}]*)\}/g)) {
    const lit = t.slice(last, m.index);
    if (/[{}]/.test(lit)) return undefined;
    const body = m[1]!;
    const reserved = body.startsWith('+');
    const name = reserved ? body.slice(1) : body;
    if (!/^[A-Za-z0-9_]{1,40}$/.test(name) || vars.includes(name)) return undefined;
    if (lit === '' && vars.length > 0) return undefined; // two expressions with nothing between them cannot be split
    src += lit.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + (reserved ? '(.+)' : "([A-Za-z0-9._~%!$&'()*+,;=:@-]+)");
    vars.push(name);
    last = m.index! + m[0].length;
  }
  const tail = t.slice(last);
  if (/[{}]/.test(tail)) return undefined;
  src += tail.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return { re: new RegExp(`^${src}$`), vars };
}

/** A value taken out of a uri must not walk (dot segments, encoded dots, slashes or control characters). */
export function badUriValue(v: string): string | undefined {
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f\\]/.test(v)) return 'a control character or backslash';
  if (v.split('/').some((s) => s === '.' || s === '..')) return 'a dot segment';
  if (/%(2e|2f|5c|00)/i.test(v)) return 'an encoded dot, slash or NUL';
  return undefined;
}

export function resourceItems(listed: readonly ListedResource[]): RegItem[] {
  return listed.filter((r) => typeof r?.uri === 'string').map((r) => ({ key: r.uri, tool: { name: pseudo('read', r.uri), description: r.description ?? r.name ?? r.uri, inputSchema: { type: 'object', properties: {} } }, digest: resourceDigest(r) }));
}
export function templateItems(listed: readonly ListedTemplate[]): RegItem[] {
  const out: RegItem[] = [];
  for (const r of listed) {
    if (typeof r?.uriTemplate !== 'string') continue;
    const c = compileTemplate(r.uriTemplate);
    if (c === undefined) continue; // an unsupported template is simply unmapped: a read of it never matches
    out.push({ key: r.uriTemplate, tool: { name: pseudo('read', r.uriTemplate), description: r.description ?? r.name ?? r.uriTemplate, inputSchema: { type: 'object', properties: Object.fromEntries(c.vars.map((v) => [v, { type: 'string', maxLength: 2048 }])), required: c.vars } }, digest: templateDigest(r) });
  }
  return out;
}
export function promptItems(listed: readonly ListedPrompt[]): RegItem[] {
  return listed.filter((p) => typeof p?.name === 'string').map((p) => {
    const args = Array.isArray(p.arguments) ? p.arguments.filter((a) => typeof a?.name === 'string') : [];
    return { key: p.name, tool: { name: pseudo('get', p.name), description: p.description ?? p.name, inputSchema: { type: 'object', properties: Object.fromEntries(args.map((a) => [a.name, { type: 'string', maxLength: 65_536 }])), required: args.filter((a) => a.required === true).map((a) => a.name) } }, digest: promptDigest(p) };
  });
}

// ---- HTTP ------------------------------------------------------------------------------------------------------------

const METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'];

/** A synthesized OpenAPI 3 document from the hand-written rules (`http.routes`). */
export function openApiFromRoutes(cfg: HttpConfig): Record<string, unknown> {
  const paths: Record<string, Record<string, unknown>> = {};
  cfg.routes.forEach((r, i) => {
    const name = r.name ?? `${r.method.toLowerCase()}_${r.path.replace(/[^A-Za-z0-9]+/g, '_').replace(/^_|_$/g, '')}`;
    const op: Record<string, unknown> = { operationId: name };
    const parameters = [...r.path.matchAll(/\{([A-Za-z0-9_]+)\}/g)].map((m) => ({ name: m[1], in: 'path', required: true, schema: { type: 'string' } }));
    const schema = r.schema ?? { type: 'object', properties: {} };
    if (r.method === 'GET' || r.method === 'DELETE' || r.method === 'HEAD') {
      const props = (schema.properties ?? {}) as Record<string, unknown>;
      const req = new Set(Array.isArray(schema.required) ? (schema.required as string[]) : []);
      for (const [k, v] of Object.entries(props)) parameters.push({ name: k, in: 'query', required: req.has(k), schema: v } as never);
    } else op.requestBody = { required: true, content: { 'application/json': { schema } } };
    if (parameters.length > 0) op.parameters = parameters;
    const item = (paths[r.path] ??= {});
    const m = r.method.toLowerCase();
    if (!METHODS.includes(m) || Object.prototype.hasOwnProperty.call(item, m)) throw new Error(`http.routes[${i}]: ${r.method} ${r.path} is repeated or not an HTTP method`);
    item[m] = op;
  });
  return { openapi: '3.0.3', info: { title: 'pca-proxy rules', version: '1' }, paths };
}

export function templateOf(path: string): RouteEntry['segments'] {
  return path.split('/').slice(1).map((s) => {
    const m = /^\{([A-Za-z0-9_]+)\}$/.exec(s);
    return m ? { param: m[1]! } : { literal: s };
  });
}

/**
 * Import the operations of `doc` and attach the operator's rule. A rule is keyed by `operationId` or `METHOD /path`; an operation
 * with none is unmapped and denied. `routeRules` are the rules of `http.routes` (keyed by the synthesized operation id).
 */
export function buildRouteRegistry(doc: unknown, cfg: HttpConfig, routeRules: Map<string, ActionRule>): { entries: ActionEntry[]; held: Map<string, string> } {
  const report = importOpenApi(doc, { ns: cfg.ns });
  const entries: ActionEntry[] = [];
  const held = new Map<string, string>();
  for (const def of report.defs) {
    const b = def.bindings?.openapi;
    if (b?.method === undefined || b.path === undefined) continue;
    const id = `${b.method} ${b.path}`;
    const own = (m: Record<string, ActionRule> | Map<string, ActionRule>, k: string): ActionRule | undefined => (m instanceof Map ? m.get(k) : Object.prototype.hasOwnProperty.call(m, k) ? m[k] : undefined);
    const rule = own(routeRules, b.operationId) ?? own(cfg.actions, b.operationId) ?? own(cfg.actions, id);
    if (rule === undefined) {
      held.set(id, 'unmapped: no rule for this operation (default deny)');
      continue;
    }
    entries.push({ id, verb: def.verb, resource: `${cfg.ns}:${b.operationId}`.slice(0, 200), def, rule, route: { method: b.method, template: b.path, segments: templateOf(b.path) } });
  }
  for (const t of report.todo) if (t.code === 'skipped_op') held.set(t.where, t.message);
  // the more literal a template, the earlier it is tried, so `/accounts/me` beats `/accounts/{id}`
  entries.sort((a, z) => z.route!.segments.filter((s) => 'literal' in s).length - a.route!.segments.filter((s) => 'literal' in s).length);
  return { entries, held };
}

/** Match a request path to a route; `undefined` when none matches. Segments are matched exactly, never by prefix. */
export function matchRoute(entries: readonly ActionEntry[], method: string, path: string): { entry: ActionEntry; params: Record<string, string> } | undefined {
  const parts = path.split('/').slice(1);
  for (const e of entries) {
    const r = e.route!;
    if (r.method !== method || r.segments.length !== parts.length) continue;
    const params: Record<string, string> = Object.create(null) as Record<string, string>;
    let ok = true;
    for (let i = 0; i < parts.length && ok; i++) {
      const s = r.segments[i]!;
      const p = parts[i]!;
      if ('literal' in s) ok = s.literal === p;
      else if (p.length === 0) ok = false;
      else {
        try {
          params[s.param] = decodeURIComponent(p);
        } catch {
          ok = false;
        }
      }
    }
    if (ok) return { entry: e, params };
  }
  return undefined;
}

// ---- the grant's catalog ---------------------------------------------------------------------------------------------

const BLAST: Record<Reversibility | 'read', number> = { read: 0.05, reversible: 0.2, rate_limited: 0.5, irreversible: 0.8 };

export interface Spec {
  connector: string;
  action: string;
  verb: string;
  reversibility: Reversibility;
  blastRadius: number;
  amountField?: string;
  description: string;
}

/** The catalog spec of an entry: a read is reversible and cheap; a write is irreversible and expensive unless the operator says otherwise. */
export function specOf(e: ActionEntry): Spec {
  const dot = e.verb.indexOf('.');
  const rev: Reversibility = e.rule.effect === 'read' ? 'reversible' : (e.rule.reversibility ?? 'irreversible');
  return {
    connector: e.verb.slice(0, dot),
    action: e.verb.slice(dot + 1),
    verb: e.verb,
    reversibility: rev,
    blastRadius: e.rule.effect === 'read' ? BLAST.read : BLAST[rev],
    ...(e.rule.amountField !== undefined ? { amountField: e.rule.amountField } : {}),
    description: (e.def.title ?? e.verb).slice(0, 200),
  };
}

export function catalogOf(specs: readonly Spec[]): Catalog {
  const by = new Map(specs.map((s) => [s.verb, s]));
  return { get: (v) => by.get(v), forConnector: (c) => specs.filter((s) => s.connector === c), all: () => [...specs], resolve: (c, a) => by.get(`${c}.${a}`) } as Catalog;
}

/** The provenance facts of an action: only what the operator declared. A `write` is sensitive; nothing is read off a hint. */
export function provInfo(e: ActionEntry): { effects: string[]; traits: string[] } {
  return { effects: e.rule.effect === 'read' ? ['read'] : ['update'], traits: [] };
}

export type { ParamDef };
