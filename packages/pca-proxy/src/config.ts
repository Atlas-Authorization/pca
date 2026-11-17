/**
 * The one configuration file: `pca-proxy.json`, `pca-proxy.yaml` or `pca-proxy.yml`.
 *
 * The parser is strict: an unknown key, a wrong type or a missing required value is an error that names the path, and the proxy
 * does not start. Secrets never live in the file: a value that must be secret is read from the environment variable the file names
 * (`principalKeyEnv`, `secretEnv`, `tokenEnv`), and `${NAME}` inside an upstream header value is replaced from the environment.
 */

import { readFileSync } from 'node:fs';
import { extname } from 'node:path';
import { parseLimit } from '@atlasauth/pca';
import { parse as parseYaml } from 'yaml';

export type Mode = 'enforce' | 'observe';
export type Policy = 'allow' | 'approve' | 'deny';
export type Effect = 'read' | 'write';
export type Reversibility = 'reversible' | 'rate_limited' | 'irreversible';

/** What the operator decided about one tool or route. This is the human decision; nothing is inferred into it. */
export interface ActionRule {
  /** `allow`: forward when the grant and the provenance gate agree. `approve`: a human approves every call. `deny`: never. */
  policy: Policy;
  /** `read`: the call only reads. `write`: anything else (the default is the dangerous one). */
  effect: Effect;
  reversibility?: Reversibility;
  /** A limit on the grant: `10/hour`, or `$100/day` together with `amountField`. */
  limit?: string;
  /** The argument that carries a money amount (a `$` limit becomes a per-call ceiling on it). */
  amountField?: string;
  /** MCP only: the digest of the tool definition the operator reviewed. A changed definition is denied until re-reviewed. */
  pin?: string;
  /**
   * DANGEROUS. By default a `write` tool with policy `allow` is held for a human once the session has relayed untrusted content
   * (any tool result). Set this to keep forwarding after that: injected content can then steer this tool within its limits.
   */
  insecureAllowAfterUntrusted?: boolean;
}

export type McpUpstream = { command: string; args?: string[]; env?: Record<string, string> } | { url: string; headers?: Record<string, string> };

export interface McpListen {
  host: string;
  port: number;
  path: string;
  /** Named clients and the environment variable that holds each one's bearer token. A session belongs to the client that opened it. */
  clients: Record<string, { tokenEnv: string }>;
  /** Origins a browser may call from. An `Origin` header that is not listed is refused (DNS-rebinding protection); no header is fine. */
  allowedOrigins: string[];
  /** `Host` header values accepted (default: the loopback names when listening on loopback). */
  allowedHosts?: string[];
  /** DANGEROUS: serve with no authentication. Only accepted on a loopback address. */
  insecureNoAuth: boolean;
  maxSessions: number;
  idleSeconds: number;
}

export interface McpConfig {
  /** The server to protect: a command to run (stdio) or a streamable-HTTP URL. The command line flags override it. */
  upstream?: McpUpstream;
  /** The namespace of the verbs the tools become (`github` gives `github.create_issue`). */
  ns: string;
  tools: Record<string, ActionRule>;
  /** Resources the client may read, keyed by the exact `uri` or the `uriTemplate` the server lists. Pinned like tools; the default effect is `read`. */
  resources: Record<string, ActionRule>;
  /** Prompts the client may get, keyed by prompt name. Pinned like tools; the default effect is `read`. */
  prompts: Record<string, ActionRule>;
  /** Serve MCP over streamable HTTP as well (remote and hosted clients). */
  listen?: McpListen;
  /** How long a tool list is trusted before the proxy asks the upstream again (default 30). */
  relistSeconds?: number;
  /** Server-to-client requests that are relayed (default `roots/list` and `ping`); every other one is refused. */
  allowServerRequests?: string[];
}

export interface RouteCfg extends ActionRule {
  method: string;
  /** `/orders/{id}`. */
  path: string;
  name?: string;
  /** A JSON Schema (`type: object`, `properties`, `required`) for the body (or the query of a GET). */
  schema?: Record<string, unknown>;
}

export interface HttpConfig {
  upstream: string;
  listen: { host: string; port: number };
  /** `sidecar`: the proxy mints the proofs from its own grant. `verify`: the caller sends `PCA-Action` and the proxy verifies it. */
  mode: 'sidecar' | 'verify';
  ns: string;
  /** An OpenAPI 3 / Swagger 2 document (JSON or YAML file). */
  openapi?: string;
  /** Decisions per operation, keyed by `operationId` or `METHOD /path`. */
  actions: Record<string, ActionRule>;
  /** The small rules file form: routes written by hand. */
  routes: RouteCfg[];
  /** Headers added to every upstream request; `${NAME}` is replaced from the environment (keeps the upstream credential off the agent). */
  upstreamHeaders: Record<string, string>;
  /** Verify mode: the grants (JSON files of encoded capabilities) the proofs must descend from. */
  grants: string[];
  /** Request headers (besides a short built-in list) that are passed to the upstream, for an agent that still brings its own credential. */
  forwardHeaders: string[];
  /**
   * The request header that names the agent session. Unset (the default): every caller shares one session, so untrusted content
   * seen by one holds writes for all. Set it only when a trusted layer in front of the proxy writes the header, never the agent.
   */
  sessionHeader?: string;
  /** Sidecar mode: also send the minted proof upstream as `PCA-Action` (for an upstream that sits behind another verifier). */
  attachProof: boolean;
}

export interface ProxyConfig {
  mode: Mode;
  audience: string;
  budget: { max: number };
  /** `issuedGrant`: a human-signed grant to enforce (its envelope admits or refuses each call) and the public key that must have signed it. */
  agent: { principalKeyEnv?: string; goal: string; revocationFile?: string; issuedGrant?: { file: string; signer: string } };
  mcp?: McpConfig;
  http?: HttpConfig;
  /**
   * Where the replay counters, the budget, the grant's identity and the session taint live. `file` (default) is crash-safe,
   * hash-chained and survives a restart; `memory` is for development only and must be asked for.
   */
  state: { backend: 'file' | 'memory'; dir: string; hmacKeyEnv?: string };
  approvals: { store?: string; waitSeconds: number; webhook?: { url: string; secretEnv: string } };
  audit: { path?: string; observedParams?: { enabled: boolean; include: string[] }; observedParamsPath?: string };
  otel: boolean;
  limits: { maxRequestBytes: number; maxResponseBytes: number; upstreamTimeoutMs: number };
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === 'object' && !Array.isArray(v);

function closed(v: unknown, path: string, keys: readonly string[]): Obj {
  if (!isObj(v)) throw new ConfigError(`${path}: expected an object`);
  for (const k of Object.keys(v)) if (!keys.includes(k)) throw new ConfigError(`${path}: unknown key '${k}' (allowed: ${keys.join(', ')})`);
  return v;
}
function str(v: unknown, path: string, opts: { max?: number; optional?: boolean } = {}): string | undefined {
  if (v === undefined && opts.optional) return undefined;
  if (typeof v !== 'string' || v.length === 0 || v.length > (opts.max ?? 2048)) throw new ConfigError(`${path}: expected a non-empty string`);
  return v;
}
function oneOf<T extends string>(v: unknown, path: string, allowed: readonly T[], dflt?: T): T {
  if (v === undefined && dflt !== undefined) return dflt;
  if (typeof v !== 'string' || !(allowed as readonly string[]).includes(v)) throw new ConfigError(`${path}: expected one of ${allowed.join(', ')}`);
  return v as T;
}
function int(v: unknown, path: string, dflt: number, min: number, max: number): number {
  if (v === undefined) return dflt;
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < min || v > max) throw new ConfigError(`${path}: expected an integer from ${min} to ${max}`);
  return v;
}
function bool(v: unknown, path: string, dflt: boolean): boolean {
  if (v === undefined) return dflt;
  if (typeof v !== 'boolean') throw new ConfigError(`${path}: expected true or false`);
  return v;
}

const NS_RE = /^[a-z][a-z0-9_]{0,31}$/;
const RULE_KEYS = ['policy', 'effect', 'reversibility', 'limit', 'amountField', 'pin', 'insecureAllowAfterUntrusted'] as const;

export function parseRule(v: unknown, path: string, extra: readonly string[] = [], dfltEffect: Effect = 'write'): ActionRule {
  const o = closed(v, path, [...RULE_KEYS, ...extra]);
  const policy = oneOf(o.policy, `${path}.policy`, ['allow', 'approve', 'deny'] as const);
  // the dangerous default: anything not declared read-only is a write
  const effect = oneOf(o.effect, `${path}.effect`, ['read', 'write'] as const, dfltEffect);
  const rule: ActionRule = { policy, effect };
  if (o.reversibility !== undefined) rule.reversibility = oneOf(o.reversibility, `${path}.reversibility`, ['reversible', 'rate_limited', 'irreversible'] as const);
  const limit = str(o.limit, `${path}.limit`, { optional: true, max: 64 });
  if (limit !== undefined) rule.limit = limit;
  const af = str(o.amountField, `${path}.amountField`, { optional: true, max: 128 });
  if (af !== undefined) rule.amountField = af;
  if (limit !== undefined) {
    let p: ReturnType<typeof parseLimit>;
    try {
      p = parseLimit(limit);
    } catch (e) {
      throw new ConfigError(`${path}.limit: ${e instanceof Error ? e.message : 'not a limit'}`);
    }
    if (p.unit === 'count' && p.periodMs === undefined) throw new ConfigError(`${path}.limit: a count limit needs a period (10/hour)`);
    if (p.unit === 'usd' && af === undefined) throw new ConfigError(`${path}.limit: a $ limit needs amountField (the argument that carries the amount)`);
  }
  const pin = str(o.pin, `${path}.pin`, { optional: true, max: 128 });
  if (pin !== undefined) rule.pin = pin;
  if (o.insecureAllowAfterUntrusted !== undefined) rule.insecureAllowAfterUntrusted = bool(o.insecureAllowAfterUntrusted, `${path}.insecureAllowAfterUntrusted`, false);
  return rule;
}

/** Validate a parsed configuration document into a {@link ProxyConfig} (every default filled). */
export function parseConfig(doc: unknown): ProxyConfig {
  const o = closed(doc, 'config', ['mode', 'audience', 'budget', 'agent', 'mcp', 'http', 'state', 'approvals', 'audit', 'otel', 'limits']);
  const mode = oneOf(o.mode, 'mode', ['enforce', 'observe'] as const, 'enforce');
  const audience = str(o.audience, 'audience', { optional: true, max: 256 }) ?? 'pca-proxy';
  const budget = o.budget === undefined ? {} : closed(o.budget, 'budget', ['max']);
  const bmax = budget.max === undefined ? 100 : budget.max;
  if (typeof bmax !== 'number' || !Number.isFinite(bmax) || bmax <= 0 || bmax > 1_000_000) throw new ConfigError('budget.max: expected a number above 0');
  const ag = o.agent === undefined ? {} : closed(o.agent, 'agent', ['principalKeyEnv', 'goal', 'revocationFile', 'issuedGrant']);
  const agent: ProxyConfig['agent'] = { goal: str(ag.goal, 'agent.goal', { optional: true, max: 512 }) ?? 'act through the pca-proxy under the operator rules' };
  const pk = str(ag.principalKeyEnv, 'agent.principalKeyEnv', { optional: true, max: 128 });
  if (pk !== undefined) agent.principalKeyEnv = pk;
  const rf = str(ag.revocationFile, 'agent.revocationFile', { optional: true });
  if (rf !== undefined) agent.revocationFile = rf;
  if (ag.issuedGrant !== undefined) {
    const ig = closed(ag.issuedGrant, 'agent.issuedGrant', ['file', 'signer']);
    const file = str(ig.file, 'agent.issuedGrant.file') as string;
    const signer = str(ig.signer, 'agent.issuedGrant.signer') as string;
    if (!/^[A-Za-z0-9_-]{43}$/.test(signer)) throw new ConfigError('agent.issuedGrant.signer: expected a raw Ed25519 public key in base64url (43 characters)');
    agent.issuedGrant = { file, signer };
  }

  const cfg: ProxyConfig = {
    mode,
    audience,
    budget: { max: bmax },
    agent,
    state: { backend: 'file', dir: './pca-proxy-state' },
    approvals: { waitSeconds: 120 },
    audit: {},
    otel: false,
    limits: { maxRequestBytes: 262_144, maxResponseBytes: 1_048_576, upstreamTimeoutMs: 30_000 },
  };

  if (o.mcp !== undefined) {
    const m = closed(o.mcp, 'mcp', ['upstream', 'ns', 'tools', 'resources', 'prompts', 'listen', 'relistSeconds', 'allowServerRequests']);
    const ns = str(m.ns, 'mcp.ns', { max: 32 })!;
    if (!NS_RE.test(ns)) throw new ConfigError('mcp.ns: expected [a-z][a-z0-9_]{0,31}');
    const tools: Record<string, ActionRule> = Object.create(null) as Record<string, ActionRule>;
    for (const [name, r] of Object.entries(m.tools === undefined ? {} : closed(m.tools, 'mcp.tools', Object.keys(isObj(m.tools) ? m.tools : {})))) tools[name] = parseRule(r, `mcp.tools.${name}`);
    const ruleMap = (v: unknown, path: string): Record<string, ActionRule> => {
      const out: Record<string, ActionRule> = Object.create(null) as Record<string, ActionRule>;
      if (v === undefined) return out;
      for (const [k, r] of Object.entries(closed(v, path, Object.keys(isObj(v) ? v : {})))) {
        if (k.length === 0 || k.length > 512) throw new ConfigError(`${path}: a key must be 1 to 512 characters`);
        out[k] = parseRule(r, `${path}.${k}`, [], 'read');
      }
      return out;
    };
    const mc: McpConfig = { ns, tools, resources: ruleMap(m.resources, 'mcp.resources'), prompts: ruleMap(m.prompts, 'mcp.prompts') };
    if (m.listen !== undefined) {
      const l = closed(m.listen, 'mcp.listen', ['host', 'port', 'path', 'clients', 'allowedOrigins', 'allowedHosts', 'insecureNoAuth', 'maxSessions', 'idleSeconds']);
      const host = str(l.host, 'mcp.listen.host', { optional: true, max: 255 }) ?? '127.0.0.1';
      const insecure = bool(l.insecureNoAuth, 'mcp.listen.insecureNoAuth', false);
      const clients: McpListen['clients'] = Object.create(null) as McpListen['clients'];
      if (l.clients !== undefined) for (const [name, v] of Object.entries(closed(l.clients, 'mcp.listen.clients', Object.keys(isObj(l.clients) ? l.clients : {})))) {
        if (!/^[A-Za-z0-9._-]{1,32}$/.test(name)) throw new ConfigError(`mcp.listen.clients.${name}: a client name is 1 to 32 of A-Za-z0-9._-`);
        clients[name] = { tokenEnv: str(closed(v, `mcp.listen.clients.${name}`, ['tokenEnv']).tokenEnv, `mcp.listen.clients.${name}.tokenEnv`, { max: 128 })! };
      }
      const loopback = host === '127.0.0.1' || host === '::1' || host === 'localhost';
      if (Object.keys(clients).length === 0 && !(insecure && loopback)) throw new ConfigError('mcp.listen: name at least one client with a tokenEnv (insecureNoAuth works only on a loopback address)');
      if (Object.keys(clients).length > 0 && insecure) throw new ConfigError('mcp.listen: insecureNoAuth and clients cannot be combined');
      const strList = (v: unknown, path: string): string[] => {
        if (v === undefined) return [];
        if (!Array.isArray(v) || !v.every((x) => typeof x === 'string' && x.length > 0 && x !== '*')) throw new ConfigError(`${path}: expected a list of exact values (no *)`);
        return [...(v as string[])];
      };
      mc.listen = {
        host,
        port: int(l.port, 'mcp.listen.port', 8789, 0, 65_535),
        path: str(l.path, 'mcp.listen.path', { optional: true, max: 128 }) ?? '/mcp',
        clients,
        allowedOrigins: strList(l.allowedOrigins, 'mcp.listen.allowedOrigins'),
        insecureNoAuth: insecure,
        maxSessions: int(l.maxSessions, 'mcp.listen.maxSessions', 64, 1, 10_000),
        idleSeconds: int(l.idleSeconds, 'mcp.listen.idleSeconds', 1800, 10, 86_400),
        ...(l.allowedHosts !== undefined ? { allowedHosts: strList(l.allowedHosts, 'mcp.listen.allowedHosts') } : {}),
      };
      if (!mc.listen.path.startsWith('/')) throw new ConfigError('mcp.listen.path: expected a path starting with /');
    }
    if (m.upstream !== undefined) {
      const u = closed(m.upstream, 'mcp.upstream', ['command', 'args', 'env', 'url', 'headers']);
      const strMap = (v: unknown, path: string): Record<string, string> | undefined => {
        if (v === undefined) return undefined;
        const out: Record<string, string> = {};
        for (const [k, x] of Object.entries(closed(v, path, Object.keys(isObj(v) ? v : {})))) out[k] = str(x, `${path}.${k}`)!;
        return out;
      };
      if ((u.command === undefined) === (u.url === undefined)) throw new ConfigError('mcp.upstream: give exactly one of command or url');
      if (u.command !== undefined) {
        if (u.args !== undefined && (!Array.isArray(u.args) || !u.args.every((x) => typeof x === 'string'))) throw new ConfigError('mcp.upstream.args: expected a list of strings');
        const env = strMap(u.env, 'mcp.upstream.env');
        mc.upstream = { command: str(u.command, 'mcp.upstream.command')!, ...(u.args !== undefined ? { args: [...(u.args as string[])] } : {}), ...(env ? { env } : {}) };
      } else {
        const headers = strMap(u.headers, 'mcp.upstream.headers');
        mc.upstream = { url: str(u.url, 'mcp.upstream.url')!, ...(headers ? { headers } : {}) };
      }
    }
    if (m.relistSeconds !== undefined) mc.relistSeconds = int(m.relistSeconds, 'mcp.relistSeconds', 30, 1, 86_400);
    if (m.allowServerRequests !== undefined) {
      if (!Array.isArray(m.allowServerRequests) || !m.allowServerRequests.every((x) => typeof x === 'string')) throw new ConfigError('mcp.allowServerRequests: expected a list of method names');
      mc.allowServerRequests = [...(m.allowServerRequests as string[])];
    }
    cfg.mcp = mc;
  }

  if (o.http !== undefined) {
    const h = closed(o.http, 'http', ['upstream', 'listen', 'mode', 'ns', 'openapi', 'actions', 'routes', 'upstreamHeaders', 'forwardHeaders', 'grants', 'sessionHeader', 'attachProof']);
    const upstream = str(h.upstream, 'http.upstream')!;
    let u: URL;
    try {
      u = new URL(upstream);
    } catch {
      throw new ConfigError('http.upstream: expected an absolute http(s) URL');
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new ConfigError('http.upstream: expected an http or https URL');
    const l = h.listen === undefined ? {} : closed(h.listen, 'http.listen', ['host', 'port']);
    const ns = str(h.ns, 'http.ns', { optional: true, max: 32 }) ?? 'api';
    if (!NS_RE.test(ns)) throw new ConfigError('http.ns: expected [a-z][a-z0-9_]{0,31}');
    const actions: Record<string, ActionRule> = Object.create(null) as Record<string, ActionRule>;
    if (h.actions !== undefined) for (const [k, r] of Object.entries(closed(h.actions, 'http.actions', Object.keys(isObj(h.actions) ? h.actions : {})))) actions[k] = parseRule(r, `http.actions.${k}`);
    const routes: RouteCfg[] = [];
    if (h.routes !== undefined) {
      if (!Array.isArray(h.routes)) throw new ConfigError('http.routes: expected a list');
      h.routes.forEach((r, i) => {
        const p = `http.routes[${i}]`;
        const ro = closed(r, p, [...RULE_KEYS, 'method', 'path', 'name', 'schema']);
        const rule = parseRule({ ...ro, method: undefined, path: undefined, name: undefined, schema: undefined }, p, ['method', 'path', 'name', 'schema']);
        const route: RouteCfg = { ...rule, method: str(ro.method, `${p}.method`, { max: 10 })!.toUpperCase(), path: str(ro.path, `${p}.path`, { max: 512 })! };
        if (!/^[A-Z]{3,7}$/.test(route.method)) throw new ConfigError(`${p}.method: expected an HTTP method`);
        if (!route.path.startsWith('/')) throw new ConfigError(`${p}.path: expected a path starting with /`);
        const nm = str(ro.name, `${p}.name`, { optional: true, max: 64 });
        if (nm !== undefined) route.name = nm;
        if (ro.schema !== undefined) {
          if (!isObj(ro.schema)) throw new ConfigError(`${p}.schema: expected a JSON Schema object`);
          route.schema = ro.schema;
        }
        routes.push(route);
      });
    }
    const uh: Record<string, string> = {};
    if (h.upstreamHeaders !== undefined) for (const [k, v] of Object.entries(closed(h.upstreamHeaders, 'http.upstreamHeaders', Object.keys(isObj(h.upstreamHeaders) ? h.upstreamHeaders : {})))) {
      if (!/^[A-Za-z0-9-]{1,64}$/.test(k)) throw new ConfigError(`http.upstreamHeaders.${k}: not a header name`);
      uh[k] = str(v, `http.upstreamHeaders.${k}`)!;
    }
    let forwardHeaders: string[] = [];
    if (h.forwardHeaders !== undefined) {
      if (!Array.isArray(h.forwardHeaders) || !h.forwardHeaders.every((x) => typeof x === 'string' && /^[A-Za-z0-9-]{1,64}$/.test(x) && !/^(x-)?pca-/i.test(x))) throw new ConfigError('http.forwardHeaders: expected a list of header names (none may start with pca- or x-pca-)');
      forwardHeaders = (h.forwardHeaders as string[]).map((x) => x.toLowerCase());
    }
    let grants: string[] = [];
    if (h.grants !== undefined) {
      if (!Array.isArray(h.grants) || !h.grants.every((x) => typeof x === 'string' && x.length > 0)) throw new ConfigError('http.grants: expected a list of file paths');
      grants = [...(h.grants as string[])];
    }
    const hc: HttpConfig = {
      upstream,
      listen: { host: str(l.host, 'http.listen.host', { optional: true, max: 255 }) ?? '127.0.0.1', port: int(l.port, 'http.listen.port', 8788, 0, 65_535) },
      mode: oneOf(h.mode, 'http.mode', ['sidecar', 'verify'] as const, 'sidecar'),
      ns,
      actions,
      routes,
      upstreamHeaders: uh,
      forwardHeaders,
      grants,
      attachProof: bool(h.attachProof, 'http.attachProof', false),
    };
    const oa = str(h.openapi, 'http.openapi', { optional: true });
    if (oa !== undefined) hc.openapi = oa;
    const sh = str(h.sessionHeader, 'http.sessionHeader', { optional: true, max: 64 });
    if (sh !== undefined) hc.sessionHeader = sh.toLowerCase();
    if (hc.mode === 'verify' && grants.length === 0) throw new ConfigError('http.grants: verify mode needs the grants the proofs must descend from');
    if (hc.openapi === undefined && routes.length === 0) throw new ConfigError('http: give an openapi document, routes, or both (an unmapped API is denied)');
    cfg.http = hc;
  }
  if (cfg.mcp === undefined && cfg.http === undefined) throw new ConfigError("config: give an 'mcp' or an 'http' section");

  if (o.state !== undefined) {
    const s = closed(o.state, 'state', ['backend', 'dir', 'hmacKeyEnv']);
    cfg.state = { backend: oneOf(s.backend, 'state.backend', ['file', 'memory'] as const, 'file'), dir: str(s.dir, 'state.dir', { optional: true }) ?? './pca-proxy-state' };
    const hk = str(s.hmacKeyEnv, 'state.hmacKeyEnv', { optional: true, max: 128 });
    if (hk !== undefined) cfg.state.hmacKeyEnv = hk;
  }
  if (o.approvals !== undefined) {
    const a = closed(o.approvals, 'approvals', ['store', 'waitSeconds', 'webhook']);
    const store = str(a.store, 'approvals.store', { optional: true });
    if (store !== undefined) cfg.approvals.store = store;
    cfg.approvals.waitSeconds = int(a.waitSeconds, 'approvals.waitSeconds', 120, 1, 3600);
    if (a.webhook !== undefined) {
      const w = closed(a.webhook, 'approvals.webhook', ['url', 'secretEnv']);
      cfg.approvals.webhook = { url: str(w.url, 'approvals.webhook.url')!, secretEnv: str(w.secretEnv, 'approvals.webhook.secretEnv', { max: 128 })! };
    }
  }
  if (o.audit !== undefined) {
    const a = closed(o.audit, 'audit', ['path', 'observedParams', 'observedParamsPath']);
    const p = str(a.path, 'audit.path', { optional: true });
    if (p !== undefined) cfg.audit.path = p;
    if (a.observedParams !== undefined) {
      const op = closed(a.observedParams, 'audit.observedParams', ['enabled', 'include']);
      let include: string[] = [];
      if (op.include !== undefined) {
        if (!Array.isArray(op.include) || !op.include.every((x) => typeof x === 'string' && /^[A-Za-z0-9_.]{1,64}$/.test(x))) throw new ConfigError('audit.observedParams.include: expected a list of parameter names');
        include = [...(op.include as string[])];
      }
      cfg.audit.observedParams = { enabled: bool(op.enabled, 'audit.observedParams.enabled', false), include };
    }
    const pp = str(a.observedParamsPath, 'audit.observedParamsPath', { optional: true });
    if (pp !== undefined) cfg.audit.observedParamsPath = pp;
  }
  cfg.otel = bool(o.otel, 'otel', false);
  if (o.limits !== undefined) {
    const l = closed(o.limits, 'limits', ['maxRequestBytes', 'maxResponseBytes', 'upstreamTimeoutMs']);
    cfg.limits = {
      maxRequestBytes: int(l.maxRequestBytes, 'limits.maxRequestBytes', 262_144, 1024, 64 * 1024 * 1024),
      maxResponseBytes: int(l.maxResponseBytes, 'limits.maxResponseBytes', 1_048_576, 1024, 256 * 1024 * 1024),
      upstreamTimeoutMs: int(l.upstreamTimeoutMs, 'limits.upstreamTimeoutMs', 30_000, 100, 600_000),
    };
  }
  return cfg;
}

/** Parse configuration text (`format` json or yaml). A duplicate YAML key is an error, not a silent last-wins. */
export function parseConfigText(text: string, format: 'json' | 'yaml'): ProxyConfig {
  let doc: unknown;
  try {
    doc = format === 'json' ? JSON.parse(text) : parseYaml(text, { strict: true, uniqueKeys: true, maxAliasCount: 0 });
  } catch (e) {
    throw new ConfigError(`config: not valid ${format}: ${e instanceof Error ? e.message : 'parse error'}`);
  }
  return parseConfig(doc);
}

/** Read a configuration file (`.json`, `.yaml`, `.yml`). */
export function loadConfig(path: string): ProxyConfig {
  const ext = extname(path).toLowerCase();
  if (ext !== '.json' && ext !== '.yaml' && ext !== '.yml') throw new ConfigError(`config: ${path} must end in .json, .yaml or .yml`);
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (e) {
    throw new ConfigError(`config: cannot read ${path}: ${e instanceof Error ? e.message : 'error'}`);
  }
  return parseConfigText(text, ext === '.json' ? 'json' : 'yaml');
}

/** Replace `${NAME}` from the environment. An unset name is an error (never an empty credential). */
export function expandEnv(value: string, env: Record<string, string | undefined> = process.env): string {
  return value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]{0,63})\}/g, (_m, name: string) => {
    const v = env[name];
    if (v === undefined || v === '') throw new ConfigError(`environment variable ${name} is not set`);
    return v;
  });
}
