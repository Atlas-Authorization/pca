/**
 * The MCP proxy: a man in the middle that speaks the protocol on both sides and changes nothing the agent or the server can see,
 * except that a tool call the rules do not allow never reaches the server.
 *
 *   client (Claude Desktop, Claude Code, Cursor, any MCP client)  <->  this proxy  <->  the real server (stdio or streamable HTTP)
 *
 * What it does with each message:
 *   - `tools/list`: answers with the tools the operator reviewed whose definition is unchanged. Everything else is hidden.
 *   - `tools/call`: maps the call to its action and asks the engine. Refused calls come back as a tool error the model can read;
 *     allowed calls are forwarded and the result is labelled untrusted (the session is tainted from then on).
 *   - the upstream's tool list is re-read on `tools/list_changed` and after `relistSeconds`; a tool that changed since it was
 *     reviewed (a rug pull) is held until the operator reviews it again.
 *   - server-to-client requests (sampling, elicitation) are refused unless the operator allows them.
 *   - any method outside the known set is refused, and so are malformed messages and batches. The upstream failing is a refusal.
 */

import { spawn, type ChildProcess } from 'node:child_process';
import {
  badUriValue,
  buildRegistry,
  buildToolRegistry,
  compileTemplate,
  prmNs,
  promptItems,
  resNs,
  resourceItems,
  templateItems,
  type ActionEntry,
  type ListedPrompt,
  type ListedResource,
  type ListedTemplate,
  type McpToolDef,
  type Registry,
  type ToolRegistry,
} from './actions';
import type { McpConfig, ProxyConfig } from './config';
import { expandEnv } from './config';
import { Engine, type Call } from './engine';

export interface RpcMsg {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const isResponse = (m: RpcMsg): boolean => m.method === undefined && m.id !== undefined && (m.result !== undefined || m.error !== undefined);
const isRequest = (m: RpcMsg): boolean => typeof m.method === 'string' && m.id !== undefined && m.id !== null;

// ---- the upstream ------------------------------------------------------------------------------------------------------

export interface Upstream {
  /** Send a request and wait for its response (rejects on a timeout, a transport failure or a closed upstream). */
  request(msg: RpcMsg, timeoutMs: number): Promise<RpcMsg>;
  notify(msg: RpcMsg): Promise<void>;
  /** Answer a request the server sent. */
  respond(msg: RpcMsg): Promise<void>;
  /** Server-initiated requests and notifications. */
  onMessage: (m: RpcMsg) => void;
  /** The upstream is gone for good. */
  onClose: (why: string) => void;
  close(): Promise<void>;
}

/** An upstream that is a child process speaking newline-delimited JSON on stdio. */
export class StdioUpstream implements Upstream {
  onMessage: (m: RpcMsg) => void = () => undefined;
  onClose: (why: string) => void = () => undefined;
  private readonly child: ChildProcess;
  private readonly pending = new Map<string, { resolve: (m: RpcMsg) => void; reject: (e: Error) => void; timer: NodeJS.Timeout }>();
  private buf = '';
  private closed = false;

  constructor(command: string, args: readonly string[], env: Record<string, string>, private readonly maxLine: number) {
    this.child = spawn(command, [...args], { stdio: ['pipe', 'pipe', 'inherit'], env: { ...process.env, ...env } });
    this.child.stdout!.setEncoding('utf8');
    this.child.stdout!.on('data', (chunk: string) => this.feed(chunk));
    this.child.on('error', (e) => this.fail(`the upstream could not run: ${e.message}`));
    this.child.on('exit', (code, sig) => this.fail(`the upstream exited (${sig ?? code})`));
    this.child.stdin!.on('error', () => undefined);
  }

  private feed(chunk: string): void {
    this.buf += chunk;
    for (let i = this.buf.indexOf('\n'); i >= 0; i = this.buf.indexOf('\n')) {
      const line = this.buf.slice(0, i).trim();
      this.buf = this.buf.slice(i + 1);
      if (line === '') continue;
      let m: RpcMsg;
      try {
        m = JSON.parse(line) as RpcMsg;
      } catch {
        continue; // a server that prints text on stdout is not speaking JSON-RPC: the line is dropped, never forwarded
      }
      if (!isObj(m)) continue;
      if (isResponse(m)) {
        const key = String(m.id);
        const p = this.pending.get(key);
        if (p !== undefined) {
          clearTimeout(p.timer);
          this.pending.delete(key);
          p.resolve(m);
        }
      } else this.onMessage(m);
    }
    if (this.buf.length > this.maxLine) this.fail('the upstream sent a line larger than the limit');
  }

  private fail(why: string): void {
    if (this.closed) return;
    this.closed = true;
    for (const [, p] of this.pending) {
      clearTimeout(p.timer);
      p.reject(new Error(why));
    }
    this.pending.clear();
    this.child.kill();
    this.onClose(why);
  }

  private write(m: RpcMsg): Promise<void> {
    if (this.closed) return Promise.reject(new Error('the upstream is closed'));
    return new Promise((resolve, reject) => this.child.stdin!.write(`${JSON.stringify({ jsonrpc: '2.0', ...m })}\n`, (e) => (e ? reject(e) : resolve())));
  }

  request(msg: RpcMsg, timeoutMs: number): Promise<RpcMsg> {
    const key = String(msg.id);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(key);
        reject(new Error('the upstream did not answer in time'));
      }, timeoutMs);
      this.pending.set(key, { resolve, reject, timer });
      this.write(msg).catch((e: Error) => {
        clearTimeout(timer);
        this.pending.delete(key);
        reject(e);
      });
    });
  }
  notify(msg: RpcMsg): Promise<void> {
    return this.write(msg);
  }
  respond(msg: RpcMsg): Promise<void> {
    return this.write(msg);
  }
  async close(): Promise<void> {
    this.closed = true;
    this.child.kill();
  }
}

/** Decode a server-sent-events body into the data payloads of its events. */
export function* sseData(text: string): Generator<string> {
  for (const ev of text.split(/\r?\n\r?\n/)) {
    const data = ev.split(/\r?\n/).filter((l) => l.startsWith('data:')).map((l) => l.slice(5).replace(/^ /, ''));
    if (data.length > 0) yield data.join('\n');
  }
}

/** An upstream that is a streamable-HTTP MCP endpoint. */
export class HttpUpstream implements Upstream {
  onMessage: (m: RpcMsg) => void = () => undefined;
  onClose: (why: string) => void = () => undefined;
  private session: string | undefined;
  private version: string | undefined;

  constructor(
    private readonly url: string,
    private readonly headers: Record<string, string>,
    private readonly maxBytes: number,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  private async post(body: RpcMsg, timeoutMs: number): Promise<Response> {
    const h: Record<string, string> = { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...this.headers };
    if (this.session !== undefined) h['mcp-session-id'] = this.session;
    if (this.version !== undefined) h['mcp-protocol-version'] = this.version;
    const res = await this.fetchImpl(this.url, { method: 'POST', headers: h, body: JSON.stringify({ jsonrpc: '2.0', ...body }), signal: AbortSignal.timeout(timeoutMs), redirect: 'error' });
    const sid = res.headers.get('mcp-session-id');
    if (sid !== null && sid.length > 0 && sid.length <= 256) this.session = sid;
    return res;
  }

  private async readBody(res: Response): Promise<string> {
    const reader = res.body?.getReader();
    if (reader === undefined) return '';
    const dec = new TextDecoder();
    let text = '';
    let n = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      n += value.byteLength;
      if (n > this.maxBytes) {
        await reader.cancel();
        throw new Error('the upstream response is larger than the limit');
      }
      text += dec.decode(value, { stream: true });
    }
    return text;
  }

  async request(msg: RpcMsg, timeoutMs: number): Promise<RpcMsg> {
    const res = await this.post(msg, timeoutMs);
    if (!res.ok) throw new Error(`the upstream answered HTTP ${res.status}`);
    const ct = res.headers.get('content-type') ?? '';
    const text = await this.readBody(res);
    const payloads: unknown[] = [];
    if (/text\/event-stream/i.test(ct)) for (const d of sseData(text)) payloads.push(JSON.parse(d));
    else payloads.push(JSON.parse(text));
    let answer: RpcMsg | undefined;
    for (const p of payloads.flatMap((x) => (Array.isArray(x) ? x : [x]))) {
      if (!isObj(p)) continue;
      const m = p as RpcMsg;
      if (isResponse(m) && String(m.id) === String(msg.id)) answer = m;
      else if (!isResponse(m)) this.onMessage(m);
    }
    if (answer === undefined) throw new Error('the upstream answered without a response to the request');
    if (msg.method === 'initialize' && isObj(answer.result) && typeof answer.result.protocolVersion === 'string') this.version = answer.result.protocolVersion;
    return answer;
  }

  async notify(msg: RpcMsg): Promise<void> {
    const res = await this.post(msg, 15_000);
    await res.body?.cancel();
    if (!res.ok) throw new Error(`the upstream answered HTTP ${res.status}`);
  }
  respond(msg: RpcMsg): Promise<void> {
    return this.notify(msg);
  }
  async close(): Promise<void> {
    if (this.session === undefined) return;
    try {
      await this.fetchImpl(this.url, { method: 'DELETE', headers: { ...this.headers, 'mcp-session-id': this.session }, signal: AbortSignal.timeout(3000) });
    } catch {
      /* best effort */
    }
  }
}

/** The upstream the configuration (or the command line) names. */
export function openUpstream(u: NonNullable<McpConfig['upstream']>, limits: ProxyConfig['limits'], env: Record<string, string | undefined> = process.env): Upstream {
  if ('command' in u) return new StdioUpstream(u.command, u.args ?? [], Object.fromEntries(Object.entries(u.env ?? {}).map(([k, v]) => [k, expandEnv(v, env)])), limits.maxResponseBytes * 2);
  const headers = Object.fromEntries(Object.entries(u.headers ?? {}).map(([k, v]) => [k.toLowerCase(), expandEnv(v, env)]));
  return new HttpUpstream(u.url, headers, limits.maxResponseBytes);
}

/**
 * Read every page of a list the upstream serves (at most 20 pages and 2000 items). A JSON-RPC error means the upstream does not
 * serve that list (an empty one); a transport failure is thrown.
 */
export async function listPaged<T>(up: Upstream, method: string, field: string, timeoutMs: number, id: () => string): Promise<T[]> {
  const out: T[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < 20; page++) {
    const r = await up.request({ jsonrpc: '2.0', id: id(), method, ...(cursor !== undefined ? { params: { cursor } } : {}) }, timeoutMs);
    if (r.error !== undefined) {
      if (method === 'tools/list') throw new Error('the upstream did not return a tool list');
      return out;
    }
    if (!isObj(r.result)) throw new Error(`the upstream returned a malformed ${method} result`);
    // a server that lacks resources or prompts may answer with an empty result; a tool list must be there
    if (r.result[field] === undefined && method !== 'tools/list') return out;
    if (!Array.isArray(r.result[field])) throw new Error(`the upstream returned a malformed ${method} result`);
    for (const t of r.result[field] as unknown[]) if (isObj(t)) out.push(t as T);
    if (out.length > 2000) throw new Error(`the upstream lists more than 2000 items in ${method}`);
    cursor = typeof r.result.nextCursor === 'string' && r.result.nextCursor.length > 0 ? r.result.nextCursor : undefined;
    if (cursor === undefined) break;
  }
  return out;
}

export const listTools = (up: Upstream, timeoutMs: number, id: () => string): Promise<McpToolDef[]> => listPaged<McpToolDef>(up, 'tools/list', 'tools', timeoutMs, id).then((t) => t.filter((x) => typeof x.name === 'string'));

/** The handshake the proxy performs itself when it talks to the upstream on its own account (init, review, bootstrap). */
export async function handshake(up: Upstream, timeoutMs: number): Promise<void> {
  const r = await up.request({ jsonrpc: '2.0', id: 'pcap-init', method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'pca-proxy', version: '0.5.0' } } }, timeoutMs);
  if (r.error !== undefined) throw new Error('the upstream refused to initialize');
  await up.notify({ jsonrpc: '2.0', method: 'notifications/initialized' });
}

/** Everything the upstream lists, as registries: what is mapped, what is held, and the definitions to show the model. */
export interface Regs {
  tools: ToolRegistry;
  resources: Registry;
  templates: Registry;
  prompts: Registry;
  listed: { resources: Map<string, ListedResource>; templates: Map<string, ListedTemplate>; prompts: Map<string, ListedPrompt> };
  matchers: Array<{ key: string; re: RegExp; vars: string[] }>;
  /** Every candidate action, for compiling the grant. */
  candidates: ActionEntry[];
}

/** Read the upstream's lists and build the registries. */
export async function loadRegs(up: Upstream, cfg: McpConfig, timeoutMs: number, id: () => string): Promise<Regs> {
  const [tools, res, tmpl, prm] = await Promise.all([
    listTools(up, timeoutMs, id),
    listPaged<ListedResource>(up, 'resources/list', 'resources', timeoutMs, id),
    listPaged<ListedTemplate>(up, 'resources/templates/list', 'resourceTemplates', timeoutMs, id),
    listPaged<ListedPrompt>(up, 'prompts/list', 'prompts', timeoutMs, id),
  ]);
  const toolsReg = buildToolRegistry(tools, cfg);
  const resources = buildRegistry(resourceItems(res), cfg.resources, resNs(cfg.ns), 'resource');
  const templates = buildRegistry(templateItems(tmpl), cfg.resources, resNs(cfg.ns), 'resource template');
  const prompts = buildRegistry(promptItems(prm), cfg.prompts, prmNs(cfg.ns), 'prompt');
  const matchers: Regs['matchers'] = [];
  for (const t of tmpl) {
    const c = typeof t.uriTemplate === 'string' ? compileTemplate(t.uriTemplate) : undefined;
    if (c !== undefined) matchers.push({ key: t.uriTemplate, re: c.re, vars: c.vars });
  }
  // the more literal the template, the earlier it is tried
  matchers.sort((a, z) => z.key.replace(/\{[^}]*\}/g, '').length - a.key.replace(/\{[^}]*\}/g, '').length);
  return {
    tools: toolsReg,
    resources,
    templates,
    prompts,
    listed: {
      resources: new Map(res.filter((r) => typeof r.uri === 'string').map((r) => [r.uri, r])),
      templates: new Map(tmpl.filter((r) => typeof r.uriTemplate === 'string').map((r) => [r.uriTemplate, r])),
      prompts: new Map(prm.filter((p) => typeof p.name === 'string').map((p) => [p.name, p])),
    },
    matchers,
    candidates: [...toolsReg.candidates, ...resources.candidates, ...templates.candidates, ...prompts.candidates],
  };
}

// ---- the proxy ---------------------------------------------------------------------------------------------------------

const ALWAYS_SERVER_REQUESTS = ['ping', 'roots/list'];
/** Methods relayed in enforce mode besides `initialize`, the lists and the mapped reads: they carry no content of the server's. */
const RELAY_METHODS = new Set(['completion/complete', 'logging/setLevel']);

export interface McpProxyOptions {
  cfg: ProxyConfig;
  upstream: Upstream;
  /** Write a message to the client. */
  send: (m: RpcMsg) => void;
  /** The engine to use, shared between sessions (the HTTP downstream). Absent: built from the first lists. */
  engine?: Engine;
  /** Build the engine once the first lists are known (tests inject one). */
  makeEngine?: (cfg: ProxyConfig, candidates: ActionEntry[]) => Engine | Promise<Engine>;
  log?: (line: string) => void;
  now?: () => number;
  /** The session name the engine keeps taint under. `client/session` shares one persisted flag per client. */
  session?: string;
  /** `http`: there is no channel for server-initiated requests, so they are refused and only list-changed notifications matter. */
  downstream?: 'stdio' | 'http';
}

export class McpProxy {
  private engine: Engine | undefined;
  private reg: Regs | undefined;
  private regAt = 0;
  private stale = false;
  private nextId = 0;
  private readonly mcp: McpConfig;
  private readonly cfg: ProxyConfig;
  private readonly up: Upstream;
  private readonly send: (m: RpcMsg) => void;
  private readonly log: (line: string) => void;
  private readonly now: () => number;
  private readonly session: string;
  private readonly relayed = new Set<string>();
  private starting: Promise<void> | undefined;
  private lastListError: string | undefined;

  constructor(private readonly o: McpProxyOptions) {
    if (o.cfg.mcp === undefined) throw new Error('McpProxy needs an mcp section');
    this.cfg = o.cfg;
    this.mcp = o.cfg.mcp;
    this.up = o.upstream;
    this.send = o.send;
    this.log = o.log ?? (() => undefined);
    this.now = o.now ?? Date.now;
    this.session = o.session ?? 'stdio';
    this.engine = o.engine;
    this.up.onMessage = (m) => void this.fromServer(m).catch((e: Error) => this.log(`server message failed: ${e.message}`));
    this.up.onClose = (why) => this.log(`${why}; every call is refused from here on`);
  }

  get currentEngine(): Engine | undefined {
    return this.engine;
  }

  private id(): string {
    return `pcap-${++this.nextId}`;
  }

  private err(id: RpcMsg['id'], code: number, message: string): RpcMsg {
    return { jsonrpc: '2.0', id: id ?? null, error: { code, message } };
  }

  private toolError(id: RpcMsg['id'], text: string): RpcMsg {
    return { jsonrpc: '2.0', id: id ?? null, result: { content: [{ type: 'text', text }], isError: true } };
  }

  /** Read the upstream's lists and rebuild the registries. */
  async refresh(): Promise<Regs> {
    const reg = await loadRegs(this.up, this.mcp, this.cfg.limits.upstreamTimeoutMs, () => this.id());
    if (this.reg !== undefined) {
      for (const [kind, now, before] of [['tool', reg.tools, this.reg.tools], ['resource', reg.resources, this.reg.resources], ['resource template', reg.templates, this.reg.templates], ['prompt', reg.prompts, this.reg.prompts]] as const) {
        for (const [name, why] of now.held) if (before.entries.has(name)) this.log(`${kind} '${name}' is now held: ${why}`);
      }
    }
    this.reg = reg;
    this.regAt = this.now();
    this.stale = false;
    this.lastListError = undefined;
    if (this.engine === undefined) this.engine = this.o.makeEngine ? await this.o.makeEngine(this.cfg, reg.candidates) : await Engine.create({ cfg: this.cfg, candidates: reg.candidates });
    return reg;
  }

  private async registry(): Promise<Regs | undefined> {
    const ttl = (this.mcp.relistSeconds ?? 30) * 1000;
    if (this.reg === undefined || this.stale || this.now() - this.regAt > ttl) {
      try {
        this.starting ??= this.refresh().then(() => undefined).finally(() => (this.starting = undefined));
        await this.starting;
      } catch (e) {
        // a list that cannot be read is not a reason to trust the old one: calls are refused until it can
        this.reg = undefined;
        this.lastListError = e instanceof Error ? e.message : 'error';
        return undefined;
      }
    }
    return this.reg;
  }

  // ---- messages from the client ----

  /** Handle one line from the client. */
  async fromClient(line: string): Promise<void> {
    let m: unknown;
    try {
      m = JSON.parse(line);
    } catch {
      this.send(this.err(null, -32700, 'parse error'));
      return;
    }
    if (Array.isArray(m)) {
      this.send(this.err(null, -32600, 'batches are not accepted by pca-proxy'));
      return;
    }
    if (!isObj(m)) {
      this.send(this.err(null, -32600, 'invalid request'));
      return;
    }
    await this.handle(m as RpcMsg);
  }

  async handle(m: RpcMsg): Promise<void> {
    const observe = this.cfg.mode === 'observe';
    try {
      if (isResponse(m)) {
        // only an answer to a request this proxy relayed goes back to the server
        if (this.relayed.delete(String(m.id))) await this.up.respond(m);
        return;
      }
      if (typeof m.method !== 'string') {
        if (m.id !== undefined) this.send(this.err(m.id, -32600, 'invalid request'));
        return;
      }
      if (m.id === undefined || m.id === null) {
        // notifications are relayed (initialized, cancelled, progress, roots/list_changed)
        await this.up.notify(m).catch((e: Error) => this.log(`notification failed: ${e.message}`));
        return;
      }
      switch (m.method) {
        case 'ping':
          this.send({ jsonrpc: '2.0', id: m.id, result: {} });
          return;
        case 'initialize': {
          const r = await this.up.request(m, this.cfg.limits.upstreamTimeoutMs);
          this.send(r);
          return;
        }
        case 'tools/list':
        case 'resources/list':
        case 'resources/templates/list':
        case 'prompts/list':
          return await this.list(m);
        case 'tools/call':
          return await this.toolsCall(m);
        case 'resources/read':
          return await this.resourcesRead(m);
        case 'prompts/get':
          return await this.promptsGet(m);
        default:
          if (RELAY_METHODS.has(m.method) || observe) return await this.relay(m);
          this.log(`refused method ${m.method}`);
          this.send(this.err(m.id, -32601, `pca-proxy does not relay '${m.method.slice(0, 60)}'`));
      }
    } catch (e) {
      this.log(`request failed: ${e instanceof Error ? e.message : 'error'}`);
      if (m.id !== undefined && m.id !== null) this.send(this.err(m.id, -32603, 'the upstream is unavailable'));
    }
  }

  private async relay(m: RpcMsg): Promise<void> {
    this.send(await this.up.request(m, this.cfg.limits.upstreamTimeoutMs));
  }

  /** `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list`: only what the operator reviewed and did not deny. */
  private async list(m: RpcMsg): Promise<void> {
    const reg = await this.registry();
    if (reg === undefined) {
      this.send(this.err(m.id, -32603, 'the upstream list is unavailable'));
      return;
    }
    const observe = this.cfg.mode === 'observe';
    const shown = (r: Registry, listed: Map<string, unknown>): unknown[] => [...listed].filter(([k]) => observe || (r.entries.get(k)?.rule.policy ?? 'deny') !== 'deny').map(([, v]) => v);
    let result: Record<string, unknown>;
    switch (m.method) {
      case 'tools/list':
        result = { tools: shown(reg.tools, reg.tools.tools) };
        break;
      case 'resources/list':
        result = { resources: shown(reg.resources, reg.listed.resources) };
        break;
      case 'resources/templates/list':
        result = { resourceTemplates: shown(reg.templates, reg.listed.templates) };
        break;
      default:
        result = { prompts: shown(reg.prompts, reg.listed.prompts) };
    }
    this.send({ jsonrpc: '2.0', id: m.id!, result });
  }

  /** Decide a call; on a refusal answer the client and return undefined. */
  private async decide(id: RpcMsg['id'], call: Call, refuse: (text: string) => RpcMsg): Promise<boolean> {
    const v = await this.engine!.evaluate(call);
    if (!v.forward) {
      this.send(refuse(`denied by pca-proxy: ${v.code}: ${v.reason}`));
      return false;
    }
    if (!v.allowed) this.log(`observe: would refuse ${call.name}: ${v.code}: ${v.reason}`);
    return true;
  }

  /** Forward a mapped request, bound its answer, label it untrusted and relay it. */
  private async forward(id: RpcMsg['id'], method: string, params: unknown, origin: 'tool' | 'retrieval', source: string, label: string): Promise<void> {
    // a tool call is refused with a tool error the model can read; a read or a prompt, with a protocol error (its result has another shape)
    const refuse = (text: string): RpcMsg => (method === 'tools/call' ? this.toolError(id, text) : this.err(id, -32001, text));
    let r: RpcMsg;
    try {
      r = await this.up.request({ jsonrpc: '2.0', id: id!, method, params }, this.cfg.limits.upstreamTimeoutMs);
    } catch (e) {
      // the upstream failing is a refusal: nothing it said is relayed
      this.log(`upstream failed on ${source}: ${e instanceof Error ? e.message : 'error'}`);
      this.send(refuse('denied by pca-proxy: upstream_error: the upstream did not complete the call'));
      return;
    }
    if (r.error !== undefined || !isObj(r.result)) {
      this.send(refuse(`denied by pca-proxy: upstream_error: the upstream returned an error${typeof r.error?.code === 'number' ? ` (${r.error.code})` : ''}`));
      return;
    }
    if (Buffer.byteLength(JSON.stringify(r.result)) > this.cfg.limits.maxResponseBytes) {
      this.send(refuse(`denied by pca-proxy: response_too_large: the result is larger than ${this.cfg.limits.maxResponseBytes} bytes`));
      return;
    }
    // what came back reaches the model: it is untrusted from here on, recorded durably before it is relayed
    try {
      await this.engine!.taint(this.session, origin, source, r.result);
    } catch (e) {
      this.log(`state failed while labelling ${source}: ${e instanceof Error ? e.message : 'error'}`);
      this.send(refuse('denied by pca-proxy: state_unavailable: the result could not be labelled untrusted, so it is not relayed'));
      return;
    }
    const prevMeta = isObj(r.result._meta) ? r.result._meta : {};
    this.send({ jsonrpc: '2.0', id: id!, result: { ...r.result, _meta: { ...prevMeta, 'pca-proxy/provenance': { origin, source: label, untrusted: true } } } });
  }

  private async mapped(id: RpcMsg['id'], tool = true): Promise<Regs | undefined> {
    const reg = await this.registry();
    if (reg === undefined || this.engine === undefined) {
      const text = `denied by pca-proxy: upstream_unavailable: the upstream lists cannot be read (${this.lastListError ?? 'no list'})`;
      this.send(tool ? this.toolError(id, text) : this.err(id, -32001, text));
      return undefined;
    }
    return reg;
  }

  private closedParams(id: RpcMsg['id'], p: unknown, allowed: readonly string[], tool = true): Record<string, unknown> | undefined {
    if (!isObj(p)) {
      this.send(this.err(id, -32602, 'the request needs params'));
      return undefined;
    }
    for (const k of Object.keys(p)) if (!allowed.includes(k)) {
      const text = `denied by pca-proxy: bad_request: the request carries an unknown member '${k.slice(0, 40)}'`;
      this.send(tool ? this.toolError(id, text) : this.err(id, -32001, text));
      return undefined;
    }
    return p;
  }

  private async toolsCall(m: RpcMsg): Promise<void> {
    const id = m.id!;
    const p = this.closedParams(id, m.params, ['name', 'arguments', '_meta']);
    if (p === undefined) return;
    if (typeof p.name !== 'string' || p.name.length === 0 || p.name.length > 256) {
      this.send(this.err(id, -32602, 'tools/call needs a tool name'));
      return;
    }
    const name = p.name;
    const reg = await this.mapped(id);
    if (reg === undefined) return;
    const entry = reg.tools.entries.get(name) ?? (this.cfg.mode === 'observe' ? reg.tools.candidates.find((c) => c.id === name) : undefined);
    const args = p.arguments === undefined ? {} : p.arguments;
    const call: Call = { kind: 'mcp', name, entry, args, session: this.session, ...(reg.tools.held.has(name) ? { why: reg.tools.held.get(name)! } : {}) };
    if (!(await this.decide(id, call, (t) => this.toolError(id, t)))) return;
    await this.forward(id, 'tools/call', { name, arguments: args, ...(p._meta !== undefined ? { _meta: p._meta } : {}) }, 'tool', name, name);
  }

  private async resourcesRead(m: RpcMsg): Promise<void> {
    const id = m.id!;
    const p = this.closedParams(id, m.params, ['uri', '_meta'], false);
    if (p === undefined) return;
    if (typeof p.uri !== 'string' || p.uri.length === 0 || p.uri.length > 2048) {
      this.send(this.err(id, -32602, 'resources/read needs a uri'));
      return;
    }
    const uri = p.uri;
    const reg = await this.mapped(id, false);
    if (reg === undefined) return;
    const observe = this.cfg.mode === 'observe';
    let entry: ActionEntry | undefined;
    let args: Record<string, unknown> = {};
    let why: string | undefined;
    if (reg.listed.resources.has(uri)) {
      // a resource the upstream lists by its exact uri is judged on that entry alone: a held one is never rescued by a template
      entry = reg.resources.entries.get(uri) ?? (observe ? reg.resources.candidates.find((c) => c.id === uri) : undefined);
      why = reg.resources.held.get(uri);
    } else {
      for (const mt of reg.matchers) {
        const mm = mt.re.exec(uri);
        if (mm === null) continue;
        const vals: Record<string, unknown> = {};
        for (const [i, v] of mt.vars.entries()) {
          const bad = badUriValue(mm[i + 1]!);
          if (bad !== undefined) {
            this.send(this.err(id, -32001, `denied by pca-proxy: bad_args: a value in the uri has ${bad}`));
            return;
          }
          vals[v] = mm[i + 1]!;
        }
        args = vals;
        entry = reg.templates.entries.get(mt.key) ?? (observe ? reg.templates.candidates.find((c) => c.id === mt.key) : undefined);
        why = reg.templates.held.get(mt.key);
        break;
      }
    }
    const call: Call = { kind: 'mcp', name: `resources/read ${uri.slice(0, 200)}`, entry, args, session: this.session, ...(why !== undefined ? { why } : {}) };
    if (!(await this.decide(id, call, (t) => this.err(id, -32001, t)))) return;
    await this.forward(id, 'resources/read', { uri, ...(p._meta !== undefined ? { _meta: p._meta } : {}) }, 'retrieval', uri.slice(0, 200), uri.slice(0, 200));
  }

  private async promptsGet(m: RpcMsg): Promise<void> {
    const id = m.id!;
    const p = this.closedParams(id, m.params, ['name', 'arguments', '_meta'], false);
    if (p === undefined) return;
    if (typeof p.name !== 'string' || p.name.length === 0 || p.name.length > 256) {
      this.send(this.err(id, -32602, 'prompts/get needs a prompt name'));
      return;
    }
    const name = p.name;
    const reg = await this.mapped(id, false);
    if (reg === undefined) return;
    const entry = reg.prompts.entries.get(name) ?? (this.cfg.mode === 'observe' ? reg.prompts.candidates.find((c) => c.id === name) : undefined);
    const args = p.arguments === undefined ? {} : p.arguments;
    const call: Call = { kind: 'mcp', name: `prompts/get ${name}`, entry, args, session: this.session, ...(reg.prompts.held.has(name) ? { why: reg.prompts.held.get(name)! } : {}) };
    if (!(await this.decide(id, call, (t) => this.err(id, -32001, t)))) return;
    await this.forward(id, 'prompts/get', { name, arguments: args, ...(p._meta !== undefined ? { _meta: p._meta } : {}) }, 'tool', `prompt:${name}`.slice(0, 200), name);
  }

  // ---- messages from the server ----

  private async fromServer(m: RpcMsg): Promise<void> {
    if (typeof m.method !== 'string') return;
    const http = this.o.downstream === 'http';
    if (m.id === undefined || m.id === null) {
      if (m.method === 'notifications/tools/list_changed' || m.method === 'notifications/resources/list_changed' || m.method === 'notifications/prompts/list_changed') this.stale = true;
      if (!http) this.send(m);
      return;
    }
    const allowed = [...ALWAYS_SERVER_REQUESTS, ...(this.mcp.allowServerRequests ?? [])];
    if (http || (this.cfg.mode === 'enforce' && !allowed.includes(m.method))) {
      this.log(`refused server request ${m.method}`);
      await this.up.respond(this.err(m.id, -32601, `pca-proxy does not relay '${m.method.slice(0, 60)}' to the client`));
      return;
    }
    this.relayed.add(String(m.id));
    this.send(m);
  }

  async close(): Promise<void> {
    await this.up.close();
  }
}

/** Run the proxy on this process's stdin and stdout (what an MCP client launches). */
export async function runStdio(proxy: McpProxy, stdin: NodeJS.ReadableStream = process.stdin): Promise<void> {
  let buf = '';
  const queue: Promise<void>[] = [];
  stdin.setEncoding('utf8');
  await new Promise<void>((resolve) => {
    stdin.on('data', (chunk: string) => {
      buf += chunk;
      for (let i = buf.indexOf('\n'); i >= 0; i = buf.indexOf('\n')) {
        const line = buf.slice(0, i).trim();
        buf = buf.slice(i + 1);
        if (line !== '') queue.push(proxy.fromClient(line));
      }
    });
    stdin.on('end', resolve);
  });
  await Promise.allSettled(queue);
  await proxy.close();
}
