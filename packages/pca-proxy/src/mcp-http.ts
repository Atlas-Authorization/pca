/**
 * The MCP proxy over streamable HTTP, for remote and hosted clients.
 *
 *   client A ─┐                         ┌─ upstream process / connection A
 *   client B ─┼─  POST /mcp  ->  proxy  ┼─ upstream process / connection B      (one engine: one grant, one budget, one audit chain)
 *   client C ─┘                         └─ ...
 *
 * Every client authenticates with its own bearer token and every session belongs to the client that opened it: another client
 * presenting the session id gets a 404, not a refusal that confirms the id exists. Each session has its own upstream and its own
 * tool lists; taint is per session and persisted per client, so a client that saw untrusted content starts its next session
 * tainted. A request with an `Origin` that is not listed is refused (DNS rebinding), so is a `Host` that is not listed when the
 * proxy listens on loopback. Answers are plain JSON; there is no server-sent stream (GET is 405), so a server's own requests to the
 * client (sampling, elicitation) are refused.
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { b64u } from '@atlasauth/pca';
import { ConfigError, type McpListen, type ProxyConfig } from './config';
import { Engine } from './engine';
import { McpProxy, handshake, loadRegs, type RpcMsg, type Upstream } from './mcp';

export interface HttpReq {
  method: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
}
export interface HttpRes {
  status: number;
  headers: Record<string, string>;
  body: Buffer;
}

interface SessionRec {
  client: string;
  proxy: McpProxy;
  sinks: Map<string, RpcMsg[]>;
  last: number;
  closed: boolean;
}

const sha = (s: string): Buffer => createHash('sha256').update(s).digest();
const reply = (status: number, body: unknown, headers: Record<string, string> = {}): HttpRes => ({ status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers }, body: Buffer.from(JSON.stringify(body)) });
const fail = (status: number, message: string, headers: Record<string, string> = {}): HttpRes => reply(status, { error: { code: status, message } }, headers);

export interface McpHttpOptions {
  cfg: ProxyConfig;
  makeUpstream: () => Upstream;
  engine: Engine;
  env?: Record<string, string | undefined>;
  log?: (line: string) => void;
  now?: () => number;
}

export class McpHttpServer {
  private readonly listen_: McpListen;
  private readonly sessions = new Map<string, SessionRec>();
  private readonly tokens: Array<{ client: string; digest: Buffer }> = [];
  private readonly now: () => number;
  private readonly log: (line: string) => void;
  private timer: NodeJS.Timeout | undefined;

  /**
   * Read the upstream once on the proxy's own account to learn what the grant must cover, build the engine, and return the server.
   * Throws when the upstream cannot be listed or the state cannot be opened: the proxy does not start.
   */
  static async create(o: Omit<McpHttpOptions, 'engine'> & { engine?: Engine }): Promise<McpHttpServer> {
    const mcp = o.cfg.mcp;
    if (mcp?.listen === undefined) throw new ConfigError('mcp.listen is not set');
    let engine = o.engine;
    if (engine === undefined) {
      const probe = o.makeUpstream();
      try {
        await handshake(probe, o.cfg.limits.upstreamTimeoutMs);
        let n = 0;
        const regs = await loadRegs(probe, mcp, o.cfg.limits.upstreamTimeoutMs, () => `pcap-boot-${++n}`);
        engine = await Engine.create({ cfg: o.cfg, candidates: regs.candidates, ...(o.env ? { env: o.env } : {}) });
      } finally {
        await probe.close();
      }
    }
    return new McpHttpServer({ ...o, engine });
  }

  constructor(private readonly o: McpHttpOptions) {
    this.listen_ = o.cfg.mcp!.listen!;
    this.now = o.now ?? Date.now;
    this.log = o.log ?? (() => undefined);
    const env = o.env ?? process.env;
    for (const [client, c] of Object.entries(this.listen_.clients)) {
      const t = env[c.tokenEnv];
      if (t === undefined || t.length < 16) throw new ConfigError(`${c.tokenEnv} must hold a bearer token of at least 16 characters (client ${client})`);
      this.tokens.push({ client, digest: sha(t) });
    }
  }

  get sessionCount(): number {
    return this.sessions.size;
  }

  private authenticate(h: HttpReq['headers']): string | undefined {
    if (this.listen_.insecureNoAuth) return 'anonymous';
    const a = h.authorization;
    if (typeof a !== 'string') return undefined;
    const m = /^Bearer ([\x21-\x7e]{16,512})$/.exec(a);
    if (m === null) return undefined;
    const d = sha(m[1]!);
    let who: string | undefined;
    // every token is compared, so the time taken does not say which one was close
    for (const t of this.tokens) if (timingSafeEqual(d, t.digest) && who === undefined) who = t.client;
    return who;
  }

  private hostOk(h: HttpReq['headers']): boolean {
    const l = this.listen_;
    const allowed = l.allowedHosts ?? (l.host === '127.0.0.1' || l.host === '::1' || l.host === 'localhost' ? ['localhost', '127.0.0.1', '[::1]'] : undefined);
    if (allowed === undefined) return true;
    const host = h.host;
    if (typeof host !== 'string') return false;
    const name = host.startsWith('[') ? host.slice(0, host.indexOf(']') + 1) : host.replace(/:\d+$/, '');
    return allowed.includes(name.toLowerCase());
  }

  /** Close sessions idle for longer than `idleSeconds`. Runs on a timer; callable directly. */
  async sweep(): Promise<number> {
    const cutoff = this.now() - this.listen_.idleSeconds * 1000;
    let n = 0;
    for (const [sid, s] of [...this.sessions]) {
      if (s.last < cutoff) {
        await this.drop(sid);
        n++;
      }
    }
    return n;
  }

  private async drop(sid: string): Promise<void> {
    const s = this.sessions.get(sid);
    if (s === undefined) return;
    this.sessions.delete(sid);
    s.closed = true;
    this.o.engine.closeSession(`${s.client}/${sid}`);
    await s.proxy.close().catch(() => undefined);
  }

  async handle(req: HttpReq): Promise<HttpRes> {
    try {
      return await this.route(req);
    } catch (e) {
      this.log(`request failed: ${e instanceof Error ? e.message : 'error'}`);
      return fail(500, 'the request could not be handled');
    }
  }

  private async route(req: HttpReq): Promise<HttpRes> {
    const l = this.listen_;
    const q = req.url.indexOf('?');
    if ((q < 0 ? req.url : req.url.slice(0, q)) !== l.path) return fail(404, 'not found');
    if (!this.hostOk(req.headers)) return fail(403, 'the Host header is not allowed');
    const origin = req.headers.origin;
    if (Array.isArray(origin) || (origin !== undefined && !l.allowedOrigins.includes(origin))) return fail(403, 'the Origin is not allowed');
    const client = this.authenticate(req.headers);
    if (client === undefined) return fail(401, 'a valid bearer token is required', { 'www-authenticate': 'Bearer realm="pca-proxy"' });
    const method = req.method.toUpperCase();
    const sidH = req.headers['mcp-session-id'];
    if (Array.isArray(sidH)) return fail(400, 'the Mcp-Session-Id header is repeated');
    const own = (sid: string | undefined): SessionRec | undefined => {
      const s = sid === undefined ? undefined : this.sessions.get(sid);
      // a session of another client looks exactly like one that does not exist
      return s !== undefined && s.client === client && !s.closed ? s : undefined;
    };

    if (method === 'DELETE') {
      if (own(sidH) === undefined) return fail(404, 'no such session');
      await this.drop(sidH!);
      return { status: 204, headers: {}, body: Buffer.alloc(0) };
    }
    if (method !== 'POST') return fail(405, 'POST or DELETE only', { allow: 'POST, DELETE' });

    if (req.body.length > this.o.cfg.limits.maxRequestBytes + 4096) return fail(413, 'the message is too large');
    const ct = req.headers['content-type'];
    if (typeof ct !== 'string' || !/^application\/json(\s*;.*)?$/i.test(ct)) return fail(415, 'the body must be application/json');
    let msg: unknown;
    try {
      msg = JSON.parse(req.body.toString('utf8'));
    } catch {
      return fail(400, 'the body is not JSON');
    }
    if (msg === null || typeof msg !== 'object' || Array.isArray(msg)) return fail(400, 'one JSON-RPC message per request (no batches)');
    const m = msg as RpcMsg;

    let sid = sidH;
    let s: SessionRec | undefined;
    if (m.method === 'initialize') {
      if (sidH !== undefined) return fail(400, 'initialize starts a session; it carries no session id');
      await this.sweep();
      if (this.sessions.size >= l.maxSessions) return fail(503, 'too many sessions');
      sid = b64u(randomBytes(32));
      s = this.open(sid, client);
    } else {
      if (sid === undefined) return fail(400, 'the Mcp-Session-Id header is required');
      s = own(sid);
      if (s === undefined) return fail(404, 'no such session');
    }
    s.last = this.now();

    if (m.id === undefined || m.id === null || typeof m.method !== 'string') {
      // a notification or a response: nothing to answer
      await s.proxy.handle(m);
      return { status: 202, headers: {}, body: Buffer.alloc(0) };
    }
    const key = String(m.id);
    const out: RpcMsg[] = [];
    s.sinks.set(key, out);
    try {
      await s.proxy.handle(m);
    } finally {
      s.sinks.delete(key);
    }
    const answer = out.find((x) => String(x.id) === key);
    if (answer === undefined) return fail(502, 'the upstream gave no answer');
    return reply(200, answer, m.method === 'initialize' ? { 'mcp-session-id': sid! } : {});
  }

  private open(sid: string, client: string): SessionRec {
    const rec: SessionRec = { client, proxy: undefined as never, sinks: new Map(), last: this.now(), closed: false };
    const upstream = this.o.makeUpstream();
    rec.proxy = new McpProxy({
      cfg: this.o.cfg,
      upstream,
      engine: this.o.engine,
      session: `${client}/${sid}`,
      downstream: 'http',
      log: (line) => this.log(`[${client}] ${line}`),
      send: (m) => {
        // a message with no waiting request (a notification) has no channel to the client and is dropped
        const sink = m.id !== undefined && m.id !== null ? rec.sinks.get(String(m.id)) : undefined;
        sink?.push(m);
      },
    });
    const onClose = upstream.onClose;
    upstream.onClose = (why) => {
      onClose(why);
      void this.drop(sid);
    };
    this.sessions.set(sid, rec);
    return rec;
  }

  /** Serve over node:http. */
  listen(host = this.listen_.host, port = this.listen_.port): Promise<Server> {
    const max = this.o.cfg.limits.maxRequestBytes + 4096;
    const server = createServer((rq: IncomingMessage, rs: ServerResponse) => {
      const chunks: Buffer[] = [];
      let n = 0;
      let over = false;
      rq.on('data', (c: Buffer) => {
        n += c.length;
        if (n > max) {
          over = true;
          rq.destroy();
          return;
        }
        chunks.push(c);
      });
      rq.on('error', () => undefined);
      rq.on('close', () => {
        if (over && !rs.headersSent) rs.writeHead(413, { 'content-type': 'application/json' }).end('{"error":{"code":413,"message":"the message is too large"}}');
      });
      rq.on('end', () => {
        void this.handle({ method: rq.method ?? 'GET', url: rq.url ?? '/', headers: rq.headers, body: Buffer.concat(chunks) }).then((r) => rs.writeHead(r.status, r.headers).end(r.body));
      });
    });
    server.headersTimeout = 15_000;
    server.requestTimeout = 60_000;
    this.timer = setInterval(() => void this.sweep(), 30_000);
    this.timer.unref();
    server.on('close', () => {
      if (this.timer !== undefined) clearInterval(this.timer);
    });
    return new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, host, () => resolve(server));
    });
  }

  async closeAll(): Promise<void> {
    for (const sid of [...this.sessions.keys()]) await this.drop(sid);
  }
}
