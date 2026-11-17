/**
 * The HTTP reverse proxy: PCA in front of a REST API, with no change to the API and no SDK in the agent.
 *
 *   agent  ->  this proxy  ->  the API
 *
 * Every request is mapped to an action from an OpenAPI document or a small rules list (anything else is refused), its arguments
 * (path, query and JSON body) are checked against the action definition, and the engine decides. Two ways to prove the call:
 *
 *   sidecar  the proxy mints the proof from its own grant (for an agent that cannot sign) and can attach it upstream as `PCA-Action`;
 *   verify   the caller sends `PCA-Action` and the proxy verifies it with the gateway (`@atlasauth/pca-gateway`), bound to this request.
 *
 * The request that reaches the API is rebuilt, not relayed: the path is the one that matched, the query and the JSON body are
 * re-serialized from what was checked (so a parser difference cannot show the API something else), and only a short list of headers
 * passes. Nothing the client sent in a `PCA-*` or `X-PCA-*` header is trusted or forwarded.
 */

import { existsSync, readFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { strictParse, type Capability, type PCActn } from '@atlasauth/pca';
import type { ParamDef } from '@atlasauth/pca-actions';
import type { MeterLike, TracerLike } from '@atlasauth/pca-otel';
import { ambiguousPathReason, authorize as gatewayAuthorize } from '@atlasauth/pca-gateway';
import { parse as parseYaml } from 'yaml';
import { buildRouteRegistry, matchRoute, openApiFromRoutes, type ActionEntry } from './actions';
import { ConfigError, expandEnv, type HttpConfig, type ProxyConfig } from './config';
import { Engine, type Call } from './engine';
import { durableProvenanceLog } from './state';

export interface HttpRequestLike {
  method: string;
  /** The request target as sent: path and optional query. */
  url: string;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
}
export interface HttpResponseLike {
  status: number;
  headers: Record<string, string>;
  body: Buffer;
}

const SAFE_HEADERS = ['accept', 'accept-language', 'content-type', 'user-agent', 'if-match', 'if-none-match', 'idempotency-key', 'x-request-id'];
const NEVER = new Set(['host', 'connection', 'content-length', 'transfer-encoding', 'te', 'trailer', 'upgrade', 'expect', 'proxy-authorization', 'proxy-connection', 'keep-alive']);
const BODY_METHODS = new Set(['POST', 'PUT', 'PATCH']);
const SESSION_RE = /^[A-Za-z0-9._:-]{1,64}$/;

const json = (status: number, body: unknown, extra: Record<string, string> = {}): HttpResponseLike => ({
  status,
  headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...extra },
  body: Buffer.from(JSON.stringify(body)),
});
const deny = (status: number, code: string, reason: string, extra: Record<string, string> = {}): HttpResponseLike => json(status, { error: { code, message: reason } }, extra);

function coerce(d: ParamDef | undefined, v: string): unknown {
  if (d?.type === 'integer' && /^-?(0|[1-9][0-9]{0,15})$/.test(v)) return Number(v);
  if (d?.type === 'boolean' && (v === 'true' || v === 'false')) return v === 'true';
  return v;
}

export interface HttpProxyOptions {
  cfg: ProxyConfig;
  engine?: Engine;
  telemetry?: { tracer?: TracerLike; meter?: MeterLike };
  fetchImpl?: typeof fetch;
  env?: Record<string, string | undefined>;
  readFile?: (p: string) => string;
}

export class HttpProxy {
  engine!: Engine;
  private readonly cfg: ProxyConfig;
  private readonly http: HttpConfig;
  private readonly entries: ActionEntry[];
  private readonly fetchImpl: typeof fetch;
  private readonly upstreamHeaders: Record<string, string>;

  /** Build the routes, open the state and the engine. Throws when any of them cannot be built: the proxy does not start. */
  static async create(o: HttpProxyOptions): Promise<HttpProxy> {
    const p = new HttpProxy(o);
    p.engine = o.engine ?? (await Engine.create({ cfg: o.cfg, candidates: p.entries, ...(o.env ? { env: o.env } : {}), ...(o.telemetry ?? {}) }));
    p.installVerifier(o);
    return p;
  }

  private constructor(o: HttpProxyOptions) {
    if (o.cfg.http === undefined) throw new ConfigError('HttpProxy needs an http section');
    this.cfg = o.cfg;
    this.http = o.cfg.http;
    this.fetchImpl = o.fetchImpl ?? fetch;
    const read = o.readFile ?? ((p: string) => readFileSync(p, 'utf8'));
    const env = o.env ?? process.env;

    // the routes: an OpenAPI document, the small rules list, or both
    const h = this.http;
    let doc: Record<string, unknown> = { openapi: '3.0.3', info: { title: 'pca-proxy', version: '1' }, paths: {} };
    if (h.openapi !== undefined) {
      const text = read(h.openapi);
      if (text.length > 8 * 1024 * 1024) throw new ConfigError('http.openapi: the document is larger than 8 MiB');
      const parsed: unknown = parseYaml(text, { maxAliasCount: 50 });
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new ConfigError('http.openapi: not an OpenAPI document');
      doc = parsed as Record<string, unknown>;
    }
    const routeRules = new Map<string, HttpConfig['routes'][number]>();
    if (h.routes.length > 0) {
      const synth = openApiFromRoutes(h);
      const paths = { ...((doc.paths ?? {}) as Record<string, Record<string, unknown>>) };
      for (const [p, item] of Object.entries(synth.paths as Record<string, Record<string, unknown>>)) {
        const merged = { ...(paths[p] ?? {}) };
        for (const [m, op] of Object.entries(item)) {
          if (Object.prototype.hasOwnProperty.call(merged, m)) throw new ConfigError(`http.routes: ${m.toUpperCase()} ${p} is also in the OpenAPI document`);
          merged[m] = op;
        }
        paths[p] = merged;
      }
      doc = { ...doc, paths };
      for (const r of h.routes) {
        const opId = r.name ?? `${r.method.toLowerCase()}_${r.path.replace(/[^A-Za-z0-9]+/g, '_').replace(/^_|_$/g, '')}`;
        if (routeRules.has(opId)) throw new ConfigError(`http.routes: the operation name '${opId}' is used twice`);
        routeRules.set(opId, r);
      }
    }
    const reg = buildRouteRegistry(doc, h, routeRules);
    this.entries = reg.entries;

    this.upstreamHeaders = Object.fromEntries(Object.entries(h.upstreamHeaders).map(([k, v]) => [k.toLowerCase(), expandEnv(v, env)]));
  }

  private installVerifier(o: HttpProxyOptions): void {
    const h = this.http;
    const read = o.readFile ?? ((p: string) => readFileSync(p, 'utf8'));
    if (h.mode === 'verify') {
      const grants = new Map<string, Capability>();
      for (const f of h.grants) {
        const g = JSON.parse(read(f)) as Capability;
        if (typeof g?.id !== 'string') throw new ConfigError(`http.grants: ${f} is not an encoded grant`);
        grants.set(g.id, g);
      }
      // the replay counters, the budget and what the gateway has seen reach each agent live in the proxy's durable state
      const state = this.engine.state.pca;
      const provenanceLog = durableProvenanceLog(this.engine.state.kv);
      const revFile = o.cfg.agent.revocationFile;
      this.engine.verifier = async (call: Call, args) => {
        const c = call.ctx as VerifyCtx;
        const e = call.entry!;
        const d = await gatewayAuthorize(
          { method: c.method, path: c.path, query: c.query, headers: c.headers, body: c.body.toString('utf8') },
          {
            audience: o.cfg.audience,
            routes: [{ method: c.method, path: c.path, capability: { verb: e.verb } }],
            resolveGrant: (ref) => grants.get(ref),
            // the single-step plan is authorized by the full pipeline below (it must be exactly the step that was signed)
            insecureSkipPlanRootCheck: true,
            unmatchedRoute: 'deny',
            pathPolicy: 'strict',
            policy: { mode: 'full', params: () => args, state, isRevoked: () => revFile !== undefined && existsSync(revFile), risk: (_g, _p, pc) => this.engine.riskOf(pc.action.verb), provenance: { actions: (op) => this.engine.infoOf(op.verb) }, provenanceLog },
          },
        );
        c.status = d.status;
        return d.allow && d.pcactn !== undefined ? { ok: true, pcactn: d.pcactn as PCActn } : { ok: false, reason: d.reason };
      };
    }
  }

  /** The mapped actions, most specific route first. */
  get routes(): readonly ActionEntry[] {
    return this.entries;
  }

  /** Handle one request. Never throws: any failure is a refusal. */
  async handle(req: HttpRequestLike): Promise<HttpResponseLike> {
    try {
      return await this.route(req);
    } catch (e) {
      return deny(500, 'internal_error', `the request could not be handled (fail closed): ${e instanceof Error ? e.message.slice(0, 100) : 'error'}`);
    }
  }

  private async route(req: HttpRequestLike): Promise<HttpResponseLike> {
    const h = this.http;
    const method = req.method.toUpperCase();
    // ---- the request line and the headers
    const q = req.url.indexOf('?');
    const path = q < 0 ? req.url : req.url.slice(0, q);
    const rawQuery = q < 0 ? '' : req.url.slice(q + 1);
    if (!path.startsWith('/') || path.length > 2048) return deny(400, 'bad_request', 'the request target is not an origin-form path');
    if (path.includes('*')) return deny(400, 'bad_request', 'a path may not contain *');
    const bad = ambiguousPathReason(path);
    if (bad !== undefined) return deny(400, 'invalid_path', bad);
    const hv = (n: string): string | undefined => {
      const v = req.headers[n];
      return Array.isArray(v) ? undefined : v;
    };
    for (const [k, v] of Object.entries(req.headers)) {
      if (Array.isArray(v) && (k === 'content-type' || k === 'content-length' || k === 'pca-action' || k === 'pca-provenance' || k === h.sessionHeader || k === 'host')) return deny(400, 'bad_request', `the header '${k}' is repeated`);
    }
    if (req.headers['transfer-encoding'] !== undefined && req.headers['content-length'] !== undefined) return deny(400, 'bad_request', 'both Transfer-Encoding and Content-Length are present');
    const sess = (h.sessionHeader !== undefined ? hv(h.sessionHeader) : undefined) ?? 'default';
    if (!SESSION_RE.test(sess)) return deny(400, 'bad_request', 'the session header is not a short token');

    // ---- the action
    const m = matchRoute(this.entries, method, path);
    const observe = this.cfg.mode === 'observe';
    if (m === undefined) {
      const v = await this.engine.evaluate({ kind: 'http', name: `${method} ${path}`, entry: undefined, args: {}, session: sess });
      if (!v.forward) return deny(403, v.code, v.reason, { 'www-authenticate': 'PCA error="access_denied"' });
      return this.forward(req, method, path, rawQuery, req.body, sess, undefined, observe);
    }
    const entry = m.entry;
    const params = entry.def.params;

    // ---- the arguments: path, query, body; a name in two places is ambiguous
    const args: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    const put = (k: string, v: unknown): string | undefined => {
      if (Object.prototype.hasOwnProperty.call(args, k)) return `the parameter '${k}' appears more than once`;
      args[k] = v;
      return undefined;
    };
    for (const [k, v] of Object.entries(m.params)) {
      const dup = put(k, coerce(params[k], v));
      if (dup) return deny(400, 'ambiguous_param', dup);
    }
    const qp = new URLSearchParams(rawQuery);
    const seen = new Map<string, string[]>();
    for (const [k, v] of qp) seen.set(k, [...(seen.get(k) ?? []), v]);
    for (const [k, vs] of seen) {
      const d = params[k];
      let val: unknown;
      if (vs.length > 1) {
        if (d?.type !== 'array' && d?.type !== 'set') return deny(400, 'ambiguous_param', `the query parameter '${k}' is repeated`);
        val = vs.map((x) => (d.items === 'integer' ? coerce({ type: 'integer' }, x) : x));
      } else val = d?.type === 'array' || d?.type === 'set' ? [coerce(d.items === 'integer' ? { type: 'integer' } : undefined, vs[0]!)] : coerce(d, vs[0]!);
      const dup = put(k, val);
      if (dup) return deny(400, 'ambiguous_param', dup);
    }
    let bodyObj: Record<string, unknown> | undefined;
    if (req.body.length > 0) {
      if (!BODY_METHODS.has(method)) return deny(400, 'bad_request', `a ${method} request may not carry a body`);
      const ct = (hv('content-type') ?? '').toLowerCase();
      if (!/^application\/(?:[a-z0-9.+-]*\+)?json(?:\s*;.*)?$/.test(ct)) return deny(415, 'unsupported_media_type', 'the body must be JSON');
      if (req.body.length > this.cfg.limits.maxRequestBytes) return deny(413, 'payload_too_large', `the body is larger than ${this.cfg.limits.maxRequestBytes} bytes`);
      let parsed: unknown;
      try {
        parsed = strictParse(req.body.toString('utf8'));
      } catch (e) {
        return deny(400, 'bad_body', `the body is not strict JSON: ${e instanceof Error ? e.message.slice(0, 80) : 'error'}`);
      }
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return deny(400, 'bad_body', 'the body must be a JSON object');
      bodyObj = parsed as Record<string, unknown>;
      for (const [k, v] of Object.entries(bodyObj)) {
        const dup = put(k, v);
        if (dup) return deny(400, 'ambiguous_param', dup);
      }
    }

    // ---- the decision
    const ctx: VerifyCtx = { method, path, query: rawQuery, headers: req.headers, body: req.body };
    const call: Call = { kind: 'http', name: `${method} ${path}`, entry, args, session: sess, ctx };
    const v = await this.engine.evaluate(call);
    if (!v.forward) {
      const noProof = h.mode === 'verify' && hv('pca-action') === undefined;
      const status = v.code === 'verify_denied' ? (noProof ? 401 : (ctx.status ?? 403)) : v.code === 'bad_args' ? 422 : 403;
      return deny(status, v.code, v.reason, { 'www-authenticate': `PCA error="${v.code === 'verify_denied' ? 'invalid_proof' : 'access_denied'}"` });
    }
    // the query goes upstream re-serialized from what was checked, not as the client spelled it
    return this.forward(req, method, path, qp.toString(), bodyObj === undefined ? undefined : Buffer.from(JSON.stringify(bodyObj)), sess, v.proof, !v.allowed);
  }

  private async forward(req: HttpRequestLike, method: string, path: string, rawQuery: string, body: Buffer | undefined, sess: string, proof: string | undefined, unvetted: boolean): Promise<HttpResponseLike> {
    const base = new URL(this.http.upstream);
    const target = new URL(`${base.pathname.replace(/\/$/, '')}${path}${rawQuery === '' ? '' : `?${rawQuery}`}`, base.origin);
    const out: Record<string, string> = {};
    for (const n of [...SAFE_HEADERS, ...this.http.forwardHeaders]) {
      const v = req.headers[n];
      if (typeof v === 'string' && !NEVER.has(n)) out[n] = v;
    }
    Object.assign(out, this.upstreamHeaders);
    if (proof !== undefined && this.http.attachProof) out['pca-action'] = proof;
    let init: RequestInit = { method, headers: out, redirect: 'manual', signal: AbortSignal.timeout(this.cfg.limits.upstreamTimeoutMs) };
    if (body !== undefined && body.length > 0) {
      init = { ...init, body: new Uint8Array(body) };
      if (out['content-type'] === undefined) out['content-type'] = 'application/json';
    }
    let res: Response;
    try {
      res = await this.fetchImpl(target, init);
    } catch {
      return deny(502, 'upstream_error', 'the upstream did not complete the request');
    }
    // a redirect or a server error is the upstream failing: nothing it said is relayed
    if (res.status >= 300 && res.status < 400) return deny(502, 'upstream_error', 'the upstream answered with a redirect');
    if (res.status >= 500) return deny(502, 'upstream_error', `the upstream failed (${res.status})`);
    const chunks: Buffer[] = [];
    let n = 0;
    if (res.body !== null) {
      const reader = res.body.getReader();
      for (;;) {
        let r: Awaited<ReturnType<typeof reader.read>>;
        try {
          r = await reader.read();
        } catch {
          return deny(502, 'upstream_error', 'the upstream response could not be read');
        }
        if (r.done) break;
        n += r.value.byteLength;
        if (n > this.cfg.limits.maxResponseBytes) {
          await reader.cancel();
          return deny(502, 'response_too_large', `the upstream response is larger than ${this.cfg.limits.maxResponseBytes} bytes`);
        }
        chunks.push(Buffer.from(r.value));
      }
    }
    const buf = Buffer.concat(chunks);
    // the response reaches the agent's context: untrusted from here on, recorded before it is relayed
    try {
      await this.engine.taint(sess, 'web', `${method} ${target.origin}${path}`.slice(0, 200), buf.toString('utf8'));
    } catch {
      return deny(503, 'state_unavailable', 'the response could not be labelled untrusted, so it is not relayed');
    }
    const headers: Record<string, string> = { 'cache-control': 'no-store', 'x-pca-proxy': unvetted ? 'observed' : 'allowed' };
    const ct = res.headers.get('content-type');
    if (ct !== null) headers['content-type'] = ct;
    return { status: res.status, headers, body: buf };
  }

  /** Serve over node:http. */
  listen(host = this.http.listen.host, port = this.http.listen.port): Promise<Server> {
    const max = this.cfg.limits.maxRequestBytes;
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
        if (over && !rs.headersSent) {
          rs.writeHead(413, { 'content-type': 'application/json' }).end(JSON.stringify({ error: { code: 'payload_too_large', message: `the body is larger than ${max} bytes` } }));
        }
      });
      rq.on('end', () => {
        void this.handle({ method: rq.method ?? 'GET', url: rq.url ?? '/', headers: rq.headers, body: Buffer.concat(chunks) }).then((r) => {
          rs.writeHead(r.status, r.headers).end(r.body);
        });
      });
    });
    server.headersTimeout = 15_000;
    server.requestTimeout = 60_000;
    return new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, host, () => resolve(server));
    });
  }
}

interface VerifyCtx {
  method: string;
  path: string;
  query: string;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
  status?: number;
}
