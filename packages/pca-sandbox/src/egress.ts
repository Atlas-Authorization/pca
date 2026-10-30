import { createHash } from 'node:crypto';
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { hashCanonical, isAuthorizedFor } from '@atlasauth/pca';
import type { AuthorizeResult, PcaGuardResult, PcaOperation } from '@atlasauth/pca';
import { ReceiptLog, type RuntimeClass } from './receipts';

/**
 * The one outbound request an authorized operation maps to. The tool author writes the mapping from the operation to this
 * template (like the `operation` mapping of the adapters); the proxy never derives it from what the tool sends.
 * Exact host, exact port, exact method; the path is exact unless `path_prefix` is true; the query must equal `query`
 * (absent = no query). A request with a body must match `body_sha256`; a request without a template body hash may not
 * carry a body. `tunnel` admits a CONNECT to host:port instead (the proxy cannot see inside TLS: this is host-and-port
 * grain only, and must be asked for explicitly).
 */
export interface EgressTemplate {
  method: string;
  scheme: 'http' | 'https';
  host: string;
  port?: number;
  path: string;
  path_prefix?: boolean;
  query?: string;
  /** base64url sha256 of the exact request body bytes. */
  body_sha256?: string;
  tunnel?: boolean;
}

export interface EgressRequest {
  method: string;
  /** Absolute URL for a plain request; `host:port` for CONNECT. */
  url: string;
  body?: Uint8Array;
}

export type EgressDecision = { allow: true; op_id: string } | { allow: false; reason: string };

interface Admission {
  op_id: string;
  op: PcaOperation;
  template: Required<Pick<EgressTemplate, 'method' | 'scheme' | 'host' | 'port' | 'path'>> & EgressTemplate;
  uses: number;
  expiresAt: number;
}

const DEFAULT_PORT = { http: 80, https: 443 } as const;
const HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;

export const sha256b64u = (b: Uint8Array): string => createHash('sha256').update(b).digest('base64url');

/** Default deny. The only way a request is allowed is by matching a template admitted from a verified operation. */
export class EgressPolicy {
  private readonly admissions: Admission[] = [];
  constructor(private readonly now: () => number = Date.now) {}

  /** Admit the request that `operation` maps to. Throws unless `result` allows exactly `operation` and the template is well formed. */
  admit(result: AuthorizeResult | PcaGuardResult, operation: PcaOperation, toRequest: (op: PcaOperation) => EgressTemplate | null, opts: { uses?: number; expiresAt?: number } = {}): void {
    if (!isAuthorizedFor(result, operation)) throw new Error('not_authorized: result does not allow exactly this operation');
    const t = toRequest(operation);
    if (!t) throw new Error('no_egress_for_operation');
    const host = t.host;
    if (!(net.isIP(host) !== 0 || HOST_RE.test(host)) || host !== host.toLowerCase()) throw new Error('bad_template_host');
    if (t.scheme !== 'http' && t.scheme !== 'https') throw new Error('bad_template_scheme');
    const port = t.port ?? DEFAULT_PORT[t.scheme];
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('bad_template_port');
    if (!/^[A-Z]+$/.test(t.method)) throw new Error('bad_template_method');
    if (!t.path.startsWith('/') || /[?#\\]|%2e|%2f|%5c|(^|\/)\.\.?(\/|$)/i.test(t.path)) throw new Error('bad_template_path');
    const uses = opts.uses ?? 1;
    if (!Number.isInteger(uses) || uses < 1) throw new Error('bad_uses');
    const bound = (result as { operation?: { id: string } }).operation;
    this.admissions.push({ op_id: bound?.id ?? '', op: operation, template: { ...t, host, port }, uses, expiresAt: opts.expiresAt ?? Infinity });
  }

  /** Decide and, if allowed, spend one use of the matching admission. Anything not matched is denied with a reason. */
  claim(req: EgressRequest): EgressDecision & { admission?: { verb: string; resource: string; params_digest: string } } {
    const parsed = parseTarget(req);
    if ('reason' in parsed) return { allow: false, reason: parsed.reason };
    const body = req.body ?? new Uint8Array(0);
    let why = 'no_admission';
    for (const a of this.admissions) {
      const t = a.template;
      if (parsed.connect !== (t.tunnel === true)) continue;
      if (t.method !== req.method.toUpperCase() && !parsed.connect) continue;
      if (parsed.scheme !== t.scheme && !parsed.connect) continue;
      if (parsed.host !== t.host || parsed.port !== t.port) continue;
      if (!parsed.connect) {
        if (!(t.path_prefix ? parsed.path === t.path || parsed.path.startsWith(t.path.endsWith('/') ? t.path : `${t.path}/`) : parsed.path === t.path)) continue;
        if (parsed.query !== (t.query ?? '')) { why = 'query_mismatch'; continue; }
        if (body.length > 0 && (t.body_sha256 === undefined || sha256b64u(body) !== t.body_sha256)) { why = 'body_mismatch'; continue; }
        if (body.length === 0 && t.body_sha256 !== undefined && t.body_sha256 !== sha256b64u(body)) { why = 'body_mismatch'; continue; }
      }
      if (a.uses < 1 || this.now() >= a.expiresAt) { why = 'spent'; continue; } // reported only when the request would otherwise have matched
      a.uses -= 1;
      return { allow: true, op_id: a.op_id, admission: { verb: a.op.verb, resource: a.op.resource, params_digest: hashCanonical(a.op.params) } };
    }
    return { allow: false, reason: why };
  }
}

type Target = { connect: boolean; scheme: 'http' | 'https'; host: string; port: number; path: string; query: string } | { reason: string };

function parseTarget(req: EgressRequest): Target {
  if (req.method.toUpperCase() === 'CONNECT') {
    const m = /^([a-z0-9.-]+|\[[0-9a-f:]+\]):(\d{1,5})$/i.exec(req.url);
    if (!m) return { reason: 'bad_connect_target' };
    return { connect: true, scheme: 'https', host: m[1]!.replace(/^\[|\]$/g, '').toLowerCase(), port: Number(m[2]), path: '', query: '' };
  }
  let u: URL;
  try {
    u = new URL(req.url);
  } catch {
    return { reason: 'not_absolute_url' };
  }
  if ((u.protocol !== 'http:' && u.protocol !== 'https:') || u.username || u.password || u.hash) return { reason: 'bad_url' };
  // encoded dots and slashes are how a prefix match is walked out of: refuse rather than decode
  if (/%2e|%2f|%5c|\\/i.test(u.pathname)) return { reason: 'encoded_path' };
  const scheme = u.protocol === 'http:' ? 'http' : 'https';
  return { connect: false, scheme, host: u.hostname.replace(/^\[|\]$/g, '').toLowerCase(), port: u.port ? Number(u.port) : DEFAULT_PORT[scheme], path: u.pathname, query: u.search.replace(/^\?/, '') };
}

/** Loopback, link-local, private, CGNAT and unspecified addresses (and v4-mapped v6 of them). */
export function isPrivateAddress(ip: string): boolean {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (mapped) return isPrivateAddress(mapped[1]!);
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number) as [number, number];
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    return l === '::' || l === '::1' || /^f[cd]/.test(l) || /^fe[89ab]/.test(l) || l.startsWith('ff');
  }
  return true;
}

const isPrivateIfLiteral = (host: string): boolean => {
  const h = host.replace(/^\[|\]$/g, '');
  return net.isIP(h) !== 0 && isPrivateAddress(h);
};

const HOP = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'host']);

export interface EgressProxyOptions {
  policy: EgressPolicy;
  log: ReceiptLog;
  runtimeClass?: RuntimeClass;
  /** Permit upstreams that resolve to private/loopback addresses (tests, internal APIs). Default false (SSRF guard). */
  allowPrivate?: boolean;
  maxBodyBytes?: number;
  upstreamTimeoutMs?: number;
}

/**
 * A forward proxy for non-WASM tools: set it as the tool's only route out (HTTP(S)_PROXY, a network namespace, or the
 * generated OS profile that permits connecting only to this proxy). Every request is claimed against the admissions;
 * refusals answer 403 and are receipted. The upstream address is resolved through a guard that refuses private addresses
 * unless `allowPrivate`, so an admitted hostname cannot be re-pointed at an internal service.
 */
export function createEgressProxy(o: EgressProxyOptions): http.Server {
  const cls = o.runtimeClass ?? 'egress_default_deny';
  const maxBody = o.maxBodyBytes ?? 1 << 20;
  const timeout = o.upstreamTimeoutMs ?? 10_000;
  const lookup: net.LookupFunction = (host, options, cb) => {
    dns.lookup(host, options as dns.LookupOptions, (err, address, family) => {
      const list = Array.isArray(address) ? address.map((a) => a.address) : address ? [address] : [];
      if (!err && !o.allowPrivate && list.some(isPrivateAddress)) return (cb as (e: NodeJS.ErrnoException | null, a?: unknown, f?: number) => void)(Object.assign(new Error('private_address'), { code: 'EACCES' }) as NodeJS.ErrnoException);
      (cb as (e: NodeJS.ErrnoException | null, a?: unknown, f?: number) => void)(err, address, family);
    });
  };
  const receipt = (method: string, url: string, d: EgressDecision & { admission?: { verb: string; resource: string; params_digest: string } }, outcome: 'ok' | 'refused' | 'error', reason: string) =>
    o.log.append(cls, { kind: 'egress', subject: { op_id: d.allow ? d.op_id : '', verb: d.allow ? d.admission?.verb ?? '' : '', resource: d.allow ? d.admission?.resource ?? '' : `${method} ${url}`.slice(0, 256), params_digest: d.allow ? d.admission?.params_digest ?? '' : '' }, outcome, reason });

  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let over = false;
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > maxBody) over = true;
      else chunks.push(c);
    });
    req.on('end', () => {
      const method = req.method ?? 'GET';
      const url = req.url ?? '';
      const deny = (reason: string, status = 403) => {
        receipt(method, url, { allow: false, reason }, 'refused', reason);
        res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify({ error: 'egress_denied', reason }));
      };
      if (over) return deny('body_too_large', 413);
      const d = o.policy.claim({ method, url, body: Buffer.concat(chunks) });
      if (!d.allow) return deny(d.reason);
      const u = new URL(url);
      // Node does not call `lookup` for an IP literal, so the private-address guard must run here too
      if (!o.allowPrivate && isPrivateIfLiteral(u.hostname)) {
        receipt(method, url, d, 'error', 'upstream:EACCES');
        return void res.writeHead(502).end();
      }
      const headers: http.OutgoingHttpHeaders = {};
      for (const [k, v] of Object.entries(req.headers)) if (!HOP.has(k)) headers[k] = v;
      const mod = u.protocol === 'https:' ? https : http;
      const up = mod.request({ protocol: u.protocol, hostname: u.hostname.replace(/^\[|\]$/g, ''), port: u.port || undefined, method, path: u.pathname + u.search, headers, lookup, timeout }, (ur) => {
        const out: http.OutgoingHttpHeaders = {};
        for (const [k, v] of Object.entries(ur.headers)) if (!HOP.has(k)) out[k] = v;
        res.writeHead(ur.statusCode ?? 502, out);
        ur.pipe(res);
        ur.on('end', () => receipt(method, url, d, 'ok', `status:${ur.statusCode}`));
      });
      up.on('timeout', () => up.destroy(new Error('timeout')));
      up.on('error', (e) => {
        receipt(method, url, d, 'error', `upstream:${(e as NodeJS.ErrnoException).code ?? e.message}`.slice(0, 64));
        if (!res.headersSent) res.writeHead(502).end();
        else res.destroy();
      });
      up.end(Buffer.concat(chunks));
    });
  });

  server.on('connect', (req, client, head) => {
    const target = req.url ?? '';
    const d = o.policy.claim({ method: 'CONNECT', url: target });
    if (!d.allow) {
      receipt('CONNECT', target, d, 'refused', d.reason);
      client.end('HTTP/1.1 403 Forbidden\r\nconnection: close\r\n\r\n');
      return;
    }
    const [host, port] = [target.slice(0, target.lastIndexOf(':')).replace(/^\[|\]$/g, ''), Number(target.slice(target.lastIndexOf(':') + 1))];
    if (!o.allowPrivate && isPrivateIfLiteral(host)) {
      receipt('CONNECT', target, d, 'error', 'upstream:EACCES');
      client.end('HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\n\r\n');
      return;
    }
    const up = net.connect({ host, port, lookup, timeout });
    up.on('connect', () => {
      receipt('CONNECT', target, d, 'ok', 'tunnel');
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length) up.write(head);
      up.pipe(client);
      client.pipe(up);
    });
    const fail = (e: Error) => {
      receipt('CONNECT', target, d, 'error', `upstream:${(e as NodeJS.ErrnoException).code ?? 'error'}`);
      client.end('HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\n\r\n');
    };
    up.once('error', fail);
    up.on('timeout', () => up.destroy(new Error('timeout')));
    client.on('error', () => up.destroy());
    up.on('close', () => client.destroy());
  });
  return server;
}
