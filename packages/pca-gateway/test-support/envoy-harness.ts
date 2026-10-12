/**
 * Test harness for the real-Envoy integration tests: a recording upstream, an HTTP ext_authz check
 * service, and an Envoy bootstrap with one listener per scenario. Everything binds 127.0.0.1 on
 * ephemeral ports. Envoy itself is supplied by the caller (PCA_ENVOY_BIN).
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { createServer, request as httpRequest, type IncomingMessage, type Server } from 'node:http';
import { createServer as createNetServer, type AddressInfo } from 'node:net';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { EnvoyHttpCheckRequest, EnvoyHttpCheckResponse } from '../src/index';

export async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = createNetServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const p = (s.address() as AddressInfo).port;
      s.close(() => resolve(p));
    });
  });
}

export interface RecordedRequest {
  method: string;
  url: string;
  rawHeaders: string[];
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

export interface Recorder<T> {
  items: T[];
  server: Server;
  port: number;
  close(): Promise<void>;
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

/** A trivial upstream that records every request it receives and answers 200 `upstream-ok`. */
export async function startUpstream(): Promise<Recorder<RecordedRequest>> {
  const items: RecordedRequest[] = [];
  const server = createServer((req, res) => {
    void readBody(req).then((body) => {
      items.push({ method: req.method ?? '', url: req.url ?? '', rawHeaders: req.rawHeaders, headers: req.headers, body });
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('upstream-ok');
    });
  });
  const port = await new Promise<number>((r) => server.listen(0, '127.0.0.1', () => r((server.address() as AddressInfo).port)));
  return { items, server, port, close: () => new Promise((r) => { server.closeAllConnections(); server.close(() => r()); }) };
}

/**
 * The HTTP ext_authz check service: exactly what Envoy's `http_service` talks to. It records the
 * REAL request Envoy sent (method, target, raw headers, body) and answers with the library adapter.
 */
export async function startHttpCheckService(
  check: (c: EnvoyHttpCheckRequest) => Promise<EnvoyHttpCheckResponse>,
): Promise<Recorder<RecordedRequest>> {
  const items: RecordedRequest[] = [];
  const server = createServer((req, res) => {
    void readBody(req).then(async (body) => {
      items.push({ method: req.method ?? '', url: req.url ?? '', rawHeaders: req.rawHeaders, headers: req.headers, body });
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.headers)) if (typeof v === 'string') headers[k] = v;
      const out = await check({ method: req.method ?? '', path: req.url ?? '/', headers });
      res.writeHead(out.status, out.headers);
      res.end(out.body);
    });
  });
  const port = await new Promise<number>((r) => server.listen(0, '127.0.0.1', () => r((server.address() as AddressInfo).port)));
  return { items, server, port, close: () => new Promise((r) => { server.closeAllConnections(); server.close(() => r()); }) };
}

export interface ListenerSpec {
  name: string;
  port: number;
  /** `http` | `grpc`; which ext_authz transport the listener uses. */
  mode: 'http' | 'grpc';
  /** Port of the check service this listener calls. */
  authzPort: number;
  failureModeAllow?: boolean;
  withBody?: { maxRequestBytes: number; allowPartialMessage: boolean };
  normalizePath?: boolean;
  mergeSlashes?: boolean;
  /** HTTP mode only: Envoy `path_prefix` on the check request. */
  pathPrefix?: string;
  /** Extra headers the http_service forwards to the check service. */
  checkHeaders?: string[];
}

function extAuthzConfig(l: ListenerSpec): Record<string, unknown> {
  const base: Record<string, unknown> = {
    '@type': 'type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz',
    transport_api_version: 'V3',
    failure_mode_allow: l.failureModeAllow ?? false,
    ...(l.withBody
      ? { with_request_body: { max_request_bytes: l.withBody.maxRequestBytes, allow_partial_message: l.withBody.allowPartialMessage } }
      : {}),
  };
  if (l.mode === 'grpc') {
    base.grpc_service = { envoy_grpc: { cluster_name: `authz_grpc_${l.name}` }, timeout: '2s' };
  } else {
    base.http_service = {
      server_uri: { uri: `127.0.0.1:${l.authzPort}`, cluster: `authz_http_${l.name}`, timeout: '2s' },
      ...(l.pathPrefix ? { path_prefix: l.pathPrefix } : {}),
      authorization_request: {
        allowed_headers: { patterns: [{ exact: 'pca-action' }, { exact: 'x-request-id' }, ...(l.checkHeaders ?? []).map((h) => ({ exact: h }))] },
      },
      authorization_response: {
        allowed_upstream_headers: { patterns: [{ prefix: 'x-pca-' }] },
        allowed_client_headers: { patterns: [{ exact: 'www-authenticate' }, { exact: 'content-type' }] },
      },
    };
  }
  return base;
}

/** Build an Envoy bootstrap (JSON is valid YAML) with one listener per spec. */
export function bootstrap(opts: {
  adminPort: number;
  upstreamPort: number;
  listeners: ListenerSpec[];
}): Record<string, unknown> {
  const cluster = (name: string, port: number, http2 = false): Record<string, unknown> => ({
    name,
    type: 'STATIC',
    connect_timeout: '1s',
    ...(http2
      ? {
          typed_extension_protocol_options: {
            'envoy.extensions.upstreams.http.v3.HttpProtocolOptions': {
              '@type': 'type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions',
              explicit_http_config: { http2_protocol_options: {} },
            },
          },
        }
      : {}),
    load_assignment: {
      cluster_name: name,
      endpoints: [{ lb_endpoints: [{ endpoint: { address: { socket_address: { address: '127.0.0.1', port_value: port } } } }] }],
    },
  });
  // One authz cluster per listener so each scenario can point at a live or a dead check service.
  const clusters = [
    cluster('upstream', opts.upstreamPort),
    ...opts.listeners.map((l) => cluster(`authz_${l.mode}_${l.name}`, l.authzPort, l.mode === 'grpc')),
  ];
  return {
    admin: { address: { socket_address: { address: '127.0.0.1', port_value: opts.adminPort } } },
    static_resources: {
      listeners: opts.listeners.map((l) => ({
        name: l.name,
        address: { socket_address: { address: '127.0.0.1', port_value: l.port } },
        filter_chains: [
          {
            filters: [
              {
                name: 'envoy.filters.network.http_connection_manager',
                typed_config: {
                  '@type': 'type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager',
                  stat_prefix: l.name,
                  normalize_path: l.normalizePath ?? false,
                  merge_slashes: l.mergeSlashes ?? false,
                  route_config: {
                    virtual_hosts: [{ name: 'all', domains: ['*'], routes: [{ match: { prefix: '/' }, route: { cluster: 'upstream' } }] }],
                  },
                  http_filters: [
                    { name: 'envoy.filters.http.ext_authz', typed_config: extAuthzConfig(l) },
                    { name: 'envoy.filters.http.router', typed_config: { '@type': 'type.googleapis.com/envoy.extensions.filters.http.router.v3.Router' } },
                  ],
                },
              },
            ],
          },
        ],
      })),
      clusters,
    },
  };
}

export interface EnvoyProcess {
  child: ChildProcess;
  log: () => string;
  stop(): Promise<void>;
}

export async function startEnvoy(bin: string, config: Record<string, unknown>, adminPort: number): Promise<EnvoyProcess> {
  const dir = mkdtempSync(join(tmpdir(), 'pca-envoy-'));
  const cfg = join(dir, 'envoy.json');
  const logFile = join(dir, 'envoy.log');
  writeFileSync(cfg, JSON.stringify(config, null, 2));
  const child = spawn(bin, ['--config-path', cfg, '--disable-hot-restart', '--log-level', 'warn', '--log-path', logFile, '--concurrency', '1'], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stderr = '';
  child.stderr?.on('data', (c: Buffer) => (stderr += c.toString()));
  child.stdout?.on('data', (c: Buffer) => (stderr += c.toString()));
  const deadline = Date.now() + 30_000;
  for (;;) {
    if (child.exitCode !== null) throw new Error(`envoy exited ${child.exitCode}: ${stderr}`);
    try {
      const r = await rawRequest({ port: adminPort, path: '/ready' });
      if (r.status === 200) break;
    } catch {
      /* not up yet */
    }
    if (Date.now() > deadline) throw new Error(`envoy not ready: ${stderr}`);
    await new Promise((r) => setTimeout(r, 100));
  }
  return {
    child,
    log: () => {
      try {
        return readFileSync(logFile, 'utf8') + stderr;
      } catch {
        return stderr;
      }
    },
    stop: () =>
      new Promise((resolve) => {
        if (child.exitCode !== null) return resolve();
        child.once('exit', () => resolve());
        child.kill('SIGTERM');
        setTimeout(() => child.kill('SIGKILL'), 3000).unref();
      }),
  };
}

export interface RawResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

/** Plain HTTP/1.1 client that preserves the exact header casing and request target given. */
export function rawRequest(o: {
  port: number;
  method?: string;
  path: string;
  headers?: Record<string, string | string[]>;
  body?: string;
}): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: '127.0.0.1', port: o.port, method: o.method ?? 'GET', path: o.path, headers: o.headers ?? {}, setHost: !(o.headers && 'Host' in o.headers) },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
      },
    );
    req.on('error', reject);
    if (o.body !== undefined) req.write(o.body);
    req.end();
  });
}
