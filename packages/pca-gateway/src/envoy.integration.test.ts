/**
 * REAL-Envoy integration tests. Skipped unless PCA_ENVOY_BIN points at an Envoy binary
 * (see scripts/run-envoy-ext-authz.sh). Envoy is put in front of a recording upstream with an
 * http ext_authz filter in both HTTP-service and gRPC mode; the adapters under test are the library's
 * `envoyExtAuthz` / `envoyGrpcExtAuthz`.
 *
 * PCA_ENVOY_CAPTURE=<dir> additionally writes the CheckRequests Envoy actually sent as fixtures.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { agent, generateKeyPair, decodePCActn, decodePcaHeader, pcaHeaders, PCA_HEADER, type Capability } from '@atlasauth/pca';
import {
  envoyExtAuthz,
  envoyGrpcExtAuthz,
  memoryReplayGuard,
  type GatewayOptions,
} from './index';
import {
  bootstrap,
  freePort,
  rawRequest,
  startEnvoy,
  startHttpCheckService,
  startUpstream,
  type EnvoyProcess,
  type ListenerSpec,
  type RawResponse,
  type Recorder,
  type RecordedRequest,
} from '../test-support/envoy-harness';
import { startGrpcCheckServer, type GrpcCheckServer } from '../test-support/envoy-grpc-server';

const BIN = process.env.PCA_ENVOY_BIN;
const AUD = 'ins_acme';

const grants = new Map<string, Capability>();

function mint(o?: { aud?: string; verb?: string; resource?: string }): string {
  const a = agent({
    principal: generateKeyPair(),
    goal: 'refunds',
    permissions: { stripe: ['refund'] },
    limits: { refund: '$500/day' },
    aud: AUD,
  });
  const { encoded, pcactn } = a.act(
    o?.verb ?? 'stripe.refund',
    o?.resource ?? 'charge:ch_1',
    { amount: 20, currency: 'usd' },
    { counter: 1, ...(o?.aud !== undefined ? { aud: o.aud } : {}) },
  );
  grants.set(pcactn.grant_ref, a.grant as Capability);
  return pcaHeaders(encoded)[PCA_HEADER] as string;
}

const gwBase: GatewayOptions = {
  audience: AUD,
  routes: [
    { method: 'POST', path: '/refunds', capability: { verb: 'stripe.refund' } },
    { method: 'POST', path: '/payouts', capability: { verb: 'stripe.payout' } },
  ],
  resolveGrant: async (ref) => grants.get(ref) ?? null,
};
/** Strict: unmapped routes denied, single-use proofs. */
const gwStrict = (): GatewayOptions => ({ ...gwBase, replayGuard: memoryReplayGuard() });
/** Public pass-through for unmapped routes; the case where path ambiguity and header spoofing matter. */
const gwPublic = (o?: Partial<GatewayOptions>): GatewayOptions => ({ ...gwBase, unmatchedRoute: 'allow', ...o });

const d = BIN ? describe : describe.skip;

d('real Envoy ext_authz (HTTP service + gRPC)', () => {
  let envoy: EnvoyProcess;
  let upstream: Recorder<RecordedRequest>;
  let httpStrict: Recorder<RecordedRequest>;
  let httpPublic: Recorder<RecordedRequest>;
  let httpPublicNoPolicy: Recorder<RecordedRequest>;
  let grpcStrict: GrpcCheckServer;
  let grpcPublic: GrpcCheckServer;
  let version = '';
  const P: Record<string, number> = {};

  beforeAll(async () => {
    upstream = await startUpstream();
    httpStrict = await startHttpCheckService(envoyExtAuthz(gwStrict()));
    httpPublic = await startHttpCheckService(envoyExtAuthz(gwPublic()));
    httpPublicNoPolicy = await startHttpCheckService(envoyExtAuthz(gwPublic({ pathPolicy: 'off' })));
    grpcStrict = await startGrpcCheckServer(envoyGrpcExtAuthz(gwStrict()));
    grpcPublic = await startGrpcCheckServer(envoyGrpcExtAuthz(gwPublic()));
    const dead = await freePort(); // nothing listens here
    const specs: Array<Omit<ListenerSpec, 'port'>> = [
      { name: 'h', mode: 'http', authzPort: httpStrict.port },
      { name: 'hq', mode: 'http', authzPort: httpStrict.port, pathPrefix: '/pca-check' },
      { name: 'hb', mode: 'http', authzPort: httpStrict.port, withBody: { maxRequestBytes: 1024, allowPartialMessage: true } },
      { name: 'hbs', mode: 'http', authzPort: httpStrict.port, withBody: { maxRequestBytes: 1024, allowPartialMessage: false } },
      { name: 'hpub', mode: 'http', authzPort: httpPublic.port },
      { name: 'hpubnopol', mode: 'http', authzPort: httpPublicNoPolicy.port },
      { name: 'hpubnorm', mode: 'http', authzPort: httpPublicNoPolicy.port, normalizePath: true, mergeSlashes: true },
      { name: 'hdead', mode: 'http', authzPort: dead },
      { name: 'hdeadopen', mode: 'http', authzPort: dead, failureModeAllow: true },
      { name: 'g', mode: 'grpc', authzPort: grpcStrict.port },
      { name: 'gb', mode: 'grpc', authzPort: grpcStrict.port, withBody: { maxRequestBytes: 1024, allowPartialMessage: true } },
      { name: 'gpub', mode: 'grpc', authzPort: grpcPublic.port },
      { name: 'gdead', mode: 'grpc', authzPort: dead },
    ];
    const listeners: ListenerSpec[] = [];
    for (const s of specs) {
      const port = await freePort();
      P[s.name] = port;
      listeners.push({ ...s, port });
    }
    const adminPort = await freePort();
    envoy = await startEnvoy(BIN as string, bootstrap({ adminPort, upstreamPort: upstream.port, listeners }), adminPort);
    const ver = await rawRequest({ port: adminPort, path: '/server_info' });
    version = (JSON.parse(ver.body) as { version: string }).version;
  }, 60_000);

  afterAll(async () => {
    await envoy?.stop();
    await Promise.all([upstream?.close(), httpStrict?.close(), httpPublic?.close(), httpPublicNoPolicy?.close(), grpcStrict?.close(), grpcPublic?.close()]);
    const dir = process.env.PCA_ENVOY_CAPTURE;
    if (dir) {
      mkdirSync(dir, { recursive: true });
      const redact = (h: Record<string, unknown>): Record<string, unknown> =>
        Object.fromEntries(Object.entries(h).map(([k, v]) => [k, k === 'pca-action' ? '<PCA-Action proof: substituted by the test>' : v]));
      const pick = (r: RecordedRequest | undefined): unknown =>
        r && { method: r.method, path: r.url, headers: redact(r.headers as Record<string, unknown>), rawHeaderNames: r.rawHeaders.filter((_, i) => i % 2 === 0), body: r.body.length > 64 ? `<${r.body.length} bytes elided>` : r.body };
      const http = captures.http ?? [];
      const out = {
        _label: `CAPTURED from a running Envoy ${version} (tetratelabs/archive-envoy darwin-arm64) HTTP ext_authz http_service; the PCA-Action value is a placeholder.`,
        envoyVersion: version,
        requests: http.map((c) => ({ scenario: c.scenario, request: pick(c.req) })),
      };
      writeFileSync(join(dir, 'envoy-captured-http-check-requests.json'), JSON.stringify(out, null, 2) + '\n');
      const gout = {
        _label: `CAPTURED from a running Envoy ${version} (tetratelabs/archive-envoy darwin-arm64) gRPC ext_authz CheckRequest, decoded by protobufjs (camelCase); the PCA-Action value is a placeholder.`,
        envoyVersion: version,
        requests: (captures.grpc ?? []).map((c) => ({
          scenario: c.scenario,
          request: JSON.parse(JSON.stringify(c.req, (_k, v: unknown) => (typeof v === 'string' && v.length > 200 && /^[A-Za-z0-9_-]+$/.test(v) ? '<PCA-Action proof: substituted by the test>' : v))) as unknown,
        })),
      };
      writeFileSync(join(dir, 'envoy-captured-grpc-check-requests.json'), JSON.stringify(gout, null, 2) + '\n');
    }
  });

  const captures: { http?: Array<{ scenario: string; req: RecordedRequest | undefined }>; grpc?: Array<{ scenario: string; req: unknown }> } = {};
  const capHttp = (scenario: string, req: RecordedRequest | undefined): void => {
    (captures.http ??= []).push({ scenario, req });
  };
  const capGrpc = (scenario: string, req: unknown): void => {
    (captures.grpc ??= []).push({ scenario, req });
  };

  const pcaHdr = (enc: string): Record<string, string> => ({ 'PCA-Action': enc });
  const upstreamCount = (): number => upstream.items.length;
  const lastUpstream = (): RecordedRequest => upstream.items[upstream.items.length - 1] as RecordedRequest;
  const errorOf = (r: RawResponse): string => (JSON.parse(r.body) as { error: string }).error;

  const FLAVOURS = [
    { label: 'HTTP service', ok: 'h', body: 'hb', pub: 'hpub', dead: 'hdead', recorder: (): RecordedRequest[] => httpStrict.items },
    { label: 'gRPC', ok: 'g', body: 'gb', pub: 'gpub', dead: 'gdead', recorder: (): RecordedRequest[] => [] },
  ] as const;

  for (const f of FLAVOURS) {
    describe(f.label, () => {
      it('allows a valid PCActn: upstream receives the request plus the injected x-pca-* headers', async () => {
        const before = upstreamCount();
        const enc = mint();
        const r = await rawRequest({ port: P[f.ok] as number, method: 'POST', path: '/refunds', headers: pcaHdr(enc), body: '{"a":1}' });
        expect(r.status).toBe(200);
        expect(r.body).toBe('upstream-ok');
        expect(upstreamCount()).toBe(before + 1);
        const u = lastUpstream();
        expect(u.url).toBe('/refunds');
        expect(u.body).toBe('{"a":1}');
        expect(u.headers['x-pca-verb']).toBe('stripe.refund');
        expect(typeof u.headers['x-pca-grant']).toBe('string');
        expect((JSON.parse(u.headers['x-pca-verdict'] as string) as { allow: boolean }).allow).toBe(true);
      });

      it('denies a missing proof: Envoy returns the adapter status/body/challenge, upstream sees nothing', async () => {
        const before = upstreamCount();
        const r = await rawRequest({ port: P[f.ok] as number, method: 'POST', path: '/refunds' });
        expect(r.status).toBe(401);
        expect(errorOf(r)).toBe('no-proof');
        expect(String(r.headers['www-authenticate'])).toMatch(/^PCA realm="ins_acme"/);
        expect(r.headers['content-type']).toBe('application/json');
        expect(upstreamCount()).toBe(before);
      });

      it('denies a tampered proof (resource swapped after signing)', async () => {
        const before = upstreamCount();
        const enc = mint();
        const obj = decodePCActn(decodePcaHeader(enc)) as unknown as { action: { resource: string } };
        obj.action.resource = 'charge:ch_EVIL';
        const forged = Buffer.from(JSON.stringify(obj)).toString('base64url');
        const r = await rawRequest({ port: P[f.ok] as number, method: 'POST', path: '/refunds', headers: pcaHdr(forged) });
        expect(r.status).toBe(401);
        expect(['verify-failed', 'invalid-proof']).toContain(errorOf(r));
        expect(upstreamCount()).toBe(before);
      });

      it('denies garbage in PCA-Action', async () => {
        const before = upstreamCount();
        const r = await rawRequest({ port: P[f.ok] as number, method: 'POST', path: '/refunds', headers: pcaHdr('!!!nope!!!') });
        expect(r.status).toBe(401);
        expect(errorOf(r)).toBe('invalid-proof');
        expect(upstreamCount()).toBe(before);
      });

      it('denies a proof for another audience with 403', async () => {
        const before = upstreamCount();
        const r = await rawRequest({ port: P[f.ok] as number, method: 'POST', path: '/refunds', headers: pcaHdr(mint({ aud: 'ins_other' })) });
        expect(r.status).toBe(403);
        expect(errorOf(r)).toBe('wrong-audience');
        expect(String(r.headers['www-authenticate'])).toContain('invalid_resource');
        expect(upstreamCount()).toBe(before);
      });

      it('denies a refund proof presented at the payouts route', async () => {
        const before = upstreamCount();
        const r = await rawRequest({ port: P[f.ok] as number, method: 'POST', path: '/payouts', headers: pcaHdr(mint()) });
        expect(r.status).toBe(403);
        expect(errorOf(r)).toBe('insufficient-capability');
        expect(upstreamCount()).toBe(before);
      });

      it('denies an unmapped route even with a valid proof (deny-by-default)', async () => {
        const before = upstreamCount();
        const r = await rawRequest({ port: P[f.ok] as number, method: 'GET', path: '/admin', headers: pcaHdr(mint()) });
        expect(r.status).toBe(403);
        expect(errorOf(r)).toBe('unmapped-route');
        expect(upstreamCount()).toBe(before);
      });

      it('denies a replayed proof: first use allowed, second use 403', async () => {
        const enc = mint();
        const first = await rawRequest({ port: P[f.ok] as number, method: 'POST', path: '/refunds', headers: pcaHdr(enc) });
        expect(first.status).toBe(200);
        const before = upstreamCount();
        const second = await rawRequest({ port: P[f.ok] as number, method: 'POST', path: '/refunds', headers: pcaHdr(enc) });
        expect(second.status).toBe(403);
        expect(errorOf(second)).toBe('replayed-proof');
        expect(upstreamCount()).toBe(before);
      });

      it('route-matches on the path when Envoy forwards a query string, and the upstream still gets the query', async () => {
        const r = await rawRequest({
          port: P[f.ok] as number,
          method: 'POST',
          path: '/refunds?currency=usd&note=a%20b',
          headers: pcaHdr(mint()),
        });
        expect(r.status).toBe(200);
        expect(lastUpstream().url).toBe('/refunds?currency=usd&note=a%20b');
      });

      it('is case-insensitive on the PCA-Action header name (client sends PCA-ACTION / pca-action)', async () => {
        for (const name of ['PCA-ACTION', 'pca-action', 'Pca-Action']) {
          const r = await rawRequest({ port: P[f.ok] as number, method: 'POST', path: '/refunds', headers: { [name]: mint() } });
          expect(r.status, name).toBe(200);
        }
      });

      it('fails closed on a duplicated PCA-Action header (one valid + one junk)', async () => {
        const before = upstreamCount();
        const r = await rawRequest({
          port: P[f.ok] as number,
          method: 'POST',
          path: '/refunds',
          headers: { 'PCA-Action': [mint(), 'junk'] },
        });
        expect(r.status).toBe(401);
        expect(upstreamCount()).toBe(before);
      });

      it('with_request_body: a body larger than max_request_bytes is judged on headers alone and reaches the upstream whole', async () => {
        const big = 'x'.repeat(10_000);
        const r = await rawRequest({ port: P[f.body] as number, method: 'POST', path: '/refunds', headers: pcaHdr(mint()), body: big });
        expect(r.status).toBe(200);
        expect(lastUpstream().body.length).toBe(10_000);
      });

      it('a client-forged x-pca-verdict never reaches the upstream, on a pass-through route', async () => {
        const before = upstreamCount();
        const r = await rawRequest({
          port: P[f.pub] as number,
          method: 'GET',
          path: '/health',
          headers: { 'x-pca-verdict': '{"allow":true,"forged":true}', 'x-pca-verb': 'stripe.payout', 'x-pca-grant': 'forged' },
        });
        expect(r.status).toBe(200);
        expect(upstreamCount()).toBe(before + 1);
        const u = lastUpstream();
        expect(u.headers['x-pca-verdict'] ?? '').not.toContain('forged');
        expect(u.headers['x-pca-verb'] ?? '').not.toBe('stripe.payout');
        expect(u.headers['x-pca-grant'] ?? '').not.toBe('forged');
      });

      it('fails closed when the check service is down (failure_mode_allow=false): Envoy answers 403, upstream sees nothing', async () => {
        const before = upstreamCount();
        const r = await rawRequest({ port: P[f.dead] as number, method: 'POST', path: '/refunds', headers: pcaHdr(mint()) });
        expect(r.status).toBe(403);
        expect(upstreamCount()).toBe(before);
      });
    });
  }

  describe('HTTP service specifics', () => {
    it('with_request_body: Envoy sends the first max_request_bytes to the check service, content-length stays the full size', async () => {
      const big = 'y'.repeat(5000);
      const n = httpStrict.items.length;
      const r = await rawRequest({ port: P.hb as number, method: 'POST', path: '/refunds', headers: pcaHdr(mint()), body: big });
      expect(r.status).toBe(200);
      const c = httpStrict.items[n] as RecordedRequest;
      expect(c.body.length).toBe(1024);
      expect(c.headers['content-length']).toBe('1024');
      capHttp('with_request_body max=1024 allow_partial=true, 5000-byte body', c);
    });

    it('with_request_body allow_partial_message=false: an oversized body is refused by Envoy (413); neither the check service nor the upstream is called', async () => {
      const n = httpStrict.items.length;
      const before = upstreamCount();
      const r = await rawRequest({ port: P.hbs as number, method: 'POST', path: '/refunds', headers: pcaHdr(mint()), body: 'z'.repeat(5000) });
      expect(r.status).toBe(413);
      expect(httpStrict.items.length).toBe(n);
      expect(upstreamCount()).toBe(before);
    });

    it('with_request_body: a body within the limit reaches the check service whole', async () => {
      const n = httpStrict.items.length;
      const r = await rawRequest({ port: P.hbs as number, method: 'POST', path: '/refunds', headers: pcaHdr(mint()), body: '{"amount":20}' });
      expect(r.status).toBe(200);
      expect((httpStrict.items[n] as RecordedRequest).body).toBe('{"amount":20}');
    });

    it('without with_request_body the check request carries no body (content-length 0)', async () => {
      const n = httpStrict.items.length;
      const r = await rawRequest({ port: P.h as number, method: 'POST', path: '/refunds?currency=usd&note=a%20b', headers: { 'PCA-ACTION': mint(), 'X-Mixed-Case': 'v' }, body: '{"amount":20}' });
      expect(r.status).toBe(200);
      const c = httpStrict.items[n] as RecordedRequest;
      expect(c.body).toBe('');
      expect(c.headers['content-length']).toBe('0');
      expect(c.method).toBe('POST');
      expect(c.url).toBe('/refunds?currency=usd&note=a%20b');
      expect(c.rawHeaders.filter((_, i) => i % 2 === 0).every((k) => k === k.toLowerCase())).toBe(true);
      capHttp('POST /refunds?currency=usd&note=a%20b, client header PCA-ACTION', c);
    });

    it('contrast: failure_mode_allow=true FAILS OPEN when the check service is down (never configure it for PCA)', async () => {
      const before = upstreamCount();
      const r = await rawRequest({ port: P.hdeadopen as number, method: 'POST', path: '/refunds' });
      expect(r.status).toBe(200);
      expect(upstreamCount()).toBe(before + 1);
    });

    it('path_prefix: Envoy prepends it to the check request target, which the adapter would not route-match', async () => {
      const n = httpStrict.items.length;
      const r = await rawRequest({ port: P.hq as number, method: 'POST', path: '/refunds', headers: pcaHdr(mint()) });
      const c = httpStrict.items[n] as RecordedRequest;
      expect(c.url).toBe('/pca-check/refunds');
      // Documented limitation: do NOT set path_prefix without stripping it; routes are matched on the received path.
      expect(r.status).toBe(403);
    });
  });

  describe('path ambiguity (Envoy without normalize_path)', () => {
    it('Envoy forwards dot segments and double slashes untouched when normalize_path/merge_slashes are off', async () => {
      const n = httpPublicNoPolicy.items.length;
      await rawRequest({ port: P.hpubnopol as number, method: 'POST', path: '//refunds' });
      await rawRequest({ port: P.hpubnopol as number, method: 'POST', path: '/public/../refunds' });
      expect(httpPublicNoPolicy.items.slice(n).map((c) => c.url)).toEqual(['//refunds', '/public/../refunds']);
    });

    it('with pathPolicy off, an unmapped-allow gateway lets //refunds through with NO proof (the bypass the strict policy closes)', async () => {
      const before = upstreamCount();
      const r = await rawRequest({ port: P.hpubnopol as number, method: 'POST', path: '//refunds' });
      expect(r.status).toBe(200);
      expect(lastUpstream().url).toBe('//refunds');
      expect(upstreamCount()).toBe(before + 1);
    });

    it('default pathPolicy=strict denies //refunds, /x/../refunds, %2e%2e, %2F and %72efunds before route matching', async () => {
      for (const p of ['//refunds', '/public/../refunds', '/public/%2e%2e/refunds', '/refunds%2Fx', '/%72efunds']) {
        const before = upstreamCount();
        const r = await rawRequest({ port: P.hpub as number, method: 'POST', path: p });
        expect(r.status, p).toBe(400);
        expect(errorOf(r), p).toBe('invalid-path');
        expect(upstreamCount(), p).toBe(before);
      }
    });

    it('Envoy normalize_path+merge_slashes canonicalises the target before ext_authz sees it', async () => {
      const n = httpPublicNoPolicy.items.length;
      await rawRequest({ port: P.hpubnorm as number, method: 'POST', path: '//public/../refunds' });
      expect((httpPublicNoPolicy.items[n] as RecordedRequest).url).toBe('/refunds');
    });
  });

  describe('gRPC specifics', () => {
    it('Envoy delivers a CheckRequest with method, path (query string included), host and lower-cased headers', async () => {
      const n = grpcStrict.received.length;
      const r = await rawRequest({
        port: P.g as number,
        method: 'POST',
        path: '/refunds?currency=usd&note=a%20b',
        headers: { 'PCA-ACTION': mint(), 'X-Mixed-Case': 'v' },
        body: '{"amount":20}',
      });
      expect(r.status).toBe(200);
      const req = grpcStrict.received[n] as { attributes: { request: { http: { method: string; path: string; host: string; headers: Record<string, string> } } } };
      const http = req.attributes.request.http;
      expect(http.method).toBe('POST');
      expect(http.path).toBe('/refunds?currency=usd&note=a%20b');
      expect(http.host).toMatch(/^127\.0\.0\.1:/);
      expect(http.headers['pca-action']).toBeTruthy();
      expect(http.headers['x-mixed-case']).toBe('v');
      expect(Object.keys(http.headers).every((k) => k === k.toLowerCase())).toBe(true);
      capGrpc('POST /refunds?currency=usd&note=a%20b, client header PCA-ACTION', req);
    });

    it('with_request_body: Envoy puts the (truncated) body in the CheckRequest', async () => {
      const n = grpcStrict.received.length;
      const r = await rawRequest({ port: P.gb as number, method: 'POST', path: '/refunds', headers: pcaHdr(mint()), body: 'w'.repeat(5000) });
      expect(r.status).toBe(200);
      const req = grpcStrict.received[n] as { attributes: { request: { http: { body?: string; rawBody?: unknown; size: string } } } };
      const h = req.attributes.request.http;
      expect((h.body ?? '').length).toBe(1024);
      expect(h.size).toBe('5000');
      capGrpc('with_request_body max=1024 allow_partial=true, 5000-byte body (body elided)', {
        ...req,
        attributes: { request: { http: { ...h, body: `<${(h.body ?? '').length} bytes elided>`, rawBody: '<elided>' } } },
      });
    });
  });
});
