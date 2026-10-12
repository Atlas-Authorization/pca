import { readFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';
import { agent, generateKeyPair, pcaHeaders, PCA_HEADER, type Capability } from '@atlasauth/pca';
import {
  authorize,
  createGateway,
  envoyExtAuthz,
  envoyGrpcExtAuthz,
  memoryReplayGuard,
  cloudflareWorker,
  lambdaAuthorizer,
  lambdaSimpleAuthorizer,
  type GatewayOptions,
  type GatewayRequest,
  type RouteRule,
  type WorkerLikeRequest,
  type LambdaRequestAuthorizerEvent,
} from './index';

const AUD = 'ins_acme';

const ROUTES: RouteRule[] = [
  { method: 'POST', path: '/refunds', capability: { verb: 'stripe.refund' } },
  { method: 'POST', path: '/payouts', capability: { verb: 'stripe.payout' } },
];

type Minted = { encoded: string; grant: Capability; grantRef: string };

/** Mint a real, signed PCActn for `stripe.refund` and the grant a gateway would resolve for it. */
function mintRefund(opts?: { aud?: string; resource?: string }): Minted {
  const a = agent({
    principal: generateKeyPair(),
    goal: 'refunds',
    permissions: { stripe: ['refund'] },
    limits: { refund: '$500/day' },
    aud: AUD,
  });
  const { encoded, pcactn } = a.act(
    'stripe.refund',
    opts?.resource ?? 'charge:ch_1',
    { amount: 20, currency: 'usd' },
    { counter: 1, ...(opts?.aud !== undefined ? { aud: opts.aud } : {}) },
  );
  const grant = a.grant as Capability;
  return { encoded, grant, grantRef: pcactn.grant_ref };
}

/** Gateway options whose `resolveGrant` returns the grant that minted `m` (so the chain roots). */
function opts(m: Minted, overrides?: Partial<GatewayOptions>): GatewayOptions {
  return {
    audience: AUD,
    routes: ROUTES,
    bindRequest: false, // these tests are about routing/adapters; binding is covered in bind.test.ts
    resolveGrant: async (ref): Promise<Capability | null> => (ref === m.grantRef ? m.grant : null),
    ...overrides,
  };
}

/** The lowercase header map a gateway hands over, carrying the base64url PCActn. */
function hdr(encoded: string): Record<string, string> {
  const value = pcaHeaders(encoded)[PCA_HEADER];
  if (value === undefined) throw new Error('pcaHeaders did not produce a PCA-Action header');
  return { 'pca-action': value };
}

function refundRequest(encoded: string): GatewayRequest {
  return { method: 'POST', path: '/refunds', headers: hdr(encoded) };
}

// ---------------------------------------------------------------------------
// Generic core
// ---------------------------------------------------------------------------

describe('authorize (core)', () => {
  it('allows a valid proof-carrying request and surfaces the verdict + verb headers', async () => {
    const m = mintRefund();
    const decision = await authorize(refundRequest(m.encoded), opts(m));
    expect(decision.allow).toBe(true);
    expect(decision.status).toBe(200);
    expect(decision.code).toBe('allow');
    expect(decision.verdict?.allow).toBe(true);
    expect(decision.pcactn?.action.verb).toBe('stripe.refund');
    expect(decision.headers['x-pca-verb']).toBe('stripe.refund');
    expect(decision.headers['x-pca-grant']).toBe(m.grantRef);
  });

  it('denies with 401 + a PCA challenge when no proof is presented', async () => {
    const m = mintRefund();
    const decision = await authorize({ method: 'POST', path: '/refunds', headers: {} }, opts(m));
    expect(decision.allow).toBe(false);
    expect(decision.status).toBe(401);
    expect(decision.code).toBe('no-proof');
    expect(decision.headers['www-authenticate']).toMatch(/PCA realm/);
  });

  it('denies with 401 (invalid-proof) when the PCA-Action header is undecodable', async () => {
    const m = mintRefund();
    const decision = await authorize(
      { method: 'POST', path: '/refunds', headers: { 'pca-action': '!!!not-base64url!!!' } },
      opts(m),
    );
    expect(decision.allow).toBe(false);
    expect(decision.status).toBe(401);
    expect(decision.code).toBe('invalid-proof');
  });

  it('denies with 401 (unknown-grant) when the grant cannot be resolved', async () => {
    const m = mintRefund();
    const decision = await authorize(refundRequest(m.encoded), opts(m, { resolveGrant: async () => null }));
    expect(decision.allow).toBe(false);
    expect(decision.status).toBe(401);
    expect(decision.code).toBe('unknown-grant');
  });

  it('denies with 403 (wrong-audience) for a proof minted for another resource', async () => {
    const m = mintRefund({ aud: 'ins_other' });
    const decision = await authorize(refundRequest(m.encoded), opts(m));
    expect(decision.allow).toBe(false);
    expect(decision.status).toBe(403);
    expect(decision.code).toBe('wrong-audience');
    expect(decision.verdict?.checks.audience).toBe('fail');
  });

  it('enforces the route→capability map: a refund proof at the payouts route is insufficient', async () => {
    const m = mintRefund();
    const decision = await authorize(
      { method: 'POST', path: '/payouts', headers: hdr(m.encoded) },
      opts(m),
    );
    expect(decision.allow).toBe(false);
    expect(decision.status).toBe(403);
    expect(decision.code).toBe('insufficient-capability');
    expect(decision.verdict?.allow).toBe(true); // the proof verifies; it just lacks the required verb
  });

  it('enforces a resource-bound route capability', async () => {
    const m = mintRefund({ resource: 'charge:ch_OTHER' });
    const routes: RouteRule[] = [
      { method: 'POST', path: '/refunds', capability: { verb: 'stripe.refund', resource: 'charge:ch_1' } },
    ];
    const decision = await authorize(refundRequest(m.encoded), opts(m, { routes }));
    expect(decision.allow).toBe(false);
    expect(decision.code).toBe('insufficient-capability');
  });

  it('denies an unmapped dangerous route by default, even with a valid proof', async () => {
    const m = mintRefund();
    const decision = await authorize(
      { method: 'DELETE', path: '/admin/wipe', headers: hdr(m.encoded) },
      opts(m), // unmatchedRoute defaults to 'deny'
    );
    expect(decision.allow).toBe(false);
    expect(decision.status).toBe(403);
    expect(decision.code).toBe('unmapped-route');
  });

  it('can forward an unmapped route when unmatchedRoute=allow (no proof needed)', async () => {
    const m = mintRefund();
    const decision = await authorize(
      { method: 'GET', path: '/healthz', headers: {} },
      opts(m, { unmatchedRoute: 'allow' }),
    );
    expect(decision.allow).toBe(true);
  });

  it('require-proof on an unmapped route demands a valid proof but no specific verb', async () => {
    const m = mintRefund();
    const allowed = await authorize(
      { method: 'POST', path: '/other', headers: hdr(m.encoded) },
      opts(m, { unmatchedRoute: 'require-proof' }),
    );
    expect(allowed.allow).toBe(true);
    const denied = await authorize(
      { method: 'POST', path: '/other', headers: {} },
      opts(m, { unmatchedRoute: 'require-proof' }),
    );
    expect(denied.allow).toBe(false);
    expect(denied.code).toBe('no-proof');
  });

  it('uses the configured clock (expired proof denies)', async () => {
    const m = mintRefund();
    const decision = await authorize(
      refundRequest(m.encoded),
      opts(m, { now: () => Date.now() + 60 * 60_000 }), // an hour ahead: past exp
    );
    expect(decision.allow).toBe(false);
    expect(decision.code).toBe('verify-failed');
    expect(decision.verdict?.checks.validity).toBe('fail');
  });
});

// ---------------------------------------------------------------------------
// Envoy HTTP ext_authz
// ---------------------------------------------------------------------------

describe('envoyExtAuthz', () => {
  it('returns 200 and forwards the verdict upstream on a valid proof', async () => {
    const m = mintRefund();
    const check = envoyExtAuthz(opts(m));
    const res = await check({ method: 'POST', path: '/refunds', headers: { 'pca-action': hdr(m.encoded)['pca-action'] } });
    expect(res.status).toBe(200);
    expect(res.headers['x-pca-verb']).toBe('stripe.refund');
    const verdict = JSON.parse(res.headers['x-pca-verdict'] ?? '{}') as { allow: boolean };
    expect(verdict.allow).toBe(true);
  });

  it('returns 401 with a PCA challenge + JSON error body when no proof is presented', async () => {
    const m = mintRefund();
    const check = envoyExtAuthz(opts(m));
    const res = await check({ method: 'POST', path: '/refunds', headers: {} });
    expect(res.status).toBe(401);
    expect(res.headers['www-authenticate']).toMatch(/PCA realm/);
    const body = JSON.parse(res.body) as { error: string; reason: string };
    expect(body.error).toBe('no-proof');
  });

  it('reads the method/path from the :method / :path pseudo-headers as a fallback', async () => {
    const m = mintRefund();
    const check = envoyExtAuthz(opts(m));
    const res = await check({ headers: { ':method': 'POST', ':path': '/refunds', 'pca-action': hdr(m.encoded)['pca-action'] } });
    expect(res.status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// Cloudflare Worker
// ---------------------------------------------------------------------------

type FakeResponse = { status: number; body: string; headers: Record<string, string> };

function fakeRequest(method: string, url: string, pcaValue?: string): WorkerLikeRequest {
  const map = new Map<string, string>();
  if (pcaValue !== undefined) map.set(PCA_HEADER.toLowerCase(), pcaValue);
  return {
    method,
    url,
    headers: { get: (name: string): string | null => map.get(name.toLowerCase()) ?? null },
  };
}

describe('cloudflareWorker', () => {
  it('forwards to next on a valid proof', async () => {
    const m = mintRefund();
    const next = vi.fn(async (): Promise<FakeResponse> => ({ status: 200, body: 'upstream', headers: {} }));
    const respond = (body: string, init: { status: number; headers: Record<string, string> }): FakeResponse => ({
      status: init.status,
      body,
      headers: init.headers,
    });
    const handler = cloudflareWorker<WorkerLikeRequest, FakeResponse>({ ...opts(m), next, respond });
    const res = await handler(fakeRequest('POST', 'https://gw.example.com/refunds?x=1', hdr(m.encoded)['pca-action']));
    expect(next).toHaveBeenCalledOnce();
    expect(res.status).toBe(200);
    expect(res.body).toBe('upstream');
  });

  it('returns a 401 Response on deny and never calls next', async () => {
    const m = mintRefund();
    const next = vi.fn(async (): Promise<FakeResponse> => ({ status: 200, body: 'upstream', headers: {} }));
    const respond = (body: string, init: { status: number; headers: Record<string, string> }): FakeResponse => ({
      status: init.status,
      body,
      headers: init.headers,
    });
    const handler = cloudflareWorker<WorkerLikeRequest, FakeResponse>({ ...opts(m), next, respond });
    const res = await handler(fakeRequest('POST', 'https://gw.example.com/refunds'));
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toBe(401);
    expect(res.headers['www-authenticate']).toMatch(/PCA realm/);
    const body = JSON.parse(res.body) as { error: string };
    expect(body.error).toBe('no-proof');
  });

  it('returns a 403 Response for an unmapped dangerous route (deny-by-default)', async () => {
    const m = mintRefund();
    const next = vi.fn(async (): Promise<FakeResponse> => ({ status: 200, body: 'upstream', headers: {} }));
    const respond = (body: string, init: { status: number; headers: Record<string, string> }): FakeResponse => ({
      status: init.status,
      body,
      headers: init.headers,
    });
    const handler = cloudflareWorker<WorkerLikeRequest, FakeResponse>({ ...opts(m), next, respond });
    const res = await handler(fakeRequest('DELETE', 'https://gw.example.com/admin/wipe', hdr(m.encoded)['pca-action']));
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toBe(403);
  });
});

// ---------------------------------------------------------------------------
// AWS Lambda authorizer
// ---------------------------------------------------------------------------

describe('lambdaAuthorizer', () => {
  const METHOD_ARN = 'arn:aws:execute-api:us-east-1:123456789012:abc/prod/POST/refunds';

  it('returns an Allow policy with the verdict in context on a valid proof', async () => {
    const m = mintRefund();
    const handler = lambdaAuthorizer(opts(m));
    const event: LambdaRequestAuthorizerEvent = {
      headers: hdr(m.encoded),
      httpMethod: 'POST',
      path: '/refunds',
      methodArn: METHOD_ARN,
    };
    const res = await handler(event);
    expect(res.policyDocument.Statement[0]?.Effect).toBe('Allow');
    expect(res.policyDocument.Statement[0]?.Action).toBe('execute-api:Invoke');
    expect(res.policyDocument.Statement[0]?.Resource).toBe(METHOD_ARN);
    expect(res.policyDocument.Version).toBe('2012-10-17');
    expect(res.principalId).toBe(m.grantRef);
    const verdict = JSON.parse(res.context.pcaVerdict ?? '{}') as { allow: boolean };
    expect(verdict.allow).toBe(true);
  });

  it('returns a Deny policy when no proof is presented', async () => {
    const m = mintRefund();
    const handler = lambdaAuthorizer(opts(m));
    const res = await handler({ headers: {}, httpMethod: 'POST', path: '/refunds', methodArn: METHOD_ARN });
    expect(res.policyDocument.Statement[0]?.Effect).toBe('Deny');
    expect(res.policyDocument.Statement[0]?.Resource).toBe(METHOD_ARN);
    expect(res.context.pcaDenied).toBe('true');
    expect(res.context.pcaCode).toBe('no-proof');
  });

  it('derives method + path from the methodArn when not given explicitly', async () => {
    const m = mintRefund();
    const handler = lambdaAuthorizer(opts(m));
    // No httpMethod/path: the ARN tail `abc/prod/POST/refunds` must yield POST /refunds (allow).
    const res = await handler({ headers: hdr(m.encoded), methodArn: METHOD_ARN });
    expect(res.policyDocument.Statement[0]?.Effect).toBe('Allow');
  });

  it('reads the HTTP-API v2 requestContext.http shape', async () => {
    const m = mintRefund();
    const handler = lambdaAuthorizer(opts(m));
    const res = await handler({
      headers: hdr(m.encoded),
      routeArn: 'arn:aws:execute-api:us-east-1:123:api/$default/POST /refunds',
      requestContext: { http: { method: 'POST', path: '/refunds' } },
    });
    expect(res.policyDocument.Statement[0]?.Effect).toBe('Allow');
    expect(res.policyDocument.Statement[0]?.Resource).toBe('arn:aws:execute-api:us-east-1:123:api/$default/POST /refunds');
  });
});

describe('lambdaSimpleAuthorizer', () => {
  it('returns { isAuthorized: true } on a valid proof and false on deny', async () => {
    const m = mintRefund();
    const handler = lambdaSimpleAuthorizer(opts(m));
    const ok = await handler({ headers: hdr(m.encoded), httpMethod: 'POST', path: '/refunds' });
    expect(ok.isAuthorized).toBe(true);
    const bad = await handler({ headers: {}, httpMethod: 'POST', path: '/refunds' });
    expect(bad.isAuthorized).toBe(false);
    expect(bad.context.pcaCode).toBe('no-proof');
  });
});

describe('createGateway', () => {
  it('builds a reusable authorizer', async () => {
    const m = mintRefund();
    const gw = createGateway(opts(m));
    const a = await gw(refundRequest(m.encoded));
    const b = await gw({ method: 'POST', path: '/refunds', headers: {} });
    expect(a.allow).toBe(true);
    expect(b.allow).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Hardening found by running a real Envoy
// ---------------------------------------------------------------------------

describe('replay guard', () => {
  it('allows a proof once and denies the second presentation (403 replayed-proof)', async () => {
    const m = mintRefund();
    const o = opts(m, { replayGuard: memoryReplayGuard() });
    expect((await authorize(refundRequest(m.encoded), o)).allow).toBe(true);
    const again = await authorize(refundRequest(m.encoded), o);
    expect(again.allow).toBe(false);
    expect(again.status).toBe(403);
    expect(again.code).toBe('replayed-proof');
  });

  it('a denied attempt does not burn the proof', async () => {
    const m = mintRefund();
    const o = opts(m, { replayGuard: memoryReplayGuard() });
    const wrongRoute = await authorize({ method: 'POST', path: '/payouts', headers: hdr(m.encoded) }, o);
    expect(wrongRoute.code).toBe('insufficient-capability');
    expect((await authorize(refundRequest(m.encoded), o)).allow).toBe(true);
  });

  it('fails closed (503) when the guard throws or is full', async () => {
    const m = mintRefund();
    const thrower = { claim: (): boolean => { throw new Error('redis down'); } };
    const d1 = await authorize(refundRequest(m.encoded), opts(m, { replayGuard: thrower }));
    expect([d1.allow, d1.status, d1.code]).toEqual([false, 503, 'replay-guard-unavailable']);
    const full = memoryReplayGuard(1);
    full.claim('other', Date.now() + 60_000);
    const d2 = await authorize(refundRequest(m.encoded), opts(m, { replayGuard: full }));
    expect(d2.code).toBe('replay-guard-unavailable');
  });

  it('forgets expired claims', () => {
    let t = 1000;
    const g = memoryReplayGuard(10, () => t);
    expect(g.claim('k', 2000)).toBe(true);
    expect(g.claim('k', 2000)).toBe(false);
    t = 2001;
    expect(g.claim('k', 3000)).toBe(true);
  });
});

describe('path policy', () => {
  it.each(['//refunds', '/a/../refunds', '/a/./refunds', '/refunds/..', '/%2e%2e/refunds', '/refunds%2fx', '/refunds%5cx', '/%72efunds', '/refunds%00', '/refunds\\x', '/re%zzfunds', '/refunds\n'])(
    'denies the ambiguous target %j with 400 invalid-path',
    async (path) => {
      const m = mintRefund();
      const d = await authorize({ method: 'POST', path, headers: hdr(m.encoded) }, opts(m, { unmatchedRoute: 'allow' }));
      expect(d.allow).toBe(false);
      expect([d.status, d.code]).toEqual([400, 'invalid-path']);
    },
  );

  it('allows canonical paths including legitimately encoded reserved characters', async () => {
    const m = mintRefund();
    const o = opts(m, { unmatchedRoute: 'allow' });
    for (const path of ['/refunds', '/files/a%20b', '/x/a%2Bb', '/a.b/c-d_e~f']) {
      expect((await authorize({ method: 'GET', path, headers: {} }, o)).allow, path).toBe(true);
    }
  });

  it("'off' disables the check", async () => {
    const m = mintRefund();
    const d = await authorize({ method: 'GET', path: '//x', headers: {} }, opts(m, { unmatchedRoute: 'allow', pathPolicy: 'off' }));
    expect(d.allow).toBe(true);
  });
});

describe('envoyExtAuthz header injection safety', () => {
  it('overwrites every x-pca-* header on a pass-through allow so a forged one cannot reach the upstream', async () => {
    const m = mintRefund();
    const check = envoyExtAuthz(opts(m, { unmatchedRoute: 'allow' }));
    const res = await check({ method: 'GET', path: '/health', headers: { 'x-pca-verdict': '{"allow":true}' } });
    expect(res.status).toBe(200);
    expect(res.headers).toMatchObject({ 'x-pca-verdict': '', 'x-pca-verb': '', 'x-pca-grant': '' });
  });
});

describe('envoyGrpcExtAuthz', () => {
  const http = (over: Record<string, unknown>, headers: Record<string, string> = {}) => ({
    attributes: { request: { http: { method: 'POST', path: '/refunds?x=1', host: 'gw', headers, ...over } } },
  });

  it('allows with OVERWRITE headers and nothing to remove', async () => {
    const m = mintRefund();
    const res = await envoyGrpcExtAuthz(opts(m))(http({}, hdr(m.encoded)));
    expect(res.status.code).toBe(0);
    expect(res.okResponse?.headers.map((h) => h.header.key).sort()).toEqual(['x-pca-grant', 'x-pca-verb', 'x-pca-verdict']);
    expect(res.okResponse?.headers.every((h) => h.appendAction === 2)).toBe(true);
    expect(res.okResponse?.headersToRemove).toEqual([]);
  });

  it('removes unset x-pca-* headers on a pass-through allow', async () => {
    const m = mintRefund();
    const res = await envoyGrpcExtAuthz(opts(m, { unmatchedRoute: 'allow' }))(http({ path: '/health', method: 'GET' }));
    expect(res.status.code).toBe(0);
    expect([...(res.okResponse?.headersToRemove ?? [])].sort()).toEqual(['x-pca-grant', 'x-pca-verb', 'x-pca-verdict']);
  });

  it('maps 401 -> UNAUTHENTICATED(16), 403 -> PERMISSION_DENIED(7), 503 -> UNAVAILABLE(14) with the HTTP status in deniedResponse', async () => {
    const m = mintRefund();
    const noProof = await envoyGrpcExtAuthz(opts(m))(http({}));
    expect([noProof.status.code, noProof.deniedResponse?.status.code]).toEqual([16, 401]);
    const unmapped = await envoyGrpcExtAuthz(opts(m))(http({ path: '/nope' }, hdr(m.encoded)));
    expect([unmapped.status.code, unmapped.deniedResponse?.status.code]).toEqual([7, 403]);
    expect(JSON.parse(unmapped.deniedResponse?.body ?? '{}')).toMatchObject({ error: 'unmapped-route' });
    const thrower = { claim: (): boolean => { throw new Error('x'); } };
    const unavailable = await envoyGrpcExtAuthz(opts(m, { replayGuard: thrower }))(http({}, hdr(m.encoded)));
    expect([unavailable.status.code, unavailable.deniedResponse?.status.code]).toEqual([14, 503]);
  });

  it('falls back to :method/:path/:authority pseudo-headers and denies a CheckRequest with no http attributes', async () => {
    const m = mintRefund();
    const check = envoyGrpcExtAuthz(opts(m));
    const ok = await check({ attributes: { request: { http: { headers: { ':method': 'POST', ':path': '/refunds', ...hdr(m.encoded) } } } } });
    expect(ok.status.code).toBe(0);
    const none = await check({});
    expect(none.status.code).toBe(7);
    expect(none.deniedResponse?.status.code).toBe(403);
  });
});

describe('review hardening: path params, route variants', () => {
  it.each(['/refunds;x=1', '/public/..;/admin', '/a;/refunds', '/refunds/..;', '/%3brefunds'.replace('%3b', ';')])(
    'denies the path-parameter target %j with 400 invalid-path',
    async (path) => {
      const m = mintRefund();
      const d = await authorize({ method: 'POST', path, headers: hdr(m.encoded) }, opts(m, { unmatchedRoute: 'allow' }));
      expect([d.allow, d.status, d.code]).toEqual([false, 400, 'invalid-path']);
    },
  );

  it('percent-encoded ; is also ambiguous', async () => {
    const m = mintRefund();
    const d = await authorize({ method: 'POST', path: '/public/..%3Badmin', headers: hdr(m.encoded) }, opts(m, { unmatchedRoute: 'allow' }));
    expect(d.code).toBe('invalid-path');
  });

  it.each(['/refunds/', '/Refunds', '/REFUNDS'])(
    'documented: %j is NOT the mapped route; unmatchedRoute=allow passes it through, require-proof demands a proof, deny rejects it',
    async (path) => {
      const m = mintRefund();
      expect((await authorize({ method: 'POST', path, headers: {} }, opts(m, { unmatchedRoute: 'allow' }))).allow).toBe(true);
      const rp = await authorize({ method: 'POST', path, headers: {} }, opts(m, { unmatchedRoute: 'require-proof' }));
      expect([rp.allow, rp.code]).toEqual([false, 'no-proof']);
      expect((await authorize({ method: 'POST', path, headers: {} }, opts(m))).code).toBe('unmapped-route');
    },
  );
});

describe('review hardening: replay guard clock', () => {
  it('passes the gateway clock to the guard', async () => {
    const m = mintRefund();
    const base = Date.now();
    const seen: Array<number | undefined> = [];
    const guard = { claim: (_k: string, _e: number, nowMs?: number): boolean => { seen.push(nowMs); return true; } };
    await authorize(refundRequest(m.encoded), opts(m, { replayGuard: guard, now: () => base }));
    expect(seen).toEqual([base]);
  });

  it('a claim is live at exactly exp (the verifier accepts now == exp)', () => {
    let t = 1000;
    const g = memoryReplayGuard(10, () => t);
    expect(g.claim('k', 2000)).toBe(true);
    t = 2000;
    expect(g.claim('k', 2000)).toBe(false);
    t = 2001;
    expect(g.claim('k', 3000)).toBe(true);
  });

  it('claim() honours an explicit now argument over the guard clock', () => {
    const g = memoryReplayGuard(10, () => 99_999_999);
    expect(g.claim('k', 2000, 1000)).toBe(true);
    expect(g.claim('k', 2000, 1500)).toBe(false);
  });
});

describe('review hardening: cloudflareWorker scrubs x-pca-*', () => {
  type FR = { status: number; body: string; headers: Record<string, string> };
  const respond = (body: string, init: { status: number; headers: Record<string, string> }): FR => ({ ...init, body });
  function req(extra: Record<string, string>, pca?: string) {
    const map = new Map<string, string>(Object.entries(extra));
    if (pca) map.set('pca-action', pca);
    return {
      method: 'POST',
      url: 'https://gw.example.com/refunds',
      headers: {
        get: (n: string): string | null => map.get(n.toLowerCase()) ?? null,
        forEach: (cb: (v: string, k: string) => void): void => map.forEach((v, k) => cb(v, k)),
      },
    };
  }

  it('removes forged x-pca-* headers before forwarding on allow', async () => {
    const m = mintRefund();
    let seen: string[] | undefined;
    const handler = cloudflareWorker<ReturnType<typeof req>, FR>({
      ...opts(m),
      respond,
      next: async (r) => {
        const names: string[] = [];
        r.headers.forEach((_v, k) => names.push(k));
        seen = names;
        return { status: 200, body: 'ok', headers: {} };
      },
      rewriteRequest: (r, drop) => {
        const map = new Map<string, string>();
        r.headers.forEach((v, k) => { if (!drop.includes(k)) map.set(k, v); });
        return req(Object.fromEntries(map));
      },
    });
    const res = await handler(req({ 'x-pca-grant': 'forged', 'x-pca-extra': '1', accept: 'x' }, hdr(m.encoded)['pca-action']));
    expect(res.status).toBe(200);
    expect(seen).not.toContain('x-pca-grant');
    expect(seen).not.toContain('x-pca-extra');
    expect(seen).toContain('accept');
  });

  it('fails closed (400) when a forged header is present and the request cannot be rewritten', async () => {
    const m = mintRefund();
    const next = vi.fn(async (): Promise<FR> => ({ status: 200, body: 'ok', headers: {} }));
    const handler = cloudflareWorker<ReturnType<typeof req>, FR>({ ...opts(m), respond, next, rewriteRequest: null });
    const res = await handler(req({ 'x-pca-verdict': '{"allow":true}' }, hdr(m.encoded)['pca-action']));
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toBe(400);
  });
});

describe('review hardening: documented Envoy snippets forward/cover every x-pca-* header', () => {
  for (const f of ['README.md', 'src/index.ts']) {
    it(`${f} allowed_upstream_headers uses the x-pca- prefix`, () => {
      const text = readFileSync(f, 'utf8');
      const lines = text.split('\n').filter((l) => l.includes('allowed_upstream_headers:'));
      expect(lines.length).toBeGreaterThan(0);
      for (const l of lines) expect(l).toMatch(/prefix: "x-pca-"/);
    });
  }
});
