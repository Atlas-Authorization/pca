import { describe, expect, it, vi } from 'vitest';
import { agent, generateKeyPair, pcaHeaders, PCA_HEADER, type Capability } from '@atlasauth/pca';
import {
  authorize,
  createGateway,
  envoyExtAuthz,
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
