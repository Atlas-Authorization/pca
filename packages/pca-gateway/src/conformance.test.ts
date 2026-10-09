/**
 * Conformance tests for the gateway adapters against real runtimes and published payload shapes:
 *
 *  - Cloudflare Worker: the adapter is driven with the platform's REAL `Request` / `Response` classes
 *    (Node's globals) and, separately, the same entry is bundled and executed inside `workerd` through
 *    Miniflare so requests and responses cross the real Workers runtime.
 *  - AWS Lambda authorizer: events copied from the AWS API Gateway documentation (REST REQUEST
 *    authorizer, HTTP API payload format 1.0 and 2.0).
 *  - Envoy HTTP ext_authz: the request shape is hand-constructed from the documented behaviour (the
 *    request target includes the query string). Envoy itself is NOT run here; the fixture is labelled
 *    "constructed" in fixtures/PROVENANCE.json.
 *
 * Provenance + sha256 of every fixture is in fixtures/PROVENANCE.json and re-checked below.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { build } from 'esbuild';
import { Miniflare } from 'miniflare';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { agent, generateKeyPair, pcaHeaders, PCA_HEADER, type Capability } from '@atlasauth/pca';
import {
  cloudflareWorker,
  envoyExtAuthz,
  lambdaAuthorizer,
  lambdaSimpleAuthorizer,
  type EnvoyHttpCheckRequest,
  type GatewayOptions,
  type LambdaRequestAuthorizerEvent,
  type RouteRule,
} from './index';

const PKG = join(__dirname, '..');
const AUD = 'ins_acme';

function fixture(name: string): string {
  return readFileSync(join(PKG, 'fixtures', name), 'utf8');
}
function jsonFixture<T>(name: string): T {
  return JSON.parse(fixture(name)) as T;
}

type Minted = { encoded: string; grant: Capability; grantRef: string };

function mint(opts?: { aud?: string; verb?: string }): Minted {
  const a = agent({
    principal: generateKeyPair(),
    goal: 'refunds',
    permissions: { stripe: ['refund'] },
    limits: { refund: '$500/day' },
    aud: AUD,
  });
  const { encoded, pcactn } = a.act(
    opts?.verb ?? 'stripe.refund',
    'charge:ch_1',
    { amount: 20, currency: 'usd' },
    { counter: 1, ...(opts?.aud !== undefined ? { aud: opts.aud } : {}) },
  );
  return { encoded, grant: a.grant as Capability, grantRef: pcactn.grant_ref };
}

function gwOpts(m: Minted, routes: RouteRule[], extra?: Partial<GatewayOptions>): GatewayOptions {
  return {
    audience: AUD,
    routes,
    resolveGrant: async (ref): Promise<Capability | null> => (ref === m.grantRef ? m.grant : null),
    ...extra,
  };
}

function headerValue(encoded: string): string {
  const v = pcaHeaders(encoded)[PCA_HEADER];
  if (v === undefined) throw new Error('pcaHeaders did not produce a header');
  return v;
}

/** Flip one base64url character in the middle of the header so the proof no longer matches what was signed. */
function tamper(value: string): string {
  const i = Math.floor(value.length / 2);
  const c = value[i] === 'A' ? 'B' : 'A';
  return value.slice(0, i) + c + value.slice(i + 1);
}

// ---------------------------------------------------------------------------
// Fixture integrity
// ---------------------------------------------------------------------------

describe('fixtures', () => {
  it('match the sha256 recorded in PROVENANCE.json', () => {
    const prov = jsonFixture<{ files: { file: string; sha256: string; kind: string }[] }>('PROVENANCE.json');
    expect(prov.files.length).toBeGreaterThanOrEqual(6);
    for (const f of prov.files) {
      const sha = createHash('sha256').update(readFileSync(join(PKG, 'fixtures', f.file))).digest('hex');
      expect(sha, f.file).toBe(f.sha256);
    }
    const kinds = new Set(prov.files.map((f) => f.kind));
    expect(kinds.has('constructed-by-maintainers')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Real Fetch-API classes (Node global Request / Response)
// ---------------------------------------------------------------------------

describe('cloudflareWorker with the real Request / Response classes', () => {
  const routes: RouteRule[] = [{ method: 'POST', path: '/refunds', capability: { verb: 'stripe.refund' } }];

  function handlerFor(m: Minted, extra?: Partial<GatewayOptions>): {
    handle: (r: Request) => Promise<Response>;
    forwarded: Request[];
  } {
    const forwarded: Request[] = [];
    const handle = cloudflareWorker<Request, Response>({
      ...gwOpts(m, routes, extra),
      next: (req: Request): Response => {
        forwarded.push(req);
        return new Response('upstream-reached', { status: 200 });
      },
      respond: (body: string, init: { status: number; headers: Record<string, string> }): Response =>
        new Response(body, init),
    });
    return { handle, forwarded };
  }

  it('forwards the original Request (body intact) on a valid proof', async () => {
    const m = mint();
    const { handle, forwarded } = handlerFor(m);
    const req = new Request('https://gw.example.com/refunds?currency=usd', {
      method: 'POST',
      headers: { [PCA_HEADER]: headerValue(m.encoded), 'content-type': 'application/json' },
      body: JSON.stringify({ amount: 20 }),
    });
    const res = await handle(req);
    expect(res).toBeInstanceOf(Response);
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('upstream-reached');
    expect(forwarded).toHaveLength(1);
    expect(forwarded[0]).toBeInstanceOf(Request);
    // The gateway must not consume the body that the upstream still needs.
    expect(await forwarded[0]?.json()).toEqual({ amount: 20 });
  });

  it('answers 401 missing_proof as a real JSON Response and never forwards', async () => {
    const m = mint();
    const { handle, forwarded } = handlerFor(m);
    const res = await handle(new Request('https://gw.example.com/refunds', { method: 'POST' }));
    expect(res).toBeInstanceOf(Response);
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toBe('PCA realm="ins_acme", error="missing_proof"');
    expect(res.headers.get('content-type')).toBe('application/json');
    const body = (await res.json()) as { error: string; reason: string };
    expect(body.error).toBe('no-proof');
    expect(forwarded).toHaveLength(0);
  });

  it('rejects a tampered header with 401 invalid_proof', async () => {
    const m = mint();
    const { handle, forwarded } = handlerFor(m);
    const res = await handle(
      new Request('https://gw.example.com/refunds', { method: 'POST', headers: { [PCA_HEADER]: tamper(headerValue(m.encoded)) } }),
    );
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toBe('PCA realm="ins_acme", error="invalid_proof"');
    expect(forwarded).toHaveLength(0);
  });

  it('rejects a proof minted for another audience with 403 invalid_resource', async () => {
    const m = mint({ aud: 'ins_other' });
    const { handle } = handlerFor(m);
    const res = await handle(
      new Request('https://gw.example.com/refunds', { method: 'POST', headers: { [PCA_HEADER]: headerValue(m.encoded) } }),
    );
    expect(res.status).toBe(403);
    expect(res.headers.get('www-authenticate')).toBe('PCA realm="ins_acme", error="invalid_resource"');
    expect(((await res.json()) as { error: string }).error).toBe('wrong-audience');
  });

  it('rejects a verified proof whose verb does not match the route (403 insufficient_capability)', async () => {
    const m = mint({ verb: 'stripe.refund' });
    const { handle } = handlerFor(m, { routes: [{ method: 'POST', path: '/refunds', capability: { verb: 'stripe.payout' } }] });
    const res = await handle(
      new Request('https://gw.example.com/refunds', { method: 'POST', headers: { [PCA_HEADER]: headerValue(m.encoded) } }),
    );
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe('insufficient-capability');
  });

  it('matches on the pathname only: the query string never reaches route matching', async () => {
    const m = mint();
    const { handle } = handlerFor(m);
    const res = await handle(
      new Request('https://gw.example.com/refunds?x=/admin#frag', { method: 'POST', headers: { [PCA_HEADER]: headerValue(m.encoded) } }),
    );
    expect(res.status).toBe(200);
  });

  it('the Request URL parser normalizes dot-segments, so traversal cannot reach a different route rule', async () => {
    const m = mint();
    const { handle } = handlerFor(m);
    // WHATWG URL resolves /refunds/../payouts to /payouts, which has no mapping => deny by default.
    const res = await handle(
      new Request('https://gw.example.com/refunds/../payouts', { method: 'POST', headers: { [PCA_HEADER]: headerValue(m.encoded) } }),
    );
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe('unmapped-route');
  });
});

// ---------------------------------------------------------------------------
// workerd via Miniflare
// ---------------------------------------------------------------------------

describe('cloudflareWorker inside workerd (Miniflare)', () => {
  const routes: RouteRule[] = [{ method: 'POST', path: '/refunds', capability: { verb: 'stripe.refund' } }];
  const minted = mint();
  let mf: Miniflare;

  beforeAll(async () => {
    const out = await build({
      entryPoints: [join(PKG, 'test-support', 'worker-entry.ts')],
      bundle: true,
      format: 'esm',
      platform: 'node',
      target: 'es2022',
      write: false,
      logLevel: 'silent',
      // The core is CommonJS-flavoured; give the ESM bundle a `require` for node: built-ins.
      banner: { js: "import { createRequire as __pcaCreateRequire } from 'node:module'; const require = __pcaCreateRequire('file:///worker.mjs');" },
    });
    const file = out.outputFiles[0];
    if (file === undefined) throw new Error('esbuild produced no output');
    mf = new Miniflare({
      modules: true,
      script: file.text,
      compatibilityDate: '2025-09-01',
      compatibilityFlags: ['nodejs_compat'],
      bindings: {
        AUDIENCE: AUD,
        ROUTES: JSON.stringify(routes),
        GRANT_REF: minted.grantRef,
        GRANT_JSON: JSON.stringify(minted.grant),
      },
    });
    await mf.ready;
  }, 120_000);

  afterAll(async () => {
    await mf.dispose();
  });

  it('allows a valid proof through workerd and reaches the upstream', async () => {
    const res = await mf.dispatchFetch('https://gw.example.com/refunds?currency=usd', {
      method: 'POST',
      headers: { [PCA_HEADER]: headerValue(minted.encoded) },
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('upstream-reached');
  }, 60_000);

  it('denies a missing proof with 401 + WWW-Authenticate from inside workerd', async () => {
    const res = await mf.dispatchFetch('https://gw.example.com/refunds', { method: 'POST' });
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toBe('PCA realm="ins_acme", error="missing_proof"');
    expect(((await res.json()) as { error: string }).error).toBe('no-proof');
  }, 60_000);

  it('denies a tampered proof from inside workerd', async () => {
    const res = await mf.dispatchFetch('https://gw.example.com/refunds', {
      method: 'POST',
      headers: { [PCA_HEADER]: tamper(headerValue(minted.encoded)) },
    });
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toBe('PCA realm="ins_acme", error="invalid_proof"');
  }, 60_000);

  it('denies an unmapped route with 403 from inside workerd', async () => {
    const res = await mf.dispatchFetch('https://gw.example.com/payouts', {
      method: 'POST',
      headers: { [PCA_HEADER]: headerValue(minted.encoded) },
    });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe('unmapped-route');
  }, 60_000);
});

// ---------------------------------------------------------------------------
// AWS API Gateway Lambda authorizer: events copied from the AWS documentation
// ---------------------------------------------------------------------------

describe('Lambda authorizer against AWS documentation events', () => {
  const REST = jsonFixture<LambdaRequestAuthorizerEvent>('aws-rest-request-authorizer.json');
  const HTTP_V1 = jsonFixture<LambdaRequestAuthorizerEvent>('aws-http-api-payload-v1.json');
  const HTTP_V2 = jsonFixture<LambdaRequestAuthorizerEvent>('aws-http-api-payload-v2.json');

  /** The doc events carry no PCA header; the client adds one. Key casing mimics each payload version. */
  function withProof(event: LambdaRequestAuthorizerEvent, key: string, value: string): LambdaRequestAuthorizerEvent {
    return { ...event, headers: { ...(event.headers ?? {}), [key]: value } };
  }

  const restRoutes: RouteRule[] = [{ method: 'GET', path: '/request', capability: { verb: 'stripe.refund' } }];
  const v2Routes: RouteRule[] = [{ method: 'POST', path: '/my/path', capability: { verb: 'stripe.refund' } }];

  function expectDocumentedIamShape(res: unknown): void {
    // Shape from the AWS docs: principalId, policyDocument{Version, Statement[{Action, Effect, Resource}]}, context.
    const r = res as { principalId: unknown; policyDocument: { Version: unknown; Statement: Record<string, unknown>[] }; context: Record<string, unknown> };
    expect(typeof r.principalId).toBe('string');
    expect(r.policyDocument.Version).toBe('2012-10-17');
    expect(r.policyDocument.Statement).toHaveLength(1);
    expect(Object.keys(r.policyDocument.Statement[0] ?? {}).sort()).toEqual(['Action', 'Effect', 'Resource']);
    // REST authorizer context values must be string/number/boolean (no nested objects).
    for (const v of Object.values(r.context)) expect(typeof v).toBe('string');
  }

  it('REST REQUEST authorizer event: mixed-case header names are found; Allow policy targets the event methodArn', async () => {
    const m = mint();
    const handler = lambdaAuthorizer(gwOpts(m, restRoutes));
    const res = await handler(withProof(REST, 'PCA-Action', headerValue(m.encoded)));
    expectDocumentedIamShape(res);
    expect(res.policyDocument.Statement[0]?.Effect).toBe('Allow');
    expect(res.policyDocument.Statement[0]?.Resource).toBe(REST.methodArn);
    expect(res.principalId).toBe(m.grantRef);
  });

  it('REST event with no proof: Deny policy, pcaCode no-proof, 401 recorded', async () => {
    const m = mint();
    const handler = lambdaAuthorizer(gwOpts(m, restRoutes));
    const res = await handler(REST);
    expectDocumentedIamShape(res);
    expect(res.policyDocument.Statement[0]?.Effect).toBe('Deny');
    expect(res.principalId).toBe('anonymous');
    expect(res.context).toMatchObject({ pcaDenied: 'true', pcaCode: 'no-proof', pcaStatus: '401' });
  });

  it('REST event with a tampered proof: Deny with pcaCode invalid-proof or verify-failed (never Allow)', async () => {
    const m = mint();
    const handler = lambdaAuthorizer(gwOpts(m, restRoutes));
    const res = await handler(withProof(REST, 'PCA-Action', tamper(headerValue(m.encoded))));
    expect(res.policyDocument.Statement[0]?.Effect).toBe('Deny');
    expect(['invalid-proof', 'verify-failed']).toContain(res.context.pcaCode);
  });

  it('REST event for a route the proof does not cover: Deny insufficient-capability', async () => {
    const m = mint();
    const handler = lambdaAuthorizer(gwOpts(m, [{ method: 'GET', path: '/request', capability: { verb: 'stripe.payout' } }]));
    const res = await handler(withProof(REST, 'PCA-Action', headerValue(m.encoded)));
    expect(res.policyDocument.Statement[0]?.Effect).toBe('Deny');
    expect(res.context.pcaCode).toBe('insufficient-capability');
    expect(res.context.pcaStatus).toBe('403');
  });

  it('REST event with a method mismatch (rule is POST, event is GET): Deny unmapped-route', async () => {
    const m = mint();
    const handler = lambdaAuthorizer(gwOpts(m, [{ method: 'POST', path: '/request', capability: { verb: 'stripe.refund' } }]));
    const res = await handler(withProof(REST, 'PCA-Action', headerValue(m.encoded)));
    expect(res.policyDocument.Statement[0]?.Effect).toBe('Deny');
    expect(res.context.pcaCode).toBe('unmapped-route');
  });

  it('HTTP API payload 1.0 event (methodArn + path + httpMethod) is handled like the REST shape', async () => {
    const m = mint();
    const handler = lambdaAuthorizer(gwOpts(m, restRoutes));
    const res = await handler(withProof(HTTP_V1, 'PCA-Action', headerValue(m.encoded)));
    expect(res.policyDocument.Statement[0]?.Effect).toBe('Allow');
    expect(res.policyDocument.Statement[0]?.Resource).toBe(HTTP_V1.methodArn);
  });

  it('HTTP API payload 2.0 event: method/path from requestContext.http and rawPath, Allow targets routeArn', async () => {
    const m = mint();
    const handler = lambdaAuthorizer(gwOpts(m, v2Routes));
    const res = await handler(withProof(HTTP_V2, 'pca-action', headerValue(m.encoded)));
    expectDocumentedIamShape(res);
    expect(res.policyDocument.Statement[0]?.Effect).toBe('Allow');
    expect(res.policyDocument.Statement[0]?.Resource).toBe(HTTP_V2.routeArn);
  });

  it('HTTP API 2.0 simple response: { isAuthorized: true } with string-only context, false on no proof', async () => {
    const m = mint();
    const handler = lambdaSimpleAuthorizer(gwOpts(m, v2Routes));
    const ok = await handler(withProof(HTTP_V2, 'pca-action', headerValue(m.encoded)));
    expect(Object.keys(ok).sort()).toEqual(['context', 'isAuthorized']);
    expect(ok.isAuthorized).toBe(true);
    const no = await handler(HTTP_V2);
    expect(no.isAuthorized).toBe(false);
    expect(no.context.pcaCode).toBe('no-proof');
  });

  it('HTTP API 2.0 wrong audience: Deny with wrong-audience / 403', async () => {
    const m = mint({ aud: 'ins_other' });
    const handler = lambdaAuthorizer(gwOpts(m, v2Routes));
    const res = await handler(withProof(HTTP_V2, 'pca-action', headerValue(m.encoded)));
    expect(res.policyDocument.Statement[0]?.Effect).toBe('Deny');
    expect(res.context).toMatchObject({ pcaCode: 'wrong-audience', pcaStatus: '403' });
  });
});

// ---------------------------------------------------------------------------
// Envoy HTTP ext_authz (shapes only; Envoy is not run)
// ---------------------------------------------------------------------------

describe('Envoy HTTP ext_authz request shape (constructed from the documented behaviour; Envoy not run)', () => {
  const routes: RouteRule[] = [{ method: 'POST', path: '/refunds', capability: { verb: 'stripe.refund' } }];

  it('the vendored Envoy proto documents that the request target includes the query string', () => {
    const proto = fixture('envoy-attribute_context.proto');
    expect(proto).toContain('This includes');
    expect(proto).toContain('the URL path and query-string. No decoding is performed.');
  });

  it('allows a request whose path carries a query string (as Envoy forwards it)', async () => {
    const m = mint();
    const check = envoyExtAuthz(gwOpts(m, routes));
    const req = jsonFixture<EnvoyHttpCheckRequest & { _label: string }>('envoy-http-check-request.json');
    const res = await check({ ...req, headers: { ...(req.headers ?? {}), 'pca-action': headerValue(m.encoded) } });
    expect(res.status).toBe(200);
    expect(res.headers['x-pca-verb']).toBe('stripe.refund');
  });

  it('allows the same request when the target arrives only in the :path pseudo-header', async () => {
    const m = mint();
    const check = envoyExtAuthz(gwOpts(m, routes));
    const res = await check({
      headers: { ':method': 'POST', ':path': '/refunds?currency=usd', ':authority': 'gw.example.com', 'pca-action': headerValue(m.encoded) },
    });
    expect(res.status).toBe(200);
  });

  it('a query string cannot smuggle a different route: /payouts?/refunds stays unmapped', async () => {
    const m = mint();
    const check = envoyExtAuthz(gwOpts(m, routes));
    const res = await check({ method: 'POST', path: '/payouts?/refunds', headers: { 'pca-action': headerValue(m.encoded) } });
    expect(res.status).toBe(403);
    expect((JSON.parse(res.body) as { error: string }).error).toBe('unmapped-route');
  });

  it('a fragment or query never makes a deny into an allow for a tampered proof', async () => {
    const m = mint();
    const check = envoyExtAuthz(gwOpts(m, routes));
    const res = await check({ method: 'POST', path: '/refunds?a=b', headers: { 'pca-action': tamper(headerValue(m.encoded)) } });
    expect(res.status).toBe(401);
    expect(res.headers['www-authenticate']).toBe('PCA realm="ins_acme", error="invalid_proof"');
  });
});
