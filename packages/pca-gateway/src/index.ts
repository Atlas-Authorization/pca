/**
 * @atlasauth/pca-gateway — drop-in, code-free Proof-Carrying Authority enforcement at the
 * gateway / service mesh.
 *
 * Put this at the LANGUAGE-AGNOSTIC choke point in front of every MCP server / agent service — an
 * Envoy `ext_authz` filter (Istio `AuthorizationPolicy action: CUSTOM`), a Cloudflare Worker, or an
 * AWS API Gateway Lambda authorizer. A service team adds it to their gateway and every inbound
 * request is proof-carrying-verified with ZERO application code: the request only reaches the
 * upstream once a valid PCActn for THIS gateway's audience, carrying the capability the route
 * requires, has been verified by the offline core (`verifyPCActnCore` in `@atlasauth/pca`).
 *
 * The client carries the proof as the `PCA-Action: <base64url>` header (see `@atlasauth/pca`
 * `pcaHeaders` / `decodePcaHeader`); that is exactly what {@link authorize} reads. The gateway's own
 * audience (RFC 8707 resource) and a route→capability map are configured once; everything is
 * DENY-BY-DEFAULT — a request with no / invalid / wrong-audience / insufficient proof is rejected,
 * and (when configured) an unmapped route is denied too.
 *
 * HONESTY: nothing here authorizes on its own. Each adapter extracts the inbound PCActn, verifies it
 * with the fail-closed `verifyPCActnCore`, checks the proof carries the capability the route maps to,
 * and maps that allow/deny onto the gateway's own contract (an HTTP 200/403 for Envoy, a `Response`
 * for a Worker, an IAM policy for Lambda). A bypassed gateway changes nothing — the resource server's
 * own `requirePCA` is still the backstop. The concrete gateway SDKs (Envoy protobufs, `aws-lambda`,
 * the Workers runtime) are NEVER imported: the event / request / response shapes are minimal
 * STRUCTURAL shims, so this package has no gateway dependency and stays version/runtime-agnostic.
 *
 * ── Envoy `http_filters` + Istio `AuthorizationPolicy action: CUSTOM` ─────────────────────────────
 * Run {@link envoyExtAuthz} as an HTTP ext_authz check server, then point Envoy at it. Raw Envoy:
 *
 *   http_filters:
 *   - name: envoy.filters.http.ext_authz
 *     typed_config:
 *       "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
 *       transport_api_version: V3
 *       http_service:
 *         server_uri: { uri: pca-gateway:8080, cluster: pca_gateway, timeout: 0.5s }
 *         authorization_request:
 *           allowed_headers: { patterns: [ { exact: "pca-action" } ] }
 *         authorization_response:                 # forward the verified verdict upstream on 200
 *           allowed_upstream_headers: { patterns: [ { exact: "x-pca-verdict" }, { exact: "x-pca-verb" } ] }
 *   - name: envoy.filters.http.router
 *
 * On Istio, deploy the same check server and bind it with a CUSTOM AuthorizationPolicy whose
 * provider is declared in the mesh config's `extensionProviders`:
 *
 *   apiVersion: security.istio.io/v1
 *   kind: AuthorizationPolicy
 *   metadata: { name: pca-gateway, namespace: istio-system }
 *   spec:
 *     selector: { matchLabels: { app: mcp-server } }
 *     action: CUSTOM
 *     provider: { name: pca-gateway-ext-authz }   # -> meshConfig.extensionProviders[].envoyExtAuthzHttp
 *     rules: [ { to: [ { operation: { paths: ["/*"] } } ] } ]
 */

import {
  PCA_HEADER,
  decodePcaHeader,
  decodePCActn,
  verifyPCActnCore,
  type PCActn,
  type Capability,
  type VerifyResult,
} from '@atlasauth/pca';

type MaybePromise<T> = T | Promise<T>;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** A header map as gateways deliver it (keys may be any case; values may repeat). */
export type HeaderMap = Record<string, string | string[] | undefined>;

/** The capability a route requires of a verified PCActn: a PCA verb, optionally bound to a resource. */
export interface RequiredCapability {
  /** The PCA action verb the proof must carry (e.g. `stripe.refund`). */
  verb: string;
  /** When set, the proof's `action.resource` must equal this exactly (bind the route to one target). */
  resource?: string;
}

/** One route→capability rule. First matching rule wins; `method` / `path` support `*` wildcards. */
export interface RouteRule {
  /** HTTP method to match (case-insensitive). `*` / `ANY` / omitted matches any method. */
  method?: string;
  /**
   * Path to match. `*` or `/*` matches any path; a trailing `/*` matches a prefix segment-boundary
   * (`/refunds/*` matches `/refunds/abc` and `/refunds`); a trailing `*` matches a raw prefix;
   * otherwise an exact match.
   */
  path: string;
  /** The capability a proof must carry to pass this route. */
  capability: RequiredCapability;
}

/** What to do when no route rule matches the request. Default `'deny'` (secure choke point). */
export type UnmatchedRoutePolicy =
  /** Reject every unmapped route, even with a valid proof (deny-by-default for dangerous routes). */
  | 'deny'
  /** Forward unmapped routes without any proof (public pass-through alongside protected routes). */
  | 'allow'
  /** Require a valid PCActn for THIS audience but enforce no specific verb on unmapped routes. */
  | 'require-proof';

/** Gateway configuration: the audience, the route map, how to resolve grants, clock + realm. */
export interface GatewayOptions {
  /**
   * This gateway's audience — the RFC 8707 `resource` identifier of the service(s) behind it. It is
   * compared against the PCActn's signed `aud`; a proof minted for another resource is DENIED
   * (`wrong-audience`), so a stolen proof cannot be replayed at a different gateway.
   */
  audience: string;
  /** Route→capability map. First matching rule wins. */
  routes: RouteRule[];
  /**
   * Resolve a PCActn's `grant_ref` to the full root `Capability` the chain must descend from (the
   * verifier needs the grant to check the chain root + issuer). Return `null`/`undefined` for an
   * unknown grant → the request is denied (`unknown-grant`).
   */
  resolveGrant: (grantRef: string, pcactn: PCActn) => MaybePromise<Capability | null | undefined>;
  /** Behaviour for a request whose path/method matches no rule. Default `'deny'`. */
  unmatchedRoute?: UnmatchedRoutePolicy;
  /** Clock (epoch ms) for the validity / freshness window. Default `Date.now`. */
  now?: () => number;
  /** `WWW-Authenticate` realm on a deny challenge. Default: the audience. */
  realm?: string;
}

// ---------------------------------------------------------------------------
// Decision
// ---------------------------------------------------------------------------

/** Machine-readable outcome of {@link authorize}. */
export type DecisionCode =
  | 'allow'
  | 'no-proof'
  | 'invalid-proof'
  | 'unknown-grant'
  | 'verify-failed'
  | 'wrong-audience'
  | 'insufficient-capability'
  | 'unmapped-route';

/** The allow/deny decision for one request, with reason + response headers to surface. */
export interface Decision {
  allow: boolean;
  /** HTTP status the gateway should answer with (200 allow, 401 unauthenticated, 403 forbidden). */
  status: number;
  code: DecisionCode;
  reason: string;
  /** Response headers to attach (verdict/verb on allow; `WWW-Authenticate` on a deny challenge). */
  headers: Record<string, string>;
  /** The verifier's verdict, when a PCActn was decoded and verified. */
  verdict?: VerifyResult;
  /** The decoded PCActn, when one was present and well-formed. */
  pcactn?: PCActn;
  /** The capability the matched route required, when a rule matched. */
  matched?: RequiredCapability;
}

// ---------------------------------------------------------------------------
// Header + PCActn extraction
// ---------------------------------------------------------------------------

/** Case-insensitive single-value header lookup over a gateway `HeaderMap`. */
function getHeader(headers: HeaderMap, name: string): string | undefined {
  const lower = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() !== lower) continue;
    const v = headers[key];
    if (Array.isArray(v)) return v.length > 0 ? v[0] : undefined;
    return v ?? undefined;
  }
  return undefined;
}

type Extraction =
  | { pcactn: PCActn }
  | { pcactn?: undefined; code: 'no-proof' | 'invalid-proof'; reason: string };

/** Pull the PCActn out of the `PCA-Action` base64url header (fail closed on absent/undecodable). */
function extractPcactn(headers: HeaderMap): Extraction {
  const raw = getHeader(headers, PCA_HEADER);
  if (raw === undefined || raw === '') {
    return { code: 'no-proof', reason: `no ${PCA_HEADER} header` };
  }
  try {
    const pcactn = decodePCActn(decodePcaHeader(raw));
    return { pcactn };
  } catch (e) {
    return { code: 'invalid-proof', reason: `undecodable ${PCA_HEADER} header: ${(e as Error).message}` };
  }
}

// ---------------------------------------------------------------------------
// Route matching
// ---------------------------------------------------------------------------

function matchMethod(rule: RouteRule, method: string): boolean {
  const m = rule.method;
  if (m === undefined || m === '*' || m.toUpperCase() === 'ANY') return true;
  return m.toUpperCase() === method.toUpperCase();
}

function matchPath(pattern: string, path: string): boolean {
  if (pattern === '*' || pattern === '/*') return true;
  if (pattern.endsWith('/*')) {
    const prefix = pattern.slice(0, -2);
    return path === prefix || path.startsWith(`${prefix}/`);
  }
  if (pattern.endsWith('*')) return path.startsWith(pattern.slice(0, -1));
  return path === pattern;
}

/** The first rule that matches `method` + `path`, or `undefined`. */
function matchRoute(routes: RouteRule[], method: string, path: string): RouteRule | undefined {
  return routes.find((r) => matchMethod(r, method) && matchPath(r.path, path));
}

// ---------------------------------------------------------------------------
// Decision helpers
// ---------------------------------------------------------------------------

const ERROR_TOKEN: Record<Exclude<DecisionCode, 'allow'>, string> = {
  'no-proof': 'missing_proof',
  'invalid-proof': 'invalid_proof',
  'unknown-grant': 'invalid_proof',
  'verify-failed': 'invalid_proof',
  'wrong-audience': 'invalid_resource',
  'insufficient-capability': 'insufficient_capability',
  'unmapped-route': 'access_denied',
};

function wwwAuthenticate(realm: string, code: Exclude<DecisionCode, 'allow'>): string {
  return `PCA realm="${realm}", error="${ERROR_TOKEN[code]}"`;
}

function deny(
  code: Exclude<DecisionCode, 'allow'>,
  status: number,
  reason: string,
  realm: string,
  extra?: { verdict?: VerifyResult; pcactn?: PCActn; matched?: RequiredCapability },
): Decision {
  return {
    allow: false,
    status,
    code,
    reason,
    headers: { 'www-authenticate': wwwAuthenticate(realm, code) },
    ...extra,
  };
}

function allowDecision(
  reason: string,
  extra?: { verdict?: VerifyResult; pcactn?: PCActn; matched?: RequiredCapability },
): Decision {
  const headers: Record<string, string> = {};
  if (extra?.verdict) headers['x-pca-verdict'] = JSON.stringify(extra.verdict);
  if (extra?.pcactn) {
    headers['x-pca-verb'] = extra.pcactn.action.verb;
    headers['x-pca-grant'] = extra.pcactn.grant_ref;
  }
  return { allow: true, status: 200, code: 'allow', reason, headers, ...extra };
}

// ---------------------------------------------------------------------------
// Generic core
// ---------------------------------------------------------------------------

/** The subset of an inbound request the gateway core needs: method + path (+ optional authority) + headers. */
export interface GatewayRequest {
  method: string;
  /** Request path (no query string), e.g. `/refunds`. */
  path: string;
  /** Optional authority / `:authority` / Host. Available to callers; route matching uses `path`. */
  authority?: string;
  headers: HeaderMap;
}

/**
 * The framework-agnostic core. Extract the PCActn from the request headers, map the request
 * (method + path) to the required capability, verify the proof via the offline `verifyPCActnCore`
 * (fail closed), enforce audience + the route's capability, and return an allow/deny {@link Decision}.
 * DENY-BY-DEFAULT at every step.
 */
export async function authorize(req: GatewayRequest, opts: GatewayOptions): Promise<Decision> {
  const realm = opts.realm ?? opts.audience;
  const unmatched = opts.unmatchedRoute ?? 'deny';

  // 1. Route → required capability. An unmapped route follows `unmatchedRoute` (default deny).
  const rule = matchRoute(opts.routes, req.method, req.path);
  if (!rule) {
    if (unmatched === 'allow') return allowDecision(`route ${req.method} ${req.path} is unmapped (unmatchedRoute=allow)`);
    if (unmatched === 'deny') {
      return deny('unmapped-route', 403, `no capability mapping for ${req.method} ${req.path} (deny-by-default)`, realm);
    }
    // 'require-proof': continue, enforcing a valid proof but no specific verb.
  }
  const required: RequiredCapability | undefined = rule?.capability;

  // 2. Extract the proof (fail closed).
  const extracted = extractPcactn(req.headers);
  if (!extracted.pcactn) {
    return deny(extracted.code, 401, extracted.reason, realm);
  }
  const pcactn = extracted.pcactn;

  // 3. Resolve the grant the chain must root in; unknown grant => deny.
  const grant = await opts.resolveGrant(pcactn.grant_ref, pcactn);
  if (!grant) {
    return deny('unknown-grant', 401, `unknown grant_ref ${pcactn.grant_ref}`, realm, { pcactn });
  }

  // 4. Offline verification (fail closed), audience bound to THIS gateway.
  const now = opts.now?.() ?? Date.now();
  const verdict = await verifyPCActnCore(pcactn, { grant, audience: opts.audience, nowEpoch: now });
  if (!verdict.allow) {
    const audienceFailed = verdict.checks.audience === 'fail';
    return deny(
      audienceFailed ? 'wrong-audience' : 'verify-failed',
      audienceFailed ? 403 : 401,
      verdict.reason ?? 'PCActn verification failed',
      realm,
      { verdict, pcactn },
    );
  }

  // 5. Capability enforcement: the verified proof must carry the verb (+ resource) the route requires.
  if (required) {
    if (pcactn.action.verb !== required.verb) {
      return deny(
        'insufficient-capability',
        403,
        `route requires capability '${required.verb}' but the proof authorizes '${pcactn.action.verb}'`,
        realm,
        { verdict, pcactn, matched: required },
      );
    }
    if (required.resource !== undefined && pcactn.action.resource !== required.resource) {
      return deny(
        'insufficient-capability',
        403,
        `route is bound to resource '${required.resource}' but the proof targets '${pcactn.action.resource}'`,
        realm,
        { verdict, pcactn, matched: required },
      );
    }
  }

  return allowDecision(
    'proof-carrying action verified',
    required ? { verdict, pcactn, matched: required } : { verdict, pcactn },
  );
}

/** Build a reusable authorizer bound to one config (verify many requests). */
export function createGateway(opts: GatewayOptions): (req: GatewayRequest) => Promise<Decision> {
  return (req: GatewayRequest) => authorize(req, opts);
}

// ---------------------------------------------------------------------------
// Adapter — Envoy HTTP ext_authz (Istio AuthorizationPolicy action: CUSTOM)
// ---------------------------------------------------------------------------

/**
 * Minimal structural shim of the request an Envoy HTTP ext_authz filter forwards to the check server:
 * the original method, path and headers. Envoy delivers the method/path as the `:method` / `:path`
 * pseudo-headers too, which this adapter reads as a fallback.
 */
export interface EnvoyHttpCheckRequest {
  method?: string;
  path?: string;
  authority?: string;
  headers?: Record<string, string | undefined>;
}

/**
 * The HTTP response the ext_authz check server returns. Envoy treats `200` as ALLOW (and copies the
 * headers named in `allowed_upstream_headers` onto the upstream request); any other status is a DENY
 * and this exact status/headers/body is returned to the downstream caller — the upstream is never hit.
 */
export interface EnvoyHttpCheckResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

function envoyRequest(check: EnvoyHttpCheckRequest): GatewayRequest {
  const headers: Record<string, string | undefined> = check.headers ?? {};
  const method = check.method ?? headers[':method'] ?? '*';
  // Envoy forwards the request target as received, query string included (`/refunds?x=1`); route
  // matching is on the path component only, so drop any `?query` / `#fragment` (as the Worker and
  // Lambda adapters already do) instead of treating every request with a query as an unmapped route.
  const target = check.path ?? headers[':path'] ?? '/';
  const mark = target.search(/[?#]/);
  const rawPath = mark >= 0 ? target.slice(0, mark) : target;
  const path = rawPath === '' ? '/' : rawPath;
  const authority = check.authority ?? headers[':authority'];
  return authority === undefined ? { method, path, headers } : { method, path, authority, headers };
}

/**
 * Envoy HTTP `ext_authz` handler. On a valid proof it returns `200` and forwards the verified verdict
 * upstream on `x-pca-verdict` / `x-pca-verb`; on deny it returns the guard's `401`/`403` with a
 * `WWW-Authenticate` challenge and a JSON error body, so Envoy answers the caller itself and never
 * forwards the request. Wire it as an HTTP ext_authz service (see the Envoy/Istio snippet in the
 * file header).
 */
export function envoyExtAuthz(opts: GatewayOptions): (check: EnvoyHttpCheckRequest) => Promise<EnvoyHttpCheckResponse> {
  const gateway = createGateway(opts);
  return async (check: EnvoyHttpCheckRequest): Promise<EnvoyHttpCheckResponse> => {
    const decision = await gateway(envoyRequest(check));
    if (decision.allow) {
      return { status: 200, headers: decision.headers, body: '' };
    }
    return {
      status: decision.status,
      headers: { 'content-type': 'application/json', ...decision.headers },
      body: JSON.stringify({ error: decision.code, reason: decision.reason }),
    };
  };
}

// ---------------------------------------------------------------------------
// Adapter — Cloudflare Worker (fetch-style middleware)
// ---------------------------------------------------------------------------

/** The structural subset of a Fetch `Request` the Worker adapter reads (no DOM/Workers types needed). */
export interface WorkerLikeRequest {
  readonly method: string;
  readonly url: string;
  readonly headers: { get(name: string): string | null };
}

/**
 * Worker config: the gateway options plus the two runtime plug points. `next` forwards the request
 * upstream on allow (e.g. `(req) => fetch(req)`), and `respond` builds the deny `Response` (e.g.
 * `(body, init) => new Response(body, init)`) — both supplied by the caller so no Workers runtime
 * type is imported here. The two share the `Res` type, so the returned middleware is `(req) => Res`.
 */
export interface CloudflareWorkerOptions<Req extends WorkerLikeRequest, Res> extends GatewayOptions {
  next: (request: Req) => MaybePromise<Res>;
  respond: (body: string, init: { status: number; headers: Record<string, string> }) => Res;
}

/** Parse the path (and authority) out of a request URL string without needing the `URL` global. */
function pathFromUrl(url: string): { path: string; authority: string } {
  let rest = url;
  let authority = '';
  const scheme = rest.indexOf('://');
  if (scheme >= 0) {
    rest = rest.slice(scheme + 3);
    const slash = rest.indexOf('/');
    if (slash >= 0) {
      authority = rest.slice(0, slash);
      rest = rest.slice(slash);
    } else {
      authority = rest;
      rest = '/';
    }
  }
  const mark = rest.search(/[?#]/);
  const path = mark >= 0 ? rest.slice(0, mark) : rest;
  return { path: path === '' ? '/' : path, authority };
}

/**
 * Cloudflare Worker middleware: a `(request) => Response` that verifies the inbound PCActn at the
 * edge (PCA's offline verify runs on Workers). On allow it calls `next(request)` to forward upstream;
 * on deny it returns a `403`/`401` `Response` (built via `respond`) with the `WWW-Authenticate`
 * challenge and a JSON error body — the upstream is never reached.
 */
export function cloudflareWorker<Req extends WorkerLikeRequest, Res>(
  opts: CloudflareWorkerOptions<Req, Res>,
): (request: Req) => Promise<Res> {
  const gateway = createGateway(opts);
  return async (request: Req): Promise<Res> => {
    const { path, authority } = pathFromUrl(request.url);
    const pcaHeader = request.headers.get(PCA_HEADER);
    const headers: HeaderMap = pcaHeader === null ? {} : { [PCA_HEADER.toLowerCase()]: pcaHeader };
    const decision = await gateway({ method: request.method, path, authority, headers });
    if (decision.allow) return opts.next(request);
    return opts.respond(JSON.stringify({ error: decision.code, reason: decision.reason }), {
      status: decision.status,
      headers: { 'content-type': 'application/json', ...decision.headers },
    });
  };
}

// ---------------------------------------------------------------------------
// Adapter — AWS API Gateway REQUEST (Lambda) authorizer
// ---------------------------------------------------------------------------

/**
 * Minimal structural shim of an API Gateway REQUEST-authorizer event. The method + path are read from
 * the HTTP-API v2 `requestContext.http` or the REST v1 `httpMethod`/`path`/`rawPath`; `methodArn`
 * (REST) / `routeArn` (HTTP API) are the policy `Resource` and a method/path fallback. `headers` is
 * the lowercase header map both payloads carry.
 */
export interface LambdaRequestAuthorizerEvent {
  headers?: Record<string, string | undefined>;
  /** REST API (payload v1). */
  methodArn?: string;
  /** HTTP API (payload v2). */
  routeArn?: string;
  httpMethod?: string;
  path?: string;
  rawPath?: string;
  requestContext?: { http?: { method?: string; path?: string } };
}

export interface IamPolicyStatement {
  Action: 'execute-api:Invoke';
  Effect: 'Allow' | 'Deny';
  Resource: string;
}

export interface IamPolicyDocument {
  Version: '2012-10-17';
  Statement: IamPolicyStatement[];
}

/** The IAM-policy authorizer response API Gateway maps onto allow / 403. */
export interface LambdaAuthResponse {
  principalId: string;
  policyDocument: IamPolicyDocument;
  /** String-only context forwarded to the integration (`$context.authorizer.*`). */
  context: Record<string, string>;
}

/** HTTP-API simple-response payload (`enableSimpleResponses: true`): a boolean instead of a policy. */
export interface LambdaSimpleAuthResponse {
  isAuthorized: boolean;
  context: Record<string, string>;
}

function lambdaResource(event: LambdaRequestAuthorizerEvent): string {
  return event.methodArn ?? event.routeArn ?? '*';
}

function lambdaMethodPath(event: LambdaRequestAuthorizerEvent): { method: string; path: string } {
  const method = event.requestContext?.http?.method ?? event.httpMethod;
  const path = event.rawPath ?? event.path ?? event.requestContext?.http?.path;
  if (method !== undefined && path !== undefined) return { method, path };
  // Fallback: parse `.../<stage>/<METHOD>/<path...>` out of the method/route ARN.
  const arn = event.methodArn ?? event.routeArn;
  if (arn !== undefined) {
    const tail = arn.split(':').slice(5).join(':');
    const parts = tail.split('/');
    const arnMethod = parts[2]?.split(' ')[0];
    return {
      method: method ?? arnMethod ?? '*',
      path: path ?? `/${parts.slice(3).join('/')}`,
    };
  }
  return { method: method ?? '*', path: path ?? '/' };
}

function lambdaRequest(event: LambdaRequestAuthorizerEvent): GatewayRequest {
  const { method, path } = lambdaMethodPath(event);
  return { method, path, headers: event.headers ?? {} };
}

function lambdaPolicy(effect: 'Allow' | 'Deny', event: LambdaRequestAuthorizerEvent): IamPolicyDocument {
  return {
    Version: '2012-10-17',
    Statement: [{ Action: 'execute-api:Invoke', Effect: effect, Resource: lambdaResource(event) }],
  };
}

function lambdaPrincipal(decision: Decision): string {
  return decision.pcactn?.grant_ref ?? 'anonymous';
}

function lambdaContext(decision: Decision): Record<string, string> {
  if (decision.allow) {
    return decision.verdict ? { pcaVerdict: JSON.stringify(decision.verdict) } : {};
  }
  return { pcaDenied: 'true', pcaCode: decision.code, pcaReason: decision.reason, pcaStatus: String(decision.status) };
}

/**
 * AWS API Gateway REQUEST (Lambda) authorizer. On a valid, capability-matching proof it returns an
 * `Allow` IAM policy (verdict on `context.pcaVerdict`); on deny a `Deny` policy, which API Gateway
 * turns into a 403 — the upstream is never invoked. Works for REST (`methodArn`) and HTTP-API
 * (`routeArn`) payloads. For the HTTP-API simple-response format use {@link lambdaSimpleAuthorizer}.
 */
export function lambdaAuthorizer(
  opts: GatewayOptions,
): (event: LambdaRequestAuthorizerEvent) => Promise<LambdaAuthResponse> {
  const gateway = createGateway(opts);
  return async (event: LambdaRequestAuthorizerEvent): Promise<LambdaAuthResponse> => {
    const decision = await gateway(lambdaRequest(event));
    return {
      principalId: lambdaPrincipal(decision),
      policyDocument: lambdaPolicy(decision.allow ? 'Allow' : 'Deny', event),
      context: lambdaContext(decision),
    };
  };
}

/**
 * HTTP-API simple-response variant (`enableSimpleResponses: true`): returns `{ isAuthorized }` instead
 * of an IAM policy. A denied request yields `isAuthorized: false`, which API Gateway maps to 403.
 * Same verification as {@link lambdaAuthorizer}.
 */
export function lambdaSimpleAuthorizer(
  opts: GatewayOptions,
): (event: LambdaRequestAuthorizerEvent) => Promise<LambdaSimpleAuthResponse> {
  const gateway = createGateway(opts);
  return async (event: LambdaRequestAuthorizerEvent): Promise<LambdaSimpleAuthResponse> => {
    const decision = await gateway(lambdaRequest(event));
    return { isAuthorized: decision.allow, context: lambdaContext(decision) };
  };
}

// ---------------------------------------------------------------------------
// Re-exports (so a gateway only needs this package)
// ---------------------------------------------------------------------------

export { PCA_HEADER, pcaHeaders, decodePcaHeader, decodePCActn, verifyPCActnCore } from '@atlasauth/pca';
export type { PCActn, Capability, VerifyResult } from '@atlasauth/pca';
