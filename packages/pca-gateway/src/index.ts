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
 * own `requirePCA` is still the backstop.
 *
 * FULL-POLICY MODE (the default since 0.5): `policy: { mode: 'full', params: 'body', state, isRevoked }`.
 * A gateway built without a `policy` is a configuration error (it throws, and every request is denied). The explicit
 * alternative, `policy: { mode: 'signature-only' }`, verifies that a proof is genuine and bound to the request, but the
 * signed params carry only the request binding, so the grant's limits (`amount <= 100`, `max_spend`) are not evaluated;
 * it requires a `replayGuard` and, unless `requireChecks` says otherwise, a `hooks.revocation` check. In full mode the agent signs the REAL params (the JSON body, or what `params(req)` returns)
 * with the request binding as a `binding` member inside them (see {@link bindParams}); the gateway checks that
 * digest and then runs the full verifier (`authorizeExecution` from `@atlasauth/pca`): the grant's predicates,
 * limits and caveats, revocation (required), the replay counter (required store) and the trust budget. A missing
 * store, revocation check or params source denies every request. The concrete gateway SDKs (Envoy protobufs, `aws-lambda`,
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
 *           allowed_upstream_headers: { patterns: [ { prefix: "x-pca-" } ] }   # prefix, not exact: so x-pca-grant is overwritten too
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
  authorizeExecution,
  decodePcaHeader,
  decodePCActn,
  missingExecutionComponents,
  verifyPCActnCore,
  paramsDigest,
  strictParse,
  type K1Input,
  type AuthorizeExecutionOptions,
  type PcaVerdict,
  type VerifyHooks,
  type EnforcementGates,
  type PCActn,
  type Capability,
  type ProvObservation,
  type VerifyResult,
  snapshotConfig,
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
  /**
   * K5: the Merkle plan roots this gateway knows the principal authorized; forwarded to the core verifier, which enforces
   * `plan_root_authorized` (default-deny) in every mode, full-policy included: configure this or the explicit `insecureSkipPlanRootCheck`.
   */
  authorizedPlanRoots?: readonly string[];
  /** Explicit, loudly named opt-out of `plan_root_authorized` when no `authorizedPlanRoots` is configured. */
  insecureSkipPlanRootCheck?: boolean;
  /** Behaviour for a request whose path/method matches no rule. Default `'deny'`. */
  unmatchedRoute?: UnmatchedRoutePolicy;
  /**
   * Single-use enforcement. The offline verifier is stateless, so on its own a captured proof is
   * accepted again until it expires. When set, each proof that would otherwise be allowed is claimed
   * once (keyed on `grant_ref` + the proof's signature); a second presentation is denied
   * (`replayed-proof`). Use {@link memoryReplayGuard} for a single gateway process or implement
   * {@link ReplayGuard} over a shared store (Redis `SET NX PX`) for a fleet.
   */
  replayGuard?: ReplayGuard;
  /**
   * Bind the proof to THIS request (RT-09). Without it a verified proof is a bearer for the matched
   * ROUTE: the same proof is accepted on every path the rule matches. With it, the proof's signed
   * `action.params_digest` must equal `paramsDigest(requestBinding(req, this))`, i.e. the agent must
   * have minted the action with the request binding `{ v, method, path[, authority][, body_sha256] }`
   * (see {@link requestBinding}) as its params. A proof for one path/method/body cannot be replayed
   * on another. Trade-off: the params slot carries the binding, so grant limits that read params
   * (`where`) cannot be evaluated here; enforce them in {@link GatewayOptions.checkProof}.
   * DEFAULT ON (R2-11, breaking): omitted means `{}` (method, path, query, and the body hash when the request
   * supplies one). Pass `false` to opt out explicitly; the gateway is then only a structural pre-filter and a
   * verified proof is a bearer for the matched route.
   */
  bindRequest?: BindRequestOptions | false;
  /** Revocation / attestation / threshold / zk hooks forwarded to the core verifier. */
  hooks?: VerifyHooks;
  /** Opt-in enforcement gates (taint / freshness / attestation) forwarded to the core verifier. */
  enforce?: EnforcementGates;
  /**
   * Core checks that MUST report `pass`. A check that is `not-enforced` (no hook supplied) then DENIES. Default (0.5), in
   * signature-only mode: `['revocation']` (so `hooks.revocation` is required); pass `[]` to waive it. Full mode takes
   * revocation from `policy.isRevoked`.
   */
  requireChecks?: string[];
  /**
   * Per-proof policy hook, run after the proof verified and the request binding held, before the
   * single-use claim. Implement grant limits / budgets / revocation here (e.g. `verifyPCActn` with
   * the grant's predicates, a spend ledger). Return `false`/`{allow:false}` or throw to DENY.
   */
  checkProof?: (ctx: ProofCheckContext) => MaybePromise<boolean | { allow: boolean; reason?: string }>;
  /**
   * Request-path hardening. `'strict'` (default) denies ambiguous targets before route matching:
   * dot segments, `//`, backslashes, control characters, percent-encoded `.` `/` `\` and
   * percent-encoded unreserved characters, because the upstream may decode or normalise them into a
   * different route than the one matched here. `'off'` disables the check (only do that behind a proxy
   * that already normalises, e.g. Envoy `normalize_path` + `merge_slashes`).
   */
  pathPolicy?: 'strict' | 'off';
  /** Clock (epoch ms) for the validity / freshness window. Default `Date.now`. */
  now?: () => number;
  /** `WWW-Authenticate` realm on a deny challenge. Default: the audience. */
  realm?: string;
  /**
   * REQUIRED (0.5). `{ mode: 'full', ... }` (the default mode: state and `isRevoked` required, the grant's limits are
   * evaluated against the real params) or the explicit `{ mode: 'signature-only' }` (the proof and its request binding
   * only; needs `replayGuard` and, by default, `hooks.revocation`). Absent: the gateway is misconfigured and denies.
   */
  policy: GatewayPolicy;
}

/**
 * Full-policy mode: the gateway evaluates the grant's limits against the real params, with revocation and replay
 * required. The options of `authorizeExecution` from `@atlasauth/pca`; the audience, grant lookup, hooks and clock
 * are the gateway's own.
 */
export type GatewayPolicy = GatewayFullPolicy | GatewaySignatureOnlyPolicy;

/** Signature-only mode: the proof is genuine and bound to the request; the grant's limits are NOT evaluated. */
export interface GatewaySignatureOnlyPolicy {
  mode: 'signature-only';
}

export interface GatewayFullPolicy extends Omit<AuthorizeExecutionOptions, 'audience' | 'grant' | 'resolveGrant' | 'hooks' | 'now' | 'k1'> {
  mode: 'full';
  /**
   * Where the operation's params come from. `'body'`: the request body, a JSON object (strict JSON; the adapter must
   * supply `GatewayRequest.body`, so it fails closed where the gateway never sees the body, e.g. a Lambda REQUEST
   * authorizer). A function: build them from the request (e.g. from the query); `undefined` denies.
   * The agent signs `bindParams(params, binding)`: these params plus the request binding as a `binding` member.
   */
  params: 'body' | ((req: GatewayRequest) => Record<string, unknown> | undefined);
  /**
   * Caveat language v2 (third-party discharges, `narrow`, `derive`, `max_uses`, `spiffe_bound`): the verifier's own K1
   * input (pins, revoked discharges, SPIFFE id, history), or a function of the request and proof returning it. The
   * presented artifacts are read from the request exactly as the native guards and `requirePCA` read them: headers
   * `PCA-Discharges` (strict base64url JSON array) and `PCA-Narrow`; with function `params` (the body is not the signed
   * params) also body members `pca_discharges` and `pca_narrow` of a JSON-object body. The configured members win over
   * presented ones. Absent: every K1 caveat refuses (fail closed). Unreadable artifacts are no artifacts.
   */
  k1?: Omit<K1Input, 'discharges' | 'narrow'> | ((req: GatewayRequest, pcactn: PCActn) => K1Input | Promise<K1Input>);
  /**
   * Provenance by default: the gateway's own record of what it let through to each agent session. Every allowed call is logged as
   * UNTRUSTED tool output reaching that session (its response flows back into the agent's context), and every later call of the
   * session is decided with those observations joined in (`observed`, raise only): an agent cannot hide from the gateway that it
   * read untrusted content. Default: an in-memory log per gateway (share one store across nodes for the same guarantee
   * cluster-wide). `false` turns the log off (the agent's signed chain is then the only evidence).
   */
  provenanceLog?: ProvenanceLog | false;
}

/** The gateway's per-session log of untrusted content it relayed (see {@link GatewayFullPolicy.provenanceLog}). */
export interface ProvenanceLog {
  seen(session: string): MaybePromise<readonly ProvObservation[]>;
  add(session: string, o: ProvObservation): MaybePromise<void>;
}

/** An in-memory {@link ProvenanceLog}: at most `maxSessions` sessions (oldest dropped first), 256 observations each. */
export function memoryProvenanceLog(maxSessions = 10_000): ProvenanceLog {
  const m = new Map<string, ProvObservation[]>();
  return {
    seen: (k) => [...(m.get(k) ?? [])],
    add: (k, o) => {
      const cur = m.get(k) ?? [];
      m.delete(k);
      if (!cur.some((x) => x.origin === o.origin && x.source === o.source) && cur.length < 256) cur.push({ origin: o.origin, source: o.source });
      m.set(k, cur);
      while (m.size > maxSessions) m.delete(m.keys().next().value as string);
    },
  };
}

const defaultLogs = new WeakMap<object, ProvenanceLog>();

/** The provenance bundle a request presents: header `PCA-Provenance` (strict base64url JSON), else body member `pca_provenance` when the body is not the signed params. */
export function presentedProvenance(req: GatewayRequest, policy: GatewayFullPolicy): unknown {
  try {
    const h = getHeader(req.headers, 'pca-provenance');
    if (h !== undefined && h !== '') return strictParse(decodePcaHeader(h));
  } catch {
    return null; // unreadable: presented but malformed, the gate denies it
  }
  if (typeof policy.params === 'function' && typeof req.body === 'string' && req.body.length > 0) {
    try {
      const b = strictParse(req.body) as Record<string, unknown>;
      if (b !== null && typeof b === 'object' && !Array.isArray(b) && b.pca_provenance !== undefined) return b.pca_provenance;
    } catch {
      /* not JSON: no body form */
    }
  }
  return undefined;
}

/** The discharges and narrow block a request presents (headers, then body members when the body is not the signed params). */
export function presentedArtifacts(req: GatewayRequest, policy: GatewayFullPolicy): Pick<K1Input, 'discharges' | 'narrow'> {
  const out: { discharges?: unknown[]; narrow?: unknown } = {};
  try {
    const d = getHeader(req.headers, 'pca-discharges');
    if (d !== undefined && d !== '') {
      const arr = strictParse(decodePcaHeader(d));
      if (Array.isArray(arr)) out.discharges = arr;
    }
  } catch {
    /* unreadable: no discharges */
  }
  try {
    const n = getHeader(req.headers, 'pca-narrow');
    if (n !== undefined && n !== '') out.narrow = strictParse(decodePcaHeader(n));
  } catch {
    /* unreadable: no narrow block */
  }
  if (typeof policy.params === 'function' && typeof req.body === 'string' && req.body.length > 0) {
    try {
      const b = strictParse(req.body) as Record<string, unknown>;
      if (b !== null && typeof b === 'object' && !Array.isArray(b)) {
        if (out.discharges === undefined && Array.isArray(b.pca_discharges)) out.discharges = b.pca_discharges;
        if (out.narrow === undefined && b.pca_narrow !== undefined) out.narrow = b.pca_narrow;
      }
    } catch {
      /* not JSON: no body form */
    }
  }
  return out;
}

/**
 * The params an agent signs for a full-policy gateway: the operation's params plus the request binding as a
 * `binding` member (omit `binding` when the gateway runs with `bindRequest: false`). A params object that already has
 * a `binding` member is refused (throws), as the gateway refuses it.
 */
export function bindParams(params: Record<string, unknown>, binding?: RequestBinding): Record<string, unknown> {
  if (binding === undefined) return params;
  if (Object.prototype.hasOwnProperty.call(params, 'binding')) throw new Error("params already have a 'binding' member");
  return { ...params, binding };
}

/** Which request attributes are bound into the proof (method and path always are). */
export interface BindRequestOptions {
  /** Also bind the request authority / Host (requires `GatewayRequest.authority`). */
  authority?: boolean;
  /**
   * Body binding. `true`: bind the SHA-256 of the body (requires `GatewayRequest.bodySha256`; absent hash => deny).
   * `false`: never bind it. Omitted (default): bind it whenever the request carries a `bodySha256`.
   */
  body?: boolean;
}

/** The canonical request binding that an agent commits as its action params (see `bindRequest`). */
export type RequestBinding = {
  v: 2;
  method: string;
  path: string;
  /** Sorted `&`-joined raw query pairs ('' when there is no query). Always bound (R2-11). */
  query: string;

  authority?: string;
  body_sha256?: string;
};

/** Context handed to {@link GatewayOptions.checkProof}. */
export interface ProofCheckContext {
  pcactn: PCActn;
  grant: Capability;
  verdict: VerifyResult;
  request: GatewayRequest;
  required?: RequiredCapability;
}

/**
 * The canonical binding of a request: upper-cased method, the matched path (query stripped by the
 * adapters), and optionally authority and body hash. Agents pass this object as the action `params`
 * so `params_digest` commits to it; the gateway recomputes it from the live request.
 */
export function requestBinding(req: GatewayRequest, opts: BindRequestOptions = {}): RequestBinding {
  const b: RequestBinding = { v: 2, method: req.method.toUpperCase(), path: req.path, query: canonicalQuery(req.query) };
  if (opts.authority) b.authority = (req.authority ?? '').toLowerCase();
  if (opts.body === true || (opts.body === undefined && req.bodySha256 !== undefined)) b.body_sha256 = (req.bodySha256 ?? '').toLowerCase();
  return b;
}

/**
 * Canonical query: strip a leading `?`, drop empty pairs, sort the raw (still percent-encoded) pairs, join
 * with `&`. THROWS (R3-07) when the query is ambiguous across upstream parsers: a repeated parameter name
 * (compared percent-decoded, `+` as space, case-insensitively; upstreams disagree on first-wins vs last-wins
 * vs array, so a sorted digest would bind both orders), a `;` separator (some parsers split on it), or a
 * malformed percent escape in a name. The gateway turns the throw into a `request-mismatch` deny.
 */
export function canonicalQuery(query: string | undefined): string {
  if (query === undefined) return '';
  const q = query.startsWith('?') ? query.slice(1) : query;
  if (q.includes(';')) throw new Error("query contains ';' (parsers disagree on it as a separator)");
  const pairs = q.split('&').filter((x) => x !== '');
  const seen = new Set<string>();
  for (const pair of pairs) {
    const eq = pair.indexOf('=');
    const rawKey = eq < 0 ? pair : pair.slice(0, eq);
    let key: string;
    try {
      key = decodeURIComponent(rawKey.replace(/\+/g, ' ')).toLowerCase();
    } catch {
      throw new Error('query parameter name has a malformed percent escape');
    }
    if (seen.has(key)) throw new Error(`duplicate query parameter '${key}'`);
    seen.add(key);
  }
  return pairs.sort().join('&');
}

/** Single-use store for proofs (see {@link GatewayOptions.replayGuard}). */
export interface ReplayGuard {
  /** Atomically claim `key` until `expiresAtMs`. Resolve `true` if first use, `false` if already claimed. */
  claim(key: string, expiresAtMs: number, nowMs?: number): MaybePromise<boolean>;
}

/**
 * In-process {@link ReplayGuard}; state is per process (a fleet or a restart does not share it, so use a
 * shared store for more than one instance). The gateway passes its own clock as `nowMs`, so a custom
 * `GatewayOptions.now` and the guard agree; `now` here is only the fallback for direct callers. A claim
 * stays live through `expiresAtMs` inclusive, matching the verifier, which accepts a proof at `now == exp`.
 * Fails CLOSED when `maxEntries` unexpired claims are held (throws, which
 * the gateway turns into a 503 deny) rather than evicting a live claim and re-opening a replay window.
 */
export function memoryReplayGuard(maxEntries = 100_000, now: () => number = Date.now): ReplayGuard {
  const seen = new Map<string, number>();
  return {
    claim(key: string, expiresAtMs: number, nowMs?: number): boolean {
      const t = nowMs ?? now();
      if (seen.size >= maxEntries) {
        for (const [k, exp] of seen) if (exp < t) seen.delete(k);
        if (seen.size >= maxEntries) throw new Error('replay guard full');
      }
      const existing = seen.get(key);
      if (existing !== undefined && existing >= t) return false;
      seen.set(key, expiresAtMs);
      return true;
    },
  };
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
  | 'unmapped-route'
  | 'invalid-path'
  | 'replayed-proof'
  | 'replay-guard-unavailable'
  | 'request-mismatch'
  | 'proof-rejected';

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
  /** Full-policy mode: the full verifier's verdict (policy, limits, revocation, replay, budget), when it ran. */
  policyVerdict?: PcaVerdict;
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
  'invalid-path': 'invalid_request',
  'replayed-proof': 'replayed_proof',
  'replay-guard-unavailable': 'temporarily_unavailable',
  'request-mismatch': 'proof_not_bound_to_request',
  'proof-rejected': 'access_denied',
};

function wwwAuthenticate(realm: string, code: Exclude<DecisionCode, 'allow'>): string {
  return `PCA realm="${realm}", error="${ERROR_TOKEN[code]}"`;
}

function deny(
  code: Exclude<DecisionCode, 'allow'>,
  status: number,
  reason: string,
  realm: string,
  extra?: { verdict?: VerifyResult; pcactn?: PCActn; matched?: RequiredCapability; policyVerdict?: PcaVerdict },
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

/**
 * Every header an allow may inject upstream. A gateway that forwards only the headers present in the
 * allow response cannot erase a client-supplied copy of one it did not set, so adapters that can
 * (gRPC `headers_to_remove`) strip the ones this decision did not set.
 */
export const PCA_INJECTED_HEADERS: readonly string[] = ['x-pca-verdict', 'x-pca-verb', 'x-pca-grant'];

function allowDecision(
  reason: string,
  extra?: { verdict?: VerifyResult; pcactn?: PCActn; matched?: RequiredCapability; policyVerdict?: PcaVerdict },
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
  /** Raw query string without the `?` (e.g. `a=1&b=2`). Bound into the proof by {@link requestBinding}. */
  query?: string;
  /** Optional authority / `:authority` / Host. Available to callers; route matching uses `path`. */
  authority?: string;
  /** Lower-case hex SHA-256 of the request body, when the adapter/caller can supply it (for `bindRequest.body`). */
  bodySha256?: string;
  /** The raw request body text, when the adapter can supply it (read only by full-policy mode with `params: 'body'`). */
  body?: string;
  headers: HeaderMap;
}

/** "full policy mode is missing x" for a full-mode (or unknown-mode) configuration, "the gateway is missing x" when there is no policy or it is signature-only. */
const missingText = (opts: GatewayOptions, missing: string[]): string => {
  const mode = (opts.policy as GatewayPolicy | undefined)?.mode;
  return `${mode === undefined || mode === 'signature-only' ? 'the gateway' : 'full policy mode'} is missing ${missing.join(', ')}`;
};

const DEFAULT_REQUIRE_CHECKS: readonly string[] = ['revocation'];

/** What is missing from the configuration (empty when complete): the policy mode's components. */
function missingPolicy(opts: GatewayOptions): string[] {
  const p = opts.policy as GatewayPolicy | undefined;
  if (p === undefined) return ["policy ({ mode: 'full', params, state, isRevoked } or an explicit { mode: 'signature-only' })"];
  if (p.mode === 'signature-only') {
    const m: string[] = [];
    if (opts.replayGuard === undefined) m.push('replayGuard (signature-only mode needs a single-use guard)');
    if ((opts.requireChecks ?? DEFAULT_REQUIRE_CHECKS).includes('revocation') && typeof opts.hooks?.revocation !== 'function') {
      m.push("hooks.revocation (required by the default requireChecks ['revocation']; pass requireChecks: [] to waive)");
    }
    return m;
  }
  if (p.mode !== 'full') return [`a known policy mode (got '${String((p as { mode?: unknown }).mode)}')`];
  const { k1: _k1, ...pRest } = p;
  const missing = missingExecutionComponents({ ...pRest, audience: opts.audience, resolveGrant: opts.resolveGrant });
  if (p.params !== 'body' && typeof p.params !== 'function') missing.push("params ('body' or a function)");
  return missing;
}

/** Full-policy mode: the params the agent must have signed for this request, or why they cannot be built. */
function signedParams(req: GatewayRequest, policy: GatewayFullPolicy, bind: BindRequestOptions | false): { params: Record<string, unknown> } | { error: string } {
  let params: unknown;
  if (policy.params === 'body') {
    if (typeof req.body !== 'string') return { error: 'full policy mode reads the params from the body, and the request carries none' };
    try {
      params = strictParse(req.body);
    } catch (e) {
      return { error: `the body is not strict JSON: ${(e as Error).message}` };
    }
  } else {
    params = policy.params(req);
  }
  if (params === null || typeof params !== 'object' || Array.isArray(params)) return { error: 'the request params are not a JSON object' };
  const obj = params as Record<string, unknown>;
  if (bind === false) return { params: obj };
  if (Object.prototype.hasOwnProperty.call(obj, 'binding')) return { error: "the request params carry a 'binding' member (reserved for the request binding)" };
  if ((bind.authority && !req.authority) || (bind.body === true && !req.bodySha256)) return { error: 'request lacks an attribute the proof must bind (authority / body hash)' };
  try {
    // the params carry the body, so its hash is bound only when asked for explicitly (bindRequest.body === true)
    return { params: { ...obj, binding: requestBinding(req, { ...(bind.authority ? { authority: true } : {}), body: bind.body === true }) } };
  } catch (e) {
    return { error: `the request cannot be bound: ${(e as Error).message}` };
  }
}

/** Why `path` is ambiguous for route matching, or `undefined` when it is canonical. */
export function ambiguousPathReason(path: string): string | undefined {
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f\\]/.test(path)) return 'control character or backslash in path';
  if (path.includes('//')) return 'repeated slash in path';
  // Path parameters (`/a;x=1`, `/public/..;/admin`): Tomcat/Jetty/Spring and some proxies strip `;...`
  // from a segment, so the upstream may route a different path than the one matched here.
  if (path.includes(';')) return 'path parameter (;) in path';
  if (path.split('/').some((seg) => seg === '.' || seg === '..')) return 'dot segment in path';
  for (const m of path.matchAll(/%([0-9a-fA-F]{2})/g)) {
    const code = parseInt(m[1] as string, 16);
    const ch = String.fromCharCode(code);
    if (code < 0x20 || code === 0x7f) return 'percent-encoded control character in path';
    if (ch === '/' || ch === '\\') return 'percent-encoded slash in path';
    if (ch === ';') return 'percent-encoded path parameter delimiter in path';
    if (/[A-Za-z0-9\-._~]/.test(ch)) return 'non-canonical percent-encoding in path';
  }
  if (/%(?![0-9a-fA-F]{2})/.test(path)) return 'malformed percent-encoding in path';
  return undefined;
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

  // 0. Ambiguous request targets are never matched against the route map.
  if ((opts.pathPolicy ?? 'strict') === 'strict') {
    const bad = ambiguousPathReason(req.path);
    if (bad !== undefined) return deny('invalid-path', 400, bad, realm);
  }

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

  // 3b. A configuration with a missing component (no policy, an unknown mode, a full-mode component) denies every request
  // (fail closed). Checked before verification so a misconfigured gateway never reports a proof-level reason.
  const missingCfg = missingPolicy(opts);
  if (missingCfg.length > 0) return deny('proof-rejected', 403, `${missingText(opts, missingCfg)} (fail closed)`, realm, { pcactn });

  // 4. Offline verification (fail closed), audience bound to THIS gateway.
  const now = opts.now?.() ?? Date.now();
  const verdict = await verifyPCActnCore(pcactn, {
    grant,
    audience: opts.audience,
    nowEpoch: now,
    ...(opts.authorizedPlanRoots ? { authorizedPlanRoots: opts.authorizedPlanRoots } : {}),
    ...(opts.insecureSkipPlanRootCheck === true ? { insecureSkipPlanRootCheck: true } : {}),
    ...(opts.hooks ? { hooks: opts.hooks } : {}),
    ...(opts.enforce ? { enforce: opts.enforce } : {}),
  });
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

  const policy = opts.policy.mode === 'full' ? opts.policy : undefined;
  let fullParams: Record<string, unknown> | undefined;
  if (policy !== undefined) {
    // 5b (full). The agent signed the real params plus the request binding: rebuild them from THIS request.
    const sp = signedParams(req, policy, opts.bindRequest ?? {});
    if ('error' in sp) return deny('request-mismatch', 403, sp.error, realm, { verdict, pcactn });
    if (pcactn.action.params_digest !== paramsDigest(sp.params)) {
      return deny('request-mismatch', 403, 'the proof is not bound to this request (params/method/path/query/authority)', realm, { verdict, pcactn });
    }
    fullParams = sp.params;
  } else if (opts.bindRequest !== false) {
    // 5b. Request binding (RT-09): the signed params digest must be the digest of THIS request.
    const b = opts.bindRequest ?? {};
    const missing =
      (b.authority && !req.authority) || (b.body === true && !req.bodySha256)
        ? 'request lacks an attribute the proof must bind (authority / body hash)'
        : undefined;
    if (missing !== undefined) return deny('request-mismatch', 403, missing, realm, { verdict, pcactn });
    let bound: string;
    try {
      bound = paramsDigest(requestBinding(req, b));
    } catch (e) {
      return deny('request-mismatch', 403, `the request cannot be bound: ${(e as Error).message}`, realm, { verdict, pcactn });
    }
    if (pcactn.action.params_digest !== bound) {
      return deny('request-mismatch', 403, 'the proof is not bound to this request (method/path/query/authority/body)', realm, { verdict, pcactn });
    }
  }

  // 5c. Required checks must have PASSED (not merely "not-enforced").
  // signature-only: revocation must have passed unless waived; full mode gets it from `isRevoked` below
  for (const c of opts.requireChecks ?? (policy === undefined ? DEFAULT_REQUIRE_CHECKS : [])) {
    if (verdict.checks[c] !== 'pass') {
      return deny('proof-rejected', 403, `required check '${c}' is ${verdict.checks[c] ?? 'absent'}`, realm, { verdict, pcactn });
    }
  }

  // 5d. Per-proof policy hook (limits, budgets, revocation lists). Throws deny.
  if (opts.checkProof) {
    try {
      const r = await opts.checkProof({ pcactn, grant, verdict, request: req, ...(required ? { required } : {}) });
      const ok = typeof r === 'boolean' ? r : r.allow;
      if (!ok) {
        const why = typeof r === 'object' && r.reason ? r.reason : 'rejected by checkProof';
        return deny('proof-rejected', 403, why, realm, { verdict, pcactn });
      }
    } catch (e) {
      return deny('proof-rejected', 403, `checkProof failed: ${(e as Error).message}`, realm, { verdict, pcactn });
    }
  }

  // 5e. Full-policy mode: the grant's limits and caveats, revocation, the replay counter and the trust budget.
  let policyVerdict: PcaVerdict | undefined;
  if (policy !== undefined && fullParams !== undefined) {
    const { mode: _m, params: _p, k1: k1Opt, ...execOpts } = policy;
    const { revocation: _r, ...hooks } = opts.hooks ?? {};
    let k1: K1Input | undefined;
    if (k1Opt !== undefined) {
      try {
        const own = typeof k1Opt === 'function' ? await k1Opt(req, pcactn) : k1Opt;
        k1 = { ...presentedArtifacts(req, policy), ...own };
      } catch (e) {
        return deny('proof-rejected', 403, `k1 input failed: ${(e as Error).message} (fail closed)`, realm, { verdict, pcactn });
      }
    }
    const { provenanceLog: logOpt, ...exec } = execOpts;
    const bundle = presentedProvenance(req, policy);
    const log = logOpt === false ? undefined : (logOpt ?? defaultLogs.get(opts) ?? (defaultLogs.set(opts, memoryProvenanceLog()), defaultLogs.get(opts)!));
    const leaf = pcactn.cap_chain?.[pcactn.cap_chain.length - 1]?.holder;
    const session = (bundle as { receipts?: Array<{ session?: unknown }> } | null | undefined)?.receipts?.[0]?.session;
    const logKey = `${pcactn.grant_ref}\n${String(leaf)}\n${typeof session === 'string' ? session : '-'}`;
    const userObserved = exec.provenance?.observed;
    const provenance = log
      ? {
          ...exec.provenance,
          observed: async (p: PCActn, op: Parameters<NonNullable<typeof userObserved>>[1], sess: string | undefined) => [
            ...(userObserved ? await userObserved(p, op, sess) : []),
            ...(await log.seen(logKey)),
          ],
        }
      : exec.provenance;
    const d = await authorizeExecution(
      pcactn,
      { verb: required?.verb ?? pcactn.action.verb, ...(required?.resource !== undefined ? { resource: required.resource } : {}), params: fullParams, ...(bundle !== undefined ? { provenance: bundle } : {}) },
      { ...exec, ...(provenance !== undefined ? { provenance } : {}), audience: opts.audience, grant, now: () => now, ...(opts.hooks ? { hooks } : {}), ...(k1 !== undefined ? { k1 } : {}) },
    );
    // what this call returns flows back into the agent's context: the session has now seen untrusted content
    if (d.allow && log) await log.add(logKey, { origin: 'tool', source: pcactn.action.verb });
    if (!d.allow) {
      const code: Exclude<DecisionCode, 'allow'> =
        d.kind === 'replay' ? 'replayed-proof' : d.kind === 'binding' ? 'insufficient-capability' : d.kind === 'authn' ? 'verify-failed' : 'proof-rejected';
      return deny(code, d.status, d.reason, realm, { verdict, pcactn, ...(d.verdict ? { policyVerdict: d.verdict } : {}) });
    }
    policyVerdict = d.verdict;
  }

  // 6. Single use (only for a proof that would otherwise be allowed, so denied attempts never burn it).
  if (opts.replayGuard) {
    let first: boolean;
    try {
      first = await opts.replayGuard.claim(`${pcactn.grant_ref}:${pcactn.sig}`, pcactn.exp, now);
    } catch (e) {
      return deny('replay-guard-unavailable', 503, `replay guard unavailable: ${(e as Error).message}`, realm, { verdict, pcactn });
    }
    if (!first) return deny('replayed-proof', 403, 'this proof has already been used', realm, { verdict, pcactn });
  }

  return allowDecision(
    policyVerdict ? 'proof-carrying action authorized (full policy)' : 'proof-carrying action verified',
    { verdict, pcactn, ...(required ? { matched: required } : {}), ...(policyVerdict ? { policyVerdict } : {}) },
  );
}

/** Build a reusable authorizer bound to one config (verify many requests). */
export function createGateway(opts: GatewayOptions): (req: GatewayRequest) => Promise<Decision> {
  // Freeze the configuration (routes, audience, ...): later edits by the caller must not change what this gateway enforces.
  const missing = missingPolicy(opts);
  if (missing.length > 0) throw new TypeError(`pca-gateway: ${missingText(opts, missing)}`);
  const frozen: GatewayOptions = Object.freeze({
    ...snapshotConfig(opts, { keep: ['replayGuard', 'hooks', 'policy'] }),
    // the policy's state store is the caller's (state, not configuration data)
    policy: snapshotConfig(opts.policy, { keep: ['state', 'usesStore', 'provenanceLog'] }),
  });
  return (req: GatewayRequest) => authorize(req, frozen);
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
  /** The request body, when Envoy forwards it (`with_request_body`); read by full-policy mode with `params: 'body'`. */
  body?: string;
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

/** The raw query (no `?`, no `#fragment`) of a request target. */
function queryOfTarget(target: string): string {
  const q = target.indexOf('?');
  if (q < 0) return '';
  const rest = target.slice(q + 1);
  const h = rest.indexOf('#');
  return h >= 0 ? rest.slice(0, h) : rest;
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
  const query = queryOfTarget(target);
  return { method, path, query, headers, ...(authority === undefined ? {} : { authority }), ...(check.body === undefined ? {} : { body: check.body }) };
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
      // HTTP-service mode can only SET upstream headers, never remove them, so a client-supplied
      // `x-pca-verdict` on a pass-through (unmapped, allowed) route would otherwise reach the
      // upstream looking like ours. Always overwrite every injected header; unset ones become ''.
      const blank: Record<string, string> = {};
      for (const h of PCA_INJECTED_HEADERS) blank[h] = '';
      return { status: 200, headers: { ...blank, ...decision.headers }, body: '' };
    }
    return {
      status: decision.status,
      headers: { 'content-type': 'application/json', ...decision.headers },
      body: JSON.stringify({ error: decision.code, reason: decision.reason }),
    };
  };
}

// ---------------------------------------------------------------------------
// Adapter — Envoy gRPC ext_authz (envoy.service.auth.v3.Authorization/Check)
// ---------------------------------------------------------------------------

/**
 * Structural subset of `envoy.service.auth.v3.CheckRequest` as decoded by protobufjs / grpc-js with
 * `keepCase: false` (camelCase field names). Only the fields this adapter reads are declared.
 */
export interface EnvoyGrpcCheckRequest {
  attributes?: {
    request?: {
      http?: {
        method?: string;
        /** The request target INCLUDING the query string, as Envoy received it. */
        path?: string;
        host?: string;
        scheme?: string;
        /** Lower-cased header names (Envoy joins repeated headers with `,`). */
        headers?: Record<string, string | undefined>;
        /** The request body as text (`with_request_body`); read by full-policy mode with `params: 'body'`. */
        body?: string;
      };
    };
  };
}

export interface EnvoyGrpcHeaderValueOption {
  header: { key: string; value: string };
  /** `OVERWRITE_IF_EXISTS_OR_ADD` (2): replaces any client-supplied copy. */
  appendAction: number;
}

/** Structural `envoy.service.auth.v3.CheckResponse`. `status.code` is a `google.rpc.Code`. */
export interface EnvoyGrpcCheckResponse {
  status: { code: number; message: string };
  okResponse?: { headers: EnvoyGrpcHeaderValueOption[]; headersToRemove: string[] };
  deniedResponse?: { status: { code: number }; headers: EnvoyGrpcHeaderValueOption[]; body: string };
}

const GRPC_OK = 0;
const GRPC_UNAUTHENTICATED = 16;
const GRPC_PERMISSION_DENIED = 7;
const GRPC_UNAVAILABLE = 14;
const OVERWRITE_IF_EXISTS_OR_ADD = 2;

function headerOptions(h: Record<string, string>): EnvoyGrpcHeaderValueOption[] {
  return Object.entries(h).map(([key, value]) => ({ header: { key, value }, appendAction: OVERWRITE_IF_EXISTS_OR_ADD }));
}

/**
 * Envoy gRPC `ext_authz` handler: `Check(CheckRequest) -> CheckResponse`. Same decisions as
 * {@link envoyExtAuthz}. On allow it also lists every `x-pca-*` header it did NOT set in
 * `headersToRemove`, so a client cannot smuggle a forged `x-pca-verdict` through an unmapped-route
 * allow. On deny it returns `deniedResponse` (the caller sees that status/headers/body; the upstream
 * sees nothing). Serving it over gRPC is the caller's job (see `test-support/envoy-grpc-server.ts`).
 */
export function envoyGrpcExtAuthz(opts: GatewayOptions): (check: EnvoyGrpcCheckRequest) => Promise<EnvoyGrpcCheckResponse> {
  const gateway = createGateway(opts);
  return async (check: EnvoyGrpcCheckRequest): Promise<EnvoyGrpcCheckResponse> => {
    const http = check.attributes?.request?.http;
    if (!http) {
      // No HTTP attributes at all: not a request we can judge. Fail closed.
      return {
        status: { code: GRPC_PERMISSION_DENIED, message: 'no http request attributes' },
        deniedResponse: {
          status: { code: 403 },
          headers: [],
          body: JSON.stringify({ error: 'invalid-request', reason: 'CheckRequest carried no HTTP attributes' }),
        },
      };
    }
    const headers = http.headers ?? {};
    const req: EnvoyHttpCheckRequest = { headers };
    const method = http.method ?? headers[':method'];
    if (method !== undefined) req.method = method;
    const path = http.path ?? headers[':path'];
    if (path !== undefined) req.path = path;
    const authority = http.host ?? headers[':authority'];
    if (authority !== undefined) req.authority = authority;
    if (http.body !== undefined) req.body = http.body;
    const decision = await gateway(envoyRequest(req));
    if (decision.allow) {
      return {
        status: { code: GRPC_OK, message: '' },
        okResponse: {
          headers: headerOptions(decision.headers),
          headersToRemove: PCA_INJECTED_HEADERS.filter((h) => !(h in decision.headers)),
        },
      };
    }
    return {
      status: {
        code:
          decision.status === 401
            ? GRPC_UNAUTHENTICATED
            : decision.status === 503
              ? GRPC_UNAVAILABLE
              : GRPC_PERMISSION_DENIED,
        message: decision.reason,
      },
      deniedResponse: {
        status: { code: decision.status },
        headers: headerOptions({ 'content-type': 'application/json', ...decision.headers }),
        body: JSON.stringify({ error: decision.code, reason: decision.reason }),
      },
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
  readonly headers: {
    get(name: string): string | null;
    /** Present on a Fetch `Headers`; lets the adapter find and scrub every inbound `x-pca-*`. */
    forEach?(callback: (value: string, name: string) => void): void;
  };
  /** Present on a Fetch `Request`: full-policy mode with `params: 'body'` reads the body from a clone. */
  clone?(): { text(): Promise<string> };
}

/**
 * Worker config: the gateway options plus the two runtime plug points. `next` forwards the request
 * upstream on allow (e.g. `(req) => fetch(req)`), and `respond` builds the deny `Response` (e.g.
 * `(body, init) => new Response(body, init)`) — both supplied by the caller so no Workers runtime
 * type is imported here. The two share the `Res` type, so the returned middleware is `(req) => Res`.
 */
export interface CloudflareWorkerOptions<Req extends WorkerLikeRequest, Res> extends GatewayOptions {
  next: (request: Req) => MaybePromise<Res>;
  /**
   * Returns a copy of the request without the named (lower-case) headers. On allow, any inbound
   * `x-pca-*` header is removed before `next` so a client cannot forge the headers the gateway owns.
   * Default: `new Request(request, { headers })` when the runtime has a global `Request` and the
   * request's headers are enumerable. Pass `null` to opt out; a request that then carries an
   * `x-pca-*` header is rejected (400) instead of forwarded.
   */
  rewriteRequest?: ((request: Req, dropHeaders: readonly string[]) => Req) | null;
  respond: (body: string, init: { status: number; headers: Record<string, string> }) => Res;
}

/** Names (lower-case) of the inbound `x-pca-*` headers a client sent. */
function inboundPcaHeaders(request: WorkerLikeRequest): string[] {
  const found = new Set<string>();
  if (typeof request.headers.forEach === 'function') {
    request.headers.forEach((_v, k) => {
      if (k.toLowerCase().startsWith('x-pca-')) found.add(k.toLowerCase());
    });
  }
  for (const n of PCA_INJECTED_HEADERS) if (request.headers.get(n) !== null) found.add(n);
  return [...found];
}

function defaultRewrite<Req extends WorkerLikeRequest>(request: Req, drop: readonly string[]): Req | undefined {
  const R = (globalThis as { Request?: new (r: unknown, init: { headers: Record<string, string> }) => unknown }).Request;
  if (!R || typeof request.headers.forEach !== 'function') return undefined;
  const kept: Record<string, string> = {};
  request.headers.forEach((v, k) => {
    if (!drop.includes(k.toLowerCase())) kept[k] = v;
  });
  return new R(request, { headers: kept }) as Req;
}

/** Parse the path (and authority) out of a request URL string without needing the `URL` global. */
function pathFromUrl(url: string): { path: string; authority: string; query: string } {
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
  return { path: path === '' ? '/' : path, authority, query: queryOfTarget(rest) };
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
    const { path, authority, query } = pathFromUrl(request.url);
    const pcaHeader = request.headers.get(PCA_HEADER);
    const headers: HeaderMap = pcaHeader === null ? {} : { [PCA_HEADER.toLowerCase()]: pcaHeader };
    for (const h of ['pca-discharges', 'pca-narrow']) {
      const v = request.headers.get(h);
      if (v !== null) headers[h] = v;
    }
    // full-policy mode with body params reads the body from a clone (the original still goes upstream intact)
    const body = opts.policy?.mode === 'full' && opts.policy.params === 'body' && typeof request.clone === 'function' ? await request.clone().text() : undefined;
    const decision = await gateway({ method: request.method, path, query, authority, headers, ...(body === undefined ? {} : { body }) });
    if (decision.allow) {
      const forged = inboundPcaHeaders(request);
      if (forged.length === 0) return opts.next(request);
      const rewrite = opts.rewriteRequest === undefined ? defaultRewrite<Req> : opts.rewriteRequest;
      const clean = rewrite?.(request, forged);
      if (clean !== undefined) return opts.next(clean);
      return opts.respond(JSON.stringify({ error: 'forged-pca-header', reason: 'inbound x-pca-* header cannot be removed' }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      });
    }
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
  /** HTTP API (payload v2): the raw query string. */
  rawQueryString?: string;
  /** REST API (payload v1). */
  queryStringParameters?: Record<string, string | undefined> | null;
  multiValueQueryStringParameters?: Record<string, string[] | undefined> | null;
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

function lambdaQuery(event: LambdaRequestAuthorizerEvent): string {
  if (typeof event.rawQueryString === 'string') return event.rawQueryString;
  const multi = event.multiValueQueryStringParameters;
  const single = event.queryStringParameters;
  const pairs: string[] = [];
  if (multi) {
    for (const [k, vs] of Object.entries(multi)) for (const v of vs ?? []) pairs.push(`${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
  } else if (single) {
    for (const [k, v] of Object.entries(single)) if (v !== undefined) pairs.push(`${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
  }
  return pairs.join('&');
}

function lambdaRequest(event: LambdaRequestAuthorizerEvent): GatewayRequest {
  const { method, path } = lambdaMethodPath(event);
  return { method, path, query: lambdaQuery(event), headers: event.headers ?? {} };
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
export { authorizeExecution, memoryPcaStore } from '@atlasauth/pca';
export type { PCActn, Capability, VerifyResult, PcaVerdict, PcaStateStore } from '@atlasauth/pca';
