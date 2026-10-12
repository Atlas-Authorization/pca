# @atlasauth/pca-gateway

Drop-in, **code-free** Proof-Carrying Authority enforcement at the gateway / service mesh — the
language-agnostic choke point in front of every MCP server / agent service. Add it to your gateway and
every inbound request is proof-carrying-verified with **zero application changes**: the request only
reaches the upstream once a valid PCActn — for this gateway's audience, carrying the capability the
route requires — has been verified by the stateless offline core (`verifyPCActnCore` from `@atlasauth/pca`).

Framework-agnostic: the only dependency is `@atlasauth/pca`. The gateway SDKs (Envoy protobufs,
`aws-lambda`, the Workers runtime) are never imported; every event, request and response shape is a
minimal structural shim.

## Install

```sh
npm i @atlasauth/pca-gateway
```

## How it works

A client carries the proof as `PCA-Action: <base64url>` (see `@atlasauth/pca` `pcaHeaders`). The
gateway:

1. extracts the PCActn from the header (fail closed if absent / undecodable),
2. maps `method` + `path` → the required capability via your route map,
3. verifies the proof offline with `verifyPCActnCore` (chain, plan inclusion, signature, counter
   well-formedness, validity window, and audience bound to **this** gateway),
4. checks the verified proof carries the route's required verb (and optional resource),
5. returns an allow / deny **Decision** mapped onto the gateway's own contract.

**Deny-by-default** everywhere: no proof, an undecodable proof, a wrong-audience proof, an
insufficient-capability proof, and (by default) an unmapped route are all rejected.

## Usage

```ts
import { authorize, createGateway, type GatewayOptions } from '@atlasauth/pca-gateway';

const options: GatewayOptions = {
  audience: 'ins_acme',                       // RFC 8707 resource id of the services behind this gateway
  routes: [
    { method: 'POST', path: '/refunds',   capability: { verb: 'stripe.refund' } },
    { method: 'POST', path: '/payouts/*', capability: { verb: 'stripe.payout', resource: 'acct:acme' } },
  ],
  resolveGrant: async (grantRef) => grants.get(grantRef), // root Capability the chain must descend from
  unmatchedRoute: 'deny',                     // 'deny' (default) | 'allow' | 'require-proof'
};

const gateway = createGateway(options);
const decision = await gateway({ method: 'POST', path: '/refunds', headers: req.headers });
// { allow, status, code, reason, headers, verdict?, pcactn?, matched? }
```

`authorize(req, opts)` is the one-shot form; `createGateway(opts)` builds a reusable authorizer.

## Adapters

### Envoy HTTP `ext_authz` (Istio `AuthorizationPolicy action: CUSTOM`)

```ts
import { envoyExtAuthz } from '@atlasauth/pca-gateway';
const check = envoyExtAuthz(options); // (checkRequest) => { status, headers, body }  (200 allow / 403|401 deny)
```

```yaml
# Envoy http_filters
http_filters:
- name: envoy.filters.http.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    transport_api_version: V3
    http_service:
      server_uri: { uri: pca-gateway:8080, cluster: pca_gateway, timeout: 0.5s }
      authorization_request:
        allowed_headers: { patterns: [ { exact: "pca-action" } ] }
      authorization_response:
        allowed_upstream_headers: { patterns: [ { prefix: "x-pca-" } ] }
- name: envoy.filters.http.router
```

```yaml
# Istio AuthorizationPolicy (CUSTOM); provider declared in meshConfig.extensionProviders
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata: { name: pca-gateway, namespace: istio-system }
spec:
  selector: { matchLabels: { app: mcp-server } }
  action: CUSTOM
  provider: { name: pca-gateway-ext-authz }
  rules: [ { to: [ { operation: { paths: ["/*"] } } ] } ]
```

Set `meshConfig.pathNormalization.normalization: MERGE_SLASHES`, otherwise `//refunds` does not match a `/refunds` rule and skips the provider (observed on Istio 1.31.1, see Status).

### Envoy gRPC `ext_authz` (`envoy.service.auth.v3.Authorization/Check`)

```ts
import { envoyGrpcExtAuthz } from '@atlasauth/pca-gateway';
const check = envoyGrpcExtAuthz(options); // (CheckRequest) => CheckResponse, both as plain camelCase objects
```

The adapter is transport-free: it takes the decoded `CheckRequest` object and returns the `CheckResponse` object, so it adds no gRPC dependency. Serve it with any gRPC stack; `test-support/envoy-grpc-server.ts` shows one with `@grpc/grpc-js` and `protobufjs` (test-only). On deny it returns `status.code` `UNAUTHENTICATED` (16) / `PERMISSION_DENIED` (7) / `UNAVAILABLE` (14) and a `deniedResponse` carrying the HTTP status, challenge header and JSON body. On allow it overwrites the `x-pca-*` headers it sets and lists the ones it did not set in `headersToRemove`, so a client cannot smuggle a forged `x-pca-verdict` through a pass-through route.

```yaml
http_filters:
- name: envoy.filters.http.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    transport_api_version: V3
    grpc_service: { envoy_grpc: { cluster_name: pca_gateway }, timeout: 0.5s }   # cluster needs http2_protocol_options
    failure_mode_allow: false
```

### Replay, path hardening and header injection

- **Replay**: `replayGuard` makes each proof single-use (`memoryReplayGuard()` per process, or implement `ReplayGuard` over a shared store). A second presentation is denied `403 replayed-proof`; a guard that throws or is full denies `503 replay-guard-unavailable`. Without it, a captured proof is accepted again until it expires. Scope and caveats: `memoryReplayGuard` is per process (a second instance or a restart does not share it, so use a shared store for a fleet); the gateway passes its own clock (`now`) to the guard, and a claim stays live through `exp` inclusive because the verifier accepts a proof at `now == exp`. API Gateway caches authorizer results by identity source (`authorizerResultTtlInSeconds`), so a cached Allow is served without invoking the Lambda and a replay inside the TTL is not seen by the guard: set the TTL to 0 for single-use enforcement. Envoy can retry a request (`retry_policy`) or a client may retry after a timeout; the check service is called again with the same proof and a single-use guard denies the retry as `replayed-proof`, so retries must carry a fresh proof (or the guard must be keyed per attempt).
- **Path policy** (`pathPolicy: 'strict'`, the default): dot segments, `//`, path parameters (`;`, including `/public/..;/admin`), backslashes, control characters, percent-encoded `.` `/` `\` and percent-encoded unreserved characters are denied `400 invalid-path` before route matching, because an upstream that decodes or normalises them would reach a different route than the one matched. Envoy without `normalize_path` forwards all of these untouched (see Status).
- **Route matching is exact**: a trailing slash (`/refunds/`) and a different case (`/Refunds`) are different paths from `/refunds`. With `unmatchedRoute: 'allow'` they are forwarded without a proof, which is only safe when the upstream normalises exactly as the gateway matches (no trailing-slash or case folding). For protected paths prefer `unmatchedRoute: 'require-proof'` (or `'deny'`) so a variant spelling still needs a valid proof.
- **Header injection**: in HTTP-service mode Envoy can only set upstream headers, not remove them, so on every allow `envoyExtAuthz` overwrites all of `x-pca-verdict`, `x-pca-verb` and `x-pca-grant` (unset ones become empty). Configure Envoy's `allowed_upstream_headers` with `prefix: "x-pca-"` (as above), not only `x-pca-verdict` and `x-pca-verb`, or a forged `x-pca-grant` is left in place. The Cloudflare Worker adapter removes every inbound `x-pca-*` header before `next` on allow (via `rewriteRequest`, default `new Request(request, { headers })`), and returns `400` if it cannot.

### Binding the proof to the request, limits and revocation

By default a verified proof is a **bearer for the matched route**: a proof minted for `refund charge:ch_1` is accepted on every path the rule matches (`/refunds/*`), and the grant's own limits and revocation are not evaluated (the core reports `revocation`, `plan_root_authorized` as `not-enforced`). Treat the default gateway as a *structural pre-filter*; the resource server's `requirePCA` is the authority. Three opt-ins close this at the gateway:

- Request binding is ON by default (breaking, R2-11). `bindRequest` (default `{}`) requires `action.params_digest == paramsDigest(requestBinding(req, opts))`. The agent mints the action with `requestBinding({ method, path, query, ... })` as its params (`{ v: 2, method, path, query }`, where `query` is the raw query string with pairs sorted (a repeated parameter name, a `;` separator or a malformed percent escape in a name makes the request unbindable: `403 request-mismatch`, because upstream parsers disagree on first-wins vs last-wins, R3-07); the adapters fill `GatewayRequest.query` for you; Lambda REST v1 rebuilds it from `queryStringParameters`). The proof then works only for that method, path and query string, plus the body SHA-256 whenever the request carries one (`GatewayRequest.bodySha256`; the adapters do not read bodies; `body: false` opts out, `body: true` makes a missing hash a deny) and the authority when `authority: true`. Otherwise `403 request-mismatch`. Pass `bindRequest: false` to opt out explicitly: the proof is then a bearer for the matched route. The params slot carries the binding, so params-dependent grant limits cannot be read here; use `checkProof`.
- `hooks` / `enforce` are forwarded to `verifyPCActnCore` (revocation, attestation, freshness, taint), and `requireChecks: ['revocation']` makes a check that is merely `not-enforced` a deny (`403 proof-rejected`).
- `checkProof(ctx)` is a per-proof policy hook (limits, budgets, deny-lists) run before the single-use claim; returning false or throwing denies.

`plan_root_authorized` is always `not-enforced` in the offline core (the agent supplies its own plan, so plan inclusion alone proves nothing); do not put it in `requireChecks` (it would deny every request). Authorize the plan root at the resource server (`requirePCA` with `context.planAuthorized`). Binding is off by default (non-breaking). Neither it nor the hooks make the gateway a substitute for `requirePCA`.

### Cloudflare Worker

```ts
import { cloudflareWorker } from '@atlasauth/pca-gateway';

const handler = cloudflareWorker({
  ...options,
  next: (request) => fetch(request),                              // forward upstream on allow
  respond: (body, init) => new Response(body, init),             // build the 401/403 Response on deny
});

export default { fetch: handler };
```

### AWS API Gateway (Lambda authorizer)

```ts
import { lambdaAuthorizer, lambdaSimpleAuthorizer } from '@atlasauth/pca-gateway';

export const handler = lambdaAuthorizer(options);        // IAM Allow/Deny policy (REST + HTTP API)
export const simple  = lambdaSimpleAuthorizer(options);  // { isAuthorized } (enableSimpleResponses: true)
```

## Status

Experimental. Each adapter wraps the fail-closed `verifyPCActnCore`, which is stateless: the gateway does not keep a replay counter, check revocation, enforce a trust budget or confirm the plan root was authorized. A captured proof can be replayed until it expires unless you set `replayGuard` (single use). For those checks, enforce at the resource server with `requirePCA` from `@atlasauth/pca` (or one of the framework packages such as `@atlasauth/pca-express`), which also remains the backstop if the gateway is bypassed. The cryptography is unaudited.

What has been checked against real runtimes and published shapes:

- **Cloudflare Worker**: the adapter is exercised with the real Fetch `Request` and `Response` classes (allow, missing proof, tampered proof, wrong audience, wrong capability, unmapped route, query strings, dot-segment paths), and the same entry is bundled and run inside `workerd` through Miniflare 4.20260730.0 for the allow and deny paths.
- **AWS API Gateway Lambda authorizer**: tested with the request-authorizer events from the AWS documentation for REST APIs and for HTTP API payload formats 1.0 and 2.0 (committed as fixtures with their source URL and sha256), including the IAM-policy response shape and the HTTP API simple response. The authorizer bundle was also run inside the official AWS Lambda Node.js 20 and 22 base images through the Runtime Interface Emulator (docker on a short-lived x86_64 Linux VM, since deleted): REST REQUEST authorizer events and HTTP API payload 2.0 simple responses, with allow, no proof, tampered proof, wrong audience, wrong capability, an empty event (fail closed) and a replay guard exercised across eight sequential invocations of one warm container (one Allow). The recorded events and responses are committed in `fixtures/lambda-run/` and replayed offline by `src/lambda-real.test.ts`. AWS SAM CLI 1.167.0 `sam local start-api` then put its emulated API Gateway in front of the same Lambda: REST REQUEST, HTTP API 2.0 simple and HTTP API 1.0 IAM routes returned 200 for valid proofs and 401/403 for missing, tampered and wrong-audience ones, and a TOKEN-type event is denied (unsupported, fail closed). Findings: a context value is a JSON string; responses carry no cache field (the TTL is an authorizer setting, so single-use needs a TTL of 0); `sam local` serves a missing identity source as 401. LocalStack (current image refuses to start without an account token; community 3.8.1 never invoked the authorizer) added no coverage and is not counted. The deployed AWS API Gateway service is not exercised, so authorizer result caching and its TTL are not verified.
- **Envoy ext_authz (HTTP service and gRPC)**: run behind a real Envoy **1.39.3** release build (`6eb0d2d.../1.39.3/Clean/RELEASE/BoringSSL`, the community `tetratelabs/archive-envoy` darwin-arm64 tarball, sha256 `e48fff9d...af312`; the vendored protos are the same version) in front of a recording upstream, 40 end-to-end tests. Covered: allow (the upstream receives the request and the injected `x-pca-*` headers); missing, undecodable, tampered, wrong-audience, wrong-capability, unmapped-route and replayed proofs (Envoy returns the adapter's status, challenge and JSON body and the upstream receives nothing); query strings (Envoy forwards the target with the query, the adapter routes on the path); header-name case (Envoy lower-cases; a duplicated `PCA-Action` header is joined with a comma and fails closed); `with_request_body` truncation (the check service gets the first `max_request_bytes`, the upstream gets the whole body, Envoy adds `x-envoy-auth-partial-body`), `allow_partial_message: false` (Envoy answers 413 itself, neither service is called) and a body within the limit; a dead check service with `failure_mode_allow: false` (Envoy answers 403, the upstream receives nothing; with `true` it would fail open); `normalize_path` / `merge_slashes` on and off. The gateway never inspects the request body, so a proof is not bound to the body it accompanies. The `CheckRequest` messages Envoy sent are committed as `fixtures/envoy-captured-*.json` with provenance (Envoy version string and tarball sha256) and replayed in the always-on conformance tests. Run the live tests with `scripts/run-envoy-ext-authz.sh` (downloads Envoy when `PCA_ENVOY_BIN` is unset; no Docker); they are skipped by default.
- **Validation findings**: in HTTP-service mode Envoy copies only the headers present in the allow response, so the adapter overwrites every `x-pca-*` header it owns on a pass-through route; with Envoy's default `normalize_path: false`, `//refunds` and `/x/../refunds` reach the adapter verbatim, which the strict path policy denies; proofs are single-use only with `replayGuard`. The `envoy.service.auth.v3` gRPC form is `envoyGrpcExtAuthz`.
- **Envoy `path_prefix`**: Envoy prepends it to the check request target (observed: `/pca-check/refunds`), so the route map no longer matches and every request is denied. Leave it unset on the `http_service`.
- **Istio 1.31.1 (real `CUSTOM` AuthorizationPolicy)**: run on a single-node k3s v1.36.5 cluster (containerd, no Docker) on a short-lived Azure VM. A sidecar-injected `client` calls a sidecar-injected `upstream`; the upstream's sidecar enforces `AuthorizationPolicy action: CUSTOM` with an `envoyExtAuthzHttp` provider pointing at `envoyExtAuthz` (scripts in `scripts/istio/`, captured output in `fixtures/istio-run/`; the HTTP-service provider only, not `envoyExtAuthzGrpc`). 16 checks passed: allow with query string (the upstream received the request and `x-pca-verb`), missing, tampered, wrong-audience, wrong-capability, replayed and undecodable proofs denied with the adapter's status and challenge, an unmapped-but-policed route denied, and the provider scaled to zero denies (Istio's `failOpen` defaults to false). Caveats the run exposed: (1) Istio only calls the provider for requests matching the policy's `rules`, so a path outside them reaches the upstream with no proof and **a forged `x-pca-verdict` is not scrubbed there**; the upstream must never trust `x-pca-*` on a route the policy does not cover; (2) with Istio's default path normalisation `//refunds` did **not** match the policy's `/refunds` rule and reached the upstream with no proof, while `/refunds/../refunds`, `/%72efunds` and `/./refunds` were normalised and sent to the check service; setting `meshConfig.pathNormalization.normalization: MERGE_SLASHES` closed it (`//refunds` and `///refunds` then denied without a proof, allowed with one). Use that setting, and prefer a policy that covers every path (`paths: ["/*"]`) with the gateway's deny-by-default route map. Not exercised: ingress gateways, multi-node clusters, mTLS between the sidecar and a mesh-injected check service.
Not validated: a deployed Lambda authorizer behind the real API Gateway service (caching and TTL behaviour in particular), Workers features beyond fetch handling, TLS or mTLS between Envoy and the check service, ext_authz under load or with retries, and Istio's `envoyExtAuthzGrpc` provider.

## License

MIT - see LICENSE
