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
        allowed_upstream_headers: { patterns: [ { exact: "x-pca-verdict" }, { exact: "x-pca-verb" } ] }
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

Experimental. Each adapter wraps the fail-closed `verifyPCActnCore`, which is stateless: the gateway does not keep a replay counter, check revocation, enforce a trust budget or confirm the plan root was authorized. A captured proof can be replayed until it expires. For those checks, enforce at the resource server with `requirePCA` from `@atlasauth/pca` (or one of the framework packages such as `@atlasauth/pca-express`), which also remains the backstop if the gateway is bypassed. The cryptography is unaudited.

## License

MIT - see LICENSE
