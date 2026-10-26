# @atlasauth/pca-mcp-rs

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

MCP authorization resource server for the 2026-07-28 MCP authorization revision, backed by Proof-Carrying Authority (PCA). Where `@atlasauth/pca-mcp` wraps tool handlers on the client so each call carries a PCActn, this package makes the server that receives those calls a correct OAuth 2.1 resource server: it serves RFC 9728 Protected Resource Metadata, validates Client-ID Metadata Documents, enforces RFC 8707 resource binding and RFC 9207 issuer validation, accumulates scopes down the delegation chain, and issues RFC 9470 step-up challenges. The authority is the PCActn, not a bearer token: its signed `aud` is the resource binding.

## Install

```sh
npm i @atlasauth/pca-mcp-rs @atlasauth/pca
```

Everything is pure and runtime-neutral (no Node builtins, no framework), so it mounts on Express, Fastify, Hono, Next.js, Fetch handlers or any router.

## Usage: authorize a tool call

`authorizeToolCall` is the complete check for one MCP tool call. Call it in each tool handler (or in middleware in
front of the MCP transport) with the request headers, the tool name and the tool arguments:

```ts
import { memoryPcaStore } from '@atlasauth/pca';
import { authorizeToolCall } from '@atlasauth/pca-mcp-rs';

const state = memoryPcaStore(); // replay counters + budgets; production: a shared store with withKeyLock

const r = await authorizeToolCall({ headers: req.headers }, {
  resource: 'https://mcp.example.com/mcp',  // this server; the PCActn's signed `aud` must equal it
  prmUrl: 'https://mcp.example.com/.well-known/oauth-protected-resource',
  tool: 'refund',                            // params.name of the tools/call
  args: { chargeId: 'ch_123', amount: 42 },  // params.arguments of the tools/call
  // Which PCA action each tool call is. The agent signs with the same mapping (pcaFetch in @atlasauth/pca-mcp).
  toolAction: (tool, args) => (tool === 'refund' ? { verb: 'stripe.refund', resource: `charge:${String(args.chargeId)}` } : null),
  resolveGrant: (ref) => grants.get(ref) ?? null, // YOUR store of registered grants, never the request
  isRevoked: (grant) => revoked.has(grant.id),
  state,
});

if (!r.ok) {
  // r.reason is plain language (safe to return as the tool error text), r.hint is for your logs,
  // r.status / r.wwwAuthenticate if you refuse at the HTTP level.
  return { content: [{ type: 'text', text: `PCA denied: ${r.reason}` }], isError: true };
}
```

It runs, in order:

1. **Admission** (`admitRequest`, below): the PCActn is present and well-formed, chains to the grant from your
   store, is signed by the holder, is for this `resource` (RFC 8707), comes from a trusted issuer (RFC 9207), and
   carries the tool's scopes and step-up tier if you configure them. Omit `authorizationServers` when your grant store
   is the trust anchor.
2. **Binding to the call**: the PCActn's signed verb and resource must be `toolAction(tool, args)`, and the tool
   arguments must hash to its signed params digest. A proof for another tool, resource or amount is refused, and
   refusing it does not spend it.
3. **The full verifier** (`requirePCA` from `@atlasauth/pca`): the grant's permissions, limits and caveats,
   revocation, the replay counter and the trust budget. A money-moving call is priced by the server from the verified
   amount (`toolCallRisk`: amount / the grant's per-call cap), never from the agent's claim. Pass `risk` to supply
   other inputs your server can vouch for; inputs it does not supply are priced at the worst case, which under the
   default risk policy asks for a human co-sign.

Denials read like: `the grant does not permit stripe.delete_customer (it permits: stripe.refund)`,
`amount <= 500 not satisfied for stripe.refund on charge:ch_1`,
`the proof is for stripe.refund on charge:ch_1, but this call is stripe.delete_customer on customer:cus_1`.
The `WWW-Authenticate` value of a binding or policy denial carries only the error code, never request text.

The `create-pca-app` `mcp` template (`npm create pca-app@latest my-mcp -- --template mcp`) is a working MCP server and
agent built this way.

## Protected Resource Metadata

```ts
import { prmHandler } from '@atlasauth/pca-mcp-rs';

const prm = prmHandler({ resource: 'https://mcp.example.com/mcp', authorizationServers: ['https://as.example.com'] });
// GET prm.path  ->  JSON prm.body (RFC 9728)
```

## `authorizeRequest` and admission only

`authorizeRequest(req, opts)` is the complete check, exactly `authorizeToolCall` (since 0.5). Admission alone is an
explicit choice: `authorizeRequest(req, { ...opts, admissionOnly: true })`, also exported as `admitRequest(req, opts)`.
**Admission does not check the grant's limits, the binding to the tool call, or replay**: a refund-only grant's PCActn
for `stripe.delete_customer`, a $5000 refund under a $500 limit, a proof made for another tool and the same proof twice
are all admitted. Use it only if you run the full verifier yourself. A call to `authorizeRequest` that omits what the
full check needs (`tool`, `toolAction`, `state`, `isRevoked`, `resolveGrant`) is refused, not downgraded to admission.

The admission options (`AdmissionOptions`) are those of `authorizeToolCall` without `args`, `toolAction`, `state` and
`isRevoked`; the `authorizationServers` list is required. For a grant minted with `agent()` or `mintGrant()`, the issuer is the
principal's public key (`grant.issuer`), not a URL; use `resolveIssuer` to map grants to an authorization-server URL.
Granted scopes come from `scope` caveats (`{ type: 'scope', scopes: [...] }`) on the capability chain, or from
`baseScopes`. A denial carries `status`, `error`, `errorDescription`, `wwwAuthenticate`, and optionally `stepUp`,
`checks` and a developer `hint`. It reads the PCActn from the `PCA-Action` header (base64url) or a JSON body
`{ pcactn }`, and fails closed.

## API

- `protectedResourceMetadata(opts)`, `prmHandler(opts)`, `WELL_KNOWN_OAUTH_PRM` - RFC 9728 metadata.
- `authorizeToolCall(req, opts)` - the complete check for one MCP tool call (admission, binding to the call, full verifier). `toolCallRisk(grant, args, { amountField? })` - the server-side pricing it uses for money-moving calls.
- `authorizeRequest(req, opts)` - the complete check by default (it is `authorizeToolCall`); with `admissionOnly: true` it is `admitRequest(req, opts)`, admission only (no limits, call binding or replay). `extractPCActn(req)` reads the proof.
- `wwwAuthenticateChallenge(opts)` - build a `WWW-Authenticate: Bearer ...` value.
- `clientIdMetadataDocument(opts)`, `verifyCimd(input, opts?)` - Client-ID Metadata Documents (https `client_id`, redirect URI checks).
- `accumulateScopes(caveats, base?)`, `isScopeCaveat` - scope narrowing from `scope` caveats.
- `requiredRolesForTier`, `verifyStepUp`, `StepUpChallenge` - step-up helpers.

## Status

Step-up is cryptographically verified and has no presence-check default. When several tier sources apply (`requiredTier`, `toolStepUp[tool]`, the `riskTiers` tier) the effective tier is their maximum, and `toolStepUp` without a `tool` fails closed (R3-08). When a tier applies (`toolStepUp`, `requiredTier`, or `riskTiers`), pass `stepUpSignerSet` (the agent, guardian and principal public keys): every share is verified against it with the tier as the required `t` (tier 2 = t 2, tier 3 = t 3, so tier 3 needs a verified principal share), through the PCA threshold verifier. Or pass your own `stepUpSatisfied`, which must verify the shares itself. With neither, the call fails closed. `riskTiers` needs a `serverRisk(pcactn, grant)` callback that recomputes risk from server-held data; the agent's signed `risk_claim.r` is never used. `authorizeRequest` calls the PCA core verifier with the grant and audience only; `authorizeToolCall` adds the call binding and the full verifier (limits, revocation, replay, budget). `authorizeToolCall` does not drive a step-up: a call whose risk needs a co-sign is refused with that reason. PCA cryptography has not been independently audited.

## License

MIT - see LICENSE
