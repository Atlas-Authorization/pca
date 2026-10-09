# @atlasauth/pca-mcp-rs

MCP authorization resource server for the 2026-07-28 MCP authorization revision, backed by Proof-Carrying Authority (PCA). Where `@atlasauth/pca-mcp` wraps tool handlers on the client so each call carries a PCActn, this package makes the server that receives those calls a correct OAuth 2.1 resource server: it serves RFC 9728 Protected Resource Metadata, validates Client-ID Metadata Documents, enforces RFC 8707 resource binding and RFC 9207 issuer validation, accumulates scopes down the delegation chain, and issues RFC 9470 step-up challenges. The authority is the PCActn, not a bearer token: its signed `aud` is the resource binding.

## Install

```sh
npm i @atlasauth/pca-mcp-rs @atlasauth/pca
```

Everything is pure and runtime-neutral (no Node builtins, no framework), so it mounts on Express, Fastify, Hono, Next.js, Fetch handlers or any router.

## Usage

```ts
import { prmHandler, authorizeRequest } from '@atlasauth/pca-mcp-rs';

const resource = 'https://mcp.example.com';
const authorizationServers = ['https://as.example.com'];

// 1. Serve the Protected Resource Metadata (RFC 9728) at the returned path.
const prm = prmHandler({ resource, authorizationServers, scopesSupported: ['refund:write'] });
// GET prm.path  ->  JSON prm.body

// 2. Admit each tool call.
const result = await authorizeRequest(req /* { headers, body? } */, {
  resource,                                   // must equal the PCActn's signed `aud`
  authorizationServers,                       // allowed grant issuers (RFC 9207)
  resolveGrant: async (ref) => grants.get(ref) ?? null,
  prmUrl: `${resource}${prm.path}`,
  tool: 'refund',
  toolScopes: { refund: 'refund:write' },
  toolStepUp: { refund: 2 },                  // optional: require a guardian (2) or principal (3) co-sign
});

if (!result.ok) {
  // result.status is 401 or 403; send the challenge header with the response.
  return new Response(JSON.stringify({ error: result.error }), {
    status: result.status,
    headers: { 'WWW-Authenticate': result.wwwAuthenticate },
  });
}
result.pcactn; result.grantedScopes; result.checks;
```

`authorizeRequest` reads the PCActn from the `PCA-Action` header (base64url) or a JSON body `{ pcactn }`, and fails closed: any missing, mismatched or unverifiable element is denied with the correct status and `WWW-Authenticate` challenge, and unexpected errors deny with 403.

## API

- `protectedResourceMetadata(opts)`, `prmHandler(opts)`, `WELL_KNOWN_OAUTH_PRM` - RFC 9728 metadata.
- `authorizeRequest(req, opts)`, `extractPCActn(req)` - the admission check.
- `wwwAuthenticateChallenge(opts)` - build a `WWW-Authenticate: Bearer ...` value.
- `clientIdMetadataDocument(opts)`, `verifyCimd(input, opts?)` - Client-ID Metadata Documents (https `client_id`, redirect URI checks).
- `accumulateScopes(caveats, base?)`, `isScopeCaveat` - scope narrowing from `scope` caveats.
- `requiredRolesForTier`, `defaultStepUpSatisfied`, `StepUpChallenge` - step-up helpers.

## Status

Step-up satisfaction defaults to a presence check: `defaultStepUpSatisfied` only tests that the PCActn carries a threshold share from a qualifying role. It does not cryptographically verify the shares. Pass `stepUpSatisfied` to `authorizeRequest` to plug in a real threshold verifier. `authorizeRequest` calls the PCA core verifier with the grant and audience only; it takes no replay store or revocation list, so add those around it if you need them. PCA cryptography has not been independently audited.

## License

MIT - see LICENSE
