---
title: Carry a PCA grant in your OAuth server
order: 23
---

# Carry a PCA grant in your OAuth server

> **Status: production (pending CI).** `pca_grant` is in `@atlasauth/pca` (the type) and `@atlasauth/pca-oauth` (helpers). See [maturity tiers](../maturity.md).

You can keep your authorization server (Auth0, Stytch, WorkOS, Descope, Microsoft Entra ID, Atlas, or your own) and still get a per-action proof at the resource server. The server issues an ordinary access token whose `authorization_details` names the grant by digest. The resource server resolves the grant and still requires a PCActn on every call. The token alone is never sufficient.

Your authorization server must support custom `authorization_details` types ([RFC 9396](https://www.rfc-editor.org/rfc/rfc9396)). What the providers document, as read on 2026-10-26:

| Provider | RFC 9396 `authorization_details` | Source |
|---|---|---|
| Auth0 | Supported; Auth0 validates the `type` only, so the shape check below is yours | [Auth0 RAR](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow/authorization-code-flow-with-rar) |
| Atlas | Supported with a per-instance type allowlist; stores and returns the details | Atlas OAuth provider settings |
| Microsoft Entra ID | Not documented: the authorize-endpoint parameter list has no `authorization_details`, and the discovery document has no `authorization_details_types_supported` | [auth code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow), [discovery](https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration) |
| WorkOS AuthKit | Not documented: the AuthKit metadata it publishes lists no `authorization_details_types_supported` | [AuthKit and MCP](https://workos.com/docs/authkit/mcp) |
| Stytch Connected Apps | Not documented on the guide page (scopes, PKCE, dynamic registration, consent) | [Stytch guide](https://stytch.com/docs/get-started/guides/ai-agents-and-apps) |
| Descope Inbound Apps | Not documented on the overview page read (audience, scopes, grant types, token exchange); the page was truncated when read | [Descope](https://docs.descope.com/agentic-identity-hub) |

"Not documented" means the pages above do not show support; it is not a statement that the provider rejects the parameter. Where a provider does not document the type, this route is not available through it today.

## The type

```json
{
  "type": "pca_grant",
  "chain_digest": "<unpadded base64url of a sha-256>",
  "chain_len": 1,
  "chain_ref": "https://as.example.com/pca/grants/g_123",
  "bundle_revision": 7,
  "locations": ["https://api.example.com"]
}
```

| Member | Required | Meaning |
|---|---|---|
| `type` | yes | `pca_grant` |
| `chain_digest` | yes | Digest over the capability ids of the first `chain_len` hops |
| `chain_len` | yes | 1 to 16 |
| `chain_ref` | no | https URL where the chain can be fetched |
| `bundle_revision` | no | The policy bundle revision in force when the token was issued |
| `locations` | no | Resource servers the grant is for (RFC 9396 section 2.2) |

The profile is closed. The RFC 9396 common members that would let the authorization server restate authority in its own words (`actions`, `datatypes`, `identifier`, `privileges`) are refused, as is any member not listed. URLs must be https, printable ASCII, without credentials or a fragment. A malformed `pca_grant` entry makes the resource server refuse the whole array; entries of other types are left alone.

## Three steps

1. **Ask for it.** The client sends `authorization_details` with the detail built by `buildPcaGrantDetail` (and `pcaGrantRequestParam` for the form encoding). The authorization server stores it with the grant and returns it in the token or in introspection.
2. **Advertise it.** The resource server lists `pca_grant` in `authorization_details_types_supported` in its protected resource metadata (`protectedResourceMetadata({ authorizationDetailsTypesSupported: ['pca_grant'] })`).
3. **Check it.** On each call, the resource server verifies the PCActn with the PCA verifier and then calls `authorizePcaGrantToken` with the token's details, its own resource identifier, the capability ids of the presented chain and the result of the proof check.

`authorizePcaGrantToken` allows only when a detail names a prefix of the presented chain (a delegated chain extends it, so sub-agents still match), the detail's `locations` include this server, and the proof was verified. The answers are a 401 for a missing, malformed or mismatched token (and for a good token with no verified proof) and a 403 for a token meant for another resource.

## Try it

The `pca-grant-atlas` example runs the whole loop offline, and against an Atlas instance that has the type enabled (`oauthProvider.authorizationDetailsTypesSupported` containing `pca_grant`). Atlas checks the type against the instance allowlist and stores and returns the details; the shape check above happens at your resource server.

## What this does not do

It does not make the token a credential for actions, and it does not make the authorization server a PCA verifier. If the server rewrites `authorization_details` in transit, the token is trusted exactly as far as the server is.
