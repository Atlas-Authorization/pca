# @atlasauth/pca-oauth

OAuth 2.1 / MCP-authorization **interop bridge** for Proof-Carrying Authority. It makes a PCA resource
server **discoverable** (RFC 9728 Protected Resource Metadata), **challengeable** (MCP 401 +
`WWW-Authenticate: Bearer resource_metadata=…`), and **bindable** (RFC 8707 resource indicators) over the
de-facto agent↔tool wire — the MCP OAuth 2.1 Resource-Server handshake.

## Honest framing

PCA is the **proof** layer: a signed PCActn whose `aud` binds one action to one resource server is the
credential a verifier (`@atlasauth/backend` `requirePCA`) checks default-deny. **This bridge does not turn
a PCActn into a bearer token and does not add an authorization server.** It is the discovery / challenge
envelope around the proof, so a PCA RS *composes with* OAuth 2.1 / MCP clients. The PCActn remains the
credential; its signed `aud` remains the cryptographic cross-server binding. A resource indicator is only
the OAuth-layer echo of that binding.

## Specs

- **RFC 9728** — OAuth 2.0 Protected Resource Metadata
- **RFC 8707** — Resource Indicators for OAuth 2.0
- **RFC 6750** — Bearer Token Usage (the `WWW-Authenticate: Bearer …` shape)
- **RFC 7235** — HTTP Authentication (multiple comma-separated challenges in one header)
- **MCP Authorization**, protocol revision **2025-11-25** (401 carries `resource_metadata` pointing at the
  RFC 9728 document)

## Install

```sh
npm i @atlasauth/pca-oauth
```

## Usage

### 1. Mount the Protected Resource Metadata (RFC 9728)

```ts
import { oauthDiscoveryHandler } from '@atlasauth/pca-oauth';

const { path, body } = oauthDiscoveryHandler({
  resource: 'https://api.acme.com', // = this RS's PCActn audience (one source of truth)
  authorizationServers: ['https://as.acme.com'], // optional
  resourceDocumentation: 'https://docs.acme.com/pca',
});

app.get(path, (_req, res) => res.json(body)); // GET /.well-known/oauth-protected-resource
```

The document embeds the PCA discovery block (from `@atlasauth/pca` `buildDiscoveryDocument`) plus a
pointer to `.well-known/pca-configuration`, so a PCA-aware client auto-configures from one fetch while a
generic OAuth/MCP client reads only the standard RFC 9728 fields.

### 2. Challenge unauthenticated requests (MCP 401)

```ts
import { mcpUnauthorized } from '@atlasauth/pca-oauth';

const prmUrl = 'https://api.acme.com/.well-known/oauth-protected-resource';
const { status, headers, body } = mcpUnauthorized(prmUrl, { error: 'invalid_request' });
// WWW-Authenticate: Bearer resource_metadata="…", PCA realm="pca", hint="…"
res.status(status).set(headers).json(body);
```

Already using `requirePCA`? Upgrade its 401 so the one header satisfies both clients:

```ts
import { upgradeUnauthorizedChallenge } from '@atlasauth/pca-oauth';

const result = await guard(req); // @atlasauth/backend requirePCA deny arm
if (!result.ok) {
  const upgraded = upgradeUnauthorizedChallenge(result, prmUrl); // reuses the existing PCA challenge verbatim
  res.status(upgraded.status).set('WWW-Authenticate', upgraded.wwwAuthenticate).json({ error: 'forbidden' });
}
```

### 3. Bind the request to this RS (RFC 8707)

```ts
import { checkResourceIndicator } from '@atlasauth/pca-oauth';

const check = checkResourceIndicator(req.query.resource, 'https://api.acme.com');
if (!check.ok) { /* early-reject: resource indicator does not match this RS */ }
// NOTE: this is the OAuth-layer echo only. The PCActn's SIGNED `aud`, enforced by requirePCA, is the
// cryptographic cross-server binding — a spoofed/dropped indicator cannot defeat it.
```

Part of Proof-Carrying Authority — see [`@atlasauth/pca`](../pca) and the framework guards
[`@atlasauth/pca-fetch`](../pca-fetch) / [`-express`](../pca-express) / [`-fastify`](../pca-fastify) /
[`-hono`](../pca-hono) / [`-next`](../pca-next).
