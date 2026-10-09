# @atlasauth/pca-oauth

OAuth 2.1 / MCP-authorization interop bridge for Proof-Carrying Authority (PCA). It makes a PCA resource server **discoverable** (RFC 9728 Protected Resource Metadata), **challengeable** (MCP-style 401 with `WWW-Authenticate: Bearer resource_metadata="..."`), and **bindable** (RFC 8707 resource indicators), so it composes with generic OAuth 2.1 / MCP clients.

PCA stays the proof layer. This package does not turn a signed PCActn into a bearer token and does not add an authorization server: it is only the discovery and challenge envelope around the proof. The PCActn's signed `aud`, enforced by `requirePCA` in `@atlasauth/pca`, remains the cryptographic cross-server binding; a resource indicator is just the OAuth-layer echo of it.

## Install

```sh
npm i @atlasauth/pca-oauth
```

## Usage

Mount the Protected Resource Metadata document (RFC 9728):

```ts
import { oauthDiscoveryHandler } from '@atlasauth/pca-oauth';

const { path, body } = oauthDiscoveryHandler({
  resource: 'https://api.acme.com', // this server's PCActn audience
  authorizationServers: ['https://as.acme.com'], // optional
  resourceDocumentation: 'https://docs.acme.com/pca',
});

app.get(path, (_req, res) => res.json(body)); // /.well-known/oauth-protected-resource
```

Challenge unauthenticated requests:

```ts
import { mcpUnauthorized } from '@atlasauth/pca-oauth';

const prmUrl = 'https://api.acme.com/.well-known/oauth-protected-resource';
const { status, headers, body } = mcpUnauthorized(prmUrl, { error: 'invalid_request' });
res.status(status).set(headers).json(body);
```

Already using `requirePCA` from `@atlasauth/pca`? Upgrade its deny result so one `WWW-Authenticate` header satisfies both MCP and PCA-aware clients:

```ts
import { upgradeUnauthorizedChallenge } from '@atlasauth/pca-oauth';

const result = await guard(req); // requirePCA guard
if (!result.ok) {
  const upgraded = upgradeUnauthorizedChallenge(result, prmUrl);
  res.status(upgraded.status).set('WWW-Authenticate', upgraded.wwwAuthenticate).json({ error: 'forbidden' });
}
```

Check an RFC 8707 resource indicator (an early reject only; the signed `aud` is what actually binds):

```ts
import { checkResourceIndicator } from '@atlasauth/pca-oauth';

const check = checkResourceIndicator(req.query.resource, 'https://api.acme.com');
if (!check.ok) { /* indicator does not match this server */ }
```

## API

- `oauthDiscoveryHandler(opts)` - `{ path, body }` for the metadata route
- `protectedResourceMetadata(opts)` / `parseProtectedResourceMetadata(value)` - build / validate the RFC 9728 document
- `wwwAuthenticate(prmUrl, opts?)` - build the challenge header value
- `mcpUnauthorized(prmUrl, opts?)` - `{ status: 401, headers, body }`
- `upgradeUnauthorizedChallenge(result, prmUrl, opts?)` - add the `resource_metadata` challenge to a PCA deny result
- `checkResourceIndicator(indicator, resource)` - RFC 8707 comparison
- `WELL_KNOWN_OAUTH_PRM` - `/.well-known/oauth-protected-resource`

Specs: RFC 9728, RFC 8707, RFC 6750, RFC 7235, MCP Authorization (revision 2025-11-25).

## Status

Part of [Proof-Carrying Authority](https://github.com/Atlas-Authorization/pca). PCA's cryptography has not been independently audited.

## License

MIT - see LICENSE
