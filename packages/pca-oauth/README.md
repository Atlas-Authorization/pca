# @atlasauth/pca-oauth

> Maturity: **experimental**. Its API may change or be removed in any release, and it is outside the stable and production tiers. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

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
- `checkTokenAudience(aud, resource)` - exact audience binding for an already-verified token's `aud` (string or array); missing or different is refused
- `prmPathForResource(resource)`, `prmUrlForResource(resource)` - the RFC 9728 section 3.1 well-known path/URL for a resource identifier (the suffix goes between host and path: `https://h/mcp` is served at `/.well-known/oauth-protected-resource/mcp`)
- `resourceIdentifierProblem(resource)` - why a string is not a valid resource identifier (https, no fragment), or `undefined`
- `protectedResourceMetadata({ ..., strict: true })` - refuse an invalid resource identifier; `parseProtectedResourceMetadata(doc, { expectedResource, strict })` - refuse a document whose `resource` (or embedded audience) is not the identifier you asked for
- `oauthDiscoveryHandler` also returns `rfcPath`, the path to mount when the resource identifier has a path component
- `WELL_KNOWN_OAUTH_PRM` - `/.well-known/oauth-protected-resource`

Specs: RFC 9728, RFC 8707, RFC 6750, RFC 7235, MCP Authorization (revision 2025-11-25).

## Failure modes

| Input | Result |
| --- | --- |
| empty `resource` | `protectedResourceMetadata` throws |
| `resource` not https / has a fragment / not absolute (with `strict`) | throws |
| fetched metadata whose `resource` differs from the identifier you asked for (with `expectedResource`) | `parseProtectedResourceMetadata` throws; do not use the document |
| fetched metadata whose embedded audience differs (with `expectedResource`) | throws |
| metadata missing `pca_*` members or an embedded discovery document | throws |
| `bearer_methods_supported` outside header/body/query (with `strict`) | throws |
| token `aud` missing, empty, a different value, a prefix, a trailing-slash or case variant | `checkTokenAudience` returns `{ ok: false }` |
| no or non-matching `resource` indicator | `checkResourceIndicator` returns `{ ok: false }` |
| quote, backslash, CR/LF or other control character in a challenge parameter or in `pcaChallenge` | `wwwAuthenticate` throws (no header injection) |
| empty `prmUrl` or expected audience | throws |

## Limits

- Pinned to RFC 9728 (OAuth 2.0 Protected Resource Metadata), RFC 8707 (Resource Indicators), RFC 6750 and the MCP authorization specification, revision 2025-11-25. The RFC 9728 example metadata and the section 3.1 and 5.1 examples are reproduced in the tests. The parser is for this package's PCA-profile document, so a document with only the standard members is refused.
- Everything is pure: this package does not fetch metadata, run an authorization server, or verify a token's signature. `checkTokenAudience` and `checkResourceIndicator` compare strings; verify the token first.
- `strict` and `expectedResource` are opt-in so existing integrations keep working. Use both when you fetch another server's metadata.

## Status

Part of [Proof-Carrying Authority](https://github.com/Atlas-Authorization/pca). PCA's cryptography has not been independently audited.

## License

MIT - see LICENSE
