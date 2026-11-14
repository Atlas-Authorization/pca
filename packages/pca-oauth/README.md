# @atlasauth/pca-oauth

> Maturity: **production** (supported for production use), pinned to RFC 9728, RFC 8707, RFC 6750 and the MCP authorization specification revision 2025-11-25. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

OAuth 2.1 / MCP-authorization interop bridge for Proof-Carrying Authority (PCA). It makes a PCA resource server **discoverable** (RFC 9728 Protected Resource Metadata), **challengeable** (MCP-style 401 with `WWW-Authenticate: Bearer resource_metadata="..."`), and **bindable** (RFC 8707 resource indicators), so it composes with generic OAuth 2.1 / MCP clients.

PCA stays the proof layer. This package does not turn a signed PCActn into a bearer token and does not add an authorization server: it is only the discovery and challenge envelope around the proof. The PCActn's signed `aud`, enforced by `requirePCA` in `@atlasauth/pca`, remains the cryptographic cross-server binding; a resource indicator is just the OAuth-layer echo of it.

## Install

```sh
npm i @atlasauth/pca-oauth
```

## Quick start

Mount the Protected Resource Metadata document (RFC 9728):

```ts
import { oauthDiscoveryHandler } from '@atlasauth/pca-oauth';

const { path, body } = oauthDiscoveryHandler({
  resource: 'https://api.acme.com', // this server's PCActn audience
  authorizationServers: ['https://as.acme.com'], // optional
  resourceDocumentation: 'https://docs.acme.com/pca',
});

app.get(path, (_req, res) => res.json(body)); // RFC 9728 path: /.well-known/oauth-protected-resource[/<resource path>]
```

Challenge unauthenticated requests:

```ts
import { mcpUnauthorized, prmUrlForResource } from '@atlasauth/pca-oauth';

const prmUrl = prmUrlForResource('https://api.acme.com'); // import it from the package
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
- `protectedResourceMetadata({ ..., strict })` - strict by default: an invalid resource identifier (not https, fragment, not absolute) throws; `strict: false` only for a local test resource
- `parseProtectedResourceMetadata(doc, { expectedResource, strict })` - strict by default: `expectedResource` is required and the document's `resource` and embedded audience must equal it; `strict: false` checks the shape only
- `oauthDiscoveryHandler` returns `path` (the RFC 9728 path to mount, including the resource path) and `rfcPath` (an alias of `path`)
- `WELL_KNOWN_OAUTH_PRM` - `/.well-known/oauth-protected-resource`

Specs: RFC 9728, RFC 8707, RFC 6750, RFC 7235, MCP Authorization (revision 2025-11-25).

## Failure modes

| Input | Result |
| --- | --- |
| empty `resource` | `protectedResourceMetadata` throws |
| `resource` not https / has a fragment / not absolute (unless `strict: false`) | throws |
| `parseProtectedResourceMetadata` without `expectedResource` (unless `strict: false`) | throws |
| fetched metadata whose `resource` differs from `expectedResource` | throws; do not use the document |
| fetched metadata whose embedded audience differs from `expectedResource` | throws |
| metadata missing `pca_*` members or an embedded discovery document | throws |
| `bearer_methods_supported` outside header/body/query (unless `strict: false`) | throws |
| token `aud` missing, empty, a different value, a prefix, a trailing-slash or case variant | `checkTokenAudience` returns `{ ok: false }` |
| no or non-matching `resource` indicator | `checkResourceIndicator` returns `{ ok: false }` |
| quote, backslash, CR/LF or other control character in a challenge parameter or in `pcaChallenge` | `wwwAuthenticate` throws (no header injection) |
| empty `prmUrl` or expected audience | throws |

## Limits

- Pinned to RFC 9728 (OAuth 2.0 Protected Resource Metadata), RFC 8707 (Resource Indicators), RFC 6750 and the MCP authorization specification, revision 2025-11-25. The RFC 9728 example metadata and the section 3.1 and 5.1 examples are reproduced in the tests. The parser is for this package's PCA-profile document, so a document with only the standard members is refused.
- Everything is pure: this package does not fetch metadata, run an authorization server, or verify a token's signature. `checkTokenAudience` and `checkResourceIndicator` compare strings; verify the token first.
- `strict` is on by default as of 0.5; `strict: false` exists for local test resources only.
- Cross-language conformance does not apply: this is a discovery and challenge envelope over RFC 9728, not a PCA wire format.

## Changes in 0.5

- `strict` defaults to true for `protectedResourceMetadata` and `parseProtectedResourceMetadata`; the parser requires `expectedResource`.
- `oauthDiscoveryHandler().path` is the RFC 9728 path with the resource path; `rfcPath` is an alias.
- The `pca_configuration_endpoint` default ignores a query component of the resource.

## Status

Production. Part of [Proof-Carrying Authority](https://github.com/Atlas-Authorization/pca).

## License

MIT - see LICENSE
