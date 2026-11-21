# @atlasauth/pca-connectors

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

The connector catalog for Proof-Carrying Authority (PCA): a declarative registry of outbound SaaS providers as data manifests, plus the authorize-URL, code-exchange and refresh helpers that feed the `@atlasauth/pca-connect` token vault. Wiring a new outbound tool is a manifest edit, and every connection minted here is bound to a PCA capability: the stored token is only released when a verified PCActn proves authority over the provider and scopes.

Built-in manifests: Airtable, Atlassian, Dropbox, GitHub, Google, HubSpot, Linear, Microsoft, Notion, Salesforce, Shopify, Slack, Snowflake, Stripe, Zoom. Each manifest declares the authorize and token URLs, default scopes, PKCE, how the access token is placed on a request, and refresh behaviour.

This package is the code layer only. It never makes the outbound API call and ships no consent UI.

## Install

```sh
npm i @atlasauth/pca-connectors
```

Depends on `@atlasauth/pca` and `@atlasauth/pca-connect` (installed automatically).

## Usage

```ts
import { TokenVault } from '@atlasauth/pca-connect';
import {
  listProviders, buildAuthorizeUrl, exchangeCode, buildVaultProviders, getProvider, applyAccessToken,
} from '@atlasauth/pca-connectors';

listProviders().map((p) => p.id); // ['airtable', 'atlassian', 'dropbox', 'github', 'google', ...]

// 1. Send the user to the provider. Keep `state` and `pkce.verifier` for the callback.
const { url, state, pkce } = buildAuthorizeUrl('google', {
  clientId: process.env.GOOGLE_CLIENT_ID!,
  redirectUri: 'https://app.example/callback',
  scopes: ['https://www.googleapis.com/auth/gmail.readonly'],
});

// 2. A vault whose auto-refresh config is derived from the manifests.
// The vault is strict by default (0.5): an encrypting store, a replay store, a revocation source and a pinned audience.
const vault = new TokenVault({
  providers: buildVaultProviders({ google: { clientId: process.env.GOOGLE_CLIENT_ID!, clientSecret: process.env.GOOGLE_CLIENT_SECRET } }),
  fetch, // your HTTP transport (the global fetch works)
  store: new EncryptedConnectionStore(durableStore, keyWrapper),
  replay: replayStore,
  isRevoked: (p) => checkRevocation(p, registry).then((r) => r.revoked),
  audience: 'rs-1',
});

// 3. On callback, exchange the code and store a capability-bound connection.
await exchangeCode({
  providerId: 'google',
  clientId: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  code, // from the redirect
  redirectUri: 'https://app.example/callback',
  codeVerifier: pkce?.verifier,
  scopes: ['https://www.googleapis.com/auth/gmail.readonly'],
  fetch,
  bind: { vault, agentId, authority: { principal } }, // b64u keys: the agent, and the root the capability chain must start at
});

// Later, a verified PCActn releases the token via vault.getConnectionToken(...); then:
const header = applyAccessToken(getProvider('google')!, accessToken); // { kind: 'header', name: 'Authorization', value: 'Bearer ...' }
```

Custom providers: `registerProvider(manifest)` validates a manifest and adds it to the default registry, or create your own `ProviderRegistry`. A provider that is already registered is not replaced silently (that would send its tokens to another endpoint): pass `{ replace: true }` on purpose, or `{ expectedDigest: manifestDigest(reviewed) }` to accept only the manifest you reviewed. `catalogDigest()` is a digest of the whole registry to pin. Manifests with a `{var}` placeholder in their URLs (such as Shopify) take `vars: { shop: 'acme' }`.

## API

- Registry: `ProviderRegistry`, `defaultRegistry`, `registerProvider`, `getProvider`, `listProviders`, `validateManifest`, `assertManifest`
- Authorization: `buildAuthorizeUrl`, `pkceChallenge`, `applyAccessToken`, `substituteVars`
- Tokens: `exchangeCode`, `refresh`, `manifestToProviderConfig`, `buildVaultProviders`
- `providers` namespace with the built-in manifests

## Fail-closed behaviour

| Missing or invalid | Result |
|---|---|
| A `{var}` value that is not a single DNS label (`evil.com/x?`, `a.b`, `a/b`) | `ConnectorError`: a variable can never move the authorization or token request to another host |
| A manifest URL with credentials, a fragment, or a placeholder that is the whole host | manifest refused |
| A scope that is empty, contains whitespace or a comma, or repeats; a scope the manifest does not list | `buildAuthorizeUrl` refuses (`allowUnlistedScopes: true` to opt out for the unlisted case) |
| `extraParams` / `authParams` that set `client_id`, `redirect_uri`, `scope`, `state`, `response_type`, a PKCE parameter, `grant_type`, `code`, `code_verifier`, `refresh_token` or `client_secret` | refused: the request builders own them |
| A caller-supplied `state` shorter than 16 characters, a PKCE verifier that is not 43 to 128 unreserved characters, the `plain` PKCE method | refused (`allowPlainPkce: true` for `plain`) |
| A redirect URI that is not absolute, has a fragment or credentials, or is plain `http` off localhost | refused |
| An access token with a space, a control character or non-ASCII | `applyAccessToken` refuses (no header injection) |
| A manifest `headerName` that is not an HTTP token or is a protocol header (`Host`, `Content-Length`, ...) | manifest refused |
| A provider id that is not registered | `UnknownProviderError` |
| A malformed manifest | `ManifestValidationError` listing the issues; nothing is registered |
| A provider that is already registered (no `replace` or matching `expectedDigest`), or a manifest that does not match the pinned digest | refused; the existing manifest stays |
| A missing or empty `clientId`, authorization code, or refresh token | `ConnectorError` |
| A PKCE provider with no `codeVerifier` at exchange | `ConnectorError` |
| `basic` client authentication with no client secret or no client id | `ConnectorError` |
| Refresh for a provider whose manifest does not support it | `ConnectorError` |
| A token endpoint that returns a non-success status, a transport error, an unparseable body, a non-object body or no `access_token` | `ConnectorError`; nothing is stored |
| A header-placed manifest with no `headerName`, or a query-placed one with no `queryParam` | `ConnectorError` |
| A provider error body or a transport error that echoes the code, the verifier, the refresh token or the client secret | the secret is replaced with `[redacted]`; an unparseable token body is reported without quoting it |

## Limits

- It is a catalog and request builders. It never calls the provider's API, ships no consent screen, and does not store tokens itself: storage and release belong to the token vault.
- Manifests describe public endpoints and defaults as best known; they can go stale when a provider changes. Check scopes and endpoints for your own app registration.
- Validation covers the shape of a manifest and of the requests built from it, not whether a provider behaves as declared. A registered custom manifest is trusted to point at the provider you meant: review it and pin its digest.
- The `state` value and PKCE verifier are returned to you; keeping them and checking `state` on the callback is the caller's job.
-

## Status

The manifests are data describing each provider's public OAuth endpoints; verify the scopes and endpoints for your own app registration before relying on them. Refresh behaviour and scope narrowing vary by provider and are declared per manifest.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE
