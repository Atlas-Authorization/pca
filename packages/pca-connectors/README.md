# @atlasauth/pca-connectors

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
const vault = new TokenVault({
  providers: buildVaultProviders({ google: { clientId: process.env.GOOGLE_CLIENT_ID!, clientSecret: process.env.GOOGLE_CLIENT_SECRET } }),
  fetch, // your HTTP transport (the global fetch works)
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

Custom providers: `registerProvider(manifest)` validates a manifest and adds it to the default registry, or create your own `ProviderRegistry`. Manifests with a `{var}` placeholder in their URLs (such as Shopify) take `vars: { shop: 'acme' }`.

## API

- Registry: `ProviderRegistry`, `defaultRegistry`, `registerProvider`, `getProvider`, `listProviders`, `validateManifest`, `assertManifest`
- Authorization: `buildAuthorizeUrl`, `pkceChallenge`, `applyAccessToken`, `substituteVars`
- Tokens: `exchangeCode`, `refresh`, `manifestToProviderConfig`, `buildVaultProviders`
- `providers` namespace with the built-in manifests

## Status

The manifests are data describing each provider's public OAuth endpoints; verify the scopes and endpoints for your own app registration before relying on them. Refresh behaviour and scope narrowing vary by provider and are declared per manifest. Cryptography in PCA is unaudited.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE
