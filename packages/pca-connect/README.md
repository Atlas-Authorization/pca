# @atlasauth/pca-connect

An outbound connection and token vault for Proof-Carrying Authority (PCA) agents. It holds an agent's third-party OAuth tokens (Google, Slack, and others) and refreshes them, and releases an access token only when a verified PCActn proves the agent has authority over the requested provider and scopes. Every outbound token presented by a tool call is then tied to a capability chain.

For each request the vault:

1. looks up the stored connection, which carries its own trust anchor (the principal the capability chain must be rooted at);
2. verifies the PCActn with the PCA core verifier against that anchor;
3. checks that the action is a token-use action for that provider (verb `use_connection`, resource `oauth:<provider>` by default);
4. checks least privilege: the requested scopes must be a subset of the scopes granted by the chain's `oauth_scope` caveats;
5. refreshes a stale token when a refresh token and provider config are present, otherwise releases the stored one.

Failures throw typed errors: `NotAuthorizedError`, `ScopeExceededError`, `ExpiredNoRefreshError`, `RefreshFailedError`, `UnknownConnectionError` (all extend `VaultError`, each with a `code`).

## Install

```sh
npm i @atlasauth/pca-connect @atlasauth/pca
```

## Usage

```ts
import { buildPCActn, encodeKey, generateKeyPair, mintRoot } from '@atlasauth/pca';
import { TokenVault, oauthScopeCaveat } from '@atlasauth/pca-connect';

const principalKeys = generateKeyPair();
const agentKeys = generateKeyPair();
const principal = encodeKey(principalKeys.publicKey);
const agentId = encodeKey(agentKeys.publicKey);

const vault = new TokenVault(); // in-memory store by default; pass { store, providers, fetch } for production

await vault.putConnection({
  agentId,
  provider: 'google',
  accessToken: 'ya29...',
  refreshToken: '1//...',
  expiresAt: Date.now() + 3_600_000,
  scopes: ['gmail.readonly', 'gmail.send'],
  authority: { principal, scopes: ['gmail.readonly'] }, // the chain must be rooted at `principal`
});

// The principal grants the agent read-only Gmail; the agent proves a token-use action.
const grant = mintRoot({
  principalSecret: principalKeys.secretKey,
  principalPublic: principal,
  holder: agentId,
  caveats: [oauthScopeCaveat('google', ['gmail.readonly'])],
});
const pcActn = buildPCActn({
  grant,
  chain: [grant],
  plan: [{ id: 'use', verb: 'use_connection', resource: 'oauth:google' }],
  nodeId: 'use',
  counter: 1,
  signerSecret: agentKeys.secretKey,
  aud: 'rs',
});

const token = await vault.getConnectionToken(pcActn, { provider: 'google', scopes: ['gmail.readonly'] });
// { provider, connectionId, accessToken, scopes, expiresAt, refreshed }

// Asking for more than the capability grants throws ScopeExceededError:
// await vault.getConnectionToken(pcActn, { provider: 'google', scopes: ['gmail.send'] });
```

To refresh expired tokens, pass `providers: { google: { tokenEndpoint, clientId, clientSecret? } }` and an injectable `fetch` to the `TokenVault` constructor.

## API

- `TokenVault`: `putConnection`, `getConnectionToken`, `deleteConnection`
- `ConnectionStore` interface and `InMemoryConnectionStore`; bring your own store for persistence
- `oauthScopeCaveat`, `isOAuthScopeCaveat`, `grantedOAuthScopes`, `OAUTH_SCOPE_CAVEAT`
- Error classes listed above; types `ProviderConfig`, `VaultFetch`, `ConnectionToken`

## Status

The returned token carries the scopes it was stored or refreshed with. The least-privilege check is made against the requested scopes, but narrowing the minted token itself only happens on refresh, and only when the provider is configured with `supportsScopeNarrowing`. The default store is in-memory and does not encrypt tokens at rest; supply an encrypting `ConnectionStore` for production. Cryptography in PCA is unaudited.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE
