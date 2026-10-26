# @atlasauth/pca-connect

> Maturity: **experimental**. Its API may change or be removed in any release, and it is outside the stable and production tiers. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

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
import { InMemoryConnectionStore } from '@atlasauth/pca-connect/testing';

const principalKeys = generateKeyPair();
const agentKeys = generateKeyPair();
const principal = encodeKey(principalKeys.publicKey);
const agentId = encodeKey(agentKeys.publicKey);

// 0.5: strict by default. Production: an encrypting store, a replay store, a revocation source and a pinned audience.
const vault = new TokenVault({
  strict: false, // tests and local development only; omit it in production
  store: new InMemoryConnectionStore(), // from '@atlasauth/pca-connect/testing'; plaintext, in memory
});

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
- `ConnectionStore` interface; bring your own store for persistence. The plaintext in-memory store is `InMemoryConnectionStore` in `@atlasauth/pca-connect/testing`
- `oauthScopeCaveat`, `isOAuthScopeCaveat`, `grantedOAuthScopes`, `OAUTH_SCOPE_CAVEAT`
- `EncryptedConnectionStore`, `KeyWrapper`, `LocalKeyWrapper`: envelope encryption of the access and refresh tokens in any `ConnectionStore`. Each secret has its own data key, wrapped by your KMS (implement `KeyWrapper`) or by a local key ring that supports rotation (`addKey`, `setActive`, `reencrypt`, `removeKey`). The wrapped key is bound to the connection and field, so a copied ciphertext does not open. A plaintext record, a tampered record or an unknown key makes `get` throw `StoreError`.
- `TokenVault` options `replay` (a one-time-use store: a captured action releases a token once), `isRevoked` (a revocation source; a throw refuses), and `strict` (default true: the constructor throws unless the store encrypts, `replay`, `isRevoked` and `audience` are set; `strict: false` is for tests and needs an explicit `store`).
- Error classes listed above, plus `StoreError` (code `store_error`); types `ProviderConfig`, `VaultFetch`, `ConnectionToken`

## Status

The returned token carries the scopes it was stored or refreshed with. The least-privilege check is made against the requested scopes, but narrowing the minted token itself only happens on refresh, and only when the provider is configured with `supportsScopeNarrowing`. There is no default store. For production wrap a durable store in `EncryptedConnectionStore` and keep the default `strict` profile. Concurrent refreshes of one connection share a single request, so a rotating refresh token is spent once. Error messages never contain a token or client secret (a provider error body that echoes one is redacted), and a store failure surfaces as `StoreError` without the store's own text. JavaScript strings cannot be wiped, so a decrypted token lives until it is garbage collected; the data keys and the local key ring are overwritten. Cryptography in PCA is unaudited.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE
