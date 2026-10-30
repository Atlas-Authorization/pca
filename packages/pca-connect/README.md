# @atlasauth/pca-connect

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

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

## Fail-closed behaviour

| Missing or invalid | Result |
|---|---|
| Default (strict) options without an encrypting store, `replay`, `isRevoked` or `audience` | The constructor throws, listing everything missing |
| `strict: false` without a store | The constructor throws |
| PCActn with no or a malformed capability chain | `NotAuthorizedError` |
| No stored connection for the agent, provider and connection id | `UnknownConnectionError` |
| Chain not rooted at the connection's bound principal | `NotAuthorizedError` |
| PCActn fails core verification (forged signature, wrong audience, expired, unpinned post-quantum root) | `NotAuthorizedError` with the verifier's reason |
| Revocation source says revoked, returns anything but `false`, throws or rejects | `NotAuthorizedError` |
| Action resource or verb is not the connection-use action | `NotAuthorizedError` |
| Chain grants no `oauth_scope` for the provider | `NotAuthorizedError` |
| Requested scopes not within the granted scopes | `ScopeExceededError`; the token is not released |
| Replay store says the action was already used, the action has no nonce, or the store throws | `NotAuthorizedError`; a refused request does not burn the action |
| Token stale (or expiry or clock not finite) and no refresh token | `ExpiredNoRefreshError` |
| Refresh with no provider config or no fetch, a transport error, a non-success status, an unparseable body, or no `access_token` | `RefreshFailedError`; the stored token is unchanged |
| The store throws on read, write or delete | `StoreError` without the store's own text |
| Encrypted record that is plaintext, tampered, truncated, moved to another connection or field, or sealed under an unknown key | `StoreError` on read |
| Key wrapper fails when storing | `StoreError`; nothing is stored |
| `putConnection` with an empty id or token, non-finite expiry, empty refresh token or non-string scopes | `TypeError` |

## Limits

- It guards release of a token. After release the provider's own rules apply, and the vault cannot stop the caller misusing a token it holds.
- The returned token carries the scopes it was stored or refreshed with. Least privilege is checked on the request; the token is narrowed only on refresh and only when the provider is configured for it.
- There is no default durable store. Encryption at rest is only as strong as the key wrapper or KMS you supply.
- Decrypted tokens live in memory until garbage collected; JavaScript strings cannot be wiped.
- Revocation and one-time use are the callbacks and stores you pass; the vault does not provide a shared one.

## Status

The returned token carries the scopes it was stored or refreshed with. The least-privilege check is made against the requested scopes, but narrowing the minted token itself only happens on refresh, and only when the provider is configured with `supportsScopeNarrowing`. There is no default store. For production wrap a durable store in `EncryptedConnectionStore` and keep the default `strict` profile. Concurrent refreshes of one connection share a single request, so a rotating refresh token is spent once. Error messages never contain a token or client secret (a provider error body that echoes one is redacted), and a store failure surfaces as `StoreError` without the store's own text. JavaScript strings cannot be wiped, so a decrypted token lives until it is garbage collected; the data keys and the local key ring are overwritten.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE
