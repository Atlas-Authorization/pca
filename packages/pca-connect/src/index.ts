/**
 * `@atlasauth/pca-connect` — an OUTBOUND connection/token vault for PCA agents.
 *
 * It holds an agent's third-party OAuth tokens (Google, Slack, …) and refreshes them, releasing a FRESH,
 * least-privilege access token only when a verified Proof-Carrying Action ({@link PCActn}) proves authority
 * over the requested provider + scopes. This is the "token vault / outbound apps" surface, brought under
 * proof-carrying authority: every outbound token presented by a tool call is provably authorized.
 */

export {
  OAUTH_SCOPE_CAVEAT,
  type OAuthScopeCaveat,
  oauthScopeCaveat,
  isOAuthScopeCaveat,
  grantedOAuthScopes,
} from './authority';

export {
  type VaultErrorCode,
  VaultError,
  NotAuthorizedError,
  ScopeExceededError,
  ExpiredNoRefreshError,
  RefreshFailedError,
  UnknownConnectionError,
} from './errors';

export {
  type ProviderConfig,
  type VaultFetch,
  type VaultHttpRequest,
  type VaultHttpResponse,
} from './refresh';

export {
  type ConnectionAuthority,
  type ConnectionKey,
  type ConnectionStore,
  type StoredConnection,
  InMemoryConnectionStore,
  cloneConnection,
} from './store';

export {
  type ConnectionToken,
  type GetConnectionTokenArgs,
  type PutConnectionArgs,
  type TokenVaultOptions,
  TokenVault,
} from './vault';
