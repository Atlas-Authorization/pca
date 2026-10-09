/**
 * `@atlasauth/pca-connectors` — the connector catalog for Proof-Carrying Authority.
 *
 * A declarative registry of outbound SaaS providers (Google, GitHub, Slack, …) as data manifests, plus the
 * authorize-URL / code-exchange / refresh helpers that feed the `@atlasauth/pca-connect` token vault. Wiring
 * a new outbound tool is a manifest edit, and EVERY connection minted here is bound to a PCA capability —
 * so every outbound token a tool call presents is a proof-carrying, least-privilege capability, not an
 * ambient secret. That capability binding is the property Composio / Descope / Auth0 Token Vault lack.
 *
 * This is the CODE layer; a hosted consent UI is a separate product piece built on top of it.
 */

export {
  type TokenPlacement,
  type RefreshMode,
  type ClientAuthMethod,
  type RefreshSpec,
  type ProviderManifest,
  type ManifestValidation,
  ConnectorError,
  ManifestValidationError,
  UnknownProviderError,
  validateManifest,
  assertManifest,
} from './manifest';

export {
  ProviderRegistry,
  createDefaultRegistry,
  defaultRegistry,
  registerProvider,
  getProvider,
  listProviders,
} from './registry';

export {
  type PkceParams,
  type PkceResult,
  type BuildAuthorizeUrlOptions,
  type AuthorizeUrl,
  type AppliedToken,
  buildAuthorizeUrl,
  pkceChallenge,
  substituteVars,
  applyAccessToken,
} from './authorize';

export {
  type ConnectionBinding,
  type ExchangeCodeArgs,
  type RefreshArgs,
  type ProviderCredentials,
  exchangeCode,
  refresh,
  manifestToProviderConfig,
  buildVaultProviders,
} from './exchange';

export * as providers from './providers';

// Re-export the vault primitives this catalog is built on, so a consumer can assemble the whole outbound
// surface — manifests + vault + capability binding — from one import.
export {
  type ConnectionToken,
  type StoredConnection,
  type ProviderConfig,
  type VaultFetch,
  type VaultHttpRequest,
  type VaultHttpResponse,
  TokenVault,
  InMemoryConnectionStore,
  oauthScopeCaveat,
  grantedOAuthScopes,
  NotAuthorizedError,
  ScopeExceededError,
  ExpiredNoRefreshError,
  RefreshFailedError,
  UnknownConnectionError,
  VaultError,
} from '@atlasauth/pca-connect';
