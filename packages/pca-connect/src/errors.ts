import type { CheckStatus } from '@atlasauth/pca';

/**
 * Stable refusal codes for the outbound token vault. These strings are part of the public contract —
 * callers branch on `err.code`, so they never change meaning.
 *
 *  - `not_authorized`     the PCActn did not verify, is not rooted at the connection's bound principal,
 *                         is not an action for this connection, or the capability grants nothing for the provider.
 *  - `scope_exceeded`     the capability DOES cover the provider, but the requested scopes are not a subset
 *                         of what the (attenuated) capability chain grants (least-privilege violation).
 *  - `expired_no_refresh` the stored access token is expired/near-expiry and there is no refresh token to mint a new one.
 *  - `refresh_failed`     a refresh was attempted but the provider token endpoint call failed (no config, network, non-2xx, or unparseable body).
 *  - `unknown_connection` no stored connection exists for this agent + provider + connectionId.
 */
export type VaultErrorCode =
  | 'not_authorized'
  | 'scope_exceeded'
  | 'expired_no_refresh'
  | 'refresh_failed'
  | 'unknown_connection';

/** Base class for every typed refusal the vault raises. Branch on {@link VaultError.code}. */
export class VaultError extends Error {
  readonly code: VaultErrorCode;
  constructor(code: VaultErrorCode, message: string) {
    super(message);
    this.name = 'VaultError';
    this.code = code;
  }
}

/** The PCActn is not a valid, provider-bound authorization for this connection. */
export class NotAuthorizedError extends VaultError {
  /** The verifier's per-check verdict map, when the refusal came from PCActn verification. */
  readonly checks?: Readonly<Record<string, CheckStatus>>;
  constructor(message: string, checks?: Readonly<Record<string, CheckStatus>>) {
    super('not_authorized', message);
    this.name = 'NotAuthorizedError';
    if (checks !== undefined) this.checks = checks;
  }
}

/** The requested scopes are not a subset of what the capability chain grants (least-privilege violation). */
export class ScopeExceededError extends VaultError {
  readonly provider: string;
  readonly requested: readonly string[];
  readonly granted: readonly string[];
  readonly missing: readonly string[];
  constructor(provider: string, requested: readonly string[], granted: readonly string[], missing: readonly string[]) {
    super(
      'scope_exceeded',
      `requested scopes exceed the capability's grant for '${provider}': not granted [${missing.join(', ')}]`,
    );
    this.name = 'ScopeExceededError';
    this.provider = provider;
    this.requested = requested;
    this.granted = granted;
    this.missing = missing;
  }
}

/** The access token is stale and there is no refresh token to mint a fresh one. */
export class ExpiredNoRefreshError extends VaultError {
  readonly provider: string;
  readonly connectionId: string;
  constructor(provider: string, connectionId: string) {
    super('expired_no_refresh', `connection '${provider}/${connectionId}' token is expired and has no refresh token`);
    this.name = 'ExpiredNoRefreshError';
    this.provider = provider;
    this.connectionId = connectionId;
  }
}

/** A refresh was attempted but the provider token endpoint call did not yield a usable token. */
export class RefreshFailedError extends VaultError {
  readonly provider: string;
  /** HTTP status, when the failure was a non-2xx response. */
  readonly status?: number;
  constructor(provider: string, detail: string, status?: number) {
    super('refresh_failed', `refresh for '${provider}' failed: ${detail}`);
    this.name = 'RefreshFailedError';
    this.provider = provider;
    if (status !== undefined) this.status = status;
  }
}

/** No stored connection for this agent + provider + connectionId. */
export class UnknownConnectionError extends VaultError {
  readonly agentId: string;
  readonly provider: string;
  readonly connectionId: string;
  constructor(agentId: string, provider: string, connectionId: string) {
    super('unknown_connection', `no connection for agent '${agentId}' provider '${provider}' id '${connectionId}'`);
    this.name = 'UnknownConnectionError';
    this.agentId = agentId;
    this.provider = provider;
    this.connectionId = connectionId;
  }
}
