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
 *  - `store_error`        the connection store (or its encryption) failed; the vault refuses rather than guess.
 *  - `unknown_action`     (K7) the PCActn's verb resolves to no pinned action definition: nothing derives its scopes, so nothing is released.
 *  - `unconfirmed_action` (K7) the action definition has no valid signed confirmation (unconfirmed means maximally dangerous): release refused.
 *  - `request_mismatch`   (K7) the outbound request the agent asked the vault to make does not re-derive the params digest the PCActn signed.
 *  - `bearer_release_disabled` (K7) a bare bearer token was asked for and the vault was not constructed with the explicit insecure opt-in.
 *  - `proxy_failed`       (K7) the outbound call itself failed (transport error or an oversized response); the action is spent.
 */
export type VaultErrorCode =
  | 'not_authorized'
  | 'scope_exceeded'
  | 'expired_no_refresh'
  | 'refresh_failed'
  | 'unknown_connection'
  | 'store_error'
  | 'unknown_action'
  | 'unconfirmed_action'
  | 'request_mismatch'
  | 'bearer_release_disabled'
  | 'proxy_failed';

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

/** The connection store or its encryption failed. The message never carries the underlying error text. */
export class StoreError extends VaultError {
  constructor(message = 'the connection store failed') {
    super('store_error', message);
    this.name = 'StoreError';
  }
}

/** The action definition for the PCActn's verb is unknown, so no scope can be derived (K7). */
export class UnknownActionError extends VaultError {
  constructor(verb: string) {
    super('unknown_action', `no pinned action definition for verb '${verb}': refusing to release a credential`);
    this.name = 'UnknownActionError';
  }
}

/** The action definition is not confirmed by a valid signed review (K7): unconfirmed means maximally dangerous. */
export class UnconfirmedActionError extends VaultError {
  constructor(verb: string) {
    super('unconfirmed_action', `the definition of '${verb}' has no valid signed confirmation: refusing to release a credential`);
    this.name = 'UnconfirmedActionError';
  }
}

/** The outbound request does not re-derive the signed params digest (K7). */
export class RequestMismatchError extends VaultError {
  constructor(message: string) {
    super('request_mismatch', message);
    this.name = 'RequestMismatchError';
  }
}

/** A bare bearer token was requested without the explicit, documented insecure opt-in (K7). */
export class BearerReleaseDisabledError extends VaultError {
  constructor() {
    super('bearer_release_disabled', 'this vault does not release bearer tokens to callers; use proxyCall(), or construct it with insecureBearerRelease: true (insecure: the caller can use the token for anything inside its scopes until it expires)');
    this.name = 'BearerReleaseDisabledError';
  }
}

/** The proxied call failed after the action was spent (K7). */
export class ProxyFailedError extends VaultError {
  constructor(message: string) {
    super('proxy_failed', message);
    this.name = 'ProxyFailedError';
  }
}
