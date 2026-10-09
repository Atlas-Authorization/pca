import { type Capability, type CapabilityChain, type PCActn, verifyPCActnCore } from '@atlasauth/pca';
import { grantedOAuthScopes } from './authority';
import {
  ExpiredNoRefreshError,
  NotAuthorizedError,
  ScopeExceededError,
  UnknownConnectionError,
} from './errors';
import { type ProviderConfig, type VaultFetch, refreshConnection } from './refresh';
import {
  type ConnectionAuthority,
  type ConnectionStore,
  type StoredConnection,
  InMemoryConnectionStore,
} from './store';

/** What a successful {@link TokenVault.getConnectionToken} hands back: a fresh, provably-authorized token. */
export interface ConnectionToken {
  provider: string;
  connectionId: string;
  accessToken: string;
  /** The scopes the returned token carries. */
  scopes: string[];
  /** Access-token expiry, epoch milliseconds. */
  expiresAt: number;
  /** True when the token was just refreshed at the provider; false when the stored token was still fresh. */
  refreshed: boolean;
}

/** Arguments identifying which connection/token a verified PCActn is asking to use. */
export interface GetConnectionTokenArgs {
  provider: string;
  /** Defaults to the vault's `defaultConnectionId`. */
  connectionId?: string;
  /** Least-privilege request: the scopes the tool call needs. Defaults to the connection's bound authority scopes. */
  scopes?: string[];
}

export interface PutConnectionArgs {
  agentId: string;
  provider: string;
  connectionId?: string;
  accessToken: string;
  refreshToken?: string;
  expiresAt: number;
  scopes: string[];
  authority: {
    /** b64u public key the capability chain must be rooted at (the PCActn's `cap_chain[0].issuer`). */
    principal: string;
    /** Scopes the capability must cover for this connection. Defaults to `scopes`. */
    scopes?: string[];
    /** When set, the PCActn's signed `aud` must equal this resource-server id. */
    audience?: string;
  };
}

export interface TokenVaultOptions {
  store?: ConnectionStore;
  /** Per-provider token-endpoint config, used only when a refresh is required. */
  providers?: Record<string, ProviderConfig>;
  /** Injectable HTTP transport for refreshes. Required to refresh; omit if tokens are always fresh. */
  fetch?: VaultFetch;
  /** Clock, epoch ms. Defaults to `Date.now`. */
  now?: () => number;
  /**
   * This vault's resource-server id, compared to each PCActn's signed `aud`. `null` (the default) opts
   * out ("accept any audience"); a string pins it. A connection's own `authority.audience` overrides this.
   */
  audience?: string | null;
  /** A token within this many ms of expiry is treated as stale and refreshed. Default 30_000. */
  expiryLeewayMs?: number;
  /** connectionId used when a caller omits one. Default `'default'`. */
  defaultConnectionId?: string;
  /** When true (default), the PCActn's action must be a token-use action for the requested provider. */
  requireActionBinding?: boolean;
  /** Maps provider+connectionId to the `action.resource` a PCActn must carry. Default `oauth:${provider}`. */
  resourceFor?: (provider: string, connectionId: string) => string;
  /** The `action.verb` a PCActn must carry. Default `'use_connection'`; `null` skips the verb check. */
  useVerb?: string | null;
  /** Expiry assumed when a refreshed token exposes neither `expires_in` nor a JWT `exp`. Default 300_000. */
  defaultTokenLifetimeMs?: number;
}

const DEFAULTS: {
  audience: string | null;
  expiryLeewayMs: number;
  defaultConnectionId: string;
  requireActionBinding: boolean;
  useVerb: string | null;
  defaultTokenLifetimeMs: number;
} = {
  audience: null,
  expiryLeewayMs: 30_000,
  defaultConnectionId: 'default',
  requireActionBinding: true,
  useVerb: 'use_connection',
  defaultTokenLifetimeMs: 300_000,
};

/**
 * An outbound connection/token vault for PCA agents. It holds an agent's third-party OAuth tokens and
 * releases a FRESH access token only when a verified Proof-Carrying Action proves least-privilege authority
 * over the requested provider + scopes. This brings "token vault / outbound apps" under proof-carrying authority.
 */
export class TokenVault {
  private readonly store: ConnectionStore;
  private readonly providers: Record<string, ProviderConfig>;
  private readonly fetchImpl: VaultFetch | undefined;
  private readonly now: () => number;
  private readonly audience: string | null;
  private readonly expiryLeewayMs: number;
  private readonly defaultConnectionId: string;
  private readonly requireActionBinding: boolean;
  private readonly resourceFor: (provider: string, connectionId: string) => string;
  private readonly useVerb: string | null;
  private readonly defaultTokenLifetimeMs: number;

  constructor(options: TokenVaultOptions = {}) {
    this.store = options.store ?? new InMemoryConnectionStore();
    this.providers = options.providers ?? {};
    this.fetchImpl = options.fetch;
    this.now = options.now ?? (() => Date.now());
    this.audience = options.audience ?? DEFAULTS.audience;
    this.expiryLeewayMs = options.expiryLeewayMs ?? DEFAULTS.expiryLeewayMs;
    this.defaultConnectionId = options.defaultConnectionId ?? DEFAULTS.defaultConnectionId;
    this.requireActionBinding = options.requireActionBinding ?? DEFAULTS.requireActionBinding;
    this.resourceFor = options.resourceFor ?? ((provider) => `oauth:${provider}`);
    this.useVerb = options.useVerb === undefined ? DEFAULTS.useVerb : options.useVerb;
    this.defaultTokenLifetimeMs = options.defaultTokenLifetimeMs ?? DEFAULTS.defaultTokenLifetimeMs;
  }

  /** Store (or replace) an agent's connection. The authority descriptor binds which capability may use it. */
  async putConnection(args: PutConnectionArgs): Promise<StoredConnection> {
    const connectionId = args.connectionId ?? this.defaultConnectionId;
    const authority: ConnectionAuthority = {
      provider: args.provider,
      principal: args.authority.principal,
      scopes: [...(args.authority.scopes ?? args.scopes)],
      ...(args.authority.audience !== undefined ? { audience: args.authority.audience } : {}),
    };
    const connection: StoredConnection = {
      agentId: args.agentId,
      provider: args.provider,
      connectionId,
      accessToken: args.accessToken,
      expiresAt: args.expiresAt,
      scopes: [...args.scopes],
      authority,
      createdAt: this.now(),
      useCount: 0,
      ...(args.refreshToken !== undefined ? { refreshToken: args.refreshToken } : {}),
    };
    await this.store.set(connection);
    return connection;
  }

  /**
   * Resolve a FRESH access token for `args` iff (a) `pcActn` verifies against the connection's bound
   * principal and (b) the capability chain's grant covers the requested provider + scopes
   * (least-privilege: requested ⊆ granted). Refreshes a stale token when a refresh token is present.
   * Throws a typed {@link VaultError} otherwise.
   */
  async getConnectionToken(pcActn: PCActn, args: GetConnectionTokenArgs): Promise<ConnectionToken> {
    const connectionId = args.connectionId ?? this.defaultConnectionId;
    const provider = args.provider;

    const chain: CapabilityChain = pcActn.cap_chain;
    if (!Array.isArray(chain) || chain.length === 0) {
      throw new NotAuthorizedError('PCActn has no capability chain');
    }
    const leaf: Capability | undefined = chain[chain.length - 1];
    const root: Capability | undefined = chain[0];
    if (leaf === undefined || root === undefined) throw new NotAuthorizedError('PCActn capability chain is malformed');
    const agentId = leaf.holder;

    // 1. Resolve the connection. The connection carries the trust anchor (bound principal), so it must be
    //    looked up before verification can be anchored.
    const connection = await this.store.get({ agentId, provider, connectionId });
    if (connection === undefined) throw new UnknownConnectionError(agentId, provider, connectionId);

    // 2. Anchor + verify. The chain must be rooted at the connection's bound principal, else a self-minted
    //    chain would verify against itself.
    if (root.issuer !== connection.authority.principal) {
      throw new NotAuthorizedError('capability chain is not rooted at the connection\'s bound principal');
    }
    const now = this.now();
    const audience = connection.authority.audience ?? this.audience;
    const result = await verifyPCActnCore(pcActn, { grant: root, audience, nowEpoch: now });
    if (!result.allow) {
      throw new NotAuthorizedError(`PCActn verification failed: ${result.reason ?? 'rejected'}`, result.checks);
    }

    // 3. Bind the action to this provider/connection (so an unrelated authorized action cannot unlock the token).
    if (this.requireActionBinding) {
      const expectedResource = this.resourceFor(provider, connectionId);
      if (pcActn.action.resource !== expectedResource) {
        throw new NotAuthorizedError(
          `PCActn action resource '${pcActn.action.resource}' is not for this connection (expected '${expectedResource}')`,
        );
      }
      if (this.useVerb !== null && pcActn.action.verb !== this.useVerb) {
        throw new NotAuthorizedError(
          `PCActn action verb '${pcActn.action.verb}' is not a connection-use verb (expected '${this.useVerb}')`,
        );
      }
    }

    // 4. Authority coverage. `null` => the capability grants nothing for this provider.
    const granted = grantedOAuthScopes(chain, provider);
    if (granted === null) {
      throw new NotAuthorizedError(`capability grants no authority for provider '${provider}'`);
    }

    // 5. Least-privilege. Requested scopes default to the connection's bound authority scopes.
    const requested = args.scopes ?? connection.authority.scopes;
    const missing = requested.filter((s) => !granted.has(s));
    if (missing.length > 0) {
      throw new ScopeExceededError(provider, requested, [...granted], missing);
    }

    // 6. Freshness: refresh a stale token, else release it as-is.
    let token = connection;
    let refreshed = false;
    if (connection.expiresAt - now <= this.expiryLeewayMs) {
      if (connection.refreshToken === undefined) throw new ExpiredNoRefreshError(provider, connectionId);
      const updated = await refreshConnection({
        connection,
        config: this.providers[provider],
        refreshToken: connection.refreshToken,
        requested,
        fetch: this.fetchImpl,
        now,
        defaultTokenLifetimeMs: this.defaultTokenLifetimeMs,
      });
      token = { ...connection, ...updated };
      refreshed = true;
    }

    // 7. Record usage and persist.
    token = { ...token, lastUsedAt: now, useCount: token.useCount + 1 };
    await this.store.set(token);

    return {
      provider,
      connectionId,
      accessToken: token.accessToken,
      scopes: [...token.scopes],
      expiresAt: token.expiresAt,
      refreshed,
    };
  }

  /** Remove a stored connection. */
  async deleteConnection(agentId: string, provider: string, connectionId?: string): Promise<void> {
    await this.store.delete({ agentId, provider, connectionId: connectionId ?? this.defaultConnectionId });
  }
}
