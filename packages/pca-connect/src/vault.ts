import { type Capability, type CapabilityChain, type PCActn, verifyPCActnCore } from '@atlasauth/pca';
import { type ReplayStore, guardPCActnReplay } from '@atlasauth/pca';
import { grantedOAuthScopes } from './authority';
import {
  ExpiredNoRefreshError,
  NotAuthorizedError,
  ScopeExceededError,
  StoreError,
  UnknownConnectionError,
  VaultError,
} from './errors';
import { type ProviderConfig, type VaultFetch, refreshConnection } from './refresh';
import {
  type ConnectionAuthority,
  type ConnectionStore,
  type StoredConnection,
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
  /**
   * Verifier-side `issuer -> pq_pk` pins (b64u). The chain root is taken from the presented PCActn, so a non-ed25519
   * (PQ / hybrid) root verifies ONLY under a pin for its issuer; without one it is refused (R4-01).
   */
  pqPins?: Readonly<Record<string, string>>;
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
  /**
   * One-time-use store for presented actions. When set, a PCActn that already released a token is refused
   * the second time (a captured action cannot be replayed to the vault). Use a durable, shared store.
   */
  replay?: ReplayStore;
  /** Revocation source. Return true to refuse the action. A throw or rejection refuses it too (fail closed). */
  isRevoked?: (pcActn: PCActn) => boolean | Promise<boolean>;
  /**
   * Production profile, ON unless set to `false`. The constructor throws unless the store encrypts at rest
   * (`EncryptedConnectionStore`), `replay` and `isRevoked` are set and `audience` is a string. `strict: false`
   * is for tests and local development and still requires an explicit `store` (the plaintext in-memory store
   * lives in `@atlasauth/pca-connect/testing`).
   */
  strict?: boolean;
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
  private readonly pqPins: Readonly<Record<string, string>> | undefined;
  private readonly defaultConnectionId: string;
  private readonly requireActionBinding: boolean;
  private readonly resourceFor: (provider: string, connectionId: string) => string;
  private readonly useVerb: string | null;
  private readonly defaultTokenLifetimeMs: number;
  private readonly replay: ReplayStore | undefined;
  private readonly isRevoked: ((pcActn: PCActn) => boolean | Promise<boolean>) | undefined;
  /** In-flight refreshes by connection, so two callers never spend one single-use refresh token twice. */
  private readonly inflight = new Map<string, Promise<Awaited<ReturnType<typeof refreshConnection>>>>();

  constructor(options: TokenVaultOptions = {}) {
    if (options.strict !== false) {
      const missing: string[] = [];
      if ((options.store as { encrypted?: unknown } | undefined)?.encrypted !== true) missing.push('an encrypting store');
      if (options.replay === undefined) missing.push('replay');
      if (options.isRevoked === undefined) missing.push('isRevoked');
      if (typeof options.audience !== 'string' || options.audience.length === 0) missing.push('audience');
      if (missing.length > 0) throw new Error(`TokenVault strict mode requires ${missing.join(', ')}`);
    } else if (options.store === undefined) {
      throw new Error('TokenVault requires a store');
    }
    this.replay = options.replay;
    this.isRevoked = options.isRevoked;
    this.store = options.store as ConnectionStore;
    this.providers = options.providers ?? {};
    this.fetchImpl = options.fetch;
    this.now = options.now ?? (() => Date.now());
    this.audience = options.audience ?? DEFAULTS.audience;
    this.pqPins = options.pqPins;
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
    for (const [k, val] of [['agentId', args.agentId], ['provider', args.provider], ['connectionId', connectionId], ['accessToken', args.accessToken], ['principal', args.authority?.principal]] as const) {
      if (typeof val !== 'string' || val.length === 0) throw new TypeError(`putConnection: ${k} must be a non-empty string`);
    }
    if (typeof args.expiresAt !== 'number' || !Number.isFinite(args.expiresAt)) throw new TypeError('putConnection: expiresAt must be a finite number');
    if (args.refreshToken !== undefined && (typeof args.refreshToken !== 'string' || args.refreshToken.length === 0)) {
      throw new TypeError('putConnection: refreshToken must be a non-empty string when given');
    }
    if (!Array.isArray(args.scopes) || args.scopes.some((s) => typeof s !== 'string')) throw new TypeError('putConnection: scopes must be a list of strings');
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
    await this.storeSet(connection);
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
    const connection = await this.storeGet({ agentId, provider, connectionId });
    if (connection === undefined) throw new UnknownConnectionError(agentId, provider, connectionId);

    // 2. Anchor + verify. The chain must be rooted at the connection's bound principal, else a self-minted
    //    chain would verify against itself.
    if (root.issuer !== connection.authority.principal) {
      throw new NotAuthorizedError('capability chain is not rooted at the connection\'s bound principal');
    }
    const now = this.now();
    const audience = connection.authority.audience ?? this.audience;
    const result = await verifyPCActnCore(pcActn, { grant: root, grantFromArtifact: true, ...(this.pqPins ? { pqPins: this.pqPins } : {}), audience, nowEpoch: now });
    if (!result.allow) {
      throw new NotAuthorizedError(`PCActn verification failed: ${result.reason ?? 'rejected'}`, result.checks);
    }

    // 2b. Revocation. No source configured means no check (opt in; `strict` makes it mandatory).
    if (this.isRevoked !== undefined) {
      let revoked: boolean;
      try {
        revoked = (await this.isRevoked(pcActn)) !== false;
      } catch {
        throw new NotAuthorizedError('revocation source unavailable');
      }
      if (revoked) throw new NotAuthorizedError('the capability chain is revoked');
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

    // 5b. One-time use, last of the authorization checks so a refused request does not burn the action.
    if (this.replay !== undefined) {
      const verdict = await guardPCActnReplay(this.replay, pcActn, { aud: pcActn.aud, now });
      if (!verdict.ok) throw new NotAuthorizedError(`replay guard refused the action: ${verdict.reason}`);
    }

    // 6. Freshness: refresh a stale token, else release it as-is. A token whose expiry or clock is not a
    //    finite number can never be shown to be fresh, so it counts as stale.
    let token = connection;
    let refreshed = false;
    if (!Number.isFinite(connection.expiresAt) || !Number.isFinite(now) || connection.expiresAt - now <= this.expiryLeewayMs) {
      if (connection.refreshToken === undefined) throw new ExpiredNoRefreshError(provider, connectionId);
      const refreshToken = connection.refreshToken;
      const flightKey = `${agentId}\u0000${provider}\u0000${connectionId}`;
      let flight = this.inflight.get(flightKey);
      if (flight === undefined) {
        flight = refreshConnection({
          connection,
          config: this.providers[provider],
          refreshToken,
          requested,
          fetch: this.fetchImpl,
          now,
          defaultTokenLifetimeMs: this.defaultTokenLifetimeMs,
        }).finally(() => this.inflight.delete(flightKey));
        this.inflight.set(flightKey, flight);
      }
      const updated = await flight;
      token = { ...connection, ...updated };
      refreshed = true;
    }

    // 7. Record usage and persist.
    token = { ...token, lastUsedAt: now, useCount: token.useCount + 1 };
    await this.storeSet(token);

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
    try {
      await this.store.delete({ agentId, provider, connectionId: connectionId ?? this.defaultConnectionId });
    } catch (e) {
      throw e instanceof VaultError ? e : new StoreError();
    }
  }

  // The store's own error text is never passed on: it can quote a connection string or a record.
  private async storeGet(key: Parameters<ConnectionStore['get']>[0]): Promise<StoredConnection | undefined> {
    try {
      return await this.store.get(key);
    } catch (e) {
      throw e instanceof VaultError ? e : new StoreError();
    }
  }

  private async storeSet(c: StoredConnection): Promise<void> {
    try {
      await this.store.set(c);
    } catch (e) {
      throw e instanceof VaultError ? e : new StoreError();
    }
  }
}
