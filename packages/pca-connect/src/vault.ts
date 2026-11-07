import { type Capability, type CapabilityChain, type PCActn, paramsDigest, verifyPCActnCore } from '@atlasauth/pca';
import { type ReplayStore, guardPCActnReplay } from '@atlasauth/pca';
import { grantedOAuthScopes } from './authority';
import {
  BearerReleaseDisabledError,
  ExpiredNoRefreshError,
  NotAuthorizedError,
  ProxyFailedError,
  RequestMismatchError,
  ScopeExceededError,
  StoreError,
  UnconfirmedActionError,
  UnknownActionError,
  UnknownConnectionError,
  VaultError,
} from './errors';
import {
  DEFAULT_PROXY_HEADERS,
  checkProxyHeaders,
  outboundRequestDigest,
  receiptActionDigest,
  signReleaseReceipt,
  type ProxyFetch,
  type ProxyRequest,
  type ProxyResponse,
  type ReleaseReceipt,
} from './proxy';
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

/**
 * K7: what the vault knows about one action, pinned by its operator from a reviewed action pack. The scopes a credential may
 * carry come from HERE (the definition's `upstream` declaration), never from the caller and never from the grant alone.
 */
export interface VaultAction {
  /** The verb a PCActn must carry for this action (the ActionDef verb, not a generic `use_connection`). */
  verb: string;
  /** Digest of the definition this mapping was written for (`defDigest`). Informational pin: recorded in receipts' audit trail by the operator. */
  def_digest: string;
  /** True iff the definition carries a valid signed confirmation (`effective(def, registry, {attestationVerified}).confirmed`). Unconfirmed: nothing is released. */
  confirmed: boolean;
  upstream: {
    provider: string;
    /** The minimum scopes the action needs. Release is `scopes_min` (and it must also be inside the grant and the stored connection). */
    scopes_min: readonly string[];
  };
  /** Proxy mode: map the outbound request back to the action's parameters (`httpExtractor`). Its result must hash to the PCActn's `params_digest`. */
  extract?: (req: ProxyRequest) => Record<string, unknown>;
}

export interface ProxyCallArgs {
  provider: string;
  connectionId?: string;
}

export interface ProxyResult {
  response: ProxyResponse;
  /** Present when the vault was constructed with `receipts`. */
  receipt?: ReleaseReceipt;
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
  /** The Merkle plan roots the principal authorized (forwarded to `verifyPCActnCore`; `plan_root_authorized`). Required unless `insecureSkipPlanRootCheck` is set: a vault with neither refuses every release. */
  authorizedPlanRoots?: readonly string[];
  /** Explicit opt-out of `plan_root_authorized` (forwarded to `verifyPCActnCore`). */
  insecureSkipPlanRootCheck?: boolean;
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
  /**
   * K7: resolve the pinned action for a PCActn's verb. With it set, every release derives its scopes from the action
   * (`upstream.scopes_min`), refuses an unknown or unconfirmed action, and the generic `use_connection` verb binding is not used.
   * Required for {@link TokenVault.proxyCall}.
   */
  actions?: (verb: string) => VaultAction | undefined | Promise<VaultAction | undefined>;
  /**
   * K7: DOCUMENTED INSECURE opt-in. Without it {@link TokenVault.getConnectionToken} throws `bearer_release_disabled`: a bare bearer
   * token is good for anything inside its scopes until it expires, so the caller can use it on a call other than the one that
   * was authorized. Prefer {@link TokenVault.proxyCall}, where the caller never holds the credential.
   */
  insecureBearerRelease?: boolean;
  /** K7: the outbound transport for proxy mode (must not follow redirects). Required for `proxyCall`. */
  proxyFetch?: ProxyFetch;
  /** K7: request headers an agent may set in proxy mode (lower case). Default content-type, accept, idempotency-key. */
  proxyHeaders?: readonly string[];
  /** K7: a proxied response larger than this many bytes is not returned (the call was made). Default 4 MiB. */
  maxProxyResponseBytes?: number;
  /** K7: sign a release receipt for every release / proxied call with this vault key, and hand it to `sink`. */
  receipts?: { secretKey: Uint8Array; sink?: (r: ReleaseReceipt) => void | Promise<void> };
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
  private readonly authorizedPlanRoots: readonly string[] | undefined;
  private readonly insecureSkipPlanRootCheck: boolean;
  private readonly defaultConnectionId: string;
  private readonly requireActionBinding: boolean;
  private readonly resourceFor: (provider: string, connectionId: string) => string;
  private readonly useVerb: string | null;
  private readonly defaultTokenLifetimeMs: number;
  private readonly replay: ReplayStore | undefined;
  private readonly isRevoked: ((pcActn: PCActn) => boolean | Promise<boolean>) | undefined;
  private readonly actions: TokenVaultOptions['actions'];
  private readonly insecureBearerRelease: boolean;
  private readonly proxyFetch: ProxyFetch | undefined;
  private readonly proxyHeaders: readonly string[];
  private readonly maxProxyResponseBytes: number;
  private readonly receipts: TokenVaultOptions['receipts'];
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
    this.actions = options.actions;
    this.insecureBearerRelease = options.insecureBearerRelease === true;
    this.proxyFetch = options.proxyFetch;
    this.proxyHeaders = (options.proxyHeaders ?? DEFAULT_PROXY_HEADERS).map((h) => h.toLowerCase());
    this.maxProxyResponseBytes = options.maxProxyResponseBytes ?? 4 * 1024 * 1024;
    this.receipts = options.receipts;
    this.replay = options.replay;
    this.isRevoked = options.isRevoked;
    this.store = options.store as ConnectionStore;
    this.providers = options.providers ?? {};
    this.fetchImpl = options.fetch;
    this.now = options.now ?? (() => Date.now());
    this.audience = options.audience ?? DEFAULTS.audience;
    this.pqPins = options.pqPins;
    this.authorizedPlanRoots = options.authorizedPlanRoots;
    this.insecureSkipPlanRootCheck = options.insecureSkipPlanRootCheck === true;
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
   *
   * INSECURE BY NATURE (K7): the caller receives a bearer credential. Disabled unless the vault was built with
   * `insecureBearerRelease: true`; prefer {@link TokenVault.proxyCall}. With `actions` set the scopes come from the pinned action
   * (`scopes_min`), an unknown or unconfirmed action is refused, and the release lives no longer than the PCActn.
   */
  async getConnectionToken(pcActn: PCActn, args: GetConnectionTokenArgs): Promise<ConnectionToken> {
    if (!this.insecureBearerRelease) throw new BearerReleaseDisabledError();
    const a = await this.authorize(pcActn, args, false);
    const { token, refreshed } = await this.freshToken(a);
    const done = await this.recordUse(a, token);
    await this.issueReceipt(pcActn, a, { mode: 'bearer', requestDigest: null, httpStatus: null, outcome: 'released', scopes: done.scopes });
    return {
      provider: a.provider,
      connectionId: a.connectionId,
      accessToken: done.accessToken,
      scopes: [...done.scopes],
      // derived mode: the release never outlives the action that asked for it
      expiresAt: a.action !== undefined && Number.isFinite(pcActn.exp) ? Math.min(done.expiresAt, pcActn.exp) : done.expiresAt,
      refreshed,
    };
  }

  /**
   * K7 proxy mode. The vault makes the outbound call itself: the agent never holds the credential. Steps: verify the PCActn and
   * the pinned, CONFIRMED action; derive the scopes from the action; map `request` back to the action's parameters with the
   * action's extractor and require `paramsDigest(params)` to equal the PCActn's signed `params_digest`; spend the action (replay
   * guard); attach the token; make the call without following redirects; sign a receipt linking the release to the effect.
   * The credential can serve exactly the authorized request and nothing else.
   */
  async proxyCall(pcActn: PCActn, request: ProxyRequest, args: ProxyCallArgs): Promise<ProxyResult> {
    if (this.actions === undefined) throw new TypeError('proxyCall requires the vault to be constructed with `actions`');
    if (this.proxyFetch === undefined) throw new TypeError('proxyCall requires the vault to be constructed with `proxyFetch`');
    const sendHeaders = checkProxyHeaders(request.headers, this.proxyHeaders); // before anything is spent
    const a = await this.authorize(pcActn, args, true, request);
    const { token, refreshed: _refreshed } = await this.freshToken(a);
    const done = await this.recordUse(a, token);
    const headers = { ...sendHeaders, authorization: `Bearer ${done.accessToken}` };
    const reqDigest = outboundRequestDigest(request.method, request.url, sendHeaders, request.body);
    let response: ProxyResponse;
    try {
      response = await this.proxyFetch({ method: request.method, url: request.url, headers, ...(request.body !== undefined ? { body: request.body } : {}), redirect: 'manual' });
    } catch {
      await this.issueReceipt(pcActn, a, { mode: 'proxy', requestDigest: reqDigest, httpStatus: null, outcome: 'failed', scopes: done.scopes });
      throw new ProxyFailedError('the outbound call failed before a response');
    }
    const size = typeof response?.body === 'string' ? new TextEncoder().encode(response.body).length : Infinity;
    const receipt = await this.issueReceipt(pcActn, a, { mode: 'proxy', requestDigest: reqDigest, httpStatus: Number.isSafeInteger(response?.status) ? response.status : null, outcome: 'executed', scopes: done.scopes });
    if (size > this.maxProxyResponseBytes) throw new ProxyFailedError('the response is larger than maxProxyResponseBytes (the call was made and the action is spent)');
    // the credential must never travel back: a response header or body that echoes it is redacted
    const body = response.body.split(done.accessToken).join('[redacted]');
    const rh: Record<string, string> = {};
    for (const [k, v] of Object.entries(response.headers ?? {})) if (k.toLowerCase() !== 'set-cookie') rh[k] = String(v).split(done.accessToken).join('[redacted]');
    return { response: { status: response.status, headers: rh, body }, ...(receipt ? { receipt } : {}) };
  }

  /** Steps 1-5b of a release: resolve, anchor and verify, revoke, bind, derive scopes, least-privilege, spend. Shared by both release modes. */
  private async authorize(
    pcActn: PCActn,
    args: GetConnectionTokenArgs,
    needAction: boolean,
    request?: ProxyRequest,
  ): Promise<{ agentId: string; provider: string; connectionId: string; connection: StoredConnection; requested: string[]; now: number; action: VaultAction | undefined }> {
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
    const result = await verifyPCActnCore(pcActn, { grant: root, grantFromArtifact: true, ...(this.pqPins ? { pqPins: this.pqPins } : {}), ...(this.authorizedPlanRoots ? { authorizedPlanRoots: this.authorizedPlanRoots } : {}), ...(this.insecureSkipPlanRootCheck ? { insecureSkipPlanRootCheck: true } : {}), audience, nowEpoch: now });
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

    // 3. Bind the action. Derived mode (K7): the verb resolves to a pinned, CONFIRMED action for this provider, and the scopes
    //    come from that action. Legacy mode: the action is a generic token-use action for this provider.
    let action: VaultAction | undefined;
    if (this.actions !== undefined) {
      const verb = pcActn.action.verb;
      action = await this.actions(verb);
      if (action === undefined || action.verb !== verb) throw new UnknownActionError(String(verb));
      if (action.confirmed !== true) throw new UnconfirmedActionError(verb);
      if (action.upstream.provider !== provider) throw new NotAuthorizedError(`the action '${verb}' is not for provider '${provider}'`);
      if (!Array.isArray(action.upstream.scopes_min) || action.upstream.scopes_min.length === 0) throw new NotAuthorizedError(`the action '${verb}' declares no upstream scopes (nothing to release)`);
    } else if (needAction) {
      throw new UnknownActionError(String(pcActn.action.verb));
    } else if (this.requireActionBinding) {
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

    // 5. Least-privilege. Legacy: requested scopes default to the connection's bound authority scopes. Derived: they ARE the
    //    action's scopes_min (a caller may ask for fewer, never more), and the stored connection must hold them.
    let requested: string[];
    if (action !== undefined) {
      const min = [...action.upstream.scopes_min];
      requested = args.scopes ?? min;
      const beyond = requested.filter((s) => !min.includes(s));
      if (beyond.length > 0) throw new ScopeExceededError(provider, requested, min, beyond);
      const unheld = min.filter((s) => !connection.scopes.includes(s) || !connection.authority.scopes.includes(s));
      if (unheld.length > 0) throw new ScopeExceededError(provider, min, connection.scopes, unheld);
      // a bare bearer token cannot be narrowed after issue: it may carry nothing beyond the action's scopes (use a connection per action)
      if (!needAction) {
        const extra = connection.scopes.filter((s) => !min.includes(s));
        if (extra.length > 0) throw new ScopeExceededError(provider, min, connection.scopes, extra);
      }
      const ungranted = min.filter((s) => !granted.has(s));
      if (ungranted.length > 0) throw new ScopeExceededError(provider, min, [...granted], ungranted);
    } else {
      requested = args.scopes ?? connection.authority.scopes;
    }
    const missing = requested.filter((s) => !granted.has(s));
    if (missing.length > 0) {
      throw new ScopeExceededError(provider, requested, [...granted], missing);
    }

    // 5a. Proxy mode: the outbound request must re-derive EXACTLY the params the PCActn signed.
    if (needAction && action !== undefined) {
      if (request === undefined || action.extract === undefined) throw new RequestMismatchError('the action has no request extractor: proxy mode cannot bind the outbound request');
      let params: Record<string, unknown>;
      try {
        params = action.extract(request);
      } catch (e) {
        throw e instanceof RequestMismatchError ? e : new RequestMismatchError('the outbound request could not be mapped to the action parameters');
      }
      let d: string;
      try { d = paramsDigest(params); } catch { throw new RequestMismatchError('the outbound request parameters are not canonical'); }
      if (d !== pcActn.action.params_digest) throw new RequestMismatchError('the outbound request does not carry the parameters the PCActn signed');
    }

    // 5b. One-time use, last of the authorization checks so a refused request does not burn the action.
    if (this.replay !== undefined) {
      const verdict = await guardPCActnReplay(this.replay, pcActn, { aud: pcActn.aud, now });
      if (!verdict.ok) throw new NotAuthorizedError(`replay guard refused the action: ${verdict.reason}`);
    }
    return { agentId, provider, connectionId, connection, requested, now, action };
  }

  /** Step 6: refresh a stale token, else use it as is. A token whose expiry or clock is not a finite number can never be shown fresh. */
  private async freshToken(a: { agentId: string; provider: string; connectionId: string; connection: StoredConnection; requested: string[]; now: number }): Promise<{ token: StoredConnection; refreshed: boolean }> {
    const { connection, now, provider, connectionId, agentId, requested } = a;
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
    return { token, refreshed };
  }

  /** Step 7: record usage and persist. */
  private async recordUse(a: { now: number }, token: StoredConnection): Promise<StoredConnection> {
    const t = { ...token, lastUsedAt: a.now, useCount: token.useCount + 1 };
    await this.storeSet(t);
    return t;
  }

  private async issueReceipt(
    pcActn: PCActn,
    a: { provider: string; connectionId: string; now: number },
    r: { mode: 'proxy' | 'bearer'; requestDigest: string | null; httpStatus: number | null; outcome: 'released' | 'executed' | 'failed'; scopes: readonly string[] },
  ): Promise<ReleaseReceipt | undefined> {
    if (this.receipts === undefined) return undefined;
    const receipt = signReleaseReceipt(
      { v: 1, kind: 'pca-release-receipt', action_digest: receiptActionDigest(pcActn), provider: a.provider, connection_id: a.connectionId, mode: r.mode, scopes_released: [...r.scopes].sort(), request_digest: r.requestDigest, http_status: r.httpStatus, outcome: r.outcome, ts: a.now },
      this.receipts.secretKey,
    );
    try {
      await this.receipts.sink?.(receipt);
    } catch {
      // a failing sink must not turn a made call into an error the caller retries; the receipt is still returned
    }
    return receipt;
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
