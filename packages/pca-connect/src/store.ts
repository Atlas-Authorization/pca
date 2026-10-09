/**
 * Persistence surface for the outbound token vault. A stored connection is an agent's third-party
 * OAuth material (access/refresh tokens, scopes, expiry) bound to a PCA authority descriptor — the
 * capability shape that is allowed to use it.
 */

/**
 * The PCA authority a connection is bound to: which capability may unlock this token.
 *
 *  - `principal` is the TRUST ANCHOR: the b64u public key the capability chain MUST be rooted at
 *    (the PCActn's `cap_chain[0].issuer`). Without pinning this, any self-minted chain would verify.
 *  - `scopes` is the OAuth scope set the capability must cover for this connection; it defaults to the
 *    connection's own `scopes` and is the least-privilege requirement a caller's request is measured against.
 *  - `audience`, when set, is the resource-server id the PCActn's signed `aud` must equal.
 */
export interface ConnectionAuthority {
  provider: string;
  principal: string;
  scopes: string[];
  audience?: string;
}

/** A stored outbound connection, keyed by agent + provider + connectionId. */
export interface StoredConnection {
  /** b64u public key of the agent (the capability chain's LEAF holder) this connection belongs to. */
  agentId: string;
  provider: string;
  connectionId: string;
  accessToken: string;
  refreshToken?: string;
  /** Access-token expiry, epoch milliseconds. */
  expiresAt: number;
  /** The scopes the stored access token actually carries. */
  scopes: string[];
  authority: ConnectionAuthority;
  createdAt: number;
  lastUsedAt?: number;
  /** Number of successful `getConnectionToken` retrievals. */
  useCount: number;
}

/** The composite key identifying one stored connection. */
export interface ConnectionKey {
  agentId: string;
  provider: string;
  connectionId: string;
}

/** Async CRUD over stored connections. Implementations must round-trip a `StoredConnection` by its key. */
export interface ConnectionStore {
  get(key: ConnectionKey): Promise<StoredConnection | undefined>;
  set(connection: StoredConnection): Promise<void>;
  delete(key: ConnectionKey): Promise<void>;
}

function keyString(key: ConnectionKey): string {
  // NUL-joined: provider / connectionId / agentId are b64u or opaque tokens, none of which contain NUL.
  return `${key.agentId}\u0000${key.provider}\u0000${key.connectionId}`;
}

/** Process-local {@link ConnectionStore}. Stored connections are shallow-cloned in and out so callers
 *  cannot mutate vault state by holding a reference. Suitable as the default; swap for a durable store in prod. */
export class InMemoryConnectionStore implements ConnectionStore {
  private readonly map = new Map<string, StoredConnection>();

  async get(key: ConnectionKey): Promise<StoredConnection | undefined> {
    const found = this.map.get(keyString(key));
    return found === undefined ? undefined : cloneConnection(found);
  }

  async set(connection: StoredConnection): Promise<void> {
    this.map.set(
      keyString({ agentId: connection.agentId, provider: connection.provider, connectionId: connection.connectionId }),
      cloneConnection(connection),
    );
  }

  async delete(key: ConnectionKey): Promise<void> {
    this.map.delete(keyString(key));
  }
}

export function cloneConnection(c: StoredConnection): StoredConnection {
  const clone: StoredConnection = {
    agentId: c.agentId,
    provider: c.provider,
    connectionId: c.connectionId,
    accessToken: c.accessToken,
    expiresAt: c.expiresAt,
    scopes: [...c.scopes],
    authority: {
      provider: c.authority.provider,
      principal: c.authority.principal,
      scopes: [...c.authority.scopes],
      ...(c.authority.audience !== undefined ? { audience: c.authority.audience } : {}),
    },
    createdAt: c.createdAt,
    useCount: c.useCount,
  };
  if (c.refreshToken !== undefined) clone.refreshToken = c.refreshToken;
  if (c.lastUsedAt !== undefined) clone.lastUsedAt = c.lastUsedAt;
  return clone;
}
