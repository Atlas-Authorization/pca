import { decodeJwt } from 'jose';
import { RefreshFailedError } from './errors';
import type { StoredConnection } from './store';

/** Per-provider OAuth token-endpoint configuration used to refresh an access token. */
export interface ProviderConfig {
  /** The provider's OAuth 2.0 token endpoint (RFC 6749 §3.2). */
  tokenEndpoint: string;
  clientId: string;
  /** Omit for public clients / PKCE. */
  clientSecret?: string;
  /** When true, a narrowed `scope` is sent on refresh so the minted token carries only the requested scopes. */
  supportsScopeNarrowing?: boolean;
  /** Extra static form parameters merged into every refresh request for this provider. */
  extraParams?: Record<string, string>;
}

/** Minimal structural view of an HTTP response — avoids a DOM/`lib` dependency and keeps `fetch` injectable. */
export interface VaultHttpResponse {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
  text(): Promise<string>;
}

export interface VaultHttpRequest {
  method: string;
  headers: Record<string, string>;
  body: string;
}

/** Injectable transport. In production pass an adapter over the platform `fetch`; in tests pass a mock. */
export type VaultFetch = (url: string, init: VaultHttpRequest) => Promise<VaultHttpResponse>;

/** The fields of an OAuth token-endpoint success response the vault consumes. */
interface TokenResponse {
  accessToken: string;
  expiresInSecs?: number;
  refreshToken?: string;
  /** Space-delimited scopes, split into a list, when the provider echoes the granted scope. */
  scopes?: string[];
}

function formEncode(params: Record<string, string>): string {
  return Object.entries(params)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');
}

/** Read own property `k` off an object as `unknown`, without a cast. Absent => `undefined`. */
function prop(o: object, k: string): unknown {
  return Object.prototype.hasOwnProperty.call(o, k) ? Reflect.get(o, k) : undefined;
}

function errText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** Parse an OAuth token-endpoint JSON body. Fails closed: a missing/empty `access_token` is a hard error. */
function parseTokenResponse(body: unknown, provider: string): TokenResponse {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    throw new RefreshFailedError(provider, 'token endpoint returned a non-object body');
  }
  const accessToken = prop(body, 'access_token');
  if (typeof accessToken !== 'string' || accessToken.length === 0) {
    throw new RefreshFailedError(provider, 'token endpoint response has no access_token');
  }
  const out: TokenResponse = { accessToken };
  const expiresIn = prop(body, 'expires_in');
  if (typeof expiresIn === 'number' && Number.isFinite(expiresIn) && expiresIn > 0) out.expiresInSecs = expiresIn;
  const refreshToken = prop(body, 'refresh_token');
  if (typeof refreshToken === 'string' && refreshToken.length > 0) out.refreshToken = refreshToken;
  const scope = prop(body, 'scope');
  if (typeof scope === 'string' && scope.trim().length > 0) out.scopes = scope.trim().split(/\s+/);
  return out;
}

/** Epoch-ms expiry claimed by a JWT access token, read with jose; `undefined` for an opaque (non-JWT) token. */
function jwtExpiryMs(accessToken: string): number | undefined {
  try {
    const exp = decodeJwt(accessToken).exp;
    return typeof exp === 'number' && Number.isFinite(exp) ? exp * 1000 : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Refresh `connection`'s access token at its provider's token endpoint using the stored refresh token.
 * `requested` is the least-privilege scope set the caller asked for; when the provider supports scope
 * narrowing it is sent so the new token is minted no wider than requested. Returns the FIELDS to apply to
 * the connection (the vault persists them); throws {@link RefreshFailedError} on any transport/parse failure.
 */
export async function refreshConnection(args: {
  connection: StoredConnection;
  config: ProviderConfig | undefined;
  refreshToken: string;
  requested: readonly string[];
  fetch: VaultFetch | undefined;
  now: number;
  defaultTokenLifetimeMs: number;
}): Promise<Pick<StoredConnection, 'accessToken' | 'refreshToken' | 'expiresAt' | 'scopes'>> {
  const provider = args.connection.provider;
  if (args.config === undefined) throw new RefreshFailedError(provider, 'no provider token-endpoint config');
  if (args.fetch === undefined) throw new RefreshFailedError(provider, 'no fetch transport configured');

  const params: Record<string, string> = {
    grant_type: 'refresh_token',
    refresh_token: args.refreshToken,
    client_id: args.config.clientId,
    ...(args.config.clientSecret !== undefined ? { client_secret: args.config.clientSecret } : {}),
    ...(args.config.extraParams ?? {}),
  };
  if (args.config.supportsScopeNarrowing === true && args.requested.length > 0) {
    params['scope'] = [...args.requested].join(' ');
  }

  let res: VaultHttpResponse;
  try {
    res = await args.fetch(args.config.tokenEndpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body: formEncode(params),
    });
  } catch (e) {
    throw new RefreshFailedError(provider, `transport error: ${errText(e)}`);
  }
  if (!res.ok) {
    let detail = '';
    try {
      detail = (await res.text()).slice(0, 256);
    } catch {
      detail = '<unreadable body>';
    }
    throw new RefreshFailedError(provider, `token endpoint ${res.status}: ${detail}`, res.status);
  }

  let json: unknown;
  try {
    json = await res.json();
  } catch (e) {
    throw new RefreshFailedError(provider, `unparseable JSON body: ${errText(e)}`);
  }
  const parsed = parseTokenResponse(json, provider);

  const expiresAt =
    parsed.expiresInSecs !== undefined
      ? args.now + parsed.expiresInSecs * 1000
      : (jwtExpiryMs(parsed.accessToken) ?? args.now + args.defaultTokenLifetimeMs);

  // New scopes: the provider's echoed scope wins; else the narrowed request (if narrowing); else unchanged.
  const scopes =
    parsed.scopes !== undefined
      ? parsed.scopes
      : args.config.supportsScopeNarrowing === true && args.requested.length > 0
        ? [...args.requested]
        : [...args.connection.scopes];

  const out: Pick<StoredConnection, 'accessToken' | 'refreshToken' | 'expiresAt' | 'scopes'> = {
    accessToken: parsed.accessToken,
    expiresAt,
    scopes,
    // Token rotation: keep the old refresh token unless the provider issued a new one.
    refreshToken: parsed.refreshToken ?? args.refreshToken,
  };
  return out;
}
