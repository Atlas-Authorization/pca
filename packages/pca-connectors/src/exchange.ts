/**
 * The token side of a connector: exchange an authorization code (or a refresh token) at a provider's token
 * endpoint and FEED the `@atlasauth/pca-connect` vault, so every stored connection is bound to a PCA
 * capability. A connection minted here is unusable until a verified Proof-Carrying Action proves authority
 * over the provider and that the requested scopes are a subset of what the capability grants — that
 * capability binding is the differentiator a plain token vault lacks.
 *
 * The vault's OWN auto-refresh (inside `getConnectionToken`) is wired from the same manifests via
 * {@link manifestToProviderConfig} / {@link buildVaultProviders}, so the catalog is the single source of
 * truth for both the initial grant and later refreshes.
 */

import { b64u, utf8 } from '@atlasauth/pca';
import type {
  ProviderConfig,
  StoredConnection,
  TokenVault,
  VaultFetch,
  VaultHttpResponse,
} from '@atlasauth/pca-connect';
import { type ProviderManifest, ConnectorError } from './manifest';
import { type ProviderRegistry, defaultRegistry } from './registry';
import { substituteVars } from './authorize';

/** How a minted connection is stored and bound to a PCA capability in the vault. */
export interface ConnectionBinding {
  vault: TokenVault;
  /** b64u public key of the agent — the capability chain's LEAF holder this connection belongs to. */
  agentId: string;
  /** Vault connection id. Defaults to the vault's own `defaultConnectionId`. */
  connectionId?: string;
  authority: {
    /** b64u public key the capability chain must be rooted at (the PCActn's `cap_chain[0].issuer`). */
    principal: string;
    /** Scopes the capability must cover. Defaults to the requested scopes (least privilege). */
    scopes?: string[];
    /** When set, the PCActn's signed `aud` must equal this resource-server id. */
    audience?: string;
  };
}

/** Default access-token lifetime assumed when the provider returns neither `expires_in` nor a JWT `exp`. */
const DEFAULT_TOKEN_LIFETIME_MS = 3_600_000;

export interface ExchangeCodeArgs {
  providerId: string;
  clientId: string;
  clientSecret?: string;
  /** The authorization code returned to the redirect URI. */
  code: string;
  redirectUri: string;
  /** The PKCE `code_verifier` used for the authorize request (required when the provider uses PKCE). */
  codeVerifier?: string;
  /** Scopes requested (and the least-privilege authority the connection is bound to). Defaults to the manifest's. */
  scopes?: string[];
  /** Injectable HTTP transport (same contract as the vault's `fetch`). */
  fetch: VaultFetch;
  /** How to store + capability-bind the resulting connection. */
  bind: ConnectionBinding;
  /** Clock, epoch ms. Defaults to `Date.now`. */
  now?: number;
  /** Registry to resolve `providerId` against. Defaults to {@link defaultRegistry}. */
  registry?: ProviderRegistry;
  /** `{var}` substitutions for the manifest token URL. */
  vars?: Record<string, string>;
  /** Extra static token-request form parameters. */
  extraParams?: Record<string, string>;
}

export interface RefreshArgs {
  providerId: string;
  clientId: string;
  clientSecret?: string;
  /** The refresh token to present (the vault does not expose stored refresh tokens without a PCActn). */
  refreshToken: string;
  /** Scopes to request / re-bind. Defaults to the manifest's `defaultScopes`. */
  scopes?: string[];
  fetch: VaultFetch;
  bind: ConnectionBinding;
  now?: number;
  registry?: ProviderRegistry;
  vars?: Record<string, string>;
  extraParams?: Record<string, string>;
}

/** The fields of a token-endpoint success response this package consumes. */
interface ParsedToken {
  accessToken: string;
  refreshToken?: string;
  expiresInSecs?: number;
  /** Provider-echoed granted scopes, when present. */
  scopes?: string[];
}

/** Read own property `k` off `o` as `unknown`, without a cast. */
function prop(o: object, k: string): unknown {
  return Object.prototype.hasOwnProperty.call(o, k) ? Reflect.get(o, k) : undefined;
}

function errText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** Standard base64 (padded) of `s` — for HTTP Basic client authentication (RFC 6749 §2.3.1). */
function basicAuthHeader(clientId: string, clientSecret: string): string {
  let s = b64u(utf8(`${clientId}:${clientSecret}`)).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4 !== 0) s += '=';
  return `Basic ${s}`;
}

function formEncode(params: Record<string, string>): string {
  return Object.entries(params)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');
}

/** Parse an OAuth token-endpoint JSON body. Fails closed: a missing/empty `access_token` is a hard error. */
function parseTokenResponse(body: unknown, provider: string): ParsedToken {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    throw new ConnectorError(`[${provider}] token endpoint returned a non-object body`);
  }
  const accessToken = prop(body, 'access_token');
  if (typeof accessToken !== 'string' || accessToken.length === 0) {
    throw new ConnectorError(`[${provider}] token endpoint response has no access_token`);
  }
  const out: ParsedToken = { accessToken };
  const expiresIn = prop(body, 'expires_in');
  if (typeof expiresIn === 'number' && Number.isFinite(expiresIn) && expiresIn > 0) out.expiresInSecs = expiresIn;
  const refreshToken = prop(body, 'refresh_token');
  if (typeof refreshToken === 'string' && refreshToken.length > 0) out.refreshToken = refreshToken;
  const scope = prop(body, 'scope');
  if (typeof scope === 'string' && scope.trim().length > 0) out.scopes = scope.trim().split(/[\s,]+/);
  return out;
}

/** POST a form to a token endpoint via the injectable transport and parse the response (fail-closed). */
async function postToken(
  manifest: ProviderManifest,
  tokenEndpoint: string,
  params: Record<string, string>,
  clientSecret: string | undefined,
  fetchImpl: VaultFetch,
): Promise<ParsedToken> {
  const headers: Record<string, string> = {
    'content-type': 'application/x-www-form-urlencoded',
    accept: 'application/json',
  };
  const body: Record<string, string> = { ...params };
  if (manifest.clientAuth === 'basic') {
    // Client credentials move to the Authorization header; they must not also appear in the body.
    if (clientSecret === undefined) throw new ConnectorError(`[${manifest.id}] clientAuth 'basic' requires a clientSecret`);
    const clientId = body['client_id'];
    if (clientId === undefined) throw new ConnectorError(`[${manifest.id}] missing client_id for basic auth`);
    headers['authorization'] = basicAuthHeader(clientId, clientSecret);
    delete body['client_id'];
    delete body['client_secret'];
  }

  let res: VaultHttpResponse;
  try {
    res = await fetchImpl(tokenEndpoint, { method: 'POST', headers, body: formEncode(body) });
  } catch (e) {
    throw new ConnectorError(`[${manifest.id}] token transport error: ${errText(e)}`);
  }
  if (!res.ok) {
    let detail = '';
    try {
      detail = (await res.text()).slice(0, 256);
    } catch {
      detail = '<unreadable body>';
    }
    throw new ConnectorError(`[${manifest.id}] token endpoint ${res.status}: ${detail}`);
  }
  let json: unknown;
  try {
    json = await res.json();
  } catch (e) {
    throw new ConnectorError(`[${manifest.id}] unparseable token JSON: ${errText(e)}`);
  }
  return parseTokenResponse(json, manifest.id);
}

/** Store the token result in the vault, bound to the PCA capability authority. */
async function storeConnection(
  manifest: ProviderManifest,
  parsed: ParsedToken,
  requested: string[],
  bind: ConnectionBinding,
  now: number,
  priorRefreshToken?: string,
): Promise<StoredConnection> {
  const expiresAt = parsed.expiresInSecs !== undefined ? now + parsed.expiresInSecs * 1000 : now + DEFAULT_TOKEN_LIFETIME_MS;
  // Scopes the stored token actually carries: the provider's echo wins; else the requested set.
  const granted = parsed.scopes ?? requested;
  // Token rotation: keep the prior refresh token unless the provider issued a new one.
  const refreshToken = parsed.refreshToken ?? priorRefreshToken;
  return bind.vault.putConnection({
    agentId: bind.agentId,
    provider: manifest.id,
    accessToken: parsed.accessToken,
    expiresAt,
    scopes: granted,
    authority: {
      principal: bind.authority.principal,
      scopes: bind.authority.scopes ?? requested,
      ...(bind.authority.audience !== undefined ? { audience: bind.authority.audience } : {}),
    },
    ...(bind.connectionId !== undefined ? { connectionId: bind.connectionId } : {}),
    ...(refreshToken !== undefined ? { refreshToken } : {}),
  });
}

/**
 * Exchange an authorization code for tokens and store a capability-bound connection in the vault. The
 * requested scopes become the connection's least-privilege authority; the connection is unusable until a
 * verified PCActn proves a capability covering them.
 */
export async function exchangeCode(args: ExchangeCodeArgs): Promise<StoredConnection> {
  const registry = args.registry ?? defaultRegistry;
  const manifest = registry.require(args.providerId);
  const now = args.now ?? Date.now();
  const requested = args.scopes ?? manifest.defaultScopes;

  if (manifest.pkce === true && args.codeVerifier === undefined) {
    throw new ConnectorError(`[${manifest.id}] provider uses PKCE; a codeVerifier is required to exchange the code`);
  }

  const params: Record<string, string> = {
    grant_type: 'authorization_code',
    code: args.code,
    redirect_uri: args.redirectUri,
    client_id: args.clientId,
    ...(args.clientSecret !== undefined ? { client_secret: args.clientSecret } : {}),
    ...(args.codeVerifier !== undefined ? { code_verifier: args.codeVerifier } : {}),
    ...(args.extraParams ?? {}),
  };
  const tokenEndpoint = substituteVars(manifest.tokenUrl, args.vars);
  const parsed = await postToken(manifest, tokenEndpoint, params, args.clientSecret, args.fetch);
  return storeConnection(manifest, parsed, requested, args.bind, now);
}

/**
 * Refresh an access token at the provider's refresh endpoint and re-store the capability-bound connection.
 * Throws when the manifest declares `refresh.mode === 'none'`. Scope narrowing is sent only when the
 * manifest opts in. The authority binding is preserved from `bind` (re-asserting least privilege).
 */
export async function refresh(args: RefreshArgs): Promise<StoredConnection> {
  const registry = args.registry ?? defaultRegistry;
  const manifest = registry.require(args.providerId);
  if (manifest.refresh.mode === 'none') {
    throw new ConnectorError(`[${manifest.id}] provider does not support token refresh`);
  }
  const now = args.now ?? Date.now();
  const requested = args.scopes ?? manifest.defaultScopes;

  const params: Record<string, string> = {
    grant_type: 'refresh_token',
    refresh_token: args.refreshToken,
    client_id: args.clientId,
    ...(args.clientSecret !== undefined ? { client_secret: args.clientSecret } : {}),
    ...(manifest.refresh.extraParams ?? {}),
    ...(args.extraParams ?? {}),
  };
  if (manifest.refresh.supportsScopeNarrowing === true && requested.length > 0) {
    params['scope'] = requested.join(manifest.scopeSeparator ?? ' ');
  }
  const tokenEndpoint = substituteVars(manifest.refresh.tokenEndpoint ?? manifest.tokenUrl, args.vars);
  const parsed = await postToken(manifest, tokenEndpoint, params, args.clientSecret, args.fetch);
  return storeConnection(manifest, parsed, requested, args.bind, now, args.refreshToken);
}

/** Per-provider client credentials used to derive a vault {@link ProviderConfig}. */
export interface ProviderCredentials {
  clientId: string;
  clientSecret?: string;
  /** `{var}` substitutions for the refresh token endpoint (e.g. `{ shop: 'acme' }`). */
  vars?: Record<string, string>;
}

/**
 * Derive the `@atlasauth/pca-connect` {@link ProviderConfig} the vault uses for its OWN auto-refresh, from a
 * manifest + credentials. This is how the catalog drives the vault's internal refresh: the manifest's token
 * endpoint, scope-narrowing flag and extra params flow straight into the vault. Throws when the manifest
 * does not support refresh.
 */
export function manifestToProviderConfig(manifest: ProviderManifest, creds: ProviderCredentials): ProviderConfig {
  if (manifest.refresh.mode === 'none') {
    throw new ConnectorError(`[${manifest.id}] provider does not support token refresh; no ProviderConfig`);
  }
  const config: ProviderConfig = {
    tokenEndpoint: substituteVars(manifest.refresh.tokenEndpoint ?? manifest.tokenUrl, creds.vars),
    clientId: creds.clientId,
  };
  if (creds.clientSecret !== undefined) config.clientSecret = creds.clientSecret;
  if (manifest.refresh.supportsScopeNarrowing !== undefined) config.supportsScopeNarrowing = manifest.refresh.supportsScopeNarrowing;
  if (manifest.refresh.extraParams !== undefined) config.extraParams = { ...manifest.refresh.extraParams };
  return config;
}

/**
 * Build the vault's `providers` map (provider id → {@link ProviderConfig}) from a set of configured
 * providers, skipping any whose manifest cannot refresh. Pass the result to `new TokenVault({ providers })`.
 */
export function buildVaultProviders(
  credsById: Record<string, ProviderCredentials>,
  registry: ProviderRegistry = defaultRegistry,
): Record<string, ProviderConfig> {
  const out: Record<string, ProviderConfig> = {};
  for (const [id, creds] of Object.entries(credsById)) {
    const manifest = registry.require(id);
    if (manifest.refresh.mode === 'none') continue;
    out[id] = manifestToProviderConfig(manifest, creds);
  }
  return out;
}
