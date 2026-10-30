/**
 * The authorization-request side of a connector: turn a declarative {@link ProviderManifest} into a correct
 * OAuth 2.0 authorize URL (with PKCE when the provider wants it), and describe how the resulting access
 * token is presented on an outbound API call.
 */

import { b64u, sha256, utf8 } from '@atlasauth/pca';
import { type ProviderManifest, ConnectorError, RESERVED_AUTHORIZE_PARAMS } from './manifest';
import { type ProviderRegistry, defaultRegistry } from './registry';

/** Caller-supplied PKCE material (RFC 7636). When omitted, {@link buildAuthorizeUrl} generates it. */
export interface PkceParams {
  /** The high-entropy `code_verifier` (43–128 unreserved chars). */
  verifier: string;
  /** Challenge method. Default `'S256'`. */
  method?: 'S256' | 'plain';
}

/** The PKCE values used for an authorize request; keep `verifier` to complete the code exchange. */
export interface PkceResult {
  verifier: string;
  challenge: string;
  method: 'S256' | 'plain';
}

const PKCE_VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;
const MIN_STATE_CHARS = 16;

export interface BuildAuthorizeUrlOptions {
  clientId: string;
  redirectUri: string;
  /** Requested scopes. Defaults to the manifest's `defaultScopes`. */
  scopes?: string[];
  /** CSRF `state`. A random value is generated when omitted; the value used is returned. */
  state?: string;
  /**
   * PKCE control. `true` forces PKCE (auto-generating a verifier); an object supplies the verifier;
   * `false` disables it; omitted follows the manifest's `pkce` flag.
   */
  pkce?: boolean | PkceParams;
  /** Substitutions for `{var}` placeholders in the manifest URLs (e.g. `{ shop: 'acme' }`). */
  vars?: Record<string, string>;
  /** Registry to resolve `providerId` against. Defaults to the shared {@link defaultRegistry}. */
  registry?: ProviderRegistry;
  /** Extra authorize-request parameters, merged after the manifest's `authParams`. May not set `client_id`, `redirect_uri`, `scope`, `state`, `response_type` or a PKCE parameter. */
  extraParams?: Record<string, string>;
  /** Accept scopes the manifest does not list in `scopesAvailable`. Default false: an unlisted scope is refused. */
  allowUnlistedScopes?: boolean;
  /** Accept the `plain` PKCE method (RFC 7636 says S256 whenever the client can). Default false. */
  allowPlainPkce?: boolean;
}

/** A built authorize URL plus the `state` and (if used) PKCE values the caller must retain for the exchange. */
export interface AuthorizeUrl {
  url: string;
  state: string;
  pkce?: PkceResult;
}

/** 32 bytes of CSPRNG entropy, base64url (unpadded). */
function randomToken(bytes = 32): string {
  const b = new Uint8Array(bytes);
  globalThis.crypto.getRandomValues(b);
  return b64u(b);
}

/** The S256 code challenge for a verifier: base64url(SHA-256(ASCII(verifier))), unpadded (RFC 7636 §4.2). */
export function pkceChallenge(verifier: string, method: 'S256' | 'plain' = 'S256'): string {
  return method === 'plain' ? verifier : b64u(sha256(utf8(verifier)));
}

/** Substitute `{var}` placeholders in `url`. Throws {@link ConnectorError} when a used var is not supplied. */
export function substituteVars(url: string, vars: Record<string, string> | undefined): string {
  return url.replace(/\{(\w+)\}/g, (_full: string, name: string) => {
    const v = vars === undefined || !Object.prototype.hasOwnProperty.call(vars, name) ? undefined : vars[name];
    if (v === undefined) throw new ConnectorError(`missing URL variable '{${name}}'`);
    // A variable is a DNS label (a shop, an account). Anything else could move the request to another host or path:
    // `evil.com/x?` in `https://{shop}.myshopify.com/...` sends the authorization code to evil.com.
    if (typeof v !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9-]{0,62}$/.test(v)) {
      throw new ConnectorError(`URL variable '{${name}}' must be a single DNS label (letters, digits and hyphens)`);
    }
    return v;
  });
}

function encodeForm(params: ReadonlyArray<readonly [string, string]>): string {
  return params.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
}

/**
 * Build the OAuth 2.0 authorization-request URL for `providerId`. Always emits `response_type=code`,
 * `client_id`, `redirect_uri`, `scope`, and `state`; adds `code_challenge` + `code_challenge_method` when
 * PKCE is in effect, and merges the manifest's `authParams` then the caller's `extraParams`. Scopes are
 * joined with the manifest's `scopeSeparator` (default space). Pure and synchronous.
 */
export function buildAuthorizeUrl(providerId: string, options: BuildAuthorizeUrlOptions): AuthorizeUrl {
  const registry = options.registry ?? defaultRegistry;
  const manifest = registry.require(providerId);

  const scopes = options.scopes ?? manifest.defaultScopes;
  const separator = manifest.scopeSeparator ?? ' ';
  const state = options.state ?? randomToken();

  if (typeof options.clientId !== 'string' || options.clientId.length === 0) throw new ConnectorError('buildAuthorizeUrl: clientId must be a non-empty string');
  checkRedirectUri(options.redirectUri);
  if (typeof state !== 'string' || state.length < MIN_STATE_CHARS) throw new ConnectorError(`buildAuthorizeUrl: state must be at least ${MIN_STATE_CHARS} characters (omit it to get a random one)`);
  checkScopes(manifest, scopes, options.allowUnlistedScopes === true);
  for (const k of Object.keys(options.extraParams ?? {})) {
    if (RESERVED_AUTHORIZE_PARAMS.has(k)) throw new ConnectorError(`buildAuthorizeUrl: extraParams may not set '${k}'`);
  }

  const params: Array<[string, string]> = [
    ['response_type', 'code'],
    ['client_id', options.clientId],
    ['redirect_uri', options.redirectUri],
  ];
  if (scopes.length > 0) params.push(['scope', scopes.join(separator)]);
  params.push(['state', state]);

  // PKCE: enabled when explicitly requested, when a verifier object is passed, or (unless disabled) when
  // the manifest declares it.
  const wantPkce = options.pkce === false ? false : options.pkce !== undefined ? true : manifest.pkce === true;
  let pkce: PkceResult | undefined;
  if (wantPkce) {
    const verifier = typeof options.pkce === 'object' ? options.pkce.verifier : randomToken();
    const method = typeof options.pkce === 'object' ? options.pkce.method ?? 'S256' : 'S256';
    if (!PKCE_VERIFIER.test(verifier)) throw new ConnectorError('buildAuthorizeUrl: the PKCE verifier must be 43 to 128 unreserved characters (RFC 7636)');
    if (method !== 'S256' && !(method === 'plain' && options.allowPlainPkce === true)) throw new ConnectorError("buildAuthorizeUrl: PKCE method must be 'S256' (pass allowPlainPkce to use 'plain')");
    const challenge = pkceChallenge(verifier, method);
    params.push(['code_challenge', challenge], ['code_challenge_method', method]);
    pkce = { verifier, challenge, method };
  }

  for (const [k, v] of Object.entries(manifest.authParams ?? {})) params.push([k, v]);
  for (const [k, v] of Object.entries(options.extraParams ?? {})) params.push([k, v]);

  const base = substituteVars(manifest.authorizeUrl, options.vars);
  const url = `${base}${base.includes('?') ? '&' : '?'}${encodeForm(params)}`;
  const result: AuthorizeUrl = { url, state };
  if (pkce !== undefined) result.pkce = pkce;
  return result;
}

function checkRedirectUri(uri: unknown): void {
  let u: URL;
  try {
    u = new URL(String(uri));
  } catch {
    throw new ConnectorError('buildAuthorizeUrl: redirectUri must be an absolute URL');
  }
  if (u.hash !== '') throw new ConnectorError('buildAuthorizeUrl: redirectUri must not have a fragment (RFC 6749 3.1.2)');
  if (u.username !== '' || u.password !== '') throw new ConnectorError('buildAuthorizeUrl: redirectUri must not carry credentials');
  const local = u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname === '[::1]';
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && local)) throw new ConnectorError('buildAuthorizeUrl: redirectUri must be https (http only for localhost)');
}

/** Every scope must be one token the manifest lists: a scope containing the separator would smuggle in another one. */
function checkScopes(manifest: ProviderManifest, scopes: readonly string[], allowUnlisted: boolean): void {
  if (!Array.isArray(scopes)) throw new ConnectorError('buildAuthorizeUrl: scopes must be a list');
  const seen = new Set<string>();
  for (const s of scopes) {
    if (typeof s !== 'string' || s.length === 0 || /[\s,]/.test(s) || s.includes(manifest.scopeSeparator ?? ' ')) {
      throw new ConnectorError('buildAuthorizeUrl: every scope must be a non-empty string without whitespace, commas or the separator');
    }
    if (seen.has(s)) throw new ConnectorError(`buildAuthorizeUrl: scope '${s}' is listed twice`);
    seen.add(s);
    if (!allowUnlisted && manifest.scopesAvailable.length > 0 && !manifest.scopesAvailable.includes(s)) {
      throw new ConnectorError(`buildAuthorizeUrl: scope '${s}' is not offered by provider '${manifest.id}'`);
    }
  }
}

/** Where a manifest says an access token belongs on an outbound request. */
export type AppliedToken =
  | { kind: 'header'; name: string; value: string }
  | { kind: 'query'; name: string; value: string };

/**
 * Describe how `accessToken` is attached to a provider API call, per the manifest's `tokenPlacement`:
 * `bearer` → `Authorization: Bearer <token>`; `header` → the custom `headerName`; `query` → the `queryParam`.
 * Returns a value the caller applies to its own request; this package never performs the outbound call.
 */
export function applyAccessToken(manifest: ProviderManifest, accessToken: string): AppliedToken {
  // A control character or space in a token would end the header value (response splitting) or add a header.
  if (typeof accessToken !== 'string' || accessToken.length === 0 || /[^\x21-\x7e]/.test(accessToken)) {
    throw new ConnectorError('applyAccessToken: the access token must be a non-empty string of printable ASCII without spaces');
  }
  switch (manifest.tokenPlacement) {
    case 'bearer':
      return { kind: 'header', name: 'Authorization', value: `Bearer ${accessToken}` };
    case 'header': {
      if (manifest.headerName === undefined) throw new ConnectorError(`manifest '${manifest.id}' is header-placed but has no headerName`);
      return { kind: 'header', name: manifest.headerName, value: accessToken };
    }
    case 'query': {
      if (manifest.queryParam === undefined) throw new ConnectorError(`manifest '${manifest.id}' is query-placed but has no queryParam`);
      return { kind: 'query', name: manifest.queryParam, value: accessToken };
    }
  }
}
