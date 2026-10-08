/**
 * The authorization-request side of a connector: turn a declarative {@link ProviderManifest} into a correct
 * OAuth 2.0 authorize URL (with PKCE when the provider wants it), and describe how the resulting access
 * token is presented on an outbound API call.
 */

import { b64u, sha256, utf8 } from '@atlasauth/pca';
import { type ProviderManifest, ConnectorError } from './manifest';
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
  /** Extra authorize-request parameters, merged after the manifest's `authParams`. */
  extraParams?: Record<string, string>;
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
    const v = vars === undefined ? undefined : vars[name];
    if (v === undefined) throw new ConnectorError(`missing URL variable '{${name}}'`);
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
