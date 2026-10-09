/**
 * OpenID Connect Discovery (OpenID Connect Discovery 1.0, §4): fetch an issuer's
 * `.well-known/openid-configuration` document and return its parsed provider metadata.
 *
 * This is the first step of rooting a PCA grant in a real OIDC-authenticated human: before an ID
 * token can be verified, the relying party needs the issuer's signing-key endpoint (`jwks_uri`). The
 * fetch uses the global `fetch` by default but accepts an injectable one so callers (and tests) can
 * run without the network.
 */

/** The error thrown for any discovery failure (network, non-2xx, bad JSON, issuer mismatch). */
export class OidcDiscoveryError extends Error {
  override readonly name = 'OidcDiscoveryError';
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/**
 * The subset of OIDC provider metadata (OpenID Connect Discovery 1.0 §3) that PCA rooting needs,
 * plus an index signature so every advertised member is preserved. `issuer` and `jwks_uri` are
 * required and validated; the rest are optional.
 */
export interface OidcProviderMetadata {
  /** The issuer identifier — MUST exactly equal the issuer the document was fetched for (§4.3). */
  issuer: string;
  /** URL of the issuer's JSON Web Key Set (the ID-token signing keys). */
  jwks_uri: string;
  authorization_endpoint?: string;
  token_endpoint?: string;
  userinfo_endpoint?: string;
  id_token_signing_alg_values_supported?: string[];
  /** Any additional (non-normative) members the provider advertises. */
  [claim: string]: unknown;
}

export interface DiscoverOidcOptions {
  /** Injectable `fetch` (defaults to the global `fetch`) so tests need no network. */
  fetch?: typeof fetch;
  /** AbortSignal for the discovery request. */
  signal?: AbortSignal;
}

const WELL_KNOWN = '/.well-known/openid-configuration';

/**
 * Build the discovery URL for an issuer per OIDC Discovery 1.0: append
 * `/.well-known/openid-configuration` to the issuer identifier, preserving any path component (a
 * single trailing slash on the issuer is normalized away so it is not doubled).
 */
export function discoveryUrl(issuer: string): string {
  const trimmed = issuer.endsWith('/') ? issuer.slice(0, -1) : issuer;
  return `${trimmed}${WELL_KNOWN}`;
}

/** Fetch and parse `${issuer}/.well-known/openid-configuration`. Throws {@link OidcDiscoveryError}. */
export async function discoverOidc(issuer: string, opts: DiscoverOidcOptions = {}): Promise<OidcProviderMetadata> {
  if (typeof issuer !== 'string' || issuer.length === 0) {
    throw new OidcDiscoveryError('discoverOidc: issuer must be a non-empty string');
  }
  const doFetch = opts.fetch ?? globalThis.fetch;
  if (typeof doFetch !== 'function') {
    throw new OidcDiscoveryError('discoverOidc: no fetch implementation available (pass opts.fetch)');
  }
  const url = discoveryUrl(issuer);
  let res: Response;
  try {
    res = await doFetch(url, {
      headers: { accept: 'application/json' },
      ...(opts.signal !== undefined ? { signal: opts.signal } : {}),
    });
  } catch (cause) {
    throw new OidcDiscoveryError(`discoverOidc: fetch of ${url} failed`, { cause });
  }
  if (!res.ok) {
    throw new OidcDiscoveryError(`discoverOidc: ${url} returned HTTP ${res.status}`);
  }
  let body: unknown;
  try {
    body = await res.json();
  } catch (cause) {
    throw new OidcDiscoveryError(`discoverOidc: ${url} did not return valid JSON`, { cause });
  }
  const meta = asMetadata(body);
  // OIDC Discovery §4.3: the document's issuer MUST exactly match the requested issuer (defends
  // against mix-up where a document is served from an unexpected origin).
  if (meta.issuer !== issuer) {
    throw new OidcDiscoveryError(`discoverOidc: metadata issuer '${meta.issuer}' does not match requested '${issuer}'`);
  }
  return meta;
}

function asMetadata(body: unknown): OidcProviderMetadata {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    throw new OidcDiscoveryError('discoverOidc: metadata is not a JSON object');
  }
  const rec: Record<string, unknown> = { ...body };
  const issuer = rec.issuer;
  if (typeof issuer !== 'string' || issuer.length === 0) {
    throw new OidcDiscoveryError('discoverOidc: metadata is missing a string "issuer"');
  }
  const jwksUri = rec.jwks_uri;
  if (typeof jwksUri !== 'string' || jwksUri.length === 0) {
    throw new OidcDiscoveryError('discoverOidc: metadata is missing a string "jwks_uri"');
  }
  // Start from the required, validated members, then copy every other advertised member through the
  // index signature (writing `unknown` values — no spread of an unknown-index object into the typed shape).
  const meta: OidcProviderMetadata = { issuer, jwks_uri: jwksUri };
  for (const [key, value] of Object.entries(rec)) {
    if (key !== 'issuer' && key !== 'jwks_uri') meta[key] = value;
  }
  return meta;
}
