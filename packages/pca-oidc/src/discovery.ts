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
  /** Reject a discovery document larger than this many bytes (default {@link DEFAULT_MAX_DISCOVERY_BYTES}). */
  maxBytes?: number;
  /**
   * Require `https:` for the issuer and for the advertised `jwks_uri` (default true). Pass `false` only
   * for a local test issuer.
   */
  requireHttps?: boolean;
}

/** Default size cap for a discovery document (1 MiB). */
export const DEFAULT_MAX_DISCOVERY_BYTES = 1024 * 1024;

function isHttps(u: string): boolean {
  try {
    return new URL(u).protocol === 'https:';
  } catch {
    return false;
  }
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
  const requireHttps = opts.requireHttps !== false;
  if (requireHttps && !isHttps(issuer)) {
    throw new OidcDiscoveryError(`discoverOidc: issuer '${issuer}' is not an https URL`);
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
  const maxBytes = opts.maxBytes ?? DEFAULT_MAX_DISCOVERY_BYTES;
  const declared = Number(res.headers?.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new OidcDiscoveryError(`discoverOidc: ${url} response exceeds ${maxBytes} bytes`);
  }
  let body: unknown;
  try {
    const text = await res.text();
    if (new TextEncoder().encode(text).length > maxBytes) {
      throw new OidcDiscoveryError(`discoverOidc: ${url} response exceeds ${maxBytes} bytes`);
    }
    body = JSON.parse(text);
  } catch (cause) {
    if (cause instanceof OidcDiscoveryError) throw cause;
    throw new OidcDiscoveryError(`discoverOidc: ${url} did not return valid JSON`, { cause });
  }
  const meta = asMetadata(body);
  // OIDC Discovery §4.3: the document's issuer MUST exactly match the requested issuer (defends
  // against mix-up where a document is served from an unexpected origin).
  if (meta.issuer !== issuer) {
    throw new OidcDiscoveryError(`discoverOidc: metadata issuer '${meta.issuer}' does not match requested '${issuer}'`);
  }
  if (requireHttps && !isHttps(meta.jwks_uri)) {
    throw new OidcDiscoveryError(`discoverOidc: jwks_uri '${meta.jwks_uri}' is not an https URL`);
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
