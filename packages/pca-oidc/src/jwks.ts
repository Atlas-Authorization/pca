/**
 * A caching JWKS key resolver that FAILS CLOSED on stale or unreachable keys.
 *
 * `createRemoteJWKSet` is fine for a single call, but `verifyIdToken({ jwksUri })` builds a new one per
 * call (no cache) and the cache policy of a long-lived one is not under your control. This resolver
 * makes the policy explicit: keys are cached for `cacheMaxAgeSec`; after that they are refetched and,
 * if the refetch fails, verification is REFUSED (a stale key set is never used). A `kid` that is not in
 * the cached set triggers at most one refetch per `cooldownSec` (key rotation without a fetch storm).
 */
import { createLocalJWKSet, type JSONWebKeySet, type JWTVerifyGetKey } from 'jose';
import { discoverOidc } from './discovery';
import { OidcVerificationError } from './verify';

export interface OidcJwksOptions {
  /** The issuer's `jwks_uri`. */
  jwksUri: string;
  /** Injectable `fetch` (defaults to the global one). */
  fetch?: typeof fetch;
  /** Seconds a fetched key set may be used (default 600). Past this the keys are refetched, never reused. */
  cacheMaxAgeSec?: number;
  /** Minimum seconds between refetches triggered by an unknown `kid` (default 30). */
  cooldownSec?: number;
  /** Reject a key set larger than this many bytes (default 1 MiB). */
  maxBytes?: number;
  /** Require an `https:` jwks_uri (default true). */
  requireHttps?: boolean;
  /** Clock in epoch ms (default `Date.now`). */
  now?: () => number;
}

const keysError = (message: string, cause?: unknown) =>
  new OidcVerificationError('keys', message, cause === undefined ? undefined : { cause });

/** Build a {@link JWTVerifyGetKey} to pass as `verifyIdToken`'s `key`. */
export function createOidcJwks(opts: OidcJwksOptions): JWTVerifyGetKey {
  const { jwksUri } = opts;
  if (typeof jwksUri !== 'string' || jwksUri.length === 0) throw new TypeError('createOidcJwks: jwksUri is required');
  if ((opts.requireHttps ?? true) && !/^https:\/\//i.test(jwksUri)) {
    throw new TypeError('createOidcJwks: jwksUri must be https (pass requireHttps: false only for local tests)');
  }
  const now = opts.now ?? (() => Date.now());
  const maxAgeMs = (opts.cacheMaxAgeSec ?? 600) * 1000;
  const cooldownMs = (opts.cooldownSec ?? 30) * 1000;
  const maxBytes = opts.maxBytes ?? 1024 * 1024;
  let cache: { at: number; resolve: ReturnType<typeof createLocalJWKSet>; kids: Set<string> } | undefined;
  let lastFetch = Number.NEGATIVE_INFINITY;
  let inflight: Promise<void> | undefined;

  async function refetch(): Promise<void> {
    const doFetch = opts.fetch ?? globalThis.fetch;
    lastFetch = now();
    let jwks: JSONWebKeySet;
    try {
      const res = await doFetch(jwksUri, { headers: { accept: 'application/json' } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const text = await res.text();
      if (new TextEncoder().encode(text).length > maxBytes) throw new Error(`response exceeds ${maxBytes} bytes`);
      jwks = JSON.parse(text) as JSONWebKeySet;
      if (jwks === null || typeof jwks !== 'object' || !Array.isArray(jwks.keys)) throw new Error('not a JWK Set');
    } catch (cause) {
      throw keysError(`could not fetch the issuer signing keys from ${jwksUri}`, cause);
    }
    const resolve = createLocalJWKSet(jwks);
    cache = { at: now(), resolve, kids: new Set(jwks.keys.map((k) => k.kid).filter((k): k is string => typeof k === 'string')) };
  }

  const load = (): Promise<void> => (inflight ??= refetch().finally(() => { inflight = undefined; }));

  return async (header, token) => {
    if (cache === undefined || now() - cache.at >= maxAgeMs) {
      cache = undefined; // never serve a stale set, even if the refetch below fails
      await load();
    } else if (typeof header?.kid === 'string' && !cache.kids.has(header.kid) && now() - lastFetch >= cooldownMs) {
      await load();
    }
    return cache!.resolve(header, token);
  };
}

/** Discover the issuer's `jwks_uri` (https required) and build the resolver. */
export async function createOidcJwksFromIssuer(
  issuer: string,
  opts: Omit<OidcJwksOptions, 'jwksUri'> = {},
): Promise<JWTVerifyGetKey> {
  const meta = await discoverOidc(issuer, { requireHttps: opts.requireHttps ?? true, ...(opts.fetch ? { fetch: opts.fetch } : {}) });
  return createOidcJwks({ ...opts, jwksUri: meta.jwks_uri });
}
