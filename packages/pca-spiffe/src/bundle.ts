import { createLocalJWKSet, type JWK, type JWTVerifyGetKey } from 'jose';
import { SpiffeError } from './index';

/** One trust domain's bundle: JWT authorities (JWKS) and/or X.509 authorities (PEM or DER). */
export interface TrustBundle {
  jwks?: { keys: JWK[] };
  x509Authorities?: readonly (string | Uint8Array)[];
}

export interface TrustBundleSourceOptions {
  /** REQUIRED. Fetches the current bundle (Workload API, SPIFFE bundle endpoint, file). May reject. */
  fetch: () => Promise<TrustBundle>;
  /** REQUIRED. Re-fetch when the cached bundle is older than this (ms, > 0). */
  refreshMs: number;
  /** REQUIRED. Longest a cached bundle may be used after its last successful fetch (ms, >= refreshMs). Past it, every call is denied. */
  maxStaleMs: number;
  /** Clock in ms (default Date.now). */
  now?: () => number;
}

export interface TrustBundleSource {
  /** Key resolver for `verifyJwtSvid({ key })`. Rejects with a SpiffeError when no usable bundle exists. */
  readonly jwtKey: JWTVerifyGetKey;
  /** Authorities for `verifyX509Svid({ roots })`. Rejects with a SpiffeError when no usable bundle exists. */
  x509Roots(): Promise<(string | Uint8Array)[]>;
}

const usable = (b: unknown): b is TrustBundle => {
  const t = b as TrustBundle | null;
  if (t === null || typeof t !== 'object') return false;
  const j = t.jwks !== undefined && Array.isArray(t.jwks.keys) && t.jwks.keys.length > 0;
  const x = Array.isArray(t.x509Authorities) && t.x509Authorities.length > 0;
  return j || x;
};

/**
 * A trust-bundle cache that fails closed: a rejected or empty/malformed refresh keeps the last good bundle only until
 * `maxStaleMs` after its last successful fetch; before the first success, or past that limit, every call throws
 * `trust_bundle_unavailable` (fetch failed) or `trust_bundle_invalid` (fetched but empty/malformed).
 * A bundle is never merged: a successful refresh replaces the previous one, so a removed authority stops being trusted.
 */
export function createTrustBundleSource(opts: TrustBundleSourceOptions): TrustBundleSource {
  if (typeof opts?.fetch !== 'function') throw new SpiffeError('trust_bundle_unavailable', 'createTrustBundleSource requires `fetch`');
  const { refreshMs, maxStaleMs } = opts;
  if (!(Number.isFinite(refreshMs) && refreshMs > 0) || !(Number.isFinite(maxStaleMs) && maxStaleMs >= refreshMs)) {
    throw new SpiffeError('trust_bundle_unavailable', 'refreshMs must be > 0 and maxStaleMs >= refreshMs (both finite)');
  }
  const now = opts.now ?? Date.now;
  let good: { bundle: TrustBundle; at: number } | undefined;
  let inflight: Promise<void> | undefined;
  let lastFailure: SpiffeError | undefined;

  const refresh = (): Promise<void> => (inflight ??= (async () => {
    try {
      const b = await opts.fetch();
      if (!usable(b)) throw new SpiffeError('trust_bundle_invalid', 'fetched trust bundle has no authorities');
      good = { bundle: b, at: now() };
      lastFailure = undefined;
    } catch (e) {
      lastFailure = e instanceof SpiffeError ? e : new SpiffeError('trust_bundle_unavailable', `trust bundle fetch failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      inflight = undefined;
    }
  })());

  async function current(): Promise<TrustBundle> {
    if (good === undefined || now() - good.at >= refreshMs) await refresh();
    if (good === undefined || now() - good.at > maxStaleMs) {
      throw lastFailure ?? new SpiffeError('trust_bundle_unavailable', 'no trust bundle available');
    }
    return good.bundle;
  }

  return {
    jwtKey: async (header, token) => {
      const jwks = (await current()).jwks;
      if (jwks === undefined || jwks.keys.length === 0) throw new SpiffeError('trust_bundle_invalid', 'trust bundle has no JWT authorities');
      return createLocalJWKSet(jwks)(header, token);
    },
    x509Roots: async () => {
      const roots = (await current()).x509Authorities;
      if (roots === undefined || roots.length === 0) throw new SpiffeError('trust_bundle_invalid', 'trust bundle has no X.509 authorities');
      return [...roots];
    },
  };
}
