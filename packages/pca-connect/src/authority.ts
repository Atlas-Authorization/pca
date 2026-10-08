import type { Capability, CapabilityChain, Caveat } from '@atlasauth/pca';

/**
 * The capability caveat that grants outbound OAuth authority. It is PURE DATA, carried inside the signed
 * capability body like any other PCA caveat, so it is attenuable: because caveats are append-only and
 * conjunctive, a delegation hop may ADD a narrower `oauth_scope` for the same provider, which can only
 * shrink the effective grant (intersection) — never widen it.
 */
export const OAUTH_SCOPE_CAVEAT = 'oauth_scope';

export interface OAuthScopeCaveat extends Caveat {
  type: typeof OAUTH_SCOPE_CAVEAT;
  provider: string;
  scopes: string[];
}

/** Build an `oauth_scope` caveat granting `scopes` on `provider`. Duplicate scopes are collapsed. */
export function oauthScopeCaveat(provider: string, scopes: readonly string[]): OAuthScopeCaveat {
  return { type: OAUTH_SCOPE_CAVEAT, provider, scopes: [...new Set(scopes)] };
}

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === 'string');
}

export function isOAuthScopeCaveat(cv: unknown): cv is OAuthScopeCaveat {
  if (cv === null || typeof cv !== 'object') return false;
  if (!('type' in cv) || !('provider' in cv) || !('scopes' in cv)) return false;
  return cv.type === OAUTH_SCOPE_CAVEAT && typeof cv.provider === 'string' && isStringArray(cv.scopes);
}

/**
 * The effective OAuth scopes a verified capability chain grants for `provider`.
 *
 * Returns the INTERSECTION of every `oauth_scope` caveat naming `provider` in the chain's leaf (the leaf
 * carries the full append-only caveat list, so this covers every hop). Returns `null` when the chain
 * grants NOTHING for `provider` — i.e. no `oauth_scope` caveat names it — so the vault can fail closed
 * and distinguish "provider not covered" (not_authorized) from "covered but scopes too narrow"
 * (scope_exceeded). Run `verifyChain`/`verifyPCActnCore` first; this only reads the (signed) caveat lineage.
 */
export function grantedOAuthScopes(chain: CapabilityChain, provider: string): Set<string> | null {
  if (!Array.isArray(chain) || chain.length === 0) return null;
  const leaf: Capability | undefined = chain[chain.length - 1];
  if (leaf === undefined || !Array.isArray(leaf.caveats)) return null;
  let effective: Set<string> | null = null;
  for (const cv of leaf.caveats) {
    if (!isOAuthScopeCaveat(cv) || cv.provider !== provider) continue;
    const here = new Set<string>(cv.scopes);
    if (effective === null) {
      effective = here;
    } else {
      const intersection = new Set<string>();
      for (const s of effective) if (here.has(s)) intersection.add(s);
      effective = intersection;
    }
  }
  return effective;
}
