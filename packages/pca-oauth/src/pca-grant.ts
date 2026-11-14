/**
 * `pca_grant` for OAuth authorization servers and resource servers (RFC 9396 Rich Authorization Requests).
 *
 * An authorization server (Auth0, Stytch, WorkOS, Descope, Entra ID, Atlas, any RFC 9396 server) that supports a custom
 * authorization-details type can carry a PCA grant without implementing PCA:
 *
 *   1. the client asks for `authorization_details=[{type:"pca_grant", chain_digest, chain_len, ...}]` ({@link pcaGrantRequestParam});
 *   2. the server puts the same array into the access token (JWT claim `authorization_details`, RFC 9396 section 9.1) or
 *      introspection response (section 9.2);
 *   3. the resource server reads it with {@link authorizePcaGrantToken} AND still requires a verified per-action PCActn.
 *
 * The type is a pointer, not authority; see `parsePcaGrantDetails` in `@atlasauth/pca` for the profile rules.
 */

import {
  PCA_GRANT_TYPE,
  checkPcaGrantPresentation,
  parsePcaGrantDetails,
  pcaChainDigest,
  validatePcaGrantDetail,
  type PcaGrantDetail,
  type PcaGrantDetailCode,
  type PcaGrantPresentationCode,
} from '@atlasauth/pca';

export interface BuildPcaGrantDetailOptions {
  /** Capability ids of the chain the grant covers, root first. The digest covers all of them. */
  chainIds: readonly string[];
  chainRef?: string;
  bundleRevision?: number;
  /** Resource servers (RFC 8707 identifiers) the grant is for. */
  locations?: readonly string[];
}

/** Build a validated `pca_grant` detail. Throws on anything the profile would refuse. */
export function buildPcaGrantDetail(o: BuildPcaGrantDetailOptions): PcaGrantDetail {
  const d = {
    type: PCA_GRANT_TYPE,
    chain_digest: pcaChainDigest(o.chainIds),
    chain_len: o.chainIds.length,
    ...(o.chainRef !== undefined ? { chain_ref: o.chainRef } : {}),
    ...(o.bundleRevision !== undefined ? { bundle_revision: o.bundleRevision } : {}),
    ...(o.locations !== undefined ? { locations: [...o.locations] } : {}),
  };
  const r = validatePcaGrantDetail(d);
  if (!r.ok) throw new RangeError(`buildPcaGrantDetail: refused (${r.code})`);
  return r.detail;
}

/** The form-encoded value of the `authorization_details` request parameter (RFC 9396 section 3). */
export function pcaGrantRequestParam(details: readonly PcaGrantDetail[]): string {
  return encodeURIComponent(JSON.stringify(details));
}

export type PcaGrantTokenResult =
  | { allow: true; detail: PcaGrantDetail }
  | { allow: false; status: 401 | 403; error: 'invalid_token' | 'insufficient_scope'; code: PcaGrantDetailCode | PcaGrantPresentationCode };

export interface AuthorizePcaGrantTokenOptions {
  /** The access token's `authorization_details` (JWT claim or introspection field), already authenticated by the caller. */
  authorizationDetails: unknown;
  /** This resource server's identifier. */
  resource: string;
  /** Capability ids of the chain the presented PCActn carries, root first. */
  chainIds: readonly string[];
  /** True only if the per-action PCActn was verified for this call. */
  proofVerified: boolean;
}

/**
 * Gate an OAuth-issued access token that carries `pca_grant` details. Allow only when the details are well formed, name a
 * prefix of the presented chain and this resource, and a verified per-action proof is present. A token that is missing,
 * malformed or names another chain is a 401 `invalid_token`; a good token without a verified proof is a 401 too (the token
 * alone is never sufficient); a token for another location is a 403. This does not authenticate the token.
 */
export function authorizePcaGrantToken(o: AuthorizePcaGrantTokenOptions): PcaGrantTokenResult {
  const parsed = parsePcaGrantDetails(o.authorizationDetails);
  if (!parsed.ok) return { allow: false, status: 401, error: 'invalid_token', code: parsed.code };
  const r = checkPcaGrantPresentation(parsed.details, { resource: o.resource, chainIds: o.chainIds, proofVerified: o.proofVerified });
  if (r.allow) return r;
  return { allow: false, status: r.code === 'wrong_location' ? 403 : 401, error: r.code === 'wrong_location' ? 'insufficient_scope' : 'invalid_token', code: r.code };
}

// ---- scopes derived from the confirmed action (K6 item 31, the OAuth scope side) -----------------------------------

import { deriveActionScopes, type ScopeAction, type ScopeDerivation } from '@atlasauth/pca';

export type OAuthScopeRequest = { ok: true; scope: string; scopes: string[]; resource?: string } | { ok: false; code: Extract<ScopeDerivation, { ok: false }>['code'] };

/**
 * The `scope` (and `resource`, RFC 8707) an OAuth client should request for one action: the confirmed action's `upstream.scopes_min`,
 * checked against the scopes the grant or connection allows. An unconfirmed or unknown action, a provider mismatch or a scope
 * outside the grant yields a refusal and nothing is requested. Token lifetime and proxying are the vault's business (K7).
 */
export function oauthScopeForAction(action: ScopeAction | undefined, o: { provider: string; granted?: readonly string[]; resource?: string }): OAuthScopeRequest {
  const d = deriveActionScopes(action, { provider: o.provider, ...(o.granted !== undefined ? { granted: o.granted } : {}) });
  if (!d.ok) return { ok: false, code: d.code };
  return { ok: true, scope: d.scopes.join(' '), scopes: d.scopes, ...(o.resource !== undefined ? { resource: o.resource } : {}) };
}
