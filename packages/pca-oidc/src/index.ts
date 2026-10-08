/**
 * `@atlasauth/pca-oidc` — root a Proof-Carrying Authority grant in a real OIDC-authenticated human.
 *
 *   discoverOidc(issuer)    → the provider's metadata (`jwks_uri`, endpoints).
 *   verifyIdToken(idToken)  → the verified ID-token claims (signature + iss/aud/exp/iat/nonce/azp).
 *   oidcPrincipal(claims)   → a PCA principal descriptor: a subject caveat + the b64u Ed25519 key the
 *                             capability chain roots at (when the token binds one via `cnf`).
 *
 * Typical flow:
 *
 *   const claims    = await verifyIdToken(idToken, { issuer, audience, key, nonce });
 *   const principal = oidcPrincipal(claims);                 // principal.principalPublic + subjectCaveat
 *   const { grant } = mintGrant({                            // from @atlasauth/pca
 *     principalSecret, principalPublic: principal.principalPublic!, holder,
 *     goal, envelope: { ..., caveats: [principal.subjectCaveat, ...] },
 *   });
 *   // verifyChain([grant, ...], principal.principalPublic)  anchors the chain in the OIDC human.
 */
export { discoverOidc, discoveryUrl, OidcDiscoveryError } from './discovery';
export type { DiscoverOidcOptions, OidcProviderMetadata } from './discovery';

export { verifyIdToken, OidcVerificationError, DEFAULT_ID_TOKEN_ALGS } from './verify';
export type {
  OidcConfirmation,
  OidcIdTokenClaims,
  OidcVerificationErrorCode,
  OidcVerifyKey,
  VerifyIdTokenOptions,
} from './verify';

export { oidcPrincipal, isOidcSubjectCaveat, OIDC_SUBJECT_CAVEAT } from './principal';
export type { OidcPrincipal, OidcPrincipalOptions, OidcSubjectCaveat } from './principal';
