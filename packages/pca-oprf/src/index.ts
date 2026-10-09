/**
 * `@atlasauth/pca-oprf` — RFC 9497 OPRF/VOPRF/POPRF on `ristretto255-SHA-512`, plus a PSI-style
 * private-membership layer for Proof-Carrying Authority:
 *
 *  - **Private revocation checks** — query the revocation set without revealing which capability.
 *  - **Private rate-limiting** — count/limit per `(identifier, window)` without seeing the identifier.
 *
 * `oprf.ts` is the pure ciphersuite; `pca.ts` is the PCA mapping built on top of it.
 */

export * from './oprf';
export * from './pca';
