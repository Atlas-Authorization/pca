/**
 * @atlasauth/pca-bbs — BBS signatures (draft-irtf-cfrg-bbs-signatures, BLS12-381-SHA-256) for PCA.
 *
 * Two layers:
 *   - the BBS core ({@link ./bbs}): KeyGen, create_generators, messages_to_scalars, Sign, Verify,
 *     ProofGen, ProofVerify — faithful to the CFRG draft, verified against its test vector;
 *   - the PCA layer ({@link ./credential}): a {@link Capability} issued as a multi-message BBS
 *     credential, then presented with selective disclosure + an unlinkable proof of knowledge.
 */
export * from './bbs';
export * from './credential';
