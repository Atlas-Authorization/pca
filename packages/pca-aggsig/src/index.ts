/**
 * @atlasauth/pca-aggsig — BLS12-381 signature aggregation for Proof-Carrying Authority.
 *
 * A whole delegation chain's per-hop signatures, and a transparency-ledger witness quorum's
 * cosignatures, collapse into ONE compact aggregate signature verified with a single pairing-product
 * check. Scheme: BLS (Boneh-Lynn-Shacham) with Proof-of-Possession (draft-irtf-cfrg-bls-signature),
 * minimal-pubkey-size variant (G1 keys, G2 signatures). See {@link ./bls}.
 */

// Core BLS scheme + aggregation.
export {
  SIG_DST,
  POP_DST,
  PUBLIC_KEY_LENGTH,
  SIGNATURE_LENGTH,
  type BlsKeyPair,
  keyGen,
  publicKeyOf,
  keyValidate,
  sign,
  verify,
  aggregate,
  aggregatePublicKeys,
  aggregateVerify,
  fastAggregateVerify,
  popProve,
  popVerify,
} from './bls';

// PCA BLS-suite capability chain.
export {
  BLS_SUITE,
  MAX_CHAIN_DEPTH,
  type BlsCapability,
  type BlsCapabilityChain,
  capHash,
  blsPublicKey,
  mintBlsRoot,
  blsAttenuate,
  blsDelegate,
  aggregateChainSignatures,
  verifyAggregatedChain,
} from './chain';

// Transparency-ledger witness cosignature aggregation.
export {
  type SthStatement,
  type BlsWitnessCosignature,
  cosignTreeHead,
  verifyWitnessCosignature,
  aggregateWitnessCosignatures,
  verifyAggregatedWitnessCosignatures,
} from './witness';
