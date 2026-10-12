/**
 * @atlasauth/pca-ratchet — the PCA Capability Ratchet.
 *
 * Two original cryptographic primitives that replace PCA bookkeeping with cryptography:
 *
 *  1. Puncturable forward-secure capability keys (ratchet.ts): a GGM puncturable-PRF tree of
 *     one-time Ed25519 keys under a Merkle-root commitment. Signing a leaf permanently punctures
 *     it — cryptographic one-time-use for the PCActn spend-once counter.
 *
 *  2. Homomorphic risk accumulator (accumulator.ts): Pedersen commitments on ristretto255 with a
 *     zero-knowledge range proof that the committed aggregate stays under the control-theoretic
 *     budget ceiling (Σrisk ≤ bMax/κ) without revealing individual risks.
 *
 * adapters.ts binds both to the @atlasauth/pca core (PCActn.counter, RiskPolicy budget) without
 * modifying it.
 */

export {
  type RatchetErrorCode,
  type RatchetSignature,
  type RatchetState,
  RatchetError,
  deriveRatchetRoot,
  signAtLeaf,
  verifyLeafSignature,
  leafNullifier,
  availableLeaves,
  isLeafAvailable,
} from './ratchet';

export { MAX_RATCHET_DEPTH } from './ggm';

export {
  type AccumulatorErrorCode,
  type RiskUnits,
  type RiskCommitment,
  type BitOrProof,
  type SchnorrProof,
  type BudgetProof,
  N_BITS,
  MAX_PROVABLE_CEILING,
  type RiskRangeProof,
  AccumulatorError,
  commitRisk,
  addCommitments,
  openCommitment,
  proveBudget,
  verifyBudget,
  proveRiskRange,
  verifyRiskRange,
  verifyBoundedBudget,
} from './accumulator';

export {
  RISK_SCALE,
  counterToLeafIndex,
  leafIndexToCounter,
  leafIndexForAction,
  riskToUnits,
  RiskQuantizer,
  budgetCeilingUnits,
} from './adapters';

export {
  type SpentLeafStore,
  type LeafUseResult,
  type RiskAttestation,
  memorySpentLeafStore,
  verifyLeafSignatureOnce,
  issueRiskCommitment,
  verifyRiskAttestation,
  verifyAttestedBudget,
} from './binding';
