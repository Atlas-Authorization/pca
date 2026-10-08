import { type PCActn, type RiskPolicy, safetyBound } from '@atlasauth/pca';
import { MAX_RATCHET_DEPTH } from './ggm';
import { RatchetError } from './ratchet';
import { type RiskUnits, AccumulatorError } from './accumulator';

/**
 * Thin adapters that bind the two cryptographic mechanisms to the existing PCA bookkeeping they
 * replace. These map values only — they do NOT modify any @atlasauth/pca core type.
 *
 *  - Mechanism 1 (ratchet)  ↔ the PCActn spend-once `counter`.
 *  - Mechanism 2 (accumulator) ↔ the control-theoretic risk budget (RiskPolicy.bMax / kappa,
 *    whose cumulative bound is `safetyBound` = bMax/κ, i.e. Σrisk ≤ bMax/κ).
 */

// ---- Mechanism 1: ratchet leaf index ↔ PCActn.counter --------------------------------

/**
 * Map a PCActn's spend-once `counter` to a ratchet leaf index. The ratchet replaces the resource
 * server's monotonic-counter check: spending counter `c` signs (and punctures) leaf `c`, so the
 * same counter can never be re-used — "already spent" is enforced by the key no longer existing.
 */
export function counterToLeafIndex(counter: number, depth: number): number {
  if (!Number.isInteger(depth) || depth < 1 || depth > MAX_RATCHET_DEPTH) {
    throw new RatchetError('invalid_depth', `depth must be an integer in [1, ${MAX_RATCHET_DEPTH}]`);
  }
  if (!Number.isSafeInteger(counter) || counter < 0) {
    throw new RatchetError('leaf_out_of_range', 'counter must be a non-negative safe integer');
  }
  if (counter >= 2 ** depth) {
    throw new RatchetError('leaf_out_of_range', `counter ${counter} exceeds the ratchet capacity 2^${depth}`);
  }
  return counter;
}

/** Inverse of {@link counterToLeafIndex}: a leaf index is the spend-once counter it realizes. */
export function leafIndexToCounter(leafIndex: number): number {
  if (!Number.isSafeInteger(leafIndex) || leafIndex < 0) {
    throw new RatchetError('leaf_out_of_range', 'leafIndex must be a non-negative safe integer');
  }
  return leafIndex;
}

/** Convenience: the ratchet leaf index for a PCActn, read straight off its `counter` field. */
export function leafIndexForAction(actn: Pick<PCActn, 'counter'>, depth: number): number {
  return counterToLeafIndex(actn.counter, depth);
}

// ---- Mechanism 2: accumulator units ↔ RiskPolicy budget ------------------------------

/**
 * Fixed-point scale for quantizing the core's continuous risk scores (r ∈ [0,1]) and budget into
 * the integer units the Pedersen accumulator commits to. 1000 = millirisk resolution.
 */
export const RISK_SCALE = 1000;

/** Quantize a core risk score (any finite r ≥ 0) to non-negative integer accumulator units. */
export function riskToUnits(r: number): RiskUnits {
  if (!Number.isFinite(r) || r < 0) {
    throw new AccumulatorError('invalid_value', 'risk must be a finite number >= 0');
  }
  return BigInt(Math.round(r * RISK_SCALE));
}

/**
 * The accumulator's budget ceiling in integer units, derived from a RiskPolicy. This is exactly the
 * core cumulative-risk safety bound Σrisk ≤ bMax/κ (`safetyBound`), quantized — so the zero-knowledge
 * `verifyBudget(..., budgetCeilingUnits(policy), ...)` proves the SAME inequality the control plane
 * enforces, without revealing the per-action risks.
 */
export function budgetCeilingUnits(policy: Pick<RiskPolicy, 'bMax' | 'kappa'>): RiskUnits {
  const bound = safetyBound(policy);
  if (!Number.isFinite(bound) || bound < 0) {
    throw new AccumulatorError('invalid_value', 'safety bound (bMax/kappa) must be finite and >= 0');
  }
  return BigInt(Math.floor(bound * RISK_SCALE));
}
