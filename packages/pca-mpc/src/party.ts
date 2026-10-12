/**
 * Per-stakeholder local evaluation. Each party (user, org, regulator, ...) runs ITS OWN Policy VM
 * locally and distills the result to a tiny DECISION VECTOR — the only thing that enters the MPC.
 * The party's policy (its envelope, risk weights, predicates, budget) never leaves its process.
 *
 * We reuse `@atlasauth/pca`'s `decide()` as the per-party Policy VM (read-only; we import it, we do
 * not modify it). The three fields we extract are exactly the ones with a well-defined composition:
 *   - allow  = `releaseGuardianShare`  (this party admits the action at all)
 *   - t      = `requiredThreshold.t`   (the proof strength this party demands: 1|2|3)
 *   - rQuant = quantize(`r`)           (this party's risk score, quantized to {0..Q})
 */

import { decide, type DecideInput } from '@atlasauth/pca';

/** Granularity of the r-quantization. r in [0,1] maps to an integer bucket in {0..Q}. */
export const DEFAULT_Q = 100;

/** A stakeholder and its PRIVATE Policy-VM input (never shared with other parties). */
export interface PartyPolicy {
  /** Human-readable id (e.g. "user", "org", "regulator"); for labelling only. */
  id: string;
  /** The party's own `@atlasauth/pca` decision input: its envelope, risk inputs, budget, etc. */
  decideInput: DecideInput;
}

/** The small, composable decision a party contributes to the MPC. */
export interface DecisionVector {
  /** 1 = this party admits the action; 0 = this party denies. */
  allow: 0 | 1;
  /** Proof-strength threshold this party requires. */
  t: 1 | 2 | 3;
  /** Risk score quantized to {0..Q}. */
  rQuant: number;
}

/** Quantize r in [0,1] to an integer in {0..Q}. Non-finite => worst case (Q). */
export function quantizeR(r: number, Q: number = DEFAULT_Q): number {
  if (!Number.isFinite(r)) return Q;
  const q = Math.round(Math.max(0, Math.min(1, r)) * Q);
  return Math.max(0, Math.min(Q, q));
}

/**
 * Evaluate a party's own policy to its decision vector, reusing the PCA Policy VM. Pure: `decide` is
 * total and never throws, so this never throws. The returned vector is the party's PRIVATE input to
 * the composition.
 */
export function evaluateParty(policy: PartyPolicy, Q: number = DEFAULT_Q): DecisionVector {
  const d = decide(policy.decideInput);
  return {
    allow: d.releaseGuardianShare ? 1 : 0,
    t: d.requiredThreshold.t,
    rQuant: quantizeR(d.r, Q),
  };
}
