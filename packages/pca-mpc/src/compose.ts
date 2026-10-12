/**
 * Composition semantics (the "meet" of stakeholder authorities) and the CLEARTEXT reference.
 *
 * Composition is deliberately conservative — it can only ever TIGHTEN, never loosen, matching PCA's
 * fail-closed philosophy:
 *   - allow  = AND over parties  (every stakeholder must admit; one deny => composed deny)
 *   - t      = MAX over parties  (the strictest required proof strength wins)
 *   - rQuant = MAX over parties  (the highest assessed risk wins)
 *
 * The secure runner (`runner.ts`) computes EXACTLY this function under MPC; `composeClear` is the
 * ground truth the correctness tests check it against.
 */

import { DEFAULT_Q, type DecisionVector } from './party';

/** The composed, revealed decision. */
export interface ComposedDecision {
  allow: 0 | 1;
  t: 1 | 2 | 3;
  rQuant: number;
}

/**
 * Reject a malformed decision vector. The composition is only meaningful for `allow ∈ {0,1}`,
 * `t ∈ {1,2,3}` and an integer `rQuant ∈ [0,Q]`: e.g. two parties both sending `allow = -1` multiply to
 * `+1` under the shared AND (an invalid pair would ALLOW), and the cleartext reference treated any
 * non-zero `allow` as an allow.
 */
export function assertDecisionVectors(vectors: ReadonlyArray<DecisionVector>, Q: number): void {
  if (!Array.isArray(vectors)) throw new TypeError('decision vectors must be an array');
  for (const [i, v] of vectors.entries()) {
    if (v === null || typeof v !== 'object') throw new TypeError(`party ${i}: decision vector must be an object`);
    if (v.allow !== 0 && v.allow !== 1) throw new RangeError(`party ${i}: allow must be 0 or 1`);
    if (v.t !== 1 && v.t !== 2 && v.t !== 3) throw new RangeError(`party ${i}: t must be 1, 2 or 3`);
    if (!Number.isInteger(v.rQuant) || v.rQuant < 0 || v.rQuant > Q) throw new RangeError(`party ${i}: rQuant must be an integer in [0, ${Q}]`);
  }
}

/** Cleartext composition over the parties' decision vectors. Requires at least one party. */
export function composeClear(vectors: ReadonlyArray<DecisionVector>, Q: number = DEFAULT_Q): ComposedDecision {
  if (vectors.length === 0) throw new Error('composeClear: no parties (fail closed)');
  assertDecisionVectors(vectors, Q);
  let allow: 0 | 1 = 1;
  let t: 1 | 2 | 3 = 1;
  let rQuant = 0;
  for (const v of vectors) {
    if (v.allow === 0) allow = 0;
    if (v.t > t) t = v.t;
    if (v.rQuant > rQuant) rQuant = v.rQuant;
  }
  return { allow, t, rQuant };
}
