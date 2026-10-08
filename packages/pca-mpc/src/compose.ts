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

import type { DecisionVector } from './party';

/** The composed, revealed decision. */
export interface ComposedDecision {
  allow: 0 | 1;
  t: 1 | 2 | 3;
  rQuant: number;
}

/** Cleartext composition over the parties' decision vectors. Requires at least one party. */
export function composeClear(vectors: ReadonlyArray<DecisionVector>): ComposedDecision {
  if (vectors.length === 0) throw new Error('composeClear: no parties (fail closed)');
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
