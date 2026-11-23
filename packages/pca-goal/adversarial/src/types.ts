// The suite's types ARE the canonical Goal IR (packages/pca-goal/src/ir.ts): re-exported, never mirrored. Type-only, erased at runtime.
import type { Decision, Value, Witness } from '../../src/ir';
export type * from '../../src/ir';
export type Atom = Extract<Value, { k: 'q' | 's' }>;
export type Verdict = { decision: Decision; witness: Witness | null };
