// binding.ts - the decision-to-effect binding (W14) and the claimed-fidelity gate (W2) of goal-to-decision.
import { createHash, timingSafeEqual } from 'node:crypto';
import { hashCanonical, tighten } from '@atlasauth/pca';
import type { Act, Decision } from './ir';

/** Digest of exactly the action that was decided: verb, resource and every parameter. */
export const actionDigest = (a: Act): string => hashCanonical({ d: 'atlas-pca/goal-action/v1', act: a });
export interface BoundDecision { decision: Decision; action_digest: string }
/** Bind a decision to the action it was made for. */
export const bindDecision = (a: Act, decision: Decision): BoundDecision => ({ decision, action_digest: actionDigest(a) });
/** Run guard: true only for an `allow` bound to exactly this action (swapped params or verb, `escalate`, `deny` all refuse). Total. */
export function guardExecute(b: BoundDecision, executed: Act): boolean {
  try {
    if (b.decision !== 'allow') return false;
    const x = Buffer.from(b.action_digest), y = Buffer.from(actionDigest(executed));
    return x.length === y.length && timingSafeEqual(x, y);
  } catch { return false; }
}
/**
 * An agent-claimed fidelity never moves the outcome; only a fidelity the verifier replayed from the committed map and found below
 * the minimum can, and only downward (escalate, via the tighten-only meet), never upward.
 */
export const claimGate = (base: Decision, minPpm: number, _claimedPpm: number, replayedPpm?: number): Decision =>
  replayedPpm !== undefined && !(replayedPpm >= minPpm) ? tighten(base, 'escalate') : base; // a NaN replay is unconfirmed: it tightens

/** Hiding goal commitment (goal binding v3): sha256("pca-goal:v3:commit:<goal>:<policy>:<salt>"), base64url. Matches the shared conformance vectors. */
export const goalCommit = (goalDigest: string, policyDigest: string, salt: string): string =>
  createHash('sha256').update(`pca-goal:v3:commit:${goalDigest}:${policyDigest}:${salt}`).digest('base64url');
/** Constant-time check that `commit` opens to (goal, policy, salt). */
export function openCommit(commit: string, goalDigest: string, policyDigest: string, salt: string): boolean {
  const x = Buffer.from(commit), y = Buffer.from(goalCommit(goalDigest, policyDigest, salt));
  return x.length === y.length && timingSafeEqual(x, y);
}
