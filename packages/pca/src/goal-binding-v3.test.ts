/**
 * Goal binding v3 (goal-to-decision W1): goal_commit = H(goal_digest || policy_digest). Replays the committed vectors
 * (conformance/goal-commit-vectors.json, generated independently by conformance/gen-goal-commit.mjs) against the real
 * implementation, and pins v1/v2 compatibility and every refusal of the v3 rule.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { goalCommitOf } from './envelope';
import { b64u } from './hash';
import {
  INTENT_GOAL_V3_PREFIX,
  decideIntentBinding,
  intentGoal,
  intentGoalCommit,
  intentGoalCommitV3,
  intentGoalV3,
  intentPolicyActive,
  isApprovedGoalRef,
  type EnvelopeIntent,
} from './intent-binding';

interface Doc {
  goal_prefix: string;
  commit: Array<{ name: string; goal_digest: string; policy_digest: string; salt: string; goal: string; commit: string }>;
  invalid: Array<{ name: string; goal_digest: string; policy_digest: string }>;
  binding: Array<{ name: string; grant_commit: string | null; intent: EnvelopeIntent | null; policy: Record<string, unknown>; session?: string; expect: 'pass' | 'fail' }>;
}
const doc = JSON.parse(readFileSync(join(__dirname, '..', 'conformance', 'goal-commit-vectors.json'), 'utf8')) as Doc;
const grantOf = (commit: string | null) => ({ caveats: commit === null ? [] : [{ type: 'envelope', goal_commit: commit }] });

describe('goal binding v3: conformance vectors', () => {
  it('has the expected shape and prefix', () => {
    expect(doc.goal_prefix).toBe(INTENT_GOAL_V3_PREFIX);
    expect(doc.commit.length).toBeGreaterThanOrEqual(7);
    expect(doc.invalid.length).toBeGreaterThanOrEqual(4);
    expect(doc.binding.length).toBeGreaterThanOrEqual(16);
    expect(new Set(doc.commit.map((c) => c.commit)).size).toBe(doc.commit.length); // every input change changes the commitment
  });
  it.each(doc.commit.map((v) => [v.name, v] as const))('commit %s', (_n, v) => {
    const ref = { goal_digest: v.goal_digest, policy_digest: v.policy_digest };
    expect(intentGoalV3(ref)).toBe(v.goal);
    expect(intentGoalCommitV3(ref, v.salt)).toBe(v.commit);
    expect(goalCommitOf(intentGoalV3(ref), v.salt)).toBe(v.commit); // the minting side (envelope.ts) agrees
  });
  it.each(doc.invalid.map((v) => [v.name, v] as const))('invalid digests are refused: %s', (_n, v) => {
    const ref = { goal_digest: v.goal_digest, policy_digest: v.policy_digest };
    expect(isApprovedGoalRef(ref)).toBe(false);
    expect(() => intentGoalV3(ref)).toThrow('canonical base64url');
    expect(() => intentGoalCommitV3(ref, 's')).toThrow();
  });
  it.each(doc.binding.map((v) => [v.name, v] as const))('binding %s', (_n, v) => {
    const r = decideIntentBinding(v.intent ?? undefined, grantOf(v.grant_commit), v.policy as never, v.session);
    expect(r.status).toBe(v.expect);
  });
});

describe('goal binding v3: the rule', () => {
  const GD = b64u(new Uint8Array(32).fill(7));
  const PD = b64u(new Uint8Array(32).fill(8));
  const REF = b64u(new Uint8Array(32).fill(1));
  const MAP = b64u(new Uint8Array(32).fill(2));
  const I: EnvelopeIntent = { ref: REF, map_digest: MAP, goal_salt: 'salt', fidelity_ppm: 1, residual_risk_ppm: 1 };
  const A = { goal_digest: GD, policy_digest: PD };
  const v3grant = grantOf(intentGoalCommitV3(A, 'salt'));

  it('approved_goal makes the intent policy active (an absent intent fails)', () => {
    expect(intentPolicyActive({ approved_goal: A })).toBe(true);
    expect(intentPolicyActive({})).toBe(false);
    expect(decideIntentBinding(undefined, v3grant, { approved_goal: A }).status).toBe('fail');
  });
  it('a v3 grant opens under the matching approved_goal and nothing else', () => {
    expect(decideIntentBinding(I, v3grant, { approved_goal: A })).toEqual({ status: 'pass' });
    expect(decideIntentBinding(I, v3grant, { approved_goal: { ...A, policy_digest: b64u(new Uint8Array(32).fill(9)) } }).status).toBe('fail');
    expect(decideIntentBinding(I, v3grant, { approved_goal: { ...A, goal_digest: b64u(new Uint8Array(32).fill(9)) } }).status).toBe('fail');
    expect(decideIntentBinding({ ...I, goal_salt: 'other' }, v3grant, { approved_goal: A }).status).toBe('fail');
  });
  it('the v3 commitment ignores ref and map_digest (the goal and policy digests carry the meaning)', () => {
    expect(decideIntentBinding({ ...I, ref: b64u(new Uint8Array(32).fill(5)) }, v3grant, { approved_goal: A })).toEqual({ status: 'pass' });
  });
  it('v1 and v2 grants still verify without approved_goal, and are refused under it', () => {
    const v1 = grantOf(intentGoalCommit(I));
    const S = 'sess';
    const v2 = grantOf(intentGoalCommit(I, S));
    expect(intentGoal(REF, MAP)).toBe(`pca-intent:v1:${REF}:${MAP}`);
    expect(decideIntentBinding(I, v1, { require: true })).toEqual({ status: 'pass' });
    expect(decideIntentBinding(I, v2, { require: true }, S)).toEqual({ status: 'pass' });
    expect(decideIntentBinding(I, v1, { approved_goal: A }).status).toBe('fail');
    expect(decideIntentBinding(I, v2, { approved_goal: A }, S).status).toBe('fail');
  });
  it('a v3 grant does not pass a verifier that has no approved_goal', () => {
    expect(decideIntentBinding(I, v3grant, { require: true }).status).toBe('fail');
  });
  it('a misconfigured approved_goal fails closed', () => {
    for (const bad of [{ goal_digest: 'x', policy_digest: PD }, { goal_digest: GD }, { ...A, extra: 1 }, null, 'x', []]) {
      expect(decideIntentBinding(I, v3grant, { approved_goal: bad as never })).toMatchObject({ status: 'fail', reason: expect.stringContaining('misconfigured') });
    }
  });
  it('thresholds still apply on top of the v3 binding', () => {
    expect(decideIntentBinding(I, v3grant, { approved_goal: A, min_fidelity_ppm: 2 }).status).toBe('fail');
    expect(decideIntentBinding(I, v3grant, { approved_goal: A, max_residual_risk_ppm: 0 }).status).toBe('fail');
    expect(decideIntentBinding(I, v3grant, { approved_goal: A, min_fidelity_ppm: 1, max_residual_risk_ppm: 1 })).toEqual({ status: 'pass' });
  });
  it('digest order matters: goal || policy is not policy || goal', () => {
    expect(intentGoalCommitV3(A, 's')).not.toBe(intentGoalCommitV3({ goal_digest: PD, policy_digest: GD }, 's'));
  });
});
