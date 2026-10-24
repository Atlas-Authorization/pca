/**
 * Mutation kills for the Intent Layer M2 binding (intent-binding.ts): every boundary, negation and branch of the wire
 * rule, the policy activation, the root-grant lookup and the threshold comparisons is pinned by an accept/reject pair.
 */
import { describe, expect, it } from 'vitest';
import {
  ENVELOPE_INTENT_FIELDS,
  INTENT_GOAL_PREFIX,
  MAX_INTENT_GOAL_SALT_LEN,
  PPM_ONE,
  decideIntentBinding,
  intentGoal,
  intentGoalCommit,
  intentPolicyActive,
  parseIntentGoal,
  rootGoalCommit,
  validateIntentWire,
  type EnvelopeIntent,
} from './intent-binding';
import { b64u } from './hash';
import { goalCommitOf } from './envelope';

const D1 = b64u(new Uint8Array(32).fill(1));
const D2 = b64u(new Uint8Array(32).fill(2));
const I: EnvelopeIntent = { ref: D1, map_digest: D2, goal_salt: 's', fidelity_ppm: 500_000, residual_risk_ppm: 10 };
const env = (goal_commit: unknown) => ({ type: 'envelope', goal_commit });
const G = { caveats: [env(intentGoalCommit(I))] };
const st = (i: EnvelopeIntent | undefined, g: unknown = G, p?: Parameters<typeof decideIntentBinding>[2]) => decideIntentBinding(i, g, p).status;

describe('intent-binding: constants and goal helpers', () => {
  it('constants', () => {
    expect(PPM_ONE).toBe(1_000_000);
    expect(MAX_INTENT_GOAL_SALT_LEN).toBe(128);
    expect([...ENVELOPE_INTENT_FIELDS]).toEqual(['ref', 'map_digest', 'goal_salt', 'fidelity_ppm', 'residual_risk_ppm']);
    expect(INTENT_GOAL_PREFIX).toBe('pca-intent:v1:');
  });
  it('intentGoal / parseIntentGoal', () => {
    expect(intentGoal('r')).toBe('pca-intent:v1:r');
    expect(intentGoal('r', 'm')).toBe('pca-intent:v1:r:m');
    expect(intentGoal('r', '')).toBe('pca-intent:v1:r');
    expect(parseIntentGoal('pca-intent:v1:r')).toEqual({ intentRef: 'r' });
    expect(parseIntentGoal('pca-intent:v1:r:m')).toEqual({ intentRef: 'r', mapDigest: 'm' });
    expect(parseIntentGoal('pca-intent:v1:r:m:x')).toBeNull();
    expect(parseIntentGoal('pca-intent:v1:')).toBeNull();
    expect(parseIntentGoal('pca-intent:v2:r')).toBeNull();
    expect(parseIntentGoal(7 as never)).toBeNull();
  });
  it('the commit is the envelope goal commitment of intentGoal(ref, map_digest)', () => {
    expect(intentGoalCommit(I)).toBe(goalCommitOf(intentGoal(D1, D2), 's'));
    expect(intentGoalCommit({ ...I, goal_salt: 't' })).not.toBe(intentGoalCommit(I));
  });
});

describe('intent-binding: wire', () => {
  const W = (x: unknown) => validateIntentWire(x);
  it('accepts the canonical shape and the range edges', () => {
    expect(W(I)).toBeNull();
    expect(W({ ...I, fidelity_ppm: 0 })).toBeNull();
    expect(W({ ...I, fidelity_ppm: 1_000_000 })).toBeNull();
    expect(W({ ...I, residual_risk_ppm: 0 })).toBeNull();
    expect(W({ ...I, residual_risk_ppm: Number.MAX_SAFE_INTEGER })).toBeNull();
    expect(W({ ...I, goal_salt: 'é'.repeat(64) })).toBeNull(); // 128 UTF-8 bytes
    expect(W({ ...I, goal_salt: 'a'.repeat(128) })).toBeNull();
  });
  it('rejects every off-range, mistyped, missing or extra member', () => {
    for (const bad of [
      null, [], 'x', 1, Object.create({ a: 1 }),
      { ...I, extra: 1 },
      { ...I, fidelity_ppm: -1 }, { ...I, fidelity_ppm: 1_000_001 }, { ...I, fidelity_ppm: 0.5 }, { ...I, fidelity_ppm: '1' }, { ...I, fidelity_ppm: true }, { ...I, fidelity_ppm: -0 },
      { ...I, residual_risk_ppm: -1 }, { ...I, residual_risk_ppm: 0.25 }, { ...I, residual_risk_ppm: Number.MAX_SAFE_INTEGER + 1 }, { ...I, residual_risk_ppm: null },
      { ...I, goal_salt: '' }, { ...I, goal_salt: 'é'.repeat(64) + 'a' }, { ...I, goal_salt: 'a'.repeat(129) }, { ...I, goal_salt: 5 },
      { ...I, ref: D1 + '=' }, { ...I, ref: b64u(new Uint8Array(31)) }, { ...I, ref: 1 }, { ...I, map_digest: b64u(new Uint8Array(33)) },
    ]) expect(W(bad), JSON.stringify(bad)).not.toBeNull();
    for (const k of ENVELOPE_INTENT_FIELDS) {
      const x: Record<string, unknown> = { ...I };
      delete x[k];
      expect(W(x), k).toMatch(new RegExp(`missing field 'intent.${k}'`));
    }
    expect(W({ ...I, extra: 1 })).toBe("unknown field 'intent.extra'");
  });
});

describe('intent-binding: policy activation', () => {
  it('active iff require is true or a threshold is set', () => {
    expect(intentPolicyActive(undefined)).toBe(false);
    expect(intentPolicyActive({})).toBe(false);
    expect(intentPolicyActive({ require: false })).toBe(false);
    expect(intentPolicyActive({ require: true })).toBe(true);
    expect(intentPolicyActive({ min_fidelity_ppm: 0 })).toBe(true);
    expect(intentPolicyActive({ max_residual_risk_ppm: 0 })).toBe(true);
    expect(intentPolicyActive({ require: 'yes' as never })).toBe(false);
  });
});

describe('intent-binding: decision', () => {
  it('not reported without the member and without an active policy', () => {
    expect(st(undefined)).toBe('absent');
    expect(st(undefined, G, {})).toBe('absent');
    expect(st(undefined, G, { require: false })).toBe('absent');
  });
  it('an active policy fails an action without the member', () => {
    expect(st(undefined, G, { require: true })).toBe('fail');
    expect(st(undefined, G, { min_fidelity_ppm: 0 })).toBe('fail');
    expect(st(undefined, G, { max_residual_risk_ppm: 10 })).toBe('fail');
  });
  it('binds to the FIRST envelope caveat of the grant only', () => {
    expect(st(I)).toBe('pass');
    expect(st(I, { caveats: [{ type: 'max_spend', usd: 1 }, env(intentGoalCommit(I))] })).toBe('pass');
    expect(st(I, { caveats: ['x', null, [], env(intentGoalCommit(I))] })).toBe('pass'); // non-object caveats are skipped
    expect(st(I, { caveats: [env('decoy'), env(intentGoalCommit(I))] })).toBe('fail');
    expect(st(I, { caveats: [env(7)] })).toBe('fail');
    expect(st(I, { caveats: [] })).toBe('fail');
    expect(st(I, { caveats: 'x' })).toBe('fail');
    expect(st(I, {})).toBe('fail');
    expect(st(I, null)).toBe('fail');
    expect(st({ ...I, ref: D2 })).toBe('fail');
    expect(st({ ...I, map_digest: D1 })).toBe('fail');
    expect(st({ ...I, goal_salt: 't' })).toBe('fail');
    expect(rootGoalCommit(G)).toBe(intentGoalCommit(I));
    expect(rootGoalCommit({ caveats: [{ type: 'envelope' }] })).toBeNull();
  });
  it('thresholds are inclusive and fail one past', () => {
    expect(st(I, G, { min_fidelity_ppm: 500_000 })).toBe('pass');
    expect(st(I, G, { min_fidelity_ppm: 500_001 })).toBe('fail');
    expect(st(I, G, { max_residual_risk_ppm: 10 })).toBe('pass');
    expect(st(I, G, { max_residual_risk_ppm: 9 })).toBe('fail');
    expect(st(I, G, { min_fidelity_ppm: 0, max_residual_risk_ppm: Number.MAX_SAFE_INTEGER })).toBe('pass');
  });
  it('misconfigured thresholds fail closed even for a bound action', () => {
    for (const bad of [-1, 0.5, NaN, Infinity, -0, '1' as never, null as never]) {
      expect(st(I, G, { min_fidelity_ppm: bad }), String(bad)).toBe('fail');
      expect(st(I, G, { max_residual_risk_ppm: bad }), String(bad)).toBe('fail');
    }
  });
  it('reasons name the failing step', () => {
    expect(decideIntentBinding(undefined, G, { require: true })).toEqual({ status: 'fail', reason: 'this verifier requires an intent binding but the PCActn carries none' });
    expect(decideIntentBinding(I, { caveats: [] })).toEqual({ status: 'fail', reason: 'the root grant carries no envelope goal commitment to bind the intent to' });
    expect(decideIntentBinding({ ...I, goal_salt: 't' }, G)).toEqual({ status: 'fail', reason: "intent ref / map_digest / goal_salt do not open the root grant's goal commitment" });
    expect((decideIntentBinding(I, G, { min_fidelity_ppm: -1 }) as { reason: string }).reason).toMatch(/misconfigured/);
    expect((decideIntentBinding(I, G, { min_fidelity_ppm: 500_001 }) as { reason: string }).reason).toMatch(/below the policy minimum 500001/);
    expect((decideIntentBinding(I, G, { max_residual_risk_ppm: 9 }) as { reason: string }).reason).toMatch(/exceeds the policy maximum 9/);
  });
});
