import { describe, expect, it } from 'vitest';
import {
  applyCosign,
  approveClass,
  batchReview,
  classApprovalCovers,
  coveredByAny,
  recordDecision,
  pendingRequests,
  reviewAction,
  timeBox,
} from './approvals';
import { agent } from './facade';
import { generateKeyPair } from './keys';
import { verifyChain } from './capability';
import { verifyPCActnCore } from './pcactn';

const AUD = 'ins_test';
// $100 payout cap, irreversible → anything over budget forces a human (tier 3). Use payout so t can exceed 1.
const mkAgent = () =>
  agent({
    principal: generateKeyPair(),
    goal: 'process October payouts',
    permissions: { stripe: ['payout'] },
    limits: { payout: '$100' },
    aud: AUD,
    // risk weights that create a step-up band: blast radius dominates, theta2 < 1 so big payouts need a human.
    riskPolicy: { theta1: 0.3, theta2: 0.6 },
    now: 0,
  });

describe('reviewAction', () => {
  it('auto-admits a small action, denies an ungranted/over-cap one, steps up a risky one', () => {
    const a = mkAgent();
    // within cap + low risk → auto
    expect(reviewAction(a, 'stripe.payout', 'acct:1', { amount: 10 }, { now: 1 }).kind).toBe('auto');
    // over the $100 per-call ceiling → hard deny (predicate)
    expect(reviewAction(a, 'stripe.payout', 'acct:1', { amount: 500 }, { now: 1 }).kind).toBe('deny');
    // ungranted verb → deny
    expect(reviewAction(a, 'stripe.refund', 'charge:1', { amount: 1 }, { now: 1 }).kind).toBe('deny');
    // mid-size payout (r between theta1 and theta2) → step_up tier 2+
    const r = reviewAction(a, 'stripe.payout', 'acct:1', { amount: 80 }, { now: 1, goal: 'process October payouts' });
    expect(r.kind).toBe('step_up');
    if (r.kind === 'step_up') {
      expect(r.request.tier).toBeGreaterThanOrEqual(2);
      expect(r.request.goalCommit).not.toBe(''); // goal-lineage present
      expect(r.request.goal).toBe('process October payouts');
      expect(r.request.id).toMatch(/^[A-Za-z0-9_-]+$/);
    }
  });

  it('a standing class approval downgrades a matching step-up to auto', () => {
    const a = mkAgent();
    const before = reviewAction(a, 'stripe.payout', 'acct:1', { amount: 80 }, { now: 1 });
    expect(before.kind).toBe('step_up');
    const standing = [approveClass(['stripe.payout'], { ttlMs: 4 * 3_600_000, by: 'owner@acme', now: 1 })];
    const after = reviewAction(a, 'stripe.payout', 'acct:1', { amount: 80 }, { now: 2, standing });
    expect(after.kind).toBe('auto');
  });
});

describe('batchReview + pendingRequests', () => {
  it('reviews a batch and extracts only the ones needing a human', () => {
    const a = mkAgent();
    const reviews = batchReview(
      a,
      [
        { verb: 'stripe.payout', resource: 'acct:1', params: { amount: 5 } }, // auto
        { verb: 'stripe.payout', resource: 'acct:2', params: { amount: 80 } }, // step_up
        { verb: 'stripe.payout', resource: 'acct:3', params: { amount: 999 } }, // deny
      ],
      { now: 1 },
    );
    expect(reviews.map((r) => r.kind)).toEqual(['auto', 'step_up', 'deny']);
    expect(pendingRequests(reviews)).toHaveLength(1);
  });
});

describe('class approvals', () => {
  it('cover respects verb set, resource matcher and ttl window', () => {
    const ap = approveClass(['stripe.payout'], { ttlMs: 1000, by: 'o', now: 100, resource: 'acct:*' });
    expect(classApprovalCovers(ap, 'stripe.payout', 'acct:1', 500)).toBe(true);
    expect(classApprovalCovers(ap, 'stripe.payout', 'other:1', 500)).toBe(false); // resource mismatch
    expect(classApprovalCovers(ap, 'gmail.send', 'acct:1', 500)).toBe(false); // verb not covered
    expect(classApprovalCovers(ap, 'stripe.payout', 'acct:1', 2000)).toBe(false); // expired
    expect(classApprovalCovers(ap, 'stripe.payout', 'acct:1', 50)).toBe(false); // before grant
    expect(coveredByAny([ap], 'stripe.payout', 'acct:1', 500)).toBe(true);
  });
});

describe('decisions + budget', () => {
  it('records a decision and a human co-sign recharges the budget', () => {
    const a = mkAgent();
    const r = reviewAction(a, 'stripe.payout', 'acct:1', { amount: 80 }, { now: 1 });
    if (r.kind !== 'step_up') throw new Error('expected step_up');
    const d = recordDecision(r.request, 'approve', 'owner@acme', 5);
    expect(d).toEqual({ requestId: r.request.id, decision: 'approve', by: 'owner@acme', at: 5 });

    const drained: typeof a.budget = { B: 10, tau: 0, asOf: 0 };
    const partial = applyCosign(drained, a.policy.riskPolicy, 10);
    expect(partial.B).toBeGreaterThan(10); // ρ recharge
    const full = applyCosign(drained, a.policy.riskPolicy, 10, { full: true });
    expect(full.B).toBe(a.policy.riskPolicy.bMax);
  });
});

describe('timeBox', () => {
  it('appends an expires caveat and the narrowed chain still verifies + actions still sign', async () => {
    const a = mkAgent();
    const boxed = timeBox(a.grant, a.holder.secretKey, 3_600_000, 1_000);
    expect(boxed.caveats.some((c) => c.type === 'expires' && Number((c as Record<string, unknown>).at) === 1_000 + 3_600_000)).toBe(true);
    // the boxed capability is a child of the grant → chain [grant, boxed] verifies to the same root
    const chain = [a.grant, boxed];
    expect(verifyChain(chain, a.principalPublic).ok).toBe(true);
  });
});
