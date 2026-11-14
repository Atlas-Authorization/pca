import { describe, expect, it } from 'vitest';
import { reviewAction, type StepUpRequest } from './approvals';
import { agent } from './facade';
import { generateKeyPair } from './keys';
import type { ApprovalRender } from './approval-render';

const mkAgent = () =>
  agent({
    principal: generateKeyPair(),
    goal: 'process October payouts',
    permissions: { stripe: ['payout'] },
    limits: { payout: '$100' },
    aud: 'ins_test',
    riskPolicy: { theta1: 0.3, theta2: 0.6 },
    now: 0,
  });
const goodRender: ApprovalRender = { v: 1, kind: 'pca-approval-render', verb: 'stripe.payout', def_digest: 'A'.repeat(43), unreviewed: false, fields: [] };
const stepUp = (r: ReturnType<typeof reviewAction>): StepUpRequest => {
  if (r.kind !== 'step_up') throw new Error(`expected step_up, got ${r.kind}`);
  return r.request;
};

describe('reviewAction render handling', () => {
  it('carries neither render nor digest when the unbound path is chosen', () => {
    const req = stepUp(reviewAction(mkAgent(), 'stripe.payout', 'acct:1', { amount: 80 }, { insecureUnboundApproval: true, now: 1 }));
    expect('render' in req).toBe(false);
    expect('renderDigest' in req).toBe(false);
  });
  it('carries both the render and its digest when a renderer is supplied', () => {
    const req = stepUp(reviewAction(mkAgent(), 'stripe.payout', 'acct:1', { amount: 80 }, { renderer: () => goodRender, now: 1 }));
    expect(req.render).toEqual(goodRender);
    expect(typeof req.renderDigest).toBe('string');
  });
  it('names an unknown failure when the renderer throws a non-Error', () => {
    const r = reviewAction(mkAgent(), 'stripe.payout', 'acct:1', { amount: 80 }, { renderer: () => { throw 'nope'; }, now: 1 });
    expect(r).toEqual({ kind: 'deny', reason: 'approval render failed (fail closed): unknown' });
  });
  it('names the Error message when the renderer throws an Error', () => {
    const r = reviewAction(mkAgent(), 'stripe.payout', 'acct:1', { amount: 80 }, { renderer: () => { throw new Error('bad'); }, now: 1 });
    expect(r).toEqual({ kind: 'deny', reason: 'approval render failed (fail closed): bad' });
  });
});
