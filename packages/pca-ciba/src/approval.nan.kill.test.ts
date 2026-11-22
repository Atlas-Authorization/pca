import { describe, expect, it } from 'vitest';
import { agent, generateKeyPair, reviewAction } from '@atlasauth/pca';
import { createDurableCibaBroker } from './index';
import { createCibaBroker, createMemoryApprovalStore } from './testing';

function stepUp() {
  const a = agent({ principal: generateKeyPair(), goal: 'reconcile October refunds', permissions: { stripe: ['payout'] }, limits: { payout: '$100' }, aud: 'ins_test', riskPolicy: { theta1: 0.3, theta2: 0.6 }, now: 0 });
  const r = reviewAction(a, 'stripe.payout', 'acct:1', { amount: 80, currency: 'USD', payee: 'bob' }, { insecureUnboundApproval: true, now: 1, goal: 'reconcile October refunds' });
  if (r.kind !== 'step_up') throw new Error('expected step_up');
  return r.request;
}
const BAD = [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY];

describe('a non-finite clock never reads a session as live (ciba)', () => {
  // pre-fix: `now >= expiresAt` / `now >= decidedAt + ttl` were false for NaN, so the session stayed pending / approved
  it.each(BAD)('durable broker: pending session, clock of %s', async (bad) => {
    const c = { t: 1_000_000 };
    const b = createDurableCibaBroker({ store: createMemoryApprovalStore(), now: () => c.t });
    const req = await b.start(stepUp());
    c.t = bad;
    expect(await b.poll(req.auth_req_id)).toEqual({ status: 'expired' });
  });
  it.each(BAD)('durable broker: approved session, clock of %s', async (bad) => {
    const c = { t: 1_000_000 };
    const b = createDurableCibaBroker({ store: createMemoryApprovalStore(), now: () => c.t });
    const req = await b.start(stepUp());
    await b.resolve(req.auth_req_id, 'approve', 'owner');
    c.t = bad;
    expect((await b.poll(req.auth_req_id)).status).toBe('expired');
  });
  it.each(BAD)('in-memory broker: pending session, clock of %s', async (bad) => {
    const c = { t: 1_000_000 };
    const b = createCibaBroker({ now: () => c.t });
    const req = await b.start(stepUp());
    c.t = bad;
    expect((await b.get(req.auth_req_id))?.status).toBe('expired');
  });
});
