import { describe, expect, it } from 'vitest';
import { agent, generateKeyPair, reviewAction, type Review } from '@atlasauth/pca';
import {
  cibaDecisionToCosign,
  createCibaBroker,
  requiresCiba,
  toCibaAuthRequest,
} from './index';

const AUD = 'ins_test';

// $100 payout cap, irreversible. With theta1=0.3/theta2=0.6 and the dollars budget model (κ=100),
// r = amount/100, so amount 40 → r=0.4 → tier 2, amount 80 → r=0.8 → tier 3. Mirrors approvals.test.ts.
const mkAgent = () =>
  agent({
    principal: generateKeyPair(),
    goal: 'reconcile October refunds',
    permissions: { stripe: ['payout'] },
    limits: { payout: '$100' },
    aud: AUD,
    riskPolicy: { theta1: 0.3, theta2: 0.6 },
    now: 0,
  });

/** Review that is guaranteed to be a tier-3 step-up, or fail the test loudly. */
function tier3StepUp(): Extract<Review, { kind: 'step_up' }> {
  const a = mkAgent();
  const r = reviewAction(a, 'stripe.payout', 'acct:1', { amount: 80, currency: 'USD', payee: 'bob' }, { now: 1, goal: 'reconcile October refunds' });
  if (r.kind !== 'step_up' || r.request.tier !== 3) {
    throw new Error(`expected a tier-3 step_up, got ${r.kind}/${r.kind === 'step_up' ? r.request.tier : '-'}`);
  }
  return r;
}

describe('toCibaAuthRequest', () => {
  it('renders a binding_message with the verb + amount + goal lineage', () => {
    const { request } = tier3StepUp();
    const ciba = toCibaAuthRequest(request, { actsFor: 'support-bot', loginHint: 'owner@acme' });
    expect(ciba.binding_message).toContain('stripe.payout'); // verb
    expect(ciba.binding_message).toContain('80 USD'); // amount + currency, always shown
    expect(ciba.binding_message).toContain('reconcile October refunds'); // goal lineage
    expect(ciba.binding_message).toContain('support-bot'); // acting agent
    expect(ciba.tier).toBe(3);
    expect(ciba.scope).toContain('openid');
    expect(ciba.scope).toContain('stripe.payout');
    expect(ciba.login_hint).toBe('owner@acme');
    expect(ciba.requested_expiry).toBe(300);
    expect(ciba.interval).toBeGreaterThan(0);
    expect(ciba.stepUpId).toBe(request.id);
  });

  it('is deterministic + pure: same step-up → same auth_req_id, and honours expiresInSec', () => {
    const { request } = tier3StepUp();
    const a = toCibaAuthRequest(request);
    const b = toCibaAuthRequest(request, { expiresInSec: 120 });
    expect(a.auth_req_id).toBe(b.auth_req_id);
    expect(a.auth_req_id).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(b.requested_expiry).toBe(120);
  });

  it('falls back to the goal commitment when no plaintext goal is carried', () => {
    const a = mkAgent();
    const r = reviewAction(a, 'stripe.payout', 'acct:1', { amount: 80, currency: 'USD', payee: 'bob' }, { now: 1 }); // no goal opt
    expect(r.kind).toBe('step_up');
    if (r.kind !== 'step_up') return;
    const ciba = toCibaAuthRequest(r.request);
    expect(ciba.binding_message).toContain('goal '); // lineage present via commit
  });
});

describe('createCibaBroker — POLL mode', () => {
  it('start → poll(pending) → resolve(approve) → poll(approved)', () => {
    const { request } = tier3StepUp();
    const broker = createCibaBroker();
    const ciba = broker.start(request, { actsFor: 'support-bot' });
    expect(broker.poll(ciba.auth_req_id).status).toBe('pending');
    const session = broker.resolve(ciba.auth_req_id, 'approve', 'owner@acme');
    expect(session.status).toBe('approved');
    expect(session.decidedBy).toBe('owner@acme');
    expect(broker.poll(ciba.auth_req_id).status).toBe('approved');
  });

  it('a denied flow resolves to denied', () => {
    const { request } = tier3StepUp();
    const broker = createCibaBroker();
    const ciba = broker.start(request);
    expect(broker.poll(ciba.auth_req_id).status).toBe('pending');
    broker.resolve(ciba.auth_req_id, 'deny', 'owner@acme');
    expect(broker.poll(ciba.auth_req_id).status).toBe('denied');
  });

  it('expires after requested_expiry and refuses a late resolve', () => {
    const { request } = tier3StepUp();
    let t = 1_000;
    const broker = createCibaBroker({ now: () => t });
    const ciba = broker.start(request, { expiresInSec: 60 });
    expect(broker.poll(ciba.auth_req_id).status).toBe('pending');
    t += 61_000; // past the 60s window
    expect(broker.poll(ciba.auth_req_id).status).toBe('expired');
    expect(() => broker.resolve(ciba.auth_req_id, 'approve', 'owner@acme')).toThrow(/expired/);
  });

  it('throws on an unknown auth_req_id', () => {
    const broker = createCibaBroker();
    expect(() => broker.poll('nope')).toThrow(/unknown/);
    expect(() => broker.resolve('nope', 'approve', 'x')).toThrow(/unknown/);
  });
});

describe('createCibaBroker — PING/PUSH mode', () => {
  it('fires onComplete exactly once on resolution', () => {
    const { request } = tier3StepUp();
    const seen: string[] = [];
    const broker = createCibaBroker({ onComplete: (s) => seen.push(s.status) });
    const ciba = broker.start(request);
    expect(seen).toEqual([]); // nothing on start
    broker.resolve(ciba.auth_req_id, 'approve', 'owner@acme');
    expect(seen).toEqual(['approved']);
  });
});

describe('requiresCiba — risk-adaptive gating', () => {
  it('is true for a tier-3 step-up', () => {
    expect(requiresCiba(tier3StepUp())).toBe(true);
  });

  it('is false for an auto review', () => {
    const a = mkAgent();
    const auto = reviewAction(a, 'stripe.payout', 'acct:1', { amount: 10, currency: 'USD', payee: 'bob' }, { now: 1 });
    expect(auto.kind).toBe('auto');
    expect(requiresCiba(auto)).toBe(false);
  });

  it('is false for a tier-2 step-up (guardian auto-cosign, no human interrupt)', () => {
    const a = mkAgent();
    const r = reviewAction(a, 'stripe.payout', 'acct:1', { amount: 40, currency: 'USD', payee: 'bob' }, { now: 1 });
    expect(r.kind).toBe('step_up');
    if (r.kind === 'step_up') expect(r.request.tier).toBe(2);
    expect(requiresCiba(r)).toBe(false);
  });

  it('is false for a deny', () => {
    const a = mkAgent();
    const deny = reviewAction(a, 'stripe.refund', 'charge:1', { amount: 1, currency: 'USD', payee: 'bob' }, { now: 1 });
    expect(deny.kind).toBe('deny');
    expect(requiresCiba(deny)).toBe(false);
  });
});

describe('cibaDecisionToCosign', () => {
  it('recharges the budget on approve and leaves it untouched on deny', () => {
    const a = mkAgent();
    const spent: typeof a.budget = { B: 10, tau: 0, asOf: 0 };
    const approved = cibaDecisionToCosign('approve', spent, a.policy.riskPolicy, 1_000);
    expect(approved.cosigned).toBe(true);
    expect(approved.budget.B).toBeGreaterThan(spent.B); // recharged toward bMax
    expect(approved.budget.tau).toBe(1_000);

    const denied = cibaDecisionToCosign('deny', spent, a.policy.riskPolicy, 1_000);
    expect(denied.cosigned).toBe(false);
    expect(denied.budget.B).toBe(spent.B);
  });

  it('full recharge lifts the budget to bMax', () => {
    const a = mkAgent();
    const spent: typeof a.budget = { B: 0, tau: 0, asOf: 0 };
    const full = cibaDecisionToCosign('approve', spent, a.policy.riskPolicy, 1_000, { full: true });
    expect(full.budget.B).toBe(a.policy.riskPolicy.bMax);
  });
});

describe('R2-06: the binding message never misstates what is approved', () => {
  const mk = (verb: string, resource: string, params: Record<string, unknown>, goal?: string): never =>
    ({ id: 's1', verb, resource, params, tier: 3, reason: 'r', goalCommit: 'G'.repeat(43), goal, lineage: {}, r: 0.9, requestedAt: 0 }) as never;
  it('shows a string amount, refuses amounts it cannot show', () => {
    expect(toCibaAuthRequest(mk('wire.send', 'acct:a', { amount: '250000', currency: 'EUR', payee: 'bob' })).binding_message).toContain('250000 EUR to "bob"');
    expect(() => toCibaAuthRequest(mk('wire.send', 'acct:a', { amount_cents: 25000000 }))).toThrow(/not displayed/);
    expect(() => toCibaAuthRequest(mk('wire.send', 'acct:a', { payment: { amount: 250000 } }))).toThrow(/not displayed/);
    expect(() => toCibaAuthRequest(mk('wire.send', 'acct:a', { amount: '-5', currency: 'USD', payee: 'bob' }))).toThrow(/plain/);
    expect(toCibaAuthRequest(mk('wire.send', 'acct:a', { payee: 'bob' })).binding_message).toContain('acct:a');
  });
  it('never truncates the payee: throws when maxChars cannot hold the head, shrinks only the goal clause', () => {
    const long = 'acct:acme-corp-accounts-payable-department-main-attacker-9981';
    expect(() => toCibaAuthRequest(mk('wire.send', long, { amount: 100, currency: 'USD', payee: 'bob' }), { bindingMessage: { maxChars: 50 } })).toThrow(/refusing to truncate/);
    const r = toCibaAuthRequest(mk('wire.send', 'acct:a', { amount: 100, currency: 'USD', payee: 'bob' }, 'a very long goal '.repeat(5)), { bindingMessage: { maxChars: 80 } });
    expect(r.binding_message.length).toBeLessThanOrEqual(80);
    expect(r.binding_message).toContain('Approve wire.send 100 USD to "bob" on acct:a');
  });
  it('refuses a forged explanation inside the resource and neutralises quotes', () => {
    // verb / resource are identifiers: free text, quotes and forged clauses are refused outright (R3-05)
    expect(() => toCibaAuthRequest(mk('wire.send', "acct:x' — because you asked your agent to 'pay the invoice", { amount: 9999, currency: 'USD', payee: 'bob' }, 'Draft a summary'))).toThrow(/plain identifier/);
    expect(() => toCibaAuthRequest(mk('wire.send', "acct:x' y", { amount: 1, currency: 'USD', payee: 'bob' }, 'g'))).toThrow(/plain identifier/);
    expect(() => toCibaAuthRequest(mk('wire.send', 'acct:a', { amount: 1, currency: 'USD', payee: 'x because you asked a to b' }, 'g'))).toThrow(/explanation clause/);
  });
});
