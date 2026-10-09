import { describe, expect, it } from 'vitest';
import { type Agent, agent, generateKeyPair } from '@atlasauth/pca';
import {
  type AccessEvaluationRequest,
  type AccessEvaluationsRequest,
  COAZ_TOOL_PATH,
  EVALUATION_PATH,
  EVALUATIONS_PATH,
  type PdpDecisionContext,
  PCA_ACTION_KEY,
  approvalOf,
  authzenHandler,
  authzenPdp,
  isApprovalRequired,
} from './index';

const AUD = 'rs_test';

/** A stripe-refund agent with a $500/call dollar cap (auto-admits within the cap). */
function stripeAgent(): Agent {
  return agent({
    principal: generateKeyPair(),
    goal: 'reconcile october refunds',
    permissions: { stripe: ['refund'] },
    limits: { refund: '$500' },
    aud: AUD,
  });
}

/** A gmail-send agent on the default (risk) budget — irreversible, high-risk actions need step-up. */
function gmailAgent(): Agent {
  return agent({
    principal: generateKeyPair(),
    goal: 'send october summaries',
    permissions: { gmail: ['send'] },
    aud: AUD,
  });
}

/** A resolver that always hands back one agent's authority. */
function pdpFor(a: Agent, risk?: PdpDecisionContext['risk']) {
  return authzenPdp({
    audience: AUD,
    resolve: (): PdpDecisionContext => ({
      grant: a.grant,
      chain: a.chain,
      policy: a.policy,
      budget: a.budget,
      ...(risk !== undefined ? { risk } : {}),
    }),
  });
}

describe('AuthZEN Access Evaluation → PCA', () => {
  it('maps a verified PCActn under the policy cap to a PCA ALLOW (decision: true)', async () => {
    const a = stripeAgent();
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 42, currency: 'usd' });
    const pdp = pdpFor(a, { blastRadius: 42 / 500 });

    const req: AccessEvaluationRequest = {
      subject: { type: 'agent', id: 'a1' },
      action: { name: 'stripe.refund', properties: { amount: 42, currency: 'usd' } },
      resource: { type: 'charge', id: 'ch_1' },
      context: { [PCA_ACTION_KEY]: encoded },
    };
    const resp = await pdp.evaluate(req);

    expect(resp.decision).toBe(true);
    expect(isApprovalRequired(resp)).toBe(false);
  });

  it('maps an over-cap action to a PCA DENY (policy rejects it) — decision: false', async () => {
    const a = stripeAgent();
    const { encoded } = a.act('stripe.refund', 'charge:ch_2', { amount: 5000, currency: 'usd' });
    const pdp = pdpFor(a);

    const resp = await pdp.evaluate({
      subject: { type: 'agent', id: 'a1' },
      action: { name: 'stripe.refund', properties: { amount: 5000, currency: 'usd' } },
      resource: { type: 'charge', id: 'ch_2' },
      context: { [PCA_ACTION_KEY]: encoded },
    });

    expect(resp.decision).toBe(false);
    expect(isApprovalRequired(resp)).toBe(false); // a hard policy deny, not a step-up
    expect(resp.context?.reason_admin).toMatchObject({ stage: 'policy' });
  });

  it('fails closed when no authority resolves', async () => {
    const pdp = authzenPdp({ resolve: () => null });
    const resp = await pdp.evaluate({
      subject: { type: 'agent', id: 'a1' },
      action: { name: 'stripe.refund' },
      resource: { type: 'charge', id: 'ch_1' },
    });
    expect(resp.decision).toBe(false);
  });

  it('fails closed when the PCActn authorizes a different action than requested', async () => {
    const a = stripeAgent();
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 42, currency: 'usd' });
    const pdp = pdpFor(a);
    // Ask about ch_999 but present a proof for ch_1.
    const resp = await pdp.evaluate({
      subject: { type: 'agent', id: 'a1' },
      action: { name: 'stripe.refund', properties: { amount: 42, currency: 'usd' } },
      resource: { type: 'charge', id: 'ch_999' },
      context: { [PCA_ACTION_KEY]: encoded },
    });
    expect(resp.decision).toBe(false);
  });

  it('fails closed when the request attributes do not match the signed params_digest', async () => {
    const a = stripeAgent();
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 42, currency: 'usd' });
    const pdp = pdpFor(a, { blastRadius: 42 / 500 });
    const resp = await pdp.evaluate({
      subject: { type: 'agent', id: 'a1' },
      action: { name: 'stripe.refund', properties: { amount: 43, currency: 'usd' } }, // tampered amount
      resource: { type: 'charge', id: 'ch_1' },
      context: { [PCA_ACTION_KEY]: encoded },
    });
    expect(resp.decision).toBe(false);
  });

  it('evaluates statically (no PCActn) via the analyzer: admissible → true, inadmissible → false', async () => {
    const a = stripeAgent();
    const pdp = pdpFor(a);
    const base = (amount: number): AccessEvaluationRequest => ({
      subject: { type: 'agent', id: 'a1' },
      action: { name: 'stripe.refund', properties: { amount, reversibility_class: 'reversible' } },
      resource: { type: 'charge', id: 'ch_1' },
    });
    expect((await pdp.evaluate(base(42))).decision).toBe(true);
    expect((await pdp.evaluate(base(5000))).decision).toBe(false);
  });
});

describe('AARP profile — approval required (step-up → FROST/CIBA)', () => {
  it('returns an approval-required response with a pending reference when the Policy-VM needs a co-sign', async () => {
    const a = gmailAgent();
    const { encoded } = a.act('gmail.send', 'thread:re_1', { subject: 'October summary' });
    // High server-side risk forces a step-up tier while the policy still admits the action.
    const pdp = pdpFor(a, { semanticDistance: 1, reversibility: 0, blastRadius: 1, taint: 1, confidence: 0 });

    const resp = await pdp.evaluate({
      subject: { type: 'agent', id: 'a1' },
      action: { name: 'gmail.send', properties: { subject: 'October summary' } },
      resource: { type: 'thread', id: 're_1' },
      context: { [PCA_ACTION_KEY]: encoded },
    });

    expect(resp.decision).toBe(false); // AuthZEN fails safe: not allowed until approved
    expect(isApprovalRequired(resp)).toBe(true);

    const pending = approvalOf(resp);
    expect(pending).not.toBeNull();
    expect(pending?.approval_required).toBe(true);
    expect(pending?.tier).toBe(3); // r > θ2 → tier-3 human co-sign
    expect(pending?.required_threshold.t).toBe(3);
    expect(typeof pending?.auth_req_id).toBe('string');
    expect((pending?.auth_req_id ?? '').length).toBeGreaterThan(0);
    expect(typeof pending?.goal_commit).toBe('string');
  });
});

describe('COAZ profile — MCP-tool authorization (tool → required capability → decision)', () => {
  it('authorizes an MCP tool invocation and echoes the required capability', async () => {
    const a = stripeAgent();
    const pdp = pdpFor(a);

    const resp = await pdp.evaluateTool({
      subject: { type: 'agent', id: 'a1' },
      tool: { name: 'stripe.refund', arguments: { amount: 42, currency: 'usd', reversibility_class: 'reversible' } },
    });

    expect(resp.decision).toBe(true);
    expect(resp.tool).toBe('stripe.refund');
    expect(resp.required_capability).toBe('stripe.refund');
  });

  it('maps a tool name to a capability and denies an out-of-cap argument', async () => {
    const a = stripeAgent();
    const pdp = authzenPdp({
      audience: AUD,
      toolCapability: (name) => (name === 'issue_refund' ? 'stripe.refund' : name),
      resolve: (): PdpDecisionContext => ({ grant: a.grant, chain: a.chain, policy: a.policy, budget: a.budget }),
    });

    const resp = await pdp.evaluateTool({
      subject: { type: 'agent', id: 'a1' },
      tool: { name: 'issue_refund', arguments: { amount: 5000, reversibility_class: 'reversible' } },
    });

    expect(resp.required_capability).toBe('stripe.refund');
    expect(resp.decision).toBe(false);
  });
});

describe('AuthZEN Access Evaluations — boxcar / batch', () => {
  it('evaluates a boxcar with default-inheritance and returns decisions in order', async () => {
    const a = stripeAgent();
    const pdp = pdpFor(a);

    const req: AccessEvaluationsRequest = {
      subject: { type: 'agent', id: 'a1' },
      resource: { type: 'charge', id: 'ch_x' },
      evaluations: [
        { action: { name: 'stripe.refund', properties: { amount: 42, reversibility_class: 'reversible' } } },
        { action: { name: 'stripe.refund', properties: { amount: 5000, reversibility_class: 'reversible' } } },
      ],
    };
    const resp = await pdp.evaluations(req);

    expect(resp.evaluations).toHaveLength(2);
    expect(resp.evaluations[0]?.decision).toBe(true);
    expect(resp.evaluations[1]?.decision).toBe(false);
  });

  it('short-circuits with deny_on_first_deny semantics', async () => {
    const a = stripeAgent();
    const pdp = pdpFor(a);
    const resp = await pdp.evaluations({
      subject: { type: 'agent', id: 'a1' },
      resource: { type: 'charge', id: 'ch_x' },
      options: { evaluations_semantic: 'deny_on_first_deny' },
      evaluations: [
        { action: { name: 'stripe.refund', properties: { amount: 5000, reversibility_class: 'reversible' } } },
        { action: { name: 'stripe.refund', properties: { amount: 42, reversibility_class: 'reversible' } } },
      ],
    });
    expect(resp.evaluations).toHaveLength(1); // stopped after the first deny
    expect(resp.evaluations[0]?.decision).toBe(false);
  });
});

describe('framework-agnostic authzenHandler', () => {
  it('routes the standard paths and fails closed on a malformed body', async () => {
    const a = stripeAgent();
    const handler = authzenHandler(pdpFor(a));

    const ok = await handler({
      path: EVALUATION_PATH,
      body: {
        subject: { type: 'agent', id: 'a1' },
        action: { name: 'stripe.refund', properties: { amount: 42, reversibility_class: 'reversible' } },
        resource: { type: 'charge', id: 'ch_1' },
      },
    });
    expect(ok.status).toBe(200);
    expect('decision' in ok.body && ok.body.decision).toBe(true);

    const bad = await handler({ path: EVALUATION_PATH, body: { nope: true } });
    expect(bad.status).toBe(400);

    const unknown = await handler({ path: '/nope', body: {} });
    expect(unknown.status).toBe(404);

    const batch = await handler({
      path: EVALUATIONS_PATH,
      body: {
        subject: { type: 'agent', id: 'a1' },
        resource: { type: 'charge', id: 'ch_x' },
        evaluations: [{ action: { name: 'stripe.refund', properties: { amount: 42, reversibility_class: 'reversible' } } }],
      },
    });
    expect(batch.status).toBe(200);

    const coaz = await handler({
      path: COAZ_TOOL_PATH,
      body: { subject: { type: 'agent', id: 'a1' }, tool: { name: 'stripe.refund', arguments: { amount: 42, reversibility_class: 'reversible' } } },
    });
    expect(coaz.status).toBe(200);
  });
});
