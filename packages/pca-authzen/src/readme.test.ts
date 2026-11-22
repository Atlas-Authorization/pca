import { describe, expect, it } from 'vitest';
import { agent, createAuthorizer, generateKeyPair, memoryPcaStore } from '@atlasauth/pca';
import { BUILTIN_ACTIONS, buildCatalog, defineAction } from '@atlasauth/pca/ext/research';
import { PCA_ACTION_KEY, PCA_PROVENANCE_KEY, authzenHandler, authzenPdp, isApprovalRequired } from './index';

// the built-in stripe.refund is irreversible (a step-up even within a cap); the quick start grants a rate-limited refund so it auto-approves
const catalog = buildCatalog([...BUILTIN_ACTIONS, defineAction({ connector: 'stripe', action: 'refund', reversibility: 'rate_limited', blastRadius: 0.9, amountField: 'amount', description: 'Refund a charge (rate-limited).' })]);

describe('README quick start (verbatim configuration)', () => {
  it('permits the signed action once, then denies the replay', async () => {
    const a = agent({
      principal: generateKeyPair(),
      goal: 'reconcile october refunds',
      permissions: { stripe: ['refund'] },
      limits: { refund: '$500' },
      aud: 'rs_demo',
      catalog,
    });
    const authorizer = createAuthorizer({
      audience: 'rs_demo',
      resolveGrant: async (ref) => (ref === a.grant.id ? a.grant : null),
      budgetStore: memoryPcaStore(),
      hooks: { revocation: () => ({ enforced: true, ok: true }) },
      plan: 'single-step',
      risk: () => ({ blastRadius: 0.1, semanticDistance: 0, reversibility: 0, taint: 0, confidence: 1 }),
    });
    a.provenance?.principal('refund charge ch_1, 42 usd');
    const { encoded, pcactn, provenance } = a.act('stripe.refund', 'charge:ch_1', { amount: 42, currency: 'usd' });
    const pdp = authzenPdp({
      audience: 'rs_demo',
      authorizedPlanRoots: [pcactn.plan.root],
      authorizer,
      resolve: () => ({ grant: a.grant, chain: a.chain, policy: a.policy, budget: a.budget }),
    });
    const body = {
      subject: { type: 'agent', id: 'a1' },
      action: { name: 'stripe.refund', properties: { amount: 42, currency: 'usd' } },
      resource: { type: 'charge', id: 'ch_1' },
      context: { [PCA_ACTION_KEY]: encoded, [PCA_PROVENANCE_KEY]: provenance },
    };
    const resp = await pdp.evaluate(body);
    expect(resp.decision).toBe(true);
    expect(isApprovalRequired(resp)).toBe(false);
    const handle = authzenHandler(pdp);
    const again = await handle({ path: '/access/v1/evaluation', body });
    expect(again.status).toBe(200);
    expect((again.body as { decision: boolean }).decision).toBe(false);
  });
});
