import { describe, expect, it } from 'vitest';
import { DEFAULT_RISK_POLICY, buildPCActn, encodeKey, generateKeyPair, mintGrant, paramsDigest, type PlanNode } from '@atlasauth/pca';
import { a2aPaymentMandateFromPca, verifyA2APaymentMandate } from './index';

const NOW = 1_800_000_000_000;
const AUD = 'atlas-instance-rs-1';
const P = generateKeyPair();
const A = generateKeyPair();
const { grant } = mintGrant({
  principalSecret: P.secretKey,
  principalPublic: encodeKey(P.publicKey),
  holder: encodeKey(A.publicKey),
  goal: 'pay the invoice',
  envelope: { predicates: [{ verb: 'purchase', resource: '*' }], caveats: [{ type: 'expires', at: NOW + 3_600_000 }], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
});
function payCase(params: Record<string, unknown>) {
  const plan: PlanNode[] = [{ id: 'n', verb: 'purchase', resource: 'merchant/acme/cart/42', params_digest: paramsDigest(params), reversibility_class: 'reversible' }];
  const p = buildPCActn({ grant, chain: [grant], plan, nodeId: 'n', params, counter: 1, signerSecret: A.secretKey, aud: AUD, now: NOW });
  const opts = {
    grant,
    aud: AUD,
    now: NOW,
    hooks: { revocation: () => ({ enforced: true as const, ok: true }) },
    context: { plan, planAuthorized: true, budget: { B: 100, tau: NOW, asOf: NOW }, risk: { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1 }, params },
  };
  return { p, opts };
}
const card = { type: 'card' };

describe('payment mandate: the authorized params amount is a non-negative integer', () => {
  it('a zero amount is a valid authorized amount', async () => {
    const { p, opts } = payCase({ amount: 0, currency: 'USD' });
    const r = await verifyA2APaymentMandate(a2aPaymentMandateFromPca(p, { amount: { currency: 'USD', value: 0 }, paymentMethod: card }), p, opts);
    expect(r.ok, r.reason).toBe(true);
  });
  it('a negative authorized amount can back no mandate, and is reported as such', async () => {
    const { p, opts } = payCase({ amount: -5, currency: 'USD' });
    const r = await verifyA2APaymentMandate(a2aPaymentMandateFromPca(p, { amount: { currency: 'USD', value: 5 }, paymentMethod: card }), p, opts);
    expect(r.reason).toBe('the PCActn params carry no integer minor-unit amount to bind the mandate amount to');
  });
});
