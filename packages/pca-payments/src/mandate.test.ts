import { describe, expect, it } from 'vitest';
import { generateKeyPair, encodeKey, readEnvelope, verifyChain, validateRiskPolicy } from '@atlasauth/pca';
import { autoSpendBound, buildPaymentMandate, type PaymentMandateParams } from './mandate';

const principal = generateKeyPair();
const agent = generateKeyPair();
const pub = (k: { publicKey: Uint8Array }) => encodeKey(k.publicKey);

const base: PaymentMandateParams = {
  principalSecret: principal.secretKey,
  principalPublic: pub(principal),
  agentPublic: pub(agent),
  merchants: ['openai', 'aws'],
  categories: ['saas', 'cloud'],
  currency: 'USD',
  perTransactionCap: 500, // X
  autoApproveThreshold: 200, // Y
  cumulativeCap: 1000,
  periodMs: 30 * 24 * 3_600_000,
  now: 1_700_000_000_000,
};

describe('buildPaymentMandate → PCA Root Intent Grant', () => {
  it('mints a grant that verifies and carries a well-formed envelope', () => {
    const m = buildPaymentMandate(base);
    expect(verifyChain([m.grant], pub(principal)).ok).toBe(true);
    const env = readEnvelope(m.grant);
    expect(env).not.toBeNull();
    expect(validateRiskPolicy(env!.risk_policy)).toBeNull();
  });

  it('tunes the risk policy so spend = risk (kappa=X, theta1=theta2=Y/X, bMax=cumulativeCap)', () => {
    const m = buildPaymentMandate(base);
    expect(m.policy.kappa).toBe(500);
    expect(m.policy.theta1).toBeCloseTo(200 / 500);
    expect(m.policy.theta2).toBeCloseTo(200 / 500);
    expect(m.policy.bMax).toBe(1000);
    expect(m.policy.lambda).toBe(0);
    expect(m.policy.weights).toMatchObject({ gamma: 1, alpha: 0, beta: 0, delta: 0, epsilon: 0, zeta: 0 });
  });

  it('starts the budget at the cumulative cap and bounds autonomous spend to it', () => {
    const m = buildPaymentMandate(base);
    expect(m.budget.B).toBe(1000);
    expect(autoSpendBound(m)).toBe(1000); // = bMax (safetyBound·kappa)
  });

  it('encodes one allow-predicate per merchant and the period/reversibility caveats', () => {
    const env = readEnvelope(buildPaymentMandate(base).grant)!;
    expect(env.predicates).toHaveLength(2);
    expect(env.predicates.map((p) => p.resource).sort()).toEqual(['merchant:aws', 'merchant:openai']);
    const types = env.caveats.map((c) => c.type);
    expect(types).toContain('not_before');
    expect(types).toContain('expires');
    expect(types).toContain('reversibility_max');
  });

  it('rejects incoherent params', () => {
    expect(() => buildPaymentMandate({ ...base, merchants: [] })).toThrow(/merchant/);
    expect(() => buildPaymentMandate({ ...base, autoApproveThreshold: 600 })).toThrow(/0 ≤ Y ≤ X/);
    expect(() => buildPaymentMandate({ ...base, cumulativeCap: 100 })).toThrow(/cumulativeCap/);
    expect(() => buildPaymentMandate({ ...base, perTransactionCap: 0 })).toThrow(/perTransactionCap/);
  });
});
