import { describe, expect, expectTypeOf, it } from 'vitest';
import { encodeKey, generateKeyPair, type Capability } from '@atlasauth/pca';
import { buildPaymentMandate, type PaymentMandate, type PaymentMandateParams } from './mandate';
import * as authz from './authorize';

/**
 * The payments decision takes its authority from the VERIFIED / STORED grant, never from the mandate object it is
 * handed (which may come from a request). authorizeCharge / chargeDecideInput require that grant, refuse a mandate whose
 * grant differs from it (content hash), and refuse terms / policy that are not the ones signed into that grant.
 */
const NOW = 1_700_000_000_000;
const principal = generateKeyPair();
const agent = generateKeyPair();
const params: PaymentMandateParams = {
  principalSecret: principal.secretKey,
  principalPublic: encodeKey(principal.publicKey),
  agentPublic: encodeKey(agent.publicKey),
  merchants: ['openai'],
  currency: 'USD',
  perTransactionCap: 500,
  autoApproveThreshold: 200,
  cumulativeCap: 1000,
  now: NOW,
};
const charge = { merchant: 'openai', amount: 50, currency: 'USD', now: NOW };
const fn = authz as unknown as Record<string, (...a: unknown[]) => unknown>;
const codeOf = (f: () => unknown): string | undefined => {
  try {
    f();
  } catch (e) {
    return (e as { code?: string }).code;
  }
  return undefined;
};

describe('payments: the decision is bound to the verified grant', () => {
  const real = buildPaymentMandate(params);

  it('allows a charge when the mandate grant IS the verified grant', () => {
    const d = fn['authorizeCharge']!(real, charge, real.grant) as authz.ChargeDecision;
    expect(d.outcome).toBe('auto');
  });

  it('refuses a mandate carrying a different grant (typed error, content-hash compare)', () => {
    const attacker = generateKeyPair();
    const forged = buildPaymentMandate({ ...params, principalSecret: attacker.secretKey, principalPublic: encodeKey(attacker.publicKey), perTransactionCap: 1_000_000, autoApproveThreshold: 1_000_000, cumulativeCap: 1_000_000 });
    expect(codeOf(() => fn['authorizeCharge']!(forged, { ...charge, amount: 900_000 }, real.grant))).toBe('mandate_grant_mismatch');
    expect(codeOf(() => fn['chargeDecideInput']!(forged, charge, NOW, real.grant))).toBe('mandate_grant_mismatch');
    // a deep copy of the same grant is the same content: accepted
    expect(codeOf(() => fn['authorizeCharge']!(real, charge, JSON.parse(JSON.stringify(real.grant))))).toBeUndefined();
  });

  it('refuses terms / policy / budget that widen what the verified grant signed', () => {
    const widerTerms: PaymentMandate = { ...real, terms: { ...real.terms, perTransactionCap: 1_000_000, autoApproveThreshold: 1_000_000 } };
    expect(codeOf(() => fn['authorizeCharge']!(widerTerms, charge, real.grant))).toBe('mandate_terms_mismatch');
    const cheaperPolicy: PaymentMandate = { ...real, policy: { ...real.policy, kappa: 0 } };
    expect(codeOf(() => fn['authorizeCharge']!(cheaperPolicy, charge, real.grant))).toBe('mandate_terms_mismatch');
    const fatBudget: PaymentMandate = { ...real, budget: { ...real.budget, B: 1e12 } };
    const d = fn['authorizeCharge']!(fatBudget, charge, real.grant) as authz.ChargeDecision;
    expect(d.budgetBefore.B).toBeLessThanOrEqual(real.policy.bMax);
  });

  it('calling without a verified grant is a runtime error (and a type error)', () => {
    expect(codeOf(() => fn['authorizeCharge']!(real, charge))).toBe('verified_grant_required');
    expect(codeOf(() => fn['chargeDecideInput']!(real, charge, NOW))).toBe('verified_grant_required');
    expect(codeOf(() => fn['authorizeCharge']!(real, charge, null))).toBe('verified_grant_required');
    // type level: the third parameter is a required Capability
    expectTypeOf(authz.authorizeCharge).parameter(2).toEqualTypeOf<Capability>();
    // @ts-expect-error - a verified grant is required
    const omit = () => authz.authorizeCharge(real, charge);
    void omit;
  });
});
