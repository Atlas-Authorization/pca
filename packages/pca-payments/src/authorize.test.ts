import { describe, expect, it } from 'vitest';
import { generateKeyPair, encodeKey } from '@atlasauth/pca';
import { buildPaymentMandate, autoSpendBound, type PaymentMandate, type PaymentMandateParams } from './mandate';
import { applyHumanCosign, authorizeCharge, settleCharge, type Charge } from './authorize';

const principal = generateKeyPair();
const agent = generateKeyPair();
const pub = (k: { publicKey: Uint8Array }) => encodeKey(k.publicKey);
const NOW = 1_700_000_000_000;

const params: PaymentMandateParams = {
  principalSecret: principal.secretKey,
  principalPublic: pub(principal),
  agentPublic: pub(agent),
  merchants: ['openai', 'aws'],
  categories: ['saas', 'cloud'],
  currency: 'USD',
  perTransactionCap: 500, // X
  autoApproveThreshold: 200, // Y
  cumulativeCap: 1000,
  now: NOW,
};
const mk = (over: Partial<PaymentMandateParams> = {}): PaymentMandate => buildPaymentMandate({ ...params, ...over });
const charge = (over: Partial<Charge> = {}): Charge => ({ merchant: 'openai', amount: 50, category: 'saas', currency: 'USD', now: NOW, ...over });

describe('authorizeCharge → PCA decision', () => {
  it('auto-approves a small, in-policy charge under Y at t=1 and debits the exact amount', () => {
    const m = mk();
    const d = authorizeCharge(m, charge({ amount: 50 }));
    expect(d.outcome).toBe('auto');
    expect(d.t).toBe(1);
    expect(d.r).toBeCloseTo(50 / 500);
    expect(d.cost).toBe(50); // dollars debited = amount (kappa·r = X·amount/X)
    expect(d.budgetAfter.B).toBe(1000 - 50);
  });

  it('forces a human co-sign (step_up, t=3) for a charge above Y', () => {
    const m = mk();
    const d = authorizeCharge(m, charge({ amount: 300 })); // Y=200 < 300 ≤ X=500
    expect(d.outcome).toBe('step_up');
    expect(d.t).toBe(3);
    expect(d.budgetAfter.B).toBe(1000); // a human-co-signed charge does NOT drain the autonomous budget
  });

  it('denies a charge over the hard ceiling X', () => {
    const d = authorizeCharge(mk(), charge({ amount: 501 })); // > X = 500
    expect(d.outcome).toBe('deny');
    expect(d.decision.releaseGuardianShare).toBe(false);
  });

  it('denies an off-allowlist merchant', () => {
    const d = authorizeCharge(mk(), charge({ merchant: 'sketchy-co', amount: 10 }));
    expect(d.outcome).toBe('deny');
  });

  it('denies an off-allowlist category and a wrong currency', () => {
    expect(authorizeCharge(mk(), charge({ category: 'gambling', amount: 10 })).outcome).toBe('deny');
    expect(authorizeCharge(mk(), charge({ currency: 'EUR', amount: 10 })).outcome).toBe('deny');
  });

  it('forces step_up once the cumulative budget is exhausted, even for a sub-Y charge', () => {
    let m = mk(); // budget 1000, Y=200
    // Five auto charges of 200 drain the budget to exactly 0 (1000 / 200 = 5).
    for (let i = 0; i < 5; i++) {
      const d = authorizeCharge(m, charge({ amount: 200 }));
      expect(d.outcome).toBe('auto');
      m = settleCharge(m, d);
    }
    expect(m.budget.B).toBe(0);
    // The sixth sub-Y charge can no longer be covered ⇒ human recharge required (step_up, t=3).
    const d6 = authorizeCharge(m, charge({ amount: 200 }));
    expect(d6.outcome).toBe('step_up');
    expect(d6.t).toBe(3);
    expect(d6.reasons.join(' ')).toMatch(/budget/i);
    // A human co-sign refills the budget; the next charge auto-approves again.
    m = applyHumanCosign(m, NOW, { full: true });
    expect(m.budget.B).toBe(1000);
    expect(authorizeCharge(m, charge({ amount: 200 })).outcome).toBe('auto');
  });

  it('PROVABLE BOUND: Σ auto-approved amounts ≤ the budget-derived bound between human co-signs', () => {
    const m0 = mk(); // X=500, Y=200, cumulativeCap=1000
    const bound = autoSpendBound(m0); // = 1000
    // An adversarial stream of max-autonomous (=Y) charges — the worst case for total spend.
    const amounts = [200, 200, 200, 200, 200, 200, 200]; // 7 attempts; only ≤ bound/Y can be auto
    let m = m0;
    let autoTotal = 0;
    let sawStepUp = false;
    for (const amount of amounts) {
      const d = authorizeCharge(m, charge({ amount }));
      if (d.outcome === 'auto') {
        autoTotal += d.cost;
        m = settleCharge(m, d);
      } else {
        sawStepUp = true; // budget exhausted ⇒ must checkpoint with a human
      }
    }
    expect(autoTotal).toBeLessThanOrEqual(bound); // the §2.4 theorem, demonstrated
    expect(autoTotal).toBe(1000);
    expect(sawStepUp).toBe(true);
    expect(m.budget.B).toBe(0);
  });

  it('exactly-Y auto-approves; one cent over Y escalates to a human co-sign', () => {
    const m = mk();
    expect(authorizeCharge(m, charge({ amount: 200 })).outcome).toBe('auto'); // amount == Y
    expect(authorizeCharge(m, charge({ amount: 201 })).outcome).toBe('step_up'); // amount > Y
  });
});
