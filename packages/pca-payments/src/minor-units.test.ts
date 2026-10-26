import { describe, expect, it } from 'vitest';
import { encodeKey, generateKeyPair } from '@atlasauth/pca';
import { buildPaymentMandate } from './mandate';
import { AMOUNT_NOT_MINOR_UNITS, ChargeStoreError, authorizeCharge, authorizeChargeAtomic, chargeActionContext, type Charge } from './authorize';
import { chargePlanNode, chargeToPCActn } from './charge-action';
import { memoryChargeBudgetStore } from './testing';

const principal = generateKeyPair();
const agent = generateKeyPair();
const NOW = 1_700_000_000_000;
const base = {
  principalSecret: principal.secretKey,
  principalPublic: encodeKey(principal.publicKey),
  agentPublic: encodeKey(agent.publicKey),
  merchants: ['acme', 'other'],
  currency: 'USD',
  perTransactionCap: 50_000,
  autoApproveThreshold: 20_000,
  cumulativeCap: 100_000,
  now: NOW,
};
const mandate = buildPaymentMandate(base);
const ch = (over: Record<string, unknown> = {}): Charge => ({ merchant: 'acme', amount: 1000, now: NOW, ...over }) as Charge;

describe('integer minor units', () => {
  it.each([[12.5], [NaN], [-1], [Infinity], [2 ** 53], ['1000' as unknown as number], [null as unknown as number]])(
    'denies amount %s with the exact reason and no debit',
    (amount) => {
      const d = authorizeCharge(mandate, ch({ amount }), mandate.grant);
      expect(d.outcome).toBe('deny');
      expect(d.reasons[0]).toBe(AMOUNT_NOT_MINOR_UNITS);
      expect(d.cost).toBe(0);
      expect(d.budgetAfter).toEqual(mandate.budget);
      expect(d.decision.admit).toBe(false);
    },
  );
  it('admits an integer amount; 0 is a valid integer', () => {
    expect(authorizeCharge(mandate, ch(), mandate.grant).outcome).toBe('auto');
    expect(authorizeCharge(mandate, ch({ amount: 0 }), mandate.grant).outcome).toBe('auto');
  });
  it('chargeToPCActn refuses a fractional amount instead of substituting the cap', () => {
    const o = { signerSecret: agent.secretKey, aud: 'a', counter: 1, now: NOW };
    expect(() => chargeToPCActn(mandate, ch({ amount: 0.5 }), o)).toThrow(/minor units/);
    expect(() => chargeToPCActn(mandate, ch({ amount: NaN }), o)).toThrow(/minor units/);
  });
  it('strictMinorUnits rejects fractional mandate terms; default still accepts them', () => {
    expect(() => buildPaymentMandate({ ...base, autoApproveThreshold: 20_000.5, strictMinorUnits: true })).toThrow(/autoApproveThreshold/);
    expect(() => buildPaymentMandate({ ...base, replenishPerCosign: 1.5, strictMinorUnits: true })).toThrow(/replenishPerCosign/);
    expect(buildPaymentMandate({ ...base, autoApproveThreshold: 20_000.5, strictMinorUnits: false }).terms.autoApproveThreshold).toBe(20_000.5);
    expect(buildPaymentMandate({ ...base, strictMinorUnits: true }).terms.perTransactionCap).toBe(50_000);
  });
});

describe('payee / amount / currency binding', () => {
  it('the committed plan node differs per payee, amount and currency', () => {
    const a = chargePlanNode(mandate, ch(), 'n');
    expect(chargePlanNode(mandate, ch({ merchant: 'other' }), 'n')).not.toEqual(a);
    expect(a.resource).toBe('merchant:acme');
    expect(chargePlanNode(mandate, ch({ amount: 1001 }), 'n').params_digest).not.toBe(a.params_digest);
    expect(chargePlanNode(mandate, ch({ currency: 'EUR' }), 'n').params_digest).not.toBe(a.params_digest);
  });
  it('the decision context carries exactly the server-provided charge', () => {
    expect(chargeActionContext(mandate, ch()).action).toEqual({
      verb: 'charge',
      resource: 'merchant:acme',
      params: { amount: 1000, currency: 'USD' },
      reversibility_class: 'reversible',
    });
  });
  it('an unlisted payee and a foreign currency are denied', () => {
    expect(authorizeCharge(mandate, ch({ merchant: 'evil' }), mandate.grant).outcome).toBe('deny');
    expect(authorizeCharge(mandate, ch({ currency: 'EUR' }), mandate.grant).outcome).toBe('deny');
  });
});

describe('authorizeChargeAtomic: durable cumulative cap', () => {
  it('requires a store (fail closed)', async () => {
    for (const bad of [undefined, null, {}, { get: async () => undefined }]) {
      await expect(authorizeChargeAtomic(mandate, ch(), mandate.grant, bad as never)).rejects.toBeInstanceOf(ChargeStoreError);
    }
  });
  it('concurrent charges cannot overspend the cap: exactly 5 of 8 20000-charges are auto', async () => {
    const store = memoryChargeBudgetStore();
    const ds = await Promise.all(Array.from({ length: 8 }, () => authorizeChargeAtomic(mandate, ch({ amount: 20_000 }), mandate.grant, store)));
    expect(ds.filter((d) => d.outcome === 'auto').length).toBe(5);
    expect(ds.filter((d) => d.outcome === 'step_up').length).toBe(3);
    expect(ds.filter((d) => d.outcome === 'auto').reduce((n, d) => n + d.cost, 0)).toBe(100_000);
  });
  it('state persists across calls (the mandate budget is only the initial value)', async () => {
    const store = memoryChargeBudgetStore();
    await authorizeChargeAtomic(mandate, ch({ amount: 20_000 }), mandate.grant, store, 'k');
    const d = await authorizeChargeAtomic(mandate, ch({ amount: 20_000 }), mandate.grant, store, 'k');
    expect(d.budgetBefore.B).toBe(80_000);
    expect(d.budgetAfter.B).toBe(60_000);
  });
  it('persistent contention denies with budget_store_conflict', async () => {
    const store = { get: async () => undefined, compareAndSet: async () => false };
    const d = await authorizeChargeAtomic(mandate, ch(), mandate.grant, store);
    expect(d.outcome).toBe('deny');
    expect(d.reasons[0]).toBe('budget_store_conflict');
    expect(d.budgetAfter).toEqual(mandate.budget);
  });
});
