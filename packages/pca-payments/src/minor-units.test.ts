import { describe, expect, it } from 'vitest';
import { encodeKey, generateKeyPair } from '@atlasauth/pca';
import { buildPaymentMandate } from './mandate';
import { sharedPaymentTokenLimits } from './spt-limits';
import { AMOUNT_NOT_MINOR_UNITS, ChargeStoreError, MERCHANT_INVALID, applyHumanCosignAtomic, authorizeCharge, authorizeChargeAtomic, chargeActionContext, type Charge } from './authorize';
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
  it('mandate terms must be integer minor units by default; only an explicit strictMinorUnits:false keeps fractional terms', () => {
    expect(() => buildPaymentMandate({ ...base, autoApproveThreshold: 20_000.5 })).toThrow(/autoApproveThreshold/);
    expect(() => buildPaymentMandate({ ...base, autoApproveThreshold: 20_000.5, strictMinorUnits: true })).toThrow(/autoApproveThreshold/);
    expect(() => buildPaymentMandate({ ...base, replenishPerCosign: 1.5 })).toThrow(/replenishPerCosign/);
    expect(() => buildPaymentMandate({ ...base, replenishPerCosign: 1.5, strictMinorUnits: true })).toThrow(/replenishPerCosign/);
    expect(() => buildPaymentMandate({ ...base, cumulativeCap: 100_000.5 })).toThrow(/cumulativeCap/);
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

describe('merchant ids are plain ids, never patterns', () => {
  it.each([['*'], ['acme*'], ['ac*me'], ['a\nb'], ['a\u0000b']])('buildPaymentMandate refuses merchant id %j', (id) => {
    expect(() => buildPaymentMandate({ ...base, merchants: ['acme', id] })).toThrow(/merchant ids/);
  });
  it.each([[''], [undefined], [null], [7], [{}]])('authorizeCharge denies a charge whose merchant is %j, reason merchant_invalid', (merchant) => {
    const d = authorizeCharge(mandate, ch({ merchant } as never), mandate.grant);
    expect(d.outcome).toBe('deny');
    expect(d.reasons[0]).toBe(MERCHANT_INVALID);
    expect(d.cost).toBe(0);
    expect(d.budgetAfter).toEqual(mandate.budget);
  });
  it('a merchant id containing a star on the charge side matches no allowlist entry', () => {
    const d = authorizeCharge(mandate, ch({ merchant: 'acme*' }), mandate.grant);
    expect(d.outcome).toBe('deny');
    expect(d.reasons[0]).toBe(MERCHANT_INVALID);
  });
});

describe('store records are validated, and a co-sign is durable', () => {
  const rec = (over: Record<string, unknown>) => ({ budget: { B: 1000, tau: 1, asOf: 1 }, version: 1, ...over });
  it.each([
    ['no budget', { budget: undefined }],
    ['NaN balance', { budget: { B: NaN, tau: 1, asOf: 1 } }],
    ['missing tau', { budget: { B: 1, asOf: 1 } }],
    ['Infinity asOf', { budget: { B: 1, tau: 1, asOf: Infinity } }],
    ['fractional version', { version: 1.5 }],
    ['string version', { version: '1' }],
    ['no version', { version: undefined }],
  ])('a malformed record (%s) throws ChargeStoreError instead of deciding on it', async (_n, over) => {
    const store = { get: async () => rec(over as Record<string, unknown>) as never, compareAndSet: async () => true };
    await expect(authorizeChargeAtomic(mandate, ch(), mandate.grant, store)).rejects.toBeInstanceOf(ChargeStoreError);
    await expect(applyHumanCosignAtomic(mandate, mandate.grant, store, NOW)).rejects.toBeInstanceOf(ChargeStoreError);
  });
  it('a store whose get rejects propagates the failure (no allow)', async () => {
    const store = { get: async () => { throw new Error('db down'); }, compareAndSet: async () => true };
    await expect(authorizeChargeAtomic(mandate, ch(), mandate.grant, store)).rejects.toThrow('db down');
  });
  it('applyHumanCosignAtomic restores the budget in the store; a full co-sign refills to bMax', async () => {
    const store = memoryChargeBudgetStore();
    for (let i = 0; i < 5; i++) await authorizeChargeAtomic(mandate, ch({ amount: 20_000 }), mandate.grant, store, 'k');
    const empty = await authorizeChargeAtomic(mandate, ch({ amount: 20_000 }), mandate.grant, store, 'k');
    expect(empty.outcome).toBe('step_up');
    const m30 = buildPaymentMandate({ ...base, replenishPerCosign: 30_000 }); // one mandate: a second build has another goal salt, hence another grant
    const partial = await applyHumanCosignAtomic(m30, m30.grant, store, NOW + 1, { key: 'k' });
    expect(partial.B).toBe(30_000);
    expect((await store.get('k'))?.budget.B).toBe(30_000);
    const full = await applyHumanCosignAtomic(mandate, mandate.grant, store, NOW + 2, { key: 'k', full: true });
    expect(full.B).toBe(100_000);
  });
  it('applyHumanCosignAtomic refuses a mandate that is not the verified grant, and a missing store', async () => {
    const other = buildPaymentMandate({ ...base, merchants: ['zzz'] });
    await expect(applyHumanCosignAtomic(other, mandate.grant, memoryChargeBudgetStore(), NOW)).rejects.toMatchObject({ code: 'mandate_grant_mismatch' });
    await expect(applyHumanCosignAtomic(mandate, mandate.grant, undefined as never, NOW)).rejects.toBeInstanceOf(ChargeStoreError);
  });
  it('persistent contention on a co-sign throws instead of dropping it', async () => {
    const store = { get: async () => undefined, compareAndSet: async () => false };
    await expect(applyHumanCosignAtomic(mandate, mandate.grant, store, NOW)).rejects.toBeInstanceOf(ChargeStoreError);
  });
  it('a stored balance above bMax is clamped to the signed bMax; a negative one to 0', async () => {
    for (const [B, expectOutcome] of [[10 ** 12, 'auto'], [-5, 'step_up']] as const) {
      const store = { get: async () => ({ budget: { B, tau: 1, asOf: 1 }, version: 1 }), compareAndSet: async () => true };
      const d = await authorizeChargeAtomic(mandate, ch({ amount: 20_000 }), mandate.grant, store);
      expect(d.outcome).toBe(expectOutcome);
      expect(d.budgetBefore.B).toBe(Math.max(0, Math.min(B, 100_000)));
    }
  });
});

describe('sharedPaymentTokenLimits (Stripe SPT usage_limits)', () => {
  const m = buildPaymentMandate({ ...base, periodMs: 3_600_000 });
  it('is the auto-approve threshold, in lowercase minor units, expiring with the period', () => {
    expect(sharedPaymentTokenLimits(m, NOW)).toEqual({ currency: 'usd', max_amount: 20_000, expires_at: Math.floor((NOW + 3_600_000) / 1000) });
  });
  it('is capped by the remaining autonomous budget (rounded down) and has no expiry without a period', () => {
    const poor = { ...buildPaymentMandate(base), budget: { B: 1234.9, tau: 0, asOf: 0 } };
    expect(sharedPaymentTokenLimits(poor, NOW)).toEqual({ currency: 'usd', max_amount: 1234 });
  });
  it('refuses when no autonomous capacity is left, after the period ended, and for a bad clock', () => {
    expect(() => sharedPaymentTokenLimits({ ...m, budget: { B: 0, tau: 0, asOf: 0 } }, NOW)).toThrow(/no autonomous spend capacity/);
    expect(() => sharedPaymentTokenLimits({ ...m, budget: { B: 0.5, tau: 0, asOf: 0 } }, NOW)).toThrow(RangeError);
    expect(() => sharedPaymentTokenLimits(m, NOW + 3_600_000)).toThrow(/period has ended/);
    expect(() => sharedPaymentTokenLimits(m, Number.NaN)).toThrow(TypeError);
  });
});
