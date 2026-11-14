import { type RiskPolicy, type TrustBudget, encodeKey, generateKeyPair, hashCanonical, mintGrant, mintRoot } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import {
  type Charge,
  type ChargeBudgetStore,
  ChargeStoreError,
  MandateGrantError,
  applyHumanCosignAtomic,
  authorizeCharge,
  authorizeChargeAtomic,
  chargeActionContext,
} from './authorize';
import { type MandateTerms, type PaymentMandate, buildPaymentMandate, mandateCaveats, mandatePredicates } from './mandate';

const principal = generateKeyPair();
const agent = generateKeyPair();
const NOW = 1_700_000_000_000;
const mk = (over: Record<string, unknown> = {}): PaymentMandate =>
  buildPaymentMandate({
    principalSecret: principal.secretKey,
    principalPublic: encodeKey(principal.publicKey),
    agentPublic: encodeKey(agent.publicKey),
    merchants: ['m1', 'm2'],
    currency: 'USD',
    perTransactionCap: 100,
    autoApproveThreshold: 50,
    cumulativeCap: 500,
    now: NOW,
    ...over,
  });
const charge = (over: Partial<Charge> = {}): Charge => ({ merchant: 'm1', amount: 10, currency: 'USD', now: NOW, ...over });
const code = (f: () => unknown): { code?: string; message: string; name: string } => {
  try {
    f();
  } catch (e) {
    return { code: (e as MandateGrantError).code, message: (e as Error).message, name: (e as Error).name };
  }
  throw new Error('did not throw');
};

/** A hand-signed mandate whose terms and policy disagree (X versus kappa), signed into a real grant. */
function custom(X: number, kappa: number): PaymentMandate {
  const terms: MandateTerms = { merchants: ['m1'], categories: [], currency: 'USD', perTransactionCap: X, autoApproveThreshold: 0, cumulativeCap: 1000, periodStart: 0 };
  const policy: RiskPolicy = { weights: { alpha: 0, beta: 0, gamma: 1, delta: 0, epsilon: 0, zeta: 0 }, theta1: 0.6, theta2: 0.6, kappa, lambda: 0, rho: 1, bMax: 1000 };
  const { grant, goalCommit, goalSalt } = mintGrant({
    principalSecret: principal.secretKey,
    principalPublic: encodeKey(principal.publicKey),
    holder: encodeKey(agent.publicKey),
    goal: 'g',
    envelope: { predicates: mandatePredicates(terms), caveats: mandateCaveats(terms), agent_binding: {}, risk_policy: policy },
  });
  return { grant, policy, budget: { B: 1000, tau: NOW, asOf: NOW }, terms, goalCommit, goalSalt };
}

describe('chargeActionContext', () => {
  it('carries merchant, amount, currency and reversibility; category only when given', () => {
    const m = mk();
    expect(chargeActionContext(m, { merchant: 'm1', amount: 7 })).toStrictEqual({ action: { verb: 'charge', resource: 'merchant:m1', params: { amount: 7, currency: 'USD' }, reversibility_class: 'reversible' } });
    expect(chargeActionContext(m, { merchant: 'm1', amount: 7, category: 'saas', currency: 'EUR' }).action.params).toStrictEqual({ amount: 7, currency: 'EUR', category: 'saas' });
    expect(chargeActionContext(m, { merchant: 'm1', amount: 7, currency: null as never }).action.params).toStrictEqual({ amount: 7, currency: null });
  });
});

describe('binding a mandate to the verified grant', () => {
  it('no verified grant is refused', () => {
    const m = mk();
    for (const g of [undefined, null, 'x', 5]) {
      expect(code(() => authorizeCharge(m, charge(), g as never))).toEqual({ code: 'verified_grant_required', message: "a verified (or stored) grant is required; the mandate's own grant is never the authority", name: 'MandateGrantError' });
    }
  });
  it('a mandate that is not an object, or whose grant differs, is a grant mismatch', () => {
    const m = mk();
    const want = { code: 'mandate_grant_mismatch', message: 'the mandate grant is not the verified grant', name: 'MandateGrantError' };
    for (const bad of [null, undefined, 'x', 5]) expect(code(() => authorizeCharge(bad as never, charge(), m.grant))).toEqual(want);
    expect(code(() => authorizeCharge(m, charge(), mk().grant))).toEqual(want);
    expect(code(() => authorizeCharge(m, charge(), 'x' as never))).toMatchObject({ code: 'verified_grant_required' });
  });
  it('terms or policy that are missing or not the signed ones are a terms mismatch', () => {
    const m = mk();
    const want = { code: 'mandate_terms_mismatch', message: 'the mandate terms / policy are not the ones signed into the verified grant', name: 'MandateGrantError' };
    expect(code(() => authorizeCharge({ ...m, terms: undefined as never }, charge(), m.grant))).toEqual(want);
    expect(code(() => authorizeCharge({ ...m, policy: undefined as never }, charge(), m.grant))).toEqual(want);
    expect(code(() => authorizeCharge({ ...m, terms: { ...m.terms, perTransactionCap: 99 } }, charge(), m.grant))).toEqual(want);
    expect(code(() => authorizeCharge({ ...m, terms: { ...m.terms, currency: 'EUR' } }, charge(), m.grant))).toEqual(want);
    expect(code(() => authorizeCharge({ ...m, policy: { ...m.policy, rho: 1 } }, charge(), m.grant))).toEqual(want);
    const bare = mintRoot({ principalSecret: principal.secretKey, principalPublic: encodeKey(principal.publicKey), holder: encodeKey(agent.publicKey), caveats: [] });
    expect(code(() => authorizeCharge({ ...m, grant: bare }, charge(), bare))).toEqual(want);
  });
  it('the budget is clamped to [0, bMax] and an unusable one is zero', () => {
    const m = mk();
    const B = (b: unknown) => authorizeCharge({ ...m, budget: b as TrustBudget }, charge(), m.grant).budgetBefore.B;
    expect(B({ B: 5000, tau: NOW, asOf: NOW })).toBe(500);
    expect(B({ B: 100, tau: NOW, asOf: NOW })).toBe(100);
    expect(B({ B: -5, tau: NOW, asOf: NOW })).toBe(0);
    for (const bad of [Number.NaN, Infinity, '100', null, undefined]) expect(B({ B: bad, tau: NOW, asOf: NOW })).toBe(0);
    expect(B(undefined)).toBe(0);
  });
});

describe('charge decisions', () => {
  it('a non-finite now falls back to the clock, as does a non-number', () => {
    const m = mk();
    expect(authorizeCharge(m, charge({ now: Number.NaN }), m.grant).outcome).toBe('auto');
    expect(authorizeCharge(m, charge({ now: 'x' as never }), m.grant).outcome).toBe('auto');
  });
  it('a non-positive per-transaction cap in the terms reads as maximum risk, with no missing-input reason', () => {
    const m = custom(0, 100);
    const d = authorizeCharge(m, charge({ amount: 0 }), m.grant);
    expect(d.r).toBe(1);
    expect(d.reasons.some((r) => r.includes('missing'))).toBe(false);
    expect(authorizeCharge(m, charge({ amount: 5 }), m.grant).reasons.some((r) => r.includes('missing'))).toBe(false);
  });
  it('the exact-amount shortcut applies only when kappa equals the per-transaction cap', () => {
    const m = custom(100, 200);
    const d = authorizeCharge(m, charge({ amount: 50 }), m.grant);
    expect(d.outcome).toBe('auto');
    expect(d.cost).toBe(100);
    expect(d.budgetAfter.B).toBe(900);
    const e = mk();
    const x = authorizeCharge(e, charge({ amount: 30 }), e.grant);
    expect(x.cost).toBe(30);
    expect(x.budgetAfter.B).toBe(470);
  });
  it('recent charge times drive the velocity caveat', () => {
    const m = mk({ periodMs: 3_600_000, maxTransactionsPerPeriod: 2 });
    const at = (recent?: number[]) => authorizeCharge(m, charge({ ...(recent ? { recentChargeTimes: recent } : {}) }), m.grant).outcome;
    expect(at([])).toBe('auto');
    expect(at([NOW - 1000])).toBe('auto');
    expect(at([NOW - 1000, NOW - 2000])).toBe('deny');
  });
});

function memStore() {
  const rec = new Map<string, { budget: TrustBudget; version: number }>();
  const s = {
    rec,
    gets: 0,
    cas: 0,
    async get(k: string) {
      s.gets++;
      return rec.get(k);
    },
    async compareAndSet(k: string, expected: number | undefined, b: TrustBudget) {
      s.cas++;
      const cur = rec.get(k);
      if (cur?.version !== expected) return false;
      rec.set(k, { budget: b, version: (expected ?? 0) + 1 });
      return true;
    },
  };
  return s;
}

describe('atomic charging against a durable store', () => {
  const NEED = 'a ChargeBudgetStore with get and compareAndSet is required';
  it('a missing or incomplete store is a ChargeStoreError', async () => {
    const m = mk();
    const get = async () => undefined;
    const cas = async () => true;
    for (const s of [undefined, null, {}, { get }, { compareAndSet: cas }, { get: 1, compareAndSet: cas }]) {
      await expect(authorizeChargeAtomic(m, charge(), m.grant, s as never)).rejects.toThrow(new ChargeStoreError(NEED));
      await expect(applyHumanCosignAtomic(m, m.grant, s as never, NOW)).rejects.toThrow(new ChargeStoreError(NEED));
    }
    const err = await applyHumanCosignAtomic(m, m.grant, {} as never, NOW).catch((e: Error) => e);
    expect((err as Error).name).toBe('ChargeStoreError');
  });
  it('a malformed record is refused, a null one included', async () => {
    const m = mk();
    const ok = { budget: { B: 1, tau: 1, asOf: 1 }, version: 1 };
    const bad: unknown[] = [null, 5, 'x', { ...ok, version: 'x' }, { ...ok, version: 1.5 }, { ...ok, version: -0 }, { version: 1 }, { ...ok, budget: { B: 'x', tau: 1, asOf: 1 } }, { ...ok, budget: { B: 1, tau: Number.NaN, asOf: 1 } }, { ...ok, budget: { B: 1, tau: 1, asOf: Infinity } }];
    for (const r of bad) {
      const store: ChargeBudgetStore = { get: async () => r as never, compareAndSet: async () => true };
      await expect(authorizeChargeAtomic(m, charge(), m.grant, store)).rejects.toThrow(new ChargeStoreError('the store returned a malformed budget record'));
      await expect(applyHumanCosignAtomic(m, m.grant, store, NOW)).rejects.toThrow(new ChargeStoreError('the store returned a malformed budget record'));
    }
  });
  it('an auto charge is committed with compare-and-set; a step-up or deny is not', async () => {
    const m = mk();
    const s = memStore();
    const d = await authorizeChargeAtomic(m, charge({ amount: 10 }), m.grant, s);
    expect(d.outcome).toBe('auto');
    expect(s.cas).toBe(1);
    expect([...s.rec.values()][0]!.budget.B).toBe(490);
    const up = await authorizeChargeAtomic(m, charge({ amount: 80 }), m.grant, s);
    expect(up.outcome).toBe('step_up');
    const no = await authorizeChargeAtomic(m, charge({ merchant: 'elsewhere' }), m.grant, s);
    expect(no.outcome).toBe('deny');
    expect(s.cas).toBe(1);
  });
  it('persistent contention tries exactly eight times and then denies with a conflict reason', async () => {
    const m = mk();
    const s = memStore();
    s.compareAndSet = async () => { s.cas++; return false; };
    const d = await authorizeChargeAtomic(m, charge(), m.grant, s);
    expect(s.gets).toBe(8);
    expect(s.cas).toBe(8);
    expect(d.outcome).toBe('deny');
    expect(d.t).toBe(3);
    expect(d.cost).toBe(0);
    expect(d.reasons[0]).toBe('budget_store_conflict');
    expect(d.budgetAfter).toEqual(d.budgetBefore);
  });
  it('a co-sign is committed with compare-and-set, partial by default and full on request', async () => {
    const m = mk({ replenishPerCosign: 20 });
    const low = { budget: { B: 100, tau: NOW, asOf: NOW }, version: 3 };
    const run = async (opts?: { full?: boolean }) => {
      const s = memStore();
      s.rec.set(hashCanonical(m.grant), { ...low });
      const b = await applyHumanCosignAtomic(m, m.grant, s, NOW, opts);
      expect(s.rec.get(hashCanonical(m.grant))!.version).toBe(4);
      return b;
    };
    expect((await run()).B).toBe(120);
    expect((await run({ full: false })).B).toBe(120);
    expect((await run({ full: true })).B).toBe(500);
    const custom = memStore();
    await applyHumanCosignAtomic(m, m.grant, custom, NOW, { key: 'k1' });
    expect(custom.rec.has('k1')).toBe(true);
  });
  it('a co-sign that never commits tries eight times and then throws', async () => {
    const m = mk();
    const s = memStore();
    s.compareAndSet = async () => false;
    await expect(applyHumanCosignAtomic(m, m.grant, s, NOW)).rejects.toThrow(new ChargeStoreError('could not commit the co-sign: the budget record kept changing'));
    expect(s.gets).toBe(8);
  });
});
