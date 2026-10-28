/**
 * Property tests (seeded, dependency-free) over the money path: whatever sequence of charges arrives, in whatever order
 * and concurrency, the autonomous spend never exceeds what the principal signed, and nothing but a clean integer charge to
 * a listed merchant inside the ceiling is ever auto-approved.
 */
import { describe, expect, it } from 'vitest';
import { encodeKey, generateKeyPair } from '@atlasauth/pca';
import { buildPaymentMandate, autoSpendBound } from './mandate';
import { authorizeCharge, authorizeChargeAtomic, settleCharge, applyHumanCosign, type Charge } from './authorize';
import { memoryChargeBudgetStore } from './testing';

const principal = generateKeyPair();
const agent = generateKeyPair();
const NOW = 1_700_000_000_000;
const X = 5_000;
const Y = 1_200;
const CAP = 12_000;
const mandate = buildPaymentMandate({
  principalSecret: principal.secretKey,
  principalPublic: encodeKey(principal.publicKey),
  agentPublic: encodeKey(agent.publicKey),
  merchants: ['acme', 'globex'],
  categories: ['saas', 'cloud'],
  currency: 'USD',
  perTransactionCap: X,
  autoApproveThreshold: Y,
  cumulativeCap: CAP,
  now: NOW,
});

/** mulberry32: a tiny deterministic PRNG so a failure reproduces from its seed. */
function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const pick = <T,>(r: () => number, xs: readonly T[]): T => xs[Math.floor(r() * xs.length)]!;
const WEIRD: readonly unknown[] = [NaN, Infinity, -Infinity, -1, 0.5, 1.5, 2 ** 53, -0.0001, '100', null, undefined, {}, [], true];

function randomCharge(r: () => number): Charge {
  const roll = r();
  const amount = roll < 0.12 ? (pick(r, WEIRD) as number) : Math.floor(r() * (X * 1.4));
  return {
    merchant: r() < 0.15 ? pick(r, ['evil', 'acme*', '*', '']) : pick(r, ['acme', 'globex']),
    amount,
    currency: r() < 0.1 ? pick(r, ['EUR', 'usd', null as unknown as string]) : 'USD',
    category: r() < 0.1 ? 'gambling' : pick(r, ['saas', 'cloud']),
    now: NOW,
  };
}
const legit = (c: Charge) =>
  ['acme', 'globex'].includes(c.merchant) && Number.isSafeInteger(c.amount) && c.amount >= 0 && c.amount <= X && c.currency === 'USD' && ['saas', 'cloud'].includes(c.category as string);

describe('payments properties', () => {
  it.each([1, 2, 3, 4, 5, 6, 7, 8])('seed %i: threaded decisions never auto-approve more than the cumulative cap, and only legitimate charges are auto', (seed) => {
    const r = rng(seed);
    let m = mandate;
    let autoTotal = 0;
    for (let i = 0; i < 400; i++) {
      const c = randomCharge(r);
      const d = authorizeCharge(m, c, mandate.grant);
      if (d.outcome === 'auto') {
        expect(legit(c), JSON.stringify(c)).toBe(true);
        expect(c.amount).toBeLessThanOrEqual(Y);
        expect(d.cost).toBe(c.amount);
        autoTotal += d.cost;
        expect(autoTotal).toBeLessThanOrEqual(CAP);
        expect(d.budgetAfter.B).toBe(d.budgetBefore.B - c.amount);
      } else {
        expect(d.cost).toBe(0);
        expect(d.budgetAfter.B).toBe(d.budgetBefore.B);
      }
      if (!legit(c)) expect(d.outcome).toBe('deny');
      if (legit(c) && c.amount > Y) expect(d.outcome).toBe('step_up');
      m = settleCharge(m, d);
      expect(m.budget.B).toBeGreaterThanOrEqual(0);
      expect(m.budget.B).toBeLessThanOrEqual(CAP);
    }
    expect(autoTotal).toBeLessThanOrEqual(autoSpendBound(mandate));
  });

  it.each([11, 12, 13])('seed %i: concurrent atomic charges commit exactly what the store debited, never more than the cap', async (seed) => {
    const r = rng(seed);
    const store = memoryChargeBudgetStore();
    const charges = Array.from({ length: 60 }, () => ({ merchant: 'acme', amount: Math.floor(r() * (Y + 1)), currency: 'USD', category: 'saas', now: NOW }) as Charge);
    const ds = await Promise.all(charges.map((c) => authorizeChargeAtomic(mandate, c, mandate.grant, store, 'k')));
    const autoSum = ds.filter((d) => d.outcome === 'auto').reduce((n, d) => n + d.cost, 0);
    expect(autoSum).toBeLessThanOrEqual(CAP);
    expect((await store.get('k'))?.budget.B ?? CAP).toBe(CAP - autoSum);
  });

  it('a co-sign only ever raises the budget, never above bMax', () => {
    const r = rng(99);
    let m = mandate;
    for (let i = 0; i < 100; i++) {
      const d = authorizeCharge(m, { merchant: 'acme', amount: Math.floor(r() * Y), currency: 'USD', category: 'saas', now: NOW }, mandate.grant);
      m = settleCharge(m, d);
      if (r() < 0.2) {
        const before = m.budget.B;
        m = applyHumanCosign(m, NOW + i, { full: r() < 0.5 });
        expect(m.budget.B).toBeGreaterThanOrEqual(before);
        expect(m.budget.B).toBeLessThanOrEqual(CAP);
      }
    }
  });

  it('the dollar bound theorem: autoSpendBound equals the signed cumulative cap', () => {
    expect(autoSpendBound(mandate)).toBe(CAP);
  });
});
