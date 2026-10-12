/** Mutation-kill suite for constraints.ts: every violation text, boundary, calendar period and the max-flow line-item matcher. */
import { describe, expect, it } from 'vitest';
import {
  checkCheckoutConstraints,
  checkPaymentConstraints,
  checkoutTotal,
  merchantMatches,
  projectCheckout,
  type MandateContext,
  type UcpCheckout,
} from './constraints';
import type { Frequency, Merchant, PaymentConstraint, PaymentMandateClaims } from './mandates';
import type { JsonObject } from './sdjwt';

const M1: Merchant = { id: 'm1', name: 'One', website: 'https://one.example' };
const closed = (over: Record<string, unknown> = {}): PaymentMandateClaims =>
  ({
    vct: 'mandate.payment.1',
    transaction_id: 'T',
    payee: M1,
    payment_amount: { amount: 1000, currency: 'USD' },
    payment_instrument: { id: 'pi', type: 'card' },
    ...over,
  }) as PaymentMandateClaims;
const NOW = Date.UTC(2026, 9, 15, 12, 0, 0) / 1000; // Thursday 2026-10-15 12:00 UTC
const check = (constraints: PaymentConstraint[], c: PaymentMandateClaims = closed(), o: { now?: number; context?: MandateContext; openCheckoutHash?: string } = {}, extra: Record<string, unknown> = {}): string[] =>
  checkPaymentConstraints({ vct: 'mandate.payment.open.1', constraints, cnf: { jwk: {} }, ...extra } as never, c, { now: NOW, ...o });
const one = (c: PaymentConstraint, cl: PaymentMandateClaims = closed(), o: Parameters<typeof check>[2] = {}) => check([c], cl, o);

describe('merchantMatches', () => {
  it('ids decide when both sides have one', () => {
    expect(merchantMatches({ id: 'a', name: 'x' }, { id: 'a', name: 'y' })).toBe(true);
    expect(merchantMatches({ id: 'a', name: 'x', website: 'w' }, { id: 'b', name: 'x', website: 'w' })).toBe(false);
  });
  it('without an id on both sides name and website must both be present and equal', () => {
    expect(merchantMatches({ id: '', name: 'x', website: 'w' }, { id: 'b', name: 'x', website: 'w' })).toBe(true);
    expect(merchantMatches({ id: 'a', name: 'x', website: 'w' }, { id: '', name: 'x', website: 'w' })).toBe(true);
    expect(merchantMatches({ name: 'x', website: 'w' } as never, { name: 'x', website: 'w' } as never)).toBe(true);
    expect(merchantMatches({ name: 'x', website: 'w' } as never, { name: 'y', website: 'w' } as never)).toBe(false);
    expect(merchantMatches({ name: 'x', website: 'w' } as never, { name: 'x', website: 'z' } as never)).toBe(false);
    expect(merchantMatches({ name: 'x' } as never, { name: 'x' } as never)).toBe(false);
    expect(merchantMatches({ website: 'w' } as never, { website: 'w' } as never)).toBe(false);
    expect(merchantMatches({ name: 'x', website: 'w' } as never, { name: 'x' } as never)).toBe(false);
    expect(merchantMatches({ id: 'a', name: 'x' }, { name: 'x' } as never)).toBe(false);
  });
});

describe('pre-set claims of the open mandate', () => {
  it('payee', () => {
    expect(check([], closed(), {}, { payee: M1 })).toEqual([]);
    expect(check([], closed(), {}, { payee: { id: 'zz', name: 'Other' } })).toEqual(['pre-set payee mismatch: expected Other, got One']);
  });
  it('payment_amount, instrument, pisp and execution_date compare by value', () => {
    expect(check([], closed(), {}, { payment_amount: { currency: 'USD', amount: 1000 } })).toEqual([]);
    expect(check([], closed(), {}, { payment_amount: { amount: 1001, currency: 'USD' } })).toEqual(['pre-set payment_amount mismatch']);
    expect(check([], closed(), {}, { payment_instrument: { type: 'card', id: 'pi' } })).toEqual([]);
    expect(check([], closed(), {}, { payment_instrument: { id: 'other', type: 'card' } })).toEqual(['pre-set payment_instrument mismatch']);
    const pisp = { legal_name: 'L', brand_name: 'B', domain_name: 'd' };
    expect(check([], closed({ pisp }), {}, { pisp: { domain_name: 'd', brand_name: 'B', legal_name: 'L' } })).toEqual([]);
    expect(check([], closed(), {}, { pisp })).toEqual(['pre-set pisp mismatch']);
    expect(check([], closed({ pisp: { ...pisp, brand_name: 'X' } }), {}, { pisp })).toEqual(['pre-set pisp mismatch']);
    expect(check([], closed({ execution_date: 'D' }), {}, { execution_date: 'D' })).toEqual([]);
    expect(check([], closed({ execution_date: 'E' }), {}, { execution_date: 'D' })).toEqual(['pre-set execution_date mismatch']);
    expect(check([], closed(), {}, { execution_date: 'D' })).toEqual(['pre-set execution_date mismatch']);
  });
  it('nested key order never matters but values do', () => {
    expect(check([], closed({ payment_amount: { amount: 5, currency: 'USD' } }), {}, { payment_amount: { currency: 'USD', amount: 5 } })).toEqual([]);
    expect(check([], closed({ payment_instrument: { id: 'a', type: 'card', description: 'd' } }), {}, { payment_instrument: { description: 'd', type: 'card', id: 'a' } })).toEqual([]);
    expect(check([], closed({ payment_instrument: { id: 'a', type: 'card', description: 'd' } }), {}, { payment_instrument: { id: 'a', type: 'card', description: 'e' } })).toEqual(['pre-set payment_instrument mismatch']);
  });
  it('arrays inside pre-set claims are compared with their objects key-sorted too', () => {
    const a = { id: 'pi', type: 'card', tags: [{ x: 1, y: 2 }, [{ p: 1, q: 2 }]] };
    const b = { id: 'pi', type: 'card', tags: [{ y: 2, x: 1 }, [{ q: 2, p: 1 }]] };
    expect(check([], closed({ payment_instrument: b }), {}, { payment_instrument: a })).toEqual([]);
    expect(check([], closed({ payment_instrument: { ...b, tags: [{ y: 2, x: 1 }] } }), {}, { payment_instrument: a })).toEqual(['pre-set payment_instrument mismatch']);
  });
  it('violations accumulate in a fixed order', () => {
    const v = check([{ type: 'payment.amount_range', currency: 'EUR', max: 1 }], closed({ execution_date: 'E' }), {}, { payee: { id: 'zz', name: 'Other' }, payment_amount: { amount: 1, currency: 'USD' }, execution_date: 'D' });
    expect(v).toEqual([
      'pre-set payee mismatch: expected Other, got One',
      'pre-set payment_amount mismatch',
      'pre-set execution_date mismatch',
      'currency mismatch: expected EUR, got USD',
      'amount 1000 exceeds maximum 1',
    ]);
  });
});

describe('recurrence needs a range and a budget', () => {
  const rec: PaymentConstraint = { type: 'payment.agent_recurrence', frequency: 'ON_DEMAND' };
  const range: PaymentConstraint = { type: 'payment.amount_range', currency: 'USD', max: 5000 };
  const budget: PaymentConstraint = { type: 'payment.budget', currency: 'USD', max: 100 };
  const ctx = { totalAmount: 0, totalUses: 0 };
  it('each companion is required on its own', () => {
    expect(check([rec, budget], closed(), { context: ctx })).toEqual(['payment.agent_recurrence requires a payment.amount_range constraint']);
    expect(check([rec, range], closed(), { context: ctx })).toEqual(['payment.agent_recurrence requires a payment.budget constraint']);
    expect(check([rec], closed(), { context: ctx })).toEqual(['payment.agent_recurrence requires a payment.amount_range constraint', 'payment.agent_recurrence requires a payment.budget constraint']);
    expect(check([rec, range, budget], closed(), { context: ctx })).toEqual([]);
    expect(check([range, budget], closed(), { context: ctx })).toEqual([]);
  });
});

describe('amount_range', () => {
  const r = (over: Record<string, unknown> = {}): PaymentConstraint => ({ type: 'payment.amount_range', currency: 'USD', max: 1000, ...over }) as PaymentConstraint;
  it('currency, min and max boundaries with exact texts', () => {
    expect(one(r())).toEqual([]);
    expect(one(r({ currency: 'EUR' }))).toEqual(['currency mismatch: expected EUR, got USD']);
    expect(one(r({ max: 999 }))).toEqual(['amount 1000 exceeds maximum 999']);
    expect(one(r({ min: 1000 }))).toEqual([]);
    expect(one(r({ min: 1001 }))).toEqual(['amount 1000 below minimum 1001']);
    expect(one(r({ min: 0 }), closed({ payment_amount: { amount: 0, currency: 'USD' } }))).toEqual([]);
    expect(one(r({ min: 1 }), closed({ payment_amount: { amount: 0, currency: 'USD' } }))).toEqual(['amount 0 below minimum 1']);
    expect(one(r({ currency: 'EUR', min: 2000, max: 500 }))).toEqual(['currency mismatch: expected EUR, got USD', 'amount 1000 below minimum 2000', 'amount 1000 exceeds maximum 500']);
  });
});

describe('allow lists', () => {
  it('payees', () => {
    expect(one({ type: 'payment.allowed_payees', allowed: [{ id: 'x', name: 'X' }, M1] })).toEqual([]);
    expect(one({ type: 'payment.allowed_payees', allowed: [{ id: 'x', name: 'X' }] })).toEqual(['payee One is not in the allowed list']);
    expect(one({ type: 'payment.allowed_payees', allowed: [] })).toEqual(['payee One is not in the allowed list']);
  });
  it('instruments by id', () => {
    expect(one({ type: 'payment.allowed_payment_instruments', allowed: [{ id: 'a', type: 'card' }, { id: 'pi', type: 'whatever' }] })).toEqual([]);
    expect(one({ type: 'payment.allowed_payment_instruments', allowed: [{ id: 'a', type: 'card' }] })).toEqual(['payment instrument pi is not in the allowed list']);
  });
  it('pisps: missing, and all three fields compared', () => {
    const p = { legal_name: 'L', brand_name: 'B', domain_name: 'd' };
    const c = (allowed: unknown[]) => ({ type: 'payment.allowed_pisps', allowed }) as PaymentConstraint;
    expect(one(c([p]))).toEqual(['missing PISP in the closed mandate']);
    expect(one(c([p]), closed({ pisp: p }))).toEqual([]);
    for (const k of ['legal_name', 'brand_name', 'domain_name']) {
      expect(one(c([{ ...p, [k]: 'other' }]), closed({ pisp: p })), k).toEqual(['PISP is not in the allowed list']);
    }
    expect(one(c([{ ...p, legal_name: 'o' }, p]), closed({ pisp: p }))).toEqual([]);
  });
});

describe('reference', () => {
  it('needs the open checkout hash and compares it', () => {
    const c: PaymentConstraint = { type: 'payment.reference', conditional_transaction_id: 'H' };
    expect(one(c)).toEqual(['openCheckoutHash is required to evaluate a payment.reference constraint']);
    expect(one(c, closed(), { openCheckoutHash: '' })).toEqual(['openCheckoutHash is required to evaluate a payment.reference constraint']);
    expect(one(c, closed(), { openCheckoutHash: 'H' })).toEqual([]);
    expect(one(c, closed(), { openCheckoutHash: 'G' })).toEqual(['payment.reference does not match the open checkout mandate hash']);
  });
});

describe('budget', () => {
  const b = (max: number, currency = 'USD'): PaymentConstraint => ({ type: 'payment.budget', currency, max });
  const ctx = (totalAmount: number): { context: MandateContext } => ({ context: { totalAmount, totalUses: 0 } });
  it('currency, exponent, context', () => {
    expect(one(b(100, 'EUR'), closed(), ctx(0))).toEqual(['budget currency mismatch: expected EUR, got USD']);
    expect(one(b(100, 'JPY'), closed({ payment_amount: { amount: 1, currency: 'JPY' } }), ctx(0))).toEqual(['budget in JPY is unsupported: budget.max is converted with a fixed x100 factor']);
    expect(one(b(100, 'KWD'), closed({ payment_amount: { amount: 1, currency: 'KWD' } }), ctx(0))).toEqual(['budget in KWD is unsupported: budget.max is converted with a fixed x100 factor']);
    expect(one(b(100))).toEqual(['mandate context is required to evaluate a budget']);
  });
  it('cumulative spend boundary (spend == budget is fine)', () => {
    expect(one(b(10), closed(), ctx(0))).toEqual([]);
    expect(one(b(10), closed(), ctx(1))).toEqual(['cumulative spend 1001 exceeds budget 1000 (past spend 1)']);
    expect(one(b(10), closed(), ctx(0)).length).toBe(0);
    expect(one(b(9.99), closed(), ctx(0))).toEqual(['cumulative spend 1000 exceeds budget 999 (past spend 0)']);
  });
  it('budget.max must be a whole number of minor units (1e-6 tolerance, either direction)', () => {
    expect(one(b(0.29), closed({ payment_amount: { amount: 29, currency: 'USD' } }), ctx(0))).toEqual([]);
    expect(one(b(0.0100000005), closed({ payment_amount: { amount: 1, currency: 'USD' } }), ctx(0))).toEqual([]);
    expect(one(b(0.01000002), closed({ payment_amount: { amount: 1, currency: 'USD' } }), ctx(0))).toEqual(['budget.max is not a whole number of minor units']);
    expect(one(b(0.0099999), closed({ payment_amount: { amount: 1, currency: 'USD' } }), ctx(0))).toEqual(['budget.max is not a whole number of minor units']);
    expect(one(b(0.005), closed(), ctx(0))).toEqual(['budget.max is not a whole number of minor units']);
    // exactly on the tolerance: 1e-8 * 100 === 1e-6, which is still accepted (rounds to a zero budget)
    expect(one(b(1e-8), closed(), ctx(0))).toEqual(['cumulative spend 1000 exceeds budget 0 (past spend 0)']);
  });
});

describe('agent_recurrence', () => {
  const companions: PaymentConstraint[] = [{ type: 'payment.amount_range', currency: 'USD', max: 100000 }, { type: 'payment.budget', currency: 'USD', max: 100000 }];
  const one = (c: PaymentConstraint, cl: PaymentMandateClaims = closed(), o: Parameters<typeof check>[2] = {}): string[] =>
    check([...companions, c], cl, o).filter((v) => v !== 'mandate context is required to evaluate a budget');
  const rec = (frequency: Frequency, max_occurrences?: number): PaymentConstraint => ({ type: 'payment.agent_recurrence', frequency, ...(max_occurrences !== undefined ? { max_occurrences } : {}) }) as PaymentConstraint;
  const cx = (totalUses: number, lastUsedDate?: number): { context: MandateContext } => ({ context: { totalAmount: 0, totalUses, ...(lastUsedDate !== undefined ? { lastUsedDate } : {}) } });
  it('occurrence limit', () => {
    expect(one(rec('ON_DEMAND', 3), closed(), cx(2))).toEqual([]);
    expect(one(rec('ON_DEMAND', 3), closed(), cx(3))).toEqual(['maximum occurrences exceeded: 3 >= 3']);
    expect(one(rec('ON_DEMAND', 3), closed(), cx(7))).toEqual(['maximum occurrences exceeded: 7 >= 3']);
    expect(one(rec('ON_DEMAND', 3))).toEqual(['mandate context is required to evaluate recurrence limits']);
    expect(one(rec('ON_DEMAND'), closed(), cx(99))).toEqual([]);
    expect(one(rec('ON_DEMAND'))).toEqual([]);
  });
  it('a frequency needs the context; ON_DEMAND never does', () => {
    expect(one(rec('DAILY'))).toEqual(['mandate context is required to evaluate recurrence frequency']);
    expect(one(rec('DAILY', 5))).toEqual(['mandate context is required to evaluate recurrence limits']);
    expect(one(rec('DAILY'), closed(), cx(0))).toEqual([]);
    expect(one(rec('ON_DEMAND'), closed(), cx(0, NOW))).toEqual([]);
  });
  it('limit and frequency violations are both reported, in that order', () => {
    expect(one(rec('DAILY', 1), closed(), cx(1, NOW - 10))).toEqual(['maximum occurrences exceeded: 1 >= 1', 'already used in the current DAILY period']);
  });
  const days = (y: number, m: number, d: number, h = 0): number => Date.UTC(y, m, d, h) / 1000;
  const periodCases: [Frequency, number, number][] = [
    // [frequency, now, expected period start]
    ['DAILY', days(2026, 9, 15, 12), days(2026, 9, 15)],
    ['WEEKLY', days(2026, 9, 15, 12), days(2026, 9, 12)], // Thursday -> Monday 12th
    ['WEEKLY', days(2026, 9, 18, 12), days(2026, 9, 12)], // Sunday -> Monday 12th
    ['WEEKLY', days(2026, 9, 12, 12), days(2026, 9, 12)], // Monday itself
    ['MONTHLY', days(2026, 10, 15, 12), days(2026, 10, 1)],
    ['QUARTERLY', days(2026, 10, 15, 12), days(2026, 9, 1)], // November -> October 1st
    ['QUARTERLY', days(2026, 1, 15, 12), days(2026, 0, 1)], // February -> January 1st
    ['ANNUALLY', days(2026, 9, 15, 12), days(2026, 0, 1)],
  ];
  for (const [f, now, start] of periodCases) {
    it(`${f} period containing ${new Date(now * 1000).toISOString()} starts at ${new Date(start * 1000).toISOString()}`, () => {
      expect(one(rec(f), closed(), { now, ...cx(0, start - 1) })).toEqual([]);
      expect(one(rec(f), closed(), { now, ...cx(0, start) })).toEqual([`already used in the current ${f} period`]);
      expect(one(rec(f), closed(), { now, ...cx(0, start + 1) })).toEqual([`already used in the current ${f} period`]);
      expect(one(rec(f), closed(), { now, ...cx(0, now) })).toEqual([`already used in the current ${f} period`]);
    });
  }
  it('BIWEEKLY periods are 14-day blocks anchored on the Monday before the epoch', () => {
    const DAY = 86_400;
    const epochMonday = -3 * DAY;
    const monday = (s: number): number => {
      const d = new Date(s * 1000);
      return days(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()) - ((d.getUTCDay() + 6) % 7) * DAY;
    };
    const expected = (s: number): number => {
      const wk = (monday(s) - epochMonday) / (7 * DAY);
      return monday(s) - (wk % 2) * 7 * DAY;
    };
    for (const now of [days(2026, 9, 15, 12), days(2026, 9, 22, 12), days(2026, 9, 18, 23)]) {
      const start = expected(now);
      expect(one(rec('BIWEEKLY'), closed(), { now, ...cx(0, start - 1) }), String(now)).toEqual([]);
      expect(one(rec('BIWEEKLY'), closed(), { now, ...cx(0, start) }), String(now)).toEqual(['already used in the current BIWEEKLY period']);
    }
    // the two consecutive Thursdays fall in different blocks
    expect(expected(days(2026, 9, 15, 12))).not.toBe(expected(days(2026, 9, 22, 12)));
    expect(expected(days(2026, 9, 15, 12)) % (14 * DAY)).toBe(((epochMonday % (14 * DAY)) + 14 * DAY) % (14 * DAY));
  });
  it('a previous use in an earlier period is fine; no previous use is fine', () => {
    expect(one(rec('MONTHLY'), closed(), cx(0, days(2026, 8, 30)))).toEqual([]);
    expect(one(rec('MONTHLY'), closed(), cx(0))).toEqual([]);
    expect(one(rec('ANNUALLY'), closed(), cx(0, 0))).toEqual([]);
  });
});

describe('execution_date', () => {
  const ed = (not_before?: string, not_after?: string): PaymentConstraint => ({ type: 'payment.execution_date', ...(not_before !== undefined ? { not_before } : {}), ...(not_after !== undefined ? { not_after } : {}) }) as PaymentConstraint;
  const nowIso = new Date(NOW * 1000).toISOString();
  it('a payment without a date is evaluated at the verification time', () => {
    expect(one(ed(nowIso))).toEqual([]);
    expect(one(ed(new Date((NOW + 1) * 1000).toISOString()))).toEqual([`execution date is before the allowed window (not_before ${new Date((NOW + 1) * 1000).toISOString()})`]);
    expect(one(ed(undefined, nowIso))).toEqual([]);
    expect(one(ed(undefined, new Date((NOW - 1) * 1000).toISOString()))).toEqual([`execution date is after the allowed window (not_after ${new Date((NOW - 1) * 1000).toISOString()})`]);
    expect(one(ed())).toEqual([]);
  });
  it('bounds are inclusive instants, not strings', () => {
    const at = closed({ execution_date: '2026-06-01T10:00:00Z' });
    expect(one(ed('2026-06-01T10:00:00Z', '2026-06-01T10:00:00Z'), at)).toEqual([]);
    expect(one(ed('2026-06-01T12:00:00+02:00', '2026-06-01T09:00:00-01:00'), at)).toEqual([]);
    expect(one(ed('2026-06-01T10:00:01Z'), at)).toEqual(['execution date is before the allowed window (not_before 2026-06-01T10:00:01Z)']);
    expect(one(ed(undefined, '2026-06-01T09:59:59Z'), at)).toEqual(['execution date is after the allowed window (not_after 2026-06-01T09:59:59Z)']);
    // both bounds violated: reported in the order not_before, not_after
    expect(one(ed('2026-06-02T00:00:00Z', '2026-05-01T00:00:00Z'), at)).toEqual([
      'execution date is before the allowed window (not_before 2026-06-02T00:00:00Z)',
      'execution date is after the allowed window (not_after 2026-05-01T00:00:00Z)',
    ]);
  });
  it('unparseable values', () => {
    expect(one(ed(), closed({ execution_date: 'tomorrow' }))).toEqual(['execution_date tomorrow is not a valid instant']);
    expect(one(ed('soon', 'later'), closed({ execution_date: '2026-06-01T10:00:00Z' }))).toEqual(['not_before soon is not a valid instant', 'not_after later is not a valid instant']);
    expect(one(ed('soon'), closed({ execution_date: '2026-06-01T10:00:00Z' }))).toEqual(['not_before soon is not a valid instant']);
    expect(one(ed(undefined, 'later'), closed({ execution_date: '2026-06-01T10:00:00Z' }))).toEqual(['not_after later is not a valid instant']);
  });
  it('an unknown constraint type is a violation', () => {
    expect(one({ type: 'payment.made_up' } as never)).toEqual(['unknown constraint type payment.made_up']);
    expect(one({} as never)).toEqual(['unknown constraint type undefined']);
  });
});

describe('projectCheckout', () => {
  const li = (over: Record<string, unknown> = {}) => ({ id: 'l', item: { id: 'sku', title: 'T', price: 100 }, quantity: 1, ...over });
  const base = (over: Record<string, unknown> = {}): JsonObject =>
    ({ id: 'c', currency: 'USD', line_items: [li()], totals: [{ type: 'total', amount: 100 }], ...over }) as never;
  const msg = (p: JsonObject): string => {
    try {
      projectCheckout(p);
    } catch (e) {
      return (e as Error).message;
    }
    return 'NO THROW';
  };
  it('projection of a good payload (extra fields dropped, merchant optional)', () => {
    const p = projectCheckout(base({ status: 'x', extra: 1, line_items: [li({ junk: 1, item: { id: 'sku', title: 'T', price: 100, more: 1 } })] }));
    expect(p).toStrictEqual({ id: 'c', currency: 'USD', line_items: [{ id: 'l', item: { id: 'sku', title: 'T', price: 100 }, quantity: 1 }], totals: [{ type: 'total', amount: 100 }] });
    expect(projectCheckout(base({ merchant: { id: 'm', name: 'N' } })).merchant).toStrictEqual({ id: 'm', name: 'N' });
    expect(projectCheckout(base({ merchant: { id: 'm', name: 'N', website: 'w' } })).merchant).toStrictEqual({ id: 'm', name: 'N', website: 'w' });
    expect(projectCheckout(base({ merchant: { id: 'm', name: 'N', website: 5 } })).merchant).toStrictEqual({ id: 'm', name: 'N' });
    expect(projectCheckout(base({ totals: [] })).totals).toEqual([]);
    expect(projectCheckout(base({ line_items: [li({ item: { id: 'a', title: '', price: 0 } })] })).line_items[0]?.item).toEqual({ id: 'a', title: '', price: 0 });
  });
  it('top-level fields', () => {
    expect(msg(base({ id: undefined }))).toBe('checkout_jwt payload: id is required');
    expect(msg(base({ id: '' }))).toBe('checkout_jwt payload: id is required');
    expect(msg(base({ id: 5 }))).toBe('checkout_jwt payload: id is required');
    for (const c of ['usd', 'US', 'USDX', '', 5, undefined, ['USD'], { toString: () => 'USD' }]) expect(msg(base({ currency: c as never })), String(c)).toBe('checkout_jwt payload: currency must be ISO 4217');
    expect(msg(base({ currency: ' USD' }))).toBe('checkout_jwt payload: currency must be ISO 4217');
    expect(msg(base({ currency: 'USD\n' }))).toBe('checkout_jwt payload: currency must be ISO 4217');
    for (const l of [[], 'x', undefined, {}]) expect(msg(base({ line_items: l })), JSON.stringify(l)).toBe('checkout_jwt payload: line_items must be a non-empty array');
    for (const t of ['x', undefined, {}]) expect(msg(base({ totals: t })), JSON.stringify(t)).toBe('checkout_jwt payload: totals must be an array');
  });
  it('line items', () => {
    for (const bad of [5, null, [], { item: { id: 'a', title: 't', price: 1 }, quantity: 1 }, { id: 5, item: { id: 'a', title: 't', price: 1 }, quantity: 1 }, { id: 'l', item: 'x', quantity: 1 }, { id: 'l', quantity: 1 }]) {
      expect(msg(base({ line_items: [li(), bad] })), JSON.stringify(bad)).toBe('checkout_jwt payload: line_items[1] is malformed');
    }
    const itemMsg = 'checkout_jwt payload: line_items[0].item needs id, title and integer minor-unit price';
    for (const item of [{ title: 't', price: 1 }, { id: 5, title: 't', price: 1 }, { id: 'a', price: 1 }, { id: 'a', title: 5, price: 1 }, { id: 'a', title: 't' }, { id: 'a', title: 't', price: 1.5 }, { id: 'a', title: 't', price: -1 }, { id: 'a', title: 't', price: '1' }, { id: 'a', title: 't', price: 2 ** 53 }]) {
      expect(msg(base({ line_items: [li({ item })] })), JSON.stringify(item)).toBe(itemMsg);
    }
    const qMsg = 'checkout_jwt payload: line_items[0].quantity must be a positive integer';
    for (const q of [0, -1, 1.5, '1', undefined, 2 ** 53]) expect(msg(base({ line_items: [li({ quantity: q })] })), String(q)).toBe(qMsg);
    expect(projectCheckout(base({ line_items: [li({ quantity: 1 })] })).line_items[0]?.quantity).toBe(1);
  });
  it('totals and merchant', () => {
    for (const t of [5, null, [], { amount: 1 }, { type: 5, amount: 1 }, { type: 'total' }, { type: 'total', amount: 1.5 }, { type: 'total', amount: '1' }]) {
      expect(msg(base({ totals: [{ type: 'subtotal', amount: 1 }, t] })), JSON.stringify(t)).toBe('checkout_jwt payload: totals[1] is malformed');
    }
    expect(projectCheckout(base({ totals: [{ type: 'discount', amount: -5 }] })).totals).toEqual([{ type: 'discount', amount: -5 }]);
    for (const m of [5, null, [], 'x', { name: 'N' }, { id: 'm' }, { id: 5, name: 'N' }, { id: 'm', name: 5 }]) {
      expect(msg(base({ merchant: m })), JSON.stringify(m)).toBe('checkout_jwt payload: merchant needs id and name');
    }
  });
});

describe('checkoutTotal', () => {
  const c = (totals: { type: string; amount: number }[]): UcpCheckout => ({ id: 'c', currency: 'USD', line_items: [], totals });
  it('exactly one total entry', () => {
    expect(checkoutTotal(c([{ type: 'subtotal', amount: 1 }, { type: 'total', amount: 9 }]))).toBe(9);
    expect(checkoutTotal(c([{ type: 'total', amount: 0 }]))).toBe(0);
    expect(checkoutTotal(c([]))).toBeUndefined();
    expect(checkoutTotal(c([{ type: 'subtotal', amount: 1 }]))).toBeUndefined();
    expect(checkoutTotal(c([{ type: 'total', amount: 1 }, { type: 'total', amount: 1 }]))).toBeUndefined();
  });
});

describe('checkout constraints', () => {
  const co = (items: [string, number][], merchant: Merchant | null = M1): UcpCheckout => ({
    id: 'c', currency: 'USD', ...(merchant ? { merchant } : {}), totals: [],
    line_items: items.map(([sku, quantity], i) => ({ id: `l${i}`, item: { id: sku, title: sku, price: 1 }, quantity })),
  });
  const req = (id: string, skus: string[], quantity: number) => ({ id, acceptable_items: skus.map((s) => ({ id: s, title: s })), quantity });
  const li = (...items: ReturnType<typeof req>[]) => ({ type: 'checkout.line_items' as const, items });
  const run = (constraints: unknown[], c: UcpCheckout): string[] => checkCheckoutConstraints({ vct: 'mandate.checkout.open.1', constraints, cnf: { jwk: {} } } as never, c);
  const bad = (assigned: number, required: number, carted: number) => `line items do not satisfy the constraint: assigned ${assigned} of ${required} required and ${carted} carted units`;

  it('merchants', () => {
    expect(run([{ type: 'checkout.allowed_merchants', allowed: [M1] }], co([]))).toEqual([]);
    expect(run([{ type: 'checkout.allowed_merchants', allowed: [M1] }], co([], null))).toEqual(['missing merchant in the checkout']);
    expect(run([{ type: 'checkout.allowed_merchants', allowed: [{ id: 'x', name: 'X' }] }], co([]))).toEqual(['merchant One is not in the allowed list']);
    expect(run([{ type: 'checkout.allowed_merchants', allowed: [] }], co([]))).toEqual(['merchant One is not in the allowed list']);
    expect(run([{ type: 'checkout.allowed_merchants', allowed: [{ id: 'x', name: 'X' }, M1] }], co([]))).toEqual([]);
  });
  it('unknown constraint type and constraint concatenation', () => {
    expect(run([{ type: 'checkout.whatever' }], co([]))).toEqual(['unknown constraint type checkout.whatever']);
    expect(run([{}], co([]))).toEqual(['unknown constraint type undefined']);
    expect(run([{ type: 'checkout.allowed_merchants', allowed: [] }, { type: 'checkout.nope' }, li(req('r', ['a'], 1))], co([]))).toEqual([
      'merchant One is not in the allowed list',
      'unknown constraint type checkout.nope',
      'empty cart does not satisfy a line_items constraint',
    ]);
    expect(run([], co([]))).toEqual([]);
  });
  it('matching quantities exactly', () => {
    expect(run([li(req('r', ['a'], 2))], co([['a', 2]]))).toEqual([]);
    expect(run([li(req('r', ['a'], 2))], co([['a', 1]]))).toEqual([bad(1, 2, 1)]);
    expect(run([li(req('r', ['a'], 2))], co([['a', 3]]))).toEqual([bad(2, 2, 3)]);
    expect(run([li(req('r', ['a'], 1))], co([['b', 1]]))).toEqual([bad(0, 1, 1)]);
    expect(run([li(req('r', ['a'], 1))], co([['a', 1], ['b', 1]]))).toEqual([bad(1, 1, 2)]);
    expect(run([li(req('r', ['a', 'b'], 3))], co([['a', 1], ['b', 2]]))).toEqual([]);
    expect(run([li(req('r', ['a'], 1))], co([]))).toEqual(['empty cart does not satisfy a line_items constraint']);
  });
  it('the same SKU on several cart lines is summed', () => {
    expect(run([li(req('r', ['a'], 3))], co([['a', 1], ['a', 2]]))).toEqual([]);
    expect(run([li(req('r', ['a'], 2))], co([['a', 1], ['a', 2]]))).toEqual([bad(2, 2, 3)]);
  });
  it('an empty acceptable list matches nothing (never a wildcard)', () => {
    expect(run([li(req('r', [], 1))], co([['a', 1]]))).toEqual([bad(0, 1, 1)]);
    expect(run([li(req('r', [], 0))], co([['a', 1]]))).toEqual([bad(0, 0, 1)]);
  });
  it('several requirements need augmenting paths (reverse edges)', () => {
    // A is acceptable to both slots, B only to the first: A must go to the second slot
    expect(run([li(req('r1', ['a', 'b'], 1), req('r2', ['a'], 1))], co([['a', 1], ['b', 1]]))).toEqual([]);
    expect(run([li(req('r1', ['a'], 1), req('r2', ['a', 'b'], 1))], co([['a', 1], ['b', 1]]))).toEqual([]);
    expect(run([li(req('r1', ['a', 'b'], 1), req('r2', ['a'], 1))], co([['a', 2]]))).toEqual([]);
    expect(run([li(req('r1', ['a'], 1), req('r2', ['a'], 1))], co([['a', 1], ['b', 1]]))).toEqual([bad(1, 2, 2)]);
    expect(run([li(req('r1', ['a'], 2), req('r2', ['b'], 2))], co([['a', 2], ['b', 2]]))).toEqual([]);
    expect(run([li(req('r1', ['a'], 2), req('r2', ['b'], 2))], co([['a', 3], ['b', 1]]))).toEqual([bad(3, 4, 4)]);
    expect(run([li(req('r1', ['a', 'b', 'c'], 2), req('r2', ['c', 'd'], 2), req('r3', ['a'], 1))], co([['a', 1], ['b', 1], ['c', 2], ['d', 1]]))).toEqual([]);
    expect(run([li(req('r1', ['a', 'b', 'c'], 2), req('r2', ['c', 'd'], 2), req('r3', ['a'], 1))], co([['a', 3], ['d', 2]]))).toEqual([]);
    expect(run([li(req('r1', ['a', 'b', 'c'], 2), req('r2', ['c', 'd'], 2), req('r3', ['a'], 1))], co([['a', 4], ['d', 1]]))).toEqual([bad(4, 5, 5)]);
  });
  it('a requirement not reachable by any carted SKU is unsatisfied while others are', () => {
    expect(run([li(req('r1', ['a'], 1), req('r2', ['zzz'], 1))], co([['a', 1]]))).toEqual([bad(1, 2, 1)]);
  });
  it('large quantities do not overflow the capacity bookkeeping', () => {
    expect(run([li(req('r', ['a'], 1_000_000))], co([['a', 1_000_000]]))).toEqual([]);
    expect(run([li(req('r', ['a'], 5_000_000_000))], co([['a', 5_000_000_000]]))).toEqual([]);
  });
});
