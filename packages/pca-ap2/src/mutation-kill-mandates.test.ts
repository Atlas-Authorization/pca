/** Mutation-kill suite for mandates.ts: currency tables, minor-unit conversions and every validator message. */
import { describe, expect, it } from 'vitest';
import {
  Ap2Error,
  FREQUENCIES,
  PCA_CLAIM,
  VCT_CHECKOUT,
  VCT_CHECKOUT_OPEN,
  VCT_PAYMENT,
  VCT_PAYMENT_OPEN,
  assertValid,
  checkoutMandateProblems,
  currencyExponent,
  fromMinorUnits,
  generateAp2KeyPair,
  openCheckoutMandateProblems,
  openPaymentMandateProblems,
  paymentMandateProblems,
  toMinorUnits,
} from './index';

const msg = (f: () => unknown): string => {
  try {
    f();
  } catch (e) {
    expect(e).toBeInstanceOf(Ap2Error);
    return (e as Error).message;
  }
  return 'NO THROW';
};

describe('constants', () => {
  it('values', () => {
    expect(VCT_CHECKOUT).toBe('mandate.checkout.1');
    expect(VCT_CHECKOUT_OPEN).toBe('mandate.checkout.open.1');
    expect(VCT_PAYMENT).toBe('mandate.payment.1');
    expect(VCT_PAYMENT_OPEN).toBe('mandate.payment.open.1');
    expect(PCA_CLAIM).toBe('x_pca');
    expect([...FREQUENCIES]).toEqual(['ON_DEMAND', 'DAILY', 'WEEKLY', 'BIWEEKLY', 'MONTHLY', 'QUARTERLY', 'ANNUALLY']);
  });
});

describe('currencyExponent', () => {
  it('every table member and a few defaults', () => {
    for (const c of ['BIF', 'CLP', 'DJF', 'GNF', 'ISK', 'JPY', 'KMF', 'KRW', 'PYG', 'RWF', 'UGX', 'UYI', 'VND', 'VUV', 'XAF', 'XOF', 'XPF']) expect(currencyExponent(c), c).toBe(0);
    for (const c of ['BHD', 'IQD', 'JOD', 'KWD', 'LYD', 'OMR', 'TND']) expect(currencyExponent(c), c).toBe(3);
    for (const c of ['CLF', 'UYW']) expect(currencyExponent(c), c).toBe(4);
    for (const c of ['USD', 'EUR', 'GBP', 'CHF', 'ZZZ']) expect(currencyExponent(c), c).toBe(2);
  });
  it('alpha-3 uppercase only, anchored', () => {
    for (const c of ['usd', 'US', 'USDX', ' USD', 'USD ', 'USD\n', '', 'U1D', 'ÜSD']) {
      expect(msg(() => currencyExponent(c)), JSON.stringify(c)).toBe(`currency must be an ISO 4217 alpha-3 code, got ${JSON.stringify(c)}`);
    }
  });
});

describe('minor units', () => {
  it('toMinorUnits', () => {
    expect(toMinorUnits(0, 'USD')).toBe(0);
    expect(toMinorUnits(1.5, 'USD')).toBe(150);
    expect(toMinorUnits(1234, 'JPY')).toBe(1234);
    expect(toMinorUnits(1.234, 'KWD')).toBe(1234);
    expect(toMinorUnits(1.2345, 'CLF')).toBe(12345);
    expect(toMinorUnits(0.07, 'USD')).toBe(7);
    expect(toMinorUnits(10, 'USD')).toBe(1000);
  });
  it('refusals', () => {
    expect(msg(() => toMinorUnits('5' as never, 'USD'))).toBe('amount must be a finite non-negative number, got 5');
    expect(msg(() => toMinorUnits(Number.NaN, 'USD'))).toBe('amount must be a finite non-negative number, got NaN');
    expect(msg(() => toMinorUnits(Number.POSITIVE_INFINITY, 'USD'))).toBe('amount must be a finite non-negative number, got Infinity');
    expect(msg(() => toMinorUnits(-0.01, 'USD'))).toBe('amount must be a finite non-negative number, got -0.01');
    expect(msg(() => toMinorUnits(0.1 + 0.2, 'USD'))).toBe(`amount ${String(0.1 + 0.2)} is not exactly representable in USD minor units`);
    expect(msg(() => toMinorUnits(1.5, 'JPY'))).toBe('amount 1.5 is not exactly representable in JPY minor units');
    expect(msg(() => toMinorUnits(1e15, 'USD'))).toBe('amount 1000000000000000 is outside the safe integer range in minor units');
    expect(msg(() => toMinorUnits(5, 'usd'))).toMatch(/^currency must be an ISO 4217 alpha-3 code/);
  });
  it('fromMinorUnits', () => {
    expect(fromMinorUnits(0, 'USD')).toBe(0);
    expect(fromMinorUnits(12345, 'USD')).toBe(123.45);
    expect(fromMinorUnits(5, 'JPY')).toBe(5);
    expect(fromMinorUnits(1234, 'KWD')).toBe(1.234);
    expect(fromMinorUnits(12345, 'CLF')).toBe(1.2345);
    expect(fromMinorUnits(Number.MAX_SAFE_INTEGER, 'JPY')).toBe(Number.MAX_SAFE_INTEGER);
    for (const m of [-1, 1.5, Number.NaN, 2 ** 53, '5' as never]) expect(msg(() => fromMinorUnits(m, 'USD')), String(m)).toBe(`minor-unit amount must be a non-negative safe integer, got ${String(m)}`);
    expect(msg(() => fromMinorUnits(1, 'xx'))).toMatch(/^currency must be/);
  });
});

const jwk = generateAp2KeyPair().publicJwk as unknown as Record<string, unknown>;
const ref = { type: 'payment.reference', conditional_transaction_id: 'H' };
const openPay = (over: Record<string, unknown> = {}, del: string[] = []): unknown => {
  const o: Record<string, unknown> = { vct: 'mandate.payment.open.1', cnf: { jwk }, constraints: [ref], ...over };
  for (const d of del) delete o[d];
  return o;
};
const withC = (c: unknown, extra: Record<string, unknown> = {}) => openPay({ constraints: [c, ref], ...extra });

describe('open payment mandate: envelope', () => {
  it('valid', () => {
    expect(openPaymentMandateProblems(openPay())).toEqual([]);
    expect(openPaymentMandateProblems(openPay({ iat: 0, exp: 5, x_pca: {} }))).toEqual([]);
  });
  it('shape, vct, times, cnf, x_pca', () => {
    for (const v of [null, [], 'x', 5, undefined]) expect(openPaymentMandateProblems(v)).toEqual(['mandate: not an object']);
    expect(openPaymentMandateProblems(openPay({ vct: 'x' }))).toEqual(['vct: must be mandate.payment.open.1']);
    expect(openPaymentMandateProblems(openPay({}, ['vct']))).toEqual(['vct: must be mandate.payment.open.1']);
    for (const t of [1.5, -1, '5', null, Number.NaN]) {
      expect(openPaymentMandateProblems(openPay({ iat: t })), String(t)).toEqual(['iat: must be an integer epoch-seconds']);
      expect(openPaymentMandateProblems(openPay({ exp: t })), String(t)).toEqual(['exp: must be an integer epoch-seconds']);
    }
    expect(openPaymentMandateProblems(openPay({ iat: 1.5, exp: -2 }))).toEqual(['iat: must be an integer epoch-seconds', 'exp: must be an integer epoch-seconds']);
    for (const c of [undefined, null, 'x', [], {}, { jwk: 'x' }, { jwk: null }, { jwk: [] }]) {
      expect(openPaymentMandateProblems(openPay({ cnf: c })), JSON.stringify(c)).toEqual(['cnf: must be { jwk }']);
    }
    expect(openPaymentMandateProblems(openPay({ cnf: { jwk: { ...jwk, kty: 'RSA' } } }))).toEqual(['cnf.jwk: JWK must be EC P-256']);
    expect(openPaymentMandateProblems(openPay({ cnf: { jwk: { ...jwk, d: 'x' } } }))).toEqual(['cnf.jwk: JWK carries private material']);
    for (const x of [5, 'x', [], null]) expect(openPaymentMandateProblems(openPay({ x_pca: x })), JSON.stringify(x)).toEqual(['x_pca: must be an object']);
  });
  it('problems from different sections arrive in a fixed order', () => {
    expect(openPaymentMandateProblems({ vct: 'x', iat: 1.5, cnf: 1, x_pca: 1, constraints: 5, payee: 1, payment_amount: 1, payment_instrument: 1, pisp: 1, execution_date: 1, risk_data: 1 })).toEqual([
      'vct: must be mandate.payment.open.1',
      'iat: must be an integer epoch-seconds',
      'cnf: must be { jwk }',
      'x_pca: must be an object',
      'constraints: must be an array',
      'payee: not an object',
      'payment_amount: not an object',
      'payment_instrument: not an object',
      'pisp: not an object',
      'execution_date: must be a string',
      'risk_data: must be an object',
    ]);
  });
  it('constraint list', () => {
    expect(openPaymentMandateProblems(openPay({ constraints: 'x' }))).toEqual(['constraints: must be an array']);
    expect(openPaymentMandateProblems(openPay({ constraints: [] }))).toEqual(['constraints: must contain a payment.reference constraint']);
    expect(openPaymentMandateProblems(openPay({ constraints: [5] }))).toEqual(['constraints[0]: constraint must be an object with a string type', 'constraints: must contain a payment.reference constraint']);
    expect(openPaymentMandateProblems(openPay({ constraints: [{ type: 5 }, ref] }))).toEqual(['constraints[0]: constraint must be an object with a string type']);
    expect(openPaymentMandateProblems(openPay({ constraints: [[], ref] }))).toEqual(['constraints[0]: constraint must be an object with a string type']);
    expect(openPaymentMandateProblems(openPay({ constraints: [{ type: 'nope' }, ref] }))).toEqual(['constraints[0]: unknown constraint type nope']);
    expect(openPaymentMandateProblems(openPay({ constraints: [ref, { type: 'nope' }] }))).toEqual(['constraints[1]: unknown constraint type nope']);
    // the reference constraint is found even when an invalid sibling precedes it
    expect(openPaymentMandateProblems(openPay({ constraints: [null, ref] }))).toEqual(['constraints[0]: constraint must be an object with a string type']);
  });
  it('optional pre-set claims', () => {
    expect(openPaymentMandateProblems(withC(ref, { payee: { id: 'a', name: 'b' } }))).toEqual([]);
    expect(openPaymentMandateProblems(openPay({ payee: { id: '', name: '' } }))).toEqual(['payee.id: required string', 'payee.name: required string']);
    expect(openPaymentMandateProblems(openPay({ payee: { id: 'a', name: 'b', website: 5 } }))).toEqual(['payee.website: must be a string']);
    expect(openPaymentMandateProblems(openPay({ payee: { id: 'a', name: 'b', website: '' } }))).toEqual([]);
    expect(openPaymentMandateProblems(openPay({ payment_amount: { amount: 1.5, currency: 'usd' } }))).toEqual([
      'payment_amount.amount: must be a non-negative integer (minor units)',
      'payment_amount.currency: must be an ISO 4217 alpha-3 code',
    ]);
    expect(openPaymentMandateProblems(openPay({ payment_amount: { amount: 0, currency: 'USD' } }))).toEqual([]);
    expect(openPaymentMandateProblems(openPay({ payment_amount: { amount: -1, currency: 5 } }))).toEqual([
      'payment_amount.amount: must be a non-negative integer (minor units)',
      'payment_amount.currency: must be an ISO 4217 alpha-3 code',
    ]);
    expect(openPaymentMandateProblems(openPay({ payment_instrument: { id: '', type: '', description: 5 } }))).toEqual([
      'payment_instrument.id: required string',
      'payment_instrument.type: required string',
      'payment_instrument.description: must be a string',
    ]);
    expect(openPaymentMandateProblems(openPay({ payment_instrument: { id: 'a', type: 'b', description: '' } }))).toEqual([]);
    expect(openPaymentMandateProblems(openPay({ pisp: { legal_name: '', brand_name: 5 } }))).toEqual(['pisp.legal_name: required string', 'pisp.brand_name: required string', 'pisp.domain_name: required string']);
    expect(openPaymentMandateProblems(openPay({ pisp: { legal_name: 'a', brand_name: 'b', domain_name: 'c' } }))).toEqual([]);
    expect(openPaymentMandateProblems(openPay({ execution_date: '' }))).toEqual([]);
    expect(openPaymentMandateProblems(openPay({ risk_data: {} }))).toEqual([]);
    expect(openPaymentMandateProblems(openPay({ risk_data: [] }))).toEqual(['risk_data: must be an object']);
  });
});

describe('open payment mandate: constraint types', () => {
  const p = (c: unknown) => openPaymentMandateProblems(withC(c));
  it('agent_recurrence', () => {
    for (const f of FREQUENCIES) expect(p({ type: 'payment.agent_recurrence', frequency: f }), f).toEqual([]);
    for (const f of ['HOURLY', 'daily', '', 5, undefined, null]) expect(p({ type: 'payment.agent_recurrence', frequency: f }), String(f)).toEqual(['constraints[0].frequency: not a known frequency']);
    expect(p({ type: 'payment.agent_recurrence', frequency: 'DAILY', max_occurrences: 1 })).toEqual([]);
    for (const m of [0, -1, 1.5, '3', null, Number.NaN]) {
      expect(p({ type: 'payment.agent_recurrence', frequency: 'DAILY', max_occurrences: m }), String(m)).toEqual(['constraints[0].max_occurrences: must be a positive integer']);
    }
    expect(p({ type: 'payment.agent_recurrence', frequency: 'x', max_occurrences: 0 })).toEqual(['constraints[0].frequency: not a known frequency', 'constraints[0].max_occurrences: must be a positive integer']);
  });
  it('allowed lists', () => {
    expect(p({ type: 'payment.allowed_payees', allowed: [] })).toEqual([]);
    expect(p({ type: 'payment.allowed_payees', allowed: 'x' })).toEqual(['constraints[0].allowed: must be an array']);
    expect(p({ type: 'payment.allowed_payees' })).toEqual(['constraints[0].allowed: must be an array']);
    expect(p({ type: 'payment.allowed_payees', allowed: [5, { id: '', name: 'n' }] })).toEqual(['constraints[0].allowed[0]: not an object', 'constraints[0].allowed[1].id: required string']);
    expect(p({ type: 'payment.allowed_payment_instruments', allowed: [{ id: 'a', type: 't' }] })).toEqual([]);
    expect(p({ type: 'payment.allowed_payment_instruments', allowed: [{ id: 'a' }, null] })).toEqual(['constraints[0].allowed[0].type: required string', 'constraints[0].allowed[1]: not an object']);
    expect(p({ type: 'payment.allowed_payment_instruments' })).toEqual(['constraints[0].allowed: must be an array']);
    expect(p({ type: 'payment.allowed_pisps', allowed: [{ legal_name: 'a', brand_name: 'b', domain_name: 'c' }] })).toEqual([]);
    expect(p({ type: 'payment.allowed_pisps', allowed: [{ legal_name: 'a' }] })).toEqual(['constraints[0].allowed[0].brand_name: required string', 'constraints[0].allowed[0].domain_name: required string']);
    expect(p({ type: 'payment.allowed_pisps', allowed: [[]] })).toEqual(['constraints[0].allowed[0]: not an object']);
    expect(p({ type: 'payment.allowed_pisps' })).toEqual(['constraints[0].allowed: must be an array']);
  });
  it('amount_range', () => {
    const r = (o: Record<string, unknown>) => p({ type: 'payment.amount_range', currency: 'USD', max: 10, ...o });
    expect(r({})).toEqual([]);
    expect(r({ min: 0 })).toEqual([]);
    expect(r({ min: 10 })).toEqual([]);
    expect(r({ min: 11 })).toEqual(['constraints[0]: min exceeds max']);
    expect(r({ max: 0, min: 0 })).toEqual([]);
    for (const c of ['usd', 'US', 5, undefined, 'USD1']) expect(r({ currency: c }), String(c)).toEqual(['constraints[0].currency: must be an ISO 4217 alpha-3 code']);
    for (const m of [-1, 1.5, '1', undefined, null]) expect(r({ max: m }), String(m)).toEqual(['constraints[0].max: must be a non-negative integer (minor units)']);
    for (const m of [-1, 1.5, '1', null]) expect(r({ min: m }), String(m)).toEqual(['constraints[0].min: must be a non-negative integer (minor units)']);
    expect(r({ max: 'x', min: 5 })).toEqual(['constraints[0].max: must be a non-negative integer (minor units)']);
    expect(r({ currency: 'x', max: -1, min: -2 })).toEqual([
      'constraints[0].currency: must be an ISO 4217 alpha-3 code',
      'constraints[0].max: must be a non-negative integer (minor units)',
      'constraints[0].min: must be a non-negative integer (minor units)',
    ]);
  });
  it('budget', () => {
    const b = (o: Record<string, unknown>) => p({ type: 'payment.budget', currency: 'USD', max: 1.5, ...o });
    expect(b({})).toEqual([]);
    expect(b({ max: 0 })).toEqual([]);
    for (const c of ['usd', 5, undefined]) expect(b({ currency: c }), String(c)).toEqual(['constraints[0].currency: must be an ISO 4217 alpha-3 code']);
    for (const m of [-0.5, Number.NaN, Number.POSITIVE_INFINITY, '1', undefined, null]) expect(b({ max: m }), String(m)).toEqual(['constraints[0].max: must be a non-negative number (major units)']);
  });
  it('execution_date and reference', () => {
    expect(p({ type: 'payment.execution_date' })).toEqual([]);
    expect(p({ type: 'payment.execution_date', not_before: 'a', not_after: 'b' })).toEqual([]);
    expect(p({ type: 'payment.execution_date', not_before: 5, not_after: 5 })).toEqual(['constraints[0].not_before: must be a string', 'constraints[0].not_after: must be a string']);
    expect(p({ type: 'payment.execution_date', not_after: 5 })).toEqual(['constraints[0].not_after: must be a string']);
    expect(p({ type: 'payment.execution_date', not_before: null })).toEqual(['constraints[0].not_before: must be a string']);
    expect(p({ type: 'payment.reference', conditional_transaction_id: 'x' })).toEqual([]);
    for (const c of ['', 5, undefined]) expect(p({ type: 'payment.reference', conditional_transaction_id: c }), String(c)).toEqual(['constraints[0].conditional_transaction_id: required string']);
  });
});

const closedPay = (over: Record<string, unknown> = {}, del: string[] = []): unknown => {
  const o: Record<string, unknown> = {
    vct: 'mandate.payment.1', transaction_id: 'T', payee: { id: 'a', name: 'b' }, payment_amount: { amount: 1, currency: 'USD' }, payment_instrument: { id: 'i', type: 't' }, ...over,
  };
  for (const d of del) delete o[d];
  return o;
};

describe('currency pattern is anchored at both ends everywhere', () => {
  it('payment_amount, amount_range and budget', () => {
    for (const c of ['XUSD', 'USDX', ' USD', 'USD ']) {
      expect(openPaymentMandateProblems(openPay({ payment_amount: { amount: 1, currency: c } })), c).toEqual(['payment_amount.currency: must be an ISO 4217 alpha-3 code']);
      expect(openPaymentMandateProblems(withC({ type: 'payment.amount_range', currency: c, max: 1 })), c).toEqual(['constraints[0].currency: must be an ISO 4217 alpha-3 code']);
      expect(openPaymentMandateProblems(withC({ type: 'payment.budget', currency: c, max: 1 })), c).toEqual(['constraints[0].currency: must be an ISO 4217 alpha-3 code']);
    }
  });
  it('min / max comparison only between genuine integers', () => {
    const r = (o: Record<string, unknown>) => openPaymentMandateProblems(withC({ type: 'payment.amount_range', currency: 'USD', ...o }));
    expect(r({ max: '1', min: 5 })).toEqual(['constraints[0].max: must be a non-negative integer (minor units)']);
    expect(r({ max: 0, min: '1' })).toEqual(['constraints[0].min: must be a non-negative integer (minor units)']);
    expect(r({ max: 1.5, min: 5 })).toEqual(['constraints[0].max: must be a non-negative integer (minor units)']);
    expect(r({ max: 5, min: 1.5 })).toEqual(['constraints[0].min: must be a non-negative integer (minor units)']);
  });
});

describe('closed payment mandate', () => {
  it('valid and optional parts', () => {
    expect(paymentMandateProblems(closedPay())).toEqual([]);
    expect(paymentMandateProblems(closedPay({ pisp: { legal_name: 'a', brand_name: 'b', domain_name: 'c' }, execution_date: 'x', risk_data: {}, iat: 0, exp: 3, x_pca: {} }))).toEqual([]);
  });
  it('each field', () => {
    for (const v of [null, [], 'x']) expect(paymentMandateProblems(v)).toEqual(['mandate: not an object']);
    expect(paymentMandateProblems(closedPay({ vct: 'mandate.payment.open.1' }))).toEqual(['vct: must be mandate.payment.1']);
    for (const t of ['', 5, undefined]) expect(paymentMandateProblems(closedPay({ transaction_id: t })), String(t)).toEqual(['transaction_id: required string']);
    expect(paymentMandateProblems(closedPay({}, ['payee', 'payment_amount', 'payment_instrument']))).toEqual(['payee: not an object', 'payment_amount: not an object', 'payment_instrument: not an object']);
    expect(paymentMandateProblems(closedPay({ iat: 1.5, exp: 'x', x_pca: [] }))).toEqual(['iat: must be an integer epoch-seconds', 'exp: must be an integer epoch-seconds', 'x_pca: must be an object']);
    expect(paymentMandateProblems(closedPay({ pisp: 5 }))).toEqual(['pisp: not an object']);
    expect(paymentMandateProblems(closedPay({ execution_date: 5 }))).toEqual(['execution_date: must be a string']);
    expect(paymentMandateProblems(closedPay({ risk_data: 5 }))).toEqual(['risk_data: must be an object']);
    expect(paymentMandateProblems(closedPay({ payment_amount: { amount: 1, currency: 'USD', extra: 1 } }))).toEqual([]);
  });
});

const chkLine = { type: 'checkout.line_items', items: [{ id: 'r', acceptable_items: [{ id: 'a', title: 'A' }], quantity: 1 }] };
const openChk = (over: Record<string, unknown> = {}): unknown => ({ vct: 'mandate.checkout.open.1', cnf: { jwk }, constraints: [chkLine], ...over });

describe('open checkout mandate', () => {
  it('valid / envelope', () => {
    expect(openCheckoutMandateProblems(openChk())).toEqual([]);
    for (const v of [null, [], 'x']) expect(openCheckoutMandateProblems(v)).toEqual(['mandate: not an object']);
    expect(openCheckoutMandateProblems(openChk({ vct: 'x', cnf: 1, x_pca: 1, iat: 1.5 }))).toEqual([
      'vct: must be mandate.checkout.open.1', 'iat: must be an integer epoch-seconds', 'cnf: must be { jwk }', 'x_pca: must be an object',
    ]);
  });
  it('constraints', () => {
    expect(openCheckoutMandateProblems(openChk({ constraints: 'x' }))).toEqual(['constraints: must be an array']);
    expect(openCheckoutMandateProblems(openChk({ constraints: [] }))).toEqual(['constraints: must contain a checkout.line_items constraint']);
    expect(openCheckoutMandateProblems(openChk({ constraints: [{ type: 'checkout.allowed_merchants', allowed: [{ id: 'a', name: 'b' }] }, chkLine] }))).toEqual([]);
    expect(openCheckoutMandateProblems(openChk({ constraints: [{ type: 'checkout.allowed_merchants', allowed: [{ id: 'a', name: 'b' }] }] }))).toEqual(['constraints: must contain a checkout.line_items constraint']);
    expect(openCheckoutMandateProblems(openChk({ constraints: [{ type: 'checkout.allowed_merchants', allowed: 5 }, chkLine] }))).toEqual(['constraints[0].allowed: must be an array']);
    expect(openCheckoutMandateProblems(openChk({ constraints: [5, chkLine] }))).toEqual(['constraints[0]: constraint must be an object with a string type']);
    expect(openCheckoutMandateProblems(openChk({ constraints: [{ type: 5 }, chkLine] }))).toEqual(['constraints[0]: constraint must be an object with a string type']);
    expect(openCheckoutMandateProblems(openChk({ constraints: [{ type: 'checkout.x' }, chkLine] }))).toEqual(['constraints[0]: unknown constraint type checkout.x']);
    expect(openCheckoutMandateProblems(openChk({ constraints: [chkLine, { type: 'payment.reference' }] }))).toEqual(['constraints[1]: unknown constraint type payment.reference']);
  });
  it('line item requirements', () => {
    const items = (it: unknown) => openCheckoutMandateProblems(openChk({ constraints: [{ type: 'checkout.line_items', items: it }] }));
    expect(items('x')).toEqual(['constraints[0].items: must be a non-empty array']);
    expect(items([])).toEqual(['constraints[0].items: must be a non-empty array']);
    expect(items(undefined)).toEqual(['constraints[0].items: must be a non-empty array']);
    expect(items([5])).toEqual(['constraints[0].items[0]: not an object']);
    expect(items([null])).toEqual(['constraints[0].items[0]: not an object']);
    expect(items([[]])).toEqual(['constraints[0].items[0]: not an object']);
    const it1 = { id: 'r', acceptable_items: [{ id: 'a', title: 'A' }], quantity: 1 };
    expect(items([{ ...it1, id: '' }])).toEqual(['constraints[0].items[0].id: required string']);
    for (const q of [0, -1, 1.5, '1', undefined]) expect(items([{ ...it1, quantity: q }]), String(q)).toEqual(['constraints[0].items[0].quantity: must be a positive integer']);
    expect(items([{ ...it1, acceptable_items: 'x' }])).toEqual(['constraints[0].items[0].acceptable_items: must be an array']);
    expect(items([{ ...it1, acceptable_items: [] }])).toEqual([]);
    expect(items([{ ...it1, acceptable_items: [5, { id: '', title: '' }] }])).toEqual([
      'constraints[0].items[0].acceptable_items[0]: not an object',
      'constraints[0].items[0].acceptable_items[1].id: required string',
      'constraints[0].items[0].acceptable_items[1].title: required string',
    ]);
    expect(items([it1, { id: '', quantity: 0, acceptable_items: 5 }])).toEqual([
      'constraints[0].items[1].id: required string',
      'constraints[0].items[1].quantity: must be a positive integer',
      'constraints[0].items[1].acceptable_items: must be an array',
    ]);
  });
});

describe('closed checkout mandate', () => {
  const c = (over: Record<string, unknown> = {}) => ({ vct: 'mandate.checkout.1', checkout_jwt: 'j', checkout_hash: 'h', ...over });
  it('fields', () => {
    expect(checkoutMandateProblems(c())).toEqual([]);
    for (const v of [null, [], 5]) expect(checkoutMandateProblems(v)).toEqual(['mandate: not an object']);
    expect(checkoutMandateProblems(c({ vct: 'x' }))).toEqual(['vct: must be mandate.checkout.1']);
    for (const j of ['', 5, undefined]) expect(checkoutMandateProblems(c({ checkout_jwt: j })), String(j)).toEqual(['checkout_jwt: required string']);
    for (const h of ['', 5, undefined]) expect(checkoutMandateProblems(c({ checkout_hash: h })), String(h)).toEqual(['checkout_hash: required string']);
    expect(checkoutMandateProblems(c({ exp: 1.5, x_pca: 1, checkout_jwt: '', checkout_hash: '' }))).toEqual([
      'exp: must be an integer epoch-seconds', 'x_pca: must be an object', 'checkout_jwt: required string', 'checkout_hash: required string',
    ]);
  });
});

describe('assertValid', () => {
  it('returns the value or throws every problem', () => {
    const v = { a: 1 };
    expect(assertValid(v, () => [], 'thing')).toBe(v);
    expect(msg(() => assertValid(v, () => ['p1', 'p2'], 'thing'))).toBe('thing: p1; p2');
    expect(msg(() => assertValid(v, () => ['only'], 'x'))).toBe('x: only');
  });
});
