/** 0.4.2 mutation kills: a processed claim is an ordinary data property (enumerable, writable, configurable) - never an accessor or a frozen slot. */
import { describe, expect, it } from 'vitest';
import { processDisclosures, sdDigest, type JsonObject } from './sdjwt';
import { checkPaymentConstraints, type OpenPaymentMandateClaims, type PaymentMandateClaims } from './index';
import { MERCHANT, NOW_S } from './testkit';

const enc = (v: unknown): string => Buffer.from(JSON.stringify(v), 'utf8').toString('base64url');

describe('processDisclosures: claim attributes', () => {
  it('disclosed and signed claims are plain data properties (the caller may reassign or delete them)', () => {
    const d = enc(['salt-1', '__proto__', { amount: 5 }]);
    const out = processDisclosures(JSON.parse('{"n": 1, "__proto__": 2, "_sd": [' + JSON.stringify(sdDigest(enc(['s', 'dis', 7]))) + ']}') as JsonObject, [enc(['s', 'dis', 7])], 'sha-256');
    for (const k of ['n', '__proto__', 'dis']) {
      expect(Object.getOwnPropertyDescriptor(out, k), k).toMatchObject({ enumerable: true, writable: true, configurable: true });
    }
    const out2 = processDisclosures({ _sd: [sdDigest(d)] }, [d], 'sha-256');
    expect(Object.getOwnPropertyDescriptor(out2, '__proto__')).toMatchObject({ enumerable: true, writable: true, configurable: true });
    expect(delete (out2 as Record<string, unknown>)['__proto__']).toBe(true);
    expect(Object.keys(out2)).toEqual([]);
  });
});


describe('payment.execution_date: only strings are instants', () => {
  const open = (constraints: unknown[]): OpenPaymentMandateClaims => ({ vct: 'mandate.payment.open.1', constraints, cnf: { jwk: {} } } as unknown as OpenPaymentMandateClaims);
  const closed = (over: Record<string, unknown>): PaymentMandateClaims =>
    ({ vct: 'mandate.payment.1', transaction_id: 't', payee: MERCHANT, payment_amount: { amount: 1000, currency: 'USD' }, payment_instrument: { id: 'i1', type: 'card' }, ...over }) as unknown as PaymentMandateClaims;
  const instant = '2026-01-01T00:00:00Z';
  const asObject = { toString: () => instant }; // a non-string that stringifies to a valid instant
  it('a non-string execution_date is not an instant (no coercion to a string)', () => {
    const r = checkPaymentConstraints(open([{ type: 'payment.execution_date' }]), closed({ execution_date: asObject }), { now: NOW_S });
    expect(r).toHaveLength(1);
    expect(r[0]).toMatch(/is not a valid instant$/);
  });
  it('a non-string window bound is not an instant either', () => {
    const r = checkPaymentConstraints(open([{ type: 'payment.execution_date', not_before: asObject }]), closed({}), { now: NOW_S });
    expect(r).toHaveLength(1);
    expect(r[0]).toMatch(/^not_before .* is not a valid instant$/);
  });
});
