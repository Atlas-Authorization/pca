import { describe, expect, it } from 'vitest';
import { Ap2Error, stripeSptSettlement, toAtomicUnits, x402Settlement, type PaymentMandateClaims } from './index';
import { MERCHANT } from './testkit';

const payment = (over: Partial<PaymentMandateClaims> = {}): PaymentMandateClaims => ({
  vct: 'mandate.payment.1',
  transaction_id: 'txn-abc',
  payee: MERCHANT,
  payment_amount: { amount: 12000, currency: 'USD' },
  payment_instrument: { id: 'spt_123', type: 'shared_payment_token' },
  ...over,
});

describe('toAtomicUnits boundaries', () => {
  it('accepts zero amount', () => expect(toAtomicUnits({ amount: 0, currency: 'USD' }, 6)).toBe('0'));
  it('rejects negative, accepts 0', () => expect(() => toAtomicUnits({ amount: -1, currency: 'USD' }, 6)).toThrow(RangeError));
  it('decimals equal to the exponent is a plain pass-through', () => {
    expect(toAtomicUnits({ amount: 1234, currency: 'USD' }, 2)).toBe('1234');
    expect(toAtomicUnits({ amount: 1234, currency: 'JPY' }, 0)).toBe('1234');
  });
  it('scales up and exactly divides down', () => {
    expect(toAtomicUnits({ amount: 12000, currency: 'USD' }, 6)).toBe('120000000');
    expect(toAtomicUnits({ amount: 1200, currency: 'USD' }, 0)).toBe('12');
    expect(toAtomicUnits({ amount: 100, currency: 'USD' }, 1)).toBe('10');
    expect(() => toAtomicUnits({ amount: 1201, currency: 'USD' }, 0)).toThrow(/cannot be expressed in atomic units with 0 decimals/);
  });
  it('decimals range and message', () => {
    expect(() => toAtomicUnits({ amount: 1, currency: 'USD' }, 19)).toThrow('x402: decimals must be an integer in 0..18, got 19');
    expect(() => toAtomicUnits({ amount: 1, currency: 'USD' }, -1)).toThrow(RangeError);
    expect(toAtomicUnits({ amount: 1, currency: 'USD' }, 18)).toBe('1' + '0'.repeat(16));
  });
});

describe('x402Settlement defaults and fields', () => {
  it('with no context: every default is exact', () => {
    const r = x402Settlement.settle(payment());
    const x = Buffer.from((r.payload.header as Record<string, string>)['X-PAYMENT'] as string, 'base64').toString('utf8');
    expect(JSON.parse(x)).toEqual({ x402Version: 1, scheme: 'exact', network: 'base-sepolia', payload: { transactionId: 'txn-abc', amount: 12000, currency: 'USD' } });
    expect(r.rail).toBe('x402');
    expect(r.merchant).toBe(MERCHANT.id);
    expect(r.amount).toEqual({ amount: 12000, currency: 'USD' });
    expect(r.payload).toMatchObject({ httpStatus: 402, x402Version: 1, error: 'X-PAYMENT header is required' });
    expect((r.payload.accepts as unknown[])[0]).toEqual({
      scheme: 'exact',
      network: 'base-sepolia',
      maxAmountRequired: '120000000',
      resource: '',
      description: 'AP2 payment mandate txn-abc',
      payTo: MERCHANT.id,
      asset: 'USD',
      mimeType: 'application/json',
      maxTimeoutSeconds: 60,
    });
  });
  it('an empty context object behaves the same, supplied values override', () => {
    const e = x402Settlement.settle(payment(), {});
    expect((e.payload.accepts as { network: string }[])[0]?.network).toBe('base-sepolia');
    const r = x402Settlement.settle(payment(), { network: 'base', resourceUrl: 'https://r', payTo: '0xabc', asset: '0xtok', decimals: 2, maxTimeoutSeconds: 5 });
    expect((r.payload.accepts as unknown[])[0]).toEqual({
      scheme: 'exact', network: 'base', maxAmountRequired: '12000', resource: 'https://r', description: 'AP2 payment mandate txn-abc', payTo: '0xabc', asset: '0xtok', mimeType: 'application/json', maxTimeoutSeconds: 5,
    });
    const x = JSON.parse(Buffer.from((r.payload.header as Record<string, string>)['X-PAYMENT'] as string, 'base64').toString('utf8')) as { network: string };
    expect(x.network).toBe('base');
  });
  it('non-ASCII transaction ids are UTF-8 in the header', () => {
    const r = x402Settlement.settle(payment({ transaction_id: 'txn-é' }));
    const b = Buffer.from((r.payload.header as Record<string, string>)['X-PAYMENT'] as string, 'base64');
    expect(b.toString('utf8')).toContain('txn-é');
  });
});

describe('stripeSptSettlement', () => {
  it('shape, lower-cased currency, optional on_behalf_of', () => {
    expect(stripeSptSettlement.settle(payment())).toEqual({
      rail: 'stripe-spt',
      amount: { amount: 12000, currency: 'USD' },
      merchant: MERCHANT.id,
      payload: { shared_payment_token: 'spt_123', amount: 12000, currency: 'usd' },
    });
    expect(stripeSptSettlement.settle(payment(), { payTo: 'acct_1' }).payload).toMatchObject({ on_behalf_of: 'acct_1' });
    expect(stripeSptSettlement.settle(payment(), {}).payload).not.toHaveProperty('on_behalf_of');
  });
  it('refuses other instrument types with the exact message', () => {
    expect(() => stripeSptSettlement.settle(payment({ payment_instrument: { id: 'c', type: 'card' } }))).toThrow(
      new Ap2Error('stripe-spt: the payment instrument must be of type shared_payment_token, got card'),
    );
  });
});
