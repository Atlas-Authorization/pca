/**
 * x402 v1 (structural settlement) against the specification examples, and the Stripe SPT shape.
 * Settlement is STRUCTURAL: no network, no signing; the X-PAYMENT payload is a placeholder envelope,
 * not a signed authorization.
 */
import { describe, expect, it } from 'vitest';
import { Ap2Error, stripeSptSettlement, toAtomicUnits, x402Settlement, type PaymentMandateClaims } from './index';
import { MERCHANT, readJson } from './testkit';

interface X402Fixture {
  transportHttpV1: {
    paymentRequiredBody: { x402Version: number; error: string; accepts: Record<string, unknown>[] };
    xPaymentHeader: string;
    paymentPayloadDecoded: Record<string, unknown>;
    settlementResponseDecoded: Record<string, unknown>;
  };
  specificationV1: {
    paymentRequirementsResponseRequiredFields: string[];
    paymentRequirementsFields: { field: string; type: string; required: boolean }[];
  };
}
const X402 = readJson<X402Fixture>('x402-v1-examples.json');

const payment = (over: Partial<PaymentMandateClaims> = {}): PaymentMandateClaims => ({
  vct: 'mandate.payment.1',
  transaction_id: 'txn-abc',
  payee: MERCHANT,
  payment_amount: { amount: 12000, currency: 'USD' },
  payment_instrument: { id: 'spt_123', type: 'shared_payment_token' },
  ...over,
});

describe('x402 v1 structural settlement against the specification examples', () => {
  const run = (over?: Parameters<typeof x402Settlement.settle>[1], p: PaymentMandateClaims = payment()) =>
    x402Settlement.settle(p, {
      resourceUrl: 'https://api.example.com/premium-data',
      payTo: '0x209693Bc6afc0C5328bA36FaF03C514EF312287C',
      network: 'base-sepolia',
      asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
      ...over,
    }).payload as {
      httpStatus: number;
      x402Version: number;
      error: string;
      accepts: Record<string, unknown>[];
      header: Record<string, string>;
    };

  it('the specification\'s X-PAYMENT example decodes (standard base64) to the documented payload', () => {
    const decoded = JSON.parse(Buffer.from(X402.transportHttpV1.xPaymentHeader, 'base64').toString('utf8')) as unknown;
    expect(decoded).toEqual(X402.transportHttpV1.paymentPayloadDecoded);
  });

  it('the 402 body carries every required top-level field of PaymentRequirementsResponse', () => {
    const body = run();
    for (const f of X402.specificationV1.paymentRequirementsResponseRequiredFields) expect(body, f).toHaveProperty(f);
    expect(body.httpStatus).toBe(402);
    expect(body.x402Version).toBe(X402.transportHttpV1.paymentRequiredBody.x402Version);
  });

  it('each accepts[] entry has every Required PaymentRequirements field with the documented type', () => {
    const req = run().accepts[0];
    expect(req).toBeDefined();
    for (const f of X402.specificationV1.paymentRequirementsFields) {
      if (f.required) expect(req, f.field).toHaveProperty(f.field);
      if (req !== undefined && f.field in req) expect(typeof req[f.field], f.field).toBe(f.type);
    }
    const specKeys = Object.keys(X402.transportHttpV1.paymentRequiredBody.accepts[0] ?? {});
    for (const k of Object.keys(req ?? {})) expect(specKeys).toContain(k);
  });

  it('maxAmountRequired is a string of ATOMIC units computed from integer minor units: 12000 cents at 6 decimals is "120000000"', () => {
    const req = run().accepts[0];
    expect(req?.maxAmountRequired).toBe('120000000');
    expect(req?.maxAmountRequired).toMatch(/^\d+$/);
    expect(run({ decimals: 2 }).accepts[0]?.maxAmountRequired).toBe('12000');
    expect(run({ decimals: 0 }).accepts[0]?.maxAmountRequired).toBe('120');
    expect(run({ decimals: 18 }).accepts[0]?.maxAmountRequired).toBe('120000000000000000000');
  });

  it('asset and payTo are passed through when supplied', () => {
    const req = run().accepts[0];
    expect(req?.asset).toBe(X402.transportHttpV1.paymentRequiredBody.accepts[0]?.asset);
    expect(req?.payTo).toBe(X402.transportHttpV1.paymentRequiredBody.accepts[0]?.payTo);
  });

  it('maxTimeoutSeconds is present and overridable', () => {
    expect(run().accepts[0]?.maxTimeoutSeconds).toBe(60);
    expect(run({ maxTimeoutSeconds: 15 }).accepts[0]?.maxTimeoutSeconds).toBe(15);
  });

  it('X-PAYMENT is standard base64 (not base64url) of JSON with the specification\'s envelope keys', () => {
    const header = run().header['X-PAYMENT'] ?? '';
    expect(header).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
    expect(header.length % 4).toBe(0);
    const decoded = JSON.parse(Buffer.from(header, 'base64').toString('utf8')) as Record<string, unknown>;
    for (const k of ['x402Version', 'scheme', 'network', 'payload']) expect(decoded).toHaveProperty(k);
    expect(Object.keys(decoded).sort()).toEqual(Object.keys(X402.transportHttpV1.paymentPayloadDecoded).sort());
  });

  it('known limit: the payload is a placeholder envelope, not a signed authorization', () => {
    const header = run().header['X-PAYMENT'] ?? '';
    const decoded = JSON.parse(Buffer.from(header, 'base64').toString('utf8')) as { payload: Record<string, unknown> };
    expect(decoded.payload).not.toHaveProperty('signature');
    expect(decoded.payload).not.toHaveProperty('authorization');
  });

  it('refuses amounts and decimals that cannot be expressed exactly in atomic units (fail closed)', () => {
    const bad = (amount: number): PaymentMandateClaims => payment({ payment_amount: { amount, currency: 'USD' } });
    expect(() => x402Settlement.settle(bad(-1))).toThrow(/atomic units/);
    expect(() => x402Settlement.settle(bad(Number.NaN))).toThrow(/atomic units/);
    expect(() => x402Settlement.settle(bad(Number.POSITIVE_INFINITY))).toThrow(/atomic units/);
    expect(() => x402Settlement.settle(bad(1.5))).toThrow(/atomic units/); // a decimal is not minor units
    expect(() => x402Settlement.settle(bad(1e300))).toThrow(/atomic units/);
    expect(() => x402Settlement.settle(bad(12001), { decimals: 0 })).toThrow(/atomic units/); // 120.01 cannot be whole units
    expect(() => x402Settlement.settle(payment(), { decimals: 19 })).toThrow(/decimals/);
    expect(() => x402Settlement.settle(payment(), { decimals: -1 })).toThrow(/decimals/);
    expect(() => x402Settlement.settle(payment(), { decimals: 1.5 })).toThrow(/decimals/);
  });

  it('converts other exponents exactly (JPY has no minor unit, KWD has three)', () => {
    expect(toAtomicUnits({ amount: 500, currency: 'JPY' }, 6)).toBe('500000000');
    expect(toAtomicUnits({ amount: 1234, currency: 'KWD' }, 6)).toBe('1234000');
    expect(toAtomicUnits({ amount: 9_007_199_254_740_991, currency: 'USD' }, 18)).toBe('90071992547409910000000000000000');
  });
});

describe('Stripe Shared Payment Token settlement', () => {
  it('is structural only: the mandate amount is already in minor units; the token is the instrument id', () => {
    const inst = stripeSptSettlement.settle(payment(), { payTo: 'acct_merchant' });
    expect(inst.payload).toEqual({ shared_payment_token: 'spt_123', amount: 12000, currency: 'usd', on_behalf_of: 'acct_merchant' });
  });
  it('refuses a payment instrument that is not a shared payment token', () => {
    expect(() => stripeSptSettlement.settle(payment({ payment_instrument: { id: 'card_1', type: 'card' } }))).toThrow(Ap2Error);
  });
});
