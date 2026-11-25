import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { reconcileSettlement } from './rails';
import { verifyStripeSignature } from './rails-stripe';

describe('a non-finite clock never admits (stripe webhook signature)', () => {
  const secret = 'whsec_test', body = '{"a":1}', t = 1000;
  const header = `t=${t},v1=${createHmac('sha256', secret).update(`${t}.${body}`, 'utf8').digest('hex')}`;
  it('the signature verifies at a finite clock inside the tolerance', () => {
    expect(verifyStripeSignature(body, header, secret, t, 300)).toBe(true);
  });
  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])('now of %s is refused', (bad) => {
    expect(verifyStripeSignature(body, header, secret, bad, 300)).toBe(false);
  });
  // old check admitted any age when the tolerance was +Infinity (`|now - t| <= Infinity`)
  it('an infinite tolerance is refused', () => {
    expect(verifyStripeSignature(body, header, secret, t + 10_000_000, Number.POSITIVE_INFINITY)).toBe(false);
    expect(verifyStripeSignature(body, header, secret, t, Number.POSITIVE_INFINITY)).toBe(false);
  });
});

describe('a non-finite settled amount never reconciles (payments)', () => {
  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])('settled amount of %s', (bad) => {
    const r = reconcileSettlement({ id: 'a', amount: 100, currency: 'USD', merchantId: 'm' }, { authorizationId: 'a', amount: bad, currency: 'USD', merchantId: 'm', captures: 1 });
    expect(r.ok).toBe(false);
  });
});
