import { describe, expect, it } from 'vitest';
import { encodeKey, generateKeyPair } from '@atlasauth/pca';
import {
  authorizeCharge,
  buildPaymentMandate,
  type PaymentMandateParams,
} from '@atlasauth/pca-payments';
import {
  AP2_VERSION,
  chainMandates,
  fromAP2Mandate,
  mandateHash,
  stripeSptSettlement,
  toAP2CartMandate,
  toAP2IntentMandate,
  toAP2PaymentMandate,
  verifyAP2Chain,
  verifyMandate,
  x402Settlement,
  type CartItem,
} from './index';

const principal = generateKeyPair();
const merchantKey = generateKeyPair();
const payerKey = generateKeyPair();
const agentKey = generateKeyPair();
const pub = (k: { publicKey: Uint8Array }) => encodeKey(k.publicKey);

const baseParams: PaymentMandateParams = {
  principalSecret: principal.secretKey,
  principalPublic: pub(principal),
  agentPublic: pub(agentKey),
  merchants: ['acme', 'globex'],
  categories: ['saas'],
  currency: 'USD',
  perTransactionCap: 500, // X
  autoApproveThreshold: 50, // Y
  cumulativeCap: 1000,
  periodMs: 30 * 24 * 3_600_000,
  now: 1_700_000_000_000,
};

const buildMandate = () => buildPaymentMandate(baseParams);

const items = (price: number): CartItem[] => [
  { sku: 'sku-1', name: 'Widget', quantity: 1, unit_price: { currency: 'USD', value: price } },
];

/** Full PCA → AP2 Intent → Cart → Payment chain, all signed. */
function buildChain(opts: { cartPrice: number; humanPresent?: boolean; pcaTier?: number }) {
  const mandate = buildMandate();
  const intent = toAP2IntentMandate(mandate, { issuerPublic: pub(principal), issuerSecret: principal.secretKey, now: baseParams.now });
  const cart = toAP2CartMandate(intent, { merchant: 'acme', items: items(opts.cartPrice), now: baseParams.now }, { issuerPublic: pub(merchantKey), issuerSecret: merchantKey.secretKey });
  const payment = toAP2PaymentMandate(cart, {
    issuerPublic: pub(payerKey),
    issuerSecret: payerKey.secretKey,
    paymentMethod: { type: 'card', display: 'Visa ••4242' },
    intent,
    now: baseParams.now,
    ...(opts.humanPresent !== undefined ? { humanPresent: opts.humanPresent } : {}),
    ...(opts.pcaTier !== undefined ? { pcaTier: opts.pcaTier } : {}),
  });
  return { mandate, intent, cart, payment };
}

describe('toAP2IntentMandate', () => {
  it('maps PCA terms (merchants, categories, caps, period) into a signed Intent VDC', () => {
    const intent = buildChain({ cartPrice: 40 }).intent;
    expect(intent.type).toEqual(['VerifiableCredential', 'IntentMandate']);
    const cs = intent.credentialSubject;
    expect(cs.merchants).toEqual(['acme', 'globex']);
    expect(cs.categories).toEqual(['saas']);
    expect(cs.max_amount).toEqual({ currency: 'USD', value: 500 });
    expect(cs.required_refundability).toBe(true);
    // Y (50) < X (500) ⇒ the user must confirm the concrete cart.
    expect(cs.user_cart_confirmation_required).toBe(true);
    expect(cs.x_pca).toMatchObject({ auto_approve_threshold: 50, cumulative_cap: 1000, per_transaction_cap: 500 });
    expect(verifyMandate(intent)).toBe(true);
  });

  it('accepts raw MandateTerms too', () => {
    const intent = toAP2IntentMandate(buildMandate().terms, { issuerPublic: pub(principal) });
    expect(intent.credentialSubject.merchants).toEqual(['acme', 'globex']);
    expect(intent.proof).toBeUndefined(); // no secret ⇒ unsigned
  });
});

describe('toAP2CartMandate', () => {
  it('commits items + total and binds to the intent by hash', () => {
    const { intent, cart } = buildChain({ cartPrice: 120 });
    expect(cart.credentialSubject.total).toEqual({ currency: 'USD', value: 120 });
    expect(cart.credentialSubject.merchant).toBe('acme');
    expect(cart.credentialSubject.intent_reference).toBe(mandateHash(intent));
    expect(verifyMandate(cart)).toBe(true);
  });

  it('sums multiple line items', () => {
    const { intent } = buildChain({ cartPrice: 10 });
    const cart = toAP2CartMandate(
      intent,
      {
        merchant: 'acme',
        items: [
          { name: 'A', quantity: 2, unit_price: { currency: 'USD', value: 30 } },
          { name: 'B', quantity: 1, unit_price: { currency: 'USD', value: 15.5 } },
        ],
      },
      { issuerPublic: pub(merchantKey), issuerSecret: merchantKey.secretKey },
    );
    expect(cart.credentialSubject.total.value).toBe(75.5);
  });
});

describe('toAP2PaymentMandate — human-present mapping', () => {
  it('PCA tier-3 human step-up ⇒ human_present = true', () => {
    const mandate = buildMandate();
    // amount 300 > Y(50) ⇒ step_up, tier 3.
    const decision = authorizeCharge(mandate, { merchant: 'acme', amount: 300, currency: 'USD', category: 'saas', now: baseParams.now });
    expect(decision.outcome).toBe('step_up');
    expect(decision.t).toBe(3);
    const { payment } = buildChain({ cartPrice: 300, pcaTier: decision.t });
    expect(payment.credentialSubject.human_present).toBe(true);
  });

  it('PCA tier-1 autonomous ⇒ human_present = false', () => {
    const mandate = buildMandate();
    const decision = authorizeCharge(mandate, { merchant: 'acme', amount: 40, currency: 'USD', category: 'saas', now: baseParams.now });
    expect(decision.outcome).toBe('auto');
    expect(decision.t).toBe(1);
    const { payment } = buildChain({ cartPrice: 40, pcaTier: decision.t });
    expect(payment.credentialSubject.human_present).toBe(false);
  });

  it('defaults amount to the cart total and binds to cart + intent by hash', () => {
    const { intent, cart, payment } = buildChain({ cartPrice: 120, humanPresent: true });
    expect(payment.credentialSubject.amount).toEqual({ currency: 'USD', value: 120 });
    expect(payment.credentialSubject.cart_hash).toBe(mandateHash(cart));
    expect(payment.credentialSubject.intent_hash).toBe(mandateHash(intent));
    expect(verifyMandate(payment)).toBe(true);
  });
});

describe('chainMandates / verifyAP2Chain', () => {
  it('verifies a well-formed narrowing chain', () => {
    const { intent, cart, payment } = buildChain({ cartPrice: 120, humanPresent: true });
    const chain = chainMandates(intent, cart, payment);
    const res = chain.verify();
    expect(res.ok).toBe(true);
    expect(res.reasons).toEqual([]);
  });

  it('rejects an amplifying chain (cart total > intent cap)', () => {
    // Cart price 600 > intent max_amount 500.
    const { intent, cart, payment } = buildChain({ cartPrice: 600, humanPresent: true });
    const res = verifyAP2Chain(intent, cart, payment);
    expect(res.ok).toBe(false);
    expect(res.reasons.some((r) => /exceeds intent cap/.test(r))).toBe(true);
  });

  it('rejects a payment that amplifies past the cart total', () => {
    const { intent, cart } = buildChain({ cartPrice: 120, humanPresent: true });
    const payment = toAP2PaymentMandate(cart, {
      issuerPublic: pub(payerKey),
      issuerSecret: payerKey.secretKey,
      paymentMethod: { type: 'card' },
      amount: { currency: 'USD', value: 200 }, // > cart total 120
      intent,
      now: baseParams.now,
    });
    const res = verifyAP2Chain(intent, cart, payment);
    expect(res.ok).toBe(false);
    expect(res.reasons.some((r) => /payment amount .* exceeds cart total/.test(r))).toBe(true);
  });

  it('rejects an off-allowlist merchant', () => {
    const { intent } = buildChain({ cartPrice: 120 });
    const cart = toAP2CartMandate(intent, { merchant: 'evil-corp', items: items(120) }, { issuerPublic: pub(merchantKey), issuerSecret: merchantKey.secretKey });
    const payment = toAP2PaymentMandate(cart, { issuerPublic: pub(payerKey), issuerSecret: payerKey.secretKey, paymentMethod: { type: 'card' }, intent });
    const res = verifyAP2Chain(intent, cart, payment);
    expect(res.ok).toBe(false);
    expect(res.reasons.some((r) => /not in intent allowlist/.test(r))).toBe(true);
  });

  it('rejects a tampered (re-signed by the wrong key) mandate', () => {
    const { intent, cart, payment } = buildChain({ cartPrice: 120, humanPresent: true });
    const forged = { ...cart, credentialSubject: { ...cart.credentialSubject, total: { currency: 'USD', value: 999 } } };
    const res = verifyAP2Chain(intent, forged, payment);
    expect(res.ok).toBe(false);
    // The signature no longer covers the mutated body.
    expect(res.reasons.some((r) => /cart signature invalid/.test(r))).toBe(true);
  });
});

describe('fromAP2Mandate — round-trip', () => {
  it('round-trips key Intent fields back to PCA terms', () => {
    const { intent } = buildChain({ cartPrice: 40 });
    const parsed = fromAP2Mandate(intent);
    expect(parsed.type).toBe('IntentMandate');
    expect(parsed.merchants).toEqual(['acme', 'globex']);
    expect(parsed.categories).toEqual(['saas']);
    expect(parsed.currency).toBe('USD');
    expect(parsed.perTransactionCap).toBe(500);
    expect(parsed.autoApproveThreshold).toBe(50);
    expect(parsed.cumulativeCap).toBe(1000);
    expect(parsed.periodStart).toBe(baseParams.now);
  });

  it('recovers concrete amount/merchant from a Cart and modality from a Payment', () => {
    const { cart, payment } = buildChain({ cartPrice: 120, humanPresent: true });
    const pc = fromAP2Mandate(cart);
    expect(pc).toMatchObject({ type: 'CartMandate', merchant: 'acme', amount: 120, currency: 'USD' });
    const pp = fromAP2Mandate(payment);
    expect(pp).toMatchObject({ type: 'PaymentMandate', amount: 120, currency: 'USD', humanPresent: true });
  });
});

describe('settlement backends (structural)', () => {
  it('x402 builds a 402 challenge + X-PAYMENT header shape', () => {
    const { payment } = buildChain({ cartPrice: 120, humanPresent: true });
    const inst = x402Settlement.settle(payment, { resourceUrl: 'https://api.example.com/x', payTo: '0xabc', network: 'base' });
    expect(inst.rail).toBe('x402');
    expect(inst.amount).toEqual({ currency: 'USD', value: 120 });
    const payload = inst.payload as { httpStatus: number; accepts: Array<{ payTo: string; network: string }>; header: Record<string, string> };
    expect(payload.httpStatus).toBe(402);
    expect(payload.accepts[0]?.payTo).toBe('0xabc');
    expect(payload.accepts[0]?.network).toBe('base');
    expect(typeof payload.header['X-PAYMENT']).toBe('string');
  });

  it('stripe-spt builds a shared-payment-token charge shape in minor units', () => {
    const { intent, cart } = buildChain({ cartPrice: 120 });
    const payment = toAP2PaymentMandate(cart, {
      issuerPublic: pub(payerKey),
      issuerSecret: payerKey.secretKey,
      paymentMethod: { type: 'shared_payment_token', token: 'spt_123' },
      intent,
    });
    const inst = stripeSptSettlement.settle(payment, { payTo: 'acct_merchant' });
    expect(inst.rail).toBe('stripe-spt');
    const payload = inst.payload as { shared_payment_token: string; amount: number; currency: string; on_behalf_of: string };
    expect(payload.shared_payment_token).toBe('spt_123');
    expect(payload.amount).toBe(12000); // 120.00 → 12000 cents
    expect(payload.currency).toBe('usd');
    expect(payload.on_behalf_of).toBe('acct_merchant');
  });
});

describe('module metadata', () => {
  it('pins the AP2 version modeled', () => {
    expect(AP2_VERSION).toBe('0.2');
  });
});
