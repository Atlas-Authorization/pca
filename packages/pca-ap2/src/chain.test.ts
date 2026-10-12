import { describe, expect, it } from 'vitest';
import {
  Ap2Error,
  fromMinorUnits,
  generateAp2KeyPair,
  parseSdJwtHop,
  presentClosedPayment,
  processDisclosures,
  sdHashOf,
  splitChain,
  toMinorUnits,
  type JsonObject,
} from './index';
import { MERCHANT, NOW_S, SCHEMA_ID, makeScenario, schema, verifyScenario } from './testkit';

const mandatesOf = (chain: string): JsonObject[] =>
  splitChain(chain).map((h) => {
    const hop = parseSdJwtHop(h);
    return (processDisclosures(hop.payload, hop.disclosures, hop.sdAlg).delegate_payload as JsonObject[])[0] as JsonObject;
  });

describe('minor units', () => {
  it('converts exactly and refuses float drift', () => {
    expect(toMinorUnits(120, 'USD')).toBe(12000);
    expect(toMinorUnits(279.99, 'USD')).toBe(27999);
    expect(toMinorUnits(0, 'USD')).toBe(0);
    expect(toMinorUnits(500, 'JPY')).toBe(500);
    expect(toMinorUnits(1.234, 'KWD')).toBe(1234);
    expect(() => toMinorUnits(0.1 + 0.2, 'USD')).toThrow(Ap2Error);
    expect(() => toMinorUnits(1.005, 'USD')).toThrow(/not exactly representable/);
    expect(() => toMinorUnits(-1, 'USD')).toThrow(Ap2Error);
    expect(() => toMinorUnits(Number.NaN, 'USD')).toThrow(Ap2Error);
    expect(() => toMinorUnits(1e300, 'USD')).toThrow(Ap2Error);
    expect(() => toMinorUnits(5, 'usd')).toThrow(/alpha-3/);
    expect(fromMinorUnits(27999, 'USD')).toBe(279.99);
    expect(fromMinorUnits(500, 'JPY')).toBe(500);
    expect(() => fromMinorUnits(1.5, 'USD')).toThrow(Ap2Error);
  });
});

describe('a PCA-bound purchase is a real AP2 SD-JWT chain', () => {
  const s = makeScenario();

  it('verifies end to end (issuer, agent key binding, merchant JWT, constraints, binding hashes)', () => {
    const r = verifyScenario(s);
    expect(r.ok, r.ok ? '' : r.reason).toBe(true);
    if (!r.ok) return;
    expect(r.payment.closed.payment_amount).toEqual({ amount: 4000, currency: 'USD' });
    expect(r.payment.closed.transaction_id).toBe(r.checkout.closed.checkout_hash);
    expect(r.checkout.openHash).toBe(sdHashOf(parseSdJwtHop(s.openCheckout)));
  });

  it('every mandate validates against the official JSON Schemas (Ajv), including the x_pca extension', () => {
    const [oc, cc] = mandatesOf(s.checkoutChain);
    const [op, cp] = mandatesOf(s.paymentChain);
    for (const [m, id] of [[oc, SCHEMA_ID.openCheckout], [cc, SCHEMA_ID.checkout], [op, SCHEMA_ID.openPayment], [cp, SCHEMA_ID.payment]] as const) {
      const v = schema(id);
      expect(v(m), `${id}: ${JSON.stringify(v.errors)}`).toBe(true);
    }
    expect(oc?.x_pca).toBeDefined();
    expect(op?.x_pca).toBeDefined();
    expect(cp?.x_pca).toBeDefined();
  });

  it('has the documented wire shape: single array-element mandate, kb+sd-jwt closed hop, sd_hash binding, integer minor units', () => {
    const hops = splitChain(s.paymentChain).map(parseSdJwtHop);
    expect(hops).toHaveLength(2);
    const [root, closed] = hops;
    expect(root?.header.alg).toBe('ES256');
    expect(root?.header.kid).toBe('agent-provider-key-1');
    expect(root?.payload.delegate_payload).toHaveLength(1);
    expect(Object.keys((root?.payload.delegate_payload as JsonObject[])[0] as JsonObject)).toEqual(['...']);
    expect(root?.payload._sd_alg).toBe('sha-256');
    expect(closed?.header).toEqual({ alg: 'ES256', typ: 'kb+sd-jwt' });
    expect(Object.keys(closed?.payload ?? {}).sort()).toEqual(['_sd_alg', 'aud', 'delegate_payload', 'iat', 'nonce', 'sd_hash']);
    expect(closed?.payload.sd_hash).toBe(sdHashOf(root as never));
    const m = mandatesOf(s.paymentChain);
    expect(Number.isInteger((m[1]?.payment_amount as { amount: number }).amount)).toBe(true);
    expect((m[0]?.constraints as JsonObject[]).find((c) => c.type === 'payment.amount_range')?.max).toBe(50000);
    expect((m[0]?.constraints as JsonObject[]).find((c) => c.type === 'payment.budget')?.max).toBe(1000);
    // chain serialisation is exactly <open>~<closed> with open ending in '~' (i.e. '~~' between hops)
    expect(s.paymentChain).toBe(`${s.openPayment}~${hops[1]?.raw}`);
    expect(s.paymentChain).toContain('~~');
  });

  it('the old non-conformant credential format is gone', async () => {
    const api = await import('./index');
    for (const name of ['toAP2IntentMandate', 'toAP2CartMandate', 'toAP2PaymentMandate', 'chainMandates', 'verifyAP2Chain', 'fromAP2Mandate', 'mandateHash', 'signMandate', 'verifyMandate', 'AP2_VERSION', 'AP2_CONTEXT']) {
      expect(api, name).not.toHaveProperty(name);
    }
  });
});

describe('tamper / replay / key matrix: every case must be refused', () => {
  const s = makeScenario();

  it('rejects wrong audience, replayed nonce, wrong issuer key, wrong merchant key', () => {
    expect(verifyScenario(s, { checkout: { expectedAudience: 'other', expectedNonce: s.nonces.checkout } }).ok).toBe(false);
    expect(verifyScenario(s, { checkout: { expectedAudience: s.aud.checkout, expectedNonce: 'replayed' } }).ok).toBe(false);
    expect(verifyScenario(s, { payment: { expectedAudience: 'other', expectedNonce: s.nonces.payment } }).ok).toBe(false);
    expect(verifyScenario(s, { payment: { expectedAudience: s.aud.payment, expectedNonce: 'replayed' } }).ok).toBe(false);
    expect(verifyScenario(s, { resolveIssuerKey: () => generateAp2KeyPair().publicJwk }).ok).toBe(false);
    expect(verifyScenario(s, { resolveIssuerKey: () => undefined }).ok).toBe(false);
    expect(verifyScenario(s, { resolveMerchantKey: () => generateAp2KeyPair().publicJwk }).ok).toBe(false);
  });

  it('rejects expired and not-yet-valid mandates', () => {
    const expired = verifyScenario(s, { now: NOW_S + 24 * 3600 + 3600 });
    expect(expired.ok).toBe(false);
    expect(!expired.ok && expired.reason).toMatch(/expired/);
    const early = verifyScenario(s, { now: NOW_S - 3600 });
    expect(early.ok).toBe(false);
    expect(!early.ok && early.reason).toMatch(/future/);
  });

  it('rejects a closed mandate signed by a key other than the open mandate\'s cnf', () => {
    const rogue = generateAp2KeyPair();
    const forged = presentClosedPayment({
      open: s.openPayment,
      agentKey: rogue,
      aud: s.aud.payment,
      nonce: s.nonces.payment,
      iat: NOW_S + 10,
      transactionId: s.transactionId,
      payee: MERCHANT,
      paymentAmount: { amount: s.amountMinor, currency: 'USD' },
      paymentInstrument: { id: 'card_4242', type: 'card' },
    });
    const r = verifyScenario(s, {}, { payment: forged });
    expect(!r.ok && r.reason).toMatch(/signature does not verify under the preceding mandate's cnf\.jwk/);
  });

  it('rejects a closed payment chained to a different open payment mandate (sd_hash)', () => {
    const other = makeScenario();
    const swapped = `${other.openPayment}${splitChain(s.paymentChain)[1]}`;
    const r = verifyScenario(s, {}, { payment: swapped });
    expect(r.ok).toBe(false);
  });

  it('rejects a payment that does not settle the quoted checkout', () => {
    const base = {
      open: s.openPayment,
      agentKey: s.agent,
      aud: s.aud.payment,
      nonce: s.nonces.payment,
      iat: NOW_S + 10,
      transactionId: s.transactionId,
      payee: MERCHANT,
      paymentAmount: { amount: s.amountMinor, currency: 'USD' },
      paymentInstrument: { id: 'card_4242', type: 'card' },
    };
    const wrongTx = verifyScenario(s, {}, { payment: presentClosedPayment({ ...base, transactionId: 'some-other-checkout' }) });
    expect(!wrongTx.ok && wrongTx.reason).toMatch(/transaction_id/);
    const cheaper = verifyScenario(s, {}, { payment: presentClosedPayment({ ...base, paymentAmount: { amount: 100, currency: 'USD' } }) });
    expect(!cheaper.ok && cheaper.reason).toMatch(/differs from the checkout total/);
    const eur = verifyScenario(s, {}, { payment: presentClosedPayment({ ...base, paymentAmount: { amount: s.amountMinor, currency: 'EUR' } }) });
    expect(eur.ok).toBe(false);
    const otherPayee = verifyScenario(s, {}, { payment: presentClosedPayment({ ...base, payee: { id: 'merchant_9', name: 'Other', website: 'https://other.example' } }) });
    expect(otherPayee.ok).toBe(false);
  });

  it('enforces the open payment constraints: per-transaction cap, cumulative budget, occurrence limit', () => {
    const big = makeScenario({ quantity: 1, unitPrice: 60_000, perTransactionCap: 800 });
    expect(verifyScenario(big).ok).toBe(true); // 600 USD: within the 800 USD cap and the 1000 USD budget
    const spent = verifyScenario(big, { context: { totalAmount: 50_000, totalUses: 1 } });
    expect(!spent.ok && spent.reason).toMatch(/cumulative spend 110000 exceeds budget 100000/);
    const used = verifyScenario(s, { context: { totalAmount: 0, totalUses: 5 } });
    expect(!used.ok && used.reason).toMatch(/maximum occurrences exceeded: 5 >= 5/);
  });

  it('a missing usage context fails closed for budgets and recurrence', () => {
    const r = verifyScenario(s, { context: undefined });
    expect(r.ok).toBe(false);
    expect(!r.ok && r.reason).toMatch(/mandate context is required/);
  });
});
