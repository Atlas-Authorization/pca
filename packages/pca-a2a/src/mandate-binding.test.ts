/**
 * verifyA2APaymentMandate binds every field of the (unsigned) Payment Mandate a payer acts on to the PCActn: the x_pca
 * backreference fields, the amount / currency the PCActn params commit to, the merchant and instrument when either side
 * names one, and human_present (a verified t=3 co-signature). Before, only `pcactn_digest` was compared, so a mandate
 * could name any amount, currency, merchant or human-present modality around a valid PCActn.
 */
import { describe, expect, it } from 'vitest';
import {
  type PCActn,
  type PlanNode,
  DEFAULT_RISK_POLICY,
  buildPCActn,
  encodeKey,
  generateKeyPair,
  mintGrant,
  paramsDigest,
  signShare,
  thresholdMessage,
} from '@atlasauth/pca';
import { type A2APaymentMandate, a2aPaymentMandateFromPca, verifyA2APaymentMandate } from './index';

const NOW = 1_800_000_000_000;
const AUD = 'atlas-instance-rs-1';
const P = generateKeyPair();
const A = generateKeyPair();
const { grant } = mintGrant({
  principalSecret: P.secretKey,
  principalPublic: encodeKey(P.publicKey),
  holder: encodeKey(A.publicKey),
  goal: 'pay the invoice',
  envelope: { predicates: [{ verb: 'purchase', resource: '*' }], caveats: [{ type: 'expires', at: NOW + 3_600_000 }], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
});

/** A PCActn committing to `params` on a one-node plan, and the verifier options that open them. */
/** `contextParams: null` = the verifier supplies no params plaintext. */
function payCase(params: Record<string, unknown>, contextParams: Record<string, unknown> | null = params) {
  const plan: PlanNode[] = [{ id: 'n', verb: 'purchase', resource: 'merchant/acme/cart/42', params_digest: paramsDigest(params), reversibility_class: 'reversible' }];
  const p = buildPCActn({ grant, chain: [grant], plan, nodeId: 'n', params, counter: 1, signerSecret: A.secretKey, aud: AUD, now: NOW });
  const opts = {
    grant,
    aud: AUD,
    now: NOW,
    hooks: { revocation: () => ({ enforced: true as const, ok: true }) },
    context: {
      plan,
      planAuthorized: true,
      budget: { B: 100, tau: NOW, asOf: NOW },
      risk: { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1 },
      ...(contextParams !== null ? { params: contextParams } : {}),
    },
  };
  return { p, opts };
}
const card = { type: 'card' };
const withSubject = (m: A2APaymentMandate, over: Record<string, unknown>): A2APaymentMandate => ({ ...m, credentialSubject: { ...m.credentialSubject, ...over } as never });

describe('verifyA2APaymentMandate: amount and currency are the authorized params', () => {
  const PAY = { amount: 50, currency: 'USD' };
  it('a mandate stating exactly the committed amount / currency verifies', async () => {
    const { p, opts } = payCase(PAY);
    const r = await verifyA2APaymentMandate(a2aPaymentMandateFromPca(p, { amount: { currency: 'USD', value: 50 }, paymentMethod: card }), p, opts);
    expect(r.ok, r.reason).toBe(true);
    expect(r.result?.checks.params_digest).toBe('pass');
  });
  it('another amount or currency around the same valid PCActn is refused', async () => {
    const { p, opts } = payCase(PAY);
    const why = 'payment mandate amount / currency differ from the authorized PCActn params';
    for (const amount of [{ currency: 'USD', value: 5000 }, { currency: 'USD', value: 51 }, { currency: 'EUR', value: 50 }, { currency: 'usd', value: 50 }]) {
      expect(await verifyA2APaymentMandate(a2aPaymentMandateFromPca(p, { amount, paymentMethod: card }), p, opts)).toStrictEqual({ ok: false, reason: why, pcActn: p });
    }
  });
  it('a malformed mandate amount is refused', async () => {
    const { p, opts } = payCase(PAY);
    const m = a2aPaymentMandateFromPca(p, { amount: { currency: 'USD', value: 50 }, paymentMethod: card });
    for (const amount of [null, { currency: 'USD', value: '50' }, { currency: 'USD', value: Number.NaN }, { currency: 'USD', value: Infinity }, { currency: 1, value: 50 }]) {
      expect((await verifyA2APaymentMandate(withSubject(m, { amount }), p, opts)).reason).toBe('payment mandate amount is malformed (value must be a non-negative integer in minor units)');
    }
  });
  it('params without an amount or a currency cannot back a mandate', async () => {
    const noAmount = payCase({ currency: 'USD' });
    const m1 = a2aPaymentMandateFromPca(noAmount.p, { amount: { currency: 'USD', value: 50 }, paymentMethod: card });
    expect((await verifyA2APaymentMandate(m1, noAmount.p, noAmount.opts)).reason).toBe('the PCActn params carry no integer minor-unit amount to bind the mandate amount to');
    const strAmount = payCase({ amount: '50', currency: 'USD' });
    const m2 = a2aPaymentMandateFromPca(strAmount.p, { amount: { currency: 'USD', value: 50 }, paymentMethod: card });
    expect((await verifyA2APaymentMandate(m2, strAmount.p, strAmount.opts)).reason).toBe('the PCActn params carry no integer minor-unit amount to bind the mandate amount to');
    const noCurrency = payCase({ amount: 50 });
    const m3 = a2aPaymentMandateFromPca(noCurrency.p, { amount: { currency: 'USD', value: 50 }, paymentMethod: card });
    expect((await verifyA2APaymentMandate(m3, noCurrency.p, noCurrency.opts)).reason).toBe('the PCActn params carry no currency to bind the mandate currency to');
  });
  it('the params plaintext is required, and must open the committed params_digest (even when requireChecks omits it)', async () => {
    const absent = payCase(PAY, null);
    const m = a2aPaymentMandateFromPca(absent.p, { amount: { currency: 'USD', value: 50 }, paymentMethod: card });
    expect((await verifyA2APaymentMandate(m, absent.p, absent.opts)).reason).toBe('context.params (the PCActn params plaintext) is required to bind the payment mandate');
    // the mandate matches the SUPPLIED params, but those are not the committed ones
    const lying = payCase(PAY, { amount: 50, currency: 'USD', note: 'x' });
    const r = await verifyA2APaymentMandate(m, lying.p, { ...lying.opts, requireChecks: ['audience'] });
    expect(r.ok).toBe(false);
    expect(r.result?.checks.params_digest).toBe('fail');
  });
});

describe('verifyA2APaymentMandate: the other bound fields', () => {
  it('every x_pca field must be the PCActn\'s own', async () => {
    const { p, opts } = payCase({ amount: 50, currency: 'USD' });
    const m = a2aPaymentMandateFromPca(p, { amount: { currency: 'USD', value: 50 }, paymentMethod: card });
    for (const k of ['aud', 'verb', 'resource', 'params_digest', 'grant_ref', 'leaf_holder']) {
      const x = { ...m.credentialSubject.x_pca, [k]: 'tampered' };
      expect((await verifyA2APaymentMandate(withSubject(m, { x_pca: x }), p, opts)).reason, k).toBe(`payment mandate x_pca.${k} is not the PCActn's`);
      const { [k as 'aud']: _drop, ...without } = m.credentialSubject.x_pca;
      void _drop;
      expect((await verifyA2APaymentMandate(withSubject(m, { x_pca: without }), p, opts)).reason, k).toBe(`payment mandate x_pca.${k} is not the PCActn's`);
    }
  });
  it('merchant: equal on both sides, or absent on both', async () => {
    const why = 'payment mandate merchant differs from the authorized PCActn params';
    const plain = payCase({ amount: 50, currency: 'USD' });
    const mWithMerchant = a2aPaymentMandateFromPca(plain.p, { amount: { currency: 'USD', value: 50 }, paymentMethod: card, merchant: 'acme' });
    expect((await verifyA2APaymentMandate(mWithMerchant, plain.p, plain.opts)).reason).toBe(why);
    const acme = payCase({ amount: 50, currency: 'USD', merchant: 'acme' });
    const dropped = a2aPaymentMandateFromPca(acme.p, { amount: { currency: 'USD', value: 50 }, paymentMethod: card });
    expect((await verifyA2APaymentMandate(dropped, acme.p, acme.opts)).reason).toBe(why);
    const other = a2aPaymentMandateFromPca(acme.p, { amount: { currency: 'USD', value: 50 }, paymentMethod: card, merchant: 'evil' });
    expect((await verifyA2APaymentMandate(other, acme.p, acme.opts)).reason).toBe(why);
    const same = a2aPaymentMandateFromPca(acme.p, { amount: { currency: 'USD', value: 50 }, paymentMethod: card, merchant: 'acme' });
    expect((await verifyA2APaymentMandate(same, acme.p, acme.opts)).ok).toBe(true);
  });
  it('payment_method: bound when the params name one', async () => {
    const pm = { type: 'card', token: 'tok_1' };
    const c = payCase({ amount: 50, currency: 'USD', payment_method: pm });
    const ok = a2aPaymentMandateFromPca(c.p, { amount: { currency: 'USD', value: 50 }, paymentMethod: { token: 'tok_1', type: 'card' } });
    expect((await verifyA2APaymentMandate(ok, c.p, c.opts)).ok).toBe(true);
    const swapped = a2aPaymentMandateFromPca(c.p, { amount: { currency: 'USD', value: 50 }, paymentMethod: { type: 'card', token: 'tok_attacker' } });
    expect((await verifyA2APaymentMandate(swapped, c.p, c.opts)).reason).toBe('payment mandate payment_method differs from the authorized PCActn params');
    const unencodable = withSubject(ok, { payment_method: { type: 'card', n: 1e21 } });
    expect((await verifyA2APaymentMandate(unencodable, c.p, c.opts)).reason).toBe('payment mandate payment_method differs from the authorized PCActn params');
  });
  it('human_present: a boolean, and true only with a verified t=3 principal co-signature', async () => {
    const PAY = { amount: 50, currency: 'USD' };
    const { p, opts } = payCase(PAY);
    const m = a2aPaymentMandateFromPca(p, { amount: { currency: 'USD', value: 50 }, paymentMethod: card });
    expect((await verifyA2APaymentMandate(withSubject(m, { human_present: 'yes' }), p, opts)).reason).toBe('payment mandate human_present must be a boolean');
    const claimed = withSubject(m, { human_present: true });
    const why = 'payment mandate claims human_present but no verified principal co-signature backs it (pass humanSignerSet)';
    expect((await verifyA2APaymentMandate(claimed, p, opts)).reason).toBe(why);
    const G = generateKeyPair();
    const signerSet = [
      { role: 'agent' as const, publicKey: encodeKey(A.publicKey) },
      { role: 'guardian' as const, publicKey: encodeKey(G.publicKey) },
      { role: 'principal' as const, publicKey: encodeKey(P.publicKey) },
    ];
    expect((await verifyA2APaymentMandate(claimed, p, { ...opts, humanSignerSet: signerSet })).reason).toBe(why);
    const msg = thresholdMessage(p);
    const cosigned = { ...p, threshold: { shares: [signShare('guardian', G.secretKey, msg, { signerSet, t: 3 }), signShare('principal', P.secretKey, msg, { signerSet, t: 3 })] } } as PCActn;
    const hm = a2aPaymentMandateFromPca(cosigned, { amount: { currency: 'USD', value: 50 }, paymentMethod: card, humanSignerSet: signerSet });
    expect(hm.credentialSubject.human_present).toBe(true);
    expect((await verifyA2APaymentMandate(hm, cosigned, opts)).reason).toBe(why);
    const r = await verifyA2APaymentMandate(hm, cosigned, { ...opts, humanSignerSet: signerSet });
    expect(r.ok, r.reason).toBe(true);
  });
});

describe('minor units only: floats and negatives never reach a mandate', () => {
  it('the builder refuses a non-integer, negative or unsafe amount', () => {
    const { p } = payCase({ amount: 50, currency: 'USD' });
    for (const value of [49.99, -1, Number.NaN, Infinity, 2 ** 53]) {
      expect(() => a2aPaymentMandateFromPca(p, { amount: { currency: 'USD', value }, paymentMethod: card })).toThrow('amount.value must be a non-negative integer in minor units');
    }
  });
  it('the verifier refuses a float or negative amount in the mandate even when the params state the same number', async () => {
    for (const v of [49.99, -50]) {
      const { p, opts } = payCase({ amount: v, currency: 'USD' });
      const m = withSubject(a2aPaymentMandateFromPca(p, { amount: { currency: 'USD', value: 50 }, paymentMethod: card }), { amount: { currency: 'USD', value: v } });
      expect((await verifyA2APaymentMandate(m, p, opts)).reason).toBe('payment mandate amount is malformed (value must be a non-negative integer in minor units)');
    }
  });
  it('a float amount in the authorized params cannot back a mandate', async () => {
    const { p, opts } = payCase({ amount: 49.99, currency: 'USD' });
    const m = a2aPaymentMandateFromPca(p, { amount: { currency: 'USD', value: 50 }, paymentMethod: card });
    expect((await verifyA2APaymentMandate(m, p, opts)).reason).toBe('the PCActn params carry no integer minor-unit amount to bind the mandate amount to');
  });
});
