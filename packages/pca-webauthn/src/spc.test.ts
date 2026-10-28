import { describe, expect, it } from 'vitest';
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { type PCActnBody, approvalChallenge, b64u, thresholdMessage } from '@atlasauth/pca';
import { type Assertion, type SpcPaymentExpectation, approvalChallengeForActn, buildApprovalChallenge, buildStepUpChallenge, verifyAssertion } from './index';

const RP = 'pay.example.com';
const ORIGIN = 'https://pay.example.com';
const body: PCActnBody = {
  ver: 2, action: { verb: 'bank.transfer.send', resource: 'acct_1', params_digest: 'AA', reversibility_class: 'irreversible' }, grant_ref: 'g', cap_chain: [],
  plan: { root: 'r', inclusion_proof: { index: 0, size: 1, path: [] }, node_id: 'n' }, attestation: { quote_digest: '', epoch: 0, model_id: '', measurement: '', operator: '' },
  provenance: { causal_hash: '', taint_level: 0, trusted_refs: [] }, freshness: { beacon_ref: '', epoch: 0, accumulator_witness: '' }, counter: 1, risk_claim: { r: 0.9, inputs: {} },
  aud: 'rs', iat: 1, exp: 2,
};
const RENDER_DIGEST = b64u(new Uint8Array(32).fill(3));
const sk = p256.utils.randomPrivateKey();
const pub = p256.getPublicKey(sk, false);
const jwk = { kty: 'EC' as const, crv: 'P-256' as const, x: b64u(pub.slice(1, 33)), y: b64u(pub.slice(33, 65)) };
const payment = { rpId: RP, topOrigin: ORIGIN, payeeName: 'Acme GmbH', total: { currency: 'EUR', value: '125.00' }, instrument: { displayName: 'Card' } };
const exp: SpcPaymentExpectation = { topOrigin: ORIGIN, total: { currency: 'EUR', value: '125.00' }, payeeName: 'Acme GmbH' };

function assertion(challenge: Uint8Array, over: { type?: string; payment?: unknown } = {}): Assertion {
  const authenticatorData = new Uint8Array(37);
  authenticatorData.set(sha256(new TextEncoder().encode(RP)), 0);
  authenticatorData[32] = 0x05;
  const clientDataJSON = new TextEncoder().encode(JSON.stringify({ type: over.type ?? 'payment.get', challenge: b64u(challenge), origin: ORIGIN, crossOrigin: false, ...(('payment' in over ? over.payment : payment) !== undefined ? { payment: 'payment' in over ? over.payment : payment } : {}) }));
  const signed = new Uint8Array([...authenticatorData, ...sha256(clientDataJSON)]);
  return { authenticatorData, clientDataJSON, signature: p256.sign(sha256(signed), sk).toDERRawBytes(), publicKey: jwk };
}
const verify = (a: Assertion, over: { challenge?: Uint8Array; payment?: SpcPaymentExpectation | undefined } = {}) =>
  verifyAssertion(a, { expectedChallenge: over.challenge ?? buildApprovalChallenge(body, RENDER_DIGEST), rpId: RP, origins: [ORIGIN], requireUV: false, storedSignCount: 0, ...('payment' in over ? { payment: over.payment } : { payment: exp }) });

describe('approval challenge', () => {
  it('commits to the action and the render', () => {
    const c = buildApprovalChallenge(body, RENDER_DIGEST);
    expect(c).toEqual(approvalChallenge(sha256(thresholdMessage(body)), RENDER_DIGEST));
    expect(c).not.toEqual(buildStepUpChallenge(body));
    expect(approvalChallengeForActn(body, RENDER_DIGEST)).toBe(b64u(c));
    expect(buildApprovalChallenge(body, b64u(new Uint8Array(32).fill(4)))).not.toEqual(c);
  });
});

describe('Secure Payment Confirmation profile (PSD2 RTS Art. 5 dynamic linking)', () => {
  const c = buildApprovalChallenge(body, RENDER_DIGEST);
  it('accepts a payment.get assertion whose signed payment data equals the canonical render', () => {
    expect(verify(assertion(c)).ok).toBe(true);
  });
  it('refuses any change to the amount, currency, payee, top origin or rpId', () => {
    for (const p of [
      { ...payment, total: { currency: 'EUR', value: '125.01' } },
      { ...payment, total: { currency: 'USD', value: '125.00' } },
      { ...payment, payeeName: 'Acme GmbH ' },
      { ...payment, topOrigin: 'https://evil.example' },
      { ...payment, rpId: 'evil.example' },
      { ...payment, payeeName: undefined },
    ]) expect(verify(assertion(c, { payment: p })).ok).toBe(false);
  });
  it('refuses a payment assertion bound to another render, and a missing payment object', () => {
    expect(verify(assertion(buildApprovalChallenge(body, b64u(new Uint8Array(32).fill(4))))).ok).toBe(false);
    expect(verify(assertion(c, { payment: undefined })).ok).toBe(false);
    expect(verify(assertion(c, { payment: null })).ok).toBe(false);
  });
  it('a payment.get assertion is refused when no payment profile is expected, and webauthn.get when one is', () => {
    expect(verify(assertion(c), { payment: undefined }).ok).toBe(false);
    expect(verify(assertion(c, { type: 'webauthn.get' })).ok).toBe(false);
  });
  it('refuses an expectation that names no payee', () => {
    expect(verify(assertion(c), { payment: { topOrigin: ORIGIN, total: exp.total } }).ok).toBe(false);
  });
});
