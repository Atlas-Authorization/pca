/** Vectors: the x402 core specification v2 examples (PaymentPayload, SettlementResponse) and the HTTP transport specification flow. */
import { describe, expect, it } from 'vitest';
import {
  X402_HTTP_STATUS,
  decodePaymentResponseHeader,
  decodePaymentSignatureHeader,
  encodePaymentResponseHeader,
  encodePaymentSignatureHeader,
  normalizeX402Payload,
  paymentPayloadV2Problems,
  readPaymentSignature,
  settlementResponseProblems,
  x402PaymentSignatureHeaders,
  x402SettlementResponse,
  type X402PaymentPayloadV2,
  type X402SettlementResponse,
} from './index';

const SIG = `0x${'ab'.repeat(65)}`; // the specification's signature is elided; any hex string is scheme-opaque here
// x402 specification v2, "PaymentPayload" example
const SPEC_PAYLOAD: X402PaymentPayloadV2 = {
  x402Version: 2,
  resource: { url: 'https://api.example.com/premium-data', description: 'Access to premium market data', mimeType: 'application/json' },
  accepted: { scheme: 'exact', network: 'eip155:84532', amount: '10000', asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e', payTo: '0x209693Bc6afc0C5328bA36FaF03C514EF312287C', maxTimeoutSeconds: 60, extra: { name: 'USDC', version: '2' } },
  payload: { signature: SIG, authorization: { from: '0x857b06519E91e3A54538791bDbb0E22373e36b66', to: '0x209693Bc6afc0C5328bA36FaF03C514EF312287C', value: '10000', validAfter: '1740672089', validBefore: '1740672154', nonce: '0xf3746613c2d920b5fdabc0856f2aeb2d4f88ee6037b8cc5d04a71a4462f13480' } },
  extensions: {},
};
// x402 specification v2, "SettlementResponse" example (verbatim)
const SPEC_SETTLEMENT: X402SettlementResponse = {
  success: true,
  transaction: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
  network: 'eip155:84532',
  payer: '0x857b06519E91e3A54538791bDbb0E22373e36b66',
};

describe('PAYMENT-SIGNATURE (request header)', () => {
  it('the specification PaymentPayload example is valid and round-trips through the header', () => {
    expect(paymentPayloadV2Problems(SPEC_PAYLOAD)).toEqual([]);
    const h = encodePaymentSignatureHeader(SPEC_PAYLOAD);
    expect(h).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
    expect(decodePaymentSignatureHeader(h)).toEqual(SPEC_PAYLOAD);
    expect(JSON.parse(Buffer.from(h, 'base64').toString('utf8'))).toEqual(SPEC_PAYLOAD);
    expect(x402PaymentSignatureHeaders(SPEC_PAYLOAD)).toEqual({ 'PAYMENT-SIGNATURE': h });
  });
  it('a server reads it case-insensitively, and the payload feeds the settlement normaliser', () => {
    const p: X402PaymentPayloadV2 = { ...SPEC_PAYLOAD, payload: { token: 'jws' } };
    const h = encodePaymentSignatureHeader(p);
    for (const name of ['PAYMENT-SIGNATURE', 'payment-signature', 'Payment-Signature']) {
      const r = readPaymentSignature({ [name]: h, accept: 'application/json' });
      expect(r).toEqual({ ok: true, payload: p });
    }
    const r = readPaymentSignature({ 'payment-signature': [h, 'ignored'] });
    expect(r.ok && normalizeX402Payload(r.payload)).toEqual({ ok: true, version: 2, token: 'jws', accepted: p.accepted, amount: 10000 });
  });
  it('a missing header is 402; an undecodable or invalid one is 400 with the reason; it never throws', () => {
    expect(readPaymentSignature({})).toEqual({ ok: false, status: 402, reason: 'PAYMENT-SIGNATURE header is required' });
    expect(readPaymentSignature({ 'payment-signature': '' })).toEqual({ ok: false, status: 402, reason: 'PAYMENT-SIGNATURE header is required' });
    expect(readPaymentSignature({ 'payment-signature': 'not base64!' })).toEqual({ ok: false, status: 400, reason: 'x402: PAYMENT-SIGNATURE is not base64' });
    expect(readPaymentSignature({ 'payment-signature': Buffer.from('{').toString('base64') })).toEqual({ ok: false, status: 400, reason: 'x402: PAYMENT-SIGNATURE is not JSON' });
    const v1 = Buffer.from(JSON.stringify({ ...SPEC_PAYLOAD, x402Version: 1 })).toString('base64');
    expect(readPaymentSignature({ 'payment-signature': v1 })).toEqual({ ok: false, status: 400, reason: 'x402: x402Version must be 2' });
  });
  it.each([
    ['no accepted requirement', { accepted: undefined }, 'accepted.requirements must be an object'],
    ['a bad accepted network', { accepted: { ...SPEC_PAYLOAD.accepted, network: 'base' } }, 'accepted.network must be a CAIP-2 identifier'],
    ['a non-object scheme payload', { payload: 'sig' }, 'payload must be an object'],
    ['a bad resource', { resource: { url: '/x' } }, 'resource.url must be an absolute http(s) URL'],
    ['non-object extensions', { extensions: [] }, 'extensions must be an object'],
  ])('refuses to encode %s', (_n, over, problem) => {
    expect(paymentPayloadV2Problems({ ...SPEC_PAYLOAD, ...over })).toEqual([problem]);
    expect(() => encodePaymentSignatureHeader({ ...SPEC_PAYLOAD, ...over } as never)).toThrow(problem);
  });
});

describe('PAYMENT-RESPONSE (response header)', () => {
  it('the specification SettlementResponse example round-trips', () => {
    expect(settlementResponseProblems(SPEC_SETTLEMENT)).toEqual([]);
    expect(decodePaymentResponseHeader(encodePaymentResponseHeader(SPEC_SETTLEMENT))).toEqual(SPEC_SETTLEMENT);
  });
  it('a settled outcome is 200 with success true; a failure is 402 with success false, the reason and an empty transaction', () => {
    const ok = x402SettlementResponse({ settled: true, transaction: SPEC_SETTLEMENT.transaction, payer: SPEC_SETTLEMENT.payer, amount: '10000' }, 'eip155:84532');
    expect(ok.status).toBe(200);
    expect(decodePaymentResponseHeader(ok.headers['PAYMENT-RESPONSE']!)).toEqual({ ...SPEC_SETTLEMENT, amount: '10000' });
    const bad = x402SettlementResponse({ settled: false, reason: 'insufficient_funds', payer: SPEC_SETTLEMENT.payer }, 'eip155:84532');
    expect(bad.status).toBe(402);
    expect(decodePaymentResponseHeader(bad.headers['PAYMENT-RESPONSE']!)).toEqual({ success: false, errorReason: 'insufficient_funds', transaction: '', network: 'eip155:84532', payer: SPEC_SETTLEMENT.payer });
  });
  it.each([
    ['a success without a transaction', { ...SPEC_SETTLEMENT, transaction: '' }, 'a successful settlement needs a transaction'],
    ['a success carrying an errorReason', { ...SPEC_SETTLEMENT, errorReason: 'x' }, 'errorReason must be omitted on success'],
    ['a failure without a reason', { success: false, transaction: '', network: 'eip155:1' }, 'errorReason is required on failure'],
    ['a non-CAIP-2 network', { ...SPEC_SETTLEMENT, network: 'base' }, 'network must be a CAIP-2 identifier'],
    ['a fractional amount', { ...SPEC_SETTLEMENT, amount: '1.5' }, 'amount must be a decimal string of atomic units'],
    ['a non-boolean success', { ...SPEC_SETTLEMENT, success: 'yes' }, 'success must be a boolean'],
  ])('refuses %s', (_n, r, problem) => {
    expect(settlementResponseProblems(r)).toContain(problem);
    expect(() => encodePaymentResponseHeader(r as never)).toThrow(problem);
    expect(() => decodePaymentResponseHeader(Buffer.from(JSON.stringify(r)).toString('base64'))).toThrow(problem);
  });
  it('a header that is not base64 or not JSON is refused on decode', () => {
    expect(() => decodePaymentResponseHeader('%%%')).toThrow('PAYMENT-RESPONSE is not base64');
    expect(() => decodePaymentResponseHeader(Buffer.from('nope').toString('base64'))).toThrow('PAYMENT-RESPONSE is not JSON');
  });
});

describe('status codes (transport specification)', () => {
  it('maps each outcome', () => {
    expect(X402_HTTP_STATUS).toEqual({ payment_required: 402, malformed: 400, failed: 402, internal_error: 500, settled: 200 });
  });
});
