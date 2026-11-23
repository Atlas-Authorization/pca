import { describe, expect, it } from 'vitest';
import {
  decodePaymentResponseHeader,
  decodePaymentSignatureHeader,
  encodePaymentResponseHeader,
  encodePaymentSignatureHeader,
  paymentPayloadV2Problems,
  readPaymentSignature,
  settlementResponseProblems,
  x402SettlementResponse,
  type X402PaymentPayloadV2,
  type X402SettlementResponse,
} from './index';

const OK_PAYLOAD: X402PaymentPayloadV2 = {
  x402Version: 2,
  accepted: { scheme: 'exact', network: 'eip155:84532', amount: '10000', asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e', payTo: '0x209693Bc6afc0C5328bA36FaF03C514EF312287C', maxTimeoutSeconds: 60, extra: { name: 'USDC', version: '2' } },
  payload: { token: 'jws' },
};
const OK_SETTLEMENT: X402SettlementResponse = { success: true, transaction: '0xabc', network: 'eip155:84532' };
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o), 'utf8').toString('base64');

describe('PaymentPayload problems', () => {
  it('a non-object is refused whole; arrays and null are not objects', () => {
    for (const bad of [null, undefined, 'x', 5, []]) expect(paymentPayloadV2Problems(bad)).toEqual(['PaymentPayload must be an object']);
  });
  it('resource and extensions are checked only when present', () => {
    expect(paymentPayloadV2Problems(OK_PAYLOAD)).toEqual([]);
    expect(paymentPayloadV2Problems({ ...OK_PAYLOAD, resource: 5 }).length).toBeGreaterThan(0);
    expect(paymentPayloadV2Problems({ ...OK_PAYLOAD, resource: { url: 'https://api.example.com/premium-data', description: 'Access to premium market data', mimeType: 'application/json' } })).toEqual([]);
    expect(paymentPayloadV2Problems({ ...OK_PAYLOAD, extensions: {} })).toEqual([]);
    expect(paymentPayloadV2Problems({ ...OK_PAYLOAD, extensions: 5 })).toEqual(['extensions must be an object']);
    expect(paymentPayloadV2Problems({ ...OK_PAYLOAD, extensions: [] })).toEqual(['extensions must be an object']);
    expect(paymentPayloadV2Problems({ ...OK_PAYLOAD, payload: [] })).toEqual(['payload must be an object']);
    expect(paymentPayloadV2Problems({ ...OK_PAYLOAD, x402Version: 1 })).toEqual(['x402Version must be 2']);
  });
});

describe('SettlementResponse problems', () => {
  it('a non-object is refused whole', () => {
    for (const bad of [null, undefined, 'x', 5, []]) expect(settlementResponseProblems(bad)).toEqual(['SettlementResponse must be an object']);
  });
  it('each field has its own message', () => {
    expect(settlementResponseProblems(OK_SETTLEMENT)).toEqual([]);
    expect(settlementResponseProblems({ ...OK_SETTLEMENT, success: 'yes' })).toEqual(['success must be a boolean']);
    expect(settlementResponseProblems({ ...OK_SETTLEMENT, transaction: 5 })).toEqual(['transaction must be a string']);
    expect(settlementResponseProblems({ ...OK_SETTLEMENT, transaction: '' })).toEqual(['a successful settlement needs a transaction']);
    expect(settlementResponseProblems({ ...OK_SETTLEMENT, network: 5 })).toEqual(['network must be a CAIP-2 identifier']);
    expect(settlementResponseProblems({ ...OK_SETTLEMENT, network: 'not caip' })).toEqual(['network must be a CAIP-2 identifier']);
    expect(settlementResponseProblems({ ...OK_SETTLEMENT, errorReason: 5 })).toEqual(['errorReason must be a string', 'errorReason must be omitted on success']);
    expect(settlementResponseProblems({ ...OK_SETTLEMENT, errorReason: 'x' })).toEqual(['errorReason must be omitted on success']);
    expect(settlementResponseProblems({ ...OK_SETTLEMENT, payer: 5 })).toEqual(['payer must be a string']);
    expect(settlementResponseProblems({ ...OK_SETTLEMENT, payer: '0xp' })).toEqual([]);
    expect(settlementResponseProblems({ ...OK_SETTLEMENT, extensions: 5 })).toEqual(['extensions must be an object']);
    expect(settlementResponseProblems({ ...OK_SETTLEMENT, extensions: {} })).toEqual([]);
  });
  it('a failure must say why', () => {
    const fail = { success: false, transaction: '', network: 'eip155:84532' };
    expect(settlementResponseProblems(fail)).toEqual(['errorReason is required on failure']);
    expect(settlementResponseProblems({ ...fail, errorReason: '' })).toEqual(['errorReason is required on failure']);
    expect(settlementResponseProblems({ ...fail, errorReason: 5 })).toEqual(['errorReason must be a string', 'errorReason is required on failure']);
    expect(settlementResponseProblems({ ...fail, errorReason: 'insufficient_funds' })).toEqual([]);
  });
  it('amount is a canonical decimal string of atomic units', () => {
    for (const ok of ['0', '1', '10000']) expect(settlementResponseProblems({ ...OK_SETTLEMENT, amount: ok })).toEqual([]);
    for (const bad of ['01', '-1', '1.5', '', 5, 'abc']) expect(settlementResponseProblems({ ...OK_SETTLEMENT, amount: bad }), String(bad)).toEqual(['amount must be a decimal string of atomic units']);
  });
});

describe('header coding', () => {
  it('encode joins every problem with "; " and prefixes x402:', () => {
    expect(() => encodePaymentResponseHeader({ success: 'x', transaction: 5, network: 'bad' } as never)).toThrow(
      new TypeError('x402: success must be a boolean; transaction must be a string; network must be a CAIP-2 identifier'),
    );
    expect(() => encodePaymentSignatureHeader({ ...OK_PAYLOAD, x402Version: 1, payload: 5 } as never)).toThrow('x402: x402Version must be 2; payload must be an object');
  });
  it('decode joins every problem with "; "', () => {
    expect(() => decodePaymentResponseHeader(b64({ success: 'x', transaction: 5, network: 'bad' }))).toThrow(
      new TypeError('x402: success must be a boolean; transaction must be a string; network must be a CAIP-2 identifier'),
    );
    expect(() => decodePaymentSignatureHeader(b64({ ...OK_PAYLOAD, x402Version: 1, payload: 5 }))).toThrow('x402: x402Version must be 2; payload must be an object');
  });
  it('the header is base64 of the UTF-8 JSON, and non-ASCII survives a round trip', () => {
    const s: X402SettlementResponse = { ...OK_SETTLEMENT, payer: 'café €' };
    const h = encodePaymentResponseHeader(s);
    expect(h).toBe(Buffer.from(JSON.stringify(s), 'utf8').toString('base64'));
    expect(decodePaymentResponseHeader(h)).toEqual(s);
  });
  it('decode refuses non-base64 and non-string input, anchored at the start', () => {
    for (const bad of ['!!!', ' abc', '', 'abc def', 5, undefined]) expect(() => decodePaymentResponseHeader(bad as never)).toThrow('x402: PAYMENT-RESPONSE is not base64');
    expect(() => decodePaymentSignatureHeader('%%%' + b64(OK_PAYLOAD))).toThrow('x402: PAYMENT-SIGNATURE is not base64');
    expect(() => decodePaymentSignatureHeader(Buffer.from('not json', 'utf8').toString('base64'))).toThrow('x402: PAYMENT-SIGNATURE is not JSON');
  });
});

describe('reading the PAYMENT-SIGNATURE request header', () => {
  const h = encodePaymentSignatureHeader(OK_PAYLOAD);
  it('looks the name up case-insensitively among other headers and uses the first value of an array', () => {
    expect(readPaymentSignature({ accept: 'x', 'Payment-Signature': h })).toEqual({ ok: true, payload: OK_PAYLOAD });
    expect(readPaymentSignature({ 'payment-signature': [h, 'ignored'] })).toEqual({ ok: true, payload: OK_PAYLOAD });
    expect(readPaymentSignature({ 'x-other': h })).toEqual({ ok: false, status: 402, reason: 'PAYMENT-SIGNATURE header is required' });
  });
  it('a missing, empty or undefined header is 402; an undecodable one is 400 with the reason', () => {
    expect(readPaymentSignature({})).toEqual({ ok: false, status: 402, reason: 'PAYMENT-SIGNATURE header is required' });
    expect(readPaymentSignature({ 'payment-signature': '' })).toEqual({ ok: false, status: 402, reason: 'PAYMENT-SIGNATURE header is required' });
    expect(readPaymentSignature({ 'payment-signature': undefined })).toEqual({ ok: false, status: 402, reason: 'PAYMENT-SIGNATURE header is required' });
    expect(readPaymentSignature({ 'payment-signature': '!!' })).toEqual({ ok: false, status: 400, reason: 'x402: PAYMENT-SIGNATURE is not base64' });
  });
});

describe('x402SettlementResponse', () => {
  const decode = (r: { headers: Record<string, string> }) => decodePaymentResponseHeader(r.headers['PAYMENT-RESPONSE']!);
  it('a settlement is 200 and carries payer and amount only when given', () => {
    const bare = x402SettlementResponse({ settled: true, transaction: '0xt' }, 'eip155:1');
    expect(bare.status).toBe(200);
    expect(decode(bare)).toStrictEqual({ success: true, transaction: '0xt', network: 'eip155:1' });
    const full = x402SettlementResponse({ settled: true, transaction: '0xt', payer: '0xp', amount: '5' }, 'eip155:1');
    expect(decode(full)).toStrictEqual({ success: true, transaction: '0xt', network: 'eip155:1', payer: '0xp', amount: '5' });
  });
  it('a failure is 402 with the reason, an empty transaction unless broadcast, and payer only when given', () => {
    const bare = x402SettlementResponse({ settled: false, reason: 'nope' }, 'eip155:1');
    expect(bare.status).toBe(402);
    expect(decode(bare)).toStrictEqual({ success: false, errorReason: 'nope', transaction: '', network: 'eip155:1' });
    const full = x402SettlementResponse({ settled: false, reason: 'nope', transaction: '0xt', payer: '0xp' }, 'eip155:1');
    expect(decode(full)).toStrictEqual({ success: false, errorReason: 'nope', transaction: '0xt', network: 'eip155:1', payer: '0xp' });
  });
});
