import { describe, expect, it } from 'vitest';
import {
  decodePaymentRequiredHeader,
  encodePaymentRequiredHeader,
  normalizeX402Payload,
  paymentRequiredV2Problems,
  requirementV2Problems,
  resourceInfoProblems,
  x402AcceptedMatches,
  x402ChallengeV2,
  x402Negotiate,
  type X402RequirementV2,
} from './index';

const REQ: X402RequirementV2 = { scheme: 'exact', network: 'eip155:84532', amount: '10000', asset: '0xasset', payTo: '0xpayee', maxTimeoutSeconds: 60 };
const PR = { x402Version: 2 as const, resource: { url: 'https://api.example/x' }, accepts: [REQ] };
const URL_MSG = 'resource.url must be an absolute http(s) URL';

describe('resourceInfoProblems', () => {
  it('requires an object', () => {
    expect(resourceInfoProblems(null)).toEqual(['resource must be an object']);
    expect(resourceInfoProblems([])).toEqual(['resource must be an object']);
    expect(resourceInfoProblems('x')).toEqual(['resource must be an object']);
  });
  it('url must be an absolute http(s) string', () => {
    expect(resourceInfoProblems({ url: 'https://a.example/' })).toEqual([]);
    expect(resourceInfoProblems({ url: 'http://a.example/' })).toEqual([]);
    for (const u of ['ftp://a.example/', 'a.example', '', undefined, 5, new URL('https://a.example/'), ['https://a.example/'], { toString: () => 'https://a.example/' }]) {
      expect(resourceInfoProblems({ url: u }), String(u)).toEqual([URL_MSG]);
    }
  });
  it('description and mimeType are strings when present', () => {
    expect(resourceInfoProblems({ url: 'https://a.example/', description: 'd', mimeType: 'text/plain' })).toEqual([]);
    expect(resourceInfoProblems({ url: 'https://a.example/', description: 5 })).toEqual(['resource.description must be a string']);
    expect(resourceInfoProblems({ url: 'https://a.example/', mimeType: 5 })).toEqual(['resource.mimeType must be a string']);
    expect(resourceInfoProblems({ url: 'https://a.example/', description: 5, mimeType: null })).toEqual(['resource.description must be a string', 'resource.mimeType must be a string']);
  });
  it('serviceName: printable ASCII up to 32', () => {
    const m = 'resource.serviceName must be printable ASCII up to 32 characters';
    expect(resourceInfoProblems({ url: 'https://a.example/', serviceName: 'a'.repeat(32) })).toEqual([]);
    expect(resourceInfoProblems({ url: 'https://a.example/', serviceName: '' })).toEqual([]);
    for (const s of ['a'.repeat(33), 'café', 'a\tb', 5, ['abc'], { length: 1 }]) expect(resourceInfoProblems({ url: 'https://a.example/', serviceName: s }), String(s)).toEqual([m]);
  });
  it('tags: up to 5 printable ASCII strings of up to 32', () => {
    const m = 'resource.tags must be up to 5 printable ASCII strings of up to 32 characters';
    const t = (tags: unknown) => resourceInfoProblems({ url: 'https://a.example/', tags });
    expect(t([])).toEqual([]);
    expect(t(['a', 'b', 'c', 'd', 'e'])).toEqual([]);
    expect(t(['a'.repeat(32)])).toEqual([]);
    for (const bad of [['a', 'b', 'c', 'd', 'e', 'f'], ['a'.repeat(33)], ['ok', 5], ['ok', 'café'], [['a']], [{ length: 1 }], 'abc', {}, ['ok', 'a'.repeat(33)], [5, 'ok'], [5]]) {
      expect(t(bad), JSON.stringify(bad)).toEqual([m]);
    }
  });
  it('iconUrl: absolute http(s) up to 2048', () => {
    const m = 'resource.iconUrl must be an absolute http(s) URL up to 2048 characters';
    const base = 'https://a.example/';
    const icon = (n: number) => base + 'a'.repeat(n - base.length);
    const i = (iconUrl: unknown) => resourceInfoProblems({ url: base, iconUrl });
    expect(i(icon(2048))).toEqual([]);
    expect(i(icon(2049))).toEqual([m]);
    expect(i('ftp://a.example/i.png')).toEqual([m]);
    expect(i(5)).toEqual([m]);
    expect(i('http://a.example/i.png')).toEqual([]);
  });
});

describe('requirementV2Problems', () => {
  const p = (over: Record<string, unknown>) => requirementV2Problems({ ...REQ, ...over });
  it('a valid requirement has no problems; non-objects are refused', () => {
    expect(requirementV2Problems(REQ)).toEqual([]);
    expect(requirementV2Problems({ ...REQ, extra: { a: 1 } })).toEqual([]);
    expect(requirementV2Problems(null)).toEqual(['requirements must be an object']);
  });
  it('scheme, asset and payTo are non-empty strings', () => {
    for (const bad of ['', undefined, 5, ['x'], { length: 3 }]) {
      expect(p({ scheme: bad }), String(bad)).toEqual(['scheme is required']);
      expect(p({ asset: bad }), String(bad)).toEqual(['asset is required']);
      expect(p({ payTo: bad }), String(bad)).toEqual(['payTo is required']);
    }
  });
  it('network is a CAIP-2 identifier string', () => {
    for (const bad of [5, ['eip155:84532'], 'eip155', 'x:y', 'eip155:', 'EIP155:1', 'eip155:84532!', '!eip155:84532']) expect(p({ network: bad }), String(bad)).toEqual(['network must be a CAIP-2 identifier']);
    expect(p({ network: 'eip155:84532' })).toEqual([]);
  });
  it('amount is a positive decimal string', () => {
    const m = 'amount must be a positive decimal string of atomic units';
    for (const ok of ['1', '10', '9007199254740993123']) expect(p({ amount: ok }), ok).toEqual([]);
    for (const bad of ['0', '00', '01', '-1', '1.5', ' 1', '1 ', 'a1', '1a', '', 5, ['5'], undefined, '1\n']) expect(p({ amount: bad }), String(bad)).toEqual([m]);
  });
  it('maxTimeoutSeconds is a positive safe integer', () => {
    const m = 'maxTimeoutSeconds must be a positive integer';
    expect(p({ maxTimeoutSeconds: 1 })).toEqual([]);
    for (const bad of [0, -1, 1.5, '5', NaN, 2 ** 53, undefined, null]) expect(p({ maxTimeoutSeconds: bad }), String(bad)).toEqual([m]);
  });
  it('extra is an object when present', () => {
    for (const bad of [5, 'x', null, [], true]) expect(p({ extra: bad }), String(bad)).toEqual(['extra must be an object']);
    expect(p({ extra: {} })).toEqual([]);
  });
  it('several problems are reported together, in order', () => {
    expect(requirementV2Problems({})).toEqual(['scheme is required', 'network must be a CAIP-2 identifier', 'amount must be a positive decimal string of atomic units', 'asset is required', 'payTo is required', 'maxTimeoutSeconds must be a positive integer']);
  });
});

describe('paymentRequiredV2Problems', () => {
  it('shape and exact messages', () => {
    expect(paymentRequiredV2Problems(PR)).toEqual([]);
    expect(paymentRequiredV2Problems({ ...PR, error: 'e' })).toEqual([]);
    expect(paymentRequiredV2Problems(null)).toEqual(['PaymentRequired must be an object']);
    expect(paymentRequiredV2Problems([])).toEqual(['PaymentRequired must be an object']);
    expect(paymentRequiredV2Problems({ ...PR, x402Version: 1 })).toEqual(['x402Version must be 2']);
    expect(paymentRequiredV2Problems({ ...PR, error: 5 })).toEqual(['error must be a string']);
    expect(paymentRequiredV2Problems({ ...PR, resource: null })).toEqual(['resource must be an object']);
    expect(paymentRequiredV2Problems({ ...PR, accepts: [] })).toEqual(['accepts must be a non-empty array']);
    expect(paymentRequiredV2Problems({ ...PR, accepts: 'x' })).toEqual(['accepts must be a non-empty array']);
  });
  it('accepts problems carry their index', () => {
    expect(paymentRequiredV2Problems({ ...PR, accepts: [REQ, { ...REQ, scheme: '' }, { ...REQ, asset: '', payTo: '' }] })).toEqual(['accepts[1].scheme is required', 'accepts[2].asset is required', 'accepts[2].payTo is required']);
  });
  it('extensions', () => {
    const ok = { info: {}, schema: {} };
    expect(paymentRequiredV2Problems({ ...PR, extensions: { a: ok } })).toEqual([]);
    expect(paymentRequiredV2Problems({ ...PR, extensions: {} })).toEqual([]);
    for (const bad of [5, 'x', null, []]) expect(paymentRequiredV2Problems({ ...PR, extensions: bad }), String(bad)).toEqual(['extensions must be an object']);
    for (const v of [null, 'x', [], { info: {} }, { schema: {} }, { info: 5, schema: {} }, { info: {}, schema: 5 }, { info: [], schema: {} }]) {
      expect(paymentRequiredV2Problems({ ...PR, extensions: { k: v } }), JSON.stringify(v)).toEqual(['extensions.k needs info and schema objects']);
    }
    expect(paymentRequiredV2Problems({ ...PR, extensions: { good: ok, bad: null } })).toEqual(['extensions.bad needs info and schema objects']);
  });
});

describe('header codec', () => {
  it('encodes valid objects as base64 JSON and refuses invalid ones with every problem joined', () => {
    expect(Buffer.from(encodePaymentRequiredHeader(PR), 'base64').toString('utf8')).toBe(JSON.stringify(PR));
    const bad = { ...PR, x402Version: 1, accepts: [{ ...REQ, scheme: '' }] } as never;
    expect(() => encodePaymentRequiredHeader(bad)).toThrow(new TypeError('x402: x402Version must be 2; accepts[0].scheme is required'));
    const uni = { ...PR, resource: { url: 'https://api.example/x', description: 'café €' } };
    expect(decodePaymentRequiredHeader(encodePaymentRequiredHeader(uni))).toEqual(uni);
    expect(Buffer.from(encodePaymentRequiredHeader(uni), 'base64').toString('utf8')).toBe(JSON.stringify(uni));
    expect(Buffer.from(encodePaymentRequiredHeader(uni), 'base64')).toEqual(Buffer.from(JSON.stringify(uni), 'utf8'));
  });
  it('decode refuses non-base64, non-JSON and invalid objects with exact messages', () => {
    const b = (s: string) => Buffer.from(s, 'utf8').toString('base64');
    expect(decodePaymentRequiredHeader(b(JSON.stringify(PR)))).toEqual(PR);
    for (const v of ['', '!!!AA', 'AA!', 'a b', 'AAA===', 5 as never, null as never]) expect(() => decodePaymentRequiredHeader(v), String(v)).toThrow(new TypeError('x402: PAYMENT-REQUIRED is not base64'));
    expect(() => decodePaymentRequiredHeader(b('not json'))).toThrow(new TypeError('x402: PAYMENT-REQUIRED is not JSON'));
    expect(() => decodePaymentRequiredHeader(b(JSON.stringify({ ...PR, x402Version: 1, accepts: [] })))).toThrow(new TypeError('x402: x402Version must be 2; accepts must be a non-empty array'));
  });
});

describe('x402ChallengeV2', () => {
  const o = { amount: 5, asset: '0xasset', payTo: '0xpayee', network: 'eip155:84532' };
  it('builds the body, the header and the content type', () => {
    const c = x402ChallengeV2('https://api.example/x', o);
    expect(c.status).toBe(402);
    expect(c.headers['Content-Type']).toBe('application/json');
    expect(Object.keys(c.headers).sort()).toEqual(['Content-Type', 'PAYMENT-REQUIRED']);
    expect(decodePaymentRequiredHeader(c.headers['PAYMENT-REQUIRED']!)).toEqual(c.body);
    expect(c.body).toStrictEqual({
      x402Version: 2,
      error: 'PAYMENT-SIGNATURE header is required',
      resource: { url: 'https://api.example/x' },
      accepts: [{ scheme: 'exact', network: 'eip155:84532', amount: '5', asset: '0xasset', payTo: '0xpayee', maxTimeoutSeconds: 60 }],
    });
  });
  it('keeps a resource object, and only adds extra and extensions when given', () => {
    const res = { url: 'https://api.example/x', description: 'd' };
    const c = x402ChallengeV2(res, { ...o, scheme: 's', maxTimeoutSeconds: 9, error: 'pay', extra: { n: 1 }, extensions: { e: { info: {}, schema: {} } } });
    expect(c.body.resource).toStrictEqual(res);
    expect(c.body.resource).not.toBe(res);
    expect(c.body.accepts[0]).toStrictEqual({ scheme: 's', network: 'eip155:84532', amount: '5', asset: '0xasset', payTo: '0xpayee', maxTimeoutSeconds: 9, extra: { n: 1 } });
    expect(c.body.error).toBe('pay');
    expect(c.body.extensions).toEqual({ e: { info: {}, schema: {} } });
    const plain = x402ChallengeV2('https://api.example/x', o);
    expect('extra' in plain.body.accepts[0]!).toBe(false);
    expect('extensions' in plain.body).toBe(false);
  });
  it('refuses an amount that is not a positive safe integer with the exact message', () => {
    const m = 'x402Challenge: amount must be a positive integer in atomic units';
    for (const amount of [0, -1, 1.5, NaN, Infinity, 2 ** 53]) expect(() => x402ChallengeV2('https://api.example/x', { ...o, amount }), String(amount)).toThrow(new TypeError(m));
    expect(() => x402ChallengeV2('https://api.example/x', { ...o, amount: 1 })).not.toThrow();
  });
  it('a string resource is wrapped as {url}, an invalid one is refused', () => {
    expect(() => x402ChallengeV2('not a url', o)).toThrow(new TypeError(`x402: ${URL_MSG}`));
  });
});

describe('x402Negotiate', () => {
  it('picks the highest common supported version, ignoring unknown ones', () => {
    expect(x402Negotiate([1, 2])).toBe(2);
    expect(x402Negotiate([2])).toBe(2);
    expect(x402Negotiate(undefined)).toBe(1);
    expect(x402Negotiate([])).toBe(1);
    expect(x402Negotiate([3])).toBeUndefined();
    expect(x402Negotiate([3, 1], [3, 2, 1])).toBe(1);
    expect(x402Negotiate([3], [3])).toBeUndefined();
    expect(x402Negotiate([1, 2], [1, 2])).toBe(2);
    expect(x402Negotiate([1, 2], [2, 1])).toBe(2);
    expect(x402Negotiate([1, 2], [1])).toBe(1);
    expect(x402Negotiate([1, 2], [2])).toBe(2);
    expect(x402Negotiate([2], [1])).toBeUndefined();
  });
});

describe('x402AcceptedMatches', () => {
  const withExtra = (extra: Record<string, unknown>): X402RequirementV2 => ({ ...REQ, extra });
  it('matches an offered requirement regardless of key order, and nothing else', () => {
    expect(x402AcceptedMatches([REQ], { ...REQ })).toBe(true);
    expect(x402AcceptedMatches([REQ], Object.fromEntries(Object.entries(REQ).reverse()))).toBe(true);
    expect(x402AcceptedMatches([], REQ)).toBe(false);
    expect(x402AcceptedMatches([REQ], { ...REQ, amount: '10001' })).toBe(false);
    expect(x402AcceptedMatches([{ ...REQ, amount: '1' }, REQ], REQ)).toBe(true);
  });
  it('an invalid echoed requirement never matches, even an identical invalid offer', () => {
    const bad = { ...REQ, amount: '0' } as X402RequirementV2;
    expect(x402AcceptedMatches([bad], bad)).toBe(false);
    expect(x402AcceptedMatches([REQ], null)).toBe(false);
  });
  it('compares nested extra exactly: null, arrays, element boundaries and arrays versus objects', () => {
    expect(x402AcceptedMatches([withExtra({ a: null })], withExtra({ a: null }))).toBe(true);
    expect(x402AcceptedMatches([withExtra({ a: null })], withExtra({ a: 0 }))).toBe(false);
    expect(x402AcceptedMatches([withExtra({ l: [1, 2] })], withExtra({ l: [1, 2] }))).toBe(true);
    expect(x402AcceptedMatches([withExtra({ l: [1, 2] })], withExtra({ l: [3] }))).toBe(false);
    expect(x402AcceptedMatches([withExtra({ l: [1, 2] })], withExtra({ l: [12] }))).toBe(false);
    expect(x402AcceptedMatches([withExtra({ l: [1, 2] })], withExtra({ l: { 0: 1, 1: 2 } }))).toBe(false);
    expect(x402AcceptedMatches([withExtra({ l: [] })], withExtra({ l: {} }))).toBe(false);
    expect(x402AcceptedMatches([withExtra({ a: 1, b: 2 })], withExtra({ b: 2, a: 1 }))).toBe(true);
    expect(x402AcceptedMatches([withExtra({ a: 1, b: 2 })], withExtra({ a: 1, b: 3 }))).toBe(false);
    expect(x402AcceptedMatches([withExtra({ a: 1, b: { c: [null, 'x'] } })], withExtra({ b: { c: [null, 'x'] }, a: 1 }))).toBe(true);
  });
});

describe('normalizeX402Payload', () => {
  const v2 = { x402Version: 2, accepted: REQ, payload: { token: 'tok' } };
  it('v2 reads payload.token and accepted.amount', () => {
    expect(normalizeX402Payload(v2)).toStrictEqual({ ok: true, version: 2, token: 'tok', accepted: REQ, amount: 10000 });
    expect(normalizeX402Payload({ ...v2, accepted: { ...REQ, amount: '9007199254740993' } })).toStrictEqual({ ok: true, version: 2, token: 'tok', accepted: { ...REQ, amount: '9007199254740993' } });
  });
  it('v2 refusals', () => {
    expect(normalizeX402Payload(null)).toEqual({ ok: false, reason: 'x402 payment payload is not an object' });
    const missing = { ok: false, reason: 'x402 v2 payload is missing payload.token' };
    expect(normalizeX402Payload({ ...v2, payload: { token: '' } })).toEqual(missing);
    expect(normalizeX402Payload({ ...v2, payload: { token: 5 } })).toEqual(missing);
    expect(normalizeX402Payload({ ...v2, payload: null })).toEqual(missing);
    expect(normalizeX402Payload({ ...v2, payload: {} })).toEqual(missing);
    expect(normalizeX402Payload({ ...v2, accepted: { ...REQ, scheme: '', asset: '' } })).toEqual({ ok: false, reason: 'x402 v2 payload.accepted is invalid: scheme is required; asset is required' });
    expect(normalizeX402Payload({ ...v2, accepted: undefined })).toEqual({ ok: false, reason: 'x402 v2 payload.accepted is invalid: requirements must be an object' });
  });
  it('v1 reads top-level members and no more', () => {
    expect(normalizeX402Payload({ token: 't' })).toStrictEqual({ ok: true, version: 1, token: 't' });
    expect(normalizeX402Payload({ x402Version: 1, token: 't', merchant: 'm', amount: 7 })).toStrictEqual({ ok: true, version: 1, token: 't', merchant: 'm', amount: 7 });
    expect(normalizeX402Payload({ token: 't', merchant: 5, amount: '7' })).toStrictEqual({ ok: true, version: 1, token: 't' });
    expect(normalizeX402Payload({ x402Version: 3, token: 't' })).toEqual({ ok: false, reason: 'unsupported x402Version 3' });
    expect(normalizeX402Payload({ x402Version: 1 })).toEqual({ ok: false, reason: 'x402 payment payload is missing a token' });
  });
});
