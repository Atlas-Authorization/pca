/**
 * Regressions for the 2026-10-12 JavaScript-semantics audit: SD-JWT claim names spelled like Object.prototype members,
 * lossy UTF-8 decoding of signed segments and disclosures, and host-dependent `Date.parse` in the execution window. Each
 * expectation also kills the mutant that reverts the fix.
 */
import { describe, expect, it } from 'vitest';
import { checkPaymentConstraints } from './constraints';
import type { PaymentConstraint, PaymentMandateClaims } from './mandates';
import { Ap2Error, parseJwt, processDisclosures, sdDigest, type JsonObject } from './sdjwt';

const enc = (v: unknown): string => Buffer.from(JSON.stringify(v), 'utf8').toString('base64url');

describe('processDisclosures: claim names are ordinary own keys', () => {
  it('a disclosed claim named __proto__ is an own claim, not the prototype of the claims object', () => {
    const d = enc(['salt-1', '__proto__', { amount: 5 }]);
    const out = processDisclosures({ _sd: [sdDigest(d)] }, [d], 'sha-256');
    expect(Object.keys(out)).toEqual(['__proto__']);
    expect(Object.getPrototypeOf(out)).toBe(Object.prototype);
    expect((out as { amount?: unknown }).amount).toBeUndefined();
    expect(Object.getOwnPropertyDescriptor(out, '__proto__')?.value).toEqual({ amount: 5 });
  });
  it('a signed payload member named __proto__ is copied as an own claim', () => {
    const payload = JSON.parse('{"__proto__": {"vct": "x"}, "n": 1}') as JsonObject;
    const out = processDisclosures(payload, [], 'sha-256');
    expect(Object.keys(out)).toEqual(['__proto__', 'n']);
    expect(Object.getPrototypeOf(out)).toBe(Object.prototype);
    expect((out as { vct?: unknown }).vct).toBeUndefined();
  });
  it('a disclosed __proto__ claim still collides with a signed one (own-key collision check)', () => {
    const d = enc(['salt-2', '__proto__', 1]);
    const payload = JSON.parse(`{"__proto__": 2, "_sd": [${JSON.stringify(sdDigest(d))}]}`) as JsonObject;
    expect(() => processDisclosures(payload, [d], 'sha-256')).toThrow('SD-JWT: disclosed claim __proto__ collides with an existing claim');
  });
});

describe('UTF-8 decoding of signed segments and disclosures is fatal', () => {
  const withByte = (pre: string, byte: number, post: string): string => Buffer.concat([Buffer.from(pre), Buffer.from([byte]), Buffer.from(post)]).toString('base64url');

  it('a disclosure with an invalid UTF-8 byte is refused (it used to read as U+FFFD)', () => {
    const d = withByte('["salt-3","n', 0xff, '","v"]');
    const err = (() => {
      try {
        processDisclosures({ _sd: [sdDigest(d)] }, [d], 'sha-256');
      } catch (e) {
        return e;
      }
      return undefined;
    })();
    expect(err).toBeInstanceOf(Ap2Error);
    expect((err as Error).message).toBe('disclosure: not valid UTF-8');
  });
  it('a JWT payload with a truncated UTF-8 sequence is refused; valid multi-byte text still parses', () => {
    const h = enc({ alg: 'ES256' });
    const bad = withByte('{"n":"', 0xc3, '"}');
    expect(() => parseJwt(`${h}.${bad}.sig`, 'jwt')).toThrow('jwt payload: not valid UTF-8');
    expect(parseJwt(`${h}.${enc({ n: 'é€😀' })}.sig`, 'jwt').payload).toEqual({ n: 'é€😀' });
  });
  it('a leading BOM is kept, so the JSON parser refuses it', () => {
    const h = enc({ alg: 'ES256' });
    const bom = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('{"n":1}')]).toString('base64url');
    expect(() => parseJwt(`${h}.${bom}.sig`, 'jwt')).toThrow(/jwt payload: invalid JSON/);
  });
});

describe('execution_date window: strict RFC 3339 instants, independent of the host', () => {
  const closed = (execution_date: string): PaymentMandateClaims =>
    ({ vct: 'mandate.payment.1', transaction_id: 'T', payee: { id: 'm', name: 'M' }, payment_amount: { amount: 1, currency: 'USD' }, payment_instrument: { id: 'pi', type: 'card' }, execution_date }) as PaymentMandateClaims;
  const win = (at: string, notBefore?: string, notAfter?: string): string[] => {
    const c = { type: 'payment.execution_date', ...(notBefore !== undefined ? { not_before: notBefore } : {}), ...(notAfter !== undefined ? { not_after: notAfter } : {}) } as PaymentConstraint;
    return checkPaymentConstraints({ vct: 'mandate.payment.open.1', constraints: [c], cnf: { jwk: {} } } as never, closed(at), { now: 0 });
  };
  const invalid = (s: string) => [`execution_date ${s} is not a valid instant`];

  it('a date-time without an offset is refused (Date.parse read it in the host time zone)', () => {
    expect(win('2026-06-01T10:00:00')).toEqual(invalid('2026-06-01T10:00:00'));
  });
  it('implementation-defined forms are refused', () => {
    for (const s of ['Jun 1 2026', '1', '2026-06-01 10:00:00Z', '2026-06-01t10:00:00z', '2026-06-01T10:00Z', '+002026-06-01T00:00:00Z', ' 2026-06-01', '2026-06-01T10:00:00.Z']) {
      expect(win(s), s).toEqual(invalid(s));
    }
  });
  it('a day that does not exist is refused, not rolled over (Date.parse read 2026-02-30 as March 2)', () => {
    expect(win('2026-02-30')).toEqual(invalid('2026-02-30'));
    expect(win('2026-04-31T00:00:00Z')).toEqual(invalid('2026-04-31T00:00:00Z'));
    expect(win('2025-02-29')).toEqual(invalid('2025-02-29'));
    expect(win('2024-02-29')).toEqual([]);
    expect(win('2026-01-00')).toEqual(invalid('2026-01-00'));
    expect(win('2026-00-10')).toEqual(invalid('2026-00-10'));
    expect(win('2026-13-01')).toEqual(invalid('2026-13-01'));
    expect(win('2026-12-31')).toEqual([]);
  });
  it('time components are range-checked at their boundaries', () => {
    expect(win('2026-06-01T23:59:59Z')).toEqual([]);
    for (const s of ['2026-06-01T24:00:00Z', '2026-06-01T10:60:00Z', '2026-06-01T10:00:60Z', '2026-06-01T10:00:00+24:00', '2026-06-01T10:00:00+05:60']) {
      expect(win(s), s).toEqual(invalid(s));
    }
    expect(win('2026-06-01T10:00:00+23:59')).toEqual([]);
  });
  it('offsets, fractions and date-only forms denote the right instant', () => {
    const at = '2026-06-01T10:00:00Z';
    expect(win('2026-06-01T12:00:00+02:00', at, at)).toEqual([]);
    expect(win('2026-06-01T08:00:00-02:00', at, at)).toEqual([]);
    expect(win('2026-06-01T05:30:00-04:30', at, at)).toEqual([]);
    expect(win('2026-06-01T12:00:00+02:00', '2026-06-01T10:00:00.001Z')).toHaveLength(1);
    expect(win('2026-06-01T10:00:00.9999Z', undefined, '2026-06-01T10:00:00.999Z')).toEqual([]); // truncated to ms, not rounded
    expect(win('2026-06-01T10:00:00.9999Z', undefined, '2026-06-01T10:00:00.998Z')).toHaveLength(1);
    expect(win('2026-06-01T10:00:00.5Z', '2026-06-01T10:00:00.500Z', '2026-06-01T10:00:00.500Z')).toEqual([]);
    expect(win('2026-06-01', '2026-06-01T00:00:00Z', '2026-06-01T00:00:00Z')).toEqual([]); // date-only == UTC midnight
  });
  it('two-digit years are not shifted to the 1900s', () => {
    expect(win('1949-06-01T00:00:00Z', '0050-01-01')).toEqual([]);
    expect(win('0049-12-31T23:59:59Z', '0050-01-01')).toHaveLength(1);
  });
  it('the bounds are parsed by the same strict rule', () => {
    expect(win('2026-06-01T10:00:00Z', '2026-06-01T09:00:00')).toEqual(['not_before 2026-06-01T09:00:00 is not a valid instant']);
    expect(win('2026-06-01T10:00:00Z', undefined, 'June 2 2026')).toEqual(['not_after June 2 2026 is not a valid instant']);
  });
});
