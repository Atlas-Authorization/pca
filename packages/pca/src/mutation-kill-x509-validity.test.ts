/** x509-validity.ts residual mutants: non-string input, minute/second overflow (not caught by the date roll-over check), infinite skew. */
import { describe, expect, it } from 'vitest';
import { parseOpenSslTime, x509ValidAt } from './x509-validity';

describe('parseOpenSslTime', () => {
  it('a non-string whose toString renders a valid time is NaN (no coercion through RegExp.exec)', () => {
    const sneaky = { toString: () => 'Jan  1 00:00:00 2030 GMT' };
    expect(parseOpenSslTime(sneaky)).toBeNaN();
    expect(parseOpenSslTime('Jan  1 00:00:00 2030 GMT')).toBe(Date.UTC(2030, 0, 1));
  });
  it('minute 60 and second 60 are refused (they roll over within the same day, so only the field check catches them)', () => {
    expect(parseOpenSslTime('Jun 15 12:60:00 2030 GMT')).toBeNaN();
    expect(parseOpenSslTime('Jun 15 12:30:60 2030 GMT')).toBeNaN();
    expect(parseOpenSslTime('Jun 15 12:59:59 2030 GMT')).toBe(Date.UTC(2030, 5, 15, 12, 59, 59));
  });
});

describe('x509ValidAt', () => {
  const cert = { validFrom: 'Jan  1 00:00:00 2030 GMT', validTo: 'Jan  1 00:00:00 2031 GMT' };
  it('an infinite skew is refused (it would otherwise widen the window to all time)', () => {
    const before = Date.UTC(2000, 0, 1);
    expect(x509ValidAt(cert, before, 0)).toBe(false);
    expect(x509ValidAt(cert, before, Number.POSITIVE_INFINITY)).toBe(false);
    expect(x509ValidAt(cert, Date.UTC(2030, 5, 1), Number.POSITIVE_INFINITY)).toBe(false);
    expect(x509ValidAt(cert, Date.UTC(2030, 5, 1), 0)).toBe(true);
  });
});
