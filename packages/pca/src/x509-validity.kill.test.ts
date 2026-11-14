import { describe, expect, it } from 'vitest';
import { x509ValidAt, x509ValidityMs } from './x509-validity';

describe('raw DER is the only source of the instants when present', () => {
  it('unreadable DER is NaN even when the rendered strings and dates would parse', () => {
    const shim = {
      raw: new Uint8Array([0x30, 0x00]),
      validFrom: 'Jan  1 00:00:00 2025 GMT',
      validTo: 'Jan  1 00:00:00 2030 GMT',
      validFromDate: new Date(Date.UTC(2025, 0, 1)),
      validToDate: new Date(Date.UTC(2030, 0, 1)),
    };
    expect(x509ValidityMs(shim)).toEqual({ from: NaN, to: NaN });
    expect(x509ValidAt(shim, Date.UTC(2026, 0, 1))).toBe(false);
  });
});
