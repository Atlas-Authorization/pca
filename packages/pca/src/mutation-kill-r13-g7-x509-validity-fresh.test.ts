/**
 * r13 mutation kills for x509-validity.ts module-level patterns (static mutants; each test re-evaluates the module):
 * DIGITS (parseDerTime's all-digits check, including inputs that Number() would still accept) and MONTHS / RENDERED
 * (parseOpenSslTime's strict OpenSSL rendering), pinned by truth tables against Date.UTC.
 */
import { describe, expect, it, vi } from 'vitest';

async function fresh() {
  vi.resetModules();
  return import('./x509-validity');
}

describe('parseDerTime digits (fresh module)', () => {
  it('accepts digit-only times and refuses anything Number() would forgive', async () => {
    const m = await fresh();
    const cases: [number, string, number][] = [
      [0x17, '250102030405Z', Date.UTC(2025, 0, 2, 3, 4, 5)],
      [0x17, '991231235959Z', Date.UTC(1999, 11, 31, 23, 59, 59)],
      [0x18, '20250102030405Z', Date.UTC(2025, 0, 2, 3, 4, 5)],
      [0x17, ' 50101000000Z', NaN], // leading space: Number(' 5') is 5
      [0x17, '5001010000 0Z', NaN], // trailing space before Z: Number(' 0') is 0
      [0x17, '2501020304 5Z', NaN],
      [0x18, '2025010203040xZ', NaN],
    ];
    expect(cases.map(([t, s]) => [s, m.parseDerTime(t, s)])).toEqual(cases.map(([, s, v]) => [s, v]));
  });
});

describe('parseOpenSslTime (fresh module)', () => {
  it('every month name maps to its index', async () => {
    const m = await fresh();
    const names = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    expect(names.map((n) => m.parseOpenSslTime(`${n}  1 00:00:00 2025 GMT`))).toEqual(names.map((_, i) => Date.UTC(2025, i, 1)));
  });
  it('accepts the exact OpenSSL renderings', async () => {
    const m = await fresh();
    const ok: [string, number][] = [
      ['Jan  2 03:04:05 2025 GMT', Date.UTC(2025, 0, 2, 3, 4, 5)],
      ['Jan 2 03:04:05 2025 GMT', Date.UTC(2025, 0, 2, 3, 4, 5)],
      ['Feb 28 23:59:59 2024 GMT', Date.UTC(2024, 1, 28, 23, 59, 59)],
      ['Mar 10 12:00:00.123 2025 GMT', Date.UTC(2025, 2, 10, 12, 0, 0, 123)],
      ['Mar 10 12:00:00.5 2025 GMT', Date.UTC(2025, 2, 10, 12, 0, 0, 500)],
      ['Dec 31 00:00:00 1999 GMT', Date.UTC(1999, 11, 31)],
    ];
    expect(ok.map(([s]) => [s, m.parseOpenSslTime(s)])).toEqual(ok);
  });
  it('refuses every near miss', async () => {
    const m = await fresh();
    const bad = [
      ' Jan  2 03:04:05 2025 GMT',
      'Jan  2 03:04:05 2025 GMTx',
      'XJan  2 03:04:05 2025 GMT',
      'jan  2 03:04:05 2025 GMT',
      'JAN  2 03:04:05 2025 GMT',
      'Ja  2 03:04:05 2025 GMT',
      'Jan   2 03:04:05 2025 GMT',
      'Jan  x 03:04:05 2025 GMT',
      'Jan 123 03:04:05 2025 GMT',
      'Jan  2 3:04:05 2025 GMT',
      'Jan  2 0x:04:05 2025 GMT',
      'Jan  2 03:4:05 2025 GMT',
      'Jan  2 03:0x:05 2025 GMT',
      'Jan  2 03:04:5 2025 GMT',
      'Jan  2 03:04:0x 2025 GMT',
      'Jan  2 03:04:05. 2025 GMT',
      'Jan  2 03:04:05.x 2025 GMT',
      'Jan  2 03:04:05 25 GMT',
      'Jan  2 03:04:05 2x25 GMT',
      'Jan  2 03:04:05 2025 UTC',
      'Jan  2 03:04:05 2025',
      'Foo  2 03:04:05 2025 GMT',
    ];
    expect(bad.map((s) => [s, m.parseOpenSslTime(s)])).toEqual(bad.map((s) => [s, NaN]));
  });
});
