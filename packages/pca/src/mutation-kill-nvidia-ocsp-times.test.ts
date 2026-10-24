/** 0.4.2 mutation kills: allAsn1TimesWellFormed - every DER time field is in range with no roll-over, anchored, recursive. */
import { describe, expect, it } from 'vitest';
import { allAsn1TimesWellFormed } from './attest-nvidia-ocsp';

class UTC { constructor(public valueBlock: { valueHexView: Uint8Array; value?: unknown }) {} }
class GEN extends UTC {} // asn1js: GeneralizedTime extends UTCTime
const asn1 = { UTCTime: UTC, GeneralizedTime: GEN } as never;
const t = (Cls: typeof UTC, text: string) => new Cls({ valueHexView: Buffer.from(text, 'latin1') });
const gen = (s: string) => allAsn1TimesWellFormed(t(GEN, s), asn1);
const utc = (s: string) => allAsn1TimesWellFormed(t(UTC, s), asn1);

describe('GeneralizedTime', () => {
  it('accepts well-formed instants, fractions with a non-zero last digit, and leap days', () => {
    for (const s of ['20240101000000Z', '20241231235959Z', '20240229120000Z', '20000229000000Z', '20240615120000.5Z', '20240615120000.123Z', '20240131000000Z', '20240430000000Z']) expect(gen(s), s).toBe(true);
  });
  it('refuses every out-of-range field and roll-over', () => {
    for (const s of ['20240001000000Z', '20241301000000Z', '20240100000000Z', '20240132000000Z', '20240230000000Z', '20230229000000Z', '19000229000000Z', '20240431000000Z', '20240101240000Z', '20240101006000Z', '20240101000060Z']) expect(gen(s), s).toBe(false);
  });
  it('refuses a fraction ending in zero or empty, a missing Z, and anything before or after the time', () => {
    for (const s of ['20240615120000.0Z', '20240615120000.50Z', '20240615120000.Z', '20240615120000', 'x20240615120000Z', '20240615120000Zx', '2024061512000Z', '20240615120000+0100']) expect(gen(s), s).toBe(false);
  });
  it('month and day / hour / minute / second bounds are inclusive at the top and bottom', () => {
    expect(gen('20240101235959Z')).toBe(true);
    expect(gen('20241201000000Z')).toBe(true);
    expect(gen('20240131000000Z')).toBe(true);
  });
});

describe('UTCTime', () => {
  it('two-digit years: 00-49 are 20xx, 50-99 are 19xx (visible through the leap rule)', () => {
    expect(utc('000229000000Z')).toBe(true); // 2000 leap
    expect(utc('480229000000Z')).toBe(true); // 2048 leap
    expect(utc('960229000000Z')).toBe(true); // 1996 leap
    expect(utc('000101000000Z')).toBe(true);
    expect(utc('490229000000Z')).toBe(false); // 2049 not leap
    expect(utc('500229000000Z')).toBe(false); // 1950 not leap
    expect(utc('000230000000Z')).toBe(false);
  });
  it('refuses fractions, bad fields, and unanchored text', () => {
    for (const s of ['491301000000Z', '490001000000Z', '490100000000Z', '490132000000Z', '490101240000Z', '490101006000Z', '490101000060Z', '490101000000.5Z', 'x490101000000Z', '490101000000Zx', '4901010000Z']) expect(utc(s), s).toBe(false);
    expect(utc('491231235959Z')).toBe(true);
  });
});

describe('traversal', () => {
  const wrap = (...kids: unknown[]) => ({ valueBlock: { value: kids } });
  it('primitives and null are fine; any malformed time anywhere in the tree refuses the whole', () => {
    expect(allAsn1TimesWellFormed(null, asn1)).toBe(true);
    expect(allAsn1TimesWellFormed(5, asn1)).toBe(true);
    expect(allAsn1TimesWellFormed({}, asn1)).toBe(true);
    expect(allAsn1TimesWellFormed(wrap(t(GEN, '20240101000000Z'), wrap(t(UTC, '490101000000Z'))), asn1)).toBe(true);
    expect(allAsn1TimesWellFormed(wrap(t(GEN, '20240101000000Z'), wrap(t(UTC, '491301000000Z'))), asn1)).toBe(false);
    expect(allAsn1TimesWellFormed(wrap(wrap(wrap(t(GEN, '20240230000000Z')))), asn1)).toBe(false);
    expect(allAsn1TimesWellFormed(wrap(t(GEN, '20240230000000Z'), t(GEN, '20240101000000Z')), asn1)).toBe(false);
    expect(allAsn1TimesWellFormed({ valueBlock: { value: 'not-an-array' } }, asn1)).toBe(true);
  });
});
