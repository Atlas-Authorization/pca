/**
 * 0.4.2 mutation kills: GEN_TIME / UTC_TIME are module-level regexes, built once when attest-nvidia-ocsp.ts is first imported.
 * Under Stryker's mutant switching that import happens before any mutant is active, so a regex mutant was never seen by the
 * statically-importing tests (mutation-kill-nvidia-ocsp-times.test.ts has these exact inputs). Each test here re-evaluates the
 * module (vi.resetModules + dynamic import) so the regexes are rebuilt with the active mutant.
 */
import { describe, expect, it, vi } from 'vitest';

class UTC { constructor(public valueBlock: { valueHexView: Uint8Array; value?: unknown }) {} }
class GEN extends UTC {} // asn1js: GeneralizedTime extends UTCTime
const asn1 = { UTCTime: UTC, GeneralizedTime: GEN } as never;
const t = (Cls: typeof UTC, text: string) => new Cls({ valueHexView: Buffer.from(text, 'latin1') });

async function fresh() {
  vi.resetModules();
  const { allAsn1TimesWellFormed } = await import('./attest-nvidia-ocsp');
  return {
    gen: (s: string) => allAsn1TimesWellFormed(t(GEN, s), asn1),
    utc: (s: string) => allAsn1TimesWellFormed(t(UTC, s), asn1),
    any: (n: unknown) => allAsn1TimesWellFormed(n, asn1),
  };
}

describe('GeneralizedTime pattern (fresh module)', () => {
  it('is anchored at the start', async () => {
    const { gen } = await fresh();
    expect(gen('x20240615120000Z')).toBe(false);
    expect(gen('120240615120000Z')).toBe(false);
  });
  it('the fraction is optional', async () => {
    const { gen } = await fresh();
    expect(gen('20240615120000Z')).toBe(true);
  });
  it('a fraction is any run of digits ending in a non-zero digit', async () => {
    const { gen } = await fresh();
    expect(gen('20240615120000.5Z')).toBe(true);
    expect(gen('20240615120000.11Z')).toBe(true);
    expect(gen('20240615120000.123Z')).toBe(true);
    expect(gen('20240615120000.10Z')).toBe(false);
    expect(gen('20240615120000.a1Z')).toBe(false);
  });
});

describe('UTCTime pattern (fresh module)', () => {
  it('is anchored at both ends', async () => {
    const { utc } = await fresh();
    expect(utc('490101000000Z')).toBe(true);
    expect(utc('x490101000000Z')).toBe(false);
    expect(utc('1490101000000Z')).toBe(false);
    expect(utc('490101000000Zx')).toBe(false);
  });
});

describe('traversal', () => {
  it('an undefined child is a primitive, not a node to descend into', async () => {
    const { any } = await fresh();
    expect(any(undefined)).toBe(true);
    expect(any({ valueBlock: { value: [undefined, t(GEN, '20240101000000Z')] } })).toBe(true);
  });
});
