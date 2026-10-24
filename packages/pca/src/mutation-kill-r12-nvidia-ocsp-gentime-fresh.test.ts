/**
 * 0.4.2 r12 mutation kill: GEN_TIME in attest-nvidia-ocsp.ts is a module-level regex (see
 * mutation-kill-nvidia-ocsp-times-fresh.test.ts). This adds the missing end-anchor probe: text after the trailing Z.
 */
import { describe, expect, it, vi } from 'vitest';

class UTC { constructor(public valueBlock: { valueHexView: Uint8Array; value?: unknown }) {} }
class GEN extends UTC {} // asn1js: GeneralizedTime extends UTCTime
const asn1 = { UTCTime: UTC, GeneralizedTime: GEN } as never;

describe('GeneralizedTime pattern end anchor (fresh module)', () => {
  it('nothing may follow the Z', async () => {
    vi.resetModules();
    const { allAsn1TimesWellFormed } = await import('./attest-nvidia-ocsp');
    const gen = (s: string) => allAsn1TimesWellFormed(new GEN({ valueHexView: Buffer.from(s, 'latin1') }), asn1);
    expect(gen('20240615120000Z')).toBe(true);
    expect(gen('20240615120000.5Z')).toBe(true);
    expect(gen('20240615120000Zx')).toBe(false);
    expect(gen('20240615120000.5Z0')).toBe(false);
  });
});
