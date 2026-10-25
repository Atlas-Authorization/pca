/**
 * 0.4.2 r11 mutation kills: attest-maa-pins.data.ts (the shipped, signed pin set) and the module-level constants of
 * attest-maa-pins.ts (the issuer-key registry, MAX_LIFETIME_MS) are evaluated once, when first imported. Under Stryker's
 * mutant switching that happens before any mutant is active, so the statically-importing guards
 * (mutation-kill-maa-pins-data.test.ts, mutation-kill-maa-pins.test.ts) never saw these mutants. Each test here re-evaluates
 * the modules (vi.resetModules + dynamic import) so the data and constants are rebuilt with the active mutant.
 */
import { describe, expect, it, vi } from 'vitest';

async function fresh() {
  vi.resetModules();
  const data = await import('./attest-maa-pins.data');
  const pins = await import('./attest-maa-pins');
  const allow = await import('./attest-allowlist');
  return { data, pins, allow };
}

describe('shipped MAA pins data (fresh module)', () => {
  it('issuer id, key suite and key material are exactly the shipped ones', async () => {
    const { data } = await fresh();
    expect(data.BUILTIN_PINS_ISSUER_ID).toBe('pca-release-maa-pins-2026-c508ee');
    expect(data.BUILTIN_PINS_MIN_VERSION).toBe(1);
    expect(data.BUILTIN_PINS_ISSUER_KEY.alg).toBe('hybrid-ed25519-ml-dsa-65');
    expect(Object.keys(data.BUILTIN_PINS_ISSUER_KEY.keys).sort()).toEqual(['edPub', 'mlDsaPub']);
    expect(data.BUILTIN_PINS_ISSUER_KEY.keys.edPub).toBe('OF1R6EzBkFePRu6kAEhgxu1pJ8wDD-PowD2nwH4Nh5k');
    expect((data.BUILTIN_PINS_ISSUER_KEY.keys as { mlDsaPub?: string }).mlDsaPub).toMatch(/^LzsIOODRk7RDp9FIyVT6KWIpNmhSe3qg/);
    expect(data.BUILTIN_PINS_MANIFEST.issuer).toBe(data.BUILTIN_PINS_ISSUER_ID);
    expect(data.BUILTIN_PINS_MANIFEST.alg).toBe('hybrid-ed25519-ml-dsa-65');
  });
  it('the manifest verifies under the shipped issuer key (hybrid: both the Ed25519 and the ML-DSA halves)', async () => {
    const { data, allow } = await fresh();
    const b = data.BUILTIN_PINS_MANIFEST.body;
    const r = allow.verifyAllowlistManifest(data.BUILTIN_PINS_MANIFEST, {
      issuerKeys: { [data.BUILTIN_PINS_ISSUER_ID]: data.BUILTIN_PINS_ISSUER_KEY },
      nowMs: b.notBefore,
      minVersion: data.BUILTIN_PINS_MIN_VERSION,
    });
    expect(r.ok, JSON.stringify(r)).toBe(true);
    expect(b.entries.length).toBe(7);
    expect(b.entries[0]).toEqual({ kind: 'maa-signing-spki', value: '97cda3af47e762fb8673d1664066082ad7a9e82120eb9523da1a39f6a84de3cc', label: 'https://sharedeus.eus.attest.azure.net' });
  });
});

describe('attest-maa-pins module constants (fresh module)', () => {
  it('the issuer-key registry holds exactly the shipped issuer key', async () => {
    const { data, pins } = await fresh();
    expect(Object.keys(pins.BUILTIN_MAA_PINS_ISSUER_KEYS)).toEqual([data.BUILTIN_PINS_ISSUER_ID]);
    expect(pins.BUILTIN_MAA_PINS_ISSUER_KEYS[data.BUILTIN_PINS_ISSUER_ID]).toBe(data.BUILTIN_PINS_ISSUER_KEY);
  });
  it('the shipped pins load (a ~1-year window is inside the 400-day lifetime cap) and expose the shipped facts', async () => {
    const { data, pins } = await fresh();
    const b = data.BUILTIN_PINS_MANIFEST.body;
    const r = pins.loadBuiltinMaaPins({ nowMs: b.notBefore + 86_400_000 });
    expect(r.ok, JSON.stringify(r)).toBe(true);
    if (!r.ok) return;
    expect(r.version).toBe(1);
    expect(r.vantages).toBe(3);
    expect(r.maaChainRootSpkis).toEqual(['02376d0908ac23041cc7d666d9daf192554f7fc36317aa9cb800908616b28af8']);
    expect(r.maaChainIntermediateSpkis).toEqual(['9ab67a5d1926476a794bcb4fa6cd74faa1486cd05931010aa7bbf1f57f1a8f58']);
  });
});
