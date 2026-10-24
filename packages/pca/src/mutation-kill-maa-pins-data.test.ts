/**
 * 0.4.2 mutation kills: the shipped MAA pins data (attest-maa-pins.data.ts) is signed content - ANY change to a value in it must
 * break either the signature check or one of the pinned facts below. (attest-maa-pins.test.ts, the large suite, is excluded from
 * mutation runs; this is the cheap guard.)
 */
import { describe, expect, it } from 'vitest';
import { verifyAllowlistManifest } from './attest-allowlist';
import { BUILTIN_MAA_PINS_ISSUER_KEYS } from './attest-maa-pins';
import { BUILTIN_PINS_ISSUER_ID, BUILTIN_PINS_ISSUER_KEY, BUILTIN_PINS_MANIFEST, BUILTIN_PINS_MIN_VERSION } from './attest-maa-pins.data';
import { hashCanonical } from './hash';

describe('shipped pins', () => {
  it('the manifest verifies under the shipped issuer key at the start of its window, with the shipped minimum version', () => {
    const b = BUILTIN_PINS_MANIFEST.body;
    const r = verifyAllowlistManifest(BUILTIN_PINS_MANIFEST, { issuerKeys: { [BUILTIN_PINS_ISSUER_ID]: BUILTIN_PINS_ISSUER_KEY }, nowMs: b.notBefore, minVersion: BUILTIN_PINS_MIN_VERSION });
    expect(r.ok, JSON.stringify(r)).toBe(true);
  });
  it('the issuer id, key suite, minimum version and registry wiring are exactly the shipped ones', () => {
    expect(BUILTIN_PINS_ISSUER_ID).toBe('pca-release-maa-pins-2026-c508ee');
    expect(BUILTIN_PINS_MIN_VERSION).toBe(1);
    expect(BUILTIN_PINS_ISSUER_KEY.alg).toBe('hybrid-ed25519-ml-dsa-65');
    expect(Object.keys(BUILTIN_PINS_ISSUER_KEY.keys).sort()).toEqual(['edPub', 'mlDsaPub']);
    expect(BUILTIN_PINS_ISSUER_KEY.keys.edPub).toBe('OF1R6EzBkFePRu6kAEhgxu1pJ8wDD-PowD2nwH4Nh5k');
    expect(BUILTIN_PINS_MANIFEST.issuer).toBe(BUILTIN_PINS_ISSUER_ID);
    expect(BUILTIN_PINS_MANIFEST.alg).toBe('hybrid-ed25519-ml-dsa-65');
    expect(BUILTIN_MAA_PINS_ISSUER_KEYS[BUILTIN_PINS_ISSUER_ID]).toBe(BUILTIN_PINS_ISSUER_KEY);
  });
  it('a one-character change to the signed body, issuer or key breaks verification (the data is tamper-evident)', () => {
    const keys = { [BUILTIN_PINS_ISSUER_ID]: BUILTIN_PINS_ISSUER_KEY };
    const nowMs = BUILTIN_PINS_MANIFEST.body.notBefore;
    const m = JSON.parse(JSON.stringify(BUILTIN_PINS_MANIFEST));
    m.body.entries[0].label = m.body.entries[0].label + 'x';
    expect(verifyAllowlistManifest(m, { issuerKeys: keys, nowMs }).ok).toBe(false);
    const k = JSON.parse(JSON.stringify(BUILTIN_PINS_ISSUER_KEY));
    k.keys.edPub = 'A' + k.keys.edPub.slice(1);
    expect(verifyAllowlistManifest(BUILTIN_PINS_MANIFEST, { issuerKeys: { [BUILTIN_PINS_ISSUER_ID]: k }, nowMs }).ok).toBe(false);
    expect(typeof hashCanonical(BUILTIN_PINS_MANIFEST.body)).toBe('string');
  });
});
