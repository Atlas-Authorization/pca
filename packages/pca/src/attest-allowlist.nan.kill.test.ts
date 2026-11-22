import { describe, expect, it } from 'vitest';
import { projectAllowlist, signAllowlistManifest, verifyAllowlistManifest, type AllowlistManifestBody, type AllowlistIssuerKey } from './attest-allowlist';
import { b64u } from './hash';
import { generateKeyPair } from './keys';

const T0 = Date.parse('2026-10-09T00:00:00Z');
const DAY = 86_400_000;
const ed = generateKeyPair();
const keys = (notAfter?: number): Record<string, AllowlistIssuerKey> => ({ 'ops-ed': { alg: 'ed25519', keys: { edPub: b64u(ed.publicKey) }, ...(notAfter !== undefined ? { notAfter } : {}) } });
const SNP = 'ab'.repeat(48);
const body = (): AllowlistManifestBody => ({ version: 1, issuedAt: T0 - DAY, notBefore: T0 - DAY, expiresAt: T0 + 30 * DAY, entries: [{ kind: 'sev-snp-measurement', value: SNP, label: 'snp', notAfter: T0 + DAY }] });
const signed = () => signAllowlistManifest(body(), { issuer: 'ops-ed', alg: 'ed25519', secrets: { edSecret: ed.secretKey } });

describe('a non-finite time bound never admits (attestation allowlist)', () => {
  it('a finite issuer notAfter in the future verifies, and the entry projects', () => {
    const v = verifyAllowlistManifest(signed(), { issuerKeys: keys(T0 + DAY), nowMs: T0 });
    expect(v.ok).toBe(true);
    if (v.ok) expect(projectAllowlist(v, { nowMs: T0 }).sevSnpMeasurements).toEqual([SNP]);
  });
  // old check `nowMs > notAfter` was false for a NaN notAfter, so a key with a garbage expiry stayed trusted forever
  it('an issuer key whose notAfter is NaN is expired', () => {
    const v = verifyAllowlistManifest(signed(), { issuerKeys: keys(Number.NaN), nowMs: T0 });
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.code).toBe('issuer-expired');
  });
  // same for the projection: a NaN clock compared false against every entry notAfter, so expiring entries projected as live
  it('projecting at a NaN clock expires every entry that carries a notAfter', () => {
    const v = verifyAllowlistManifest(signed(), { issuerKeys: keys(), nowMs: T0 });
    expect(v.ok).toBe(true);
    if (v.ok) {
      const p = projectAllowlist(v, { nowMs: Number.NaN });
      expect(p.sevSnpMeasurements).toEqual([]);
      expect(p.expired.length).toBe(1);
    }
  });
  // old check `nowMs <= notAfter` is true for -Infinity, so an expiring entry projected as live
  it('projecting at an infinite clock expires every entry that carries a notAfter', () => {
    const v = verifyAllowlistManifest(signed(), { issuerKeys: keys(), nowMs: T0 });
    expect(v.ok).toBe(true);
    if (v.ok) {
      for (const nowMs of [Number.NEGATIVE_INFINITY, Number.POSITIVE_INFINITY]) {
        const p = projectAllowlist(v, { nowMs });
        expect(p.sevSnpMeasurements).toEqual([]);
        expect(p.expired.length).toBe(1);
      }
    }
  });
});
