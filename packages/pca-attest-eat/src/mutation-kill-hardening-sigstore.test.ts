/**
 * 0.5 hardening in the Sigstore verifier: the RFC 3161 timestamp cap (H6) and the RSA public-key rule (H1).
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { KeyObject } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parseTrustedRoot, rsaKeyOk, verifySigstoreBundle } from './sigstore';

const FIX = join(__dirname, '..', 'test-fixtures', 'sigstore');
const ROOTS = parseTrustedRoot(JSON.parse(readFileSync(join(FIX, 'trusted_root.json'), 'utf8')));
const ATT = JSON.parse(readFileSync(join(FIX, 'npm-sigstore-5.0.0.attestations.json'), 'utf8')).attestations as { predicateType: string; bundle: any }[];
const SLSA = ATT.find((a) => a.predicateType === 'https://slsa.dev/provenance/v1')!.bundle;
const withTimestamps = (n: number) => {
  const b = JSON.parse(JSON.stringify(SLSA));
  b.verificationMaterial.timestampVerificationData = { rfc3161Timestamps: Array.from({ length: n }, () => ({ signedTimestamp: 'AAAA' })) };
  return b;
};
const why = (b: unknown) => {
  const r = verifySigstoreBundle(b, { roots: ROOTS });
  return r.ok ? 'ok' : `${r.code}: ${r.detail}`;
};

describe('RFC 3161 timestamp cap', () => {
  it('nine timestamps are refused before any is verified, with the count in the detail', () => {
    expect(why(withTimestamps(9))).toBe('tsa: too many RFC 3161 timestamps (9, at most 8)');
    expect(why(withTimestamps(100))).toBe('tsa: too many RFC 3161 timestamps (100, at most 8)');
  });
  it('eight (and fewer) go on to be verified individually: the refusal is about the timestamp, not the count', () => {
    for (const n of [1, 8]) expect(why(withTimestamps(n))).not.toMatch(/too many RFC 3161/);
  });
  it('the genuine bundle with no timestamp list still verifies', () => {
    expect(why(SLSA)).toBe('ok');
  });
});

const fake = (type: string, modulusLength?: number, publicExponent?: bigint): KeyObject =>
  ({ asymmetricKeyType: type, asymmetricKeyDetails: modulusLength === undefined ? undefined : { modulusLength, publicExponent } }) as unknown as KeyObject;

describe('rsaKeyOk (Sigstore copy)', () => {
  it('modulus 512..16384, exponent odd, >= 3, at most 32 bits; other key types pass', () => {
    expect(rsaKeyOk(fake('rsa', 512, 65537n))).toBe(true);
    expect(rsaKeyOk(fake('rsa', 511, 65537n))).toBe(false);
    expect(rsaKeyOk(fake('rsa', 16384, 65537n))).toBe(true);
    expect(rsaKeyOk(fake('rsa', 16385, 65537n))).toBe(false);
    for (const e of [1n, 2n, 4n, 2n ** 32n, 2n ** 33n + 1n]) expect(rsaKeyOk(fake('rsa', 2048, e)), String(e)).toBe(false);
    for (const e of [3n, 65537n, 2n ** 32n - 1n]) expect(rsaKeyOk(fake('rsa', 2048, e)), String(e)).toBe(true);
    expect(rsaKeyOk(fake('rsa-pss', 2048, 1n))).toBe(false);
    expect(rsaKeyOk(fake('rsa'))).toBe(false);
    expect(rsaKeyOk(fake('ec'))).toBe(true);
  });
});
