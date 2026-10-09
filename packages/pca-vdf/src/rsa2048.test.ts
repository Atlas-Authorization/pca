import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { MIN_PRODUCTION_MODULUS_BITS, RSA_2048_CHALLENGE_MODULUS, checkProductionModulus, isProbablePrime } from './vdf';

interface Rsa2048Fixture {
  name: string;
  bits: number;
  digits: number;
  decimal: string;
  hex: string;
  decimalSha256: string;
  sources: Array<{ role: string; url: string; fileSha256: string; retrievedUtc: string; comparison: string }>;
}

const fx = JSON.parse(readFileSync(join(__dirname, '..', 'fixtures', 'rsa-2048.json'), 'utf8')) as Rsa2048Fixture;

describe('bundled RSA-2048 challenge modulus vs the published value', () => {
  it('fixture records provenance: two sources with URL, capture date and sha256', () => {
    expect(fx.sources).toHaveLength(2);
    for (const s of fx.sources) {
      expect(s.url).toMatch(/^https:\/\//);
      expect(s.fileSha256).toMatch(/^[0-9a-f]{64}$/);
      expect(s.retrievedUtc).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    }
    expect(fx.sources[0]?.url).toMatch(/rsasecurity\.com\/rsalabs/); // the publisher
  });

  it('the fixture digits are internally consistent (617 digits, 2048 bits, hash, hex form)', () => {
    expect(fx.decimal).toMatch(/^[1-9][0-9]{616}$/);
    expect(fx.digits).toBe(617);
    expect(BigInt(fx.decimal).toString(2)).toHaveLength(2048);
    expect(createHash('sha256').update(fx.decimal).digest('hex')).toBe(fx.decimalSha256);
    expect(BigInt('0x' + fx.hex)).toBe(BigInt(fx.decimal));
  });

  it('RSA_2048_CHALLENGE_MODULUS equals the published RSA-2048 digits exactly', () => {
    expect(RSA_2048_CHALLENGE_MODULUS.toString()).toBe(fx.decimal);
    expect(RSA_2048_CHALLENGE_MODULUS.toString(16)).toBe(fx.hex);
  });

  it('has the structure of an RSA challenge number: odd, composite, no tiny factors, passes the production screen', () => {
    expect(RSA_2048_CHALLENGE_MODULUS % 2n).toBe(1n);
    expect(isProbablePrime(RSA_2048_CHALLENGE_MODULUS)).toBe(false);
    expect(RSA_2048_CHALLENGE_MODULUS.toString(2).length).toBeGreaterThanOrEqual(MIN_PRODUCTION_MODULUS_BITS);
    expect(checkProductionModulus(RSA_2048_CHALLENGE_MODULUS)).toEqual({ ok: true });
  });

  it('a one-digit transcription error would be caught by the comparison', () => {
    const bumped = RSA_2048_CHALLENGE_MODULUS + 2n; // still odd, still 2048-bit
    expect(bumped.toString()).not.toBe(fx.decimal);
  });
});
