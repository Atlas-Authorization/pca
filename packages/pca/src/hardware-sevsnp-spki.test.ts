/**
 * AMD VCEK public-key extraction: the P-384 point comes from the certificate key's JWK export, never from a byte
 * scan of the SPKI. Certificates are forged with test-support/forge-x509 (extraction does not need a valid AMD chain).
 */
import { describe, expect, it } from 'vitest';
import { extractVcekPublicKey } from './hardware-sevsnp';
import { ecPointFromKey } from './x509-strict';
import { createPublicKey } from 'node:crypto';
import { cat, forgeCert, forgeKey, oid, seq, tlv, bytesToHex } from './test-support/forge-x509';

const NB = new Date('2020-01-01Z');
const NA = new Date('2040-01-01Z');
const certWith = (spki: Uint8Array | undefined, curve: 'P-256' | 'P-384' = 'P-384') => {
  const key = forgeKey('vcek-spki', curve);
  return forgeCert({
    subject: [['CN', 'SEV-VCEK']],
    issuer: [['CN', 'SEV-VCEK']],
    subjectKey: spki ? { ...key, spki } : key,
    signer: forgeKey('vcek-signer', 'P-384'),
    serial: 1n,
    notBefore: NB,
    notAfter: NA,
  });
};
const algId = seq(oid('1.2.840.10045.2.1'), oid('1.3.132.0.34'));

describe('extractVcekPublicKey: strict point extraction', () => {
  it('returns exactly the certificate key point (97 bytes, uncompressed) for a P-384 VCEK', async () => {
    const key = forgeKey('vcek-spki', 'P-384');
    const c = certWith(undefined);
    const r = await extractVcekPublicKey(c.der);
    expect(r.key.point.length).toBe(97);
    expect(bytesToHex(r.key.point)).toBe(bytesToHex(key.spki.slice(-97)));
  });
  it('rejects a P-256 key in a VCEK with the specific curve reason', async () => {
    await expect(extractVcekPublicKey(certWith(undefined, 'P-256').der)).rejects.toThrow('VCEK is not EC secp384r1 (got ec/prime256v1)');
  });
  it('normalises a COMPRESSED-point SPKI of the real key (decompressed by OpenSSL, not byte-scanned)', async () => {
    const key = forgeKey('vcek-spki', 'P-384');
    const pt = key.spki.slice(-97);
    const compressed = cat(Uint8Array.of(pt[96]! & 1 ? 3 : 2), pt.slice(1, 49));
    const c = certWith(seq(algId, tlv(0x03, Uint8Array.of(0), compressed)));
    const r = await extractVcekPublicKey(c.der);
    expect(bytesToHex(r.key.point)).toBe(bytesToHex(pt));
  });
  it('rejects an off-curve / truncated point instead of reading trailing bytes', async () => {
    const short = certWith(seq(algId, tlv(0x03, Uint8Array.of(0), cat(Uint8Array.of(4), new Uint8Array(95).fill(7)))));
    await expect(extractVcekPublicKey(short.der)).rejects.toThrow();
    const offCurve = certWith(seq(algId, tlv(0x03, Uint8Array.of(0), cat(Uint8Array.of(4), new Uint8Array(96).fill(7)))));
    await expect(extractVcekPublicKey(offCurve.der)).rejects.toThrow();
  });
  it('rejects garbage DER', async () => {
    await expect(extractVcekPublicKey(new Uint8Array([1, 2, 3]))).rejects.toThrow();
  });
});

describe('ecPointFromKey', () => {
  it('rejects a mismatched curve with the specific reason, and a private key', () => {
    const p256 = createPublicKey({ key: Buffer.from(forgeKey('pc', 'P-256').spki), format: 'der', type: 'spki' });
    expect(() => ecPointFromKey(p256, 'P-384')).toThrow('public key is not on P-384 (got P-256)');
    expect(ecPointFromKey(p256, 'P-256').length).toBe(65);
  });
  it('rejects a non-EC key', () => {
    const ed = createPublicKey({ key: Buffer.from('302a300506032b6570032100' + '11'.repeat(32), 'hex'), format: 'der', type: 'spki' });
    expect(() => ecPointFromKey(ed, 'P-256')).toThrow('public key is not EC (got ed25519)');
  });
});
