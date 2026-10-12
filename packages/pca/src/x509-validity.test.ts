/**
 * X.509 validity parsing. Hand-built DER certificates: an out-of-range time (second 60, month 13, Feb 30, ...) still
 * constructs an X509Certificate, and a GeneralizedTime year below 1000 renders unpadded ("... 49 GMT", which Date.parse
 * reads as 2049). How Node renders such times depends on the OpenSSL it links, so the assertions here are on OUR instants,
 * parsed from the certificate DER (x509ValidityMs / x509ValidAt), never on Node's rendering: the verdict is the same on
 * every platform, exact, and fails closed.
 */
import { X509Certificate, createHash, generateKeyPairSync, sign as nsign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { derValidityMs, parseDerTime, parseOpenSslTime, x509ValidAt, x509ValidityMs } from './x509-validity';
import { verifyIntelPckChainX509 } from './attest-intel-tdx';
import { verifyNvidiaDeviceChain } from './attest-nvidia-spdm';
import { verifyX5cChain } from './attest-azure-maa';

const cat = (...a: Uint8Array[]) => Buffer.concat(a.map((x) => Buffer.from(x)));
const len = (n: number) => (n < 0x80 ? Buffer.from([n]) : n < 0x100 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 0xff]));
const tlv = (t: number, c: Uint8Array) => cat(Buffer.from([t]), len(c.length), c);
const seq = (...x: Uint8Array[]) => tlv(0x30, cat(...x));
const oid = (hex: string) => tlv(0x06, Buffer.from(hex, 'hex'));
const utc = (s: string) => tlv(0x17, Buffer.from(s, 'ascii'));
const gen = (s: string) => tlv(0x18, Buffer.from(s, 'ascii'));
const name = seq(tlv(0x31, seq(oid('550403'), tlv(0x0c, Buffer.from('r2-validity-probe')))));

/** A self-signed certificate with the given validity encodings. */
function selfSigned(nb: Uint8Array, na: Uint8Array, curve: 'P-256' | 'P-384' = 'P-256'): { der: Buffer; spkiSha256: string } {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: curve });
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const alg = seq(oid(curve === 'P-256' ? '2a8648ce3d040302' : '2a8648ce3d040303'));
  const tbs = seq(tlv(0xa0, tlv(0x02, Buffer.from([2]))), tlv(0x02, Buffer.from([7])), alg, name, seq(nb, na), name, spki);
  const sig = nsign(curve === 'P-256' ? 'sha256' : 'sha384', tbs, privateKey);
  return { der: seq(tbs, alg, tlv(0x03, cat(Buffer.from([0]), sig))), spkiSha256: createHash('sha256').update(spki).digest('hex') };
}
const pem = (der: Buffer) => `-----BEGIN CERTIFICATE-----\n${der.toString('base64').replace(/(.{64})/g, '$1\n')}\n-----END CERTIFICATE-----\n`;
const NOW = Date.UTC(2026, 9, 11);

describe('validity instants come from the certificate DER (independent of how Node / OpenSSL renders them)', () => {
  it('out-of-range times are NaN and never valid, on every platform', () => {
    for (const t of ['250101000060Z', '251301000000Z', '250230000000Z', '250101240000Z', '250100000000Z', '250431000000Z', '250101006000Z']) {
      const c = new X509Certificate(selfSigned(utc(t), utc('300101000000Z')).der);
      expect(Number.isNaN(x509ValidityMs(c).from), t).toBe(true);
      expect(x509ValidityMs(c).to).toBe(Date.UTC(2030, 0, 1));
      expect(x509ValidAt(c, NOW)).toBe(false);
    }
  });
  it('a year-49 GeneralizedTime notAfter is year 49 (Date.parse of the rendering read it as 2049)', () => {
    const c = new X509Certificate(selfSigned(utc('250101000000Z'), gen('00490101000000Z')).der);
    expect(x509ValidityMs(c)).toEqual({ from: Date.UTC(2025, 0, 1), to: new Date(0).setUTCFullYear(49, 0, 1) });
    expect(new Date(x509ValidityMs(c).to).getUTCFullYear()).toBe(49);
    expect(x509ValidAt(c, NOW)).toBe(false);
  });
  it('exact instants: UTCTime two-digit years (50..99 => 19xx, 00..49 => 20xx), GeneralizedTime, leap day', () => {
    const v = (nb: Uint8Array, na: Uint8Array) => x509ValidityMs(new X509Certificate(selfSigned(nb, na).der));
    expect(v(utc('500101000000Z'), utc('491231235959Z'))).toEqual({ from: Date.UTC(1950, 0, 1), to: Date.UTC(2049, 11, 31, 23, 59, 59) });
    expect(v(gen('20240229120000Z'), gen('99991231235959Z'))).toEqual({ from: Date.UTC(2024, 1, 29, 12), to: Date.UTC(9999, 11, 31, 23, 59, 59) });
    expect(Number.isNaN(v(gen('20250229120000Z'), utc('300101000000Z')).from)).toBe(true); // not a leap year
  });
  it('non-RFC 5280 encodings are NaN: fractions, offsets, missing seconds, wrong tag/length, non-digits', () => {
    // straight from our DER reader: OpenSSL itself may refuse to construct some of these, and that must not matter
    const v = (nb: Uint8Array) => derValidityMs(selfSigned(nb, utc('300101000000Z')).der).from;
    for (const nb of [gen('20250101000000.5Z'), utc('2501010000Z'), gen('20250101000000+0000'), utc('25010100000+Z'), gen('2025010100000Z')]) {
      expect(Number.isNaN(v(nb))).toBe(true);
    }
  });
  it('the parsers on their own', () => {
    expect(parseDerTime(0x17, '300101000000Z')).toBe(Date.UTC(2030, 0, 1));
    expect(parseDerTime(0x18, '20300101000000Z')).toBe(Date.UTC(2030, 0, 1));
    expect(Number.isNaN(parseDerTime(0x18, '300101000000Z'))).toBe(true);
    expect(Number.isNaN(parseDerTime(0x04, '300101000000Z'))).toBe(true);
    expect(derValidityMs(new Uint8Array([0x30, 0x00]))).toEqual({ from: NaN, to: NaN });
    expect(derValidityMs(new Uint8Array([0x02, 0x01, 0x00]))).toEqual({ from: NaN, to: NaN });
  });
  it('a shim without raw DER falls back to the strict rendered-string parser', () => {
    expect(x509ValidityMs({ validFrom: 'Jan  1 00:00:00 2025 GMT', validTo: 'Jan  1 00:00:00 2030 GMT' })).toEqual({ from: Date.UTC(2025, 0, 1), to: Date.UTC(2030, 0, 1) });
  });
  it('the strict renderer parser (fallback when validFromDate is unavailable)', () => {
    expect(parseOpenSslTime('Jan  1 00:00:00 2030 GMT')).toBe(Date.UTC(2030, 0, 1));
    expect(parseOpenSslTime('Dec 31 23:59:59.5 9999 GMT')).toBe(Date.UTC(9999, 11, 31, 23, 59, 59, 500));
    for (const bad of ['Jan  1 00:00:00 49 GMT', 'Bad time value', 'Feb 30 00:00:00 2030 GMT', 'Jan  1 24:00:00 2030 GMT', 'Foo  1 00:00:00 2030 GMT', '', 5]) {
      expect(Number.isNaN(parseOpenSslTime(bad))).toBe(true);
    }
    const shim = { validFrom: 'Jan  1 00:00:00 2025 GMT', validTo: 'Jan  1 00:00:00 49 GMT' };
    expect(x509ValidAt(shim, NOW)).toBe(false);
    expect(x509ValidAt({ validFrom: 'Jan  1 00:00:00 2025 GMT', validTo: 'Jan  1 00:00:00 2030 GMT' }, NOW)).toBe(true);
    expect(x509ValidAt({ validFrom: 'Jan  1 00:00:00 2025 GMT', validTo: 'Jan  1 00:00:00 2030 GMT' }, NaN)).toBe(false);
  });
});

describe('r2 SECURITY: chain verifiers enforce validity exactly', () => {
  it('Intel PCK chain: a root that expired in year 49 is outside its validity period (Date.parse read it as 2049)', async () => {
    const root = selfSigned(utc('250101000000Z'), gen('00490101000000Z'));
    const r = await verifyIntelPckChainX509({ pckChainPem: pem(root.der), trustAnchorRootCaSpkiSha256: root.spkiSha256, nowMs: NOW });
    expect(r.ok).toBe(false);
    expect(r.failure).toBe('validity');
  });
  it('NVIDIA device chain: a certificate whose notAfter has second 60 is refused (a NaN bound was accepted at any time)', () => {
    const root = selfSigned(utc('250101000000Z'), utc('300101000060Z'), 'P-384');
    const r = verifyNvidiaDeviceChain(pem(root.der), [root.spkiSha256], NOW);
    expect(r.ok).toBe(false);
    expect((r as { reason?: string }).reason).toMatch(/validity window/);
    const y49 = selfSigned(utc('250101000000Z'), gen('00490101000000Z'), 'P-384');
    const r2 = verifyNvidiaDeviceChain(pem(y49.der), [y49.spkiSha256], NOW);
    expect(r2.ok).toBe(false);
    expect((r2 as { reason?: string }).reason).toMatch(/validity window/);
  });
  it('Azure MAA x5c chain: a year-49 certificate is outside its validity window', async () => {
    const root = selfSigned(utc('250101000000Z'), gen('00490101000000Z'));
    const r = await verifyX5cChain([root.der.toString('base64')], { rootSpkiSha256: [root.spkiSha256] }, { nowMs: NOW });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/validity window/);
  });
});
