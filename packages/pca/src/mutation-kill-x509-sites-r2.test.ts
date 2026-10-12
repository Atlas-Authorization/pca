/**
 * Per-site regression for X.509 validity parsing in the GCP Confidential Space x5c chain (see x509-validity.test.ts for
 * the library probes): an out-of-range time is "Bad time value" (NaN) and a year below 1000 is rendered unpadded, which
 * Date.parse read as 19xx/20xx. Both must be refused as outside the validity window.
 */
import { createHash, generateKeyPairSync, sign as nsign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { verifyJwkX5cChain } from './attest-gcp-confidential-space';

const cat = (...a: Uint8Array[]) => Buffer.concat(a.map((x) => Buffer.from(x)));
const len = (n: number) => (n < 0x80 ? Buffer.from([n]) : n < 0x100 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 0xff]));
const tlv = (t: number, c: Uint8Array) => cat(Buffer.from([t]), len(c.length), c);
const seq = (...x: Uint8Array[]) => tlv(0x30, cat(...x));
const oid = (hex: string) => tlv(0x06, Buffer.from(hex, 'hex'));
const utc = (s: string) => tlv(0x17, Buffer.from(s, 'ascii'));
const gen = (s: string) => tlv(0x18, Buffer.from(s, 'ascii'));
const ALG = seq(oid('2a8648ce3d040302'));
const name = seq(tlv(0x31, seq(oid('550403'), tlv(0x0c, Buffer.from('r2 gcp anchor')))));

function selfSigned(na: Uint8Array): { b64: string; pem: string; spki: string } {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const tbs = seq(tlv(0xa0, tlv(0x02, Buffer.from([2]))), tlv(0x02, Buffer.from([3])), ALG, name, seq(utc('250101000000Z'), na), name, spki);
  const der = seq(tbs, ALG, tlv(0x03, cat(Buffer.from([0]), nsign('sha256', tbs, privateKey))));
  return { b64: der.toString('base64'), pem: `-----BEGIN CERTIFICATE-----\n${der.toString('base64').replace(/(.{64})/g, '$1\n')}\n-----END CERTIFICATE-----\n`, spki: createHash('sha256').update(spki).digest('hex') };
}
const NOW = Date.UTC(2026, 9, 11);

describe('r2: GCP Confidential Space x5c chain validity', () => {
  it('control: a valid self-signed anchor passes the validity check', async () => {
    const c = selfSigned(utc('300101000000Z'));
    const r = await verifyJwkX5cChain([c.b64], { rootCertsPem: [c.pem] } as never, { nowMs: NOW, skewMs: 0 });
    expect(r ?? '').not.toMatch(/validity window/);
  });
  for (const [label, na] of [['notAfter second 60 ("Bad time value")', utc('300101000060Z')], ['notAfter year 49 (Date.parse read 2049)', gen('00490101000000Z')]] as const) {
    it(label, async () => {
      const c = selfSigned(na);
      const r = await verifyJwkX5cChain([c.b64], { rootCertsPem: [c.pem] } as never, { nowMs: NOW, skewMs: 0 });
      expect(r).toMatch(/outside its validity window/);
    });
  }
});
