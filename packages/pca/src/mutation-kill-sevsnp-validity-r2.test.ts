/**
 * Round-2: the AMD chain check compares validity with `now + skew < from` / `now - skew > to`, which a NaN bound
 * silently passes. The ledger called the explicit `Number.isFinite(from/to)` guard unreachable ("Node's X509Certificate
 * rejects certificates with unparseable validity at construction"); probed false: an out-of-range time constructs and
 * renders as "Bad time value". This builds a structurally valid ARK -> ASK -> VCEK chain (pinned ARK) whose VCEK
 * notAfter is out of range and requires the "unparseable" refusal.
 */
import { createHash, generateKeyPairSync, sign as nsign, type KeyObject } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { verifyAmdCertChain } from './hardware-sevsnp';

const cat = (...a: Uint8Array[]) => Buffer.concat(a.map((x) => Buffer.from(x)));
const len = (n: number) => (n < 0x80 ? Buffer.from([n]) : n < 0x100 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 0xff]));
const tlv = (t: number, c: Uint8Array) => cat(Buffer.from([t]), len(c.length), c);
const seq = (...x: Uint8Array[]) => tlv(0x30, cat(...x));
const oid = (hex: string) => tlv(0x06, Buffer.from(hex, 'hex'));
const utc = (s: string) => tlv(0x17, Buffer.from(s, 'ascii'));
const ALG = seq(oid('2a8648ce3d040303')); // ecdsa-with-SHA384
const name = (cn: string) => seq(tlv(0x31, seq(oid('550403'), tlv(0x0c, Buffer.from(cn)))));
const caExt = tlv(0xa3, seq(seq(oid('551d13'), tlv(0x01, Buffer.from([0xff])), tlv(0x04, seq(tlv(0x01, Buffer.from([0xff])))))));

function cert(subject: string, issuer: string, pub: KeyObject, signer: KeyObject, serial: number, ca: boolean, notAfter = '300101000000Z'): Buffer {
  const spki = pub.export({ type: 'spki', format: 'der' });
  const tbs = seq(tlv(0xa0, tlv(0x02, Buffer.from([2]))), tlv(0x02, Buffer.from([serial])), ALG, name(issuer), seq(utc('250101000000Z'), utc(notAfter)), name(subject), spki, ...(ca ? [caExt] : []));
  return seq(tbs, ALG, tlv(0x03, cat(Buffer.from([0]), nsign('sha384', tbs, signer))));
}
const pem = (der: Buffer) => `-----BEGIN CERTIFICATE-----\n${der.toString('base64').replace(/(.{64})/g, '$1\n')}\n-----END CERTIFICATE-----\n`;

describe('r2: AMD chain refuses a certificate whose validity is unparseable', () => {
  it('VCEK with notAfter second=60 ("Bad time value") is refused as unparseable, not accepted', async () => {
    const ark = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
    const ask = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
    const vcek = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
    const arkDer = cert('ARK-R2', 'ARK-R2', ark.publicKey, ark.privateKey, 1, true);
    const askDer = cert('ASK-R2', 'ARK-R2', ask.publicKey, ark.privateKey, 2, true);
    const pin = createHash('sha384').update(ark.publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
    const now = Date.UTC(2026, 9, 11);
    const good = await verifyAmdCertChain({ vcekDer: cert('VCEK-R2', 'ASK-R2', vcek.publicKey, ask.privateKey, 3, false), askArkPem: pem(askDer) + pem(arkDer), trustAnchorArkSpkiSha384: pin, nowMs: now });
    expect(good.reason ?? '').not.toMatch(/validity|valid yet|expired/);
    const bad = await verifyAmdCertChain({ vcekDer: cert('VCEK-R2', 'ASK-R2', vcek.publicKey, ask.privateKey, 3, false, '300101000060Z'), askArkPem: pem(askDer) + pem(arkDer), trustAnchorArkSpkiSha384: pin, nowMs: now });
    expect(bad.ok).toBe(false);
    expect(bad.reason).toMatch(/VCEK certificate validity is unparseable/);
  });
});
