/**
 * Round-2: evaluateMaaJwks compares validity with `now + skew < from` / `now - skew > to`, which a NaN bound passes.
 * The ledger called the `Number.isFinite` guard unreachable ("X509Certificate validity dates always parse to finite
 * numbers"); probed false (an out-of-range time renders as "Bad time value"). A self-signed MAA instance key whose
 * notAfter is out of range must be rejected as unparsable, never accepted as a trust anchor.
 */
import { generateKeyPairSync, sign as nsign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { evaluateMaaJwks } from './attest-maa-keys';

const cat = (...a: Uint8Array[]) => Buffer.concat(a.map((x) => Buffer.from(x)));
const len = (n: number) => (n < 0x80 ? Buffer.from([n]) : n < 0x100 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 0xff]));
const tlv = (t: number, c: Uint8Array) => cat(Buffer.from([t]), len(c.length), c);
const seq = (...x: Uint8Array[]) => tlv(0x30, cat(...x));
const oid = (hex: string) => tlv(0x06, Buffer.from(hex, 'hex'));
const utc = (s: string) => tlv(0x17, Buffer.from(s, 'ascii'));
const gen = (s: string) => tlv(0x18, Buffer.from(s, 'ascii'));
const ALG = seq(oid('2a8648ce3d040302'));
const ISSUER = 'https://r2probe.wus.attest.azure.net';
const name = seq(tlv(0x31, seq(oid('550403'), tlv(0x0c, Buffer.from(ISSUER)))));

function selfSigned(notAfter: string | Uint8Array): string {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const tbs = seq(tlv(0xa0, tlv(0x02, Buffer.from([2]))), tlv(0x02, Buffer.from([9])), ALG, name, seq(utc('260101000000Z'), typeof notAfter === 'string' ? utc(notAfter) : notAfter), name, publicKey.export({ type: 'spki', format: 'der' }));
  return seq(tbs, ALG, tlv(0x03, cat(Buffer.from([0]), nsign('sha256', tbs, privateKey)))).toString('base64');
}
const NOW = Date.UTC(2026, 9, 11);
const policy = { trustedIssuers: [ISSUER], allowTrustOnFirstUse: true, builtinPins: false } as never;

describe('r2: MAA key trust rejects unparsable certificate validity', () => {
  it('control: a well-formed self-signed instance key is accepted', () => {
    const ev = evaluateMaaJwks({ keys: [{ kid: 'k', kty: 'EC', x5c: [selfSigned('301231000000Z')] }] } as never, ISSUER, policy, NOW);
    expect(ev.rejected.map((r) => r.reason)).toEqual([]);
    expect(ev.accepted).toHaveLength(1);
  });
  it('notAfter "Bad time value" (second 60) is rejected as unparsable, not accepted', () => {
    const ev = evaluateMaaJwks({ keys: [{ kid: 'k', kty: 'EC', x5c: [selfSigned('301231000060Z')] }] } as never, ISSUER, policy, NOW);
    expect(ev.accepted).toHaveLength(0);
    expect(ev.rejected[0]?.reason).toMatch(/unparsable validity/);
  });
  it('a key that expired in year 49 is expired (Date.parse read the unpadded year as 2049)', () => {
    const ev = evaluateMaaJwks({ keys: [{ kid: 'k', kty: 'EC', x5c: [selfSigned(gen('00490101000000Z'))] }] } as never, ISSUER, policy, NOW);
    expect(ev.accepted).toHaveLength(0);
    expect(ev.rejected[0]?.reason).toMatch(/expired/);
  });
});
