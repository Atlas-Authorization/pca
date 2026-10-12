/**
 * Round-2 regression: X.509 validity parsing in verifyX509Svid. An out-of-range time renders as "Bad time value" and must be
 * 'chain_expired'. A notAfter in year 49 (which `new Date(validTo)` would read as 2049) is already refused by this package's
 * strict DER reader as a malformed certificate, so the misread is unreachable here; both refusals are pinned.
 */
import { generateKeyPairSync, sign as nsign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { verifyX509Svid, SpiffeError } from './index';

const cat = (...a: Uint8Array[]) => Buffer.concat(a.map((x) => Buffer.from(x)));
const len = (n: number) => (n < 0x80 ? Buffer.from([n]) : n < 0x100 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 0xff]));
const tlv = (t: number, c: Uint8Array) => cat(Buffer.from([t]), len(c.length), c);
const seq = (...x: Uint8Array[]) => tlv(0x30, cat(...x));
const oid = (hex: string) => tlv(0x06, Buffer.from(hex, 'hex'));
const utc = (s: string) => tlv(0x17, Buffer.from(s, 'ascii'));
const gen = (s: string) => tlv(0x18, Buffer.from(s, 'ascii'));
const ALG = seq(oid('2a8648ce3d040302'));
const name = (cn: string) => seq(tlv(0x31, seq(oid('550403'), tlv(0x0c, Buffer.from(cn)))));
const ext = (o: string, critical: boolean, value: Uint8Array) => seq(oid(o), ...(critical ? [tlv(0x01, Buffer.from([0xff]))] : []), tlv(0x04, value));

/** A self-signed SPIFFE leaf (URI SAN, keyUsage digitalSignature) with the given notAfter encoding. */
function leaf(na: Uint8Array): string {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const san = ext('551d11', false, seq(tlv(0x86, Buffer.from('spiffe://example.org/workload'))));
  const ku = ext('551d0f', true, tlv(0x03, Buffer.from([0x07, 0x80])));
  const tbs = seq(tlv(0xa0, tlv(0x02, Buffer.from([2]))), tlv(0x02, Buffer.from([5])), ALG, name('leaf'), seq(utc('250101000000Z'), na), name('leaf'), publicKey.export({ type: 'spki', format: 'der' }), tlv(0xa3, seq(san, ku)));
  const der = seq(tbs, ALG, tlv(0x03, cat(Buffer.from([0]), nsign('sha256', tbs, privateKey))));
  return `-----BEGIN CERTIFICATE-----\n${der.toString('base64').replace(/(.{64})/g, '$1\n')}\n-----END CERTIFICATE-----\n`;
}
const NOW = new Date(Date.UTC(2026, 9, 11));
const codeOf = (f: () => unknown): string => { try { f(); return 'no-throw'; } catch (e) { return e instanceof SpiffeError ? e.code : `other: ${(e as Error).message}`; } };

describe('r2: verifyX509Svid validity parsing', () => {
  it('control: a currently-valid leaf gets past the validity check (fails later on trust, not on validity)', () => {
    const l = leaf(utc('300101000000Z'));
    expect(codeOf(() => verifyX509Svid(l, { trustDomain: 'example.org', roots: [leaf(utc('300101000000Z'))], now: NOW }))).not.toBe('chain_expired');
  });
  it('notAfter second 60 ("Bad time value") is chain_expired', () => {
    const l = leaf(utc('300101000060Z'));
    expect(codeOf(() => verifyX509Svid(l, { trustDomain: 'example.org', roots: [leaf(utc('300101000000Z'))], now: NOW }))).toBe('chain_expired');
  });
  it('notAfter year 49 is refused (malformed by the strict DER reader, never accepted as valid until 2049)', () => {
    const l = leaf(gen('00490101000000Z'));
    expect(['malformed_certificate', 'chain_expired']).toContain(codeOf(() => verifyX509Svid(l, { trustDomain: 'example.org', roots: [leaf(utc('300101000000Z'))], now: NOW })));
  });
});
