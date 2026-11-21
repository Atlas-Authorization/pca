import { X509Certificate } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { verifyCrl } from './attest-intel-collateral';
import { forgeTdxQuote } from './test-support/forge-dcap';
import { forgeCrl } from './test-support/forge-x509';

const Q = forgeTdxQuote();
const rootPub = new X509Certificate(Q.pki.root.der).publicKey;
const crl = forgeCrl({ issuer: Q.pki.rootDn, signer: Q.pki.rootKey, revoked: [], thisUpdate: new Date('2026-10-08T21:28:48Z'), nextUpdate: new Date('2026-11-07T21:28:48Z'), authorityKey: Q.pki.rootKey } as never);
const NOW = new Date('2026-10-20T00:00:00Z');

describe('an unreadable clock never passes freshness (Intel collateral)', () => {
  it('a finite in-window clock verifies', () => {
    expect(verifyCrl(crl, rootPub, NOW).ok).toBe(true);
  });
  // old `now < thisUpdate` and `now > nextUpdate` were both false for an Invalid Date (NaN), so a stale CRL verified
  it('an invalid clock refuses the CRL', () => {
    expect(verifyCrl(crl, rootPub, new Date(Number.NaN))).toEqual({ ok: false, reason: 'CRL time is not finite' });
  });
});
