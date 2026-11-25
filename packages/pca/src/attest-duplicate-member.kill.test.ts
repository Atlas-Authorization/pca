import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parseMaaJwt } from './attest-azure-maa';
import { parseGcpCsJwt } from './attest-gcp-confidential-space';
import { verifySignedJson } from './attest-intel-collateral';

// A duplicate JSON member in signed or digested input is a parser differential: JSON.parse keeps the LAST value while the signer (and a strict
// verifier) saw the first. Every vendor-document parser refuses it, with a fixed message the natives reproduce.
const HEADER = 'eyJhbGciOiJFUzI1NiIsImtpZCI6ImsxIiwiamt1IjoiaHR0cHM6Ly9tYWEuZXhhbXBsZS5uZXQvY2VydHMiLCJ0eXAiOiJKV1QiLCJ4NWMiOlsiQUFBQSIsIkJCQkIiXX0';
const DUP_PAYLOAD = Buffer.from('{"a":1,"a":2}').toString('base64url');
const OK_PAYLOAD = Buffer.from('{"a":2}').toString('base64url');

describe('duplicate members in vendor documents are refused', () => {
  it('an Azure MAA JWT with a duplicate payload member', () => {
    expect(() => parseMaaJwt(`${HEADER}.${DUP_PAYLOAD}.c2ln`)).toThrow(new TypeError('parseMaaJwt: malformed JSON segment: invalid JSON'));
    expect(parseMaaJwt(`${HEADER}.${OK_PAYLOAD}.c2ln`).payload).toEqual({ a: 2 });
  });
  it('a Google Confidential Space JWT with a duplicate payload member', () => {
    expect(() => parseGcpCsJwt(`${HEADER}.${DUP_PAYLOAD}.c2ln`)).toThrow(new TypeError('parseGcpCsJwt: malformed JSON segment: invalid JSON'));
    expect(parseGcpCsJwt(`${HEADER}.${OK_PAYLOAD}.c2ln`).payload).toEqual({ a: 2 });
  });
  it('non-canonical numbers (8.0, 1e3) are read as JSON.parse reads them; non-JSON has one engine-independent reason', () => {
    const p = Buffer.from('{"a":8.0,"b":1e3}').toString('base64url');
    expect(parseMaaJwt(`${HEADER}.${p}.c2ln`).payload).toEqual({ a: 8, b: 1000 });
    expect(parseGcpCsJwt(`${HEADER}.${p}.c2ln`).payload).toEqual({ a: 8, b: 1000 });
    const junk = Buffer.from('not json').toString('base64url');
    expect(() => parseMaaJwt(`${junk}.${p}.c2ln`)).toThrow(new TypeError('parseMaaJwt: malformed JSON segment: invalid JSON'));
    expect(() => parseGcpCsJwt(`${HEADER}.${junk}.c2ln`)).toThrow(new TypeError('parseGcpCsJwt: malformed JSON segment: invalid JSON'));
  });
  it('a duplicate member in the header is refused too', () => {
    const dupHeader = Buffer.from('{"alg":"ES256","alg":"none","kid":"k1"}').toString('base64url');
    expect(() => parseMaaJwt(`${dupHeader}.${OK_PAYLOAD}.c2ln`)).toThrow(new TypeError('parseMaaJwt: malformed JSON segment: invalid JSON'));
  });
  it('an Intel collateral document with a duplicate member inside the signed body, or beside the signature', () => {
    const key = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey;
    const sig = '0'.repeat(128);
    expect(verifySignedJson(`{"tcbInfo":{"a":1,"a":2},"signature":"${sig}"}`, 'tcbInfo', key)).toEqual({ error: 'tcbInfo document is not valid JSON' });
    expect(verifySignedJson(`{"tcbInfo":{"a":1},"signature":"${sig}","signature":"${sig}"}`, 'tcbInfo', key)).toEqual({ error: 'tcbInfo document is not valid JSON' });
  });
});
