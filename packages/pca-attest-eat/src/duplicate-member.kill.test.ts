import { createPrivateKey, generateKeyPairSync, sign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { EAT_TYP, verifyEAT } from './index';

// Compact JWS built from raw header/payload text (so a duplicate member survives), signed with a key generated here.
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const b64u = (b: Buffer | string) => Buffer.from(b).toString('base64url');
const eat = (headerText: string, payloadText: string) => {
  const input = `${b64u(headerText)}.${b64u(payloadText)}`;
  return `${input}.${b64u(sign(null, Buffer.from(input), createPrivateKey(privateKey.export({ type: 'pkcs8', format: 'pem' }))))}`;
};
const HEADER = `{"alg":"EdDSA","typ":"${EAT_TYP}"}`;

// verifyEAT runs the canonical compact-JWS gate first, which reads both segments with the strict profile (strictParse):
// a duplicate member, and a non-canonical number, are refused there, before the duplicate-only parse behind it.
const GATE = 'EAT invalid: non-canonical compact JWS: bad-json (strict JSON: ';

describe('EAT duplicate members', () => {
  it('a duplicate payload member is refused by the canonical gate', () => {
    expect(() => verifyEAT(eat(HEADER, '{"iss":"a","iss":"b","iat":1}'), publicKey)).toThrow(`${GATE}duplicate key "iss"`);
  });
  it('a duplicate header member is refused by the canonical gate', () => {
    expect(() => verifyEAT(eat(`{"alg":"EdDSA","alg":"none","typ":"${EAT_TYP}"}`, '{"iss":"a","iat":1}'), publicKey)).toThrow(`${GATE}duplicate key "alg"`);
  });
  it('non-canonical numbers (8.0, 1e3) are refused by the canonical gate too', () => {
    expect(() => verifyEAT(eat(HEADER, '{"iss":"a","iat":8.0}'), publicKey)).toThrow(GATE);
    expect(() => verifyEAT(eat(HEADER, '{"iss":"a","iat":1e3}'), publicKey)).toThrow(GATE);
  });
  it('the same claims written canonically verify', () => {
    expect(verifyEAT(eat(HEADER, '{"iss":"a","iat":8}'), publicKey)).toMatchObject({ iss: 'a', iat: 8 });
  });
});
