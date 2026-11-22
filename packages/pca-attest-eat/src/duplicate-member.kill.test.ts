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

describe('EAT duplicate members', () => {
  it('a duplicate payload member is refused with the exact message', () => {
    expect(() => verifyEAT(eat(HEADER, '{"iss":"a","iss":"b","iat":1}'), publicKey)).toThrow('EAT invalid: payload is not valid JSON');
  });
  it('a duplicate header member is refused with the exact message', () => {
    expect(() => verifyEAT(eat(`{"alg":"EdDSA","alg":"none","typ":"${EAT_TYP}"}`, '{"iss":"a","iat":1}'), publicKey)).toThrow('EAT invalid: header is not valid JSON');
  });
  it('non-canonical numbers (8.0, 1e3) are accepted', () => {
    expect(verifyEAT(eat(HEADER, '{"iss":"a","iat":8.0,"lat":1e3}'), publicKey)).toMatchObject({ iss: 'a', iat: 8 });
  });
});
