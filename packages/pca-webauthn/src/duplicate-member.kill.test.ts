import { describe, expect, it } from 'vitest';
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { b64u } from '@atlasauth/pca';
import { type Assertion, type VerifyExpectations, verifyAssertion } from './index';

const RP_ID = 'login.example.com';
const ORIGIN = 'https://login.example.com';
const enc = new TextEncoder();
const CHALLENGE = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const sk = p256.utils.randomPrivateKey(); // generated per run
const pub = p256.getPublicKey(sk, false);
const jwk = { kty: 'EC' as const, crv: 'P-256' as const, x: b64u(pub.slice(1, 33)), y: b64u(pub.slice(33, 65)) };
const ad = (() => {
  const out = new Uint8Array(37);
  out.set(sha256(enc.encode(RP_ID)), 0);
  out[32] = 0x05;
  new DataView(out.buffer).setUint32(33, 1, false);
  return out;
})();
const expectations: VerifyExpectations = { expectedChallenge: CHALLENGE, rpId: RP_ID, origins: [ORIGIN], requireUV: true, storedSignCount: 0 };

// Build clientDataJSON from raw text so a duplicate member survives; sign it correctly so only the parse decides.
const assertion = (clientText: string): Assertion => {
  const cd = enc.encode(clientText);
  const msg = new Uint8Array([...ad, ...sha256(cd)]);
  return { authenticatorData: ad, clientDataJSON: cd, signature: p256.sign(sha256(msg), sk).toDERRawBytes(), publicKey: jwk };
};
const base = `"type":"webauthn.get","challenge":"${b64u(CHALLENGE)}","origin":"${ORIGIN}","crossOrigin":false`;

describe('WebAuthn clientDataJSON duplicate members', () => {
  it('a duplicate member is refused with the exact reason', () => {
    expect(verifyAssertion(assertion(`{${base},"origin":"https://evil.example"}`), expectations)).toEqual({ ok: false, reason: 'clientDataJSON is not valid JSON' });
  });
  it('non-canonical numbers (8.0, 1e3) are accepted', () => {
    expect(verifyAssertion(assertion(`{${base},"x":8.0,"y":1e3}`), expectations).ok).toBe(true);
  });
});
