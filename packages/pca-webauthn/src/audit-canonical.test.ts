/**
 * Canonical-encoding audit. The verified assertion signature is NOT retained, hashed or used as an identifier
 * by this package (VerifyResult carries only alg/signCount/flags), so ECDSA high-S is accepted on purpose
 * (WebAuthn does not require low-S). Anything that would let a *different byte string for the same
 * signature* through a strict parser must still fail: non-minimal DER, trailing garbage, Ed25519 S + L.
 */
import { describe, expect, it } from 'vitest';
import { p256 } from '@noble/curves/p256';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { b64u } from '@atlasauth/pca';
import { type Assertion, type VerifyExpectations, verifyAssertion as verifyAssertionRaw } from './index';

// 0.5: storedSignCount is required (0 = never used). These suites exercise other checks, so they default it to 0 here.
const verifyAssertion = (a: Assertion, e: Omit<VerifyExpectations, 'storedSignCount'> & { storedSignCount?: number }) =>
  verifyAssertionRaw(a, { storedSignCount: 0, ...e } as VerifyExpectations);

const RP = 'example.com';
const ORIGIN = 'https://example.com';

function setup() {
  const challenge = new Uint8Array(32).fill(3);
  const authData = new Uint8Array(37);
  authData.set(sha256(new TextEncoder().encode(RP)), 0);
  authData[32] = 0x05; // UP | UV
  authData[36] = 1;
  const clientDataJSON = new TextEncoder().encode(JSON.stringify({ type: 'webauthn.get', challenge: b64u(challenge), origin: ORIGIN }));
  const signedData = new Uint8Array([...authData, ...sha256(clientDataJSON)]);
  return { challenge, authData, clientDataJSON, signedData };
}
const exp = (challenge: Uint8Array) => ({ expectedChallenge: challenge, rpId: RP, origins: [ORIGIN], requireUV: true });

describe('webauthn signature encodings', () => {
  it('ES256: non-minimal DER (extra leading zero in r) and trailing bytes are rejected', () => {
    const s = setup();
    const sk = p256.utils.randomPrivateKey();
    const pub = p256.getPublicKey(sk, false);
    const publicKey = { kty: 'EC' as const, crv: 'P-256' as const, x: b64u(pub.slice(1, 33)), y: b64u(pub.slice(33, 65)) };
    const sig = p256.sign(sha256(s.signedData), sk);
    const der = sig.toDERRawBytes();
    const run = (signature: Uint8Array) =>
      verifyAssertion({ authenticatorData: s.authData, clientDataJSON: s.clientDataJSON, signature, publicKey }, exp(s.challenge)).ok;
    expect(run(der)).toBe(true);
    // 30 LL 02 rl <r> 02 sl <s>  ->  prepend 0x00 to r only when its top bit is clear (non-minimal)
    const rLen = der[3]!;
    const r = der.slice(4, 4 + rLen);
    const rest = der.slice(4 + rLen);
    const padded = new Uint8Array([0x30, der[1]! + 1, 0x02, rLen + 1, 0x00, ...r, ...rest]);
    if ((r[0]! & 0x80) === 0 && r[0] !== 0) expect(run(padded)).toBe(false);
    expect(run(new Uint8Array([...der, 0x00]))).toBe(false);
    // high-S is a valid ECDSA signature and WebAuthn does not forbid it: accepted by design, never retained.
    expect(run(sig.hasHighS() ? sig.toDERRawBytes() : new p256.Signature(sig.r, p256.CURVE.n - sig.s).toDERRawBytes())).toBe(true);
  });
  it('Ed25519: S + L is rejected', () => {
    const s = setup();
    const sk = ed25519.utils.randomPrivateKey();
    const pk = ed25519.getPublicKey(sk);
    const sig = ed25519.sign(s.signedData, sk);
    let S = 0n;
    for (let i = 63; i >= 32; i--) S = (S << 8n) | BigInt(sig[i]!);
    S += ed25519.CURVE.n;
    const bad = sig.slice();
    for (let i = 32; i < 64; i++) {
      bad[i] = Number(S & 0xffn);
      S >>= 8n;
    }
    const okRes = verifyAssertion({ authenticatorData: s.authData, clientDataJSON: s.clientDataJSON, signature: sig, publicKey: { kty: 'OKP', crv: 'Ed25519', x: b64u(pk) } }, exp(s.challenge));
    const badRes = verifyAssertion({ authenticatorData: s.authData, clientDataJSON: s.clientDataJSON, signature: bad, publicKey: { kty: 'OKP', crv: 'Ed25519', x: b64u(pk) } }, exp(s.challenge));
    expect(okRes.ok).toBe(true);
    expect(badRes.ok).toBe(false);
  });
});
