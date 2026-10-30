/**
 * R6-ALIAS-02: encoding aliases in the step-up verifier.
 *  - EdDSA must be strict RFC 8032 (not ZIP-215): a small-order public key with R = identity, S = 0 verified ANY message.
 *  - clientData.challenge must be canonical base64url (no `=` padding, no `+` `/`, canonical trailing bits).
 *  - ES256 high-S: refused when the caller sets `requireLowS` (off by default: authenticators emit high-S about half
 *    the time and WebAuthn does not require low-S; see audit-canonical.test.ts).
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
const enc = new TextEncoder();
const challenge = sha256(enc.encode('r6-alias step-up'));

function assertionFor(challengeField: string) {
  const authData = new Uint8Array(37);
  authData.set(sha256(enc.encode(RP)), 0);
  authData[32] = 0x05; // UP | UV
  authData[36] = 1;
  const clientDataJSON = enc.encode(JSON.stringify({ type: 'webauthn.get', challenge: challengeField, origin: ORIGIN }));
  const signedData = new Uint8Array([...authData, ...sha256(clientDataJSON)]);
  return { authData, clientDataJSON, signedData };
}
const exp = (extra: Record<string, unknown> = {}) => ({ expectedChallenge: challenge, rpId: RP, origins: [ORIGIN], requireUV: true, ...extra });

describe('R6-ALIAS-02 EdDSA is strict (no ZIP-215)', () => {
  it('identity public key + (R = identity, S = 0) does not verify', () => {
    const a = assertionFor(b64u(challenge));
    const identity = new Uint8Array(32);
    identity[0] = 1;
    const sig = new Uint8Array(64);
    sig.set(identity, 0);
    expect(ed25519.verify(sig, a.signedData, identity)).toBe(true); // control: noble's ZIP-215 default accepts it
    const r = verifyAssertion({ authenticatorData: a.authData, clientDataJSON: a.clientDataJSON, signature: sig, publicKey: { kty: 'OKP', crv: 'Ed25519', x: b64u(identity) } }, exp());
    expect(r.ok).toBe(false);
  });
  it('a torsion-shifted key (A + T8) does not verify for its holder', () => {
    const sk = ed25519.utils.randomPrivateKey();
    const A = ed25519.ExtendedPoint.fromHex(ed25519.getPublicKey(sk));
    const T8 = ed25519.ExtendedPoint.fromHex('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a'); // order-8 point
    const shifted = A.add(T8).toRawBytes();
    const a = assertionFor(b64u(challenge));
    const r = verifyAssertion({ authenticatorData: a.authData, clientDataJSON: a.clientDataJSON, signature: ed25519.sign(a.signedData, sk), publicKey: { kty: 'OKP', crv: 'Ed25519', x: b64u(shifted) } }, exp());
    expect(r.ok).toBe(false);
  });
  it('an honest Ed25519 assertion still verifies', () => {
    const sk = ed25519.utils.randomPrivateKey();
    const a = assertionFor(b64u(challenge));
    const r = verifyAssertion({ authenticatorData: a.authData, clientDataJSON: a.clientDataJSON, signature: ed25519.sign(a.signedData, sk), publicKey: { kty: 'OKP', crv: 'Ed25519', x: b64u(ed25519.getPublicKey(sk)) } }, exp());
    expect(r.ok).toBe(true);
  });
});

describe('R6-ALIAS-02 challenge is canonical base64url', () => {
  const sk = p256.utils.randomPrivateKey();
  const pub = p256.getPublicKey(sk, false);
  const publicKey = { kty: 'EC' as const, crv: 'P-256' as const, x: b64u(pub.slice(1, 33)), y: b64u(pub.slice(33, 65)) };
  const run = (field: string) => {
    const a = assertionFor(field);
    const signature = p256.sign(sha256(a.signedData), sk).toDERRawBytes();
    return verifyAssertion({ authenticatorData: a.authData, clientDataJSON: a.clientDataJSON, signature, publicKey }, exp());
  };
  const canonical = b64u(challenge);
  it('the canonical form verifies', () => expect(run(canonical).ok).toBe(true));
  it('"=" padding is refused', () => expect(run(canonical + '=').ok).toBe(false));
  it('the standard alphabet (+ /) is refused', () => {
    const std = canonical.replace(/-/g, '+').replace(/_/g, '/');
    // make sure the vector actually differs; flip to a challenge that has - or _ if needed
    expect(std === canonical ? run(canonical.slice(0, -1) + '+').ok : run(std).ok).toBe(false);
  });
  it('non-canonical trailing bits are refused', () => {
    const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const last = alpha.indexOf(canonical[42]!);
    const alias = canonical.slice(0, 42) + alpha[last ^ 1]; // 32 bytes -> 43 chars, the last char carries 2 unused bits
    expect(alias).not.toBe(canonical);
    expect(run(alias).ok).toBe(false);
  });
  it('a string expectedChallenge must be canonical too', () => {
    const a = assertionFor(canonical);
    const signature = p256.sign(sha256(a.signedData), sk).toDERRawBytes();
    const r = verifyAssertion({ authenticatorData: a.authData, clientDataJSON: a.clientDataJSON, signature, publicKey }, { ...exp(), expectedChallenge: canonical + '=' });
    expect(r.ok).toBe(false);
  });
});

describe('R6-ALIAS-02 ES256 low-S', () => {
  const sk = p256.utils.randomPrivateKey();
  const pub = p256.getPublicKey(sk, false);
  const publicKey = { kty: 'EC' as const, crv: 'P-256' as const, x: b64u(pub.slice(1, 33)), y: b64u(pub.slice(33, 65)) };
  const a = assertionFor(b64u(challenge));
  const sig = p256.sign(sha256(a.signedData), sk); // noble's p256 does NOT normalise s; do it here
  const n = p256.CURVE.n;
  const lowS = sig.s > n / 2n ? n - sig.s : sig.s;
  const compact = (r: bigint, s: bigint) => {
    const o = new Uint8Array(64);
    o.set(p256.CURVE.Fp.toBytes(r), 0);
    o.set(p256.CURVE.Fp.toBytes(s), 32);
    return o;
  };
  const high = compact(sig.r, n - lowS);
  const run = (signature: Uint8Array, extra = {}) => verifyAssertion({ authenticatorData: a.authData, clientDataJSON: a.clientDataJSON, signature, publicKey }, exp(extra)).ok;
  it('requireLowS refuses (r, n-s) and still accepts (r, s)', () => {
    expect(run(compact(sig.r, lowS), { requireLowS: true })).toBe(true);
    expect(run(high, { requireLowS: true })).toBe(false);
  });
  it('default stays interoperable with authenticators that emit high-S', () => {
    expect(run(high)).toBe(true);
  });
});
