/**
 * Assertions in the shapes real authenticators emit, generated at test time: a synced platform passkey (attestation
 * "none": backup flags, counter 0), a hardware key with "packed" attestation (UP+UV, counter, extension data), a
 * "fido-u2f" key (UP only, ES256 DER) and an Ed25519 credential. Each is judged against an exact whole-result.
 * The same shapes are judged by an established library in crosscheck/live-crosscheck.mjs (a CI job).
 */
import { ed25519 } from '@noble/curves/ed25519';
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { b64u } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import { type Assertion, type CredentialPublicKey, verifyAssertion } from './index';

const RP = 'login.example.com';
const ORIGIN = 'https://login.example.com';
const CHALLENGE = Uint8Array.from({ length: 32 }, (_, i) => (i * 11 + 3) & 0xff);
const enc = (o: unknown) => new TextEncoder().encode(typeof o === 'string' ? o : JSON.stringify(o));
const FLAGS = (up: boolean, uv: boolean, be: boolean, bs: boolean, at: boolean, ed: boolean) => ({ up, uv, be, bs, at, ed });

function authData(flags: number, signCount: number, tail: Uint8Array = new Uint8Array(0)): Uint8Array {
  const out = new Uint8Array(37 + tail.length);
  out.set(sha256(enc(RP)), 0);
  out[32] = flags;
  new DataView(out.buffer).setUint32(33, signCount, false);
  out.set(tail, 37);
  return out;
}
const clientData = () => enc({ type: 'webauthn.get', challenge: b64u(CHALLENGE), origin: ORIGIN, crossOrigin: false });
const expectations = (over: Record<string, unknown> = {}) =>
  ({ expectedChallenge: CHALLENGE, rpId: RP, origins: [ORIGIN], requireUV: true, storedSignCount: 0, ...over }) as Parameters<typeof verifyAssertion>[1];

const esSk = p256.utils.randomPrivateKey();
const esPub = p256.getPublicKey(esSk, false);
const esKey: CredentialPublicKey = { kty: 'EC', crv: 'P-256', x: b64u(esPub.slice(1, 33)), y: b64u(esPub.slice(33)) };
const edSk = ed25519.utils.randomPrivateKey();
const edKey: CredentialPublicKey = { kty: 'OKP', crv: 'Ed25519', x: b64u(ed25519.getPublicKey(edSk)) };

function es256(ad: Uint8Array, form: 'der' | 'compact' = 'der'): Assertion {
  const cd = clientData();
  const sig = p256.sign(sha256(new Uint8Array([...ad, ...sha256(cd)])), esSk);
  return { authenticatorData: ad, clientDataJSON: cd, signature: form === 'der' ? sig.toDERRawBytes() : sig.toCompactRawBytes(), publicKey: esKey };
}
function eddsa(ad: Uint8Array): Assertion {
  const cd = clientData();
  return { authenticatorData: ad, clientDataJSON: cd, signature: ed25519.sign(new Uint8Array([...ad, ...sha256(cd)]), edSk), publicKey: edKey };
}

describe('assertions in real-authenticator shapes', () => {
  it('synced platform passkey (attestation none): UP+UV+BE+BS, counter 0 against stored 0', () => {
    expect(verifyAssertion(es256(authData(0x1d, 0)), expectations())).toEqual({ ok: true, alg: 'ES256', signCount: 0, flags: FLAGS(true, true, true, true, false, false) });
  });
  it('hardware key (attestation packed): UP+UV, incrementing counter, extension data after the header', () => {
    // CBOR {"credProps": {"rk": true}} as the authenticator appends it when the ED flag is set.
    const ext = Uint8Array.from([0xa1, 0x69, ...enc('credProps'), 0xa1, 0x62, ...enc('rk'), 0xf5]);
    const ad = authData(0x85, 42, ext);
    expect(verifyAssertion(es256(ad), expectations({ storedSignCount: 41 }))).toEqual({ ok: true, alg: 'ES256', signCount: 42, flags: FLAGS(true, true, false, false, false, true) });
  });
  it('U2F key (attestation fido-u2f): user presence only, so UV-required is refused and UV-optional passes', () => {
    const a = es256(authData(0x01, 7));
    expect(verifyAssertion(a, expectations({ storedSignCount: 6 }))).toEqual({ ok: false, reason: 'User Verified (UV) flag is required but not set' });
    expect(verifyAssertion(a, expectations({ storedSignCount: 6, requireUV: false }))).toEqual({ ok: true, alg: 'ES256', signCount: 7, flags: FLAGS(true, false, false, false, false, false) });
  });
  it('Ed25519 credential: UP+UV', () => {
    expect(verifyAssertion(eddsa(authData(0x05, 3)), expectations({ storedSignCount: 2 }))).toEqual({ ok: true, alg: 'EdDSA', signCount: 3, flags: FLAGS(true, true, false, false, false, false) });
  });
  it('raw r||s ES256 signatures (some stacks re-encode) are accepted like DER', () => {
    expect(verifyAssertion(es256(authData(0x05, 1), 'compact'), expectations())).toEqual({ ok: true, alg: 'ES256', signCount: 1, flags: FLAGS(true, true, false, false, false, false) });
  });
  it('attested-credential data after the header (AT set) is carried inside the signed bytes and not decoded', () => {
    const ad = authData(0x45, 1, new Uint8Array(40).fill(9));
    expect(verifyAssertion(es256(ad), expectations())).toEqual({ ok: true, alg: 'ES256', signCount: 1, flags: FLAGS(true, true, false, false, true, false) });
    const tampered = es256(ad);
    const bad = tampered.authenticatorData.slice();
    bad[40] = 0;
    expect(verifyAssertion({ ...tampered, authenticatorData: bad }, expectations())).toEqual({ ok: false, reason: 'assertion signature did not verify' });
  });
  it('a credential key of an unsupported type (RSA, COSE kty 3) is refused with a named reason', () => {
    const a = es256(authData(0x05, 1));
    expect(verifyAssertion({ ...a, publicKey: Uint8Array.from([0xa1, 0x01, 0x03]) }, expectations())).toEqual({
      ok: false,
      reason: 'public key could not be resolved: coseKeyToJwk: unsupported COSE key type (kty=3)',
    });
  });
  it('an assertion signed by a different credential is refused', () => {
    const other = p256.getPublicKey(p256.utils.randomPrivateKey(), false);
    const a = es256(authData(0x05, 1));
    expect(verifyAssertion({ ...a, publicKey: { kty: 'EC', crv: 'P-256', x: b64u(other.slice(1, 33)), y: b64u(other.slice(33)) } }, expectations())).toEqual({
      ok: false,
      reason: 'assertion signature did not verify',
    });
  });
});
