import { describe, it, expect } from 'vitest';
import { p256 } from '@noble/curves/p256';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { type PCActnBody, b64u, frostActionDigest, thresholdMessage } from '@atlasauth/pca';
import {
  type Assertion,
  type VerifyExpectations,
  buildStepUpChallenge,
  coseKeyToJwk,
  parseAuthenticatorData,
  stepUpChallengeB64u,
  verifyAssertion,
} from './index';

// ------------------------------------------------------------------------------------------------
// Minimal CBOR encoder for COSE_Key (test-only; the library has its own reader).
// ------------------------------------------------------------------------------------------------

function cborUint(n: number): number[] {
  if (n < 24) return [n];
  if (n < 256) return [0x18, n];
  throw new Error('test cbor: uint too large');
}
function cborNint(n: number): number[] {
  const arg = -1 - n;
  if (arg < 24) return [(1 << 5) | arg];
  if (arg < 256) return [(1 << 5) | 24, arg];
  throw new Error('test cbor: nint too large');
}
function cborBstr(b: Uint8Array): number[] {
  const len = b.length;
  if (len < 24) return [(2 << 5) | len, ...b];
  if (len < 256) return [(2 << 5) | 24, len, ...b];
  throw new Error('test cbor: bstr too large');
}
function cborMapHeader(count: number): number[] {
  if (count < 24) return [(5 << 5) | count];
  throw new Error('test cbor: map too large');
}

function coseEc2(x: Uint8Array, y: Uint8Array): Uint8Array {
  return Uint8Array.from([
    ...cborMapHeader(5),
    ...cborUint(1),
    ...cborUint(2), // kty: EC2
    ...cborUint(3),
    ...cborNint(-7), // alg: ES256
    ...cborNint(-1),
    ...cborUint(1), // crv: P-256
    ...cborNint(-2),
    ...cborBstr(x), // x
    ...cborNint(-3),
    ...cborBstr(y), // y
  ]);
}
function coseOkp(pub: Uint8Array): Uint8Array {
  return Uint8Array.from([
    ...cborMapHeader(4),
    ...cborUint(1),
    ...cborUint(1), // kty: OKP
    ...cborUint(3),
    ...cborNint(-8), // alg: EdDSA
    ...cborNint(-1),
    ...cborUint(6), // crv: Ed25519
    ...cborNint(-2),
    ...cborBstr(pub), // x (public key)
  ]);
}

// ------------------------------------------------------------------------------------------------
// Assertion-crafting helpers.
// ------------------------------------------------------------------------------------------------

const RP_ID = 'login.example.com';
const ORIGIN = 'https://login.example.com';
const UP = 0x01;
const UV = 0x04;

function authDataFor(rpId: string, flags: number, signCount: number): Uint8Array {
  const out = new Uint8Array(37);
  out.set(sha256(new TextEncoder().encode(rpId)), 0);
  out[32] = flags;
  new DataView(out.buffer, out.byteOffset, out.byteLength).setUint32(33, signCount, false);
  return out;
}

function clientDataFor(challengeB64u: string, origin: string, type = 'webauthn.get'): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({ type, challenge: challengeB64u, origin, crossOrigin: false }));
}

/** A representative high-risk PCActn body to step up on. */
function sampleBody(): PCActnBody {
  return {
    ver: 2,
    action: { verb: 'payments.transfer', resource: 'acct_7781', params_digest: 'AA', reversibility_class: 'irreversible' },
    grant_ref: 'grant_abc',
    cap_chain: [],
    plan: { root: 'root0', inclusion_proof: { index: 0, size: 1, path: [] }, node_id: 'node0' },
    attestation: { quote_digest: '', epoch: 0, model_id: '', measurement: '', operator: '' },
    provenance: { causal_hash: '', taint_level: 0, trusted_refs: [] },
    freshness: { beacon_ref: '', epoch: 0, accumulator_witness: '' },
    counter: 1,
    risk_claim: { r: 0.92, inputs: {} },
    aud: 'ins_live_123',
    iat: 1_700_000_000_000,
    exp: 1_700_000_600_000,
  };
}

interface Es256Material {
  publicKeyJwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string };
  cose: Uint8Array;
  sign: (signedData: Uint8Array, format: 'der' | 'compact') => Uint8Array;
}

function es256Key(): Es256Material {
  const sk = p256.utils.randomPrivateKey();
  const pub = p256.getPublicKey(sk, false); // 0x04 ‖ X ‖ Y
  const x = pub.slice(1, 33);
  const y = pub.slice(33, 65);
  return {
    publicKeyJwk: { kty: 'EC', crv: 'P-256', x: b64u(x), y: b64u(y) },
    cose: coseEc2(x, y),
    sign: (signedData, format) => {
      const sig = p256.sign(sha256(signedData), sk);
      return format === 'der' ? sig.toDERRawBytes() : sig.toCompactRawBytes();
    },
  };
}

interface EdDsaMaterial {
  cose: Uint8Array;
  publicKeyJwk: { kty: 'OKP'; crv: 'Ed25519'; x: string };
  sign: (signedData: Uint8Array) => Uint8Array;
}

function ed25519Key(): EdDsaMaterial {
  const sk = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(sk);
  return {
    cose: coseOkp(pub),
    publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: b64u(pub) },
    sign: (signedData) => ed25519.sign(signedData, sk),
  };
}

function expectations(overrides: Partial<VerifyExpectations> = {}): VerifyExpectations {
  return { expectedChallenge: new Uint8Array(32), rpId: RP_ID, origins: [ORIGIN], requireUV: true, ...overrides };
}

// ------------------------------------------------------------------------------------------------
// Tests.
// ------------------------------------------------------------------------------------------------

describe('buildStepUpChallenge — binds the passkey to the FROST action digest', () => {
  it('equals sha256(thresholdMessage) and its b64u is the frost action_digest', () => {
    const body = sampleBody();
    const challenge = buildStepUpChallenge(body);
    expect(challenge).toHaveLength(32);
    expect(challenge).toEqual(sha256(thresholdMessage(body)));
    expect(b64u(challenge)).toBe(frostActionDigest(thresholdMessage(body)));
    expect(stepUpChallengeB64u(body)).toBe(frostActionDigest(thresholdMessage(body)));
  });

  it('accepts the base64url digest and raw 32-byte digest forms (round-trip)', () => {
    const body = sampleBody();
    const digestB64u = stepUpChallengeB64u(body);
    expect(buildStepUpChallenge(digestB64u)).toEqual(buildStepUpChallenge(body));
    expect(buildStepUpChallenge(buildStepUpChallenge(body))).toEqual(buildStepUpChallenge(body));
  });

  it('throws on a non-32-byte / non-canonical digest', () => {
    expect(() => buildStepUpChallenge(new Uint8Array(31))).toThrow();
    expect(() => buildStepUpChallenge('not valid base64url!!')).toThrow();
  });
});

describe('coseKeyToJwk — round-trips EC2/P-256 and OKP/Ed25519', () => {
  it('EC2 P-256', () => {
    const k = es256Key();
    const jwk = coseKeyToJwk(k.cose);
    expect(jwk).toEqual({ kty: 'EC', crv: 'P-256', x: k.publicKeyJwk.x, y: k.publicKeyJwk.y, alg: 'ES256' });
  });

  it('OKP Ed25519', () => {
    const k = ed25519Key();
    const jwk = coseKeyToJwk(k.cose);
    expect(jwk).toEqual({ kty: 'OKP', crv: 'Ed25519', x: k.publicKeyJwk.x, alg: 'EdDSA' });
  });

  it('rejects an unsupported / malformed COSE key', () => {
    expect(() => coseKeyToJwk(new Uint8Array([0xa0]))).toThrow(); // empty map, no kty
    expect(() => coseKeyToJwk(new Uint8Array([0x58, 0x05]))).toThrow(); // truncated bstr
  });
});

describe('parseAuthenticatorData', () => {
  it('parses the header and flags', () => {
    const parsed = parseAuthenticatorData(authDataFor(RP_ID, UP | UV, 42));
    expect(parsed).not.toBeNull();
    expect(parsed?.signCount).toBe(42);
    expect(parsed?.flags.up).toBe(true);
    expect(parsed?.flags.uv).toBe(true);
  });

  it('returns null when too short', () => {
    expect(parseAuthenticatorData(new Uint8Array(36))).toBeNull();
  });
});

describe('verifyAssertion — valid assertions', () => {
  it('accepts a valid ES256 (DER sig) assertion with a JWK key', () => {
    const body = sampleBody();
    const challenge = buildStepUpChallenge(body);
    const k = es256Key();
    const authData = authDataFor(RP_ID, UP | UV, 1);
    const clientDataJSON = clientDataFor(b64u(challenge), ORIGIN);
    const signedData = new Uint8Array([...authData, ...sha256(clientDataJSON)]);
    const assertion: Assertion = {
      authenticatorData: authData,
      clientDataJSON,
      signature: k.sign(signedData, 'der'),
      publicKey: k.publicKeyJwk,
    };
    const res = verifyAssertion(assertion, expectations({ expectedChallenge: challenge }));
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.alg).toBe('ES256');
      expect(res.signCount).toBe(1);
      expect(res.flags.uv).toBe(true);
    }
  });

  it('accepts a valid ES256 (compact sig) assertion and a base64url expectedChallenge', () => {
    const challenge = buildStepUpChallenge(sampleBody());
    const k = es256Key();
    const authData = authDataFor(RP_ID, UP | UV, 7);
    const clientDataJSON = clientDataFor(b64u(challenge), ORIGIN);
    const signedData = new Uint8Array([...authData, ...sha256(clientDataJSON)]);
    const res = verifyAssertion(
      { authenticatorData: authData, clientDataJSON, signature: k.sign(signedData, 'compact'), publicKey: k.publicKeyJwk },
      expectations({ expectedChallenge: b64u(challenge) }),
    );
    expect(res.ok).toBe(true);
  });

  it('accepts a valid Ed25519 assertion with a RAW COSE_Key', () => {
    const challenge = buildStepUpChallenge(sampleBody());
    const k = ed25519Key();
    const authData = authDataFor(RP_ID, UP | UV, 99);
    const clientDataJSON = clientDataFor(b64u(challenge), ORIGIN);
    const signedData = new Uint8Array([...authData, ...sha256(clientDataJSON)]);
    const res = verifyAssertion(
      { authenticatorData: authData, clientDataJSON, signature: k.sign(signedData), publicKey: k.cose },
      expectations({ expectedChallenge: challenge }),
    );
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.alg).toBe('EdDSA');
  });

  it('accepts UP-only when requireUV is false', () => {
    const challenge = buildStepUpChallenge(sampleBody());
    const k = es256Key();
    const authData = authDataFor(RP_ID, UP, 1);
    const clientDataJSON = clientDataFor(b64u(challenge), ORIGIN);
    const signedData = new Uint8Array([...authData, ...sha256(clientDataJSON)]);
    const res = verifyAssertion(
      { authenticatorData: authData, clientDataJSON, signature: k.sign(signedData, 'der'), publicKey: k.publicKeyJwk },
      expectations({ expectedChallenge: challenge, requireUV: false }),
    );
    expect(res.ok).toBe(true);
  });
});

describe('verifyAssertion — tampering fails closed', () => {
  // A fresh valid assertion each test, which we then mutate.
  function freshValid(): { assertion: Assertion; expect: VerifyExpectations; challenge: Uint8Array; k: Es256Material } {
    const challenge = buildStepUpChallenge(sampleBody());
    const k = es256Key();
    const authData = authDataFor(RP_ID, UP | UV, 1);
    const clientDataJSON = clientDataFor(b64u(challenge), ORIGIN);
    const signedData = new Uint8Array([...authData, ...sha256(clientDataJSON)]);
    return {
      assertion: { authenticatorData: authData, clientDataJSON, signature: k.sign(signedData, 'der'), publicKey: k.publicKeyJwk },
      expect: expectations({ expectedChallenge: challenge }),
      challenge,
      k,
    };
  }

  it('wrong challenge', () => {
    const { assertion, expect: exp } = freshValid();
    const other = new Uint8Array(32).fill(9);
    const res = verifyAssertion(assertion, { ...exp, expectedChallenge: other });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/challenge/i);
  });

  it('origin not in the allowlist', () => {
    const { assertion, expect: exp } = freshValid();
    const res = verifyAssertion(assertion, { ...exp, origins: ['https://evil.example'] });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/origin/i);
  });

  it('bad rpIdHash (rpId mismatch)', () => {
    const { assertion, expect: exp } = freshValid();
    const res = verifyAssertion(assertion, { ...exp, rpId: 'other.example.com' });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/rpIdHash/i);
  });

  it('User Present (UP) unset', () => {
    const challenge = buildStepUpChallenge(sampleBody());
    const k = es256Key();
    const authData = authDataFor(RP_ID, UV, 1); // UV set, UP clear
    const clientDataJSON = clientDataFor(b64u(challenge), ORIGIN);
    const signedData = new Uint8Array([...authData, ...sha256(clientDataJSON)]);
    const res = verifyAssertion(
      { authenticatorData: authData, clientDataJSON, signature: k.sign(signedData, 'der'), publicKey: k.publicKeyJwk },
      expectations({ expectedChallenge: challenge, requireUV: false }),
    );
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/UP/);
  });

  it('User Verified (UV) required but unset', () => {
    const challenge = buildStepUpChallenge(sampleBody());
    const k = es256Key();
    const authData = authDataFor(RP_ID, UP, 1); // UP only
    const clientDataJSON = clientDataFor(b64u(challenge), ORIGIN);
    const signedData = new Uint8Array([...authData, ...sha256(clientDataJSON)]);
    const res = verifyAssertion(
      { authenticatorData: authData, clientDataJSON, signature: k.sign(signedData, 'der'), publicKey: k.publicKeyJwk },
      expectations({ expectedChallenge: challenge, requireUV: true }),
    );
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/UV/);
  });

  it('bad signature', () => {
    const { assertion, expect: exp } = freshValid();
    const sig = assertion.signature.slice();
    const last = sig.length - 1;
    const prev = sig[last] ?? 0;
    sig[last] = prev ^ 0xff;
    const res = verifyAssertion({ ...assertion, signature: sig }, exp);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/signature/i);
  });

  it('truncated authenticatorData', () => {
    const { assertion, expect: exp } = freshValid();
    const res = verifyAssertion({ ...assertion, authenticatorData: assertion.authenticatorData.slice(0, 36) }, exp);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/too short/i);
  });

  it('wrong clientData.type', () => {
    const challenge = buildStepUpChallenge(sampleBody());
    const k = es256Key();
    const authData = authDataFor(RP_ID, UP | UV, 1);
    const clientDataJSON = clientDataFor(b64u(challenge), ORIGIN, 'webauthn.create');
    const signedData = new Uint8Array([...authData, ...sha256(clientDataJSON)]);
    const res = verifyAssertion(
      { authenticatorData: authData, clientDataJSON, signature: k.sign(signedData, 'der'), publicKey: k.publicKeyJwk },
      expectations({ expectedChallenge: challenge }),
    );
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/webauthn\.get/);
  });

  it('never throws on hostile/empty input (fails closed)', () => {
    const res = verifyAssertion(
      { authenticatorData: new Uint8Array(0), clientDataJSON: new Uint8Array(0), signature: new Uint8Array(0), publicKey: new Uint8Array(0) },
      expectations(),
    );
    expect(res.ok).toBe(false);
  });
});
