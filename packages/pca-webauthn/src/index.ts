/**
 * @atlasauth/pca-webauthn — phishing-resistant HUMAN co-sign for PCA FROST step-up via WebAuthn/FIDO2.
 *
 * The idea: a WebAuthn passkey assertion (the result of `navigator.credentials.get`) IS the human
 * approval proof. The WebAuthn challenge the authenticator signs is set EQUAL to the PCA step-up
 * challenge — i.e. the FROST action digest, `sha256(thresholdMessage(pcactn))`, whose base64url form is
 * exactly the `action_digest` a `frost-net` allow token binds to (see `frostActionDigest`). So a valid
 * assertion is cryptographic proof that a human, holding a hardware-bound credential, approved THIS
 * action and no other: the signature covers `authenticatorData ‖ sha256(clientDataJSON)`, and the
 * clientDataJSON embeds the action digest as its challenge. An attacker who phishes the human onto a
 * look-alike origin fails the origin + rpIdHash binding; one who replays an old assertion fails the
 * challenge binding (it names a different action digest).
 *
 * This module is the SERVER-SIDE verify. It is self-contained: ES256 (P-256) and EdDSA (Ed25519) via
 * `@noble/curves`, SHA-256 via `@noble/hashes`, and a hand-rolled minimal COSE_Key/CBOR reader (no CBOR
 * dependency). Every public entry point fails CLOSED and never throws on hostile input.
 */

import { p256 } from '@noble/curves/p256';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import {
  type PCActn,
  type PCActnBody,
  b64u,
  unb64u,
  decodeB64uStrict,
  frostActionDigest,
  thresholdMessage,
} from '@atlasauth/pca';

// ================================================================================================
// Byte helpers (fail-closed; no non-null assertions, `noUncheckedIndexedAccess`-safe).
// ================================================================================================

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true });

/** Concatenate byte arrays into a fresh buffer. */
function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** Constant-time byte equality (length first, then XOR-accumulate). */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    const x = a[i];
    const y = b[i];
    if (x === undefined || y === undefined) return false;
    diff |= x ^ y;
  }
  return diff === 0;
}

/**
 * Tolerant base64url -> bytes: accepts the URL alphabet with or without `=` padding (WebAuthn
 * clientDataJSON uses base64url WITHOUT padding). Returns null for anything that is not decodable,
 * never throws.
 */
function base64urlToBytes(s: unknown): Uint8Array | null {
  if (typeof s !== 'string') return null;
  const trimmed = s.replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  if (!/^[A-Za-z0-9_-]*$/.test(trimmed)) return null;
  try {
    return unb64u(trimmed);
  } catch {
    return null;
  }
}

/** A plain object, or null — a narrowing helper so parsed JSON stays `unknown` until checked. */
function asRecord(v: unknown): Record<string, unknown> | null {
  return typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

// ================================================================================================
// Minimal COSE_Key / CBOR reader (no dependency).
//
// COSE_Key is a flat CBOR map with INTEGER labels. We support exactly the CBOR needed to read one:
// unsigned ints (major 0), negative ints (major 1), byte strings (major 2) and maps (major 5), with
// 1/2/4-byte arguments. Indefinite-length (ai 31) and 8-byte arguments (ai 27) are rejected. Any
// deviation throws; callers that must not throw (verifyAssertion) wrap this.
// ================================================================================================

type CborValue = number | Uint8Array | Map<number, CborValue>;

interface CborItem {
  value: CborValue;
  next: number;
}

function readCborItem(dv: DataView, offset: number): CborItem {
  const initial = dv.getUint8(offset); // RangeError if past the end -> caught by caller
  const major = initial >> 5;
  const ai = initial & 0x1f;
  let p = offset + 1;
  let arg: number;
  if (ai < 24) {
    arg = ai;
  } else if (ai === 24) {
    arg = dv.getUint8(p);
    p += 1;
  } else if (ai === 25) {
    arg = dv.getUint16(p, false);
    p += 2;
  } else if (ai === 26) {
    arg = dv.getUint32(p, false);
    p += 4;
  } else {
    throw new Error('cose: unsupported CBOR argument encoding (8-byte or indefinite length)');
  }

  switch (major) {
    case 0:
      return { value: arg, next: p };
    case 1:
      return { value: -1 - arg, next: p };
    case 2: {
      const end = p + arg;
      if (end > dv.byteLength) throw new Error('cose: byte string length out of range');
      const out = new Uint8Array(arg);
      for (let i = 0; i < arg; i++) out[i] = dv.getUint8(p + i);
      return { value: out, next: end };
    }
    case 5: {
      const map = new Map<number, CborValue>();
      let q = p;
      for (let i = 0; i < arg; i++) {
        const key = readCborItem(dv, q);
        if (typeof key.value !== 'number') throw new Error('cose: non-integer map key');
        const val = readCborItem(dv, key.next);
        map.set(key.value, val.value);
        q = val.next;
      }
      return { value: map, next: q };
    }
    default:
      throw new Error(`cose: unsupported CBOR major type ${major}`);
  }
}

// ================================================================================================
// Public key shapes.
// ================================================================================================

/** EC2 P-256 (ES256) public key as a JWK. */
export interface Es256Jwk {
  kty: 'EC';
  crv: 'P-256';
  /** base64url(32-byte X coordinate). */
  x: string;
  /** base64url(32-byte Y coordinate). */
  y: string;
  alg?: 'ES256';
}

/** OKP Ed25519 (EdDSA) public key as a JWK. */
export interface EdDsaJwk {
  kty: 'OKP';
  crv: 'Ed25519';
  /** base64url(32-byte public key). */
  x: string;
  alg?: 'EdDSA';
}

/** A credential public key accepted by {@link verifyAssertion}: a JWK or a raw COSE_Key byte string. */
export type CredentialPublicKey = Es256Jwk | EdDsaJwk | Uint8Array;

// COSE_Key integer labels (RFC 9052 / RFC 9053).
const COSE_KTY = 1;
const COSE_CRV = -1;
const COSE_X = -2;
const COSE_Y = -3;
const COSE_KTY_OKP = 1;
const COSE_KTY_EC2 = 2;
const COSE_CRV_P256 = 1;
const COSE_CRV_ED25519 = 6;

/**
 * Decode a raw COSE_Key (as stored in `attestedCredentialData.credentialPublicKey`) into a JWK.
 * Supports the two passkey signature algorithms PCA uses: ES256 (EC2/P-256) and EdDSA (OKP/Ed25519).
 * Throws on malformed input or an unsupported key type.
 */
export function coseKeyToJwk(bytes: Uint8Array): Es256Jwk | EdDsaJwk {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('coseKeyToJwk: expected a Uint8Array');
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const { value } = readCborItem(dv, 0);
  if (!(value instanceof Map)) throw new Error('coseKeyToJwk: COSE_Key is not a CBOR map');

  const kty = value.get(COSE_KTY);
  if (kty === COSE_KTY_EC2) {
    const crv = value.get(COSE_CRV);
    const x = value.get(COSE_X);
    const y = value.get(COSE_Y);
    if (crv !== COSE_CRV_P256) throw new Error('coseKeyToJwk: EC2 key is not P-256 (crv != 1)');
    if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array)) {
      throw new Error('coseKeyToJwk: EC2 key missing an x/y coordinate');
    }
    if (x.length !== 32 || y.length !== 32) throw new Error('coseKeyToJwk: EC2 coordinate is not 32 bytes');
    return { kty: 'EC', crv: 'P-256', x: b64u(x), y: b64u(y), alg: 'ES256' };
  }
  if (kty === COSE_KTY_OKP) {
    const crv = value.get(COSE_CRV);
    const x = value.get(COSE_X);
    if (crv !== COSE_CRV_ED25519) throw new Error('coseKeyToJwk: OKP key is not Ed25519 (crv != 6)');
    if (!(x instanceof Uint8Array)) throw new Error('coseKeyToJwk: OKP key missing its public key');
    if (x.length !== 32) throw new Error('coseKeyToJwk: Ed25519 public key is not 32 bytes');
    return { kty: 'OKP', crv: 'Ed25519', x: b64u(x), alg: 'EdDSA' };
  }
  throw new Error(`coseKeyToJwk: unsupported COSE key type (kty=${String(kty)})`);
}

/** Resolve a credential key to its signature algorithm and the raw bytes `@noble/curves` verifies with. */
function resolveKey(pub: CredentialPublicKey): { alg: 'ES256'; raw: Uint8Array } | { alg: 'EdDSA'; raw: Uint8Array } {
  const jwk = pub instanceof Uint8Array ? coseKeyToJwk(pub) : pub;
  if (jwk.kty === 'EC') {
    if (jwk.crv !== 'P-256') throw new Error('resolveKey: EC JWK is not P-256');
    const x = base64urlToBytes(jwk.x);
    const y = base64urlToBytes(jwk.y);
    if (!x || !y || x.length !== 32 || y.length !== 32) throw new Error('resolveKey: invalid EC JWK coordinates');
    // Uncompressed SEC1 point: 0x04 ‖ X ‖ Y.
    const raw = new Uint8Array(65);
    raw[0] = 0x04;
    raw.set(x, 1);
    raw.set(y, 33);
    return { alg: 'ES256', raw };
  }
  if (jwk.kty === 'OKP') {
    if (jwk.crv !== 'Ed25519') throw new Error('resolveKey: OKP JWK is not Ed25519');
    const x = base64urlToBytes(jwk.x);
    if (!x || x.length !== 32) throw new Error('resolveKey: invalid OKP JWK public key');
    return { alg: 'EdDSA', raw: x };
  }
  throw new Error('resolveKey: unsupported public key');
}

// ================================================================================================
// authenticatorData.
// ================================================================================================

/** The authenticator flag bits (WebAuthn §6.1). */
export interface AuthenticatorFlags {
  /** User Present. */
  up: boolean;
  /** User Verified (PIN / biometric). */
  uv: boolean;
  /** Backup Eligible (the credential MAY be backed up / synced). */
  be: boolean;
  /** Backup State (the credential IS currently backed up). */
  bs: boolean;
  /** Attested credential data present. */
  at: boolean;
  /** Extension data present. */
  ed: boolean;
}

/** Parsed authenticator data (the fixed 37-byte header; extension/attested bytes are not decoded). */
export interface ParsedAuthenticatorData {
  /** SHA-256 of the Relying Party ID (32 bytes). */
  rpIdHash: Uint8Array;
  flags: AuthenticatorFlags;
  /** Signature counter (big-endian uint32). */
  signCount: number;
}

/**
 * Parse the fixed header of `authenticatorData` (rpIdHash[32] ‖ flags[1] ‖ signCount[4]). Returns null
 * when the buffer is too short; does not decode the optional attested-credential-data / extension tail
 * (an assertion does not carry it).
 */
export function parseAuthenticatorData(authData: Uint8Array): ParsedAuthenticatorData | null {
  if (!(authData instanceof Uint8Array) || authData.length < 37) return null;
  const dv = new DataView(authData.buffer, authData.byteOffset, authData.byteLength);
  const flagByte = dv.getUint8(32);
  return {
    rpIdHash: authData.slice(0, 32),
    flags: {
      up: (flagByte & 0x01) !== 0,
      uv: (flagByte & 0x04) !== 0,
      be: (flagByte & 0x08) !== 0,
      bs: (flagByte & 0x10) !== 0,
      at: (flagByte & 0x40) !== 0,
      ed: (flagByte & 0x80) !== 0,
    },
    signCount: dv.getUint32(33, false),
  };
}

// ================================================================================================
// Step-up challenge binding.
// ================================================================================================

/**
 * Derive the WebAuthn challenge bytes for a PCA step-up from the action being approved. The result is
 * `sha256(thresholdMessage(pcactn))` — exactly the bytes whose base64url form is the FROST
 * `action_digest` (`frostActionDigest(thresholdMessage(pcactn))`). Set this as the `challenge` passed to
 * `navigator.credentials.get`, and the passkey will sign precisely the action under step-up.
 *
 * Accepts a PCActn (or body), the base64url action-digest string, or raw 32-byte digest bytes; returns
 * the 32-byte challenge. Throws only when given a digest that is not 32 bytes / not canonical base64url.
 */
export function buildStepUpChallenge(pcActnOrDigest: PCActn | PCActnBody | string | Uint8Array): Uint8Array {
  if (pcActnOrDigest instanceof Uint8Array) {
    if (pcActnOrDigest.length !== 32) throw new Error('buildStepUpChallenge: digest bytes must be 32 bytes');
    return pcActnOrDigest.slice();
  }
  if (typeof pcActnOrDigest === 'string') {
    const bytes = decodeB64uStrict(pcActnOrDigest, 32);
    if (!bytes) throw new Error('buildStepUpChallenge: digest is not a canonical base64url 32-byte value');
    return bytes;
  }
  return sha256(thresholdMessage(pcActnOrDigest));
}

/** The base64url step-up challenge (== the FROST `action_digest`) for a PCActn/body/digest. */
export function stepUpChallengeB64u(pcActnOrDigest: PCActn | PCActnBody | string | Uint8Array): string {
  return b64u(buildStepUpChallenge(pcActnOrDigest));
}

// ================================================================================================
// Assertion verification.
// ================================================================================================

/** The parts of a WebAuthn assertion the server verifies (bytes already base64url-decoded). */
export interface Assertion {
  /** `response.authenticatorData`. */
  authenticatorData: Uint8Array;
  /** `response.clientDataJSON`. */
  clientDataJSON: Uint8Array;
  /** `response.signature`. */
  signature: Uint8Array;
  /** The registered credential public key: a JWK or a raw COSE_Key. */
  publicKey: CredentialPublicKey;
}

/** Expectations the assertion must satisfy. */
export interface VerifyExpectations {
  /** The step-up challenge — raw bytes from {@link buildStepUpChallenge}, or its base64url form. */
  expectedChallenge: Uint8Array | string;
  /** The Relying Party ID; `rpIdHash` MUST equal `sha256(rpId)`. */
  rpId: string;
  /** Allowed `clientData.origin` values (exact match). */
  origins: string[];
  /** Require the User Verified flag (true for a genuine human co-sign; a bare touch is not enough). */
  requireUV: boolean;
}

/** A successful verification, with the facts the caller may want to record. */
export interface VerifyOk {
  ok: true;
  /** The credential's signature algorithm. */
  alg: 'ES256' | 'EdDSA';
  /** The authenticator signature counter. */
  signCount: number;
  flags: AuthenticatorFlags;
}

/** A failed verification (fail-closed) with a human-readable reason. */
export interface VerifyFail {
  ok: false;
  reason: string;
}

export type AssertionResult = VerifyOk | VerifyFail;

function fail(reason: string): VerifyFail {
  return { ok: false, reason };
}

/**
 * Verify a WebAuthn/FIDO2 assertion as a human step-up co-sign. Checks, in order: well-formed inputs;
 * clientDataJSON is `webauthn.get` with the EXACT step-up challenge and an allow-listed origin;
 * authenticatorData's rpIdHash matches `sha256(rpId)`, User Present is set, and User Verified is set when
 * `requireUV`; and the assertion signature over `authenticatorData ‖ sha256(clientDataJSON)` verifies
 * under the credential key (ES256 with DER- or raw-encoded ECDSA, or EdDSA). Fails CLOSED and never
 * throws on malformed/hostile input.
 */
export function verifyAssertion(assertion: Assertion, expect: VerifyExpectations): AssertionResult {
  try {
    const { authenticatorData, clientDataJSON, signature, publicKey } = assertion;
    if (!(authenticatorData instanceof Uint8Array)) return fail('authenticatorData is not bytes');
    if (!(clientDataJSON instanceof Uint8Array)) return fail('clientDataJSON is not bytes');
    if (!(signature instanceof Uint8Array)) return fail('signature is not bytes');
    if (typeof expect.rpId !== 'string' || expect.rpId.length === 0) return fail('rpId is required');
    if (!Array.isArray(expect.origins) || expect.origins.length === 0) return fail('origins allowlist is empty');

    // --- clientDataJSON ---
    let clientText: string;
    try {
      clientText = textDecoder.decode(clientDataJSON);
    } catch {
      return fail('clientDataJSON is not valid UTF-8');
    }
    let clientParsed: unknown;
    try {
      clientParsed = JSON.parse(clientText);
    } catch {
      return fail('clientDataJSON is not valid JSON');
    }
    const client = asRecord(clientParsed);
    if (!client) return fail('clientDataJSON is not a JSON object');
    if (client['type'] !== 'webauthn.get') return fail(`clientData.type is not "webauthn.get" (${String(client['type'])})`);

    const challenge = client['challenge'];
    const gotChallenge = base64urlToBytes(challenge);
    if (!gotChallenge) return fail('clientData.challenge is missing or not base64url');
    const expChallenge =
      expect.expectedChallenge instanceof Uint8Array ? expect.expectedChallenge : base64urlToBytes(expect.expectedChallenge);
    if (!expChallenge) return fail('expectedChallenge is not decodable');
    if (!bytesEqual(gotChallenge, expChallenge)) return fail('clientData.challenge does not match the step-up challenge');

    const origin = client['origin'];
    if (typeof origin !== 'string') return fail('clientData.origin is missing');
    if (!expect.origins.includes(origin)) return fail(`clientData.origin "${origin}" is not in the allowlist`);

    // --- authenticatorData ---
    const parsed = parseAuthenticatorData(authenticatorData);
    if (!parsed) return fail('authenticatorData is too short (< 37 bytes)');
    if (!bytesEqual(parsed.rpIdHash, sha256(textEncoder.encode(expect.rpId)))) {
      return fail('rpIdHash does not match sha256(rpId)');
    }
    if (!parsed.flags.up) return fail('User Present (UP) flag is not set');
    if (expect.requireUV && !parsed.flags.uv) return fail('User Verified (UV) flag is required but not set');

    // --- signature over authenticatorData ‖ sha256(clientDataJSON) ---
    const signedData = concatBytes(authenticatorData, sha256(clientDataJSON));
    let key: { alg: 'ES256'; raw: Uint8Array } | { alg: 'EdDSA'; raw: Uint8Array };
    try {
      key = resolveKey(publicKey);
    } catch (e) {
      return fail(`public key could not be resolved: ${e instanceof Error ? e.message : 'unknown'}`);
    }

    let signatureValid = false;
    if (key.alg === 'ES256') {
      const msgHash = sha256(signedData); // ECDSA/P-256 signs the SHA-256 of the signed data
      const isDer = signature.at(0) === 0x30 && signature.length !== 64;
      signatureValid = p256.verify(signature, msgHash, key.raw, { lowS: false, format: isDer ? 'der' : 'compact' });
    } else {
      signatureValid = ed25519.verify(signature, signedData, key.raw); // Ed25519 hashes internally
    }
    if (!signatureValid) return fail('assertion signature did not verify');

    return { ok: true, alg: key.alg, signCount: parsed.signCount, flags: parsed.flags };
  } catch (e) {
    return fail(`verification error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`);
  }
}
