import { ed25519 } from '@noble/curves/ed25519';

const EdPoint = ed25519.ExtendedPoint;
import { b64u, decodeB64uStrict, unb64u } from './hash';

export interface KeyPair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

export function generateKeyPair(): KeyPair {
  const secretKey = ed25519.utils.randomPrivateKey();
  return { secretKey, publicKey: ed25519.getPublicKey(secretKey) };
}

export function publicKeyOf(secretKey: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(secretKey);
}

export function sign(secretKey: Uint8Array, msg: Uint8Array): Uint8Array {
  return ed25519.sign(msg, secretKey);
}

/**
 * STRICT RFC 8032 verification (not the permissive ZIP-215 default): rejects non-canonical point
 * encodings (y >= p), non-canonical S (>= L), small-order public keys, and a small-order / mixed-order
 * R or public key. Canonical signatures produced by `sign` (and every conformance vector) still verify.
 * Never throws: malformed keys/signatures simply fail verification.
 */
export function verify(publicKey: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  try {
    if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) return false;
    if (!(sig instanceof Uint8Array) || sig.length !== 64) return false;
    if (!ed25519.verify(sig, msg, publicKey, { zip215: false })) return false;
    const A = EdPoint.fromHex(publicKey);
    const R = EdPoint.fromHex(sig.subarray(0, 32));
    if (A.isSmallOrder() || R.isSmallOrder()) return false;
    if (!A.isTorsionFree() || !R.isTorsionFree()) return false;
    return true;
  } catch {
    return false;
  }
}

export const encodeKey = b64u;
export const decodeKey = unb64u;
export const encodeSig = b64u;
export const decodeSig = unb64u;

/** verify() over base64url-encoded key and signature; false on any decoding error. */
export function verifyB64u(publicKeyB64u: string, msg: Uint8Array, sigB64u: string): boolean {
  try {
    const pk = decodeB64uStrict(publicKeyB64u, 32);
    const sg = decodeB64uStrict(sigB64u, 64);
    if (!pk || !sg) return false; // non-canonical base64url / wrong length => reject
    return verify(pk, msg, sg);
  } catch {
    return false;
  }
}
