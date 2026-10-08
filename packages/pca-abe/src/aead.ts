import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

/**
 * Authenticated symmetric encryption: AES-256-GCM (via `node:crypto`). The content-encryption key is
 * derived from the ABE/KEM layer; this module only turns a 32-byte key into a sealed payload and back.
 * The ABE header is passed as Additional Authenticated Data so any tampering with the policy or the KEM
 * ciphertext — not just the payload — fails the GCM tag.
 */

const IV_LEN = 12;
const TAG_LEN = 16;

export interface Sealed {
  iv: Uint8Array;
  ct: Uint8Array;
  tag: Uint8Array;
}

/** AES-256-GCM seal. `key` must be 32 bytes. A fresh random 96-bit IV is used per call. */
export function seal(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Sealed {
  if (key.length !== 32) throw new RangeError('aead.seal: key must be 32 bytes');
  const iv = new Uint8Array(randomBytes(IV_LEN));
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad);
  const ct = new Uint8Array(Buffer.concat([cipher.update(plaintext), cipher.final()]));
  const tag = new Uint8Array(cipher.getAuthTag());
  return { iv, ct, tag };
}

/**
 * AES-256-GCM open. Returns the plaintext, or null (never throws) if the key is wrong, the tag/AAD does
 * not authenticate, or any field is malformed.
 */
export function open(key: Uint8Array, sealed: Sealed, aad: Uint8Array): Uint8Array | null {
  if (key.length !== 32 || sealed.iv.length !== IV_LEN || sealed.tag.length !== TAG_LEN) return null;
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, sealed.iv);
    decipher.setAAD(aad);
    decipher.setAuthTag(sealed.tag);
    return new Uint8Array(Buffer.concat([decipher.update(sealed.ct), decipher.final()]));
  } catch {
    return null;
  }
}
