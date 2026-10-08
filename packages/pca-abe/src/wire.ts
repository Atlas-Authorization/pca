/**
 * Wire helpers: base64url codec (no padding) and fail-closed structural type guards for parsing
 * UNTRUSTED ciphertext/key material. Nothing here throws on bad input — every parser returns a typed
 * value or `null`, so a malformed ciphertext is rejected cleanly rather than crashing the decryptor.
 */

/** Encode bytes as unpadded base64url. */
export function b64u(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

/** Decode unpadded base64url; null on any non-string / malformed input (round-trip checked, never throws). */
export function unb64u(s: unknown): Uint8Array | null {
  if (typeof s !== 'string') return null;
  if (!/^[A-Za-z0-9_-]*$/.test(s)) return null;
  try {
    const bytes = new Uint8Array(Buffer.from(s, 'base64url'));
    // Reject non-canonical encodings (trailing bits / padding variance): require exact round-trip.
    if (Buffer.from(bytes).toString('base64url') !== s) return null;
    return bytes;
  } catch {
    return null;
  }
}

export function isObject(x: unknown): x is Record<string, unknown> {
  return x !== null && typeof x === 'object' && !Array.isArray(x);
}

export function isString(x: unknown): x is string {
  return typeof x === 'string';
}

export function isPosInt(x: unknown): x is number {
  return typeof x === 'number' && Number.isInteger(x) && x > 0;
}

/** XOR two equal-length byte arrays; null if lengths differ. */
export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array | null {
  if (a.length !== b.length) return null;
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = (a[i] ?? 0) ^ (b[i] ?? 0);
  return out;
}
