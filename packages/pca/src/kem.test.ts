import { describe, expect, it } from 'vitest';
import {
  HYBRID_CIPHERTEXT_LEN,
  HYBRID_PUBLIC_KEY_LEN,
  HYBRID_SHARED_SECRET_LEN,
  decodeHybridCiphertext,
  decodeHybridPublicKey,
  encodeHybridCiphertext,
  encodeHybridPublicKey,
  hybridDecapsulate,
  hybridEncapsulate,
  hybridKemKeygen,
} from './kem';

const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

describe('hybrid X25519 + ML-KEM-768 KEM', () => {
  it('encapsulate → decapsulate recovers the same 32-byte secret, with the right sizes', () => {
    const kp = hybridKemKeygen();
    expect(kp.publicKey.length).toBe(HYBRID_PUBLIC_KEY_LEN);
    const { ciphertext, sharedSecret } = hybridEncapsulate(kp.publicKey);
    expect(ciphertext.length).toBe(HYBRID_CIPHERTEXT_LEN);
    expect(sharedSecret.length).toBe(HYBRID_SHARED_SECRET_LEN);
    const recovered = hybridDecapsulate(ciphertext, kp.secretKey);
    expect(eq(recovered, sharedSecret)).toBe(true);
  });

  it('a different recipient key recovers a different secret', () => {
    const a = hybridKemKeygen();
    const b = hybridKemKeygen();
    const { ciphertext, sharedSecret } = hybridEncapsulate(a.publicKey);
    const wrong = hybridDecapsulate(ciphertext, b.secretKey);
    expect(eq(wrong, sharedSecret)).toBe(false);
  });

  it('fresh encapsulations to the same key differ (ephemeral)', () => {
    const kp = hybridKemKeygen();
    const e1 = hybridEncapsulate(kp.publicKey);
    const e2 = hybridEncapsulate(kp.publicKey);
    expect(eq(e1.ciphertext, e2.ciphertext)).toBe(false);
    expect(eq(e1.sharedSecret, e2.sharedSecret)).toBe(false);
  });

  it('hybrid: corrupting EITHER the X25519 half OR the ML-KEM half breaks the secret', () => {
    const kp = hybridKemKeygen();
    const { ciphertext, sharedSecret } = hybridEncapsulate(kp.publicKey);

    // flip a byte in the ephemeral-X25519 half (first 32 bytes)
    const tamperX = Uint8Array.from(ciphertext);
    tamperX[0] = tamperX[0]! ^ 0xff;
    expect(eq(hybridDecapsulate(tamperX, kp.secretKey), sharedSecret)).toBe(false);

    // flip a byte in the ML-KEM ciphertext half (after byte 32)
    const tamperK = Uint8Array.from(ciphertext);
    tamperK[100] = tamperK[100]! ^ 0xff;
    expect(eq(hybridDecapsulate(tamperK, kp.secretKey), sharedSecret)).toBe(false);
  });

  it('fails closed on malformed sizes', () => {
    const kp = hybridKemKeygen();
    expect(() => hybridEncapsulate(new Uint8Array(10))).toThrow(/public key must be/);
    expect(() => hybridDecapsulate(new Uint8Array(10), kp.secretKey)).toThrow(/ciphertext must be/);
    expect(() => hybridDecapsulate(hybridEncapsulate(kp.publicKey).ciphertext, new Uint8Array(8))).toThrow(/malformed secret key/);
  });

  it('b64u wire helpers round-trip', () => {
    const kp = hybridKemKeygen();
    expect(eq(decodeHybridPublicKey(encodeHybridPublicKey(kp.publicKey)), kp.publicKey)).toBe(true);
    const { ciphertext } = hybridEncapsulate(kp.publicKey);
    expect(eq(decodeHybridCiphertext(encodeHybridCiphertext(ciphertext)), ciphertext)).toBe(true);
  });
});
