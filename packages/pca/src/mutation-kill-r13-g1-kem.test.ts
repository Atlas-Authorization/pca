// r13 g1: the opt-in X25519 + ML-KEM-1024 hybrid (kem.ts) had no test at all (every mutant NoCoverage), and the
// 768 hybrid's secret-key length guard was only probed far from its boundary. Exact sizes, an independently
// recomputed shared secret (pins the combiner transcript and its 1024 domain separator), and the exact refusals.
import { describe, expect, it } from 'vitest';
import { x25519 } from '@noble/curves/ed25519';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import {
  HYBRID1024_CIPHERTEXT_LEN,
  HYBRID1024_KEM_SUITE,
  HYBRID1024_PUBLIC_KEY_LEN,
  HYBRID1024_SHARED_SECRET_LEN,
  hybridDecapsulate,
  hybridDecapsulate1024,
  hybridEncapsulate,
  hybridEncapsulate1024,
  hybridKem1024Keygen,
  hybridKemKeygen,
} from './kem';

type Outcome = { ok: true; value: unknown } | { ok: false; error: { name: string; message: string } };
const settle = (f: () => unknown): Outcome => {
  try {
    return { ok: true, value: f() };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? { name: e.constructor.name, message: e.message } : { name: typeof e, message: String(e) } };
  }
};
const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
const cat = (...p: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(p.reduce((n, x) => n + x.length, 0));
  let o = 0;
  for (const x of p) {
    out.set(x, o);
    o += x.length;
  }
  return out;
};
const DOMAIN_1024 = new TextEncoder().encode('atlas-pca/kem/x25519-ml-kem-1024/v1\0');

describe('hybrid X25519 + ML-KEM-1024 KEM', () => {
  it('declares the Category-5 sizes and suite id', () => {
    expect(HYBRID1024_PUBLIC_KEY_LEN).toBe(1600);
    expect(HYBRID1024_CIPHERTEXT_LEN).toBe(1600);
    expect(HYBRID1024_SHARED_SECRET_LEN).toBe(32);
    expect(HYBRID1024_KEM_SUITE).toBe('x25519-ml-kem-1024');
  });

  it('keygen lays out X25519 pub ‖ ML-KEM-1024 pub and X25519 priv ‖ ML-KEM-1024 secret', () => {
    const kp = hybridKem1024Keygen();
    expect(kp.publicKey).toBeInstanceOf(Uint8Array);
    expect(kp.publicKey.length).toBe(1600);
    expect(kp.secretKey.length).toBe(32 + 3168);
    // the first 32 bytes of the public key are the X25519 public key of the first 32 bytes of the secret key
    expect(hex(kp.publicKey.subarray(0, 32))).toBe(hex(x25519.getPublicKey(kp.secretKey.subarray(0, 32))));
    // the ML-KEM halves are a working ML-KEM-1024 pair
    const { cipherText, sharedSecret } = ml_kem1024.encapsulate(kp.publicKey.subarray(32));
    expect(hex(ml_kem1024.decapsulate(cipherText, kp.secretKey.subarray(32)))).toBe(hex(sharedSecret));
  });

  it('encapsulate -> decapsulate recovers the same 32-byte secret, which equals the documented HKDF transcript', () => {
    const kp = hybridKem1024Keygen();
    // outcomes captured, so a mutant that throws (or returns nothing) fails an assertion, not an uncaught error
    const encO = settle(() => {
      const e = hybridEncapsulate1024(kp.publicKey);
      return { keys: Object.keys(e).sort(), ct: hex(e.ciphertext), ss: hex(e.sharedSecret) };
    });
    expect(encO.ok).toBe(true);
    const enc = (encO as { value: { keys: string[]; ct: string; ss: string } }).value;
    expect(enc.keys).toEqual(['ciphertext', 'sharedSecret']);
    expect(enc.ct.length).toBe(3200);
    expect(enc.ss.length).toBe(64);
    const ct = Uint8Array.from(Buffer.from(enc.ct, 'hex'));
    expect(settle(() => hex(hybridDecapsulate1024(ct, kp.secretKey)))).toEqual({ ok: true, value: enc.ss });

    // independent recomputation: ss = HKDF-SHA256(ss_mlkem ‖ ss_x ‖ eph_pub ‖ recip_x_pub, info = DOMAIN_1024)
    const ephPub = ct.subarray(0, 32);
    const ssX = x25519.getSharedSecret(kp.secretKey.subarray(0, 32), ephPub);
    const ssM = ml_kem1024.decapsulate(ct.subarray(32), kp.secretKey.subarray(32));
    const want = hkdf(sha256, cat(ssM, ssX, ephPub, kp.publicKey.subarray(0, 32)), undefined, DOMAIN_1024, 32);
    expect(enc.ss).toBe(hex(want));
  });

  it('a different recipient key recovers a different secret; fresh encapsulations differ', () => {
    const a = hybridKem1024Keygen();
    const b = hybridKem1024Keygen();
    const e1 = hybridEncapsulate1024(a.publicKey);
    const e2 = hybridEncapsulate1024(a.publicKey);
    expect(hex(e1.ciphertext)).not.toBe(hex(e2.ciphertext));
    expect(hex(hybridDecapsulate1024(e1.ciphertext, b.secretKey))).not.toBe(hex(e1.sharedSecret));
  });

  it('refuses a public key of the wrong length with the exact message (boundaries 1599 / 1601)', () => {
    for (const n of [0, 1599, 1601, 1216]) {
      expect(() => hybridEncapsulate1024(new Uint8Array(n))).toThrow(
        new Error(`hybridEncapsulate1024: public key must be 1600 bytes (got ${n})`),
      );
    }
  });

  it('refuses a ciphertext of the wrong length with the exact message', () => {
    const kp = hybridKem1024Keygen();
    for (const n of [0, 1599, 1601, 1120]) {
      expect(() => hybridDecapsulate1024(new Uint8Array(n), kp.secretKey)).toThrow(
        new Error(`hybridDecapsulate1024: ciphertext must be 1600 bytes (got ${n})`),
      );
    }
  });

  it('refuses a secret key of at most 32 bytes (boundary: exactly 32) with the exact message', () => {
    const kp = hybridKem1024Keygen();
    const { ciphertext } = hybridEncapsulate1024(kp.publicKey);
    for (const n of [0, 31, 32]) {
      expect(() => hybridDecapsulate1024(ciphertext, kp.secretKey.subarray(0, n))).toThrow(
        new Error('hybridDecapsulate1024: malformed secret key'),
      );
    }
  });
});

describe('hybrid X25519 + ML-KEM-768 KEM: secret-key length boundary', () => {
  it('a 32-byte secret key (X25519 part only) is refused as malformed, not passed to ML-KEM', () => {
    const kp = hybridKemKeygen();
    const { ciphertext } = hybridEncapsulate(kp.publicKey);
    for (const n of [0, 32]) {
      expect(() => hybridDecapsulate(ciphertext, kp.secretKey.subarray(0, n))).toThrow(
        new Error('hybridDecapsulate: malformed secret key'),
      );
    }
  });
});
