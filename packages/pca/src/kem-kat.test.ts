import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ml_kem1024, ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { x25519 } from '@noble/curves/ed25519';
import { describe, expect, it } from 'vitest';
import {
  HYBRID1024_CIPHERTEXT_LEN,
  HYBRID_CIPHERTEXT_LEN,
  hybridDecapsulate,
  hybridDecapsulate1024,
  hybridEncapsulate,
  hybridEncapsulate1024,
  hybridKem1024Keygen,
  hybridKemKeygen,
  xwingDecapsulate,
  xwingEncapsulate,
  xwingKeygen,
} from './kem';

// Known-answer vectors for the hybrid KEMs. Produced by OpenSSL (node:crypto) via scripts/gen-kem-kat.mjs, independent of src/kem.ts.
const kat = JSON.parse(readFileSync(resolve(__dirname, '../testdata/kem-kat/hybrid-kat.json'), 'utf8')) as {
  vectors: { suite: string; mlkem_seed: string; x25519_sk: string; ciphertext: string; shared_secret: string; ml_kem_public_key: string }[];
};
const hex = (s: string) => Uint8Array.from(Buffer.from(s, 'hex'));
const toHex = (b: Uint8Array) => Buffer.from(b).toString('hex');

const variants = [
  { suite: 'x25519-ml-kem-768', ml: ml_kem768, dec: hybridDecapsulate, enc: hybridEncapsulate, ctLen: HYBRID_CIPHERTEXT_LEN, gen: hybridKemKeygen },
  { suite: 'x25519-ml-kem-1024', ml: ml_kem1024, dec: hybridDecapsulate1024, enc: hybridEncapsulate1024, ctLen: HYBRID1024_CIPHERTEXT_LEN, gen: hybridKem1024Keygen },
] as const;

describe.each(variants)('hybrid KEM known answers: $suite', ({ suite, ml, dec, enc, ctLen, gen }) => {
  const v = kat.vectors.find((x) => x.suite === suite)!;
  const mlKeys = ml.keygen(hex(v.mlkem_seed));
  const sk = new Uint8Array([...hex(v.x25519_sk), ...mlKeys.secretKey]);

  it('the ML-KEM key derived from the seed is the one OpenSSL derived', () => {
    expect(toHex(mlKeys.publicKey)).toBe(v.ml_kem_public_key);
  });

  it('decapsulating the OpenSSL-made ciphertext yields the OpenSSL-computed shared secret', () => {
    expect(toHex(dec(hex(v.ciphertext), sk))).toBe(v.shared_secret);
  });

  it('a flipped bit in either half of the ciphertext changes the secret (X25519 half; ML-KEM half by implicit rejection, no throw)', () => {
    for (const i of [0, 31, 32, 100, ctLen - 1]) {
      const ct = hex(v.ciphertext);
      ct[i] = ct[i]! ^ 1;
      let out: string | undefined;
      try {
        out = toHex(dec(ct, sk));
      } catch (e) {
        // an X25519 half that is not usable may fail closed instead; it must never return the real secret
        expect(e).toBeInstanceOf(Error);
      }
      expect(out).not.toBe(v.shared_secret);
      if (i >= 32) {
        // implicit rejection: no error, 32 bytes, deterministic
        expect(out).toHaveLength(64);
        expect(toHex(dec(ct, sk))).toBe(out);
      }
    }
  });

  it('refuses every wrong ciphertext length and a short or empty secret key', () => {
    for (const n of [0, 1, 32, ctLen - 1, ctLen + 1, 2 * ctLen]) expect(() => dec(new Uint8Array(n), sk)).toThrow(/ciphertext must be/);
    expect(() => dec(hex(v.ciphertext), new Uint8Array(0))).toThrow();
    expect(() => dec(hex(v.ciphertext), new Uint8Array(32))).toThrow();
    expect(() => dec(hex(v.ciphertext), sk.subarray(0, sk.length - 1))).toThrow();
    expect(() => dec(hex(v.ciphertext), new Uint8Array(sk.length + 1))).toThrow();
  });

  it('refuses a public key of the wrong length at encapsulation', () => {
    const k = gen();
    for (const n of [0, 32, k.publicKey.length - 1, k.publicKey.length + 1]) expect(() => enc(new Uint8Array(n))).toThrow(/public key must be/);
  });

  it('an all-zero (low-order) ephemeral X25519 key is refused or never yields the real secret', () => {
    const ct = hex(v.ciphertext);
    ct.fill(0, 0, 32);
    let out: string | undefined;
    try {
      out = toHex(dec(ct, sk));
    } catch {
      /* fail closed */
    }
    expect(out).not.toBe(v.shared_secret);
  });

  it('a fresh round trip still agrees and the X25519 public part of the key is the clamped-scalar public key', () => {
    const k = gen();
    const e = enc(k.publicKey);
    expect(toHex(dec(e.ciphertext, k.secretKey))).toBe(toHex(e.sharedSecret));
    expect(toHex(k.publicKey.subarray(0, 32))).toBe(toHex(x25519.getPublicKey(k.secretKey.subarray(0, 32))));
  });
});

describe('X-Wing abuse', () => {
  it('wrong lengths are refused and a corrupted ciphertext decapsulates to a different 32-byte value (implicit rejection)', () => {
    const k = xwingKeygen();
    const e = xwingEncapsulate(k.publicKey);
    for (const n of [0, 1, e.ciphertext.length - 1, e.ciphertext.length + 1]) expect(() => xwingDecapsulate(new Uint8Array(n), k.secretKey)).toThrow();
    const bad = Uint8Array.from(e.ciphertext);
    bad[10] = bad[10]! ^ 0x80;
    const ss = xwingDecapsulate(bad, k.secretKey);
    expect(ss).toHaveLength(32);
    expect(toHex(ss)).not.toBe(toHex(e.sharedSecret));
  });
});
