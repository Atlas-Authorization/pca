/**
 * Hybrid post-quantum key encapsulation — X25519 + ML-KEM-768 (spec Part 1.2 P5, "ML-KEM hybrid for
 * key exchange / secret wrap").
 *
 * Establishes a 32-byte shared secret between a sender and a holder of the recipient key, for wrapping
 * any secret that must survive "harvest now, decrypt later" — a guardian share, a data-encryption key,
 * a cross-domain channel key. It is HYBRID: the shared secret is derived from BOTH an X25519
 * ephemeral-static ECDH AND an ML-KEM-768 (FIPS-203) encapsulation, combined through HKDF-SHA256 over
 * the full transcript. An attacker must break BOTH the elliptic curve (classical) AND the lattice
 * (quantum) to recover it, so it stays secure if either one falls — including to a quantum computer.
 *
 * This module establishes the shared SECRET only; it deliberately ships no symmetric cipher. Use the
 * 32-byte result as the key for an AEAD you already trust (AES-256-GCM via WebCrypto, XChaCha20-Poly1305,
 * …) — PCA does not hand-roll a cipher. All inputs are length-checked and fail closed.
 *
 * Construction: a dual-KEM combiner binding the transcript (akin to X-Wing / the TLS hybrid drafts):
 *   ss = HKDF-SHA256( ss_mlkem ‖ ss_x25519 ‖ eph_x25519_pub ‖ recipient_x25519_pub, info = DOMAIN ).
 */

import { x25519 } from '@noble/curves/ed25519';
import { ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { sha3_256, shake256 } from '@noble/hashes/sha3.js';
import { randomBytes } from '@noble/hashes/utils';
import { b64u, unb64u } from './hash';

const X25519_LEN = 32;
const MLKEM_PK_LEN = 1184;
const MLKEM_CT_LEN = 1088;
const SS_LEN = 32;

/** Public-key size: X25519 (32) ‖ ML-KEM-768 (1184). */
export const HYBRID_PUBLIC_KEY_LEN = X25519_LEN + MLKEM_PK_LEN; // 1216
/** Ciphertext size: ephemeral X25519 (32) ‖ ML-KEM-768 ct (1088). */
export const HYBRID_CIPHERTEXT_LEN = X25519_LEN + MLKEM_CT_LEN; // 1120
/** Shared-secret size. */
export const HYBRID_SHARED_SECRET_LEN = SS_LEN; // 32

export const HYBRID_KEM_SUITE = 'x25519-ml-kem-768';
const DOMAIN = new TextEncoder().encode('atlas-pca/kem/x25519-ml-kem-768/v1\0');

export interface HybridKemKeyPair {
  /** X25519 pub (32) ‖ ML-KEM-768 pub (1184). */
  publicKey: Uint8Array;
  /** X25519 secret (32) ‖ ML-KEM-768 secret. */
  secretKey: Uint8Array;
}

export interface HybridEncapsulation {
  /** eph X25519 pub (32) ‖ ML-KEM-768 ciphertext (1088). */
  ciphertext: Uint8Array;
  /** The 32-byte shared secret (use as an AEAD key). */
  sharedSecret: Uint8Array;
}

function cat(...parts: Uint8Array[]): Uint8Array {
  const n = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function combine(ssMlkem: Uint8Array, ssX: Uint8Array, ephPub: Uint8Array, recipX: Uint8Array): Uint8Array {
  return hkdf(sha256, cat(ssMlkem, ssX, ephPub, recipX), undefined, DOMAIN, SS_LEN);
}

/** Generate a hybrid recipient keypair. */
export function hybridKemKeygen(): HybridKemKeyPair {
  const xPriv = x25519.utils.randomPrivateKey();
  const xPub = x25519.getPublicKey(xPriv);
  const mlkem = ml_kem768.keygen();
  return {
    publicKey: cat(xPub, mlkem.publicKey),
    secretKey: cat(xPriv, mlkem.secretKey),
  };
}

/** Encapsulate to a recipient public key: returns the ciphertext (send it) + the shared secret (keep it). */
export function hybridEncapsulate(recipientPublicKey: Uint8Array): HybridEncapsulation {
  if (recipientPublicKey.length !== HYBRID_PUBLIC_KEY_LEN) {
    throw new Error(`hybridEncapsulate: public key must be ${HYBRID_PUBLIC_KEY_LEN} bytes (got ${recipientPublicKey.length})`);
  }
  const recipX = recipientPublicKey.subarray(0, X25519_LEN);
  const recipMlkem = recipientPublicKey.subarray(X25519_LEN);

  const ephPriv = x25519.utils.randomPrivateKey();
  const ephPub = x25519.getPublicKey(ephPriv);
  const ssX = x25519.getSharedSecret(ephPriv, recipX);

  const { cipherText: mlkemCt, sharedSecret: ssMlkem } = ml_kem768.encapsulate(recipMlkem);

  return {
    ciphertext: cat(ephPub, mlkemCt),
    sharedSecret: combine(ssMlkem, ssX, ephPub, recipX),
  };
}

/** Decapsulate with the recipient secret key: recovers the same shared secret. */
export function hybridDecapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array {
  if (ciphertext.length !== HYBRID_CIPHERTEXT_LEN) {
    throw new Error(`hybridDecapsulate: ciphertext must be ${HYBRID_CIPHERTEXT_LEN} bytes (got ${ciphertext.length})`);
  }
  if (secretKey.length <= X25519_LEN) {
    throw new Error('hybridDecapsulate: malformed secret key');
  }
  const ephPub = ciphertext.subarray(0, X25519_LEN);
  const mlkemCt = ciphertext.subarray(X25519_LEN);

  const xPriv = secretKey.subarray(0, X25519_LEN);
  const mlkemPriv = secretKey.subarray(X25519_LEN);

  const ssX = x25519.getSharedSecret(xPriv, ephPub);
  const ssMlkem = ml_kem768.decapsulate(mlkemCt, mlkemPriv);

  // The recipient's own X25519 public key is part of the transcript the sender bound.
  const recipX = x25519.getPublicKey(xPriv);
  return combine(ssMlkem, ssX, ephPub, recipX);
}

// ---- b64u convenience (the wire form for storing/transporting keys + ciphertexts) ----------------

export const encodeHybridPublicKey = (k: HybridKemKeyPair['publicKey']): string => b64u(k);
export const decodeHybridPublicKey = (s: string): Uint8Array => unb64u(s);
export const encodeHybridCiphertext = (c: Uint8Array): string => b64u(c);
export const decodeHybridCiphertext = (s: string): Uint8Array => unb64u(s);

// ==================================================================================================
// X-Wing — the standard CFRG hybrid KEM (draft-connolly-cfrg-xwing-kem-09)
// ==================================================================================================
/**
 * X-Wing is the de-facto CFRG / HPKE / TLS / X.509 post-quantum hybrid KEM: X25519 + ML-KEM-768 combined
 * with a FIXED, standardized SHA3-256 combiner and a published MAL-BIND-K-CT binding proof (the strongest
 * binding notion — the shared secret is bound to the whole key+ciphertext, so neither half can be mauled).
 * Unlike the custom HKDF hybrid above (kept for back-compat), X-Wing is byte-interoperable with every other
 * X-Wing implementation across the ecosystem and is the RECOMMENDED PCA key-exchange suite going forward.
 *
 * This is a BYTE-EXACT implementation of draft-09 — verified against the draft's Appendix C known-answer
 * vectors (see kem-xwing.test.ts: seed → public key, derandomized ciphertext, and shared secret all match
 * the published hex). Shapes:
 *   - secret (decapsulation) key: a 32-byte SEED (draft-09's seed form); expanded on use.
 *   - public (encapsulation) key: pk_M ‖ pk_X   (ML-KEM-768 pub 1184 ‖ X25519 pub 32  = 1216 bytes).
 *   - ciphertext:                 ct_M ‖ ct_X   (ML-KEM-768 ct 1088 ‖ X25519 eph pub 32 = 1120 bytes).
 *   - shared secret:              32 bytes.
 *
 * Combiner (draft-09 §5.3) — SHA3-256, NOT HKDF:
 *   ss = SHA3-256( ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel )
 * where ss_M = the ML-KEM-768 shared secret, ss_X = X25519(ek_X, pk_X) shared secret, ct_X = the ephemeral
 * X25519 public key, pk_X = the recipient X25519 public key, and XWingLabel = the 6 bytes `\.//^\`.
 *
 * WHY ct_M IS DELIBERATELY ABSENT FROM THE COMBINER (a draft requirement, not an oversight): the ML-KEM
 * ciphertext ct_M is intentionally NOT hashed in. This is sound ONLY because ML-KEM's Fujisaki–Okamoto
 * transform already binds ss_M to ct_M — any change to ct_M yields a different ss_M, which changes ss. The
 * X25519 half is bound because ss_X depends on ct_X, and ct_X IS in the combiner. Do NOT "fix" this by
 * adding ct_M: that would diverge from every other X-Wing implementation and break interoperability.
 *
 * Like the hybrid KEM above, this establishes the 32-byte SECRET only and ships no symmetric cipher — use
 * the result as a key for an AEAD you already trust. All inputs are length-checked and fail closed.
 */

/** X-Wing suite id (draft-connolly-cfrg-xwing-kem-09). */
export const XWING_SUITE = 'xwing';
/** X-Wing decapsulation-key seed length — the secret key IS this 32-byte seed (draft-09 seed form). */
export const XWING_SEED_LEN = 32;
/** X-Wing secret-key length (== the 32-byte seed). */
export const XWING_SECRET_KEY_LEN = XWING_SEED_LEN; // 32
/** X-Wing public-key length: ML-KEM-768 pub (1184) ‖ X25519 pub (32). */
export const XWING_PUBLIC_KEY_LEN = MLKEM_PK_LEN + X25519_LEN; // 1216
/** X-Wing ciphertext length: ML-KEM-768 ct (1088) ‖ X25519 ephemeral pub (32). */
export const XWING_CIPHERTEXT_LEN = MLKEM_CT_LEN + X25519_LEN; // 1120
/** X-Wing shared-secret length. */
export const XWING_SHARED_SECRET_LEN = SS_LEN; // 32
/** X-Wing encapsulation-seed length (derandomized encaps: ML-KEM message m (32) ‖ X25519 eph secret (32)). */
export const XWING_ESEED_LEN = 64;
/** The 6-byte X-Wing domain label, ASCII `\.//^\` (draft-09 §5.3); hex `5c2e2f2f5e5c`. */
export const XWING_LABEL: Uint8Array = Uint8Array.of(0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c);

export interface XWingKeyPair {
  /** The 32-byte X-Wing seed — draft-09's decapsulation key; expanded to the component keys on use. */
  secretKey: Uint8Array;
  /** pk_M ‖ pk_X (1216 bytes). */
  publicKey: Uint8Array;
}

export interface XWingEncapsulation {
  /** ct_M ‖ ct_X (1120 bytes) — send it. */
  ciphertext: Uint8Array;
  /** The 32-byte shared secret (use as an AEAD key). */
  sharedSecret: Uint8Array;
}

interface XWingExpandedKey {
  /** Full ML-KEM-768 decapsulation key (noble's expanded secret-key form). */
  mlkemSecret: Uint8Array;
  /** ML-KEM-768 encapsulation key pk_M. */
  mlkemPublic: Uint8Array;
  /** X25519 secret scalar sk_X (32 bytes). */
  xSecret: Uint8Array;
  /** X25519 public key pk_X (32 bytes). */
  xPublic: Uint8Array;
}

/**
 * draft-09 §5.2 decapsulation-key expansion. SHAKE-256(seed) → 96 bytes = d(32) ‖ z(32) ‖ sk_X(32):
 * `(d, z)` seed ML-KEM-768 key generation (noble's keygen takes the 64-byte `d‖z`), and `sk_X` is the
 * X25519 scalar with `pk_X = X25519(sk_X, G)`. Throws on a wrong-length seed (fail-closed).
 */
function expandXWingKey(seed: Uint8Array): XWingExpandedKey {
  if (seed.length !== XWING_SEED_LEN) {
    throw new Error(`expandXWingKey: seed must be ${XWING_SEED_LEN} bytes (got ${seed.length})`);
  }
  const expanded = shake256(seed, { dkLen: 96 });
  const dz = expanded.subarray(0, 64); // d ‖ z
  const xSecret = expanded.subarray(64, 96);
  const mlkem = ml_kem768.keygen(dz);
  return { mlkemSecret: mlkem.secretKey, mlkemPublic: mlkem.publicKey, xSecret, xPublic: x25519.getPublicKey(xSecret) };
}

/** The X-Wing SHA3-256 combiner (draft-09 §5.3). */
function xwingCombiner(ssM: Uint8Array, ssX: Uint8Array, ctX: Uint8Array, pkX: Uint8Array): Uint8Array {
  return sha3_256(cat(ssM, ssX, ctX, pkX, XWING_LABEL));
}

/**
 * Generate an X-Wing keypair. With no argument a fresh 32-byte seed is drawn from the system CSPRNG; pass
 * a 32-byte `seed` for deterministic / KAT keygen. The returned `secretKey` IS that 32-byte seed (copied).
 */
export function xwingKeygen(seed?: Uint8Array): XWingKeyPair {
  const sk = seed === undefined ? randomBytes(XWING_SEED_LEN) : Uint8Array.from(seed);
  const ex = expandXWingKey(sk);
  return { secretKey: sk, publicKey: cat(ex.mlkemPublic, ex.xPublic) };
}

/**
 * Derandomized X-Wing encapsulation (draft-09): `eseed` (64 bytes) = ML-KEM-768 message `m` (32) ‖ X25519
 * ephemeral secret `ek_X` (32). Exposed for KAT reproduction and for callers needing deterministic
 * encapsulation (HPKE-style vectors); production code should prefer {@link xwingEncapsulate}.
 */
export function xwingEncapsulateDerand(recipientPublicKey: Uint8Array, eseed: Uint8Array): XWingEncapsulation {
  if (recipientPublicKey.length !== XWING_PUBLIC_KEY_LEN) {
    throw new Error(`xwingEncapsulateDerand: public key must be ${XWING_PUBLIC_KEY_LEN} bytes (got ${recipientPublicKey.length})`);
  }
  if (eseed.length !== XWING_ESEED_LEN) {
    throw new Error(`xwingEncapsulateDerand: eseed must be ${XWING_ESEED_LEN} bytes (got ${eseed.length})`);
  }
  const pkM = recipientPublicKey.subarray(0, MLKEM_PK_LEN);
  const pkX = recipientPublicKey.subarray(MLKEM_PK_LEN);
  const mlkemMsg = eseed.subarray(0, 32);
  const ekX = eseed.subarray(32, 64);

  const { cipherText: ctM, sharedSecret: ssM } = ml_kem768.encapsulate(pkM, mlkemMsg);
  const ctX = x25519.getPublicKey(ekX);
  const ssX = x25519.getSharedSecret(ekX, pkX);

  return { ciphertext: cat(ctM, ctX), sharedSecret: xwingCombiner(ssM, ssX, ctX, pkX) };
}

/** Encapsulate to an X-Wing public key with fresh randomness: returns the ciphertext (send it) + shared secret (keep it). */
export function xwingEncapsulate(recipientPublicKey: Uint8Array): XWingEncapsulation {
  return xwingEncapsulateDerand(recipientPublicKey, randomBytes(XWING_ESEED_LEN));
}

/** Decapsulate an X-Wing ciphertext with the 32-byte seed secret key: recovers the same shared secret. */
export function xwingDecapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array {
  if (ciphertext.length !== XWING_CIPHERTEXT_LEN) {
    throw new Error(`xwingDecapsulate: ciphertext must be ${XWING_CIPHERTEXT_LEN} bytes (got ${ciphertext.length})`);
  }
  const ex = expandXWingKey(secretKey); // validates the 32-byte seed length (fail-closed)
  const ctM = ciphertext.subarray(0, MLKEM_CT_LEN);
  const ctX = ciphertext.subarray(MLKEM_CT_LEN);

  const ssM = ml_kem768.decapsulate(ctM, ex.mlkemSecret);
  const ssX = x25519.getSharedSecret(ex.xSecret, ctX);
  // The recipient's own X25519 public key is part of the combiner transcript (draft-09 §5.3).
  return xwingCombiner(ssM, ssX, ctX, ex.xPublic);
}

export const encodeXWingPublicKey = (k: XWingKeyPair['publicKey']): string => b64u(k);
export const decodeXWingPublicKey = (s: string): Uint8Array => unb64u(s);
export const encodeXWingCiphertext = (c: Uint8Array): string => b64u(c);
export const decodeXWingCiphertext = (s: string): Uint8Array => unb64u(s);

// ==================================================================================================
// Optional high-assurance variant: X25519 + ML-KEM-1024 (the SAME custom HKDF hybrid as above, at
// ML-KEM Category 5). For key exchange that must match the assurance level of a Category-5 signing
// anchor; opt-in, NOT a default. Byte-layout and combiner mirror the ML-KEM-768 hybrid exactly, with
// its own domain separator so a 1024 secret can never be combined under the 768 transcript.
// ==================================================================================================

const MLKEM1024_PK_LEN = 1568;
const MLKEM1024_CT_LEN = 1568;

/** Public-key size: X25519 (32) ‖ ML-KEM-1024 (1568). */
export const HYBRID1024_PUBLIC_KEY_LEN = X25519_LEN + MLKEM1024_PK_LEN; // 1600
/** Ciphertext size: ephemeral X25519 (32) ‖ ML-KEM-1024 ct (1568). */
export const HYBRID1024_CIPHERTEXT_LEN = X25519_LEN + MLKEM1024_CT_LEN; // 1600
/** Shared-secret size. */
export const HYBRID1024_SHARED_SECRET_LEN = SS_LEN; // 32

export const HYBRID1024_KEM_SUITE = 'x25519-ml-kem-1024';
const DOMAIN_1024 = new TextEncoder().encode('atlas-pca/kem/x25519-ml-kem-1024/v1\0');

function combine1024(ssMlkem: Uint8Array, ssX: Uint8Array, ephPub: Uint8Array, recipX: Uint8Array): Uint8Array {
  return hkdf(sha256, cat(ssMlkem, ssX, ephPub, recipX), undefined, DOMAIN_1024, SS_LEN);
}

/** Generate a hybrid X25519 + ML-KEM-1024 recipient keypair. */
export function hybridKem1024Keygen(): HybridKemKeyPair {
  const xPriv = x25519.utils.randomPrivateKey();
  const xPub = x25519.getPublicKey(xPriv);
  const mlkem = ml_kem1024.keygen();
  return { publicKey: cat(xPub, mlkem.publicKey), secretKey: cat(xPriv, mlkem.secretKey) };
}

/** Encapsulate to a hybrid X25519 + ML-KEM-1024 public key. */
export function hybridEncapsulate1024(recipientPublicKey: Uint8Array): HybridEncapsulation {
  if (recipientPublicKey.length !== HYBRID1024_PUBLIC_KEY_LEN) {
    throw new Error(`hybridEncapsulate1024: public key must be ${HYBRID1024_PUBLIC_KEY_LEN} bytes (got ${recipientPublicKey.length})`);
  }
  const recipX = recipientPublicKey.subarray(0, X25519_LEN);
  const recipMlkem = recipientPublicKey.subarray(X25519_LEN);

  const ephPriv = x25519.utils.randomPrivateKey();
  const ephPub = x25519.getPublicKey(ephPriv);
  const ssX = x25519.getSharedSecret(ephPriv, recipX);

  const { cipherText: mlkemCt, sharedSecret: ssMlkem } = ml_kem1024.encapsulate(recipMlkem);

  return { ciphertext: cat(ephPub, mlkemCt), sharedSecret: combine1024(ssMlkem, ssX, ephPub, recipX) };
}

/** Decapsulate with a hybrid X25519 + ML-KEM-1024 secret key. */
export function hybridDecapsulate1024(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array {
  if (ciphertext.length !== HYBRID1024_CIPHERTEXT_LEN) {
    throw new Error(`hybridDecapsulate1024: ciphertext must be ${HYBRID1024_CIPHERTEXT_LEN} bytes (got ${ciphertext.length})`);
  }
  if (secretKey.length <= X25519_LEN) {
    throw new Error('hybridDecapsulate1024: malformed secret key');
  }
  const ephPub = ciphertext.subarray(0, X25519_LEN);
  const mlkemCt = ciphertext.subarray(X25519_LEN);

  const xPriv = secretKey.subarray(0, X25519_LEN);
  const mlkemPriv = secretKey.subarray(X25519_LEN);

  const ssX = x25519.getSharedSecret(xPriv, ephPub);
  const ssMlkem = ml_kem1024.decapsulate(mlkemCt, mlkemPriv);

  const recipX = x25519.getPublicKey(xPriv);
  return combine1024(ssMlkem, ssX, ephPub, recipX);
}
