import { bls12_381 } from '@noble/curves/bls12-381';
import { bytesToHex } from '@noble/hashes/utils';

/**
 * BLS signatures on BLS12-381, aggregation-ready.
 *
 * SCHEME — Proof-of-Possession (PoP), per draft-irtf-cfrg-bls-signature-05 §3.3.
 * Variant: "minimal-pubkey-size" — public keys live in G1 (48 bytes compressed), signatures in
 * G2 (96 bytes compressed). This is the eth2 / Ethereum-consensus convention.
 *
 * WHY PoP (not message-augmentation / basic): the whole point of this package is to aggregate
 * signatures from DIFFERENT keys — a delegation chain's per-hop keys, and a quorum of transparency
 * witnesses cosigning the SAME statement. Same-message aggregation is exactly where the rogue-key
 * attack lives: an adversary who registers pk_adv = pk_victim^-1 · g^a can forge an aggregate that
 * "verifies" against {pk_victim, pk_adv}. PoP closes this: every key must ship a proof-of-possession
 * (a signature, under a DISTINCT domain, over its own public key) that only the true secret-key
 * holder can produce, so a rogue key chosen as a function of other keys cannot pass {@link popVerify}.
 * The signing and PoP ciphersuites therefore use the `_POP_` domain separation tags below.
 *
 * Every function is total: verification never throws, it returns `false` on any malformed input.
 *
 * THIS MODULE IS INTERNAL. Its `aggregateVerify` / `fastAggregateVerify` / `aggregatePublicKeys` take RAW public
 * keys and are only sound if the caller has already checked a proof of possession for every key. They are not
 * exported from the package index (and `package.json` `exports` blocks deep imports); the public versions in
 * `./bls` accept only {@link RegisteredKey}s, which can only be obtained from a verified PoP.
 */

/** Ciphersuite ID / hash-to-curve DST for SIGNATURES (PoP variant, signatures in G2). */
export const SIG_DST = 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_';
/** DISTINCT DST for proofs-of-possession, so a PoP can never be replayed as a message signature. */
export const POP_DST = 'BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_';

/** Compressed G1 public-key length in bytes. */
export const PUBLIC_KEY_LENGTH = 48;
/** Compressed G2 signature length in bytes. */
export const SIGNATURE_LENGTH = 96;

/**
 * Strict ZCash/IETF compressed-encoding gate. The pinned `@noble/curves` decodes a 96-byte G2 value without
 * insisting on the compression flag, so clearing the top bit of a valid signature still verified: every
 * signature then had two accepted encodings (malleable bytes, and different `capHash` values for one hop).
 * Reject anything that is not a 96-byte (G2) / 48-byte (G1) value with the compression bit set.
 */
export function isCompressed(bytes: unknown, len: number): boolean {
  return bytes instanceof Uint8Array && bytes.length === len && ((bytes[0] ?? 0) & 0x80) !== 0;
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

/**
 * Canonical signature encoding: a 96-byte compressed G2 point that is EXACTLY the re-encoding of the point it decodes to.
 * The pinned `@noble/curves` decodes without reducing coordinates, so `c0 + p` parses to the same point: every signature
 * would have a second accepted byte string (malleable, and a different `capHash` for one hop). Never throws.
 */
export function isCanonicalSignature(sig: unknown): boolean {
  if (!isCompressed(sig, SIGNATURE_LENGTH)) return false;
  try {
    return sameBytes(bls12_381.G2.ProjectivePoint.fromHex(sig as Uint8Array).toRawBytes(true), sig as Uint8Array);
  } catch {
    return false;
  }
}

const SIG_OPTS = { DST: SIG_DST } as const;
const POP_OPTS = { DST: POP_DST } as const;

export interface BlsKeyPair {
  /** 32-byte scalar (mod r). */
  secretKey: Uint8Array;
  /** 48-byte compressed G1 point. */
  publicKey: Uint8Array;
}

/** Fresh key pair: a random scalar mod r and its G1 public key. */
export function keyGen(): BlsKeyPair {
  const secretKey = bls12_381.utils.randomPrivateKey();
  const publicKey = bls12_381.getPublicKey(secretKey);
  // A stuck-at-zero entropy source maps to the scalar 1 (public key = the group generator): a publicly
  // known "secret". Probability of this under a healthy RNG is ~2^-255.
  if (bytesToHex(publicKey) === bytesToHex(bls12_381.getPublicKey(Uint8Array.from([...new Array(31).fill(0), 1])))) {
    throw new Error('keyGen: entropy source produced the degenerate key 1 (RNG failure); refusing to continue');
  }
  return { secretKey, publicKey };
}

/** Public key (compressed G1) for a secret scalar. */
export function publicKeyOf(secretKey: Uint8Array): Uint8Array {
  return bls12_381.getPublicKey(secretKey);
}

/**
 * KeyValidate (draft §2.5): the public key decodes to a valid point, is NOT the identity, and lies
 * in the prime-order subgroup. A key that fails this is rejected everywhere before it can contribute
 * to an aggregate. Never throws.
 */
export function keyValidate(publicKey: Uint8Array): boolean {
  if (!isCompressed(publicKey, PUBLIC_KEY_LENGTH)) return false;
  try {
    const P = bls12_381.G1.ProjectivePoint.fromHex(publicKey);
    if (P.equals(bls12_381.G1.ProjectivePoint.ZERO)) return false;
    P.assertValidity();
    // noble does not reduce coordinates: x + p decodes to the same point. A second byte string for one signer would
    // defeat byte-keyed distinct-signer counting, so only the canonical encoding is a key.
    if (!sameBytes(P.toRawBytes(true), publicKey)) return false;
    return P.isTorsionFree();
  } catch {
    return false;
  }
}

/** CoreSign: H(msg) in G2 under the signature DST, multiplied by the secret scalar. */
export function sign(secretKey: Uint8Array, msg: Uint8Array): Uint8Array {
  return bls12_381.sign(msg, secretKey, SIG_OPTS);
}

/** CoreVerify of a single signature: e(pk, H(msg)) == e(g1, sig). Never throws. */
export function verify(publicKey: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  try {
    if (!isCanonicalSignature(sig)) return false;
    if (!keyValidate(publicKey)) return false;
    return bls12_381.verify(sig, msg, publicKey, SIG_OPTS);
  } catch {
    return false;
  }
}

/**
 * Aggregate: sum the G2 signature points into one 96-byte aggregate. Order-independent. Requires at
 * least one signature.
 */
export function aggregate(sigs: Uint8Array[]): Uint8Array {
  if (sigs.length === 0) throw new RangeError('aggregate: need at least one signature');
  for (const sg of sigs) if (!isCanonicalSignature(sg)) throw new RangeError('aggregate: every signature must be a 96-byte compressed G2 point');
  return bls12_381.aggregateSignatures(sigs);
}

/** Aggregate a set of G1 public keys into one 48-byte key (used by {@link fastAggregateVerify}). */
export function aggregatePublicKeys(publicKeys: Uint8Array[]): Uint8Array {
  if (publicKeys.length === 0) throw new RangeError('aggregatePublicKeys: need at least one key');
  return bls12_381.aggregatePublicKeys(publicKeys);
}

function hasDistinctMessages(msgs: Uint8Array[]): boolean {
  const seen = new Set<string>();
  for (const m of msgs) {
    const h = bytesToHex(m);
    if (seen.has(h)) return false;
    seen.add(h);
  }
  return true;
}

/**
 * AggregateVerify (draft §3.1.1) for DISTINCT messages: one pairing-product check that all N hops'
 * signatures are present in the aggregate — e(g1, aggSig) == Π e(pk_i, H(msg_i)).
 *
 * The draft REQUIRES the messages be pairwise distinct (same-message aggregation across different keys
 * must go through {@link fastAggregateVerify}); we enforce that as defence-in-depth even though PoP
 * already defeats the rogue-key attack. Every public key is KeyValidate'd first. Never throws; returns
 * `false` on length mismatch, a repeated message, a bad key, or a failed pairing check.
 */
export function aggregateVerify(publicKeys: Uint8Array[], msgs: Uint8Array[], aggSig: Uint8Array): boolean {
  try {
    if (!isCanonicalSignature(aggSig)) return false;
    if (publicKeys.length === 0 || publicKeys.length !== msgs.length) return false;
    if (!hasDistinctMessages(msgs)) return false;
    for (const pk of publicKeys) {
      if (!keyValidate(pk)) return false;
    }
    return bls12_381.verifyBatch(aggSig, msgs, publicKeys, SIG_OPTS);
  } catch {
    return false;
  }
}

/**
 * FastAggregateVerify (draft §3.3.4): all signers signed the SAME message. Aggregate the public keys
 * into one, then a single CoreVerify — e(g1, aggSig) == e(Σ pk_i, H(msg)). This is the surface for a
 * quorum of transparency witnesses cosigning one tree head. KeyValidate'd; never throws.
 */
export function fastAggregateVerify(publicKeys: Uint8Array[], msg: Uint8Array, aggSig: Uint8Array): boolean {
  try {
    if (!isCanonicalSignature(aggSig)) return false;
    if (publicKeys.length === 0) return false;
    for (const pk of publicKeys) {
      if (!keyValidate(pk)) return false;
    }
    const aggPk = bls12_381.aggregatePublicKeys(publicKeys);
    // KeyValidate the AGGREGATE too (draft §3.3.4 -> CoreVerify): keys {P, -P} each pass KeyValidate but
    // sum to the identity, for which the identity "signature" would verify over ANY message. (The pinned
    // noble-curves currently throws on that pairing; this makes the rejection explicit and version-proof.)
    if (!keyValidate(aggPk)) return false;
    return bls12_381.verify(aggSig, msg, aggPk, SIG_OPTS);
  } catch {
    return false;
  }
}

/**
 * PopProve (draft §3.3.2): sign one's OWN public key under the PoP DST. Only the holder of the secret
 * scalar can produce this, so a rogue key defined as a function of other keys cannot.
 */
export function popProve(secretKey: Uint8Array): Uint8Array {
  const pk = bls12_381.getPublicKey(secretKey);
  return bls12_381.sign(pk, secretKey, POP_OPTS);
}

/** PopVerify (draft §3.3.3): the proof-of-possession is a valid PoP-DST signature by `publicKey` over
 *  `publicKey`. A key must pass this before it is admitted to any aggregate. Never throws. */
export function popVerify(publicKey: Uint8Array, pop: Uint8Array): boolean {
  try {
    if (!isCanonicalSignature(pop)) return false;
    if (!keyValidate(publicKey)) return false;
    return bls12_381.verify(pop, publicKey, publicKey, POP_OPTS);
  } catch {
    return false;
  }
}
