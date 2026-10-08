import {
  G2_BASE,
  type G1Point,
  g1ToBytes,
  g2Mul,
  g2ToBytes,
  g2FromBytes,
  gtPow,
  gtToBytes,
  hashAttrToG1,
  kdf32,
  pairing,
  randomScalar,
} from './bls';

/**
 * Boneh-Franklin Identity-Based Encryption as a Key-Encapsulation Mechanism (BF-IBE KEM) on BLS12-381.
 *
 * Treat each ATTRIBUTE string as a BF "identity". For master secret `s` and public `P_pub = s * g2`:
 *   - the decryption key for attribute `A` is `d_A = s * H1(A)` in G1 (issued by `keygen`),
 *   - encapsulation to `A` picks a fresh ephemeral `x`, publishes `U = x * g2` in G2, and derives the
 *     shared GT secret `K_GT = e(H1(A), P_pub)^x = e(H1(A), g2)^{s*x}`,
 *   - decapsulation with `d_A` recomputes `K_GT = e(d_A, U) = e(s*H1(A), x*g2) = e(H1(A), g2)^{s*x}`.
 *
 * The two sides agree, and a holder WITHOUT `d_A` cannot compute `K_GT` without solving Bilinear
 * Diffie-Hellman. The GT secret is run through HKDF-SHA256 (modelled as a random oracle) to a 32-byte
 * symmetric key that masks the payload share.
 *
 * SECURITY: confidentiality holds under the Bilinear Diffie-Hellman assumption in the random-oracle
 * model (standard BF-IBE). This is NOT a proof of knowledge / NIZK: it binds confidentiality to
 * possession of attribute keys, not to an interactive or non-interactive proof.
 */

const KEM_KDF_INFO = 'atlas-pca-abe/kem/v1';

/** A per-leaf encapsulation: the ephemeral `U` (G2, compressed) that pins the derived KEM key. */
export interface Encapsulation {
  /** Compressed G2 ephemeral `U = x * g2`. */
  U: Uint8Array;
  /** 32-byte symmetric key derived from the GT secret (encryptor side). */
  key: Uint8Array;
}

/** Compute `P_pub = s * g2` (the master public element) for master secret `s`. */
export function masterPublic(s: bigint): Uint8Array {
  return g2ToBytes(g2Mul(G2_BASE, s));
}

/** Issue the BF decryption key `d_A = s * H1(A)` (G1, compressed) for attribute `A`. */
export function keygenAttr(s: bigint, attr: string): Uint8Array {
  const qA = hashAttrToG1(attr);
  return g1ToBytes(qA.multiply(s));
}

function kemKey(gtBytes: Uint8Array, salt: Uint8Array, attr: string, uBytes: Uint8Array): Uint8Array {
  // Bind the derived key to BOTH the attribute and the specific ephemeral so a key cannot be replayed
  // across attributes or ciphertexts even if (hypothetically) a GT value repeated.
  const info = `${KEM_KDF_INFO}|${attr}|${Buffer.from(uBytes).toString('base64url')}`;
  return kdf32(gtBytes, salt, info);
}

/**
 * Encapsulate to attribute `A` under master public `pPubBytes`. Returns the ephemeral `U` and the
 * 32-byte KEM key. `salt` is the ciphertext-wide HKDF salt (bound into every derived key). Returns null
 * only if `pPubBytes` is not a valid G2 point.
 */
export function encapsulate(pPubBytes: Uint8Array, attr: string, salt: Uint8Array): Encapsulation | null {
  const pPub = g2FromBytes(pPubBytes);
  if (pPub === null) return null;
  const qA = hashAttrToG1(attr);
  const x = randomScalar();
  const uBytes = g2ToBytes(g2Mul(G2_BASE, x));
  // K_GT = e(Q_A, P_pub)^x
  const kGt = gtPow(pairing(qA, pPub), x);
  const key = kemKey(gtToBytes(kGt), salt, attr, uBytes);
  return { U: uBytes, key };
}

/**
 * Decapsulate: recover the 32-byte KEM key from decryption key `dA` (G1) and ephemeral `uBytes` (G2).
 * Returns null (fail-closed) if either point is malformed. The attribute string must match the one used
 * at encapsulation (it is bound into the KDF).
 */
export function decapsulate(dA: G1Point, attr: string, uBytes: Uint8Array, salt: Uint8Array): Uint8Array | null {
  const U = g2FromBytes(uBytes);
  if (U === null) return null;
  // K_GT = e(d_A, U)
  const kGt = pairing(dA, U);
  return kemKey(gtToBytes(kGt), salt, attr, uBytes);
}
