import { canonicalBytes, type Capability } from '@atlasauth/pca';
import { bytesToScalar, scalarToBytes, g1FromBytes, type G1Point, kdf32 } from './bls';
import { decapsulate, encapsulate, keygenAttr, masterPublic } from './ibe';
import { open, seal } from './aead';
import { recoverSecret, randomSecret, splitSecret, type Share } from './sss';
import { capabilityAttributes } from './attributes';
import { normalizePolicy, type Policy, type ThresholdTree } from './policy';
import { b64u, isObject, isPosInt, isString, unb64u, xorBytes } from './wire';
import { randomBytes } from '@noble/hashes/utils';

/**
 * Proof-carrying encryption: Ciphertext-Policy attribute/policy-based encryption built from a
 * Boneh-Franklin IBE KEM on BLS12-381, composed over a monotone access structure by Shamir
 * secret-sharing (an LSSS), sealing the payload with AES-256-GCM.
 *
 * CONSTRUCTION
 *   setup()             -> master key pair (s, P_pub = s*g2).
 *   keygen(attrs)       -> one BF decryption key d_A = s*H1(A) per attribute A the holder owns.
 *   encrypt(policy, m)  -> pick a random root secret S; share it down the policy's threshold tree with
 *                          Shamir (AND = n-of-n, OR = 1-of-n, threshold = k-of-n); at each leaf attribute
 *                          A, BF-encapsulate a fresh KEM key and XOR-mask that leaf's assigned share.
 *                          The content-encryption key is HKDF(S); the payload is AES-256-GCM sealed with
 *                          the whole KEM header as AAD.
 *   decrypt(key, ct)    -> at every leaf the key owns, decapsulate -> unmask that share; interpolate each
 *                          gate once >= t shares are recovered; recover S iff the key's attribute set
 *                          satisfies the policy; derive the CEK and open the AEAD. Else fail (null).
 *
 * SECURITY PROPERTY (honest)
 *   Confidentiality holds under the Bilinear Diffie-Hellman assumption on BLS12-381 in the random-oracle
 *   model (standard BF-IBE), and the Shamir sharing is information-theoretic (fewer than `t` shares of a
 *   gate reveal nothing about its secret). A holder whose attribute set does NOT satisfy the policy
 *   cannot recover enough shares to reconstruct S and therefore cannot derive the CEK. Payload and header
 *   integrity are guaranteed by AES-256-GCM.
 *
 *   This is NOT a proof-of-knowledge / NIZK: it binds confidentiality to POSSESSION of capability-derived
 *   attribute keys, not to a verified proof. Like any IBE-KEM-composed access structure (as opposed to a
 *   single monolithic CP-ABE with per-key randomisation), it is collusion-resistant only within a single
 *   issued key: two SEPARATELY issued keys under the same master, each holding part of the required
 *   attributes, could in principle pool their attribute keys. Atlas issues exactly one key per capability
 *   (`keygenForCapability`), and decryption is evaluated against that one key's attribute set — so the
 *   enforced statement is precisely "this capability's authority satisfies the policy".
 */

export const ABE_ALG = 'bf-ibe-bls12381/lsss/aes-256-gcm';
const CEK_INFO = 'atlas-pca-abe/cek/v1';
const SALT_LEN = 16;

// ---- key material -----------------------------------------------------------------------------

export interface MasterPublicKey {
  v: 1;
  curve: 'bls12-381';
  /** b64u compressed G2 point `P_pub = s * g2`. */
  pPub: string;
}

export interface MasterSecretKey {
  v: 1;
  curve: 'bls12-381';
  /** b64u 32-byte master secret scalar `s`. */
  s: string;
}

export interface DecryptionKey {
  v: 1;
  curve: 'bls12-381';
  /** The capability's bound holder key, when issued from a capability (informational). */
  holder?: string;
  /** attribute token -> b64u compressed G1 decryption key `d_A = s * H1(A)`. */
  attrs: Record<string, string>;
}

// ---- ciphertext wire format -------------------------------------------------------------------

/** The KEM header: the access structure realised as a tree of per-leaf encapsulations. */
export type KemTree =
  | { kind: 'leaf'; attr: string; U: string; wrap: string }
  | { kind: 'gate'; t: number; of: { i: number; sub: KemTree }[] };

export interface AbeCiphertext {
  v: 1;
  alg: typeof ABE_ALG;
  /** b64u HKDF salt (16 bytes) bound into every derived key and the CEK. */
  salt: string;
  /** The share-distribution tree (also the authenticated access structure). */
  kem: KemTree;
  /** b64u AES-256-GCM IV (12 bytes). */
  iv: string;
  /** b64u AES-256-GCM ciphertext. */
  ct: string;
  /** b64u AES-256-GCM tag (16 bytes). */
  tag: string;
}

export class PcaEncryptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PcaEncryptionError';
  }
}

// ---- setup / keygen ---------------------------------------------------------------------------

/** Generate a fresh master key pair. */
export function setup(): { mpk: MasterPublicKey; msk: MasterSecretKey } {
  const { scalar, bytes } = randomSecret();
  return {
    msk: { v: 1, curve: 'bls12-381', s: b64u(bytes) },
    mpk: { v: 1, curve: 'bls12-381', pPub: b64u(masterPublic(scalar)) },
  };
}

function mskScalar(msk: MasterSecretKey): bigint {
  const bytes = unb64u(msk?.s);
  const s = bytes === null ? null : bytesToScalar(bytes);
  if (s === null || s === 0n) throw new PcaEncryptionError('invalid master secret key');
  return s;
}

/** Issue a decryption key for an explicit set of attribute tokens. */
export function keygenForAttributes(msk: MasterSecretKey, attrs: Iterable<string>): DecryptionKey {
  const s = mskScalar(msk);
  const out: Record<string, string> = {};
  for (const a of attrs) {
    if (typeof a === 'string' && a.length > 0) out[a] = b64u(keygenAttr(s, a));
  }
  return { v: 1, curve: 'bls12-381', attrs: out };
}

/**
 * Issue a decryption key BOUND to a PCA capability: its attributes are exactly those the (signed)
 * capability carries — holder, and the verbs/resources/scopes of its policy envelope — optionally
 * extended with explicit extra tokens. The key can decrypt only ciphertexts whose policy is satisfied
 * by this capability's authority.
 */
export function keygenForCapability(
  msk: MasterSecretKey,
  capability: Capability,
  extraAttributes: Iterable<string> = [],
): DecryptionKey {
  const attrs = capabilityAttributes(capability);
  for (const a of extraAttributes) if (typeof a === 'string' && a.length > 0) attrs.add(a);
  const key = keygenForAttributes(msk, attrs);
  if (typeof capability.holder === 'string') key.holder = capability.holder;
  return key;
}

// ---- encrypt ----------------------------------------------------------------------------------

function distribute(
  mpkPub: Uint8Array,
  node: ThresholdTree,
  nodeSecret: bigint,
  salt: Uint8Array,
): KemTree {
  if (node.kind === 'leaf') {
    const enc = encapsulate(mpkPub, node.attr, salt);
    if (enc === null) throw new PcaEncryptionError('invalid master public key');
    const wrap = xorBytes(scalarToBytes(nodeSecret), enc.key);
    if (wrap === null) throw new PcaEncryptionError('internal: wrap length mismatch');
    return { kind: 'leaf', attr: node.attr, U: b64u(enc.U), wrap: b64u(wrap) };
  }
  const shares: Share[] = splitSecret(nodeSecret, node.t, node.of.length);
  const of: { i: number; sub: KemTree }[] = [];
  for (let idx = 0; idx < node.of.length; idx++) {
    const child = node.of[idx];
    const share = shares[idx];
    if (child === undefined || share === undefined) throw new PcaEncryptionError('internal: share/child mismatch');
    of.push({ i: Number(share.x), sub: distribute(mpkPub, child, share.y, salt) });
  }
  return { kind: 'gate', t: node.t, of };
}

function aad(c: Pick<AbeCiphertext, 'v' | 'alg' | 'salt' | 'kem'>): Uint8Array {
  return canonicalBytes({ v: c.v, alg: c.alg, salt: c.salt, kem: c.kem });
}

/**
 * Encrypt `plaintext` so that it decrypts only for a holder whose attribute set satisfies `policy`.
 * Throws {@link PcaEncryptionError} on an invalid policy or master public key.
 */
export function encryptForPolicy(
  mpk: MasterPublicKey,
  policy: Policy,
  plaintext: Uint8Array | string,
): { ciphertext: AbeCiphertext } {
  const norm = normalizePolicy(policy);
  if (!norm.ok) throw new PcaEncryptionError(`invalid policy: ${norm.reason}`);
  const mpkPub = unb64u(mpk?.pPub);
  if (mpkPub === null) throw new PcaEncryptionError('invalid master public key');

  const salt = new Uint8Array(randomBytes(SALT_LEN));
  const { scalar: rootSecret, bytes: rootBytes } = randomSecret();
  const kem = distribute(mpkPub, norm.tree, rootSecret, salt);

  const header: Pick<AbeCiphertext, 'v' | 'alg' | 'salt' | 'kem'> = { v: 1, alg: ABE_ALG, salt: b64u(salt), kem };
  const cek = kdf32(rootBytes, salt, CEK_INFO);
  const pt = typeof plaintext === 'string' ? new TextEncoder().encode(plaintext) : plaintext;
  const sealed = seal(cek, pt, aad(header));

  return {
    ciphertext: { ...header, iv: b64u(sealed.iv), ct: b64u(sealed.ct), tag: b64u(sealed.tag) },
  };
}

// ---- decrypt ----------------------------------------------------------------------------------

function parseKemTree(x: unknown, depth: number): KemTree | null {
  if (depth > 64 || !isObject(x)) return null;
  if (x.kind === 'leaf') {
    if (!isString(x.attr) || !isString(x.U) || !isString(x.wrap)) return null;
    if (unb64u(x.U) === null || unb64u(x.wrap) === null) return null;
    return { kind: 'leaf', attr: x.attr, U: x.U, wrap: x.wrap };
  }
  if (x.kind === 'gate') {
    if (!isPosInt(x.t) || !Array.isArray(x.of) || x.of.length === 0) return null;
    if (x.t > x.of.length) return null;
    const of: { i: number; sub: KemTree }[] = [];
    for (const branch of x.of) {
      if (!isObject(branch) || !isPosInt(branch.i)) return null;
      const sub = parseKemTree(branch.sub, depth + 1);
      if (sub === null) return null;
      of.push({ i: branch.i, sub });
    }
    return { kind: 'gate', t: x.t, of };
  }
  return null;
}

/** Validate an untrusted value as an {@link AbeCiphertext}; null (fail-closed) on any deviation. */
export function parseCiphertext(x: unknown): AbeCiphertext | null {
  if (!isObject(x) || x.v !== 1 || x.alg !== ABE_ALG) return null;
  if (!isString(x.salt) || !isString(x.iv) || !isString(x.ct) || !isString(x.tag)) return null;
  if (unb64u(x.salt) === null || unb64u(x.iv) === null || unb64u(x.ct) === null || unb64u(x.tag) === null) return null;
  const kem = parseKemTree(x.kem, 0);
  if (kem === null) return null;
  return { v: 1, alg: ABE_ALG, salt: x.salt, kem, iv: x.iv, ct: x.ct, tag: x.tag };
}

function recover(
  node: KemTree,
  keys: ReadonlyMap<string, G1Point>,
  salt: Uint8Array,
): bigint | null {
  if (node.kind === 'leaf') {
    const dA = keys.get(node.attr);
    if (dA === undefined) return null; // the key does not own this attribute: nothing to recover here.
    const uBytes = unb64u(node.U);
    const wrapBytes = unb64u(node.wrap);
    if (uBytes === null || wrapBytes === null) return null;
    const kemKey = decapsulate(dA, node.attr, uBytes, salt);
    if (kemKey === null) return null;
    const shareBytes = xorBytes(wrapBytes, kemKey);
    if (shareBytes === null) return null;
    return bytesToScalar(shareBytes);
  }
  const shares: Share[] = [];
  for (const branch of node.of) {
    const y = recover(branch.sub, keys, salt);
    if (y !== null) shares.push({ x: BigInt(branch.i), y });
    if (shares.length >= node.t) break; // enough branches recovered; no need to decrypt more.
  }
  if (shares.length < node.t) return null;
  return recoverSecret(shares);
}

/**
 * Decrypt. Returns the plaintext iff the key's attribute set satisfies the ciphertext's policy AND the
 * AEAD authenticates; otherwise returns null (never throws). A key missing a required attribute cannot
 * recover the root secret and therefore cannot derive the content-encryption key.
 */
export function decrypt(key: DecryptionKey, ciphertext: unknown): Uint8Array | null {
  const ct = parseCiphertext(ciphertext);
  if (ct === null) return null;
  if (!isObject(key) || !isObject(key.attrs)) return null;

  const salt = unb64u(ct.salt);
  const iv = unb64u(ct.iv);
  const body = unb64u(ct.ct);
  const tag = unb64u(ct.tag);
  if (salt === null || iv === null || body === null || tag === null) return null;

  // Decode the attribute decryption keys we hold (skip any malformed point: fail-closed per attribute).
  const keys = new Map<string, G1Point>();
  for (const [attr, enc] of Object.entries(key.attrs)) {
    const bytes = unb64u(enc);
    if (bytes === null) continue;
    const pt = g1FromBytes(bytes);
    if (pt !== null) keys.set(attr, pt);
  }

  const rootSecret = recover(ct.kem, keys, salt);
  if (rootSecret === null) return null; // attribute set does not satisfy the policy.

  const cek = kdf32(scalarToBytes(rootSecret), salt, CEK_INFO);
  // The AEAD is the final integrity gate: a wrong reconstructed secret (cross-master key / tamper) or a
  // tampered payload/header yields a null here.
  return open(cek, { iv, ct: body, tag }, aad(ct));
}

/** Like {@link decrypt} but returns the plaintext decoded as UTF-8 text, or null. */
export function decryptText(key: DecryptionKey, ciphertext: unknown): string | null {
  const pt = decrypt(key, ciphertext);
  return pt === null ? null : new TextDecoder().decode(pt);
}
