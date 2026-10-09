/**
 * @atlasauth/pca-abe — proof-carrying encryption.
 *
 * Ciphertext-policy attribute/policy-based encryption on BLS12-381 (a Boneh-Franklin IBE KEM composed
 * over a monotone access structure by Shamir secret sharing, sealed with AES-256-GCM) so a tool payload
 * or result decrypts ONLY for a holder whose PCA capability satisfies the policy. See `abe.ts` for the
 * full construction and security property.
 */

export {
  ABE_ALG,
  PcaEncryptionError,
  setup,
  keygenForAttributes,
  keygenForCapability,
  encryptForPolicy,
  decrypt,
  decryptText,
  parseCiphertext,
  type MasterPublicKey,
  type MasterSecretKey,
  type DecryptionKey,
  type AbeCiphertext,
  type KemTree,
} from './abe';

export { encryptToolPayload, decryptWithCapability, type DecryptedPayload } from './pca';

export {
  normalizePolicy,
  satisfies,
  policyAttributes,
  MAX_POLICY_NODES,
  type Policy,
  type ThresholdTree,
  type PolicyResult,
} from './policy';

export { Attr, capabilityAttributes } from './attributes';
