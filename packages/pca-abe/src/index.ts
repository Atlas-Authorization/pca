/**
 * @atlasauth/pca-abe — proof-carrying encryption.
 *
 * Collusion-resistant ciphertext-policy attribute-based encryption on BLS12-381 (the FAME scheme of Agrawal and Chase,
 * CCS 2017, adaptively secure in the type-3 setting; Shamir access tree as a span program; AES-256-GCM) so a
 * tool payload or result decrypts ONLY for a holder whose PCA capability satisfies the policy. See `abe.ts` for the
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
  type AttributeKey,
} from './abe';

export { encryptToolPayload, decryptWithCapability, type DecryptedPayload } from './pca';

export {
  normalizePolicy,
  satisfies,
  policyAttributes,
  MAX_POLICY_NODES,
  MAX_POLICY_DEPTH,
  type Policy,
  type ThresholdTree,
  type PolicyResult,
} from './policy';

export { Attr, capabilityAttributes, type CapabilityAttributeOpts } from './attributes';
