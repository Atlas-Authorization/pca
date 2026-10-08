import {
  type AbeCiphertext,
  type DecryptionKey,
  type MasterPublicKey,
  decrypt,
  encryptForPolicy,
} from './abe';
import type { Policy } from './policy';

/**
 * PCA integration: proof-carrying encryption for tool payloads and results.
 *
 * A tool result is sealed under an ACCESS STRUCTURE over the SAME canonical attributes a PCA capability
 * carries (verb / resource / scope / holder — see `attributes.ts`). Only an agent holding a decryption
 * key issued (via `keygenForCapability`) for a capability whose authority SATISFIES that structure can
 * read the payload. Confidentiality is thus bound to proven authority, not merely to a bearer key.
 *
 * HOW THIS COMPOSES WITH A PCActn
 *   A PCActn proves, to a resource server, that the agent's capability chain authorises a specific
 *   action (verb/resource under the signed policy envelope). The ABE decryption key handed to that agent
 *   is derived from the very SAME capability (`keygenForCapability(msk, capability)`). So:
 *
 *     1. The principal mints a capability (grant/attenuation) bounding the agent's authority.
 *     2. The issuer derives an ABE key from that capability and gives it to the agent.
 *     3. A tool/result is encrypted with `encryptToolPayload(mpk, policy, payload)`, where `policy`
 *        restates the authority required to read it (e.g. "holder X AND verb:read on this resource").
 *     4. The agent proves the action with a PCActn (the server verifies the chain + predicates), AND can
 *        decrypt the payload ONLY because its capability-derived key satisfies the same policy.
 *
 *   The decrypt gate and the PCActn admission gate are therefore keyed to ONE authority: an agent that
 *   cannot prove the action also cannot have been issued a key that decrypts its payload, because both
 *   derive from the same signed capability. Encryption adds CONFIDENTIALITY (a passive observer, or a
 *   holder of a different/weaker capability, learns nothing) on top of the PCActn's AUTHORISATION.
 *
 * SECURITY: as in `abe.ts` — confidentiality under Bilinear Diffie-Hellman (ROM), integrity under
 * AES-256-GCM. Not a NIZK; collusion resistance is within a single issued key (one key per capability).
 */

/** Result of a payload decryption attempt. `ok:false` means the key's authority did not satisfy the policy (or the ciphertext was tampered/malformed). */
export type DecryptedPayload = { ok: true; payload: unknown } | { ok: false; reason: string };

/**
 * Encrypt a JSON-serialisable tool payload/result under `requiredCapabilityPolicy` — an access
 * structure over capability attributes. Only a capability-derived key satisfying the policy can decrypt.
 */
export function encryptToolPayload(
  mpk: MasterPublicKey,
  requiredCapabilityPolicy: Policy,
  payload: unknown,
): { ciphertext: AbeCiphertext } {
  const json = JSON.stringify(payload ?? null);
  return encryptForPolicy(mpk, requiredCapabilityPolicy, json);
}

/**
 * Decrypt a tool payload with a capability-derived key. Returns the parsed payload iff the key's
 * authority satisfies the policy and the AEAD authenticates; otherwise a typed failure.
 */
export function decryptWithCapability(key: DecryptionKey, ciphertext: unknown): DecryptedPayload {
  const pt = decrypt(key, ciphertext);
  if (pt === null) return { ok: false, reason: 'capability does not satisfy the policy, or ciphertext is invalid' };
  try {
    return { ok: true, payload: JSON.parse(new TextDecoder().decode(pt)) as unknown };
  } catch {
    return { ok: false, reason: 'decrypted payload is not valid JSON' };
  }
}
