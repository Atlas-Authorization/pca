/**
 * ORIGIN AUTHENTICATION for the encrypted risk claim.
 *
 * BFV gives confidentiality only. The encryption key is PUBLIC, so anyone who holds it (the evaluator, a
 * network attacker, a different agent) can mint a ciphertext that decrypts to any slack they like. Hiding
 * the inputs says nothing about WHO produced the ciphertext. This module adds that:
 *
 *  1. The encryptor (the principal / guardian, or whoever the key holder trusts to attest the inputs) signs
 *     the claim with Ed25519 (`@atlasauth/pca`, i.e. @noble/curves, strict RFC 8032 verification). The signed
 *     message is domain-separated (`atlas-pca-fhe/signed-claim/v1`) and covers: the grant/policy `context`,
 *     the action binding (aud, params digest, counter, nonce), a digest of the public gate policy, a digest
 *     of the ciphertext bytes, a fresh random nonce, and the signer's key.
 *  2. The evaluator calls {@link verifySignedRiskClaim} / {@link evalSignedRiskClaim} BEFORE touching the
 *     ciphertext. It refuses: an unsigned or malformed claim, a signer that is not pinned, a context /
 *     binding / policy different from what the evaluator expects, a ciphertext changed after signing, and
 *     (via a {@link NonceGuard}) a claim it has already seen.
 *  3. Optionally the key holder attests the decision back ({@link attestVerdict}): it signs `admit` bound to
 *     the signed claim and to the exact gate ciphertexts it decrypted, so a consumer can check that the
 *     decision came from the key holder for THIS claim, not from the evaluator or a replay.
 *
 * WHAT THIS BUYS: integrity and origin of the input ciphertext, and a binding of the decision to a claim.
 * It does NOT hide anything (context, binding, signer and policy are in the clear; the signature is over
 * the ciphertext, not under it).
 *
 * WHAT IT DOES NOT PREVENT:
 *  - A malicious EVALUATOR can still refuse or delay service, evaluate a different circuit and return wrong
 *    gate ciphertexts (the key holder decrypts a wrong number; BFV is not verifiable computation), observe
 *    the signed metadata and the ciphertext size, and replay a signed claim to a second evaluator that does
 *    not share its {@link NonceGuard}. Pair with an attested evaluator (TEE) or a verifiable-computation proof
 *    for those.
 *  - The SIGNER authenticates origin, not truth: a compromised or lying signer can sign a ciphertext of false
 *    or out-of-range inputs (values >= the plaintext modulus wrap), so the evaluator cannot range-check it.
 *  - A leaked signer key lets the holder of it mint accepted claims until the key is unpinned.
 */

import {
  type PCActn,
  b64u,
  canonicalBytes,
  decodeB64uStrict,
  hashCanonical,
  publicKeyOf,
  sha256,
  sign,
  utf8,
  verify,
} from '@atlasauth/pca';
import {
  type EncryptedGate,
  type EncryptedRiskClaim,
  type EvalKeys,
  type FheRiskPolicy,
  type RiskClaimBinding,
  type Verdict,
  bindingFromPCActn,
  encryptRiskInputs,
  evalRiskGate,
  quantizeRiskInputs,
  riskInputsFromPCActn,
} from './index';

const CLAIM_DOMAIN = 'atlas-pca-fhe/signed-claim/v1\0';
const VERDICT_DOMAIN = 'atlas-pca-fhe/verdict-attestation/v1\0';
const NONCE_BYTES = 16;
const MAX_CONTEXT_LEN = 512;

/** An encrypted risk claim, signed by its encryptor. The only claim form {@link evalSignedRiskClaim} accepts. */
export interface SignedRiskClaim {
  claim: EncryptedRiskClaim;
  /** Grant / policy context the claim is valid for (for example a grant id). The evaluator pins its own. */
  context: string;
  /** b64u, 16 random bytes: single use, tracked by the evaluator's {@link NonceGuard}. */
  nonce: string;
  /** b64u Ed25519 public key of the encryptor. */
  signer: string;
  /** b64u Ed25519 signature over the domain-separated claim statement. */
  sig: string;
}

const bytesDigest = (s: string): string => b64u(sha256(utf8(s)));

function claimStatement(c: { claim: EncryptedRiskClaim; context: string; nonce: string; signer: string }): Uint8Array {
  const body = canonicalBytes({
    v: 1,
    context: c.context,
    nonce: c.nonce,
    signer: c.signer,
    binding: c.claim.binding,
    policy: hashCanonical(c.claim.policy),
    enc_inputs: bytesDigest(c.claim.encInputs),
  });
  const p = utf8(CLAIM_DOMAIN);
  const m = new Uint8Array(p.length + body.length);
  m.set(p);
  m.set(body, p.length);
  return m;
}

/** Content address of a signed claim (signature included): what a verdict attestation binds to. */
export function signedClaimDigest(s: SignedRiskClaim): string {
  return hashCanonical(s);
}

/**
 * Sign an already-built encrypted claim. `signerSecretKey` is the encryptor's Ed25519 secret key; its public key
 * is embedded and must be pinned by the evaluator.
 */
export function signRiskClaim(args: { claim: EncryptedRiskClaim; signerSecretKey: Uint8Array; context: string }): SignedRiskClaim {
  if (typeof args.context !== 'string' || args.context.length === 0 || args.context.length > MAX_CONTEXT_LEN) {
    throw new Error(`context must be a non-empty string of at most ${MAX_CONTEXT_LEN} characters`);
  }
  const nonceBytes = new Uint8Array(NONCE_BYTES);
  globalThis.crypto.getRandomValues(nonceBytes);
  if (nonceBytes.every((b) => b === 0)) throw new Error('signRiskClaim: random source returned all zeros (RNG failure)');
  const signer = b64u(signerPublicKey(args.signerSecretKey));
  const body = { claim: args.claim, context: args.context, nonce: b64u(nonceBytes), signer };
  return { ...body, sig: b64u(sign(args.signerSecretKey, claimStatement(body))) };
}

function signerPublicKey(secretKey: Uint8Array): Uint8Array {
  if (!(secretKey instanceof Uint8Array) || secretKey.length !== 32) throw new Error('signing key must be a 32-byte Ed25519 secret key');
  return publicKeyOf(secretKey);
}

/**
 * Agent / encryptor side: read the PCActn's risk inputs, quantize, encrypt under the public key, bind the
 * ciphertext to the action, and SIGN it. The plaintext inputs never leave this call.
 */
export async function encryptedRiskClaim(args: {
  actn: PCActn;
  publicKey: string;
  policy: FheRiskPolicy;
  /** Ed25519 secret key of the encryptor (the principal / guardian the evaluator pins). */
  signerSecretKey: Uint8Array;
  /** Grant / policy context the evaluator will require. */
  context: string;
}): Promise<SignedRiskClaim> {
  if (args.policy === null || typeof args.policy !== 'object') throw new Error('policy must be an object');
  const inputs = riskInputsFromPCActn(args.actn);
  const scaled = quantizeRiskInputs(inputs, args.policy.scale);
  const encInputs = await encryptRiskInputs(args.publicKey, scaled);
  const claim: EncryptedRiskClaim = { binding: bindingFromPCActn(args.actn), encInputs, policy: args.policy };
  return signRiskClaim({ claim, signerSecretKey: args.signerSecretKey, context: args.context });
}

/** Single-use tracking for claim nonces. */
export interface NonceGuard {
  /** Record `key`; return `true` the first time, `false` if it was already used (or the guard cannot record it). */
  claim(key: string): boolean;
}

/**
 * In-memory {@link NonceGuard}. FAILS CLOSED when `maxEntries` is reached (it never evicts, because eviction
 * would re-open replay); the operator rotates the signer key or restarts with a persistent guard.
 */
export function memoryNonceGuard(maxEntries = 100_000): NonceGuard {
  const seen = new Set<string>();
  return {
    claim(key: string): boolean {
      if (seen.has(key) || seen.size >= maxEntries) return false;
      seen.add(key);
      return true;
    },
  };
}

/** What the evaluator expects, from its OWN view of the grant. Nothing here is taken from the claim. */
export interface ClaimExpectations {
  /** b64u Ed25519 keys of the encryptors the evaluator trusts. */
  trustedSigners: readonly string[];
  /** The grant / policy context this evaluation is for. */
  context: string;
  /** The action the claim must be bound to. */
  binding: RiskClaimBinding;
  /** The public gate policy the evaluator will run. */
  policy: FheRiskPolicy;
  /** Single-use nonces. */
  nonces: NonceGuard;
}

export type ClaimCheck = { ok: true; claim: EncryptedRiskClaim; digest: string } | { ok: false; reason: string };

const fail = (reason: string): { ok: false; reason: string } => ({ ok: false, reason });

/**
 * Verify a signed claim. Never throws. Order: shape, pinned signer, signature, context / binding / policy
 * equality, and only then the nonce is consumed (so unauthenticated junk cannot burn nonces).
 */
export function verifySignedRiskClaim(s: unknown, exp: ClaimExpectations): ClaimCheck {
  try {
    if (s === null || typeof s !== 'object' || Array.isArray(s)) return fail('claim is not signed: malformed envelope');
    const c = s as Partial<SignedRiskClaim>;
    if (
      typeof c.context !== 'string' ||
      typeof c.nonce !== 'string' ||
      typeof c.signer !== 'string' ||
      typeof c.sig !== 'string' ||
      c.claim === null ||
      typeof c.claim !== 'object' ||
      typeof c.claim.encInputs !== 'string' ||
      c.claim.binding === null ||
      typeof c.claim.binding !== 'object' ||
      c.claim.policy === null ||
      typeof c.claim.policy !== 'object'
    ) {
      return fail('claim is not signed: malformed envelope');
    }
    if (decodeB64uStrict(c.nonce, NONCE_BYTES) === null) return fail('malformed nonce');
    const signerBytes = decodeB64uStrict(c.signer, 32);
    const sigBytes = decodeB64uStrict(c.sig, 64);
    if (signerBytes === null || sigBytes === null) return fail('malformed signer key or signature');
    if (!exp.trustedSigners.includes(c.signer)) return fail('signer is not a trusted encryptor');
    const signed = { claim: c.claim, context: c.context, nonce: c.nonce, signer: c.signer };
    if (!verify(signerBytes, claimStatement(signed), sigBytes)) return fail('signature does not verify (ciphertext, binding, policy, context or nonce was altered, or wrong signer)');
    if (c.context !== exp.context) return fail('context mismatch: claim was signed for a different grant/policy');
    if (hashCanonical(c.claim.binding) !== hashCanonical(exp.binding)) return fail('binding mismatch: claim is bound to a different action');
    if (hashCanonical(c.claim.policy) !== hashCanonical(exp.policy)) return fail('policy mismatch: claim was signed for a different gate policy');
    if (!exp.nonces.claim(`${c.signer}:${c.nonce}`)) return fail('replay: nonce already used (or the replay window is full)');
    return { ok: true, claim: c.claim as EncryptedRiskClaim, digest: signedClaimDigest(c as SignedRiskClaim) };
  } catch {
    return fail('claim could not be verified (malformed)');
  }
}

export type SignedEval = { ok: true; gate: EncryptedGate; claimDigest: string } | { ok: false; reason: string };

/**
 * Evaluator: verify the signed claim, then run the gate. The ciphertext is not loaded into SEAL unless the
 * signature, signer, context, binding, policy and nonce all check out. The unsigned `evalRiskGate` remains as a
 * low-level primitive; the PCA claim path has no unsigned entry.
 */
export async function evalSignedRiskClaim(evalKeys: EvalKeys, signed: unknown, exp: ClaimExpectations): Promise<SignedEval> {
  const chk = verifySignedRiskClaim(signed, exp);
  if (!chk.ok) return chk;
  try {
    const gate = await evalRiskGate(evalKeys, chk.claim.encInputs, chk.claim.policy);
    return { ok: true, gate, claimDigest: chk.digest };
  } catch (e) {
    return fail(`evaluation failed: ${e instanceof Error ? e.message : 'unknown error'}`);
  }
}

// ---------------------------------------------------------------------------------------------
// Verdict attestation (the key holder signs the admit decision back).
// ---------------------------------------------------------------------------------------------

/** The key holder's signed admit/deny decision for one signed claim and one gate output. Reveals only `admit`. */
export interface VerdictAttestation {
  /** {@link signedClaimDigest} of the claim that was evaluated. */
  claimDigest: string;
  /** Digests of the exact gate ciphertexts the holder decrypted. */
  gateDigest: { encRiskRaw: string; encSlack: string };
  admit: boolean;
  /** b64u Ed25519 key of the key holder. */
  holder: string;
  sig: string;
}

function verdictStatement(a: Omit<VerdictAttestation, 'sig'>): Uint8Array {
  const body = canonicalBytes({ v: 1, claim: a.claimDigest, gate: a.gateDigest, admit: a.admit, holder: a.holder });
  const p = utf8(VERDICT_DOMAIN);
  const m = new Uint8Array(p.length + body.length);
  m.set(p);
  m.set(body, p.length);
  return m;
}

/**
 * Key-holder side, after `decryptVerdict`: sign the decision. `holderSecretKey` is the holder's Ed25519 signing
 * key (distinct from the FHE secret key). Only `admit` is signed, never `slack` or `r`, so the attestation can be
 * shown to a relying party without disclosing the risk.
 */
export function attestVerdict(args: { holderSecretKey: Uint8Array; signed: SignedRiskClaim; gate: EncryptedGate; verdict: Verdict }): VerdictAttestation {
  const body = {
    claimDigest: signedClaimDigest(args.signed),
    gateDigest: { encRiskRaw: bytesDigest(args.gate.encRiskRaw), encSlack: bytesDigest(args.gate.encSlack) },
    admit: args.verdict.admit,
    holder: b64u(signerPublicKey(args.holderSecretKey)),
  };
  return { ...body, sig: b64u(sign(args.holderSecretKey, verdictStatement(body))) };
}

/**
 * Relying-party side: the attestation is by a pinned holder, over exactly this claim and (optionally) this gate
 * output. Never throws. Returns the attested decision, or a refusal reason.
 */
export function verifyVerdictAttestation(
  a: unknown,
  exp: { trustedHolders: readonly string[]; claimDigest: string; gate?: EncryptedGate },
): { ok: true; admit: boolean } | { ok: false; reason: string } {
  try {
    if (a === null || typeof a !== 'object') return fail('malformed attestation');
    const x = a as Partial<VerdictAttestation>;
    if (
      typeof x.claimDigest !== 'string' ||
      typeof x.holder !== 'string' ||
      typeof x.sig !== 'string' ||
      typeof x.admit !== 'boolean' ||
      x.gateDigest === null ||
      typeof x.gateDigest !== 'object' ||
      typeof x.gateDigest.encRiskRaw !== 'string' ||
      typeof x.gateDigest.encSlack !== 'string'
    ) {
      return fail('malformed attestation');
    }
    if (!exp.trustedHolders.includes(x.holder)) return fail('attestation holder is not trusted');
    const holder = decodeB64uStrict(x.holder, 32);
    const sig = decodeB64uStrict(x.sig, 64);
    if (holder === null || sig === null) return fail('malformed holder key or signature');
    const body = { claimDigest: x.claimDigest, gateDigest: x.gateDigest, admit: x.admit, holder: x.holder };
    if (!verify(holder, verdictStatement(body), sig)) return fail('attestation signature does not verify');
    if (x.claimDigest !== exp.claimDigest) return fail('attestation is for a different claim');
    if (exp.gate !== undefined) {
      if (x.gateDigest.encRiskRaw !== bytesDigest(exp.gate.encRiskRaw) || x.gateDigest.encSlack !== bytesDigest(exp.gate.encSlack)) {
        return fail('attestation is for a different gate output');
      }
    }
    return { ok: true, admit: x.admit };
  } catch {
    return fail('attestation could not be verified (malformed)');
  }
}
