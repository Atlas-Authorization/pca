import { decodeKey, encodeKey, encodeSig, hashCanonical, sign, verifyB64u, canonicalBytesStrict } from '@atlasauth/pca';
import type { VerifyContext } from '@atlasauth/pca';
import type { AttestationDocument, ExpectedAttestationBinding, HardwareAttestationVerifier } from '@atlasauth/pca/ext/attestation';
import { RUNTIME_CLASSES, type RuntimeClass } from './receipts';

/**
 * A signed statement that a sandbox instance runs at `class`, bound to the signed passport (by digest) of the agent it
 * contains. The signer is an attestor the verifier pins (a platform or attestation key); an operator saying so is not
 * enough. Anything that does not verify is treated as `none`.
 */
export interface RuntimeClaim {
  v: 1;
  class: RuntimeClass;
  /** hashCanonical of the signed passport this claim is about. */
  passport_digest: string;
  /** Digest of the evidence the attestor looked at (attestation quote, profile hash), opaque here. */
  evidence_digest: string;
  iat: number;
  exp: number;
  /** base64url Ed25519 public key of the attestor. */
  attestor: string;
  sig: string;
}

/** Signed bytes: `domain || canonical(claim without sig)`, the same construction as the other signed records (blueprints, fresh-at). */
export const RUNTIME_CLAIM_DOMAIN = 'atlas-pca/runtime-class-claim/v1\0';
const KEYS = ['v', 'class', 'passport_digest', 'evidence_digest', 'iat', 'exp', 'attestor', 'sig'];
const body = (c: Omit<RuntimeClaim, 'sig'>) => {
  const d = new TextEncoder().encode(RUNTIME_CLAIM_DOMAIN);
  const b = canonicalBytesStrict(c);
  return Uint8Array.from([...d, ...b]);
};

export function signRuntimeClaim(secretKey: Uint8Array, publicKey: Uint8Array, c: Omit<RuntimeClaim, 'v' | 'sig' | 'attestor'>): RuntimeClaim {
  const unsigned = { v: 1 as const, ...c, attestor: encodeKey(publicKey) };
  return { ...unsigned, sig: encodeSig(sign(secretKey, body(unsigned))) };
}

export interface ClaimTrust {
  /** base64url attestor public keys the verifier pins. */
  pinnedAttestors: readonly string[];
  /** hashCanonical of the signed passport the claim must be about. */
  passportDigest: string;
  /**
   * Digests of evidence the caller has already verified with an attestation verifier (see {@link trustFromAttestation}). A claim
   * is valid only if its `evidence_digest` is in this list: a signature by a pinned attestor over evidence nobody verified proves nothing.
   */
  verifiedEvidenceDigests: readonly string[];
  now: number;
}

/** The class the claim proves, or `none` for anything missing, unsigned, unpinned, expired, for another passport or malformed. */
export function verifiedRuntimeClass(claim: unknown, trust: ClaimTrust): RuntimeClass {
  try {
    const c = claim as RuntimeClaim;
    if (!c || typeof c !== 'object' || Object.keys(c).length !== KEYS.length || !Object.keys(c).every((k) => KEYS.includes(k))) return 'none';
    if (c.v !== 1 || !(RUNTIME_CLASSES as readonly string[]).includes(c.class)) return 'none';
    if (typeof c.sig !== 'string' || typeof c.attestor !== 'string' || !trust.pinnedAttestors.includes(c.attestor)) return 'none';
    if (c.passport_digest !== trust.passportDigest || !Number.isInteger(c.iat) || !Number.isInteger(c.exp) || !Number.isInteger(trust.now) || trust.now < c.iat || trust.now >= c.exp) return 'none';
    if (typeof c.evidence_digest !== 'string' || !trust.verifiedEvidenceDigests.includes(c.evidence_digest) || typeof c.passport_digest !== 'string' || decodeKey(c.attestor).length !== 32) return 'none';
    const { sig, ...rest } = c;
    return verifyB64u(c.attestor, body(rest), sig) ? c.class : 'none';
  } catch {
    return 'none';
  }
}

export const passportDigest = (signedPassport: unknown): string => hashCanonical(signedPassport);

/** The digest a claim's `evidence_digest` must equal for this attestation document. */
export const evidenceDigest = (document: AttestationDocument): string => hashCanonical(document);

/**
 * Run an existing hardware attestation verifier over the evidence; only if it says `ok` and `bound` is the evidence's digest
 * admitted into the trust. Anything else (a throw, a malformed answer, not bound) leaves the list empty, so every claim is `none`.
 */
export async function trustFromAttestation(o: {
  document: AttestationDocument;
  verifier: HardwareAttestationVerifier;
  ctx: VerifyContext;
  expected: ExpectedAttestationBinding;
  nowMs: number;
  pinnedAttestors: readonly string[];
  passportDigest: string;
}): Promise<ClaimTrust> {
  let ok = false;
  try {
    const h = await o.verifier.verify({ document: o.document, ctx: o.ctx, nowMs: o.nowMs, expected: o.expected });
    ok = h?.ok === true && h?.bound === true;
  } catch {
    ok = false;
  }
  return { pinnedAttestors: o.pinnedAttestors, passportDigest: o.passportDigest, verifiedEvidenceDigests: ok ? [evidenceDigest(o.document)] : [], now: o.nowMs };
}
