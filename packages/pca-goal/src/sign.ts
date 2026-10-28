// sign.ts - the ONE signer of the goal-to-decision flow. GoalApproval, GoalTestSet, policy pins and precedents are all artifacts
// signed with the suite-agile signer of @atlasauth/pca (`signArtifact`: Ed25519, or a hybrid post-quantum suite via `suite`), under a
// per-kind domain, over STRICT canonical bytes (safe integers or short plain decimals; no exponents, NaN or Infinity). Nothing here rolls its own signature.
import { b64u, publicKeyOf, type SignerSuiteOpts } from '@atlasauth/pca';
import { artifactSuiteError, signArtifact, verifyArtifactSig, type PinnedSigner } from '@atlasauth/pca/ext/intent';

export type { PinnedSigner };
export type SignerSecret = Uint8Array;

/** Domain separation: an artifact of one kind never verifies as another kind. */
export const goalDomain = (kind: string): string => `atlas-pca/goal/${kind}/v1\0`;

/** The pinned public identity (b64u Ed25519) of a signer secret. */
export const signerId = (secret: SignerSecret): string => b64u(publicKeyOf(secret));

/** Sign a flat artifact body (it must already carry its signer identity member). Throws on a non-canonical body (e.g. an unsafe integer or NaN). */
export function signGoalArtifact<T extends Record<string, unknown>>(kind: string, body: T, secret: SignerSecret, suite?: SignerSuiteOpts): T & { sig: string } {
  return signArtifact(goalDomain(kind), body, secret, suite);
}

/** Verify a signed artifact against the caller's PINNED signers: the pin whose `pk` equals the artifact's own `signerField` member must verify. Total. */
export function verifyGoalArtifact(kind: string, artifact: unknown, signerField: string, pins: readonly (string | PinnedSigner)[]): boolean {
  try {
    if (artifact === null || typeof artifact !== 'object' || Array.isArray(artifact)) return false;
    const a = artifact as Record<string, unknown>;
    if (artifactSuiteError(a) !== null) return false;
    const who = a[signerField];
    if (typeof who !== 'string') return false;
    const pin = pins.find((p) => (typeof p === 'string' ? p : p.pk) === who);
    return pin !== undefined && verifyArtifactSig(goalDomain(kind), a, pin);
  } catch {
    return false;
  }
}

/** A payload wrapped with its kind and signer: the envelope used by tests, pins and precedents. */
export interface SignedPayload<T> extends Record<string, unknown> { v: 1; kind: string; signer: string; payload: T; sig: string; alg?: string; pq_pk?: string; pq_sig?: string }

export function signPayload<T>(kind: string, payload: T, secret: SignerSecret, suite?: SignerSuiteOpts): SignedPayload<T> {
  return signGoalArtifact(kind, { v: 1 as const, kind, signer: signerId(secret), payload }, secret, suite) as unknown as SignedPayload<T>;
}

export const verifyPayload = <T>(s: SignedPayload<T>, kind: string, pins: readonly (string | PinnedSigner)[]): boolean =>
  s !== null && typeof s === 'object' && s.v === 1 && s.kind === kind && verifyGoalArtifact(kind, s, 'signer', pins);
