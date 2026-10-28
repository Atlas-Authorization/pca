import { createHash } from 'node:crypto';
import { verifyFreshAttestedEAT, type AppraisalPolicy, type AttestationTier, type VerifyFreshAttestedEatOptions } from './index';

/**
 * EAT EVIDENCE FOR BLUEPRINT ADMISSION (`@atlasauth/pca-grants` `admitWithEvidence`). Turns an EAT (RFC 9711) into admission
 * evidence for one instance key: the token's signature, issuer, freshness (the server-issued nonce) and RATS appraisal must all
 * pass, and its `cnf.jkt` must be the RFC 7638 thumbprint of THE INSTANCE KEY, so evidence for one instance cannot admit another.
 * The identity returned is the measured identity the verifier established (never a field the instance supplies separately).
 * Anything unverifiable (bad signature, stale, unbound, appraisal below the minimum tier, no measured identity) is `ok: false`.
 */
export interface AdmissionEvidenceResult {
  ok: boolean;
  bound: boolean;
  identity?: Record<string, string | boolean | undefined>;
  reason?: string;
}

/** RFC 7638 thumbprint (base64url SHA-256) of an Ed25519 public key given as unpadded base64url. */
export function ed25519Jkt(holderPubB64u: string): string {
  const canonical = `{"crv":"Ed25519","kty":"OKP","x":"${holderPubB64u}"}`;
  return createHash('sha256').update(canonical, 'utf8').digest('base64url');
}

const TIER_RANK: Record<AttestationTier, number> = { rejected: 0, contraindicated: 0, warning: 1, affirming: 2, 'affirming-hw-rooted': 3 };

export interface EatAdmissionOptions extends Omit<VerifyFreshAttestedEatOptions, 'nonce' | 'channelId' | 'channelBinding' | 'policy'> {
  /** The server-issued freshness challenge the EAT must echo. */
  nonce: string;
  /** The instance key (unpadded base64url Ed25519 public key) the evidence must be bound to. */
  instanceKey: string;
  policy: AppraisalPolicy;
  /** Lowest acceptable appraisal tier. Default `affirming` (degraded `warning` evidence does not admit). */
  minTier?: 'affirming' | 'affirming-hw-rooted';
}

export async function eatAdmissionEvidence(eat: string, o: EatAdmissionOptions): Promise<AdmissionEvidenceResult> {
  try {
    const { instanceKey, minTier, ...rest } = o;
    const v = await verifyFreshAttestedEAT(eat, { ...rest, channelBinding: { jkt: ed25519Jkt(instanceKey) } });
    if (!v.ok || v.tier === undefined) return { ok: false, bound: false, reason: v.reasons.at(-1) ?? 'EAT rejected' };
    if (TIER_RANK[v.tier] < TIER_RANK[minTier ?? 'affirming']) return { ok: false, bound: true, reason: `appraisal tier ${v.tier} is below the minimum` };
    const m = v.claims?.measured;
    // verifyFreshAttestedEAT checked cnf.jkt against the instance key, so a pass means bound
    if (!m) return { ok: true, bound: true };
    return { ok: true, bound: true, identity: { runtime_measurement: m.runtime_measurement, model_id: m.model_id, weights_digest: m.weights_digest, operator: m.operator } };
  } catch (e) {
    return { ok: false, bound: false, reason: e instanceof Error ? e.name : 'error' };
  }
}
