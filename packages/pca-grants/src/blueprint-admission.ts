import type { VerifyContext } from '@atlasauth/pca';
import type {
  ExpectedAttestationBinding,
  HardwareAttestationVerifier,
  AttestationDocument,
  MeasuredIdentity,
} from '@atlasauth/pca/ext/attestation';
import type { AgentBlueprint, RuntimePin } from './blueprint';

/**
 * ATTESTATION-GATED BLUEPRINT ADMISSION. A blueprint with `runtime_pins` admits an instance key only after hardware evidence
 * for that key was verified by one of the existing attestation verifiers (AMD SEV-SNP, Intel TDX, Azure Attestation, Google
 * Confidential Space, NVIDIA; or the multi-root verifier) and the MEASURED identity matched a pin. Anything that cannot be
 * verified is a deny: no evidence, a verifier that throws, `ok` false, evidence not bound to the expected holder/grant/nonce,
 * no measured identity, or no matching pin. The identity compared is the verifier's measurement, never the document's own claims.
 *
 * Admissions are held by instance key, blueprint key and the blueprint EPOCH they were made under, so a group kill or any new
 * record invalidates them; they also expire.
 */
export type AdmissionCode = 'no_pins' | 'verifier_error' | 'not_ok' | 'not_bound' | 'no_identity' | 'no_matching_pin';
export type AdmissionResult = { admitted: true; identity: MeasuredIdentity | Record<string, unknown>; pin: RuntimePin } | { admitted: false; code: AdmissionCode; reason?: string };

const pinMatches = (pin: RuntimePin, id: Record<string, unknown>): boolean =>
  Object.entries(pin).every(([k, v]) => v !== undefined && id[k] === v) && Object.keys(pin).length > 0;

/**
 * What an evidence adapter (EAT, SPIFFE, a hardware verifier) reports about an instance. `ok` and `bound` must both be exactly
 * true: `bound` means the evidence was tied to THIS instance key (and the freshness challenge), not merely genuine. `identity` holds
 * what the adapter itself established (measured values, the verified SPIFFE ID), never what the instance claims.
 */
export interface AdmissionEvidence {
  ok: boolean;
  bound: boolean;
  identity?: Record<string, string | boolean | undefined>;
  reason?: string;
}

/** Admit from adapter evidence: the generic core of {@link admitBlueprintInstance}. A thrown error or malformed result denies. */
export async function admitWithEvidence(blueprint: AgentBlueprint, getEvidence: () => AdmissionEvidence | Promise<AdmissionEvidence>): Promise<
  { admitted: true; identity: Record<string, unknown>; pin: RuntimePin } | { admitted: false; code: AdmissionCode; reason?: string }
> {
  const pins = blueprint.runtime_pins;
  if (pins === undefined || pins.length === 0) return { admitted: false, code: 'no_pins' };
  let r: AdmissionEvidence;
  try {
    r = await getEvidence();
  } catch (e) {
    return { admitted: false, code: 'verifier_error', reason: e instanceof Error ? e.name : 'error' };
  }
  if (r?.ok !== true) return { admitted: false, code: 'not_ok', ...(typeof r?.reason === 'string' ? { reason: r.reason } : {}) };
  if (r.bound !== true) return { admitted: false, code: 'not_bound' };
  if (r.identity === undefined || r.identity === null || typeof r.identity !== 'object') return { admitted: false, code: 'no_identity' };
  const id = r.identity as Record<string, unknown>;
  const pin = pins.find((p) => pinMatches(p, id));
  return pin ? { admitted: true, identity: id, pin } : { admitted: false, code: 'no_matching_pin' };
}

export async function admitBlueprintInstance(o: {
  blueprint: AgentBlueprint;
  document: AttestationDocument | undefined;
  verifier: HardwareAttestationVerifier;
  ctx: VerifyContext;
  expected: ExpectedAttestationBinding;
  nowMs: number;
}): Promise<AdmissionResult> {
  if (o.blueprint.runtime_pins === undefined || o.blueprint.runtime_pins.length === 0) return { admitted: false, code: 'no_pins' };
  if (o.document === undefined || o.document === null) return { admitted: false, code: 'not_ok', reason: 'no evidence' };
  const r = await admitWithEvidence(o.blueprint, async () => {
    const h = await o.verifier.verify({ document: o.document as AttestationDocument, ctx: o.ctx, nowMs: o.nowMs, expected: o.expected });
    return { ok: h?.ok === true, bound: h?.bound === true, ...(h?.measured ? { identity: h.measured as unknown as Record<string, string> } : {}), ...(typeof h?.reason === 'string' ? { reason: h.reason } : {}) };
  });
  return r as AdmissionResult;
}

/** Holds admissions; plug `admitted` into `checkBlueprints`. */
export class AdmissionRegistry {
  private readonly m = new Map<string, { epoch: number; until: number }>();
  /** Record an admission made under `bp` (its epoch) valid until `until` (epoch ms). */
  admit(instanceKey: string, bp: AgentBlueprint, until: number): void {
    this.m.set(`${bp.key}\u0000${instanceKey}`, { epoch: bp.epoch, until });
  }
  revoke(instanceKey: string, bpKey: string): boolean {
    return this.m.delete(`${bpKey}\u0000${instanceKey}`);
  }
  /** A function for `BlueprintCheckOptions.admitted`: true only for an unexpired admission made under the record's current epoch. */
  checker(now: number): (instanceKey: string, bp: AgentBlueprint) => boolean {
    return (k, bp) => {
      const a = this.m.get(`${bp.key}\u0000${k}`);
      return a !== undefined && a.epoch === bp.epoch && now < a.until;
    };
  }
}
