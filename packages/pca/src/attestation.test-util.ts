import type { AttestationHookResult } from './attestation';

/** The `enforced: true` arm of an attestation hook result. */
export type EnforcedAttestation = Extract<AttestationHookResult, { enforced: true }>;

/** Narrow a hook result to its enforced arm (an attestation verifier is always enforcing); throws if it somehow is not. */
export function enforced(r: AttestationHookResult): EnforcedAttestation {
  if (!r.enforced) throw new Error('expected an enforced attestation hook result');
  return r;
}
