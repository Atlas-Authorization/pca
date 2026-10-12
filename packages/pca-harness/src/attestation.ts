import type { HookResult, VerifyContext } from '@atlasauth/pca';
import { HARNESS_MODEL_ID } from './harness';

/**
 * PCA framework-evolution item **B1 — server-side acceptance of an attested orchestration harness**.
 *
 * The spec's L0 rung satisfies the attestation hook with a TEE/software quote that measures the opaque
 * *model* (see `@atlasauth/pca`'s `createAttestationVerifier`). B1 pivots the trusted computing base onto a
 * small, auditable **orchestration harness** (the mediator): the model is an untrusted oracle, and what an
 * attestation measures is the harness's policy-relevant surface ({@link computeHarnessMeasurement}). This
 * module is the RESOURCE-SERVER verifier for that pivot: a hook that admits a PCActn whose signed
 * `attestation.measurement` equals one of an operator-allowlisted set of harness measurements.
 *
 * TRUST MODEL (honest, not faked). The measurement travels in the PCActn's `attestation` block, which is
 * covered by the leaf-holder signature the verifier independently checks (`leaf_signature`). So this hook
 * trusts the measurement ONLY insofar as the overall verdict requires `leaf_signature` to pass — i.e. the
 * measurement was stamped by the key holder. In B1 the key holder IS the harness (the untrusted oracle
 * never holds the signing key), so an allowlisted measurement means "the signer is running an allowlisted
 * mediator". Like the SOFTWARE attestation mode in `@atlasauth/pca`, the measurement is self-asserted by the
 * signer, not hardware-rooted; trust is rooted in the operator's decision to ALLOWLIST it (as a TEE verifier
 * roots trust in `trustedAttestorKeys`). A hardware attestation OF the harness binary would root it in
 * silicon; that is the same seam the TEE path already defines, out of scope for this reference verifier.
 *
 * This hook is a drop-in `AttestationVerifier` (`(ctx) => HookResult`). It is FAIL-CLOSED and is only ever
 * built when an operator configures it, so there is no default-on behaviour.
 */
export interface HarnessAttestationConfig {
  /**
   * The allowlisted harness measurements (b64u SHA-256 digests, each an output of
   * {@link computeHarnessMeasurement} for a harness version + enforced-checks manifest + risk policy the
   * operator trusts). An action whose `attestation.measurement` is one of these is accepted.
   */
  measurements: readonly string[];
  /**
   * Fail-closed on an ABSENT harness measurement. Default `true`: a PCActn that carries no (empty) harness
   * measurement is rejected, so a configured requirement cannot be bypassed by simply omitting the stamp.
   * `false` makes an absent measurement a no-opinion `not-enforced` result (for composing with another
   * attestation path) — but a PRESENT-but-unallowlisted measurement is ALWAYS a hard fail regardless.
   */
  required?: boolean;
  /**
   * Optionally also require `attestation.model_id` to equal this identity (default {@link HARNESS_MODEL_ID}
   * when `true`, or a custom string). `false`/absent ⇒ the model_id is not checked and only the measurement
   * is matched. Pinning it refuses an action that carries an allowlisted measurement under a different
   * declared mediator identity.
   */
  expectedModelId?: string | boolean;
}

const asMeasurementSet = (xs: readonly string[] | undefined): Set<string> =>
  new Set((Array.isArray(xs) ? xs : []).filter((m): m is string => typeof m === 'string' && m.length > 0));

const resolveExpectedModelId = (v: HarnessAttestationConfig['expectedModelId']): string | undefined => {
  if (v === true) return HARNESS_MODEL_ID;
  if (typeof v === 'string' && v.length > 0) return v;
  return undefined;
};

/**
 * Build the B1 harness-mediator attestation verifier hook. Enforcement order, fail-closed throughout:
 *   1. an empty allowlist can accept NOTHING (configuring the hook with no measurements is a hard fail);
 *   2. an ABSENT (`''`) measurement fails when `required` (the default), else yields `not-enforced`;
 *   3. a declared `model_id` that is not the pinned identity (when pinned) fails;
 *   4. a PRESENT measurement that is not allowlisted ALWAYS fails (even when `required: false`);
 *   5. otherwise the action carries an allowlisted mediator measurement ⇒ pass.
 *
 * Note the measurement's integrity is NOT established here: it rests on the surrounding verdict requiring
 * the leaf signature to verify (the `attestation` block is signed). This hook only decides allowlisting.
 */
export function createHarnessAttestationVerifier(
  config: HarnessAttestationConfig,
): (ctx: VerifyContext) => HookResult {
  const allow = asMeasurementSet(config.measurements);
  const required = config.required !== false;
  const expectedModelId = resolveExpectedModelId(config.expectedModelId);

  return (ctx: VerifyContext): HookResult => {
    if (allow.size === 0) {
      return { enforced: true, ok: false, reason: 'harness attestation configured with an empty measurement allowlist (fail closed)' };
    }
    const att = ctx?.pcactn?.attestation;
    const measurement = typeof att?.measurement === 'string' ? att.measurement : '';
    if (measurement.length === 0) {
      return required
        ? { enforced: true, ok: false, reason: 'harness attestation required but the PCActn carries no harness measurement (fail closed)' }
        : { enforced: false };
    }
    if (expectedModelId !== undefined && att?.model_id !== expectedModelId) {
      return {
        enforced: true,
        ok: false,
        reason: `attestation.model_id '${String(att?.model_id)}' is not the required harness identity '${expectedModelId}'`,
      };
    }
    if (!allow.has(measurement)) {
      return { enforced: true, ok: false, reason: 'harness measurement is not in the allowlisted set (unattested or unknown mediator)' };
    }
    return { enforced: true, ok: true };
  };
}
