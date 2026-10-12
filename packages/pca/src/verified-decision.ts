/**
 * Glue between the PCA verifier and the machine-proved decision core (`@atlasauth/pca-verified-core`, formal/dafny).
 *
 * TRUSTED BASE. The call sites in `pcactn.ts` (verifyPCActnCore) and `server/verify.ts` (verifyPCActn, enforceRequired) evaluate
 * every cryptographic / structural primitive and hand the RESULTS to the proved core, which decides the checks, their order,
 * the first reason, the F-1 threshold rule, the final `allow` and `enforceRequired` (see docs/pca/security/verified-core.md).
 * This file holds the few helpers those call sites share; it contains no decision logic of its own.
 */
import { pqBinding, type CoreState } from '@atlasauth/pca-verified-core';
import { holderPqCommitment } from './capability';
import { resolveSigAlg } from './pq';
import type { CheckStatus, VerifyResult } from './pcactn';

/** F-2 / R2-01 binding rule for a PQ-key suite; returns the legacy error string or undefined. The decision is the verified `pqBinding`. */
export function pqBindingErrorVerified(
  alg: unknown,
  pqPk: unknown,
  committed: string | undefined,
  label: string,
  policy: { allowUnboundPq?: boolean } | undefined,
): string | undefined {
  const suite = resolveSigAlg(alg);
  const needs = suite !== null && suite.needsPqPk;
  const allowUnbound = policy?.allowUnboundPq === true;
  const hasCommit = committed !== undefined;
  // `matches` is only meaningful (and only evaluated) when a commitment exists and the rule can bite.
  const matches = needs && !allowUnbound && hasCommit ? typeof pqPk === 'string' && holderPqCommitment(pqPk) === committed : false;
  const v = pqBinding(needs, allowUnbound, hasCommit, matches);
  if (v === undefined) return undefined;
  if (v === 'no-pq-commitment') {
    return `${label}: suite '${suite!.alg}' needs a PQ key bound to the signer, but the signer's holder carries no holder_pq commitment (unbound PQ keys are rejected; F-2)`;
  }
  return `${label}: pq_pk does not match the signer's committed holder_pq (F-2)`;
}

/** The verified core's fold, rendered as the legacy `VerifyResult` (insertion-ordered `checks`; `reason` only on deny). */
export function coreResultOf(st: CoreState<string, string>): VerifyResult {
  const checks = Object.fromEntries(st.checks) as Record<string, CheckStatus>;
  return st.allow ? { allow: true, checks } : { allow: false, checks, reason: st.reason };
}

/**
 * The threshold a hook reports, as the integer the verified F-1 rule compares. For an integer `t`, `x >= t` iff
 * `floor(x) >= t`; NaN (never `>=`) maps to "unreported", +/-Infinity to the safe-integer extremes.
 */
export function hookTInt(h: unknown): number | undefined {
  if (typeof h !== 'number' || Number.isNaN(h)) return undefined;
  if (h >= Number.MAX_SAFE_INTEGER) return Number.MAX_SAFE_INTEGER;
  if (h <= -Number.MAX_SAFE_INTEGER) return -Number.MAX_SAFE_INTEGER;
  return Math.floor(h);
}
