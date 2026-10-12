import { validityDecision } from '@atlasauth/pca-verified-core';
import { PCACTN_MAX_LIFETIME_MS } from './pcactn';

/** Which full-verifier check a {@link pcactnCheapClaims} refusal corresponds to. */
export interface PcactnCheapClaimFailure {
  check: 'audience' | 'validity';
  reason: string;
}

/**
 * R5-API-03: the PCActn's `aud`, `iat` and `exp`, checked BEFORE any signature verification or metering.
 *
 * These are unauthenticated fields at this point, so a pass proves nothing; but a FAIL is final: the full verifier
 * (`verifyPCActn`) makes exactly the same `audience` and `validity` decisions on the same fields (it calls the same
 * verified-core `validityDecision`), so a document refused here could never be admitted. A server therefore refuses it
 * without touching a shared rate-limit bucket or doing any crypto. O(1). Returns null when both checks pass.
 *
 * `audience` is this verifier's audience id (the hosted API passes the instance id); `now` is epoch ms.
 */
export function pcactnCheapClaims(
  p: { aud?: unknown; iat?: unknown; exp?: unknown },
  opts: { audience: string; now: number },
): PcactnCheapClaimFailure | null {
  if (typeof p.aud !== 'string' || p.aud.length === 0 || p.aud !== opts.audience) {
    return { check: 'audience', reason: 'aud does not match this resource server / instance' };
  }
  if (!Number.isSafeInteger(p.iat) || !Number.isSafeInteger(p.exp)) {
    return { check: 'validity', reason: 'iat and exp must be safe-integer epoch ms' };
  }
  let decision: ReturnType<typeof validityDecision>;
  try {
    decision = validityDecision(Number.isSafeInteger(opts.now), p.iat as number, p.exp as number, opts.now);
  } catch {
    return { check: 'validity', reason: 'unverifiable validity window' };
  }
  switch (decision) {
    case 'pass':
      return null;
    case 'bad-clock':
      return { check: 'validity', reason: 'the verifier clock is not a safe integer epoch-ms' };
    case 'not-greater':
      return { check: 'validity', reason: 'exp must be greater than iat' };
    case 'too-long':
      return { check: 'validity', reason: `lifetime exceeds ${PCACTN_MAX_LIFETIME_MS} ms` };
    case 'future':
      return { check: 'validity', reason: 'iat is in the future (clock skew)' };
    default:
      return { check: 'validity', reason: 'the PCActn has expired' };
  }
}
