/**
 * TEST-ONLY adapters (R3-01). Production code can no longer hand a raw PQ key string to `verifyWithSuite`: the key must be
 * an opaque `PinnedPqKey` minted by `resolvePqVerifyKey`. Unit tests of the primitive seam routinely hold a bare key they
 * generated themselves, so these wrappers accept the legacy string-slot shape and mint the key as a verifier-TRUSTED one.
 * Never import this module from non-test code (scripts/check-pq-pinning.mjs fails the build if you do).
 */
import {
  resolvePqVerifyKey,
  verifyLeafSuite as realVerifyLeafSuite,
  verifyWithSuite as realVerifyWithSuite,
  type LeafSuiteInput,
  type SuiteSignatureInput,
  type SuitePublicKeys,
  type SuitePublicKeyStrings,
} from './pq';

type Slots = SuitePublicKeyStrings;

export function trustedPq(pk: unknown): SuitePublicKeys['pq'] {
  if (typeof pk !== 'string' || pk.length === 0) return undefined;
  return resolvePqVerifyKey('', undefined, { trustedPk: pk }) ?? undefined;
}

/** `verifyWithSuite` taking the legacy per-slot string keys; the first defined PQ slot is the trusted PQ key. */
export function verifyWithSuite(alg: unknown, keys: Slots, msg: Uint8Array, s: SuiteSignatureInput): boolean {
  const pk = keys.mlDsaPub ?? keys.slhDsaPub ?? keys.mlDsa87Pub ?? keys.slhDsa256sPub ?? keys.fnDsa512Pub ?? keys.fnDsa1024Pub ?? keys.lessCat1Pub;
  const pq = trustedPq(pk);
  return realVerifyWithSuite(alg, { ...(keys.edPub !== undefined ? { edPub: keys.edPub } : {}), ...(pq !== undefined ? { pq } : {}) }, msg, s);
}

/** `verifyLeafSuite` taking the legacy `pqPublicKey` string. */
export function verifyLeafSuite(i: Omit<LeafSuiteInput, 'pq'> & { pqPublicKey?: unknown }): boolean {
  const { pqPublicKey, ...rest } = i;
  const pq = trustedPq(pqPublicKey);
  return realVerifyLeafSuite({ ...rest, ...(pq !== undefined ? { pq } : {}) });
}
