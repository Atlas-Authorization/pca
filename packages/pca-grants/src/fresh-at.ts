/** Consistency tokens live in the core package (they are a PCActn member); re-exported here for the operational plane. */
export {
  FRESH_AT_DOMAIN, FRESH_AT_REF_DOMAIN, FreshAtIssuer, checkFreshAt, decideFreshAt, freshAtDigest, gateDecision, mergeFreshAt, signFreshAt,
  validateFreshAtWire, verifyFreshAt,
} from '@atlasauth/pca';
export type { CheckFreshAtOptions, FreshAt, FreshAtCheck, FreshAtCode, FreshAtPolicy, FreshAtState, FreshAtToken, FreshAtVerdict, Tri } from '@atlasauth/pca';
