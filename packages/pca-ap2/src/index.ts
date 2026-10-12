/**
 * @atlasauth/pca-ap2: AP2 (Agent Payments Protocol) mandates as real SD-JWT credentials, bound to a PCA grant.
 *
 * PCA governs: it decides who may spend, how much, until when, and when a human must co-sign. AP2 is
 * the mandate wire other parties verify. Settlement rails (x402, Stripe Shared Payment Tokens) move
 * the value, fed by PCA's decision.
 */
export * from './sdjwt';
export * from './mandates';
export * from './constraints';
export * from './chain';
export * from './pca';
export * from './settlement';

/** The AP2 repository commit whose schemas and documentation this package is checked against. */
export const AP2_COMMIT = 'e1ea56db72a6385bce3e5c1112b3a56ce60acb43';
