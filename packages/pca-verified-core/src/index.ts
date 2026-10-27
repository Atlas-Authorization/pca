/**
 * @atlasauth/pca-verified-core
 *
 * The decision logic of the PCA verifier, written and PROVED in Dafny (formal/dafny/*.dfy in the monorepo) and
 * compiled to JavaScript. The package takes plain JSON-like facts (booleans, small enums, integers, opaque
 * messages and pure closures standing for trusted crypto primitives) and returns plain decisions.
 * See docs/pca/security/verified-core.md for the theorem list, the trusted base and what is NOT covered.
 */
export * from './chain';
export * from './threshold';
export * from './replay';
export * from './verdict';
export type { Res, Status } from './bridge';
export * from './ext-wire';
export * from './ext-merkle';
export * from './ext-taint';
export * from './ext-attest';
export * from './ext-policyvm';
export * from './ext-regex';
export * from './goal';
