/**
 * @atlasauth/pca-intent: the PCA Intent Layer prototype (docs/specs/pca-intent-layer.md).
 *
 * Intent as a measurable object: a typed outcome space Ω derived from the grant/caveat vocabulary, an exact
 * Bayesian / version-space learner over grant hypotheses (boxes, unions of boxes, decision lists; agnostic
 * selection), maximal-disagreement question selection (boundary witnesses as optimal questions), partial answers
 * with cut refinement, residual-risk / burden / fidelity estimates, the conservative grant synthesiser, the
 * content-addressed Intent Map, the k-compiler disagreement pipeline, runtime conformance routing (judge panel
 * hook + IC-Att, optimistic bonds, JIT consent), effect postconditions, the trust ramp with drift detection,
 * multi-principal and cross-org aggregation, signed intent statements (`intent_ref`), a deterministic
 * plain-language renderer, and question cards for human studies.
 */
export * from './omega';
export * from './policy';
export * from './slots';
export * from './region';
export * from './learner';
export * from './metrics';
export * from './render';
export * from './witnesses';
export * from './statement';
export * from './map';
export * from './map-commit';
export * from './refine';
export * from './multi';
export * from './compilers';
export * from './runtime';
export * from './effects';
export * from './ramp';
export * from './ux';
export * from './layers';
export * from './world';
export * from './provenance';
export * from './classifier';
export * from './frames';
export * from './schema';
export * from './trajectory';
export * from './jit';
export * from './profile';
