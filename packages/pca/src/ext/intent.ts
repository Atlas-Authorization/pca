/**
 * `@atlasauth/pca/ext/intent`: the intent layer. Binding and enforcement (intent statements and the envelope intent binding, action
 * schemas, sessions, accumulators and monitors, world facts, offer sets, provenance, classifier dimensions, committed maps,
 * revocation, questions) is in the production tier. The frontier members (`semanticThreshold`, `objectiveRisk`, `progress` and
 * their helpers) are experimental. Not part of PCA Core and not re-exported from the root `@atlasauth/pca`; hand `INTENT_EXTENSIONS`
 * to `verifyPCActnCore` from `@atlasauth/pca/core` to give Core the layer.
 */
export * from '../intent-binding';
// Intent Layer v2 wire batch W-B (conformance rules 16-18): world facts, offer sets, per-parameter provenance, label
// receipts and flows, classifier verdicts, and their composition for the verifier pipeline.
export * from '../intent-artifacts';
export * from '../oracle-facts';
export * from '../offer-set';
export * from '../label-receipts';
export * from '../param-provenance';
export * from '../intent-classifier';
export * from '../intent-env';
export * from '../intent-layers';
export * from '../intent';
export * from '../action-schema';
export * from '../intent-acc';
export * from '../intent-session-caveat';
export * from '../intent-session';
export * from '../intent-revocation';
export * from '../intent-required';
export * from '../intent-v2';
export * from '../intent-map-commit';
export * from '../intent-history';
export * from '../budget-ledger';
export * from '../objective-binding';
export * from '../semantic-threshold';
// Frontier capabilities (docs/pca-frontier-research.md). Namespaced so their
// APIs compose cleanly and don't collide (e.g. objectiveRisk.commitGoal vs
// progress.commitGoal). Library-complete; server/wire integration is staged.
export * as objectiveRisk from '../objective-risk';
export * as progress from '../progress';

// The intent layer as a PCA Core extension: pass to `verifyPCActnCore(p, { ..., extensions: INTENT_EXTENSIONS })` from `@atlasauth/pca/core`.
export { FULL_EXTENSIONS as INTENT_EXTENSIONS, INTENT_WIRE_EXTENSION } from '../pcactn-full';
