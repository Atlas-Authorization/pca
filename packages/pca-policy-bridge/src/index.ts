/**
 * @atlasauth/pca-policy-bridge
 *
 * Import external authorization policy into PCA so existing enterprise policy engines drive
 * proof-carrying authority. Each translator compiles a policy source into PCA envelope
 * predicates/caveats (the exact shapes from `@atlasauth/pca`) plus a report of what was and was
 * not translated. Everything unmodeled fails closed (default deny).
 *
 *   - cedarToPca(policyText)      Cedar permit/forbid policies
 *   - regoToPca(moduleText)       OPA/Rego allow-rule subset
 *   - openfgaToPca(model, tuples) OpenFGA/Zanzibar ReBAC model + relationship tuples
 *
 * The emitted `predicates` plug straight into `Envelope.predicates`; `denies` (Cedar forbid) is
 * applied via `decide` (deny-overrides-permit) built on the core `evaluatePredicates`.
 */
export { cedarToPca } from './cedar';
export { regoToPca } from './rego';
export { openfgaToPca } from './openfga';
export { decide } from './types';
export type { BridgeResult, TranslationReport, PolicySource } from './types';
