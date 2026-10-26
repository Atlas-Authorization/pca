/**
 * `@atlasauth/pca/ext/research`: Research and product-layer modules: agent mesh, multi-agent sessions, behavioural immune system, reputation, safety certificates, natural-language policy, DLP, QRNG entropy, hybrid KEM, guardian HA, console, budget forecast, policy simulation and debugging, contracts, connector catalog.
 *
 * Tier: experimental (see docs/pca/maturity.md). Not part of PCA Core and not re-exported from the root `@atlasauth/pca`.
 */
export * from '../policy-debug';
export * from '../safety-certificate';
export * from '../catalog';
export * as contracts from '../contracts';
export * as mesh from '../mesh';
export * from '../policy-sim';
export * from '../immune';
export * from '../console';
export * from '../dlp';
export * from '../reputation';
export * from '../budget-forecast';
export * from '../session';
export * from '../nl';
export * from '../ha';
export * from '../kem';
export * from '../entropy';
