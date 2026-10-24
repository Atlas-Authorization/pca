/**
 * @atlasauth/pca-evidence: the Intent Layer v2 dispute evidence bundle (docs/specs/pca-intent-layer-v2.md §3.11):
 * build a `pca-intent-evidence` v1 bundle, replay it deterministically into a findings report, anchor it and register it
 * as a SCITT signed statement. CLI: `pca-evidence verify <bundle.json> [--trust trust.json] [--json]`.
 */
export * from './bundle';
export * from './verify';
export * from './scitt';
export { runCli, type CliIo } from './cli';
