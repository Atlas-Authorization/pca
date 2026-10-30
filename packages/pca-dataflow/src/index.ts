/**
 * @atlasauth/pca-dataflow — the CaMeL-style data-flow model (now part of `@atlasauth/pca`, subpath `@atlasauth/pca/dataflow`,
 * where the default `authorize()` provenance gate shares its lattice), plus the trace rules and detector adapters built on it.
 * This package re-exports the core model unchanged so existing imports keep working.
 */
export * from '@atlasauth/pca/dataflow';
export * from './trace-rules';
export * from './detectors';
