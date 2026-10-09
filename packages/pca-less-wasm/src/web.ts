/**
 * Browser / worker / edge entry (no `node:*` imports). Call `await initLess(urlOrBytes)` once, or use
 * `@atlasauth/pca-less-wasm/embedded` for a self-contained load. Every other export is identical to the
 * Node entry.
 */
export * from './core.js';
