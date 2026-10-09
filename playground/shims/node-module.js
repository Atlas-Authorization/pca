// Browser stand-in for `node:module`. The only importer is the lazy FN-DSA wasm loader in pq.ts, which wraps the call
// in try/catch and pins "no binding", so every FN-DSA verification fails closed in the browser.
export function createRequire() {
  throw new Error('node:module is not available in the browser');
}
