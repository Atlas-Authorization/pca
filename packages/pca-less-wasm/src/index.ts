/**
 * Node / Bun / Deno entry: the portable API from `core.ts`, plus a synchronous filesystem loader for the
 * bundled `wasm/less_cat1.wasm`, so `verify()` etc. work with no explicit init (the shape `@atlasauth/pca`
 * relies on). Browsers and edge workers resolve `./web` instead (see package.json `exports`).
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { setSyncWasmLoader } from './core.js';

setSyncWasmLoader(() => new Uint8Array(readFileSync(join(__dirname, '..', 'wasm', 'less_cat1.wasm'))));

export * from './core.js';
