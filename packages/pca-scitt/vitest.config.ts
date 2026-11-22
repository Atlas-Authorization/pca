import { defineConfig } from 'vitest/config';
import { resolve } from 'node:path';

// Resolve the workspace dependency from source so tests never depend on a stale pca dist build.
export default defineConfig({
  resolve: { alias: { '@atlasauth/pca': resolve(__dirname, '../pca/src/index.ts') } },
});
