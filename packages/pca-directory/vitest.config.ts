import { defineConfig } from 'vitest/config';
import { resolve } from 'node:path';

// Resolve the workspace dependencies from source so tests never depend on a stale dist build.
export default defineConfig({
  resolve: {
    alias: [
      { find: /^@atlasauth\/pca\/ext\/(.+)$/, replacement: `${resolve(__dirname, '../pca/src')}/ext/$1.ts` },
      { find: '@atlasauth/pca-verified-core', replacement: resolve(__dirname, '../pca-verified-core/src/index.ts') },
      { find: '@atlasauth/pca', replacement: resolve(__dirname, '../pca/src/index.ts') },
    ],
  },
});
