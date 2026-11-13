import { defineConfig } from 'vitest/config';
import { resolve } from 'node:path';

// Resolve the workspace dependency from source so tests never depend on a stale pca dist build.
export default defineConfig({
  resolve: {
    alias: [
      // the extension subpaths (`@atlasauth/pca/ext/<name>`) come from source too
      { find: /^@atlasauth\/pca\/ext\/(.+)$/, replacement: `${resolve(__dirname, '../pca/src')}/ext/$1.ts` },
      { find: '@atlasauth/pca', replacement: resolve(__dirname, '../pca/src/index.ts') },
    ],
  },
});
