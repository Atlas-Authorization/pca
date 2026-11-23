import { defineConfig } from 'vitest/config';
import { dirname, resolve } from 'node:path';
import { existsSync } from 'node:fs';

// Resolve the workspace dependency from source so tests never depend on a stale pca dist build.
// Under a Stryker sandbox (packages/pca-mpc/.stryker-tmp-*/sandbox-*/) the package sits two levels deeper, so walk up.
const pcaSrc = [resolve(__dirname, '../pca/src/index.ts'), resolve(__dirname, '../../../pca/src/index.ts')].find(existsSync) ?? resolve(__dirname, '../pca/src/index.ts');
export default defineConfig({
  resolve: {
    alias: [
      // the extension subpaths (`@atlasauth/pca/ext/<name>`) come from source too
      { find: /^@atlasauth\/pca\/ext\/(.+)$/, replacement: `${dirname(pcaSrc)}/ext/$1.ts` },
      { find: '@atlasauth/pca', replacement: pcaSrc },
    ],
  },
});
