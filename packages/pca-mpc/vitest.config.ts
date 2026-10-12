import { defineConfig } from 'vitest/config';
import { resolve } from 'node:path';
import { existsSync } from 'node:fs';

// Resolve the workspace dependency from source so tests never depend on a stale pca dist build.
// Under a Stryker sandbox (packages/pca-mpc/.stryker-tmp-*/sandbox-*/) the package sits two levels deeper, so walk up.
const pcaSrc = [resolve(__dirname, '../pca/src/index.ts'), resolve(__dirname, '../../../pca/src/index.ts')].find(existsSync) ?? resolve(__dirname, '../pca/src/index.ts');
export default defineConfig({
  resolve: { alias: { '@atlasauth/pca': pcaSrc } },
});
