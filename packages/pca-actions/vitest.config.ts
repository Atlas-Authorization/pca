import { defineConfig } from 'vitest/config';
import { resolve } from 'node:path';

// tests (and the repo scripts they import, e.g. scripts/actions-packs) run against this package's SOURCE, and the verified-core SOURCE (and its generated goal compiler), not a stale dist
export default defineConfig({
  resolve: { alias: { '@atlasauth/pca-actions': resolve(__dirname, 'src/index.ts'), '@atlasauth/pca-verified-core': resolve(__dirname, '../pca-verified-core/src/index.ts') } },
  test: { include: ['test/**/*.test.ts', 'src/**/*.test.ts'], exclude: ['**/node_modules/**', '**/dist/**'], testTimeout: 120_000 },
});
