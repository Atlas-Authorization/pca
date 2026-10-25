import { defineConfig } from 'vitest/config';
import { resolve } from 'node:path';

// Stryker (in-place) runs of src/ext-attest.ts: only the differential and kill suites that exercise it.
export default defineConfig({
  resolve: { alias: { '@atlasauth/pca-verified-core': resolve(__dirname, 'src/index.ts') } },
  test: { include: ['test/ext-attest.diff.test.ts', 'test/mutation-kill-ext-attest.test.ts'], exclude: ['**/node_modules/**', '**/dist/**'], testTimeout: 120_000 },
});
