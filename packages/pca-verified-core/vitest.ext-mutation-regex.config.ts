import { defineConfig } from 'vitest/config';
import { resolve } from 'node:path';

// Stryker (in-place) runs of src/ext-regex.ts: the proved-engine differential and the budget tests.
export default defineConfig({
  resolve: { alias: { '@atlasauth/pca-verified-core': resolve(__dirname, 'src/index.ts') } },
  test: { include: ['test/ext-regex.diff.test.ts', 'test/ext-regex-budget.test.ts', 'test/mutation-kill-ext-regex-r9.test.ts'], exclude: ['**/node_modules/**', '**/dist/**'], testTimeout: 120_000 },
});
