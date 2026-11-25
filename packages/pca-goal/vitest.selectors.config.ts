import { defineConfig } from 'vitest/config';
import { resolve } from 'node:path';

// the mutation run kills selectors.ts mutants with the selector tests alone (they need no generated compiler): the behaviour tests and the exact-output kill tests
export default defineConfig({
  resolve: { alias: { '@atlasauth/pca-verified-core': resolve(__dirname, '../pca-verified-core/src/index.ts') } },
  test: { include: ['test/selectors.test.ts', 'test/selectors.mutation.test.ts'], exclude: ['**/node_modules/**', '**/dist/**'], testTimeout: 120_000 },
});
