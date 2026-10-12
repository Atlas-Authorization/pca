import { defineConfig } from 'vitest/config';
import { resolve } from 'node:path';

// Same as vitest.ext-mutation.config.ts minus the Merkle differential (used for the non-Merkle ext-* modules).
export default defineConfig({
  resolve: { alias: { '@atlasauth/pca-verified-core': resolve(__dirname, 'src/index.ts') } },
  test: { include: ['test/ext-*.diff.test.ts', 'test/mutation-kill-ext-*.test.ts'], exclude: ['**/node_modules/**', '**/dist/**', 'test/ext-regex.diff.test.ts', 'test/ext-merkle.diff.test.ts'], testTimeout: 120_000 },
});
