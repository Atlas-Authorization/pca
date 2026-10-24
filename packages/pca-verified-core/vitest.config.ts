import { defineConfig } from 'vitest/config';
import { resolve } from 'node:path';

// The differential tests exercise the monorepo's pca SOURCE (not a stale dist) against the verified core SOURCE.
export default defineConfig({
  resolve: {
    alias: {
      '@atlasauth/pca-verified-core': resolve(__dirname, 'src/index.ts'),
    },
  },
  test: { include: ['test/**/*.test.ts', 'src/**/*.test.ts'], exclude: ['**/node_modules/**', '**/dist/**'], testTimeout: 120_000,
    // a worker thread with a large stack: test/mutation-kill-ext-wire-depth.test.ts feeds the proved wire layer a 4097-deep document,
    // which the default (~1 MB) worker stack cannot even recurse to
    pool: 'threads',
    poolOptions: { threads: { resourceLimits: { stackSizeMb: 256 } } },
  },
});
