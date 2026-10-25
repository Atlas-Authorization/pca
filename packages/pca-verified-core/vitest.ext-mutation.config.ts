import { defineConfig } from 'vitest/config';
import { resolve } from 'node:path';

// Stryker (in-place) runs of the ext-* glue: only the differential tests that exercise those modules, run against the SOURCE.
export default defineConfig({
  resolve: { alias: { '@atlasauth/pca-verified-core': resolve(__dirname, 'src/index.ts') } },
  test: { include: ['test/ext-*.diff.test.ts', 'test/mutation-kill-ext-*.test.ts'], exclude: ['**/node_modules/**', '**/dist/**', 'test/ext-regex.diff.test.ts'], testTimeout: 120_000,
    // a worker thread with a large stack: test/mutation-kill-ext-wire-depth.test.ts feeds the proved wire layer a 4097-deep document,
    // which the default (~1 MB) worker stack cannot even recurse to
    pool: 'threads',
    poolOptions: { threads: { resourceLimits: { stackSizeMb: 256 } } },
  },
});
