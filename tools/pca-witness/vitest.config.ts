import { defineConfig } from 'vitest/config';
import { resolve } from 'node:path';

const pca = (f: string) => resolve(__dirname, '../../packages/pca/src/' + f);
export default defineConfig({
  resolve: {
    alias: [
      { find: '@atlasauth/pca/durable-state', replacement: pca('durable-state.ts') },
      { find: /^@atlasauth\/pca\/ext\/(.*)$/, replacement: pca('ext/$1.ts') },
      { find: /^@atlasauth\/pca$/, replacement: pca('index.ts') },
    ],
  },
  test: { pool: 'forks', poolOptions: { forks: { singleFork: true } } },
});
