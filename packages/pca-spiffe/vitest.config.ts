import { defineConfig } from 'vitest/config';
import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

// Resolve the workspace dependency from source so tests never depend on a stale pca dist build.
// Under a Stryker sandbox the package sits deeper (`.stryker-tmp-*/sandbox-*`), so walk up to the sibling `pca`.
function pcaSource(): string {
  for (let dir = __dirname, i = 0; i < 5; i++, dir = dirname(dir)) {
    const candidate = resolve(dir, '../pca/src/index.ts');
    if (existsSync(candidate)) return candidate;
  }
  return resolve(__dirname, '../pca/src/index.ts');
}
export default defineConfig({
  resolve: { alias: { '@atlasauth/pca': pcaSource() } },
});
