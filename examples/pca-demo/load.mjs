/**
 * Resolve the two PCA packages the demo needs.
 *
 * The demo also uses the extension subpaths of `@atlasauth/pca` (`ext/frost`, `ext/ledger`, `ext/research`); they are merged
 * into one namespace with the root exports.
 *
 *  1. Normal case (npx / npm install / packed tarballs): bare specifiers resolve from node_modules.
 *  2. Repo checkout: if they are not installed, fall back to the built workspace packages
 *     (`packages/pca/dist`, `packages/pca-fetch/dist`) so `node examples/pca-demo/run.mjs` works
 *     straight after `pnpm install && pnpm --filter @atlasauth/pca-fetch... build`.
 */
import { existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';

async function load(spec, repoRel, buildHint) {
  try {
    return await import(spec);
  } catch (e) {
    // Node names the package (not the subpath) in this error
    const pkgName = spec.split('/').slice(0, 2).join('/');
    const missing = e && e.code === 'ERR_MODULE_NOT_FOUND' && String(e.message).includes(`'${pkgName}'`);
    if (!missing) throw e;
    const p = fileURLToPath(new URL(repoRel, import.meta.url));
    if (!existsSync(p)) {
      throw new Error(
        `Cannot find ${spec}. Install it (npm i ${spec}) or, in the repo checkout, build it first: ${buildHint}`,
      );
    }
    return import(pathToFileURL(p).href);
  }
}

export async function loadPca() {
  const hint = 'pnpm install && pnpm --filter @atlasauth/pca-fetch... build';
  const root = await load('@atlasauth/pca', '../../packages/pca/dist/index.js', hint);
  const exts = await Promise.all(['frost', 'ledger', 'research'].map((e) => load(`@atlasauth/pca/ext/${e}`, `../../packages/pca/dist/ext/${e}.js`, hint)));
  const pca = Object.assign({}, root, ...exts);
  const fetchGuard = await load('@atlasauth/pca-fetch', '../../packages/pca-fetch/dist/index.js', hint);
  return { pca, fetchGuard };
}
