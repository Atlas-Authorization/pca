// Copies the public PCA docs (markdown) from the repository into ./docs-bundle so they ship with the package.
// Runs on `npm pack` / `npm publish`. Internal material (specs, release notes, validation notes, advisories) is not bundled.
import { cpSync, existsSync, mkdirSync, readdirSync, rmSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
// the monorepo keeps the PCA docs under docs/pca, the public repository at docs/
const docsRoot = resolve(here, '../../../docs');
const src = existsSync(join(docsRoot, 'pca')) ? join(docsRoot, 'pca') : docsRoot;
const out = resolve(here, '../docs-bundle');
const SKIP = new Set(['specs', 'release-notes', 'validation', 'advisories', 'diagrams', 'public']);

if (!existsSync(src)) {
  console.error(`bundle-docs: ${src} not found (run from the repository)`);
  process.exit(1);
}
rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
let n = 0;
const walk = (dir, rel) => {
  for (const name of readdirSync(dir)) {
    if (name.startsWith('_') || name.startsWith('.')) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      if (!SKIP.has(name)) walk(p, join(rel, name));
    } else if (name.endsWith('.md')) {
      mkdirSync(join(out, rel), { recursive: true });
      cpSync(p, join(out, rel, name));
      n++;
    }
  }
};
walk(src, '');
console.log(`bundle-docs: ${n} markdown files -> docs-bundle`);
