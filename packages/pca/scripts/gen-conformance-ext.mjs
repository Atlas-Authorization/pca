// Extension-member vectors (conformance/LAYERS.md, layer `extension`): conformance/optimistic-vectors.json and
// conformance/ledger-vectors.json. The cases and their intended outcomes live in conformance-ext.mjs.
//
//     node packages/pca/scripts/gen-conformance-ext.mjs [--check]                          (reads ../dist)
//     PCA_SRC=1 packages/pca/node_modules/.bin/tsx packages/pca/scripts/gen-conformance-ext.mjs   (reads ../src)
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { confDir } from './conformance-io.mjs';
import { buildLedger, buildOptimistic, serializeExt } from './conformance-ext.mjs';

const src = !!process.env.PCA_SRC;
const core = src ? await import('../src/index.ts') : await import('../dist/index.js');
const opt = src ? await import('../src/ext/optimistic.ts') : await import('../dist/ext/optimistic.js');
// B17: the Map-backed bond ledger is not part of the shipped optimistic extension; the vectors are computed with the testing ledger
const bonds = src ? await import('../src/bond-ledger-testing.ts') : await import('../dist/bond-ledger-testing.js');
const led = src ? await import('../src/ext/ledger.ts') : await import('../dist/ext/ledger.js');

const files = {
  'optimistic-vectors.json': serializeExt(buildOptimistic({ opt: { ...opt, BondLedger: bonds.BondLedger, InMemoryBondAccount: bonds.InMemoryBondAccount }, core })),
  'ledger-vectors.json': serializeExt(buildLedger({ led, core })),
};
let bad = 0;
for (const [name, text] of Object.entries(files)) {
  const path = join(confDir, name);
  if (process.argv.includes('--check')) {
    let committed = '';
    try { committed = readFileSync(path, 'utf8'); } catch { /* absent */ }
    if (committed !== text) { console.error(`${name} differs from a fresh regeneration: re-run gen-conformance-ext.mjs and commit`); bad++; }
    else console.log(`${name} up to date`);
  } else {
    writeFileSync(path, text);
    console.log(`wrote ${path}: ${JSON.parse(text).counts ? JSON.stringify(JSON.parse(text).counts) : ''}`);
  }
}
process.exit(bad ? 1 : 0);
