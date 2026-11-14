// Regenerate conformance/pca-grant-vectors.json from the TypeScript reference (deterministic).
//   tsx scripts/gen-conformance-pca-grant.ts [--check]
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildPcaGrantVectors } from '../src/test-support/pca-grant-vectors';

const out = join(__dirname, '..', 'conformance', 'pca-grant-vectors.json');
const text = `${JSON.stringify(buildPcaGrantVectors(), null, 2)}\n`;
if (process.argv.includes('--check')) {
  if (readFileSync(out, 'utf8') !== text) {
    console.error('pca-grant-vectors.json is stale: run tsx scripts/gen-conformance-pca-grant.ts');
    process.exit(1);
  }
} else {
  writeFileSync(out, text);
  console.log(`wrote ${out}`);
}
