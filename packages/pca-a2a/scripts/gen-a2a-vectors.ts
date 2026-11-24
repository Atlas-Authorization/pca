// Regenerate packages/pca/conformance/a2a-vectors.json from the TypeScript reference (deterministic).
//   tsx scripts/gen-a2a-vectors.ts [--check]
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildA2aVectors } from '../src/test-support/a2a-vectors';

const out = join(__dirname, '..', '..', 'pca', 'conformance', 'a2a-vectors.json');
const text = `${JSON.stringify(buildA2aVectors(), null, 2)}\n`;
if (process.argv.includes('--check')) {
  if (readFileSync(out, 'utf8') !== text) {
    console.error('a2a-vectors.json is stale: run tsx scripts/gen-a2a-vectors.ts');
    process.exit(1);
  }
} else {
  writeFileSync(out, text);
  console.log(`wrote ${out}`);
}
