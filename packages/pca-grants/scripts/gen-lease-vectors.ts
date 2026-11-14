// Regenerate packages/pca/conformance/lease-vectors.json from the TypeScript reference (deterministic).
//   tsx scripts/gen-lease-vectors.ts [--check]
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildLeaseVectors } from '../src/test-support/lease-vectors';

const out = join(__dirname, '..', '..', 'pca', 'conformance', 'lease-vectors.json');
buildLeaseVectors().then((v) => {
  const text = `${JSON.stringify(v, null, 2)}\n`;
  if (process.argv.includes('--check')) {
    if (readFileSync(out, 'utf8') !== text) {
      console.error('lease-vectors.json is stale: run tsx scripts/gen-lease-vectors.ts');
      process.exit(1);
    }
  } else {
    writeFileSync(out, text);
    console.log(`wrote ${out}`);
  }
});
