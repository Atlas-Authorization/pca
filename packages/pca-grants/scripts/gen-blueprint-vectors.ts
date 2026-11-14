// Regenerate packages/pca/conformance/blueprint-vectors.json from the TypeScript reference (deterministic).
//   tsx scripts/gen-blueprint-vectors.ts [--check]
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildBlueprintVectors } from '../src/test-support/blueprint-vectors';

const out = join(__dirname, '..', '..', 'pca', 'conformance', 'blueprint-vectors.json');
buildBlueprintVectors().then((v) => {
  const text = `${JSON.stringify(v, null, 2)}\n`;
  if (process.argv.includes('--check')) {
    if (readFileSync(out, 'utf8') !== text) {
      console.error('blueprint-vectors.json is stale: run tsx scripts/gen-blueprint-vectors.ts');
      process.exit(1);
    }
  } else {
    writeFileSync(out, text);
    console.log(`wrote ${out}`);
  }
});
