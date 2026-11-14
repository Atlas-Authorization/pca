// Regenerate packages/pca/conformance/{workflow,readside}-vectors.json from the TypeScript reference (deterministic).
//   tsx packages/pca/scripts/gen-k5-vectors.ts [--check]
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildReadsideVectors, buildVaultAggregateVectors, buildWorkflowVectors } from '../src/test-support/k5-vectors';

const dir = join(__dirname, '..', 'conformance');
let stale = false;
for (const [name, build] of [['workflow-vectors.json', buildWorkflowVectors], ['readside-vectors.json', buildReadsideVectors], ['vault-aggregate-vectors.json', buildVaultAggregateVectors]] as const) {
  const out = join(dir, name);
  const text = `${JSON.stringify(build(), null, 2)}\n`;
  if (process.argv.includes('--check')) {
    if (readFileSync(out, 'utf8') !== text) {
      console.error(`${name} is stale: run tsx packages/pca/scripts/gen-k5-vectors.ts`);
      stale = true;
    }
  } else {
    writeFileSync(out, text);
    console.log(`wrote ${out}`);
  }
}
if (stale) process.exit(1);
