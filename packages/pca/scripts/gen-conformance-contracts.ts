// Regenerate conformance/contracts-vectors.json from the TypeScript reference (deterministic).
//   tsx scripts/gen-conformance-contracts.ts [--check]
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildContractsVectors } from '../src/test-support/contracts-vectors';

const out = join(__dirname, '..', 'conformance', 'contracts-vectors.json');
void (async () => {
  const text = `${JSON.stringify(await buildContractsVectors(), null, 2)}\n`;
  if (process.argv.includes('--check')) {
    if (readFileSync(out, 'utf8') !== text) {
      console.error('contracts-vectors.json is stale: run tsx scripts/gen-conformance-contracts.ts');
      process.exit(1);
    }
  } else {
    writeFileSync(out, text);
    console.log(`wrote ${out}`);
  }
})();
