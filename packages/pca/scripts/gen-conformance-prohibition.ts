// Regenerate conformance/prohibition-vectors.json from the TypeScript reference (deterministic).
//   tsx scripts/gen-conformance-prohibition.ts [--check]
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildProhibitionVectors } from '../src/test-support/prohibition-vectors';

const out = join(__dirname, '..', 'conformance', 'prohibition-vectors.json');
const text = `${JSON.stringify(buildProhibitionVectors(), null, 2)}\n`;
if (process.argv.includes('--check')) {
  if (readFileSync(out, 'utf8') !== text) {
    console.error('prohibition-vectors.json is stale: run tsx scripts/gen-conformance-prohibition.ts');
    process.exit(1);
  }
} else {
  writeFileSync(out, text);
  console.log(`wrote ${out}`);
}
