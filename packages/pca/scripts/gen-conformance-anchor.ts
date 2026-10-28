// Regenerate conformance/allowlist-anchor-vectors.json from the TypeScript reference (deterministic).
//   tsx scripts/gen-conformance-anchor.ts [--check]
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildAnchorVectors } from '../src/test-support/anchor-vectors';

const out = join(__dirname, '..', 'conformance', 'allowlist-anchor-vectors.json');
const text = `${JSON.stringify(buildAnchorVectors(), null, 2)}\n`;
if (process.argv.includes('--check')) {
  if (readFileSync(out, 'utf8') !== text) {
    console.error('allowlist-anchor-vectors.json is stale: run tsx scripts/gen-conformance-anchor.ts');
    process.exit(1);
  }
} else {
  writeFileSync(out, text);
  console.log(`wrote ${out}`);
}
